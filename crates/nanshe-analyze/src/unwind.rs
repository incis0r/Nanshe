//! Odwijanie stosu wątku Windows x64 po tablicach wyjątków obrazów PE (`.pdata`), bez pomocy systemu.
//!
//! Cel jest wąski: dla wątku czekającego w wywołaniu jądra ustalić pierwszy adres powrotu, który
//! leży poza wszystkimi obrazami modułów. Wszystkie dane (nagłówki PE, tablice, stos) pochodzą
//! z pamięci badanego procesu, więc są niezaufane: każda pętla ma limit, każdy odczyt może się
//! nie udać, a wynik wątpliwy jest porzucany zamiast zgadywany.

use nanshe_core::{Region, RegionKind, ThreadRegs};
use std::collections::HashMap;

/// Najwięcej ramek jednego wątku.
pub const MAX_FRAMES: usize = 64;
/// Najwięcej ogniw łańcucha informacji o odwijaniu jednej funkcji.
const MAX_CHAIN: usize = 32;
/// O ile najwyżej może urosnąć wskaźnik stosu w trakcie odwijania (największy stos wątku to 1 GiB; typowy 1 MiB).
const MAX_STACK_SPAN: u64 = 64 << 20;
/// Najwięcej wpisów tablicy funkcji jednego obrazu (12 bajtów każdy).
const MAX_FUNCTIONS: u32 = 4 << 20;

const RSP: usize = 4;

/// Obraz modułu w pamięci: spójny zakres regionów typu obraz z tego samego pliku.
#[derive(Clone, Debug, PartialEq)]
pub struct Image { pub base: u64, pub end: u64 }

/// Obrazy modułów z mapy regionów (posortowanej po adresie). Kolejne regiony tego samego pliku
/// tworzą jeden obraz; jego początek to nagłówek PE.
pub fn images(regions: &[Region]) -> Vec<Image> {
    let mut out: Vec<Image> = Vec::new();
    let mut last: Option<&str> = None;
    for r in regions {
        let name = if r.kind == RegionKind::Image { r.backing.as_deref() } else { None };
        match (name, last, out.last_mut()) {
            (Some(n), Some(l), Some(img)) if n == l && r.base >= img.end => img.end = r.base.saturating_add(r.size),
            (Some(_), _, _) => out.push(Image { base: r.base, end: r.base.saturating_add(r.size) }),
            _ => {}
        }
        last = name;
    }
    out
}

/// Tablica funkcji obrazu: adres i liczba wpisów; None, gdy obraz jej nie ma albo nagłówek jest zły.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Table { addr: u64, count: u32 }

/// Odczyt pamięci badanego procesu: true tylko wtedy, gdy przeczytano cały bufor.
pub trait Mem { fn read(&self, addr: u64, buf: &mut [u8]) -> bool; }
impl<F: Fn(u64, &mut [u8]) -> bool> Mem for F { fn read(&self, addr: u64, buf: &mut [u8]) -> bool { self(addr, buf) } }

fn rd<const N: usize>(m: &dyn Mem, addr: u64) -> Option<[u8; N]> { let mut b = [0u8; N]; m.read(addr, &mut b).then_some(b) }
fn u16at(m: &dyn Mem, a: u64) -> Option<u16> { rd::<2>(m, a).map(u16::from_le_bytes) }
fn u32at(m: &dyn Mem, a: u64) -> Option<u32> { rd::<4>(m, a).map(u32::from_le_bytes) }
fn u64at(m: &dyn Mem, a: u64) -> Option<u64> { rd::<8>(m, a).map(u64::from_le_bytes) }

/// Katalog wyjątków obrazu PE32+ (indeks 3). Zakres tablicy musi mieścić się w obrazie.
fn table(m: &dyn Mem, img: &Image) -> Option<Table> {
    if u16at(m, img.base)? != 0x5a4d { return None; }
    let pe = img.base.checked_add(u32at(m, img.base + 0x3c)? as u64)?;
    if pe.checked_add(0x108)? > img.end || u32at(m, pe)? != 0x0000_4550 { return None; }
    let opt = pe + 24;
    if u16at(m, opt)? != 0x20b { return None; } // tylko PE32+
    if u32at(m, opt + 108)? < 4 { return None; } // liczba katalogów danych
    let (rva, size) = (u32at(m, opt + 112 + 3 * 8)?, u32at(m, opt + 112 + 3 * 8 + 4)?);
    let count = size / 12;
    if rva == 0 || count == 0 || count > MAX_FUNCTIONS { return None; }
    let addr = img.base.checked_add(rva as u64)?;
    if addr.checked_add(count as u64 * 12)? > img.end { return None; }
    Some(Table { addr, count })
}

/// Wpis tablicy funkcji: początek, koniec i informacja o odwijaniu (wszystko jako RVA).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Func { begin: u32, end: u32, info: u32 }

fn func_at(m: &dyn Mem, addr: u64) -> Option<Func> {
    let b = rd::<12>(m, addr)?;
    Some(Func { begin: u32::from_le_bytes(b[0..4].try_into().ok()?), end: u32::from_le_bytes(b[4..8].try_into().ok()?), info: u32::from_le_bytes(b[8..12].try_into().ok()?) })
}

/// Wyszukiwanie binarne funkcji zawierającej `rva`. Ok(None): funkcja bez wpisu (liść). Err: odczyt się nie udał.
fn lookup(m: &dyn Mem, t: Table, rva: u32) -> Result<Option<Func>, ()> {
    let (mut lo, mut hi) = (0u32, t.count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let f = func_at(m, t.addr + mid as u64 * 12).ok_or(())?;
        if rva < f.begin { hi = mid } else if rva >= f.end { lo = mid + 1 } else { return Ok(Some(f)); }
    }
    Ok(None)
}

/// Stan odwijania: rejestry ogólne (numeracja x64: 4 = rsp) i adres instrukcji.
#[derive(Clone, Debug)]
struct State { gpr: [u64; 16], rip: u64 }

/// Cofa skutki prologu jednej funkcji. `off`: odległość rip od początku funkcji (operacje prologu
/// późniejsze niż rip jeszcze się nie wykonały). Zwraca true, gdy ramka była ramką maszynową
/// (rip i rsp są już ustawione, nie ma adresu powrotu do zdjęcia).
fn undo_prolog(m: &dyn Mem, img: &Image, mut f: Func, off: u32, s: &mut State) -> Option<bool> {
    for depth in 0..MAX_CHAIN {
        // Bit 0 oznacza wskazanie na inny wpis tablicy zamiast na informację o odwijaniu.
        if f.info & 1 == 1 { f = func_at(m, img.base.checked_add((f.info & !1) as u64)?)?; continue; }
        let ui = img.base.checked_add(f.info as u64)?;
        if ui.checked_add(4)? > img.end { return None; }
        let h = rd::<4>(m, ui)?;
        let (version, flags, count, freg, foff) = (h[0] & 7, h[0] >> 3, h[2] as usize, (h[3] & 15) as usize, (h[3] >> 4) as u64);
        if version != 1 && version != 2 { return None; }
        let mut codes = vec![0u8; count * 2];
        if count > 0 && !m.read(ui + 4, &mut codes) { return None; }
        let slot = |i: usize| -> Option<u64> { codes.get(i * 2..i * 2 + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u64) };
        let mut i = 0;
        while i < count {
            let (at, op, info) = (codes[i * 2] as u32, codes[i * 2 + 1] & 15, (codes[i * 2 + 1] >> 4) as usize);
            // w pierwszym ogniwie pomijamy operacje, do których prolog jeszcze nie doszedł
            let done = depth > 0 || off >= at;
            let sp = s.gpr[RSP];
            let len = match op {
                0 => { if done { s.gpr[info] = u64at(m, sp)?; s.gpr[RSP] = sp.checked_add(8)?; } 1 } // PUSH_NONVOL
                1 => { // ALLOC_LARGE
                    let (n, len) = if info == 0 { (slot(i + 1)? * 8, 2) } else { (slot(i + 1)? | slot(i + 2)? << 16, 3) };
                    if done { s.gpr[RSP] = sp.checked_add(n)?; }
                    len
                }
                2 => { if done { s.gpr[RSP] = sp.checked_add(info as u64 * 8 + 8)?; } 1 } // ALLOC_SMALL
                3 => { if done { s.gpr[RSP] = s.gpr[freg].checked_sub(foff * 16)?; } 1 } // SET_FPREG
                4 => { if done { s.gpr[info] = u64at(m, sp.checked_add(slot(i + 1)? * 8)?)?; } 2 } // SAVE_NONVOL
                5 => { if done { s.gpr[info] = u64at(m, sp.checked_add(slot(i + 1)? | slot(i + 2)? << 16)?)?; } 3 } // SAVE_NONVOL_FAR
                6 => if version == 2 { 1 } else { 2 }, // EPILOG (wersja 2) albo dawne SAVE_XMM
                7 => 3,
                8 => 2, // SAVE_XMM128
                9 => 3, // SAVE_XMM128_FAR
                10 => { // PUSH_MACHFRAME
                    if done {
                        let fr = sp.checked_add(if info == 1 { 8 } else { 0 })?;
                        s.rip = u64at(m, fr)?;
                        s.gpr[RSP] = u64at(m, fr.checked_add(24)?)?;
                        return Some(true);
                    }
                    1
                }
                _ => return None,
            };
            i += len;
        }
        if flags & 4 == 0 { return Some(false); }
        // łańcuch: po kodach (wyrównanych do parzystej liczby) leży wpis funkcji nadrzędnej
        f = func_at(m, ui + 4 + ((count + 1) & !1) as u64 * 2)?;
    }
    None
}

/// Adres powrotu poza obrazami modułów i liczba odwiniętych ramek.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Foreign { pub addr: u64, pub frames: usize }

/// Odwijanie stosów wątków jednego procesu; tablice funkcji obrazów są wyszukiwane raz.
pub struct Unwinder<'a> { mem: &'a dyn Mem, images: Vec<Image>, tables: HashMap<u64, Option<Table>> }

impl<'a> Unwinder<'a> {
    pub fn new(mem: &'a dyn Mem, regions: &[Region]) -> Self { Unwinder { mem, images: images(regions), tables: HashMap::new() } }

    fn image(&self, addr: u64) -> Option<Image> {
        let i = self.images.partition_point(|m| m.end <= addr);
        self.images.get(i).filter(|m| m.base <= addr).cloned()
    }

    /// Pierwszy adres powrotu poza obrazami modułów na stosie wątku, który stoi tuż za instrukcją
    /// `syscall` w obrazie modułu. None: wątek nie jest w takim stanie, cały stos wraca do obrazów
    /// albo odwijania nie dało się przeprowadzić wiarygodnie.
    pub fn foreign_return(&mut self, t: &ThreadRegs) -> Option<Foreign> {
        self.image(t.rip)?;
        if rd::<2>(self.mem, t.rip.checked_sub(2)?)? != [0x0f, 0x05] { return None; }
        let start = t.gpr[RSP];
        let mut s = State { gpr: t.gpr, rip: t.rip };
        for frames in 0..MAX_FRAMES {
            let Some(img) = self.image(s.rip) else {
                return (frames > 0).then_some(Foreign { addr: s.rip, frames });
            };
            let mem = self.mem;
            let tab = (*self.tables.entry(img.base).or_insert_with(|| table(mem, &img)))?;
            let rva = u32::try_from(s.rip - img.base).ok()?;
            let machine = match lookup(mem, tab, rva).ok()? {
                Some(f) => undo_prolog(mem, &img, f, rva - f.begin, &mut s)?,
                None => false, // liść: adres powrotu leży pod rsp
            };
            if !machine {
                s.rip = u64at(mem, s.gpr[RSP])?;
                s.gpr[RSP] = s.gpr[RSP].checked_add(8)?;
            }
            // stos rośnie w dół: po odwinięciu ramki wskaźnik musi być wyżej, wyrównany i niedaleko
            let sp = s.gpr[RSP];
            if sp <= start || sp % 8 != 0 || sp - start > MAX_STACK_SPAN { return None; }
        }
        None
    }
}
