//! Pamięć procesów gościa Windows czytana z hosta KVM/QEMU, bez niczego uruchamianego w gościu.
//!
//! Skaner czyta pamięć procesu QEMU na hoście (tylko odczyt), znajduje w niej jądro Windows i tablice
//! stron procesów gościa. Dzięki temu widzi też procesy, których skan z wnętrza systemu nie otworzy
//! (LSASS, procesy antywirusa), i nie da się go oszukać z poziomu gościa tak łatwo jak agenta.
//!
//! Ograniczenia, o których mówi też wynik:
//! - regiony pochodzą z tablic stron, więc obejmują tylko strony obecne w pamięci fizycznej (stron
//!   wyrzuconych do pliku wymiany nie widać), a rodzaj regionu wynika z listy modułów procesu;
//! - gość działa w trakcie odczytu, więc obraz nie jest spójną migawką.

#![forbid(unsafe_code)]

use std::path::Path;

/// Proces gościa z listy jądra.
#[derive(Clone, Debug)]
pub struct GuestProc { pub pid: u32, pub name: String, pub path: String, pub cmdline: String, pub alive: bool }

/// Jak skaner ma zdobyć symbole jądra gościa.
pub struct Symbols<'a> {
    /// Katalog z plikami symboli w układzie `<nazwa.pdb>/<identyfikator>`; None = katalog domyślny użytkownika.
    pub dir: Option<&'a Path>,
    /// Zgoda na pobranie brakującego pliku z serwera symboli Microsoftu (jedyne połączenie sieciowe tego modułu).
    pub fetch: bool,
}

#[cfg(all(target_os = "linux", feature = "guest"))]
mod imp;
#[cfg(all(target_os = "linux", feature = "guest"))]
pub use imp::{open, Guest, GuestProcess};

#[cfg(not(all(target_os = "linux", feature = "guest")))]
pub fn open(_target: &str, _symbols: Symbols) -> nanshe_core::Result<()> {
    Err(nanshe_core::Error::Unsupported(nanshe_core::tr!("odczyt z hiperwizora działa tylko na hoście Linux z KVM/QEMU", "hypervisor reads work only on a Linux host with KVM/QEMU").into()))
}

/// Zakres stron o jednej ochronie, z tablic stron procesu.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PageRange { pub base: u64, pub size: u64, pub write: bool, pub exec: bool }

/// Moduł załadowany w procesie gościa.
#[derive(Clone, Debug, PartialEq)]
pub struct Module { pub base: u64, pub size: u64, pub path: String }

/// Najwyższy adres przestrzeni użytkownika x86_64; powyżej są strony jądra, wspólne dla wszystkich procesów.
pub const USER_MAX: u64 = 0x0000_7fff_ffff_ffff;

/// Limit tablic stron czytanych dla jednego procesu (ochrona przed uszkodzonymi albo zapętlonymi tablicami).
pub const MAX_TABLES: usize = 1 << 17;
/// Limit zakresów stron jednego procesu: tablice ułożone na przemian (co druga strona inna ochrona) dałyby
/// dziesiątki milionów zakresów i wyczerpały pamięć skanera. Gość jest dla skanera danymi niezaufanymi.
pub const MAX_RANGES: usize = 1 << 20;

/// Przejście czteropoziomowych tablic stron x86_64 od adresu `dtb`: strony przestrzeni użytkownika obecne
/// w pamięci fizycznej, połączone w zakresy o jednej ochronie. `table` zwraca 512 wpisów tablicy spod adresu
/// fizycznego albo None, gdy nie da się jej przeczytać.
///
/// Uprawnienia łączone są jak w procesorze: zapis i dostęp z trybu użytkownika wymagają zgody na każdym
/// poziomie, a zakaz wykonywania wystarczy na jednym. (Biblioteka memflow 0.2.4 łączy bit zapisu odwrotnie,
/// przez co każda strona wygląda na zapisywalną; dlatego tablice czytamy sami.)
/// Drugi element wyniku mówi, czy przejście było pełne (false: nieczytelna tablica albo przekroczony limit).
/// Wpis tablicy stron nieważny dla procesora, ale wskazujący stronę, która nadal leży w pamięci fizycznej
/// (strona "przejściowa" Windows: zdjęta z zestawu roboczego procesu, jeszcze nie oddana). Tak wygląda duża
/// część pamięci bezczynnych procesów; bez tych stron skan z hiperwizora gubił regiony widoczne od środka.
pub fn is_transition(entry: u64) -> bool { entry & 1 == 0 && entry & (1 << 11) != 0 && entry & (1 << 10) == 0 }

/// Możliwe adresy fizyczne strony wskazanej przez wpis. Dla wpisu ważnego jest jeden. We wpisie nieważnym
/// Windows na procesorach podatnych na L1TF ustawia dodatkowy wysoki bit adresu, żeby wskazywał poza pamięć;
/// maski nie znamy, więc kolejne kandydatury to adres z odciętymi coraz niższymi wysokimi bitami. Wywołujący
/// bierze pierwszą, którą da się przeczytać.
pub fn frame_candidates(entry: u64) -> Vec<u64> {
    let base = entry & 0x000f_ffff_ffff_f000;
    let mut out = vec![base];
    if entry & 1 == 0 {
        for bits in [48u32, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36] {
            let c = base & ((1u64 << bits) - 1);
            if out.last() != Some(&c) { out.push(c); }
        }
    }
    out
}

/// Ochrona strony przejściowej z jej wpisu: (zapis, wykonanie) albo None, gdy strona nie ma dostępu.
/// Kod ochrony Windows w bitach 5-9; liczą się trzy najmłodsze: 1 odczyt, 2 wykonanie, 3 wykonanie i odczyt,
/// 4 zapis, 5 kopia przy zapisie, 6 wykonanie i zapis, 7 wykonanie i kopia przy zapisie.
pub fn transition_protection(entry: u64) -> Option<(bool, bool)> {
    match (entry >> 5) & 7 { 0 => None, c => Some((c == 4 || c == 6, matches!(c, 2 | 3 | 6 | 7))) }
}

/// Wpis końcowy (strony) dla adresu wirtualnego i rozmiar strony; None, gdy adres nie jest zmapowany w pamięci
/// fizycznej. Obsługuje wpisy ważne i przejściowe na każdym poziomie.
pub fn leaf_entry<T: AsRef<[u64]>>(dtb: u64, va: u64, mut table: impl FnMut(u64) -> Option<T>) -> Option<(u64, u64)> {
    let mut read = |entry: u64| frame_candidates(entry).into_iter().find_map(|a| table(a).filter(|t| t.as_ref().len() == 512));
    let usable = |e: u64| e & 1 != 0 || is_transition(e);
    let mut t = read(dtb | 1)?;
    for (shift, large) in [(39u32, 0u64), (30, 1 << 30), (21, 1 << 21)] {
        let e = t.as_ref()[((va >> shift) & 511) as usize];
        if !usable(e) { return None; }
        if large != 0 && e & 1 != 0 && e & 0x80 != 0 { return Some((e, large)); }
        t = read(e)?;
    }
    let e = t.as_ref()[((va >> 12) & 511) as usize];
    usable(e).then_some((e, 4096))
}

pub fn walk_page_tables(dtb: u64, mut table: impl FnMut(u64) -> Option<Vec<u64>>) -> (Vec<PageRange>, bool) {
    const P: u64 = 1; const W: u64 = 2; const U: u64 = 4; const PS: u64 = 0x80; const NX: u64 = 1 << 63;
    const ADDR: u64 = 0x000f_ffff_ffff_f000;
    // wpis tablicy wyższego poziomu w stanie przejściowym: tablica nadal jest w pamięci, a uprawnień sprzętowych
    // wpis nie niesie, więc nie ogranicza stron pod sobą
    const OPEN: u64 = P | W | U;
    let norm = |e: u64| if is_transition(e) { (e & ADDR) | OPEN | (1 << 62) } else { e };
    let mut out: Vec<PageRange> = Vec::new();
    let mut complete = true;
    let mut tables = 0usize;
    let mut overflow = false;
    let mut emit = |base: u64, size: u64, write: bool, exec: bool| {
        let full = out.len() >= MAX_RANGES;
        match out.last_mut() {
            Some(l) if l.base + l.size == base && l.write == write && l.exec == exec => l.size += size,
            _ if full => overflow = true,
            _ => out.push(PageRange { base, size, write, exec }),
        }
    };
    // stos zamiast rekurencji: (adres tablicy, poziom 4..1, adres wirtualny początku, zapis, użytkownik, zakaz wykonania)
    let mut read = |addr: u64, tables: &mut usize, complete: &mut bool| -> Option<Vec<u64>> {
        if *tables >= MAX_TABLES { *complete = false; return None; }
        *tables += 1;
        let t = table(addr).filter(|t| t.len() == 512);
        if t.is_none() { *complete = false; }
        t
    };
    // tablica wskazana przez wpis: dla wpisu przejściowego próbujemy kolejnych kandydatur adresu
    let mut read_entry = |raw: u64, tables: &mut usize, complete: &mut bool| -> Option<Vec<u64>> {
        if raw & P != 0 { return read(raw & ADDR, tables, complete); }
        let before = *complete;
        for a in frame_candidates(raw) {
            *complete = before;
            if let Some(t) = read(a, tables, complete) { return Some(t); }
        }
        None
    };
    let Some(pml4) = read_entry(dtb | P, &mut tables, &mut complete) else { return (out, false) };
    for (i4, &r4) in pml4.iter().enumerate().take(256) {
        let e4 = norm(r4);
        if e4 & P == 0 { continue; }
        let Some(pdpt) = read_entry(r4, &mut tables, &mut complete) else { continue };
        for (i3, &r3) in pdpt.iter().enumerate() {
            let e3 = norm(r3);
            if e3 & P == 0 { continue; }
            let va3 = ((i4 as u64) << 39) | ((i3 as u64) << 30);
            let (w3, u3, nx3) = (e4 & e3 & W != 0, e4 & e3 & U != 0, (e4 | e3) & NX != 0);
            if r3 & P != 0 && e3 & PS != 0 { if u3 { emit(va3, 1 << 30, w3, !nx3); } continue; }
            let Some(pd) = read_entry(r3, &mut tables, &mut complete) else { continue };
            for (i2, &r2) in pd.iter().enumerate() {
                let e2 = norm(r2);
                if e2 & P == 0 { continue; }
                let va2 = va3 | ((i2 as u64) << 21);
                let (w2, u2, nx2) = (w3 && e2 & W != 0, u3 && e2 & U != 0, nx3 || e2 & NX != 0);
                if r2 & P != 0 && e2 & PS != 0 { if u2 { emit(va2, 1 << 21, w2, !nx2); } continue; }
                let Some(pt) = read_entry(r2, &mut tables, &mut complete) else { continue };
                for (i1, &e1) in pt.iter().enumerate() {
                    let va = va2 | ((i1 as u64) << 12);
                    if e1 & P != 0 {
                        if u2 && e1 & U != 0 { emit(va, 4096, w2 && e1 & W != 0, !(nx2 || e1 & NX != 0)); }
                    } else if is_transition(e1) && u2 {
                        // strona przejściowa: ochrona z kodu zapisanego we wpisie, ograniczona zakazami wyższych poziomów
                        if let Some((w, x)) = transition_protection(e1) { emit(va, 4096, w && w2, x && !nx2); }
                    }
                }
            }
        }
    }
    (out, complete && !overflow)
}

/// Położenie pól opisu regionu (VAD) w strukturach jądra danej wersji Windows; pochodzi z pliku symboli.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VadOffsets {
    /// Wskaźniki na lewe i prawe poddrzewo w węźle.
    pub left: usize, pub right: usize,
    pub start_vpn: usize, pub end_vpn: usize, pub start_high: usize, pub end_high: usize,
    /// Słowo znaczników i numery bitów: pierwszy bit rodzaju regionu (3 bity) oraz bit pamięci prywatnej.
    pub flags: usize, pub type_bit: u32, pub private_bit: u32,
}

/// Region z drzewa VAD: adres węzła w jądrze, zakres [start, end) i rodzaj.
#[derive(Clone, Debug, PartialEq)]
pub struct Vad { pub node: u64, pub start: u64, pub end: u64, pub private: bool, pub image: bool }

/// Limit węzłów drzewa VAD jednego procesu (drzewo pochodzi z pamięci gościa).
pub const MAX_VADS: usize = 1 << 18;
/// Wartość pola rodzaju regionu dla obrazu programu albo biblioteki (VadImageMap).
const VAD_IMAGE_MAP: u32 = 2;
const KERNEL_MIN: u64 = 0xffff_8000_0000_0000;

/// Przejście drzewa VAD od korzenia. `read` czyta pamięć jądra gościa pod adresem wirtualnym i zwraca false,
/// gdy się nie da. Wynik jest posortowany i bez nakładających się regionów; drugi element mówi, czy drzewo
/// przeczytano w całości (false: nieczytelny węzeł, błędny wskaźnik, przekroczony limit, nakładające się wpisy).
pub fn walk_vads(root: u64, o: &VadOffsets, mut read: impl FnMut(u64, &mut [u8]) -> bool) -> (Vec<Vad>, bool) {
    let need = [o.left, o.right, o.flags + 4, o.start_vpn + 4, o.end_vpn + 4, o.start_high + 1, o.end_high + 1].into_iter().max().unwrap_or(0).max(16);
    let mut node = vec![0u8; need.min(4096)];
    if need > node.len() { return (Vec::new(), false); }
    let mut out: Vec<Vad> = Vec::new();
    let mut complete = true;
    let mut stack = vec![root];
    let mut visited = 0usize;
    let u32at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let u64at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    while let Some(addr) = stack.pop() {
        if addr == 0 { continue; }
        // węzeł musi leżeć w pamięci jądra i być wyrównany; liczba odwiedzin jest ograniczona (pętle w drzewie)
        if addr < KERNEL_MIN || addr & 7 != 0 || visited >= MAX_VADS { complete = false; continue; }
        visited += 1;
        if !read(addr, &mut node) { complete = false; continue; }
        let (left, right) = (u64at(&node, o.left), u64at(&node, o.right));
        let start = ((node[o.start_high] as u64) << 32 | u32at(&node, o.start_vpn) as u64) << 12;
        let last = (node[o.end_high] as u64) << 32 | u32at(&node, o.end_vpn) as u64;
        let end = (last + 1) << 12;
        let flags = u32at(&node, o.flags);
        if start < end && end <= USER_MAX + 1 {
            out.push(Vad { node: addr, start, end, private: flags >> (o.private_bit & 31) & 1 == 1, image: flags >> (o.type_bit & 31) & 7 == VAD_IMAGE_MAP });
        } else { complete = false; }
        stack.push(right);
        stack.push(left);
    }
    out.sort_by_key(|v| v.start);
    // drzewo uszkodzone albo zmieniane w trakcie odczytu może dać wpisy nakładające się: zostaje pierwszy
    let before = out.len();
    let mut last_end = 0u64;
    out.retain(|v| { let keep = v.start >= last_end; if keep { last_end = v.end; } keep });
    let no_overlap = out.len() == before;
    (out, complete && no_overlap)
}

/// Regiony z zakresów stron i drzewa VAD: ochrona pochodzi z tablic stron (stan faktyczny), a rodzaj regionu
/// i nazwa pliku z VAD. Zakres stron jest dzielony na granicach regionów VAD; strony poza jakimkolwiek VAD
/// mają rodzaj nieznany. `vads` musi być posortowane i bez nakładania (jak wynik `walk_vads`).
pub fn regions_from_vads(ranges: &[PageRange], vads: &[(Vad, Option<String>)]) -> Vec<nanshe_core::Region> {
    use nanshe_core::{Prot, Region, RegionKind};
    let mut out: Vec<(Region, u64)> = Vec::new();
    let mut sorted: Vec<PageRange> = ranges.iter().copied().filter(|r| r.size > 0 && r.base <= USER_MAX).collect();
    sorted.sort_by_key(|r| r.base);
    for r in sorted {
        let end = r.base.saturating_add(r.size).min(USER_MAX + 1);
        let mut at = r.base;
        while at < end {
            // region VAD zawierający adres albo najbliższy za nim
            let i = vads.partition_point(|v| v.0.end <= at);
            let (next, owner) = match vads.get(i) {
                Some((v, name)) if v.start <= at => (v.end.min(end), Some((v, name))),
                Some((v, _)) => (v.start.min(end), None),
                None => (end, None),
            };
            let prot = Prot(Prot::R | if r.write { Prot::W } else { 0 } | if r.exec { Prot::X } else { 0 });
            let (kind, backing, label, id) = match owner {
                Some((v, _)) if v.private => (RegionKind::Private, None, None, v.node),
                Some((v, Some(name))) if v.image => (RegionKind::Image, Some(name.clone()), None, v.node),
                // Obraz, którego pliku nie da się nazwać: tak wygląda proces utworzony z pliku usuniętego albo
                // podmienionego przed uruchomieniem. Nie jest traktowany jak zwykły moduł, tylko jak mapowanie
                // bez pliku, które detektory oceniają.
                Some((v, None)) if v.image => (RegionKind::Mapped, None, Some("[image without file name]".to_string()), v.node),
                Some((v, name)) => (RegionKind::Mapped, name.clone(), name.is_none().then(|| "[section]".to_string()), v.node),
                // Strona obecna w tablicach stron, której nie opisuje żaden region VAD: tak ukrywa się pamięć przez
                // odpięcie jej opisu z drzewa. Kod w takim miejscu jest traktowany jak prywatny i oceniany.
                None if r.exec => (RegionKind::Private, None, Some("[no VAD]".to_string()), 0),
                None => (RegionKind::Unknown, None, None, 0),
            };
            match out.last_mut() {
                // Ten sam region VAD i ta sama ochrona: jeden region także wtedy, gdy między stronami jest przerwa
                // (strony nieobecne w pamięci fizycznej). Bez tego jeden region procesu rozpadał się na dziesiątki
                // znalezisk. Strony spoza VAD łączymy tylko, gdy sąsiadują.
                Some((l, lid)) if l.prot == Some(prot) && *lid == id && l.kind == kind && (id != 0 || l.base + l.size == at) => l.size = next - l.base,
                _ => out.push((Region { base: at, size: next - at, prot: Some(prot), kind, backing, backing_deleted: false, label, readable: true }, id)),
            }
            at = next;
        }
    }
    out.into_iter().map(|x| x.0).collect()
}

/// Ziarno alokacji pamięci wirtualnej Windows.
const ALLOC: u64 = 0x1_0000;

/// Zamienia zakresy stron na regiony: sąsiednie zakresy o tej samej ochronie i tym samym module są łączone,
/// zakres wewnątrz modułu staje się regionem obrazu z jego ścieżką, a zakres na granicy modułu jest dzielony.
pub fn build_regions(ranges: &[PageRange], modules: &[Module]) -> Vec<nanshe_core::Region> {
    use nanshe_core::{Prot, Region, RegionKind};
    // Windows Server 2025 mapuje za każdym obrazem jedną dodatkową stronę kodu (pomiar na kontrolerze domeny
    // LAB, 2026-11-23: strona r-x tuż za końcem każdego modułu, także gdy obraz kończy się na granicy 64 KiB).
    // Doliczamy ją do modułu, a koniec zaokrąglamy w górę do granicy alokacji (64 KiB): Windows przydziela
    // pamięć od adresów podzielnych przez 64 KiB, więc reszta tego ziarna nie może należeć do innej alokacji.
    // Znane ograniczenie: gdy obraz kończy się dokładnie na granicy 64 KiB, jedna strona za nim nie jest
    // odróżniana od osobnej alokacji.
    // Adres i rozmiar modułu pochodzą z pamięci gościa: moduł spoza przestrzeni użytkownika jest pomijany,
    // a koniec przycinany do jej granicy, zanim cokolwiek zostanie doliczone (znalezione fuzzingiem: adres
    // bliski końca zakresu liczb przepełniał zaokrąglenie).
    let grown: Vec<Module> = modules.iter().filter(|m| m.size > 0 && m.base <= USER_MAX).map(|m| {
        let end = (m.base.saturating_add(m.size).min(USER_MAX + 1).saturating_add(0xfff) / 0x1000 * 0x1000 + 0x1000).min(USER_MAX + 1);
        let end = (end.saturating_add(ALLOC - 1) / ALLOC * ALLOC).min(USER_MAX + 1).max(m.base);
        Module { base: m.base, size: end - m.base, path: m.path.clone() }
    }).filter(|m| m.size > 0).collect();
    let mut mods: Vec<&Module> = grown.iter().collect();
    mods.sort_by_key(|m| m.base);
    // punkty podziału: początki i końce modułów
    let mut cuts: Vec<u64> = mods.iter().flat_map(|m| [m.base, m.base.saturating_add(m.size)]).collect();
    cuts.sort_unstable(); cuts.dedup();
    let module_at = |a: u64| mods.iter().rev().find(|m| a >= m.base && a < m.base.saturating_add(m.size)).copied();
    let mut out: Vec<Region> = Vec::new();
    let mut sorted: Vec<PageRange> = ranges.iter().copied().filter(|r| r.size > 0 && r.base <= USER_MAX).collect();
    sorted.sort_by_key(|r| r.base);
    for r in sorted {
        let end = r.base.saturating_add(r.size).min(USER_MAX + 1);
        let mut at = r.base;
        while at < end {
            let next = cuts.iter().copied().find(|&c| c > at && c < end).unwrap_or(end);
            let m = module_at(at);
            let prot = Prot(Prot::R | if r.write { Prot::W } else { 0 } | if r.exec { Prot::X } else { 0 });
            // bez listy modułów nie wiadomo, co jest obrazem z pliku: rodzaj regionu zostaje nieznany
            let (kind, backing) = match m { Some(m) => (RegionKind::Image, Some(m.path.clone())), None if mods.is_empty() => (RegionKind::Unknown, None),
                // region wykonywalny poza modułami traktujemy jak prywatny; niewykonywalny może być plikiem
                // zmapowanym jako dane, czego lista modułów nie mówi, więc jego rodzaj zostaje nieznany
                None if r.exec => (RegionKind::Private, None), None => (RegionKind::Unknown, None) };
            match out.last_mut() {
                Some(l) if l.base + l.size == at && l.prot == Some(prot) && l.backing == backing => l.size += next - at,
                _ => out.push(Region { base: at, size: next - at, prot: Some(prot), kind, backing, backing_deleted: false, label: None, readable: true }),
            }
            at = next;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pr(base: u64, size: u64, write: bool, exec: bool) -> PageRange { PageRange { base, size, write, exec } }

    #[test]
    fn page_ranges_become_regions_split_at_module_borders() {
        let mods = [Module { base: 0x7ff0_0000, size: 0x3000, path: "C:\\Windows\\System32\\a.dll".into() }];
        let regs = build_regions(&[
            pr(0x1_0000, 0x1000, true, false), pr(0x1_1000, 0x1000, true, false),   // sąsiednie, ta sama ochrona: jeden region
            pr(0x1_2000, 0x1000, true, true),                                         // inna ochrona: osobny
            pr(0x7fef_f000, 0x5000, false, true),                                     // zaczyna się przed modułem, kończy stronę za nim
            pr(0xffff_8000_0000_0000, 0x1000, false, true),                           // jądro: pomijane
        ], &mods);
        let name = |p: nanshe_core::Prot| format!("{}{}{}", if p.r() { "r" } else { "-" }, if p.w() { "w" } else { "-" }, if p.x() { "x" } else { "-" });
        let s: Vec<(u64, u64, String, Option<&str>)> = regs.iter().map(|r| (r.base, r.size, name(r.prot.unwrap()), r.backing.as_deref())).collect();
        assert_eq!(s, vec![
            (0x1_0000, 0x2000, "rw-".to_string(), None),
            (0x1_2000, 0x1000, "rwx".to_string(), None),
            (0x7fef_f000, 0x1000, "r-x".to_string(), None),
            (0x7ff0_0000, 0x4000, "r-x".to_string(), Some("C:\\Windows\\System32\\a.dll")),
        ]);
        // strona tuż za obrazem należy do niego (ta sama alokacja), ale tylko do granicy 64 KiB
        let far = build_regions(&[pr(0x7ff0_f000, 0x2000, false, true)], &mods);
        assert_eq!(far.iter().map(|r| (r.base, r.size, r.backing.is_some())).collect::<Vec<_>>(), vec![(0x7ff0_f000, 0x1000, true), (0x7ff1_0000, 0x1000, false)]);
        // obraz kończący się dokładnie na granicy 64 KiB: doliczana jest jedna strona, czyli następne ziarno
        let exact = [Module { base: 0x7ff0_0000, size: 0x1_0000, path: "b.dll".into() }];
        let e = build_regions(&[pr(0x7ff1_0000, 0x1000, false, true), pr(0x7ff2_0000, 0x1000, false, true)], &exact);
        assert_eq!(e.iter().map(|r| (r.base, r.backing.is_some())).collect::<Vec<_>>(), vec![(0x7ff1_0000, true), (0x7ff2_0000, false)]);
        // moduły z adresem albo rozmiarem na granicy zakresu liczb (dane gościa): bez przepełnienia, moduł spoza
        // przestrzeni użytkownika pomijany, a sięgający poza nią przycięty
        let hostile = [Module { base: u64::MAX - 0x10, size: u64::MAX, path: "a".into() }, Module { base: 0xc4c4_c4c4_c4c4_c4c4, size: 0xc4c4_c4c4_c4c4_c4c4, path: "b".into() },
            Module { base: USER_MAX - 0xfff, size: u64::MAX, path: "c".into() }, Module { base: 0x1000, size: u64::MAX, path: "d".into() }];
        let h = build_regions(&[pr(0x2000, 0x1000, false, true), pr(USER_MAX - 0xfff, 0x1000, false, true)], &hostile);
        assert_eq!(h.iter().map(|r| (r.base, r.size, r.backing.as_deref())).collect::<Vec<_>>(), vec![(0x2000, 0x1000, Some("d")), (USER_MAX - 0xfff, 0x1000, Some("c"))]);
        // bez listy modułów rodzaj regionu jest nieznany, a nie "prywatny"
        assert_eq!(build_regions(&[pr(0x1000, 0x1000, false, true)], &[])[0].kind, nanshe_core::RegionKind::Unknown);
        assert_eq!(regs[3].kind, nanshe_core::RegionKind::Image);
        assert_eq!(regs[2].kind, nanshe_core::RegionKind::Private);
    }

    /// Pamięć fizyczna z tablicami stron do testów: adres tablicy -> wpisy.
    fn tables(entries: &[(u64, usize, u64)]) -> impl FnMut(u64) -> Option<Vec<u64>> {
        let mut m: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
        for &(table, index, value) in entries { m.entry(table).or_insert_with(|| vec![0; 512])[index] = value; }
        move |a| m.get(&a).cloned()
    }

    #[test]
    fn page_walk_combines_permissions_like_the_processor() {
        const P: u64 = 1; const W: u64 = 2; const U: u64 = 4; const PS: u64 = 0x80; const NX: u64 = 1 << 63;
        let up = P | W | U; // wyższe poziomy: wszystko dozwolone, jak w Windows
        let (r, complete) = walk_page_tables(0x1000, tables(&[
            (0x1000, 0, 0x2000 | up), (0x2000, 0, 0x3000 | up), (0x3000, 1, 0x4000 | up),
            // strony 4 KiB pod adresem 0x200000: kod (r-x), dwie strony danych (rw-), rwx, strona jądra, nieobecna
            (0x4000, 0, 0x10_0000 | P | U),
            (0x4000, 1, 0x10_1000 | P | U | W | NX), (0x4000, 2, 0x10_2000 | P | U | W | NX),
            (0x4000, 3, 0x10_3000 | P | U | W),
            (0x4000, 4, 0x10_4000 | P | W),
            (0x4000, 5, 0x10_5000 | U | W),
            // duża strona 2 MiB tylko do odczytu, bez wykonywania
            (0x3000, 2, 0x4000_0000 | P | U | PS | NX),
            // górna połowa przestrzeni adresowej (jądro): pomijana
            (0x1000, 300, 0x2000 | up),
        ]));
        assert!(complete);
        assert_eq!(r, vec![
            pr(0x20_0000, 0x1000, false, true),
            pr(0x20_1000, 0x2000, true, false),
            pr(0x20_3000, 0x1000, true, true),
            pr(0x40_0000, 0x20_0000, false, false),
        ]);
        // zakaz zapisu albo wykonania na wyższym poziomie obowiązuje wszystkie strony pod nim
        let (r, _) = walk_page_tables(0x1000, tables(&[
            (0x1000, 0, 0x2000 | up), (0x2000, 0, 0x3000 | P | U | NX), (0x3000, 0, 0x4000 | P | U),
            (0x4000, 0, 0x10_0000 | P | U | W),
        ]));
        assert_eq!(r, vec![pr(0, 0x1000, false, false)]);
    }

    #[test]
    fn transition_pages_are_part_of_the_map_and_can_be_located() {
        const UP: u64 = 7; const T: u64 = 1 << 11;
        // strony pod 0x200000: ważna r-x, przejściowa r-x (kod 3), przejściowa rw- (kod 4), przejściowa bez dostępu,
        // wpis prototypowy (bit 10) i wpis pliku wymiany: dwa ostatnie nie są w pamięci fizycznej
        let mem = [(0x1000u64, 0usize, 0x2000 | UP), (0x2000, 0, 0x3000 | UP), (0x3000, 1, 0x4000 | UP),
            (0x4000, 0, 0x10_0000 | 5), (0x4000, 1, 0x10_1000 | T | 3 << 5), (0x4000, 2, 0x10_2000 | T | 4 << 5), (0x4000, 3, 0x10_3000 | T),
            (0x4000, 4, 0x10_4000 | T | 1 << 10 | 3 << 5), (0x4000, 5, 0x10_5000 | 3 << 5),
            // tablica stron sama w stanie przejściowym, z wysokim bitem ustawionym jak przy ochronie L1TF
            (0x3000, 2, 0x5000 | T | 1 << 45), (0x5000, 0, 0x20_0000 | T | 6 << 5)];
        let (r, complete) = walk_page_tables(0x1000, tables(&mem));
        assert!(complete);
        assert_eq!(r, vec![pr(0x20_0000, 0x2000, false, true), pr(0x20_2000, 0x1000, true, false), pr(0x40_0000, 0x1000, true, true)]);
        assert_eq!(leaf_entry(0x1000, 0x20_1234, tables(&mem)), Some((0x10_1000 | T | 3 << 5, 4096)));
        assert_eq!(leaf_entry(0x1000, 0x40_0000, tables(&mem)), Some((0x20_0000 | T | 6 << 5, 4096)));
        assert_eq!(leaf_entry(0x1000, 0x20_4000, tables(&mem)), None, "wpis prototypowy");
        assert_eq!(leaf_entry(0x1000, 0x7000_0000, tables(&mem)), None, "adres niezmapowany");
        assert_eq!(frame_candidates(0x10_0000 | 5), vec![0x10_0000]);
        assert!(frame_candidates(0x5000 | T | 1 << 45).contains(&0x5000));
        assert_eq!((transition_protection(0), transition_protection(5 << 5), transition_protection(7 << 5)), (None, Some((false, false)), Some((false, true))));
    }

    #[test]
    fn page_walk_survives_unreadable_and_looping_tables() {
        const UP: u64 = 7;
        // brak tablicy głównej
        assert_eq!(walk_page_tables(0x1000, |_| None), (vec![], false));
        // nieczytelna tablica niższego poziomu: reszta jest czytana, wynik oznaczony jako niepełny
        let (r, complete) = walk_page_tables(0x1000, tables(&[
            (0x1000, 0, 0x2000 | UP), (0x2000, 0, 0x3000 | UP), (0x3000, 0, 0x9000 | UP), (0x3000, 1, 0x4000 | UP), (0x4000, 0, 0x10_0000 | 5),
        ]));
        assert_eq!((r, complete), (vec![pr(0x20_0000, 0x1000, false, true)], false));
        // tablica wskazująca na samą siebie na każdym poziomie: limit kończy przejście
        let mut reads = 0usize;
        let (_, complete) = walk_page_tables(0x1000, |_| { reads += 1; Some(vec![0x1000 | UP; 512]) });
        assert!(!complete && reads <= MAX_TABLES, "{reads}");
        // tablice z ochroną zmieniającą się co stronę: liczba zakresów jest ograniczona, wynik oznaczony jako niepełny
        let (r, complete) = walk_page_tables(0x1000, |a| Some(match a {
            0x1000 => vec![0x2000 | UP; 512], 0x2000 => vec![0x3000 | UP; 512], 0x3000 => vec![0x4000 | UP; 512],
            _ => (0..512u64).map(|i| 0x10_0000 | 5 | ((i & 1) << 1)).collect(),
        }));
        assert!(r.len() == MAX_RANGES && !complete, "{} {complete}", r.len());
        // tablica o złej długości jest odrzucana
        assert_eq!(walk_page_tables(0x1000, |_| Some(vec![0x1000 | UP; 4])), (vec![], false));
    }

    const VO: VadOffsets = VadOffsets { left: 0, right: 8, start_vpn: 0x18, end_vpn: 0x1c, start_high: 0x20, end_high: 0x21, flags: 0x30, type_bit: 4, private_bit: 20 };
    /// Pamięć jądra z węzłami VAD do testów: (adres węzła, lewy, prawy, pierwsza strona, ostatnia strona, rodzaj, prywatny).
    fn vad_mem(nodes: &[(u64, u64, u64, u64, u64, u32, bool)]) -> impl FnMut(u64, &mut [u8]) -> bool {
        let m: std::collections::HashMap<u64, Vec<u8>> = nodes.iter().map(|&(a, l, r, s, e, t, p)| {
            let mut b = vec![0u8; 0x40];
            b[0..8].copy_from_slice(&l.to_le_bytes()); b[8..16].copy_from_slice(&r.to_le_bytes());
            b[0x18..0x1c].copy_from_slice(&(s as u32).to_le_bytes()); b[0x1c..0x20].copy_from_slice(&(e as u32).to_le_bytes());
            b[0x20] = (s >> 32) as u8; b[0x21] = (e >> 32) as u8;
            b[0x30..0x34].copy_from_slice(&((t << 4) | (p as u32) << 20).to_le_bytes());
            (a, b)
        }).collect();
        move |a, buf| match m.get(&a) { Some(b) => { buf.copy_from_slice(&b[..buf.len()]); true } None => false }
    }
    const K: u64 = 0xffff_9000_0000_0000;

    #[test]
    fn vad_tree_gives_sorted_regions_with_their_kind() {
        let (v, complete) = walk_vads(K, &VO, vad_mem(&[
            (K, K + 0x100, K + 0x200, 0x7ff0_0000, 0x7ff0_000f, 2, false),    // obraz
            (K + 0x100, 0, 0, 0x10, 0x1f, 0, true),                            // pamięć prywatna
            (K + 0x200, 0, 0, 0x7_fff0_0000, 0x7_fff0_0000, 0, false),         // mapowanie powyżej 4 GiB stron
        ]));
        assert!(complete);
        assert_eq!(v.iter().map(|x| (x.start, x.end, x.private, x.image)).collect::<Vec<_>>(), vec![
            (0x10_000, 0x20_000, true, false), (0x7ff0_0000_000, 0x7ff0_0010_000, false, true), (0x7fff_0000_0000, 0x7fff_0000_1000, false, false)]);
    }

    #[test]
    fn vad_walk_survives_hostile_trees() {
        // pusty korzeń, korzeń spoza pamięci jądra, niewyrównany, nieczytelny
        assert_eq!(walk_vads(0, &VO, |_, _| true), (vec![], true));
        for bad in [0x1000u64, K + 3] { assert_eq!(walk_vads(bad, &VO, |_, _| true), (vec![], false)); }
        assert_eq!(walk_vads(K, &VO, |_, _| false), (vec![], false));
        // węzeł wskazujący na siebie: limit odwiedzin, jeden region, wynik niepełny
        let (v, complete) = walk_vads(K, &VO, vad_mem(&[(K, K, K, 0x10, 0x1f, 0, true)]));
        assert!(v.len() == 1 && !complete);
        // zakres odwrócony, poza przestrzenią użytkownika i nakładające się regiony
        let (v, complete) = walk_vads(K, &VO, vad_mem(&[
            (K, K + 0x100, K + 0x200, 0x20, 0x2f, 0, true), (K + 0x100, K + 0x300, 0, 0x50, 0x40, 0, true),
            (K + 0x200, 0, 0, 0x28, 0x3f, 0, true), (K + 0x300, 0, 0, 0xf_ffff_ffff, 0xff_ffff_ffff, 0, true)]));
        assert_eq!((v.iter().map(|x| x.start).collect::<Vec<_>>(), complete), (vec![0x20_000], false));
        // położenia pól poza rozsądnym rozmiarem węzła
        assert_eq!(walk_vads(K, &VadOffsets { flags: 1 << 20, ..VO }, |_, _| true), (vec![], false));
    }

    #[test]
    fn regions_take_protection_from_pages_and_kind_from_vads() {
        let v = |start: u64, end: u64, private: bool, image: bool, name: Option<&str>| (Vad { node: K + start, start, end, private, image }, name.map(String::from));
        let vads = [v(0x10_000, 0x20_000, true, false, None), v(0x7ff0_0000, 0x7ff0_8000, false, true, Some("\\Windows\\System32\\a.dll")),
            v(0x7ff0_8000, 0x7ff0_a000, false, false, None), v(0x7ff1_0000, 0x7ff1_1000, false, true, None)];
        let regs = regions_from_vads(&[
            pr(0x10_000, 0x2000, true, false), pr(0x12_000, 0x1000, true, true),   // dwie ochrony w jednym regionie prywatnym
            pr(0x7ff0_0000, 0xa000, false, true),                                   // obraz i zaraz za nim sekcja bez pliku
            pr(0x7ff1_0000, 0x2000, false, true),                                   // obraz bez nazwy i strona poza jakimkolwiek VAD
        ], &vads);
        let s: Vec<(u64, u64, RegionKindT, Option<&str>, Option<&str>)> = regs.iter().map(|r| (r.base, r.size, kind(r), r.backing.as_deref(), r.label.as_deref())).collect();
        assert_eq!(s, vec![
            (0x10_000, 0x2000, "private", None, None), (0x12_000, 0x1000, "private", None, None),
            (0x7ff0_0000, 0x8000, "image", Some("\\Windows\\System32\\a.dll"), None), (0x7ff0_8000, 0x2000, "mapped", None, Some("[section]")),
            (0x7ff1_0000, 0x1000, "mapped", None, Some("[image without file name]")), (0x7ff1_1000, 0x1000, "private", None, Some("[no VAD]"))]);
        assert!(regs[1].is_x() && regs[1].is_w() && !regs[0].is_x());
        // strony tego samego regionu VAD z przerwą (część poza pamięcią fizyczną): jeden region obejmujący przerwę;
        // inna ochrona w środku dzieli region, a strony spoza VAD z przerwą pozostają osobne
        let gap = regions_from_vads(&[pr(0x10_000, 0x1000, false, true), pr(0x14_000, 0x2000, false, true), pr(0x18_000, 0x1000, true, false), pr(0x1a_000, 0x1000, false, true),
            pr(0x30_000, 0x1000, false, true), pr(0x32_000, 0x1000, false, true)], &vads);
        assert_eq!(gap.iter().map(|r| (r.base, r.size)).collect::<Vec<_>>(), vec![(0x10_000, 0x6000), (0x18_000, 0x1000), (0x1a_000, 0x1000), (0x30_000, 0x1000), (0x32_000, 0x1000)]);
        // strona wykonywalna poza jakimkolwiek VAD jest oceniana jak pamięć prywatna; niewykonywalna ma rodzaj nieznany
        let hidden = regions_from_vads(&[pr(0x30_000, 0x1000, false, true), pr(0x40_000, 0x1000, true, false)], &vads);
        assert_eq!(hidden.iter().map(|r| (kind(r), r.label.as_deref())).collect::<Vec<_>>(), vec![("private", Some("[no VAD]")), ("unknown", None)]);
        assert!(regions_from_vads(&[], &vads).is_empty() && regions_from_vads(&[pr(0x1000, 0x1000, false, false)], &[])[0].kind == nanshe_core::RegionKind::Unknown);
    }
    type RegionKindT = &'static str;
    fn kind(r: &nanshe_core::Region) -> RegionKindT {
        match r.kind { nanshe_core::RegionKind::Private => "private", nanshe_core::RegionKind::Image => "image", nanshe_core::RegionKind::Mapped => "mapped", nanshe_core::RegionKind::Unknown => "unknown", _ => "other" }
    }

    #[test]
    fn empty_and_degenerate_input_gives_no_regions() {
        assert!(build_regions(&[], &[]).is_empty());
        assert!(build_regions(&[pr(0x1000, 0, true, true)], &[Module { base: 0, size: 0, path: String::new() }]).is_empty());
        // zakres sięgający poza przestrzeń użytkownika jest przycinany
        let r = build_regions(&[pr(USER_MAX - 0xfff, 0x10_0000, false, false)], &[]);
        assert_eq!((r[0].base, r[0].size), (USER_MAX - 0xfff, 0x1000));
    }
}
