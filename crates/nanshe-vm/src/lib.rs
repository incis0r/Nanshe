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

/// Co tablice stron mówią o jednym adresie wirtualnym.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Leaf {
    /// Strona leży w pamięci fizycznej: wpis (ważny albo przejściowy) i rozmiar strony.
    Page(u64, u64),
    /// Wpis strony istnieje, ale nie wskazuje pamięci fizycznej (surowa wartość; zero = nigdy nieużyta w tym procesie).
    Soft(u64),
    /// Brak tablicy stron dla tego adresu.
    Missing,
}

/// Stan adresu wirtualnego w tablicach stron. Obsługuje wpisy ważne i przejściowe na każdym poziomie.
pub fn leaf<T: AsRef<[u64]>>(dtb: u64, va: u64, mut table: impl FnMut(u64) -> Option<T>) -> Leaf {
    let mut read = |entry: u64| frame_candidates(entry).into_iter().find_map(|a| table(a).filter(|t| t.as_ref().len() == 512));
    let usable = |e: u64| e & 1 != 0 || is_transition(e);
    let Some(mut t) = read(dtb | 1) else { return Leaf::Missing };
    for (shift, large) in [(39u32, 0u64), (30, 1 << 30), (21, 1 << 21)] {
        let e = t.as_ref()[((va >> shift) & 511) as usize];
        if !usable(e) { return Leaf::Missing; }
        if large != 0 && e & 1 != 0 && e & 0x80 != 0 { return Leaf::Page(e, large); }
        match read(e) { Some(n) => t = n, None => return Leaf::Missing }
    }
    let e = t.as_ref()[((va >> 12) & 511) as usize];
    if usable(e) { Leaf::Page(e, 4096) } else { Leaf::Soft(e) }
}

/// Wpis końcowy (strony) dla adresu wirtualnego i rozmiar strony; None, gdy adres nie jest zmapowany w pamięci
/// fizycznej.
pub fn leaf_entry<T: AsRef<[u64]>>(dtb: u64, va: u64, table: impl FnMut(u64) -> Option<T>) -> Option<(u64, u64)> {
    match leaf(dtb, va, table) { Leaf::Page(e, size) => Some((e, size)), _ => None }
}

/// Czy zakres [addr, addr + len) mieści się w pamięci fizycznej gościa o najwyższym adresie `max`.
/// Wpisy stron nieważnych dla procesora niosą w adresie dodatkowe wysokie bity (zob. `frame_candidates`),
/// a biblioteka czytająca pamięć QEMU dla adresu poza pamięcią gościa potrafi zwrócić sukces i same zera:
/// bez tej kontroli błędna kandydatura "czytała się" jako pusta strona.
pub fn within_physical(addr: u64, len: usize, max: u64) -> bool {
    len > 0 && matches!(addr.checked_add(len as u64 - 1), Some(last) if last <= max)
}

/// Region współdzielony (plik albo sekcja) i jego prototypowe wpisy stron w jądrze: pierwszy i ostatni
/// z ciągłej tablicy (pola FirstPrototypePte i LastContiguousPte opisu regionu).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProtoVad { pub start: u64, pub end: u64, pub first: u64, pub last: u64 }

/// Wartość pola adresu we wpisie strony, która każe szukać wpisu prototypowego przez opis regionu (VAD).
const PROTO_VIA_VAD: u64 = 0xffff_ffff_0000;

/// Adres prototypowego wpisu strony dla adresu wirtualnego, którego proces nie ma w swoich tablicach stron.
/// Strona pliku albo sekcji współdzielonej, której proces jeszcze nie dotknął (albo którą oddał), może nadal
/// leżeć w pamięci fizycznej: wskazuje ją wpis prototypowy w jądrze. Jego adres jest we wpisie strony procesu
/// (bit 10, adres w bitach 16-63) albo wynika z opisu regionu, gdy wpis jest pusty lub odsyła do opisu regionu.
/// `raw`: surowy wpis strony albo None, gdy brak tablicy stron. `vads` posortowane po adresie.
pub fn proto_pte_addr(raw: Option<u64>, va: u64, vads: &[ProtoVad]) -> Option<u64> {
    let via_vad = match raw {
        None | Some(0) => true,
        // wpis ważny albo przejściowy nie potrzebuje prototypu; bez bitu 10 to plik wymiany albo strona zerowa
        Some(e) if e & 1 != 0 || e & (1 << 10) == 0 => return None,
        Some(e) if e >> 16 == PROTO_VIA_VAD => true,
        Some(e) => return Some(((e as i64) >> 16) as u64).filter(|a| *a >= KERNEL_MIN && a & 7 == 0),
    };
    if !via_vad { return None; }
    let i = vads.partition_point(|v| v.end <= va);
    let v = vads.get(i).filter(|v| v.start <= va)?;
    let addr = v.first.checked_add(((va - v.start) >> 12).checked_mul(8)?)?;
    (v.first >= KERNEL_MIN && v.first & 7 == 0 && addr <= v.last).then_some(addr)
}

/// Adresy fizyczne strony wskazanej przez wpis prototypowy; pusto, gdy strona nie leży w pamięci (wpis
/// odsyła do pliku albo jest pusty).
pub fn proto_frames(proto: u64) -> Vec<u64> {
    if proto & 1 != 0 || is_transition(proto) { frame_candidates(proto) } else { Vec::new() }
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

/// Położenie pól potrzebnych do odczytania rejestrów wątków z jądra; pochodzi z pliku symboli.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThreadOffsets {
    /// Głowa listy wątków w opisie procesu (_EPROCESS.ThreadListHead) i ogniwo tej listy w opisie wątku (_ETHREAD.ThreadListEntry).
    pub list_head: usize, pub list_entry: usize,
    /// Identyfikatory procesu i wątku (_ETHREAD.Cid), stan wątku i wskaźnik ramki pułapki (_KTHREAD.State, _KTHREAD.TrapFrame).
    pub cid: usize, pub state: usize, pub trap_frame: usize,
    /// Rejestry trybu użytkownika w ramce pułapki (_KTRAP_FRAME.Rip, Rsp, Rbp).
    pub rip: usize, pub rsp: usize, pub rbp: usize,
}

/// Limit wątków jednego procesu (lista pochodzi z pamięci gościa).
pub const MAX_THREADS: usize = 1 << 16;
/// Wartość pola stanu wątku, który czeka (KTHREAD_STATE: Waiting).
const THREAD_WAITING: u8 = 5;

/// Rejestry trybu użytkownika wątków, które czekają w jądrze. Wejście do jądra zapisuje je w ramce pułapki
/// na stosie jądrowym wątku; dopóki wątek czeka, ramka się nie zmienia. Wywołanie systemowe zapisuje tam
/// na pewno adres powrotu, wskaźnik stosu i rbp; pozostałe rejestry nieulotne trafiają na stos jądra
/// w innych miejscach, więc są zgłaszane jako nieznane. Wątek działający albo gotowy ma w polu ramki
/// wartość z poprzedniego wejścia do jądra, dlatego liczy się tylko stan "czeka".
/// `read` czyta pamięć jądra gościa i zwraca false, gdy się nie da (np. stos jądrowy wyrzucony z pamięci).
pub fn walk_threads(eprocess: u64, o: &ThreadOffsets, mut read: impl FnMut(u64, &mut [u8]) -> bool) -> (Vec<nanshe_core::ThreadRegs>, ThreadCounts) {
    let mut u64at = |a: u64| -> Option<u64> { let mut b = [0u8; 8]; read(a, &mut b).then(|| u64::from_le_bytes(b)) };
    let kernel = |a: u64| a >= KERNEL_MIN && a & 7 == 0;
    let (mut out, mut n) = (Vec::new(), ThreadCounts::default());
    let Some(head) = eprocess.checked_add(o.list_head as u64).filter(|a| kernel(*a)) else { return (out, n) };
    let mut seen = std::collections::HashSet::new();
    let mut link = u64at(head);
    while let Some(entry) = link {
        // lista jest cykliczna: koniec to powrót do głowy; ogniwo spoza pamięci jądra albo powtórzone przerywa przejście
        if entry == head || !kernel(entry) || seen.len() >= MAX_THREADS || !seen.insert(entry) { break; }
        link = u64at(entry);
        n.total += 1;
        let Some(thread) = entry.checked_sub(o.list_entry as u64).filter(|a| kernel(*a)) else { n.unreadable += 1; continue };
        let Some(state) = u64at(thread + o.state as u64).map(|v| v as u8) else { n.unreadable += 1; continue };
        if state != THREAD_WAITING { n.not_waiting += 1; continue; }
        let Some(tid) = u64at(thread + o.cid as u64 + 8).and_then(|v| u32::try_from(v).ok()).filter(|t| *t != 0) else { n.unreadable += 1; continue };
        let Some(frame) = u64at(thread + o.trap_frame as u64) else { n.unreadable += 1; continue };
        if !kernel(frame) { n.no_frame += 1; continue; }
        let (Some(rip), Some(rsp), Some(rbp)) = (u64at(frame + o.rip as u64), u64at(frame + o.rsp as u64), u64at(frame + o.rbp as u64)) else { n.frame_unreadable += 1; continue };
        // ramka wejścia z trybu użytkownika: adres instrukcji i stos w przestrzeni użytkownika
        if rip == 0 || rip > USER_MAX || rsp == 0 || rsp > USER_MAX { n.not_user += 1; continue; }
        let mut gpr = [0u64; 16];
        gpr[4] = rsp; gpr[5] = rbp;
        out.push(nanshe_core::ThreadRegs { tid, rip, gpr, known: 1 << 4 | 1 << 5 });
    }
    out.sort_by_key(|t| t.tid);
    (out, n)
}

/// Ile wątków procesu było na liście jądra i dlaczego części z nich nie dało się użyć.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ThreadCounts {
    pub total: u32,
    /// Wątek działa albo jest gotowy do działania: jego ramka pułapki jest nieaktualna.
    pub not_waiting: u32,
    /// Opis wątku nieczytelny.
    pub unreadable: u32,
    /// Wątek bez ramki pułapki (wątek jądra albo wątek, który jeszcze nie wszedł do jądra z trybu użytkownika).
    pub no_frame: u32,
    /// Ramka pułapki poza pamięcią fizyczną (stos jądrowy wątku czekającego długo bywa z niej usuwany).
    pub frame_unreadable: u32,
    /// Ramka nie pochodzi z trybu użytkownika.
    pub not_user: u32,
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

/// Dowód, że proces gościa ma środowisko tworzące kod w locie, z danych jądra (nie z listy modułów procesu).
/// `images`: ścieżki obrazów z drzewa VAD (bez litery dysku) z adresem obiektu urządzenia, na którym leży plik;
/// `exe`: obraz programu głównego. Warunki, wszystkie naraz:
/// - wolumin systemowy to ten, z którego zmapowana jest `ntdll.dll` (tej biblioteki proces nie wybiera);
/// - program główny leży na tym woluminie w katalogu systemowym (reguła wspólna ze skanem na żywo);
/// - biblioteka środowiska (`clr.dll`, `coreclr.dll`, `msedge.dll`) leży na tym woluminie w swoim katalogu instalacyjnym.
/// Plik o takiej samej ścieżce na innym dysku nie spełnia warunku. Właściciela pliku skaner z hosta nie sprawdza.
pub fn jit_evidence_windows(images: &[(String, u64)], exe: Option<&(String, u64)>) -> Option<String> {
    let lower: Vec<(String, u64)> = images.iter().map(|(p, d)| (p.to_ascii_lowercase(), *d)).collect();
    let mut ntdll = lower.iter().filter(|(p, _)| p == "\\windows\\system32\\ntdll.dll").map(|x| x.1);
    let system = ntdll.next().filter(|d| *d != 0)?;
    if ntdll.any(|d| d != system) { return None; }
    let (exe_path, exe_dev) = exe?;
    let roots = ["c:\\windows".to_string(), "c:\\program files".to_string(), "c:\\program files (x86)".to_string()];
    if *exe_dev != system || !exe_path.starts_with('\\') || !nanshe_live::wintables::exe_in_system_dir(&format!("c:{exe_path}"), &roots) { return None; }
    lower.iter().filter(|(_, d)| *d == system).find_map(|(p, _)| {
        if p.contains("\\..\\") { return None; }
        let under = |dirs: &[&str]| dirs.iter().any(|d| p.starts_with(d));
        match p.rsplit('\\').next()? {
            "clr.dll" if under(&["\\windows\\microsoft.net\\framework\\", "\\windows\\microsoft.net\\framework64\\"]) => Some("jit:dotnet".to_string()),
            "coreclr.dll" if under(&["\\program files\\dotnet\\shared\\", "\\program files (x86)\\dotnet\\shared\\", "\\program files\\windowsapps\\"]) => Some("jit:dotnet".to_string()),
            "msedge.dll" if under(&["\\program files\\microsoft\\edgewebview\\application\\", "\\program files (x86)\\microsoft\\edgewebview\\application\\",
                "\\program files\\microsoft\\edge\\application\\", "\\program files (x86)\\microsoft\\edge\\application\\"]) => Some("jit:webview2".to_string()),
            _ => None,
        }
    })
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

    const TO: ThreadOffsets = ThreadOffsets { list_head: 0x5e0, list_entry: 0x4e8, cid: 0x478, state: 0x184, trap_frame: 0x90, rip: 0x168, rsp: 0x180, rbp: 0x158 };
    /// Pamięć jądra z procesem i wątkami: (numer, stan, rip, rsp, rbp); wątek i ma opis pod K + 0x10000 * (i + 1).
    fn thread_mem(threads: &[(u32, u8, u64, u64, u64)]) -> std::collections::HashMap<u64, u64> {
        let mut m = std::collections::HashMap::new();
        let head = K + TO.list_head as u64;
        let entry = |i: usize| K + 0x10000 * (i as u64 + 1) + TO.list_entry as u64;
        m.insert(head, if threads.is_empty() { head } else { entry(0) });
        for (i, &(tid, state, rip, rsp, rbp)) in threads.iter().enumerate() {
            let (t, frame) = (K + 0x10000 * (i as u64 + 1), K + 0x10000 * (i as u64 + 1) + 0x8000);
            m.insert(entry(i), if i + 1 < threads.len() { entry(i + 1) } else { head });
            m.insert(t + TO.state as u64, state as u64 | 0xaa00); // sąsiednie bajty pola stanu nie mają znaczenia
            m.insert(t + TO.cid as u64 + 8, tid as u64);
            m.insert(t + TO.trap_frame as u64, frame);
            m.insert(frame + TO.rip as u64, rip); m.insert(frame + TO.rsp as u64, rsp); m.insert(frame + TO.rbp as u64, rbp);
        }
        m
    }
    fn kread(m: &std::collections::HashMap<u64, u64>) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
        move |a, b| match m.get(&a) { Some(v) => { b.copy_from_slice(&v.to_le_bytes()[..b.len()]); true } None => false }
    }

    #[test]
    fn prototype_entry_is_found_in_the_page_entry_or_through_the_region() {
        let vads = [ProtoVad { start: 0x7ff0_0000_0000, end: 0x7ff0_0001_0000, first: K + 0x1000, last: K + 0x1000 + 15 * 8 },
            ProtoVad { start: 0x7ff0_0002_0000, end: 0x7ff0_0003_0000, first: K + 0x2000, last: K + 0x2000 + 3 * 8 }];
        let va = 0x7ff0_0000_3123u64;
        // adres wprost we wpisie strony (bit 10, adres w bitach 16-63 z rozszerzeniem znaku)
        let direct = ((K + 0x5008) << 16) | 1 << 10;
        assert_eq!(proto_pte_addr(Some(direct), va, &vads), Some(K + 0x5008));
        // wpis pusty, brak tablicy stron i wpis odsyłający do opisu regionu: adres z regionu, czwarta strona
        for raw in [Some(0), None, Some(PROTO_VIA_VAD << 16 | 1 << 10)] { assert_eq!(proto_pte_addr(raw, va, &vads), Some(K + 0x1000 + 3 * 8), "{raw:x?}"); }
        // kontrole: wpis ważny, przejściowy, plik wymiany (bez bitu 10), adres spoza jądra albo niewyrównany
        // (wpis pliku wymiany może mieć w starszych bitach wartość wyglądającą jak adres jądra: bez bitu 10 to nie prototyp)
        for raw in [0x1234_5067u64, 0x1234_5000 | 1 << 11, 0x1234_0000_0080, ((K + 0x5008) << 16) | 0x80, (0x7000_0000u64 << 16) | 1 << 10, ((K + 0x5003) << 16) | 1 << 10] {
            assert_eq!(proto_pte_addr(Some(raw), va, &vads), None, "{raw:x}");
        }
        // adres poza regionami, w luce między nimi i strona za końcem ciągłej tablicy wpisów
        for a in [0x1000u64, 0x7ff0_0001_8000, 0x7ff0_0002_4000] { assert_eq!(proto_pte_addr(Some(0), a, &vads), None, "{a:x}"); }
        assert_eq!(proto_pte_addr(Some(0), 0x7ff0_0002_3000, &vads), Some(K + 0x2000 + 3 * 8));
        // region z tablicą wpisów spoza pamięci jądra nie jest używany
        assert_eq!(proto_pte_addr(Some(0), 0x5000, &[ProtoVad { start: 0, end: 0x10000, first: 0x4000, last: u64::MAX }]), None);
        // wpis prototypowy: ważny i przejściowy dają adres strony, odsyłający do pliku i pusty nie
        assert_eq!(proto_frames(0x8000_0000_1234_5025)[0], 0x1234_5000);
        assert_eq!(proto_frames(0x1234_5000 | 1 << 11)[0], 0x1234_5000);
        assert!(proto_frames(0xffff_9000_0000_0000 | 1 << 10).is_empty() && proto_frames(0).is_empty());
    }

    #[test]
    fn physical_reads_stay_inside_guest_memory() {
        let max = 0x1_7fff_ffff;
        assert!(within_physical(0x1_7606_0000, 4096, max) && within_physical(max, 1, max) && within_physical(0, 4096, max));
        // adres z dodatkowym wysokim bitem, zakres wychodzący za koniec, przepełnienie i pusty odczyt
        for (a, n) in [(0x2001_7606_0000u64, 4096usize), (max, 2), (max - 4094, 4096), (u64::MAX, 8), (0x1000, 0)] { assert!(!within_physical(a, n, max), "{a:x} {n}"); }
    }

    #[test]
    fn page_state_distinguishes_present_soft_and_missing() {
        let mut t = tables(&[(0x1000, 0, 0x2007), (0x2000, 0, 0x3007), (0x3000, 0, 0x4007), (0x4000, 0, 0x5025), (0x4000, 1, 0xabc0_0400), (0x4000, 2, 0)]);
        assert_eq!(leaf(0x1000, 0, &mut t), Leaf::Page(0x5025, 4096));
        assert_eq!(leaf(0x1000, 0x1000, &mut t), Leaf::Soft(0xabc0_0400));
        assert_eq!(leaf(0x1000, 0x2000, &mut t), Leaf::Soft(0));
        assert_eq!(leaf(0x1000, 1 << 30, &mut t), Leaf::Missing);
        assert_eq!((leaf_entry(0x1000, 0, &mut t), leaf_entry(0x1000, 0x1000, &mut t)), (Some((0x5025, 4096)), None));
    }

    #[test]
    fn waiting_threads_give_user_registers_from_their_trap_frames() {
        let m = thread_mem(&[(40, 5, 0x7ffd_0000_1012, 0x20_f000, 0x20_f100), (12, 2, 0x7ffd_0000_2012, 0x30_f000, 1), (28, 5, 0x7ffd_0000_3012, 0x40_f000, 2)]);
        let (t, n) = walk_threads(K, &TO, kread(&m));
        assert_eq!(n, ThreadCounts { total: 3, not_waiting: 1, ..Default::default() });
        // tylko wątki czekające, posortowane; znane są wyłącznie rsp i rbp
        assert_eq!(t.iter().map(|t| (t.tid, t.rip, t.gpr[4], t.gpr[5], t.known)).collect::<Vec<_>>(),
            [(28, 0x7ffd_0000_3012, 0x40_f000, 2, 0x30), (40, 0x7ffd_0000_1012, 0x20_f000, 0x20_f100, 0x30)]);
        assert!(t.iter().all(|t| t.gpr.iter().enumerate().all(|(i, v)| i == 4 || i == 5 || *v == 0)));
        assert!(walk_threads(K, &TO, kread(&thread_mem(&[]))).0.is_empty());
    }

    #[test]
    fn thread_walk_survives_hostile_lists_and_frames() {
        let good = (40u32, 5u8, 0x7ffd_0000_1012u64, 0x20_f000u64, 0u64);
        let tids = |m: &std::collections::HashMap<u64, u64>| walk_threads(K, &TO, kread(m)).0.iter().map(|t| t.tid).collect::<Vec<_>>();
        // ramka z adresem jądra albo zerem w rip lub rsp to nie wejście z trybu użytkownika
        for bad in [(1, 5, K, 0x20_f000, 0), (1, 5, 0, 0x20_f000, 0), (1, 5, 0x7ffd_0000_1012, K, 0), (1, 5, 0x7ffd_0000_1012, 0, 0), (0, 5, 0x7ffd_0000_1012, 0x20_f000, 0)] {
            assert_eq!(tids(&thread_mem(&[bad, good])), [40], "{bad:x?}");
        }
        // wskaźnik ramki poza pamięcią jądra, nieczytelna ramka (stos jądrowy poza pamięcią), nieczytelny opis wątku
        let frame_ptr = K + 0x10000 + TO.trap_frame as u64;
        let mut m = thread_mem(&[good, (41, 5, 0x7ffd_0000_1012, 0x20_f000, 0)]); m.insert(frame_ptr, 0x1000);
        assert_eq!(tids(&m), [41]);
        let mut m = thread_mem(&[good, (41, 5, 0x7ffd_0000_1012, 0x20_f000, 0)]); m.remove(&(K + 0x10000 + 0x8000 + TO.rsp as u64));
        assert_eq!(tids(&m), [41]);
        let mut m = thread_mem(&[good, (41, 5, 0x7ffd_0000_1012, 0x20_f000, 0)]); m.remove(&(K + 0x10000 + TO.state as u64));
        assert_eq!(tids(&m), [41]);
        // liczniki mówią, dlaczego wątek odpadł
        let mut m = thread_mem(&[good, (41, 5, 0x7ffd_0000_1012, 0x20_f000, 0), (42, 5, K, 1, 0), (43, 5, 0x7ffd_0000_1012, 0x20_f000, 0)]);
        m.remove(&(K + 0x20000 + 0x8000 + TO.rip as u64)); m.insert(K + 0x40000 + TO.trap_frame as u64, 0);
        assert_eq!(walk_threads(K, &TO, kread(&m)).1, ThreadCounts { total: 4, frame_unreadable: 1, not_user: 1, no_frame: 1, ..Default::default() });
        // lista zapętlona na sobie (bez powrotu do głowy) kończy się po jednym obiegu; ogniwo spoza jądra ją przerywa
        let mut m = thread_mem(&[good]); m.insert(K + 0x10000 + TO.list_entry as u64, K + 0x10000 + TO.list_entry as u64);
        assert_eq!(tids(&m), [40]);
        let mut m = thread_mem(&[good, (41, 5, 0x7ffd_0000_1012, 0x20_f000, 0)]); m.insert(K + 0x10000 + TO.list_entry as u64, 0x4141_4141);
        assert_eq!(tids(&m), [40]);
        // nieczytelna głowa listy, proces spoza pamięci jądra
        assert!(walk_threads(K, &TO, |_, _| false).0.is_empty());
        assert!(walk_threads(0x1000, &TO, kread(&thread_mem(&[good]))).0.is_empty());
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
    fn jit_evidence_needs_system_volume_program_directory_and_runtime_directory() {
        let img = |p: &str, d: u64| (p.to_string(), d);
        let ntdll = img("\\Windows\\System32\\ntdll.dll", 7);
        let clr = img("\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll", 7);
        let exe = img("\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe", 7);
        assert_eq!(jit_evidence_windows(&[ntdll.clone(), clr.clone()], Some(&exe)).as_deref(), Some("jit:dotnet"));
        let edge = img("\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\140.0\\msedge.dll", 7);
        assert_eq!(jit_evidence_windows(&[ntdll.clone(), edge], Some(&img("\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\140.0\\msedgewebview2.exe", 7))).as_deref(), Some("jit:webview2"));
        // każdy brakujący warunek odbiera dowód
        let none = |images: &[(String, u64)], exe: Option<&(String, u64)>, why: &str| assert_eq!(jit_evidence_windows(images, exe), None, "{why}");
        none(&[clr.clone()], Some(&exe), "brak ntdll: nie wiadomo, który wolumin jest systemowy");
        none(&[ntdll.clone(), img("\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll", 9)], Some(&exe), "clr.dll o tej samej ścieżce na innym dysku");
        none(&[ntdll.clone(), clr.clone()], Some(&img("\\Windows\\ADWS\\x.exe", 9)), "program na innym dysku");
        none(&[ntdll.clone(), clr.clone()], Some(&img("\\Users\\u\\x.exe", 7)), "program spoza katalogów systemowych");
        none(&[ntdll.clone(), clr.clone()], Some(&img("\\Windows\\Temp\\x.exe", 7)), "program w podkatalogu zapisywalnym dla użytkownika");
        none(&[ntdll.clone(), clr.clone()], None, "nieznany program główny");
        none(&[ntdll.clone(), img("\\Users\\u\\clr.dll", 7)], Some(&exe), "clr.dll spoza katalogu instalacyjnego");
        none(&[ntdll.clone(), img("\\Windows\\Microsoft.NET\\Framework64\\..\\..\\Temp\\clr.dll", 7)], Some(&exe), "ścieżka z cofnięciem");
        none(&[ntdll.clone(), img("\\Windows\\System32\\ntdll.dll", 9), clr.clone()], Some(&exe), "dwie ntdll z różnych dysków");
        none(&[img("\\Windows\\System32\\ntdll.dll", 0), img("\\Windows\\Microsoft.NET\\Framework64\\v4\\clr.dll", 0)], Some(&img("\\Windows\\ADWS\\x.exe", 0)), "nieznane urządzenie");
        none(&[ntdll, clr], Some(&img("Windows\\ADWS\\x.exe", 7)), "ścieżka programu bez korzenia");
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
