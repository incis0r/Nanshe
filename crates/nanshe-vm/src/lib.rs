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
pub fn walk_page_tables(dtb: u64, mut table: impl FnMut(u64) -> Option<Vec<u64>>) -> (Vec<PageRange>, bool) {
    const P: u64 = 1; const W: u64 = 2; const U: u64 = 4; const PS: u64 = 0x80; const NX: u64 = 1 << 63;
    const ADDR: u64 = 0x000f_ffff_ffff_f000;
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
    let Some(pml4) = read(dtb & ADDR, &mut tables, &mut complete) else { return (out, false) };
    for (i4, &e4) in pml4.iter().enumerate().take(256) {
        if e4 & P == 0 { continue; }
        let Some(pdpt) = read(e4 & ADDR, &mut tables, &mut complete) else { continue };
        for (i3, &e3) in pdpt.iter().enumerate() {
            if e3 & P == 0 { continue; }
            let va3 = ((i4 as u64) << 39) | ((i3 as u64) << 30);
            let (w3, u3, nx3) = (e4 & e3 & W != 0, e4 & e3 & U != 0, (e4 | e3) & NX != 0);
            if e3 & PS != 0 { if u3 { emit(va3, 1 << 30, w3, !nx3); } continue; }
            let Some(pd) = read(e3 & ADDR, &mut tables, &mut complete) else { continue };
            for (i2, &e2) in pd.iter().enumerate() {
                if e2 & P == 0 { continue; }
                let va2 = va3 | ((i2 as u64) << 21);
                let (w2, u2, nx2) = (w3 && e2 & W != 0, u3 && e2 & U != 0, nx3 || e2 & NX != 0);
                if e2 & PS != 0 { if u2 { emit(va2, 1 << 21, w2, !nx2); } continue; }
                let Some(pt) = read(e2 & ADDR, &mut tables, &mut complete) else { continue };
                for (i1, &e1) in pt.iter().enumerate() {
                    if e1 & P == 0 || !(u2 && e1 & U != 0) { continue; }
                    emit(va2 | ((i1 as u64) << 12), 4096, w2 && e1 & W != 0, !(nx2 || e1 & NX != 0));
                }
            }
        }
    }
    (out, complete && !overflow)
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
            let (kind, backing) = match m { Some(m) => (RegionKind::Image, Some(m.path.clone())), None if mods.is_empty() => (RegionKind::Unknown, None), None => (RegionKind::Private, None) };
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

    #[test]
    fn empty_and_degenerate_input_gives_no_regions() {
        assert!(build_regions(&[], &[]).is_empty());
        assert!(build_regions(&[pr(0x1000, 0, true, true)], &[Module { base: 0, size: 0, path: String::new() }]).is_empty());
        // zakres sięgający poza przestrzeń użytkownika jest przycinany
        let r = build_regions(&[pr(USER_MAX - 0xfff, 0x10_0000, false, false)], &[]);
        assert_eq!((r[0].base, r[0].size), (USER_MAX - 0xfff, 0x1000));
    }
}
