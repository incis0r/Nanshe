//! Tablice stron gościa: pamięć fizyczna maszyny wirtualnej jest daną niezaufaną. Wejście to "pamięć fizyczna"
//! pocięta na tablice po 4 KiB; adresy spoza wejścia są nieczytelne. Przejście musi się zakończyć w limitach.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_vm::{build_regions, walk_page_tables, Module, MAX_RANGES};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }
    let dtb = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mem = &data[8..];
    let (ranges, _complete) = walk_page_tables(dtb, |addr| {
        let at = usize::try_from(addr).ok()?;
        let table = mem.get(at..at.checked_add(4096)?)?;
        Some(table.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
    });
    assert!(ranges.len() <= MAX_RANGES);
    // zakresy rosną, nie nakładają się i leżą w przestrzeni użytkownika
    assert!(ranges.windows(2).all(|w| w[0].base + w[0].size <= w[1].base));
    assert!(ranges.iter().all(|r| r.size > 0 && r.base + r.size <= 1 << 47));
    // moduły też pochodzą z pamięci gościa
    let modules: Vec<Module> = mem.chunks_exact(16).take(64).map(|c| Module {
        base: u64::from_le_bytes(c[..8].try_into().unwrap()), size: u64::from_le_bytes(c[8..].try_into().unwrap()), path: "m".into() }).collect();
    let take = ranges.len().min(4096);
    let regions = build_regions(&ranges[..take], &modules);
    assert!(regions.windows(2).all(|w| w[0].base + w[0].size <= w[1].base));
});
