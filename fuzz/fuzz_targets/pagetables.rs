//! Tablice stron gościa: pamięć fizyczna maszyny wirtualnej jest daną niezaufaną. Wejście to "pamięć fizyczna"
//! pocięta na tablice po 4 KiB; adresy spoza wejścia są nieczytelne. Przejście musi się zakończyć w limitach.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_vm::{build_regions, leaf_entry, regions_from_vads, walk_page_tables, walk_vads, Module, VadOffsets, MAX_RANGES, MAX_VADS};

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
    // tłumaczenie pojedynczego adresu po tych samych tablicach (także wpisy przejściowe)
    let va = u64::from_le_bytes(mem.get(..8).unwrap_or(&[0; 8]).try_into().unwrap()) & ((1 << 47) - 1);
    let _ = leaf_entry(dtb, va, |addr| {
        let at = usize::try_from(addr).ok()?;
        let table = mem.get(at..at.checked_add(4096)?)?;
        Some(table.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect::<Vec<u64>>())
    });
    // drzewo VAD z tej samej "pamięci": adresy jądra są mapowane na przesunięcia w wejściu
    const K: u64 = 0xffff_9000_0000_0000;
    let o = VadOffsets { left: 0, right: 8, start_vpn: 24, end_vpn: 28, start_high: 32, end_high: 33, flags: 48, type_bit: 4, private_bit: 21 };
    let (vads, _) = walk_vads(K + (dtb & 0xfff8), &o, |addr, buf| {
        let Some(at) = addr.checked_sub(K).and_then(|a| usize::try_from(a).ok()) else { return false };
        match mem.get(at..at.saturating_add(buf.len())) { Some(src) => { buf.copy_from_slice(src); true } None => false }
    });
    assert!(vads.len() <= MAX_VADS && vads.windows(2).all(|w| w[0].end <= w[1].start) && vads.iter().all(|v| v.start < v.end && v.end <= 1 << 47));
    let named: Vec<_> = vads.into_iter().map(|v| (v, None)).collect();
    let regions = regions_from_vads(&ranges[..take], &named);
    assert!(regions.windows(2).all(|w| w[0].base + w[0].size <= w[1].base));
});
