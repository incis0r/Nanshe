//! Zrzut pamięci procesu (plik core ELF albo minidump) z dowolnych bajtów: otwarcie, mapa, wątki i odczyt
//! nie mogą spanikować, zawisnąć ani czytać poza plikiem.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_core::MemorySource;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // parser czyta z pliku; jeden plik na proces fuzzera, w pamięci (tmpfs), nadpisywany przy każdej próbie
    let path = std::env::temp_dir().join(format!("nanshe-fuzz-dump-{}", std::process::id()));
    { let mut f = std::fs::File::create(&path).unwrap(); f.write_all(data).unwrap(); }
    if let Ok(d) = nanshe_dump::open(&path) {
        let _ = d.info();
        let _ = d.threads();
        let mut buf = [0u8; 4096];
        if let Ok(regions) = d.regions() {
            for r in regions.iter().take(64) {
                let _ = d.read_at(r.base, &mut buf);
                let _ = d.read_at(r.base.wrapping_add(r.size).wrapping_sub(1), &mut buf);
            }
        }
        let _ = d.read_at(u64::MAX - 8, &mut buf);
    }
});
