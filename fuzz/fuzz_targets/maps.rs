//! Mapa pamięci procesu Linux (/proc/<pid>/maps i smaps): nazwy mapowań ustala badany proces.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let regions = nanshe_live::maps::parse_maps(&s);
    for r in &regions { assert!(r.base.checked_add(r.size).is_some()); }
    let _ = nanshe_live::maps::parse_smaps(&s);
});
