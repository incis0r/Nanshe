//! Detektory nad dowolną zawartością pamięci badanego procesu: nagłówki PE, ELF i Mach-O, tablice sekcji,
//! entropia i podgląd bajtów. Pierwsze bajty wejścia wybierają system, uprawnienia i rodzaj regionu.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_core::{MemorySource, Prot, Region, RegionKind, Result, SourceInfo};

struct One { os: &'static str, source: &'static str, region: Region, data: Vec<u8> }
impl MemorySource for One {
    fn info(&self) -> SourceInfo {
        SourceInfo { os: self.os.into(), arch: "x86_64".into(), pid: Some(7), name: Some("p".into()), source_type: self.source.into(), exe: Some("/usr/bin/p".into()), exe_deleted: false, exe_verified: true }
    }
    fn regions(&self) -> Result<Vec<Region>> { Ok(vec![self.region.clone()]) }
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let off = addr.saturating_sub(self.region.base) as usize;
        let src = self.data.get(off..).unwrap_or(&[]);
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 { return; }
    let os = ["linux", "windows", "macos"][data[0] as usize % 3];
    let source = ["live", "dump", "vm"][data[1] as usize % 3];
    let kind = [RegionKind::Private, RegionKind::Mapped, RegionKind::Image, RegionKind::Heap, RegionKind::Stack, RegionKind::Unknown][data[2] as usize % 6];
    let backing = match data[3] % 4 { 0 => None, 1 => Some("/usr/lib/x.so".to_string()), 2 => Some("memfd:libffi".to_string()), _ => Some("/tmp/x".to_string()) };
    let body = &data[4..];
    // rozmiar regionu bywa większy niż przeczytana treść (odczyt częściowy)
    let size = (body.len() as u64 + (data[3] as u64 >> 2) * 4096).max(4096);
    let region = Region { base: 0x7f00_0000_0000, size, prot: Some(Prot(data[2] >> 5)), kind, backing_deleted: data[3] & 0x80 != 0, backing, label: None, readable: true };
    let src = One { os, source, region, data: body.to_vec() };
    let cfg = nanshe_analyze::Config::default();
    let rep = nanshe_analyze::scan_source(&src, &cfg);
    for r in &rep.regions { for f in &r.findings { assert!(f.addr >= r.region.base && f.addr < r.region.base + r.region.size.max(1)); } }
});
