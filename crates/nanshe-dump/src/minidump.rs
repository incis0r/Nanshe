//! Minidump systemu Windows (sygnatura MDMP), w praktyce pełny zrzut procesu
//! (`procdump -ma`, Menedżer zadań, `MiniDumpWriteDump` z pełną pamięcią).
//! Regiony pochodzą ze strumienia MemoryInfoList (ten sam opis co VirtualQueryEx), treść ze
//! strumienia Memory64List albo MemoryList, nazwy modułów z ModuleList, adresy startu wątków
//! z ThreadInfoList, rejestry wątków (do odwijania stosów) z ThreadList.
use crate::{covered, range_at, short, u16le, u32le, u64le, Parsed, Seg, Src, MAX_TABLE};
use nanshe_core::*;
use nanshe_core::{tr, trf};

const THREAD_LIST: u32 = 3;
const MODULE_LIST: u32 = 4;
const MEMORY_LIST: u32 = 5;
const SYSTEM_INFO: u32 = 7;
const MEMORY64_LIST: u32 = 9;
const MISC_INFO: u32 = 15;
const MEMORY_INFO_LIST: u32 = 16;
const THREAD_INFO_LIST: u32 = 17;

/// Położenie rejestrów w strukturze CONTEXT (x64): Rax..R15 w numeracji procesora, potem Rip.
const CONTEXT_RAX: usize = 0x78;
const CONTEXT_RIP: usize = 0xf8;
/// Najwięcej kontekstów wątków czytanych z jednego zrzutu.
const MAX_THREAD_CONTEXTS: usize = 1 << 16;

const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x2_0000;
const MEM_MAPPED: u32 = 0x4_0000;
const MEM_IMAGE: u32 = 0x100_0000;
const PAGE_GUARD: u32 = 0x100;

/// Uprawnienia strony Windows jako r/w/x i informacja, czy stronę wolno czytać (jak w skanie na żywo).
fn prot_from_page(protect: u32) -> (Prot, bool) {
    let p = match protect & 0xff {
        0x02 => Prot::R,                    // PAGE_READONLY
        0x04 | 0x08 => Prot::R | Prot::W,   // PAGE_READWRITE, PAGE_WRITECOPY
        0x10 => Prot::X,                    // PAGE_EXECUTE
        0x20 => Prot::R | Prot::X,          // PAGE_EXECUTE_READ
        0x40 | 0x80 => Prot::R | Prot::W | Prot::X, // PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
        _ => 0,                             // PAGE_NOACCESS i nieznane
    };
    (Prot(p), p & Prot::R != 0 && protect & PAGE_GUARD == 0)
}

fn utf16_at(src: &mut Src, rva: u64) -> Option<String> {
    let len = u32le(&src.read(rva, 4).ok()?, 0)? as usize;
    if len == 0 || len > 65536 { return None; }
    let b = src.read(rva + 4, len).ok()?;
    let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&u).trim_end_matches('\0').to_string()).filter(|s| !s.is_empty())
}

pub(crate) fn parse(src: &mut Src) -> Result<Parsed> {
    let h = src.read(0, 32).map_err(|_| short())?;
    let (count, dir) = (u32le(&h, 8).ok_or_else(short)? as usize, u32le(&h, 12).ok_or_else(short)? as u64);
    if count > 4096 { return Err(Error::Invalid(tr!("minidump: nieprawdopodobna liczba strumieni", "minidump: implausible number of streams").into())); }
    let table = src.read(dir, count * 12)?;
    // strumień: (przesunięcie, rozmiar), z rozmiarem przyciętym do pliku
    let stream = |typ: u32| -> Option<(u64, usize)> {
        (0..count).find_map(|i| (u32le(&table, i * 12) == Some(typ)).then(|| (u32le(&table, i * 12 + 8).unwrap_or(0) as u64, u32le(&table, i * 12 + 4).unwrap_or(0) as usize)))
    };
    let load = |src: &mut Src, s: Option<(u64, usize)>| -> Option<Vec<u8>> {
        let (rva, size) = s?;
        let size = size.min(src.len.saturating_sub(rva.min(src.len)) as usize).min(MAX_TABLE);
        src.read(rva, size).ok()
    };

    let mut p = Parsed { os: "windows", arch: "unknown".into(), ..Default::default() };
    if let Some(b) = load(src, stream(SYSTEM_INFO)) {
        p.arch = match u16le(&b, 0) { Some(9) => "x86_64".into(), Some(0) => "x86".into(), Some(12) => "aarch64".into(), Some(5) => "arm".into(), x => format!("windows-arch-{}", x.unwrap_or(0xffff)) };
    }
    if let Some(b) = load(src, stream(MISC_INFO)) {
        if u32le(&b, 4).unwrap_or(0) & 1 != 0 { p.pid = u32le(&b, 8).filter(|x| *x != 0); }
    }

    // --- moduły: zakres adresów i ścieżka pliku
    let mut modules: Vec<(u64, u64, String)> = Vec::new();
    if let Some(b) = load(src, stream(MODULE_LIST)) {
        let n = (u32le(&b, 0).unwrap_or(0) as usize).min(b.len().saturating_sub(4) / 108).min(65536);
        for i in 0..n {
            let e = &b[4 + i * 108..4 + (i + 1) * 108];
            let (Some(base), Some(size), Some(name_rva)) = (u64le(e, 0), u32le(e, 8), u32le(e, 20)) else { continue };
            if let Some(name) = utf16_at(src, name_rva as u64) { modules.push((base, size as u64, name)); }
        }
    }
    if let Some((_, _, exe)) = modules.first() {
        p.name = exe.rsplit(['\\', '/']).next().map(String::from);
        p.exe = Some(exe.clone());
    }

    // --- treść pamięci
    if let Some((rva, size)) = stream(MEMORY64_LIST) {
        let head = src.read(rva, 16.min(size)).map_err(|_| short())?;
        let (n, base) = (u64le(&head, 0).ok_or_else(short)?, u64le(&head, 8).ok_or_else(short)?);
        let n = (n.min((size.saturating_sub(16) / 16) as u64).min(MAX_REGIONS as u64)) as usize;
        let b = src.read(rva + 16, (n * 16).min(MAX_TABLE))?;
        let mut off = base;
        for i in 0..b.len() / 16 {
            let (Some(start), Some(len)) = (u64le(&b, i * 16), u64le(&b, i * 16 + 8)) else { break };
            // treść leży jeden fragment za drugim; fragment wychodzący poza plik jest przycinany
            let avail = src.len.saturating_sub(off.min(src.len));
            p.segs.push(Seg { vaddr: start, len: len.min(avail), off });
            off = match off.checked_add(len) { Some(o) => o, None => break };
        }
    } else if let Some(b) = load(src, stream(MEMORY_LIST)) {
        let n = (u32le(&b, 0).unwrap_or(0) as usize).min(b.len().saturating_sub(4) / 16);
        for i in 0..n {
            let e = &b[4 + i * 16..4 + (i + 1) * 16];
            let (Some(start), Some(len), Some(rva)) = (u64le(e, 0), u32le(e, 8), u32le(e, 12)) else { continue };
            let avail = src.len.saturating_sub((rva as u64).min(src.len));
            p.segs.push(Seg { vaddr: start, len: (len as u64).min(avail), off: rva as u64 });
        }
        p.notes.push(tr!("minidump bez pełnej pamięci (strumień MemoryList): zawiera tylko wybrane fragmenty, zwykle stosy; większość regionów nie ma treści", "minidump without full memory (MemoryList stream): it contains only selected fragments, usually stacks; most regions have no content").into());
    } else {
        p.notes.push(tr!("minidump nie zawiera treści pamięci: oceniane są tylko uprawnienia i rodzaje regionów", "the minidump contains no memory content: only region permissions and types are assessed").into());
    }
    p.segs.retain(|s| s.len > 0 && s.vaddr.checked_add(s.len).is_some());
    p.segs.sort_by_key(|s| s.vaddr);

    // --- regiony
    // moduły jako zakresy [początek, koniec) posortowane po adresie: wyszukiwanie binarne
    let mut ranges: Vec<(u64, u64, String)> = modules.iter().map(|(b, s, n)| (*b, b.saturating_add(*s), n.clone())).collect();
    ranges.sort_by_key(|m| m.0);
    let module_of = |addr: u64| range_at(&ranges, addr).cloned();
    if let Some((rva, size)) = stream(MEMORY_INFO_LIST) {
        let head = src.read(rva, 16.min(size)).map_err(|_| short())?;
        let (hs, es, n) = (u32le(&head, 0).ok_or_else(short)? as usize, u32le(&head, 4).ok_or_else(short)? as usize, u64le(&head, 8).ok_or_else(short)?);
        if hs < 16 || es < 48 { return Err(short()); }
        let n = (n.min((size.saturating_sub(hs) / es) as u64).min(MAX_REGIONS as u64)) as usize;
        let b = src.read(rva + hs as u64, (n * es).min(MAX_TABLE))?;
        for e in b.chunks_exact(es) {
            let (Some(base), Some(size), Some(state), Some(protect), Some(typ)) = (u64le(e, 0), u64le(e, 24), u32le(e, 32), u32le(e, 36), u32le(e, 40)) else { continue };
            if state != MEM_COMMIT || size == 0 || base.checked_add(size).is_none() { continue; }
            let (prot, readable) = prot_from_page(protect);
            let kind = match typ { MEM_IMAGE => RegionKind::Image, MEM_MAPPED => RegionKind::Mapped, MEM_PRIVATE => RegionKind::Private, _ => RegionKind::Unknown };
            let backing = if kind == RegionKind::Image { module_of(base) } else { None };
            let label = (protect & PAGE_GUARD != 0).then(|| GUARD_LABEL.to_string());
            p.regions.push(Region { base, size, prot: Some(prot), kind, backing, backing_deleted: false, label, readable: readable && covered(&p.segs, base) });
        }
        p.notes.push(tr!("minidump nie zawiera nazw plików dla mapowań innych niż obrazy modułów", "the minidump has no file names for mappings other than module images").into());
    } else {
        // bez opisu regionów: każdy fragment treści to region o nieznanych uprawnieniach
        for s in &p.segs {
            p.regions.push(Region { base: s.vaddr, size: s.len, prot: None, kind: if module_of(s.vaddr).is_some() { RegionKind::Image } else { RegionKind::Unknown }, backing: module_of(s.vaddr), backing_deleted: false, label: None, readable: true });
        }
        p.notes.push(tr!("minidump nie zawiera opisu regionów (strumień MemoryInfoList): uprawnienia i rodzaje pamięci są nieznane, więc detektory oparte na uprawnieniach nie działają", "the minidump has no region description (MemoryInfoList stream): permissions and memory types are unknown, so permission-based detectors do not work").into());
    }

    // --- wątki: adres startu (jak w skanie na żywo)
    if let Some((rva, size)) = stream(THREAD_INFO_LIST) {
        let head = src.read(rva, 12.min(size)).map_err(|_| short())?;
        let (hs, es, n) = (u32le(&head, 0).ok_or_else(short)? as usize, u32le(&head, 4).ok_or_else(short)? as usize, u32le(&head, 8).ok_or_else(short)? as usize);
        if hs >= 12 && es >= 64 {
            let n = n.min(size.saturating_sub(hs) / es).min(1 << 20);
            if let Ok(b) = src.read(rva + hs as u64, (n * es).min(MAX_TABLE)) {
                for e in b.chunks_exact(es) {
                    if let (Some(tid), Some(start)) = (u32le(e, 0), u64le(e, 48)) { if tid != 0 && start != 0 { p.threads.push(ThreadInfo { tid, addr: start }); } }
                }
            }
        }
    }
    // --- rejestry wątków: struktura CONTEXT (x64) zapisana dla każdego wątku w strumieniu ThreadList
    if p.arch == "x86_64" {
        if let Some(b) = load(src, stream(THREAD_LIST)) {
            let n = (u32le(&b, 0).unwrap_or(0) as usize).min(b.len().saturating_sub(4) / 48).min(MAX_THREAD_CONTEXTS);
            for e in b[4..4 + n * 48].chunks_exact(48) {
                let (Some(tid), Some(size), Some(rva)) = (u32le(e, 0), u32le(e, 40), u32le(e, 44)) else { continue };
                // Rax..R15 leżą od 0x78, Rip pod 0xf8; krótszy zapis nie jest kontekstem x64
                if tid == 0 { continue; }
                if (size as usize) < CONTEXT_RIP + 8 { p.regs.unread += 1; continue; }
                let Ok(c) = src.read(rva as u64, CONTEXT_RIP + 8) else { p.regs.unread += 1; continue };
                let mut gpr = [0u64; 16];
                for (i, g) in gpr.iter_mut().enumerate() { *g = u64le(&c, CONTEXT_RAX + i * 8).unwrap_or(0); }
                p.regs.regs.push(ThreadRegs { tid, rip: u64le(&c, CONTEXT_RIP).unwrap_or(0), gpr, known: 0xffff });
            }
            p.regs.regs.sort_by_key(|t| t.tid);
        }
    }
    if p.threads.is_empty() {
        p.notes.push(tr!("minidump nie zawiera adresów startu wątków (strumień ThreadInfoList): wątki nie są oceniane", "the minidump has no thread start addresses (ThreadInfoList stream): threads are not assessed").into());
    }
    p.threads.sort_by_key(|t| t.tid);
    let missing = p.regions.iter().filter(|r| !r.readable && r.label.is_none() && r.prot.map(|x| x.r()).unwrap_or(false)).count();
    if missing > 0 {
        p.notes.push(trf!("{missing} czytelnych regionów nie ma treści w zrzucie: detektory treści ich nie sprawdziły", "{missing} readable regions have no content in the dump: content detectors did not examine them"));
    }
    Ok(p)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Tmp;

    /// Region do zrzutu testowego: (adres, rozmiar, Protect, Type, treść albo brak).
    pub(crate) type R = (u64, u64, u32, u32, Option<Vec<u8>>);

    /// Pełny minidump z podanymi regionami, modułami (adres, rozmiar, ścieżka) i wątkami (tid, adres startu).
    pub(crate) fn minidump(regions: &[R], modules: &[(u64, u32, &str)], threads: &[(u32, u64)], pid: u32) -> Vec<u8> { minidump_with(regions, modules, threads, pid, &[]) }

    /// Jak `minidump`, dodatkowo ze strumieniem ThreadList: (tid, rip, rsp, rozmiar zapisanego kontekstu).
    pub(crate) fn minidump_with(regions: &[R], modules: &[(u64, u32, &str)], threads: &[(u32, u64)], pid: u32, contexts: &[(u32, u64, u64, u32)]) -> Vec<u8> {
        let mut streams: Vec<(u32, Vec<u8>)> = Vec::new();
        if !contexts.is_empty() {
            // wpisy po 48 bajtów, za nimi konteksty; RVA kontekstu jest na razie względne i zostanie przesunięte o położenie strumienia
            let mut tl = Vec::new(); tl.extend((contexts.len() as u32).to_le_bytes());
            let mut ctx = Vec::new();
            for (tid, rip, rsp, size) in contexts {
                let mut e = vec![0u8; 48];
                e[0..4].copy_from_slice(&tid.to_le_bytes()); e[40..44].copy_from_slice(&size.to_le_bytes());
                e[44..48].copy_from_slice(&((4 + contexts.len() * 48 + ctx.len()) as u32).to_le_bytes());
                tl.extend(e);
                let mut c = vec![0u8; 1232];
                c[CONTEXT_RAX + 4 * 8..CONTEXT_RAX + 5 * 8].copy_from_slice(&rsp.to_le_bytes()); c[CONTEXT_RIP..CONTEXT_RIP + 8].copy_from_slice(&rip.to_le_bytes());
                c[CONTEXT_RAX + 5 * 8..CONTEXT_RAX + 6 * 8].copy_from_slice(&0x55u64.to_le_bytes());
                ctx.extend(c);
            }
            tl.extend(ctx);
            streams.push((THREAD_LIST, tl));
        }
        let mut sys = vec![0u8; 56]; sys[0..2].copy_from_slice(&9u16.to_le_bytes());
        streams.push((SYSTEM_INFO, sys));
        let mut misc = vec![0u8; 24]; misc[4..8].copy_from_slice(&1u32.to_le_bytes()); misc[8..12].copy_from_slice(&pid.to_le_bytes());
        streams.push((MISC_INFO, misc));
        let mut mi = Vec::new();
        mi.extend(16u32.to_le_bytes()); mi.extend(48u32.to_le_bytes()); mi.extend((regions.len() as u64).to_le_bytes());
        for (base, size, protect, typ, _) in regions {
            let mut e = vec![0u8; 48];
            e[0..8].copy_from_slice(&base.to_le_bytes()); e[24..32].copy_from_slice(&size.to_le_bytes());
            e[32..36].copy_from_slice(&MEM_COMMIT.to_le_bytes()); e[36..40].copy_from_slice(&protect.to_le_bytes()); e[40..44].copy_from_slice(&typ.to_le_bytes());
            mi.extend(e);
        }
        streams.push((MEMORY_INFO_LIST, mi));
        let mut ti = Vec::new();
        ti.extend(12u32.to_le_bytes()); ti.extend(64u32.to_le_bytes()); ti.extend((threads.len() as u32).to_le_bytes());
        for (tid, start) in threads { let mut e = vec![0u8; 64]; e[0..4].copy_from_slice(&tid.to_le_bytes()); e[48..56].copy_from_slice(&start.to_le_bytes()); ti.extend(e); }
        streams.push((THREAD_INFO_LIST, ti));

        // układ pliku: nagłówek, katalog, strumienie, nazwy modułów, treść pamięci
        let nstreams = streams.len() + 2;
        let mut off = 32 + nstreams * 12;
        let mut placed: Vec<(u32, usize, Vec<u8>)> = Vec::new();
        for (t, mut b) in streams {
            if t == THREAD_LIST { for i in 0..contexts.len() { let o = 4 + i * 48 + 44; let v = u32le(&b, o).unwrap() + off as u32; b[o..o + 4].copy_from_slice(&v.to_le_bytes()); } }
            placed.push((t, off, b.clone())); off += b.len();
        }
        let ml_off = off; off += 4 + modules.len() * 108;
        let mut names = Vec::new(); let mut name_rvas = Vec::new();
        for (_, _, n) in modules {
            name_rvas.push(off + names.len());
            let u: Vec<u8> = n.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            names.extend((u.len() as u32).to_le_bytes()); names.extend(u);
        }
        off += names.len();
        let with: Vec<&R> = regions.iter().filter(|r| r.4.is_some()).collect();
        let m64_off = off; off += 16 + with.len() * 16;
        let data_off = off;
        let mut ml = Vec::new(); ml.extend((modules.len() as u32).to_le_bytes());
        for (i, (base, size, _)) in modules.iter().enumerate() {
            let mut e = vec![0u8; 108];
            e[0..8].copy_from_slice(&base.to_le_bytes()); e[8..12].copy_from_slice(&size.to_le_bytes()); e[20..24].copy_from_slice(&(name_rvas[i] as u32).to_le_bytes());
            ml.extend(e);
        }
        let mut m64 = Vec::new(); m64.extend((with.len() as u64).to_le_bytes()); m64.extend((data_off as u64).to_le_bytes());
        let mut data: Vec<u8> = Vec::new();
        for r in &with { let d = r.4.as_ref().unwrap(); m64.extend(r.0.to_le_bytes()); m64.extend((d.len() as u64).to_le_bytes()); data.extend(d); }
        placed.push((MODULE_LIST, ml_off, ml.clone()));
        placed.push((MEMORY64_LIST, m64_off, m64.clone()));

        let mut f = Vec::new();
        f.extend(b"MDMP"); f.extend(0xa793u32.to_le_bytes()); f.extend((nstreams as u32).to_le_bytes()); f.extend(32u32.to_le_bytes()); f.extend([0u8; 16]);
        for (t, o, b) in &placed { f.extend(t.to_le_bytes()); f.extend((b.len() as u32).to_le_bytes()); f.extend((*o as u32).to_le_bytes()); }
        for (t, _, b) in &placed { if *t != MODULE_LIST && *t != MEMORY64_LIST { f.extend(b); } }
        f.extend(ml); f.extend(names); f.extend(m64); f.extend(data);
        f
    }

    #[test]
    fn minidump_gives_regions_modules_threads_and_memory() {
        let regions: Vec<R> = vec![
            (0x7ff6_0000_0000, 0x2000, 0x20, MEM_IMAGE, Some(vec![0x11; 0x2000])),   // kod programu
            (0x1_0000, 0x1000, 0x40, MEM_PRIVATE, Some(vec![0x22; 0x1000])),          // prywatny RWX
            (0x1_1000, 0x1000, 0x04, MEM_PRIVATE, Some(vec![0x33; 0x1000])),          // sąsiedni RW: treść przylega w pliku
            (0x2_0000, 0x1000, 0x20 | PAGE_GUARD, MEM_PRIVATE, None),                 // wykonywalny za strażnikiem
            (0x3_0000, 0x1000, 0x20, MEM_MAPPED, None),                               // mapowanie bez treści w zrzucie
            (0x4_0000, 0x1000, 0x01, MEM_PRIVATE, None),                              // PAGE_NOACCESS
        ];
        let bytes = minidump(&regions, &[(0x7ff6_0000_0000, 0x2000, "C:\\Program Files\\App\\app.exe"), (0x7ffd_0000_0000, 0x1000, "C:\\Windows\\System32\\ntdll.dll")], &[(100, 0x7ff6_0000_0100), (104, 0x1_0010)], 777);
        let t = Tmp::new("mdmp", &bytes);
        let d = crate::open(&t.0).unwrap();
        let i = d.info();
        assert_eq!((i.os.as_str(), i.arch.as_str(), i.pid, i.name.as_deref(), i.exe.as_deref(), i.source_type.as_str(), i.exe_verified),
            ("windows", "x86_64", Some(777), Some("app.exe"), Some("C:\\Program Files\\App\\app.exe"), "dump", false));
        let r = d.regions().unwrap();
        assert_eq!(r.len(), 6);
        let by = |base: u64| r.iter().find(|x| x.base == base).unwrap();
        assert_eq!((by(0x7ff6_0000_0000).kind, by(0x7ff6_0000_0000).backing.as_deref(), by(0x7ff6_0000_0000).prot.unwrap().to_string()), (RegionKind::Image, Some("C:\\Program Files\\App\\app.exe"), "r-x".to_string()));
        assert_eq!((by(0x1_0000).kind, by(0x1_0000).prot.unwrap().to_string(), by(0x1_0000).readable), (RegionKind::Private, "rwx".to_string(), true));
        assert_eq!((by(0x2_0000).label.as_deref(), by(0x2_0000).readable), (Some(GUARD_LABEL), false));
        assert_eq!((by(0x3_0000).kind, by(0x3_0000).backing.as_deref(), by(0x3_0000).readable), (RegionKind::Mapped, None, false));
        assert_eq!((by(0x4_0000).prot.unwrap().to_string(), by(0x4_0000).readable), ("---".to_string(), false));
        assert_eq!(d.threads(), vec![ThreadInfo { tid: 100, addr: 0x7ff6_0000_0100 }, ThreadInfo { tid: 104, addr: 0x1_0010 }]);
        // odczyt przechodzi przez przylegające fragmenty i kończy na luce
        let mut buf = vec![0u8; 0x3000];
        assert_eq!(d.read_at(0x1_0000, &mut buf).unwrap(), 0x2000);
        assert!(buf[..0x1000].iter().all(|b| *b == 0x22) && buf[0x1000..0x2000].iter().all(|b| *b == 0x33));
        assert!(d.read_at(0x3_0000, &mut buf).is_err());
        assert!(d.notes.iter().any(|n| n.contains("1 czytelnych regionów nie ma treści")), "{:?}", d.notes);
    }

    #[test]
    fn thread_registers_come_from_the_thread_list_stream() {
        let regions: Vec<R> = vec![(0x1_0000, 0x1000, 0x04, MEM_PRIVATE, Some(vec![0; 0x1000]))];
        let mods = [(0x7ff6_0000_0000u64, 0x2000u32, "C:\\a.exe")];
        let set = |b: &[u8]| { let t = Tmp::new("mdmp-regs", b); crate::open(&t.0).unwrap().thread_regs() };
        let open = |b: &[u8]| set(b).regs;
        // dwa wątki z pełnym kontekstem; trzeci ma zapis za krótki na kontekst x64, czwarty zerowy numer
        let d = open(&minidump_with(&regions, &mods, &[(9, 0x1_0000)], 5, &[(9, 0x7ff6_0000_1012, 0x1_0800, 1232), (4, 0x7ff6_0000_1100, 0x1_0900, 1232), (11, 1, 2, 0xf0), (0, 1, 2, 1232)]));
        assert_eq!(d.iter().map(|t| (t.tid, t.rip, t.gpr[4], t.gpr[5], t.known)).collect::<Vec<_>>(), [(4, 0x7ff6_0000_1100, 0x1_0900, 0x55, 0xffff), (9, 0x7ff6_0000_1012, 0x1_0800, 0x55, 0xffff)]);
        // kontrola: zrzut bez strumienia ThreadList nie ma rejestrów
        assert!(open(&minidump(&regions, &mods, &[(9, 0x1_0000)], 5)).is_empty());
        // kontekst wskazany poza plik jest pomijany, pozostałe zostają
        let mut bad = minidump_with(&regions, &mods, &[], 5, &[(0x4242_4242, 1, 2, 1232), (4, 3, 4, 1232)]);
        let at = bad.windows(4).position(|w| w == 0x4242_4242u32.to_le_bytes()).unwrap();
        bad[at + 44..at + 48].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert_eq!((set(&bad).regs.iter().map(|t| t.tid).collect::<Vec<_>>(), set(&bad).unread), (vec![4], 1));
    }

    #[test]
    fn hostile_minidump_does_not_panic_or_read_outside_the_file() {
        let good = minidump(&[(0x1_0000, 0x1000, 0x40, MEM_PRIVATE, Some(vec![7; 0x1000]))], &[(0x7ff6_0000_0000, 0x1000, "C:\\a.exe")], &[(1, 0x1_0000)], 5);
        let mut buf = vec![0u8; 0x2000];
        // każde obcięcie pliku: błąd albo wynik bez paniki; odczyt nigdy nie daje więcej, niż jest w pliku
        for cut in (0..good.len()).step_by(5) {
            let t = Tmp::new("mdmp-cut", &good[..cut]);
            if let Ok(d) = crate::open(&t.0) { let _ = d.regions(); if let Ok(n) = d.read_at(0x1_0000, &mut buf) { assert!(n <= 0x1000); } }
        }
        // każdy bajt nagłówka i katalogu ustawiony na 0xff: bez paniki
        for i in 4..32 + 6 * 12 {
            let mut bad = good.clone(); bad[i] = 0xff;
            let t = Tmp::new("mdmp-bad", &bad);
            if let Ok(d) = crate::open(&t.0) { let _ = d.regions(); let _ = d.read_at(0x1_0000, &mut buf); let _ = d.threads(); }
        }
        // liczba strumieni większa niż limit
        let mut many = good.clone(); many[8..12].copy_from_slice(&100_000u32.to_le_bytes());
        let t = Tmp::new("mdmp-many", &many);
        assert!(crate::open(&t.0).is_err());
    }
}
