//! Plik core systemu Linux: ELF typu ET_CORE, 64 bity, little endian (x86_64 i aarch64).
//! Segmenty PT_LOAD opisują regiony pamięci, notatki PT_NOTE niosą nazwę i numer procesu
//! (NT_PRPSINFO), rejestry wątków (NT_PRSTATUS), listę zmapowanych plików (NT_FILE) i wektor
//! pomocniczy z adresem ścieżki programu (NT_AUXV).
use crate::{covered, range_at, short, u16le, u32le, u64le, Parsed, Seg, Src, MAX_TABLE};
use nanshe_core::*;
use nanshe_core::{tr, trf};

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4c45;
const AT_EXECFN: u64 = 31;
/// Adres obrazu vdso: kod dostarczany przez jądro, bez pliku na dysku.
const AT_SYSINFO_EHDR: u64 = 33;
/// Stały adres strony vsyscall na x86_64: kod jądra widoczny w każdym procesie, bez pliku.
const VSYSCALL_X86_64: u64 = 0xffff_ffff_ff60_0000;
/// Przesunięcie tablicy rejestrów w strukturze elf_prstatus (64 bity).
const PR_REG: usize = 112;

/// Indeksy (licznik rozkazów, wskaźnik stosu) w tablicy rejestrów danej architektury.
fn reg_index(machine: u16) -> Option<(usize, usize)> {
    match machine { 62 => Some((16, 19)), 183 => Some((32, 31)), _ => None }
}

/// Limity list budowanych z notatek. Plik core jest daną niezaufaną: jeden blok notatek może być wskazany
/// przez tysiące nagłówków, a w bloku mogą być setki tysięcy minimalnych wpisów.
const MAX_THREADS: usize = 1 << 16;
const MAX_STACKS: usize = 4096;
const MAX_NAME: usize = 4096;

/// Bloki notatek do przeczytania: każdy adres w pliku najwyżej raz (największy zadeklarowany rozmiar),
/// przycięte do pliku, a łącznie nie więcej niż `budget` bajtów na cały plik. Drugi element: czy coś pominięto.
pub(crate) fn note_blocks(mut at: Vec<(u64, u64)>, file_len: u64, mut budget: u64) -> (Vec<(u64, usize)>, bool) {
    at.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    at.dedup_by_key(|n| n.0);
    let (mut out, mut limited) = (Vec::new(), false);
    for (off, size) in at {
        let size = size.min(file_len.saturating_sub(off.min(file_len)));
        if size == 0 { continue; }
        let take = size.min(budget);
        if take < size { limited = true; }
        if take == 0 { break; }
        budget -= take;
        out.push((off, take as usize));
    }
    (out, limited)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

pub(crate) fn parse(src: &mut Src) -> Result<Parsed> {
    let h = src.read(0, 64).map_err(|_| short())?;
    if h[4] != 2 || h[5] != 1 {
        return Err(Error::Unsupported(tr!("plik core: obsługiwane są tylko zrzuty 64-bitowe little endian", "core file: only 64-bit little-endian dumps are supported").into()));
    }
    if u16le(&h, 16) != Some(4) {
        return Err(Error::Unsupported(tr!("plik ELF nie jest zrzutem pamięci (typ inny niż CORE)", "the ELF file is not a memory dump (type other than CORE)").into()));
    }
    let machine = u16le(&h, 18).ok_or_else(short)?;
    let arch = match machine { 62 => "x86_64".to_string(), 183 => "aarch64".to_string(), m => format!("elf-machine-{m}") };
    let (phoff, phentsize, phnum) = (u64le(&h, 0x20).ok_or_else(short)?, u16le(&h, 0x36).ok_or_else(short)? as usize, u16le(&h, 0x38).ok_or_else(short)? as usize);
    if phnum == 0xffff {
        return Err(Error::Unsupported(tr!("plik core z ponad 65534 segmentami nie jest obsługiwany", "a core file with more than 65534 segments is not supported").into()));
    }
    if phentsize < 56 { return Err(short()); }
    let table = src.read(phoff, phentsize.checked_mul(phnum).filter(|n| *n <= MAX_TABLE).ok_or_else(short)?)?;

    let mut p = Parsed { os: "linux", arch, ..Default::default() };
    let mut notes_at: Vec<(u64, u64)> = Vec::new();
    let mut clipped = 0u32;
    for i in 0..phnum {
        let e = &table[i * phentsize..(i + 1) * phentsize];
        let (typ, flags) = (u32le(e, 0).ok_or_else(short)?, u32le(e, 4).ok_or_else(short)?);
        let (off, vaddr, filesz, memsz) = (u64le(e, 8).ok_or_else(short)?, u64le(e, 16).ok_or_else(short)?, u64le(e, 32).ok_or_else(short)?, u64le(e, 40).ok_or_else(short)?);
        match typ {
            PT_LOAD => {
                if memsz == 0 || vaddr.checked_add(memsz).is_none() { continue; }
                // treść segmentu nie może wychodzić poza plik ani poza segment
                let avail = src.len.saturating_sub(off.min(src.len));
                let present = filesz.min(memsz).min(avail);
                if present < filesz.min(memsz) { clipped += 1; }
                let prot = (if flags & 4 != 0 { Prot::R } else { 0 }) | (if flags & 2 != 0 { Prot::W } else { 0 }) | (if flags & 1 != 0 { Prot::X } else { 0 });
                p.regions.push(Region { base: vaddr, size: memsz, prot: Some(Prot(prot)), kind: RegionKind::Private, backing: None, backing_deleted: false, label: None, readable: present > 0 });
                if present > 0 { p.segs.push(Seg { vaddr, len: present, off }); }
            }
            PT_NOTE => notes_at.push((off, filesz)),
            _ => {}
        }
    }
    if clipped > 0 {
        p.notes.push(trf!("plik core jest obcięty: {clipped} segmentów ma mniej treści, niż deklaruje nagłówek", "the core file is truncated: {clipped} segments have less content than the header declares"));
    }

    let mut files: Vec<(u64, u64, String)> = Vec::new();
    let mut stacks: Vec<u64> = Vec::new();
    let mut execfn: Option<u64> = None;
    let mut vdso: Option<u64> = None;
    // Budżet bajtów notatek jest jeden na cały plik, nie na blok: nagłówki wskazujące ten sam albo nakładające
    // się fragmenty nie mogą wymusić wielokrotnego parsowania tych samych danych.
    let (blocks, mut limited) = note_blocks(notes_at, src.len, MAX_TABLE as u64);
    for (off, size) in blocks {
        let b = src.read(off, size)?;
        let mut o = 0usize;
        while o + 12 <= b.len() {
            let (namesz, descsz, typ) = (u32le(&b, o).ok_or_else(short)? as usize, u32le(&b, o + 4).ok_or_else(short)? as usize, u32le(&b, o + 8).ok_or_else(short)?);
            let name_at = o + 12;
            let Some(desc_at) = name_at.checked_add(namesz.checked_add(3).map(|n| n & !3).unwrap_or(usize::MAX)) else { break };
            let Some(next) = desc_at.checked_add(descsz.checked_add(3).map(|n| n & !3).unwrap_or(usize::MAX)) else { break };
            let (Some(name), Some(d)) = (b.get(name_at..name_at + namesz), b.get(desc_at..desc_at.saturating_add(descsz))) else { break };
            o = next;
            if cstr(name) != "CORE" { continue; }
            match typ {
                NT_PRPSINFO if d.len() >= 136 => {
                    p.pid = u32le(d, 24).filter(|x| *x > 0 && *x < i32::MAX as u32);
                    p.ppid = u32le(d, 28).filter(|x| *x > 0 && *x < i32::MAX as u32);
                    p.name = Some(cstr(&d[40..56])).filter(|s| !s.is_empty());
                    p.cmdline = Some(cstr(&d[56..136])).filter(|s| !s.is_empty());
                }
                NT_PRSTATUS => {
                    if let Some((pc_i, sp_i)) = reg_index(machine) {
                        if let (Some(tid), Some(pc), Some(sp)) = (u32le(d, 32), u64le(d, PR_REG + pc_i * 8), u64le(d, PR_REG + sp_i * 8)) {
                            if tid != 0 && pc != 0 { if p.threads.len() < MAX_THREADS { p.threads.push(ThreadInfo { tid, addr: pc }); } else { limited = true; } }
                            if stacks.len() < MAX_STACKS { stacks.push(sp); } else { limited = true; }
                        }
                    }
                }
                NT_AUXV => {
                    for pair in d.chunks_exact(16) {
                        match u64le(pair, 0) { Some(AT_EXECFN) => execfn = u64le(pair, 8), Some(AT_SYSINFO_EHDR) => vdso = u64le(pair, 8), _ => {} }
                    }
                }
                NT_FILE => {
                    let count = u64le(d, 0).unwrap_or(0).min(MAX_REGIONS as u64) as usize;
                    let names_at = 16usize.saturating_add(count.saturating_mul(24));
                    let Some(names) = d.get(names_at..) else { continue };
                    let mut it = names.split(|c| *c == 0);
                    for k in 0..count {
                        let (Some(s), Some(e), Some(n)) = (u64le(d, 16 + k * 24), u64le(d, 24 + k * 24), it.next()) else { break };
                        if files.len() >= MAX_REGIONS { limited = true; break; }
                        files.push((s, e, String::from_utf8_lossy(&n[..n.len().min(MAX_NAME)]).into_owned()));
                    }
                }
                _ => {}
            }
        }
    }
    if limited {
        p.notes.push(tr!("plik core ma więcej notatek, wątków albo zmapowanych plików, niż wynoszą limity skanera; nadmiar został pominięty, więc lista wątków i nazwy plików mogą być niepełne",
            "the core file has more notes, threads or mapped files than the scanner's limits; the excess was skipped, so the thread list and file names may be incomplete").into());
    }
    p.threads.sort_by_key(|t| t.tid);
    p.threads.dedup_by_key(|t| t.tid);

    // nazwy plików z NT_FILE i stos (region, w którym leży wskaźnik stosu któregoś wątku)
    files.sort_by_key(|f| f.0);
    p.segs.sort_by_key(|s| s.vaddr);
    for r in &mut p.regions {
        if let Some(n) = range_at(&files, r.base) {
            let (name, deleted) = match n.strip_suffix(" (deleted)") { Some(x) => (x.to_string(), true), None => (n.clone(), false) };
            // plik utworzony przez memfd_create ma w jądrze nazwę "/memfd:nazwa"
            let name = name.strip_prefix("/memfd:").map(|m| format!("memfd:{m}")).unwrap_or(name);
            r.backing_deleted = deleted || name.starts_with("memfd:");
            r.backing = Some(name);
            r.kind = RegionKind::Mapped;
        } else if machine == 62 && r.base == VSYSCALL_X86_64 && r.size == 0x1000 {
            // strona vsyscall (tylko x86_64): wykonywalna, pod stałym adresem, bez pliku. Skan na żywo zna ją
            // z etykiety w /proc/<pid>/maps; w pliku core etykiet nie ma, więc rozpoznajemy ją po adresie.
            r.label = Some("[vsyscall]".into());
        } else if vdso == Some(r.base) {
            // obraz vdso zaczyna się nagłówkiem ELF i jest wykonywalny; bez tej etykiety wyglądałby
            // jak program załadowany do pamięci anonimowej
            r.label = Some("[vdso]".into());
        } else if stacks.iter().any(|sp| *sp >= r.base && *sp - r.base < r.size) {
            r.kind = RegionKind::Stack;
        }
    }
    if files.is_empty() { p.notes.push(tr!("plik core nie zawiera listy zmapowanych plików (NT_FILE): regiony z plików są nie do odróżnienia od pamięci anonimowej", "the core file has no list of mapped files (NT_FILE): file-backed regions cannot be told apart from anonymous memory").into()); }
    if p.threads.is_empty() { p.notes.push(tr!("plik core nie zawiera rejestrów wątków w obsługiwanym układzie: wątki nie są oceniane", "the core file has no thread registers in a supported layout: threads are not assessed").into()); }

    // ścieżka programu: napis w pamięci procesu wskazany przez wektor pomocniczy
    if let Some(a) = execfn {
        if let Some(s) = p.segs.iter().find(|s| a >= s.vaddr && a - s.vaddr < s.len) {
            let n = (s.len - (a - s.vaddr)).min(4096) as usize;
            if let Ok(b) = src.read(s.off + (a - s.vaddr), n) { p.exe = Some(cstr(&b)).filter(|x| x.starts_with('/')); }
        }
    }
    let missing = p.regions.iter().filter(|r| !covered(&p.segs, r.base)).count();
    if missing > 0 {
        p.notes.push(trf!("{missing} regionów nie ma treści w zrzucie (zwykle niezmieniony kod i dane z plików, których jądro nie zapisuje): detektory treści ich nie sprawdziły", "{missing} regions have no content in the dump (usually unmodified file-backed code and data, which the kernel does not write): content detectors did not examine them"));
    }
    Ok(p)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Tmp;

    fn note(typ: u32, desc: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(5u32.to_le_bytes()); v.extend((desc.len() as u32).to_le_bytes()); v.extend(typ.to_le_bytes());
        v.extend(b"CORE\0\0\0\0");
        v.extend(desc); while v.len() % 4 != 0 { v.push(0); }
        v
    }

    /// Plik core z podanymi segmentami (adres, rozmiar w pamięci, flagi, treść) i notatkami.
    pub(crate) fn core(machine: u16, loads: &[(u64, u64, u32, Vec<u8>)], notes: &[u8]) -> Vec<u8> {
        let phnum = loads.len() + 1;
        let mut data_off = (64 + phnum * 56) as u64;
        let mut ph = Vec::new();
        let mut body = Vec::new();
        let mut entry = |typ: u32, flags: u32, vaddr: u64, memsz: u64, content: &[u8], ph: &mut Vec<u8>, body: &mut Vec<u8>| {
            ph.extend(typ.to_le_bytes()); ph.extend(flags.to_le_bytes()); ph.extend(data_off.to_le_bytes()); ph.extend(vaddr.to_le_bytes());
            ph.extend(0u64.to_le_bytes()); ph.extend((content.len() as u64).to_le_bytes()); ph.extend(memsz.to_le_bytes()); ph.extend(0x1000u64.to_le_bytes());
            body.extend(content); data_off += content.len() as u64;
        };
        entry(PT_NOTE, 0, 0, 0, notes, &mut ph, &mut body);
        for (vaddr, memsz, flags, content) in loads { entry(PT_LOAD, *flags, *vaddr, *memsz, content, &mut ph, &mut body); }
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF"); h[4] = 2; h[5] = 1; h[6] = 1;
        h[16..18].copy_from_slice(&4u16.to_le_bytes()); h[18..20].copy_from_slice(&machine.to_le_bytes());
        h[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); h[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); h[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());
        h.extend(ph); h.extend(body);
        h
    }

    pub(crate) fn sample_notes(machine: u16, pc: u64, sp: u64, execfn: u64) -> Vec<u8> {
        let mut ps = vec![0u8; 136];
        ps[24..28].copy_from_slice(&4321u32.to_le_bytes()); ps[28..32].copy_from_slice(&1u32.to_le_bytes());
        ps[40..46].copy_from_slice(b"sample"); ps[56..71].copy_from_slice(b"sample --mode x");
        let (pc_i, sp_i) = reg_index(machine).unwrap();
        let mut st = vec![0u8; PR_REG + 34 * 8];
        st[32..36].copy_from_slice(&4321u32.to_le_bytes());
        st[PR_REG + pc_i * 8..PR_REG + pc_i * 8 + 8].copy_from_slice(&pc.to_le_bytes());
        st[PR_REG + sp_i * 8..PR_REG + sp_i * 8 + 8].copy_from_slice(&sp.to_le_bytes());
        let mut aux = Vec::new(); aux.extend(AT_EXECFN.to_le_bytes()); aux.extend(execfn.to_le_bytes()); aux.extend(AT_SYSINFO_EHDR.to_le_bytes()); aux.extend(0x7ffd_0000_0000u64.to_le_bytes()); aux.extend([0u8; 16]);
        let mut nf = Vec::new();
        nf.extend(2u64.to_le_bytes()); nf.extend(0x1000u64.to_le_bytes());
        for (s, e) in [(0x40_0000u64, 0x40_2000u64), (0x7f00_0000_0000, 0x7f00_0000_2000)] { nf.extend(s.to_le_bytes()); nf.extend(e.to_le_bytes()); nf.extend(0u64.to_le_bytes()); }
        nf.extend(b"/usr/bin/sample\0/memfd:payload (deleted)\0");
        [note(NT_PRPSINFO, &ps), note(NT_PRSTATUS, &st), note(NT_AUXV, &aux), note(NT_FILE, &nf)].concat()
    }

    #[test]
    fn core_file_gives_regions_threads_names_and_memory() {
        for machine in [62u16, 183] {
            let mut stack = vec![0u8; 0x2000];
            stack[0x100..0x110].copy_from_slice(b"/usr/bin/sample\0");
            let loads = vec![
                (0x40_0000u64, 0x2000u64, 5u32, vec![]),                       // kod z pliku: bez treści w zrzucie
                (0x10_0000, 0x3000, 7, vec![0xAA; 0x1000]),                     // rwx, treść tylko w części
                (0x7f00_0000_0000, 0x2000, 5, vec![0xCC; 0x2000]),              // memfd
                (0x7ffc_0000_0000, 0x2000, 6, stack),
                (0x7ffd_0000_0000, 0x1000, 5, b"\x7fELF".to_vec()),             // vdso: wykonywalny, z nagłówkiem ELF, bez pliku
                (0x7ffe_0000_0000, 0x1000, 5, b"\x7fELF".to_vec()),             // to samo bez wpisu w wektorze pomocniczym (kontrola)
                (VSYSCALL_X86_64, 0x1000, 5, vec![]),                          // strona vsyscall: etykieta tylko na x86_64
            ];
            let bytes = core(machine, &loads, &sample_notes(machine, 0x10_0040, 0x7ffc_0000_0800, 0x7ffc_0000_0100));
            let t = Tmp::new(&format!("core-{machine}"), &bytes);
            let d = crate::open(&t.0).unwrap();
            let i = d.info();
            assert_eq!((i.os.as_str(), i.pid, i.name.as_deref(), i.exe.as_deref(), i.source_type.as_str(), i.exe_verified), ("linux", Some(4321), Some("sample"), Some("/usr/bin/sample"), "dump", false), "{machine}");
            assert_eq!(i.arch, if machine == 62 { "x86_64" } else { "aarch64" });
            assert_eq!((d.cmdline.as_deref(), d.ppid), (Some("sample --mode x"), Some(1)));
            let r = d.regions().unwrap();
            assert_eq!(r.iter().map(|x| x.base).collect::<Vec<_>>(), vec![0x10_0000, 0x40_0000, 0x7f00_0000_0000, 0x7ffc_0000_0000, 0x7ffd_0000_0000, 0x7ffe_0000_0000, VSYSCALL_X86_64]);
            let by = |base: u64| r.iter().find(|x| x.base == base).unwrap();
            assert_eq!((by(0x10_0000).prot.unwrap().to_string(), by(0x10_0000).kind, by(0x10_0000).readable), ("rwx".to_string(), RegionKind::Private, true));
            assert_eq!((by(0x40_0000).backing.as_deref(), by(0x40_0000).kind, by(0x40_0000).readable, by(0x40_0000).backing_deleted), (Some("/usr/bin/sample"), RegionKind::Mapped, false, false));
            assert_eq!((by(0x7f00_0000_0000).backing.as_deref(), by(0x7f00_0000_0000).backing_deleted), (Some("memfd:payload"), true));
            assert_eq!(by(0x7ffc_0000_0000).kind, RegionKind::Stack);
            assert_eq!(by(VSYSCALL_X86_64).label.as_deref(), if machine == 62 { Some("[vsyscall]") } else { None }, "{machine}");
            assert_eq!((by(0x7ffd_0000_0000).label.as_deref(), by(0x7ffe_0000_0000).label.as_deref()), (Some("[vdso]"), None));
            assert_eq!(d.threads(), vec![ThreadInfo { tid: 4321, addr: 0x10_0040 }]);
            // odczyt: tyle, ile jest w zrzucie; luka kończy odczyt; brak treści to błąd, a nie zera
            let mut buf = vec![0u8; 0x3000];
            assert_eq!(d.read_at(0x10_0000, &mut buf).unwrap(), 0x1000);
            assert!(buf[..0x1000].iter().all(|b| *b == 0xAA));
            assert_eq!(d.read_at(0x10_0ff0, &mut buf[..0x20]).unwrap(), 0x10);
            assert!(d.read_at(0x40_0000, &mut buf).is_err() && d.read_at(0x10_1000, &mut buf).is_err() && d.read_at(u64::MAX, &mut buf).is_err());
            assert!(d.notes.iter().any(|n| n.contains("2 regionów nie ma treści")), "{:?}", d.notes);
        }
    }

    #[test]
    fn note_blocks_are_read_once_and_within_one_budget() {
        // ten sam adres wskazany wiele razy: jeden blok, o największym zadeklarowanym rozmiarze, przycięty do pliku
        assert_eq!(note_blocks(vec![(100, 50), (100, 400), (100, 10)], 300, 1 << 20), (vec![(100, 200)], false));
        // nakładające się bloki pod różnymi adresami: łącznie nie więcej niż budżet, reszta pominięta i odnotowana
        let overlapping: Vec<(u64, u64)> = (0..1000u64).map(|i| (i, 1 << 20)).collect();
        let (blocks, limited) = note_blocks(overlapping, 1 << 20, 3 << 20);
        assert!(limited && blocks.iter().map(|b| b.1 as u64).sum::<u64>() <= 3 << 20 && blocks.len() <= 4, "{}", blocks.len());
        // bloki puste, poza plikiem i zerowy budżet
        assert_eq!(note_blocks(vec![(10, 0), (5000, 100), (u64::MAX, u64::MAX)], 1000, 1 << 20), (vec![], false));
        assert_eq!(note_blocks(vec![(0, 100)], 1000, 0), (vec![], true));
    }

    /// Plik core, w którym `headers` nagłówków PT_NOTE wskazuje ten sam blok z `threads` minimalnymi wpisami wątków
    /// i jedną listą `files` zmapowanych plików. Bez limitów praca i pamięć rosły jak headers x zawartość bloku.
    fn amplified(headers: usize, threads: u32, files: u64) -> Vec<u8> {
        let (pc_i, _) = reg_index(62).unwrap();
        let mut block = Vec::new();
        for t in 1..=threads {
            let mut st = vec![0u8; PR_REG + 34 * 8];
            st[32..36].copy_from_slice(&t.to_le_bytes());
            st[PR_REG + pc_i * 8..PR_REG + pc_i * 8 + 8].copy_from_slice(&0x40_0000u64.to_le_bytes());
            block.extend(note(NT_PRSTATUS, &st));
        }
        let mut nf = Vec::new();
        nf.extend(files.to_le_bytes()); nf.extend(0x1000u64.to_le_bytes());
        for k in 0..files { nf.extend((k * 0x1000).to_le_bytes()); nf.extend((k * 0x1000 + 0x1000).to_le_bytes()); nf.extend(0u64.to_le_bytes()); }
        for _ in 0..files { nf.extend(b"/x\0"); }
        block.extend(note(NT_FILE, &nf));
        let data_off = (64 + headers * 56) as u64;
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF"); h[4] = 2; h[5] = 1; h[6] = 1;
        h[16..18].copy_from_slice(&4u16.to_le_bytes()); h[18..20].copy_from_slice(&62u16.to_le_bytes());
        h[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); h[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); h[0x38..0x3a].copy_from_slice(&(headers as u16).to_le_bytes());
        for _ in 0..headers {
            h.extend(PT_NOTE.to_le_bytes()); h.extend(0u32.to_le_bytes()); h.extend(data_off.to_le_bytes()); h.extend(0u64.to_le_bytes());
            h.extend(0u64.to_le_bytes()); h.extend((block.len() as u64).to_le_bytes()); h.extend(0u64.to_le_bytes()); h.extend(4u64.to_le_bytes());
        }
        h.extend(block);
        h
    }

    #[test]
    fn repeated_note_headers_do_not_multiply_work_or_memory() {
        // 65534 nagłówki wskazujące jeden blok z 2000 wątków: blok jest parsowany raz
        let t = Tmp::new("core-amp", &amplified(65534, 2000, 50));
        let started = std::time::Instant::now();
        let d = crate::open(&t.0).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        assert_eq!(d.threads().len(), 2000);
        assert!(!d.notes.iter().any(|n| n.contains("limity")), "{:?}", d.notes);
        // więcej wpisów niż limit: listy są obcinane w trakcie budowania, a wynik to mówi
        let t = Tmp::new("core-many", &amplified(3, MAX_THREADS as u32 + 500, 10));
        let d = crate::open(&t.0).unwrap();
        assert_eq!(d.threads().len(), MAX_THREADS);
        assert!(d.notes.iter().any(|n| n.contains("limity")), "{:?}", d.notes);
    }

    #[test]
    fn hostile_headers_do_not_panic_or_read_outside_the_file() {
        let good = core(62, &[(0x10_0000, 0x1000, 7, vec![1; 0x1000])], &sample_notes(62, 0x10_0000, 0, 0));
        // segment deklarujący treść poza plikiem: przycięty i odnotowany
        let mut big = good.clone();
        let ph = 64 + 56; // drugi wpis (PT_LOAD)
        big[ph + 32..ph + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        big[ph + 40..ph + 48].copy_from_slice(&0x10_0000u64.to_le_bytes());
        let t = Tmp::new("core-big", &big);
        let d = crate::open(&t.0).unwrap();
        let mut buf = vec![0u8; 0x4000];
        assert_eq!(d.read_at(0x10_0000, &mut buf).unwrap(), 0x1000, "tylko to, co jest w pliku");
        assert!(d.notes.iter().any(|n| n.contains("obcięty")));
        // tablica segmentów poza plikiem, zły typ, 32 bity, każde obcięcie pliku: błąd albo wynik, nigdy panika
        let mut far = good.clone(); far[0x20..0x28].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        let mut exec = good.clone(); exec[16] = 2;
        let mut c32 = good.clone(); c32[4] = 1;
        for (name, data) in [("far", far), ("exec", exec), ("c32", c32)] {
            let t = Tmp::new(&format!("core-{name}"), &data);
            assert!(crate::open(&t.0).is_err(), "{name}");
        }
        for cut in (0..good.len()).step_by(7) {
            let t = Tmp::new("core-cut", &good[..cut]);
            if let Ok(d) = crate::open(&t.0) { let _ = d.regions(); let _ = d.read_at(0x10_0000, &mut buf); }
        }
        // notatka z rozmiarem przepełniającym licznik
        let mut n = good.clone();
        let notes_off = 64 + 2 * 56;
        n[notes_off + 4..notes_off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let t = Tmp::new("core-note", &n);
        let d = crate::open(&t.0).unwrap();
        assert_eq!(d.info().pid, None, "uszkodzona notatka jest pomijana");
    }
}
