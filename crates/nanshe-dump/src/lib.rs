//! Zrzuty pamięci pojedynczych procesów jako źródło dla tych samych detektorów co skan na żywo:
//! plik core systemu Linux (ELF, 64 bity) i minidump systemu Windows (MDMP).
//!
//! Plik zrzutu jest daną niezaufaną: mógł powstać na przejętej stacji albo zostać spreparowany.
//! Każde przesunięcie i każda liczba z pliku są sprawdzane względem jego długości, liczby wpisów
//! mają limity, a treść pamięci jest czytana z pliku dopiero na żądanie (zrzut nie jest ładowany w całości).
#![forbid(unsafe_code)]

mod elfcore;
mod minidump;

use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Ciągły fragment pamięci procesu zapisany w pliku: adres, długość, przesunięcie w pliku.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Seg { pub vaddr: u64, pub len: u64, pub off: u64 }

/// Wynik rozbioru nagłówków zrzutu (bez treści pamięci).
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub os: &'static str,
    pub arch: String,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub name: Option<String>,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub regions: Vec<Region>,
    pub segs: Vec<Seg>,
    pub threads: Vec<ThreadInfo>,
    pub notes: Vec<String>,
}

/// Dostęp do pliku z kontrolą zakresu. Wszystkie odczyty nagłówków idą przez tę strukturę.
pub(crate) struct Src { f: File, pub len: u64 }

impl Src {
    pub fn read(&mut self, off: u64, n: usize) -> Result<Vec<u8>> {
        let end = off.checked_add(n as u64).filter(|e| *e <= self.len)
            .ok_or_else(|| Error::Invalid(trf!("zrzut: odwołanie poza plik (przesunięcie {off:#x}, długość {n})", "dump: reference outside the file (offset {off:#x}, length {n})")))?;
        let _ = end;
        let mut b = vec![0u8; n];
        self.f.seek(SeekFrom::Start(off))?;
        self.f.read_exact(&mut b)?;
        Ok(b)
    }
}

pub(crate) fn u16le(b: &[u8], o: usize) -> Option<u16> { b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]])) }
pub(crate) fn u32le(b: &[u8], o: usize) -> Option<u32> { b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])) }
pub(crate) fn u64le(b: &[u8], o: usize) -> Option<u64> { b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().expect("8 bajtów"))) }
pub(crate) fn short() -> Error { Error::Invalid(tr!("zrzut: obcięta struktura nagłówka", "dump: truncated header structure").into()) }

/// Największy nagłówek albo tablica, jaką czytamy do pamięci naraz.
pub(crate) const MAX_TABLE: usize = 64 << 20;

/// Otwarty zrzut procesu.
pub struct Dump {
    info: SourceInfo,
    regions: Vec<Region>,
    segs: Vec<Seg>,
    threads: Vec<ThreadInfo>,
    file: RefCell<File>,
    /// Wiersz poleceń procesu, jeśli zrzut go zawiera (plik core: pierwsze 80 znaków).
    pub cmdline: Option<String>,
    pub ppid: Option<u32>,
    /// Ograniczenia tego zrzutu stwierdzone przy otwieraniu; trafiają do raportu.
    pub notes: Vec<String>,
}

/// Otwiera zrzut i rozpoznaje format po sygnaturze.
pub fn open(path: &Path) -> Result<Dump> {
    let f = File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() { return Err(Error::Invalid(tr!("zrzut nie jest zwykłym plikiem", "the dump is not a regular file").into())); }
    let mut src = Src { f, len: meta.len() };
    let magic = src.read(0, 4).map_err(|_| Error::Invalid(tr!("plik za krótki na zrzut pamięci", "file too short to be a memory dump").into()))?;
    let mut p = match magic.as_slice() {
        b"\x7fELF" => elfcore::parse(&mut src)?,
        b"MDMP" => minidump::parse(&mut src)?,
        _ => return Err(Error::Unsupported(tr!("nieznany format zrzutu (obsługiwane: plik core ELF 64-bit, minidump Windows)", "unknown dump format (supported: 64-bit ELF core file, Windows minidump)").into())),
    };
    p.segs.retain(|s| s.len > 0);
    p.segs.sort_by_key(|s| s.vaddr);
    p.regions.sort_by_key(|r| r.base);
    if p.regions.len() > MAX_REGIONS { p.regions.truncate(MAX_REGIONS); }
    let info = SourceInfo { os: p.os.into(), arch: p.arch, pid: p.pid, name: p.name, source_type: "dump".into(), exe: p.exe, exe_deleted: false, exe_verified: false };
    Ok(Dump { info, regions: p.regions, segs: p.segs, threads: p.threads, file: RefCell::new(src.f), cmdline: p.cmdline, ppid: p.ppid, notes: p.notes })
}

/// Czy w zrzucie jest treść pod danym adresem. `segs` muszą być posortowane po adresie:
/// wyszukiwanie binarne, bo liczby regionów i fragmentów pochodzą z niezaufanego pliku.
pub(crate) fn covered(segs: &[Seg], addr: u64) -> bool {
    let i = segs.partition_point(|s| s.vaddr <= addr);
    i.checked_sub(1).map(|i| addr - segs[i].vaddr < segs[i].len).unwrap_or(false)
}

/// Zakres [początek, koniec) zawierający adres, w tablicy posortowanej po początku.
pub(crate) fn range_at<T>(sorted: &[(u64, u64, T)], addr: u64) -> Option<&T> {
    let i = sorted.partition_point(|r| r.0 <= addr);
    i.checked_sub(1).and_then(|i| (addr < sorted[i].1).then(|| &sorted[i].2))
}

impl MemorySource for Dump {
    fn info(&self) -> SourceInfo { self.info.clone() }
    fn regions(&self) -> Result<Vec<Region>> { Ok(self.regions.clone()) }
    fn threads(&self) -> Vec<ThreadInfo> { self.threads.clone() }

    /// Czyta tyle, ile zrzut zawiera od podanego adresu, także przez sąsiadujące fragmenty; kończy na pierwszej luce.
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut done = 0usize;
        let mut f = self.file.borrow_mut();
        while done < buf.len() {
            let a = match addr.checked_add(done as u64) { Some(a) => a, None => break };
            // ostatni fragment zaczynający się nie dalej niż `a`
            let i = self.segs.partition_point(|s| s.vaddr <= a);
            let Some(s) = i.checked_sub(1).map(|i| self.segs[i]) else { break };
            let within = a - s.vaddr;
            if within >= s.len { break; }
            let n = ((s.len - within).min((buf.len() - done) as u64)) as usize;
            f.seek(SeekFrom::Start(s.off + within))?;
            match f.read(&mut buf[done..done + n]) { Ok(0) => break, Ok(k) => done += k, Err(e) => return Err(e.into()) }
        }
        if done == 0 && !buf.is_empty() { return Err(Error::Access(trf!("zrzut nie zawiera pamięci pod adresem {addr:#x}", "the dump contains no memory at address {addr:#x}"))); }
        Ok(done)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::io::Write;
    /// Plik tymczasowy z podaną treścią; usuwany przy zwolnieniu.
    pub struct Tmp(pub std::path::PathBuf);
    impl Tmp {
        pub fn new(name: &str, data: &[u8]) -> Tmp {
            let p = std::env::temp_dir().join(format!("nanshe-dump-test-{}-{name}", std::process::id()));
            std::fs::File::create(&p).unwrap().write_all(data).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
}

#[cfg(test)]
mod tests {
    /// Ziarna dla fuzzera: poprawne pliki z budowniczych testowych. Zapisywane tylko, gdy ustawiono NANSHE_FUZZ_SEEDS.
    #[test]
    fn fuzz_seeds() {
        let Some(dir) = std::env::var_os("NANSHE_FUZZ_SEEDS") else { return };
        let dir = std::path::Path::new(&dir).join("dump");
        std::fs::create_dir_all(&dir).unwrap();
        for machine in [62u16, 183] {
            let core = crate::elfcore::tests::core(machine, &[(0x40_0000, 0x2000, 5, vec![0x90; 0x800]), (0x7f00_0000_0000, 0x1000, 7, vec![1; 0x400])], &crate::elfcore::tests::sample_notes(machine, 0x40_0010, 0x7f00_0000_0100, 0x40_0100));
            std::fs::write(dir.join(format!("core-{machine}")), core).unwrap();
        }
        let md = crate::minidump::tests::minidump(&[(0x10_0000, 0x1000, 0x40, 0x20000, Some(vec![0x90; 0x200])), (0x7ff0_0000_0000, 0x2000, 0x20, 0x1000000, Some(vec![0x4d, 0x5a, 0, 0]))],
            &[(0x7ff0_0000_0000, 0x2000, "C:\\Windows\\System32\\a.dll")], &[(11, 0x10_0000)], 4321);
        std::fs::write(dir.join("minidump"), md).unwrap();
    }

    use super::*;

    #[test]
    fn unknown_or_short_files_are_rejected() {
        for (name, data) in [("empty", &b""[..]), ("short", &b"MD"[..]), ("text", &b"this is not a dump"[..])] {
            let t = testutil::Tmp::new(name, data);
            assert!(open(&t.0).is_err(), "{name}");
        }
    }
}
