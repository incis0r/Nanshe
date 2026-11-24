//! Backendy żywych procesów. Wyłącznie odczyt (Z1).
//! Linux: /proc/<pid>/maps + /proc/<pid>/mem (bez `unsafe`, bez zatrzymywania procesu).
//! Windows: OpenProcess + VirtualQueryEx + ReadProcessMemory (`unsafe` tylko w module `windows`).
#![deny(unsafe_code)]

pub mod maps;
pub mod pediff;
pub mod sysctx;
pub mod wintables;
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod windows;

/// Metadane pliku potrzebne do weryfikacji programu: (uid, tryb, urządzenie, i-węzeł).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FileId { pub uid: u32, pub mode: u32, pub dev: u64, pub ino: u64 }

/// Czy plik programu badanego procesu można uznać za systemowy.
/// `actual`: plik faktycznie uruchomiony (przez /proc/<pid>/exe, niezależnie od przestrzeni
/// montowań procesu). `at_path`: plik pod tą samą ścieżką widziany przez skaner.
/// Ścieżka z innej przestrzeni montowań (kontener) wskaże inny plik albo żaden.
pub fn exe_is_trusted(actual: Option<FileId>, at_path: Option<FileId>) -> bool {
    match (actual, at_path) {
        (Some(a), Some(p)) => a.uid == 0 && a.mode & 0o022 == 0 && a.dev == p.dev && a.ino == p.ino,
        _ => false,
    }
}

/// Ta sama przestrzeń nazw: oba dowiązania przeczytane i równe. Nieczytelne dowiązanie to brak potwierdzenia.
pub fn same_namespace<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

use nanshe_core::*;
#[allow(unused_imports)]
use nanshe_core::{tr, trf};

#[derive(Clone, Debug)]
pub struct ProcEntry { pub pid: u32, pub name: String }

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::os::unix::fs::FileExt;

    pub struct LinuxProcess { pid: u32, name: Option<String>, exe: Option<String>, exe_deleted: bool, exe_verified: bool, mem: fs::File,
        /// strony anonimowe wg smaps, wczytywane przy pierwszym pytaniu o zmieniony kod
        anon: std::cell::OnceCell<std::collections::HashMap<u64, crate::sysctx::SmapsEntry>> }

    fn map_err(pid: u32, e: std::io::Error) -> Error {
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => Error::Access(trf!("pid {pid}: {e} (root lub CAP_SYS_PTRACE; kernel.yama.ptrace_scope)", "pid {pid}: {e} (root or CAP_SYS_PTRACE; kernel.yama.ptrace_scope)")),
            std::io::ErrorKind::NotFound => Error::NotFound(format!("pid {pid}")),
            // ESRCH: proces zakończył się między listą a otwarciem (albo nie ma pamięci użytkownika)
            _ if e.raw_os_error() == Some(3) => Error::NotFound(format!("pid {pid}")),
            _ => Error::Io(e),
        }
    }

    impl LinuxProcess {
        pub fn open(pid: u32) -> Result<Self> {
            let mem = fs::File::open(format!("/proc/{pid}/mem")).map_err(|e| map_err(pid, e))?;
            let name = fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim_end().to_string());
            let link = fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
            let (exe, exe_deleted) = match link {
                Some(l) => match l.strip_suffix(" (deleted)") { Some(s) => (Some(s.to_string()), true), None => (Some(l), false) },
                None => (None, false),
            };
            use std::os::unix::fs::MetadataExt;
            let id = |m: fs::Metadata| FileId { uid: m.uid(), mode: m.mode(), dev: m.dev(), ino: m.ino() };
            // metadata() podąża za dowiązaniem /proc/<pid>/exe do faktycznego pliku programu
            let actual = fs::metadata(format!("/proc/{pid}/exe")).ok().map(id);
            let at_path = exe.as_deref().and_then(|p| fs::metadata(p).ok()).map(id);
            // Proces w innej przestrzeni nazw użytkowników niż skaner mógł sam (bez uprawnień) zbudować sobie
            // prywatny widok systemu plików: zamontować własny katalog w miejscu /usr i podać w mapie ścieżki,
            // które wyglądają na systemowe. Taki proces nie jest "potwierdzony", choć jego plik programu się zgadza.
            let ns = |who: &str| fs::read_link(format!("/proc/{who}/ns/user")).ok();
            let same_user_ns = same_namespace(ns(&pid.to_string()), ns("self"));
            let exe_verified = !exe_deleted && same_user_ns && exe_is_trusted(actual, at_path);
            Ok(LinuxProcess { pid, name, exe, exe_deleted, exe_verified, mem, anon: std::cell::OnceCell::new() })
        }
    }

    impl MemorySource for LinuxProcess {
        fn info(&self) -> SourceInfo {
            SourceInfo { os: "linux".into(), arch: std::env::consts::ARCH.into(), pid: Some(self.pid), name: self.name.clone(), source_type: "live".into(), exe: self.exe.clone(), exe_deleted: self.exe_deleted, exe_verified: self.exe_verified }
        }
        fn regions(&self) -> Result<Vec<Region>> {
            let s = fs::read_to_string(format!("/proc/{}/maps", self.pid)).map_err(|e| map_err(self.pid, e))?;
            Ok(maps::parse_maps(&s))
        }
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
            Ok(self.mem.read_at(buf, addr)?)
        }
        fn threads(&self) -> Vec<ThreadInfo> {
            let Ok(dir) = fs::read_dir(format!("/proc/{}/task", self.pid)) else { return Vec::new() };
            let mut v: Vec<ThreadInfo> = dir.flatten().filter_map(|e| {
                let tid: u32 = e.file_name().to_str()?.parse().ok()?;
                let line = fs::read_to_string(e.path().join("syscall")).ok()?;
                Some(ThreadInfo { tid, addr: crate::sysctx::syscall_pc(&line)? })
            }).collect();
            v.sort_by_key(|t| t.tid);
            v
        }
        /// Kod z pliku, w którym proces ma strony anonimowe (zapisane): treść pamięci jest porównywana
        /// z plikiem. Plik jest otwierany przez /proc/<pid>/map_files (dokładnie ten zmapowany, także
        /// usunięty), a gdy to niedostępne, po ścieżce, o ile urządzenie i i-węzeł zgadzają się z mapą.
        fn modified_code(&self, r: &Region) -> Option<CodeChange> {
            let map = self.anon.get_or_init(|| fs::read_to_string(format!("/proc/{}/smaps", self.pid)).map(|s| crate::sysctx::smaps_anonymous(&s)).unwrap_or_default());
            let e = map.get(&r.base).filter(|e| e.anonymous > 0)?;
            // bez porównania: wiadomo tylko, ile stron zapisano; adresem znaleziska jest początek mapowania
            let unverified = Some(CodeChange { bytes: e.anonymous, first: r.base, compared: false, verified: false });
            if r.size > crate::sysctx::MAX_COMPARE_BYTES { return unverified; }
            let dev_of = |d: u64| format!("{:02x}:{:02x}", ((d >> 8) & 0xfff) | ((d >> 32) & !0xfff), (d & 0xff) | ((d >> 12) & !0xff));
            let via_map = format!("/proc/{}/map_files/{:x}-{:x}", self.pid, r.base, r.base.saturating_add(r.size));
            let file = crate::sysctx::read_file_range(&via_map, e.offset, r.size).ok().map(|x| x.0).or_else(|| {
                let path = r.backing.as_deref().filter(|p| p.starts_with('/') && !r.backing_deleted)?;
                let (data, dev, ino) = crate::sysctx::read_file_range(path, e.offset, r.size).ok()?;
                // plik pod tą ścieżką w systemie skanera musi być tym samym plikiem co w mapie procesu
                (ino == e.inode && dev_of(dev) == e.dev).then_some(data)
            });
            let Some(file) = file else { return unverified };
            let mut mem = vec![0u8; r.size as usize];
            let mut got = 0usize;
            while got < mem.len() {
                match self.mem.read_at(&mut mem[got..], r.base + got as u64) { Ok(0) | Err(_) => break, Ok(n) => got += n }
            }
            // niepełny odczyt regionu: nieodczytana część mogła się różnić, więc wynik porównania nie jest wiążący
            if got < mem.len() { return unverified; }
            let (n, first) = crate::sysctx::count_diff(&mem, &file);
            // plik otwarty przez map_files albo o zgodnym urządzeniu i i-węźle to ten sam plik, który jest zmapowany
            Some(CodeChange { bytes: n, first: r.base + first.unwrap_or(0) as u64, compared: true, verified: true })
        }
    }

    pub fn list() -> Result<Vec<ProcEntry>> {
        let mut v = Vec::new();
        for e in fs::read_dir("/proc")? {
            let e = e?;
            if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                // wątki jądra nie mają pamięci użytkownika: nie są procesami do skanowania
                if fs::read_to_string(format!("/proc/{pid}/stat")).map(|s| crate::sysctx::is_kernel_thread(&s)).unwrap_or(false) { continue; }
                let name = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim_end().to_string();
                v.push(ProcEntry { pid, name });
            }
        }
        v.sort_by_key(|p| p.pid);
        Ok(v)
    }
}

#[cfg(target_os = "linux")]
pub fn open_process(pid: u32) -> Result<Box<dyn MemorySource>> {
    Ok(Box::new(linux::LinuxProcess::open(pid)?))
}
#[cfg(target_os = "linux")]
pub fn list_processes() -> Result<Vec<ProcEntry>> { linux::list() }

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub fn open_process(pid: u32) -> Result<Box<dyn MemorySource>> {
    Ok(Box::new(macos::MacProcess::open(pid)?))
}
#[cfg(target_os = "macos")]
pub fn list_processes() -> Result<Vec<ProcEntry>> { macos::list() }

#[cfg(windows)]
pub fn open_process(pid: u32) -> Result<Box<dyn MemorySource>> {
    Ok(Box::new(windows::WinProcess::open(pid)?))
}
#[cfg(windows)]
pub fn list_processes() -> Result<Vec<ProcEntry>> { windows::list() }

/// Przygotowanie skanera przed pierwszym otwarciem procesu. Zwraca ostrzeżenie, jeśli się nie udało.
pub fn prepare() -> Option<String> {
    #[cfg(windows)]
    if !windows::enable_debug_privilege() {
        return Some(tr!("nie udało się włączyć SeDebugPrivilege (uruchom jako administrator); część procesów będzie niedostępna", "could not enable SeDebugPrivilege (run as administrator); some processes will be inaccessible").into());
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn open_process(_pid: u32) -> Result<Box<dyn MemorySource>> {
    Err(Error::Unsupported(trf!("skan żywego procesu na {} nie jest jeszcze zaimplementowany (etap M3: macOS, FreeBSD)", "live process scanning on {} is not implemented yet (stage M3: macOS, FreeBSD)", std::env::consts::OS)))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn list_processes() -> Result<Vec<ProcEntry>> {
    Err(Error::Unsupported(trf!("lista procesów na {} nie jest jeszcze zaimplementowana", "process listing on {} is not implemented yet", std::env::consts::OS)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exe_trust_requires_every_condition() {
        let good = FileId { uid: 0, mode: 0o100755, dev: 8, ino: 100 };
        assert!(exe_is_trusted(Some(good), Some(good)));
        // każda pojedyncza zmiana musi odebrać zaufanie
        assert!(!exe_is_trusted(Some(FileId { uid: 1000, ..good }), Some(good)), "właściciel inny niż root");
        assert!(!exe_is_trusted(Some(FileId { mode: 0o100775, ..good }), Some(good)), "zapisywalny dla grupy");
        assert!(!exe_is_trusted(Some(FileId { mode: 0o100757, ..good }), Some(good)), "zapisywalny dla innych");
        assert!(!exe_is_trusted(Some(FileId { ino: 101, ..good }), Some(good)), "inny plik pod tą samą ścieżką (kontener)");
        assert!(!exe_is_trusted(Some(FileId { dev: 9, ..good }), Some(good)), "inne urządzenie");
        assert!(!exe_is_trusted(Some(good), None), "ścieżka nie istnieje u skanera");
        assert!(!exe_is_trusted(None, Some(good)));
        // przestrzeń nazw użytkowników: potwierdzenie tylko przy dwóch przeczytanych, równych dowiązaniach
        assert!(same_namespace(Some("user:[4026531837]"), Some("user:[4026531837]")));
        assert!(!same_namespace(Some("user:[4026532999]"), Some("user:[4026531837]")), "proces we własnej przestrzeni nazw");
        assert!(!same_namespace(None, Some("user:[4026531837]")) && !same_namespace(Some("x"), None) && !same_namespace::<&str>(None, None), "nieczytelne dowiązanie");
    }
}

pub fn hostname() -> String {
    #[cfg(target_os = "macos")]
    if let Some(h) = macos::hostname() { return h; }
    std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown".into())
}

/// Mapa bez odczytu zawartości pamięci. Nie uruchamia detektorów.
pub fn process_memory(p: ProcEntry) -> ProcessMemory {
    let mut out = ProcessMemory { pid: p.pid, name: p.name, exe: None, regions: vec![], error: None, notes: vec![] };
    #[cfg(target_os = "linux")]
    {
        if out.name.is_empty() {
            out.name = std::fs::read_to_string(format!("/proc/{}/comm", out.pid)).unwrap_or_default().trim_end().to_string();
        }
        out.exe = std::fs::read_link(format!("/proc/{}/exe", out.pid)).ok()
            .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string());
        match std::fs::read_to_string(format!("/proc/{}/smaps", out.pid)) {
            Ok(s) => out.regions = maps::parse_smaps(&s),
            Err(e) => {
                out.notes.push(trf!("smaps niedostępne: {e}; RSS/PSS nieznane", "smaps unavailable: {e}; RSS/PSS unknown"));
                match std::fs::read_to_string(format!("/proc/{}/maps", out.pid)) {
                    Ok(s) => out.regions = maps::mapped_regions(&s),
                    Err(e) => out.error = Some(trf!("mapa niedostępna: {e}", "map unavailable: {e}")),
                }
            }
        }
    }
    #[cfg(windows)]
    {
        match windows::WinProcess::open(out.pid) {
            Ok(src) => {
                let info = src.info();
                if out.name.is_empty() { out.name = info.name.unwrap_or_default(); }
                out.exe = info.exe;
                match src.regions() {
                    Ok(r) => out.regions = r.into_iter().map(Into::into).collect(),
                    Err(e) => out.error = Some(e.to_string()),
                }
            }
            Err(e) => out.error = Some(e.to_string()),
        }
        out.notes.push(tr!("Tylko MEM_COMMIT; RSS/PSS nieznane. Nazwy mapowań mogą być ścieżkami urządzeń NT; brak nazwy nie oznacza pamięci anonimowej.", "MEM_COMMIT only; RSS/PSS unknown. Mapping names may be NT device paths; a missing name does not mean anonymous memory.").into());
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    { out.error = Some("backend mapowania tego systemu nie jest zaimplementowany".into()); }
    out
}

/// Obraz hosta zebrany raz na skan; z niego powstaje kontekst systemowy procesów (wyłącznie odczyt).
#[cfg(target_os = "linux")]
pub use sysctx::Snapshot;
#[cfg(windows)]
pub use windows::Snapshot;
#[cfg(not(any(target_os = "linux", windows)))]
pub struct Snapshot;
#[cfg(not(any(target_os = "linux", windows)))]
impl Snapshot {
    pub fn take() -> Self { Snapshot }
    pub fn host(&self) -> HostContext { HostContext::default() }
    pub fn context(&self, _pid: u32) -> ProcessContext { ProcessContext { notes: vec!["kontekst systemowy nie jest zbierany na tym systemie".into()], ..Default::default() } }
}

/// Skróty SHA-256 plików z badanej stacji, każdy plik liczony raz na skan. Wyłącznie odczyt.
/// Kluczem jest ścieżka pokazywana w wyniku; plik otwierany jest drogą, która prowadzi do
/// faktycznie użytego pliku (Linux: /proc/<pid>/exe i map_files, także dla plików usuniętych
/// i z innej przestrzeni montowań; Windows: ścieżka urządzenia przez \\?\GLOBALROOT).
#[derive(Default)]
pub struct HashCache { files: std::collections::BTreeMap<String, FileHash> }

impl HashCache {
    /// Liczy skrót pierwszą drogą, która się otworzy. `ways`: (ścieżka do otwarcia, adnotacja do wyniku).
    /// Na Windows ścieżki sieciowe nie są otwierane: skaner działa z wysokimi uprawnieniami, a ścieżkę
    /// podaje badany proces, więc otwarcie wysłałoby poświadczenia komputera na obcy serwer.
    fn add(&mut self, shown: String, ways: &[(String, Option<&str>)]) {
        if self.files.contains_key(&shown) { return; }
        let mut last_err = String::from(tr!("brak drogi dostępu", "no access path"));
        for (open, note) in ways {
            #[cfg(windows)]
            if !windows::path_is_local(open) { last_err = tr!("zasób sieciowy albo urządzenie inne niż dysk; skaner go nie otwiera", "network share or a device other than a disk; the scanner does not open it").into(); continue; }
            match sysctx::sha256_open(open) {
                Ok(h) => {
                    let note = h.why.or_else(|| note.map(String::from));
                    self.files.insert(shown.clone(), FileHash { path: shown, size: h.size, sha256: h.sha256, note });
                    return;
                }
                Err(e) => last_err = e,
            }
        }
        self.files.insert(shown.clone(), FileHash { path: shown, size: 0, sha256: None, note: Some(trf!("plik niedostępny: {last_err}", "file inaccessible: {last_err}")) });
    }

    /// Plik programu procesu.
    pub fn exe(&mut self, pid: u32, exe: Option<&str>) {
        let Some(exe) = exe else { return };
        let open = if cfg!(target_os = "linux") { format!("/proc/{pid}/exe") } else { exe.to_string() };
        self.add(exe.to_string(), &[(open, None)]);
    }

    /// Pliki zmapowane do pamięci procesu (z pełnej mapy regionów).
    pub fn modules(&mut self, pid: u32, layout: &[Region]) {
        for r in layout {
            let Some(b) = r.backing.as_deref() else { continue };
            // plik tylko w pamięci albo usunięty istnieje wyłącznie w tym procesie: klucz z numerem procesu
            let private = b.starts_with("memfd:") || r.backing_deleted;
            let shown = if private { trf!("{b} (proces {pid})", "{b} (process {pid})") } else { b.to_string() };
            if self.files.contains_key(&shown) { continue; }
            let mut ways: Vec<(String, Option<&str>)> = Vec::new();
            if cfg!(target_os = "linux") {
                // map_files prowadzi do faktycznie zmapowanego pliku, ale wymaga pełnych uprawnień;
                // droga zapasowa to ścieżka widziana przez skaner, która w kontenerze może wskazać inny plik
                ways.push((format!("/proc/{pid}/map_files/{:x}-{:x}", r.base, r.base.saturating_add(r.size)), None));
                if !private { ways.push((b.to_string(), Some(tr!("skrót pliku pod tą ścieżką w systemie skanera (bez dostępu do map_files); dla procesu w kontenerze może to być inny plik", "hash of the file at this path in the scanner's system (no access to map_files); for a process in a container this may be a different file")))); }
            } else if b.starts_with("\\Device\\") { ways.push((format!("\\\\?\\GLOBALROOT{b}"), None)); } else { ways.push((b.to_string(), None)); }
            self.add(shown, &ways);
        }
    }

    pub fn into_files(self) -> Vec<FileHash> { self.files.into_values().collect() }
}
