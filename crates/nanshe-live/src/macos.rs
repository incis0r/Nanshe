//! Backend macOS: mapa regionów przez `mach_vm_region_recurse`, odczyt przez `mach_vm_read_overwrite`.
//! Wyłącznie odczyt. Dostęp do cudzego procesu wymaga portu zadania (`task_for_pid`): uprawnień root,
//! a procesów chronionych przez SIP i programów z utwardzonym środowiskiem system nie udostępnia wcale.

// Wywołania systemowe Mach i libproc nie mają bezpiecznych odpowiedników w bibliotece standardowej.
#![allow(unsafe_code)]

use nanshe_core::{tr, trf, Error, MemorySource, Prot, Region, RegionKind, Result, SourceInfo};
use std::ffi::c_void;

/// `vm_region_submap_info_64` z `<mach/vm_region.h>` (układ z `#pragma pack(4)`).
#[repr(C, packed(4))]
#[derive(Clone, Copy, Default)]
pub(crate) struct SubmapInfo {
    protection: i32, max_protection: i32, inheritance: u32, offset: u64, user_tag: u32,
    pages_resident: u32, pages_shared_now_private: u32, pages_swapped_out: u32, pages_dirtied: u32,
    ref_count: u32, shadow_depth: u16, external_pager: u8, share_mode: u8, is_submap: u32,
    behavior: i32, object_id: u32, user_wired_count: u16, pages_reusable: u32, object_id_full: u64,
}
const INFO_COUNT: u32 = (std::mem::size_of::<SubmapInfo>() / 4) as u32;

extern "C" {
    static mach_task_self_: u32;
    fn task_for_pid(target: u32, pid: i32, task: *mut u32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn mach_vm_region_recurse(task: u32, address: *mut u64, size: *mut u64, depth: *mut u32, info: *mut SubmapInfo, count: *mut u32) -> i32;
    fn mach_vm_read_overwrite(task: u32, address: u64, size: u64, data: u64, out_size: *mut u64) -> i32;
    fn proc_listallpids(buffer: *mut c_void, size: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut c_void, size: u32) -> i32;
    fn proc_name(pid: i32, buffer: *mut c_void, size: u32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, size: i32) -> i32;
    fn gethostname(name: *mut u8, len: usize) -> i32;
    fn _dyld_get_shared_cache_range(length: *mut usize) -> *const c_void;
    fn dyld_shared_cache_file_path() -> *const std::ffi::c_char;
}

/// `PROC_PIDREGIONPATHINFO`: opis regionu zawierającego adres razem ze ścieżką jego pliku (pustą dla pamięci
/// bez pliku). `proc_regionfilename` się do tego nie nadaje: dla regionu bez pliku zwraca ścieżkę następnego
/// regionu z plikiem (zaobserwowane: anonimowy region próbki opisany jako /usr/lib/dyld).
const PROC_PIDREGIONPATHINFO: i32 = 8;
/// Rozmiar `struct proc_regionwithpathinfo` i położenie pól, z `<sys/proc_info.h>`.
const REGION_PATH_INFO_SIZE: usize = 96 + 152 + 1024;
const PRI_ADDRESS_OFFSET: usize = 80;
const VIP_PATH_OFFSET: usize = 96 + 152;
pub(crate) const SHARED_CACHE_LABEL: &str = "[dyld shared cache]";

/// Ścieżka pliku regionu zaczynającego się pod `addr`; None dla pamięci bez pliku albo gdy jądro opisało inny region.
pub(crate) fn file_of(info: &[u8], addr: u64) -> Option<String> {
    if info.len() < REGION_PATH_INFO_SIZE { return None; }
    let found = u64::from_le_bytes(info[PRI_ADDRESS_OFFSET..PRI_ADDRESS_OFFSET + 8].try_into().ok()?);
    if found != addr { return None; }
    let path = &info[VIP_PATH_OFFSET..];
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    (end > 0 && path[0] == b'/').then(|| String::from_utf8_lossy(&path[..end]).into_owned())
}

/// Zakres wspólnej pamięci bibliotek systemowych (dyld shared cache) i ścieżka jej pliku. System mapuje ją
/// pod tym samym adresem we wszystkich procesach tej samej architektury, więc wystarczy zapytać o własny proces.
fn shared_cache() -> Option<(u64, u64, String)> {
    let mut len = 0usize;
    // SAFETY: funkcje dyld zwracają wskaźniki do danych żyjących przez cały czas działania procesu albo null.
    let (base, path) = unsafe { (_dyld_get_shared_cache_range(&mut len), dyld_shared_cache_file_path()) };
    if base.is_null() || len == 0 { return None; }
    // SAFETY: niepusty wskaźnik wskazuje napis zakończony zerem.
    let path = if path.is_null() { "dyld shared cache".to_string() } else { unsafe { std::ffi::CStr::from_ptr(path) }.to_string_lossy().into_owned() };
    Some((base as u64, len as u64, path))
}

const VM_MEMORY_STACK: u32 = 30;
/// Znaczniki alokatora `malloc` (`VM_MEMORY_MALLOC` .. `VM_MEMORY_MALLOC_NANO`).
const MALLOC_TAGS: std::ops::RangeInclusive<u32> = 1..=11;
/// Limit regionów jednego procesu (mapa pochodzi z badanego procesu).
const MAX_REGIONS: usize = 1 << 20;
const PATH_MAX: usize = 4096;

fn text(buf: &[u8], n: i32) -> Option<String> {
    (n > 0).then(|| String::from_utf8_lossy(&buf[..(n as usize).min(buf.len())]).trim_end_matches('\0').to_string()).filter(|s| !s.is_empty())
}

pub fn hostname() -> Option<String> {
    let mut b = [0u8; 256];
    // SAFETY: bufor ma podany rozmiar; wynik jest zakończony zerem albo obcięty do rozmiaru bufora.
    if unsafe { gethostname(b.as_mut_ptr(), b.len() - 1) } != 0 { return None; }
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    Some(String::from_utf8_lossy(&b[..end]).into_owned()).filter(|s| !s.is_empty())
}

pub fn list() -> Result<Vec<super::ProcEntry>> {
    // SAFETY: pierwsze wywołanie tylko pyta o liczbę; drugie dostaje bufor o podanym rozmiarze w bajtach.
    let n = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 { return Err(Error::Access(tr!("nie udało się pobrać listy procesów", "could not get the process list").into())); }
    let mut pids = vec![0i32; n as usize + 64];
    let got = unsafe { proc_listallpids(pids.as_mut_ptr() as *mut c_void, (pids.len() * 4) as i32) };
    if got <= 0 { return Err(Error::Access(tr!("nie udało się pobrać listy procesów", "could not get the process list").into())); }
    pids.truncate(got as usize);
    let mut out: Vec<super::ProcEntry> = pids.into_iter().filter(|p| *p > 0).map(|p| super::ProcEntry { pid: p as u32, name: name_of(p).unwrap_or_default() }).collect();
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

fn name_of(pid: i32) -> Option<String> {
    let mut b = [0u8; 256];
    // SAFETY: bufor ma podany rozmiar; funkcja zwraca liczbę zapisanych bajtów.
    let n = unsafe { proc_name(pid, b.as_mut_ptr() as *mut c_void, b.len() as u32) };
    text(&b, n)
}

fn path_of(pid: i32) -> Option<String> {
    let mut b = vec![0u8; PATH_MAX];
    // SAFETY: jak wyżej.
    let n = unsafe { proc_pidpath(pid, b.as_mut_ptr() as *mut c_void, b.len() as u32) };
    text(&b, n)
}

pub struct MacProcess { pid: u32, task: u32, own_port: bool, name: Option<String>, exe: Option<String>, exe_verified: bool }

impl MacProcess {
    pub fn open(pid: u32) -> Result<Self> {
        let me = std::process::id();
        let (task, own_port) = if pid == me {
            // SAFETY: zmienna inicjowana przez system przy starcie procesu, tylko do odczytu.
            (unsafe { mach_task_self_ }, false)
        } else {
            if name_of(pid as i32).is_none() && path_of(pid as i32).is_none() { return Err(Error::NotFound(trf!("proces {pid}", "process {pid}"))); }
            let mut t = 0u32;
            // SAFETY: wskaźnik na lokalną zmienną; przy błędzie port nie jest przydzielany.
            let mut kr = unsafe { task_for_pid(mach_task_self_, pid as i32, &mut t) };
            // pierwsze wywołanie po uruchomieniu bywa zwracane bez portu i bez kodu błędu (zaobserwowane): jedna powtórka
            if kr == 0 && t == 0 { kr = unsafe { task_for_pid(mach_task_self_, pid as i32, &mut t) }; }
            if kr != 0 || t == 0 {
                return Err(Error::Access(trf!("proces {pid}: system odmówił dostępu do pamięci (kod {kr}); potrzebne są uprawnienia root, a procesów chronionych przez SIP i programów z utwardzonym środowiskiem macOS nie udostępnia",
                    "process {pid}: the system refused access to its memory (code {kr}); root privileges are required, and macOS does not give access to processes protected by SIP or to programs with a hardened runtime")));
            }
            (t, true)
        };
        let exe = path_of(pid as i32);
        use std::os::unix::fs::MetadataExt;
        // ścieżkę podaje jądro; potwierdzenie: plik należy do roota i nie jest zapisywalny dla grupy ani innych
        let id = exe.as_deref().and_then(|p| std::fs::metadata(p).ok()).map(|m| super::FileId { uid: m.uid(), mode: m.mode(), dev: m.dev(), ino: m.ino() });
        Ok(MacProcess { pid, task, own_port, name: name_of(pid as i32), exe_verified: super::exe_is_trusted(id, id), exe })
    }
}

impl Drop for MacProcess {
    fn drop(&mut self) {
        // SAFETY: zwalniamy tylko port, który sami dostaliśmy z task_for_pid.
        if self.own_port { unsafe { mach_port_deallocate(mach_task_self_, self.task); } }
    }
}

/// Region z danych jądra: ochrona, znacznik alokacji i ścieżka pliku (jeśli jest).
pub(crate) fn make_region(base: u64, size: u64, protection: i32, user_tag: u32, file: Option<String>) -> Region {
    let prot = Prot((protection & 7) as u8);
    let (kind, label) = match (&file, user_tag) {
        (Some(_), _) => (RegionKind::Mapped, None),
        (None, VM_MEMORY_STACK) => (RegionKind::Stack, Some("[stack]".to_string())),
        (None, t) if MALLOC_TAGS.contains(&t) => (RegionKind::Heap, Some("[malloc]".to_string())),
        (None, 0) => (RegionKind::Private, None),
        (None, t) => (RegionKind::Private, Some(format!("[vm tag {t}]"))),
    };
    Region { base, size, prot: Some(prot), kind, backing: file, backing_deleted: false, label, readable: prot.r() }
}

impl MemorySource for MacProcess {
    fn info(&self) -> SourceInfo {
        SourceInfo { os: "macos".into(), arch: std::env::consts::ARCH.into(), pid: Some(self.pid), name: self.name.clone(), source_type: "live".into(),
            exe: self.exe.clone(), exe_deleted: false, exe_verified: self.exe_verified }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let mut out = Vec::new();
        let (mut addr, mut depth) = (0u64, 0u32);
        let mut path = vec![0u8; REGION_PATH_INFO_SIZE];
        let cache = shared_cache();
        while out.len() < MAX_REGIONS {
            let (mut size, mut info, mut count) = (0u64, SubmapInfo::default(), INFO_COUNT);
            // SAFETY: wszystkie wskaźniki wskazują lokalne zmienne o rozmiarach zgodnych z `count`.
            let kr = unsafe { mach_vm_region_recurse(self.task, &mut addr, &mut size, &mut depth, &mut info, &mut count) };
            if kr != 0 || size == 0 { break; }
            if info.is_submap != 0 { depth += 1; continue; }
            let (protection, tag) = (info.protection, info.user_tag);
            // Region wewnątrz wspólnej pamięci bibliotek, widziany przez mapę podrzędną jądra (depth > 0): kod
            // bibliotek systemowych, ten sam we wszystkich procesach. Strona podmieniona prywatnie w tym zakresie
            // nie leży już w mapie podrzędnej (depth == 0), więc pozostaje zwykłym regionem prywatnym.
            let in_cache = cache.as_ref().filter(|(b, l, _)| depth > 0 && addr >= *b && addr.saturating_add(size) <= b.saturating_add(*l));
            let mut r = match in_cache {
                Some((_, _, file)) => { let mut r = make_region(addr, size, protection, 0, Some(file.clone())); r.kind = RegionKind::Image; r.label = Some(SHARED_CACHE_LABEL.into()); r }
                None => {
                    path.fill(0);
                    // SAFETY: bufor ma podany rozmiar; jądro zapisuje najwyżej tyle bajtów.
                    let n = unsafe { proc_pidinfo(self.pid as i32, PROC_PIDREGIONPATHINFO, addr, path.as_mut_ptr() as *mut c_void, path.len() as i32) };
                    make_region(addr, size, protection, tag, if n as usize >= REGION_PATH_INFO_SIZE { file_of(&path, addr) } else { None })
                }
            };
            if r.size == 0 { r.readable = false; }
            out.push(r);
            match addr.checked_add(size) { Some(next) => addr = next, None => break }
        }
        Ok(out)
    }

    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut got = 0u64;
        // SAFETY: cel to bufor wywołującego o podanej długości; jądro kopiuje najwyżej tyle bajtów.
        let kr = unsafe { mach_vm_read_overwrite(self.task, addr, buf.len() as u64, buf.as_mut_ptr() as u64, &mut got) };
        if kr == 0 { return Ok(got as usize); }
        // odczyt całości się nie udał: czytamy stronami do pierwszej nieczytelnej (odczyt częściowy jest dozwolony)
        let mut done = 0usize;
        while done < buf.len() {
            let step = (4096 - ((addr as usize + done) & 4095)).min(buf.len() - done);
            let mut n = 0u64;
            // SAFETY: jak wyżej, dla fragmentu bufora.
            let kr = unsafe { mach_vm_read_overwrite(self.task, addr + done as u64, step as u64, buf[done..].as_mut_ptr() as u64, &mut n) };
            if kr != 0 || n == 0 { break; }
            done += n as usize;
        }
        if done == 0 { Err(Error::Access(trf!("odczyt pamięci pod adresem {addr:#x} nie powiódł się", "reading memory at {addr:#x} failed"))) } else { Ok(done) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_structure_has_the_documented_size() {
        assert_eq!(std::mem::size_of::<SubmapInfo>(), 76);
        assert_eq!(INFO_COUNT, 19);
    }

    #[test]
    fn region_kind_follows_file_and_allocation_tag() {
        let r = make_region(0x1000, 0x4000, 5, 0, Some("/usr/lib/dyld".into()));
        assert_eq!((r.kind, r.backing.as_deref(), r.is_x(), r.is_w(), r.readable), (RegionKind::Mapped, Some("/usr/lib/dyld"), true, false, true));
        assert_eq!(make_region(0, 1, 3, VM_MEMORY_STACK, None).kind, RegionKind::Stack);
        assert_eq!(make_region(0, 1, 3, 2, None).kind, RegionKind::Heap);
        let p = make_region(0, 1, 7, 0, None);
        assert_eq!((p.kind, p.is_x(), p.is_w(), p.label), (RegionKind::Private, true, true, None));
        assert_eq!(make_region(0, 1, 0, 64, None).label.as_deref(), Some("[vm tag 64]"));
        assert!(!make_region(0, 1, 0, 0, None).readable);
        // bity spoza odczyt/zapis/wykonanie (np. VM_PROT_COPY) nie trafiają do ochrony
        assert_eq!(make_region(0, 1, 0x15, 0, None).prot, Some(Prot(5)));
    }

    #[test]
    fn region_file_is_taken_only_for_the_exact_region() {
        let mut info = vec![0u8; REGION_PATH_INFO_SIZE];
        info[PRI_ADDRESS_OFFSET..PRI_ADDRESS_OFFSET + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        info[VIP_PATH_OFFSET..VIP_PATH_OFFSET + 13].copy_from_slice(b"/usr/lib/dyld");
        assert_eq!(file_of(&info, 0x1000).as_deref(), Some("/usr/lib/dyld"));
        // jądro opisało inny (następny) region: jego ścieżka nie należy do pytanego adresu
        assert_eq!(file_of(&info, 0x800), None);
        // pamięć bez pliku, ścieżka względna i za krótki bufor
        info[VIP_PATH_OFFSET] = 0;
        assert_eq!(file_of(&info, 0x1000), None);
        info[VIP_PATH_OFFSET] = b'x';
        assert_eq!(file_of(&info, 0x1000), None);
        assert_eq!(file_of(&info[..200], 0x1000), None);
    }

    #[test]
    fn own_process_is_listed_mapped_and_readable() {
        let me = std::process::id();
        assert!(list().unwrap().iter().any(|p| p.pid == me));
        let p = MacProcess::open(me).unwrap();
        let info = p.info();
        assert_eq!(info.os, "macos");
        assert!(info.exe.as_deref().map(|e| e.starts_with('/')).unwrap_or(false), "{:?}", info.exe);
        let regs = p.regions().unwrap();
        // regiony rosną i się nie nakładają
        assert!(regs.len() > 10 && regs.windows(2).all(|w| w[0].base + w[0].size <= w[1].base), "{}", regs.len());
        // dane testu leżą w zapisywalnym regionie i dają się przeczytać przez backend
        let marker: Vec<u8> = (0..8192u32).map(|i| (i * 31 + 7) as u8).collect();
        let at = marker.as_ptr() as u64;
        let r = regs.iter().find(|r| at >= r.base && at < r.base + r.size).expect("region z danymi testu");
        assert!(r.is_w() && !r.is_x(), "{r:?}");
        let mut buf = vec![0u8; marker.len()];
        assert_eq!(p.read_at(at, &mut buf).unwrap(), marker.len());
        assert_eq!(buf, marker);
        // kod testu leży w wykonywalnym regionie z pliku programu
        let code = own_process_is_listed_mapped_and_readable as *const () as usize as u64;
        let c = regs.iter().find(|r| code >= r.base && code < r.base + r.size).expect("region z kodem testu");
        assert!(c.is_x() && !c.is_w() && c.backing.is_some(), "{c:?}");
        // biblioteki systemowe ze wspólnej pamięci są rozpoznane i mają ścieżkę pliku; pamięć prywatna jej nie ma
        assert!(regs.iter().any(|r| r.label.as_deref() == Some(SHARED_CACHE_LABEL) && r.is_x() && r.kind == RegionKind::Image && r.backing.is_some()));
        assert!(r.backing.is_none(), "dane testu nie pochodzą z pliku: {r:?}");
        assert!(c.backing.as_deref() == std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()).as_deref().and_then(|p| p.to_str()), "{:?}", c.backing);
        // adres bez mapowania: błąd, nie panika
        assert!(p.read_at(8, &mut [0u8; 16]).is_err());
        assert!(matches!(MacProcess::open(0x7fff_fff0), Err(Error::NotFound(_))));
    }
}
