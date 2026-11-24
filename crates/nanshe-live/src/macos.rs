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
    fn sysctl(name: *const i32, namelen: u32, oldp: *mut c_void, oldlenp: *mut usize, newp: *const c_void, newlen: usize) -> i32;
    fn sysctlbyname(name: *const std::ffi::c_char, oldp: *mut c_void, oldlenp: *mut usize, newp: *const c_void, newlen: usize) -> i32;
    fn csops(pid: i32, ops: u32, useraddr: *mut c_void, usersize: usize) -> i32;
    fn getpwuid(uid: u32) -> *const *const std::ffi::c_char;
    fn getuid() -> u32;
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
        // Ścieżkę podaje jądro, ale plik pod nią mógł zostać podmieniony po starcie procesu, a niezależnej
        // tożsamości uruchomionego pliku skaner jeszcze nie pobiera. Dlatego plik programu nie jest na macOS
        // uznawany za potwierdzony i żadna obniżka wagi od niego nie zależy.
        Ok(MacProcess { pid, task, own_port, name: name_of(pid as i32), exe_verified: false, exe })
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

    fn jit_evidence(&self) -> Option<String> {
        signing(self.pid).filter(jit_allowed).map(|_| "jit:macos-allow-jit".to_string())
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

// ---- kontekst systemowy -------------------------------------------------------------------------

const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDTASKINFO: i32 = 4;
const PROC_PIDT_SHORTBSDINFO: i32 = 13;
const CS_OPS_STATUS: u32 = 0;
const CS_OPS_ENTITLEMENTS_BLOB: u32 = 7;
const CS_VALID: u32 = 0x1;
const CS_ADHOC: u32 = 0x2;
const CS_GET_TASK_ALLOW: u32 = 0x4;
const CS_HARD: u32 = 0x100;
const CS_KILL: u32 = 0x200;
const CS_RUNTIME: u32 = 0x1_0000;
const CS_PLATFORM_BINARY: u32 = 0x400_0000;
/// Uprawnienia programu, które zmieniają ocenę pamięci wykonywalnej albo dostęp do procesu.
const NOTABLE_ENTITLEMENTS: [&str; 6] = ["com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-executable-page-protection", "com.apple.security.cs.disable-library-validation",
    "com.apple.security.get-task-allow", "com.apple.security.cs.debugger"];
const MAX_ARGS: usize = 1 << 20;

fn u32at(b: &[u8], at: usize) -> Option<u32> { b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) }
fn cstr_at(b: &[u8], at: usize, max: usize) -> String {
    let part = &b[at.min(b.len())..(at + max).min(b.len())];
    String::from_utf8_lossy(&part[..part.iter().position(|c| *c == 0).unwrap_or(part.len())]).into_owned()
}

fn pidinfo(pid: u32, flavor: i32, size: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; size];
    // SAFETY: bufor ma podany rozmiar; jądro zapisuje najwyżej tyle bajtów i zwraca ich liczbę.
    let n = unsafe { proc_pidinfo(pid as i32, flavor, 0, b.as_mut_ptr() as *mut c_void, size as i32) };
    (n as usize >= size).then_some(b)
}

/// (ppid, uid, nazwa) z krótkiego opisu procesu, dostępnego także dla procesów innych użytkowników.
fn short_info(pid: u32) -> Option<(u32, u32, String)> {
    let b = pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 64)?;
    Some((u32at(&b, 4)?, u32at(&b, 36)?, cstr_at(&b, 16, 16)))
}

/// Wiersz poleceń z `KERN_PROCARGS2`: liczba argumentów, ścieżka programu, wypełnienie zerami, argumenty.
/// Treść pochodzi z pamięci badanego procesu (może ją zmienić), więc jest tylko wskazówką.
pub(crate) fn parse_procargs(b: &[u8]) -> Option<String> {
    let argc = u32at(b, 0)? as usize;
    let rest = b.get(4..)?;
    let path_end = rest.iter().position(|c| *c == 0)?;
    let mut at = path_end;
    while at < rest.len() && rest[at] == 0 { at += 1; }
    let args: Vec<String> = rest[at..].split(|c| *c == 0).take(argc.min(4096)).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    (!args.is_empty() && argc > 0).then(|| args.join(" "))
}

fn cmdline(pid: u32) -> Option<String> {
    let mib = [1i32, 49, pid as i32]; // CTL_KERN, KERN_PROCARGS2
    let mut len = 0usize;
    // SAFETY: pierwsze wywołanie pyta o rozmiar; drugie dostaje bufor tej wielkości.
    if unsafe { sysctl(mib.as_ptr(), 3, std::ptr::null_mut(), &mut len, std::ptr::null(), 0) } != 0 || len == 0 || len > MAX_ARGS { return None; }
    let mut b = vec![0u8; len];
    if unsafe { sysctl(mib.as_ptr(), 3, b.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null(), 0) } != 0 { return None; }
    parse_procargs(&b[..len.min(b.len())])
}

fn sysctl_text(name: &std::ffi::CStr) -> Option<String> {
    let mut b = [0u8; 256];
    let mut len = b.len();
    // SAFETY: bufor ma podany rozmiar, nazwa jest zakończona zerem.
    if unsafe { sysctlbyname(name.as_ptr(), b.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null(), 0) } != 0 { return None; }
    Some(cstr_at(&b, 0, len)).filter(|s| !s.is_empty())
}

fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid zwraca wskaźnik na strukturę biblioteki (pierwsze pole to nazwa) albo null; skaner jest jednowątkowy.
    let name = unsafe { let p = getpwuid(uid); if p.is_null() || (*p).is_null() { None } else { Some(std::ffi::CStr::from_ptr(*p).to_string_lossy().into_owned()) } };
    match name { Some(n) => format!("{n} (uid {uid})"), None => format!("uid {uid}") }
}

/// Stan podpisu kodu procesu według jądra i lista jego istotnych uprawnień (entitlements).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Signing { flags: u32, entitlements: Vec<String> }

fn signing(pid: u32) -> Option<Signing> {
    let mut flags = 0u32;
    // SAFETY: jądro zapisuje cztery bajty znaczników pod wskazany adres.
    if unsafe { csops(pid as i32, CS_OPS_STATUS, &mut flags as *mut u32 as *mut c_void, 4) } != 0 { return None; }
    let mut blob = vec![0u8; 64 << 10];
    // SAFETY: bufor ma podany rozmiar. Przy zbyt małym buforze albo braku uprawnień wywołanie zwraca błąd i lista jest pusta.
    let ok = unsafe { csops(pid as i32, CS_OPS_ENTITLEMENTS_BLOB, blob.as_mut_ptr() as *mut c_void, blob.len()) } == 0;
    Some(Signing { flags, entitlements: if ok { entitlements_in(&blob) } else { Vec::new() } })
}

/// Uprawnienia ustawione na "prawda" w dokumencie XML uprawnień. Dokument jest częścią podpisu sprawdzanego przez jądro.
pub(crate) fn entitlements_in(blob: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(blob);
    NOTABLE_ENTITLEMENTS.iter().filter(|e| {
        let key = format!("<key>{e}</key>");
        text.find(&key).map(|at| text[at + key.len()..].trim_start().starts_with("<true/>")).unwrap_or(false)
    }).map(|e| e.to_string()).collect()
}

/// Opis podpisu dla człowieka.
pub(crate) fn signing_text(s: &Signing) -> String {
    let mut parts: Vec<&str> = Vec::new();
    parts.push(if s.flags & CS_VALID != 0 { tr!("ważny", "valid") } else { tr!("NIEWAŻNY albo brak", "INVALID or missing") });
    if s.flags & CS_PLATFORM_BINARY != 0 { parts.push(tr!("program systemowy Apple", "Apple platform binary")); }
    if s.flags & CS_ADHOC != 0 { parts.push(tr!("lokalny (adhoc), bez tożsamości wydawcy", "local (adhoc), no publisher identity")); }
    if s.flags & CS_RUNTIME != 0 { parts.push(tr!("utwardzone środowisko", "hardened runtime")); } else { parts.push(tr!("bez utwardzonego środowiska", "no hardened runtime")); }
    if s.flags & (CS_HARD | CS_KILL) != 0 { parts.push(tr!("wymuszanie podpisu stron", "page signature enforcement")); }
    if s.flags & CS_GET_TASK_ALLOW != 0 { parts.push(tr!("pozwala się debugować", "allows debugging")); }
    parts.join(", ")
}

/// Dowód, że region JIT jest w tym procesie dozwolony przez system: ważny podpis z utwardzonym środowiskiem
/// i uprawnienie allow-jit. Obie rzeczy sprawdza jądro, proces nie może ich sobie nadać po uruchomieniu.
pub(crate) fn jit_allowed(s: &Signing) -> bool {
    s.flags & CS_VALID != 0 && s.flags & CS_RUNTIME != 0 && s.entitlements.iter().any(|e| e == "com.apple.security.cs.allow-jit")
}

/// Obraz hosta zebrany raz na skan: lista procesów z rodzicami.
pub struct Snapshot { procs: std::collections::HashMap<u32, (u32, u32, String)> }

impl Snapshot {
    pub fn take() -> Self {
        let procs = list().unwrap_or_default().into_iter().filter_map(|p| short_info(p.pid).map(|i| (p.pid, i))).collect();
        Snapshot { procs }
    }

    pub fn host(&self) -> nanshe_core::HostContext {
        // SAFETY: wywołanie bez argumentów.
        let uid = unsafe { getuid() };
        let me = signing(std::process::id());
        let debugger = me.as_ref().map(|s| s.entitlements.iter().any(|e| e == "com.apple.security.cs.debugger")).unwrap_or(false);
        let privileges = match (uid == 0, debugger) {
            (true, _) => tr!("root; procesy chronione przez system (SIP, utwardzone środowisko) pozostają niedostępne", "root; processes protected by the system (SIP, hardened runtime) remain inaccessible").to_string(),
            (false, true) => tr!("zwykły użytkownik z uprawnieniem debugera: tylko niechronione procesy tego samego użytkownika", "ordinary user with the debugger entitlement: only unprotected processes of the same user").to_string(),
            (false, false) => tr!("zwykły użytkownik bez uprawnienia debugera: pamięć innych procesów jest niedostępna", "ordinary user without the debugger entitlement: the memory of other processes is inaccessible").to_string(),
        };
        nanshe_core::HostContext {
            os: sysctl_text(c"kern.osproductversion").map(|v| format!("macOS {v}")),
            kernel: sysctl_text(c"kern.osrelease").map(|v| format!("Darwin {v}")),
            scanner_user: Some(user_name(uid)), scanner_privileges: Some(privileges), scanner_limited: uid != 0,
            ..Default::default()
        }
    }

    fn proc_ref(&self, pid: u32) -> nanshe_core::ProcRef {
        let name = self.procs.get(&pid).map(|p| p.2.clone()).filter(|n| !n.is_empty()).or_else(|| name_of(pid as i32)).unwrap_or_default();
        nanshe_core::ProcRef { pid, name, exe: path_of(pid as i32), cmdline: None }
    }

    pub fn context(&self, pid: u32) -> nanshe_core::ProcessContext {
        let mut c = nanshe_core::ProcessContext::default();
        if let Some((ppid, uid, _)) = self.procs.get(&pid).cloned().or_else(|| short_info(pid)) {
            c.ppid = Some(ppid);
            c.user = Some(user_name(uid));
        }
        if let Some(b) = pidinfo(pid, PROC_PIDTBSDINFO, 136) {
            let secs = b.get(120..128).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0);
            if secs > 0 { c.started = Some(nanshe_core::rfc3339(secs as i64)); }
        }
        c.threads = pidinfo(pid, PROC_PIDTASKINFO, 96).and_then(|b| u32at(&b, 84)).filter(|n| *n > 0);
        c.cmdline = cmdline(pid);
        // przodkowie: od rodzica w górę, z limitem (lista procesów pochodzi z jednej chwili, pętla jest niemożliwa
        // tylko w teorii)
        let mut at = c.ppid;
        while let Some(p) = at.filter(|p| *p > 0) {
            if c.ancestors.len() >= 32 || c.ancestors.iter().any(|a| a.pid == p) { break; }
            c.ancestors.push(self.proc_ref(p));
            at = self.procs.get(&p).map(|x| x.0);
        }
        let mut children: Vec<u32> = self.procs.iter().filter(|(_, v)| v.0 == pid).map(|(k, _)| *k).collect();
        children.sort_unstable();
        c.children = children.into_iter().take(64).map(|p| self.proc_ref(p)).collect();
        match signing(pid) {
            Some(s) => {
                c.flags.push((tr!("podpis kodu", "code signature").into(), signing_text(&s)));
                if !s.entitlements.is_empty() { c.flags.push((tr!("uprawnienia programu", "program entitlements").into(), s.entitlements.iter().map(|e| e.rsplit('.').next().unwrap_or(e)).collect::<Vec<_>>().join(", "))); }
            }
            None => c.notes.push(tr!("stan podpisu kodu procesu jest niedostępny", "the code signature state of the process is unavailable").into()),
        }
        c.notes.push(tr!("na macOS skaner nie zbiera jeszcze połączeń sieciowych ani otwartych plików procesu", "on macOS the scanner does not collect network connections or open files of the process yet").into());
        c
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
    fn command_line_is_parsed_from_the_kernel_argument_block() {
        let mut b = Vec::new();
        b.extend(3u32.to_le_bytes()); b.extend(b"/usr/local/bin/tool\0\0\0\0"); b.extend(b"tool\0--mode\0x y\0ENV=1\0");
        assert_eq!(parse_procargs(&b).as_deref(), Some("tool --mode x y"), "zmienne środowiska za argumentami nie należą do wiersza poleceń");
        // dane uszkodzone: brak końca ścieżki, zero argumentów, liczba argumentów większa niż dane, pusty bufor
        assert_eq!(parse_procargs(&[2, 0, 0, 0, b'a', b'b']), None);
        assert_eq!(parse_procargs(&[0, 0, 0, 0, b'a', 0, b'x', 0]), None);
        assert_eq!(parse_procargs(&[255, 255, 255, 255, b'a', 0, b'x', 0]).as_deref(), Some("x "));
        assert_eq!(parse_procargs(&[]), None);
    }

    #[test]
    fn jit_is_allowed_only_by_a_valid_hardened_signature_with_the_entitlement() {
        let xml = b"<plist><dict><key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.security.get-task-allow</key><false/><key>com.apple.security.cs.debugger</key>\n\t<true/></dict></plist>";
        let ent = entitlements_in(xml);
        assert_eq!(ent, ["com.apple.security.cs.allow-jit", "com.apple.security.cs.debugger"]);
        let ok = Signing { flags: CS_VALID | CS_RUNTIME, entitlements: ent.clone() };
        assert!(jit_allowed(&ok));
        // każdy brakujący element odbiera obniżkę: nieważny podpis, brak utwardzonego środowiska, brak uprawnienia
        assert!(!jit_allowed(&Signing { flags: CS_RUNTIME, ..ok.clone() }));
        assert!(!jit_allowed(&Signing { flags: CS_VALID | CS_ADHOC, ..ok.clone() }));
        assert!(!jit_allowed(&Signing { entitlements: vec!["com.apple.security.cs.debugger".into()], ..ok.clone() }));
        // nazwa uprawnienia w innym miejscu dokumentu (wartość, komentarz) nie wystarcza
        assert!(entitlements_in(b"<string>com.apple.security.cs.allow-jit</string><key>x</key><true/>").is_empty());
        assert!(signing_text(&ok).contains("ważny") && signing_text(&Signing::default()).contains("NIEWAŻNY"));
    }

    #[test]
    fn own_process_has_context_from_the_system() {
        let me = std::process::id();
        let snap = Snapshot::take();
        let c = snap.context(me);
        assert!(c.ppid.unwrap_or(0) > 0 && c.threads.unwrap_or(0) >= 1 && c.started.is_some(), "{c:?}");
        assert!(c.cmdline.as_deref().map(|l| !l.is_empty()).unwrap_or(false) && c.user.as_deref().map(|u| u.contains("uid")).unwrap_or(false), "{c:?}");
        assert!(!c.ancestors.is_empty() && c.ancestors[0].pid == c.ppid.unwrap());
        assert!(c.flags.iter().any(|f| f.0 == "podpis kodu"), "{:?}", c.flags);
        let h = snap.host();
        assert!(h.os.as_deref().map(|o| o.starts_with("macOS ")).unwrap_or(false) && h.kernel.is_some() && h.scanner_user.is_some());
        // proces testu nie ma utwardzonego środowiska, więc nie ma dowodu na dozwolony JIT
        assert_eq!(MacProcess::open(me).unwrap().jit_evidence(), None);
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
