//! Windows: OpenProcess + VirtualQueryEx + ReadProcessMemory. Wyłącznie odczyt (Z1).
//! Jedyny moduł z `unsafe` (FFI); każde wywołanie ma uzasadnienie.
use crate::ProcEntry;
use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
use windows_sys::Win32::System::Threading::*;

use nanshe_core::MAX_REGIONS;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: uchwyt pochodzi z udanego wywołania API i jest zamykany dokładnie raz.
        unsafe { CloseHandle(self.0); }
    }
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Włącza SeDebugPrivilege we własnym tokenie (nie zmienia stanu badanych procesów).
pub fn enable_debug_privilege() -> bool {
    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    // SAFETY: wszystkie wskaźniki wskazują lokalne, poprawnie zainicjowane zmienne o właściwych
    // rozmiarach; uchwyt tokenu zamyka Handle.
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 { return false; }
        let tok = Handle(tok);
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) == 0 { return false; }
        let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
        AdjustTokenPrivileges(tok.0, 0, &tp, 0, null_mut(), null_mut()) != 0 && GetLastError() == ERROR_SUCCESS
    }
}

/// Ile prywatnych stron kodu jednego regionu jest porównywanych z plikiem (16 MiB).
const MAX_COMPARE_PAGES: usize = 4096;

pub struct WinProcess { pid: u32, name: Option<String>, exe: Option<String>, h: Handle }

impl WinProcess {
    pub fn open(pid: u32) -> Result<Self> {
        // SAFETY: wywołanie bez wskaźników; wynik sprawdzany. Prawa wyłącznie do odczytu.
        let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if h.is_null() {
            // SAFETY: odczyt kodu błędu bieżącego wątku.
            let e = unsafe { GetLastError() };
            return Err(match e {
                ERROR_INVALID_PARAMETER => Error::NotFound(format!("pid {pid}")),
                ERROR_ACCESS_DENIED => Error::Access(trf!("pid {pid}: odmowa dostępu (wymagany administrator z SeDebugPrivilege; procesy chronione PPL są niedostępne)", "pid {pid}: access denied (an administrator with SeDebugPrivilege is required; PPL-protected processes are inaccessible)")),
                _ => Error::Access(trf!("pid {pid}: OpenProcess, błąd {e}", "pid {pid}: OpenProcess, error {e}")),
            });
        }
        let h = Handle(h);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: bufor i jego długość są spójne; funkcja zapisuje najwyżej `len` znaków.
        let ok = unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) };
        let exe = if ok != 0 { Some(String::from_utf16_lossy(&buf[..len as usize])) } else { None };
        let name = exe.as_deref().and_then(|e| e.rsplit('\\').next()).map(String::from);
        Ok(WinProcess { pid, name, exe, h })
    }

    fn mapped_name(&self, base: *const c_void) -> Option<String> {
        let mut buf = [0u16; 1024];
        // SAFETY: bufor i długość spójne; adres jest tylko kluczem zapytania, nie jest dereferowany u nas.
        let n = unsafe { K32GetMappedFileNameW(self.h.0, base, buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 { None } else { Some(String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())])) }
    }
}

/// Uprawnienia strony Windows -> R/W/X oraz czy wolno próbować odczytu.
pub fn prot_from_page(protect: u32) -> (Prot, bool) {
    let p = match protect & 0xff {
        PAGE_READONLY => Prot::R,
        PAGE_READWRITE | PAGE_WRITECOPY => Prot::R | Prot::W,
        PAGE_EXECUTE => Prot::X,
        PAGE_EXECUTE_READ => Prot::R | Prot::X,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => Prot::R | Prot::W | Prot::X,
        _ => 0, // PAGE_NOACCESS i nieznane
    };
    // PAGE_GUARD: odczyt zdjąłby flagę strażnika, czyli zmienił stan celu - nie czytamy.
    let readable = p & Prot::R != 0 && protect & PAGE_GUARD == 0;
    (Prot(p), readable)
}

impl MemorySource for WinProcess {
    fn info(&self) -> SourceInfo {
        // exe_verified: plik programu w katalogu systemowym wg środowiska skanera (nie badanego procesu).
        // Faktycznych ACL pliku nie sprawdzamy; opis ograniczenia w `wintables::exe_in_system_dir`.
        let roots: Vec<String> = ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|v| std::env::var(v).ok()).collect();
        // Oba warunki: katalog systemowy (bez podkatalogów zapisywalnych dla użytkowników) i właściciel
        // pliku będący kontem systemowym. Listy DACL pliku nie analizujemy.
        let verified = self.exe.as_deref().map(|e| crate::wintables::exe_in_system_dir(e, &roots)
            && file_owner_sid(e).map(|s| crate::wintables::owner_sid_trusted(&s)).unwrap_or(false)).unwrap_or(false);
        SourceInfo { os: "windows".into(), arch: std::env::consts::ARCH.into(), pid: Some(self.pid), name: self.name.clone(),
            source_type: "live".into(), exe: self.exe.clone(), exe_deleted: false, exe_verified: verified }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        while out.len() < MAX_REGIONS {
            // SAFETY: MEMORY_BASIC_INFORMATION to zwykła struktura danych; zero jest poprawną wartością.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            // SAFETY: wskaźnik na lokalną strukturę o podanym rozmiarze; `addr` to klucz zapytania.
            let n = unsafe { VirtualQueryEx(self.h.0, addr as *const c_void, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
            if n == 0 {
                // SAFETY: kod błędu ostatniego zapytania w bieżącym wątku.
                let e = unsafe { GetLastError() };
                if e == ERROR_INVALID_PARAMETER { break; } // koniec dostępnej przestrzeni adresowej
                return Err(Error::Access(trf!("VirtualQueryEx {addr:#x}: błąd {e}; mapa niekompletna", "VirtualQueryEx {addr:#x}: error {e}; map incomplete")));
            }
            let base = mbi.BaseAddress as usize;
            if mbi.State == MEM_COMMIT {
                let (prot, readable) = prot_from_page(mbi.Protect);
                let kind = match mbi.Type { MEM_IMAGE => RegionKind::Image, MEM_MAPPED => RegionKind::Mapped, MEM_PRIVATE => RegionKind::Private, _ => RegionKind::Unknown };
                let backing = if matches!(kind, RegionKind::Image | RegionKind::Mapped) { self.mapped_name(mbi.BaseAddress) } else { None };
                // Strażnik: treści nie czytamy (odczyt zdjąłby flagę), ale analiza musi o tym wiedzieć.
                let label = (mbi.Protect & PAGE_GUARD != 0).then(|| nanshe_core::GUARD_LABEL.to_string());
                out.push(Region { base: base as u64, size: mbi.RegionSize as u64, prot: Some(prot), kind, backing, backing_deleted: false, label, readable });
            }
            match base.checked_add(mbi.RegionSize) { Some(next) if next > addr => addr = next, _ => break }
        }
        // Po osiągnięciu limitu zwracamy to, co zebrano: analiza oznaczy wynik jako niekompletny (Z8).
        Ok(out)
    }

    /// Wątki z adresem startu (ThreadQuerySetWin32StartAddress). Uchwyty tylko do zapytań.
    fn threads(&self) -> Vec<ThreadInfo> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        const START_ADDRESS: u32 = 9;
        let mut out = Vec::new();
        let mut prev: Option<Handle> = None;
        for _ in 0..100_000 {
            let mut next: HANDLE = null_mut();
            // SAFETY: uchwyt procesu jest ważny; poprzedni uchwyt wątku (albo null) wskazuje miejsce w liście; wynik w zmiennej lokalnej.
            let st = unsafe { NtGetNextThread(self.h.0, prev.as_ref().map(|h| h.0).unwrap_or(null_mut()), THREAD_QUERY_INFORMATION, 0, 0, &mut next) };
            if st < 0 || next.is_null() { break; }
            let h = Handle(next);
            let mut addr: usize = 0;
            // SAFETY: bufor to lokalna zmienna rozmiaru wskaźnika; funkcja zapisuje dokładnie tyle.
            let ok = unsafe { NtQueryInformationThread(h.0, START_ADDRESS, &mut addr as *mut usize as *mut c_void, size_of::<usize>() as u32, null_mut()) };
            // SAFETY: uchwyt wątku z udanego wywołania.
            let tid = unsafe { GetThreadId(h.0) };
            if ok >= 0 && addr != 0 && tid != 0 { out.push(ThreadInfo { tid, addr: addr as u64 }); }
            prev = Some(h);
        }
        out.sort_by_key(|t| t.tid);
        out
    }

    /// Rezerwacje: kolejne regiony o wspólnym AllocationBase (także zarezerwowane, bez przydzielonej pamięci).
    fn allocations(&self) -> Vec<nanshe_core::Allocation> {
        let mut out: Vec<nanshe_core::Allocation> = Vec::new();
        let mut addr: usize = 0;
        for _ in 0..MAX_REGIONS * 2 {
            // SAFETY: MEMORY_BASIC_INFORMATION to zwykła struktura danych; zero jest poprawną wartością.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            // SAFETY: wskaźnik na lokalną strukturę o podanym rozmiarze; `addr` to klucz zapytania.
            let n = unsafe { VirtualQueryEx(self.h.0, addr as *const c_void, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
            if n == 0 { break; }
            let (base, alloc) = (mbi.BaseAddress as usize, mbi.AllocationBase as u64);
            let Some(next) = base.checked_add(mbi.RegionSize).filter(|n| *n > addr) else { break };
            // wolna przestrzeń ma zerowy AllocationBase
            if alloc != 0 && alloc <= base as u64 {
                match out.last_mut() {
                    Some(a) if a.base == alloc => a.size = next as u64 - alloc,
                    _ => out.push(nanshe_core::Allocation { base: alloc, size: next as u64 - alloc }),
                }
            }
            addr = next;
        }
        out
    }

    /// Rejestry wątków (GetThreadContext) bez wstrzymywania: proces nie jest zatrzymywany ani zmieniany.
    /// Dla wątku czekającego w jądrze wartości są stałe; dla działającego mogą być niespójne, co
    /// odbiorca sprawdza sam (drugi odczyt po analizie). Tylko x86_64.
    #[cfg(target_arch = "x86_64")]
    fn thread_regs(&self) -> nanshe_core::ThreadSet {
        const THREAD_GET_CONTEXT: u32 = 0x0008;
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
        const FLAGS: u32 = 0x0010_0003;
        // struktura CONTEXT (x64): 1232 bajty, wyrównanie 16; ContextFlags pod 0x30, Rax..R15 od 0x78, Rip pod 0xf8
        #[repr(C, align(16))]
        struct Context([u8; 1232]);
        let mut out = Vec::new();
        let mut unread = 0u32;
        let mut prev: Option<Handle> = None;
        for _ in 0..100_000 {
            let mut next: HANDLE = null_mut();
            // SAFETY: uchwyt procesu jest ważny; poprzedni uchwyt wątku (albo null) wskazuje miejsce w liście; wynik w zmiennej lokalnej.
            let st = unsafe { NtGetNextThread(self.h.0, prev.as_ref().map(|h| h.0).unwrap_or(null_mut()), THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, 0, &mut next) };
            if st < 0 || next.is_null() { break; }
            let h = Handle(next);
            let mut c = Context([0u8; 1232]);
            c.0[0x30..0x34].copy_from_slice(&FLAGS.to_le_bytes());
            // SAFETY: bufor ma rozmiar i wyrównanie struktury CONTEXT; funkcja zapisuje tylko w nim.
            let ok = unsafe { GetThreadContext(h.0, c.0.as_mut_ptr() as *mut c_void) };
            // SAFETY: uchwyt wątku z udanego wywołania.
            let tid = unsafe { GetThreadId(h.0) };
            if ok != 0 && tid != 0 {
                let q = |o: usize| u64::from_le_bytes(c.0[o..o + 8].try_into().unwrap_or([0; 8]));
                let mut gpr = [0u64; 16];
                for (i, g) in gpr.iter_mut().enumerate() { *g = q(0x78 + i * 8); }
                out.push(nanshe_core::ThreadRegs { tid, rip: q(0xf8), gpr, known: 0xffff });
            } else { unread += 1; }
            prev = Some(h);
        }
        out.sort_by_key(|t| t.tid);
        nanshe_core::ThreadSet { regs: out, unread }
    }

    /// Strony kodu obrazu, które nie są już współdzielone z plikiem (kopia przy zapisie), wg zestawu
    /// roboczego procesu. Strony spoza zestawu roboczego nie są oceniane.
    fn modified_code(&self, r: &Region) -> Option<CodeChange> {
        if r.kind != RegionKind::Image { return None; }
        let pages = (r.size / 4096) as usize;
        let (mut bytes, mut first) = (0u64, 0u64);
        let mut private: Vec<u64> = Vec::new();
        let mut page = 0usize;
        while page < pages {
            let n = (pages - page).min(4096);
            // wpis: adres strony (8 bajtów) i atrybuty (8 bajtów) wypełniane przez system
            let mut buf: Vec<[u64; 2]> = (0..n).map(|i| [r.base + ((page + i) as u64) * 4096, 0]).collect();
            // SAFETY: bufor ma n wpisów po 16 bajtów; funkcja wypełnia tylko pole atrybutów.
            let ok = unsafe { K32QueryWorkingSetEx(self.h.0, buf.as_mut_ptr() as *mut c_void, (n * 16) as u32) };
            if ok == 0 { return None; }
            for e in &buf {
                // bit 0: strona w zestawie roboczym; bit 15: współdzielona
                if e[1] & 1 == 1 && (e[1] >> 15) & 1 == 0 {
                    if bytes == 0 { first = e[0]; }
                    bytes += 4096;
                    if private.len() < MAX_COMPARE_PAGES { private.push(e[0]); }
                }
            }
            page += n;
        }
        if bytes == 0 { return None; }
        let unverified = Some(CodeChange { bytes, first, compared: false, verified: false });
        // Porównanie prywatnych stron z plikiem na dysku, z naniesionymi relokacjami dla adresu załadowania.
        if (bytes / 4096) as usize > private.len() { return unverified; } // za dużo stron: bez porównania
        let Some(path) = r.backing.as_deref() else { return unverified };
        let open = if path.starts_with("\\Device\\") { format!("\\\\?\\GLOBALROOT{path}") } else { path.to_string() };
        if !path_is_local(&open) { return unverified; }
        // SAFETY: MEMORY_BASIC_INFORMATION to zwykła struktura danych; zero jest poprawną wartością.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        // SAFETY: wskaźnik na lokalną strukturę o podanym rozmiarze; adres jest tylko kluczem zapytania.
        let n = unsafe { VirtualQueryEx(self.h.0, r.base as *const c_void, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
        let image = mbi.AllocationBase as u64;
        if n == 0 || image == 0 || image > r.base { return unverified; }
        let Ok((file, _, _)) = crate::sysctx::read_file_range(&open, 0, crate::sysctx::MAX_COMPARE_BYTES) else { return unverified };
        let Some(pe) = crate::pediff::Pe::parse(&file) else { return unverified };
        // tablica relokacji nieodczytana w całości: po załadowaniu pod inny adres porównanie nie jest wiarygodne
        if !pe.relocs_complete && image != pe.image_base { return unverified; }
        let mut buf = [0u8; 4096];
        // Plik pod tą ścieżką mógł zostać zastąpiony po załadowaniu (aktualizacja albo celowa podmiana).
        // Nagłówek obrazu w pamięci musi odpowiadać nagłówkowi pliku: znacznik czasu, suma kontrolna,
        // rozmiar obrazu i liczba sekcji. To wykrywa inny plik, ale nie dowodzi tożsamości.
        if self.read_at(image, &mut buf).ok() != Some(4096) || !crate::pediff::same_image_header(&buf, &file) { return unverified; }
        let (mut diff, mut at) = (0u64, None);
        for p in &private {
            let Ok(rva) = u32::try_from(p - image) else { return unverified };
            // strona, której nie da się odczytać w całości, mogła się różnić: bez niej wynik nie jest wiążący
            if self.read_at(*p, &mut buf).ok() != Some(4096) { return unverified; }
            let want = pe.expected(rva, 4096, image);
            let (k, i) = crate::sysctx::count_diff(&buf, &want);
            if k > 0 && at.is_none() { at = Some(p + i.unwrap_or(0) as u64); }
            diff += k;
        }
        // tożsamości pliku nie da się tu potwierdzić (zgodność nagłówka to tylko przesłanka), więc `verified` jest
        // fałszywe: brak różnic nie wygasza znaleziska, tylko zmienia jego opis
        Some(CodeChange { bytes: diff, first: at.unwrap_or(first), compared: true, verified: false })
    }

    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut n: usize = 0;
        // SAFETY: bufor docelowy ma buf.len() bajtów; adres źródłowy należy do innego procesu
        // i jest sprawdzany przez jądro; `n` to lokalna zmienna wyjściowa.
        let ok = unsafe { ReadProcessMemory(self.h.0, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut n) };
        if ok != 0 || n > 0 { Ok(n) } else { Err(Error::Access(format!("ReadProcessMemory {addr:#x}"))) }
    }
}

// --- kontekst systemowy (wyłącznie odczyt) ---

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: u32, reserved: u32) -> u32;
    fn GetExtendedUdpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: u32, reserved: u32) -> u32;
}
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtGetNextThread(process: HANDLE, thread: HANDLE, access: u32, attributes: u32, flags: u32, next: *mut HANDLE) -> i32;
    fn NtQueryInformationThread(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn RtlGetVersion(info: *mut OsVersion) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn GetNamedSecurityInfoW(name: *const u16, object_type: u32, info: u32, owner: *mut *mut c_void, group: *mut *mut c_void,
        dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
}

/// Czy plik pod tą ścieżką wolno otworzyć skanerowi: postać ścieżki lokalna, a dysk pod literą
/// nie jest mapowaniem sieciowym. Chroni przed wysłaniem poświadczeń komputera na serwer wskazany
/// przez badany proces.
pub fn path_is_local(path: &str) -> bool {
    if !crate::wintables::path_form_is_local(path) { return false; }
    let p = path.strip_prefix("\\\\?\\").unwrap_or(path);
    let b = p.as_bytes();
    if b.len() >= 2 && b[1] == b':' {
        let root: Vec<u16> = format!("{}:\\", b[0] as char).encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: ciąg zakończony zerem; funkcja tylko odczytuje typ dysku.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        return kind != 4 && kind != 1 && kind != 0; // DRIVE_REMOTE, DRIVE_NO_ROOT_DIR, DRIVE_UNKNOWN
    }
    true
}

/// SID właściciela pliku w postaci tekstowej (odczyt deskryptora zabezpieczeń, bez otwierania treści).
fn file_owner_sid(path: &str) -> Option<String> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let (mut owner, mut sd): (*mut c_void, *mut c_void) = (null_mut(), null_mut());
    // SAFETY: nazwa zakończona zerem; funkcja przydziela deskryptor, który zwalniamy przez LocalFree.
    let rc = unsafe { GetNamedSecurityInfoW(wide.as_ptr(), 1 /* SE_FILE_OBJECT */, 1 /* OWNER_SECURITY_INFORMATION */, &mut owner, null_mut(), null_mut(), null_mut(), &mut sd) };
    if rc != 0 || owner.is_null() { return None; }
    let mut text: *mut u16 = null_mut();
    // SAFETY: SID wskazuje w deskryptor z udanego wywołania; wynik to ciąg zakończony zerem przydzielony przez system.
    let out = unsafe {
        let ok = ConvertSidToStringSidW(owner, &mut text);
        let s = if ok != 0 && !text.is_null() {
            let mut n = 0; while *text.add(n) != 0 { n += 1; }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(text, n)))
        } else { None };
        if !text.is_null() { LocalFree(text as *mut c_void); }
        LocalFree(sd);
        s
    };
    out
}

#[link(name = "kernel32")]
extern "system" {
    fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
    fn GetFileType(h: HANDLE) -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetThreadId(h: HANDLE) -> u32;
    #[cfg(target_arch = "x86_64")]
    fn GetThreadContext(h: HANDLE, context: *mut c_void) -> i32;
    fn K32QueryWorkingSetEx(process: HANDLE, buf: *mut c_void, size: u32) -> i32;
    fn GetFinalPathNameByHandleW(h: HANDLE, path: *mut u16, len: u32, flags: u32) -> u32;
    fn GetTickCount64() -> u64;
}
#[repr(C)]
struct OsVersion { size: u32, major: u32, minor: u32, build: u32, platform: u32, csd: [u16; 128] }

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;
const FILE_TYPE_PIPE: u32 = 3;
const MAX_HANDLES: usize = 300;

/// UNICODE_STRING na początku bufora wypełnionego przez jądro: długość w bajtach (u16), a po
/// dopełnieniu wskaźnik, który musi wskazywać w ten sam bufor.
fn ustr(buf: &[u64]) -> Option<String> {
    let len = (buf.first()? & 0xffff) as usize / 2;
    let start = buf.as_ptr() as usize;
    let off = (*buf.get(1)? as usize).checked_sub(start)?;
    if len == 0 || off % 2 != 0 || off + len * 2 > buf.len() * 8 { return None; }
    // SAFETY: zakres [off, off + 2*len) sprawdzony wyżej, leży w `buf`; wyrównanie do u16 zachowane.
    let wide = unsafe { std::slice::from_raw_parts((start + off) as *const u16, len) };
    Some(String::from_utf16_lossy(wide))
}

/// Zapytania o nazwę obiektu idą przez wątek roboczy z limitem czasu: sterownik albo filtr potrafi
/// przytrzymać NtQueryObject bez końca (znane dla potoków, możliwe dla innych obiektów), a skan nie
/// może przez to stanąć. Po przekroczeniu limitu wątek zostaje porzucony razem z kopią uchwytu,
/// której używa, i powstaje nowy.
struct NameWorker {
    tx: std::sync::mpsc::Sender<(usize, bool)>,
    rx: std::sync::mpsc::Receiver<Option<String>>,
}
const NAME_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const MAX_NAME_TIMEOUTS: u32 = 3;

fn final_path(h: HANDLE) -> Option<String> {
    let mut buf = [0u16; 1024];
    // SAFETY: bufor i jego długość są spójne.
    let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
    if n == 0 || n >= buf.len() { return None; }
    let p = String::from_utf16_lossy(&buf[..n]);
    Some(p.strip_prefix("\\\\?\\").map(String::from).unwrap_or(p))
}

impl NameWorker {
    fn spawn() -> Self {
        let (tx, jobs) = std::sync::mpsc::channel::<(usize, bool)>();
        let (results, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // uchwyt przychodzi jako liczba, bo wskaźnik nie przechodzi między wątkami; właścicielem jest wątek pytający
            while let Ok((h, is_file)) = jobs.recv() {
                let r = if is_file { final_path(h as HANDLE) } else { object_info(h as HANDLE, OBJECT_NAME_INFORMATION) };
                if results.send(r).is_err() { break; }
            }
        });
        NameWorker { tx, rx }
    }
    /// Ok(nazwa albo brak nazwy); Err, gdy zapytanie nie wróciło w czasie. Wtedy kopia uchwytu
    /// nie jest zamykana (porzucony wątek nadal jej używa), a wątek roboczy jest wymieniany.
    fn query(&mut self, h: Handle, is_file: bool) -> std::result::Result<Option<String>, ()> {
        if self.tx.send((h.0 as usize, is_file)).is_err() { return Err(()); }
        match self.rx.recv_timeout(NAME_TIMEOUT) {
            Ok(r) => Ok(r),
            Err(_) => { std::mem::forget(h); *self = NameWorker::spawn(); Err(()) }
        }
    }
}

/// Tabela wszystkich uchwytów systemu jako bufor bajtów; parsowanie w `wintables`.
fn system_handles() -> Vec<u8> {
    let mut size: usize = 1 << 22;
    for _ in 0..6 {
        let mut buf = vec![0u64; size / 8];
        let mut ret: u32 = 0;
        // SAFETY: bufor ma `size` bajtów; funkcja zapisuje najwyżej tyle.
        let st = unsafe { NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr() as *mut c_void, size as u32, &mut ret) };
        if st >= 0 {
            // SAFETY: reinterpretacja bufora u64 jako bajtów o tej samej długości.
            return unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, size) }.to_vec();
        }
        if st != STATUS_INFO_LENGTH_MISMATCH { return Vec::new(); }
        size = (ret as usize).max(size) * 2;
        if size > 1 << 30 { break; }
    }
    Vec::new()
}

fn object_info(h: HANDLE, class: u32) -> Option<String> {
    let mut buf = vec![0u64; 1024]; // 8 KiB
    let mut ret: u32 = 0;
    // SAFETY: bufor ma 8192 bajty; funkcja zapisuje najwyżej tyle.
    let st = unsafe { NtQueryObject(h, class, buf.as_mut_ptr() as *mut c_void, 8192, &mut ret) };
    if st < 0 { None } else { ustr(&buf) }
}

type TableFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, u32, u32) -> u32;

/// Pobiera tabelę gniazd do bufora bajtów; parsowanie jest w `wintables` (bez `unsafe`).
fn socket_table(f: TableFn, af: u32, class: u32) -> Vec<u8> {
    let mut size: u32 = 0;
    // SAFETY: pierwsze wywołanie z pustym buforem tylko zwraca wymagany rozmiar.
    unsafe { f(null_mut(), &mut size, 0, af, class, 0) };
    for _ in 0..4 {
        if size == 0 { return Vec::new(); }
        let mut buf = vec![0u8; size as usize + 1024];
        let mut len = buf.len() as u32;
        // SAFETY: bufor ma `len` bajtów; funkcja zapisuje najwyżej tyle i zwraca kod błędu.
        let rc = unsafe { f(buf.as_mut_ptr() as *mut c_void, &mut len, 0, af, class, 0) };
        if rc == 0 { return buf; }
        if rc != ERROR_INSUFFICIENT_BUFFER { return Vec::new(); }
        size = len; // tabela urosła między wywołaniami
    }
    Vec::new()
}

fn open_limited(pid: u32) -> Option<Handle> {
    // SAFETY: wywołanie bez wskaźników; prawo wyłącznie do zapytań o metadane.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() { None } else { Some(Handle(h)) }
}

fn image_path(h: &Handle) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: bufor i jego długość są spójne.
    let ok = unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Czas utworzenia procesu jako FILETIME.
fn creation_time(h: &Handle) -> Option<u64> {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    // SAFETY: cztery wskaźniki na lokalne struktury FILETIME.
    let ok = unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) };
    (ok != 0).then(|| ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
}

/// Wiersz poleceń przez NtQueryInformationProcess(ProcessCommandLineInformation): jądro kopiuje
/// UNICODE_STRING do naszego bufora, więc nie czytamy pamięci celu.
fn command_line(h: &Handle) -> Option<String> {
    let mut buf = vec![0u64; 8192]; // 64 KiB, wyrównane do wskaźnika
    let bytes = (buf.len() * 8) as u32;
    let mut ret: u32 = 0;
    // SAFETY: bufor ma `bytes` bajtów; funkcja zapisuje najwyżej tyle.
    let st = unsafe { NtQueryInformationProcess(h.0, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr() as *mut c_void, bytes, &mut ret) };
    if st < 0 { return None; }
    let s = ustr(&buf)?;
    let s = s.trim();
    if s.is_empty() { return None; }
    Some(if s.chars().count() > 2000 { format!("{}...", s.chars().take(2000).collect::<String>()) } else { s.to_string() })
}

/// Użytkownik (DOMENA\\nazwa), poziom integralności i podniesienie uprawnień z tokenu procesu.
fn token_facts(h: &Handle) -> (Option<String>, Vec<(String, String)>) {
    let mut flags = Vec::new();
    let mut tok: HANDLE = null_mut();
    // SAFETY: wskaźnik na lokalny uchwyt; token otwierany wyłącznie do odczytu.
    if unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut tok) } == 0 { return (None, flags); }
    let tok = Handle(tok);
    // `len`: rozmiar podawany systemowi. Klasy o stałym rozmiarze (TokenElevation) dostają dokładny.
    let info = |class: TOKEN_INFORMATION_CLASS, len: u32| -> Option<Vec<u64>> {
        let mut buf = vec![0u64; 64]; // 512 bajtów, wyrównane do wskaźnika
        let mut ret: u32 = 0;
        // SAFETY: bufor ma 512 bajtów, a `len` nie przekracza 512; funkcja zapisuje najwyżej `len`.
        let ok = unsafe { GetTokenInformation(tok.0, class, buf.as_mut_ptr() as *mut c_void, len.min(512), &mut ret) };
        (ok != 0).then_some(buf)
    };
    let mut user = None;
    if let Some(buf) = info(TokenUser, 512) {
        // SAFETY: udane wywołanie wypełniło bufor strukturą TOKEN_USER; wskaźnik SID wskazuje w ten bufor.
        let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        let (mut name, mut dom) = ([0u16; 256], [0u16; 256]);
        let (mut nl, mut dl, mut kind) = (256u32, 256u32, 0);
        // SAFETY: bufory i ich długości są spójne; SID pochodzi z udanego zapytania.
        if unsafe { LookupAccountSidW(null(), sid, name.as_mut_ptr(), &mut nl, dom.as_mut_ptr(), &mut dl, &mut kind) } != 0 {
            user = Some(format!("{}\\{}", from_wide(&dom), from_wide(&name)));
        }
    }
    if let Some(buf) = info(TokenIntegrityLevel, 512) {
        // SAFETY: bufor zawiera TOKEN_MANDATORY_LABEL; funkcje SID zwracają wskaźniki w ten sam bufor.
        let rid = unsafe {
            let sid = (*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL)).Label.Sid;
            let n = *GetSidSubAuthorityCount(sid);
            if n == 0 { None } else { Some(*GetSidSubAuthority(sid, n as u32 - 1)) }
        };
        if let Some(r) = rid { flags.push((tr!("poziom integralności", "integrity level").into(), crate::wintables::integrity(r).to_string())); }
    }
    if let Some(buf) = info(TokenElevation, 4) {
        flags.push((tr!("podniesione uprawnienia", "elevated").into(), if buf[0] as u32 != 0 { tr!("tak", "yes").into() } else { tr!("nie", "no").into() }));
    }
    (user, flags)
}

/// Obraz hosta zebrany raz na skan: procesy (rodzic, wątki) i gniazda z właścicielem.
pub struct Snapshot {
    procs: std::collections::HashMap<u32, (String, u32, u32)>,
    sockets: std::collections::HashMap<u32, Vec<Socket>>,
    /// tabela uchwytów systemu (surowy bufor) i pamięć nazw typów wg indeksu
    handles: Vec<u8>,
    types: std::cell::RefCell<std::collections::HashMap<u16, String>>,
}

impl Snapshot {
    pub fn take() -> Self {
        let mut procs = std::collections::HashMap::new();
        // SAFETY: wywołanie bez wskaźników; wynik sprawdzany.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap != INVALID_HANDLE_VALUE {
            let snap = Handle(snap);
            // SAFETY: PROCESSENTRY32W to zwykła struktura danych; zero jest poprawną wartością.
            let mut e: PROCESSENTRY32W = unsafe { zeroed() };
            e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            // SAFETY: `e` ma ustawione dwSize i żyje przez całe wywołanie.
            let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
            while ok != 0 {
                procs.insert(e.th32ProcessID, (from_wide(&e.szExeFile), e.th32ParentProcessID, e.cntThreads));
                // SAFETY: jw.
                ok = unsafe { Process32NextW(snap.0, &mut e) };
            }
        }
        let mut sockets: std::collections::HashMap<u32, Vec<Socket>> = std::collections::HashMap::new();
        use crate::wintables as wt;
        let all = wt::tcp4(&socket_table(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL)).into_iter()
            .chain(wt::tcp6(&socket_table(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL)))
            .chain(wt::udp4(&socket_table(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)))
            .chain(wt::udp6(&socket_table(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)));
        for (pid, s) in all { let v = sockets.entry(pid).or_default(); if !v.contains(&s) { v.push(s); } }
        Snapshot { procs, sockets, handles: system_handles(), types: Default::default() }
    }

    /// Otwarte uchwyty procesu. Żeby poznać typ i nazwę obiektu, uchwyt jest kopiowany do skanera
    /// bez żadnych praw (DuplicateHandle z dostępem 0) i zaraz zamykany: stan celu się nie zmienia,
    /// obiekt ma tylko chwilowo o jedno odwołanie więcej. Nazwy są pytane wyłącznie dla plików
    /// dyskowych i obiektów innych niż pliki: zapytanie o nazwę potoku potrafi zawiesić wątek.
    fn open_handles(&self, pid: u32, c: &mut ProcessContext) {
        if cfg!(not(target_pointer_width = "64")) { c.notes.push(tr!("otwarte uchwyty zbierane tylko w wersji 64-bitowej", "open handles are collected only in the 64-bit build").into()); return; }
        let list = crate::wintables::handles_of(&self.handles, pid);
        if list.is_empty() { c.notes.push(tr!("tabela uchwytów systemu niedostępna albo pusta dla procesu: otwarte uchwyty nieznane", "system handle table unavailable or empty for the process: open handles unknown").into()); return; }
        c.files_total = list.len() as u32;
        // SAFETY: wywołanie bez wskaźników; prawo wyłącznie do kopiowania uchwytów.
        let src = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
        if src.is_null() { c.notes.push(tr!("brak prawa kopiowania uchwytów procesu: znana tylko ich liczba", "no right to duplicate the process's handles: only their count is known").into()); return; }
        let src = Handle(src);
        let dup = |value: u64, access: u32| -> Option<Handle> {
            let mut out: HANDLE = null_mut();
            // SAFETY: uchwyt źródłowy to wartość z tabeli systemu (jądro ją sprawdza); wynik trafia do lokalnej zmiennej i jest zamykany przez Handle.
            let ok = unsafe { DuplicateHandle(src.0, value as HANDLE, GetCurrentProcess(), &mut out, access, 0, 0) };
            (ok != 0 && !out.is_null()).then(|| Handle(out))
        };
        let mut unnamed = 0u32;
        let mut worker = NameWorker::spawn();
        let mut timeouts = 0u32;
        for (value, type_index, access) in list {
            if timeouts >= MAX_NAME_TIMEOUTS {
                c.notes.push(trf!("zapytania o nazwy uchwytów przerwane po {MAX_NAME_TIMEOUTS} przekroczeniach limitu czasu; lista uchwytów niepełna", "handle name queries stopped after {MAX_NAME_TIMEOUTS} timeouts; handle list incomplete"));
                break;
            }
            let known = self.types.borrow().get(&type_index).cloned();
            let (type_name, held) = match known {
                Some(t) => (t, None),
                None => {
                    let Some(d) = dup(value, 0) else { continue };
                    let Some(t) = object_info(d.0, OBJECT_TYPE_INFORMATION) else { continue };
                    self.types.borrow_mut().insert(type_index, t.clone());
                    (t, Some(d))
                }
            };
            let kind = crate::wintables::handle_kind(&type_name);
            if !matches!(kind, "file" | "key" | "section" | "mutant" | "process") || c.files.len() >= MAX_HANDLES { continue; }
            let target = match kind {
                "process" => {
                    // prawo zapytania o metadane, żeby poznać PID wskazywanego procesu
                    let Some(d) = dup(value, PROCESS_QUERY_LIMITED_INFORMATION) else { unnamed += 1; continue };
                    // SAFETY: uchwyt procesu z udanego kopiowania.
                    let target_pid = unsafe { GetProcessId(d.0) };
                    if target_pid == pid || target_pid == 0 { continue; } // uchwyt do samego siebie nie jest ciekawy
                    let name = self.procs.get(&target_pid).map(|p| p.0.as_str()).unwrap_or("?");
                    let notes = crate::wintables::process_access_notes(access);
                    format!("PID {target_pid} ({name}){}", if notes.is_empty() { String::new() } else { trf!("; prawa: {}", "; rights: {}", notes.join(", ")) })
                }
                "file" => {
                    let Some(d) = held.or_else(|| dup(value, 0)) else { unnamed += 1; continue };
                    // SAFETY: uchwyt z udanego kopiowania; GetFileType nie blokuje.
                    match unsafe { GetFileType(d.0) } {
                        FILE_TYPE_DISK => match worker.query(d, true) {
                            Ok(Some(p)) => p,
                            Ok(None) => { unnamed += 1; continue; }
                            Err(()) => { timeouts += 1; c.notes.push(trf!("uchwyt {value:#x}: zapytanie o ścieżkę pliku przekroczyło limit czasu", "handle {value:#x}: file path query timed out")); continue; }
                        },
                        FILE_TYPE_PIPE => { c.files.push(OpenFile { fd: value as u32, kind: "pipe".into(), target: tr!("potok albo gniazdo (nazwa niepytana)", "pipe or socket (name not queried)").into(), deleted: false }); continue; }
                        FILE_TYPE_CHAR => { c.files.push(OpenFile { fd: value as u32, kind: "device".into(), target: tr!("urządzenie znakowe", "character device").into(), deleted: false }); continue; }
                        _ => { unnamed += 1; continue; }
                    }
                }
                _ => {
                    let Some(d) = held.or_else(|| dup(value, 0)) else { unnamed += 1; continue };
                    match worker.query(d, false) {
                        Ok(Some(n)) => n,
                        Ok(None) => { unnamed += 1; continue; } // obiekt bez nazwy
                        Err(()) => { timeouts += 1; c.notes.push(trf!("uchwyt {value:#x} ({kind}): zapytanie o nazwę przekroczyło limit czasu", "handle {value:#x} ({kind}): name query timed out")); continue; }
                    }
                }
            };
            c.files.push(OpenFile { fd: value as u32, kind: kind.into(), target, deleted: false });
        }
        if c.files.len() >= MAX_HANDLES { c.notes.push(trf!("uchwytów: {}, zapisano pierwsze {MAX_HANDLES} nazwanych", "handles: {}, first {MAX_HANDLES} named ones recorded", c.files_total)); }
        let _ = unnamed;
    }

    pub fn host(&self) -> HostContext {
        // SAFETY: struktura lokalna z ustawionym rozmiarem; funkcja tylko ją wypełnia.
        let os = unsafe {
            let mut v: OsVersion = zeroed();
            v.size = size_of::<OsVersion>() as u32;
            (RtlGetVersion(&mut v) == 0).then(|| (format!("Windows {}.{}", v.major, v.minor), trf!("kompilacja {}", "build {}", v.build)))
        };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        // SAFETY: wywołanie bez argumentów.
        let up = unsafe { GetTickCount64() } / 1000;
        let user = std::env::var("USERNAME").ok().map(|u| match std::env::var("USERDOMAIN") { Ok(d) => format!("{d}\\{u}"), Err(_) => u });
        // Uprawnienia samego skanera: bez podniesienia i SeDebugPrivilege widać tylko własne procesy.
        // SAFETY: pseudouchwyt bieżącego procesu; nie wolno go zamykać, stąd ManuallyDrop.
        let me = std::mem::ManuallyDrop::new(Handle(unsafe { GetCurrentProcess() }));
        let (token_user, flags) = token_facts(&me);
        let flag = |k: &str| flags.iter().find(|f| f.0 == k).map(|f| f.1.clone()).unwrap_or_else(|| tr!("nieznane", "unknown").into());
        let debug = enable_debug_privilege();
        // Rozstrzyga poziom integralności tokenu: "wysoki" to administrator z podniesionymi uprawnieniami,
        // "systemowy" to konto SYSTEM. Pole TokenElevation jest tylko informacją dodatkową.
        let integrity = flag(tr!("poziom integralności", "integrity level"));
        let (privileges, limited) = crate::wintables::scanner_privileges(&integrity, debug, token_user.as_deref().map(|u| u.ends_with("\\SYSTEM")).unwrap_or(false));
        HostContext { os: os.as_ref().map(|o| o.0.clone()), kernel: os.map(|o| o.1), boot: Some(rfc3339(now.saturating_sub(up) as i64)), scanner_user: user,
            system_drive: std::env::var("SystemRoot").ok().filter(|r| r.as_bytes().get(1) == Some(&b':')).map(|r| r[..2].to_string()),
            scanner_privileges: Some(privileges), scanner_limited: limited }
    }

    fn proc_ref(&self, pid: u32, name: &str, h: Option<&Handle>) -> ProcRef {
        ProcRef { pid, name: name.to_string(), exe: h.and_then(image_path), cmdline: h.and_then(command_line) }
    }

    pub fn context(&self, pid: u32) -> ProcessContext {
        let mut c = ProcessContext::default();
        let Some(h) = open_limited(pid) else {
            c.notes.push(tr!("proces niedostępny dla zapytań o metadane: kontekst systemowy niezebrany", "process inaccessible to metadata queries: system context not collected").into());
            return c;
        };
        if let Some((_, ppid, threads)) = self.procs.get(&pid) { c.ppid = Some(*ppid); c.threads = Some(*threads); }
        let created = creation_time(&h);
        c.started = created.map(|t| rfc3339(crate::wintables::filetime_to_unix(t)));
        c.cmdline = command_line(&h);
        let (user, flags) = token_facts(&h);
        c.user = user;
        c.flags = flags;
        let mut session: u32 = 0;
        // SAFETY: wskaźnik na lokalną zmienną wyjściową.
        if unsafe { ProcessIdToSessionId(pid, &mut session) } != 0 { c.flags.push(("sesja".into(), session.to_string())); }

        if let Some(path) = image_path(&h) {
            if !path_is_local(&path) {
                c.notes.push(tr!("plik programu leży na zasobie sieciowym: skaner go nie otwiera, brak rozmiaru i skrótu SHA-256", "program file is on a network share: the scanner does not open it, no size or SHA-256 hash").into());
            } else {
                match std::fs::metadata(&path) {
                    Ok(m) => {
                        let modified = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| rfc3339(d.as_secs() as i64));
                        c.exe_file = Some(FileFacts { size: m.len(), modified, owner: None, mode: None, sha256: crate::sysctx::sha256_file(&path, m.len()) });
                    }
                    Err(_) => c.notes.push(tr!("plik programu niedostępny: brak rozmiaru i skrótu SHA-256", "program file inaccessible: no size or SHA-256 hash").into()),
                }
            }
        }

        // Przodkowie: numer PID rodzica mógł zostać użyty ponownie, więc rodzic musi być starszy od dziecka.
        let (mut cur, mut child_created) = (c.ppid, created);
        while let Some(p) = cur.filter(|p| *p != 0 && c.ancestors.len() < 16) {
            let Some((name, ppid, _)) = self.procs.get(&p) else {
                c.notes.push(trf!("proces nadrzędny PID {p} już nie istnieje", "parent process PID {p} no longer exists"));
                break;
            };
            let ph = open_limited(p);
            let pc = ph.as_ref().and_then(creation_time);
            if let (Some(a), Some(b)) = (pc, child_created) {
                if a > b { c.notes.push(trf!("PID {p} został użyty ponownie po zakończeniu procesu nadrzędnego; łańcuch przodków urwany", "PID {p} was reused after the parent process exited; ancestor chain cut short")); break; }
            }
            c.ancestors.push(self.proc_ref(p, name, ph.as_ref()));
            if pc.is_some() { child_created = pc; }
            cur = Some(*ppid);
        }
        let mut kids: Vec<(&u32, &(String, u32, u32))> = self.procs.iter().filter(|(k, v)| v.1 == pid && **k != pid).collect();
        kids.sort_by_key(|k| *k.0);
        for (k, (name, _, _)) in kids.into_iter().take(50) {
            let kh = open_limited(*k);
            // dziecko musi być młodsze od badanego procesu (ochrona przed ponownym użyciem PID)
            if let (Some(a), Some(b)) = (kh.as_ref().and_then(creation_time), created) { if a < b { continue; } }
            c.children.push(self.proc_ref(*k, name, kh.as_ref()));
        }
        c.sockets = self.sockets.get(&pid).cloned().unwrap_or_default();
        self.open_handles(pid, &mut c);
        c.notes.push(tr!("Windows: katalog roboczy nie jest zbierany; z uchwytów zapisywane są nazwane pliki, klucze rejestru, sekcje, muteksy i uchwyty do innych procesów", "Windows: the working directory is not collected; of the handles, named files, registry keys, sections, mutexes and handles to other processes are recorded").into());
        c
    }
}

pub fn list() -> Result<Vec<ProcEntry>> {
    // SAFETY: wywołanie bez wskaźników; wynik sprawdzany.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE { return Err(Error::Access("CreateToolhelp32Snapshot".into())); }
    let snap = Handle(snap);
    // SAFETY: PROCESSENTRY32W to zwykła struktura danych; zero jest poprawną wartością.
    let mut e: PROCESSENTRY32W = unsafe { zeroed() };
    e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut v = Vec::new();
    // SAFETY: `e` ma ustawione dwSize i żyje przez całe wywołanie.
    let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
    while ok != 0 {
        v.push(ProcEntry { pid: e.th32ProcessID, name: from_wide(&e.szExeFile) });
        // SAFETY: jw.
        ok = unsafe { Process32NextW(snap.0, &mut e) };
    }
    v.sort_by_key(|p| p.pid);
    Ok(v)
}
