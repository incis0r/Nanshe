//! Parsery tabel gniazd Windows (GetExtendedTcpTable / GetExtendedUdpTable z właścicielem PID).
//! Czyste funkcje na surowym buforze: bez `unsafe`, testowalne na każdej platformie.
//! Układ: u32 liczba wierszy, potem wiersze o stałym rozmiarze; porty i adresy IPv4 w kolejności sieciowej.
use nanshe_core::{tr, trf, Socket};

fn u32at(b: &[u8], o: usize) -> Option<u32> { b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])) }
fn port(v: u32) -> u16 { u16::from_be(v as u16) }
fn v4(b: &[u8], o: usize) -> Option<String> { b.get(o..o + 4).map(|x| format!("{}.{}.{}.{}", x[0], x[1], x[2], x[3])) }
fn v6(b: &[u8], o: usize) -> Option<String> {
    let a: [u8; 16] = b.get(o..o + 16)?.try_into().ok()?;
    Some(format!("[{}]", std::net::Ipv6Addr::from(a)))
}
fn state(s: u32) -> &'static str {
    match s { 1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD", 5 => "ESTABLISHED", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT", 9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB", _ => "?" }
}
fn rows(b: &[u8], row: usize) -> impl Iterator<Item = &[u8]> {
    let n = u32at(b, 0).unwrap_or(0) as usize;
    b.get(4..).unwrap_or(&[]).chunks_exact(row).take(n)
}
fn tcp(proto: &str, local: String, remote: String, st: u32) -> Socket {
    let listening = st == 2;
    Socket { proto: proto.into(), local, remote: (!listening).then_some(remote), state: Some(state(st).into()) }
}

/// MIB_TCPROW_OWNER_PID: stan, adres lokalny, port lokalny, adres zdalny, port zdalny, PID (6 x u32).
pub fn tcp4(b: &[u8]) -> Vec<(u32, Socket)> {
    rows(b, 24).filter_map(|r| Some((u32at(r, 20)?, tcp("tcp", format!("{}:{}", v4(r, 4)?, port(u32at(r, 8)?)), format!("{}:{}", v4(r, 12)?, port(u32at(r, 16)?)), u32at(r, 0)?)))).collect()
}
/// MIB_TCP6ROW_OWNER_PID: adres lokalny (16), zakres, port, adres zdalny (16), zakres, port, stan, PID.
pub fn tcp6(b: &[u8]) -> Vec<(u32, Socket)> {
    rows(b, 56).filter_map(|r| Some((u32at(r, 52)?, tcp("tcp6", format!("{}:{}", v6(r, 0)?, port(u32at(r, 20)?)), format!("{}:{}", v6(r, 24)?, port(u32at(r, 44)?)), u32at(r, 48)?)))).collect()
}
/// MIB_UDPROW_OWNER_PID: adres lokalny, port lokalny, PID.
pub fn udp4(b: &[u8]) -> Vec<(u32, Socket)> {
    rows(b, 12).filter_map(|r| Some((u32at(r, 8)?, Socket { proto: "udp".into(), local: format!("{}:{}", v4(r, 0)?, port(u32at(r, 4)?)), remote: None, state: None }))).collect()
}
/// MIB_UDP6ROW_OWNER_PID: adres lokalny (16), zakres, port, PID.
pub fn udp6(b: &[u8]) -> Vec<(u32, Socket)> {
    rows(b, 28).filter_map(|r| Some((u32at(r, 24)?, Socket { proto: "udp6".into(), local: format!("{}:{}", v6(r, 0)?, port(u32at(r, 20)?)), remote: None, state: None }))).collect()
}

/// Czy plik programu leży w jednym z katalogów systemowych (`roots`: np. C:\\Windows, C:\\Program Files).
/// Te katalogi są domyślnie zapisywalne tylko dla administratora i TrustedInstaller. Faktycznych
/// ACL pliku nie sprawdzamy: katalog aplikacji z osłabionymi uprawnieniami przejdzie ten test.
pub fn exe_in_system_dir(exe: &str, roots: &[String]) -> bool {
    let e = exe.to_ascii_lowercase();
    if e.contains("\\..\\") || e.contains('/') { return false; }
    // podkatalogi \Windows, w których zwykły użytkownik może tworzyć pliki
    const USER_WRITABLE: [&str; 12] = ["\\temp\\", "\\tasks\\", "\\tracing\\", "\\spool\\", "\\debug\\", "\\registration\\crmlog\\", "\\system32\\fxstmp\\",
        "\\system32\\com\\dmp\\", "\\syswow64\\fxstmp\\", "\\syswow64\\com\\dmp\\", "\\system32\\microsoft\\crypto\\rsa\\machinekeys\\", "\\servicing\\"];
    if USER_WRITABLE.iter().any(|d| e.contains(d)) { return false; }
    roots.iter().any(|r| { let r = r.trim_end_matches('\\').to_ascii_lowercase(); r.len() >= 3 && e.starts_with(&r) && e[r.len()..].starts_with('\\') })
}

/// Opis uprawnień skanera na Windows i informacja, czy są niepełne. Pełne: poziom integralności
/// wysoki (administrator z podniesionymi uprawnieniami) albo systemowy, z włączonym SeDebugPrivilege.
pub fn scanner_privileges(integrity: &str, debug: bool, system_account: bool) -> (String, bool) {
    // nazwa poziomu przychodzi w języku programu; rozpoznajemy obie postaci
    let (is_system, is_high) = (matches!(integrity, "systemowy" | "system"), matches!(integrity, "wysoki" | "high"));
    let who = if system_account || is_system { tr!("konto SYSTEM", "SYSTEM account") }
        else if is_high { tr!("administrator z podniesionymi uprawnieniami", "elevated administrator") }
        else { tr!("bez podniesionych uprawnień administratora", "without elevated administrator privileges") };
    let full = debug && (system_account || is_high || is_system);
    (trf!("{who}; poziom integralności: {integrity}; SeDebugPrivilege: {}", "{who}; integrity level: {integrity}; SeDebugPrivilege: {}", if debug { tr!("włączone", "enabled") } else { tr!("brak", "absent") }), !full)
}

/// Czy ścieżka Windows wskazuje plik lokalny, sądząc po samej postaci ścieżki. Skaner działa jako
/// administrator albo SYSTEM: otwarcie ścieżki sieciowej podanej przez badany proces wysłałoby
/// poświadczenia komputera na wskazany serwer. Litery dysków (które mogą być mapowaniem sieciowym)
/// rozstrzyga osobno typ dysku; tutaj przechodzą.
pub fn path_form_is_local(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let p = p.strip_prefix("\\\\?\\globalroot").unwrap_or(&p);
    if let Some(dev) = p.strip_prefix("\\device\\") {
        // z urządzeń tylko wolumeny dyskowe; Mup, LanmanRedirector, WebDavRedirector to sieć
        return dev.strip_prefix("harddiskvolume").map(|r| r.starts_with(|c: char| c.is_ascii_digit())).unwrap_or(false);
    }
    let p = p.strip_prefix("\\\\?\\").unwrap_or(p);
    if p.starts_with("unc\\") || p.starts_with("\\\\") || p.starts_with("//") { return false; }
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Czy właściciel pliku (SID w postaci tekstowej) to konto systemowe: SYSTEM, grupa Administratorzy
/// albo TrustedInstaller. Plik podrzucony przez zwykłego użytkownika (także administratora bez
/// podniesienia uprawnień) ma za właściciela tego użytkownika.
pub fn owner_sid_trusted(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544" | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
}

/// FILETIME (100 ns od 1601) -> sekundy uniksowe.
pub fn filetime_to_unix(ft: u64) -> i64 { (ft / 10_000_000) as i64 - 11_644_473_600 }

/// Poziom integralności z ostatniego podurzędu SID etykiety.
pub fn integrity(rid: u32) -> &'static str {
    match rid { 0..=0x0fff => tr!("niezaufany", "untrusted"), 0x1000..=0x1fff => tr!("niski", "low"), 0x2000..=0x2fff => tr!("średni", "medium"), 0x3000..=0x3fff => tr!("wysoki", "high"), _ => tr!("systemowy", "system") }
}

/// Wpis tabeli uchwytów systemu (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, x64, 40 bajtów):
/// obiekt (8), PID (8), wartość uchwytu (8), prawa (4), indeks śladu (2), indeks typu (2), atrybuty (4), rezerwa (4).
/// Nagłówek tabeli: liczba wpisów (8), rezerwa (8). Zwraca (uchwyt, indeks typu, prawa) dla podanego PID.
pub fn handles_of(b: &[u8], pid: u32) -> Vec<(u64, u16, u32)> {
    let u64at = |r: &[u8], o: usize| r.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap()));
    let n = u64at(b, 0).unwrap_or(0) as usize;
    b.get(16..).unwrap_or(&[]).chunks_exact(40).take(n).filter_map(|r| {
        if u64at(r, 8)? != pid as u64 { return None; }
        Some((u64at(r, 16)?, u16::from_le_bytes([r[30], r[31]]), u32at(r, 24)?))
    }).collect()
}

/// Nazwa typu obiektu Windows -> rodzaj w wyniku skanu.
pub fn handle_kind(type_name: &str) -> &'static str {
    match type_name {
        "File" => "file", "Key" => "key", "Section" => "section", "Mutant" => "mutant", "Process" => "process",
        "Thread" => "thread", "Token" => "token", "Event" | "Semaphore" | "Timer" | "IRTimer" | "WaitCompletionPacket" | "IoCompletion" | "TpWorkerFactory" => "sync",
        _ => "other",
    }
}

/// Prawa do obcego procesu, które pozwalają zmieniać jego pamięć albo uruchamiać w nim kod.
pub fn process_access_notes(access: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if access & 0x0020 != 0 { v.push(tr!("zapis pamięci", "memory write")); }       // PROCESS_VM_WRITE
    if access & 0x0008 != 0 { v.push(tr!("operacje na pamięci", "memory operations")); } // PROCESS_VM_OPERATION
    if access & 0x0002 != 0 { v.push(tr!("tworzenie wątków", "thread creation")); }    // PROCESS_CREATE_THREAD
    if access & 0x0040 != 0 { v.push(tr!("kopiowanie uchwytów", "handle duplication")); } // PROCESS_DUP_HANDLE
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u(v: u32) -> [u8; 4] { v.to_le_bytes() }
    fn p(port: u16) -> [u8; 4] { let b = port.to_be_bytes(); [b[0], b[1], 0, 0] }

    #[test]
    fn tcp_and_udp_tables() {
        let mut t = u(2).to_vec();
        for (st, la, lp, ra, rp, pid) in [(2u32, [0u8, 0, 0, 0], 445u16, [0u8, 0, 0, 0], 0u16, 4u32), (5, [192, 168, 7, 26], 50123, [192, 168, 7, 50], 11434, 777)] {
            t.extend(u(st)); t.extend(la); t.extend(p(lp)); t.extend(ra); t.extend(p(rp)); t.extend(u(pid));
        }
        let v = tcp4(&t);
        assert_eq!(v[0], (4, Socket { proto: "tcp".into(), local: "0.0.0.0:445".into(), remote: None, state: Some("LISTEN".into()) }));
        assert_eq!(v[1], (777, Socket { proto: "tcp".into(), local: "192.168.7.26:50123".into(), remote: Some("192.168.7.50:11434".into()), state: Some("ESTABLISHED".into()) }));
        // licznik większy niż dane i obcięty bufor: bez paniki, tylko pełne wiersze
        let mut bad = t.clone(); bad[0] = 9; bad.truncate(4 + 24 + 10);
        assert_eq!(tcp4(&bad).len(), 1);
        assert!(tcp4(&[]).is_empty());

        let mut t6 = u(1).to_vec();
        let mut lo = [0u8; 16]; lo[15] = 1;
        t6.extend(lo); t6.extend(u(0)); t6.extend(p(8080)); t6.extend([0u8; 16]); t6.extend(u(0)); t6.extend(p(0)); t6.extend(u(2)); t6.extend(u(900));
        assert_eq!(tcp6(&t6), vec![(900, Socket { proto: "tcp6".into(), local: "[::1]:8080".into(), remote: None, state: Some("LISTEN".into()) })]);

        let mut d = u(1).to_vec(); d.extend([127, 0, 0, 1]); d.extend(p(53)); d.extend(u(11));
        assert_eq!(udp4(&d), vec![(11, Socket { proto: "udp".into(), local: "127.0.0.1:53".into(), remote: None, state: None })]);
        let mut d6 = u(1).to_vec(); d6.extend(lo); d6.extend(u(0)); d6.extend(p(5353)); d6.extend(u(12));
        assert_eq!(udp6(&d6)[0].1.local, "[::1]:5353");
    }

    #[test]
    fn handle_table_filtered_by_pid() {
        let mut t = Vec::new();
        t.extend(3u64.to_le_bytes()); t.extend(0u64.to_le_bytes());
        for (pid, h, access, typ) in [(10u64, 0x4u64, 0x1f0fffu32, 7u16), (11, 0x8, 0x1, 37), (10, 0x1c, 0x120089, 37)] {
            t.extend(0xffff_8000_0000_0000u64.to_le_bytes()); t.extend(pid.to_le_bytes()); t.extend(h.to_le_bytes());
            t.extend(access.to_le_bytes()); t.extend(0u16.to_le_bytes()); t.extend(typ.to_le_bytes()); t.extend(0u32.to_le_bytes()); t.extend(0u32.to_le_bytes());
        }
        assert_eq!(handles_of(&t, 10), vec![(0x4, 7, 0x1f0fff), (0x1c, 37, 0x120089)]);
        assert!(handles_of(&t, 99).is_empty());
        // licznik większy niż dane i obcięty bufor: bez paniki
        let mut bad = t.clone(); bad[0] = 200; bad.truncate(16 + 40 + 7);
        assert_eq!(handles_of(&bad, 10).len(), 1);
        assert!(handles_of(&[1, 2, 3], 10).is_empty());
        assert_eq!((handle_kind("File"), handle_kind("Key"), handle_kind("Process"), handle_kind("Event"), handle_kind("Desktop")), ("file", "key", "process", "sync", "other"));
        assert_eq!(process_access_notes(0x1f0fff), ["zapis pamięci", "operacje na pamięci", "tworzenie wątków", "kopiowanie uchwytów"]);
        assert!(process_access_notes(0x1000).is_empty(), "samo zapytanie o metadane nie jest oznaczane");
    }

    #[test]
    fn exe_must_sit_under_a_system_root() {
        let roots = vec!["C:\\WINDOWS".to_string(), "C:\\Program Files\\".to_string(), "C:\\Program Files (x86)".to_string()];
        for ok in ["C:\\Windows\\System32\\svchost.exe", "c:\\program files\\App\\a.exe", "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\1\\msedgewebview2.exe"] { assert!(exe_in_system_dir(ok, &roots), "{ok}"); }
        for writable in ["C:\\Windows\\Temp\\a.exe", "C:\\Windows\\Tasks\\a.exe", "C:\\Windows\\System32\\spool\\drivers\\color\\a.exe", "C:\\Windows\\Tracing\\a.exe"] { assert!(!exe_in_system_dir(writable, &roots), "{writable}"); }
        assert!(owner_sid_trusted("S-1-5-18") && owner_sid_trusted("S-1-5-32-544"));
        assert!(!owner_sid_trusted("S-1-5-21-1111111111-2222222222-3333333333-1001") && !owner_sid_trusted("S-1-5-32-545") && !owner_sid_trusted(""));
        for bad in ["C:\\temp\\tools\\helper.exe", "C:\\Users\\jan\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "C:\\WindowsEvil\\a.exe", "D:\\Windows\\a.exe",
            "C:\\Windows\\..\\temp\\a.exe", "C:/Windows/a.exe", "C:\\Windows"] { assert!(!exe_in_system_dir(bad, &roots), "{bad}"); }
        assert!(!exe_in_system_dir("C:\\Windows\\a.exe", &[]), "bez znanych katalogów nic nie jest zaufane");
        assert!(!exe_in_system_dir("C:\\Windows\\a.exe", &["".to_string()]));
    }

    #[test]
    fn network_paths_are_never_treated_as_local() {
        for ok in ["C:\\Windows\\System32\\a.dll", "\\Device\\HarddiskVolume3\\Windows\\a.dll", "\\\\?\\C:\\x\\a.exe", "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume12\\a"] { assert!(path_form_is_local(ok), "{ok}"); }
        for net in ["\\\\serwer\\udzial\\a.exe", "\\Device\\Mup\\serwer\\udzial\\a.dll", "\\Device\\LanmanRedirector\\serwer\\a.dll", "\\Device\\WebDavRedirector\\x",
            "\\\\?\\UNC\\serwer\\udzial\\a", "//serwer/udzial/a", "\\Device\\HarddiskVolumeEvil\\a", "\\Device\\NamedPipe\\x", "wzgledna\\sciezka", ""] { assert!(!path_form_is_local(net), "{net}"); }
    }

    #[test]
    fn scanner_privileges_follow_integrity_and_debug_privilege() {
        assert_eq!(scanner_privileges("wysoki", true, false), ("administrator z podniesionymi uprawnieniami; poziom integralności: wysoki; SeDebugPrivilege: włączone".to_string(), false));
        assert_eq!(scanner_privileges("systemowy", true, true), ("konto SYSTEM; poziom integralności: systemowy; SeDebugPrivilege: włączone".to_string(), false));
        // niepełne: zwykły użytkownik, administrator bez podniesienia (poziom średni), brak SeDebugPrivilege
        assert!(scanner_privileges("średni", false, false).1 && scanner_privileges("średni", true, false).1 && scanner_privileges("wysoki", false, false).1);
        assert!(scanner_privileges("nieznane", true, false).0.starts_with("bez podniesionych"));
    }

    #[test]
    fn time_and_integrity() {
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), 0);
        assert_eq!(filetime_to_unix(116_444_736_000_000_000 + 951_782_400 * 10_000_000), 951_782_400);
        assert_eq!((integrity(0x1000), integrity(0x2000), integrity(0x2010), integrity(0x3000), integrity(0x4000)), ("niski", "średni", "średni", "wysoki", "systemowy"));
    }
}
