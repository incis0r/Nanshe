//! Kontekst systemowy procesu na Linuksie: wyłącznie odczyt /proc (Z1). Parsery są czystymi
//! funkcjami, testowalnymi na każdej platformie; odczyt plików jest w `collect`.
use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
const MAX_FILES: usize = 200;
#[cfg(target_os = "linux")]
const MAX_CHILDREN: usize = 50;
const MAX_CMDLINE: usize = 2000;
const MAX_HASH_BYTES: u64 = 512 << 20;
/// Jądro liczy czas startu w tyknięciach; USER_HZ to w praktyce zawsze 100.
#[cfg(target_os = "linux")]
const USER_HZ: u64 = 100;

/// Pola /proc/<pid>/stat: (nazwa, ppid, liczba wątków, start w tyknięciach od startu systemu).
/// Nazwa może zawierać spacje i nawiasy, dlatego liczymy od ostatniego ')'.
pub fn parse_stat(s: &str) -> Option<(String, u32, u32, u64)> {
    let (open, close) = (s.find('(')?, s.rfind(')')?);
    let name = s.get(open + 1..close)?.to_string();
    let f: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    Some((name, f.get(1)?.parse().ok()?, f.get(17)?.parse().ok()?, f.get(19)?.parse().ok()?))
}

/// Wartość pola z /proc/<pid>/status, np. "Uid" -> "1000 1000 1000 1000".
pub fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':'))).map(str::trim)
}

pub fn cmdline(raw: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(raw);
    let t = s.split('\0').filter(|a| !a.is_empty()).collect::<Vec<_>>().join(" ");
    if t.is_empty() { return None; }
    Some(if t.chars().count() > MAX_CMDLINE { format!("{}...", t.chars().take(MAX_CMDLINE).collect::<String>()) } else { t })
}

/// Adres z /proc/net/tcp: "0100007F:1F90" albo 32 cyfry szesnastkowe dla IPv6. Jądro wypisuje
/// słowa 32-bitowe w kolejności bajtów hosta; zakładamy little-endian (x86_64, aarch64).
pub fn parse_addr(s: &str) -> Option<String> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let bytes = unhex(&a.to_ascii_lowercase())?;
    match bytes.len() {
        4 => Some(format!("{}.{}.{}.{}:{port}", bytes[3], bytes[2], bytes[1], bytes[0])),
        16 => {
            let mut b = [0u8; 16];
            for (i, w) in bytes.chunks(4).enumerate() { for k in 0..4 { b[i * 4 + k] = w[3 - k]; } }
            Some(format!("[{}]:{port}", std::net::Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED", "02" => "SYN_SENT", "03" => "SYN_RECV", "04" => "FIN_WAIT1", "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT", "07" => "CLOSE", "08" => "CLOSE_WAIT", "09" => "LAST_ACK", "0A" => "LISTEN", "0B" => "CLOSING",
        _ => "?",
    }
}

/// Tabela /proc/net/{tcp,tcp6,udp,udp6}: i-węzeł gniazda -> opis.
pub fn parse_inet(table: &str, proto: &str) -> HashMap<u64, Socket> {
    let mut m = HashMap::new();
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (Some(local), Some(remote), Some(st), Some(ino)) = (f.get(1).and_then(|a| parse_addr(a)), f.get(2).and_then(|a| parse_addr(a)), f.get(3), f.get(9).and_then(|i| i.parse::<u64>().ok())) else { continue };
        if ino == 0 { continue; }
        let unconnected = remote.ends_with(":0");
        let state = if proto.starts_with("tcp") { Some(tcp_state(st).to_string()) } else { None };
        m.insert(ino, Socket { proto: proto.into(), local, remote: (!unconnected).then_some(remote), state });
    }
    m
}

/// Tabela /proc/net/unix: i-węzeł -> ścieżka (pusta dla gniazd bez nazwy).
pub fn parse_unix(table: &str) -> HashMap<u64, Socket> {
    let mut m = HashMap::new();
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(ino) = f.get(6).and_then(|i| i.parse::<u64>().ok()) else { continue };
        let path = f.get(7..).map(|p| p.join(" ")).unwrap_or_default();
        m.insert(ino, Socket { proto: "unix".into(), local: if path.is_empty() { tr!("(bez nazwy)", "(unnamed)").into() } else { path }, remote: None, state: None });
    }
    m
}

/// Cel deskryptora (/proc/<pid>/fd/N) -> (rodzaj, cel bez sufiksu, czy usunięty, i-węzeł gniazda).
pub fn classify_fd(target: &str) -> (&'static str, String, bool, Option<u64>) {
    let (t, deleted) = match target.strip_suffix(" (deleted)") { Some(t) => (t, true), None => (target, false) };
    if let Some(i) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) { return ("socket", t.into(), false, i.parse().ok()); }
    if t.starts_with("pipe:[") { return ("pipe", t.into(), false, None); }
    if t.starts_with("anon_inode:") { return ("anon", t.into(), false, None); }
    if let Some(m) = t.strip_prefix("/memfd:") { return ("memfd", format!("memfd:{m}"), deleted, None); }
    if t.starts_with("/dev/") { return ("device", t.into(), deleted, None); }
    if t.starts_with('/') { return ("file", t.into(), deleted, None); }
    ("other", t.into(), deleted, None)
}

/// Nazwa użytkownika z treści /etc/passwd.
pub fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let (name, _, id) = (f.next()?, f.next()?, f.next()?);
        (id.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

/// Opis uprawnień skanera na Linuksie z pól Uid i CapEff jego /proc/self/status. Zwraca
/// (opis, czy uprawnienia są niepełne). Pełne: root z CAP_SYS_PTRACE (bit 19).
pub fn scanner_privileges(status: &str) -> (String, bool) {
    let uid = status_field(status, "Uid").and_then(|v| v.split_whitespace().nth(1)?.parse::<u32>().ok());
    let ptrace = status_field(status, "CapEff").and_then(|v| u64::from_str_radix(v, 16).ok()).map(|c| c & (1 << 19) != 0).unwrap_or(false);
    let full = uid == Some(0) && ptrace;
    (format!("{}; CAP_SYS_PTRACE: {}", match uid { Some(0) => "root".to_string(), Some(u) => trf!("zwykły użytkownik (uid {u})", "regular user (uid {u})"), None => tr!("użytkownik nieznany", "unknown user").into() }, if ptrace { tr!("tak", "yes") } else { tr!("nie", "no") }), !full)
}

/// Zmienne środowiskowe wpływające na ładowanie kodu; reszty środowiska nie zbieramy.
pub fn loader_env(environ: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(environ).split('\0').filter_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"].contains(&k).then(|| (k.to_string(), v.chars().take(300).collect()))
    }).collect()
}

/// Adres instrukcji z /proc/<pid>/task/<tid>/syscall: "numer arg0..arg5 sp pc" albo "-1 sp pc"
/// dla wątku zablokowanego poza wywołaniem systemowym. "running" i błędne dane dają None.
pub fn syscall_pc(line: &str) -> Option<u64> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 3 || f[0] == "running" { return None; }
    let pc = f.last()?.strip_prefix("0x")?;
    u64::from_str_radix(pc, 16).ok().filter(|v| *v != 0)
}

/// Z /proc/<pid>/smaps: początek mapowania -> bajty stron anonimowych (pole "Anonymous").
/// Dla mapowania pliku niezerowa wartość oznacza strony zmienione w pamięci (kopia przy zapisie).
/// Mapowanie wg smaps: rozmiar stron anonimowych (zapisanych przez proces) oraz skąd w pliku pochodzi.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SmapsEntry {
    pub anonymous: u64,
    /// Przesunięcie początku mapowania w pliku.
    pub offset: u64,
    /// Urządzenie ("maj:min", szesnastkowo) i numer i-węzła pliku: do sprawdzenia, czy plik pod ścieżką to ten sam plik.
    pub dev: String,
    pub inode: u64,
}

pub fn smaps_anonymous(smaps: &str) -> HashMap<u64, SmapsEntry> {
    let mut out: HashMap<u64, SmapsEntry> = HashMap::new();
    let mut base: Option<u64> = None;
    for l in smaps.lines() {
        if let Some(v) = l.strip_prefix("Anonymous:") {
            if let (Some(b), Some(kb)) = (base, v.split_whitespace().next().and_then(|x| x.parse::<u64>().ok())) { out.entry(b).or_default().anonymous = kb * 1024; }
        } else if let Some((range, rest)) = l.split_once(' ') {
            // nagłówek mapowania: "start-end perms offset dev inode ..."; wiersze pól mają dwukropek w pierwszym słowie
            if let Some((a, b)) = range.split_once('-') {
                if let (Ok(s), Ok(_)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) {
                    base = Some(s);
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    let e = out.entry(s).or_default();
                    e.offset = f.get(1).and_then(|x| u64::from_str_radix(x, 16).ok()).unwrap_or(0);
                    e.dev = f.get(2).map(|x| x.to_string()).unwrap_or_default();
                    e.inode = f.get(3).and_then(|x| x.parse().ok()).unwrap_or(0);
                }
            }
        }
    }
    out
}

/// Otwiera zwykły plik z kontrolami jak przy liczeniu skrótu: najpierw zapytanie bez otwierania
/// (urządzenia i potoki nie są otwierane), potem otwarcie i ponowna kontrola na otwartym uchwycie.
fn open_regular(path: &str) -> std::result::Result<(std::fs::File, std::fs::Metadata), String> {
    let before = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !before.is_file() { return Err(tr!("nie jest zwykłym plikiem", "not a regular file").into()); }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    { use std::os::unix::fs::OpenOptionsExt; opts.custom_flags(0o4000 | 0o400); } // O_NONBLOCK | O_NOCTTY
    let f = opts.open(path).map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() { return Err(tr!("nie jest zwykłym plikiem", "not a regular file").into()); }
    #[cfg(unix)]
    { use std::os::unix::fs::MetadataExt; if (m.dev(), m.ino()) != (before.dev(), before.ino()) { return Err(tr!("plik podmieniony między sprawdzeniem a otwarciem", "file replaced between check and open").into()); } }
    Ok((f, m))
}

/// Największy fragment pliku czytany do porównania kodu z plikiem na dysku.
pub const MAX_COMPARE_BYTES: u64 = 64 << 20;

/// Czyta najwyżej `len` bajtów zwykłego pliku od przesunięcia `off` (krócej, jeśli plik się kończy).
/// Zwraca też urządzenie i i-węzeł otwartego pliku (na systemach uniksowych), żeby wywołujący mógł
/// sprawdzić, że to ten plik, o który chodziło.
pub fn read_file_range(path: &str, off: u64, len: u64) -> std::result::Result<(Vec<u8>, u64, u64), String> {
    use std::io::{Read, Seek, SeekFrom};
    let (mut f, m) = open_regular(path)?;
    #[cfg(unix)]
    let id = { use std::os::unix::fs::MetadataExt; (m.dev(), m.ino()) };
    #[cfg(not(unix))]
    let id = (0u64, 0u64);
    let want = len.min(MAX_COMPARE_BYTES).min(m.len().saturating_sub(off.min(m.len())));
    f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(want as usize);
    f.take(want).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok((buf, id.0, id.1))
}

/// Liczba różnych bajtów i indeks pierwszego; krótszy bufor jest dopełniany zerami
/// (część mapowania za końcem pliku system wypełnia zerami).
pub fn count_diff(mem: &[u8], file: &[u8]) -> (u64, Option<usize>) {
    let (mut n, mut first) = (0u64, None);
    for (i, b) in mem.iter().enumerate() {
        if *b != file.get(i).copied().unwrap_or(0) { n += 1; if first.is_none() { first = Some(i); } }
    }
    (n, first)
}

/// Wynik liczenia skrótu: rozmiar wg otwartego uchwytu i skrót albo powód jego braku.
pub struct Hashed { pub size: u64, pub sha256: Option<String>, pub why: Option<String> }

/// SHA-256 pliku. Najpierw zapytanie o typ bez otwierania: urządzenia, potoki i gniazda nie są
/// otwierane wcale (samo otwarcie urządzenia potrafi mieć skutki uboczne). Potem jedno otwarcie
/// (na Linuksie bez blokowania i bez przejmowania terminala) i ponowna kontrola na otwartym uchwycie:
/// to musi być nadal ten sam zwykły plik, więc podmiana między zapytaniem a otwarciem daje błąd.
/// Czytane jest najwyżej MAX_HASH_BYTES: plik, który urósł ponad limit w trakcie czytania, nie dostaje skrótu.
pub fn sha256_open(path: &str) -> std::result::Result<Hashed, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let (f, m) = open_regular(path)?;
    if m.len() > MAX_HASH_BYTES { return Ok(Hashed { size: m.len(), sha256: None, why: Some(tr!("plik większy niż limit 512 MiB", "file larger than the 512 MiB limit").into()) }); }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut limited = f.take(MAX_HASH_BYTES + 1);
    let mut total: u64 = 0;
    loop {
        match limited.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { total += n as u64; if total > MAX_HASH_BYTES { return Ok(Hashed { size: total, sha256: None, why: Some(tr!("plik urósł ponad limit 512 MiB w trakcie czytania", "file grew beyond the 512 MiB limit while being read").into()) }); } h.update(&buf[..n]); }
            Err(e) => return Ok(Hashed { size: m.len(), sha256: None, why: Some(trf!("błąd odczytu: {e}", "read error: {e}")) }),
        }
    }
    Ok(Hashed { size: total, sha256: Some(hex(&h.finalize())), why: None })
}

/// Skrót pliku albo None; rozmiar podany przez wywołującego nie jest używany do decyzji.
pub fn sha256_file(path: &str, _size: u64) -> Option<String> { sha256_open(path).ok().and_then(|h| h.sha256) }

#[cfg(target_os = "linux")]
mod collect {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    /// Obraz hosta zebrany raz na skan: procesy i czas startu systemu.
    pub struct Snapshot { procs: HashMap<u32, (String, u32)>, btime: Option<u64>, passwd: String }

    fn read(pid: u32, f: &str) -> Option<String> { fs::read_to_string(format!("/proc/{pid}/{f}")).ok() }

    fn proc_ref(pid: u32, name: &str) -> ProcRef {
        ProcRef { pid, name: name.to_string(),
            exe: fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned()),
            cmdline: fs::read(format!("/proc/{pid}/cmdline")).ok().and_then(|c| cmdline(&c)) }
    }

    impl Snapshot {
        pub fn take() -> Self {
            let mut procs = HashMap::new();
            if let Ok(dir) = fs::read_dir("/proc") {
                for e in dir.flatten() {
                    if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                        if let Some((name, ppid, _, _)) = read(pid, "stat").as_deref().and_then(parse_stat) { procs.insert(pid, (name, ppid)); }
                    }
                }
            }
            let btime = fs::read_to_string("/proc/stat").ok().and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ")).and_then(|v| v.trim().parse().ok()));
            Snapshot { procs, btime, passwd: fs::read_to_string("/etc/passwd").unwrap_or_default() }
        }

        pub fn host(&self) -> HostContext {
            let os = fs::read_to_string("/etc/os-release").ok().and_then(|s| s.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string()));
            let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string());
            let status = read(std::process::id(), "status").unwrap_or_default();
            let (privileges, limited) = scanner_privileges(&status);
            let uid = status_field(&status, "Uid").and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok());
            HostContext { os, kernel, boot: self.btime.map(|b| rfc3339(b as i64)),
                scanner_user: uid.map(|u| format!("{} (uid {u})", user_name(&self.passwd, u).unwrap_or_else(|| "?".into()))), system_drive: None,
                scanner_privileges: Some(privileges), scanner_limited: limited }
        }

        pub fn context(&self, pid: u32) -> ProcessContext {
            let mut c = ProcessContext::default();
            let stat = read(pid, "stat").as_deref().and_then(parse_stat);
            if let Some((_, ppid, threads, start)) = &stat {
                c.ppid = Some(*ppid);
                c.threads = Some(*threads);
                c.started = self.btime.map(|b| rfc3339((b + start / USER_HZ) as i64));
            } else { c.notes.push(tr!("brak /proc/<pid>/stat: rodzic, wątki i czas startu nieznane", "no /proc/<pid>/stat: parent, threads and start time unknown").into()); }
            c.cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok().and_then(|x| cmdline(&x));
            c.cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok().map(|p| p.to_string_lossy().into_owned());

            if let Some(st) = read(pid, "status") {
                if let Some(uid) = status_field(&st, "Uid").and_then(|v| v.split_whitespace().nth(1)?.parse::<u32>().ok()) {
                    // nazwa wg /etc/passwd skanera; proces w kontenerze może mieć własną bazę użytkowników
                    c.user = Some(format!("{} (uid {uid})", user_name(&self.passwd, uid).unwrap_or_else(|| "?".into())));
                }
                if let Some(t) = status_field(&st, "TracerPid").filter(|t| *t != "0") { c.flags.push((tr!("śledzony przez (ptrace)", "traced by (ptrace)").into(), format!("PID {t}"))); }
                if let Some(v) = status_field(&st, "CapEff") { c.flags.push((tr!("uprawnienia efektywne (CapEff)", "effective capabilities (CapEff)").into(), v.to_string())); }
                if let Some(v) = status_field(&st, "Seccomp") { c.flags.push(("seccomp".into(), match v { "0" => tr!("wyłączony", "disabled").into(), "1" => tr!("ścisły", "strict").into(), "2" => tr!("filtr", "filter").into(), x => x.to_string() })); }
                if let Some(v) = status_field(&st, "NoNewPrivs") { c.flags.push(("no_new_privs".into(), v.to_string())); }
            }
            if let Ok(root) = fs::read_link(format!("/proc/{pid}/root")) {
                if root.as_os_str() != "/" { c.flags.push((tr!("katalog główny (chroot)", "root directory (chroot)").into(), root.to_string_lossy().into_owned())); }
            }
            match fs::read(format!("/proc/{pid}/environ")) {
                Ok(env) => for (k, v) in loader_env(&env) { c.flags.push((trf!("zmienna {k}", "env {k}"), v)); },
                Err(_) => c.notes.push(tr!("środowisko procesu niedostępne: zmienne LD_PRELOAD/LD_AUDIT niesprawdzone", "process environment inaccessible: LD_PRELOAD/LD_AUDIT variables not checked").into()),
            }

            // plik programu: przez /proc/<pid>/exe, czyli faktycznie uruchomiony plik, także usunięty
            let exe = format!("/proc/{pid}/exe");
            if let Ok(m) = fs::metadata(&exe) {
                c.exe_file = Some(FileFacts { size: m.len(), modified: Some(rfc3339(m.mtime())),
                    owner: Some(format!("{} (uid {})", user_name(&self.passwd, m.uid()).unwrap_or_else(|| "?".into()), m.uid())),
                    mode: Some(format!("{:04o}", m.mode() & 0o7777)), sha256: sha256_file(&exe, m.len()) });
            } else { c.notes.push(tr!("plik programu niedostępny: brak rozmiaru i skrótu SHA-256", "program file inaccessible: no size or SHA-256 hash").into()); }

            // przodkowie i dzieci z obrazu hosta
            let mut cur = c.ppid;
            while let Some(p) = cur.filter(|p| *p != 0 && c.ancestors.len() < 16) {
                let Some((name, ppid)) = self.procs.get(&p) else { break };
                c.ancestors.push(proc_ref(p, name));
                cur = Some(*ppid);
            }
            let mut kids: Vec<(&u32, &(String, u32))> = self.procs.iter().filter(|(_, v)| v.1 == pid).collect();
            kids.sort_by_key(|k| *k.0);
            if kids.len() > MAX_CHILDREN { c.notes.push(trf!("procesów potomnych: {}, pokazano {MAX_CHILDREN}", "child processes: {}, {MAX_CHILDREN} shown", kids.len())); }
            c.children = kids.into_iter().take(MAX_CHILDREN).map(|(p, (n, _))| proc_ref(*p, n)).collect();

            // deskryptory i gniazda (tabele sieci z przestrzeni nazw badanego procesu)
            match fs::read_dir(format!("/proc/{pid}/fd")) {
                Ok(dir) => {
                    let mut fds: Vec<(u32, String)> = dir.flatten().filter_map(|e| Some((e.file_name().to_str()?.parse().ok()?, fs::read_link(e.path()).ok()?.to_string_lossy().into_owned()))).collect();
                    fds.sort();
                    c.files_total = fds.len() as u32;
                    let mut inet: HashMap<u64, Socket> = HashMap::new();
                    for proto in ["tcp", "tcp6", "udp", "udp6"] {
                        if let Some(t) = read(pid, &format!("net/{proto}")) { inet.extend(parse_inet(&t, proto)); }
                    }
                    if let Some(t) = read(pid, "net/unix") { for (k, v) in parse_unix(&t) { inet.entry(k).or_insert(v); } }
                    for (fd, target) in fds {
                        let (kind, t, deleted, ino) = classify_fd(&target);
                        if let Some(s) = ino.and_then(|i| inet.get(&i)) { if !c.sockets.contains(s) { c.sockets.push(s.clone()); } }
                        if c.files.len() < MAX_FILES { c.files.push(OpenFile { fd, kind: kind.into(), target: t, deleted }); }
                    }
                    if c.files_total as usize > MAX_FILES { c.notes.push(trf!("deskryptorów: {}, zapisano pierwsze {MAX_FILES}", "descriptors: {}, first {MAX_FILES} recorded", c.files_total)); }
                }
                Err(_) => c.notes.push(tr!("lista deskryptorów niedostępna: otwarte pliki i gniazda nieznane", "descriptor list inaccessible: open files and sockets unknown").into()),
            }
            c
        }
    }
}
#[cfg(target_os = "linux")]
pub use collect::Snapshot;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_hostile_name() {
        // nazwa procesu ze spacją i nawiasem nie może przesunąć pól
        let s = "42 (a) b (c)) S 7 42 42 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 3 0 12345 1000 10 18446744073709551615";
        assert_eq!(parse_stat(s), Some(("a) b (c)".into(), 7, 3, 12345)));
        assert_eq!(parse_stat("śmieci"), None);
        assert_eq!(parse_stat("1 (x) S 1"), None);
    }

    #[test]
    fn thread_pc_and_modified_pages() {
        assert_eq!(syscall_pc("73 0x0 0x0 0x0 0x0 0x0 0x0 0xffffd2a0 0xffff9c1a4e2c"), Some(0xffff9c1a4e2c));
        assert_eq!(syscall_pc("-1 0x7ffc1000 0x7f00aabb"), Some(0x7f00aabb));
        for bad in ["running", "", "73 0x0", "73 0x0 0x0 zz", "-1 0x0 0x0"] { assert_eq!(syscall_pc(bad), None, "{bad}"); }
        let smaps = "55d0c3a02000-55d0c3a06000 r-xp 00002000 fd:01 1234 /usr/bin/cat\nSize:                 16 kB\nRss:                  16 kB\nAnonymous:             4 kB\nVmFlags: rd ex mr\n7f1000000000-7f1000010000 r-xp 00000000 fd:01 77 /usr/lib/libc.so.6\nSize:                 64 kB\nAnonymous:             0 kB\nAnonHugePages:         0 kB\n";

        let m = smaps_anonymous(smaps);
        assert_eq!((m[&0x55d0c3a02000].anonymous, m[&0x7f1000000000].anonymous, m.len()), (4096, 0, 2));
        assert_eq!(m[&0x55d0c3a02000], SmapsEntry { anonymous: 4096, offset: 0x2000, dev: "fd:01".into(), inode: 1234 });
        // porównanie treści: różnice liczone bajt po bajcie, koniec pliku to zera
        assert_eq!(count_diff(b"abcdef", b"abcdef"), (0, None));
        assert_eq!(count_diff(b"abXdeY", b"abcdef"), (2, Some(2)));
        assert_eq!(count_diff(&[1, 2, 0, 0], &[1, 2]), (0, None));
        assert_eq!(count_diff(&[1, 2, 0, 9], &[1, 2]), (1, Some(3)));
        assert!(smaps_anonymous("śmieci\nAnonymous: 4 kB\n").is_empty(), "pole bez nagłówka mapowania jest ignorowane");
    }

    #[test]
    fn hashing_opens_once_and_takes_only_regular_files() {
        let dir = std::env::temp_dir().join(format!("nanshe-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.bin");
        std::fs::write(&f, b"abc").unwrap();
        let h = sha256_open(f.to_str().unwrap()).unwrap();
        assert_eq!((h.size, h.sha256.as_deref()), (3, Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
        // katalog i brak pliku to błąd, nie pusty skrót
        assert!(sha256_open(dir.to_str().unwrap()).is_err());
        assert!(sha256_open(dir.join("brak").to_str().unwrap()).is_err());
        #[cfg(target_os = "linux")]
        {
            // potok nazwany bez piszącego: otwarcie nie może się zawiesić i nie daje skrótu
            let fifo = dir.join("fifo");
            let st = std::process::Command::new("mkfifo").arg(&fifo).status();
            if matches!(st, Ok(s) if s.success()) { assert!(sha256_open(fifo.to_str().unwrap()).is_err()); }
            // urządzenie znakowe nie jest zwykłym plikiem
            assert!(sha256_open("/dev/zero").is_err());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scanner_privileges_from_status() {
        assert_eq!(scanner_privileges("Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n"), ("root; CAP_SYS_PTRACE: tak".to_string(), false));
        // root w kontenerze bez CAP_SYS_PTRACE i zwykły użytkownik: uprawnienia niepełne
        assert_eq!(scanner_privileges("Uid:\t0\t0\t0\t0\nCapEff:\t00000000a80425fb\n"), ("root; CAP_SYS_PTRACE: nie".to_string(), true));
        assert_eq!(scanner_privileges("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n"), ("zwykły użytkownik (uid 1000); CAP_SYS_PTRACE: nie".to_string(), true));
        assert!(scanner_privileges("").1);
    }

    #[test]
    fn status_and_cmdline() {
        let st = "Name:\tx\nUid:\t1000\t1001\t1000\t1000\nTracerPid:\t0\nCapEff:\t0000000000000000\n";
        assert_eq!(status_field(st, "Uid"), Some("1000\t1001\t1000\t1000"));
        assert_eq!(status_field(st, "TracerPid"), Some("0"));
        assert_eq!(status_field(st, "Brak"), None);
        assert_eq!(cmdline(b"/bin/sh\0-c\0echo hi\0").as_deref(), Some("/bin/sh -c echo hi"));
        assert_eq!(cmdline(b""), None);
        assert!(cmdline(&vec![b'a'; 5000]).unwrap().ends_with("..."));
    }

    #[test]
    fn addresses_and_tables() {
        assert_eq!(parse_addr("0100007F:1F90").as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(parse_addr("3207A8C0:01BB").as_deref(), Some("192.168.7.50:443"));
        assert_eq!(parse_addr("00000000000000000000000001000000:0016").as_deref(), Some("[::1]:22"));
        assert_eq!(parse_addr("zz:1"), None);
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n\
   1: 0A00000A:D431 3207A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0 20 4 30 10 -1\n   2: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0 100 0 0 10 0\n";

        let m = parse_inet(tcp, "tcp");
        assert_eq!(m.len(), 2, "wiersz bez i-węzła pominięty");
        assert_eq!(m[&111], Socket { proto: "tcp".into(), local: "0.0.0.0:22".into(), remote: None, state: Some("LISTEN".into()) });
        assert_eq!(m[&222], Socket { proto: "tcp".into(), local: "10.0.0.10:54321".into(), remote: Some("192.168.7.50:443".into()), state: Some("ESTABLISHED".into()) });
        let ux = "Num       RefCount Protocol Flags    Type St Inode Path\n0000: 00000002 00000000 00010000 0001 01 333 /run/my sock\n0000: 00000002 00000000 00000000 0002 01 444\n";
        let u = parse_unix(ux);
        assert_eq!(u[&333].local, "/run/my sock");
        assert_eq!(u[&444].local, "(bez nazwy)");
    }

    #[test]
    fn descriptors_users_and_loader_env() {
        assert_eq!(classify_fd("socket:[777]"), ("socket", "socket:[777]".into(), false, Some(777)));
        assert_eq!(classify_fd("/memfd:payload (deleted)"), ("memfd", "memfd:payload".into(), true, None));
        assert_eq!(classify_fd("/tmp/x.so (deleted)"), ("file", "/tmp/x.so".into(), true, None));
        assert_eq!(classify_fd("/dev/pts/0"), ("device", "/dev/pts/0".into(), false, None));
        assert_eq!(classify_fd("pipe:[5]").0, "pipe");
        assert_eq!(classify_fd("anon_inode:[eventpoll]").0, "anon");
        let pw = "root:x:0:0:root:/root:/bin/bash\njan:x:1000:1000::/home/jan:/bin/sh\n";
        assert_eq!(user_name(pw, 1000).as_deref(), Some("jan"));
        assert_eq!(user_name(pw, 5), None);
        // tylko zmienne ładowania kodu; reszta środowiska (w tym sekrety) nie jest zbierana
        let env = b"PATH=/bin\0API_TOKEN=tajne\0LD_PRELOAD=/tmp/evil.so\0";
        assert_eq!(loader_env(env), vec![("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string())]);
    }
}
