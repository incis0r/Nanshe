//! Typy wspólne: regiony, źródła pamięci, znaleziska, wynik skanu.
#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Etykieta regionu, którego treści celowo nie czytamy, bo odczyt zmieniłby stan celu (Windows PAGE_GUARD).
pub const GUARD_LABEL: &str = "[guard]";
pub const SCHEMA_VERSION: u32 = 1;
pub const PAGE: usize = 4096;
/// Limit liczby regionów jednego procesu. Po jego przekroczeniu backend zwraca pierwsze
/// MAX_REGIONS regionów, a analiza oznacza wynik procesu jako niekompletny (Z8).
pub const MAX_REGIONS: usize = 1 << 20;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{}: {}", crate::tr!("brak dostępu", "access denied"), .0)]
    Access(String),
    #[error("{}: {}", crate::tr!("nie znaleziono", "not found"), .0)]
    NotFound(String),
    #[error("{}: {}", crate::tr!("błąd wejścia/wyjścia", "input/output error"), .0)]
    Io(#[from] std::io::Error),
    #[error("{}: {}", crate::tr!("nieobsługiwane", "unsupported"), .0)]
    Unsupported(String),
    #[error("{}: {}", crate::tr!("błędne dane", "invalid data"), .0)]
    Invalid(String),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Język tekstów dla człowieka (raport, opisy w wyniku skanu, komunikaty). Identyfikatory, tagi
/// i nazwy pól wyniku są niezależne od języka.
pub mod lang {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU8, Ordering};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Lang { Pl, En }

    impl Lang {
        pub fn parse(s: &str) -> Option<Lang> {
            match s.trim().to_ascii_lowercase().as_str() { "pl" => Some(Lang::Pl), "en" => Some(Lang::En), _ => None }
        }
        pub fn code(self) -> &'static str { match self { Lang::Pl => "pl", Lang::En => "en" } }
    }

    static GLOBAL: AtomicU8 = AtomicU8::new(0);
    thread_local! { static LOCAL: Cell<Option<Lang>> = const { Cell::new(None) }; }

    /// Język całego programu (ustawiany raz, z wiersza poleceń).
    pub fn set(l: Lang) { GLOBAL.store(l as u8, Ordering::Relaxed); }
    /// Język tylko dla bieżącego wątku; ma pierwszeństwo przed językiem programu. `None` cofa wybór.
    pub fn set_thread(l: Option<Lang>) { LOCAL.with(|c| c.set(l)); }
    pub fn get() -> Lang {
        LOCAL.with(|c| c.get()).unwrap_or(if GLOBAL.load(Ordering::Relaxed) == 1 { Lang::En } else { Lang::Pl })
    }
    /// Wykonuje `f` w podanym języku i przywraca poprzedni wybór wątku.
    pub fn with<T>(l: Lang, f: impl FnOnce() -> T) -> T {
        let prev = LOCAL.with(|c| c.replace(Some(l)));
        let out = f();
        LOCAL.with(|c| c.set(prev));
        out
    }
}

/// Stały tekst w języku programu: `tr!("po polsku", "in English")`.
#[macro_export]
macro_rules! tr {
    ($pl:expr, $en:expr) => { match $crate::lang::get() { $crate::lang::Lang::Pl => $pl, $crate::lang::Lang::En => $en } };
}

/// Tekst z parametrami w języku programu: `trf!("{} procesów", "{} processes", n)`.
/// Oba wzorce muszą używać tych samych argumentów w tej samej kolejności.
#[macro_export]
macro_rules! trf {
    ($pl:literal, $en:literal $(, $($a:tt)*)?) => { match $crate::lang::get() {
        $crate::lang::Lang::Pl => format!($pl $(, $($a)*)?), $crate::lang::Lang::En => format!($en $(, $($a)*)?) } };
}

/// Uprawnienia regionu. Serializowane jako "rwx" / "r-x" itd.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Prot(pub u8);

impl Prot {
    pub const R: u8 = 1;
    pub const W: u8 = 2;
    pub const X: u8 = 4;
    pub fn r(self) -> bool { self.0 & Self::R != 0 }
    pub fn w(self) -> bool { self.0 & Self::W != 0 }
    pub fn x(self) -> bool { self.0 & Self::X != 0 }
    pub fn parse(s: &str) -> Option<Prot> {
        let b = s.as_bytes();
        if b.len() < 3 { return None; }
        let mut p = 0;
        match b[0] { b'r' => p |= Self::R, b'-' => {}, _ => return None }
        match b[1] { b'w' => p |= Self::W, b'-' => {}, _ => return None }
        match b[2] { b'x' => p |= Self::X, b'-' => {}, _ => return None }
        Some(Prot(p))
    }
}
impl fmt::Display for Prot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}",
            if self.r() { 'r' } else { '-' },
            if self.w() { 'w' } else { '-' },
            if self.x() { 'x' } else { '-' })
    }
}
impl Serialize for Prot {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Prot {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Prot::parse(&s).ok_or_else(|| serde::de::Error::custom(crate::tr!("błędne uprawnienia", "invalid permissions")))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RegionKind { Private, Mapped, Image, Stack, Heap, Physical, Unknown }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    /// None = nieznane (poziom B1, minidump bez MemoryInfo)
    pub prot: Option<Prot>,
    pub kind: RegionKind,
    /// plik źródłowy, jeśli jest
    pub backing: Option<String>,
    pub backing_deleted: bool,
    /// etykieta jądra, np. "[vdso]", "[anon:nazwa]"
    pub label: Option<String>,
    pub readable: bool,
}
impl Region {
    pub fn is_x(&self) -> bool { self.prot.map(|p| p.x()).unwrap_or(false) }
    pub fn is_w(&self) -> bool { self.prot.map(|p| p.w()).unwrap_or(false) }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SourceInfo {
    pub os: String,
    pub arch: String,
    pub pid: Option<u32>,
    pub name: Option<String>,
    /// "live" | "process-dump" | "physical"
    pub source_type: String,
    /// ścieżka programu wg jądra (Linux: /proc/<pid>/exe), nie nazwa ustawiana przez sam proces
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default)]
    pub exe_deleted: bool,
    /// backend potwierdził, że `exe` to ten sam plik, który widzi skaner, należący do roota
    /// i niezapisywalny dla innych; bez tego lista dozwolonych nie działa
    #[serde(default)]
    pub exe_verified: bool,
}

/// Wątek procesu i adres, który go lokalizuje w pamięci. Windows: adres startu wątku.
/// Linux: adres instrukcji, z której wątek wywołał jądro (dostępny tylko dla wątków
/// czekających w wywołaniu systemowym).
#[derive(Clone, Debug, PartialEq)]
pub struct ThreadInfo { pub tid: u32, pub addr: u64 }

/// Rejestry wątku potrzebne do odwinięcia jego stosu (x86_64): adres instrukcji i 16 rejestrów
/// ogólnych w numeracji procesora (0 rax, 1 rcx, 2 rdx, 3 rbx, 4 rsp, 5 rbp, 6 rsi, 7 rdi, 8-15).
/// `known`: maska bitowa rejestrów, których wartość źródło faktycznie zna (odczyt z jądra gościa
/// daje tylko część rejestrów); rsp musi być znany zawsze.
#[derive(Clone, Debug, PartialEq)]
pub struct ThreadRegs { pub tid: u32, pub rip: u64, pub gpr: [u64; 16], pub known: u16 }

/// Rejestry wątków procesu i liczba wątków, których rejestrów źródło nie umiało odczytać (np. odmowa
/// dostępu albo stos jądrowy wątku wyrzucony z pamięci gościa).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ThreadSet { pub regs: Vec<ThreadRegs>, pub unread: u32 }

/// Rezerwacja przestrzeni adresowej (Windows: jedno wywołanie przydziału albo jedno mapowanie, czyli
/// jeden opis regionu w jądrze). Kilka regionów o różnej ochronie może należeć do jednej rezerwacji.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Allocation { pub base: u64, pub size: u64 }

/// Rezerwacja, do której należy region ze znaleziskiem: adres, rozmiar i liczba regionów mapy w jej zakresie.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct AllocInfo { pub base: u64, pub size: u64, pub regions: u32 }

/// Ile stosów wątków procesu udało się zbadać (Windows x64). Brak znalezisk znaczy coś tylko wtedy,
/// gdy stosy faktycznie odwinięto do dna.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct StackStats {
    /// Wątki, których rejestry źródło odczytało.
    pub threads: u32,
    /// Wątki, których rejestrów źródło nie umiało odczytać: ich stosy nie zostały zbadane.
    #[serde(skip_serializing_if = "is_zero", default)]
    pub unread: u32,
    /// Wątki czekające w wywołaniu jądra (tylko ich stosy są odwijane).
    pub waiting: u32,
    /// Stosy odwinięte do dna; każda ramka wraca do obrazu modułu.
    pub complete: u32,
    /// Stosy z adresem powrotu poza obrazami modułów (zgłoszone jako znaleziska).
    pub foreign: u32,
    /// Stosy, których odwijanie porzucono, z podziałem na powody (stałe tokeny).
    pub abandoned: u32,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty", default)]
    pub reasons: std::collections::BTreeMap<String, u32>,
}

/// Zmiana kodu pochodzącego z pliku, stwierdzona przez backend dla jednego regionu.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CodeChange {
    /// Gdy `compared`: liczba bajtów pamięci różnych od pliku na dysku. W przeciwnym razie: rozmiar
    /// stron, które nie są już współdzielone z plikiem (wiadomo, że je zapisano, nie wiadomo czym).
    pub bytes: u64,
    /// Adres pierwszej różnicy (albo pierwszej takiej strony).
    pub first: u64,
    /// Treść pamięci została porównana z plikiem na dysku.
    pub compared: bool,
    /// Plik użyty do porównania to na pewno ten, z którego powstało mapowanie. Gdy tego nie wiadomo,
    /// zgodność treści nie wygasza znaleziska: plik pod tą samą ścieżką mógł zostać podmieniony.
    pub verified: bool,
}

pub trait MemorySource {
    fn info(&self) -> SourceInfo;
    fn regions(&self) -> Result<Vec<Region>>;
    /// Częściowy odczyt dozwolony; zwraca liczbę przeczytanych bajtów.
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;
    /// Odczyt całego bufora albo nic: true tylko wtedy, gdy każdy bajt pochodzi z pamięci procesu. Źródła,
    /// które w `read_at` wypełniają zerami strony nieobecne w pamięci, muszą tę metodę zastąpić.
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> bool { matches!(self.read_at(addr, buf), Ok(n) if n == buf.len()) }
    /// Wątki z adresami; pusta lista, gdy źródło ich nie udostępnia.
    fn threads(&self) -> Vec<ThreadInfo> { Vec::new() }
    /// Rejestry wątków odczytane bez wstrzymywania procesu; pusta lista, gdy źródło ich nie udostępnia.
    /// Wartości wątku, który właśnie działa, mogą być niespójne: odbiorca sprawdza je sam.
    fn thread_regs(&self) -> ThreadSet { ThreadSet::default() }
    /// Rezerwacje przestrzeni adresowej posortowane po adresie; pusta lista, gdy źródło ich nie zna.
    fn allocations(&self) -> Vec<Allocation> { Vec::new() }
    /// Ile bajtów kodu z pliku zostało w tym regionie zmienionych w pamięci (strony, które przestały
    /// być współdzielone z plikiem) i adres pierwszej takiej strony, jeśli znany. None: źródło tego nie wie.
    fn modified_code(&self, _r: &Region) -> Option<CodeChange> { None }
    /// Dowód z systemu operacyjnego, że proces ma prawo tworzyć kod w trakcie działania (stały token do
    /// raportu). None: backend takiego dowodu nie ma i decyduje lista dozwolonych programów.
    fn jit_evidence(&self) -> Option<String> { None }
}

fn is_zero(v: &u32) -> bool { *v == 0 }

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity { None, Info, Suspicious, High }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    /// stabilny identyfikator: "<pid>:<base hex>:<tag>"
    pub id: String,
    pub detector: String,
    pub tag: String,
    pub addr: u64,
    pub size: u64,
    pub prot: Option<Prot>,
    pub entropy: Option<f32>,
    pub weight: u32,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bytes_hex: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegionReport {
    pub region: Region,
    pub bytes_read: u64,
    pub truncated: bool,
    pub entropy_max: Option<f32>,
    pub entropy_mean: Option<f32>,
    pub zero_pages: u64,
    pub score: u32,
    pub severity: Severity,
    /// powód obniżenia punktacji (lista dozwolonych), jawnie w raporcie
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowlisted: Option<String>,
    /// rezerwacja przestrzeni adresowej, do której należy region (gdy źródło ją zna): pojedynczy
    /// przydział wstrzykniętego kodu to zwykle samotny region, sterta kodu JIT to duża rezerwacja
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allocation: Option<AllocInfo>,
    pub findings: Vec<Finding>,
    /// entropia komórek mapy ciepła w dziesiątych częściach bita (0..=80)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub heat: Option<Vec<u8>>,
    /// profil entropii regionu ze znaleziskiem: najwyżej 64 równe odcinki, maksimum stron
    /// w odcinku, w dziesiątych częściach bita (0..=80)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub profile: Option<Vec<u8>>,
    /// ciągi tekstowe z regionu ze znaleziskiem (heurystyka; brak przy `--no-bytes`)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<String>,
    /// SHA-256 odczytanej zawartości regionu ze znaleziskiem: pozwala rozpoznać ten sam ładunek
    /// w innym procesie, na innej stacji albo w kolejnym skanie
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256: Option<String>,
}

/// Skrót pliku z dysku badanej stacji (program albo plik zmapowany do pamięci procesu).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct FileHash {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256: Option<String>,
    /// dlaczego skrótu nie ma (plik niedostępny, za duży)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProcessReport {
    pub info: SourceInfo,
    pub regions_total: u64,
    pub regions_unreadable: u64,
    pub bytes_scanned: u64,
    pub max_severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    /// tylko regiony ze znaleziskami (lub wszystkie przy mapie ciepła)
    pub regions: Vec<RegionReport>,
    /// pełna mapa regionów procesu ze znaleziskami od wagi "podejrzane" (do diagramu w raporcie)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub layout: Option<Vec<Region>>,
    /// pokrycie odwijania stosów wątków; brak, gdy źródło nie udostępnia rejestrów wątków
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stacks: Option<StackStats>,
    /// kontekst systemowy procesu zebrany poza pamięcią (rodzice, sieć, pliki)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<ProcessContext>,
}

/// Odwołanie do innego procesu (rodzic, dziecko).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ProcRef {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cmdline: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Socket {
    /// "tcp" | "tcp6" | "udp" | "udp6" | "unix"
    pub proto: String,
    pub local: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct OpenFile {
    pub fd: u32,
    /// "file" | "socket" | "pipe" | "memfd" | "anon" | "device" | "other"
    pub kind: String,
    pub target: String,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct FileFacts {
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256: Option<String>,
}

/// Kontekst systemowy procesu. Wszystko zebrane wyłącznie odczytem (Z1); pola puste, gdy
/// system ich nie udostępnił, a powód jest w `notes`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ProcessContext {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threads: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exe_file: Option<FileFacts>,
    /// od rodzica w górę
    #[serde(default)]
    pub ancestors: Vec<ProcRef>,
    #[serde(default)]
    pub children: Vec<ProcRef>,
    #[serde(default)]
    pub sockets: Vec<Socket>,
    /// otwarte pliki (z limitem); `files_total` to liczba wszystkich deskryptorów
    #[serde(default)]
    pub files: Vec<OpenFile>,
    #[serde(default)]
    pub files_total: u32,
    /// cechy bezpieczeństwa: (nazwa, wartość), np. ("śledzony przez", "PID 12")
    #[serde(default)]
    pub flags: Vec<(String, String)>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct HostContext {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub boot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scanner_user: Option<String>,
    /// Windows: dysk systemowy wg środowiska skanera, np. "C:"
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub system_drive: Option<String>,
    /// uprawnienia, z którymi działał skaner (opis dla człowieka)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scanner_privileges: Option<String>,
    /// skaner nie miał pełnych uprawnień: część procesów mogła być niedostępna tylko z tego powodu
    #[serde(default)]
    pub scanner_limited: bool,
}

/// Czas uniksowy (sekundy) jako RFC 3339 w UTC.
pub fn rfc3339(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // algorytm dni -> data cywilna (H. Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ScanResult {
    pub schema_version: u32,
    pub tool_version: String,
    /// jedyne pole niedeterministyczne (Z6)
    pub timestamp: String,
    pub host: String,
    pub heat_cell_bytes: u64,
    pub partial: bool,
    pub processes: Vec<ProcessReport>,
    /// język opisów zapisanych w wyniku ("pl" albo "en"); brak pola oznacza "pl"
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host_info: Option<HostContext>,
    /// skróty SHA-256: pliki programów wszystkich procesów i pliki zmapowane w procesach ze znaleziskami
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<FileHash>,
}

impl ScanResult {
    pub fn max_severity(&self) -> Severity {
        self.processes.iter().map(|p| p.max_severity).max().unwrap_or(Severity::None)
    }
    pub fn finding_count(&self) -> usize {
        self.processes.iter().flat_map(|p| &p.regions).map(|r| r.findings.len()).sum()
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push(T[(b >> 4) as usize] as char); s.push(T[(b & 15) as usize] as char); }
    s
}
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prot_roundtrip() {
        for s in ["rwx", "r-x", "---", "rw-"] {
            assert_eq!(Prot::parse(s).unwrap().to_string(), s);
        }
        assert!(Prot::parse("zzz").is_none());
        let j = serde_json::to_string(&Prot(5)).unwrap();
        assert_eq!(j, "\"r-x\"");
        assert_eq!(serde_json::from_str::<Prot>(&j).unwrap(), Prot(5));
    }
    #[test]
    fn hex_roundtrip() {
        assert_eq!(unhex(&hex(&[0, 255, 16])).unwrap(), vec![0, 255, 16]);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951782400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1795305599), "2026-11-21T23:59:59Z");
    }
}

/// Inwentaryzacja metadanych; niezależna od schematu wyników detektorów.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemoryInventory {
    pub inventory_version: u32,
    pub timestamp: String,
    pub host: String,
    pub os: String,
    pub processes: Vec<ProcessMemory>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessMemory {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub regions: Vec<MappedRegion>,
    pub error: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MappedRegion {
    // Tekst chroni 64-bitowe adresy i liczniki przed utratą precyzji w JavaScript.
    pub base: String,
    pub size: String,
    pub prot: Option<Prot>,
    pub kind: RegionKind,
    pub backing: Option<String>,
    pub backing_deleted: bool,
    pub label: Option<String>,
    #[serde(default)]
    pub file_offset: Option<String>,
    /// Linux device:inode; identyfikator w kontekście przestrzeni montowań.
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub sharing: Option<String>,
    pub rss: Option<String>,
    pub pss: Option<String>,
}
impl From<Region> for MappedRegion {
    fn from(r: Region) -> Self {
        Self { base: format!("0x{:016x}", r.base), size: r.size.to_string(), prot: r.prot,
            kind: r.kind, backing: r.backing, backing_deleted: r.backing_deleted,
            label: r.label, file_offset: None, file_id: None, sharing: None, rss: None, pss: None }
    }
}
