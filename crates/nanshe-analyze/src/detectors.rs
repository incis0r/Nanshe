//! Detektory etapu M1 (+ MEMFD i DEL-EXEC, które wynikają wprost z mapy regionów).
use crate::{Config, Ctx};
use nanshe_core::{tr, trf, Finding, Region, RegionKind, PAGE};

pub trait Detector: Sync {
    fn id(&self) -> &'static str;
    fn applies(&self, _info: &nanshe_core::SourceInfo) -> bool { true }
    fn scan(&self, region: &Region, data: &[u8], ctx: &Ctx) -> Vec<Finding>;
}

pub fn all() -> Vec<Box<dyn Detector>> {
    vec![Box::new(Rwx), Box::new(XPriv), Box::new(XMap), Box::new(GuardX), Box::new(Memfd), Box::new(DelExec), Box::new(XTmp), Box::new(EntX), Box::new(Hdr), Box::new(ThrPriv), Box::new(ImgMod)]
}

fn is_memfd(r: &Region) -> bool {
    r.backing.as_deref().map(|b| b.starts_with("memfd:")).unwrap_or(false)
}

/// Katalogi zapisywalne dla wszystkich (sticky), w których wykonywalne mapowanie pliku jest
/// rozpoznanym wskaźnikiem: utwardzanie (CIS) montuje je `noexec` właśnie z tego powodu.
const WORLD_WRITABLE_DIRS: [&str; 8] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/", "/var/lock/", "/run/lock/", "/dev/mqueue/"];
fn is_kernel_special(r: &Region) -> bool {
    matches!(r.label.as_deref(), Some("[vdso]") | Some("[vvar]") | Some("[vsyscall]") | Some("[vvar_vclock]") | Some("[sigpage]") | Some("[vectors]") | Some("[uprobes]"))
}

struct Rwx;
impl Detector for Rwx {
    fn id(&self) -> &'static str { "rwx" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_w() && r.is_x() {
            vec![ctx.finding(self.id(), "RWX", r, r.base, r.size, 30,
                tr!("region jednocześnie zapisywalny i wykonywalny", "region both writable and executable").into())]
        } else { vec![] }
    }
}

struct XPriv;
impl Detector for XPriv {
    fn id(&self) -> &'static str { "x-priv" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        let anon = r.backing.is_none()
            && matches!(r.kind, RegionKind::Private | RegionKind::Heap | RegionKind::Stack)
            && !is_kernel_special(r);
        if r.is_x() && anon {
            let what = match r.kind { RegionKind::Heap => tr!("sterta", "heap"), RegionKind::Stack => tr!("stos", "stack"), _ => tr!("pamięć prywatna/anonimowa", "private/anonymous memory") };
            vec![ctx.finding(self.id(), "X-PRIV", r, r.base, r.size, 30,
                trf!("wykonywalna {what} bez pliku źródłowego", "executable {what} not backed by a file"))]
        } else { vec![] }
    }
}

struct XMap;
impl Detector for XMap {
    fn id(&self) -> &'static str { "x-map" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "windows" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_x() && r.kind == RegionKind::Mapped {
            vec![ctx.finding(self.id(), "X-MAP", r, r.base, r.size, 30,
                trf!("wykonywalne mapowanie niebędące obrazem modułu ({})", "executable mapping that is not a module image ({})", r.backing.as_deref().unwrap_or(tr!("sekcja bez pliku", "section without a file"))))]
        } else { vec![] }
    }
}

/// Czy to wykonywalny region za strażnikiem, którego treści nie odczytano.
pub fn is_guarded_exec(r: &Region) -> bool {
    r.is_x() && r.label.as_deref() == Some(nanshe_core::GUARD_LABEL)
}

struct GuardX;
impl Detector for GuardX {
    fn id(&self) -> &'static str { "guard-x" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if is_guarded_exec(r) {
            vec![ctx.finding(self.id(), "GUARD-X", r, r.base, r.size, 30,
                tr!("wykonywalny region za strażnikiem (PAGE_GUARD): treść nie została odczytana, detektory treści go nie sprawdziły", "executable region behind a guard page (PAGE_GUARD): contents were not read, content detectors did not examine it").into())]
        } else { vec![] }
    }
}

/// Największy region memfd uznawany za tablicę skoków libffi (jedna strona, także przy stronach 64 KiB).
const LIBFFI_MAX: u64 = 0x1_0000;

struct Memfd;
impl Detector for Memfd {
    fn id(&self) -> &'static str { "memfd" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "linux" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_x() && is_memfd(r) {
            // Biblioteka libffi (wywołania zwrotne w Pythonie, GNOME i innych) tworzy wykonywalne mapowania memfd
            // o nazwie "libffi". Pomiar na 20 hostach Linux (2026-11-23): wszystkie 19 mapowań memfd miały tę nazwę.
            // Nazwę nadaje sam proces, więc obniżka dotyczy tylko procesu z potwierdzonym plikiem programu, który
            // faktycznie ma zmapowaną libffi; kod wstrzyknięty do takiego procesu mógłby się pod nią podszyć.
            // Dodatkowo tylko dla tego, co libffi faktycznie tworzy: mała tablica skoków, niezapisywalna, o niskiej
            // entropii (pomiar: 16 z 16 takich regionów miało 4 KiB, r-x i entropię poniżej 5). Większy, zapisywalny
            // albo gęsty region pod tą nazwą dostaje pełną wagę.
            let small_table = r.size <= LIBFFI_MAX && !r.is_w() && ctx.page_entropy.iter().all(|e| *e < 6.0);
            if ctx.traits.libffi && small_table && r.backing.as_deref() == Some("memfd:libffi") {
                return vec![ctx.finding(self.id(), "MEMFD", r, r.base, r.size, 10,
                    tr!("wykonywalne mapowanie memfd:libffi w procesie korzystającym z biblioteki libffi (wywołania zwrotne); nazwę mapowania nadaje sam proces",
                        "executable mapping memfd:libffi in a process that uses the libffi library (callbacks); the mapping name is chosen by the process itself").into())];
            }
            vec![ctx.finding(self.id(), "MEMFD", r, r.base, r.size, 40,
                trf!("wykonywalne mapowanie {}", "executable mapping {}", r.backing.as_deref().unwrap_or("memfd:")))]
        } else { vec![] }
    }
}

/// Katalogi, do których instalują pakiety systemu i oprogramowanie dodatkowe (zapis wymaga uprawnień root).
const PACKAGE_DIRS: [&str; 7] = ["/usr/", "/lib/", "/lib64/", "/opt/", "/bin/", "/sbin/", "/snap/"];

struct DelExec;
impl Detector for DelExec {
    fn id(&self) -> &'static str { "del-exec" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "linux" || i.os == "freebsd" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_x() && r.backing_deleted && !is_memfd(r) {
            let path = r.backing.as_deref().unwrap_or("?");
            // Plik z katalogu, do którego instalują pakiety: aktualizacja usuwa starą wersję biblioteki, a proces
            // używa jej do restartu. Pomiar na 20 hostach Linux (2026-11-23): 3660 z 3662 takich regionów.
            // To informacja dla administratora (usługa wymaga restartu), a nie ślad ukrywania kodu.
            // Sama ścieżka nie wystarcza: proces w kontenerze ma własne /usr, do którego może pisać. Obniżka
            // dotyczy więc tylko procesu z potwierdzonym plikiem programu (ten sam plik, który widzi skaner).
            if ctx.info.exe_verified && !ctx.info.exe_deleted && PACKAGE_DIRS.iter().any(|d| path.starts_with(d)) && !path.contains("/../") {
                return vec![ctx.finding(self.id(), "DEL-EXEC", r, r.base, r.size, 10,
                    trf!("wykonywalne mapowanie pliku {path} usuniętego z katalogu pakietów: zwykle biblioteka zaktualizowana na dysku, proces używa starej wersji do restartu",
                         "executable mapping of file {path} deleted from a package directory: usually a library updated on disk, the process uses the old version until restarted"))];
            }
            vec![ctx.finding(self.id(), "DEL-EXEC", r, r.base, r.size, 30,
                trf!("wykonywalne mapowanie usuniętego pliku {path}", "executable mapping of deleted file {path}"))]
        } else { vec![] }
    }
}

/// Wykonywalne mapowanie pliku z katalogu zapisywalnego dla wszystkich (np. `/tmp`). Zamyka
/// znany ślepy punkt M1 na Linuksie (próbka red team `rx-file`): tu nie ma semantyki obrazu
/// jak `X-MAP` na Windows, więc ładunek R-X z pliku omijał wszystkie detektory. Pliki usunięte
/// pokrywa `DEL-EXEC`, pamięć anonimowa `X-PRIV`; ten detektor celuje w plik, który pozostał na dysku.
struct XTmp;
impl Detector for XTmp {
    fn id(&self) -> &'static str { "x-tmp" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "linux" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        let Some(b) = r.backing.as_deref() else { return vec![] };
        if r.is_x() && r.kind == RegionKind::Mapped && !r.backing_deleted && !is_memfd(r)
            && WORLD_WRITABLE_DIRS.iter().any(|d| b.starts_with(d)) {
            vec![ctx.finding(self.id(), "X-TMP", r, r.base, r.size, 30,
                trf!("wykonywalne mapowanie pliku z katalogu zapisywalnego dla wszystkich ({b})", "executable mapping of a file from a world-writable directory ({b})"))]
        } else { vec![] }
    }
}

/// Wątek zlokalizowany w pamięci bez pliku. Sterty JIT mają wykonywalne regiony bez pliku, ale ich
/// wątki startują (Windows) i wywołują jądro (Linux) z kodu bibliotek, więc ten sygnał odróżnia
/// działający wstrzyknięty kod od zwykłej kompilacji w locie. Nie podlega obniżce dla JIT.
struct ThrPriv;
impl Detector for ThrPriv {
    fn id(&self) -> &'static str { "thr-priv" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if ctx.threads.is_empty() || r.backing.is_some() || r.kind == RegionKind::Image || is_kernel_special(r) { return vec![]; }
        let tids = ctx.threads.iter().take(4).map(|t| t.tid.to_string()).collect::<Vec<_>>().join(", ");
        let more = if ctx.threads.len() > 4 { format!(" i {} kolejnych", ctx.threads.len() - 4) } else { String::new() };
        let what = if ctx.info.os == "windows" { tr!("ma adres startu w pamięci bez pliku", "has its start address in memory not backed by a file") } else { tr!("wywołuje jądro z kodu w pamięci bez pliku", "calls the kernel from code in memory not backed by a file") };
        vec![ctx.finding(self.id(), "THR-PRIV", r, ctx.threads[0].addr, PAGE as u64, 40, trf!("wątek {tids}{more} {what}", "thread {tids}{more} {what}"))]
    }
}

/// Kod z pliku zmieniony w pamięci: strony wykonywalnego, niezapisywalnego mapowania pliku, które
/// przestały być współdzielone z plikiem. Tak wyglądają łatki funkcji (hooki, wyłączanie AMSI/ETW)
/// i podmiana obrazu. Detektor mówi, że kod zmieniono, a nie co zmieniono.
struct ImgMod;
impl Detector for ImgMod {
    fn id(&self) -> &'static str { "img-mod" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        let Some(c) = ctx.modified else { return vec![] };
        let (bytes, first) = (c.bytes, c.first);
        let name = r.backing.as_deref().unwrap_or("?");
        // Windows: strony obrazu przestają być współdzielone także z łagodnych powodów (relokacja
        // biblioteki bez ASLR, podpięcia piaskownicy Chromium w ntdll, samo środowisko .NET w clr.dll,
        // procesy 32-bitowe). Pomiar na stacji testowej Windows 2026-11-22: 28 takich regionów w 19 procesach.
        // Dlatego pełną wagę mają tylko moduły, których nikt poza obejściami zabezpieczeń nie zmienia;
        // reszta dostaje 10 punktów: razem z rzadkimi stronami o wysokiej entropii w tym samym kodzie
        // (ENT-X 10) nadal jest to "info" (przy 20 punktach dziesięć zwykłych procesów stawało się "podejrzane").
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase();
        let full = ctx.info.os != "windows" || matches!(base.as_str(), "amsi.dll" | "wldp.dll");
        let addr = first.clamp(r.base, r.base.saturating_add(r.size.saturating_sub(1)));
        // Po porównaniu z plikiem różnica jest faktem, a nie domysłem, ale waga zwykłej biblioteki Windows zostaje 10.
        // Pomiar na stacji testowej 2026-11-23 (232 procesy): 26 regionów z potwierdzoną różnicą, z czego 10 to te same
        // 12 bajtów w user32.dll we wszystkich procesach 32-bitowych, a 8 to te same 15 bajtów w clr.dll we wszystkich
        // procesach .NET. Przy 20 punktach (razem z ENT-X 10) liczba procesów "podejrzanych" rosła z 5 do 14.
        let (weight, reason) = if c.compared && bytes == 0 {
            // treść zgodna z plikiem pod tą ścieżką, ale nie wiadomo, czy to ten sam plik: znalezisko zostaje jako "info"
            (10, trf!("strony kodu są prywatną kopią; treść zgodna z plikiem pod tą ścieżką, ale tożsamości pliku nie potwierdzono ({name})", "code pages are a private copy; contents equal the file at this path, but the identity of the file was not confirmed ({name})"))
        } else if c.compared {
            (if full { 40 } else { 10 }, trf!("kod w pamięci różni się od pliku na dysku: {bytes} bajtów, pierwszy pod adresem {addr:#x} ({name})", "code in memory differs from the file on disk: {bytes} bytes, the first at address {addr:#x} ({name})"))
        } else {
            (if full { 40 } else { 10 }, trf!("kod z pliku zmieniony w pamięci: {} KiB stron niewspółdzielonych z plikiem; treści nie porównano z plikiem ({name})", "code from a file changed in memory: {} KiB of pages not shared with the file; contents were not compared with the file ({name})", bytes.div_ceil(1024)))
        };
        vec![ctx.finding(self.id(), "IMG-MOD", r, addr, PAGE as u64, weight, reason)]
    }
}

struct EntX;
impl Detector for EntX {
    fn id(&self) -> &'static str { "ent-x" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if !r.is_x() { return vec![]; }
        let cfg: &Config = ctx.cfg;
        let Some((idx, &max)) = ctx.page_entropy.iter().enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal)) else { return vec![] };
        if max < cfg.ent_high { return vec![]; }
        let n = ctx.page_entropy.iter().filter(|&&e| e >= cfg.ent_high).count();
        let (mut w, lvl) = if max >= cfg.ent_very_high { (30, tr!("bardzo wysoka", "very high")) } else { (20, tr!("wysoka", "high")) };
        // Strojenie na próbkach: kod z pliku na dysku miewa pojedyncze strony o wysokiej entropii
        // (tablice stałych w .text, np. libc). Pełna waga dopiero, gdy dotyczy to dużej części
        // regionu (obraz spakowany) albo region nie ma zwykłego pliku źródłowego.
        let total = ctx.page_entropy.len();
        let plain_file = r.backing.is_some() && !r.backing_deleted && !is_memfd(r);
        let sparse = plain_file && (n as f32) < cfg.ent_file_fraction * total as f32;
        if sparse { w = 10; }
        let mut f = ctx.finding(self.id(), "ENT-X", r, r.base + (idx * PAGE) as u64, PAGE as u64, w,
            trf!("{lvl} entropia w regionie wykonywalnym: max {max:.2}, stron powyżej progu: {n} z {total}{}", "{lvl} entropy in an executable region: max {max:.2}, pages above threshold: {n} of {total}{}",
                if sparse { tr!(" (pojedyncze strony w kodzie z pliku: niska waga)", " (isolated pages in code from a file: low weight)") } else { "" }));
        f.id = format!("{}:{:x}:ENT-X", ctx.pid_str(), r.base);
        f.entropy = Some(round2(max));
        vec![f]
    }
}

pub(crate) fn round2(v: f32) -> f32 { (v * 100.0).round() / 100.0 }

/// Najmniejszy region danych procesu hiperwizora traktowany jako pamięć maszyny wirtualnej.
const GUEST_RAM_MIN: u64 = 16 << 20;

struct Hdr;
impl Detector for Hdr {
    fn id(&self) -> &'static str { "hdr" }
    fn scan(&self, r: &Region, d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.backing.is_some() || is_kernel_special(r) { return vec![]; }
        // Odczyt z hiperwizora zna tylko moduły z listy programu ładującego: plików zmapowanych jako dane
        // (biblioteki zasobów, pliki językowe) nie odróżni od pamięci prywatnej, a każdy z nich zaczyna się
        // nagłówkiem. Pomiar na kontrolerze domeny LAB (2026-11-23): 466 takich regionów w 96 procesach.
        // Dlatego w tym trybie nagłówek liczy się tylko w regionie wykonywalnym.
        if ctx.info.source_type == "vm" && !r.is_x() { return vec![]; }
        // Niewykonywalny stos pomijamy: program ładujący trzyma na nim kopię nagłówka każdej ładowanej
        // biblioteki, a przy losowym położeniu stosu kopia co jakiś czas wypada na początku strony
        // (zaobserwowane w e2e na próbce delexec, 2026-11-22).
        if r.kind == RegionKind::Stack && !r.is_x() { return vec![]; }
        // Nagłówek może leżeć pod dowolnym przesunięciem: ładunek w buforze zaczyna się za nagłówkiem
        // alokatora, nie na granicy strony. Poza granicą strony szukamy jednak tylko w regionach
        // wykonywalnych: w zwykłych danych kopie nagłówków są codziennością (ld.so trzyma na stosie
        // nagłówek każdej ładowanej biblioteki, programy czytające pliki mają je na stercie).
        // Mach-O (sama 4-bajtowa sygnatura i dwa pola) tylko na początku strony.
        let any_offset = r.is_x();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 64 <= d.len() {
            let aligned = i % PAGE == 0;
            if !aligned && !any_offset { i = (i / PAGE + 1) * PAGE; continue; }
            let candidate = matches!((d[i], d[i + 1]), (0x7f, b'E') | (b'M', b'Z')) || aligned;
            let found = if candidate { header_kind(&d[i..(i + PAGE).min(d.len())]).filter(|k| aligned || *k != "Mach-O") } else { None };
            if let Some(fmt) = found {
                let addr = r.base + i as u64;
                // Proces hiperwizora QEMU trzyma pamięć maszyn wirtualnych w dużych regionach danych: nagłówki
                // programów działających w gościu są tam normalne (pomiar 2026-11-23: wszystkie HDR na pięciu
                // hiperwizorach LAB). Region wykonywalny albo mały nadal dostaje pełną wagę.
                if ctx.traits.vm_host && !r.is_x() && r.size >= GUEST_RAM_MIN {
                    let mut f = ctx.finding(self.id(), "HDR", r, addr, PAGE as u64, 10,
                        trf!("nagłówek {fmt} w dużym regionie danych procesu hiperwizora: najpewniej pamięć maszyny wirtualnej, a nie kod samego procesu",
                             "{fmt} header in a large data region of a hypervisor process: most likely virtual machine memory, not code of the process itself"));
                    f.id = format!("{}:{:x}:HDR", ctx.pid_str(), addr);
                    out.push(f);
                    break; // jeden wpis na region: pamięć gościa zawiera wiele nagłówków
                }
                let reason = if aligned { trf!("nagłówek {fmt} w regionie bez pliku źródłowego", "{fmt} header in a region not backed by a file") }
                    else { trf!("nagłówek {fmt} w regionie bez pliku źródłowego, {:#x} bajtów za początkiem strony", "{fmt} header in a region not backed by a file, {:#x} bytes past the start of a page", i % PAGE) };
                let mut f = ctx.finding(self.id(), "HDR", r, addr, PAGE as u64, 40, reason);
                f.id = format!("{}:{:x}:HDR", ctx.pid_str(), addr);
                out.push(f);
                if out.len() >= 8 { break; }
                i += 64; // nagłówek znaleziony: kolejnego nie szukamy w jego wnętrzu
            } else if aligned && any_offset {
                // Nagłówek z wymazanymi sygnaturami: znaczniki formatu usunięte po załadowaniu, ale tablica
                // sekcji albo segmentów została. Szukamy tylko w regionach wykonywalnych: w zwykłych danych
                // kopie nagłówków plików są codziennością (program czytający pliki wykonywalne ma je na stercie,
                // a tablica sekcji takiej kopii leży w środku strony). Pomiar na stacji testowej 2026-11-23:
                // szukanie także na początku regionów niewykonywalnych dało dwa fałszywe alarmy na stercie.
                if let Some(fmt) = wiped_header_kind(&d[i..(i + PAGE).min(d.len())]) {
                    let addr = r.base + i as u64;
                    let mut f = ctx.finding(self.id(), "HDR", r, addr, PAGE as u64, 40,
                        trf!("nagłówek {fmt} z wymazaną sygnaturą w regionie bez pliku źródłowego: jest tablica sekcji obrazu, brak znacznika formatu", "{fmt} header with a wiped signature in a region not backed by a file: the image section table is present, the format marker is missing"));
                    f.id = format!("{}:{:x}:HDR", ctx.pid_str(), addr);
                    out.push(f);
                    if out.len() >= 8 { break; }
                    i += PAGE;
                } else { i += 1; }
            } else { i += 1; }
        }
        out
    }
}

fn u16_at(d: &[u8], o: usize, le: bool) -> Option<u16> {
    let b = d.get(o..o + 2)?;
    Some(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
}
fn u32_at(d: &[u8], o: usize, le: bool) -> Option<u32> {
    let b = d.get(o..o + 4)?;
    let a = [b[0], b[1], b[2], b[3]];
    Some(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
}

/// Tablica sekcji PE bez sygnatur: co najmniej dwa kolejne 40-bajtowe wpisy o nazwach jak w plikach
/// wykonywalnych, adresach wyrównanych do strony i rosnących, z flagami pamięci, w tym jeden wykonywalny.
fn pe_section_table(p: &[u8]) -> bool {
    let entry = |o: usize| -> Option<(u32, u32)> {
        let e = p.get(o..o + 40)?;
        // nazwa: znaki drukowalne, potem same zera
        if !(e[0] == b'.' || e[0].is_ascii_alphanumeric() || e[0] == b'_') { return None; }
        let len = e[..8].iter().position(|c| *c == 0).unwrap_or(8);
        if !e[..len].iter().all(|c| (0x21..0x7f).contains(c)) || !e[len..8].iter().all(|c| *c == 0) { return None; }
        let (vsize, va, raw_size, raw, chars) = (u32_at(e, 8, true)?, u32_at(e, 12, true)?, u32_at(e, 16, true)?, u32_at(e, 20, true)?, u32_at(e, 36, true)?);
        let ok = vsize > 0 && vsize < 0x4000_0000 && va != 0 && va % 0x1000 == 0 && raw_size % 0x200 == 0 && raw % 0x200 == 0
            && chars & 0xe000_0000 != 0 && chars & 0x1f == 0;
        ok.then_some((va, chars))
    };
    let mut o = 0x40;
    while o + 80 <= p.len() {
        let (mut n, mut last, mut exec, mut at) = (0u32, 0u32, false, o);
        while let Some((va, chars)) = entry(at) {
            if va <= last { break; }
            last = va; n += 1; exec |= chars & 0x2000_0000 != 0; at += 40;
        }
        if n >= 2 && exec { return true; }
        o += 8;
    }
    false
}

/// Tablica segmentów ELF (64 bity, little endian) w zwykłym miejscu za nagłówkiem, bez sygnatury:
/// co najmniej dwa segmenty PT_LOAD o spójnych polach, w tym jeden wykonywalny.
fn elf_program_table(p: &[u8]) -> bool {
    let u64_at = |o: usize| p.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bajtów")));
    let (mut loads, mut exec, mut o) = (0u32, false, 64usize);
    while o + 56 <= p.len() && o < 64 + 56 * 32 {
        let Some(typ) = u32_at(p, o, true) else { break };
        match typ {
            1 => {
                let (Some(flags), Some(off), Some(vaddr), Some(filesz), Some(memsz), Some(align)) = (u32_at(p, o + 4, true), u64_at(o + 8), u64_at(o + 16), u64_at(o + 32), u64_at(o + 40), u64_at(o + 48)) else { break };
                if !(1..=7).contains(&flags) || memsz == 0 || filesz > memsz || !matches!(align, 0x1000 | 0x4000 | 0x1_0000 | 0x20_0000) || vaddr % align != off % align { break; }
                loads += 1; exec |= flags & 1 != 0;
            }
            // inne znane typy segmentów mogą leżeć między segmentami ładowanymi
            2..=7 | 0x6474_e550..=0x6474_e553 | 0x7000_0000..=0x7fff_ffff => {}
            _ => break,
        }
        o += 56;
    }
    loads >= 2 && exec
}

/// Nagłówek obrazu, z którego usunięto znaczniki formatu (częsty zabieg po ręcznym załadowaniu
/// programu do pamięci), rozpoznany po tablicy sekcji albo segmentów. Zwraca nazwę formatu.
pub fn wiped_header_kind(p: &[u8]) -> Option<&'static str> {
    if p.len() < 512 || header_kind(p).is_some() { return None; }
    if pe_section_table(p) { return Some("PE"); }
    if elf_program_table(p) { return Some("ELF"); }
    None
}

/// Rozpoznaje nagłówek obrazu na początku strony; sama sygnatura nie wystarcza.
pub fn header_kind(p: &[u8]) -> Option<&'static str> {
    if p.len() < 64 { return None; }
    if &p[..4] == b"\x7fELF" {
        let le = match p[5] { 1 => true, 2 => false, _ => return None };
        if !(1..=2).contains(&p[4]) || p[6] != 1 { return None; }
        let et = u16_at(p, 16, le)?;
        if (1..=4).contains(&et) { return Some("ELF"); }
        return None;
    }
    if &p[..2] == b"MZ" {
        let off = u32_at(p, 0x3c, true)? as usize;
        if off >= 0x40 && off <= PAGE - 4 && p.get(off..off + 4) == Some(b"PE\0\0") {
            // Same sygnatury nie wystarczają: szkielet "MZ...PE" z zerowym polem Machine zdarza się
            // w zwykłych danych systemowych (svchost, stacja testowa 2026-11-22). Obraz ma typ maszyny i sekcje.
            let (machine, sections) = (u16_at(p, off + 4, true)?, u16_at(p, off + 6, true)?);
            if machine != 0 && (1..=96).contains(&sections) { return Some("PE"); }
        }
        return None;
    }
    let m = u32_at(p, 0, true)?;
    let le = match m { 0xfeedface | 0xfeedfacf => true, 0xcefaedfe | 0xcffaedfe => false, _ => return None };
    let filetype = u32_at(p, 12, le)?;
    let ncmds = u32_at(p, 16, le)?;
    if (1..=12).contains(&filetype) && (1..=4096).contains(&ncmds) { Some("Mach-O") } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn elf() -> Vec<u8> {
        let mut p = vec![0u8; PAGE];
        p[..4].copy_from_slice(b"\x7fELF"); p[4] = 2; p[5] = 1; p[6] = 1; p[16] = 3;
        p
    }
    #[test]
    fn headers() {
        assert_eq!(header_kind(&elf()), Some("ELF"));
        let mut bad = elf(); bad[16] = 9;
        assert_eq!(header_kind(&bad), None, "sama sygnatura ELF nie wystarcza");
        let mut pe = vec![0u8; PAGE];
        pe[..2].copy_from_slice(b"MZ"); pe[0x3c] = 0x80; pe[0x80..0x84].copy_from_slice(b"PE\0\0"); pe[0x80 + 4] = 0x64; pe[0x80 + 5] = 0x86; pe[0x80 + 6] = 1;
        assert_eq!(header_kind(&pe), Some("PE"));
        pe[0x80] = b'X';
        assert_eq!(header_kind(&pe), None, "MZ bez PE to nie nagłówek");
        pe[0x80] = b'P';
        assert_eq!(header_kind(&pe), Some("PE"));
        pe[0x84] = 0; pe[0x85] = 0;
        assert_eq!(header_kind(&pe), None, "zerowe pole Machine: szkielet, nie obraz");
        pe[0x84] = 0x64; pe[0x85] = 0x86; pe[0x86] = 0;
        assert_eq!(header_kind(&pe), None, "zero sekcji");
        let mut m = vec![0u8; PAGE];
        m[..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes()); m[12] = 2; m[16] = 20;
        assert_eq!(header_kind(&m), Some("Mach-O"));
        assert_eq!(header_kind(&vec![0u8; PAGE]), None);
        assert_eq!(header_kind(b"MZ"), None);
    }
    /// Strona z nagłówkiem PE: sygnatury i tablica sekcji (.text wykonywalna, .rdata, .data).
    fn pe_page() -> Vec<u8> {
        let mut p = vec![0u8; PAGE];
        p[..2].copy_from_slice(b"MZ"); p[0x3c] = 0x80; p[0x80..0x84].copy_from_slice(b"PE\0\0");
        p[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); p[0x86] = 3;
        for (i, (name, va, chars)) in [(&b".text"[..], 0x1000u32, 0x6000_0020u32), (b".rdata", 0x3000, 0x4000_0040), (b".data", 0x5000, 0xc000_0040)].iter().enumerate() {
            let o = 0x188 + i * 40;
            p[o..o + name.len()].copy_from_slice(name);
            p[o + 8..o + 12].copy_from_slice(&0x1800u32.to_le_bytes()); p[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            p[o + 16..o + 20].copy_from_slice(&0x1800u32.to_le_bytes()); p[o + 20..o + 24].copy_from_slice(&(0x400 + i as u32 * 0x1800).to_le_bytes());
            p[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }
        p
    }
    /// Strona z nagłówkiem ELF 64-bit: sygnatura i trzy segmenty (PT_PHDR, PT_LOAD r-x, PT_LOAD rw-).
    fn elf_page() -> Vec<u8> {
        let mut p = elf();
        for (i, (typ, flags, off, memsz)) in [(6u32, 4u32, 0x40u64, 0xa8u64), (1, 5, 0, 0x2000), (1, 6, 0x2000, 0x1000)].iter().enumerate() {
            let o = 64 + i * 56;
            p[o..o + 4].copy_from_slice(&typ.to_le_bytes()); p[o + 4..o + 8].copy_from_slice(&flags.to_le_bytes());
            p[o + 8..o + 16].copy_from_slice(&off.to_le_bytes()); p[o + 16..o + 24].copy_from_slice(&(0x40_0000 + off).to_le_bytes());
            p[o + 32..o + 40].copy_from_slice(&memsz.to_le_bytes()); p[o + 40..o + 48].copy_from_slice(&memsz.to_le_bytes()); p[o + 48..o + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        p
    }

    #[test]
    fn header_with_wiped_signature_is_recognised_by_its_tables() {
        // z sygnaturą: zwykły nagłówek, a nie "wymazany" (żeby nie zgłaszać tego samego dwa razy)
        assert_eq!((header_kind(&pe_page()), wiped_header_kind(&pe_page())), (Some("PE"), None));
        assert_eq!((header_kind(&elf_page()), wiped_header_kind(&elf_page())), (Some("ELF"), None));
        // PE: wymazane MZ, wymazane PE, oba naraz, cały początek strony wyzerowany aż do tablicy sekcji
        let mut a = pe_page(); a[..2].fill(0);
        let mut b = pe_page(); b[0x80..0x84].fill(0);
        let mut c = pe_page(); c[..0x188].fill(0);
        for (n, p) in [("MZ", &a), ("PE", &b), ("all", &c)] { assert_eq!((header_kind(p), wiped_header_kind(p)), (None, Some("PE")), "{n}"); }
        // ELF: wymazane pierwsze 16 bajtów albo sam typ pliku
        let mut e = elf_page(); e[..16].fill(0);
        let mut t = elf_page(); t[16] = 0;
        for (n, p) in [("ident", &e), ("type", &t)] { assert_eq!((header_kind(p), wiped_header_kind(p)), (None, Some("ELF")), "{n}"); }
        // kontrole: tylko jedna sekcja, żadna sekcja nie jest wykonywalna, adresy nierosnące, dane losowe, zera, tekst z nazwami sekcji
        let mut one = c.clone(); one[0x188 + 40..0x188 + 120].fill(0);
        let mut noexec = c.clone(); noexec[0x188 + 36..0x188 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        let mut order = c.clone(); order[0x188 + 40 + 12..0x188 + 40 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); order[0x188 + 80 + 12..0x188 + 80 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        let noise: Vec<u8> = (0..PAGE as u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let mut text = vec![b' '; PAGE]; for (i, w) in [".text", ".rdata", ".data", ".reloc"].iter().cycle().take(200).enumerate() { text[i * 16..i * 16 + w.len()].copy_from_slice(w.as_bytes()); }
        let mut one_load = e.clone(); one_load[64 + 2 * 56] = 4;
        for (n, p) in [("one", &one), ("noexec", &noexec), ("order", &order), ("noise", &noise), ("zero", &vec![0u8; PAGE]), ("text", &text), ("one_load", &one_load)] {
            assert_eq!(wiped_header_kind(p), None, "{n}");
        }
    }

    /// Tablica sekcji bez sygnatury liczy się tylko w regionie wykonywalnym: kopia nagłówka pliku w danych
    /// (sterta programu czytającego pliki wykonywalne) nie jest znaleziskiem.
    #[test]
    fn wiped_header_is_reported_only_in_executable_regions() {
        use crate::{scan_source, Config};
        use nanshe_core::*;
        struct One(Region, Vec<u8>);
        impl MemorySource for One {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), arch: "x86_64".into(), pid: Some(1), name: None, source_type: "live".into(), exe: None, exe_deleted: false, exe_verified: false } }
            fn regions(&self) -> Result<Vec<Region>> { Ok(vec![self.0.clone()]) }
            fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
                let o = (addr - self.0.base) as usize; let n = buf.len().min(self.1.len() - o); buf[..n].copy_from_slice(&self.1[o..o + n]); Ok(n)
            }
        }
        // sterta: na początku strony nagłówek alokatora, dalej kopia nagłówka pliku z tablicą sekcji
        let mut heap = vec![0u8; 2 * PAGE];
        heap[0x40..0x40 + PAGE - 0x40].copy_from_slice(&pe_page()[..PAGE - 0x40]);
        let mut wiped = pe_page(); wiped[..2].fill(0); wiped[0x80..0x84].fill(0); wiped.resize(2 * PAGE, 0x90);
        let scan = |prot: &str, data: &Vec<u8>| {
            let r = Region { base: 0x10000, size: data.len() as u64, prot: Prot::parse(prot), kind: RegionKind::Private, backing: None, backing_deleted: false, label: None, readable: true };
            let rep = scan_source(&One(r, data.clone()), &Config::default());
            rep.regions.iter().flat_map(|x| x.findings.iter().map(|f| (f.tag.clone(), f.reason.clone()))).collect::<Vec<_>>()
        };
        let hdr = |v: &Vec<(String, String)>| v.iter().filter(|f| f.0 == "HDR").count();
        assert_eq!(hdr(&scan("rw-", &heap)), 0, "kopia nagłówka w danych");
        assert_eq!(hdr(&scan("rw-", &wiped)), 0, "wymazany nagłówek w danych niewykonywalnych nie jest zgłaszany");
        let x = scan("r-x", &wiped);
        assert_eq!(hdr(&x), 1);
        assert!(x.iter().any(|f| f.0 == "HDR" && f.1.contains("wymazaną sygnaturą")), "{x:?}");
    }

}
