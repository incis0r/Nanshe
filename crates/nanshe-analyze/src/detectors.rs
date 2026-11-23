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

struct Memfd;
impl Detector for Memfd {
    fn id(&self) -> &'static str { "memfd" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "linux" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_x() && is_memfd(r) {
            vec![ctx.finding(self.id(), "MEMFD", r, r.base, r.size, 40,
                trf!("wykonywalne mapowanie {}", "executable mapping {}", r.backing.as_deref().unwrap_or("memfd:")))]
        } else { vec![] }
    }
}

struct DelExec;
impl Detector for DelExec {
    fn id(&self) -> &'static str { "del-exec" }
    fn applies(&self, i: &nanshe_core::SourceInfo) -> bool { i.os == "linux" || i.os == "freebsd" }
    fn scan(&self, r: &Region, _d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.is_x() && r.backing_deleted && !is_memfd(r) {
            vec![ctx.finding(self.id(), "DEL-EXEC", r, r.base, r.size, 30,
                trf!("wykonywalne mapowanie usuniętego pliku {}", "executable mapping of deleted file {}", r.backing.as_deref().unwrap_or("?")))]
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
        let Some((bytes, first)) = ctx.modified else { return vec![] };
        let name = r.backing.as_deref().unwrap_or("?");
        // Windows: strony obrazu przestają być współdzielone także z łagodnych powodów (relokacja
        // biblioteki bez ASLR, podpięcia piaskownicy Chromium w ntdll, samo środowisko .NET w clr.dll,
        // procesy 32-bitowe). Pomiar na stacji testowej Windows 2026-11-22: 28 takich regionów w 19 procesach.
        // Dlatego pełną wagę mają tylko moduły, których nikt poza obejściami zabezpieczeń nie zmienia;
        // reszta dostaje 10 punktów: razem z rzadkimi stronami o wysokiej entropii w tym samym kodzie
        // (ENT-X 10) nadal jest to "info" (przy 20 punktach dziesięć zwykłych procesów stawało się "podejrzane").
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase();
        let weight = if ctx.info.os != "windows" || matches!(base.as_str(), "amsi.dll" | "wldp.dll") { 40 } else { 10 };
        vec![ctx.finding(self.id(), "IMG-MOD", r, first.clamp(r.base, r.base.saturating_add(r.size.saturating_sub(1))), PAGE as u64, weight,
            trf!("kod z pliku zmieniony w pamięci: {} KiB stron niewspółdzielonych z plikiem ({name})", "code from a file changed in memory: {} KiB of pages not shared with the file ({name})", bytes.div_ceil(1024)))]
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

struct Hdr;
impl Detector for Hdr {
    fn id(&self) -> &'static str { "hdr" }
    fn scan(&self, r: &Region, d: &[u8], ctx: &Ctx) -> Vec<Finding> {
        if r.backing.is_some() || is_kernel_special(r) { return vec![]; }
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
                let reason = if aligned { trf!("nagłówek {fmt} w regionie bez pliku źródłowego", "{fmt} header in a region not backed by a file") }
                    else { trf!("nagłówek {fmt} w regionie bez pliku źródłowego, {:#x} bajtów za początkiem strony", "{fmt} header in a region not backed by a file, {:#x} bytes past the start of a page", i % PAGE) };
                let mut f = ctx.finding(self.id(), "HDR", r, addr, PAGE as u64, 40, reason);
                f.id = format!("{}:{:x}:HDR", ctx.pid_str(), addr);
                out.push(f);
                if out.len() >= 8 { break; }
                i += 64; // nagłówek znaleziony: kolejnego nie szukamy w jego wnętrzu
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
}
