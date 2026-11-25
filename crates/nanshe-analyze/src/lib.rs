//! Entropia, detektory, punktacja. Widzi wyłącznie abstrakcję `MemorySource` (Z2).
#![forbid(unsafe_code)]

pub mod detectors;
pub mod entropy;

use nanshe_core::*;
use nanshe_core::trf;

#[derive(Clone, Debug)]
pub struct Config {
    pub max_region_bytes: u64,
    /// 0 = bez podglądu bajtów (`--no-bytes`)
    pub preview_bytes: usize,
    pub heat_cell: u64,
    pub heatmap: bool,
    pub ent_high: f32,
    pub ent_very_high: f32,
    /// udział stron o wysokiej entropii, od którego kod z pliku dostaje pełną wagę ENT-X
    pub ent_file_fraction: f32,
    /// nazwy programów z silnikiem JIT; obniżają wagę RWX / X-PRIV / ENT-X.
    /// Dopasowanie po ścieżce programu z jądra, nigdy po nazwie, którą proces ustawia sam.
    pub allow_jit: Vec<String>,
    /// katalogi, z których program musi pochodzić, żeby lista dozwolonych zadziałała
    pub allow_jit_dirs: Vec<String>,
    /// zachowaj pełną mapę regionów procesu ze znaleziskami od wagi "podejrzane"
    pub keep_layout: bool,
    /// limit liczby regionów procesu; mapa o tej długości jest traktowana jako obcięta
    pub max_regions: usize,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            max_region_bytes: 64 << 20,
            preview_bytes: 256,
            heat_cell: 64 << 10,
            heatmap: false,
            ent_high: 7.2,
            ent_very_high: 7.8,
            ent_file_fraction: 0.25,
            // Programy, które same tworzą kod w trakcie pracy. Druga grupa pochodzi z pomiaru na 20 hostach
            // Linux (2026-11-23): serwer WWW i PHP (wyrażenia regularne PCRE kompilowane w locie), powłoka
            // GNOME i gjs (silnik JavaScript), interpreter Pythona (libffi, a od 3.13 własny JIT).
            allow_jit: ["node", "java", "dotnet", "firefox", "firefox-esr", "chrome", "chromium",
                "msedge", "brave", "electron", "code", "pwsh", "powershell", "qemu-system-x86_64", "luajit",
                "apache2", "httpd", "php", "php-fpm", "gjs", "gjs-console", "gnome-shell", "gnome-terminal-server", "python", "uwsgi"]
                .iter().map(|s| s.to_string()).collect(),
            allow_jit_dirs: ["/usr/", "/opt/", "/bin/", "/sbin/", "/snap/"].iter().map(|s| s.to_string()).collect(),
            keep_layout: false,
            max_regions: MAX_REGIONS,
        }
    }
}

pub const SCORE_SUSPICIOUS: u32 = 30;
pub const SCORE_HIGH: u32 = 60;
const JIT_TAGS: [&str; 4] = ["RWX", "X-PRIV", "X-MAP", "ENT-X"];
const JIT_DIVISOR: u32 = 3;

pub fn severity(score: u32) -> Severity {
    match score {
        0 => Severity::None,
        s if s < SCORE_SUSPICIOUS => Severity::Info,
        s if s < SCORE_HIGH => Severity::Suspicious,
        _ => Severity::High,
    }
}

pub struct Ctx<'a> {
    pub info: &'a SourceInfo,
    pub cfg: &'a Config,
    pub page_entropy: &'a [f32],
    /// wątki, których adres leży w tym regionie
    pub threads: &'a [ThreadInfo],
    /// zmieniony kod z pliku w tym regionie: (bajty, adres pierwszej strony)
    pub modified: Option<CodeChange>,
    pub traits: ProcTraits,
    /// Znacznik rozpoznanego środowiska tworzącego kod w locie (np. "jit:webview2"), jeśli proces je ma.
    pub allow: Option<&'a str>,
    data: &'a [u8],
}
impl<'a> Ctx<'a> {
    pub fn pid_str(&self) -> String {
        self.info.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
    }
    pub fn finding(&self, detector: &str, tag: &str, r: &Region, addr: u64, size: u64, weight: u32, reason: String) -> Finding {
        let off = addr.saturating_sub(r.base) as usize;
        let bytes_hex = if self.cfg.preview_bytes > 0 && off < self.data.len() {
            let end = (off + self.cfg.preview_bytes).min(self.data.len());
            Some(hex(&self.data[off..end]))
        } else { None };
        Finding {
            id: format!("{}:{:x}:{}", self.pid_str(), r.base, tag),
            detector: detector.into(), tag: tag.into(), addr, size, prot: r.prot,
            entropy: None, weight, reason, bytes_hex,
        }
    }
}

fn skip_read(r: &Region) -> bool {
    !r.readable || !r.prot.map(|p| p.r()).unwrap_or(true)
        || matches!(r.label.as_deref(), Some("[vvar]") | Some("[vsyscall]") | Some("[vvar_vclock]"))
        // macOS: kod bibliotek systemowych we wspólnej pamięci (ponad 1 GiB, identyczny w każdym procesie)
        // nie jest czytany; strona podmieniona prywatnie nie ma tej etykiety i jest czytana jak każda inna
        || r.label.as_deref() == Some("[dyld shared cache]")
}

/// Czyta region kawałkami; zatrzymuje się na pierwszym błędzie (częściowy wynik, Z8).
fn read_region(src: &dyn MemorySource, r: &Region, max: u64) -> Vec<u8> {
    let want = r.size.min(max) as usize;
    // Bufor rośnie po 1 MiB razem z udanymi odczytami: region nieczytelny nie kosztuje alokacji 64 MiB.
    let mut buf: Vec<u8> = Vec::new();
    let mut done = 0;
    while done < want {
        let end = (done + (1 << 20)).min(want);
        buf.resize(end, 0);
        match src.read_at(r.base + done as u64, &mut buf[done..end]) {
            Ok(n) if n > 0 => done += n,
            _ => break,
        }
    }
    buf.truncate(done);
    buf
}

/// Windows: środowisko JIT rozpoznajemy po załadowanym module, nie po nazwie programu, bo .NET
/// i WebView2 działają wewnątrz dowolnych programów. Oba warunki są konieczne:
/// - backend potwierdził, że plik programu leży w katalogu systemowym (`exe_verified`),
/// - moduł środowiska jest obrazem (`MEM_IMAGE`) załadowanym z `\Windows\` albo `\Program Files\`.
/// Bez pierwszego warunku wystarczyłoby załadować `clr.dll` do własnego programu z `%TEMP%`.
/// Ryzyko, które zostaje: kod wstrzyknięty do legalnego procesu .NET dziedziczy obniżkę
/// (tak samo jak na Linuksie w procesie `node`); `HDR` i `GUARD-X` nie są obniżane.
fn jit_allow_windows(info: &SourceInfo, regions: &[Region]) -> Option<String> {
    if !info.exe_verified || info.exe_deleted { return None; }
    regions.iter().filter(|r| r.kind == RegionKind::Image).find_map(|r| {
        let path = r.backing.as_deref()?.to_ascii_lowercase();
        // ścieżka urządzenia: \Device\HarddiskVolumeN\Windows\...; katalog musi stać w korzeniu wolumenu
        let rest = path.strip_prefix("\\device\\harddiskvolume")?.trim_start_matches(|c: char| c.is_ascii_digit());
        // Konkretne katalogi instalacyjne środowisk, nie całe \Windows ani \Program Files: w \Windows
        // są podkatalogi zapisywalne dla zwykłego użytkownika (Temp, Tasks, spool\drivers\color).
        let under = |dirs: &[&str]| dirs.iter().any(|d| rest.starts_with(d));
        match rest.rsplit('\\').next()? {
            "clr.dll" if under(&["\\windows\\microsoft.net\\framework\\", "\\windows\\microsoft.net\\framework64\\"]) => Some("jit:dotnet".to_string()),
            "coreclr.dll" if under(&["\\program files\\dotnet\\shared\\", "\\program files (x86)\\dotnet\\shared\\", "\\program files\\windowsapps\\"]) => Some("jit:dotnet".to_string()),
            "msedge.dll" if under(&["\\program files\\microsoft\\edgewebview\\application\\", "\\program files (x86)\\microsoft\\edgewebview\\application\\",
                "\\program files\\microsoft\\edge\\application\\", "\\program files (x86)\\microsoft\\edge\\application\\"]) => Some("jit:webview2".to_string()),
            _ => None,
        }
    })
}

fn jit_allow(cfg: &Config, info: &SourceInfo) -> Option<String> {
    // Nazwa procesu (comm) jest pod kontrolą samego procesu, więc nie może niczego obniżać.
    // Liczy się plik programu wg jądra: istniejący na dysku, z katalogu systemowego i potwierdzony
    // przez backend (ten sam plik, który widzi skaner, własność roota, niezapisywalny dla innych).
    // Sama ścieżka nie wystarcza: proces w kontenerze ma własne /usr.
    let exe = info.exe.as_deref()?;
    if !info.exe_verified || info.exe_deleted || exe.contains("/../") || !cfg.allow_jit_dirs.iter().any(|d| exe.starts_with(d.as_str())) { return None; }
    let base = exe.rsplit('/').next()?.to_lowercase();
    // Nazwa pliku bywa z numerem wersji (python3.14, php-fpm8.2): porównujemy też nazwę bez końcowych cyfr i kropek.
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    // Do raportu (i dalej do modelu) trafia stały token z listy, nie ścieżka z badanego systemu.
    cfg.allow_jit.iter().find(|a| a.as_str() == base || (!stem.is_empty() && a.as_str() == stem)).map(|a| format!("jit:{a}"))
}

/// Cechy procesu ustalone raz z pliku programu i mapy regionów; zmieniają opis i wagę niektórych znalezisk.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ProcTraits {
    /// Proces hiperwizora QEMU: jego duże regiony danych to pamięć maszyn wirtualnych.
    pub vm_host: bool,
    /// Proces ma zmapowaną bibliotekę libffi z katalogu systemowego (tworzy wykonywalne mapowania memfd o nazwie "libffi").
    pub libffi: bool,
}

/// Tylko Linux i tylko dla potwierdzonego pliku programu z katalogu systemowego (te same warunki co obniżka JIT).
fn proc_traits(cfg: &Config, info: &SourceInfo, regions: &[Region]) -> ProcTraits {
    let Some(exe) = info.exe.as_deref() else { return ProcTraits::default() };
    if info.os != "linux" || !info.exe_verified || info.exe_deleted || exe.contains("/../") || !cfg.allow_jit_dirs.iter().any(|d| exe.starts_with(d.as_str())) { return ProcTraits::default(); }
    let base = exe.rsplit('/').next().unwrap_or("");
    let sys_lib = |p: &str| ["/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/"].iter().any(|d| p.starts_with(d)) && !p.contains("/../");
    ProcTraits {
        vm_host: base.starts_with("qemu-system-") || base == "qemu-kvm",
        libffi: regions.iter().any(|r| r.is_x() && r.backing.as_deref().map(|b| sys_lib(b) && b.rsplit('/').next().unwrap_or("").starts_with("libffi.so")).unwrap_or(false)),
    }
}

pub fn scan_source(src: &dyn MemorySource, cfg: &Config) -> ProcessReport {
    let info = src.info();
    let mut rep = ProcessReport {
        info: info.clone(), regions_total: 0, regions_unreadable: 0, bytes_scanned: 0,
        max_severity: Severity::None, error: None, regions: vec![], layout: None, context: None,
    };
    let mut regions = match src.regions() {
        Ok(r) => r,
        Err(e) => { rep.error = Some(e.to_string()); return rep; }
    };
    // Mapa o długości limitu jest obcięta: skanujemy to, co mamy, ale wynik procesu jest niekompletny.
    if regions.len() >= cfg.max_regions {
        regions.truncate(cfg.max_regions);
        rep.error = Some(trf!("mapa regionów obcięta do limitu {}; dalsze regiony nie zostały sprawdzone", "region map truncated at the limit of {}; further regions were not examined", cfg.max_regions));
    }
    let dets: Vec<_> = detectors::all().into_iter().filter(|d| d.applies(&info)).collect();
    let threads = src.threads();
    let allow = if info.os == "windows" { jit_allow_windows(&info, &regions) } else { jit_allow(cfg, &info) };
    // dowód z systemu (np. podpis z uprawnieniem do JIT na macOS) ma pierwszeństwo przed listą nazw programów
    let allow = src.jit_evidence().or(allow);
    let traits = proc_traits(cfg, &info, &regions);
    rep.regions_total = regions.len() as u64;

    for r in &regions {
        let skip = skip_read(r);
        let data = if skip { Vec::new() } else { read_region(src, r, cfg.max_region_bytes) };
        if !skip && data.is_empty() && r.size > 0 { rep.regions_unreadable += 1; }
        // Wykonywalny region za strażnikiem liczy się jako nieczytelny (wynik częściowy). Zwykłych
        // strażników stosu (RW) nie liczymy: ma je każdy wątek, więc każdy skan byłby "częściowy".
        if detectors::is_guarded_exec(r) { rep.regions_unreadable += 1; }
        rep.bytes_scanned += data.len() as u64;
        let stats = entropy::page_stats(&data);
        let end = r.base.saturating_add(r.size);
        let here: Vec<ThreadInfo> = threads.iter().filter(|t| t.addr >= r.base && t.addr < end).cloned().collect();
        // pytamy tylko o wykonywalny, niezapisywalny kod z pliku: tam zmiana w pamięci jest nietypowa
        let modified = if r.backing.is_some() && r.is_x() && !r.is_w() { src.modified_code(r).filter(|m| m.bytes > 0 || (m.compared && !m.verified)) } else { None };
        let ctx = Ctx { info: &info, cfg, page_entropy: &stats.entropy, threads: &here, modified, traits, allow: allow.as_deref(), data: &data };

        let mut findings: Vec<Finding> = dets.iter().flat_map(|d| d.scan(r, &data, &ctx)).collect();
        if findings.is_empty() && !(cfg.heatmap && !data.is_empty()) { continue; }

        let mut allowlisted = None;
        if let Some(a) = &allow {
            // X-MAP jest obniżany tylko dla sekcji bez pliku (tak .NET mapuje wygenerowany kod);
            // wykonywalne mapowanie pliku nigdy nie dostaje obniżki.
            for f in findings.iter_mut().filter(|f| JIT_TAGS.contains(&f.tag.as_str()) && !(f.tag == "X-MAP" && r.backing.is_some())) {
                f.weight /= JIT_DIVISOR;
                allowlisted = Some(a.clone());
            }
        }
        let has_findings = !findings.is_empty();
        let score: u32 = findings.iter().map(|f| f.weight).sum();
        let sev = severity(score);
        rep.max_severity = rep.max_severity.max(sev);
        let nz: Vec<f32> = stats.entropy.clone();
        let (emax, emean) = if nz.is_empty() { (None, None) } else {
            (Some(detectors::round2(nz.iter().cloned().fold(0.0, f32::max))),
             Some(detectors::round2(nz.iter().sum::<f32>() / nz.len() as f32)))
        };
        rep.regions.push(RegionReport {
            region: r.clone(), bytes_read: data.len() as u64,
            truncated: (data.len() as u64) < r.size && !skip,
            entropy_max: emax, entropy_mean: emean, zero_pages: stats.zero_pages,
            score, severity: sev, allowlisted, findings,
            heat: if cfg.heatmap { Some(entropy::heat_cells(&stats.entropy, cfg.heat_cell)) } else { None },
            profile: if has_findings && !stats.entropy.is_empty() { Some(entropy::profile(&stats.entropy, 64)) } else { None },
            strings: if has_findings && cfg.preview_bytes > 0 { entropy::text_strings(&data, 40) } else { Vec::new() },
            sha256: if has_findings && !data.is_empty() { Some(sha256_hex(&data)) } else { None },
        });
    }
    if cfg.keep_layout && rep.max_severity >= Severity::Suspicious { rep.layout = Some(regions); }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake { name: &'static str, exe: Option<&'static str>, exe_deleted: bool, exe_verified: bool, regs: Vec<(Region, Vec<u8>)> }
    impl MemorySource for Fake {
        fn info(&self) -> SourceInfo {
            SourceInfo { os: "linux".into(), arch: "x86_64".into(), pid: Some(7), name: Some(self.name.into()), source_type: "live".into(), exe: self.exe.map(Into::into), exe_deleted: self.exe_deleted, exe_verified: self.exe_verified }
        }
        fn regions(&self) -> Result<Vec<Region>> { Ok(self.regs.iter().map(|r| r.0.clone()).collect()) }
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
            for (r, d) in &self.regs {
                if addr >= r.base && addr < r.base + d.len() as u64 {
                    let o = (addr - r.base) as usize;
                    let n = buf.len().min(d.len() - o);
                    buf[..n].copy_from_slice(&d[o..o + n]);
                    return Ok(n);
                }
            }
            Err(Error::Access("poza regionem".into()))
        }
    }
    fn reg(base: u64, size: u64, prot: &str, kind: RegionKind, backing: Option<&str>) -> Region {
        Region { base, size, prot: Prot::parse(prot), kind, backing: backing.map(Into::into), backing_deleted: false, label: None, readable: true }
    }
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x9e3779b97f4a7c15u64;
        (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 32) as u8 }).collect()
    }
    fn tags(p: &ProcessReport) -> Vec<String> {
        p.regions.iter().flat_map(|r| r.findings.iter().map(|f| f.tag.clone())).collect()
    }

    #[test]
    fn clean_process_has_no_findings() {
        let f = Fake { name: "cat", exe: None, exe_deleted: false, exe_verified: false, regs: vec![
            (reg(0x1000, 8192, "r-x", RegionKind::Mapped, Some("/bin/cat")), vec![0x90; 8192]),
            (reg(0x9000, 8192, "rw-", RegionKind::Private, None), noise(8192)), // wysoka entropia w danych to nie znalezisko
        ]};
        let p = scan_source(&f, &Config::default());
        assert!(p.regions.is_empty(), "{:?}", tags(&p));
        assert_eq!(p.max_severity, Severity::None);
        assert_eq!(p.bytes_scanned, 16384);
    }

    #[test]
    fn rwx_anon_high_entropy_is_high() {
        let f = Fake { name: "evil", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x10000, 8192, "rwx", RegionKind::Private, None), noise(8192))] };
        let p = scan_source(&f, &Config::default());
        let mut t = tags(&p); t.sort();
        assert_eq!(t, ["ENT-X", "RWX", "X-PRIV"]);
        assert_eq!(p.regions[0].severity, Severity::High);
        assert_eq!(p.regions[0].findings[0].bytes_hex.as_ref().unwrap().len(), 512);
    }

    #[test]
    fn each_condition_is_necessary() {
        // mutacje: każda zmiana jednej cechy musi zgasić odpowiedni tag
        let cfg = Config::default();
        let base = |prot, backing: Option<&str>, data| Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x10000, 8192, prot, RegionKind::Private, backing), data)] };
        assert!(!tags(&scan_source(&base("r-x", None, noise(8192)), &cfg)).contains(&"RWX".to_string()));
        assert!(!tags(&scan_source(&base("rw-", None, noise(8192)), &cfg)).contains(&"X-PRIV".to_string()));
        assert!(!tags(&scan_source(&base("r-x", None, vec![0x90; 8192]), &cfg)).contains(&"ENT-X".to_string()));
        let mut mapped = base("r-x", Some("/lib/x.so"), vec![0x90; 8192]);
        mapped.regs[0].0.kind = RegionKind::Mapped;
        assert!(tags(&scan_source(&mapped, &cfg)).is_empty());
    }

    #[test]
    fn hdr_only_without_backing() {
        let mut d = vec![0u8; 8192];
        d[4096..4100].copy_from_slice(b"\x7fELF"); d[4100] = 2; d[4101] = 1; d[4102] = 1; d[4112] = 3;
        let cfg = Config::default();
        let anon = Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x20000, 8192, "rw-", RegionKind::Private, None), d.clone())] };
        let p = scan_source(&anon, &cfg);
        assert_eq!(tags(&p), ["HDR"]);
        assert_eq!(p.regions[0].findings[0].addr, 0x21000);
        assert_eq!(p.regions[0].findings[0].id, "7:21000:HDR");
        let file = Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x20000, 8192, "rw-", RegionKind::Mapped, Some("/lib/x.so")), d)] };
        assert!(tags(&scan_source(&file, &cfg)).is_empty());
    }

    #[test]
    fn hdr_found_at_any_offset_with_same_validation() {
        // ładunek w buforze ze sterty: nagłówek 0x20 bajtów za początkiem strony (nagłówek alokatora)
        let cfg = Config::default();
        let mk_prot = |d: Vec<u8>, prot: &str| Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x20000, 8192, prot, RegionKind::Private, None), d)] };
        let mk = |d: Vec<u8>| mk_prot(d, "r-x");
        let hdr = |p: &ProcessReport| p.regions.iter().flat_map(|r| &r.findings).filter(|f| f.tag == "HDR").map(|f| f.addr).collect::<Vec<u64>>();
        let mut elf = vec![0u8; 8192];
        elf[0x1020..0x1024].copy_from_slice(b"\x7fELF"); elf[0x1024] = 2; elf[0x1025] = 1; elf[0x1026] = 1; elf[0x1030] = 3;
        let p = scan_source(&mk(elf.clone()), &cfg);
        assert_eq!(hdr(&p), [0x21020]);
        assert!(p.regions[0].findings.iter().any(|f| f.reason.contains("0x20 bajtów za początkiem strony")));
        // kontrola: w danych niewykonywalnych kopia nagłówka poza granicą strony to codzienność (ld.so na stosie)
        assert!(hdr(&scan_source(&mk_prot(elf.clone(), "rw-"), &cfg)).is_empty());
        let mut pe = vec![0u8; 8192];
        pe[0x10..0x12].copy_from_slice(b"MZ"); pe[0x10 + 0x3c] = 0x80; pe[0x90..0x94].copy_from_slice(b"PE\0\0"); pe[0x90 + 4] = 0x64; pe[0x90 + 5] = 0x86; pe[0x90 + 6] = 1;
        assert_eq!(hdr(&scan_source(&mk(pe.clone()), &cfg)), [0x20010]);
        // kontrole: uszkodzone pole ELF, MZ bez PE i Mach-O poza początkiem strony nie są nagłówkiem
        elf[0x1030] = 9;
        assert!(hdr(&scan_source(&mk(elf), &cfg)).is_empty());
        pe[0x90] = b'X';
        assert!(hdr(&scan_source(&mk(pe), &cfg)).is_empty());
        let mut macho = vec![0u8; 8192];
        macho[0x40..0x44].copy_from_slice(&0xfeedfacfu32.to_le_bytes()); macho[0x4c] = 2; macho[0x50] = 20;
        assert!(hdr(&scan_source(&mk(macho.clone()), &cfg)).is_empty());
        macho.copy_within(0x40..0x60, 0x1000);
        assert_eq!(hdr(&scan_source(&mk(macho), &cfg)), [0x21000], "Mach-O na początku strony nadal wykrywany");
        // niewykonywalny stos: kopia nagłówka z programu ładującego, nawet na początku strony, to nie znalezisko;
        // ten sam nagłówek na stosie wykonywalnym nadal jest zgłaszany
        let mut hdr_page = vec![0u8; 8192];
        hdr_page[0x1000..0x1004].copy_from_slice(b"\x7fELF"); hdr_page[0x1004] = 2; hdr_page[0x1005] = 1; hdr_page[0x1006] = 1; hdr_page[0x1010] = 3;
        let stack = |prot: &str| Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x20000, 8192, prot, RegionKind::Stack, None), hdr_page.clone())] };
        assert!(hdr(&scan_source(&stack("rw-"), &cfg)).is_empty());
        assert_eq!(hdr(&scan_source(&stack("rwx"), &cfg)), [0x21000]);
        // dane losowe nie dają fałszywych nagłówków
        assert!(!tags(&scan_source(&mk(noise(8192)), &cfg)).contains(&"HDR".to_string()));
    }

    #[test]
    fn x_map_is_windows_only_and_needs_exec_mapped() {
        struct Win(Fake);
        impl MemorySource for Win {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), ..self.0.info() } }
            fn regions(&self) -> Result<Vec<Region>> { self.0.regions() }
            fn read_at(&self, a: u64, b: &mut [u8]) -> Result<usize> { self.0.read_at(a, b) }
        }
        let cfg = Config::default();
        let mk = |prot, kind| Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x10000, 4096, prot, kind, None), vec![0x90; 4096])] };
        assert_eq!(tags(&scan_source(&Win(mk("r-x", RegionKind::Mapped)), &cfg)), ["X-MAP"]);
        assert!(tags(&scan_source(&Win(mk("r--", RegionKind::Mapped)), &cfg)).is_empty(), "bez X");
        assert!(tags(&scan_source(&Win(mk("r-x", RegionKind::Image)), &cfg)).is_empty(), "obraz modułu to nie X-MAP");
        assert!(tags(&scan_source(&mk("r-x", RegionKind::Mapped), &cfg)).is_empty(), "na Linuksie detektor nie działa");
        // MEMFD i DEL-EXEC nie dotyczą Windows
        let mut d = reg(0x40000, 4096, "r-x", RegionKind::Image, Some("C:\\x.dll"));
        d.backing_deleted = true;
        let w = Win(Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(d, vec![1; 4096])] });
        assert!(tags(&scan_source(&w, &cfg)).is_empty());
    }

    #[test]
    fn memfd_and_deleted() {
        let cfg = Config::default();
        let mut m = reg(0x30000, 4096, "r-x", RegionKind::Mapped, Some("memfd:payload"));
        m.backing_deleted = true;
        let mut d = reg(0x40000, 4096, "r-x", RegionKind::Mapped, Some("/tmp/x"));
        d.backing_deleted = true;
        let f = Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(m, vec![1; 4096]), (d, vec![1; 4096])] };
        assert_eq!(tags(&scan_source(&f, &cfg)), ["MEMFD", "DEL-EXEC"]);
    }

    #[test]
    fn x_tmp_flags_exec_from_world_writable_dir() {
        let cfg = Config::default();
        // NOP sled: niska entropia, żeby ENT-X nie mieszał w punktacji: liczy się sam X-TMP
        let mk = |path: &str, deleted: bool, prot: &str| {
            let mut r = reg(0x10000, 8192, prot, RegionKind::Mapped, Some(path));
            r.backing_deleted = deleted;
            Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(r, vec![0x90u8; 8192])] }
        };
        // wykonywalne mapowanie pliku z /tmp (plik na dysku): X-TMP, waga 30 = podejrzane
        let p = scan_source(&mk("/tmp/ns-rxfile-123", false, "r-x"), &cfg);
        assert_eq!(tags(&p), ["X-TMP"]);
        assert_eq!((p.regions[0].score, p.regions[0].severity), (30, Severity::Suspicious));
        for dir in ["/var/tmp/x", "/dev/shm/x", "/run/shm/x"] {
            assert!(tags(&scan_source(&mk(dir, false, "r-x"), &cfg)).contains(&"X-TMP".to_string()), "{dir}");
        }
        // kontrole: każdy warunek jest konieczny
        assert!(tags(&scan_source(&mk("/usr/bin/foo", false, "r-x"), &cfg)).is_empty(), "katalog systemowy");
        assert!(tags(&scan_source(&mk("/tmp/x", false, "r--"), &cfg)).is_empty(), "bez prawa wykonania");
        // plik usunięty to domena DEL-EXEC; X-TMP nie dubluje
        let del = tags(&scan_source(&mk("/tmp/x", true, "r-x"), &cfg));
        assert_eq!(del, ["DEL-EXEC"]);
        // tylko Linux
        struct Win(Fake);
        impl MemorySource for Win {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), ..self.0.info() } }
            fn regions(&self) -> Result<Vec<Region>> { self.0.regions() }
            fn read_at(&self, a: u64, b: &mut [u8]) -> Result<usize> { self.0.read_at(a, b) }
        }
        assert!(!tags(&scan_source(&Win(mk("/tmp/x", false, "r-x")), &cfg)).contains(&"X-TMP".to_string()));
    }

    #[test]
    fn x_tmp_flags_windows_module_image_from_temp_dir() {
        let cfg = Config::default();
        struct Win(Region);
        impl MemorySource for Win {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), arch: "x86_64".into(), pid: Some(7), name: Some("app.exe".into()), source_type: "live".into(),
                exe: Some("C:\\Program Files\\App\\app.exe".into()), exe_deleted: false, exe_verified: true } }
            fn regions(&self) -> Result<Vec<Region>> { Ok(vec![self.0.clone()]) }
            fn read_at(&self, _a: u64, b: &mut [u8]) -> Result<usize> { b.fill(0x90); Ok(b.len()) }
        }
        let run = |path: &str, prot: &str, kind: RegionKind| tags(&scan_source(&Win(reg(0x10000, 8192, prot, kind, Some(path))), &cfg));
        // obraz modułu z katalogu tymczasowego: X-TMP, waga 30; wielkość liter i postać ścieżki bez znaczenia
        let p = scan_source(&Win(reg(0x10000, 8192, "r-x", RegionKind::Image, Some("C:\\Users\\jan\\AppData\\Local\\Temp\\ns-ximage-1.exe"))), &cfg);
        assert_eq!(tags(&p), ["X-TMP"]);
        assert_eq!((p.regions[0].score, p.regions[0].severity), (30, Severity::Suspicious));
        for path in ["\\Device\\HarddiskVolume3\\WINDOWS\\TEMP\\a.dll", "C:\\Users\\Public\\a.dll", "\\Users\\x\\AppData\\LocalLow\\Temp\\a.dll", "C:\\$Recycle.Bin\\S-1-5\\a.exe"] {
            assert_eq!(run(path, "r-x", RegionKind::Image), ["X-TMP"], "{path}");
        }
        // kontrole: każdy warunek jest konieczny
        assert!(run("C:\\Windows\\System32\\a.dll", "r-x", RegionKind::Image).is_empty(), "katalog systemowy");
        assert!(run("C:\\Users\\jan\\AppData\\Local\\Microsoft\\Teams\\a.dll", "r-x", RegionKind::Image).is_empty(), "profil użytkownika poza katalogiem tymczasowym");
        assert!(run("C:\\Users\\jan\\AppData\\Local\\Temp\\a.dll", "r--", RegionKind::Image).is_empty(), "bez prawa wykonania");
        // sekcja niebędąca obrazem to domena X-MAP; X-TMP nie dubluje
        assert_eq!(run("C:\\Windows\\Temp\\a.dll", "r-x", RegionKind::Mapped), ["X-MAP"]);
    }

    #[test]
    fn windows_jit_needs_verified_exe_and_system_runtime_image() {
        struct Win { verified: bool, runtime: Option<(&'static str, RegionKind)>, payload: Vec<u8>, map_x: bool }
        impl MemorySource for Win {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), arch: "x86_64".into(), pid: Some(7), name: Some("app.exe".into()), source_type: "live".into(),
                exe: Some("C:\\Windows\\System32\\app.exe".into()), exe_deleted: false, exe_verified: self.verified } }
            fn regions(&self) -> Result<Vec<Region>> {
                let mut v = vec![reg(0x10000, 8192, "rwx", RegionKind::Private, None)];
                if self.map_x { v.push(reg(0x30000, 4096, "r-x", RegionKind::Mapped, None)); v.push(reg(0x40000, 4096, "r-x", RegionKind::Mapped, Some("\\Device\\HarddiskVolume3\\Users\\jan\\AppData\\Local\\Temp\\payload.bin"))); }
                if let Some((path, kind)) = self.runtime { v.push(reg(0x7ff0_0000, 4096, "r--", kind, Some(path))); }
                Ok(v)
            }
            fn read_at(&self, a: u64, b: &mut [u8]) -> Result<usize> {
                if (0x10000..0x12000).contains(&a) { let o = (a - 0x10000) as usize; let n = b.len().min(self.payload.len() - o); b[..n].copy_from_slice(&self.payload[o..o + n]); Ok(n) }
                else { let n = b.len().min(4096); b[..n].fill(0); Ok(n) }
            }
        }
        const CLR: &str = "\\Device\\HarddiskVolume3\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll";
        let cfg = Config::default();
        let scan = |verified, runtime, payload: Vec<u8>, map_x| scan_source(&Win { verified, runtime, payload, map_x }, &cfg);
        let nop = || vec![0x90u8; 8192];
        // sterta JIT w procesie z systemowym .NET: 60 -> 20, znaleziska widoczne, stały token
        let p = scan(true, Some((CLR, RegionKind::Image)), nop(), true);
        assert_eq!((p.regions[0].score, p.regions[0].severity, p.regions[0].allowlisted.as_deref()), (20, Severity::Info, Some("jit:dotnet")));
        assert_eq!(p.regions[0].findings.len(), 2);
        assert_eq!((p.regions[1].score, p.regions[1].allowlisted.is_some()), (10, true), "X-MAP sekcji bez pliku obniżony");
        assert_eq!((p.regions[2].score, p.regions[2].allowlisted.is_some()), (30, false), "wykonywalne mapowanie pliku nigdy nie jest obniżane");
        assert_eq!(scan(true, Some(("\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\1.2\\msedge.dll", RegionKind::Image)), nop(), false).regions[0].allowlisted.as_deref(), Some("jit:webview2"));
        // każdy warunek jest konieczny
        assert_eq!(scan(false, Some((CLR, RegionKind::Image)), nop(), false).regions[0].score, 60, "program spoza katalogów systemowych");
        assert_eq!(scan(true, None, nop(), false).regions[0].score, 60, "brak modułu środowiska");
        assert_eq!(scan(true, Some((CLR, RegionKind::Mapped)), nop(), false).regions[0].score, 60, "plik zmapowany jako dane, nie obraz");
        for fake in ["\\Device\\HarddiskVolume3\\Users\\jan\\AppData\\clr.dll", "\\Device\\HarddiskVolume3\\x\\Windows\\Microsoft.NET\\Framework64\\v4\\clr.dll", "\\Device\\HarddiskVolume3\\Windows\\System32\\notclr.dll",
            "\\Device\\HarddiskVolume3\\Windows\\Temp\\clr.dll", "\\Device\\HarddiskVolume3\\Windows\\System32\\spool\\drivers\\color\\coreclr.dll", "\\Device\\HarddiskVolume3\\Program Files\\Evil\\msedge.dll"] {
            assert_eq!(scan(true, Some((fake, RegionKind::Image)), nop(), false).regions[0].score, 60, "{fake}");
        }
        // ładunek o wysokiej entropii przebija próg mimo obniżki, a nagłówek obrazu nie jest obniżany
        assert_eq!(scan(true, Some((CLR, RegionKind::Image)), noise(8192), false).regions[0].severity, Severity::Suspicious);
        let mut pe = nop(); pe[..2].copy_from_slice(b"MZ"); pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); pe[0x80..0x88].copy_from_slice(b"PE\0\0\x64\x86\x01\x00");
        let h = scan(true, Some((CLR, RegionKind::Image)), pe, false);
        assert_eq!((h.regions[0].score, h.regions[0].severity), (60, Severity::High), "RWX 10 + X-PRIV 10 + HDR 40");
    }

    /// Źródło z wątkami i informacją o zmienionym kodzie, do testów detektorów THR-PRIV i IMG-MOD.
    struct Live { os: &'static str, verified: bool, regs: Vec<Region>, threads: Vec<ThreadInfo>, modified: Vec<(u64, u64)>, compared: bool, same_file: bool }
    impl MemorySource for Live {
        fn info(&self) -> SourceInfo { SourceInfo { os: self.os.into(), arch: "x86_64".into(), pid: Some(7), name: Some("p".into()), source_type: "live".into(),
            exe: Some("C:\\Windows\\System32\\p.exe".into()), exe_deleted: false, exe_verified: self.verified } }
        fn regions(&self) -> Result<Vec<Region>> { Ok(self.regs.clone()) }
        fn read_at(&self, _a: u64, b: &mut [u8]) -> Result<usize> { let n = b.len().min(4096); b[..n].fill(0x90); Ok(n) }
        fn threads(&self) -> Vec<ThreadInfo> { self.threads.clone() }
        fn modified_code(&self, r: &Region) -> Option<CodeChange> { self.modified.iter().find(|m| m.0 == r.base).map(|m| CodeChange { bytes: m.1, first: r.base + 0x1000, compared: self.compared, verified: self.same_file }) }
    }

    #[test]
    fn thread_in_memory_without_a_file_is_flagged_at_full_weight() {
        let cfg = Config::default();
        let regs = vec![reg(0x10000, 4096, "r-x", RegionKind::Private, None), reg(0x7ff0_0000, 8192, "r-x", RegionKind::Image, Some("\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll")),
            reg(0x7ff1_0000, 4096, "r--", RegionKind::Image, Some("\\Device\\HarddiskVolume3\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll"))];
        let scan = |threads: Vec<ThreadInfo>, verified| scan_source(&Live { os: "windows", verified, regs: regs.clone(), threads, modified: vec![], compared: false, same_file: false }, &cfg);
        let p = scan(vec![ThreadInfo { tid: 44, addr: 0x10800 }, ThreadInfo { tid: 45, addr: 0x7ff0_0100 }], false);
        assert_eq!(tags(&p), ["X-PRIV", "THR-PRIV"]);
        let f = p.regions[0].findings.iter().find(|f| f.tag == "THR-PRIV").unwrap();
        assert_eq!((f.addr, f.weight, p.regions[0].score, p.regions[0].severity), (0x10800, 40, 70, Severity::High));
        assert!(f.reason.contains("44") && !f.reason.contains("45"));
        // kontrola: wątek w kodzie z pliku nie jest znaleziskiem, a bez wątków zostaje sam X-PRIV
        assert_eq!(tags(&scan(vec![ThreadInfo { tid: 45, addr: 0x7ff0_0100 }], false)), ["X-PRIV"]);
        assert_eq!(tags(&scan(vec![], false)), ["X-PRIV"]);
        // w procesie ze środowiskiem JIT X-PRIV jest obniżany, ale wątek w pamięci bez pliku nie
        let j = scan(vec![ThreadInfo { tid: 44, addr: 0x10800 }], true);
        assert_eq!((j.regions[0].score, j.regions[0].severity, j.regions[0].allowlisted.as_deref()), (50, Severity::Suspicious, Some("jit:dotnet")));
        // Linux: ten sam detektor; region jądra ([vdso]) nie jest znaleziskiem
        let mut vdso = reg(0x20000, 4096, "r-x", RegionKind::Unknown, None); vdso.label = Some("[vdso]".into());
        let l = scan_source(&Live { os: "linux", verified: false, regs: vec![vdso, reg(0x30000, 4096, "rwx", RegionKind::Private, None)],
            threads: vec![ThreadInfo { tid: 9, addr: 0x20010 }, ThreadInfo { tid: 10, addr: 0x30010 }], modified: vec![], compared: false, same_file: false }, &cfg);
        assert_eq!(tags(&l), ["RWX", "X-PRIV", "THR-PRIV"]);
    }

    #[test]
    fn modified_code_of_a_file_is_flagged_only_in_read_only_executable_mappings() {
        let cfg = Config::default();
        let code = reg(0x7ff0_0000, 8192, "r-x", RegionKind::Image, Some("\\Device\\HarddiskVolume3\\Windows\\System32\\amsi.dll"));
        let scan = |r: Region, modified: Vec<(u64, u64)>| scan_source(&Live { os: "windows", verified: false, regs: vec![r], threads: vec![], modified, compared: false, same_file: false }, &cfg);
        let p = scan(code.clone(), vec![(0x7ff0_0000, 4096)]);
        assert_eq!(tags(&p), ["IMG-MOD"]);
        assert_eq!((p.regions[0].findings[0].addr, p.regions[0].findings[0].weight, p.regions[0].severity), (0x7ff0_1000, 40, Severity::Suspicious));
        assert!(p.regions[0].findings[0].reason.contains("4 KiB"));
        // Windows: zmiana w zwykłej bibliotece ma wagę "info" (łagodne przyczyny są częste), w Linuksie pełną
        let user32 = Region { backing: Some("\\Device\\HarddiskVolume3\\Windows\\System32\\user32.dll".into()), ..code.clone() };
        let u = scan(user32.clone(), vec![(0x7ff0_0000, 4096)]);
        assert_eq!((u.regions[0].findings[0].weight, u.regions[0].severity), (10, Severity::Info));
        let lin = scan_source(&Live { os: "linux", verified: false, regs: vec![Region { kind: RegionKind::Mapped, backing: Some("/usr/lib/libc.so.6".into()), ..code.clone() }], threads: vec![], modified: vec![(0x7ff0_0000, 4096)], compared: false, same_file: false }, &cfg);
        assert_eq!((lin.regions[0].findings[0].weight, lin.regions[0].severity), (40, Severity::Suspicious));
        // po porównaniu z plikiem znalezisko podaje liczbę różnych bajtów i adres pierwszego; zwykła biblioteka
        // Windows ma nadal 10 punktów (takie różnice są na stacji powszechne), moduł ochronny 40
        let cmp_as = |r: Region, bytes, same_file| scan_source(&Live { os: "windows", verified: false, regs: vec![r], threads: vec![], modified: vec![(0x7ff0_0000, bytes)], compared: true, same_file }, &cfg);
        let cmp = |r: Region, bytes| cmp_as(r, bytes, true);
        let c = cmp(user32.clone(), 5);
        assert_eq!((c.regions[0].findings[0].weight, c.regions[0].severity), (10, Severity::Info));
        assert!(c.regions[0].findings[0].reason.contains("5 bajtów") && c.regions[0].findings[0].reason.contains("0x7ff01000"), "{}", c.regions[0].findings[0].reason);
        assert_eq!(cmp(code.clone(), 5).regions[0].findings[0].weight, 40);
        // kontrola: porównanie z plikiem o potwierdzonej tożsamości nie wykazało różnic, więc znaleziska nie ma
        assert!(tags(&cmp(user32.clone(), 0)).is_empty());
        // zgodność z plikiem, którego tożsamości nie potwierdzono, nie wygasza znaleziska (plik mógł zostać podmieniony)
        let u = cmp_as(user32, 0, false);
        assert_eq!((tags(&u), u.regions[0].findings[0].weight), (vec!["IMG-MOD".to_string()], 10));
        assert!(u.regions[0].findings[0].reason.contains("tożsamości pliku nie potwierdzono"), "{}", u.regions[0].findings[0].reason);
        assert_eq!(cmp_as(code.clone(), 0, false).regions[0].findings[0].weight, 10, "także dla modułu ochronnego: różnicy nie stwierdzono");
        // kontrole: brak zmian, zero bajtów, dane (bez prawa wykonania), kod zapisywalny (to domena RWX), pamięć bez pliku
        assert!(tags(&scan(code.clone(), vec![])).is_empty());
        assert!(tags(&scan(code.clone(), vec![(0x7ff0_0000, 0)])).is_empty());
        assert!(tags(&scan(Region { prot: Prot::parse("r--"), ..code.clone() }, vec![(0x7ff0_0000, 4096)])).is_empty());
        assert!(!tags(&scan(Region { prot: Prot::parse("rwx"), ..code.clone() }, vec![(0x7ff0_0000, 4096)])).contains(&"IMG-MOD".to_string()));
        assert!(!tags(&scan(Region { backing: None, kind: RegionKind::Private, ..code }, vec![(0x7ff0_0000, 4096)])).contains(&"IMG-MOD".to_string()));
    }

    #[test]
    fn region_limit_keeps_findings_and_marks_result_incomplete() {
        let mk = || Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: (0..5u64).map(|i|
            (reg(0x10000 + i * 0x10000, 8192, "rwx", RegionKind::Private, None), vec![0x90u8; 8192])).collect() };
        let cut = scan_source(&mk(), &Config { max_regions: 3, ..Config::default() });
        assert_eq!(cut.regions.len(), 3, "znaleziska z regionów przed limitem zostają");
        assert!(cut.error.as_deref().unwrap_or("").contains("obcięta do limitu 3"));
        // kontrola: poniżej limitu wynik jest pełny i bez błędu
        let full = scan_source(&mk(), &Config { max_regions: 6, ..Config::default() });
        assert_eq!((full.regions.len(), full.error.is_none()), (5, true));
    }

    #[test]
    fn unreadable_region_does_not_allocate_its_full_size() {
        struct Dead;
        impl MemorySource for Dead {
            fn info(&self) -> SourceInfo { SourceInfo { os: "linux".into(), arch: "x86_64".into(), pid: Some(1), name: None, source_type: "live".into(), exe: None, exe_deleted: false, exe_verified: false } }
            fn regions(&self) -> Result<Vec<Region>> { Ok(vec![]) }
            fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize> { Err(Error::Access("x".into())) }
        }
        let big = reg(0x10000, 64 << 20, "r--", RegionKind::Private, None);
        let buf = read_region(&Dead, &big, 64 << 20);
        assert!(buf.is_empty() && buf.capacity() <= 1 << 20, "pojemność {}", buf.capacity());
    }

    #[test]
    fn jit_allowlist_lowers_but_shows() {
        let mk = |name, exe, exe_deleted| Fake { name, exe, exe_deleted, exe_verified: true, regs: vec![(reg(0x10000, 8192, "rwx", RegionKind::Private, None), vec![0x90; 8192])] };
        let cfg = Config::default();
        let jit = scan_source(&mk("node", Some("/usr/bin/node"), false), &cfg);
        assert_eq!(jit.regions[0].score, 20);
        assert_eq!(jit.regions[0].allowlisted.as_deref(), Some("jit:node"), "stały token, bez ścieżki z badanego systemu");
        // właściwa ścieżka, ale plik niepotwierdzony przez backend (np. /usr z kontenera)
        let mut unverified = mk("node", Some("/usr/bin/node"), false);
        unverified.exe_verified = false;
        assert_eq!(scan_source(&unverified, &cfg).regions[0].score, 60);
        assert_eq!(jit.regions[0].findings.len(), 2, "znaleziska pozostają widoczne");
        // sama nazwa procesu niczego nie obniża: proces może nazwać się dowolnie
        for (name, exe, deleted) in [
            ("node", None, false),                         // nieznany plik programu
            ("node", Some("/tmp/evil"), false),            // nazwa podszyta, inny plik
            ("node", Some("/tmp/node"), false),            // właściwa nazwa pliku, zły katalog
            ("node", Some("/usr/bin/node"), true),         // plik usunięty z dysku
            ("node", Some("/usr/../tmp/node"), false),
            ("evil", Some("/usr/bin/evil"), false),
        ] {
            let p = scan_source(&mk(name, exe, deleted), &cfg);
            assert_eq!((p.regions[0].score, p.regions[0].allowlisted.clone()), (60, None), "{name} {exe:?} {deleted}");
        }
    }

    #[test]
    fn ent_x_in_file_backed_code_needs_large_share() {
        let cfg = Config::default();
        let file = |hot: usize| {
            // 40 stron kodu, z czego `hot` o wysokiej entropii
            let mut d = vec![0x90u8; 40 * 4096];
            d[..hot * 4096].copy_from_slice(&noise(hot * 4096));
            Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x10000, 40 * 4096, "r-x", RegionKind::Mapped, Some("/usr/lib/libc.so.6")), d)] }
        };
        let few = scan_source(&file(3), &cfg);
        assert_eq!((few.regions[0].score, few.regions[0].severity), (10, Severity::Info), "tablice stałych w .text to nie alarm");
        let many = scan_source(&file(20), &cfg);
        assert_eq!((many.regions[0].score, many.regions[0].severity), (30, Severity::Suspicious), "obraz spakowany");
        // ten sam układ bez zwykłego pliku: pełna waga już od jednej strony
        let mut del = file(3); del.regs[0].0.backing_deleted = true;
        assert!(scan_source(&del, &cfg).regions[0].findings.iter().any(|f| f.tag == "ENT-X" && f.weight == 30));
    }

    #[test]
    fn guarded_exec_region_is_flagged_and_counted_unreadable() {
        let mk = |prot, label: Option<&str>| {
            let mut r = reg(0x10000, 4096, prot, RegionKind::Private, None);
            r.label = label.map(String::from); r.readable = label.is_none();
            // dane z nagłówkiem PE: gdyby skaner czytał region strażnika, odpaliłby HDR
            let mut d = vec![0u8; 4096]; d[..2].copy_from_slice(b"MZ"); d[0x3c] = 0x80; d[0x80..0x84].copy_from_slice(b"PE\0\0"); d[0x80 + 4] = 0x64; d[0x80 + 5] = 0x86; d[0x80 + 6] = 1;
            Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(r, d)] }
        };
        let p = scan_source(&mk("r-x", Some(GUARD_LABEL)), &Config::default());
        assert_eq!(tags(&p), ["X-PRIV", "GUARD-X"]);
        assert_eq!((p.regions_unreadable, p.bytes_scanned, p.regions[0].score), (1, 0, 60));
        // kontrole: ten sam region bez strażnika jest czytany; strażnik bez X (stos) nie jest znaleziskiem
        let p = scan_source(&mk("r-x", None), &Config::default());
        assert_eq!((tags(&p), p.regions_unreadable), (vec!["X-PRIV".to_string(), "HDR".to_string()], 0));
        let p = scan_source(&mk("rw-", Some(GUARD_LABEL)), &Config::default());
        assert!(tags(&p).is_empty());
        assert_eq!(p.regions_unreadable, 0);
    }

    #[test]
    fn unreadable_region_is_counted_and_scan_continues() {
        let f = Fake { name: "x", exe: None, exe_deleted: false, exe_verified: false, regs: vec![
            (reg(0x50000, 4096, "r--", RegionKind::Private, None), vec![]), // odczyt się nie powiedzie
            (reg(0x60000, 4096, "rwx", RegionKind::Private, None), vec![0x90; 4096]),
        ]};
        let p = scan_source(&f, &Config::default());
        assert_eq!(p.regions_unreadable, 1);
        assert_eq!(p.regions.len(), 1);
    }

    #[test]
    fn deterministic_and_no_bytes() {
        let f = Fake { name: "evil", exe: None, exe_deleted: false, exe_verified: false, regs: vec![(reg(0x10000, 8192, "rwx", RegionKind::Private, None), noise(8192))] };
        let mut cfg = Config::default();
        assert_eq!(scan_source(&f, &cfg), scan_source(&f, &cfg));
        cfg.preview_bytes = 0;
        assert!(scan_source(&f, &cfg).regions[0].findings.iter().all(|f| f.bytes_hex.is_none()));
    }
    /// Strojenie z pomiaru na 20 hostach Linux: każda reguła ma kontrole, w których pełna waga zostaje.
    #[test]
    fn lab_tuning_lowers_only_the_measured_benign_classes() {
        let cfg = Config::default();
        let weights = |f: &Fake, tag: &str| -> Vec<u32> { scan_source(f, &cfg).regions.iter().flat_map(|r| r.findings.iter().filter(|x| x.tag == tag).map(|x| x.weight)).collect() };
        let fake = |exe: &'static str, verified: bool, regs: Vec<(Region, Vec<u8>)>| Fake { name: "p", exe: Some(exe), exe_deleted: false, exe_verified: verified, regs };
        let code = vec![0x90u8; 8192];

        // 1. usunięty plik z katalogu pakietów: informacja o potrzebie restartu, nie "podejrzane"
        let del = |path: &'static str| { let mut r = reg(0x10000, 8192, "r-x", RegionKind::Mapped, Some(path)); r.backing_deleted = true; fake("/usr/sbin/sshd", true, vec![(r, code.clone())]) };
        assert_eq!(weights(&del("/usr/lib64/libssl.so.3.2.2"), "DEL-EXEC"), [10]);
        for other in ["/tmp/x.so", "/home/u/.cache/x.so", "/dev/shm/x", "/usr/../tmp/x.so", "/var/lib/app/x.so"] { assert_eq!(weights(&del(other), "DEL-EXEC"), [30], "{other}"); }
        // proces bez potwierdzonego pliku programu (np. z kontenera z własnym /usr): pełna waga
        let mut unverified = del("/usr/lib64/libssl.so.3.2.2"); unverified.exe_verified = false;
        assert_eq!(weights(&unverified, "DEL-EXEC"), [30]);

        // 2. memfd o nazwie libffi w procesie, który ma zmapowaną libffi: niska waga
        let ffi = |exe: &'static str, verified: bool, lib: Option<&'static str>, memfd: &'static str| {
            let mut m = reg(0x30000, 8192, "r-x", RegionKind::Mapped, Some(memfd)); m.backing_deleted = true;
            let mut regs = vec![(m, code.clone())];
            if let Some(l) = lib { regs.push((reg(0x50000, 8192, "r-x", RegionKind::Mapped, Some(l)), code.clone())); }
            fake(exe, verified, regs)
        };
        assert_eq!(weights(&ffi("/usr/bin/python3.11", true, Some("/usr/lib64/libffi.so.8.1.2"), "memfd:libffi"), "MEMFD"), [10]);
        assert_eq!(weights(&ffi("/usr/bin/python3.11", true, Some("/usr/lib64/libffi.so.8.1.2"), "memfd:payload"), "MEMFD"), [40], "inna nazwa mapowania");
        // ta sama nazwa, ale region nie wygląda jak tablica skoków libffi: duży, zapisywalny albo o wysokiej entropii
        let ffi_shape = |size: usize, prot: &'static str, noisy: bool| {
            let mut m = reg(0x30000, size as u64, prot, RegionKind::Mapped, Some("memfd:libffi")); m.backing_deleted = true;
            let data: Vec<u8> = if noisy { (0..size).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(13) as u8 ^ (i >> 3) as u8).collect() } else { vec![0x90u8; size] };
            fake("/usr/bin/python3.11", true, vec![(m, data), (reg(0x5000000, 8192, "r-x", RegionKind::Mapped, Some("/usr/lib64/libffi.so.8.1.2")), code.clone())])
        };
        assert_eq!(weights(&ffi_shape(4096, "r-x", false), "MEMFD"), [10]);
        assert_eq!(weights(&ffi_shape(1 << 20, "r-x", false), "MEMFD"), [40], "duży region");
        assert_eq!(weights(&ffi_shape(4096, "rwx", false), "MEMFD"), [40], "zapisywalny");
        assert_eq!(weights(&ffi_shape(4096, "r-x", true), "MEMFD"), [40], "wysoka entropia");
        // region nieprzeczytany (tylko wykonywalny) albo przeczytany częściowo: brak danych to nie "niska entropia"
        let unread = |prot: &'static str, have: usize| {
            let mut m = reg(0x30000, 8192, prot, RegionKind::Mapped, Some("memfd:libffi")); m.backing_deleted = true;
            fake("/usr/bin/python3.11", true, vec![(m, vec![0x90u8; have]), (reg(0x5000000, 8192, "r-x", RegionKind::Mapped, Some("/usr/lib64/libffi.so.8.1.2")), code.clone())])
        };
        assert_eq!(weights(&unread("--x", 0), "MEMFD"), [40], "bez prawa odczytu");
        assert_eq!(weights(&unread("r-x", 4096), "MEMFD"), [40], "odczyt częściowy");
        assert_eq!(weights(&unread("r-x", 8192), "MEMFD"), [10], "kontrola: odczyt pełny");
        assert_eq!(weights(&ffi("/usr/bin/python3.11", true, None, "memfd:libffi"), "MEMFD"), [40], "proces bez libffi");
        assert_eq!(weights(&ffi("/usr/bin/python3.11", true, Some("/tmp/libffi.so.8"), "memfd:libffi"), "MEMFD"), [40], "libffi spoza katalogu systemowego");
        assert_eq!(weights(&ffi("/usr/bin/python3.11", false, Some("/usr/lib64/libffi.so.8.1.2"), "memfd:libffi"), "MEMFD"), [40], "niepotwierdzony plik programu");
        assert_eq!(weights(&ffi("/home/u/python3.11", true, Some("/usr/lib64/libffi.so.8.1.2"), "memfd:libffi"), "MEMFD"), [40], "program spoza katalogów systemowych");

        // 3. nagłówek programu w dużym regionie danych procesu QEMU: pamięć maszyny wirtualnej
        let guest = |exe: &'static str, size: usize, prot: &'static str| {
            let mut d = vec![0u8; size];
            for at in [0usize, 4096 * 3] { if at + 64 <= size { d[at..at + 4].copy_from_slice(b"\x7fELF"); d[at + 4] = 2; d[at + 5] = 1; d[at + 6] = 1; d[at + 16] = 3; } }
            fake(exe, true, vec![(reg(0x7f00_0000_0000, size as u64, prot, RegionKind::Private, None), d)])
        };
        assert_eq!(weights(&guest("/usr/libexec/qemu-kvm", 16 << 20, "rw-"), "HDR"), [10], "jeden wpis na region o niskiej wadze");
        assert_eq!(weights(&guest("/usr/bin/qemu-system-x86_64", 16 << 20, "rw-"), "HDR"), [10]);
        assert_eq!(weights(&guest("/usr/sbin/sshd", 16 << 20, "rw-"), "HDR"), [40, 40], "zwykły proces");
        assert_eq!(weights(&guest("/usr/bin/qemu-img", 16 << 20, "rw-"), "HDR"), [40, 40], "narzędzie QEMU, które nie jest hiperwizorem");
        assert_eq!(weights(&guest("/usr/libexec/qemu-kvm", 16384, "rw-"), "HDR"), [40, 40], "mały region w procesie hiperwizora");
        assert_eq!(weights(&guest("/usr/libexec/qemu-kvm", 16 << 20, "r-x"), "HDR"), [40, 40], "region wykonywalny w procesie hiperwizora");

        // 3b. odczyt z hiperwizora: nagłówek w regionie niewykonywalnym liczy się tylko przy znanym rodzaju "prywatny"
        struct Vm(Fake, RegionKind);
        impl MemorySource for Vm {
            fn info(&self) -> SourceInfo { SourceInfo { os: "windows".into(), source_type: "vm".into(), ..self.0.info() } }
            fn regions(&self) -> nanshe_core::Result<Vec<Region>> { self.0.regions().map(|v| v.into_iter().map(|mut r| { r.kind = self.1; r }).collect()) }
            fn read_at(&self, a: u64, b: &mut [u8]) -> nanshe_core::Result<usize> { self.0.read_at(a, b) }
        }
        let vm_hdr = |prot: &'static str, kind: RegionKind| -> usize { scan_source(&Vm(guest("/usr/sbin/sshd", 16384, prot), kind), &cfg).regions.iter().flat_map(|r| &r.findings).filter(|x| x.tag == "HDR").count() };
        assert_eq!((vm_hdr("rw-", RegionKind::Unknown), vm_hdr("rw-", RegionKind::Mapped), vm_hdr("rw-", RegionKind::Private), vm_hdr("r-x", RegionKind::Unknown)), (0, 0, 2, 2));

        // 4. interpretery i programy z własną kompilacją w locie: obniżka także dla nazw z numerem wersji
        let rwx = |exe: &'static str, verified: bool| scan_source(&fake(exe, verified, vec![(reg(0x10000, 8192, "rwx", RegionKind::Private, None), code.clone())]), &cfg);
        for exe in ["/usr/bin/python3.14", "/usr/sbin/php-fpm8.2", "/usr/sbin/apache2", "/usr/bin/gnome-shell"] {
            let p = rwx(exe, true);
            assert!(p.regions[0].allowlisted.is_some() && p.regions[0].score == 20, "{exe}: {:?} {}", p.regions[0].allowlisted, p.regions[0].score);
        }
        assert_eq!(rwx("/usr/bin/python3.14", true).regions[0].allowlisted.as_deref(), Some("jit:python"));
        for (exe, verified) in [("/usr/bin/python3.14", false), ("/usr/bin/pythonista", true), ("/home/u/python3.14", true), ("/usr/bin/3.14", true)] {
            let p = rwx(exe, verified);
            assert!(p.regions[0].allowlisted.is_none() && p.regions[0].score == 60, "{exe} {verified}");
        }
    }

    /// Detektor wzorców shellcode'u: każda klasa osobno, zasady wagi i kontrole, w których nie ma znaleziska.
    #[test]
    fn shellcode_patterns_are_found_only_in_code_without_a_plain_file() {
        use crate::detectors::{shc_arm64, shc_x86, ShcClass};
        let pad = |code: &[u8]| { let mut d = vec![0x90u8; 4096]; d[64..64 + code.len()].copy_from_slice(code); d };
        let classes = |code: &[u8]| -> Vec<ShcClass> { shc_x86(&pad(code)).into_iter().map(|h| h.0).collect() };
        assert_eq!(classes(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0]), [ShcClass::Peb]);                 // mov rax, gs:[0x60]
        assert_eq!(classes(&[0x64, 0xa1, 0x30, 0, 0, 0]), [ShcClass::Peb]);                                   // mov eax, fs:[0x30]
        assert_eq!(classes(&[0x64, 0x8b, 0x15, 0x30, 0, 0, 0]), [ShcClass::Peb]);                             // mov edx, fs:[0x30]
        assert_eq!(classes(&[0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1]), [ShcClass::ApiHash]); // pętla block_api
        assert_eq!(classes(&[0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0, 0, 0, 0x0f, 0x05, 0xc3]), [ShcClass::SyscallStub]);
        assert_eq!(classes(&[0xe8, 0, 0, 0, 0, 0x5b]), [ShcClass::GetPc]);
        assert_eq!(classes(&[0xd9, 0xee, 0xd9, 0x74, 0x24, 0xf4, 0x5b]), [ShcClass::GetPc]);
        assert_eq!(classes(&[0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0, 0, 0]), [ShcClass::StagerPrologue]);
        assert_eq!(classes(&[0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x0f, 0x05]), [ShcClass::Execve]);
        // kontrole: sama instrukcja ror 13 bez pętli, odczyt TEB (gs:[0x30]), mov eax bez syscall, zwykły call, nic
        for benign in [&[0xc1u8, 0xc9, 0x0d][..], &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0], &[0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0, 0, 0, 0xc3], &[0xe8, 0x10, 0, 0, 0, 0x5b], &[0x6a, 0x3b, 0x58, 0xc3], &[]] {
            assert_eq!(classes(benign), [], "{benign:x?}");
        }
        // arm64: svc tylko jako wyrównana instrukcja
        // arm64: svc liczy się tylko z ustawieniem numeru wywołania tuż przed nim (mov x16 na macOS, mov x8 na Linuksie)
        let mac = [0x30u8, 0x00, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4];   // mov x16, #1; svc #0x80
        let lin = [0xa8u8, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4];   // mov x8, #221; svc #0
        assert_eq!((shc_arm64(&mac), shc_arm64(&lin)), (vec![(ShcClass::Svc, 4)], vec![(ShcClass::Svc, 4)]));
        // kontrole: samo svc (przypadkowe cztery bajty w kodzie JIT), numer w innym rejestrze, svc niewyrównane
        assert_eq!(shc_arm64(&[0x1f, 0x20, 0x03, 0xd5, 0x01, 0x10, 0x00, 0xd4]), []);
        assert_eq!(shc_arm64(&[0x28, 0x00, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4]), []);
        assert_eq!(shc_arm64(&[0x00, 0x30, 0x00, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4, 0x00, 0x00, 0x00]), []);

        let cfg = Config::default();
        let run = |arch: &'static str, prot: &'static str, backing: Option<&'static str>, deleted: bool, code: &[u8]| -> Vec<u32> {
            struct A(Fake, &'static str);
            impl MemorySource for A {
                fn info(&self) -> SourceInfo { SourceInfo { arch: self.1.into(), ..self.0.info() } }
                fn regions(&self) -> nanshe_core::Result<Vec<Region>> { self.0.regions() }
                fn read_at(&self, a: u64, b: &mut [u8]) -> nanshe_core::Result<usize> { self.0.read_at(a, b) }
            }
            let mut r = reg(0x10000, 4096, prot, if backing.is_some() { RegionKind::Mapped } else { RegionKind::Private }, backing); r.backing_deleted = deleted;
            let f = Fake { name: "p", exe: Some("/usr/bin/p"), exe_deleted: false, exe_verified: true, regs: vec![(r, pad(code))] };
            scan_source(&A(f, arch), &cfg).regions.iter().flat_map(|r| r.findings.iter().filter(|x| x.tag == "SHC").map(|x| x.weight)).collect()
        };
        let peb = [0x65u8, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0];
        let two: Vec<u8> = [&peb[..], &[0xe8, 0, 0, 0, 0, 0x5b][..]].concat();
        let stager = [0xfcu8, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0, 0, 0];
        assert_eq!(run("x86_64", "r-x", None, false, &peb), [20], "pojedyncza słabsza klasa");
        assert_eq!(run("x86_64", "r-x", None, false, &two), [40], "dwie klasy");
        assert_eq!(run("x86_64", "rwx", None, false, &stager), [40], "mocna klasa");
        assert_eq!(run("x86_64", "r-x", Some("memfd:x"), true, &two), [40], "plik tylko w pamięci");
        // kontrole: kod z pliku na dysku (także usuniętego: zaktualizowana biblioteka), region niewykonywalny, inna architektura
        assert_eq!(run("x86_64", "r-x", Some("/usr/lib/x.so"), true, &two), []);
        assert_eq!(run("x86_64", "r-x", Some("/usr/lib/x.so"), false, &two), []);
        assert_eq!(run("x86_64", "rw-", None, false, &two), []);
        assert_eq!(run("aarch64", "r-x", None, false, &two), []);
        assert_eq!(run("aarch64", "r-x", None, false, &[0xa8, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4]), [20]);
        // piaskownica Chromium kopiuje wejścia do jądra do własnej pamięci: w procesie rozpoznanym jako przeglądarka
        // sama taka kopia ma wagę 10; razem z inną klasą albo w zwykłym procesie zostaje pełna waga
        let stub = [0x4cu8, 0x8b, 0xd1, 0xb8, 0x18, 0, 0, 0, 0x0f, 0x05, 0xc3];
        let stub_and_peb: Vec<u8> = [&stub[..], &peb[..]].concat();
        let browser = |exe: &'static str, code: &[u8]| -> Vec<u32> {
            let r = reg(0x10000, 4096, "r-x", RegionKind::Private, None);
            let f = Fake { name: "p", exe: Some(exe), exe_deleted: false, exe_verified: true, regs: vec![(r, pad(code))] };
            scan_source(&f, &cfg).regions.iter().flat_map(|r| r.findings.iter().filter(|x| x.tag == "SHC").map(|x| x.weight)).collect()
        };
        assert_eq!(browser("/usr/bin/chromium", &stub), [10]);
        // ten sam kod w regionie zapisywalnym albo dużym nie wygląda jak piaskownica: pełna waga także w przeglądarce
        let shaped = |prot: &'static str, size: usize| -> Vec<u32> {
            let mut d = vec![0x90u8; size]; d[64..64 + stub.len()].copy_from_slice(&stub);
            let f = Fake { name: "p", exe: Some("/usr/bin/chromium"), exe_deleted: false, exe_verified: true, regs: vec![(reg(0x10000, size as u64, prot, RegionKind::Private, None), d)] };
            scan_source(&f, &cfg).regions.iter().flat_map(|r| r.findings.iter().filter(|x| x.tag == "SHC").map(|x| x.weight)).collect()
        };
        assert_eq!((shaped("rwx", 4096), shaped("r-x", 1 << 20)), (vec![20], vec![20]));
        assert_eq!(browser("/usr/bin/chromium", &stub_and_peb), [40]);
        assert_eq!(browser("/usr/bin/sshd", &stub), [20]);
        assert_eq!(browser("/usr/bin/java", &stub), [20], "środowisko JIT, które nie jest przeglądarką");
    }

}
