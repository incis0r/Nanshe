//! `nanshe` - triage pamięci. Kody wyjścia: 0 brak znalezisk powyżej progu,
//! 1 znaleziska, 2 błąd, 3 wynik częściowy bez znalezisk powyżej progu.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "llm")]
mod explain;

#[derive(Parser)]
#[command(name = "nanshe", version, about = "Triage pamięci: wskazuje regiony, którym powinien przyjrzeć się człowiek")]
struct Cli {
    /// Język raportu i opisów w wyniku skanu: pl albo en. Bez opcji: skan po polsku, raport w języku skanu
    #[arg(long, global = true, env = "NANSHE_LANG", value_parser = ["pl", "en"])] lang: Option<String>,
    #[command(subcommand)] cmd: Option<Cmd>,
}

/// Język wybrany jawnie (opcja --lang albo zmienna NANSHE_LANG); None, gdy nie wybrano.
static LANG_CHOICE: std::sync::OnceLock<Option<lang::Lang>> = std::sync::OnceLock::new();
pub fn chosen_lang() -> Option<lang::Lang> { LANG_CHOICE.get().copied().flatten() }

#[derive(Clone, Copy, ValueEnum)]
enum Min { Info, Suspicious, High }
impl From<Min> for Severity {
    fn from(m: Min) -> Self { match m { Min::Info => Severity::Info, Min::Suspicious => Severity::Suspicious, Min::High => Severity::High } }
}

#[derive(Subcommand)]
enum Cmd {
    /// Interaktywna mapa pamięci (domyślnie wszystkie procesy, bez czytania bajtów)
    Map {
        #[arg(long, conflicts_with = "input")] pid: Option<u32>,
        /// Zapisana inwentaryzacja JSON (także na stacji bez backendu live)
        #[arg(long)] input: Option<PathBuf>,
        #[arg(long, default_value = "nanshe.memory.html")] output: PathBuf,
        /// Zapis metadanych do ponownego otwarcia
        #[arg(long)] json: Option<PathBuf>,
        /// Nie otwieraj przeglądarki
        #[arg(long)] no_open: bool,
    },
    /// Lista procesów
    Ps,
    /// Skan żywego procesu (--pid, --all) albo zrzutu pamięci procesu (plik core ELF, minidump Windows)
    Scan {
        /// Plik zrzutu pamięci procesu: core (Linux) albo minidump (Windows)
        #[arg(conflicts_with_all = ["pid", "all"])] dump: Option<PathBuf>,
        #[arg(long, conflicts_with = "all")] pid: Option<u32>,
        /// Wszystkie dostępne procesy
        #[arg(long)] all: bool,
        /// Zapis pełnego wyniku JSON do pliku ("-" = stdout)
        #[arg(long)] json: Option<PathBuf>,
        /// Dołącz mapę ciepła entropii wszystkich przeczytanych regionów
        #[arg(long)] heatmap: bool,
        /// Bez podglądu bajtów w wyniku (wynik może zawierać sekrety)
        #[arg(long)] no_bytes: bool,
        /// Próg znalezisk dla wydruku i kodu wyjścia
        #[arg(long, value_enum, default_value = "suspicious")] min: Min,
        /// Limit bajtów czytanych z jednego regionu (MiB)
        #[arg(long, default_value_t = 64)] max_region_mib: u64,
        /// Bez kontekstu systemowego (rodzice, wiersz poleceń, sieć, pliki) i pełnej mapy regionów
        #[arg(long)] no_context: bool,
        /// Bez skrótów SHA-256 plików programów i plików zmapowanych
        #[arg(long)] no_hashes: bool,
    },
    /// Skan procesów gościa Windows z hosta KVM/QEMU, bez agenta w gościu (wymaga builda z cechą "vm")
    Vm {
        /// Nazwa maszyny wirtualnej (jak w libvirt) albo PID procesu QEMU
        target: String,
        #[arg(long, conflicts_with = "all")] pid: Option<u32>,
        /// Wszystkie procesy gościa
        #[arg(long)] all: bool,
        /// Tylko lista procesów gościa
        #[arg(long, conflicts_with_all = ["pid", "all"])] ps: bool,
        /// Katalog z symbolami jądra gościa (układ: <plik.pdb>/<identyfikator>)
        #[arg(long)] symbols: Option<PathBuf>,
        /// Pozwól pobrać brakujące symbole jądra z serwera symboli Microsoftu
        #[arg(long)] fetch_symbols: bool,
        /// Zapis pełnego wyniku JSON do pliku ("-" = stdout)
        #[arg(long)] json: Option<PathBuf>,
        /// Bez podglądu bajtów w wyniku (wynik może zawierać sekrety)
        #[arg(long)] no_bytes: bool,
        /// Próg znalezisk dla wydruku i kodu wyjścia
        #[arg(long, value_enum, default_value = "suspicious")] min: Min,
        /// Limit bajtów czytanych z jednego regionu (MiB)
        #[arg(long, default_value_t = 64)] max_region_mib: u64,
    },
    /// Raport dla człowieka (Markdown i PDF) z wyniku skanu i, jeśli jest, interpretacji LLM
    Report {
        /// Wynik skanu (JSON)
        result: PathBuf,
        /// Interpretacja LLM; domyślnie <wynik>.llm.json, jeśli istnieje
        #[arg(long)] llm: Option<PathBuf>,
        /// Pomiń interpretację LLM, nawet gdy plik istnieje
        #[arg(long, conflicts_with = "llm")] no_llm: bool,
        /// Plik Markdown (domyślnie <wynik>.report.md)
        #[arg(long)] md: Option<PathBuf>,
        /// Plik PDF (domyślnie <wynik>.report.pdf)
        #[arg(long)] pdf: Option<PathBuf>,
        /// Minimalna waga regionów w raporcie
        #[arg(long, value_enum, default_value = "suspicious")] min: Min,
        /// Katalog z bazą wiedzy (common.json, <system>.json) zamiast wbudowanej
        #[arg(long, env = "NANSHE_KB_DIR")] kb: Option<PathBuf>,
    },
    /// Raport różnicowy (Markdown i PDF): co zmieniło się między dwoma skanami tej samej stacji
    Diff {
        /// Wcześniejszy wynik skanu (JSON)
        old: PathBuf,
        /// Późniejszy wynik skanu (JSON)
        new: PathBuf,
        /// Plik Markdown (domyślnie <późniejszy wynik>.diff.md)
        #[arg(long)] md: Option<PathBuf>,
        /// Plik PDF (domyślnie <późniejszy wynik>.diff.pdf)
        #[arg(long)] pdf: Option<PathBuf>,
        /// Minimalna waga porównywanych regionów
        #[arg(long, value_enum, default_value = "suspicious")] min: Min,
    },
    /// Obsługiwane formaty i źródła
    Formats,
    /// Interpretacja LLM gotowego wyniku (wymaga buildu z cechą `llm`)
    #[cfg(feature = "llm")]
    Explain(explain::ExplainArgs),
    /// Narzędzia warstwy LLM
    #[cfg(feature = "llm")]
    Llm { #[command(subcommand)] cmd: explain::LlmCmd },
    /// Dostawcy i modele chmurowe warstwy LLM
    #[cfg(feature = "llm")]
    Cloud { #[command(subcommand)] cmd: explain::CloudCmd },
}

/// Zapisuje raport .md i .pdf obok wyniku (albo pod wskazanymi ścieżkami).
/// Język: wybrany jawnie, a bez wyboru ten, w którym wykonano skan.
pub fn write_report(result: &std::path::Path, llm: Option<&std::path::Path>, md: Option<PathBuf>, pdf: Option<PathBuf>, min: Severity, kb: Option<&std::path::Path>) -> Result<()> {
    let raw = std::fs::read(result)?;
    let llm_v: Option<serde_json::Value> = match llm {
        Some(p) => Some(serde_json::from_slice(&std::fs::read(p)?).map_err(|e| Error::Invalid(format!("{}: {e}", p.display())))?),
        None => None,
    };
    let name = result.file_name().map(|n| n.to_string_lossy().into_owned());
    let (m, p) = nanshe_report::build_report_lang(&raw, llm_v.as_ref(), min, name, kb, chosen_lang())?;
    let md = md.unwrap_or_else(|| result.with_extension("report.md"));
    let pdf = pdf.unwrap_or_else(|| result.with_extension("report.pdf"));
    std::fs::write(&md, m)?;
    std::fs::write(&pdf, p)?;
    eprintln!("{}", trf!("raport: {} i {}{}", "report: {} and {}{}", md.display(), pdf.display(), if llm.is_some() { tr!(" (z interpretacją LLM)", " (with LLM interpretation)") } else { tr!(" (bez interpretacji LLM)", " (without LLM interpretation)") }));
    Ok(())
}

pub fn now_rfc3339() -> String {
    rfc3339(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64)
}

#[allow(clippy::too_many_arguments)]
fn scan(dump: Option<PathBuf>, pid: Option<u32>, all: bool, json: Option<PathBuf>, heatmap: bool, no_bytes: bool, min: Min, max_region_mib: u64, no_context: bool, no_hashes: bool) -> Result<ExitCode> {
    let mut cfg = nanshe_analyze::Config { heatmap, max_region_bytes: max_region_mib << 20, keep_layout: !no_context, ..Default::default() };
    if no_bytes { cfg.preview_bytes = 0; }
    if let Some(d) = dump {
        // Zrzut pamięci jednego procesu: te same detektory, bez kontekstu systemowego (zrzut go nie zawiera).
        let src = nanshe_dump::open(&d)?;
        let mut rep = nanshe_analyze::scan_source(&src, &cfg);
        let file = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut notes = vec![trf!("źródło: zrzut pamięci procesu ({file}); sieć, otwarte pliki i drzewo procesów nie są dostępne ze zrzutu, a obniżka wagi dla środowisk JIT nie jest stosowana, bo pliku programu nie da się sprawdzić",
            "source: process memory dump ({file}); network, open files and the process tree are not available from a dump, and the severity reduction for JIT runtimes is not applied because the program file cannot be verified")];
        notes.extend(src.notes.iter().cloned());
        rep.context = Some(ProcessContext { cmdline: src.cmdline.clone(), ppid: src.ppid, notes, ..Default::default() });
        let partial = rep.regions_unreadable > 0 || rep.error.is_some();
        let result = ScanResult {
            schema_version: SCHEMA_VERSION, tool_version: env!("CARGO_PKG_VERSION").into(), timestamp: now_rfc3339(),
            host: tr!("nieznany (analiza zrzutu)", "unknown (dump analysis)").into(), heat_cell_bytes: cfg.heat_cell, partial, processes: vec![rep],
            lang: Some(lang::get().code().to_string()), host_info: None, files: vec![],
        };
        return finish(&result, &json, min.into(), partial);
    }
    if let Some(w) = nanshe_live::prepare() { eprintln!("{}", trf!("nanshe: ostrzeżenie: {w}", "nanshe: warning: {w}")); }
    let me = std::process::id();
    let pids: Vec<u32> = match (pid, all) {
        (Some(p), _) => vec![p],
        (None, true) => nanshe_live::list_processes()?.into_iter().map(|p| p.pid).filter(|&p| p != me).collect(),
        _ => return Err(Error::Invalid(tr!("podaj --pid <PID> albo --all", "specify --pid <PID> or --all").into())),
    };
    let single = pid.is_some();
    // Kontekst systemowy tylko dla procesów ze znaleziskami od wagi "podejrzane": schodzimy
    // od pamięci do systemu, nie inwentaryzujemy całego hosta.
    let snapshot = (!no_context).then(nanshe_live::Snapshot::take);
    let mut hashes = (!no_hashes).then(nanshe_live::HashCache::default);
    let mut processes = Vec::new();
    let mut partial = false;
    for p in pids {
        match nanshe_live::open_process(p) {
            Ok(src) => {
                let mut rep = nanshe_analyze::scan_source(src.as_ref(), &cfg);
                if let Some(s) = snapshot.as_ref().filter(|_| rep.max_severity >= Severity::Suspicious) { rep.context = Some(s.context(p)); }
                if let Some(h) = hashes.as_mut() {
                    h.exe(p, rep.info.exe.as_deref());
                    if let Some(l) = &rep.layout { h.modules(p, l); }
                }
                if rep.regions_unreadable > 0 || rep.error.is_some() { partial = true; }
                processes.push(rep);
            }
            Err(e) if single => return Err(e),
            // proces zniknął w trakcie albo brak dostępu: wynik częściowy, skan idzie dalej (Z8)
            Err(Error::NotFound(_)) => {}
            Err(e) => {
                partial = true;
                processes.push(ProcessReport {
                    info: SourceInfo { os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into(), pid: Some(p), name: None, source_type: "live".into(), exe: None, exe_deleted: false, exe_verified: false },
                    regions_total: 0, regions_unreadable: 0, bytes_scanned: 0, max_severity: Severity::None, error: Some(e.to_string()), regions: vec![], layout: None, context: None,
                });
            }
        }
    }
    let result = ScanResult {
        schema_version: SCHEMA_VERSION, tool_version: env!("CARGO_PKG_VERSION").into(), timestamp: now_rfc3339(),
        host: nanshe_live::hostname(), heat_cell_bytes: cfg.heat_cell, partial, processes,
        lang: Some(lang::get().code().to_string()),
        host_info: snapshot.as_ref().map(|s| s.host()),
        files: hashes.map(|h| h.into_files()).unwrap_or_default(),
    };
    finish(&result, &json, min.into(), partial)
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
#[allow(clippy::too_many_arguments)]
fn vm(_target: String, _pid: Option<u32>, _all: bool, _ps: bool, _symbols: Option<PathBuf>, _fetch: bool, _json: Option<PathBuf>, _no_bytes: bool, _min: Min, _max_region_mib: u64) -> Result<ExitCode> {
    Err(Error::Unsupported(tr!("polecenie vm wymaga hosta Linux z KVM/QEMU i builda z cechą \"vm\"", "the vm command requires a Linux host with KVM/QEMU and a build with the \"vm\" feature").into()))
}

/// Skan procesów gościa Windows z hosta: te same detektory, pamięć czytana przez proces QEMU.
#[cfg(all(feature = "vm", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn vm(target: String, pid: Option<u32>, all: bool, ps: bool, symbols: Option<PathBuf>, fetch: bool, json: Option<PathBuf>, no_bytes: bool, min: Min, max_region_mib: u64) -> Result<ExitCode> {
    let guest = nanshe_vm::open(&target, nanshe_vm::Symbols { dir: symbols.as_deref(), fetch })?;
    let procs = guest.processes()?;
    if ps {
        for p in procs.iter().filter(|p| p.alive) { println!("{:>7}  {:<28} {}", p.pid, p.name, p.path); }
        return Ok(ExitCode::SUCCESS);
    }
    let pids: Vec<u32> = match (pid, all) {
        (Some(p), _) => vec![p],
        (None, true) => procs.iter().filter(|p| p.alive).map(|p| p.pid).collect(),
        _ => return Err(Error::Invalid(tr!("podaj --pid <PID>, --all albo --ps", "specify --pid <PID>, --all or --ps").into())),
    };
    let mut cfg = nanshe_analyze::Config { max_region_bytes: max_region_mib << 20, keep_layout: true, ..Default::default() };
    if no_bytes { cfg.preview_bytes = 0; }
    let mut processes = Vec::new();
    let mut partial = false;
    for p in pids {
        match guest.process(p) {
            Ok(src) => {
                let mut rep = nanshe_analyze::scan_source(&src, &cfg);
                if rep.max_severity >= Severity::Suspicious || !src.modules_known {
                    let mut notes = vec![if src.from_vad {
                        tr!("źródło: pamięć gościa czytana z hiperwizora. Granice, rodzaj i nazwy plików regionów pochodzą z drzewa VAD jądra gościa, a ochrona z tablic stron (tylko strony obecne w pamięci fizycznej); sieć, otwarte pliki i drzewo procesów nie są dostępne tą drogą. Obniżka wagi dla środowisk JIT jest stosowana tylko na podstawie obrazów z woluminu systemowego gościa.",
                            "source: guest memory read from the hypervisor. Region borders, types and file names come from the VAD tree of the guest kernel, protection from page tables (only pages present in physical memory); network, open files and the process tree are not available this way. The severity reduction for JIT runtimes is applied only on the evidence of images from the guest's system volume.").to_string()
                    } else {
                        tr!("źródło: pamięć gościa czytana z hiperwizora. Regiony pochodzą z tablic stron (tylko strony obecne w pamięci fizycznej), rodzaj regionu wynika z listy modułów procesu, która bywa niepełna (wtedy kod biblioteki wygląda jak pamięć prywatna); sieć, otwarte pliki i drzewo procesów nie są dostępne tą drogą, a obniżka wagi dla środowisk JIT nie jest stosowana.",
                            "source: guest memory read from the hypervisor. Regions come from page tables (only pages present in physical memory), the region type follows from the process module list, which can be incomplete (library code then looks like private memory); network, open files and the process tree are not available this way, and the severity reduction for JIT runtimes is not applied.").to_string()
                    }];
                    if !src.modules_known { notes.push(tr!("lista modułów procesu była nieczytelna (proces bez bloku środowiska, chroniony albo ze stronami poza pamięcią): rodzaj regionów jest nieznany, więc kod bez pliku nie jest w tym procesie wykrywany", "the process module list was unreadable (a process without an environment block, protected, or with pages out of memory): region types are unknown, so code without a file is not detected in this process").into()); }
                    rep.context = Some(ProcessContext { cmdline: Some(src.cmdline()).filter(|c| !c.is_empty()), notes, ..Default::default() });
                }
                if !src.tables_complete && rep.error.is_none() { rep.error = Some(tr!("tablice stron procesu przeczytane tylko częściowo; mapa regionów jest niepełna", "the process page tables were read only partially; the region map is incomplete").into()); }
                if rep.error.is_some() { partial = true; }
                processes.push(rep);
            }
            Err(e) if pid.is_some() => return Err(e),
            Err(Error::NotFound(_)) => {}
            Err(e) => {
                partial = true;
                let name = procs.iter().find(|x| x.pid == p).map(|x| x.name.clone());
                processes.push(ProcessReport {
                    info: SourceInfo { os: "windows".into(), arch: "x86_64".into(), pid: Some(p), name, source_type: "vm".into(), exe: None, exe_deleted: false, exe_verified: false },
                    regions_total: 0, regions_unreadable: 0, bytes_scanned: 0, max_severity: Severity::None, error: Some(e.to_string()), regions: vec![], layout: None, context: None,
                });
            }
        }
    }
    let result = ScanResult {
        schema_version: SCHEMA_VERSION, tool_version: env!("CARGO_PKG_VERSION").into(), timestamp: now_rfc3339(),
        host: trf!("{} (gość, odczyt z hiperwizora {})", "{} (guest, read from hypervisor {})", guest.target, nanshe_live::hostname()), heat_cell_bytes: cfg.heat_cell, partial, processes,
        lang: Some(lang::get().code().to_string()), host_info: None, files: vec![],
    };
    finish(&result, &json, min.into(), partial)
}

/// Zapis wyniku, wydruk i kod wyjścia: wspólne dla skanu na żywo i analizy zrzutu.
fn finish(result: &ScanResult, json: &Option<PathBuf>, min: Severity, partial: bool) -> Result<ExitCode> {
    match json {
        Some(p) if p.as_os_str() == "-" => println!("{}", nanshe_report::to_json(result)),
        Some(p) => { std::fs::write(p, nanshe_report::to_json(result))?; eprint!("{}", nanshe_report::to_text(result, min)); }
        None => print!("{}", nanshe_report::to_text(result, min)),
    }
    Ok(if result.max_severity() >= min { ExitCode::from(1) } else if partial { ExitCode::from(3) } else { ExitCode::SUCCESS })
}


fn memory_map(pid: Option<u32>, input: Option<PathBuf>, output: PathBuf, json: Option<PathBuf>, no_open: bool) -> Result<ExitCode> {
    if json.as_ref() == Some(&output) || input.as_ref() == Some(&output) || (input.is_some() && input == json) {
        return Err(Error::Invalid(tr!("pliki wejścia, HTML i JSON muszą mieć różne ścieżki", "the input, HTML and JSON files must have different paths").into()));
    }
    let inventory: MemoryInventory = if let Some(path) = input {
        serde_json::from_slice(&std::fs::read(path)?).map_err(|e| Error::Invalid(trf!("inwentaryzacja JSON: {e}", "inventory JSON: {e}")))?
    } else {
        let entries = if let Some(pid) = pid {
            vec![nanshe_live::ProcEntry { pid, name: String::new() }]
        } else { nanshe_live::list_processes()? };
        if let Some(w) = nanshe_live::prepare() { eprintln!("nanshe: {w}"); }
        let processes = entries.into_iter().map(nanshe_live::process_memory).collect();
        MemoryInventory { inventory_version: 1, timestamp: now_rfc3339(), host: nanshe_live::hostname(),
            os: std::env::consts::OS.into(), processes }
    };
    if inventory.inventory_version != 1 { return Err(Error::Unsupported(tr!("wersja inwentaryzacji inna niż 1", "inventory version other than 1").into())); }
    for p in &inventory.processes {
        for r in &p.regions {
            let base = r.base.strip_prefix("0x").and_then(|s| u64::from_str_radix(s, 16).ok());
            let size = r.size.parse::<u64>().ok().filter(|s| *s > 0);
            if base.zip(size).and_then(|(b,s)| b.checked_add(s)).is_none()
                || [&r.rss, &r.pss].iter().any(|v| v.as_ref().is_some_and(|v| v.parse::<u64>().is_err())) {
                return Err(Error::Invalid(trf!("nieprawidłowy adres lub licznik, PID {}", "invalid address or counter, PID {}", p.pid)));
            }
        }
    }
    std::fs::write(&output, nanshe_report::memory::render(&inventory))?;
    if let Some(path) = json {
        std::fs::write(path, serde_json::to_vec_pretty(&inventory).map_err(|e| Error::Invalid(e.to_string()))?)?;
    }
    let partial = inventory.processes.iter().any(|p| p.error.is_some() || !p.notes.is_empty());
    eprintln!("mapa: {} | procesów: {} | niedostępnych: {} | {}", output.display(), inventory.processes.len(),
        inventory.processes.iter().filter(|p| p.error.is_some()).count(), if partial { "sprawdź ograniczenia w raporcie" } else { "metadane zebrane" });
    if !no_open {
        let path = std::fs::canonicalize(&output)?;
        #[cfg(target_os = "macos")]
        let status = std::process::Command::new("open").arg(&path).status();
        #[cfg(target_os = "linux")]
        let status = std::process::Command::new("xdg-open").arg(&path).status();
        #[cfg(windows)]
        let status = std::process::Command::new("explorer.exe").arg(&path).status();
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        let status: std::io::Result<std::process::ExitStatus> = Err(std::io::Error::other("brak programu do otwarcia przeglądarki"));
        if !matches!(status, Ok(s) if s.success()) { eprintln!("otwórz zapisany plik HTML w przeglądarce: {}", path.display()); }
    }
    Ok(if partial { ExitCode::from(3) } else { ExitCode::SUCCESS })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let choice = cli.lang.as_deref().and_then(lang::Lang::parse);
    let _ = LANG_CHOICE.set(choice);
    if let Some(l) = choice { lang::set(l); }
    let r: Result<ExitCode> = match cli.cmd.unwrap_or(Cmd::Map {
        pid: None, input: None, output: PathBuf::from("nanshe.memory.html"), json: None, no_open: false,
    }) {
        Cmd::Map { pid, input, output, json, no_open } => memory_map(pid, input, output, json, no_open),
        Cmd::Ps => nanshe_live::list_processes().map(|l| {
            for p in l { println!("{:>8}  {}", p.pid, p.name); }
            ExitCode::SUCCESS
        }),
        Cmd::Vm { target, pid, all, ps, symbols, fetch_symbols, json, no_bytes, min, max_region_mib } => vm(target, pid, all, ps, symbols, fetch_symbols, json, no_bytes, min, max_region_mib),
        Cmd::Scan { dump, pid, all, json, heatmap, no_bytes, min, max_region_mib, no_context, no_hashes } => scan(dump, pid, all, json, heatmap, no_bytes, min, max_region_mib, no_context, no_hashes),
        Cmd::Report { result, llm, no_llm, md, pdf, min, kb } => {
            let llm = if no_llm { None } else { llm.or_else(|| Some(result.with_extension("llm.json")).filter(|p| p.exists())) };
            write_report(&result, llm.as_deref(), md, pdf, min.into(), kb.as_deref()).map(|_| ExitCode::SUCCESS)
        }
        Cmd::Diff { old, new, md, pdf, min } => (|| {
            let name = |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().into_owned());
            let (m, p) = nanshe_report::build_diff(&std::fs::read(&old)?, &std::fs::read(&new)?, min.into(), name(&old), name(&new), chosen_lang())?;
            let md = md.unwrap_or_else(|| new.with_extension("diff.md"));
            let pdf = pdf.unwrap_or_else(|| new.with_extension("diff.pdf"));
            std::fs::write(&md, m)?;
            std::fs::write(&pdf, p)?;
            eprintln!("{}", trf!("raport różnicowy: {} i {}", "differential report: {} and {}", md.display(), pdf.display()));
            Ok(ExitCode::SUCCESS)
        })(),
        Cmd::Formats => {
            println!("źródła żywe:   linux (/proc/<pid>/maps + mem), windows (VirtualQueryEx + ReadProcessMemory)\nzrzuty:        plik core ELF 64-bit (Linux), minidump (Windows)\nhiperwizor:    gość Windows x86_64 z hosta KVM/QEMU (nanshe vm; build z --features vm, tylko Linux)\nraport:        Markdown, PDF (nanshe report)\ndetektory:     RWX X-PRIV X-MAP GUARD-X MEMFD DEL-EXEC X-TMP ENT-X HDR THR-PRIV IMG-MOD\nwarstwa LLM:   {}",
                if cfg!(feature = "llm") { "wbudowana (ollama; chmura za --allow-cloud: nous, anthropic, google, openai)" } else { "niewbudowana (build z --features llm)" });
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(feature = "llm")]
        Cmd::Explain(a) => explain::run(a),
        #[cfg(feature = "llm")]
        Cmd::Llm { cmd } => explain::llm_cmd(cmd),
        #[cfg(feature = "llm")]
        Cmd::Cloud { cmd } => explain::cloud_cmd(cmd),
    };
    match r {
        Ok(c) => c,
        Err(e) => { eprintln!("nanshe: {e}"); ExitCode::from(2) }
    }
}
