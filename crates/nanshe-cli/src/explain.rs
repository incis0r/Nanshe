//! Komendy `nanshe explain`, `nanshe llm check` i `nanshe cloud list`.
use clap::{Args, Subcommand};
use nanshe_core::*;
use nanshe_llm::backend::{LlmBackend, ModelInfo, Ollama};
use nanshe_llm::cloud::{self, Cloud, Provider};
use nanshe_llm::context::DataLevel;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const OLLAMA_MODEL: &str = "gemma3:12b";

#[derive(Args)]
pub struct Conn {
    /// Backend modelu: ollama (lokalny, domyślny) albo dostawca chmurowy: nous, anthropic, google, openai
    #[arg(long = "llm", default_value = "ollama")] pub backend: String,
    /// Adres Ollamy (dotyczy tylko --llm ollama)
    #[arg(long, env = "NANSHE_OLLAMA_URL", default_value = "http://127.0.0.1:11434")] pub url: String,
    /// Model; domyślnie gemma3:12b dla Ollamy albo model domyślny dostawcy (nanshe cloud list providers)
    #[arg(long, env = "NANSHE_LLM_MODEL")] pub model: Option<String>,
    /// Plik z kluczem dostawcy chmurowego (sam klucz); inaczej zmienna środowiskowa dostawcy
    #[arg(long)] pub key_file: Option<PathBuf>,
    /// Dopuść czyste HTTP do adresu innego niż loopback (tylko w zaufanej sieci)
    #[arg(long)] pub insecure_llm: bool,
    /// Limit czasu jednego zapytania (s)
    #[arg(long, default_value_t = 300)] pub timeout: u64,
}

impl Conn {
    /// `None` = Ollama; błąd dla nieznanej nazwy.
    fn provider(&self) -> Result<Option<&'static Provider>> {
        if self.backend == "ollama" { return Ok(None); }
        cloud::provider(&self.backend).map(Some).ok_or_else(|| Error::Invalid(format!("--llm {}: nieznany backend (dostępne: ollama, {})",
            self.backend, cloud::PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", "))))
    }
    fn model(&self) -> Result<String> {
        if let Some(m) = &self.model { return Ok(m.clone()); }
        match self.provider()? {
            None => Ok(OLLAMA_MODEL.into()),
            Some(p) => p.default_model.map(String::from).ok_or_else(|| Error::Invalid(format!(
                "dostawca {} nie ma modelu domyślnego: podaj --model (lista: nanshe cloud list models --provider {})", p.id, p.id))),
        }
    }
    fn backend(&self) -> Result<Box<dyn LlmBackend>> {
        let timeout = Duration::from_secs(self.timeout);
        Ok(match self.provider()? {
            None => Box::new(Ollama::new(&self.url, &self.model()?, self.insecure_llm, timeout).map_err(Error::Invalid)?),
            Some(p) => Box::new(Cloud::new(p, &self.model()?, cloud::resolve_key(p, self.key_file.as_deref()).map_err(Error::Invalid)?, timeout)),
        })
    }
}

#[derive(Args)]
pub struct ExplainArgs {
    /// Wynik skanu (JSON)
    pub result: PathBuf,
    #[command(flatten)] pub conn: Conn,
    /// Zgoda na wysłanie danych poza własną infrastrukturę (wymagana dla backendów chmurowych)
    #[arg(long)] pub allow_cloud: bool,
    /// d0 = tylko metadane, d1 = + ciągi po filtrze sekretów i nazwy, d2 = + surowy hex.
    /// Domyślnie d1 dla Ollamy i d0 dla chmury; d2 nigdy nie idzie do chmury
    #[arg(long)] pub data_level: Option<String>,
    /// Minimalna waga regionu: suspicious | high | info
    #[arg(long, default_value = "suspicious")] pub min: String,
    /// Pokaż dokładnie, co zostałoby wysłane; niczego nie wysyła
    #[arg(long)] pub dry_run: bool,
    /// Plik wyjściowy (domyślnie <wynik>.llm.json)
    #[arg(long)] pub out: Option<PathBuf>,
    /// Zapisz pełną wymianę z modelem (zawiera dane z pamięci)
    #[arg(long)] pub llm_audit: Option<PathBuf>,
    #[arg(long)] pub cache_dir: Option<PathBuf>,
    #[arg(long)] pub no_cache: bool,
    /// Okno kontekstu; domyślnie 8192 dla Ollamy, dla chmury okno podane przez dostawcę
    #[arg(long)] pub num_ctx: Option<u32>,
    /// Limit tokenów odpowiedzi; domyślnie 900 dla Ollamy, 16000 dla chmury (modele rozumujące zużywają go także na rozumowanie)
    #[arg(long)] pub max_tokens: Option<u32>,
    #[arg(long, default_value_t = 60)] pub max_calls: usize,
    /// Ile regionów jednego procesu (od najwyższego wyniku) interpretować; 0 = wszystkie. Raport opisuje szczegółowo tyle samo
    #[arg(long, default_value_t = 6)] pub max_regions: usize,
    /// Tylko do oceny odporności: wyślij także ciągi wyglądające na instrukcje
    #[arg(long)] pub keep_suspect_strings: bool,
    /// Nie generuj raportu <wynik>.report.md i <wynik>.report.pdf
    #[arg(long)] pub no_report: bool,
}

#[derive(Subcommand)]
pub enum LlmCmd {
    /// Test łączności i modelu; nie wysyła żadnych danych ze skanu
    Check { #[command(flatten)] conn: Conn },
}

#[derive(Subcommand)]
pub enum CloudCmd {
    /// Wbudowani dostawcy i modele; nie wysyła żadnych danych ze skanu
    List { #[command(subcommand)] what: CloudList },
}

#[derive(Subcommand)]
pub enum CloudList {
    /// Dostawcy chmurowi: adres, zmienna z kluczem, model domyślny (bez połączenia sieciowego)
    Providers,
    /// Modele dostawcy (zapytanie do jego API; wymaga klucza)
    Models {
        /// Dostawca; bez tej opcji wszyscy, dla których jest klucz
        #[arg(long)] provider: Option<String>,
        /// Plik z kluczem (tylko razem z --provider)
        #[arg(long, requires = "provider")] key_file: Option<PathBuf>,
        /// Pokaż tylko modele, których identyfikator zawiera ten tekst
        #[arg(long)] filter: Option<String>,
        #[arg(long, default_value_t = 60)] timeout: u64,
    },
}

pub fn llm_cmd(cmd: LlmCmd) -> Result<ExitCode> {
    let LlmCmd::Check { conn } = cmd;
    let b = conn.backend()?;
    let i = b.info().map_err(Error::Access)?;
    let place = match conn.provider()? { None => conn.url.clone(), Some(p) => format!("{} - CHMURA", p.base_url) };
    println!("backend:  {} {} ({place})", i.backend, i.server_version.as_deref().unwrap_or(""));
    println!("model:    {}{}", i.model, i.digest.as_deref().map(|d| format!(" [{}]", &d[..d.len().min(12)])).unwrap_or_default());
    println!("kontekst: {} tokenów (maksimum modelu)", i.context_length.map(|c| c.to_string()).unwrap_or("?".into()));
    println!("próbkowanie: {}", if i.fixed_sampling { "temperatura 0" } else { "domyślne modelu (nie da się ustalić)" });
    Ok(ExitCode::SUCCESS)
}

pub fn cloud_cmd(cmd: CloudCmd) -> Result<ExitCode> {
    let CloudCmd::List { what } = cmd;
    match what {
        CloudList::Providers => {
            println!("{:<10} {:<10} {:<28} {:<26} {}", "DOSTAWCA", "API", "KLUCZ", "MODEL DOMYŚLNY", "ADRES");
            for p in cloud::PROVIDERS {
                let api = match p.api { cloud::Api::OpenAi => "openai", cloud::Api::Anthropic => "anthropic" };
                let key = cloud::key_source(p, None).map(|s| format!("jest ({s})")).unwrap_or_else(|| format!("brak ({})", p.key_env[0]));
                println!("{:<10} {:<10} {:<28} {:<26} {}", p.id, api, key, p.default_model.unwrap_or("- (podaj --model)"), p.base_url);
            }
            println!("\nKlucz: zmienna z kolumny KLUCZ, NANSHE_<DOSTAWCA>_KEY_FILE albo --key-file <plik>.\nUżycie: nanshe explain wynik.json --llm <dostawca> --allow-cloud [--model <id>]");
            Ok(ExitCode::SUCCESS)
        }
        CloudList::Models { provider, key_file, filter, timeout } => {
            let chosen: Vec<&'static Provider> = match &provider {
                Some(id) => vec![cloud::provider(id).ok_or_else(|| Error::Invalid(format!("nieznany dostawca: {id} (nanshe cloud list providers)")))?],
                None => cloud::PROVIDERS.iter().collect(),
            };
            let (mut shown, mut failed) = (0, false);
            for p in chosen {
                let key = match cloud::resolve_key(p, key_file.as_deref()) {
                    Ok(k) => k,
                    Err(e) if provider.is_some() => return Err(Error::Invalid(e)),
                    Err(_) => { eprintln!("{}: pominięty, brak klucza ({})", p.id, p.key_env[0]); continue; }
                };
                let list = match Cloud::new(p, "", key, Duration::from_secs(timeout)).list_models() {
                    Ok(l) => l,
                    Err(e) => { eprintln!("{}: {e}", p.id); failed = true; continue; }
                };
                let list: Vec<_> = list.into_iter().filter(|m| filter.as_ref().map(|f| m.id.to_lowercase().contains(&f.to_lowercase())).unwrap_or(true)).collect();
                println!("# {} ({} modeli{})", p.id, list.len(), filter.as_ref().map(|f| format!(", filtr \"{f}\"")).unwrap_or_default());
                println!("{:<48} {:>10} {:>18}  {}", "MODEL", "KONTEKST", "USD/1M wej.+wyj.", "UWAGI");
                for m in &list {
                    let price = m.price_per_mtok.map(|(i, o)| format!("{i}+{o}")).unwrap_or_else(|| "-".into());
                    let mut notes = Vec::new();
                    if p.default_model == Some(m.id.as_str()) { notes.push("domyślny"); }
                    if let Some(pr) = &m.params {
                        if !pr.iter().any(|x| x == "structured_outputs") { notes.push("bez wymuszania schematu"); }
                        if !pr.iter().any(|x| x == "temperature") { notes.push("bez ustalonej temperatury"); }
                    }
                    println!("{:<48} {:>10} {:>18}  {}", m.id, m.context_length.map(|c| c.to_string()).unwrap_or_else(|| "-".into()), price, notes.join(", "));
                }
                shown += 1;
            }
            Ok(if failed || shown == 0 { ExitCode::from(3) } else { ExitCode::SUCCESS })
        }
    }
}

fn parse_min(s: &str) -> Result<Severity> {
    match s { "info" => Ok(Severity::Info), "suspicious" => Ok(Severity::Suspicious), "high" => Ok(Severity::High),
        _ => Err(Error::Invalid(format!("--min: {s}"))) }
}

pub fn run(a: ExplainArgs) -> Result<ExitCode> {
    let raw = std::fs::read(&a.result)?;
    let scan = nanshe_report::from_json(std::str::from_utf8(&raw).map_err(|_| Error::Invalid("wynik nie jest UTF-8".into()))?)?;
    let provider = a.conn.provider()?;
    let is_cloud = provider.is_some();
    let level_s = a.data_level.clone().unwrap_or_else(|| if is_cloud { "d0" } else { "d1" }.into());
    let level = DataLevel::parse(&level_s).ok_or_else(|| Error::Invalid(format!("--data-level: {level_s}")))?;
    // Zasady chmury obowiązują także przy --dry-run: podgląd ma pokazywać tylko to, co wolno wysłać.
    if is_cloud { nanshe_llm::cloud_policy(level, a.allow_cloud || a.dry_run).map_err(Error::Invalid)?; }
    let cache_dir = if a.no_cache { None } else {
        a.cache_dir.clone().or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/nanshe/llm")))
    };
    let mut opts = nanshe_llm::Options { data_level: level, min_severity: parse_min(&a.min)?, lang: lang::get().code().to_string(), num_ctx: a.num_ctx.unwrap_or(8192),
        max_tokens: a.max_tokens.unwrap_or(if is_cloud { 16000 } else { 900 }), max_calls: a.max_calls, max_regions: a.max_regions, cache_dir, dry_run: a.dry_run,
        keep_suspect: a.keep_suspect_strings, audit: a.llm_audit.is_some(), cloud: is_cloud };
    let sha = nanshe_llm::sha256_hex(&raw);

    if a.dry_run {
        // bez żadnego połączenia sieciowego i bez czytania klucza
        struct Never;
        impl LlmBackend for Never {
            fn info(&self) -> std::result::Result<ModelInfo, String> { Err("dry-run".into()) }
            fn complete(&self, _: &nanshe_llm::backend::Request) -> std::result::Result<nanshe_llm::backend::Response, String> { Err("dry-run".into()) }
        }
        let mi = ModelInfo { backend: "dry-run".into(), model: a.conn.model().unwrap_or_else(|_| "?".into()), digest: None, context_length: None, server_version: None, fixed_sampling: false };
        let o = nanshe_llm::explain(&scan, &sha, &Never, &mi, &opts, &crate::now_rfc3339());
        println!("{}", serde_json::to_string_pretty(&o.payloads).expect("json"));
        eprintln!("dry-run: {} zapytań zostałoby wysłanych do {} (poziom danych {}{}); nic nie wysłano", o.payloads.len(),
            provider.map(|p| format!("{} - CHMURA", p.id)).unwrap_or_else(|| "ollama".into()), level.as_str(),
            if is_cloud { ", po pseudonimizacji" } else { "" });
        return Ok(ExitCode::SUCCESS);
    }

    let b = a.conn.backend()?;
    let mi = b.info().map_err(Error::Access)?;
    match (a.num_ctx, mi.context_length) {
        (Some(n), Some(c)) if (n as u64) > c => return Err(Error::Invalid(format!("--num-ctx {n} przekracza okno modelu ({c})"))),
        // chmura: okno podane przez dostawcę (zapas ostrożności: nie więcej niż 200 tys.)
        (None, c) if is_cloud => opts.num_ctx = c.unwrap_or(64_000).min(200_000) as u32,
        _ => {}
    }
    if let Some(p) = provider {
        eprintln!("UWAGA: dane ze skanu (poziom {}, po pseudonimizacji) idą poza własną infrastrukturę do {} ({}), model {}", level.as_str(), p.id, p.base_url, mi.model);
    }
    let o = nanshe_llm::explain(&scan, &sha, b.as_ref(), &mi, &opts, &crate::now_rfc3339());
    let out = a.out.clone().unwrap_or_else(|| a.result.with_extension("llm.json"));
    std::fs::write(&out, serde_json::to_string_pretty(&o.result).expect("json"))?;
    if let Some(p) = &a.llm_audit { std::fs::write(p, serde_json::to_string_pretty(&o.audit).expect("json"))?; }

    println!("== {} ==", nanshe_llm::NOTICE);
    let h = &o.result["header"];
    println!("model {} | poziom danych {} | zapytań {} | z pamięci podręcznej {} | tokeny {}+{}",
        h["model"].as_str().unwrap_or("?"), level.as_str(), h["usage"]["calls"], h["usage"]["cache_hits"], h["usage"]["prompt_tokens"], h["usage"]["output_tokens"]);
    let mut not_ok = 0;
    for p in o.result["processes"].as_array().into_iter().flatten() {
        println!("\n[{}] {}", p["pid"], p["name"].as_str().unwrap_or("?"));
        for r in p["regions"].as_array().into_iter().flatten() {
            let markers: Vec<&str> = r["markers"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
            print!("  {} (pkt {}){}", r["base"].as_str().unwrap_or("?"), r["deterministic_score"],
                if markers.is_empty() { String::new() } else { format!(" [{}]", markers.join(",")) });
            if r["status"] == "ok" {
                println!();
                for hy in r["explanation"]["hypotheses"].as_array().into_iter().flatten() {
                    println!("      {:<17} {:<12} dowody: {}", hy["label"].as_str().unwrap_or("?"), hy["confidence"].as_str().unwrap_or("?"),
                        hy["evidence"].as_array().map(|e| e.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default());
                }
                println!("      {}", r["explanation"]["summary"].as_str().unwrap_or(""));
            } else {
                not_ok += 1;
                println!(" - brak interpretacji ({}): {}", r["status"].as_str().unwrap_or("?"), r["reason"].as_str().unwrap_or(""));
            }
        }
        let c = &p["correlation"];
        if c["status"] == "ok" {
            println!("  korelacja: {}", c["summary"].as_str().unwrap_or(""));
            println!("  proponowana kolejność: {}", c["review_order"].as_array().map(|e| e.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" > ")).unwrap_or_default());
            for s in c["next_steps"].as_array().into_iter().flatten() { println!("  - {}", s.as_str().unwrap_or("")); }
        } else if c["status"] == "rejected" {
            not_ok += 1;
            println!("  korelacja: brak ({})", c["reason"].as_str().unwrap_or(""));
        }
    }
    eprintln!("\nzapisano: {}", out.display());
    if !a.no_report { crate::write_report(&a.result, Some(&out), None, None, parse_min(&a.min)?, std::env::var_os("NANSHE_KB_DIR").map(std::path::PathBuf::from).as_deref())?; }
    // brak interpretacji to wynik częściowy, nie błąd
    Ok(if not_ok > 0 { ExitCode::from(3) } else { ExitCode::SUCCESS })
}
