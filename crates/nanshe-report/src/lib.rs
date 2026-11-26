//! Wyjścia: JSON (wersjonowany schemat) i skrót tekstowy.
#![forbid(unsafe_code)]

pub mod diff;
pub mod doc;
pub mod md;
pub mod memory;
pub mod pdf;
pub mod text;

use nanshe_core::*;
use nanshe_core::{tr, trf};

pub fn to_json(r: &ScanResult) -> String {
    serde_json::to_string_pretty(r).expect("serializacja wyniku")
}

pub fn from_json(s: &str) -> Result<ScanResult> {
    let r: ScanResult = serde_json::from_str(s).map_err(|e| Error::Invalid(trf!("wynik JSON: {e}", "result JSON: {e}")))?;
    if r.schema_version != SCHEMA_VERSION {
        return Err(Error::Unsupported(trf!("wersja schematu {} (obsługiwana: {SCHEMA_VERSION})", "schema version {} (supported: {SCHEMA_VERSION})", r.schema_version)));
    }
    Ok(r)
}

pub fn sev_label(s: Severity) -> &'static str {
    match s { Severity::None => "-", Severity::Info => "info", Severity::Suspicious => tr!("podejrzane", "suspicious"), Severity::High => tr!("wysokie", "high") }
}

pub use text::{to_text, TextOptions};

pub use nanshe_core::sha256_hex;

/// Raport z wyniku skanu i (opcjonalnie) interpretacji LLM: zwraca (Markdown, PDF).
/// `raw` to bajty pliku wyniku; interpretacja innego wyniku jest odrzucana.
pub fn build_report(raw: &[u8], llm: Option<&serde_json::Value>, min: Severity, result_name: Option<String>) -> Result<(String, Vec<u8>)> {
    build_report_with(raw, llm, min, result_name, None)
}

/// Jak `build_report`, z opcjonalnym katalogiem bazy wiedzy (`common.json`, `<system>.json`)
/// używanym zamiast bazy wbudowanej. Błędny katalog to błąd, a nie cichy powrót do wbudowanej.
pub fn build_report_with(raw: &[u8], llm: Option<&serde_json::Value>, min: Severity, result_name: Option<String>, kb_dir: Option<&std::path::Path>) -> Result<(String, Vec<u8>)> {
    build_report_lang(raw, llm, min, result_name, kb_dir, None)
}

/// Raport w wybranym języku. `None`: język, w którym wykonano skan (pole `lang` wyniku; brak pola
/// oznacza polski), żeby opisy zapisane w wyniku i tekst raportu były w jednym języku.
pub fn build_report_lang(raw: &[u8], llm: Option<&serde_json::Value>, min: Severity, result_name: Option<String>, kb_dir: Option<&std::path::Path>, language: Option<lang::Lang>) -> Result<(String, Vec<u8>)> {
    let scan_lang = serde_json::from_slice::<serde_json::Value>(raw).ok().and_then(|v| v["lang"].as_str().and_then(lang::Lang::parse)).unwrap_or(lang::Lang::Pl);
    lang::with(language.unwrap_or(scan_lang), || build_in_current_lang(raw, llm, min, result_name, kb_dir))
}

/// Raport różnicowy z dwóch wyników skanu (wcześniejszy, późniejszy). Język: wybrany, a bez
/// wyboru ten, w którym wykonano późniejszy skan.
pub fn build_diff(old_raw: &[u8], new_raw: &[u8], min: Severity, old_name: Option<String>, new_name: Option<String>, language: Option<lang::Lang>) -> Result<(String, Vec<u8>)> {
    let parse = |raw: &[u8]| from_json(std::str::from_utf8(raw).map_err(|_| Error::Invalid(tr!("wynik nie jest UTF-8", "result is not UTF-8").into()))?);
    let (old, new) = (parse(old_raw)?, parse(new_raw)?);
    let l = language.or_else(|| new.lang.as_deref().and_then(lang::Lang::parse)).unwrap_or(lang::Lang::Pl);
    lang::with(l, || {
        let d = diff::build(&old, &new, &diff::Options { min, old_name, new_name, old_sha256: Some(sha256_hex(old_raw)), new_sha256: Some(sha256_hex(new_raw)) });
        Ok((md::render(&d), pdf::render(&d)))
    })
}

fn build_in_current_lang(raw: &[u8], llm: Option<&serde_json::Value>, min: Severity, result_name: Option<String>, kb_dir: Option<&std::path::Path>) -> Result<(String, Vec<u8>)> {
    if let Some(d) = kb_dir { nanshe_kb::Kb::from_dir(d, "linux").map_err(Error::Invalid)?; }
    let scan = from_json(std::str::from_utf8(raw).map_err(|_| Error::Invalid(tr!("wynik nie jest UTF-8", "result is not UTF-8").into()))?)?;
    let sha = sha256_hex(raw);
    if let Some(l) = llm { doc::check_llm_matches(l, &sha)?; }
    let d = doc::build(&scan, llm, &doc::Options { min, result_sha256: Some(sha), result_name, kb_dir: kb_dir.map(|d| d.to_path_buf()) });
    Ok((md::render(&d), pdf::render(&d)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan_json() -> Vec<u8> {
        let region = Region { base: 0x7f00_0000, size: 65536, prot: Prot::parse("rwx"), kind: RegionKind::Private, backing: None, backing_deleted: false, label: None, readable: true };
        let f = |tag: &str, reason: &str| Finding { id: format!("5:7f000000:{tag}"), detector: tag.to_lowercase(), tag: tag.into(), addr: 0x7f00_0000, size: 65536, prot: region.prot,
            entropy: None, weight: 30, reason: reason.into(), bytes_hex: None };
        let rr = RegionReport { region: region.clone(), bytes_read: 65536, truncated: false, entropy_max: Some(7.96), entropy_mean: Some(7.9), zero_pages: 0,
            score: 60, severity: Severity::High, allowlisted: None, allocation: None, findings: vec![f("RWX", "region zapisywalny i wykonywalny"), f("X-PRIV", "zły | opis <b>x</b>")], heat: None, profile: None, strings: vec![], sha256: None };
        let low = RegionReport { score: 10, severity: Severity::Info, findings: vec![f("ENT-X", "rzadkie strony")], region: Region { base: 0x1000, ..region.clone() }, ..rr.clone() };
        let info = |pid, name: &str| SourceInfo { os: "linux".into(), arch: "x86_64".into(), pid: Some(pid), name: Some(name.into()), source_type: "live".into(), exe: Some("/usr/bin/zażółć".into()), exe_deleted: false, exe_verified: false };
        let s = ScanResult { schema_version: SCHEMA_VERSION, tool_version: "0.1.0".into(), timestamp: "2026-11-22T00:00:00Z".into(), host: "lab-host".into(), heat_cell_bytes: 65536, partial: true,
            processes: vec![
                ProcessReport { info: info(5, "próbka"), regions_total: 20, regions_unreadable: 1, bytes_scanned: 1 << 20, max_severity: Severity::High, error: None, regions: vec![rr, low], layout: None, stacks: None, context: None },
                ProcessReport { info: info(6, "bezznalezisk"), regions_total: 9, regions_unreadable: 0, bytes_scanned: 4096, max_severity: Severity::None, error: None, regions: vec![], layout: None, stacks: None, context: None },
                ProcessReport { info: info(7, "chroniony"), regions_total: 0, regions_unreadable: 0, bytes_scanned: 0, max_severity: Severity::None, error: Some("odmowa dostępu".into()), regions: vec![], layout: None, stacks: None, context: None },
            ], lang: None, host_info: None, files: vec![] };
        to_json(&s).into_bytes()
    }
    fn llm(sha: &str) -> serde_json::Value {
        json!({ "header": { "result_sha256": sha, "model": "m", "backend": "nous", "cloud": true, "pseudonymized_values": 2, "data_level": "d0", "prompt_version": "p",
                "params": { "temperature": null, "seed": null }, "usage": { "calls": 1, "cache_hits": 0, "prompt_tokens": 10, "output_tokens": 5 }, "timestamp": "t" },
            "processes": [ { "pid": 5, "name": "próbka", "regions": [ { "base": "0x7f000000", "status": "ok", "markers": ["LLM-INJECT"], "strings_redacted": 0, "validator_notes": [],
                "explanation": { "hypotheses": [ { "label": "packer", "confidence": "assessed", "for": ["wysoka entropia"], "against": ["brak nagłówka"], "evidence": ["5:7f000000:RWX"] } ], "summary": "Spakowany kod." } } ],
                "correlation": { "status": "ok", "summary": "Jeden obraz.", "review_order": ["r:5:7f000000"], "groups": [], "next_steps": ["Zrzucić region."] } } ] })
    }

    #[test]
    fn report_without_llm_lists_findings_and_gaps() {
        let raw = scan_json();
        let (md, pdf) = build_report(&raw, None, Severity::Suspicious, Some("wynik.json".into())).unwrap();
        for want in ["# Nanshe: raport triage pamięci", "**Spis treści**", "- [1. Podsumowanie dla decydenta](#ch-1)", "WYNIK CZĘŚCIOWY", "próbka", "0x7f000000", "RWX, X-PRIV", "Proces 7 niedostępny: odmowa dostępu",
            "1 regionów ze znaleziskami poniżej poziomu", "Brak interpretacji LLM", &sha256_hex(&raw)] {
            assert!(md.contains(want), "brak: {want}\n{md}");
        }
        assert!(!md.contains("Interpretacja LLM (do weryfikacji)"));
        assert!(!md.contains("bezznalezisk"), "proces bez znalezisk nie ma sekcji");
        assert!(!md.contains("0x1000"), "region poniżej progu nie jest pokazywany");
        // opis znaleziska pochodzi z badanego procesu: nie może wstrzyknąć znaczników
        assert!(md.contains("zły \\| opis &lt;b&gt;x&lt;/b&gt;") && !md.contains("<b>"));
        assert!(pdf.starts_with(b"%PDF-"));
    }

    /// Wynik bez polskich danych: wszystko, co polskie w raporcie angielskim, pochodziłoby z narzędzia.
    fn ascii_scan(lang: Option<&str>) -> Vec<u8> {
        let mut s: ScanResult = from_json(std::str::from_utf8(&scan_json()).unwrap()).unwrap();
        s.lang = lang.map(String::from);
        for p in &mut s.processes {
            p.info.name = Some("sample".into()); p.info.exe = Some("/usr/bin/sample".into());
            if p.error.is_some() { p.error = Some("access denied".into()); }
            for r in &mut p.regions { for f in &mut r.findings { f.reason = "region both writable and executable".into(); } }
        }
        to_json(&s).into_bytes()
    }

    #[test]
    fn english_report_has_no_polish_text() {
        let raw = ascii_scan(Some("en"));
        let mut l = llm(&sha256_hex(&raw));
        let text = serde_json::to_string(&l).unwrap().replace("próbka", "sample").replace("wysoka entropia", "high entropy").replace("brak nagłówka", "no header")
            .replace("Spakowany kod.", "Packed code.").replace("Jeden obraz.", "One image.").replace("Zrzucić region.", "Dump the region.");
        l = serde_json::from_str(&text).unwrap();
        for with_llm in [false, true] {
            let (md, pdf) = build_report_lang(&raw, with_llm.then_some(&l), Severity::Suspicious, Some("result.json".into()), None, None).unwrap();
            for want in ["# Nanshe: memory triage report", "**Contents**", "- [1. Executive summary](#ch-1)", "Executive summary", "PARTIAL RESULT", "How to read this report", "Process 5: sample", "Assessment", "What the findings mean in this process",
                "Process 7 inaccessible: access denied", "What this report does not cover", "Glossary", "Legend", "Triage, not a verdict."] {
                assert!(md.contains(want), "brak: {want}\n{md}");
            }
            if with_llm { for want in ["LLM interpretation (requires verification)", "packer (packed or encrypted code)", "model's judgement", "| Hypothesis 1: what supports it | What undermines it |", "| high entropy | no header |", "Model summary: Packed code."] { assert!(md.contains(want), "brak: {want}"); } }
            let polish: Vec<&str> = md.lines().filter(|l| l.chars().any(|c| "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ„".contains(c))).collect();
            assert!(polish.is_empty(), "polski tekst w raporcie angielskim: {polish:#?}");
            assert!(!md.contains('\u{2014}') && !md.contains('\u{2013}'));
            assert!(pdf.starts_with(b"%PDF-"));
        }
    }

    #[test]
    fn report_language_follows_the_scan_unless_chosen() {
        // skan po polsku (brak pola lang), raport bez wyboru języka: po polsku, bez uwagi o językach
        let (md, _) = build_report_lang(&ascii_scan(None), None, Severity::Suspicious, None, None, None).unwrap();
        assert!(md.contains("Podsumowanie dla decydenta") && !md.contains("w innym języku"));
        // ten sam skan, raport angielski na życzenie: tekst angielski i uwaga, że opisy ze skanu są w języku skanu
        let (md, _) = build_report_lang(&ascii_scan(None), None, Severity::Suspicious, None, None, Some(lang::Lang::En)).unwrap();
        assert!(md.contains("Executive summary") && md.contains("different language from the report language"), "{md}");
        // skan po angielsku, raport polski na życzenie
        let (md, _) = build_report_lang(&ascii_scan(Some("en")), None, Severity::Suspicious, None, None, Some(lang::Lang::Pl)).unwrap();
        assert!(md.contains("Podsumowanie dla decydenta") && md.contains("w innym języku"));
        // wybór języka nie wycieka poza wywołanie
        assert_eq!(lang::get(), lang::Lang::Pl);
    }

    #[test]
    fn report_with_llm_marks_it_and_rejects_foreign_analysis() {
        let raw = scan_json();
        let l = llm(&sha256_hex(&raw));
        let (md, _) = build_report(&raw, Some(&l), Severity::Suspicious, None).unwrap();
        for want in ["Interpretacja LLM (do weryfikacji)", "packer (kod spakowany lub zaszyfrowany)", "osąd modelu", "| Hipoteza 1: co ją wspiera | Co ją podważa |", "| wysoka entropia | brak nagłówka |",
            "Podsumowanie modelu: Spakowany kod.", "chmura, poza własną infrastrukturą", "tekst wyglądający na instrukcję", "Proponowana kolejność przeglądu: 0x7f000000.", "Zrzucić region.", "niedeterministyczne"] {
            assert!(md.contains(want), "brak: {want}\n{md}");
        }
        // interpretacja innego wyniku skanu nie może trafić do raportu
        let e = build_report(&raw, Some(&llm("00ff")), Severity::Suspicious, None).unwrap_err();
        assert!(e.to_string().contains("innego wyniku"));
        // próg wyższy niż znaleziska: raport mówi, że nic nie ma, zamiast pustej tabeli
        let mut s: ScanResult = from_json(std::str::from_utf8(&raw).unwrap()).unwrap();
        s.processes[0].regions.remove(0); s.processes[0].max_severity = Severity::Info;
        let (md, _) = build_report(to_json(&s).as_bytes(), None, Severity::High, None).unwrap();
        assert!(md.contains("Brak znalezisk od poziomu"));
    }
}
