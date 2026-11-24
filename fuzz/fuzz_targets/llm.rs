//! Odpowiedź modelu językowego i teksty z pamięci badanego procesu, które trafiają do zapytania: model może
//! zwrócić cokolwiek, a ciągi z pamięci wybiera badany proces.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let ids = vec!["7:10000:RWX".to_string(), "7:10000:X-PRIV".to_string()];
    let _ = nanshe_llm::validate::validate_explanation(&text, &ids);
    let _ = nanshe_llm::validate::validate_correlation(&text, &["r:7:10000".to_string()]);
    let json = nanshe_llm::cloud::extract_json(&text);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
        let _ = nanshe_llm::cloud::parse_models(&v);
        let _ = nanshe_llm::cloud::openai_response(&v);
        let _ = nanshe_llm::cloud::anthropic_response(&v);
        let _ = nanshe_llm::cloud::strict_schema(&v);
    }
    let _ = nanshe_llm::context::ascii_strings(data);
    let _ = nanshe_llm::context::secret_kind(&text);
    let _ = nanshe_llm::context::looks_like_injection(&text);
    let mut injection = false;
    let _ = nanshe_llm::context::sanitize_field(&text, false, &mut injection);
    let _ = nanshe_llm::backend::check_url(&text, false);
});
