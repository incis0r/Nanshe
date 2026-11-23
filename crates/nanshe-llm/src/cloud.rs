//! Backendy chmurowe: dostawcy wbudowani, klucze, lista modeli, zapytania.
//! Dane wychodzą poza własną infrastrukturę, więc wywołujący musi mieć jawną zgodę (`--allow-cloud`),
//! a poziom D2 jest odrzucany w kodzie (patrz `crate::cloud_policy`).
use crate::backend::{LlmBackend, ModelInfo, Request, Response, SEED, TEMPERATURE};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Api {
    /// `/chat/completions` + `/models` w stylu OpenAI
    OpenAi,
    /// Anthropic Messages API
    Anthropic,
}

pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub api: Api,
    pub base_url: &'static str,
    /// Zmienne środowiskowe z kluczem, w kolejności sprawdzania.
    pub key_env: &'static [&'static str],
    /// Model domyślny; `None` = trzeba podać `--model` (identyfikatory zmieniają się zbyt często, by je zgadywać).
    pub default_model: Option<&'static str>,
}

pub const PROVIDERS: &[Provider] = &[
    Provider { id: "nous", name: "Nous Research (agregator modeli)", api: Api::OpenAi,
        base_url: "https://inference-api.nousresearch.com/v1", key_env: &["NOUS_API_KEY"], default_model: Some("anthropic/claude-opus-5.5") },
    Provider { id: "anthropic", name: "Anthropic", api: Api::Anthropic,
        base_url: "https://api.anthropic.com", key_env: &["ANTHROPIC_API_KEY"], default_model: Some("claude-opus-5-5") },
    Provider { id: "google", name: "Google Gemini (tryb zgodności z OpenAI)", api: Api::OpenAi,
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai", key_env: &["GEMINI_API_KEY", "GOOGLE_API_KEY"], default_model: None },
    Provider { id: "openai", name: "OpenAI", api: Api::OpenAi,
        base_url: "https://api.openai.com/v1", key_env: &["OPENAI_API_KEY"], default_model: None },
];

pub fn provider(id: &str) -> Option<&'static Provider> { PROVIDERS.iter().find(|p| p.id == id) }

const ANTHROPIC_VERSION: &str = "2026-10-21";

/// Skąd wziąłby się klucz, bez czytania go (do `cloud list providers`).
pub fn key_source(p: &Provider, key_file: Option<&Path>) -> Option<String> {
    if let Some(f) = key_file { return Some(format!("plik {}", f.display())); }
    for e in p.key_env { if std::env::var_os(e).map(|v| !v.is_empty()).unwrap_or(false) { return Some(format!("zmienna {e}")); } }
    let fe = key_file_env(p);
    std::env::var_os(&fe).filter(|v| !v.is_empty()).map(|_| format!("plik ze zmiennej {fe}"))
}

pub fn key_file_env(p: &Provider) -> String { format!("NANSHE_{}_KEY_FILE", p.id.to_ascii_uppercase()) }

/// Klucz: `--key-file`, potem zmienne dostawcy, potem `NANSHE_<DOSTAWCA>_KEY_FILE`.
/// Klucz nigdy nie trafia do komunikatów błędów, wyniku ani audytu.
pub fn resolve_key(p: &Provider, key_file: Option<&Path>) -> Result<String, String> {
    let from_file = |f: &Path| -> Result<String, String> {
        let s = std::fs::read_to_string(f).map_err(|e| format!("plik klucza {}: {e}", f.display()))?;
        let k = s.trim().to_string();
        if k.is_empty() { return Err(format!("plik klucza {} jest pusty", f.display())); }
        if k.chars().any(|c| c.is_whitespace() || c.is_control()) { return Err(format!("plik klucza {} zawiera więcej niż sam klucz", f.display())); }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(f) {
                if m.permissions().mode() & 0o077 != 0 { eprintln!("uwaga: plik klucza {} jest dostępny dla innych użytkowników (chmod 600)", f.display()); }
            }
        }
        Ok(k)
    };
    if let Some(f) = key_file { return from_file(f); }
    for e in p.key_env {
        if let Ok(v) = std::env::var(e) { let v = v.trim().to_string(); if !v.is_empty() { return Ok(v); } }
    }
    if let Some(f) = std::env::var_os(key_file_env(p)).filter(|v| !v.is_empty()) { return from_file(Path::new(&f)); }
    Err(format!("brak klucza dla dostawcy {}: ustaw {} albo podaj --key-file <plik>", p.id, p.key_env.join(" / ")))
}

#[derive(Clone, Debug, PartialEq)]
pub struct CloudModel {
    pub id: String,
    pub name: Option<String>,
    pub context_length: Option<u64>,
    /// Parametry zapytania obsługiwane przez model, jeśli dostawca je podaje (Nous).
    pub params: Option<Vec<String>>,
    /// Cena za milion tokenów (wejście, wyjście) w USD, jeśli dostawca ją podaje.
    pub price_per_mtok: Option<(f64, f64)>,
}

/// Lista modeli z odpowiedzi `/models` (oba style API).
pub fn parse_models(v: &Value) -> Vec<CloudModel> {
    let per_mtok = |x: &Value| x.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| x.as_f64()).map(|p| (p * 1e8).round() / 100.0);
    v["data"].as_array().into_iter().flatten().filter_map(|m| {
        // Google w trybie zgodności zwraca identyfikatory z przedrostkiem "models/"
        let id = m["id"].as_str()?.trim_start_matches("models/").to_string();
        Some(CloudModel {
            name: m["display_name"].as_str().or(m["name"].as_str()).map(String::from),
            context_length: m["context_length"].as_u64().or(m["max_input_tokens"].as_u64()),
            params: m["supported_parameters"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
            price_per_mtok: per_mtok(&m["pricing"]["prompt"]).zip(per_mtok(&m["pricing"]["completion"])),
            id,
        })
    }).collect()
}

/// Schemat w podzbiorze przyjmowanym przez ścisłe tryby wyjścia: bez `minItems`/`maxItems`
/// (te granice i tak egzekwuje walidator po naszej stronie).
pub fn strict_schema(s: &Value) -> Value {
    match s {
        Value::Object(o) => Value::Object(o.iter().filter(|(k, _)| !matches!(k.as_str(), "minItems" | "maxItems"))
            .map(|(k, v)| (k.clone(), strict_schema(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(strict_schema).collect()),
        x => x.clone(),
    }
}

fn system_with_schema(req: &Request) -> String {
    format!("{}\nJSON schema of the answer:\n{}", req.system, req.schema)
}

/// Ciało zapytania `/chat/completions`. `params`: lista parametrów obsługiwanych przez model,
/// jeśli dostawca ją podał; inaczej zachowawcze ustawienia per dostawca.
pub fn openai_body(provider_id: &str, model: &str, req: &Request, params: Option<&[String]>) -> Value {
    let has = |p: &str| params.map(|l| l.iter().any(|x| x == p));
    let mut b = json!({ "model": model, "messages": [
        { "role": "system", "content": system_with_schema(req) }, { "role": "user", "content": req.user } ] });
    // OpenAI: modele rozumujące odrzucają `max_tokens` i temperaturę inną niż domyślna.
    let openai = provider_id == "openai";
    let limit_key = match (has("max_tokens"), has("max_completion_tokens")) {
        (Some(true), _) => "max_tokens", (Some(false), Some(true)) => "max_completion_tokens",
        _ => if openai { "max_completion_tokens" } else { "max_tokens" },
    };
    b[limit_key] = json!(req.max_tokens);
    if has("temperature").unwrap_or(!openai) { b["temperature"] = json!(TEMPERATURE); }
    if has("seed").unwrap_or(false) { b["seed"] = json!(SEED); }
    let schema_fmt = json!({ "type": "json_schema", "json_schema": { "name": "nanshe_answer", "strict": true, "schema": strict_schema(&req.schema) } });
    match (has("structured_outputs"), has("response_format")) {
        (Some(true), _) | (None, _) => b["response_format"] = schema_fmt,
        (Some(false), Some(true)) => b["response_format"] = json!({ "type": "json_object" }),
        _ => {}
    }
    b
}

/// Czy zapytanie ma ustalone próbkowanie (temperatura 0), do nagłówka wyniku.
pub fn openai_fixed_sampling(provider_id: &str, params: Option<&[String]>) -> bool {
    params.map(|l| l.iter().any(|x| x == "temperature")).unwrap_or(provider_id != "openai")
}

pub fn anthropic_body(model: &str, req: &Request) -> Value {
    // Bez parametrów próbkowania: wersja API 2026-10-21 je odrzuca.
    json!({ "model": model, "max_tokens": req.max_tokens, "system": req.system,
        "messages": [ { "role": "user", "content": req.user } ],
        "output_config": { "format": { "type": "json_schema", "schema": strict_schema(&req.schema) } } })
}

/// Modele bywają gadatliwe mimo trybu JSON: zdejmujemy płotek ``` i tekst wokół obiektu.
pub fn extract_json(text: &str) -> String {
    let t = text.trim();
    match (t.find('{'), t.rfind('}')) {
        (Some(a), Some(b)) if a < b && (a > 0 || b + 1 < t.len()) => t[a..=b].to_string(),
        _ => t.to_string(),
    }
}

pub fn openai_response(v: &Value) -> Result<Response, String> {
    let c = &v["choices"][0];
    if c["finish_reason"] == "length" { return Err("odpowiedź obcięta limitem tokenów (zwiększ --max-tokens)".into()); }
    if c["finish_reason"] == "content_filter" { return Err("dostawca odfiltrował odpowiedź".into()); }
    let text = c["message"]["content"].as_str().filter(|s| !s.trim().is_empty())
        .ok_or_else(|| match c["message"]["refusal"].as_str() { Some(r) => format!("model odmówił: {}", r.chars().take(200).collect::<String>()), None => "odpowiedź bez treści".to_string() })?;
    Ok(Response { text: extract_json(text), prompt_tokens: v["usage"]["prompt_tokens"].as_u64().unwrap_or(0), output_tokens: v["usage"]["completion_tokens"].as_u64().unwrap_or(0) })
}

pub fn anthropic_response(v: &Value) -> Result<Response, String> {
    // Odmowa klasyfikatora: HTTP 200 ze stop_reason "refusal". Nie przełączamy po cichu na inny model,
    // bo wynik musi wskazywać model, który faktycznie odpowiedział.
    match v["stop_reason"].as_str() {
        Some("refusal") => return Err(format!("model odmówił (kategoria: {})", v["stop_details"]["category"].as_str().unwrap_or("nieokreślona"))),
        Some("max_tokens") => return Err("odpowiedź obcięta limitem tokenów (zwiększ --max-tokens)".into()),
        _ => {}
    }
    let text: String = v["content"].as_array().into_iter().flatten()
        .filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect();
    if text.trim().is_empty() { return Err("odpowiedź bez bloku tekstowego".into()); }
    Ok(Response { text: extract_json(&text), prompt_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0), output_tokens: v["usage"]["output_tokens"].as_u64().unwrap_or(0) })
}

pub struct Cloud {
    p: &'static Provider,
    model: String,
    key: String,
    agent: ureq::Agent,
    /// Parametry obsługiwane przez model; wypełniane przez `info()`.
    params: RefCell<Option<Vec<String>>>,
}

impl Cloud {
    pub fn new(p: &'static Provider, model: &str, key: String, timeout: Duration) -> Self {
        Cloud { p, model: model.to_string(), key, params: RefCell::new(None),
            agent: ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout(timeout).redirects(0).build() }
    }
    pub fn provider(&self) -> &'static Provider { self.p }

    fn auth(&self, r: ureq::Request) -> ureq::Request {
        match self.p.api {
            Api::OpenAi => r.set("Authorization", &format!("Bearer {}", self.key)),
            Api::Anthropic => r.set("x-api-key", &self.key).set("anthropic-version", ANTHROPIC_VERSION),
        }
    }
    fn err(&self, e: ureq::Error) -> String {
        let s = match e {
            ureq::Error::Status(code, r) => format!("{} HTTP {code}: {}", self.p.id, r.into_string().unwrap_or_default().chars().take(300).collect::<String>()),
            ureq::Error::Transport(t) => format!("{} transport: {t}", self.p.id),
        };
        // gdyby serwer odbił klucz w treści błędu
        s.replace(&self.key, "[klucz]")
    }

    pub fn list_models(&self) -> Result<Vec<CloudModel>, String> {
        let url = match self.p.api { Api::OpenAi => format!("{}/models", self.p.base_url), Api::Anthropic => format!("{}/v1/models?limit=1000", self.p.base_url) };
        let v: Value = self.auth(self.agent.get(&url)).call().map_err(|e| self.err(e))?.into_json().map_err(|e| e.to_string())?;
        let mut l = parse_models(&v);
        l.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(l)
    }
}

impl LlmBackend for Cloud {
    fn info(&self) -> Result<ModelInfo, String> {
        let m = self.list_models()?.into_iter().find(|m| m.id == self.model)
            .ok_or_else(|| format!("model {} nie jest dostępny u dostawcy {} (sprawdź: nanshe cloud list models --provider {})", self.model, self.p.id, self.p.id))?;
        let fixed = match self.p.api { Api::OpenAi => openai_fixed_sampling(self.p.id, m.params.as_deref()), Api::Anthropic => false };
        *self.params.borrow_mut() = m.params;
        Ok(ModelInfo { backend: self.p.id.into(), model: self.model.clone(), digest: None, context_length: m.context_length, server_version: None, fixed_sampling: fixed })
    }

    fn complete(&self, req: &Request) -> Result<Response, String> {
        let (url, body) = match self.p.api {
            Api::OpenAi => (format!("{}/chat/completions", self.p.base_url), openai_body(self.p.id, &self.model, req, self.params.borrow().as_deref())),
            Api::Anthropic => (format!("{}/v1/messages", self.p.base_url), anthropic_body(&self.model, req)),
        };
        let v: Value = self.auth(self.agent.post(&url)).send_json(body).map_err(|e| self.err(e))?.into_json().map_err(|e| e.to_string())?;
        match self.p.api { Api::OpenAi => openai_response(&v), Api::Anthropic => anthropic_response(&v) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> Request {
        Request { system: "S".into(), user: "{}".into(), max_tokens: 100, num_ctx: 0,
            schema: json!({ "type": "object", "properties": { "a": { "type": "array", "minItems": 1, "maxItems": 3, "items": { "type": "string" } } } }) }
    }
    fn params(l: &[&str]) -> Vec<String> { l.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn providers_built_in() {
        assert_eq!(PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>(), ["nous", "anthropic", "google", "openai"]);
        for p in PROVIDERS {
            assert!(p.base_url.starts_with("https://"), "{}: tylko https", p.id);
            assert!(crate::backend::check_url(p.base_url, false).is_ok());
        }
        assert!(provider("ollama").is_none());
    }

    #[test]
    fn strict_schema_drops_only_item_bounds() {
        let s = strict_schema(&req().schema);
        assert_eq!(s, json!({ "type": "object", "properties": { "a": { "type": "array", "items": { "type": "string" } } } }));
    }

    #[test]
    fn openai_body_follows_supported_params() {
        let full = params(&["max_tokens", "temperature", "seed", "structured_outputs", "response_format"]);
        let b = openai_body("nous", "m", &req(), Some(&full));
        assert_eq!((b["max_tokens"].as_u64(), b["temperature"].as_f64(), b["seed"].as_u64()), (Some(100), Some(0.0), Some(42)));
        assert_eq!(b["response_format"]["type"], "json_schema");
        assert!(b["response_format"]["json_schema"]["schema"]["properties"]["a"].get("maxItems").is_none());
        assert!(b["messages"][0]["content"].as_str().unwrap().contains("JSON schema of the answer"));

        // model bez temperatury, ziarna i schematów: nic z tego nie może pójść
        let b = openai_body("nous", "m", &req(), Some(&params(&["max_completion_tokens", "response_format"])));
        assert!(b.get("temperature").is_none() && b.get("seed").is_none() && b.get("max_tokens").is_none());
        assert_eq!(b["max_completion_tokens"], 100);
        assert_eq!(b["response_format"], json!({ "type": "json_object" }));
        let b = openai_body("nous", "m", &req(), Some(&params(&["max_tokens"])));
        assert!(b.get("response_format").is_none());

        // dostawca bez listy parametrów
        let b = openai_body("openai", "m", &req(), None);
        assert!(b.get("temperature").is_none() && b.get("max_tokens").is_none());
        assert_eq!(b["max_completion_tokens"], 100);
        let b = openai_body("google", "m", &req(), None);
        assert_eq!((b["max_tokens"].as_u64(), b["temperature"].as_f64()), (Some(100), Some(0.0)));
        assert!(!openai_fixed_sampling("openai", None) && openai_fixed_sampling("google", None));
    }

    #[test]
    fn anthropic_body_has_no_sampling_params() {
        let b = anthropic_body("claude-opus-5-5", &req());
        for k in ["temperature", "top_p", "top_k", "seed"] { assert!(b.get(k).is_none(), "{k}"); }
        assert_eq!(b["system"], "S");
        assert_eq!(b["output_config"]["format"]["type"], "json_schema");
        assert!(b["output_config"]["format"]["schema"]["properties"]["a"].get("minItems").is_none());
    }

    #[test]
    fn responses_parsed_and_failures_named() {
        let ok = json!({ "choices": [ { "finish_reason": "stop", "message": { "content": "```json\n{\"a\":1}\n```" } } ], "usage": { "prompt_tokens": 7, "completion_tokens": 3 } });
        let r = openai_response(&ok).unwrap();
        assert_eq!((r.text.as_str(), r.prompt_tokens, r.output_tokens), ("{\"a\":1}", 7, 3));
        assert!(openai_response(&json!({ "choices": [ { "finish_reason": "length", "message": { "content": "{" } } ] })).unwrap_err().contains("obcięta"));
        assert!(openai_response(&json!({ "choices": [ { "message": { "content": null, "refusal": "no" } } ] })).unwrap_err().contains("odmówił"));
        assert!(openai_response(&json!({})).is_err());

        let ok = json!({ "stop_reason": "end_turn", "content": [ { "type": "thinking", "thinking": "" }, { "type": "text", "text": "{\"a\":1}" } ], "usage": { "input_tokens": 9, "output_tokens": 4 } });
        let r = anthropic_response(&ok).unwrap();
        assert_eq!((r.text.as_str(), r.prompt_tokens, r.output_tokens), ("{\"a\":1}", 9, 4));
        let e = anthropic_response(&json!({ "stop_reason": "refusal", "stop_details": { "category": "cyber" }, "content": [] })).unwrap_err();
        assert!(e.contains("odmówił") && e.contains("cyber"));
        assert!(anthropic_response(&json!({ "stop_reason": "max_tokens", "content": [ { "type": "text", "text": "{" } ] })).is_err());
        assert!(anthropic_response(&json!({ "stop_reason": "end_turn", "content": [ { "type": "thinking", "thinking": "x" } ] })).is_err());
    }

    #[test]
    fn models_parsed_from_both_api_styles() {
        let nous = json!({ "data": [ { "id": "a/b", "name": "B", "context_length": 1000, "supported_parameters": ["seed"], "pricing": { "prompt": "0.0000040000", "completion": "0.0000200000" } } ] });
        assert_eq!(parse_models(&nous), vec![CloudModel { id: "a/b".into(), name: Some("B".into()), context_length: Some(1000), params: Some(params(&["seed"])), price_per_mtok: Some((4.0, 20.0)) }]);
        let anth = json!({ "data": [ { "id": "claude-x", "display_name": "X", "max_input_tokens": 5 } ] });
        assert_eq!(parse_models(&anth), vec![CloudModel { id: "claude-x".into(), name: Some("X".into()), context_length: Some(5), params: None, price_per_mtok: None }]);
        assert_eq!(parse_models(&json!({ "data": [ { "id": "models/gemini-x" }, { "no": "id" } ] }))[0].id, "gemini-x");
        assert!(parse_models(&json!({ "error": "x" })).is_empty());
    }

    #[test]
    fn key_from_file_must_be_a_single_token() {
        let d = std::env::temp_dir().join(format!("nanshe-key-{}", std::process::id()));
        std::fs::write(&d, "  abc123\n").unwrap();
        assert_eq!(resolve_key(provider("nous").unwrap(), Some(&d)).unwrap(), "abc123");
        std::fs::write(&d, "abc 123\n").unwrap();
        assert!(resolve_key(provider("nous").unwrap(), Some(&d)).is_err());
        std::fs::write(&d, "\n").unwrap();
        let e = resolve_key(provider("nous").unwrap(), Some(&d)).unwrap_err();
        assert!(e.contains("pusty"));
        std::fs::remove_file(&d).ok();
    }
}
