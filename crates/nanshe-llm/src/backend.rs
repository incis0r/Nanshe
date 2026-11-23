//! Backendy modeli. Jedyny kod sieciowy w projekcie.
use serde_json::{json, Value};
use std::time::Duration;

pub struct Request { pub system: String, pub user: String, pub schema: Value, pub max_tokens: u32, pub num_ctx: u32 }
#[derive(Debug)]
pub struct Response { pub text: String, pub prompt_tokens: u64, pub output_tokens: u64 }

#[derive(Clone, Debug)]
pub struct ModelInfo { pub backend: String, pub model: String, pub digest: Option<String>, pub context_length: Option<u64>, pub server_version: Option<String>,
    /// Czy zapytania idą z temperaturą 0 (i ziarnem, jeśli backend je przyjmuje); część modeli chmurowych nie pozwala tego ustawić.
    pub fixed_sampling: bool }

pub trait LlmBackend {
    fn info(&self) -> Result<ModelInfo, String>;
    fn complete(&self, req: &Request) -> Result<Response, String>;
}

pub const TEMPERATURE: f64 = 0.0;
pub const SEED: u64 = 42;

/// Odmawia czystego HTTP poza loopback, chyba że jawnie dopuszczono (`--insecure-llm`).
/// Adres jest parsowany tym samym parserem, którego używa klient HTTP (crate `url`),
/// a zapytania budowane są ze zwróconego obiektu: brak różnicy między tym, co sprawdzone,
/// a tym, z czym nastąpi połączenie.
pub fn check_url(raw: &str, insecure: bool) -> Result<url::Url, String> {
    let u = url::Url::parse(raw).map_err(|e| format!("błędny adres modelu {raw}: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") { return Err(format!("adres modelu musi zaczynać się od http:// lub https://: {raw}")); }
    if !u.username().is_empty() || u.password().is_some() { return Err("adres modelu nie może zawierać danych logowania".into()); }
    if u.query().is_some() || u.fragment().is_some() { return Err("adres modelu nie może zawierać zapytania ani fragmentu".into()); }
    let loopback = match u.host() {
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => return Err(format!("adres modelu bez hosta: {raw}")),
    };
    let host = u.host_str().unwrap_or("?").to_string();
    if u.scheme() == "https" || loopback || insecure { Ok(u) } else {
        Err(format!("połączenie z {host} po czystym HTTP: fragmenty pamięci szłyby siecią bez szyfrowania i uwierzytelnienia. Użyj https, tunelu SSH do loopback albo jawnie --insecure-llm."))
    }
}

pub struct Ollama { url: String, model: String, agent: ureq::Agent }

impl Ollama {
    pub fn new(url: &str, model: &str, insecure: bool, timeout: Duration) -> Result<Self, String> {
        let parsed = check_url(url, insecure)?;
        Ok(Ollama { url: parsed.as_str().trim_end_matches('/').to_string(), model: model.to_string(),
            agent: ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(5)).timeout(timeout).build() })
    }
    fn err(e: ureq::Error) -> String {
        match e {
            ureq::Error::Status(code, r) => format!("HTTP {code}: {}", r.into_string().unwrap_or_default().chars().take(300).collect::<String>()),
            ureq::Error::Transport(t) => format!("transport: {t}"),
        }
    }
}

impl LlmBackend for Ollama {
    fn info(&self) -> Result<ModelInfo, String> {
        let ver: Value = self.agent.get(&format!("{}/api/version", self.url)).call().map_err(Self::err)?
            .into_json().map_err(|e| e.to_string())?;
        let tags: Value = self.agent.get(&format!("{}/api/tags", self.url)).call().map_err(Self::err)?
            .into_json().map_err(|e| e.to_string())?;
        let entry = tags["models"].as_array().and_then(|a| a.iter().find(|m| m["name"] == self.model.as_str()))
            .ok_or_else(|| format!("model {} nie jest dostępny na {}", self.model, self.url))?;
        let show: Value = self.agent.post(&format!("{}/api/show", self.url)).send_json(json!({ "model": self.model }))
            .map_err(Self::err)?.into_json().map_err(|e| e.to_string())?;
        let ctx = show["model_info"].as_object()
            .and_then(|o| o.iter().find(|(k, _)| k.ends_with(".context_length")).and_then(|(_, v)| v.as_u64()));
        Ok(ModelInfo { backend: "ollama".into(), model: self.model.clone(),
            digest: entry["digest"].as_str().map(String::from), context_length: ctx,
            server_version: ver["version"].as_str().map(String::from), fixed_sampling: true })
    }

    fn complete(&self, req: &Request) -> Result<Response, String> {
        let body = json!({
            "model": self.model, "stream": false, "format": req.schema,
            "messages": [ { "role": "system", "content": req.system }, { "role": "user", "content": req.user } ],
            "options": { "temperature": TEMPERATURE, "seed": SEED, "num_ctx": req.num_ctx, "num_predict": req.max_tokens }
        });
        let v: Value = self.agent.post(&format!("{}/api/chat", self.url)).send_json(body).map_err(Self::err)?
            .into_json().map_err(|e| e.to_string())?;
        let text = v["message"]["content"].as_str().ok_or("odpowiedź bez message.content")?.to_string();
        Ok(Response { text, prompt_tokens: v["prompt_eval_count"].as_u64().unwrap_or(0), output_tokens: v["eval_count"].as_u64().unwrap_or(0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_http_only_to_loopback() {
        for ok in ["http://127.0.0.1:11434", "http://localhost:11434/", "http://[::1]:11434", "https://ollama.lab:443", "http://127.0.0.5"] {
            assert!(check_url(ok, false).is_ok(), "{ok}");
        }
        for bad in ["http://192.168.7.50:11434", "http://127.0.0.1.evil.example:11434", "http://localhost@192.168.7.50:11434", "http://localhost.evil.example", "ftp://x", "192.168.7.50:11434",
            // różnice parserów: wszystko to klient HTTP odczytałby jako host evil.example
            "http://evil.example\\@127.0.0.1", "http://evil.example?@127.0.0.1", "http://evil.example#@127.0.0.1", "http://evil.example/@127.0.0.1/../",
            // dane logowania, zapytanie i fragment odrzucane także dla loopback i https
            "http://user:pw@127.0.0.1:11434", "https://user@ollama.lab", "http://127.0.0.1:11434/?x=1", "http://127.0.0.1:11434/#f"] {
            assert!(check_url(bad, false).is_err(), "{bad}");
        }
        assert_eq!(check_url("http://2130706433:11434", false).unwrap().host_str(), Some("127.0.0.1"), "zapis dziesiętny rozwiązany przez parser");
        assert_eq!(check_url("http://LOCALHOST:11434/", false).unwrap().as_str(), "http://localhost:11434/");
        assert!(check_url("http://192.168.7.50:11434", true).is_ok());
        assert!(check_url("ftp://x", true).is_err());
    }
}
