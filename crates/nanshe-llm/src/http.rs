//! Cienka warstwa nad klientem HTTP: jedno miejsce, w którym ustawiamy limity czasu i zamieniamy odpowiedź
//! albo błąd na wartość JSON lub czytelny komunikat.

use serde_json::Value;
use std::time::Duration;

/// Klient z limitem czasu na połączenie i na całą wymianę. Kody HTTP spoza 2xx nie są zamieniane na błąd
/// przez klienta: treść odpowiedzi z błędem jest potrzebna w komunikacie.
pub fn agent(connect: Duration, total: Duration, redirects: Option<u32>) -> ureq::Agent {
    let mut c = ureq::Agent::config_builder().timeout_connect(Some(connect)).timeout_global(Some(total)).http_status_as_error(false);
    if let Some(n) = redirects { c = c.max_redirects(n); }
    c.build().into()
}

/// Odpowiedź 2xx jako JSON; inny kod jako "HTTP <kod>: <początek treści>", błąd połączenia jako "transport: ...".
pub fn json(resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value, String> {
    let mut r = resp.map_err(|e| format!("transport: {e}"))?;
    let code = r.status().as_u16();
    if !(200..300).contains(&code) {
        let body = r.body_mut().read_to_string().unwrap_or_default();
        return Err(format!("HTTP {code}: {}", body.chars().take(300).collect::<String>()));
    }
    r.body_mut().read_json::<Value>().map_err(|e| e.to_string())
}
