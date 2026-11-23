//! Walidacja odpowiedzi modelu. Odpowiedź jest danymi niezaufanymi: schemat,
//! zamknięty słownik, limity długości i odwołania wyłącznie do istniejących identyfikatorów.
use nanshe_core::{tr, trf};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const LABELS: [&str; 8] = ["jit", "packer", "reflective-load", "hollowing", "shellcode-stager", "fileless-exec", "benign-unknown", "unknown"];
pub const BENIGN: [&str; 2] = ["jit", "benign-unknown"];
pub const CONFIDENCE: [&str; 3] = ["established", "assessed", "unconfirmed"];
const MAX_TEXT: usize = 600;
const MAX_ITEMS: usize = 6;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub label: String,
    pub confidence: String,
    #[serde(rename = "for")]
    pub arguments_for: Vec<String>,
    pub against: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    pub hypotheses: Vec<Hypothesis>,
    pub summary: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Group { pub region_ids: Vec<String>, pub description: String }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub groups: Vec<Group>,
    pub review_order: Vec<String>,
    pub next_steps: Vec<String>,
    pub summary: String,
}

/// Za długi tekst jest przycinany (limit pozostaje twardy), a nie powodem odrzucenia całej odpowiedzi.
fn clip(s: &mut String, what: &str, notes: &mut Vec<String>) {
    if s.chars().count() > MAX_TEXT {
        *s = s.chars().take(MAX_TEXT - 1).chain(std::iter::once('…')).collect();
        notes.push(trf!("{what}: tekst przycięty do {MAX_TEXT} znaków", "{what}: text trimmed to {MAX_TEXT} characters"));
    }
}
fn list_ok(v: &mut [String], what: &str, notes: &mut Vec<String>) -> Result<(), String> {
    if v.len() > MAX_ITEMS { return Err(trf!("{what}: więcej niż {MAX_ITEMS} pozycji", "{what}: more than {MAX_ITEMS} items")); }
    v.iter_mut().for_each(|s| clip(s, what, notes));
    Ok(())
}

pub fn explanation_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["hypotheses", "summary"],
        "properties": {
            "hypotheses": { "type": "array", "minItems": 1, "maxItems": 3, "items": {
                "type": "object", "additionalProperties": false,
                "required": ["label", "confidence", "for", "against", "evidence"],
                "properties": {
                    "label": { "type": "string", "enum": LABELS },
                    "confidence": { "type": "string", "enum": CONFIDENCE },
                    "for": { "type": "array", "items": { "type": "string" } },
                    "against": { "type": "array", "items": { "type": "string" } },
                    "evidence": { "type": "array", "minItems": 1, "items": { "type": "string" } }
                } } },
            "summary": { "type": "string" }
        }
    })
}

pub fn correlation_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["groups", "review_order", "next_steps", "summary"],
        "properties": {
            "groups": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                "required": ["region_ids", "description"],
                "properties": { "region_ids": { "type": "array", "items": { "type": "string" } }, "description": { "type": "string" } } } },
            "review_order": { "type": "array", "items": { "type": "string" } },
            "next_steps": { "type": "array", "items": { "type": "string" } },
            "summary": { "type": "string" }
        }
    })
}

/// `finding_ids`: identyfikatory znalezisk tego regionu.
pub fn validate_explanation(raw: &str, finding_ids: &[String]) -> Result<(Explanation, Vec<String>), String> {
    let mut e: Explanation = serde_json::from_str(raw).map_err(|e| format!("schemat: {e}"))?;
    let mut notes = Vec::new();
    if e.hypotheses.is_empty() || e.hypotheses.len() > 3 { return Err(tr!("liczba hipotez poza zakresem 1-3", "number of hypotheses outside the range 1-3").into()); }
    // Hipoteza bez uzasadnienia jest dla analityka bezużyteczna: odrzucamy, zamiast pokazywać pustą.
    if e.summary.trim().is_empty() { return Err(tr!("puste pole summary", "empty summary field").into()); }
    clip(&mut e.summary, "summary", &mut notes);
    for h in e.hypotheses.iter_mut() {
        if h.arguments_for.iter().all(|a| a.trim().is_empty()) { return Err(trf!("hipoteza {} bez żadnego argumentu w polu for", "hypothesis {} has no argument in the for field", h.label)); }
        if !LABELS.contains(&h.label.as_str()) { return Err(trf!("hipoteza spoza słownika: {}", "hypothesis not in the vocabulary: {}", h.label)); }
        if !CONFIDENCE.contains(&h.confidence.as_str()) { return Err(trf!("pewność spoza słownika: {}", "confidence not in the vocabulary: {}", h.confidence)); }
        list_ok(&mut h.arguments_for, "for", &mut notes)?;
        list_ok(&mut h.against, "against", &mut notes)?;
        if h.evidence.is_empty() { return Err(trf!("hipoteza {} bez dowodów", "hypothesis {} has no evidence", h.label)); }
        for id in &h.evidence {
            if !finding_ids.contains(id) { return Err(trf!("odwołanie do nieistniejącego znaleziska: {id}", "reference to a non-existent finding: {id}")); }
        }
        // Żadne dane wejściowe (także lista dozwolonych) nie dowodzą, że region jest łagodny.
        if BENIGN.contains(&h.label.as_str()) && h.confidence == "established" {
            return Err(trf!("hipoteza łagodna „{}\" nie może mieć pewności established", "benign hypothesis \"{}\" cannot have confidence established", h.label));
        }
    }
    Ok((e, notes))
}

/// Kolejność przeglądu nigdy nie usuwa pozycji: brakujące regiony są dopisywane na końcu.
pub fn validate_correlation(raw: &str, region_ids: &[String]) -> Result<(Correlation, Vec<String>), String> {
    let mut c: Correlation = serde_json::from_str(raw).map_err(|e| format!("schemat: {e}"))?;
    let mut notes = Vec::new();
    clip(&mut c.summary, "summary", &mut notes);
    list_ok(&mut c.next_steps, "next_steps", &mut notes)?;
    if c.groups.len() > MAX_ITEMS { return Err(tr!("za dużo grup", "too many groups").into()); }
    for g in c.groups.iter_mut() {
        clip(&mut g.description, "group.description", &mut notes);
        for id in &g.region_ids {
            if !region_ids.contains(id) { return Err(trf!("grupa odwołuje się do nieistniejącego regionu: {id}", "group refers to a non-existent region: {id}")); }
        }
    }
    let mut seen = Vec::new();
    for id in &c.review_order {
        if !region_ids.contains(id) { return Err(trf!("kolejność odwołuje się do nieistniejącego regionu: {id}", "review order refers to a non-existent region: {id}")); }
        if !seen.contains(id) { seen.push(id.clone()); }
    }
    let missing: Vec<_> = region_ids.iter().filter(|id| !seen.contains(id)).cloned().collect();
    if !missing.is_empty() {
        notes.push(trf!("model pominął {} region(ów) w kolejności; dopisane na końcu", "the model omitted {} region(s) from the order; appended at the end", missing.len()));
        seen.extend(missing);
    }
    c.review_order = seen;
    Ok((c, notes))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids() -> Vec<String> { vec!["5:7000:RWX".into(), "5:7000:X-PRIV".into()] }
    fn exp(label: &str, conf: &str, ev: &str) -> String {
        json!({"hypotheses":[{"label":label,"confidence":conf,"for":["a"],"against":[],"evidence":[ev]}],"summary":"s"}).to_string()
    }
    #[test]
    fn accepts_valid() {
        assert!(validate_explanation(&exp("shellcode-stager", "assessed", "5:7000:RWX"), &ids()).is_ok());
    }
    #[test]
    fn rejects_each_violation() {
        let i = ids();
        assert!(validate_explanation("nie json", &i).is_err());
        assert!(validate_explanation(&exp("malware", "assessed", "5:7000:RWX"), &i).unwrap_err().contains("słownika"));
        assert!(validate_explanation(&exp("packer", "certain", "5:7000:RWX"), &i).unwrap_err().contains("pewność"));
        assert!(validate_explanation(&exp("packer", "assessed", "5:9999:HDR"), &i).unwrap_err().contains("nieistniejącego"));
        let noev = json!({"hypotheses":[{"label":"packer","confidence":"assessed","for":["a"],"against":[],"evidence":[]}],"summary":"s"}).to_string();
        assert!(validate_explanation(&noev, &i).unwrap_err().contains("bez dowodów"));
        let extra = json!({"hypotheses":[],"summary":"s","verdict":"clean"}).to_string();
        assert!(validate_explanation(&extra, &i).unwrap_err().contains("schemat"));
        let long = json!({"hypotheses":[{"label":"packer","confidence":"assessed","for":["a"],"against":[],"evidence":["5:7000:RWX"]}],"summary":"x".repeat(601)}).to_string();
        let (e, notes) = validate_explanation(&long, &i).unwrap();
        assert_eq!((e.summary.chars().count(), notes.len()), (600, 1), "za długi tekst przycięty, z adnotacją");
        let many = json!({"hypotheses":[{"label":"packer","confidence":"assessed","for":vec!["a"; 7],"against":[],"evidence":["5:7000:RWX"]}],"summary":"s"}).to_string();
        assert!(validate_explanation(&many, &i).is_err());
    }
    #[test]
    fn benign_is_never_established() {
        let raw = exp("jit", "established", "5:7000:RWX");
        assert!(validate_explanation(&raw, &ids()).is_err());
        assert!(validate_explanation(&exp("benign-unknown", "established", "5:7000:RWX"), &ids()).is_err());
        assert!(validate_explanation(&exp("jit", "assessed", "5:7000:RWX"), &ids()).is_ok());
        assert!(validate_explanation(&exp("packer", "established", "5:7000:RWX"), &ids()).is_ok());
    }
    #[test]
    fn correlation_never_drops_regions() {
        let r: Vec<String> = vec!["r:5:1000".into(), "r:5:2000".into(), "r:5:3000".into()];
        let raw = json!({"groups":[{"region_ids":["r:5:1000"],"description":"d"}],"review_order":["r:5:3000","r:5:3000"],"next_steps":[],"summary":"s"}).to_string();
        let (c, notes) = validate_correlation(&raw, &r).unwrap();
        assert_eq!(c.review_order, ["r:5:3000", "r:5:1000", "r:5:2000"]);
        assert_eq!(notes.len(), 1);
        let bad = json!({"groups":[],"review_order":["r:5:dead"],"next_steps":[],"summary":"s"}).to_string();
        assert!(validate_correlation(&bad, &r).is_err());
        let badg = json!({"groups":[{"region_ids":["r:9:1"],"description":"d"}],"review_order":[],"next_steps":[],"summary":"s"}).to_string();
        assert!(validate_correlation(&badg, &r).is_err());
    }

    #[test]
    fn explanation_without_reasoning_is_rejected() {
        let ids = vec!["1:a:RWX".to_string()];
        let mk = |f: serde_json::Value, summary: &str| serde_json::json!({"hypotheses":[{"label":"packer","confidence":"assessed","for":f,"against":[],"evidence":["1:a:RWX"]}],"summary":summary}).to_string();
        assert!(validate_explanation(&mk(serde_json::json!(["bo tak"]), "s"), &ids).is_ok(), "kontrola: pusta lista against jest dozwolona");
        assert!(validate_explanation(&mk(serde_json::json!([]), "s"), &ids).unwrap_err().contains("for"));
        assert!(validate_explanation(&mk(serde_json::json!(["  "]), "s"), &ids).unwrap_err().contains("for"));
        assert!(validate_explanation(&mk(serde_json::json!(["bo tak"]), " "), &ids).unwrap_err().contains("summary"));
    }
}
