//! Baza wiedzy do raportu: wyjaśnienia znalezisk, pojęć, procesów i modułów prostym językiem,
//! osobno dla każdego systemu. Treść leży w plikach `kb/*.json` w repozytorium i jest wbudowana
//! w binarium; katalog z nowszymi plikami można wskazać przy generowaniu raportu.
//! Baza niczego nie punktuje: tylko objaśnia to, co ustaliły detektory.
#![forbid(unsafe_code)]

use nanshe_core::lang::Lang;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

const COMMON: &str = include_str!("../../../kb/common.json");
const LINUX: &str = include_str!("../../../kb/linux.json");
const WINDOWS: &str = include_str!("../../../kb/windows.json");
const MACOS: &str = include_str!("../../../kb/macos.json");
const COMMON_EN: &str = include_str!("../../../kb/en/common.json");
const LINUX_EN: &str = include_str!("../../../kb/en/linux.json");
const WINDOWS_EN: &str = include_str!("../../../kb/en/windows.json");
const MACOS_EN: &str = include_str!("../../../kb/en/macos.json");

/// Systemy, które mają własny plik bazy. Pozostałe (macOS, FreeBSD) dostają część wspólną.
pub const SYSTEMS: [&str; 3] = ["linux", "windows", "macos"];

#[derive(Deserialize, Clone, Debug, Default)]
pub struct TagInfo {
    pub name: String,
    /// Krótka definicja po angielsku do słowniczka w zapytaniu do modelu.
    pub en: String,
    pub meaning: String,
    pub why: String,
    /// Warstwa techniczna dla doświadczonego czytelnika: dokładny warunek detektora.
    #[serde(default)]
    pub tech: String,
    /// Powiązane techniki MITRE ATT&CK ("T1055 Process Injection"); orientacyjnie.
    #[serde(default)]
    pub attack: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Hint {
    /// Some(true): pokaż, gdy w procesie rozpoznano środowisko JIT; Some(false): gdy nie rozpoznano.
    #[serde(default)]
    pub runtime: Option<bool>,
    pub text: String,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Combo {
    pub tags: Vec<String>,
    pub title: String,
    pub meaning: String,
    #[serde(default)]
    pub benign: Vec<String>,
    #[serde(default)]
    pub malicious: Vec<String>,
    #[serde(default)]
    pub hints: Vec<Hint>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ProcInfo {
    pub names: Vec<String>,
    pub what: String,
    /// Typowe położenia pliku (małe litery, bez litery dysku); puste = bez sprawdzania.
    /// Wpis bez końcowego separatora to dokładna ścieżka pliku; z końcowym separatorem: plik
    /// bezpośrednio w tym katalogu; z końcówką `**`: dowolnie głęboko w tym katalogu.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Typowi rodzice (nazwy procesów); puste = bez sprawdzania.
    #[serde(default)]
    pub parents: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ModInfo {
    pub names: Vec<String>,
    pub what: String,
    /// Nazwa środowiska z kompilacją w locie, jeśli moduł nim jest.
    #[serde(default)]
    pub runtime: Option<String>,
}

/// Krok sprawdzenia regionu: co zrobić, jakim poleceniem i jak czytać wynik.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Step {
    /// Co zrobić, jednym zdaniem.
    pub what: String,
    /// Polecenie do uruchomienia; puste, gdy krok polega na obejrzeniu czegoś w narzędziu graficznym.
    pub cmd: String,
    /// Jak czytać wynik: co jest zwykłe, co powinno zaniepokoić, co zrobić dalej.
    pub look: String,
}

impl<'de> Deserialize<'de> for Step {
    /// Krok jako obiekt {"do", "cmd", "look"} albo, w starszych plikach, jako sam tekst.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Any { Text(String), Full { #[serde(rename = "do")] what: String, #[serde(default)] cmd: String, #[serde(default)] look: String } }
        Ok(match Any::deserialize(d)? { Any::Text(what) => Step { what, ..Default::default() }, Any::Full { what, cmd, look } => Step { what, cmd, look } })
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
struct Raw {
    #[serde(default)] version: String,
    #[serde(default)] guide: Vec<String>,
    #[serde(default)] severity: Map<String, Value>,
    #[serde(default)] sections: Map<String, Value>,
    #[serde(default)] tags: BTreeMap<String, TagInfo>,
    #[serde(default)] combos: Vec<Combo>,
    #[serde(default)] terms: Map<String, Value>,
    #[serde(default)] verify: BTreeMap<String, Vec<Step>>,
    #[serde(default)] flags: Map<String, Value>,
    #[serde(default)] handles: Map<String, Value>,
    #[serde(default)] socket_states: Map<String, Value>,
    #[serde(default)] processes: Vec<ProcInfo>,
    #[serde(default)] modules: Vec<ModInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct Kb {
    pub version: String,
    pub os: String,
    pub guide: Vec<String>,
    pub severity: Vec<(String, String)>,
    pub sections: Vec<(String, String)>,
    pub tags: BTreeMap<String, TagInfo>,
    pub combos: Vec<Combo>,
    pub terms: Vec<(String, String)>,
    pub verify: BTreeMap<String, Vec<Step>>,
    pub flags: Vec<(String, String)>,
    pub handles: Vec<(String, String)>,
    pub socket_states: Vec<(String, String)>,
    pub processes: Vec<ProcInfo>,
    pub modules: Vec<ModInfo>,
}

/// Scalanie: obiekty rekurencyjnie (plik systemu nadpisuje wspólny), tablice sklejane
/// (najpierw wpisy systemu, żeby miały pierwszeństwo przy wyszukiwaniu).
fn merge(base: Value, over: Value) -> Value {
    match (base, over) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = match b.remove(&k) { Some(old) => merge(old, v), None => v };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        (Value::Array(b), Value::Array(mut o)) => { o.extend(b); Value::Array(o) }
        (_, o) => o,
    }
}

fn pairs(m: Map<String, Value>) -> Vec<(String, String)> {
    m.into_iter().filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string()))).collect()
}

fn base_name(path: &str) -> &str { path.rsplit(['/', '\\']).next().unwrap_or(path) }

impl Kb {
    fn build(common: &str, system: Option<&str>, os: &str) -> Result<Kb, String> {
        let mut v: Value = serde_json::from_str(common).map_err(|e| format!("baza wiedzy (część wspólna): {e}"))?;
        if let Some(s) = system {
            let o: Value = serde_json::from_str(s).map_err(|e| format!("baza wiedzy ({os}): {e}"))?;
            v = merge(v, o);
        }
        let r: Raw = serde_json::from_value(v).map_err(|e| format!("baza wiedzy ({os}): {e}"))?;
        Ok(Kb { version: r.version, os: os.to_string(), guide: r.guide, severity: pairs(r.severity), sections: pairs(r.sections), tags: r.tags,
            combos: r.combos, terms: pairs(r.terms), verify: r.verify, flags: pairs(r.flags), handles: pairs(r.handles),
            socket_states: pairs(r.socket_states), processes: r.processes, modules: r.modules })
    }

    /// Baza wbudowana w binarium, w języku programu. System bez własnego pliku dostaje część wspólną.
    pub fn embedded(os: &str) -> Kb { Kb::embedded_lang(os, nanshe_core::lang::get()) }

    pub fn embedded_lang(os: &str, l: Lang) -> Kb {
        let (common, system) = match l {
            Lang::Pl => (COMMON, match os { "linux" => Some(LINUX), "windows" => Some(WINDOWS), "macos" => Some(MACOS), _ => None }),
            Lang::En => (COMMON_EN, match os { "linux" => Some(LINUX_EN), "windows" => Some(WINDOWS_EN), "macos" => Some(MACOS_EN), _ => None }),
        };
        Kb::build(common, system, os).expect("wbudowana baza wiedzy jest sprawdzana testem")
    }

    /// Baza z katalogu (`common.json` i `<system>.json`); brak pliku systemu nie jest błędem.
    /// Dla języka angielskiego używany jest podkatalog `en`, jeśli istnieje (układ jak w repozytorium).
    pub fn from_dir(dir: &std::path::Path, os: &str) -> Result<Kb, String> {
        let sub = dir.join(nanshe_core::lang::get().code());
        let dir = if nanshe_core::lang::get() != Lang::Pl && sub.join("common.json").is_file() { sub.as_path() } else { dir };
        let common = std::fs::read_to_string(dir.join("common.json")).map_err(|e| format!("{}: {e}", dir.join("common.json").display()))?;
        let system = std::fs::read_to_string(dir.join(format!("{os}.json"))).ok();
        Kb::build(&common, system.as_deref(), os)
    }

    /// Opis dokładnie tego zestawu tagów (kolejność bez znaczenia).
    pub fn combo(&self, tags: &[&str]) -> Option<&Combo> {
        let mut want: Vec<&str> = tags.to_vec();
        want.sort_unstable(); want.dedup();
        self.combos.iter().find(|c| { let mut have: Vec<&str> = c.tags.iter().map(String::as_str).collect(); have.sort_unstable(); have == want })
    }

    pub fn process(&self, name: &str) -> Option<&ProcInfo> {
        let n = name.to_lowercase();
        self.processes.iter().find(|p| p.names.iter().any(|x| *x == n))
    }

    /// Moduł po nazwie pliku: wpis pasuje, gdy nazwa pliku zaczyna się od wzorca (albo cała ścieżka,
    /// dla wzorców w rodzaju `memfd:`).
    pub fn module(&self, path: &str) -> Option<&ModInfo> {
        let (full, base) = (path.to_lowercase(), base_name(path).to_lowercase());
        self.modules.iter().find(|m| m.names.iter().any(|x| base.starts_with(x.as_str()) || full.starts_with(x.as_str())))
    }

    /// Objaśnienie cechy procesu; klucz bazy jest początkiem nazwy cechy.
    pub fn flag(&self, name: &str) -> Option<&str> {
        self.flags.iter().find(|(k, _)| name.starts_with(k.as_str())).map(|(_, v)| v.as_str())
    }

    pub fn lookup<'a>(list: &'a [(String, String)], key: &str) -> Option<&'a str> {
        list.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Czy plik programu leży w typowym miejscu. None tylko wtedy, gdy baza nie ma oczekiwań.
    /// Ścieżka sieciowa (UNC) albo ścieżka urządzenia nie jest typowym położeniem. Na Windows plik musi leżeć na
    /// dysku systemowym (`system_drive`, np. "c:"; domyślnie c:): `D:\Windows\System32\svchost.exe`
    /// nie jest typowym położeniem.
    pub fn path_expected(p: &ProcInfo, exe: &str, system_drive: Option<&str>) -> Option<bool> {
        if p.paths.is_empty() { return None; }
        let e = exe.to_lowercase();
        let e = e.strip_prefix("\\\\?\\").unwrap_or(&e);
        let rest = if e.as_bytes().get(1) == Some(&b':') {
            if !e[..2].eq_ignore_ascii_case(system_drive.unwrap_or("c:")) { return Some(false); }
            &e[2..]
        } else if e.starts_with("\\") { return Some(false); } else { e }; // UNC albo ścieżka urządzenia: znany program stamtąd nie jest typowy
        if rest.contains("\\..\\") || rest.contains("/../") { return Some(false); }
        let sep = |c: char| c == '/' || c == '\\';
        Some(p.paths.iter().any(|x| {
            if let Some(dir) = x.strip_suffix("**") { rest.starts_with(dir) && rest.len() > dir.len() }
            else if x.ends_with(sep) { rest.strip_prefix(x.as_str()).map(|tail| !tail.is_empty() && !tail.contains(sep)).unwrap_or(false) }
            else { rest == x }
        }))
    }

    pub fn parent_expected(p: &ProcInfo, parent: &str) -> Option<bool> {
        if p.parents.is_empty() { return None; }
        let n = parent.to_lowercase();
        Some(p.parents.iter().any(|x| *x == n))
    }

    /// Kroki sprawdzenia regionu: ogólne i dla jego tagów, z wstawionym numerem procesu i adresami.
    pub fn verify_steps(&self, tags: &[&str], pid: u32, start: u64, end: u64) -> Vec<Step> {
        let fill = |s: &str| s.replace("{pid}", &pid.to_string()).replace("{start_plain}", &format!("{start:x}"))
            .replace("{start}", &format!("{start:#x}")).replace("{end}", &format!("{end:#x}")).replace("{size}", &end.saturating_sub(start).to_string());
        let mut out: Vec<Step> = Vec::new();
        let keys = std::iter::once("*").chain(tags.iter().copied());
        for k in keys {
            for s in self.verify.get(k).into_iter().flatten() {
                let t = Step { what: fill(&s.what), cmd: fill(&s.cmd), look: fill(&s.look) };
                if !out.contains(&t) { out.push(t); }
            }
        }
        out
    }

    /// Słowniczek tagów po angielsku do zapytania do modelu: wszystkie systemy, stała kolejność.
    pub fn llm_glossary() -> String {
        let mut all: BTreeMap<String, String> = BTreeMap::new();
        for os in SYSTEMS { for (t, i) in Kb::embedded_lang(os, Lang::Pl).tags { all.entry(t).or_insert(i.en); } }
        // kolejność jak w dotychczasowym zapytaniu: od cech uprawnień do cech treści
        const ORDER: [&str; 11] = ["RWX", "X-PRIV", "X-MAP", "GUARD-X", "MEMFD", "DEL-EXEC", "X-TMP", "ENT-X", "HDR", "THR-PRIV", "IMG-MOD"];
        let mut keys: Vec<&String> = all.keys().collect();
        keys.sort_by_key(|k| ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()));
        format!("Tags: {}.", keys.iter().map(|k| format!("{k} = {}", all[*k])).collect::<Vec<_>>().join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wersja angielska ma dokładnie tę samą strukturę co polska: te same tagi, zestawy, kroki,
    /// procesy i moduły; różni się tylko tekstem. Bez tego raport angielski gubiłby objaśnienia.
    #[test]
    fn english_base_mirrors_the_polish_one() {
        for os in ["linux", "windows", "macos"] {
            let (pl, en) = (Kb::embedded_lang(os, Lang::Pl), Kb::embedded_lang(os, Lang::En));
            assert_eq!(pl.version, en.version, "{os}");
            assert_eq!(pl.tags.keys().collect::<Vec<_>>(), en.tags.keys().collect::<Vec<_>>(), "{os}");
            for (t, i) in &pl.tags { let e = &en.tags[t]; assert_eq!((&i.en, &i.attack, i.tech.is_empty()), (&e.en, &e.attack, e.tech.is_empty()), "{os}/{t}"); }
            assert_eq!(pl.combos.iter().map(|c| (&c.tags, c.benign.len(), c.malicious.len(), c.hints.iter().map(|h| h.runtime).collect::<Vec<_>>())).collect::<Vec<_>>(),
                en.combos.iter().map(|c| (&c.tags, c.benign.len(), c.malicious.len(), c.hints.iter().map(|h| h.runtime).collect::<Vec<_>>())).collect::<Vec<_>>(), "{os}");
            // te same kroki z tymi samymi poleceniami; opis i wskazówka są w obu językach
            assert_eq!(pl.verify.iter().map(|(k, v)| (k, v.iter().map(|s| &s.cmd).collect::<Vec<_>>())).collect::<Vec<_>>(), en.verify.iter().map(|(k, v)| (k, v.iter().map(|s| &s.cmd).collect::<Vec<_>>())).collect::<Vec<_>>(), "{os}");
            for v in pl.verify.values().chain(en.verify.values()) { for s in v { assert!(!s.what.is_empty() && !s.look.is_empty(), "{os}: krok bez opisu albo wskazówki: {s:?}"); } }
            assert_eq!(pl.processes.iter().map(|p| (&p.names, &p.paths, &p.parents)).collect::<Vec<_>>(), en.processes.iter().map(|p| (&p.names, &p.paths, &p.parents)).collect::<Vec<_>>(), "{os}");
            assert_eq!(pl.modules.iter().map(|m| (&m.names, &m.runtime)).collect::<Vec<_>>(), en.modules.iter().map(|m| (&m.names, &m.runtime)).collect::<Vec<_>>(), "{os}");
            assert_eq!((pl.guide.len(), pl.sections.len(), pl.terms.len(), pl.flags.len()), (en.guide.len(), en.sections.len(), en.terms.len(), en.flags.len()), "{os}");
            let keys = |v: &[(String, String)]| { let mut k: Vec<String> = v.iter().map(|x| x.0.clone()).collect(); k.sort(); k };
            assert_eq!(keys(&pl.severity), keys(&en.severity), "{os}");
            assert_eq!(keys(&pl.handles), keys(&en.handles), "{os}");
            assert_eq!(keys(&pl.socket_states), keys(&en.socket_states), "{os}");
            let text = format!("{en:?}");
            assert!(!text.chars().any(|c| "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ\u{2014}\u{2013}".contains(c)), "{os}: polskie znaki albo długie myślniki w wersji angielskiej");
        }
    }

    /// Tagi, które potrafią zgłosić detektory na danym systemie.
    fn detector_tags(os: &str) -> Vec<&'static str> {
        match os {
            "linux" => vec!["RWX", "X-PRIV", "ENT-X", "HDR", "THR-PRIV", "IMG-MOD", "MEMFD", "DEL-EXEC", "X-TMP"],
            "windows" => vec!["RWX", "X-PRIV", "ENT-X", "HDR", "THR-PRIV", "IMG-MOD", "X-MAP", "GUARD-X"],
            _ => vec!["RWX", "X-PRIV", "ENT-X", "HDR", "THR-PRIV", "IMG-MOD"],
        }
    }

    #[test]
    fn every_system_explains_every_tag_its_detectors_can_raise() {
        for os in ["linux", "windows", "macos", "freebsd"] {
            let kb = Kb::embedded(os);
            for t in detector_tags(os) {
                let i = kb.tags.get(t).unwrap_or_else(|| panic!("{os}: brak opisu tagu {t}"));
                assert!(!i.name.is_empty() && !i.en.is_empty() && i.meaning.len() > 40 && i.why.len() > 40, "{os}/{t}");
                // systemy z własnym plikiem mają dla każdego tagu warstwę techniczną; identyfikatory ATT&CK mają poprawną postać
                if SYSTEMS.contains(&os) { assert!(i.tech.len() > 30, "{os}/{t}: brak warstwy technicznej"); }
                for a in &i.attack { let id = a.split(' ').next().unwrap_or(""); assert!(id.starts_with('T') && id[1..].chars().all(|c| c.is_ascii_digit() || c == '.') && a.len() > id.len() + 3, "{os}/{t}: {a}"); }
                // każdy tag występujący samotnie ma albo opis zestawu, albo wystarczy opis tagu
            }
            assert!(!kb.guide.is_empty() && kb.severity.len() == 3 && kb.sections.len() >= 8 && kb.terms.len() >= 10, "{os}");
        }
        // systemy z własnym plikiem mają kroki sprawdzenia dla każdego tagu albo ogólne
        for os in SYSTEMS {
            let kb = Kb::embedded(os);
            assert!(kb.verify.get("*").map(|v| v.len() >= 2).unwrap_or(false), "{os}: brak ogólnych kroków sprawdzenia");
            assert!(!kb.processes.is_empty() && !kb.modules.is_empty(), "{os}");
            // cechy procesu i rodzaje uchwytów opisują kontekst systemowy, którego na macOS skaner jeszcze nie zbiera
            if os != "macos" { assert!(!kb.flags.is_empty() && !kb.handles.is_empty(), "{os}"); }
        }
    }

    #[test]
    fn combos_reference_known_tags_and_are_unambiguous() {
        for os in SYSTEMS {
            let kb = Kb::embedded(os);
            let mut seen: Vec<Vec<String>> = Vec::new();
            for c in &kb.combos {
                for t in &c.tags { assert!(kb.tags.contains_key(t), "{os}: zestaw z nieznanym tagiem {t}"); }
                let mut k = c.tags.clone(); k.sort();
                assert!(!seen.contains(&k), "{os}: dwa opisy zestawu {k:?}");
                seen.push(k);
                assert!(!c.title.is_empty() && c.meaning.len() > 30 && !c.benign.is_empty() && !c.malicious.is_empty(), "{os}: {:?}", c.tags);
            }
            for k in kb.verify.keys() { assert!(k == "*" || kb.tags.contains_key(k), "{os}: kroki dla nieznanego tagu {k}"); }
        }
        let kb = Kb::embedded("linux");
        assert_eq!(kb.combo(&["X-PRIV", "RWX"]).map(|c| c.title.as_str()), Some("kod tworzony w trakcie pracy"), "kolejność tagów bez znaczenia");
        assert!(kb.combo(&["RWX"]).is_none() && kb.combo(&["X-MAP"]).is_none() && kb.combo(&["IMG-MOD"]).is_some(), "zestaw Windows nie przecieka do Linuksa");
        assert!(Kb::embedded("windows").combo(&["X-MAP"]).is_some());
    }

    #[test]
    fn text_is_plain_and_placeholders_are_filled() {
        for (name, raw) in [("common", COMMON), ("linux", LINUX), ("windows", WINDOWS)] {
            assert!(!raw.contains('\u{2014}') && !raw.contains('\u{2013}'), "{name}: długi myślnik w treści");
        }
        let kb = Kb::embedded("linux");
        let steps = kb.verify_steps(&["HDR", "X-PRIV"], 663, 0xffff_a420_3000, 0xffff_a420_7000);
        assert!(steps.len() >= 4);
        assert!(steps.iter().any(|s| s.cmd.contains("gdb -p 663") && s.cmd.contains("0xffffa4203000 0xffffa4207000")), "{steps:?}");
        assert!(steps.iter().any(|s| s.cmd.contains("readelf -h /tmp/region_ffffa4203000.bin")));
        let all = |s: &Step| format!("{} {} {}", s.what, s.cmd, s.look);
        assert!(steps.iter().all(|s| !all(s).contains('{')), "niewypełnione pole: {steps:?}");
        // każdy krok mówi, co zrobić i jak czytać wynik; polecenie może być puste tylko dla kroku w narzędziu graficznym
        assert!(steps.iter().all(|s| s.what.len() > 15 && s.look.len() > 40), "{steps:?}");
        // kontrola: krok dla innego tagu się nie pojawia
        let memfd = kb.verify_steps(&["MEMFD"], 663, 0xffff_a420_3000, 0xffff_a420_7000);
        assert!(memfd.iter().any(|m| !steps.contains(m)) && memfd.iter().filter(|m| !steps.contains(m)).all(|m| !steps.iter().any(|s| s.cmd == m.cmd && !m.cmd.is_empty())));
        // starszy zapis kroku (sam tekst) nadal się wczytuje
        let old = Kb::build(r#"{"verify":{"*":["Zrób coś: polecenie {pid}"]}}"#, None, "linux").unwrap();
        assert_eq!(old.verify_steps(&[], 7, 0, 0), vec![Step { what: "Zrób coś: polecenie 7".into(), cmd: String::new(), look: String::new() }]);
        for os in SYSTEMS {
            let kb = Kb::embedded(os);
            let tags: Vec<&str> = kb.tags.keys().map(String::as_str).collect();
            assert!(kb.verify_steps(&tags, 1, 0x1000, 0x2000).iter().all(|s| !format!("{} {} {}", s.what, s.cmd, s.look).contains('{')), "{os}");
        }
    }

    #[test]
    fn processes_modules_and_expectations() {
        let w = Kb::embedded("windows");
        let sv = w.process("SVCHOST.EXE").expect("svchost");
        assert_eq!(Kb::path_expected(sv, "C:\\Windows\\System32\\svchost.exe", None), Some(true));
        assert_eq!(Kb::path_expected(sv, "\\\\?\\C:\\Windows\\System32\\svchost.exe", Some("c:")), Some(true));
        assert_eq!(Kb::path_expected(sv, "C:\\Users\\jan\\AppData\\svchost.exe", None), Some(false), "podszywanie się pod nazwę");
        assert_eq!(Kb::path_expected(sv, "C:\\Windows\\System32\\evil\\svchost.exe", None), Some(false));
        // ten sam układ katalogów na innym dysku to nie jest typowe położenie
        assert_eq!(Kb::path_expected(sv, "D:\\Windows\\System32\\svchost.exe", None), Some(false));
        assert_eq!(Kb::path_expected(sv, "D:\\Windows\\System32\\svchost.exe", Some("D:")), Some(true), "system zainstalowany na D:");
        assert_eq!(Kb::path_expected(sv, "C:\\Windows\\System32\\svchost.exe.evil", None), Some(false), "wpis pliku to dokładna ścieżka");
        assert_eq!(Kb::path_expected(sv, "C:\\Windows\\Temp\\..\\System32\\svchost.exe", None), Some(false));
        assert_eq!(Kb::path_expected(sv, "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe", None), Some(false), "ścieżka urządzenia nie jest typowym położeniem");
        assert_eq!(Kb::path_expected(sv, "\\\\serwer\\udzial\\Windows\\System32\\svchost.exe", None), Some(false), "znany program z udziału sieciowego");
        // katalog: tylko pliki bezpośrednio w nim; `**`: dowolnie głęboko
        let wi = w.process("wininit.exe").expect("wininit");
        assert_eq!((Kb::path_expected(wi, "C:\\Windows\\System32\\wininit.exe", None), Kb::path_expected(wi, "C:\\Windows\\System32\\spool\\drivers\\color\\wininit.exe", None)), (Some(true), Some(false)));
        let ps = w.process("powershell.exe").expect("powershell");
        assert_eq!(Kb::path_expected(ps, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", None), Some(true));
        assert_eq!(Kb::path_expected(ps, "C:\\Windows\\System32\\powershell.exe", None), Some(false));
        let sshd = Kb::embedded("linux").process("sshd").unwrap().clone();
        assert_eq!((Kb::path_expected(&sshd, "/usr/sbin/sshd", None), Kb::path_expected(&sshd, "/tmp/sshd", None), Kb::path_expected(&sshd, "/usr/sbin/sshd/x", None)), (Some(true), Some(false), Some(false)));
        assert_eq!((Kb::parent_expected(sv, "services.exe"), Kb::parent_expected(sv, "WINWORD.EXE")), (Some(true), Some(false)));
        let teams = w.process("teams.exe").expect("teams");
        assert_eq!((Kb::path_expected(teams, "C:\\x", None), Kb::parent_expected(teams, "x")), (None, None), "brak oczekiwań to brak oceny");
        assert!(w.process("nieznany.exe").is_none());
        assert_eq!(w.module("\\Device\\HarddiskVolume3\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll").and_then(|m| m.runtime.as_deref()), Some(".NET Framework"));
        assert!(w.module("C:\\Windows\\System32\\clrjit.dll").map(|m| m.runtime.is_none()).unwrap_or(false), "clrjit nie może pasować do wzorca clr.dll");
        let l = Kb::embedded("linux");
        assert!(l.module("/usr/lib/aarch64-linux-gnu/libc.so.6").is_some() && l.module("memfd:payload").is_some() && l.module("/opt/app/libcustom.so").is_none());
        assert_eq!(l.module("/usr/lib/jvm/lib/server/libjvm.so").and_then(|m| m.runtime.as_deref()), Some("Java"));
        assert!(l.flag("uprawnienia efektywne (CapEff)").is_some() && l.flag("zmienna LD_PRELOAD").is_some() && l.flag("nieznana cecha").is_none());
        assert!(w.flag("poziom integralności").is_some());
    }

    #[test]
    fn merge_and_external_directory() {
        // plik systemu nadpisuje wpis wspólny i dokłada własne
        let common = r#"{"version":"1","tags":{"A":{"name":"a","en":"a","meaning":"m","why":"w"}},"combos":[{"tags":["A"],"title":"wspólny","meaning":"m"}],"terms":{"x":"wspólne"}}"#;
        let sys = r#"{"tags":{"B":{"name":"b","en":"b","meaning":"m","why":"w"}},"combos":[{"tags":["A"],"title":"systemowy","meaning":"m"}],"terms":{"x":"systemowe","y":"nowe"}}"#;
        let kb = Kb::build(common, Some(sys), "t").unwrap();
        assert_eq!(kb.tags.len(), 2);
        assert_eq!(kb.combo(&["A"]).unwrap().title, "systemowy", "wpis systemu ma pierwszeństwo");
        assert_eq!(kb.terms, vec![("x".to_string(), "systemowe".to_string()), ("y".to_string(), "nowe".to_string())]);
        assert!(Kb::build("{", None, "t").is_err() && Kb::build(common, Some("[1]"), "t").is_err());
        // katalog zewnętrzny: brak pliku systemu daje część wspólną, brak części wspólnej to błąd
        let dir = std::env::temp_dir().join(format!("nanshe-kb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(Kb::from_dir(&dir, "linux").is_err());
        std::fs::write(dir.join("common.json"), common).unwrap();
        assert_eq!(Kb::from_dir(&dir, "linux").unwrap().combo(&["A"]).unwrap().title, "wspólny");
        std::fs::write(dir.join("linux.json"), sys).unwrap();
        assert_eq!(Kb::from_dir(&dir, "linux").unwrap().combo(&["A"]).unwrap().title, "systemowy");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn llm_glossary_covers_all_tags_in_stable_order() {
        let g = Kb::llm_glossary();
        for t in ["RWX", "X-PRIV", "X-MAP", "GUARD-X", "MEMFD", "DEL-EXEC", "X-TMP", "ENT-X", "HDR", "THR-PRIV", "IMG-MOD"] { assert!(g.contains(&format!("{t} = ")), "{t}"); }
        assert!(g.find("RWX = ").unwrap() < g.find("HDR = ").unwrap() && g.starts_with("Tags: ") && g.ends_with('.'));
        assert_eq!(g, Kb::llm_glossary());
    }
}
