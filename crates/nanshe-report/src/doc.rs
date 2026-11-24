//! Raport dla człowieka: wynik skanu (deterministyczny) plus opcjonalna interpretacja LLM.
//! Tu powstaje model dokumentu; `md` i `pdf` tylko go rysują, więc oba formaty mają tę samą treść.
use nanshe_core::*;
use nanshe_core::{tr, trf};
use nanshe_kb::Kb;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub enum Block {
    H1(String),
    H2(String),
    H3(String),
    Para(String),
    /// Zastrzeżenie albo ostrzeżenie w ramce.
    Note(String),
    Bullets(Vec<String>),
    /// `widths`: wagi szerokości kolumn (PDF).
    Table { head: Vec<String>, rows: Vec<Vec<String>>, widths: Vec<f32> },
    KeyVals(Vec<(String, String)>),
    /// Diagram przestrzeni adresowej procesu: wiersze od najniższego adresu.
    MemMap(Vec<MapRow>),
    /// Drzewo procesów (przodkowie, badany proces, dzieci).
    Tree(Vec<TreeNode>),
    /// Podgląd bajtów: adres pierwszego bajtu i dane.
    Hex { base: u64, bytes: Vec<u8> },
    /// Profil entropii regionu: komórki w dziesiątych częściach bita, od początku regionu.
    Heat { base: u64, size: u64, cells: Vec<u8> },
    /// Wykres słupkowy: (etykieta, wartość).
    Bars(Vec<(String, u32)>),
    /// Macierz procesy x cechy: w komórce liczba regionów z cechą i najwyższa waga.
    Matrix { cols: Vec<String>, rows: Vec<(String, Vec<(u32, Severity)>)> },
    /// Wykres rozrzutu regionów procesu: (rozmiar w bajtach, entropia 0-8, waga).
    Scatter(Vec<(u64, f32, Severity)>),
    /// Łańcuch pamięć -> proces -> sieć: regiony ze znaleziskami (opis, waga), proces, połączenia
    /// (opis, czy połączenie z adresem zdalnym).
    Flow { regions: Vec<(String, Severity)>, process: String, endpoints: Vec<(String, bool)> },
    /// Spis treści: (tytuł rozdziału głównego, kotwica) w kolejności. W PDF dostaje numery stron.
    Toc(Vec<(String, String)>),
    /// Kroki sprawdzenia: co zrobić, polecenie (wyróżnione) i jak czytać wynik.
    Steps(Vec<StepLine>),
    /// Cel odnośnika wewnątrz dokumentu; dotyczy nagłówka, który następuje po nim.
    Anchor(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct StepLine { pub what: String, pub cmd: String, pub look: String }

/// Znak na początku wartości w tabeli pól: wartość jest poleceniem albo wierszem poleceń
/// i ma być wyróżniona jako kod.
pub const CODE: char = '\u{1}';

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MapClass { Code, File, Anon, Heap, Stack, Special, Gap, Collapsed, Finding(Severity) }

#[derive(Clone, Debug, PartialEq)]
pub struct MapRow {
    pub start: u64,
    pub end: u64,
    /// suma rozmiarów mapowań w wierszu (dla przerwy: jej długość)
    pub size: u64,
    pub prot: String,
    pub what: String,
    pub note: String,
    pub class: MapClass,
    /// Kotwica opisu tego regionu w dalszej części raportu (dla regionów ze szczegółowym opisem).
    pub link: Option<String>,
}

/// Kotwica opisu regionu.
pub fn region_anchor(pid: &str, base: u64) -> String { format!("r-{pid}-{base:x}") }

#[derive(Clone, Debug, PartialEq)]
pub struct TreeNode { pub depth: u8, pub text: String, pub mark: bool }

pub fn class_label(c: MapClass) -> &'static str {
    match c {
        MapClass::Code => tr!("kod z pliku", "code from file"), MapClass::File => tr!("dane z pliku", "data from file"), MapClass::Anon => tr!("pamięć anonimowa", "anonymous memory"), MapClass::Heap => tr!("sterta", "heap"),
        MapClass::Stack => tr!("stos", "stack"), MapClass::Special => tr!("region jądra", "kernel region"), MapClass::Gap => tr!("przerwa", "gap"), MapClass::Collapsed => tr!("zwinięte", "collapsed"),
        MapClass::Finding(Severity::High) => tr!("ZNALEZISKO (wysokie)", "FINDING (high)"), MapClass::Finding(Severity::Suspicious) => tr!("ZNALEZISKO (podejrzane)", "FINDING (suspicious)"), MapClass::Finding(_) => tr!("znalezisko (info)", "finding (info)"),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Doc {
    pub title: String,
    pub subtitle: String,
    /// Stopka każdej strony PDF.
    pub footer: String,
    pub blocks: Vec<Block>,
}

pub struct Options {
    pub min: Severity,
    /// SHA-256 pliku wyniku, jeśli znany (wiąże raport z konkretnym wynikiem).
    pub result_sha256: Option<String>,
    /// Nazwa pliku wyniku do pokazania w raporcie.
    pub result_name: Option<String>,
    /// Katalog z bazą wiedzy używaną zamiast wbudowanej.
    pub kb_dir: Option<std::path::PathBuf>,
}

const MAX_CELL: usize = 600;
/// Ile regionów jednego procesu dostaje pełny opis (sąsiedzi, profil entropii, bajty, ciągi, LLM).
pub const DETAIL_PER_PROCESS: usize = 6;

/// Tekst z badanego procesu albo od modelu: bez znaków sterujących, z limitem długości.
pub(crate) fn clean(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > MAX_CELL { format!("{}...", t.chars().take(MAX_CELL).collect::<String>()) } else { t }
}

pub fn size_h(b: u64) -> String {
    if b >= 1 << 40 { format!("{:.1} TiB", b as f64 / (1u64 << 40) as f64) }
    else if b >= 1 << 30 { format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64) }
    else if b >= 1 << 20 { format!("{:.1} MiB", b as f64 / (1u64 << 20) as f64) }
    else { format!("{} KiB", b / 1024) }
}

fn tag_gloss(tag: &str) -> &'static str {
    match tag {
        "RWX" => tr!("region jednocześnie zapisywalny i wykonywalny", "region both writable and executable"),
        "X-PRIV" => tr!("wykonywalna pamięć prywatna/anonimowa bez pliku źródłowego", "executable private/anonymous memory not backed by a file"),
        "X-MAP" => tr!("wykonywalne mapowanie, które nie jest obrazem załadowanego modułu (Windows)", "executable mapping that is not the image of a loaded module (Windows)"),
        "GUARD-X" => tr!("wykonywalny region za strażnikiem (PAGE_GUARD); treść celowo nieodczytana", "executable region behind a guard page (PAGE_GUARD); contents deliberately not read"),
        "MEMFD" => tr!("wykonywalne mapowanie memfd (plik istniejący tylko w pamięci)", "executable memfd mapping (a file that exists only in memory)"),
        "DEL-EXEC" => tr!("wykonywalne mapowanie pliku usuniętego z dysku", "executable mapping of a file deleted from disk"),
        "X-TMP" => tr!("wykonywalne mapowanie pliku z katalogu zapisywalnego dla wszystkich, np. /tmp (Linux)", "executable mapping of a file from a world-writable directory, e.g. /tmp (Linux)"),
        "ENT-X" => tr!("wysoka entropia w regionie wykonywalnym (kod spakowany lub zaszyfrowany)", "high entropy in an executable region (packed or encrypted code)"),
        "HDR" => tr!("nagłówek obrazu PE/ELF/Mach-O w pamięci bez pliku źródłowego", "PE/ELF/Mach-O image header in memory not backed by a file"),
        "THR-PRIV" => tr!("wątek ulokowany w pamięci bez pliku źródłowego", "thread located in memory not backed by a file"),
        "IMG-MOD" => tr!("kod z pliku zmieniony w pamięci", "code from a file changed in memory"),
        _ => "",
    }
}

fn label_gloss(l: &str) -> &'static str {
    match l {
        "jit" => tr!("kompilacja JIT", "JIT compilation"),
        "packer" => tr!("kod spakowany lub zaszyfrowany", "packed or encrypted code"),
        "reflective-load" => tr!("obraz załadowany z pamięci", "image loaded from memory"),
        "hollowing" => tr!("podmiana obrazu procesu", "process image replacement"),
        "shellcode-stager" => tr!("shellcode lub etap ładujący", "shellcode or a loader stage"),
        "fileless-exec" => tr!("wykonanie bez pliku na dysku", "execution without a file on disk"),
        "benign-unknown" => tr!("prawdopodobnie łagodne, przyczyna nieznana", "probably benign, cause unknown"),
        "unknown" => tr!("nieokreślone", "undetermined"),
        _ => "",
    }
}

fn confidence_pl(c: &str) -> &str {
    match c { "established" => tr!("ustalone z danych", "established from data"), "assessed" => tr!("osąd modelu", "model's judgement"), "unconfirmed" => tr!("niepotwierdzone", "unconfirmed"), x => x }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(clean).collect()
}

/// Interpretacja musi dotyczyć tego samego wyniku skanu.
pub fn check_llm_matches(llm: &Value, result_sha256: &str) -> Result<()> {
    match llm["header"]["result_sha256"].as_str() {
        Some(h) if h == result_sha256 => Ok(()),
        Some(h) => Err(Error::Invalid(trf!("interpretacja LLM dotyczy innego wyniku skanu (sha256 {}..., a ten wynik ma {}...)", "the LLM interpretation belongs to a different scan result (sha256 {}..., this result has {}...)", &h[..h.len().min(12)], &result_sha256[..result_sha256.len().min(12)]))),
        None => Err(Error::Invalid(tr!("plik interpretacji LLM bez nagłówka result_sha256", "LLM interpretation file has no result_sha256 header").into())),
    }
}

pub fn build(scan: &ScanResult, llm: Option<&Value>, o: &Options) -> Doc {
    let mut b: Vec<Block> = Vec::new();
    let flagged: Vec<&ProcessReport> = scan.processes.iter().filter(|p| p.max_severity >= o.min && p.max_severity > Severity::None).collect();
    let failed: Vec<&ProcessReport> = scan.processes.iter().filter(|p| p.error.is_some()).collect();
    let unreadable: u64 = scan.processes.iter().map(|p| p.regions_unreadable).sum();

    // --- metryka
    let mut kv = vec![
        ("Host".to_string(), clean(&scan.host)),
        (tr!("Czas skanu", "Scan time").to_string(), clean(&scan.timestamp)),
        (tr!("Narzędzie", "Tool").to_string(), format!("nanshe {}", clean(&scan.tool_version))),
        (tr!("Procesy", "Processes").to_string(), trf!("{} przeskanowanych, {} ze znaleziskami od poziomu „{}\"", "{} scanned, {} with findings at severity \"{}\" or above", scan.processes.len(), flagged.len(), crate::sev_label(o.min))),
        (tr!("Znaleziska", "Findings").to_string(), scan.finding_count().to_string()),
        (tr!("Kompletność", "Completeness").to_string(), if scan.partial {
            trf!("WYNIK CZĘŚCIOWY: {} procesów niedostępnych, {} regionów nieodczytanych", "PARTIAL RESULT: {} processes inaccessible, {} regions not read", failed.len(), unreadable)
        } else { tr!("pełny", "complete").into() }),
    ];
    if let Some(h) = &scan.host_info {
        let os = [h.os.as_deref(), h.kernel.as_deref().map(|k| k)].iter().flatten().map(|s| clean(s)).collect::<Vec<_>>().join(tr!(", jądro/wersja ", ", kernel/version "));
        if !os.is_empty() { kv.push((tr!("System hosta", "Host operating system").into(), os)); }
        if let Some(t) = &h.boot { kv.push((tr!("Start systemu", "System boot").into(), clean(t))); }
        if let Some(u) = &h.scanner_user { kv.push((tr!("Skan wykonał", "Scan run by").into(), clean(u))); }
        if let Some(p) = &h.scanner_privileges { kv.push((tr!("Uprawnienia skanera", "Scanner privileges").into(), clean(p))); }
    }
    kv.push((tr!("Klasyfikacja", "Classification").into(), tr!("Poufne: dokument zawiera dane z badanej stacji; udostępniać wyłącznie osobom prowadzącym analizę", "Confidential: this document contains data from the examined host; share only with those conducting the analysis").into()));
    if let Some(n) = &o.result_name { kv.push((tr!("Plik wyniku", "Result file").into(), clean(n))); }
    if let Some(h) = &o.result_sha256 { kv.push((tr!("SHA-256 wyniku", "Result SHA-256").into(), h.clone())); }
    b.push(Block::KeyVals(kv));

    if scan.host_info.as_ref().map(|h| h.scanner_limited).unwrap_or(false) {
        b.push(Block::Note(tr!("UWAGA: skan wykonano bez pełnych uprawnień. Procesy innych użytkowników i usługi systemowe mogły być niedostępne tylko z tego powodu, więc brak znalezisk znaczy tu mniej niż zwykle. Do analizy powłamaniowej skan trzeba powtórzyć jako administrator z podniesionymi uprawnieniami (Windows) albo jako root (Linux).", "WARNING: the scan was run without full privileges. Processes of other users and system services may have been inaccessible for that reason alone, so the absence of findings means less than usual here. For post-incident analysis, repeat the scan as an elevated administrator (Windows) or as root (Linux).").into()));
    }
    let scan_lang = scan.lang.as_deref().and_then(lang::Lang::parse).unwrap_or(lang::Lang::Pl);
    if scan_lang != lang::get() {
        b.push(Block::Note(tr!("Skan wykonano w innym języku niż język raportu. Opisy zapisane w wyniku skanu (uzasadnienia znalezisk, cechy procesu, uwagi skanera) pozostają w języku skanu, a objaśnienia cech procesu z bazy wiedzy mogą być niedostępne. Aby uzyskać raport w całości w jednym języku, wykonaj skan z tą samą opcją --lang.",
            "The scan was run in a different language from the report language. Descriptions recorded in the scan result (finding reasons, process attributes, scanner notes) remain in the scan language, and knowledge-base explanations of process attributes may be unavailable. For a report entirely in one language, run the scan with the same --lang option.").into()));
    }
    b.push(Block::Note(tr!("To wynik triage, nie werdykt. Znaleziska wskazują miejsca warte ręcznej analizy; ich brak nie dowodzi, że proces jest czysty. Nazwy procesów, ścieżki i opisy pochodzą z badanego systemu i mogą być kontrolowane przez atakującego.", "This is a triage result, not a verdict. Findings point to places that merit manual analysis; their absence does not prove a process is clean. Process names, paths and descriptions come from the examined system and may be controlled by an attacker.").into()));

    if scan.processes.iter().any(|p| p.context.is_some() || p.regions.iter().any(|r| !r.strings.is_empty())) {
        b.push(Block::Note(tr!("Raport zawiera dane z badanej stacji bez filtrowania: wiersze poleceń, ścieżki, adresy sieciowe, bajty i ciągi tekstowe z pamięci. Mogą wśród nich być hasła i klucze. Traktuj ten dokument jak materiał dowodowy.", "The report contains unfiltered data from the examined host: command lines, paths, network addresses, bytes and text strings from memory. These may include passwords and keys. Treat this document as evidence.").into()));

    }

    // --- baza wiedzy: objaśnienia prostym językiem dla systemu, z którego pochodzi wynik
    let os = scan.processes.iter().find(|p| p.max_severity > Severity::None).or(scan.processes.first()).map(|p| p.info.os.as_str()).unwrap_or("linux");
    let kb = o.kb_dir.as_deref().and_then(|d| Kb::from_dir(d, os).ok()).unwrap_or_else(|| Kb::embedded(os));
    let toc_at = b.len();
    executive_summary(&mut b, scan, &kb, o, &flagged, &failed, unreadable);

    if let Some(l) = llm {
        let h = &l["header"];
        b.push(Block::H1(tr!("Interpretacja LLM: parametry", "LLM interpretation: parameters").into()));
        b.push(Block::Note(tr!("Sekcje oznaczone „Interpretacja LLM\" są niedeterministyczne i wymagają weryfikacji przez analityka. Model nie zmienia punktacji ani wagi znalezisk; widzi wyłącznie dane opisane poziomem danych poniżej.", "Sections marked \"LLM interpretation\" are non-deterministic and require verification by an analyst. The model does not change the score or severity of findings; it sees only the data described by the data level below.").into()));

        let u = &h["usage"];
        b.push(Block::KeyVals(vec![
            ("Model".into(), format!("{} (backend: {})", clean(h["model"].as_str().unwrap_or("?")), clean(h["backend"].as_str().unwrap_or("?")))),
            (tr!("Gdzie przetwarzano", "Where processed").into(), if h["cloud"] == true {
                // Na poziomie d0 do modelu nie idą ścieżki, nazwy ani ciągi, więc zwykle nie ma czego podmieniać.
                if h["data_level"] == "d0" && h["pseudonymized_values"] == 0 { tr!("chmura, poza własną infrastrukturą; wysłano same metadane regionów (poziom d0: bez nazwy hosta, ścieżek użytkowników, nazw procesów i ciągów z pamięci), więc nie było wartości do podmiany", "cloud, outside your own infrastructure; only region metadata was sent (level d0: no host name, user paths, process names or strings from memory), so there were no values to substitute").to_string() }
                else { trf!("chmura, poza własną infrastrukturą; podmienionych wartości (host, użytkownicy, adresy IP): {}", "cloud, outside your own infrastructure; substituted values (host, users, IP addresses): {}", h["pseudonymized_values"]) }
            } else { tr!("lokalnie (własna infrastruktura)", "locally (own infrastructure)").into() }),
            (tr!("Poziom danych", "Data level").into(), match h["data_level"].as_str() { Some("d0") => tr!("d0: same metadane", "d0: metadata only").into(), Some("d1") => tr!("d1: metadane, ciągi po filtrze sekretów, nazwy", "d1: metadata, strings after the secret filter, names").into(), Some("d2") => tr!("d2: także surowe bajty", "d2: raw bytes as well").into(), x => x.unwrap_or("?").to_string() }),
            (tr!("Próbkowanie", "Sampling").into(), if h["params"]["temperature"].is_null() { tr!("domyślne modelu (wynik może się różnić między przebiegami)", "model default (output may differ between runs)").into() } else { trf!("temperatura {}, ziarno {}", "temperature {}, seed {}", h["params"]["temperature"], h["params"]["seed"]) }),
            (tr!("Wersja promptu", "Prompt version").into(), clean(h["prompt_version"].as_str().unwrap_or("?"))),
            (tr!("Zapytania", "Requests").into(), trf!("{} (z pamięci podręcznej: {}), tokeny: {} wejścia, {} wyjścia", "{} (from cache: {}), tokens: {} input, {} output", u["calls"], u["cache_hits"], u["prompt_tokens"], u["output_tokens"])),
            (tr!("Czas interpretacji", "Interpretation time").into(), clean(h["timestamp"].as_str().unwrap_or("?"))),
        ]));
    }

    b.push(Block::H1(tr!("Jak czytać ten raport", "How to read this report").into()));
    for g in &kb.guide { b.push(Block::Para(g.clone())); }
    b.push(Block::Table { head: [tr!("Waga", "Severity"), tr!("Co oznacza", "Meaning")].map(String::from).to_vec(),
        rows: [(Severity::High, "high"), (Severity::Suspicious, "suspicious"), (Severity::Info, "info")].iter()
            .map(|(s, k)| vec![crate::sev_label(*s).to_string(), Kb::lookup(&kb.severity, k).unwrap_or("").to_string()]).collect(), widths: vec![1.2, 6.0] });
    b.push(Block::Table { head: [tr!("Część raportu", "Report section"), tr!("Co pokazuje i na co patrzeć", "What it shows and what to look for")].map(String::from).to_vec(),
        rows: kb.sections.iter().map(|(k, v)| vec![k.clone(), v.clone()]).collect(), widths: vec![1.8, 6.0] });

    // --- podsumowanie
    b.push(Block::H1(tr!("Przegląd procesów", "Process overview").into()));
    if flagged.is_empty() {
        b.push(Block::Para(trf!("Brak znalezisk od poziomu „{}\" w {} przeskanowanych procesach.", "No findings at severity \"{}\" or above in {} scanned processes.", crate::sev_label(o.min), scan.processes.len())));
    } else {
        let mut order = flagged.clone();
        order.sort_by(|a, c| priority(a, &kb, o.min).0.cmp(priority(c, &kb, o.min).0).then(c.max_severity.cmp(&a.max_severity)).then(top_score(c, o.min).cmp(&top_score(a, o.min))).then(a.info.pid.cmp(&c.info.pid)));
        // procesy tego samego programu o identycznych cechach zajmują jeden wiersz i jeden rozdział
        let groups = group_similar(&order, &kb, o.min);
        let rows = groups.iter().map(|g| {
            let p = g[0];
            let regs = shown_regions(p, o.min);
            let mut tags: Vec<&str> = regs.iter().flat_map(|r| r.findings.iter().map(|f| f.tag.as_str())).collect();
            tags.sort(); tags.dedup();
            let pid = if g.len() > 1 { format!("{} (+{})", pid_s(p), g.len() - 1) } else { pid_s(p) };
            vec![priority(p, &kb, o.min).0.to_string(), pid, clean(p.info.name.as_deref().unwrap_or("?")), crate::sev_label(p.max_severity).to_string(),
                regs.len().to_string(), top_score(p, o.min).to_string(), tags.join(", ")]
        }).collect();
        b.push(Block::Table { head: [tr!("Priorytet", "Priority"), "PID", tr!("Proces", "Process"), tr!("Waga", "Severity"), tr!("Regiony", "Regions"), tr!("Maks. pkt", "Max pts"), tr!("Tagi", "Tags")].map(String::from).to_vec(), rows, widths: vec![1.1, 0.9, 2.5, 1.3, 1.0, 1.1, 3.0] });
        if groups.len() < order.len() {
            b.push(Block::Para(trf!("Procesów do weryfikacji jest {}, w {} grupach: procesy tego samego programu z tym samym zestawem cech i priorytetem zajmują jeden wiersz („+N\" przy numerze PID) i mają jeden wspólny rozdział.",
                "There are {} processes to verify, in {} groups: processes of the same program with the same set of characteristics and priority share one row (\"+N\" next to the PID) and one chapter.", order.len(), groups.len())));
        }
        b.push(Block::Para(tr!("Priorytet to kolejność weryfikacji (P1 w pierwszej kolejności), wyznaczona z rodzaju znalezisk i kontekstu procesu. Nie jest oceną szkodliwości; uzasadnienie znajduje się w części „Ocena\" każdego procesu.", "Priority is the order of verification (P1 first), derived from the type of findings and the process context. It is not an assessment of maliciousness; the rationale is in the \"Assessment\" section of each process.").into()));
        // rozkład znalezisk wg tagu w pokazanych regionach
        let mut counts: Vec<(String, u32)> = Vec::new();
        for f in order.iter().flat_map(|p| shown_regions(p, o.min)).flat_map(|r| &r.findings) {
            match counts.iter_mut().find(|c| c.0 == f.tag) { Some(c) => c.1 += 1, None => counts.push((f.tag.clone(), 1)) }
        }
        counts.sort_by(|a, c| c.1.cmp(&a.1).then(a.0.cmp(&c.0)));
        b.push(Block::H3(tr!("Znaleziska według tagu", "Findings by tag").into()));
        b.push(Block::Bars(counts.clone()));
        // macierz: które cechy w których procesach (kolumny w kolejności od najczęstszej cechy)
        let cols: Vec<String> = counts.iter().map(|c| c.0.clone()).collect();
        let rows: Vec<(String, Vec<(u32, Severity)>)> = groups.iter().map(|g| {
            let p = g[0];
            let regs = shown_regions(p, o.min);
            (format!("{} {}{}", pid_s(p), clean(p.info.name.as_deref().unwrap_or("?")), if g.len() > 1 { format!(" (x{})", g.len()) } else { String::new() }), cols.iter().map(|t| {
                let with: Vec<&&RegionReport> = regs.iter().filter(|r| r.findings.iter().any(|f| &f.tag == t)).collect();
                (with.len() as u32, with.iter().map(|r| r.severity).max().unwrap_or(Severity::None))
            }).collect())
        }).collect();
        b.push(Block::H3(tr!("Procesy i cechy", "Processes and characteristics").into()));
        b.push(Block::Para(tr!("Liczba regionów z daną cechą w każdym procesie; kolor komórki to najwyższa waga takiego regionu. Proces z cechą, której nie mają podobne procesy, warto obejrzeć pierwszy.", "Number of regions with a given characteristic in each process; the cell colour is the highest severity of such a region. A process with a characteristic that similar processes lack is worth examining first.").into()));
        b.push(Block::Matrix { cols, rows });
        if let Some(nodes) = host_tree(&order) {
            b.push(Block::H3(tr!("Drzewo procesów ze znaleziskami", "Process tree with findings").into()));
            b.push(Block::Tree(nodes));
        }

        // --- szczegóły
        for g in &groups {
            let p = g[0];
            let similar = if g.len() > 1 { trf!(" (i {} podobnych)", " (and {} similar)", g.len() - 1) } else { String::new() };
            b.push(Block::H1(trf!("Proces {}: {}{}", "Process {}: {}{}", pid_s(p), clean(p.info.name.as_deref().unwrap_or("?")), similar)));
            if g.len() > 1 {
                let mut pids: Vec<String> = g[1..].iter().take(40).map(|x| pid_s(x)).collect();
                if g.len() - 1 > 40 { pids.push(trf!("... i {} kolejnych", "... and {} more", g.len() - 41)); }
                b.push(Block::Note(trf!("Ten sam program z tym samym zestawem cech i priorytetem działa w {} innych procesach: PID {}. Poniżej opisany jest jeden z nich; adresy regionów w pozostałych mogą być inne, a ich pełne dane są w pliku wyniku.",
                    "The same program with the same set of characteristics and priority runs in {} other processes: PID {}. One of them is described below; region addresses in the others may differ, and their full data is in the result file.", g.len() - 1, pids.join(", "))));
            }
            let mut kv = vec![
                ("System".to_string(), format!("{}/{}", clean(&p.info.os), clean(&p.info.arch))),
                (tr!("Plik programu", "Program file").to_string(), match &p.info.exe { Some(e) => format!("{}{}", clean(e), if p.info.exe_deleted { tr!(" (usunięty z dysku)", " (deleted from disk)") } else { "" }), None => tr!("nieznany", "unknown").into() }),
                (tr!("Regiony", "Regions").to_string(), trf!("{} łącznie, {} nieodczytanych, przeskanowano {}", "{} total, {} not read, {} scanned", p.regions_total, p.regions_unreadable, size_h(p.bytes_scanned))),
            ];
            if p.info.source_type == "dump" { kv.push((tr!("Źródło danych", "Data source").into(), tr!("zrzut pamięci procesu (stan z chwili wykonania zrzutu, nie z chwili analizy)", "process memory dump (state at the time the dump was taken, not at analysis time)").into())); }
            if let Some(e) = &p.error { kv.push((tr!("Błąd", "Error").into(), clean(e))); }
            if let Some(c) = &p.context { context_keyvals(&mut kv, c); }
            b.push(Block::KeyVals(kv));
            let (prio, reasons, step) = priority(p, &kb, o.min);
            b.push(Block::H2(tr!("Ocena", "Assessment").into()));
            b.push(Block::KeyVals(vec![(tr!("Priorytet weryfikacji", "Verification priority").into(), format!("{prio}: {}", match prio { "P1" => tr!("w pierwszej kolejności", "verify first"), "P2" => tr!("w drugiej kolejności", "verify second"), _ => tr!("przy okazji", "when convenient") })),
                (tr!("Uzasadnienie", "Rationale").into(), reasons.join(" ")), (tr!("Pierwszy krok", "First step").into(), step)]));
            identity(&mut b, &kb, p, scan.host_info.as_ref().and_then(|h| h.system_drive.as_deref()));
            let from_dump = p.info.source_type == "dump";
            if let Some(c) = p.context.as_ref().filter(|_| !from_dump) { context_blocks(&mut b, &kb, p, c); }
            if let Some(l) = &p.layout { modules(&mut b, &kb, p, l, &scan.files); }
            if let Some(rows) = mem_map(p, o.min) {
                b.push(Block::H2(tr!("Mapa przestrzeni adresowej", "Address space map").into()));
                b.push(Block::Para(trf!("Wszystkie {} regionów procesu od najniższego adresu. Sąsiednie mapowania tego samego pliku są połączone w jeden wiersz, długie ciągi zwykłych mapowań zwinięte, a duże nieużywane zakresy pokazane jako przerwy. Wysokość bloku rośnie z rozmiarem (skala logarytmiczna).", "All {} regions of the process from the lowest address. Adjacent mappings of the same file are merged into one row, long runs of ordinary mappings are collapsed, and large unused ranges are shown as gaps. Block height grows with size (logarithmic scale).", l_len(p))));

                b.push(Block::MemMap(rows));
            }
            let regs = shown_regions(p, o.min);
            explain_findings(&mut b, &kb, p, &regs);
            // wykres rozrzutu wszystkich regionów ze znaleziskami (także poniżej progu raportu): tło do oceny odstających
            let pts: Vec<(u64, f32, Severity)> = p.regions.iter().filter(|r| !r.findings.is_empty()).filter_map(|r| r.entropy_max.map(|e| (r.region.size, e, r.severity))).collect();
            if pts.len() >= 3 {
                b.push(Block::H3(tr!("Rozmiar i entropia regionów", "Region size and entropy").into()));
                b.push(Block::Para(trf!("Każdy punkt to jeden z {} regionów ze znaleziskiem w tym procesie (także o wadze „info\"). Punkt wysoko (entropia od 7,2) albo daleko od reszty to region odstający.", "Each point is one of the {} regions with a finding in this process (including severity \"info\"). A point high up (entropy of 7.2 or more) or far from the rest is an outlier region.", pts.len())));
                b.push(Block::Scatter(pts));
            }
            if let Some(c) = p.context.as_ref().filter(|_| !from_dump) { flow(&mut b, p, c, &regs); }
            b.push(Block::H2(tr!("Regiony ze znaleziskami", "Regions with findings").into()));

            let rows = regs.iter().map(|r| vec![
                format!("{:#x}", r.region.base), size_h(r.region.size), r.region.prot.map(|x| x.to_string()).unwrap_or_else(|| "???".into()),
                crate::sev_label(r.severity).to_string(), r.score.to_string(), r.entropy_max.map(|e| format!("{e:.2}")).unwrap_or_else(|| "-".into()),
                r.findings.iter().map(|f| f.tag.as_str()).collect::<Vec<_>>().join(", "),
                clean(r.region.backing.as_deref().or(r.region.label.as_deref()).unwrap_or(tr!("brak pliku", "no file"))),
            ]).collect();
            b.push(Block::Table { head: [tr!("Adres", "Address"), tr!("Rozmiar", "Size"), tr!("Prawa", "Perms"), tr!("Waga", "Severity"), tr!("Pkt", "Pts"), tr!("Entropia", "Entropy"), tr!("Tagi", "Tags"), tr!("Źródło", "Source")].map(String::from).to_vec(), rows, widths: vec![2.1, 1.2, 1.0, 1.4, 0.7, 1.35, 2.2, 2.4] });

            let lp = llm.and_then(|l| l["processes"].as_array()).and_then(|a| a.iter().find(|x| x["pid"].as_u64() == p.info.pid.map(u64::from)));
            // Szczegóły dla regionów o najwyższym wyniku; reszta zostaje w tabeli powyżej i w pliku wyniku.
            if regs.len() > DETAIL_PER_PROCESS {
                b.push(Block::Para(trf!("Poniżej szczegóły {DETAIL_PER_PROCESS} regionów o najwyższym wyniku z {}; pozostałe są w tabeli powyżej i w pliku wyniku.", "Details follow for the {DETAIL_PER_PROCESS} highest-scoring regions out of {}; the rest are in the table above and in the result file.", regs.len())));
            }
            for r in regs.iter().take(DETAIL_PER_PROCESS) {
                b.push(Block::Anchor(region_anchor(&pid_s(p), r.region.base)));
                b.push(Block::H2(trf!("Region {:#x} ({}, {} pkt)", "Region {:#x} ({}, {} pts)", r.region.base, crate::sev_label(r.severity), r.score)));
                let tags: Vec<&str> = r.findings.iter().map(|f| f.tag.as_str()).collect();
                b.push(Block::Para(trf!("W skrócie: {}. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie\".", "In short: {}. The explanation is above, in the section \"What the findings mean in this process\".", combo_title(&kb, &tags))));
                b.push(Block::Bullets(r.findings.iter().map(|f| format!("{}: {}", f.tag, clean(&f.reason))).collect()));
                if let Some(a) = &r.allowlisted { b.push(Block::Para(trf!("Waga obniżona przez listę dozwolonych ({}): program ma znane środowisko tworzące kod w locie, więc typowe dla niego cechy liczą się trzykrotnie mniej. Znalezisko pozostaje w wyniku.", "Severity reduced by the allowlist ({}): the program has a known runtime that generates code just in time, so characteristics typical of it count three times less. The finding remains in the result.", clean(a)))); }
                if r.truncated { b.push(Block::Para(trf!("Region odczytany częściowo: {} z {}.", "Region read partially: {} of {}.", size_h(r.bytes_read), size_h(r.region.size)))); }
                region_detail(&mut b, p, r);
                let steps = kb.verify_steps(&tags, p.info.pid.unwrap_or(0), r.region.base, r.region.base.saturating_add(r.region.size));
                if !steps.is_empty() {
                    b.push(Block::H3(tr!("Jak sprawdzić ten region", "How to verify this region").into()));
                    b.push(Block::Steps(steps.into_iter().map(|s| StepLine { what: s.what, cmd: s.cmd, look: s.look }).collect()));
                }
                if llm.is_some() { region_llm(&mut b, lp, r.region.base); }
            }
            if let Some(c) = lp.map(|x| &x["correlation"]) { correlation(&mut b, c); }
        }
    }

    // --- czego nie ma
    b.push(Block::H1(tr!("Czego ten raport nie obejmuje", "What this report does not cover").into()));
    let mut gaps = Vec::new();
    for p in &failed { gaps.push(trf!("Proces {} niedostępny: {}", "Process {} inaccessible: {}", pid_s(p), clean(p.error.as_deref().unwrap_or("")))); }
    let shown = 25;
    if gaps.len() > shown { let n = gaps.len() - shown; gaps.truncate(shown); gaps.push(trf!("... i {n} kolejnych niedostępnych procesów (pełna lista w pliku wyniku).", "... and {n} more inaccessible processes (full list in the result file).")); }
    if unreadable > 0 { gaps.push(trf!("{unreadable} regionów nie zostało odczytanych; detektory treści (ENT-X, HDR) ich nie sprawdziły.", "{unreadable} regions were not read; the content detectors (ENT-X, HDR) did not examine them.")); }
    let below = scan.processes.iter().flat_map(|p| &p.regions).filter(|r| !r.findings.is_empty() && r.severity < o.min).count();
    if below > 0 { gaps.push(trf!("{below} regionów ze znaleziskami poniżej poziomu „{}\" pominięto; są w pliku wyniku.", "{below} regions with findings below severity \"{}\" were omitted; they are in the result file.", crate::sev_label(o.min))); }
    gaps.push(tr!("Podgląd bajtów w raporcie to pierwsze 128 bajtów znaleziska; pełne 256 bajtów jest w pliku wyniku (JSON). Pełnego zrzutu regionu narzędzie nie robi.", "The byte preview in the report is the first 128 bytes of a finding; the full 256 bytes are in the result file (JSON). The tool does not take a full dump of the region.").into());
    let ctx_missing = flagged.iter().filter(|p| p.context.is_none()).count();
    if ctx_missing > 0 { gaps.push(trf!("{ctx_missing} procesów ze znaleziskami nie ma kontekstu systemowego ani mapy pamięci (skan z --no-context, starsza wersja narzędzia albo waga poniżej „podejrzane\").", "{ctx_missing} processes with findings have no system context or memory map (scan with --no-context, an older tool version, or severity below \"suspicious\").")); }
    // uwagi skanera powtarzają się między procesami tego samego programu: każda treść raz
    let mut seen_notes: Vec<String> = Vec::new();
    for p in &flagged { for n in p.context.iter().flat_map(|c| &c.notes).filter(|n| { let new = !seen_notes.contains(n); if new { seen_notes.push((*n).clone()); } new }) { gaps.push(trf!("Proces {}: {}", "Process {}: {}", pid_s(p), clean(n))); } }
    gaps.push(tr!("Kontekst systemowy to stan z chwili skanu: połączenia zamknięte wcześniej, zakończone procesy potomne i usunięte pliki nie są widoczne. Historii (logów, dziennika audytu) raport nie obejmuje.", "System context is the state at scan time: connections closed earlier, child processes that have exited and deleted files are not visible. The report does not cover history (logs, audit trail).").into());
    gaps.push(tr!("Skan obejmuje pamięć procesów w chwili skanu; nie obejmuje jądra, treści plików na dysku ani zawartości ruchu sieciowego.", "The scan covers process memory at scan time; it does not cover the kernel, the contents of files on disk or the contents of network traffic.").into());
    if scan.files.is_empty() { gaps.push(tr!("Wynik nie zawiera skrótów SHA-256 plików (skan z --no-hashes albo starsza wersja narzędzia).", "The result contains no SHA-256 file hashes (scan with --no-hashes or an older tool version).").into()); }
    else { gaps.push(trf!("Plik wyniku zawiera skróty SHA-256 {} plików (programy wszystkich procesów i pliki zmapowane w procesach ze znaleziskami); raport pokazuje tylko część. Raport nie sprawdza skrótów w zewnętrznych bazach.", "The result file contains SHA-256 hashes of {} files (programs of all processes and files mapped in processes with findings); the report shows only some. The report does not check hashes against external databases.", scan.files.len())); }
    gaps.push(tr!("Znalezisko THR-PRIV opiera się na adresie startu wątku (Windows) albo na miejscu wywołania jądra przez wątki czekające (Linux); wątek, który w chwili skanu coś liczył, nie jest na Linuksie oceniany. IMG-MOD podaje, ile bajtów kodu różni się od pliku na dysku i gdzie jest pierwszy; podgląd pokazuje bajty z pamięci, bez treści z pliku do porównania.", "The THR-PRIV finding relies on the thread start address (Windows) or on the place where waiting threads call the kernel (Linux); a thread that was computing at scan time is not assessed on Linux. IMG-MOD states how many bytes of code differ from the file on disk and where the first one is; the preview shows the bytes from memory, without the file contents to compare against.").into());
    if llm.is_some() { gaps.push(tr!("Model nie widział kontekstu systemowego ani mapy pamięci; jego hipotezy opierają się wyłącznie na danych regionów.", "The model did not see the system context or the memory map; its hypotheses rely solely on region data.").into()); }
    if llm.is_none() { gaps.push(tr!("Brak interpretacji LLM (raport wyłącznie z danych deterministycznych).", "No LLM interpretation (report built from deterministic data only).").into()); }
    b.push(Block::Bullets(gaps));

    // --- słowniczek pojęć z bazy wiedzy
    b.push(Block::H1(tr!("Słowniczek", "Glossary").into()));
    b.push(Block::Table { head: [tr!("Pojęcie", "Term"), tr!("Znaczenie", "Meaning")].map(String::from).to_vec(), rows: kb.terms.iter().map(|(k, v)| vec![k.clone(), v.clone()]).collect(), widths: vec![1.8, 6.0] });
    b.push(Block::Para(trf!("Objaśnienia w tym raporcie pochodzą z bazy wiedzy narzędzia (wersja {}, system {}). Opisują typowe przypadki; nie zastępują sprawdzenia konkretnego procesu.", "The explanations in this report come from the tool's knowledge base (version {}, system {}). They describe typical cases; they do not replace checking the specific process.", clean(&kb.version), clean(&kb.os))));

    // --- legenda
    b.push(Block::H1(tr!("Legenda", "Legend").into()));
    let mut tags: Vec<&str> = scan.processes.iter().flat_map(|p| &p.regions).flat_map(|r| &r.findings).map(|f| f.tag.as_str()).collect();
    tags.sort(); tags.dedup();
    if !tags.is_empty() {
        b.push(Block::Table { head: ["Tag", tr!("Znaczenie", "Meaning")].map(String::from).to_vec(),
            rows: tags.iter().map(|t| vec![t.to_string(), kb.tags.get(*t).map(|i| format!("{}: {}", i.name, i.meaning)).unwrap_or_else(|| tag_gloss(t).to_string())]).collect(), widths: vec![1.0, 6.0] });
    }
    b.push(Block::Para(tr!("Waga regionu wynika z sumy punktów jego znalezisk: poniżej 30 „info\", 30-59 „podejrzane\", od 60 „wysokie\".", "Region severity follows from the sum of points of its findings: below 30 \"info\", 30-59 \"suspicious\", 60 and above \"high\".").into()));
    if llm.is_some() {
        b.push(Block::Para(tr!("Pewność hipotez LLM: „ustalone z danych\" wynika wprost z danych deterministycznych; „osąd modelu\" to ocena modelu; „niepotwierdzone\" jest możliwe, ale wymaga sprawdzenia przez człowieka. Hipoteza łagodna nigdy nie ma pewności „ustalone z danych\".", "Confidence of LLM hypotheses: \"established from data\" follows directly from deterministic data; \"model's judgement\" is the model's assessment; \"unconfirmed\" is possible but requires checking by a human. A benign hypothesis never has confidence \"established from data\".").into()));

    }

    // rozdziały główne są numerowane, żeby dało się do nich odwoływać w korespondencji
    let mut n = 0;
    for blk in b.iter_mut() { if let Block::H1(t) = blk { n += 1; *t = format!("{n}. {t}"); } }
    // spis treści przed pierwszym rozdziałem: przy raporcie z wielu procesów pozwala trafić do procesu bez przewijania
    let chapters: Vec<(String, String)> = b.iter().filter_map(|x| if let Block::H1(t) = x { Some(t.clone()) } else { None }).enumerate().map(|(i, t)| (t, format!("ch-{}", i + 1))).collect();
    // kotwica przed każdym rozdziałem: cel odnośników ze spisu treści
    let mut with_anchors: Vec<Block> = Vec::with_capacity(b.len() + chapters.len());
    let mut k = 0;
    for blk in b { if matches!(blk, Block::H1(_)) { k += 1; with_anchors.push(Block::Anchor(format!("ch-{k}"))); } with_anchors.push(blk); }
    let mut b = with_anchors;
    // spis stoi przed kotwicą pierwszego rozdziału
    b.insert(toc_at, Block::Toc(chapters));
    Doc { title: tr!("Nanshe: raport triage pamięci", "Nanshe: memory triage report").into(),
        subtitle: trf!("host {} | skan {}", "host {} | scan {}", clean(&scan.host), clean(&scan.timestamp)),
        footer: if llm.is_some() { tr!("Triage, nie werdykt. Interpretacja LLM niedeterministyczna, do weryfikacji.", "Triage, not a verdict. LLM interpretation is non-deterministic and requires verification.").into() } else { tr!("Triage, nie werdykt.", "Triage, not a verdict.").into() },
        blocks: b }
}

pub(crate) fn pid_s(p: &ProcessReport) -> String { p.info.pid.map(|x| x.to_string()).unwrap_or_else(|| "-".into()) }

pub(crate) fn shown_regions(p: &ProcessReport, min: Severity) -> Vec<&RegionReport> {
    let mut v: Vec<&RegionReport> = p.regions.iter().filter(|r| !r.findings.is_empty() && r.severity >= min).collect();
    v.sort_by(|a, b| b.score.cmp(&a.score).then(a.region.base.cmp(&b.region.base)));
    v
}
fn top_score(p: &ProcessReport, min: Severity) -> u32 { shown_regions(p, min).first().map(|r| r.score as u32).unwrap_or(0) }

fn region_llm(b: &mut Vec<Block>, lp: Option<&Value>, base: u64) {
    let want = format!("{base:#x}");
    let Some(r) = lp.and_then(|p| p["regions"].as_array()).and_then(|a| a.iter().find(|x| x["base"] == want.as_str())) else {
        b.push(Block::Para(tr!("Interpretacja LLM: region nie był analizowany (poniżej progu interpretacji).", "LLM interpretation: the region was not analysed (below the interpretation threshold).").into()));
        return;
    };
    b.push(Block::H3(tr!("Interpretacja LLM (do weryfikacji)", "LLM interpretation (requires verification)").into()));
    let markers = strs(&r["markers"]);
    if markers.iter().any(|m| m == "LLM-INJECT") {
        b.push(Block::Note(tr!("W danych tego regionu wykryto tekst wyglądający na instrukcję dla modelu. Sam w sobie jest to ślad próby manipulacji analizą.", "Text that looks like an instruction to the model was detected in this region's data. This is in itself a trace of an attempt to manipulate the analysis.").into()));
    }
    if r["status"] != "ok" {
        b.push(Block::Para(trf!("Brak interpretacji ({}): {}", "No interpretation ({}): {}", clean(r["status"].as_str().unwrap_or("?")), clean(r["reason"].as_str().unwrap_or("")))));
        return;
    }
    let e = &r["explanation"];
    let hyps: Vec<&Value> = e["hypotheses"].as_array().into_iter().flatten().collect();
    b.push(Block::Table { head: [tr!("Nr", "No."), tr!("Hipoteza", "Hypothesis"), tr!("Pewność", "Confidence"), tr!("Dowody (tagi)", "Evidence (tags)")].map(String::from).to_vec(),
        rows: hyps.iter().enumerate().map(|(i, h)| {
            let l = h["label"].as_str().unwrap_or("?");
            vec![(i + 1).to_string(), format!("{} ({})", clean(l), label_gloss(l)), confidence_pl(h["confidence"].as_str().unwrap_or("?")).to_string(),
                // identyfikator znaleziska to pid:adres:TAG; w raporcie wystarcza tag
                strs(&h["evidence"]).iter().map(|id| id.rsplit(':').next().unwrap_or(id).to_string()).collect::<Vec<_>>().join(", ")]
        }).collect(), widths: vec![0.5, 3.6, 1.6, 2.4] });
    b.push(Block::Para(tr!("Pewność: „ustalone z danych\" wynika wprost z danych skanu; „osąd modelu\" to ocena modelu, którą trzeba sprawdzić; „niepotwierdzone\" jest możliwe, ale bez oparcia w danych.",
        "Confidence: \"established from data\" follows directly from the scan data; \"model's judgement\" is the model's assessment and must be checked; \"unconfirmed\" is possible but not supported by the data.").into()));
    // argumenty każdej hipotezy w dwóch kolumnach: wspierające obok podważających
    for (i, h) in hyps.iter().enumerate() {
        let (pro, con) = (strs(&h["for"]), strs(&h["against"]));
        if pro.is_empty() && con.is_empty() { continue; }
        let rows = (0..pro.len().max(con.len())).map(|k| vec![pro.get(k).cloned().unwrap_or_default(), con.get(k).cloned().unwrap_or_default()]).collect();
        b.push(Block::Table { head: vec![trf!("Hipoteza {}: co ją wspiera", "Hypothesis {}: what supports it", i + 1), tr!("Co ją podważa", "What undermines it").into()], rows, widths: vec![1.0, 1.0] });
    }
    b.push(Block::Para(trf!("Podsumowanie modelu: {}", "Model summary: {}", clean(e["summary"].as_str().unwrap_or("")))));
    let notes = strs(&r["validator_notes"]);
    if !notes.is_empty() { b.push(Block::Para(trf!("Uwagi walidatora: {}", "Validator notes: {}", notes.join("; ")))); }
    if r["strings_redacted"].as_u64().unwrap_or(0) > 0 {
        b.push(Block::Para(trf!("Ciągów wyciętych przez filtr sekretów przed wysyłką: {}.", "Strings removed by the secret filter before sending: {}.", r["strings_redacted"])));
    }
}

fn correlation(b: &mut Vec<Block>, c: &Value) {
    match c["status"].as_str() {
        Some("ok") => {
            b.push(Block::H2(tr!("Korelacja regionów: interpretacja LLM (do weryfikacji)", "Region correlation: LLM interpretation (requires verification)").into()));
            b.push(Block::Para(clean(c["summary"].as_str().unwrap_or(""))));
            // identyfikator regionu to r:pid:adres; w raporcie pokazujemy adres
            let addr = |id: &str| format!("0x{}", id.rsplit(':').next().unwrap_or(id));
            let order = strs(&c["review_order"]);
            if !order.is_empty() { b.push(Block::Para(trf!("Proponowana kolejność przeglądu: {}.", "Proposed review order: {}.", order.iter().map(|s| addr(s)).collect::<Vec<_>>().join(", ")))); }
            for g in c["groups"].as_array().into_iter().flatten() {
                b.push(Block::Para(trf!("Grupa ({}): {}", "Group ({}): {}", strs(&g["region_ids"]).iter().map(|s| addr(s)).collect::<Vec<_>>().join(", "), clean(g["description"].as_str().unwrap_or("")))));
            }
            let steps = strs(&c["next_steps"]);
            if !steps.is_empty() { b.push(Block::H3(tr!("Proponowane kolejne kroki", "Proposed next steps").into())); b.push(Block::Bullets(steps)); }
        }
        Some("rejected") => {
            b.push(Block::H2(tr!("Korelacja regionów: interpretacja LLM", "Region correlation: LLM interpretation").into()));
            b.push(Block::Para(trf!("Brak korelacji (odpowiedź odrzucona): {}", "No correlation (response rejected): {}", clean(c["reason"].as_str().unwrap_or("")))));
        }
        _ => {}
    }
}

fn l_len(p: &ProcessReport) -> usize { p.layout.as_ref().map(|l| l.len()).unwrap_or(0) }

const TMP_DIRS: [&str; 4] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
fn in_tmp(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    TMP_DIRS.iter().any(|d| path.starts_with(d)) || l.contains("\\temp\\") || l.contains("\\appdata\\local\\temp")
}

/// Czy plik leży w katalogu, z którego zwykle pochodzi oprogramowanie systemowe i instalowane.
/// To wskazówka do sortowania raportu, nie ocena zaufania: plik w katalogu systemowym też może być podmieniony.
fn in_system_dir(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    ["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/snap/", "/etc/"].iter().any(|d| path.starts_with(d))
        || l.contains("\\windows\\") || l.contains("\\program files\\") || l.contains("\\program files (x86)\\") || l.contains("\\programdata\\microsoft\\")
}
/// Ile zwykłych (nieoznaczonych) pozycji pokazać obok oznaczonych.
const PLAIN_ROWS: usize = 8;

fn context_keyvals(kv: &mut Vec<(String, String)>, c: &ProcessContext) {
    if let Some(v) = &c.cmdline { kv.push((tr!("Wiersz poleceń", "Command line").into(), format!("{CODE}{}", clean(v)))); }
    if let Some(v) = &c.user { kv.push((tr!("Użytkownik", "User").into(), clean(v))); }
    if let Some(v) = &c.started { kv.push((tr!("Uruchomiony", "Started").into(), clean(v))); }
    if let Some(v) = c.ppid { kv.push((tr!("Proces nadrzędny", "Parent process").into(), match c.ancestors.first() { Some(a) => format!("{v} ({})", clean(&a.name)), None => v.to_string() })); }
    if let Some(v) = &c.cwd { kv.push((tr!("Katalog roboczy", "Working directory").into(), clean(v))); }
    if let Some(v) = c.threads { kv.push((tr!("Wątki", "Threads").into(), v.to_string())); }
    if let Some(f) = &c.exe_file {
        let mut parts = vec![size_h(f.size)];
        if let Some(m) = &f.modified { parts.push(trf!("zmieniony {}", "modified {}", clean(m))); }
        if let Some(o) = &f.owner { parts.push(trf!("właściciel {}", "owner {}", clean(o))); }
        if let Some(m) = &f.mode { parts.push(trf!("tryb {}", "mode {}", clean(m))); }
        kv.push((tr!("Plik programu: metadane", "Program file: metadata").into(), parts.join(", ")));
        kv.push((tr!("Plik programu: SHA-256", "Program file: SHA-256").into(), f.sha256.clone().map(|s| clean(&s)).unwrap_or_else(|| tr!("nie policzono", "not computed").into())));
    }
    for (k, v) in &c.flags { kv.push((clean(k), clean(v))); }
}

fn proc_line(r: &ProcRef) -> String {
    let what = r.cmdline.as_deref().or(r.exe.as_deref()).unwrap_or("");
    let what: String = clean(what).chars().take(110).collect();
    if what.is_empty() { format!("{} {}", r.pid, clean(&r.name)) } else { format!("{} {}: {}", r.pid, clean(&r.name), what) }
}

fn context_blocks(b: &mut Vec<Block>, kb: &Kb, p: &ProcessReport, c: &ProcessContext) {
    // objaśnienia cech bezpieczeństwa z tabeli powyżej
    let notes: Vec<String> = c.flags.iter().filter_map(|(k, v)| kb.flag(k).map(|e| format!("{} = {}: {}", clean(k), clean(v), e))).collect();
    if !notes.is_empty() { b.push(Block::H3(tr!("Co oznaczają cechy procesu", "What the process attributes mean").into())); b.push(Block::Bullets(notes)); }
    // drzewo: przodkowie od korzenia, badany proces, dzieci
    b.push(Block::H2(tr!("Drzewo procesów", "Process tree").into()));
    let mut nodes: Vec<TreeNode> = c.ancestors.iter().rev().enumerate().map(|(i, a)| TreeNode { depth: i as u8, text: proc_line(a), mark: false }).collect();
    let d = nodes.len() as u8;
    let me = ProcRef { pid: p.info.pid.unwrap_or(0), name: p.info.name.clone().unwrap_or_else(|| "?".into()), exe: p.info.exe.clone(), cmdline: c.cmdline.clone() };
    nodes.push(TreeNode { depth: d, text: trf!("{} (badany proces)", "{} (examined process)", proc_line(&me)), mark: true });
    nodes.extend(c.children.iter().map(|k| TreeNode { depth: d + 1, text: proc_line(k), mark: false }));
    b.push(Block::Tree(nodes));
    if c.children.is_empty() { b.push(Block::Para(tr!("Brak procesów potomnych w chwili skanu.", "No child processes at scan time.").into())); }

    b.push(Block::H2(tr!("Sieć", "Network").into()));
    if c.sockets.is_empty() {
        b.push(Block::Para(tr!("Brak gniazd sieciowych i uniksowych w chwili skanu.", "No network or Unix sockets at scan time.").into()));
    } else {
        let rows = c.sockets.iter().map(|s| vec![clean(&s.proto), clean(&s.local), s.remote.as_deref().map(clean).unwrap_or_else(|| "-".into()), s.state.as_deref().map(clean).unwrap_or_else(|| "-".into())]).collect();
        b.push(Block::Table { head: [tr!("Protokół", "Protocol"), tr!("Adres lokalny", "Local address"), tr!("Adres zdalny", "Remote address"), tr!("Stan", "State")].map(String::from).to_vec(), rows, widths: vec![1.0, 3.2, 3.2, 1.6] });
    }

    b.push(Block::H2(tr!("Otwarte pliki i uchwyty", "Open files and handles").into()));
    // rodzaje w kolejności pokazywania; "sync" i "thread" nie są zapisywane z nazwami
    const KINDS_T: [(&str, &str, &str); 11] = [("process", "inny proces", "other process"), ("memfd", "memfd", "memfd"), ("file", "plik", "file"), ("section", "sekcja", "section"),
        ("key", "klucz rejestru", "registry key"), ("mutant", "muteks", "mutex"), ("socket", "gniazdo", "socket"), ("pipe", "potok", "pipe"), ("device", "urządzenie", "device"),
        ("anon", "obiekt jądra", "kernel object"), ("other", "inne", "other")];
    let kinds: Vec<(&str, &str)> = KINDS_T.iter().map(|x| (x.0, tr!(x.1, x.2))).collect();
    let label = |k: &str| kinds.iter().find(|x| x.0 == k).map(|x| x.1).unwrap_or(tr!("inne", "other"));
    let counts: Vec<String> = kinds.iter().filter_map(|(k, l)| { let n = c.files.iter().filter(|f| f.kind == *k).count(); (n > 0).then(|| format!("{l}: {n}")) }).collect();
    b.push(Block::Para(trf!("Wszystkich deskryptorów lub uchwytów: {}. Zapisane z nazwą: {}{}.", "Total descriptors or handles: {}. Recorded with a name: {}{}.", c.files_total, c.files.len(),
        if counts.is_empty() { String::new() } else { format!(" ({})", counts.join(", ")) })));
    let mut files: Vec<&OpenFile> = c.files.iter().filter(|f| matches!(f.kind.as_str(), "file" | "memfd" | "process" | "section" | "key" | "mutant")).collect();
    let flag = |f: &OpenFile| {
        let mut v = Vec::new();
        if f.kind == "memfd" { v.push(tr!("tylko w pamięci", "in memory only")); } else if f.deleted { v.push(tr!("usunięty z dysku", "deleted from disk")); }
        if f.kind == "file" && in_tmp(&f.target) { v.push(tr!("katalog tymczasowy", "temporary directory")); }
        else if f.kind == "file" && !in_system_dir(&f.target) { v.push(tr!("poza katalogami systemowymi", "outside system directories")); }
        if f.kind == "process" { v.push(if f.target.contains("; prawa: ") || f.target.contains("; rights: ") { tr!("uchwyt do innego procesu z prawami ingerencji", "handle to another process with rights to interfere") } else { tr!("uchwyt do innego procesu", "handle to another process") }); }
        v.join(", ")
    };
    let rank = |f: &OpenFile| kinds.iter().position(|x| x.0 == f.kind).unwrap_or(99);
    files.sort_by_key(|f| (flag(f).is_empty(), rank(f), f.fd));
    let total = files.len();
    let flagged = files.iter().filter(|f| !flag(f).is_empty()).count();
    let shown = (flagged.min(40) + PLAIN_ROWS).min(total);
    if total > 0 {
        let rows = files.iter().take(shown).map(|f| vec![format!("{:#x}", f.fd), label(&f.kind).to_string(), clean(&f.target), flag(f)]).collect();
        b.push(Block::Table { head: [tr!("Nr", "No."), tr!("Rodzaj", "Type"), tr!("Obiekt", "Object"), tr!("Uwagi", "Notes")].map(String::from).to_vec(), rows, widths: vec![0.7, 1.3, 5.0, 2.2] });
        if total > shown { b.push(Block::Para(trf!("Pokazano {shown} z {total}: wszystkie oznaczone uwagą (do 40) i {PLAIN_ROWS} zwykłych; pozostałe są w pliku wyniku.", "Shown {shown} of {total}: all flagged with a note (up to 40) and {PLAIN_ROWS} ordinary ones; the rest are in the result file."))); }
    }
}

/// Pliki zmapowane do procesu, z mapy regionów: najpierw te, które wymagają uwagi.
fn modules(b: &mut Vec<Block>, kb: &Kb, p: &ProcessReport, layout: &[Region], files: &[FileHash]) {
    struct M<'a> { path: &'a str, size: u64, exec: bool, deleted: bool, n: u32 }
    let mut ms: Vec<M> = Vec::new();
    for r in layout {
        let Some(path) = r.backing.as_deref() else { continue };
        match ms.iter_mut().find(|m| m.path == path) {
            Some(m) => { m.size += r.size; m.exec |= r.is_x(); m.deleted |= r.backing_deleted; m.n += 1; }
            None => ms.push(M { path, size: r.size, exec: r.is_x(), deleted: r.backing_deleted, n: 1 }),
        }
    }
    if ms.is_empty() { return; }
    let note = |m: &M| {
        let mut v = Vec::new();
        if Some(m.path) == p.info.exe.as_deref() { v.push(tr!("plik programu", "program file")); }
        if m.path.starts_with("memfd:") { v.push(tr!("tylko w pamięci", "in memory only")); } else if m.deleted { v.push(tr!("usunięty z dysku", "deleted from disk")); }
        if in_tmp(m.path) { v.push(tr!("katalog tymczasowy", "temporary directory")); }
        else if !m.path.starts_with("memfd:") && !in_system_dir(m.path) { v.push(tr!("poza katalogami systemowymi", "outside system directories")); }
        v.join(", ")
    };
    let risky = |m: &M| m.path.starts_with("memfd:") || m.deleted || in_tmp(m.path) || !in_system_dir(m.path);
    let total = ms.len();
    // moduły opisane w bazie jako środowiska JIT idą zaraz po wymagających uwagi: tłumaczą znaleziska
    let is_rt = |m: &M| kb.module(m.path).map(|x| x.runtime.is_some()).unwrap_or(false);
    ms.sort_by(|a, c| risky(c).cmp(&risky(a)).then(is_rt(c).cmp(&is_rt(a))).then((Some(c.path) == p.info.exe.as_deref()).cmp(&(Some(a.path) == p.info.exe.as_deref()))).then(c.exec.cmp(&a.exec)).then(a.path.cmp(c.path)));
    let shown = (ms.iter().filter(|m| risky(m)).count().min(30) + ms.iter().filter(|m| !risky(m) && is_rt(m)).count() + PLAIN_ROWS).min(total);
    b.push(Block::H2(tr!("Pliki zmapowane do pamięci", "Files mapped into memory").into()));
    let describe = |m: &M| { let (n, d) = (note(m), kb.module(m.path).map(|x| x.what.as_str()).unwrap_or("")); if n.is_empty() { d.to_string() } else if d.is_empty() { n } else { format!("{n}; {d}") } };
    let rows = ms.iter().take(shown).map(|m| vec![clean(m.path), size_h(m.size), if m.exec { tr!("tak", "yes").into() } else { tr!("nie", "no").into() }, describe(m)]).collect();
    b.push(Block::Table { head: [tr!("Plik", "File"), tr!("Rozmiar", "Size"), tr!("Kod", "Code"), tr!("Uwagi i opis", "Notes and description")].map(String::from).to_vec(), rows, widths: vec![4.2, 1.0, 0.6, 3.6] });
    if total > shown { b.push(Block::Para(trf!("Pokazano {shown} z {total} plików: wszystkie oznaczone uwagą (do 30) i {PLAIN_ROWS} zwykłych; pełna lista jest w pliku wyniku.", "Shown {shown} of {total} files: all flagged with a note (up to 30) and {PLAIN_ROWS} ordinary ones; the full list is in the result file."))); }
    // skróty SHA-256 pokazanych plików; plik tylko w pamięci albo usunięty ma w wyniku klucz z numerem procesu
    let pid = p.info.pid.unwrap_or(0);
    let hash_of = |m: &M| files.iter().find(|f| f.path == m.path || f.path == format!("{} (proces {pid})", m.path) || f.path == format!("{} (process {pid})", m.path));
    let rows: Vec<Vec<String>> = ms.iter().take(shown).filter_map(|m| hash_of(m).map(|f| vec![clean(m.path.rsplit(['/', '\\']).next().unwrap_or(m.path)),
        f.sha256.clone().map(|s| clean(&s)).unwrap_or_else(|| trf!("brak: {}", "none: {}", clean(f.note.as_deref().unwrap_or(tr!("nie policzono", "not computed")))))])).collect();
    if !rows.is_empty() {
        b.push(Block::H3(tr!("Skróty SHA-256 plików", "SHA-256 hashes of files").into()));
        b.push(Block::Table { head: [tr!("Plik", "File"), "SHA-256"].map(String::from).to_vec(), rows, widths: vec![2.4, 5.4] });
    }
}

fn owner(r: &Region) -> String {
    match (&r.backing, &r.label) {
        (Some(b), _) => clean(b),
        (None, Some(l)) => clean(l),
        (None, None) => match r.kind { RegionKind::Stack => tr!("[stos]", "[stack]").into(), RegionKind::Heap => tr!("[sterta]", "[heap]").into(),
            RegionKind::Mapped => tr!("mapowanie bez nazwy pliku", "mapping without a file name").into(), RegionKind::Image => tr!("obraz bez nazwy pliku", "image without a file name").into(), _ => tr!("pamięć anonimowa", "anonymous memory").into() },
    }
}

fn class_of(r: &Region) -> MapClass {
    match r.kind {
        RegionKind::Stack => MapClass::Stack,
        RegionKind::Heap => MapClass::Heap,
        _ if r.backing.is_some() => if r.is_x() { MapClass::Code } else { MapClass::File },
        _ if r.label.as_deref().map(|l| l.starts_with("[v") || l == "[sigpage]" || l == "[vectors]" || l == "[uprobes]").unwrap_or(false) => MapClass::Special,
        _ => MapClass::Anon,
    }
}

const GAP_MIN: u64 = 256 << 20;
const MAP_ROWS_MAX: usize = 36;
/// Ile regionów ze znaleziskami ma własny wiersz w długiej mapie; pozostałe są zwijane z adnotacją.
const MAP_FINDINGS_MAX: usize = 12;

/// Wiersze diagramu przestrzeni adresowej. Regiony ze znaleziskami od progu `min` mają zawsze
/// własny wiersz; reszta jest łączona po właścicielu, a przy długich mapach zwijana.
pub fn mem_map(p: &ProcessReport, min: Severity) -> Option<Vec<MapRow>> {
    let mut layout: Vec<&Region> = p.layout.as_ref()?.iter().collect();
    if layout.is_empty() { return None; }
    // regiony, które mają dalej własny opis: tylko do nich prowadzi odnośnik z mapy
    let detailed: Vec<u64> = shown_regions(p, min).iter().take(DETAIL_PER_PROCESS).map(|r| r.region.base).collect();
    layout.sort_by_key(|r| r.base);
    struct G { row: MapRow, prots: Vec<String>, n: u32, cls: MapClass }
    let mut gs: Vec<G> = Vec::new();
    for r in layout {
        let fr = p.regions.iter().find(|x| x.region.base == r.base && !x.findings.is_empty() && x.severity >= min);
        let prot = r.prot.map(|x| x.to_string()).unwrap_or_else(|| "???".into());
        let end = r.base.saturating_add(r.size);
        if let Some(f) = fr {
            let tags = f.findings.iter().map(|x| x.tag.as_str()).collect::<Vec<_>>().join(", ");
            gs.push(G { row: MapRow { start: r.base, end, size: r.size, prot: prot.clone(), what: owner(r), note: trf!("{tags} ({} pkt)", "{tags} ({} pts)", f.score), class: MapClass::Finding(f.severity), link: detailed.contains(&r.base).then(|| region_anchor(&pid_s(p), r.base)) }, prots: vec![prot], n: 1, cls: MapClass::Finding(f.severity) });
            continue;
        }
        let (o, cls) = (owner(r), class_of(r));
        match gs.last_mut() {
            Some(g) if !matches!(g.cls, MapClass::Finding(_)) && g.row.what == o && r.base.saturating_sub(g.row.end) < (16 << 20) => {
                g.row.end = end; g.row.size += r.size; g.n += 1;
                if !g.prots.contains(&prot) { g.prots.push(prot); }
                // wiersz z kodem i danymi tego samego pliku pokazujemy jako kod
                if cls == MapClass::Code { g.cls = MapClass::Code; g.row.class = MapClass::Code; }
            }
            _ => gs.push(G { row: MapRow { start: r.base, end, size: r.size, prot: String::new(), what: o, note: String::new(), class: cls, link: None }, prots: vec![prot], n: 1, cls }),
        }
    }
    let mut rows: Vec<MapRow> = Vec::new();
    for g in gs {
        let mut row = g.row;
        if row.prot.is_empty() { row.prot = g.prots.join(" "); }
        if row.note.is_empty() && g.n > 1 { row.note = trf!("mapowań: {}", "mappings: {}", g.n); }
        if let Some(prev) = rows.last() {
            let gap = row.start.saturating_sub(prev.end);
            if gap >= GAP_MIN { rows.push(MapRow { start: prev.end, end: row.start, size: gap, prot: String::new(), what: tr!("nieużywany zakres adresów", "unused address range").into(), note: String::new(), class: MapClass::Gap, link: None }); }
        }
        rows.push(row);
    }
    if rows.len() <= MAP_ROWS_MAX { return Some(rows); }
    // zwijanie: zostają znaleziska (najwyżej MAP_FINDINGS_MAX o najwyższym wyniku) i ich sąsiedzi,
    // stos, sterta, plik programu oraz skrajne wiersze
    let n = rows.len();
    let score = |r: &MapRow| p.regions.iter().find(|x| x.region.base == r.start).map(|x| x.score).unwrap_or(0);
    let mut ranked: Vec<(u32, u64)> = rows.iter().filter(|r| matches!(r.class, MapClass::Finding(_))).map(|r| (score(r), r.start)).collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked.truncate(MAP_FINDINGS_MAX);
    let finding = |i: usize| matches!(rows[i].class, MapClass::Finding(_)) && ranked.iter().any(|x| x.1 == rows[i].start);
    let exe = p.info.exe.as_deref().map(clean);
    let keep: Vec<bool> = (0..n).map(|i| i == 0 || i == n - 1 || finding(i) || (i > 0 && finding(i - 1)) || (i + 1 < n && finding(i + 1))
        || matches!(rows[i].class, MapClass::Stack | MapClass::Heap) || Some(&rows[i].what) == exe.as_ref()).collect();
    let mut out: Vec<MapRow> = Vec::new();
    let mut i = 0;
    while i < n {
        if keep[i] { out.push(rows[i].clone()); i += 1; continue; }
        let mut j = i;
        while j < n && !keep[j] { j += 1; }
        let run: Vec<&MapRow> = rows[i..j].iter().filter(|r| r.class != MapClass::Gap).collect();
        if run.len() <= 1 { out.extend(rows[i..j].iter().cloned()); }
        else {
            let files = run.iter().filter(|r| matches!(r.class, MapClass::Code | MapClass::File)).count();
            let hidden = run.iter().filter(|r| matches!(r.class, MapClass::Finding(_))).count();
            let mut names: Vec<String> = run.iter().filter(|r| r.class == MapClass::Code).map(|r| r.what.rsplit(['/', '\\']).next().unwrap_or(&r.what).to_string()).collect();
            names.dedup();
            let more = names.len().saturating_sub(4);
            names.truncate(4);
            out.push(MapRow { start: rows[i].start, end: rows[j - 1].end, size: run.iter().map(|r| r.size).sum(), prot: String::new(),
                what: if hidden > 0 { trf!("{} wierszy zwiniętych, w tym {} ze znaleziskami o niższym wyniku (są w tabeli regionów)", "{} rows collapsed, including {} with lower-scoring findings (listed in the regions table)", run.len(), hidden) }
                    else { trf!("{} wierszy zwiniętych: {} plików, {} pozostałych", "{} rows collapsed: {} files, {} other", run.len(), files, run.len() - files) },
                note: if names.is_empty() { String::new() } else { trf!("m.in. {}{}", "incl. {}{}", names.join(", "), if more > 0 { trf!(" i {more} innych", " and {more} more") } else { String::new() }) },
                class: MapClass::Collapsed, link: None });
        }
        i = j;
    }
    Some(out)
}

fn region_detail(b: &mut Vec<Block>, p: &ProcessReport, r: &RegionReport) {
    let end = r.region.base.saturating_add(r.region.size);
    let mut kv = vec![
        (tr!("Zakres adresów", "Address range").to_string(), trf!("{:#x} - {:#x} ({}, odczytano {})", "{:#x} - {:#x} ({}, {} read)", r.region.base, end, size_h(r.region.size), size_h(r.bytes_read))),
        (tr!("Rodzaj i źródło", "Type and source").to_string(), format!("{}; {}{}", match r.region.kind { RegionKind::Private => tr!("pamięć prywatna", "private memory"), RegionKind::Mapped => tr!("mapowanie", "mapping"), RegionKind::Image => tr!("obraz modułu", "module image"),
            RegionKind::Stack => tr!("stos", "stack"), RegionKind::Heap => tr!("sterta", "heap"), RegionKind::Physical => tr!("pamięć fizyczna", "physical memory"), RegionKind::Unknown => tr!("nieznany", "unknown") },
            if r.region.backing.is_none() && r.region.label.is_none() { tr!("bez pliku źródłowego", "not backed by a file").to_string() } else { owner(&r.region) },
            if r.region.backing_deleted && !r.region.backing.as_deref().unwrap_or("").starts_with("memfd:") { tr!(" (usunięty z dysku)", " (deleted from disk)") } else { "" })),
    ];
    if let (Some(mx), Some(mean)) = (r.entropy_max, r.entropy_mean) {
        kv.push((tr!("Entropia", "Entropy").into(), trf!("maksymalna {mx:.2}, średnia {mean:.2} (skala 0-8); stron zerowych: {}", "maximum {mx:.2}, mean {mean:.2} (scale 0-8); zero pages: {}", r.zero_pages)));
    }
    if let Some(h) = &r.sha256 { kv.push((tr!("SHA-256 zawartości", "Content SHA-256").into(), clean(h))); }
    if let Some(l) = &p.layout {
        let mut sorted: Vec<&Region> = l.iter().collect();
        sorted.sort_by_key(|x| x.base);
        let near = |x: &Region, gap: u64| format!("{:#x} {} {}{}", x.base, x.prot.map(|q| q.to_string()).unwrap_or_else(|| "???".into()), owner(x),
            if gap == 0 { tr!(" (przylega)", " (adjacent)").to_string() } else { trf!(" (odstęp {})", " (gap {})", size_h(gap)) });
        if let Some(x) = sorted.iter().rev().find(|x| x.base < r.region.base) { kv.push((tr!("Sąsiad poniżej", "Neighbour below").into(), near(x, r.region.base.saturating_sub(x.base.saturating_add(x.size))))); }
        if let Some(x) = sorted.iter().find(|x| x.base > r.region.base) { kv.push((tr!("Sąsiad powyżej", "Neighbour above").into(), near(x, x.base.saturating_sub(end)))); }
    }
    b.push(Block::KeyVals(kv));
    if let Some(cells) = r.profile.as_ref().filter(|c| !c.is_empty()) {
        b.push(Block::H3(tr!("Profil entropii regionu", "Region entropy profile").into()));
        b.push(Block::Heat { base: r.region.base, size: r.bytes_read.max(1), cells: cells.clone() });
    }
    if let Some(f) = r.findings.iter().find(|f| f.bytes_hex.is_some()) {
        if let Some(bytes) = f.bytes_hex.as_deref().and_then(unhex).filter(|x| !x.is_empty()) {
            if let Some(facts) = header_facts(&bytes) {
                b.push(Block::H3(tr!("Nagłówek obrazu odczytany z pamięci", "Image header read from memory").into()));
                b.push(Block::KeyVals(facts));
            }
            b.push(Block::H3(trf!("Podgląd bajtów od {:#x}", "Byte preview from {:#x}", f.addr)));
            b.push(Block::Hex { base: f.addr, bytes: bytes.into_iter().take(128).collect() });
        }
    }
    if !r.strings.is_empty() {
        let shown = 15;
        b.push(Block::H3(tr!("Ciągi tekstowe w regionie", "Text strings in the region").into()));
        let mut items: Vec<String> = r.strings.iter().take(shown).map(|s| clean(s)).collect();
        if r.strings.len() > shown { items.push(trf!("... i {} kolejnych w pliku wyniku", "... and {} more in the result file", r.strings.len() - shown)); }
        b.push(Block::Bullets(items));
    }
}

/// Pola nagłówka ELF albo PE odczytane z podglądu bajtów. To dane z badanego procesu: opisują,
/// co nagłówek deklaruje, a nie co faktycznie jest w pamięci.
pub fn header_facts(b: &[u8]) -> Option<Vec<(String, String)>> {
    let u16le = |o: usize| b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]));
    let u32le = |o: usize| b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
    let u64le = |o: usize| b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap()));
    if b.starts_with(b"\x7fELF") && b.len() >= 0x40 && b[5] == 1 {
        let is64 = b[4] == 2;
        let machine = match u16le(18)? { 3 => "x86".into(), 62 => "x86-64".into(), 40 => "ARM".into(), 183 => "AArch64".into(), 243 => "RISC-V".into(), m => trf!("kod {m}", "code {m}") };
        let typ = match u16le(16)? { 1 => tr!("plik relokowalny (REL)", "relocatable file (REL)").into(), 2 => "program (EXEC)".into(), 3 => tr!("biblioteka lub program PIE (DYN)", "library or PIE program (DYN)").into(), 4 => tr!("zrzut (CORE)", "core dump (CORE)").into(), t => trf!("kod {t}", "code {t}") };
        let (entry, phnum, shnum) = if is64 { (u64le(24)?, u16le(56)?, u16le(60)?) } else { (u32le(24)? as u64, u16le(44)?, u16le(48)?) };
        return Some(vec![("Format".into(), trf!("ELF {}-bitowy, {machine}", "ELF {}-bit, {machine}", if is64 { 64 } else { 32 })), (tr!("Typ", "Type").into(), typ),
            (tr!("Punkt wejścia", "Entry point").into(), format!("{entry:#x}")), (tr!("Nagłówki programu / sekcji", "Program / section headers").into(), format!("{phnum} / {shnum}"))]);
    }
    if b.starts_with(b"MZ") {
        let pe = u32le(0x3c)? as usize;
        if b.get(pe..pe + 4)? != b"PE\0\0" { return None; }
        let machine = match u16le(pe + 4)? { 0x14c => "x86".into(), 0x8664 => "x86-64".into(), 0xaa64 => "ARM64".into(), m => trf!("kod {m:#x}", "code {m:#x}") };
        // pole Characteristics leży 22 bajty za sygnaturą: przy nagłówku blisko końca podglądu może go nie być
        let kind = match u16le(pe + 22) { Some(ch) if ch & 0x2000 != 0 => tr!(", biblioteka DLL", ", DLL library"), Some(_) => tr!(", program EXE", ", EXE program"), None => "" };
        return Some(vec![("Format".into(), format!("PE, {machine}{kind}")),
            (tr!("Sekcje", "Sections").into(), u16le(pe + 6)?.to_string()),
            (tr!("Znacznik czasu kompilacji", "Build timestamp").into(), match u32le(pe + 8)? { 0 => tr!("0 (wyzerowany)", "0 (zeroed)").into(), t => rfc3339(t as i64) })]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(base: u64, size: u64, prot: &str, kind: RegionKind, backing: Option<&str>) -> Region {
        Region { base, size, prot: Prot::parse(prot), kind, backing: backing.map(Into::into), backing_deleted: false, label: None, readable: true }
    }
    fn proc_with(layout: Vec<Region>, finding_at: &[u64]) -> ProcessReport {
        let regions = finding_at.iter().map(|&base| {
            let r = layout.iter().find(|r| r.base == base).unwrap().clone();
            RegionReport { region: r.clone(), bytes_read: r.size, truncated: false, entropy_max: Some(7.9), entropy_mean: Some(7.0), zero_pages: 0, score: 60, severity: Severity::High, allowlisted: None,
                findings: vec![Finding { id: format!("1:{base:x}:RWX"), detector: "rwx".into(), tag: "RWX".into(), addr: base, size: r.size, prot: r.prot, entropy: None, weight: 60, reason: "r".into(), bytes_hex: None }],
                heat: None, profile: None, strings: vec![], sha256: None }
        }).collect();
        ProcessReport { info: SourceInfo { os: "linux".into(), arch: "x86_64".into(), pid: Some(1), name: Some("p".into()), source_type: "live".into(), exe: Some("/usr/bin/p".into()), exe_deleted: false, exe_verified: false },
            regions_total: layout.len() as u64, regions_unreadable: 0, bytes_scanned: 0, max_severity: Severity::High, error: None, regions, layout: Some(layout), context: None }
    }

    #[test]
    fn map_merges_files_marks_findings_and_shows_gaps() {
        let layout = vec![
            region(0x40_0000, 0x1000, "r--", RegionKind::Mapped, Some("/usr/bin/p")),
            region(0x40_1000, 0x2000, "r-x", RegionKind::Mapped, Some("/usr/bin/p")),
            region(0x40_3000, 0x1000, "rw-", RegionKind::Mapped, Some("/usr/bin/p")),
            region(0x7f00_0000_0000, 0x10000, "rwx", RegionKind::Private, None),
            region(0x7f00_0001_0000, 0x4000, "rw-", RegionKind::Private, None),
            region(0x7ffc_0000_0000, 0x21000, "rw-", RegionKind::Stack, None),
        ];
        let rows = mem_map(&proc_with(layout.clone(), &[0x7f00_0000_0000]), Severity::Suspicious).unwrap();
        let kinds: Vec<MapClass> = rows.iter().map(|r| r.class).collect();
        assert_eq!(kinds, [MapClass::Code, MapClass::Gap, MapClass::Finding(Severity::High), MapClass::Anon, MapClass::Gap, MapClass::Stack]);
        assert_eq!((rows[0].start, rows[0].end, rows[0].size, rows[0].prot.as_str(), rows[0].note.as_str()), (0x40_0000, 0x40_4000, 0x4000, "r-- r-x rw-", "mapowań: 3"));
        assert_eq!(rows[2].note, "RWX (60 pkt)");
        // kontrola: bez znaleziska ten sam region jest zwykłą pamięcią anonimową i łączy się z sąsiadem
        let plain = mem_map(&proc_with(layout, &[]), Severity::Suspicious).unwrap();
        assert!(plain.iter().all(|r| !matches!(r.class, MapClass::Finding(_))));
        assert_eq!(plain.iter().filter(|r| r.class == MapClass::Anon).count(), 1);
        // bez mapy regionów nie ma diagramu
        let mut p = proc_with(vec![region(0x1000, 0x1000, "rwx", RegionKind::Private, None)], &[0x1000]);
        p.layout = None;
        assert!(mem_map(&p, Severity::Suspicious).is_none());
    }

    #[test]
    fn long_map_is_collapsed_but_findings_and_neighbours_stay() {
        let mut layout: Vec<Region> = (0..200u64).map(|i| region(0x1000_0000 + i * 0x10_0000, 0x1000, "r-x", RegionKind::Mapped, Some(&format!("/usr/lib/lib{i}.so")))).collect();
        layout.push(region(0x1000_0000 + 100 * 0x10_0000 + 0x8000, 0x1000, "rwx", RegionKind::Private, None));
        let rows = mem_map(&proc_with(layout, &[0x1000_0000 + 100 * 0x10_0000 + 0x8000]), Severity::Suspicious).unwrap();
        assert!(rows.len() <= 10, "{}", rows.len());
        let i = rows.iter().position(|r| matches!(r.class, MapClass::Finding(_))).unwrap();
        assert_eq!((rows[i - 1].what.as_str(), rows[i + 1].what.as_str()), ("/usr/lib/lib100.so", "/usr/lib/lib101.so"));
        let collapsed: Vec<&MapRow> = rows.iter().filter(|r| r.class == MapClass::Collapsed).collect();
        assert_eq!(collapsed.len(), 2);
        assert!(collapsed[0].what.starts_with("99 wierszy zwiniętych") && collapsed[0].note.contains("lib1.so"), "{:?}", collapsed[0]);
        // suma rozmiarów nie gubi regionów
        assert_eq!(rows.iter().filter(|r| r.class != MapClass::Gap).map(|r| r.size).sum::<u64>(), 201 * 0x1000);
    }

    #[test]
    fn system_dirs_only_sort_the_report() {
        for p in ["/usr/lib/x.so", "/opt/app/bin/a", "C:\\Windows\\System32\\ntdll.dll", "\\Device\\HarddiskVolume3\\Program Files\\App\\a.dll"] { assert!(in_system_dir(p), "{p}"); }
        for p in ["/home/jan/x.so", "/tmp/x", "C:\\Users\\jan\\AppData\\Roaming\\evil.dll", "D:\\tools\\a.exe", "memfd:x"] { assert!(!in_system_dir(p), "{p}"); }
    }

    #[test]
    fn only_top_regions_get_full_detail() {
        let layout: Vec<Region> = (0..10u64).map(|i| region(0x10_0000 + i * 0x10_0000, 0x1000, "rwx", RegionKind::Private, None)).collect();
        let bases: Vec<u64> = layout.iter().map(|r| r.base).collect();
        let mut p = proc_with(layout, &bases);
        p.regions[9].score = 90; // najwyższy wynik musi trafić do szczegółów mimo ostatniej pozycji
        let scan = ScanResult { schema_version: SCHEMA_VERSION, tool_version: "t".into(), timestamp: "x".into(), host: "h".into(), heat_cell_bytes: 65536, partial: false, processes: vec![p], lang: None, host_info: None, files: vec![] };
        let d = build(&scan, None, &Options { min: Severity::Suspicious, result_sha256: None, result_name: None, kb_dir: None });
        let detailed: Vec<&String> = d.blocks.iter().filter_map(|b| match b { Block::H2(t) if t.starts_with("Region ") => Some(t), _ => None }).collect();
        assert_eq!(detailed.len(), DETAIL_PER_PROCESS);
        assert!(detailed[0].starts_with("Region 0xa00000 "), "{}", detailed[0]);
        assert!(d.blocks.iter().any(|b| matches!(b, Block::Para(t) if t.contains("szczegóły 6 regionów o najwyższym wyniku z 10"))));
        // tabela regionów nadal ma wszystkie
        assert!(d.blocks.iter().any(|b| matches!(b, Block::Table { head, rows, .. } if head[0] == "Adres" && rows.len() == 10)));
    }

    #[test]
    fn map_with_many_findings_keeps_the_top_ones_and_says_what_it_hid() {
        // 60 regionów ze znaleziskami przeplecionych zwykłymi: mapa nie może mieć 120 wierszy
        let mut layout = Vec::new();
        for i in 0..60u64 {
            layout.push(region(0x1000_0000 + i * 0x20_0000, 0x1000, "r-x", RegionKind::Mapped, None));
            layout.push(region(0x1000_0000 + i * 0x20_0000 + 0x1000, 0x1000, "rw-", RegionKind::Private, None));
        }
        let bases: Vec<u64> = layout.iter().filter(|r| r.kind == RegionKind::Mapped).map(|r| r.base).collect();
        let mut p = proc_with(layout, &bases);
        p.regions[59].score = 90;
        let rows = mem_map(&p, Severity::Suspicious).unwrap();
        let shown: Vec<&MapRow> = rows.iter().filter(|r| matches!(r.class, MapClass::Finding(_))).collect();
        assert_eq!(shown.len(), MAP_FINDINGS_MAX);
        assert!(shown.iter().any(|r| r.start == *bases.last().unwrap()), "region o najwyższym wyniku zostaje");
        assert_eq!(shown[0].what, "mapowanie bez nazwy pliku");
        let hidden: usize = rows.iter().filter(|r| r.class == MapClass::Collapsed).filter_map(|r| r.what.split("w tym ").nth(1)?.split(' ').next()?.parse::<usize>().ok()).sum();
        assert_eq!(hidden, 60 - MAP_FINDINGS_MAX, "każde ukryte znalezisko jest policzone w zwiniętym wierszu");
        assert!(rows.len() < 60, "{}", rows.len());
    }

    fn doc_text(d: &Doc) -> String {
        d.blocks.iter().map(|b| match b {
            Block::H1(t) | Block::H2(t) | Block::H3(t) | Block::Para(t) | Block::Note(t) => t.clone(),
            Block::Bullets(v) => v.join("\n"),
            Block::Table { rows, .. } => rows.iter().map(|r| r.join(" | ")).collect::<Vec<_>>().join("\n"),
            Block::KeyVals(kv) => kv.iter().map(|(k, v)| format!("{k}: {}", v.trim_start_matches(CODE))).collect::<Vec<_>>().join("\n"),
            Block::Steps(v) => v.iter().map(|s| format!("{}\n{}\n{}", s.what, s.cmd, s.look)).collect::<Vec<_>>().join("\n"),
            _ => String::new(),
        }).collect::<Vec<_>>().join("\n")
    }
    fn scan_of(p: ProcessReport) -> ScanResult {
        ScanResult { schema_version: SCHEMA_VERSION, tool_version: "t".into(), timestamp: "x".into(), host: "h".into(), heat_cell_bytes: 65536, partial: false, processes: vec![p], lang: None, host_info: None, files: vec![] }
    }
    fn opts() -> Options { Options { min: Severity::Suspicious, result_sha256: None, result_name: None, kb_dir: None } }

    #[test]
    fn knowledge_base_explains_findings_in_plain_language() {
        let layout = vec![region(0x40_0000, 0x1000, "r-x", RegionKind::Mapped, Some("/usr/bin/p")), region(0x7f00_0000_0000, 0x10000, "rwx", RegionKind::Private, None)];
        let mut p = proc_with(layout.clone(), &[0x7f00_0000_0000]);
        let extra = Finding { tag: "X-PRIV".into(), id: "1:7f0000000000:X-PRIV".into(), ..p.regions[0].findings[0].clone() };
        p.regions[0].findings.push(extra);
        let t = doc_text(&build(&scan_of(p.clone()), None, &opts()));
        for want in ["Jak czytać ten raport", "Co to za program", "Co oznaczają znaleziska w tym procesie", "RWX + X-PRIV: kod tworzony w trakcie pracy",
            "Łagodne wyjaśnienie: Kompilacja w locie", "Niepokojące wyjaśnienie: Wstrzyknięty kod", "W tym procesie: W tym procesie nie rozpoznano środowiska",
            "Jak sprawdzić ten region", "gdb -p 1 -batch", "0x7f0000000000 0x7f0000010000", "Słowniczek", "entropia", "W skrócie: kod tworzony w trakcie pracy"] {
            assert!(t.contains(want), "brak: {want}");
        }
        // środowisko JIT wśród zmapowanych plików zmienia wskazówkę na przeciwną
        let mut with_rt = layout.clone();
        with_rt.push(region(0x7f10_0000_0000, 0x1000, "r-x", RegionKind::Mapped, Some("/usr/lib/jvm/lib/server/libjvm.so")));
        let mut q = p.clone(); q.layout = Some(with_rt);
        let t2 = doc_text(&build(&scan_of(q), None, &opts()));
        assert!(t2.contains("załadowane środowisko z kompilacją w locie (Java)") && !t2.contains("nie rozpoznano środowiska"));
        assert!(t2.contains("maszyna wirtualna Javy"), "opis modułu w tabeli plików");
        // bez mapy regionów nie wiemy, czy jest środowisko JIT: raport nie zgaduje w żadną stronę
        let mut r = p.clone(); r.layout = None;
        let t3 = doc_text(&build(&scan_of(r), None, &opts()));
        assert!(!t3.contains("W tym procesie:") && t3.contains("Łagodne wyjaśnienie"));
        // zestaw bez własnego opisu jest składany z opisów pojedynczych cech
        let mut odd = p.clone();
        odd.regions[0].findings[1].tag = "HDR".into();
        let t4 = doc_text(&build(&scan_of(odd), None, &opts()));
        assert!(t4.contains("Ten region łączy kilka cech naraz") && t4.contains("HDR (cały program schowany w pamięci)"));
    }

    #[test]
    fn identical_processes_share_one_row_and_chapter() {
        let mk = |pid: u32, name: &str, n: u64| {
            let layout: Vec<Region> = (0..n).map(|i| region(0x10_0000 + i * 0x10_0000, 0x1000, "rwx", RegionKind::Private, None)).collect();
            let bases: Vec<u64> = layout.iter().map(|r| r.base).collect();
            let mut p = proc_with(layout, &bases);
            p.info.pid = Some(pid); p.info.name = Some(name.into()); p.info.exe = Some(format!("/usr/sbin/{name}"));
            p
        };
        // trzy procesy tego samego programu z tym samym zestawem cech (liczba regionów może się różnić) i jeden inny
        let mut scan = scan_of(mk(10, "apache2", 1));
        scan.processes.push(mk(11, "apache2", 1));
        scan.processes.push(mk(12, "apache2", 2));
        scan.processes.push(mk(20, "sshd", 1));
        let d = build(&scan, None, &opts());
        let chapters: Vec<&String> = d.blocks.iter().filter_map(|b| if let Block::H1(t) = b { Some(t) } else { None }).filter(|t| t.contains("Proces ")).collect();
        assert_eq!(chapters.len(), 2, "{chapters:?}");
        assert!(chapters.iter().any(|t| t.contains("apache2 (i 2 podobnych)")) && chapters.iter().any(|t| t.contains("sshd") && !t.contains("podobnych")), "{chapters:?}");
        let text = doc_text(&d);
        for want in ["(+2)", "w 2 grupach", "działa w 2 innych procesach: PID "] { assert!(text.contains(want), "brak: {want}\n{text}"); }
        // wszystkie numery PID grupy są w raporcie: jeden w tytule rozdziału, pozostałe w uwadze
        let group: Vec<&str> = ["10", "11", "12"].into_iter().filter(|p| chapters.iter().any(|t| t.contains(&format!("Proces {p}:"))) || text.contains(&format!("PID {p}")) || text.contains(&format!(", {p}"))).collect();
        assert_eq!(group.len(), 3, "{text}");
        // podsumowanie liczy procesy, nie grupy
        assert!(text.contains("4 (P1"), "{text}");
        // kontrola: różne programy nie są łączone i nie ma wzmianki o grupach
        let mut two = scan_of(mk(10, "apache2", 1));
        two.processes.push(mk(20, "sshd", 1));
        let t2 = doc_text(&build(&two, None, &opts()));
        assert!(!t2.contains("grupach") && !t2.contains("(+") && !t2.contains("podobnych)"), "{t2}");
        // kontrola: ten sam program z innym zestawem cech to osobna grupa
        let mut other = mk(13, "apache2", 1);
        other.regions[0].findings[0].tag = "X-PRIV".into();
        let mut mixed = scan_of(mk(10, "apache2", 1));
        mixed.processes.push(other);
        let dm = build(&mixed, None, &opts());
        let hm: Vec<&String> = dm.blocks.iter().filter_map(|b| if let Block::H1(t) = b { Some(t) } else { None }).filter(|t| t.contains("Proces ")).collect();
        assert!(hm.len() == 2 && hm.iter().all(|t| !t.contains("podobnych")), "{hm:?}");
    }

    #[test]
    fn overview_matrix_tree_scatter_and_hashes() {
        let mk = |pid: u32, name: &str, n: u64, parent: u32| {
            let layout: Vec<Region> = (0..n).map(|i| region(0x10_0000 + i * 0x10_0000, 0x1000 << i, "rwx", RegionKind::Private, None))
                .chain(std::iter::once(region(0x7f00_0000_0000, 0x1000, "r-x", RegionKind::Mapped, Some("/usr/lib/libssl.so.3")))).collect();
            let bases: Vec<u64> = layout.iter().filter(|r| r.backing.is_none()).map(|r| r.base).collect();
            let mut p = proc_with(layout, &bases);
            p.info.pid = Some(pid); p.info.name = Some(name.into());
            p.regions[0].sha256 = Some("ab".repeat(32));
            p.context = Some(ProcessContext { ancestors: vec![ProcRef { pid: parent, name: "rodzic".into(), exe: None, cmdline: None }, ProcRef { pid: 1, name: "init".into(), exe: None, cmdline: None }], ..Default::default() });
            p
        };
        let mut scan = scan_of(mk(10, "pierwszy", 4, 5));
        scan.processes.push(mk(11, "drugi", 1, 5));
        scan.files = vec![FileHash { path: "/usr/lib/libssl.so.3".into(), size: 10, sha256: Some("cd".repeat(32)), note: None }];
        let d = build(&scan, None, &opts());
        // macierz: wiersz na proces, kolumna na cechę, liczba regionów w komórce
        let (cols, rows) = d.blocks.iter().find_map(|b| match b { Block::Matrix { cols, rows } => Some((cols, rows)), _ => None }).expect("macierz");
        assert_eq!(cols, &["RWX"]);
        assert_eq!(rows.iter().map(|r| (r.0.as_str(), r.1[0])).collect::<Vec<_>>(), [("10 pierwszy", (4, Severity::High)), ("11 drugi", (1, Severity::High))]);
        // wspólne drzewo: jeden korzeń, wspólny rodzic raz, oba procesy zaznaczone
        let tree = d.blocks.iter().filter_map(|b| match b { Block::Tree(t) => Some(t), _ => None }).next().expect("drzewo");
        assert_eq!(tree.iter().map(|n| (n.depth, n.text.as_str(), n.mark)).collect::<Vec<_>>(),
            [(0, "1 init", false), (1, "5 rodzic", false), (2, "10 pierwszy (wysokie)", true), (2, "11 drugi (wysokie)", true)]);
        // wykres rozrzutu tylko dla procesu z co najmniej trzema regionami
        let scatters: Vec<&Vec<(u64, f32, Severity)>> = d.blocks.iter().filter_map(|b| match b { Block::Scatter(p) => Some(p), _ => None }).collect();
        assert_eq!((scatters.len(), scatters[0].len()), (1, 4));
        let t = doc_text(&d);
        assert!(t.contains(&format!("SHA-256 zawartości: {}", "ab".repeat(32))), "skrót regionu");
        assert!(t.contains(&format!("libssl.so.3 | {}", "cd".repeat(32))), "skrót pliku zmapowanego");
        // kontrola: jeden proces nie ma macierzy z drzewem hosta, a wynik bez skrótów mówi o tym wprost
        let single = build(&scan_of(mk(10, "pierwszy", 1, 5)), None, &opts());
        assert!(!single.blocks.iter().any(|b| matches!(b, Block::H3(t) if t == "Drzewo procesów ze znaleziskami")));
        assert!(doc_text(&single).contains("nie zawiera skrótów SHA-256 plików"));
        // oba formaty rysują nowe bloki bez paniki
        let md = crate::md::render(&d);
        assert!(md.contains("| 10 pierwszy | 4 (wysokie) |") && md.contains("Entropia \\\\ rozmiar"));
        assert!(crate::pdf::render(&d).starts_with(b"%PDF-"));
    }

    #[test]
    fn report_states_scanner_privileges_and_warns_when_limited() {
        let p = proc_with(vec![region(0x10000, 0x1000, "rwx", RegionKind::Private, None)], &[0x10000]);
        let mut scan = scan_of(p);
        scan.host_info = Some(HostContext { scanner_user: Some("H\\jan".into()), scanner_privileges: Some("bez uprawnień administratora; poziom integralności: średni".into()), scanner_limited: true, ..Default::default() });
        let t = doc_text(&build(&scan, None, &opts()));
        assert!(t.contains("Uprawnienia skanera: bez uprawnień administratora") && t.contains("UWAGA: skan wykonano bez pełnych uprawnień"));
        // kontrola: pełne uprawnienia są pokazane, ale bez ostrzeżenia
        scan.host_info = Some(HostContext { scanner_privileges: Some("konto SYSTEM; SeDebugPrivilege: włączone".into()), scanner_limited: false, ..Default::default() });
        let t = doc_text(&build(&scan, None, &opts()));
        assert!(t.contains("Uprawnienia skanera: konto SYSTEM") && !t.contains("bez pełnych uprawnień"));
    }

    #[test]
    fn flow_links_regions_process_and_sockets_without_overclaiming() {
        let mut p = proc_with(vec![region(0x10000, 0x1000, "rwx", RegionKind::Private, None), region(0x30000, 0x1000, "rwx", RegionKind::Private, None)], &[0x10000, 0x30000]);
        p.info.pid = Some(77); p.info.name = Some("agent".into());
        let sock = |proto: &str, local: &str, remote: Option<&str>, state: Option<&str>| Socket { proto: proto.into(), local: local.into(), remote: remote.map(Into::into), state: state.map(Into::into) };
        p.context = Some(ProcessContext { user: Some("SYSTEM".into()), sockets: vec![sock("tcp", "0.0.0.0:8080", None, Some("LISTEN")),
            sock("tcp", "10.0.0.5:51000", Some("203.0.113.9:443"), Some("ESTABLISHED")), sock("unix", "/run/x.sock", None, None)], ..Default::default() });
        let d = build(&scan_of(p.clone()), None, &opts());
        let (regions, process, endpoints) = d.blocks.iter().find_map(|b| match b { Block::Flow { regions, process, endpoints } => Some((regions, process, endpoints)), _ => None }).expect("diagram");
        assert_eq!(regions.len(), 2);
        assert!(regions[0].0.starts_with("0x10000 RWX (60 pkt)"));
        assert_eq!(process, "77 agent, SYSTEM");
        // połączenie zdalne pierwsze, potem nasłuch; gniazdo uniksowe pominięte
        assert_eq!(endpoints, &[("tcp 10.0.0.5:51000 -> 203.0.113.9:443 (ESTABLISHED)".to_string(), true), ("nasłuch tcp 0.0.0.0:8080".to_string(), false)]);
        assert!(doc_text(&d).contains("nie dowodzi, że to kod z danego regionu otworzył połączenie"));
        // proces bez gniazd: diagram mówi to wprost; bez kontekstu diagramu nie ma
        let mut quiet = p.clone(); quiet.context = Some(ProcessContext::default());
        let dq = build(&scan_of(quiet), None, &opts());
        assert!(dq.blocks.iter().any(|b| matches!(b, Block::Flow { endpoints, .. } if endpoints[0].0 == "brak gniazd sieciowych w chwili skanu")));
        let mut none = p.clone(); none.context = None;
        assert!(!build(&scan_of(none), None, &opts()).blocks.iter().any(|b| matches!(b, Block::Flow { .. })));
        let md = crate::md::render(&d);
        assert!(md.contains("| 0x10000 RWX (60 pkt) | =&gt; 77 agent, SYSTEM =&gt; | tcp 10.0.0.5:51000 -&gt; 203.0.113.9:443 (ESTABLISHED) |"), "{md}");
        assert!(crate::pdf::render(&d).starts_with(b"%PDF-"));
    }

    #[test]
    fn priority_follows_findings_and_context_and_summary_is_calibrated() {
        let kb = Kb::embedded("linux");
        let base = |with_rt: bool| {
            let mut layout = vec![region(0x10000, 0x1000, "rwx", RegionKind::Private, None)];
            if with_rt { layout.push(region(0x7f10_0000_0000, 0x1000, "r-x", RegionKind::Mapped, Some("/usr/lib/jvm/lib/server/libjvm.so"))); }
            let mut p = proc_with(layout, &[0x10000]);
            p.info.exe = Some("/usr/bin/p".into());
            p
        };
        // waga wysoka bez środowiska JIT: P1; z rozpoznanym środowiskiem: P2 z jego nazwą; bez mapy pamięci: P2 z zastrzeżeniem
        assert_eq!(priority(&base(false), &kb, Severity::Suspicious).0, "P1");
        let (p2, why, step) = priority(&base(true), &kb, Severity::Suspicious);
        assert!(p2 == "P2" && why[0].contains("środowisko Java") && step.contains("skrót SHA-256"), "{why:?}");
        let mut unknown = base(false); unknown.layout = None;
        let (pu, why_u, _) = priority(&unknown, &kb, Severity::Suspicious);
        assert!(pu == "P2" && why_u[0].contains("nie zawiera mapy pamięci"));
        // cecha, której JIT nie tłumaczy, daje P1 mimo środowiska
        let mut thr = base(true);
        let extra = Finding { tag: "THR-PRIV".into(), ..thr.regions[0].findings[0].clone() };
        thr.regions[0].findings.push(extra);
        let (pt, why_t, step_t) = priority(&thr, &kb, Severity::Suspicious);
        assert!(pt == "P1" && why_t[0].contains("THR-PRIV") && step_t.contains("zrzut pamięci"));
        // waga podejrzane: P3 w katalogu systemowym, P2 poza nim; uprawnienia i sieć są dopisywane do uzasadnienia
        let mut low = base(true); low.max_severity = Severity::Suspicious; low.regions[0].severity = Severity::Suspicious; low.regions[0].score = 30;
        assert_eq!(priority(&low, &kb, Severity::Suspicious).0, "P3");
        low.info.exe = Some("/home/jan/p".into());
        low.context = Some(ProcessContext { user: Some("root (uid 0)".into()), sockets: vec![Socket { proto: "tcp".into(), local: "10.0.0.1:1".into(), remote: Some("203.0.113.9:443".into()), state: None }], ..Default::default() });
        let (pl, why_l, _) = priority(&low, &kb, Severity::Suspicious);
        assert!(pl == "P2" && why_l.iter().any(|w| w.contains("wysokimi uprawnieniami")) && why_l.iter().any(|w| w.contains("adresami zdalnymi")), "{why_l:?}");

        // podsumowanie dla decydenta: P1 każe zabezpieczyć zrzut; brak znalezisk nie jest nazywany czystością
        let t = doc_text(&build(&scan_of(base(false)), None, &opts()));
        assert!(t.contains("1. Podsumowanie dla decydenta") && t.contains("Wymaga weryfikacji w pierwszej kolejności") && t.contains("(P1: 1, P2: 0, P3: 0)") && t.contains("zabezpieczyć zrzut pamięci procesu"));
        assert!(t.contains("Priorytet weryfikacji: P1") && t.contains("Podstawa techniczna. RWX:") && t.contains("T1055 Process Injection"));
        let mut clean_scan = scan_of(base(false));
        clean_scan.processes[0].regions.clear(); clean_scan.processes[0].max_severity = Severity::None;
        let tc = doc_text(&build(&clean_scan, None, &opts()));
        assert!(tc.contains("Nie jest to potwierdzenie, że stacja jest wolna od złośliwego kodu") && !tc.contains("zabezpieczyć zrzut"));
        // skan bez pełnych uprawnień: pierwszym zaleceniem jest powtórka
        let mut lim = scan_of(base(true));
        lim.host_info = Some(HostContext { scanner_limited: true, ..Default::default() });
        assert!(doc_text(&build(&lim, None, &opts())).contains("Powtórzyć skan z pełnymi uprawnieniami"));
        // rozdziały główne są numerowane kolejno
        let d = build(&scan_of(base(true)), None, &opts());
        let h1: Vec<&String> = d.blocks.iter().filter_map(|b| match b { Block::H1(t) => Some(t), _ => None }).collect();
        assert!(h1.iter().enumerate().all(|(i, t)| t.starts_with(&format!("{}. ", i + 1))), "{h1:?}");
    }

    #[test]
    fn identity_check_flags_a_known_name_in_the_wrong_place() {
        let mk = |name: &str, exe: &str, parent: &str| {
            let mut p = proc_with(vec![region(0x10000, 0x1000, "rwx", RegionKind::Private, None)], &[0x10000]);
            p.info.os = "windows".into(); p.info.name = Some(name.into()); p.info.exe = Some(exe.into());
            p.context = Some(ProcessContext { ancestors: vec![ProcRef { pid: 4, name: parent.into(), exe: None, cmdline: None }], ..Default::default() });
            doc_text(&build(&scan_of(p), None, &opts()))
        };
        let good = mk("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "services.exe");
        assert!(good.contains("Wspólny proces-gospodarz usług") && good.contains("Położenie pliku jest typowe") && good.contains("Proces nadrzędny (services.exe) jest typowy") && !good.contains("UWAGA"));
        let bad = mk("svchost.exe", "C:\\Users\\jan\\AppData\\svchost.exe", "WINWORD.EXE");
        assert!(bad.contains("UWAGA: plik leży w nietypowym miejscu") && bad.contains("UWAGA: nietypowy proces nadrzędny (WINWORD.EXE)"));
        let unknown = mk("cos-wlasnego.exe", "C:\\x\\cos-wlasnego.exe", "explorer.exe");
        assert!(unknown.contains("nie opisuje programu o tej nazwie") && !unknown.contains("UWAGA"));
    }

    #[test]
    fn external_knowledge_base_replaces_the_embedded_one() {
        let dir = std::env::temp_dir().join(format!("nanshe-kb-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("common.json"), r#"{"version":"moja","guide":["Własny przewodnik zespołu."],"tags":{"RWX":{"name":"rwx","en":"e","meaning":"m","why":"w"}}}"#).unwrap();
        let p = proc_with(vec![region(0x10000, 0x1000, "rwx", RegionKind::Private, None)], &[0x10000]);
        let t = doc_text(&build(&scan_of(p.clone()), None, &Options { kb_dir: Some(dir.clone()), ..opts() }));
        assert!(t.contains("Własny przewodnik zespołu.") && t.contains("wersja moja") && !t.contains("Raport przedstawia wynik przeglądu pamięci"));
        // kontrola: bez katalogu jest baza wbudowana
        assert!(doc_text(&build(&scan_of(p), None, &opts())).contains("Raport przedstawia wynik przeglądu pamięci"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn headers_decoded_and_garbage_ignored() {
        let mut elf = vec![0u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[16] = 3; elf[18] = 183; elf[24..32].copy_from_slice(&0x1040u64.to_le_bytes()); elf[56] = 9; elf[60] = 28;
        let f = header_facts(&elf).unwrap();
        assert_eq!(f[0].1, "ELF 64-bitowy, AArch64");
        assert_eq!((f[1].1.as_str(), f[2].1.as_str(), f[3].1.as_str()), ("biblioteka lub program PIE (DYN)", "0x1040", "9 / 28"));
        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ"); pe[0x3c] = 0x80; pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); pe[0x86] = 5; pe[0x88..0x8c].copy_from_slice(&951782400u32.to_le_bytes()); pe[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
        let f = header_facts(&pe).unwrap();
        assert_eq!((f[0].1.as_str(), f[1].1.as_str(), f[2].1.as_str()), ("PE, x86-64, biblioteka DLL", "5", "2000-02-29T00:00:00Z"));
        // nagłówek PE pod przesunięciem 0xf0 w podglądzie 256 bajtów: pole z rodzajem pliku jest już poza
        // podglądem, ale format, liczba sekcji i znacznik czasu nadal są odczytywane
        let mut late = vec![0u8; 256];
        late[..2].copy_from_slice(b"MZ"); late[0x3c] = 0xf0; late[0xf0..0xf4].copy_from_slice(b"PE\0\0");
        late[0xf4..0xf6].copy_from_slice(&0x8664u16.to_le_bytes()); late[0xf6] = 7; late[0xf8..0xfc].copy_from_slice(&951782400u32.to_le_bytes());
        let f = header_facts(&late).unwrap();
        assert_eq!((f[0].1.as_str(), f[1].1.as_str(), f[2].1.as_str()), ("PE, x86-64", "7", "2000-02-29T00:00:00Z"));
        // kontrole: sama sygnatura MZ, obcięty ELF, losowe dane
        pe[0x80] = b'X';
        assert!(header_facts(&pe).is_none());
        assert!(header_facts(&elf[..20]).is_none());
        assert!(header_facts(&[0x90; 128]).is_none());
        // wskaźnik nagłówka PE poza podglądem nie powoduje paniki
        let mut far = vec![0u8; 64]; far[..2].copy_from_slice(b"MZ"); far[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert!(header_facts(&far).is_none());
    }
}

/// Środowisko z kompilacją w locie rozpoznane w procesie: po zmapowanych plikach opisanych w bazie
/// wiedzy. None, gdy wynik nie ma mapy regionów (wtedy nie wiemy).
fn runtime_of(kb: &Kb, p: &ProcessReport) -> Option<Option<String>> {
    let layout = p.layout.as_ref()?;
    Some(layout.iter().filter_map(|r| r.backing.as_deref()).find_map(|b| kb.module(b).and_then(|m| m.runtime.clone())))
}

fn combo_title(kb: &Kb, tags: &[&str]) -> String {
    match kb.combo(tags) {
        Some(c) => c.title.clone(),
        None => { let mut t: Vec<&str> = tags.to_vec(); t.sort_unstable(); t.dedup(); t.iter().map(|x| kb.tags.get(*x).map(|i| i.name.as_str()).unwrap_or(x)).collect::<Vec<_>>().join(tr!(" oraz ", " and ")) }
    }
}

/// „Co to za program": opis z bazy wiedzy i porównanie położenia pliku oraz rodzica z typowymi.
/// To objaśnienie, nie punktacja: nazwę proces nadaje sobie sam.
fn identity(b: &mut Vec<Block>, kb: &Kb, p: &ProcessReport, system_drive: Option<&str>) {
    b.push(Block::H2(tr!("Co to za program", "What this program is").into()));
    let name = p.info.name.as_deref().unwrap_or("");
    let Some(info) = kb.process(name) else {
        b.push(Block::Para(tr!("Baza wiedzy narzędzia nie opisuje programu o tej nazwie. To nie znaczy, że jest podejrzany: ustal, czym jest, po ścieżce pliku, wierszu poleceń i skrócie SHA-256 (można go wyszukać w bazach znanych plików).", "The tool's knowledge base does not describe a program with this name. This does not mean it is suspicious: establish what it is from the file path, the command line and the SHA-256 hash (which can be looked up in databases of known files).").into()));
        return;
    };
    b.push(Block::Para(trf!("Program o nazwie {} to zwykle: {}", "A program named {} is usually: {}", clean(name), info.what)));
    let mut items = Vec::new();
    match p.info.exe.as_deref().and_then(|e| Kb::path_expected(info, e, system_drive).map(|ok| (e, ok))) {
        Some((_, true)) => items.push(tr!("Położenie pliku jest typowe dla tego programu.", "The file location is typical for this program.").to_string()),
        Some((e, false)) => items.push(trf!("UWAGA: plik leży w nietypowym miejscu ({}). Program podszywający się pod znaną nazwę wygląda właśnie tak; możliwa jest też niestandardowa instalacja. Sprawdź skrót SHA-256 i podpis pliku.", "WARNING: the file is in an unusual location ({}). A program masquerading under a known name looks exactly like this; a non-standard installation is also possible. Check the SHA-256 hash and the file signature.", clean(e))),
        None => {}
    }
    if let Some(parent) = p.context.as_ref().and_then(|c| c.ancestors.first()) {
        match Kb::parent_expected(info, &parent.name) {
            Some(true) => items.push(trf!("Proces nadrzędny ({}) jest typowy dla tego programu.", "The parent process ({}) is typical for this program.", clean(&parent.name))),
            Some(false) => items.push(trf!("UWAGA: nietypowy proces nadrzędny ({}). Ustal, dlaczego to on uruchomił ten program.", "WARNING: unusual parent process ({}). Establish why it started this program.", clean(&parent.name))),
            None => {}
        }
    }
    items.push(tr!("Nazwę procesu program może ustawić sam, więc powyższe opiera się na nazwie tylko jako na wskazówce.", "A program can set its own process name, so the above relies on the name only as a hint.").to_string());
    b.push(Block::Bullets(items));
}

/// „Co oznaczają znaleziska w tym procesie": każdy zestaw tagów raz, z liczbą regionów,
/// wyjaśnieniem, łagodnymi i niepokojącymi przyczynami oraz wskazówką dla tego procesu.
fn explain_findings(b: &mut Vec<Block>, kb: &Kb, p: &ProcessReport, regs: &[&RegionReport]) {
    if regs.is_empty() { return; }
    b.push(Block::H2(tr!("Co oznaczają znaleziska w tym procesie", "What the findings mean in this process").into()));
    let runtime = runtime_of(kb, p);
    // zestawy w kolejności od najwyższego wyniku (regs są już tak posortowane)
    let mut sets: Vec<(Vec<&str>, usize, u32)> = Vec::new();
    for r in regs {
        let mut t: Vec<&str> = r.findings.iter().map(|f| f.tag.as_str()).collect();
        t.sort_unstable(); t.dedup();
        match sets.iter_mut().find(|s| s.0 == t) { Some(s) => s.1 += 1, None => sets.push((t, 1, r.score)) }
    }
    for (tags, n, score) in sets {
        b.push(Block::H3(format!("{}: {}", tags.join(" + "), combo_title(kb, &tags))));
        b.push(Block::Para(trf!("Regionów z tym zestawem cech: {n}; najwyższy wynik: {score} pkt.", "Regions with this set of characteristics: {n}; highest score: {score} pts.")));
        let tech: Vec<String> = tags.iter().filter_map(|t| kb.tags.get(*t).filter(|i| !i.tech.is_empty()).map(|i| format!("{t}: {}", i.tech))).collect();
        let mut attack: Vec<&str> = tags.iter().filter_map(|t| kb.tags.get(*t)).flat_map(|i| i.attack.iter().map(String::as_str)).collect();
        attack.sort_unstable(); attack.dedup();
        match kb.combo(&tags) {
            Some(c) => {
                b.push(Block::Para(c.meaning.clone()));
                let mut items: Vec<String> = c.benign.iter().map(|x| trf!("Łagodne wyjaśnienie: {x}", "Benign explanation: {x}")).collect();
                items.extend(c.malicious.iter().map(|x| trf!("Niepokojące wyjaśnienie: {x}", "Malicious explanation: {x}")));
                if let Some(rt) = &runtime {
                    for h in c.hints.iter().filter(|h| h.runtime == Some(rt.is_some())) {
                        items.push(trf!("W tym procesie: {}", "In this process: {}", h.text.replace("{runtime}", rt.as_deref().unwrap_or(""))));
                    }
                }
                b.push(Block::Bullets(items));
            }
            None => {
                // brak opisu całego zestawu: składamy go z opisów pojedynczych cech
                let items: Vec<String> = tags.iter().filter_map(|t| kb.tags.get(*t).map(|i| format!("{t} ({}): {} {}", i.name, i.meaning, i.why))).collect();
                if items.is_empty() { b.push(Block::Para(tr!("Baza wiedzy nie opisuje tych cech.", "The knowledge base does not describe these characteristics.").into())); } else {
                    b.push(Block::Para(tr!("Ten region łączy kilka cech naraz; każda jest opisana osobno. Im więcej cech w jednym regionie, tym mniej prawdopodobne łagodne wyjaśnienie.", "This region combines several characteristics at once; each is described separately. The more characteristics in one region, the less likely a benign explanation.").into()));
                    b.push(Block::Bullets(items));
                }
            }
        }
        // warstwa dla doświadczonego czytelnika: dokładny warunek detektora i odniesienie do katalogu technik
        if !tech.is_empty() { b.push(Block::Para(trf!("Podstawa techniczna. {}", "Technical basis. {}", tech.join(" ")))); }
        if !attack.is_empty() { b.push(Block::Para(trf!("Powiązane techniki MITRE ATT&CK (orientacyjnie; znalezisko nie dowodzi użycia techniki): {}.", "Related MITRE ATT&CK techniques (indicative; a finding does not prove the technique was used): {}.", attack.join(", ")))); }
    }
}

/// Wspólne drzewo procesów ze znaleziskami, złożone z łańcuchów przodków zapisanych w kontekście.
/// None, gdy żaden proces nie ma kontekstu albo jest tylko jeden proces.
fn host_tree(order: &[&ProcessReport]) -> Option<Vec<TreeNode>> {
    use std::collections::BTreeMap;
    if order.len() < 2 || order.iter().all(|p| p.context.is_none()) { return None; }
    // pid -> (rodzic, tekst, czy proces ze znaleziskiem)
    let mut nodes: BTreeMap<u32, (Option<u32>, String, bool)> = BTreeMap::new();
    for p in order {
        let Some(pid) = p.info.pid else { continue };
        let anc = p.context.as_ref().map(|c| c.ancestors.as_slice()).unwrap_or(&[]);
        let mut parent = None;
        for a in anc.iter().rev() {
            nodes.entry(a.pid).or_insert((parent, format!("{} {}", a.pid, clean(&a.name)), false));
            parent = Some(a.pid);
        }
        let text = format!("{pid} {} ({})", clean(p.info.name.as_deref().unwrap_or("?")), crate::sev_label(p.max_severity));
        let e = nodes.entry(pid).or_insert((parent, text.clone(), true));
        *e = (e.0.or(parent), text, true);
    }
    let mut out = Vec::new();
    fn walk(pid: u32, depth: u8, nodes: &BTreeMap<u32, (Option<u32>, String, bool)>, out: &mut Vec<TreeNode>) {
        let (_, text, mark) = &nodes[&pid];
        out.push(TreeNode { depth, text: text.clone(), mark: *mark });
        if depth >= 24 { return; }
        for (k, v) in nodes { if v.0 == Some(pid) && *k != pid { walk(*k, depth + 1, nodes, out); } }
    }
    let roots: Vec<u32> = nodes.iter().filter(|(_, v)| v.0.map(|p| !nodes.contains_key(&p)).unwrap_or(true)).map(|(k, _)| *k).collect();
    for r in roots { walk(r, 0, &nodes, &mut out); }
    Some(out)
}

/// Diagram „od pamięci do sieci": regiony ze znaleziskami, proces i jego gniazda z chwili skanu.
/// Łączy fakty zebrane osobno; nie przypisuje połączenia do konkretnego regionu.
fn flow(b: &mut Vec<Block>, p: &ProcessReport, c: &ProcessContext, regs: &[&RegionReport]) {
    if regs.is_empty() { return; }
    const MAX: usize = 6;
    let mut regions: Vec<(String, Severity)> = regs.iter().take(MAX).map(|r| (trf!("{:#x} {} ({} pkt)", "{:#x} {} ({} pts)", r.region.base,
        r.findings.iter().map(|f| f.tag.as_str()).collect::<Vec<_>>().join(", "), r.score), r.severity)).collect();
    if regs.len() > MAX { regions.push((trf!("... i {} kolejnych regionów", "... and {} more regions", regs.len() - MAX), Severity::Info)); }
    // najpierw połączenia z adresem zdalnym, potem nasłuch; gniazda uniksowe pomijamy (to komunikacja lokalna)
    let mut endpoints: Vec<(String, bool)> = Vec::new();
    for s in c.sockets.iter().filter(|s| s.proto != "unix") {
        let e = match &s.remote {
            Some(r) => (format!("{} {} -> {}{}", clean(&s.proto), clean(&s.local), clean(r), s.state.as_deref().map(|x| format!(" ({})", clean(x))).unwrap_or_default()), true),
            None => (trf!("nasłuch {} {}", "listening {} {}", clean(&s.proto), clean(&s.local)), false),
        };
        if !endpoints.contains(&e) { endpoints.push(e); }
    }
    endpoints.sort_by(|a, c| c.1.cmp(&a.1));
    let total = endpoints.len();
    endpoints.truncate(8);
    if total > 8 { endpoints.push((trf!("... i {} kolejnych gniazd", "... and {} more sockets", total - 8), false)); }
    if endpoints.is_empty() { endpoints.push((tr!("brak gniazd sieciowych w chwili skanu", "no network sockets at scan time").into(), false)); }
    b.push(Block::H2(tr!("Od pamięci do sieci", "From memory to network").into()));
    b.push(Block::Para(tr!("Regiony ze znaleziskami, proces i jego połączenia sieciowe z chwili skanu. Diagram pokazuje, że podejrzany kod i połączenie współistnieją w jednym procesie; nie dowodzi, że to kod z danego regionu otworzył połączenie.", "Regions with findings, the process and its network connections at scan time. The diagram shows that suspicious code and a connection coexist in one process; it does not prove that code from a given region opened the connection.").into()));
    let who = c.user.as_deref().map(|u| format!(", {}", clean(u))).unwrap_or_default();
    b.push(Block::Flow { regions, process: format!("{} {}{}", pid_s(p), clean(p.info.name.as_deref().unwrap_or("?")), who), endpoints });
}

/// Grupy procesów, które w raporcie wyglądają tak samo: ten sam plik programu i nazwa, ten sam zestaw
/// cech w pokazanych regionach i ten sam priorytet. Kolejność grup i procesów w grupie jak w `order`.
/// Pierwszy proces grupy jest opisywany w całości, pozostałe są przy nim wymienione.
pub fn group_similar<'a>(order: &[&'a ProcessReport], kb: &Kb, min: Severity) -> Vec<Vec<&'a ProcessReport>> {
    let key = |p: &ProcessReport| {
        let mut t: Vec<String> = shown_regions(p, min).iter().flat_map(|r| r.findings.iter().map(|f| f.tag.clone())).collect();
        t.sort(); t.dedup();
        (p.info.exe.clone().unwrap_or_default(), p.info.name.clone().unwrap_or_default(), t, priority(p, kb, min).0, p.max_severity)
    };
    let mut groups: Vec<(_, Vec<&ProcessReport>)> = Vec::new();
    for p in order {
        let k = key(p);
        match groups.iter_mut().find(|g| g.0 == k) { Some(g) => g.1.push(p), None => groups.push((k, vec![p])) }
    }
    groups.into_iter().map(|g| g.1).collect()
}

/// Cechy, których nie tłumaczy samo środowisko kompilujące kod w locie.
const STRONG_TAGS: [&str; 4] = ["THR-PRIV", "HDR", "MEMFD", "GUARD-X"];

/// Priorytet weryfikacji procesu: (P1 | P2 | P3, uzasadnienie zdaniami, pierwszy krok).
/// To kolejność pracy analityka wyprowadzona wprost ze znalezisk i kontekstu, nie nowa punktacja:
/// - P1: cecha, której nie tłumaczy środowisko JIT (wątek w pamięci bez pliku, obraz programu
///   w pamięci, kod z pliku tylko w pamięci, kod za stroną strażnika, zmieniony moduł ochronny),
///   albo waga „wysokie" w procesie bez rozpoznanego środowiska JIT;
/// - P2: waga „wysokie" z rozpoznanym środowiskiem JIT albo bez wiedzy o nim, oraz waga „podejrzane"
///   w programie spoza katalogów systemowych;
/// - P3: pozostałe.
pub fn priority(p: &ProcessReport, kb: &Kb, min: Severity) -> (&'static str, Vec<String>, String) {
    let regs = shown_regions(p, min);
    // cecha o wadze obniżonej przez detektor (np. memfd biblioteki libffi, nagłówek w pamięci maszyny wirtualnej)
    // nie wymusza najwyższego priorytetu
    let has = |t: &str| regs.iter().any(|r| r.findings.iter().any(|f| f.tag == t && f.weight >= 30));
    let strong: Vec<&str> = STRONG_TAGS.iter().copied().filter(|t| has(t)).collect();
    let patched_guard = regs.iter().any(|r| r.findings.iter().any(|f| f.tag == "IMG-MOD" && f.weight >= 40));
    let runtime = runtime_of(kb, p);
    let outside = p.info.exe.as_deref().map(|e| !in_system_dir(e)).unwrap_or(false);
    let privileged = p.context.as_ref().map(|c| c.user.as_deref().map(|u| u.contains("SYSTEM") || u.starts_with("root")).unwrap_or(false)
        || c.flags.iter().any(|f| (f.0.starts_with("poziom integralności") && (f.1 == "systemowy" || f.1 == "wysoki")) || (f.0.starts_with("integrity level") && (f.1 == "system" || f.1 == "high")))).unwrap_or(false);
    let remote = p.context.as_ref().map(|c| c.sockets.iter().any(|s| s.remote.is_some())).unwrap_or(false);
    let mut why: Vec<String> = Vec::new();
    let pid = pid_s(p);

    let prio = if !strong.is_empty() || patched_guard {
        let mut names: Vec<String> = strong.iter().map(|t| format!("{t} ({})", kb.tags.get(*t).map(|i| i.name.as_str()).unwrap_or(""))).collect();
        if patched_guard { names.push(tr!("IMG-MOD (kod biblioteki różni się od pliku na dysku)", "IMG-MOD (library code differs from the file on disk)").into()); }
        why.push(trf!("Występuje cecha, której nie tłumaczy środowisko kompilujące kod w locie: {}.", "A characteristic is present that a just-in-time (JIT) runtime does not explain: {}.", names.join(", ")));
        "P1"
    } else if p.max_severity >= Severity::High && runtime == Some(None) {
        why.push(tr!("Region o wadze „wysokie\" w procesie, w którym nie rozpoznano środowiska kompilującego kod w locie, więc brak gotowego łagodnego wyjaśnienia.", "A region of severity \"high\" in a process where no JIT runtime was recognised, so there is no ready benign explanation.").into());
        "P1"
    } else if p.max_severity >= Severity::High {
        match &runtime {
            Some(Some(rt)) => why.push(trf!("Regiony o wadze „wysokie\" mają prawdopodobne łagodne wyjaśnienie: w procesie działa środowisko {rt}, które tworzy takie regiony. Wymaga potwierdzenia, bo wstrzyknięty kod mógłby się wśród nich ukryć.", "Regions of severity \"high\" have a probable benign explanation: the {rt} runtime, which creates such regions, is running in the process. Confirmation is required, because injected code could hide among them.")),
            _ => why.push(tr!("Regiony o wadze „wysokie\"; wynik nie zawiera mapy pamięci, więc nie wiadomo, czy w procesie działa środowisko kompilujące kod w locie.", "Regions of severity \"high\"; the result contains no memory map, so it is not known whether a JIT runtime is running in the process.").into()),
        }
        "P2"
    } else if outside {
        why.push(tr!("Znaleziska o wadze „podejrzane\" w programie uruchomionym spoza katalogów systemowych.", "Findings of severity \"suspicious\" in a program started from outside system directories.").into());
        "P2"
    } else {
        why.push(tr!("Pojedyncze cechy o wadze „podejrzane\" w programie z katalogu systemowego; najczęściej mają przyczynę łagodną.", "Isolated characteristics of severity \"suspicious\" in a program from a system directory; they most often have a benign cause.").into());
        "P3"
    };
    // okoliczności, które nie zmieniają priorytetu, ale zmieniają wagę ewentualnego błędu w ocenie
    if outside && prio != "P2" || (outside && p.max_severity >= Severity::High) { why.push(tr!("Plik programu leży poza katalogami systemowymi.", "The program file is located outside system directories.").into()); }
    if privileged { why.push(tr!("Proces działa z wysokimi uprawnieniami, więc przejęcie go oznaczałoby kontrolę nad stacją.", "The process runs with high privileges, so compromising it would mean control of the host.").into()); }
    if remote { why.push(tr!("Proces ma w chwili skanu połączenia z adresami zdalnymi.", "The process has connections to remote addresses at scan time.").into()); }
    why.dedup();

    let step = match prio {
        "P1" => trf!("Zabezpieczyć pełny zrzut pamięci procesu {pid} przed jakąkolwiek zmianą na stacji, a następnie wykonać kroki z części „Jak sprawdzić ten region\" dla regionów o najwyższym wyniku.", "Secure a full memory dump of process {pid} before making any change on the host, then follow the steps in \"How to verify this region\" for the highest-scoring regions."),
        "P2" => trf!("Potwierdzić tożsamość programu (ścieżka, skrót SHA-256, podpis) i porównać liczbę oraz rozmiary regionów z innym procesem tego samego programu; przy rozbieżności postąpić jak dla P1 (proces {pid}).", "Confirm the identity of the program (path, SHA-256 hash, signature) and compare the number and sizes of regions with another process of the same program; if they differ, proceed as for P1 (process {pid})."),
        _ => trf!("Odnotować; wrócić do procesu {pid}, jeśli inne ustalenia wskażą na ten program.", "Note it; return to process {pid} if other findings point to this program."),
    };
    (prio, why, step)
}

/// „Podsumowanie dla decydenta": zakres, wynik, ocena ogólna, zalecane działania i ograniczenia
/// na jednej stronie. Wszystkie zdania wynikają z danych skanu; ocena jest skalibrowana
/// (brak znalezisk nie jest nazywany czystością).
fn executive_summary(b: &mut Vec<Block>, scan: &ScanResult, kb: &Kb, o: &Options, flagged: &[&ProcessReport], failed: &[&ProcessReport], unreadable: u64) {
    b.push(Block::H1(tr!("Podsumowanie dla decydenta", "Executive summary").into()));
    let limited = scan.host_info.as_ref().map(|h| h.scanner_limited).unwrap_or(false);
    let pr = |want: &str| flagged.iter().filter(|p| priority(p, kb, o.min).0 == want).count();
    let (p1, p2, p3) = (pr("P1"), pr("P2"), pr("P3"));

    let verdict = if flagged.is_empty() {
        tr!("Przegląd nie wskazał regionów pamięci wymagających weryfikacji. Nie jest to potwierdzenie, że stacja jest wolna od złośliwego kodu: narzędzie ma znane ograniczenia, opisane niżej.", "The review did not identify memory regions requiring verification. This is not confirmation that the host is free of malicious code: the tool has known limitations, described below.")
    } else if p1 > 0 {
        tr!("Co najmniej jeden proces ma cechy, których nie tłumaczy znane środowisko uruchomieniowe. Wymaga weryfikacji w pierwszej kolejności, zanim na stacji zostaną wprowadzone zmiany.", "At least one process has characteristics that a known runtime does not explain. It requires verification first, before any changes are made on the host.")
    } else if p2 > 0 {
        tr!("Znaleziska mają prawdopodobne łagodne wyjaśnienia, ale część wymaga potwierdzenia. Nie stwierdzono cech jednoznacznie wskazujących na wstrzyknięty kod.", "The findings have probable benign explanations, but some require confirmation. No characteristics unambiguously indicating injected code were found.")
    } else {
        tr!("Stwierdzono wyłącznie pojedyncze cechy o niskim priorytecie, najczęściej o przyczynie łagodnej.", "Only isolated low-priority characteristics were found, most often with a benign cause.")
    };
    b.push(Block::Para(trf!("Ocena ogólna. {verdict}", "Overall assessment. {verdict}")));

    b.push(Block::KeyVals(vec![
        (tr!("Zakres", "Scope").into(), trf!("{} procesów na hoście {}, stan z {}", "{} process(es) on host {}, state as of {}", scan.processes.len(), clean(&scan.host), clean(&scan.timestamp))),
        (tr!("Kompletność", "Completeness").into(), if scan.partial { trf!("częściowa: {} procesów niedostępnych, {} regionów nieodczytanych{}", "partial: {} processes inaccessible, {} regions not read{}", failed.len(), unreadable, if limited { tr!("; skaner działał bez pełnych uprawnień", "; the scanner ran without full privileges") } else { "" }) }
            else { tr!("pełna dla procesów dostępnych skanerowi", "complete for processes accessible to the scanner").into() }),
        (tr!("Procesy do weryfikacji", "Processes to verify").into(), trf!("{} (P1: {p1}, P2: {p2}, P3: {p3}) od wagi „{}\"", "{} (P1: {p1}, P2: {p2}, P3: {p3}) at severity \"{}\" or above", flagged.len(), crate::sev_label(o.min))),
    ]));

    if !flagged.is_empty() {
        let mut top: Vec<&&ProcessReport> = flagged.iter().collect();
        top.sort_by(|a, c| priority(a, kb, o.min).0.cmp(priority(c, kb, o.min).0).then(top_score(c, o.min).cmp(&top_score(a, o.min))).then(a.info.pid.cmp(&c.info.pid)));
        let top_refs: Vec<&ProcessReport> = top.iter().map(|p| **p).collect();
        let top_groups = group_similar(&top_refs, kb, o.min);
        let rows: Vec<Vec<String>> = top_groups.iter().take(5).map(|g| { let p = g[0]; let (prio, why, _) = priority(p, kb, o.min);
            vec![prio.to_string(), format!("{} {}{}", pid_s(p), clean(p.info.name.as_deref().unwrap_or("?")), if g.len() > 1 { format!(" (x{})", g.len()) } else { String::new() }), why.first().cloned().unwrap_or_default()] }).collect();
        b.push(Block::H3(tr!("Najważniejsze procesy", "Key processes").into()));
        b.push(Block::Table { head: [tr!("Priorytet", "Priority"), tr!("Proces", "Process"), tr!("Dlaczego", "Why")].map(String::from).to_vec(), rows, widths: vec![0.9, 2.2, 6.0] });
        if top_groups.len() > 5 { b.push(Block::Para(trf!("Pozostałe grupy procesów ({}) są w rozdziale „Przegląd procesów\".", "The remaining process groups ({}) are in the chapter \"Process overview\".", top_groups.len() - 5))); }
    }

    let mut actions: Vec<String> = Vec::new();
    if limited { actions.push(tr!("Powtórzyć skan z pełnymi uprawnieniami (administrator z podniesionymi uprawnieniami albo root): obecny wynik nie obejmuje procesów innych użytkowników i usług.", "Repeat the scan with full privileges (elevated administrator or root): the current result does not cover processes of other users and services.").into()); }
    if p1 > 0 { actions.push(tr!("Dla procesów P1: zabezpieczyć zrzut pamięci procesu i nie restartować stacji przed zakończeniem weryfikacji; pamięć jest jedynym nośnikiem tych śladów.", "For P1 processes: secure a memory dump of the process and do not restart the host before verification is complete; memory is the only medium holding these traces.").into()); }
    if p2 > 0 { actions.push(tr!("Dla procesów P2: potwierdzić tożsamość programu (ścieżka, skrót SHA-256, podpis) i zasadność jego działania na tej stacji.", "For P2 processes: confirm the identity of the program (path, SHA-256 hash, signature) and that its operation on this host is legitimate.").into()); }
    if !failed.is_empty() { actions.push(trf!("Uwzględnić, że {} procesów nie zostało sprawdzonych; jeśli są wśród nich procesy istotne dla sprawy, potrzebny jest zrzut pamięci wykonany innym narzędziem.", "Take into account that {} process(es) were not examined; if any of them matter to the case, a memory dump made with another tool is needed.", failed.len())); }
    if actions.is_empty() { actions.push(tr!("Brak działań wynikających z tego przeglądu. Przy innych przesłankach incydentu zastosować pozostałe źródła (logi, dysk, ruch sieciowy).", "No actions follow from this review. If there are other indications of an incident, use the remaining sources (logs, disk, network traffic).").into()); }
    b.push(Block::H3(tr!("Zalecane działania", "Recommended actions").into()));
    b.push(Block::Bullets(actions));
    b.push(Block::Para(tr!("Ograniczenia oceny: przegląd dotyczy stanu pamięci z jednej chwili, nie obejmuje procesów chronionych przez system ani pamięci jądra i opiera się na cechach, które mają też przyczyny łagodne. Szczegóły są w rozdziale „Czego ten raport nie obejmuje\".", "Limitations of the assessment: the review concerns the state of memory at a single moment, does not cover processes protected by the system or kernel memory, and relies on characteristics that also have benign causes. Details are in the chapter \"What this report does not cover\".").into()));
}
