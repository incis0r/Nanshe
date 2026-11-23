//! Raport różnicowy: co zmieniło się między dwoma skanami tej samej stacji.
//! Porównuje wyłącznie dane deterministyczne z plików wyniku; niczego nie punktuje na nowo.
//! Dokument powstaje w tym samym modelu bloków co zwykły raport, więc ma oba formaty.
use crate::doc::{clean, pid_s, shown_regions, size_h, Block, Doc};
use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::collections::BTreeSet;

pub struct Options {
    /// Najniższa waga regionów branych do porównania.
    pub min: Severity,
    pub old_name: Option<String>,
    pub new_name: Option<String>,
    pub old_sha256: Option<String>,
    pub new_sha256: Option<String>,
}

/// Ile pozycji jednej listy zmian kontekstu pokazać w raporcie.
const LIST_MAX: usize = 12;

fn started(p: &ProcessReport) -> Option<&str> { p.context.as_ref().and_then(|c| c.started.as_deref()) }

/// Ten sam proces w obu skanach: ten sam PID, nazwa i plik programu, a jeśli oba wyniki znają czas
/// startu, to także ten sam czas startu (PID bywa użyty ponownie przez inny proces).
pub fn same_process(a: &ProcessReport, b: &ProcessReport) -> bool {
    a.info.pid.is_some() && a.info.pid == b.info.pid && a.info.name == b.info.name && a.info.exe == b.info.exe
        && match (started(a), started(b)) { (Some(x), Some(y)) => x == y, _ => true }
}

fn flagged(p: &ProcessReport, min: Severity) -> bool { p.max_severity >= min && p.max_severity > Severity::None }
fn name(p: &ProcessReport) -> String { format!("{} {}", pid_s(p), clean(p.info.name.as_deref().unwrap_or("?"))) }
fn tags(r: &RegionReport) -> Vec<&str> { let mut t: Vec<&str> = r.findings.iter().map(|f| f.tag.as_str()).collect(); t.sort_unstable(); t.dedup(); t }
fn prot(r: &RegionReport) -> String { r.region.prot.map(|x| x.to_string()).unwrap_or_else(|| "???".into()) }
fn top(p: &ProcessReport, min: Severity) -> u32 { shown_regions(p, min).first().map(|r| r.score).unwrap_or(0) }
fn all_tags(p: &ProcessReport, min: Severity) -> String {
    let mut t: Vec<&str> = shown_regions(p, min).iter().flat_map(|r| r.findings.iter().map(|f| f.tag.as_str())).collect();
    t.sort_unstable(); t.dedup(); t.join(", ")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change { New, Gone, BelowThreshold, Changed }

/// Zmiana jednego regionu ze znaleziskiem w procesie obecnym w obu skanach.
#[derive(Clone, Debug, PartialEq)]
pub struct RegionChange { pub change: Change, pub base: u64, pub size: u64, pub prot: String, pub severity: Severity, pub score: u32, pub tags: String, pub what: String }

/// Zmiany regionów ze znaleziskami od wagi `min` między dwoma skanami tego samego procesu.
/// Regiony są dopasowywane po adresie początku.
pub fn region_changes(old: &ProcessReport, new: &ProcessReport, min: Severity) -> Vec<RegionChange> {
    let (o, n) = (shown_regions(old, min), shown_regions(new, min));
    let mut out = Vec::new();
    for r in &n {
        let row = |change, what: String| RegionChange { change, base: r.region.base, size: r.region.size, prot: prot(r), severity: r.severity, score: r.score, tags: tags(r).join(", "), what };
        match o.iter().find(|x| x.region.base == r.region.base) {
            None => {
                // region mógł istnieć wcześniej ze znaleziskiem poniżej progu porównania
                let before = old.regions.iter().find(|x| x.region.base == r.region.base && !x.findings.is_empty());
                out.push(row(Change::New, match before {
                    Some(b) => trf!("wcześniej poniżej progu ({} pkt, {})", "previously below the threshold ({} pts, {})", b.score, tags(b).join(", ")),
                    None => tr!("nie było go w poprzednim skanie", "absent from the earlier scan").to_string(),
                }));
            }
            Some(b) => {
                let mut what: Vec<String> = Vec::new();
                let (tb, tn) = (tags(b), tags(r));
                let added: Vec<&str> = tn.iter().copied().filter(|t| !tb.contains(t)).collect();
                let removed: Vec<&str> = tb.iter().copied().filter(|t| !tn.contains(t)).collect();
                if !added.is_empty() { what.push(trf!("doszły cechy: {}", "characteristics added: {}", added.join(", "))); }
                if !removed.is_empty() { what.push(trf!("ubyły cechy: {}", "characteristics removed: {}", removed.join(", "))); }
                if b.score != r.score { what.push(trf!("wynik {} -> {} pkt", "score {} -> {} pts", b.score, r.score)); }
                if prot(b) != prot(r) { what.push(trf!("prawa {} -> {}", "permissions {} -> {}", prot(b), prot(r))); }
                if b.region.size != r.region.size { what.push(trf!("rozmiar {} -> {}", "size {} -> {}", size_h(b.region.size), size_h(r.region.size))); }
                if let (Some(x), Some(y)) = (&b.sha256, &r.sha256) { if x != y { what.push(tr!("zawartość zmieniona (inny skrót SHA-256)", "contents changed (different SHA-256 hash)").to_string()); } }
                if !what.is_empty() { out.push(row(Change::Changed, what.join("; "))); }
            }
        }
    }
    for b in &o {
        if n.iter().any(|x| x.region.base == b.region.base) { continue; }
        let now = new.regions.iter().find(|x| x.region.base == b.region.base && !x.findings.is_empty());
        let (change, what) = match now {
            Some(x) => (Change::BelowThreshold, trf!("nadal istnieje, teraz poniżej progu ({} pkt, {})", "still present, now below the threshold ({} pts, {})", x.score, tags(x).join(", "))),
            None => (Change::Gone, tr!("brak znaleziska pod tym adresem w nowym skanie", "no finding at this address in the later scan").to_string()),
        };
        out.push(RegionChange { change, base: b.region.base, size: b.region.size, prot: prot(b), severity: b.severity, score: b.score, tags: tags(b).join(", "), what });
    }
    out.sort_by(|a, c| (a.change as u8).cmp(&(c.change as u8)).then(c.score.cmp(&a.score)).then(a.base.cmp(&c.base)));
    out
}

fn change_label(c: Change) -> &'static str {
    match c { Change::New => tr!("NOWY", "NEW"), Change::Gone => tr!("zniknął", "gone"), Change::BelowThreshold => tr!("poniżej progu", "below threshold"), Change::Changed => tr!("zmieniony", "changed") }
}

fn set_diff(old: BTreeSet<String>, new: BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (new.difference(&old).cloned().collect(), old.difference(&new).cloned().collect())
}

fn listed(label: &str, mut v: Vec<String>) -> Option<String> {
    if v.is_empty() { return None; }
    let n = v.len();
    v.truncate(LIST_MAX);
    Some(format!("{label} ({n}): {}{}", v.join("; "), if n > LIST_MAX { trf!("; ... i {} kolejnych", "; ... and {} more", n - LIST_MAX) } else { String::new() }))
}

/// Zmiany poza pamięcią w procesie obecnym w obu skanach: gniazda, procesy potomne, zmapowane pliki, plik programu.
pub fn context_changes(old: &ProcessReport, new: &ProcessReport) -> Vec<String> {
    let mut out = Vec::new();
    if let (Some(a), Some(b)) = (&old.context, &new.context) {
        let sock = |c: &ProcessContext| c.sockets.iter().filter(|s| s.proto != "unix").map(|s| match &s.remote {
            Some(r) => format!("{} {} -> {}", clean(&s.proto), clean(&s.local), clean(r)), None => trf!("nasłuch {} {}", "listening {} {}", clean(&s.proto), clean(&s.local)) }).collect::<BTreeSet<_>>();
        let (added, removed) = set_diff(sock(a), sock(b));
        out.extend(listed(tr!("Nowe gniazda sieciowe", "New network sockets"), added));
        out.extend(listed(tr!("Zamknięte gniazda sieciowe", "Closed network sockets"), removed));
        let kids = |c: &ProcessContext| c.children.iter().map(|k| format!("{} {}", k.pid, clean(&k.name))).collect::<BTreeSet<_>>();
        let (added, removed) = set_diff(kids(a), kids(b));
        out.extend(listed(tr!("Nowe procesy potomne", "New child processes"), added));
        out.extend(listed(tr!("Zakończone procesy potomne", "Exited child processes"), removed));
        if let (Some(x), Some(y)) = (a.exe_file.as_ref().and_then(|f| f.sha256.as_ref()), b.exe_file.as_ref().and_then(|f| f.sha256.as_ref())) {
            if x != y { out.push(tr!("UWAGA: plik programu na dysku ma inny skrót SHA-256 niż przy poprzednim skanie (podmiana albo aktualizacja pliku działającego programu).",
                "WARNING: the program file on disk has a different SHA-256 hash than at the earlier scan (the file of a running program was replaced or updated).").into()); }
        }
    }
    if let (Some(a), Some(b)) = (&old.layout, &new.layout) {
        let files = |l: &[Region]| l.iter().filter_map(|r| r.backing.as_deref()).map(clean).collect::<BTreeSet<_>>();
        let (added, removed) = set_diff(files(a), files(b));
        out.extend(listed(tr!("Nowe pliki zmapowane do pamięci", "New files mapped into memory"), added));
        out.extend(listed(tr!("Pliki już niezmapowane", "Files no longer mapped"), removed));
    }
    out
}

fn proc_table(ps: &[&ProcessReport], min: Severity) -> Block {
    let rows = ps.iter().map(|p| vec![pid_s(p), clean(p.info.name.as_deref().unwrap_or("?")), crate::sev_label(p.max_severity).to_string(), shown_regions(p, min).len().to_string(),
        top(p, min).to_string(), all_tags(p, min), clean(started(p).unwrap_or("-")), clean(p.info.exe.as_deref().unwrap_or("-"))]).collect();
    Block::Table { head: ["PID", tr!("Proces", "Process"), tr!("Waga", "Severity"), tr!("Regiony", "Regions"), tr!("Maks. pkt", "Max pts"), tr!("Tagi", "Tags"), tr!("Uruchomiony", "Started"), tr!("Plik programu", "Program file")].map(String::from).to_vec(),
        rows, widths: vec![0.8, 1.8, 1.2, 0.9, 0.9, 2.0, 2.0, 3.2] }
}

pub fn build(old: &ScanResult, new: &ScanResult, o: &Options) -> Doc {
    let mut b: Vec<Block> = Vec::new();
    let find = |list: &'_ [ProcessReport], p: &ProcessReport| list.iter().position(|x| same_process(x, p));

    // --- klasyfikacja procesów
    let mut appeared: Vec<&ProcessReport> = Vec::new();   // ze znaleziskami, bez odpowiednika we wcześniejszym skanie
    let mut vanished: Vec<&ProcessReport> = Vec::new();   // miały znaleziska, nie ma ich w późniejszym skanie
    let mut changed: Vec<(&ProcessReport, &ProcessReport, Vec<RegionChange>, Vec<String>)> = Vec::new();
    let mut unchanged: Vec<&ProcessReport> = Vec::new();
    for p in &new.processes {
        match find(&old.processes, p) {
            None => if flagged(p, o.min) { appeared.push(p); },
            Some(i) => {
                let q = &old.processes[i];
                if !flagged(p, o.min) && !flagged(q, o.min) { continue; }
                let (rc, cc) = (region_changes(q, p, o.min), context_changes(q, p));
                if rc.is_empty() && cc.is_empty() { unchanged.push(p); } else { changed.push((q, p, rc, cc)); }
            }
        }
    }
    for q in &old.processes { if flagged(q, o.min) && find(&new.processes, q).is_none() { vanished.push(q); } }
    let order = |a: &&ProcessReport, c: &&ProcessReport| c.max_severity.cmp(&a.max_severity).then(top(c, o.min).cmp(&top(a, o.min))).then(a.info.pid.cmp(&c.info.pid));
    appeared.sort_by(order); vanished.sort_by(order);
    let new_regions = |v: &[RegionChange]| v.iter().filter(|r| r.change == Change::New).count();
    changed.sort_by(|a, c| new_regions(&c.2).cmp(&new_regions(&a.2)).then(c.1.max_severity.cmp(&a.1.max_severity)).then(a.1.info.pid.cmp(&c.1.info.pid)));
    let injected: usize = changed.iter().map(|c| new_regions(&c.2)).sum();
    let all_new = new.processes.iter().filter(|p| find(&old.processes, p).is_none()).count();
    let all_gone = old.processes.iter().filter(|p| find(&new.processes, p).is_none()).count();

    // --- metryka
    let scan_line = |s: &ScanResult, n: &Option<String>, h: &Option<String>| {
        let mut v = vec![clean(&s.timestamp), trf!("procesów: {}", "processes: {}", s.processes.len()), format!("nanshe {}", clean(&s.tool_version))];
        if s.partial { v.push(tr!("wynik częściowy", "partial result").into()); }
        if let Some(n) = n { v.push(clean(n)); }
        if let Some(h) = h { v.push(format!("SHA-256 {h}")); }
        v.join("; ")
    };
    b.push(Block::KeyVals(vec![
        ("Host".into(), clean(&new.host)),
        (tr!("Skan wcześniejszy", "Earlier scan").into(), scan_line(old, &o.old_name, &o.old_sha256)),
        (tr!("Skan późniejszy", "Later scan").into(), scan_line(new, &o.new_name, &o.new_sha256)),
        (tr!("Próg porównania", "Comparison threshold").into(), trf!("regiony od wagi „{}\"", "regions at severity \"{}\" or above", crate::sev_label(o.min))),
        (tr!("Klasyfikacja", "Classification").into(), tr!("Poufne: dokument zawiera dane z badanej stacji; udostępniać wyłącznie osobom prowadzącym analizę", "Confidential: this document contains data from the examined host; share only with those conducting the analysis").into()),
    ]));
    if old.host != new.host {
        b.push(Block::Note(trf!("UWAGA: wyniki pochodzą z różnych hostów ({} i {}). Porównanie procesów po numerze PID nie ma wtedy sensu; poniższe zestawienie należy traktować jako dwie niezależne listy.",
            "WARNING: the results come from different hosts ({} and {}). Matching processes by PID is then meaningless; treat the listing below as two independent lists.", clean(&old.host), clean(&new.host))));
    }
    if old.timestamp > new.timestamp {
        b.push(Block::Note(tr!("UWAGA: skan podany jako wcześniejszy ma późniejszy czas niż drugi. „Nowe\" i „zniknęły\" są wtedy zamienione miejscami; powtórz polecenie z plikami w odwrotnej kolejności.",
            "WARNING: the scan given as the earlier one has a later time than the other. \"New\" and \"gone\" are then swapped; repeat the command with the files in the opposite order.").into()));
    }
    let boot = |s: &ScanResult| s.host_info.as_ref().and_then(|h| h.boot.clone());
    if let (Some(x), Some(y)) = (boot(old), boot(new)) {
        if x != y { b.push(Block::Note(trf!("System został uruchomiony ponownie między skanami (start {} i {}). Wszystkie procesy są wtedy nowe, a ślady, które istniały tylko w pamięci, przepadły.",
            "The system was restarted between the scans (boot {} and {}). All processes are then new, and traces that existed only in memory are lost.", clean(&x), clean(&y)))); }
    }
    let limited = |s: &ScanResult| s.host_info.as_ref().map(|h| h.scanner_limited).unwrap_or(false);
    if limited(old) != limited(new) {
        b.push(Block::Note(tr!("UWAGA: skany wykonano z różnymi uprawnieniami. Proces widoczny tylko w jednym z nich mógł być po prostu niedostępny dla drugiego skanu.",
            "WARNING: the scans were run with different privileges. A process visible in only one of them may simply have been inaccessible to the other scan.").into()));
    }
    b.push(Block::Note(tr!("To porównanie dwóch stanów pamięci, nie zapis zdarzeń. Tego, co pojawiło się i znikło między skanami, raport nie widzi. Znaleziska są hipotezami do weryfikacji; szczegóły regionów są w zwykłym raporcie z późniejszego skanu.",
        "This compares two states of memory; it is not a record of events. Anything that appeared and disappeared between the scans is not visible. Findings are hypotheses to verify; region details are in the regular report of the later scan.").into()));

    // --- podsumowanie
    b.push(Block::H1(tr!("Podsumowanie zmian", "Summary of changes").into()));
    let verdict = if injected > 0 {
        tr!("W procesie, który działał już przy wcześniejszym skanie, pojawił się nowy region ze znaleziskiem. To najważniejszy sygnał tego raportu: kod pojawił się w trakcie pracy procesu. Ma też przyczyny łagodne (środowiska kompilujące kod w locie stale tworzą nowe regiony), dlatego wymaga weryfikacji, a nie przesądza o włamaniu.",
            "A new region with a finding appeared in a process that was already running at the earlier scan. This is the most important signal in this report: code appeared while the process was running. It also has benign causes (just-in-time runtimes keep creating new regions), so it requires verification and does not by itself establish a compromise.")
    } else if !appeared.is_empty() {
        tr!("Pojawiły się nowe procesy ze znaleziskami. W procesach działających przy obu skanach nie przybył żaden region ze znaleziskiem.",
            "New processes with findings appeared. No region with a finding was added in processes running at both scans.")
    } else if !changed.is_empty() || !vanished.is_empty() {
        tr!("Nie przybył żaden proces ani region ze znaleziskiem; zmiany dotyczą istniejących znalezisk albo kontekstu procesów.",
            "No process or region with a finding was added; the changes concern existing findings or process context.")
    } else {
        tr!("Między skanami nie stwierdzono zmian w znaleziskach od progu porównania. Nie znaczy to, że nic się nie działo: porównywane są tylko dwa stany.",
            "No changes in findings at or above the comparison threshold were found between the scans. This does not mean nothing happened: only two states are compared.")
    };
    b.push(Block::Para(trf!("Ocena ogólna. {verdict}", "Overall assessment. {verdict}")));
    b.push(Block::KeyVals(vec![
        (tr!("Nowe regiony w działających procesach", "New regions in running processes").into(), injected.to_string()),
        (tr!("Nowe procesy ze znaleziskami", "New processes with findings").into(), trf!("{} (wszystkich nowych procesów: {})", "{} (all new processes: {})", appeared.len(), all_new)),
        (tr!("Procesy ze zmianami", "Processes with changes").into(), changed.len().to_string()),
        (tr!("Procesy ze znaleziskami, które zniknęły", "Processes with findings that are gone").into(), trf!("{} (wszystkich zakończonych procesów: {})", "{} (all exited processes: {})", vanished.len(), all_gone)),
        (tr!("Procesy ze znaleziskami bez zmian", "Processes with findings, unchanged").into(), unchanged.len().to_string()),
    ]));

    // --- procesy zmienione
    b.push(Block::H1(tr!("Zmiany w działających procesach", "Changes in running processes").into()));
    if changed.is_empty() {
        b.push(Block::Para(tr!("Brak zmian w procesach obecnych w obu skanach.", "No changes in processes present in both scans.").into()));
    }
    for (_, p, rc, cc) in &changed {
        b.push(Block::H2(trf!("Proces {}", "Process {}", name(p))));
        if rc.is_empty() {
            b.push(Block::Para(tr!("Regiony ze znaleziskami bez zmian.", "Regions with findings are unchanged.").into()));
        } else {
            let rows = rc.iter().map(|r| vec![change_label(r.change).to_string(), format!("{:#x}", r.base), size_h(r.size), r.prot.clone(), crate::sev_label(r.severity).to_string(), r.score.to_string(), r.tags.clone(), r.what.clone()]).collect();
            b.push(Block::Table { head: [tr!("Zmiana", "Change"), tr!("Adres", "Address"), tr!("Rozmiar", "Size"), tr!("Prawa", "Perms"), tr!("Waga", "Severity"), tr!("Pkt", "Pts"), tr!("Tagi", "Tags"), tr!("Co się zmieniło", "What changed")].map(String::from).to_vec(),
                rows, widths: vec![1.2, 2.0, 1.0, 0.8, 1.2, 0.6, 1.8, 3.4] });
        }
        if !cc.is_empty() {
            b.push(Block::H3(tr!("Zmiany poza pamięcią", "Changes outside memory").into()));
            b.push(Block::Bullets(cc.clone()));
        }
    }

    // --- nowe i zakończone procesy
    b.push(Block::H1(tr!("Nowe procesy ze znaleziskami", "New processes with findings").into()));
    if appeared.is_empty() { b.push(Block::Para(tr!("Brak.", "None.").into())); } else {
        b.push(Block::Para(tr!("Procesy ze znaleziskami, których nie było we wcześniejszym skanie (albo ich numer PID należał wtedy do innego programu).",
            "Processes with findings that were absent from the earlier scan (or whose PID then belonged to a different program).").into()));
        b.push(proc_table(&appeared, o.min));
    }
    b.push(Block::H1(tr!("Procesy ze znaleziskami, które zniknęły", "Processes with findings that are gone").into()));
    if vanished.is_empty() { b.push(Block::Para(tr!("Brak.", "None.").into())); } else {
        b.push(Block::Para(tr!("Procesy, które miały znaleziska we wcześniejszym skanie i nie występują w późniejszym. Ich pamięci nie da się już zbadać; zostaje wcześniejszy plik wyniku.",
            "Processes that had findings in the earlier scan and do not appear in the later one. Their memory can no longer be examined; the earlier result file remains.").into()));
        b.push(proc_table(&vanished, o.min));
    }
    if !unchanged.is_empty() {
        b.push(Block::H1(tr!("Procesy ze znaleziskami bez zmian", "Processes with findings, unchanged").into()));
        let mut names: Vec<String> = unchanged.iter().map(|p| name(p)).collect();
        let n = names.len(); names.truncate(40);
        b.push(Block::Para(format!("{}{}", names.join(", "), if n > 40 { trf!(" ... i {} kolejnych", " ... and {} more", n - 40) } else { String::new() })));
    }

    // --- ograniczenia
    b.push(Block::H1(tr!("Ograniczenia porównania", "Limitations of the comparison").into()));
    let mut gaps = vec![
        tr!("Procesy są dopasowywane po numerze PID, nazwie, pliku programu i czasie startu. Program uruchomiony ponownie jest nowym procesem.", "Processes are matched by PID, name, program file and start time. A restarted program is a new process.").to_string(),
        tr!("Regiony są dopasowywane po adresie początku. Region zwolniony i przydzielony ponownie pod tym samym adresem jest widoczny jako zmieniony, a nie jako nowy.", "Regions are matched by start address. A region freed and allocated again at the same address shows as changed, not as new.").to_string(),
        tr!("Zmiana zawartości regionu jest wykrywana tylko wtedy, gdy oba wyniki mają skrót SHA-256 regionu.", "A change of region contents is detected only when both results carry the region's SHA-256 hash.").to_string(),
        tr!("Zmiany poza pamięcią (gniazda, procesy potomne, zmapowane pliki) są porównywane tylko dla procesów ze znaleziskami, bo tylko dla nich wynik zawiera kontekst.", "Changes outside memory (sockets, child processes, mapped files) are compared only for processes with findings, because only for them does the result contain context.").to_string(),
    ];
    if old.partial || new.partial { gaps.push(tr!("Co najmniej jeden z wyników jest częściowy: proces niedostępny w jednym ze skanów nie jest porównywany.", "At least one of the results is partial: a process inaccessible in one of the scans is not compared.").into()); }
    if old.tool_version != new.tool_version { gaps.push(trf!("Skany wykonano różnymi wersjami narzędzia ({} i {}); część różnic może wynikać ze zmian w detektorach.", "The scans were made with different tool versions ({} and {}); some differences may come from detector changes.", clean(&old.tool_version), clean(&new.tool_version))); }
    b.push(Block::Bullets(gaps));

    let mut n = 0;
    for blk in b.iter_mut() { if let Block::H1(t) = blk { n += 1; *t = format!("{n}. {t}"); } }
    Doc { title: tr!("Nanshe: raport różnicowy", "Nanshe: differential report").into(),
        subtitle: trf!("host {} | {} -> {}", "host {} | {} -> {}", clean(&new.host), clean(&old.timestamp), clean(&new.timestamp)),
        footer: tr!("Porównanie dwóch skanów. Triage, nie werdykt.", "Comparison of two scans. Triage, not a verdict.").into(),
        blocks: b }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Region ze znaleziskami: (adres, tagi, wynik, skrót zawartości).
    fn reg(base: u64, tags: &[&str], score: u32, sha: Option<&str>) -> RegionReport {
        let region = Region { base, size: 0x1000, prot: Prot::parse("rwx"), kind: RegionKind::Private, backing: None, backing_deleted: false, label: None, readable: true };
        RegionReport { region: region.clone(), bytes_read: 0x1000, truncated: false, entropy_max: Some(7.0), entropy_mean: Some(6.0), zero_pages: 0, score,
            severity: if score >= 60 { Severity::High } else if score >= 30 { Severity::Suspicious } else { Severity::Info }, allowlisted: None,
            findings: tags.iter().map(|t| Finding { id: format!("5:{base:x}:{t}"), detector: t.to_lowercase(), tag: t.to_string(), addr: base, size: 0x1000, prot: region.prot, entropy: None, weight: score, reason: "r".into(), bytes_hex: None }).collect(),
            heat: None, profile: None, strings: vec![], sha256: sha.map(String::from) }
    }
    fn proc(pid: u32, name: &str, regions: Vec<RegionReport>) -> ProcessReport {
        let max = regions.iter().map(|r| r.severity).max().unwrap_or(Severity::None);
        ProcessReport { info: SourceInfo { os: "linux".into(), arch: "x86_64".into(), pid: Some(pid), name: Some(name.into()), source_type: "live".into(), exe: Some(format!("/usr/bin/{name}")), exe_deleted: false, exe_verified: false },
            regions_total: 10, regions_unreadable: 0, bytes_scanned: 0, max_severity: max, error: None, regions, layout: None, context: None }
    }
    fn scan(ts: &str, processes: Vec<ProcessReport>) -> ScanResult {
        ScanResult { schema_version: SCHEMA_VERSION, tool_version: "t".into(), timestamp: ts.into(), host: "h".into(), heat_cell_bytes: 65536, partial: false, processes, lang: None, host_info: None, files: vec![] }
    }
    fn opts() -> Options { Options { min: Severity::Suspicious, old_name: None, new_name: None, old_sha256: None, new_sha256: None } }
    fn text(d: &Doc) -> String { crate::md::render(d) }

    #[test]
    fn new_region_in_a_running_process_is_the_headline() {
        let old = scan("2026-11-23T10:00:00Z", vec![proc(5, "srv", vec![reg(0x1000, &["RWX"], 30, None)]), proc(6, "idle", vec![])]);
        let new = scan("2026-11-23T11:00:00Z", vec![proc(5, "srv", vec![reg(0x1000, &["RWX"], 30, None), reg(0x9000, &["RWX", "X-PRIV"], 60, None)]), proc(6, "idle", vec![])]);
        let rc = region_changes(&old.processes[0], &new.processes[0], Severity::Suspicious);
        assert_eq!(rc.len(), 1);
        assert_eq!((rc[0].change, rc[0].base, rc[0].score), (Change::New, 0x9000, 60));
        let t = text(&build(&old, &new, &opts()));
        for want in ["# Nanshe: raport różnicowy", "pojawił się nowy region ze znaleziskiem", "| Nowe regiony w działających procesach | 1 |", "### Proces 5 srv", "| NOWY | 0x9000 |", "nie było go w poprzednim skanie", "Ograniczenia porównania"] {
            assert!(t.contains(want), "brak: {want}\n{t}");
        }
        assert!(!t.contains("0x1000"), "region bez zmian nie jest wymieniany");
        // kontrola: te same skany nie dają żadnej zmiany, a proces trafia do listy "bez zmian"
        let same = text(&build(&old, &old, &opts()));
        assert!(same.contains("nie stwierdzono zmian") && same.contains("| Nowe regiony w działających procesach | 0 |") && same.contains("Procesy ze znaleziskami bez zmian") && !same.contains("NOWY"), "{same}");
        // proces bez znalezisk w obu skanach nie pojawia się wcale
        assert!(!t.contains("idle"));
    }

    #[test]
    fn reused_pid_is_a_new_process_not_a_change() {
        let mut a = proc(7, "updater", vec![reg(0x1000, &["RWX"], 60, None)]);
        a.context = Some(ProcessContext { started: Some("2026-11-23T09:00:00Z".into()), ..Default::default() });
        let mut b = a.clone();
        b.context = Some(ProcessContext { started: Some("2026-11-23T10:30:00Z".into()), ..Default::default() });
        b.regions.push(reg(0x9000, &["RWX"], 60, None));
        assert!(!same_process(&a, &b) && same_process(&a, &a));
        let t = text(&build(&scan("2026-11-23T10:00:00Z", vec![a.clone()]), &scan("2026-11-23T11:00:00Z", vec![b]), &opts()));
        assert!(t.contains("| Nowe regiony w działających procesach | 0 |") && t.contains("| Nowe procesy ze znaleziskami | 1 (wszystkich nowych procesów: 1) |")
            && t.contains("| Procesy ze znaleziskami, które zniknęły | 1 (wszystkich zakończonych procesów: 1) |") && !t.contains("NOWY"), "{t}");
        // inny program pod tym samym numerem PID to też inny proces
        let mut c = a.clone(); c.info.exe = Some("/tmp/updater".into());
        assert!(!same_process(&a, &c));
        // bez czasu startu w jednym z wyników decydują PID, nazwa i plik programu
        let mut d = a.clone(); d.context = None;
        assert!(same_process(&a, &d));
    }

    #[test]
    fn changed_gone_and_threshold_crossings_are_told_apart() {
        let old = proc(5, "srv", vec![reg(0x1000, &["RWX"], 30, Some("aa")), reg(0x2000, &["RWX"], 60, None), reg(0x3000, &["RWX"], 30, None), reg(0x4000, &["ENT-X"], 10, None), reg(0x5000, &["RWX"], 30, Some("cc"))]);
        let new = proc(5, "srv", vec![reg(0x1000, &["RWX", "HDR"], 70, Some("bb")), reg(0x3000, &["ENT-X"], 10, None), reg(0x4000, &["ENT-X", "RWX"], 40, None), reg(0x5000, &["RWX"], 30, Some("cc"))]);
        let rc = region_changes(&old, &new, Severity::Suspicious);
        let get = |base: u64| rc.iter().find(|r| r.base == base).unwrap_or_else(|| panic!("brak {base:#x} w {rc:#?}"));
        assert_eq!(rc.len(), 4, "{rc:#?}");
        assert_eq!(get(0x1000).change, Change::Changed);
        for want in ["doszły cechy: HDR", "wynik 30 -> 70 pkt", "zawartość zmieniona"] { assert!(get(0x1000).what.contains(want), "{}", get(0x1000).what); }
        assert_eq!(get(0x2000).change, Change::Gone);
        assert_eq!(get(0x3000).change, Change::BelowThreshold);
        assert_eq!(get(0x4000).change, Change::New);
        assert!(get(0x4000).what.contains("wcześniej poniżej progu (10 pkt, ENT-X)"));
        assert!(!rc.iter().any(|r| r.base == 0x5000), "region bez zmian");
        // nowe regiony są na początku listy
        assert_eq!(rc[0].change, Change::New);
        // z niższym progiem przejście przez próg jest zwykłą zmianą
        let low = region_changes(&old, &new, Severity::Info);
        assert_eq!(low.iter().find(|r| r.base == 0x4000).unwrap().change, Change::Changed);
    }

    #[test]
    fn context_changes_and_scan_level_warnings() {
        let sock = |local: &str, remote: Option<&str>| Socket { proto: "tcp".into(), local: local.into(), remote: remote.map(String::from), state: None };
        let file = |sha: &str| Some(FileFacts { size: 1, modified: None, owner: None, mode: None, sha256: Some(sha.into()) });
        let lib = |p: &str| Region { base: 0x7000, size: 0x1000, prot: Prot::parse("r-x"), kind: RegionKind::Mapped, backing: Some(p.into()), backing_deleted: false, label: None, readable: true };
        let mut a = proc(5, "srv", vec![reg(0x1000, &["RWX"], 30, None)]);
        a.context = Some(ProcessContext { sockets: vec![sock("0.0.0.0:80", None), sock("10.0.0.5:5000", Some("10.0.0.9:443"))], exe_file: file("aa"), ..Default::default() });
        a.layout = Some(vec![lib("/usr/lib/libc.so.6")]);
        let mut b = a.clone();
        b.context = Some(ProcessContext { sockets: vec![sock("0.0.0.0:80", None), sock("10.0.0.5:6000", Some("203.0.113.7:4444"))], exe_file: file("bb"),
            children: vec![ProcRef { pid: 99, name: "sh".into(), exe: None, cmdline: None }], ..Default::default() });
        b.layout = Some(vec![lib("/usr/lib/libc.so.6"), lib("/tmp/x.so")]);
        let cc = context_changes(&a, &b).join("\n");
        for want in ["Nowe gniazda sieciowe (1): tcp 10.0.0.5:6000 -> 203.0.113.7:4444", "Zamknięte gniazda sieciowe (1): tcp 10.0.0.5:5000 -> 10.0.0.9:443", "Nowe procesy potomne (1): 99 sh", "UWAGA: plik programu na dysku ma inny skrót", "Nowe pliki zmapowane do pamięci (1): /tmp/x.so"] {
            assert!(cc.contains(want), "brak: {want}\n{cc}");
        }
        assert!(!cc.contains("0.0.0.0:80") && !cc.contains("libc"), "pozycje bez zmian nie są wymieniane");
        assert!(context_changes(&a, &a).is_empty());
        // proces bez zmian regionów, ale ze zmianą kontekstu, jest w części "zmiany", nie "bez zmian"
        let (mut old, mut new) = (scan("2026-11-23T10:00:00Z", vec![a]), scan("2026-11-23T11:00:00Z", vec![b]));
        let t = text(&build(&old, &new, &opts()));
        assert!(t.contains("| Procesy ze zmianami | 1 |") && t.contains("Zmiany poza pamięcią") && t.contains("Regiony ze znaleziskami bez zmian."), "{t}");
        assert!(!t.contains("różnych hostów") && !t.contains("System został uruchomiony ponownie") && !t.contains("zamienione miejscami"), "ostrzeżenia tylko gdy jest powód");
        // ostrzeżenia: inny host, ponowne uruchomienie systemu, pliki w odwrotnej kolejności
        new.host = "inny".into();
        old.host_info = Some(HostContext { boot: Some("2026-11-20T00:00:00Z".into()), ..Default::default() });
        new.host_info = Some(HostContext { boot: Some("2026-11-23T10:30:00Z".into()), ..Default::default() });
        let t = text(&build(&old, &new, &opts()));
        assert!(t.contains("różnych hostów") && t.contains("System został uruchomiony ponownie"), "{t}");
        assert!(text(&build(&new, &old, &opts())).contains("zamienione miejscami"));
    }

    #[test]
    fn english_differential_report_has_no_polish_text() {
        let old = scan("2026-11-23T10:00:00Z", vec![proc(5, "srv", vec![reg(0x1000, &["RWX"], 30, Some("aa")), reg(0x2000, &["RWX"], 60, None)]), proc(8, "old", vec![reg(0x1000, &["RWX"], 60, None)])]);
        let new = scan("2026-11-23T11:00:00Z", vec![proc(5, "srv", vec![reg(0x1000, &["RWX", "HDR"], 70, Some("bb")), reg(0x9000, &["RWX"], 60, None)]), proc(9, "fresh", vec![reg(0x1000, &["RWX"], 60, None)])]);
        let t = lang::with(lang::Lang::En, || text(&build(&old, &new, &opts())));
        for want in ["# Nanshe: differential report", "Summary of changes", "| NEW | 0x9000 |", "| changed | 0x1000 |", "| gone | 0x2000 |", "New processes with findings", "9 | fresh", "8 | old", "Limitations of the comparison"] {
            assert!(t.contains(want), "brak: {want}\n{t}");
        }
        let polish: Vec<&str> = t.lines().filter(|l| l.chars().any(|c| "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ„".contains(c))).collect();
        assert!(polish.is_empty(), "{polish:#?}");
    }
}
