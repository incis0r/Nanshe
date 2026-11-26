//! Skrót tekstowy wyniku skanu dla terminala: procesy od najwyższej wagi, regiony o tych samych
//! cechach w jednym wierszu, procesy niedostępne zebrane razem, opisy znaczników raz na końcu.

use crate::sev_label;
use nanshe_core::*;
use nanshe_core::{tr, trf};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt::Write;

pub struct TextOptions {
    /// próg wagi, od którego regiony i procesy trafiają do wydruku
    pub min: Severity,
    /// sekwencje ANSI; barwy dobrane do ciemnego tła
    pub color: bool,
    /// każdy region w osobnym wierszu, z entropią i opisami znalezisk
    pub regions: bool,
}

/// Ile adresów mieści wiersz grupy i ile PID-ów wiersz procesów niedostępnych.
const ADDRS: usize = 4;
const PIDS: usize = 24;

struct Paint(bool);

impl Paint {
    fn code(&self, code: &str, s: &str) -> String {
        if self.0 { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn bold(&self, s: &str) -> String { self.code("1", s) }
    fn note(&self, s: &str) -> String { self.code("92", s) }
    fn head(&self, s: &str) -> String { self.code("1;96", s) }
    fn sev(&self, sev: Severity, s: &str) -> String {
        match sev {
            Severity::High => self.code("1;91", s),
            Severity::Suspicious => self.code("1;93", s),
            Severity::Info => self.code("96", s),
            Severity::None => s.to_string(),
        }
    }
}

/// Liczba z rzeczownikiem w odpowiedniej formie: polskie [1, 2-4, 5+], angielskie [1, pozostałe].
fn count(n: usize, pl: [&str; 3], en: [&str; 2]) -> String {
    let word = match lang::get() {
        lang::Lang::Pl => if n == 1 { pl[0] } else if (2..=4).contains(&(n % 10)) && !(12..=14).contains(&(n % 100)) { pl[1] } else { pl[2] },
        lang::Lang::En => if n == 1 { en[0] } else { en[1] },
    };
    format!("{n} {word}")
}

fn size(bytes: u64) -> String {
    let k = bytes / 1024;
    if k < 1024 { format!("{k} KiB") } else if k < 10 * 1024 { format!("{:.1} MiB", k as f64 / 1024.0) } else { format!("{} MiB", k / 1024) }
}

fn size_range(lo: u64, hi: u64) -> String {
    let (a, b) = (size(lo), size(hi));
    if a == b { return a; }
    match (a.split_once(' '), b.split_once(' ')) {
        (Some((x, u)), Some((y, v))) if u == v => format!("{x}-{y} {u}"),
        _ => format!("{a}-{b}"),
    }
}

/// Wspólna część opisów jednego znacznika: opisy różnią się tylko szczegółem na końcu (adres, nazwa).
fn common(a: &str, b: &str) -> String {
    let n: usize = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).map(|(x, _)| x.len_utf8()).sum();
    if n == a.len() && n == b.len() { return a.to_string(); }
    let cut = a[..n].rfind(' ').unwrap_or(0);
    a[..cut].trim_end_matches([' ', '@', ':', ',', '(', '=']).to_string()
}

fn name_of(x: &RegionReport) -> &str {
    x.region.backing.as_deref().or(x.region.label.as_deref()).unwrap_or("<anon>")
}

pub fn to_text(r: &ScanResult, opt: &TextOptions) -> String {
    let p = Paint(opt.color);
    let mut o = String::new();
    let shown = |x: &&RegionReport| x.severity >= opt.min && !x.findings.is_empty();
    let listed = |pr: &ProcessReport| pr.max_severity >= opt.min && pr.regions.iter().any(|x| shown(&x));

    let with_findings = r.processes.iter().filter(|pr| pr.regions.iter().any(|x| !x.findings.is_empty())).count();
    let mut head = vec![format!("nanshe {}", r.tool_version), format!("host {}", r.host)];
    let mut platforms: Vec<String> = r.processes.iter().map(|pr| format!("{}/{}", pr.info.os, pr.info.arch)).collect();
    platforms.dedup();
    if let [one] = platforms.as_slice() { head.push(one.clone()); }
    head.push(count(r.processes.len(), ["proces", "procesy", "procesów"], ["process", "processes"]));
    head.push(trf!("{} w {}", "{} in {}",
        count(r.finding_count(), ["znalezisko", "znaleziska", "znalezisk"], ["finding", "findings"]),
        count(with_findings, ["procesie", "procesach", "procesach"], ["process", "processes"])));
    let _ = write!(o, "{}", p.bold(&head.join(" | ")));
    if r.partial { let _ = write!(o, " | {}", p.sev(Severity::Suspicious, tr!("WYNIK CZĘŚCIOWY", "PARTIAL RESULT"))); }
    o.push('\n');

    // jedna szerokość kolumny znaczników w całym wydruku, żeby kolumny procesów stały pod sobą
    let width = r.processes.iter().filter(|pr| listed(pr)).flat_map(|pr| pr.regions.iter().filter(shown))
        .map(|x| x.findings.iter().map(|f| f.tag.chars().count() + 1).sum::<usize>().saturating_sub(1)).max().unwrap_or(0);
    let mut legend: BTreeMap<&str, String> = BTreeMap::new();
    let mut totals = Vec::new();
    for sev in [Severity::High, Severity::Suspicious, Severity::Info] {
        if sev < opt.min { continue; }
        let mut procs: Vec<&ProcessReport> = r.processes.iter().filter(|pr| pr.max_severity == sev && listed(pr)).collect();
        if procs.is_empty() { continue; }
        procs.sort_by_key(|pr| (Reverse(pr.regions.iter().map(|x| x.score).max().unwrap_or(0)), pr.info.pid));
        totals.push(format!("{} {}", sev_label(sev), procs.len()));
        let _ = writeln!(o, "\n{}", p.sev(sev, &format!("{} ({})", sev_label(sev).to_uppercase(), procs.len())));
        for pr in procs {
            let pid = pr.info.pid.map(|x| x.to_string()).unwrap_or("-".into());
            let _ = write!(o, "[{pid}] {}  {}, {}", p.bold(pr.info.name.as_deref().unwrap_or("?")),
                count(pr.regions_total as usize, ["region", "regiony", "regionów"], ["region", "regions"]), size(pr.bytes_scanned));
            if pr.regions_unreadable > 0 { let _ = write!(o, "{}", trf!(", nieczytelnych: {}", ", unreadable: {}", pr.regions_unreadable)); }
            o.push('\n');
            if let Some(e) = &pr.error { let _ = writeln!(o, "{}", trf!("    błąd: {e}", "    error: {e}")); }

            // grupa: regiony o tej samej punktacji, znacznikach, uprawnieniach, źródle i obniżce
            let mut groups: BTreeMap<(Reverse<u32>, String, String, &str, &str), Vec<&RegionReport>> = BTreeMap::new();
            for x in pr.regions.iter().filter(shown) {
                let tags = x.findings.iter().map(|f| f.tag.as_str()).collect::<Vec<_>>().join(",");
                let prot = x.region.prot.map(|q| q.to_string()).unwrap_or("???".into());
                groups.entry((Reverse(x.score), tags, prot, name_of(x), x.allowlisted.as_deref().unwrap_or(""))).or_default().push(x);
                for f in &x.findings {
                    let text = match legend.get(f.tag.as_str()) { Some(known) => common(known, &f.reason), None => f.reason.clone() };
                    legend.insert(&f.tag, text);
                }
            }
            for ((Reverse(score), tags, prot, name, allow), mut regs) in groups {
                regs.sort_by_key(|x| x.region.base);
                let worst = regs.iter().map(|x| x.severity).max().unwrap_or(sev);
                let (lo, hi) = (regs.iter().map(|x| x.region.size).min().unwrap_or(0), regs.iter().map(|x| x.region.size).max().unwrap_or(0));
                let _ = write!(o, "    {}  {:>3} x {:<17} {prot}  {} {score:>3}  {name}", p.sev(worst, &format!("{tags:<width$}")), regs.len(), size_range(lo, hi), tr!("pkt", "score"));
                if !allow.is_empty() { let _ = write!(o, " {}", p.note(&trf!("(obniżone: {allow})", "(reduced: {allow})"))); }
                o.push('\n');
                if opt.regions {
                    for x in regs {
                        let _ = writeln!(o, "        {:#018x} {:>10}  ent {}", x.region.base, size(x.region.size), x.entropy_max.map(|e| format!("{e:.2}")).unwrap_or("-".into()));
                        for f in &x.findings { let _ = writeln!(o, "            {:<8} {}", f.tag, f.reason); }
                    }
                } else {
                    let addrs: Vec<String> = regs.iter().take(ADDRS).map(|x| format!("{:#x}", x.region.base)).collect();
                    let more = regs.len().saturating_sub(ADDRS);
                    let _ = writeln!(o, "        {}{}", addrs.join(", "), if more > 0 { format!(" (+{more})") } else { String::new() });
                }
            }
        }
    }

    // procesy z błędem, których nie ma wyżej, zebrane według przyczyny (komunikat bez numeru procesu)
    let mut denied: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pr in r.processes.iter().filter(|pr| !listed(pr)) {
        let Some(e) = &pr.error else { continue };
        let pid = pr.info.pid.map(|x| x.to_string()).unwrap_or("-".into());
        let mut cause = e.clone();
        for word in ["pid", "proces", "process"] { cause = cause.replace(&format!("{word} {pid}: "), ""); }
        denied.entry(cause).or_default().push(match &pr.info.name { Some(n) => format!("{pid} ({n})"), None => pid });
    }
    let denied_total: usize = denied.values().map(Vec::len).sum();
    if denied_total > 0 {
        let _ = writeln!(o, "\n{}", p.head(&trf!("NIEDOSTĘPNE ({denied_total})", "INACCESSIBLE ({denied_total})")));
        for (cause, pids) in &denied {
            let more = pids.len().saturating_sub(PIDS);
            let _ = writeln!(o, "    {cause}");
            let _ = writeln!(o, "        pid: {}{}", pids.iter().take(PIDS).cloned().collect::<Vec<_>>().join(", "), if more > 0 { format!(" (+{more})") } else { String::new() });
        }
        totals.push(trf!("niedostępne {denied_total}", "inaccessible {denied_total}"));
    }

    if !legend.is_empty() {
        let _ = writeln!(o, "\n{}", p.head(tr!("ZNACZNIKI", "TAGS")));
        let width = legend.keys().map(|t| t.chars().count()).max().unwrap_or(0);
        for (tag, text) in &legend { let _ = writeln!(o, "    {}  {text}", p.bold(&format!("{tag:<width$}"))); }
    }

    o.push('\n');
    if legend.is_empty() {
        let _ = writeln!(o, "{}", trf!("Brak znalezisk od progu \"{}\".", "No findings at or above \"{}\".", sev_label(opt.min)));
    }
    if !totals.is_empty() {
        let _ = writeln!(o, "{} {} | {} \"{}\"", tr!("Procesy:", "Processes:"), totals.join(", "), tr!("próg wydruku", "print threshold"), sev_label(opt.min));
    }
    if !legend.is_empty() && !opt.regions {
        let _ = writeln!(o, "{}", tr!("Każdy region osobno, z entropią i opisami: opcja --regions; pełny wynik: --json <plik>.", "Every region on its own line, with entropy and descriptions: option --regions; full result: --json <file>."));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(base: u64, size: u64, tags: &[(&str, &str)], score: u32, sev: Severity) -> RegionReport {
        let prot = Prot::parse("rwx");
        RegionReport {
            region: Region { base, size, prot, kind: RegionKind::Private, backing: None, backing_deleted: false, label: None, readable: true },
            bytes_read: size, truncated: false, zero_pages: 0, heat: None, profile: None, sha256: None, strings: Default::default(), entropy_max: Some(6.5), entropy_mean: None, score, severity: sev, allowlisted: None, allocation: None,
            findings: tags.iter().map(|(t, why)| Finding { id: format!("1:{base:x}:{t}"), detector: t.to_lowercase(), tag: t.to_string(), addr: base, size, prot,
                entropy: None, weight: 30, reason: why.to_string(), bytes_hex: None }).collect(),
        }
    }

    fn process(pid: u32, name: Option<&str>, regions: Vec<RegionReport>, error: Option<&str>) -> ProcessReport {
        ProcessReport {
            info: SourceInfo { os: "windows".into(), arch: "x86_64".into(), pid: Some(pid), name: name.map(str::to_string), source_type: "live".into(), exe: None, exe_deleted: false, exe_verified: false },
            regions_total: 100, regions_unreadable: 0, bytes_scanned: 20 << 20, max_severity: regions.iter().map(|x| x.severity).max().unwrap_or(Severity::None),
            error: error.map(str::to_string), regions, layout: None, stacks: None, context: None,
        }
    }

    fn scan() -> ScanResult {
        let shc = |a: u64| ("SHC", if a == 1 { "wzorce kodu: własny adres @ 0x1111" } else { "wzorce kodu: własny adres @ 0x2222" });
        ScanResult {
            schema_version: SCHEMA_VERSION, tool_version: "0.0.0".into(), timestamp: "t".into(), host: "stacja".into(), heat_cell_bytes: 4096, partial: true,
            processes: vec![
                process(4, None, vec![], Some("brak dostępu: pid 4: chroniony")),
                process(10, Some("niski.exe"), vec![region(0x9000, 4096, &[("X-PRIV", "prywatna wykonywalna")], 30, Severity::Suspicious)], None),
                process(140, None, vec![], Some("brak dostępu: pid 140: chroniony")),
                process(20, Some("wysoki.exe"), vec![
                    region(0x1000, 4096, &[("RWX", "zapis i wykonanie"), shc(1)], 60, Severity::High),
                    region(0x3000, 8192, &[("RWX", "zapis i wykonanie"), shc(2)], 60, Severity::High),
                    region(0x5000, 4096, &[("X-PRIV", "prywatna wykonywalna")], 30, Severity::Suspicious),
                    region(0x7000, 4096, &[("ENT", "entropia")], 5, Severity::Info),
                ], None),
            ],
            lang: None, host_info: None, files: vec![],
        }
    }

    fn opts(regions: bool, color: bool) -> TextOptions { TextOptions { min: Severity::Suspicious, color, regions } }

    #[test]
    fn processes_are_ordered_by_severity_and_regions_grouped() {
        let t = to_text(&scan(), &opts(false, false));
        let at = |s: &str| t.find(s).unwrap_or_else(|| panic!("brak \"{s}\" w:\n{t}"));
        // najpierw waga wysoka, choć proces ma wyższy PID i stoi dalej w wyniku
        assert!(at("WYSOKIE (1)") < at("wysoki.exe") && at("wysoki.exe") < at("PODEJRZANE (1)") && at("PODEJRZANE (1)") < at("niski.exe"), "{t}");
        // dwa regiony o tych samych cechach to jeden wiersz z zakresem rozmiarów i oboma adresami
        assert!(t.contains("RWX,SHC    2 x 4-8 KiB "), "{t}");
        assert!(t.contains("0x1000, 0x3000\n"), "{t}");
        // region poniżej progu nie trafia do wydruku ani do legendy
        assert!(!t.contains("ENT") && !t.contains("0x7000"), "{t}");
        assert!(t.contains("4 procesy | 7 znalezisk w 2 procesach"), "{t}");
        assert!(t.contains("WYNIK CZĘŚCIOWY"), "{t}");
        assert!(!t.contains('\x1b'), "bez opcji koloru wydruk nie zawiera sekwencji ANSI");
    }

    #[test]
    fn inaccessible_processes_are_collapsed_by_cause() {
        let t = to_text(&scan(), &opts(false, false));
        assert!(t.contains("NIEDOSTĘPNE (2)\n    brak dostępu: chroniony\n        pid: 4, 140\n"), "{t}");
        assert_eq!(t.matches("chroniony").count(), 1, "{t}");
        assert!(t.contains("Procesy: wysokie 1, podejrzane 1, niedostępne 2"), "{t}");
    }

    #[test]
    fn tag_descriptions_are_printed_once_without_the_varying_detail() {
        let t = to_text(&scan(), &opts(false, false));
        assert_eq!(t.matches("zapis i wykonanie").count(), 1, "{t}");
        assert_eq!(t.matches("prywatna wykonywalna").count(), 1, "{t}");
        assert!(t.contains("SHC     wzorce kodu: własny adres\n"), "{t}");
        assert!(!t.contains("0x1111"), "{t}");
    }

    #[test]
    fn regions_option_lists_every_region_with_its_own_description() {
        let t = to_text(&scan(), &opts(true, false));
        for want in ["0x0000000000001000", "0x0000000000003000", "@ 0x1111", "@ 0x2222", "ent 6.50"] { assert!(t.contains(want), "brak {want}:\n{t}"); }
        assert!(!t.contains("--regions"), "{t}");
    }

    #[test]
    fn colour_marks_severity_and_english_has_no_polish_words() {
        let t = to_text(&scan(), &opts(false, true));
        assert!(t.contains("\x1b[1;91mWYSOKIE (1)\x1b[0m") && t.contains("\x1b[1;93mPODEJRZANE (1)\x1b[0m"), "{t:?}");
        let en = lang::with(lang::Lang::En, || to_text(&scan(), &opts(false, false)));
        for want in ["HIGH (1)", "SUSPICIOUS (1)", "INACCESSIBLE (2)", "score  60", "4 processes | 7 findings in 2 processes", "Processes: high 1, suspicious 1, inaccessible 2"] {
            assert!(en.contains(want), "brak {want}:\n{en}");
        }
        for bad in ["pkt", "proces ", "znalezisk", "próg"] { assert!(!en.contains(bad), "polskie \"{bad}\" w:\n{en}"); }
    }

    #[test]
    fn nothing_above_the_threshold_is_said_plainly() {
        let mut s = scan();
        s.processes.retain(|pr| pr.error.is_none());
        s.partial = false;
        let t = to_text(&s, &TextOptions { min: Severity::High, color: false, regions: false });
        assert!(t.contains("WYSOKIE (1)") && !t.contains("PODEJRZANE") && !t.contains("0x5000"), "{t}");
        s.processes.retain(|pr| pr.info.pid == Some(10));
        let t = to_text(&s, &TextOptions { min: Severity::High, color: false, regions: false });
        assert!(t.contains("Brak znalezisk od progu \"wysokie\"."), "{t}");
    }
}
