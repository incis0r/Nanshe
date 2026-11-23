//! Raport w Markdown. Cała treść jest traktowana jako dane: znaki o znaczeniu w Markdown
//! i HTML są neutralizowane, bo nazwy procesów, ścieżki i tekst modelu nie są zaufane.
use crate::doc::{class_label, size_h, Block, Doc, MapClass};
use nanshe_core::{tr, trf};
use std::fmt::Write;

/// Neutralizuje składnię Markdown/HTML w tekście niezaufanym.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '#' | '~' | '!' => { o.push('\\'); o.push(c); }
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '\n' | '\r' => o.push(' '),
            c => o.push(c),
        }
    }
    // początek wiersza: znacznik listy ("- x", "+ x", "1. x", "1) x")
    let digits = o.chars().take_while(|c| c.is_ascii_digit()).count();
    let rest = &o[digits..];
    let ordered = digits > 0 && (rest.starts_with(". ") || rest.starts_with(") "));
    if ordered { o.insert(digits, '\\'); } else if o.starts_with("- ") || o.starts_with("+ ") { o.insert(0, '\\'); }
    o
}

fn table(o: &mut String, head: &[String], rows: &[Vec<String>]) {
    let _ = writeln!(o, "| {} |", head.iter().map(|h| esc(h)).collect::<Vec<_>>().join(" | "));
    let _ = writeln!(o, "|{}|", head.iter().map(|_| "---").collect::<Vec<_>>().join("|"));
    for r in rows { let _ = writeln!(o, "| {} |", r.iter().map(|c| esc(c)).collect::<Vec<_>>().join(" | ")); }
    o.push('\n');
}

pub fn render(d: &Doc) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# {}\n\n{}\n", esc(&d.title), esc(&d.subtitle));
    for b in &d.blocks {
        match b {
            // numer rozdziału ("3. Tytuł") po znaczniku nagłówka nie jest listą, więc nie wymaga ucieczki
            Block::H1(t) => { let _ = writeln!(o, "## {}\n", esc(t).replacen("\\. ", ". ", 1)); }
            Block::H2(t) => { let _ = writeln!(o, "### {}\n", esc(t)); }
            Block::H3(t) => { let _ = writeln!(o, "#### {}\n", esc(t)); }
            Block::Para(t) => { let _ = writeln!(o, "{}\n", esc(t)); }
            Block::Note(t) => { let _ = writeln!(o, "> {}\n", esc(t)); }
            Block::Bullets(l) => { for i in l { let _ = writeln!(o, "- {}", esc(i)); } o.push('\n'); }
            Block::Table { head, rows, .. } => table(&mut o, head, rows),
            Block::KeyVals(kv) => table(&mut o, &[tr!("Pole", "Field").to_string(), tr!("Wartość", "Value").to_string()], &kv.iter().map(|(k, v)| vec![k.clone(), v.clone()]).collect::<Vec<_>>()),
            Block::MemMap(rows) => {
                let head = [tr!("Początek", "Start"), tr!("Koniec", "End"), tr!("Rozmiar", "Size"), tr!("Prawa", "Perms"), tr!("Rodzaj", "Type"), tr!("Zawartość", "Contents"), tr!("Uwagi", "Notes")].map(String::from);
                let body: Vec<Vec<String>> = rows.iter().map(|r| vec![format!("{:#x}", r.start), format!("{:#x}", r.end), size_h(r.size),
                    if r.prot.is_empty() { "-".into() } else { r.prot.clone() }, class_label(r.class).to_string(), r.what.clone(),
                    if matches!(r.class, MapClass::Finding(_)) { format!("<<< {}", r.note) } else { r.note.clone() }]).collect();
                table(&mut o, &head, &body);
            }
            Block::Tree(nodes) => {
                for n in nodes { let _ = writeln!(o, "{}- {}{}", "  ".repeat(n.depth as usize), if n.mark { "=> " } else { "" }, esc(&n.text)); }
                o.push('\n');
            }
            // Bloki kodu zawierają wyłącznie znaki wygenerowane tutaj (cyfry szesnastkowe, kropki, drukowalne ASCII
            // bez odwrotnego apostrofu), więc dane nie mogą zamknąć bloku.
            Block::Hex { base, bytes } => {
                o.push_str("```text\n");
                for (i, row) in bytes.chunks(16).enumerate() {
                    let hex: Vec<String> = row.iter().map(|x| format!("{x:02x}")).collect();
                    let asc: String = row.iter().map(|&x| if (0x20..0x7f).contains(&x) && x != b'`' { x as char } else { '.' }).collect();
                    let _ = writeln!(o, "{:#014x}  {:<47}  {}", base + (i * 16) as u64, hex.join(" "), asc);
                }
                o.push_str("```\n\n");
            }
            Block::Heat { base, size, cells } => {
                const RAMP: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];
                let line: String = cells.iter().map(|&c| RAMP[((c.min(80) as usize) * 7 + 40) / 80]).collect();
                let _ = writeln!(o, "```text\n{:#x} {} {:#x}\n```\n", base, line, base.saturating_add(*size));
                let _ = writeln!(o, "{}\n", trf!("Entropia odcinków (0-8): najniższa {:.1}, najwyższa {:.1}; {} odcinków po {}.", "Segment entropy (0-8): lowest {:.1}, highest {:.1}; {} segments of {}.",
                    cells.iter().min().copied().unwrap_or(0) as f32 / 10.0, cells.iter().max().copied().unwrap_or(0) as f32 / 10.0, cells.len(), size_h(size / cells.len().max(1) as u64)));
            }
            Block::Matrix { cols, rows } => {
                let mut head = vec![tr!("Proces", "Process").to_string()]; head.extend(cols.iter().cloned());
                let body: Vec<Vec<String>> = rows.iter().map(|(l, cells)| { let mut r = vec![l.clone()];
                    r.extend(cells.iter().map(|(n, s)| if *n == 0 { "-".to_string() } else { format!("{n} ({})", crate::sev_label(*s)) })); r }).collect();
                table(&mut o, &head, &body);
            }
            Block::Scatter(points) => {
                // w Markdown zamiast wykresu: liczba regionów w przedziałach entropii i rozmiaru
                let sizes: [(&str, u64); 4] = [(tr!("do 16 KiB", "up to 16 KiB"), 16 << 10), (tr!("do 256 KiB", "up to 256 KiB"), 256 << 10), (tr!("do 4 MiB", "up to 4 MiB"), 4 << 20), (tr!("powyżej 4 MiB", "above 4 MiB"), u64::MAX)];
                let ent: [(&str, f32); 4] = [(tr!("bardzo wysoka (od 7,8)", "very high (7.8 and above)"), 7.8), (tr!("wysoka (7,2-7,8)", "high (7.2-7.8)"), 7.2), (tr!("średnia (5-7,2)", "medium (5-7.2)"), 5.0), (tr!("niska (poniżej 5)", "low (below 5)"), -1.0)];
                let mut head = vec![tr!("Entropia \\ rozmiar", "Entropy \\ size").to_string()]; head.extend(sizes.iter().map(|s| s.0.to_string()));
                let band = |e: f32| ent.iter().position(|b| e >= b.1).unwrap_or(3);
                let col = |s: u64| sizes.iter().position(|b| s <= b.1).unwrap_or(3);
                let body: Vec<Vec<String>> = (0..4).map(|i| { let mut r = vec![ent[i].0.to_string()];
                    r.extend((0..4).map(|j| { let n = points.iter().filter(|p| band(p.1) == i && col(p.0) == j).count(); if n == 0 { "-".to_string() } else { n.to_string() } })); r }).collect();
                table(&mut o, &head, &body);
            }
            Block::Flow { regions, process, endpoints } => {
                // w Markdown łańcuch jako tabela: w każdym wierszu region, proces i połączenie
                let n = regions.len().max(endpoints.len());
                let body: Vec<Vec<String>> = (0..n).map(|i| vec![regions.get(i).map(|r| r.0.clone()).unwrap_or_default(),
                    if i == 0 { format!("=> {process} =>") } else { String::new() }, endpoints.get(i).map(|e| e.0.clone()).unwrap_or_default()]).collect();
                table(&mut o, &[tr!("Region w pamięci", "Region in memory").to_string(), tr!("Proces", "Process").to_string(), tr!("Sieć", "Network").to_string()], &body);
            }
            Block::Toc(items) => {
                let _ = writeln!(o, "**{}**\n", tr!("Spis treści", "Contents"));
                for i in items { let _ = writeln!(o, "- {}", esc(i).replacen("\\. ", ". ", 1)); }
                o.push('\n');
            }
            Block::Bars(items) => {
                let max = items.iter().map(|i| i.1).max().unwrap_or(1).max(1);
                let rows: Vec<Vec<String>> = items.iter().map(|(l, v)| vec![l.clone(), v.to_string(), "\u{2588}".repeat(((*v as usize) * 24).div_ceil(max as usize))]).collect();
                table(&mut o, &["Tag".to_string(), tr!("Liczba", "Count").to_string(), tr!("Udział", "Share").to_string()], &rows);
            }
        }
    }
    let _ = writeln!(o, "---\n\n{}", esc(&d.footer));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_text_cannot_inject_markup() {
        for (i, want) in [
            ("a|b", "a\\|b"), ("<script>x</script>", "&lt;script&gt;x&lt;/script&gt;"), ("[x](http://e)", "\\[x\\](http://e)"),
            ("**b** `c`", "\\*\\*b\\*\\* \\`c\\`"), ("line1\nline2", "line1 line2"), ("# h", "\\# h"), ("- item", "\\- item"), ("1. x", "1\\. x"), ("2) x", "2\\) x"), ("7.96", "7.96"), ("-", "-"),
            ("![i](u)", "\\!\\[i\\](u)"), ("a&b", "a&amp;b"),
        ] { assert_eq!(esc(i), want, "{i}"); }
        assert_eq!(esc("zwykły tekst 0x7f00, 12.5 KiB"), "zwykły tekst 0x7f00, 12.5 KiB");
    }

    #[test]
    fn table_cell_cannot_break_the_row() {
        let d = Doc { title: "t".into(), subtitle: "s".into(), footer: "f".into(), blocks: vec![
            Block::Table { head: vec!["A".into(), "B".into()], rows: vec![vec!["x | y\n| z".into(), "ok".into()]], widths: vec![1.0, 1.0] } ] };
        let md = render(&d);
        let row = md.lines().find(|l| l.contains("ok")).unwrap();
        assert_eq!(row, "| x \\| y \\| z | ok |");
    }
}
