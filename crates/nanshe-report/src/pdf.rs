//! Raport w PDF, pisany bez zewnętrznych programów: A4, czcionka DejaVu osadzona w pliku
//! (polskie znaki, tekst da się zaznaczać i przeszukiwać). Wynik jest deterministyczny:
//! ten sam dokument daje ten sam plik, bez znaczników czasu.
use crate::doc::{class_label, size_h, Block, Doc, MapClass, MapRow, TreeNode};
use nanshe_core::Severity;
use nanshe_core::{tr, trf};
use std::collections::BTreeMap;
use std::fmt::Write;
use ttf_parser::{Face, GlyphId};

const REGULAR: &[u8] = include_bytes!("../fonts/DejaVuSans.ttf");
const BOLD: &[u8] = include_bytes!("../fonts/DejaVuSans-Bold.ttf");

const PAGE_W: f32 = 595.28;
const PAGE_H: f32 = 841.89;
const LEFT: f32 = 51.0;
const RIGHT: f32 = 51.0;
const TOP: f32 = 62.0;
const BOTTOM: f32 = 54.0;
const WIDTH: f32 = PAGE_W - LEFT - RIGHT;

type Rgb = (f32, f32, f32);
const INK: Rgb = (0.10, 0.10, 0.12);
const GREY: Rgb = (0.42, 0.42, 0.45);
const WHITE: Rgb = (1.0, 1.0, 1.0);
// Paleta identyfikacji wizualnej (img/logo/README.md): slate #475569, navy #142338, teal #159C9C.
const ACCENT: Rgb = (0.278, 0.333, 0.412);
const ACCENT_DARK: Rgb = (0.078, 0.137, 0.220);
const ACCENT_LIGHT: Rgb = (0.886, 0.910, 0.941);
const BORDER: Rgb = (0.580, 0.639, 0.722);
const TEAL: Rgb = (0.082, 0.612, 0.612);
const TEAL_LIGHT: Rgb = (0.75, 0.90, 0.90);
const RED: Rgb = (0.75, 0.18, 0.15);
const RED_LIGHT: Rgb = (0.99, 0.91, 0.90);
const ORANGE: Rgb = (0.88, 0.54, 0.12);
const ORANGE_LIGHT: Rgb = (0.99, 0.95, 0.86);
const YELLOW: Rgb = (0.93, 0.80, 0.30);
const PALE: Rgb = (0.945, 0.957, 0.973);

fn class_color(c: MapClass) -> Rgb {
    match c {
        MapClass::Code => ACCENT, MapClass::File => BORDER, MapClass::Anon => (0.80, 0.84, 0.88), MapClass::Heap => TEAL_LIGHT, MapClass::Stack => TEAL,
        MapClass::Special => ACCENT_LIGHT, MapClass::Gap | MapClass::Collapsed => WHITE,
        MapClass::Finding(Severity::High) => RED, MapClass::Finding(Severity::Suspicious) => ORANGE, MapClass::Finding(_) => YELLOW,
    }
}

/// Kolor komórki profilu entropii (dziesiąte części bita): jasny, turkus, pomarańcz od 7.2, czerwień od 7.8.
fn heat_color(c: u8) -> Rgb {
    match c {
        78.. => RED, 72..=77 => ORANGE,
        _ => { let t = c as f32 / 72.0; (PALE.0 + (TEAL.0 - PALE.0) * t, PALE.1 + (TEAL.1 - PALE.1) * t, PALE.2 + (TEAL.2 - PALE.2) * t) }
    }
}

/// Znak projektu (img/logo/nanshe-symbol.svg) jako ścieżki PDF w układzie SVG 256x256.
const SYMBOL_SLATE: &str = "128 8 m 232 68 l 232 188 l 128 248 l 24 188 l 24 68 l h 128 38 m 50 83 l 50 173 l 128 218 l 206 173 l 206 83 l h f*\n128 51 m 190 87 l 190 126 l 96 72 l h 68 92 m 92 78 l 92 145 l 68 131 l h 164 130 m 190 145 l 190 175 l 164 190 l h 68 145 m 160 198 l 128 216 l 68 181 l h f\n";

const SYMBOL_TEAL: &str = "104 141 10 17 re 123 130 10 28 re 142 118 10 40 re f\n";
const NOTE_BG: Rgb = (0.99, 0.96, 0.86);
const NOTE_BORDER: Rgb = (0.80, 0.66, 0.25);

const R: usize = 0;
const B: usize = 1;

struct Font<'a> {
    face: Face<'a>,
    data: &'a [u8],
    name: &'static str,
    upem: f32,
    /// Użyte glify -> znak (do tablicy szerokości i mapy ToUnicode).
    used: BTreeMap<u16, char>,
}

impl<'a> Font<'a> {
    fn new(data: &'a [u8], name: &'static str) -> Self {
        let face = Face::parse(data, 0).expect("osadzona czcionka");
        let upem = face.units_per_em() as f32;
        Font { face, data, name, upem, used: BTreeMap::new() }
    }
    /// Glif znaku; znak spoza czcionki (np. emoji od modelu) staje się pytajnikiem.
    fn glyph(&self, c: char) -> (u16, char) {
        match self.face.glyph_index(c) {
            Some(g) if g.0 != 0 => (g.0, c),
            _ => (self.face.glyph_index('?').map(|g| g.0).unwrap_or(0), '?'),
        }
    }
    fn advance(&self, gid: u16) -> f32 { self.face.glyph_hor_advance(GlyphId(gid)).unwrap_or(0) as f32 }
    fn width(&self, s: &str, size: f32) -> f32 {
        s.chars().map(|c| self.advance(self.glyph(c).0)).sum::<f32>() * size / self.upem
    }
    fn encode(&mut self, s: &str) -> String {
        let mut h = String::with_capacity(s.len() * 4);
        for c in s.chars() {
            let (g, shown) = self.glyph(c);
            self.used.insert(g, shown);
            let _ = write!(h, "{g:04X}");
        }
        h
    }
}

struct Layout<'a> {
    fonts: [Font<'a>; 2],
    pages: Vec<String>,
    cur: String,
    /// Górna krawędź wolnego miejsca (współrzędna PDF: od dołu strony).
    y: f32,
    /// Numer strony każdego rozdziału głównego, w kolejności (do spisu treści).
    h1_pages: Vec<usize>,
}

impl<'a> Layout<'a> {
    fn new_page(&mut self) {
        self.pages.push(std::mem::take(&mut self.cur));
        self.y = PAGE_H - TOP;
    }
    fn ensure(&mut self, h: f32) -> bool {
        if self.y - h < BOTTOM { self.new_page(); true } else { false }
    }
    fn fill(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb) {
        let _ = writeln!(self.cur, "{:.3} {:.3} {:.3} rg {x:.2} {y:.2} {w:.2} {h:.2} re f", c.0, c.1, c.2);
    }
    fn stroke(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb) {
        let _ = writeln!(self.cur, "0.5 w {:.3} {:.3} {:.3} RG {x:.2} {y:.2} {w:.2} {h:.2} re S", c.0, c.1, c.2);
    }
    fn line(&mut self, x1: f32, y: f32, x2: f32, c: Rgb) {
        let _ = writeln!(self.cur, "0.6 w {:.3} {:.3} {:.3} RG {x1:.2} {y:.2} m {x2:.2} {y:.2} l S", c.0, c.1, c.2);
    }
    /// Znak projektu o boku `size`, lewy górny róg w (x, top).
    fn symbol(&mut self, x: f32, top: f32, size: f32) {
        let k = size / 256.0;
        let _ = write!(self.cur, "q {k:.4} 0 0 -{k:.4} {x:.2} {top:.2} cm {:.3} {:.3} {:.3} rg {SYMBOL_SLATE}{:.3} {:.3} {:.3} rg {SYMBOL_TEAL}Q\n",
            ACCENT.0, ACCENT.1, ACCENT.2, TEAL.0, TEAL.1, TEAL.2);
    }
    fn text(&mut self, f: usize, size: f32, c: Rgb, x: f32, baseline: f32, s: &str) {
        if s.is_empty() { return; }
        let hex = self.fonts[f].encode(s);
        let _ = writeln!(self.cur, "BT /F{} {size:.2} Tf {:.3} {:.3} {:.3} rg {x:.2} {baseline:.2} Td <{hex}> Tj ET", f + 1, c.0, c.1, c.2);
    }

    /// Zawijanie po słowach; słowo dłuższe niż wiersz (adres, ścieżka, skrót) jest łamane po znakach.
    fn wrap(&self, f: usize, size: f32, s: &str, max: f32) -> Vec<String> {
        let font = &self.fonts[f];
        let mut lines = Vec::new();
        let mut cur = String::new();
        for word in s.split_whitespace() {
            let candidate = if cur.is_empty() { word.to_string() } else { format!("{cur} {word}") };
            if font.width(&candidate, size) <= max { cur = candidate; continue; }
            if !cur.is_empty() { lines.push(std::mem::take(&mut cur)); }
            if font.width(word, size) <= max { cur = word.to_string(); continue; }
            for ch in word.chars() {
                let mut t = cur.clone(); t.push(ch);
                if font.width(&t, size) > max && !cur.is_empty() { lines.push(std::mem::take(&mut cur)); cur.push(ch); } else { cur = t; }
            }
        }
        if !cur.is_empty() { lines.push(cur); }
        if lines.is_empty() { lines.push(String::new()); }
        lines
    }

    /// Skraca tekst do jednego wiersza o zadanej szerokości.
    fn fit(&self, f: usize, size: f32, s: &str, max: f32) -> String {
        if self.fonts[f].width(s, size) <= max { return s.to_string(); }
        let mut t: String = s.to_string();
        while !t.is_empty() && self.fonts[f].width(&format!("{t}..."), size) > max { t.pop(); }
        format!("{t}...")
    }

    fn paragraph(&mut self, f: usize, size: f32, c: Rgb, x: f32, w: f32, s: &str) {
        let lh = size * 1.38;
        for l in self.wrap(f, size, s, w) {
            self.ensure(lh);
            let base = self.y - size;
            self.text(f, size, c, x, base, &l);
            self.y -= lh;
        }
    }

    fn heading(&mut self, level: u8, s: &str) {
        match level {
            1 => {
                self.y -= 8.0;
                self.ensure(20.0 + 48.0);
                let t = self.fit(B, 11.5, s, WIDTH - 14.0);
                self.fill(LEFT, self.y - 20.0, WIDTH, 20.0, ACCENT);
                self.text(B, 11.5, WHITE, LEFT + 7.0, self.y - 14.2, &t);
                self.y -= 20.0 + 7.0;
            }
            2 => {
                self.y -= 6.0;
                self.ensure(17.0 + 36.0);
                let t = self.fit(B, 10.0, s, WIDTH - 12.0);
                self.fill(LEFT, self.y - 17.0, WIDTH, 17.0, ACCENT_LIGHT);
                self.text(B, 10.0, ACCENT_DARK, LEFT + 6.0, self.y - 12.2, &t);
                self.y -= 17.0 + 6.0;
            }
            _ => {
                self.y -= 3.0;
                self.ensure(13.0 + 26.0);
                let t = self.fit(B, 9.5, s, WIDTH);
                self.text(B, 9.5, ACCENT_DARK, LEFT, self.y - 9.5, &t);
                self.y -= 13.0 + 3.0;
            }
        }
    }

    fn note(&mut self, s: &str) {
        let (size, pad) = (8.8, 6.0);
        let lh = size * 1.38;
        let lines = self.wrap(R, size, s, WIDTH - 2.0 * pad);
        let h = lines.len() as f32 * lh + 2.0 * pad;
        self.ensure(h);
        self.fill(LEFT, self.y - h, WIDTH, h, NOTE_BG);
        self.stroke(LEFT, self.y - h, WIDTH, h, NOTE_BORDER);
        let mut base = self.y - pad - size;
        for l in lines { self.text(R, size, INK, LEFT + pad, base, &l); base -= lh; }
        self.y -= h + 7.0;
    }

    fn bullets(&mut self, items: &[String]) {
        let size = 9.2;
        let lh = size * 1.38;
        for it in items {
            let lines = self.wrap(R, size, it, WIDTH - 14.0);
            for (i, l) in lines.iter().enumerate() {
                self.ensure(lh);
                let base = self.y - size;
                if i == 0 { self.text(R, size, ACCENT_DARK, LEFT + 3.0, base, "\u{2022}"); }
                self.text(R, size, INK, LEFT + 14.0, base, l);
                self.y -= lh;
            }
            self.y -= 1.5;
        }
        self.y -= 5.0;
    }

    /// Jeden wiersz tabeli; zwraca jego wysokość. `styles`: (czcionka, kolor tekstu, tło) per kolumna.
    fn row(&mut self, cells: &[String], widths: &[f32], styles: &[(usize, Rgb, Option<Rgb>)], head: Option<(&[String], &[(usize, Rgb, Option<Rgb>)])>) {
        let (size, pad) = (8.0, 3.2);
        let lh = size * 1.32;
        let wrapped: Vec<Vec<String>> = cells.iter().zip(widths).zip(styles).map(|((c, w), st)| self.wrap(st.0, size, c, w - 2.0 * pad)).collect();
        let h = wrapped.iter().map(|l| l.len()).max().unwrap_or(1) as f32 * lh + 2.0 * pad;
        if self.ensure(h) {
            // tabela przeszła na nową stronę: powtórz nagłówek
            if let Some((hc, hs)) = head { self.row(hc, widths, hs, None); }
        }
        let mut x = LEFT;
        for ((lines, w), st) in wrapped.iter().zip(widths).zip(styles) {
            if let Some(bg) = st.2 { self.fill(x, self.y - h, *w, h, bg); }
            self.stroke(x, self.y - h, *w, h, BORDER);
            let mut base = self.y - pad - size + 0.6;
            for l in lines { self.text(st.0, size, st.1, x + pad, base, l); base -= lh; }
            x += w;
        }
        self.y -= h;
    }

    fn table(&mut self, head: &[String], rows: &[Vec<String>], weights: &[f32]) {
        let n = head.len();
        let total: f32 = (0..n).map(|i| weights.get(i).copied().unwrap_or(1.0)).sum();
        let widths: Vec<f32> = (0..n).map(|i| weights.get(i).copied().unwrap_or(1.0) / total * WIDTH).collect();
        let hs: Vec<(usize, Rgb, Option<Rgb>)> = vec![(B, WHITE, Some(ACCENT)); n];
        let body: Vec<(usize, Rgb, Option<Rgb>)> = vec![(R, INK, None); n];
        // nagłówek nie może zostać sam na dole strony
        self.ensure(46.0);
        self.row(head, &widths, &hs, None);
        for r in rows {
            let mut cells = r.clone();
            cells.resize(n, String::new());
            self.row(&cells, &widths, &body, Some((head, &hs)));
        }
        self.y -= 8.0;
    }

    fn seg(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, c: Rgb) {
        let _ = writeln!(self.cur, "0.6 w {:.3} {:.3} {:.3} RG {x1:.2} {y1:.2} m {x2:.2} {y2:.2} l S", c.0, c.1, c.2);
    }

    /// Diagram przestrzeni adresowej: adres, blok w kolorze rodzaju, opis. Najniższe adresy u góry.
    fn mem_map(&mut self, rows: &[MapRow]) {
        let (ax, bx, bw) = (LEFT, LEFT + 88.0, 30.0);
        let tx = bx + bw + 8.0;
        let (px, sx) = (PAGE_W - RIGHT - 118.0, PAGE_W - RIGHT - 50.0);
        for r in rows {
            let finding = matches!(r.class, MapClass::Finding(_));
            let h = match r.class {
                MapClass::Gap => 11.0,
                MapClass::Collapsed => 13.0,
                _ => { let pages = (r.size.max(4096) / 4096) as f32; (11.0 + 1.6 * pages.log2()).clamp(if finding { 24.0 } else { 12.0 }, 34.0) }
            };
            self.ensure(h + 1.0);
            let y = self.y - h;
            if finding { self.fill(LEFT, y, WIDTH, h, if r.class == MapClass::Finding(Severity::High) { RED_LIGHT } else { ORANGE_LIGHT }); }
            match r.class {
                MapClass::Gap | MapClass::Collapsed => {
                    // przerwa w osi: dwie krótkie kreski zamiast bloku
                    for dx in [bw * 0.35, bw * 0.65] { self.seg(bx + dx, y + 2.0, bx + dx, y + h - 2.0, BORDER); }
                    let t = if r.class == MapClass::Gap { format!("{} ({})", r.what, size_h(r.size)) } else { format!("{} ({}){}", r.what, size_h(r.size), if r.note.is_empty() { String::new() } else { format!(": {}", r.note) }) };
                    let t = self.fit(R, 7.0, &t, PAGE_W - RIGHT - tx);
                    self.text(R, 7.0, GREY, tx, y + h / 2.0 - 2.4, &t);
                }
                _ => {
                    self.fill(bx, y, bw, h, class_color(r.class));
                    self.stroke(bx, y, bw, h, if finding { class_color(r.class) } else { ACCENT });
                    self.text(R, 6.6, GREY, ax, self.y - 7.2, &format!("{:#x}", r.start));
                    let top = self.y - 8.4;
                    let name = self.fit(if finding { B } else { R }, 8.0, &r.what, px - tx - 6.0);
                    self.text(if finding { B } else { R }, 8.0, INK, tx, top, &name);
                    self.text(R, 7.4, INK, px, top, &r.prot.chars().take(15).collect::<String>());
                    let s = size_h(r.size);
                    let w = self.fonts[R].width(&s, 7.4);
                    self.text(R, 7.4, INK, PAGE_W - RIGHT - w - 2.0, top, &s);
                    let _ = sx;
                    if !r.note.is_empty() && h >= 20.0 {
                        let n = self.fit(if finding { B } else { R }, 7.2, &if finding { format!("{}: {}", class_label(r.class), r.note) } else { r.note.clone() }, PAGE_W - RIGHT - tx);
                        self.text(if finding { B } else { R }, 7.2, if finding { class_color(r.class) } else { GREY }, tx, top - 10.0, &n);
                    } else if !r.note.is_empty() {
                        let used = self.fonts[R].width(&name, 8.0);
                        let n = self.fit(R, 6.8, &r.note, (px - tx - used - 14.0).max(0.0));
                        if n != "..." { self.text(R, 6.8, GREY, tx + used + 6.0, top, &n); }
                    }
                }
            }
            self.y -= h + 1.0;
        }
        // adres końca i legenda kolorów
        if let Some(l) = rows.last() { self.ensure(10.0); self.text(R, 6.6, GREY, ax, self.y - 6.6, &format!("{:#x}", l.end)); self.y -= 12.0; }
        self.ensure(12.0);
        let mut x = LEFT;
        for c in [MapClass::Finding(Severity::High), MapClass::Finding(Severity::Suspicious), MapClass::Code, MapClass::File, MapClass::Anon, MapClass::Heap, MapClass::Stack] {
            let label = match c { MapClass::Finding(Severity::High) => tr!("znalezisko: wysokie", "finding: high"), MapClass::Finding(_) => tr!("podejrzane", "suspicious"), c => class_label(c) };
            self.fill(x, self.y - 8.0, 8.0, 8.0, class_color(c));
            self.stroke(x, self.y - 8.0, 8.0, 8.0, ACCENT);
            self.text(R, 7.0, GREY, x + 11.0, self.y - 7.0, label);
            x += 11.0 + self.fonts[R].width(label, 7.0) + 10.0;
        }
        self.y -= 18.0;
    }

    /// Drzewo procesów: pudełko na proces, wcięcie na poziom, łącznik do rodzica.
    fn tree(&mut self, nodes: &[TreeNode]) {
        let max_depth = nodes.iter().map(|n| n.depth).max().unwrap_or(0) as f32;
        let step = if max_depth > 0.0 { (200.0 / max_depth).min(16.0) } else { 0.0 };
        let (h, gap) = (14.0, 3.0);
        for n in nodes {
            self.ensure(h + gap);
            let x = LEFT + n.depth as f32 * step;
            let y = self.y - h;
            if n.depth > 0 {
                let ex = x - step * 0.55;
                self.seg(ex, self.y + gap, ex, y + h / 2.0, ACCENT);
                self.seg(ex, y + h / 2.0, x, y + h / 2.0, ACCENT);
            }
            let w = PAGE_W - RIGHT - x;
            self.fill(x, y, w, h, if n.mark { TEAL_LIGHT } else { PALE });
            self.stroke(x, y, w, h, if n.mark { TEAL } else { BORDER });
            let t = self.fit(if n.mark { B } else { R }, 8.0, &n.text, w - 10.0);
            self.text(if n.mark { B } else { R }, 8.0, INK, x + 5.0, y + 4.2, &t);
            self.y -= h + gap;
        }
        self.y -= 6.0;
    }

    /// Podgląd bajtów: adres, 16 bajtów szesnastkowo, znaki drukowalne. Każdy element ma stałą
    /// pozycję, więc kolumny są równe mimo czcionki proporcjonalnej.
    fn hexdump(&mut self, base: u64, bytes: &[u8]) {
        let (size, lh, pad) = (7.0, 9.4, 4.0);
        let rows = bytes.len().div_ceil(16);
        let h = rows as f32 * lh + 2.0 * pad;
        self.ensure(h);
        self.fill(LEFT, self.y - h, WIDTH, h, PALE);
        self.stroke(LEFT, self.y - h, WIDTH, h, BORDER);
        let (hx, ax) = (LEFT + 78.0, LEFT + 78.0 + 16.0 * 14.6 + 16.0);
        let mut base_y = self.y - pad - size;
        for (i, row) in bytes.chunks(16).enumerate() {
            self.text(R, size, GREY, LEFT + pad, base_y, &format!("{:#014x}", base + (i * 16) as u64));
            for (k, b) in row.iter().enumerate() {
                let x = hx + k as f32 * 14.6 + if k >= 8 { 6.0 } else { 0.0 };
                self.text(R, size, if *b == 0 { GREY } else { INK }, x, base_y, &format!("{b:02x}"));
                let ch = if (0x21..0x7f).contains(b) { (*b as char).to_string() } else { "\u{00b7}".to_string() };
                self.text(R, size, if (0x21..0x7f).contains(b) { INK } else { BORDER }, ax + k as f32 * 6.4, base_y, &ch);
            }
            base_y -= lh;
        }
        self.y -= h + 7.0;
    }

    /// Profil entropii: pasek komórek w kolorze entropii, adresy końców i skala.
    fn heat(&mut self, base: u64, size: u64, cells: &[u8]) {
        if cells.is_empty() { return; }
        let h = 14.0;
        self.ensure(h + 26.0);
        let w = WIDTH / cells.len() as f32;
        for (i, c) in cells.iter().enumerate() { self.fill(LEFT + i as f32 * w, self.y - h, w + 0.3, h, heat_color(*c)); }
        self.stroke(LEFT, self.y - h, WIDTH, h, ACCENT);
        self.y -= h + 2.0;
        self.text(R, 6.6, GREY, LEFT, self.y - 6.6, &format!("{base:#x}"));
        let e = format!("{:#x}", base.saturating_add(size));
        let ew = self.fonts[R].width(&e, 6.6);
        self.text(R, 6.6, GREY, PAGE_W - RIGHT - ew, self.y - 6.6, &e);
        self.y -= 10.0;
        let mut x = LEFT;
        for (c, label) in [(10u8, tr!("niska", "low")), (45, tr!("średnia (zwykły kod)", "medium (ordinary code)")), (74, tr!("od 7.2: wysoka", "7.2 and above: high")), (79, tr!("od 7.8: bardzo wysoka", "7.8 and above: very high"))] {
            self.fill(x, self.y - 7.0, 7.0, 7.0, heat_color(c));
            self.stroke(x, self.y - 7.0, 7.0, 7.0, BORDER);
            self.text(R, 6.8, GREY, x + 10.0, self.y - 6.4, label);
            x += 10.0 + self.fonts[R].width(label, 6.8) + 10.0;
        }
        let s = trf!("{} odcinków po {}; min {:.1}, max {:.1}", "{} segments of {}; min {:.1}, max {:.1}", cells.len(), size_h(size / cells.len() as u64),
            cells.iter().min().copied().unwrap_or(0) as f32 / 10.0, cells.iter().max().copied().unwrap_or(0) as f32 / 10.0);
        let sw = self.fonts[R].width(&s, 6.8);
        self.text(R, 6.8, GREY, PAGE_W - RIGHT - sw, self.y - 6.4, &s);
        self.y -= 15.0;
    }

    /// Macierz procesy x cechy: komórka w kolorze najwyższej wagi z liczbą regionów.
    fn matrix(&mut self, cols: &[String], rows: &[(String, Vec<(u32, Severity)>)]) {
        if cols.is_empty() { return; }
        let lw = 170.0;
        let cw = ((WIDTH - lw) / cols.len() as f32).min(48.0);
        let h = 13.0;
        let header = |l: &mut Self| {
            l.ensure(h * 2.0);
            for (i, c) in cols.iter().enumerate() {
                let t = l.fit(B, 6.8, c, cw - 3.0);
                let w = l.fonts[B].width(&t, 6.8);
                l.text(B, 6.8, ACCENT_DARK, LEFT + lw + i as f32 * cw + (cw - w) / 2.0, l.y - 9.0, &t);
            }
            l.y -= h;
        };
        header(self);
        for (label, cells) in rows {
            if self.ensure(h) { header(self); }
            let y = self.y - h;
            let t = self.fit(R, 7.6, label, lw - 6.0);
            self.text(R, 7.6, INK, LEFT, y + 3.8, &t);
            for (i, (n, sev)) in cells.iter().enumerate() {
                let x = LEFT + lw + i as f32 * cw;
                let fill = match sev { Severity::High => RED, Severity::Suspicious => ORANGE, Severity::Info => ACCENT_LIGHT, Severity::None => WHITE };
                if *n > 0 { self.fill(x + 1.0, y + 1.0, cw - 2.0, h - 2.0, fill); }
                self.stroke(x + 1.0, y + 1.0, cw - 2.0, h - 2.0, BORDER);
                if *n > 0 {
                    let s = n.to_string();
                    let w = self.fonts[B].width(&s, 7.6);
                    self.text(B, 7.6, if matches!(sev, Severity::High | Severity::Suspicious) { WHITE } else { INK }, x + (cw - w) / 2.0, y + 3.8, &s);
                }
            }
            self.y -= h;
        }
        self.y -= 8.0;
    }

    /// Wykres rozrzutu: w poziomie rozmiar regionu (skala logarytmiczna), w pionie entropia 0-8.
    fn scatter(&mut self, points: &[(u64, f32, Severity)]) {
        let (pw, ph, lx) = (330.0, 120.0, LEFT + 34.0);
        self.ensure(ph + 34.0);
        let top = self.y - 4.0;
        let bottom = top - ph;
        self.fill(lx, bottom, pw, ph, PALE);
        self.stroke(lx, bottom, pw, ph, BORDER);
        // oś pionowa: entropia; progi detektora 7.2 i 7.8 zaznaczone liniami
        for e in [0.0f32, 2.0, 4.0, 6.0, 8.0] {
            let y = bottom + ph * e / 8.0;
            self.text(R, 6.6, GREY, lx - 12.0, y - 2.2, &format!("{e:.0}"));
            if e > 0.0 && e < 8.0 { self.seg(lx, y, lx + pw, y, WHITE); }
        }
        for (e, c) in [(7.2f32, ORANGE), (7.8, RED)] { let y = bottom + ph * e / 8.0; self.seg(lx, y, lx + pw, y, c); }
        self.text(R, 6.6, GREY, LEFT, top + 3.0, tr!("entropia (0-8)", "entropy (0-8)"));
        // oś pozioma: od 4 KiB do największego regionu, co najmniej do 1 MiB
        let lo = 12.0f32;
        let hi = points.iter().map(|p| (p.0.max(4096) as f32).log2()).fold(20.0f32, f32::max).ceil();
        let x_of = |size: u64| lx + pw * (((size.max(4096) as f32).log2() - lo) / (hi - lo)).clamp(0.0, 1.0);
        let mut k = lo as u32;
        while k as f32 <= hi {
            let x = x_of(1u64 << k);
            let label = size_h(1u64 << k);
            let w = self.fonts[R].width(&label, 6.6);
            self.text(R, 6.6, GREY, (x - w / 2.0).clamp(lx, lx + pw - w), bottom - 9.0, &label);
            k += if hi - lo > 12.0 { 4 } else { 2 };
        }
        // punkty: najpierw słabe, na wierzchu mocne
        let mut pts: Vec<&(u64, f32, Severity)> = points.iter().collect();
        pts.sort_by_key(|p| p.2);
        for p in pts {
            let (x, y) = (x_of(p.0), bottom + ph * p.1.clamp(0.0, 8.0) / 8.0);
            let c = match p.2 { Severity::High => RED, Severity::Suspicious => ORANGE, _ => ACCENT };
            self.fill((x - 2.0).clamp(lx, lx + pw - 4.0), (y - 2.0).clamp(bottom, top - 4.0), 4.0, 4.0, c);
        }
        // legenda po prawej
        let gx = lx + pw + 14.0;
        let mut gy = top - 8.0;
        for (c, label) in [(RED, tr!("wysokie", "high")), (ORANGE, tr!("podejrzane", "suspicious")), (ACCENT, "info")] {
            self.fill(gx, gy - 1.0, 6.0, 6.0, c);
            self.text(R, 7.0, GREY, gx + 10.0, gy - 0.4, label);
            gy -= 11.0;
        }
        self.text(R, 6.6, ORANGE, gx, gy - 6.0, tr!("linia 7,2: wysoka", "line 7.2: high"));
        self.text(R, 6.6, RED, gx, gy - 16.0, tr!("linia 7,8: bardzo wysoka", "line 7.8: very high"));
        self.text(R, 6.6, GREY, lx + pw / 2.0 - 30.0, bottom - 19.0, tr!("rozmiar regionu", "region size"));
        self.y = bottom - 28.0;
    }

    /// Łańcuch pamięć -> proces -> sieć: trzy kolumny pudełek połączone liniami.
    fn flow(&mut self, regions: &[(String, Severity)], process: &str, endpoints: &[(String, bool)]) {
        let (bh, gap) = (15.0, 4.0);
        let rows = regions.len().max(endpoints.len()).max(1) as f32;
        let total = rows * (bh + gap);
        self.ensure(total + 22.0);
        let (lw, cw, rw) = (168.0, 96.0, 196.0);
        let (lx, cx, rx) = (LEFT, LEFT + lw + 16.0, PAGE_W - RIGHT - rw);
        // nagłówki kolumn
        for (x, t) in [(lx, tr!("pamięć: regiony ze znaleziskami", "memory: regions with findings")), (cx, tr!("proces", "process")), (rx, tr!("sieć: gniazda z chwili skanu", "network: sockets at scan time"))] { self.text(B, 7.0, GREY, x, self.y - 7.0, t); }
        self.y -= 12.0;
        let top = self.y;
        let col_y = |n: usize, i: usize| top - (rows - n as f32) * (bh + gap) / 2.0 - i as f32 * (bh + gap) - bh;
        let mid = top - total / 2.0;
        // linie pod pudełkami
        for i in 0..regions.len() { let y = col_y(regions.len(), i) + bh / 2.0; self.seg(lx + lw, y, cx, mid, BORDER); }
        for i in 0..endpoints.len() { let y = col_y(endpoints.len(), i) + bh / 2.0; self.seg(cx + cw, mid, rx, y, if endpoints[i].1 { TEAL } else { BORDER }); }
        for (i, (label, sev)) in regions.iter().enumerate() {
            let y = col_y(regions.len(), i);
            let (fill, edge) = match sev { Severity::High => (RED_LIGHT, RED), Severity::Suspicious => (ORANGE_LIGHT, ORANGE), _ => (PALE, BORDER) };
            self.fill(lx, y, lw, bh, fill); self.stroke(lx, y, lw, bh, edge);
            let t = self.fit(R, 7.0, label, lw - 8.0);
            self.text(R, 7.0, INK, lx + 4.0, y + 4.6, &t);
        }
        // proces: wyższe pudełko pośrodku
        let ph = 30.0f32.min(total.max(bh));
        self.fill(cx, mid - ph / 2.0, cw, ph, TEAL_LIGHT); self.stroke(cx, mid - ph / 2.0, cw, ph, TEAL);
        let lines = self.wrap(B, 7.6, process, cw - 8.0);
        let mut ty = mid + (lines.len().min(2) as f32 * 9.0) / 2.0 - 7.6;
        for l in lines.iter().take(2) { self.text(B, 7.6, INK, cx + 4.0, ty, l); ty -= 9.0; }
        for (i, (label, remote)) in endpoints.iter().enumerate() {
            let y = col_y(endpoints.len(), i);
            self.fill(rx, y, rw, bh, if *remote { TEAL_LIGHT } else { PALE }); self.stroke(rx, y, rw, bh, if *remote { TEAL } else { BORDER });
            let t = self.fit(R, 7.0, label, rw - 8.0);
            self.text(R, 7.0, INK, rx + 4.0, y + 4.6, &t);
        }
        self.y = top - total - 6.0;
    }

    fn bars(&mut self, items: &[(String, u32)]) {
        let max = items.iter().map(|i| i.1).max().unwrap_or(1).max(1) as f32;
        let (lw, h) = (70.0, 11.0);
        for (label, v) in items {
            self.ensure(h + 3.0);
            let t = self.fit(B, 8.0, label, lw - 4.0);
            self.text(B, 8.0, ACCENT_DARK, LEFT, self.y - 8.6, &t);
            let w = ((WIDTH - lw - 30.0) * *v as f32 / max).max(2.0);
            self.fill(LEFT + lw, self.y - h, w, h, TEAL);
            self.text(R, 8.0, INK, LEFT + lw + w + 5.0, self.y - 8.6, &v.to_string());
            self.y -= h + 3.0;
        }
        self.y -= 6.0;
    }

    /// Spis treści. `pages`: numery stron rozdziałów z poprzedniego przebiegu układu; pusty w pierwszym
    /// przebiegu. Wysokość zależy tylko od liczby pozycji, więc numery stron z pierwszego przebiegu
    /// pozostają prawdziwe w drugim.
    fn toc(&mut self, items: &[String], pages: &[usize]) {
        const ROW: f32 = 12.5;
        self.ensure(20.0 + ROW * items.len().min(12) as f32);
        self.text(B, 10.0, ACCENT_DARK, LEFT, self.y - 10.0, tr!("Spis treści", "Contents"));
        self.y -= 17.0;
        for (i, t) in items.iter().enumerate() {
            self.ensure(ROW);
            let num = pages.get(i).map(|p| p.to_string()).unwrap_or_default();
            let nw = self.fonts[R].width(&num, 9.0);
            let label = self.fit(R, 9.0, t, WIDTH - nw - 24.0);
            let lw = self.fonts[R].width(&label, 9.0);
            self.text(R, 9.0, INK, LEFT + 6.0, self.y - 9.0, &label);
            self.text(R, 9.0, INK, PAGE_W - RIGHT - nw, self.y - 9.0, &num);
            if !num.is_empty() { self.line(LEFT + 6.0 + lw + 5.0, self.y - 8.0, PAGE_W - RIGHT - nw - 5.0, BORDER); }
            self.y -= ROW;
        }
        self.y -= 8.0;
    }
    fn keyvals(&mut self, kv: &[(String, String)]) {
        let widths = [WIDTH * 0.24, WIDTH * 0.76];
        let st = [(B, ACCENT_DARK, Some(ACCENT_LIGHT)), (R, INK, None)];
        for (k, v) in kv { self.row(&[k.clone(), v.clone()], &widths, &st, None); }
        self.y -= 8.0;
    }
}

fn stream(dict_extra: &str, data: &[u8]) -> Vec<u8> {
    let z = miniz_oxide::deflate::compress_to_vec_zlib(data, 6);
    let mut o = format!("<< /Length {} /Filter /FlateDecode{dict_extra} >>\nstream\n", z.len()).into_bytes();
    o.extend_from_slice(&z);
    o.extend_from_slice(b"\nendstream");
    o
}

fn utf16_hex(s: &str) -> String {
    let mut h = String::from("FEFF");
    for u in s.encode_utf16() { let _ = write!(h, "{u:04X}"); }
    h
}

fn to_unicode(used: &BTreeMap<u16, char>) -> Vec<u8> {
    let mut s = String::from("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");

    let all: Vec<(&u16, &char)> = used.iter().collect();
    for chunk in all.chunks(100) {
        let _ = writeln!(s, "{} beginbfchar", chunk.len());
        for (g, c) in chunk {
            let mut u = String::new();
            for x in c.encode_utf16(&mut [0u16; 2]) { let _ = write!(u, "{x:04X}"); }
            let _ = writeln!(s, "<{g:04X}> <{u}>");
        }
        s.push_str("endbfchar\n");
    }
    s.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    s.into_bytes()
}

pub fn render(d: &Doc) -> Vec<u8> {
    // dwa przebiegi układu: pierwszy ustala, na której stronie zaczyna się każdy rozdział,
    // drugi wpisuje te numery do spisu treści
    let has_toc = d.blocks.iter().any(|b| matches!(b, Block::Toc(_)));
    let pages = if has_toc { render_pass(d, &[]).1 } else { Vec::new() };
    render_pass(d, &pages).0
}

fn render_pass(d: &Doc, toc_pages: &[usize]) -> (Vec<u8>, Vec<usize>) {
    let mut l = Layout { fonts: [Font::new(REGULAR, "DejaVuSans"), Font::new(BOLD, "DejaVuSans-Bold")], pages: Vec::new(), cur: String::new(), y: PAGE_H - TOP, h1_pages: Vec::new() };

    // tytuł na pierwszej stronie
    const MARK: f32 = 40.0;
    l.symbol(PAGE_W - RIGHT - MARK, l.y + 4.0, MARK);
    let title = l.fit(B, 18.0, &d.title, WIDTH - MARK - 10.0);
    l.text(B, 18.0, ACCENT_DARK, LEFT, l.y - 18.0, &title);
    l.y -= 26.0;
    let sub = l.fit(R, 9.5, &d.subtitle, WIDTH - MARK - 10.0);
    l.text(R, 9.5, GREY, LEFT, l.y - 9.5, &sub);
    l.y -= 16.0;
    l.line(LEFT, l.y, PAGE_W - RIGHT, TEAL);
    l.y -= 12.0;

    for (i, b) in d.blocks.iter().enumerate() {
        // nagłówek nie zostaje sam na dole strony: razem z nim musi się zmieścić początek następnego bloku
        if matches!(b, Block::H2(_) | Block::H3(_)) {
            let next = match d.blocks.get(i + 1) {
                Some(Block::Hex { bytes, .. }) => bytes.len().div_ceil(16) as f32 * 9.4 + 8.0,
                Some(Block::Heat { .. }) | Some(Block::MemMap(_)) => 44.0,
                Some(Block::Table { .. }) | Some(Block::KeyVals(_)) => 40.0,
                _ => 20.0,
            };
            l.ensure(30.0 + next);
        }
        match b {
            Block::H1(t) => { l.heading(1, t); l.h1_pages.push(l.pages.len() + 1); }
            Block::Toc(items) => l.toc(items, toc_pages),
            Block::H2(t) => l.heading(2, t),
            Block::H3(t) => l.heading(3, t),
            Block::Para(t) => { l.paragraph(R, 9.5, INK, LEFT, WIDTH, t); l.y -= 6.0; }
            Block::Note(t) => l.note(t),
            Block::Bullets(i) => l.bullets(i),
            Block::Table { head, rows, widths } => l.table(head, rows, widths),
            Block::KeyVals(kv) => l.keyvals(kv),
            Block::MemMap(rows) => l.mem_map(rows),
            Block::Tree(nodes) => l.tree(nodes),
            Block::Hex { base, bytes } => l.hexdump(*base, bytes),
            Block::Heat { base, size, cells } => l.heat(*base, *size, cells),
            Block::Bars(items) => l.bars(items),
            Block::Matrix { cols, rows } => l.matrix(cols, rows),
            Block::Scatter(points) => l.scatter(points),
            Block::Flow { regions, process, endpoints } => l.flow(regions, process, endpoints),
        }
    }
    let last = std::mem::take(&mut l.cur);
    l.pages.push(last);

    // nagłówek i stopka, gdy znana jest liczba stron
    let n = l.pages.len();
    let pages = std::mem::take(&mut l.pages);
    let mut contents: Vec<String> = Vec::with_capacity(n);
    for (i, body) in pages.into_iter().enumerate() {
        l.cur = body;
        if i > 0 {
            let t = l.fit(R, 7.5, &d.title, WIDTH * 0.45);
            l.text(R, 7.5, GREY, LEFT, PAGE_H - 40.0, &t);
            let s = l.fit(R, 7.5, &d.subtitle, WIDTH * 0.5);
            let w = l.fonts[R].width(&s, 7.5);
            l.text(R, 7.5, GREY, PAGE_W - RIGHT - w, PAGE_H - 40.0, &s);
            l.line(LEFT, PAGE_H - 45.0, PAGE_W - RIGHT, BORDER);
        }
        l.line(LEFT, 40.0, PAGE_W - RIGHT, BORDER);
        let num = trf!("Strona {} z {n}", "Page {} of {n}", i + 1);
        let w = l.fonts[R].width(&num, 7.5);
        l.text(R, 7.5, GREY, PAGE_W - RIGHT - w, 29.0, &num);
        let f = l.fit(R, 7.5, &d.footer, WIDTH - w - 12.0);
        l.text(R, 7.5, GREY, LEFT, 29.0, &f);
        contents.push(std::mem::take(&mut l.cur));
    }

    // --- obiekty PDF. Numery: 1 katalog, 2 drzewo stron, 3..12 czcionki (po 5 na czcionkę), potem strony.
    let font_base = |k: usize| 3 + 5 * k;
    let page_base = 3 + 5 * l.fonts.len();
    let info_id = page_base + 2 * n;
    let mut objs: Vec<(usize, Vec<u8>)> = Vec::new();
    objs.push((1, format!("<< /Type /Catalog /Pages 2 0 R /Lang ({}) >>", tr!("pl-PL", "en-GB")).into_bytes()));
    let kids = (0..n).map(|i| format!("{} 0 R", page_base + 2 * i + 1)).collect::<Vec<_>>().join(" ");
    objs.push((2, format!("<< /Type /Pages /Count {n} /Kids [{kids}] >>").into_bytes()));

    for (k, f) in l.fonts.iter().enumerate() {
        let id = font_base(k);
        let sc = |v: f32| (v * 1000.0 / f.upem).round() as i32;
        let bb = f.face.global_bounding_box();
        objs.push((id, stream(&format!(" /Length1 {}", f.data.len()), f.data)));
        objs.push((id + 1, format!("<< /Type /FontDescriptor /FontName /{} /Flags 32 /FontBBox [{} {} {} {}] /ItalicAngle 0 /Ascent {} /Descent {} /CapHeight {} /StemV {} /FontFile2 {} 0 R >>",
            f.name, sc(bb.x_min as f32), sc(bb.y_min as f32), sc(bb.x_max as f32), sc(bb.y_max as f32), sc(f.face.ascender() as f32), sc(f.face.descender() as f32),
            sc(f.face.capital_height().unwrap_or(f.face.ascender()) as f32), if k == B { 140 } else { 80 }, id).into_bytes()));
        let w = f.used.keys().map(|g| format!("{g} [{}]", sc(f.advance(*g)))).collect::<Vec<_>>().join(" ");
        objs.push((id + 2, format!("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor {} 0 R /DW 600 /W [{w}] /CIDToGIDMap /Identity >>",
            f.name, id + 1).into_bytes()));
        objs.push((id + 3, stream("", &to_unicode(&f.used))));
        objs.push((id + 4, format!("<< /Type /Font /Subtype /Type0 /BaseFont /{} /Encoding /Identity-H /DescendantFonts [{} 0 R] /ToUnicode {} 0 R >>", f.name, id + 2, id + 3).into_bytes()));
    }
    for (i, c) in contents.iter().enumerate() {
        let cid = page_base + 2 * i;
        objs.push((cid, stream("", c.as_bytes())));
        objs.push((cid + 1, format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources << /Font << /F1 {} 0 R /F2 {} 0 R >> >> /Contents {cid} 0 R >>",
            font_base(R) + 4, font_base(B) + 4).into_bytes()));
    }
    objs.push((info_id, format!("<< /Title <{}> /Producer (nanshe {}) >>", utf16_hex(&d.title), env!("CARGO_PKG_VERSION")).into_bytes()));
    objs.sort_by_key(|o| o.0);

    let mut out: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objs.len());
    for (id, body) in &objs {
        offsets.push(out.len());
        out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in &offsets { out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()); }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R /Info {info_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    (out, l.h1_pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(paras: usize) -> Doc {
        let mut blocks = vec![Block::H1("Zażółć gęślą jaźń".into()), Block::Note("uwaga".into()),
            Block::KeyVals(vec![("Host".into(), "h".into())]),
            Block::Table { head: vec!["A".into(), "B".into()], rows: vec![vec!["1".into(), "x".repeat(400)]], widths: vec![1.0, 3.0] },
            Block::Bullets(vec!["jeden".into(), "dwa".into()])];
        for i in 0..paras { blocks.push(Block::Para(format!("akapit {i} {}", "słowo ".repeat(60)))); }
        Doc { title: "T".into(), subtitle: "s".into(), footer: "f".into(), blocks }
    }
    fn find(h: &[u8], n: &[u8]) -> usize { h.windows(n.len()).filter(|w| *w == n).count() }

    #[test]
    fn structure_is_valid_and_offsets_point_at_objects() {
        let p = render(&doc(3));
        assert!(p.starts_with(b"%PDF-1.7\n") && p.ends_with(b"%%EOF\n"));
        // startxref wskazuje tablicę, a każdy wpis tablicy wskazuje początek właściwego obiektu
        let tail = String::from_utf8_lossy(&p[p.len() - 40..]).to_string();
        let xref: usize = tail.split("startxref\n").nth(1).unwrap().lines().next().unwrap().parse().unwrap();
        assert!(p[xref..].starts_with(b"xref\n"));
        let table = String::from_utf8_lossy(&p[xref..]).to_string();
        let mut lines = table.lines().skip(1);
        let count: usize = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        lines.next();
        for id in 1..count {
            let off: usize = lines.next().unwrap()[..10].parse().unwrap();
            assert!(p[off..].starts_with(format!("{id} 0 obj\n").as_bytes()), "obiekt {id}");
        }
        assert_eq!(find(&p, b"/Subtype /Type0"), 2);
        assert_eq!(find(&p, b"/FontFile2"), 2);
    }

    #[test]
    fn long_document_breaks_into_pages_and_is_deterministic() {
        let one = render(&doc(1));
        let many = render(&doc(60));
        let pages = |p: &[u8]| find(p, b"/Type /Page /Parent");
        assert_eq!(pages(&one), 1);
        assert!(pages(&many) >= 4, "{}", pages(&many));
        assert_eq!(render(&doc(60)), many, "ten sam dokument, ten sam plik");
        // znak projektu jest rysowany raz, na pierwszej stronie
        let mut l = Layout { fonts: [Font::new(REGULAR, "r"), Font::new(BOLD, "b")], pages: vec![], cur: String::new(), y: 0.0, h1_pages: Vec::new() };
        l.symbol(10.0, 800.0, 40.0);
        assert!(l.cur.starts_with("q 0.1562 0 0 -0.1562 10.00 800.00 cm") && l.cur.contains("f*") && l.cur.ends_with("Q\n"));
    }

    /// Spis treści: numery stron rozdziałów rosną, a wpisanie ich do spisu nie przesuwa rozdziałów
    /// (drugi przebieg układu daje te same strony co pierwszy).
    #[test]
    fn toc_page_numbers_are_stable_between_passes() {
        let titles: Vec<String> = (1..=12).map(|i| format!("{i}. Rozdział {i}")).collect();
        let mut blocks = vec![Block::Para("wstęp".into()), Block::Toc(titles.clone())];
        for t in &titles { blocks.push(Block::H1(t.clone())); for _ in 0..5 { blocks.push(Block::Para("słowo ".repeat(120))); } }
        let d = Doc { title: "t".into(), subtitle: "s".into(), footer: "f".into(), blocks };
        let (first, pages) = render_pass(&d, &[]);
        assert_eq!(pages.len(), 12);
        assert!(pages.windows(2).all(|w| w[0] <= w[1]) && pages[0] >= 1 && *pages.last().unwrap() > 2, "{pages:?}");
        let (second, again) = render_pass(&d, &pages);
        assert_eq!(pages, again, "numery stron w spisie muszą odpowiadać stronom rozdziałów");
        assert_ne!(first, second, "drugi przebieg wpisuje numery stron");
        assert_eq!(render(&d), second);
        // dokument bez spisu: jeden przebieg, wynik jak dotąd
        let plain = Doc { blocks: d.blocks.iter().filter(|b| !matches!(b, Block::Toc(_))).cloned().collect(), ..d.clone() };
        assert_eq!(render(&plain), render_pass(&plain, &[]).0);
    }

    #[test]
    fn long_token_is_broken_and_unknown_glyph_replaced() {
        let l = Layout { fonts: [Font::new(REGULAR, "r"), Font::new(BOLD, "b")], pages: vec![], cur: String::new(), y: 0.0, h1_pages: Vec::new() };
        let lines = l.wrap(R, 8.0, &"a".repeat(300), 100.0);
        assert!(lines.len() > 5);
        assert!(lines.iter().all(|x| l.fonts[R].width(x, 8.0) <= 100.0));
        assert_eq!(l.fonts[R].glyph('漢').1, '?');
        assert_eq!(l.fonts[R].glyph('ł').1, 'ł');
        assert!(l.fit(R, 8.0, &"x".repeat(100), 50.0).ends_with("..."));
    }
}
