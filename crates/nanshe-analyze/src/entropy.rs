//! Entropia Shannona, bajtowa, skala 0-8, per strona 4 KB.
use nanshe_core::PAGE;

pub fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut hist = [0u32; 256];
    for &b in data { hist[b as usize] += 1; }
    let n = data.len() as f64;
    let mut e = 0.0f64;
    for &c in hist.iter() {
        if c != 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e as f32
}

pub struct PageStats {
    pub entropy: Vec<f32>,
    pub zero_pages: u64,
}

pub fn page_stats(data: &[u8]) -> PageStats {
    let mut entropy = Vec::with_capacity(data.len() / PAGE + 1);
    let mut zero_pages = 0;
    for page in data.chunks(PAGE) {
        if page.iter().all(|&b| b == 0) { zero_pages += 1; entropy.push(0.0); }
        else { entropy.push(shannon(page)); }
    }
    PageStats { entropy, zero_pages }
}

/// Komórki mapy ciepła: max entropii stron w komórce, w dziesiątych częściach bita.
pub fn heat_cells(page_entropy: &[f32], cell_bytes: u64) -> Vec<u8> {
    let per = ((cell_bytes as usize) / PAGE).max(1);
    page_entropy.chunks(per)
        .map(|c| (c.iter().cloned().fold(0.0f32, f32::max) * 10.0).round() as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7u8; 4096]), 0.0);
        let all: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-5);
        let two: Vec<u8> = (0..4096).map(|i| (i % 2) as u8).collect();
        assert!((shannon(&two) - 1.0).abs() < 1e-5);
    }
    #[test]
    fn pages_and_heat() {
        let mut d = vec![0u8; PAGE];
        d.extend((0..PAGE).map(|i| (i % 256) as u8));
        d.extend([1u8; 10]); // niepełna strona
        let s = page_stats(&d);
        assert_eq!(s.entropy.len(), 3);
        assert_eq!(s.zero_pages, 1);
        assert_eq!(heat_cells(&s.entropy, 8192), vec![80, 0]);
    }
}

/// Profil entropii regionu: najwyżej `cells` równych odcinków, maksimum stron w odcinku,
/// w dziesiątych częściach bita.
pub fn profile(page_entropy: &[f32], cells: usize) -> Vec<u8> {
    let per = page_entropy.len().div_ceil(cells.max(1)).max(1);
    page_entropy.chunks(per).map(|c| (c.iter().cloned().fold(0.0f32, f32::max) * 10.0).round() as u8).collect()
}

/// Ciągi tekstowe (ASCII i UTF-16LE) o długości 10-120 znaków, bez powtórzeń, w kolejności
/// występowania. Heurystyka: co najmniej 3/4 znaków to litery, cyfry, odstęp albo `./\\:-_`,
/// żeby dane losowe nie zalewały listy.
pub fn text_strings(data: &[u8], max: usize) -> Vec<String> {
    const MIN: usize = 10;
    const MAX_LEN: usize = 120;
    fn plausible(s: &str) -> bool {
        let good = s.chars().filter(|c| c.is_ascii_alphanumeric() || " ./\\:-_".contains(*c)).count();
        good * 4 >= s.len() * 3 && s.chars().any(|c| c.is_ascii_alphabetic())
    }
    let mut out: Vec<String> = Vec::new();
    let push = |s: &str, out: &mut Vec<String>| {
        let t: String = s.chars().take(MAX_LEN).collect();
        if t.len() >= MIN && plausible(&t) && !out.contains(&t) { out.push(t); }
    };
    let printable = |b: u8| (0x20..0x7f).contains(&b);
    let mut cur = String::new();
    for &b in data {
        if out.len() >= max { return out; }
        if printable(b) { cur.push(b as char); } else { if cur.len() >= MIN { push(&cur, &mut out); } cur.clear(); }
    }
    if cur.len() >= MIN { push(&cur, &mut out); }
    // UTF-16LE: znak drukowalny, po nim bajt zerowy
    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < data.len() && out.len() < max {
        if printable(data[i]) && data[i + 1] == 0 { cur.push(data[i] as char); i += 2; }
        else { if cur.len() >= MIN { push(&cur, &mut out); } cur.clear(); i += 1; }
    }
    if cur.len() >= MIN && out.len() < max { push(&cur, &mut out); }
    out
}

#[cfg(test)]
mod more_tests {
    use super::*;
    #[test]
    fn profile_downsamples_with_max() {
        assert_eq!(profile(&[1.0, 7.96, 0.0, 2.0], 2), vec![80, 20]);
        assert_eq!(profile(&[3.0; 5], 64).len(), 5);
        assert_eq!(profile(&vec![1.0; 1000], 64).len(), 63);
        assert!(profile(&[], 64).is_empty());
    }
    #[test]
    fn strings_found_in_ascii_and_utf16_and_noise_rejected() {
        let mut d = b"\x00\x01/usr/lib/libssl.so.3\x00short\x00\x01".to_vec();
        d.extend("C:\\Windows\\evil.dll".encode_utf16().flat_map(|u| u.to_le_bytes()));
        d.extend_from_slice(b"\x00\x00!@#$%^&*()!@#$%^\x00/usr/lib/libssl.so.3\x00");
        assert_eq!(text_strings(&d, 40), vec!["/usr/lib/libssl.so.3".to_string(), "C:\\Windows\\evil.dll".to_string()]);
        // limit liczby
        let many: Vec<u8> = (0..100).flat_map(|i| format!("string-number-{i:03}\0").into_bytes()).collect();
        assert_eq!(text_strings(&many, 7).len(), 7);
    }
}
