//! Porównanie kodu obrazu PE w pamięci z plikiem na dysku.
//!
//! System ładuje plik sekcjami pod wybrany adres i poprawia w kodzie adresy bezwzględne
//! (relokacje). Żeby porównanie nie zgłaszało tych poprawek jako zmian, funkcja odtwarza treść,
//! jaką system powinien był umieścić w pamięci: bajty sekcji z pliku z naniesionymi relokacjami
//! dla faktycznego adresu załadowania. Różnica względem tak odtworzonej treści oznacza, że kod
//! zmieniono po załadowaniu (albo że plik na dysku nie jest tym, z którego powstał obraz).
//!
//! Plik pochodzi z badanej stacji, więc jest daną niezaufaną: każde pole jest sprawdzane względem
//! długości pliku. Czysta logika, bez wywołań systemowych, testowana na każdej platformie.

fn u16le(b: &[u8], o: usize) -> Option<u16> { b.get(o..o.checked_add(2)?).map(|x| u16::from_le_bytes([x[0], x[1]])) }
fn u32le(b: &[u8], o: usize) -> Option<u32> { b.get(o..o.checked_add(4)?).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])) }
fn u64le(b: &[u8], o: usize) -> Option<u64> { b.get(o..o.checked_add(8)?).map(|x| u64::from_le_bytes(x.try_into().expect("8 bajtów"))) }

#[derive(Clone, Copy, Debug)]
struct Sec { va: u32, raw: u32, raw_size: u32 }

/// Nagłówki pliku PE potrzebne do odtworzenia treści sekcji w pamięci.
pub struct Pe<'a> {
    file: &'a [u8],
    /// Adres, pod który plik został zlinkowany; relokacje poprawiają kod o różnicę względem niego.
    pub image_base: u64,
    sections: Vec<Sec>,
    /// Relokacje do naniesienia: (adres względny celu, szerokość), posortowane.
    fixups: Vec<(u32, u8)>,
    /// Tablica relokacji została odczytana w całości; bez tego porównanie po załadowaniu pod inny adres nie jest wiarygodne.
    pub relocs_complete: bool,
}

impl<'a> Pe<'a> {
    pub fn parse(file: &'a [u8]) -> Option<Pe<'a>> {
        if file.get(..2)? != b"MZ" { return None; }
        let pe = u32le(file, 0x3c)? as usize;
        if file.get(pe..pe.checked_add(4)?)? != b"PE\0\0" { return None; }
        let nsec = u16le(file, pe + 6)? as usize;
        let opt_size = u16le(file, pe + 20)? as usize;
        let opt = pe + 24;
        let (image_base, dirs) = match u16le(file, opt)? {
            0x20b => (u64le(file, opt + 24)?, opt + 112),
            0x10b => (u32le(file, opt + 28)? as u64, opt + 96),
            _ => return None,
        };
        // katalog nr 5: tablica relokacji (może nie istnieć)
        let reloc = if dirs + 6 * 8 <= opt + opt_size { (u32le(file, dirs + 5 * 8)?, u32le(file, dirs + 5 * 8 + 4)?) } else { (0, 0) };
        if nsec == 0 || nsec > 96 { return None; }
        let table = opt.checked_add(opt_size)?;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let s = table.checked_add(i * 40)?;
            sections.push(Sec { va: u32le(file, s + 12)?, raw_size: u32le(file, s + 16)?, raw: u32le(file, s + 20)? });
        }
        let (fixups, relocs_complete) = read_fixups(file, &sections, reloc);
        Some(Pe { file, image_base, sections, fixups, relocs_complete })
    }

    /// Bajt pliku odpowiadający adresowi względnemu `rva`; None, gdy w pliku go nie ma
    /// (część sekcji dopełniana zerami albo adres poza sekcjami).
    fn file_off(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|s| {
            let within = rva.checked_sub(s.va)?;
            (within < s.raw_size).then(|| (s.raw as usize).checked_add(within as usize)).flatten()
        }).filter(|o| *o < self.file.len())
    }

    fn byte(&self, rva: u32) -> u8 { self.file_off(rva).map(|o| self.file[o]).unwrap_or(0) }

    /// Treść, jaką system powinien umieścić w pamięci w zakresie [rva, rva+len) po załadowaniu obrazu pod `base`.
    pub fn expected(&self, rva: u32, len: usize, base: u64) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for s in &self.sections {
            // część wspólna zakresu i surowych danych sekcji
            let (a, b) = (rva.max(s.va) as u64, (rva as u64 + len as u64).min(s.va as u64 + s.raw_size as u64));
            if a >= b { continue; }
            let src = s.raw as u64 + (a - s.va as u64);
            let n = (b - a).min((self.file.len() as u64).saturating_sub(src)) as usize;
            let dst = (a - rva as u64) as usize;
            if n > 0 { out[dst..dst + n].copy_from_slice(&self.file[src as usize..src as usize + n]); }
        }
        let delta = base.wrapping_sub(self.image_base);
        if delta == 0 { return out; }
        // poprawki, których cel (do 8 bajtów) zachodzi na porównywany zakres; tablica jest posortowana
        let (lo, hi) = (rva as u64, rva as u64 + len as u64);
        let from = self.fixups.partition_point(|f| (f.0 as u64) + 8 <= lo);
        for &(target, width) in self.fixups[from..].iter().take_while(|f| (f.0 as u64) < hi) {
            let (target, width) = (target as u64, width as u64);
            if target + width <= lo || target > u32::MAX as u64 - 8 { continue; }
            let mut v = [0u8; 8];
            for k in 0..width { v[k as usize] = self.byte((target + k) as u32); }
            let fixed = if width == 8 { u64::from_le_bytes(v).wrapping_add(delta).to_le_bytes() } else {
                let mut w = [0u8; 8]; w[..4].copy_from_slice(&u32::from_le_bytes([v[0], v[1], v[2], v[3]]).wrapping_add(delta as u32).to_le_bytes()); w };
            for k in 0..width { let a = target + k; if a >= lo && a < hi { out[(a - lo) as usize] = fixed[k as usize]; } }
        }
        out
    }
}

/// Najwięcej wpisów tablicy relokacji, jakie są przetwarzane. Plik deklarujący więcej jest uznawany
/// za nieporównywalny, żeby spreparowany plik nie mógł zająć skanera na długo.
pub const MAX_FIXUPS: usize = 4 << 20;

/// Tablica relokacji odczytana raz: (adres względny celu, szerokość 4 albo 8 bajtów), posortowana.
/// Drugi element: czy tablica została odczytana w całości (bez przekroczenia limitu i bez uszkodzeń).
/// Rozmiar tablicy jest przycinany do bajtów faktycznie obecnych w pliku.
fn read_fixups(file: &[u8], sections: &[Sec], reloc: (u32, u32)) -> (Vec<(u32, u8)>, bool) {
    if reloc.1 < 8 { return (Vec::new(), true); }
    let off = sections.iter().find_map(|s| { let w = reloc.0.checked_sub(s.va)?; (w < s.raw_size).then(|| s.raw as usize + w as usize) });
    let Some(off) = off.filter(|o| *o < file.len()) else { return (Vec::new(), false) };
    let table = &file[off..off + (reloc.1 as usize).min(file.len() - off)];
    let mut out: Vec<(u32, u8)> = Vec::new();
    let mut at = 0usize;
    while at + 8 <= table.len() {
        let (page, size) = (u32le(table, at).unwrap_or(0), u32le(table, at + 4).unwrap_or(0) as usize);
        if size == 0 { break; }              // koniec tablicy (dopełnienie zerami)
        if size < 8 || size % 2 != 0 || at + size > table.len() { return (out, false); }
        for e in table[at + 8..at + size].chunks_exact(2) {
            let e = u16::from_le_bytes([e[0], e[1]]);
            let width = match e >> 12 { 10 => 8u8, 3 => 4, 0 => continue, _ => return (out, false) };
            let Some(target) = page.checked_add((e & 0xfff) as u32) else { return (out, false) };
            if out.len() >= MAX_FIXUPS { return (out, false); }
            out.push((target, width));
        }
        at += size;
    }
    out.sort_unstable();
    (out, true)
}

/// Czy nagłówek obrazu w pamięci (pierwsza strona) i nagłówek pliku opisują ten sam obraz: położenie
/// nagłówka PE, znacznik czasu, liczba sekcji, rozmiar obrazu i suma kontrolna. Adres załadowania
/// w nagłówku system zmienia, więc nie jest porównywany. Różnica oznacza inny plik niż załadowany.
pub fn same_image_header(mem: &[u8], file: &[u8]) -> bool {
    let fields = |b: &[u8]| -> Option<(u32, u16, u32, u16, u32, u32)> {
        if b.get(..2)? != b"MZ" { return None; }
        let pe = u32le(b, 0x3c)? as usize;
        if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" { return None; }
        let opt = pe + 24;
        let magic = u16le(b, opt)?;
        if magic != 0x20b && magic != 0x10b { return None; }
        // SizeOfImage i CheckSum mają te same przesunięcia w obu odmianach nagłówka opcjonalnego
        Some((pe as u32, u16le(b, pe + 6)?, u32le(b, pe + 8)?, magic, u32le(b, opt + 56)?, u32le(b, opt + 64)?))
    };
    match (fields(mem), fields(file)) { (Some(a), Some(b)) => a == b, _ => false }
}

/// Liczba bajtów pamięci różnych od treści odtworzonej z pliku i adres względny pierwszego z nich.
/// `rva`: adres początku `mem` względem początku obrazu; `base`: faktyczny adres załadowania obrazu.
/// None, gdy plik nie jest poprawnym obrazem PE (wtedy porównania nie da się wykonać).
pub fn diff(file: &[u8], base: u64, rva: u32, mem: &[u8]) -> Option<(u64, u32)> {
    let pe = Pe::parse(file)?;
    if rva as u64 + mem.len() as u64 > u32::MAX as u64 { return None; }
    if !pe.relocs_complete && base != pe.image_base { return None; }
    let want = pe.expected(rva, mem.len(), base);
    let mut n = 0u64;
    let mut first = None;
    for (i, (a, b)) in mem.iter().zip(want.iter()).enumerate() {
        if a != b { n += 1; if first.is_none() { first = Some(rva + i as u32); } }
    }
    Some((n, first.unwrap_or(rva)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_4000_0000;

    /// Minimalny plik PE32+: sekcja kodu pod adresem względnym 0x1000 (0x400 bajtów w pliku, 0x1000 w pamięci)
    /// i tablica relokacji z wpisami 64-bitowymi pod podanymi przesunięciami w kodzie.
    fn pe_file(code: &[u8], relocs: &[u16]) -> Vec<u8> {
        let mut f = vec![0u8; 0x400];
        f[..2].copy_from_slice(b"MZ"); f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80; f[pe..pe + 4].copy_from_slice(b"PE\0\0");
        f[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes()); f[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
        f[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let opt = pe + 24;
        f[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); f[opt + 24..opt + 32].copy_from_slice(&BASE.to_le_bytes());
        let mut rel = Vec::new();
        rel.extend(0x1000u32.to_le_bytes()); rel.extend(((8 + relocs.len() * 2) as u32).to_le_bytes());
        for r in relocs { rel.extend(((10u16 << 12) | r).to_le_bytes()); }
        f[opt + 112 + 40..opt + 112 + 44].copy_from_slice(&0x2000u32.to_le_bytes()); f[opt + 112 + 44..opt + 112 + 48].copy_from_slice(&(rel.len() as u32).to_le_bytes());
        let sec = opt + 240;
        let mut s = |i: usize, name: &[u8], vsize: u32, va: u32, raw_size: u32, raw: u32| {
            let o = sec + i * 40; f[o..o + name.len()].copy_from_slice(name);
            f[o + 8..o + 12].copy_from_slice(&vsize.to_le_bytes()); f[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            f[o + 16..o + 20].copy_from_slice(&raw_size.to_le_bytes()); f[o + 20..o + 24].copy_from_slice(&raw.to_le_bytes());
        };
        s(0, b".text", 0x1000, 0x1000, 0x400, 0x400);
        s(1, b".reloc", 0x1000, 0x2000, 0x200, 0x800);
        let mut text = code.to_vec(); text.resize(0x400, 0xcc);
        f.extend(text);
        rel.resize(0x200, 0);
        f.extend(rel);
        f
    }

    fn code() -> Vec<u8> {
        let mut c: Vec<u8> = (0..0x300u32).map(|i| (i * 7 % 251) as u8).collect();
        // dwa adresy bezwzględne w kodzie (cele relokacji), zapisane dla adresu z nagłówka
        c[0x10..0x18].copy_from_slice(&(BASE + 0x1234).to_le_bytes());
        c[0x200..0x208].copy_from_slice(&(BASE + 0x1100).to_le_bytes());
        c
    }

    /// Treść sekcji kodu, jaką system umieści w pamięci po załadowaniu obrazu pod `base`.
    fn loaded(base: u64) -> Vec<u8> {
        let mut m = code(); m.resize(0x400, 0xcc); m.resize(0x1000, 0);
        m[0x10..0x18].copy_from_slice(&(base + 0x1234).to_le_bytes());
        m[0x200..0x208].copy_from_slice(&(base + 0x1100).to_le_bytes());
        m
    }

    #[test]
    fn relocated_image_matches_the_file_and_a_patch_is_counted() {
        let file = pe_file(&code(), &[0x10, 0x200]);
        for base in [BASE, 0x7ff6_1234_0000, 0x1_0000] {
            let mem = loaded(base);
            assert_eq!(diff(&file, base, 0x1000, &mem), Some((0, 0x1000)), "{base:#x}: obraz po relokacji nie różni się od pliku");
            // łatka: pięć bajtów w środku kodu
            let mut patched = mem.clone();
            for b in &mut patched[0x80..0x85] { *b ^= 0xff; }
            assert_eq!(diff(&file, base, 0x1000, &patched), Some((5, 0x1080)), "{base:#x}");
            // porównanie fragmentu zaczynającego się w środku sekcji, także gdy relokacja leży na jego granicy
            assert_eq!(diff(&file, base, 0x1000 + 0x14, &mem[0x14..0x300]), Some((0, 0x1014)), "{base:#x}");
            assert_eq!(diff(&file, base, 0x1000 + 0x80, &patched[0x80..0x100]), Some((5, 0x1080)));
        }
        // kontrola: bez naniesienia relokacji (porównanie z adresem z nagłówka) obraz załadowany gdzie indziej różni się
        let (n, first) = diff(&file, BASE, 0x1000, &loaded(0x7ff6_1234_0000)).unwrap();
        assert!(n >= 8 && (0x1010..0x1018).contains(&first), "{n} {first:#x}");
        // kontrola: plik bez tablicy relokacji nie tłumaczy różnic po załadowaniu pod inny adres
        let plain = pe_file(&code(), &[]);
        assert!(diff(&plain, 0x7ff6_1234_0000, 0x1000, &loaded(0x7ff6_1234_0000)).unwrap().0 >= 8);
        assert_eq!(diff(&plain, BASE, 0x1000, &loaded(BASE)), Some((0, 0x1000)));
    }

    /// Ziarno dla fuzzera: poprawny plik PE z relokacjami, poprzedzony nagłówkiem celu (adres bazowy, adres
    /// względny, punkt podziału na plik i pamięć). Zapisywane tylko, gdy ustawiono NANSHE_FUZZ_SEEDS.
    #[test]
    fn fuzz_seeds() {
        let Some(dir) = std::env::var_os("NANSHE_FUZZ_SEEDS") else { return };
        let dir = std::path::Path::new(&dir).join("pediff");
        std::fs::create_dir_all(&dir).unwrap();
        let file = pe_file(&[0x90; 0x400], &[0x10, 0x20]);
        let mut seed = Vec::new();
        seed.extend(0x7ff0_0000_0000u64.to_le_bytes()); seed.extend(0x1000u32.to_le_bytes()); seed.extend((file.len() as u32).to_le_bytes());
        seed.extend(&file); seed.extend([0x90u8; 0x400]);
        std::fs::write(dir.join("pe"), seed).unwrap();
    }

    #[test]
    fn image_header_in_memory_must_match_the_file() {
        let file = pe_file(&code(), &[0x10, 0x200]);
        // w pamięci system zmienia adres załadowania w nagłówku; reszta pól zostaje
        let mut mem = file[..0x400].to_vec();
        mem[0x80 + 24 + 24..0x80 + 24 + 32].copy_from_slice(&0x7ff6_1234_0000u64.to_le_bytes());
        assert!(same_image_header(&mem, &file));
        // inny znacznik czasu, inna liczba sekcji, inny rozmiar obrazu: to nie ten plik
        for (off, n) in [(0x80 + 8, 4usize), (0x80 + 6, 1), (0x80 + 24 + 56, 4), (0x80 + 24 + 64, 4)] {
            let mut other = file.clone(); for b in &mut other[off..off + n] { *b ^= 0x5a; }
            assert!(!same_image_header(&mem, &other), "pole pod {off:#x}");
        }
        // wymazany nagłówek w pamięci albo plik niebędący obrazem: brak potwierdzenia
        assert!(!same_image_header(&vec![0u8; 0x400], &file) && !same_image_header(&mem, b"MZ") && !same_image_header(&mem, &[]));
    }

    #[test]
    fn garbage_and_truncated_files_do_not_panic() {
        let file = pe_file(&code(), &[0x10, 0x200]);
        let mem = loaded(BASE);
        assert_eq!(diff(b"MZ", BASE, 0x1000, &mem), None);
        assert_eq!(diff(&[0u8; 4096], BASE, 0x1000, &mem), None);
        for cut in (0..file.len()).step_by(13) { let _ = diff(&file[..cut], 0x7ff6_0000_0000, 0x1000, &mem); }
        // każdy bajt nagłówków ustawiony na 0xff: wynik dowolny, ale bez paniki i bez czytania poza plik
        for i in 0x3c..0x400 { let mut bad = file.clone(); bad[i] = 0xff; let _ = diff(&bad, 0x7ff6_0000_0000, 0x1000, &mem); let _ = diff(&bad, 0x7ff6_0000_0000, 0xffff_f000, &mem); }
        // blok relokacji o rozmiarze zerowym kończy tablicę; blok wychodzący poza tablicę albo o nieznanym typie
        // wpisu oznacza tablicę niewiarygodną: po załadowaniu pod inny adres porównania nie ma, pod adresem z nagłówka jest
        let mut zero = file.clone(); zero[0x804..0x808].copy_from_slice(&0u32.to_le_bytes());
        assert!(diff(&zero, 0x7ff6_0000_0000, 0x1000, &mem).is_some());
        let mut over = file.clone(); over[0x804..0x808].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
        assert_eq!(diff(&over, 0x7ff6_0000_0000, 0x1000, &mem), None);
        assert_eq!(diff(&over, BASE, 0x1000, &mem), Some((0, 0x1000)));
        let mut kind = file.clone(); kind[0x809] = 0x50; // typ wpisu 5: nieobsługiwany
        assert_eq!(diff(&kind, 0x7ff6_0000_0000, 0x1000, &mem), None);
        // katalog relokacji deklarujący 4 GiB: rozmiar jest przycinany do pliku, praca jest ograniczona
        let mut huge = file.clone(); huge[0x80 + 24 + 112 + 44..0x80 + 24 + 112 + 48].copy_from_slice(&u32::MAX.to_le_bytes());
        let t = std::time::Instant::now();
        for _ in 0..200 { let _ = diff(&huge, 0x7ff6_0000_0000, 0x1000, &mem); }
        assert!(t.elapsed().as_secs() < 5, "tablica relokacji o zadeklarowanym ogromnym rozmiarze nie może zająć skanera");
    }
}
