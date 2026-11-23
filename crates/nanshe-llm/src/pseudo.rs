//! Pseudonimizacja ładunku wysyłanego do chmury (punkt 15.3 założeń): nazwa hosta,
//! nazwy użytkowników w ścieżkach domowych i adresy IPv4 są zastępowane stabilnymi
//! etykietami. Mapa zostaje lokalnie i jest odwracana w odpowiedzi modelu.
use serde_json::Value;

#[derive(Clone, Default)]
pub struct Pseudo {
    host: Option<String>,
    /// (wartość prawdziwa, etykieta)
    map: Vec<(String, String)>,
}

/// Przedrostki, po których stoi nazwa użytkownika (dopasowanie bez względu na wielkość liter;
/// "/Users/" obejmuje też zapis C:/Users/).
const HOME_PREFIXES: &[&str] = &["/home/", "/Users/", "\\Users\\", "\\Documents and Settings\\", "/Documents and Settings/",
    "USERNAME=", "LOGNAME=", "USER="];
/// Katalogi wspólne, które nie identyfikują osoby.
const NOT_USERS: &[&str] = &["Public", "Shared", "Default", "All Users"];

impl Pseudo {
    pub fn new(host: &str) -> Self {
        Pseudo { host: Some(host.to_string()).filter(|h| h.len() >= 3), map: Vec::new() }
    }
    pub fn replaced(&self) -> usize { self.map.len() }

    fn label(&mut self, real: &str, kind: &str) -> String {
        if let Some((_, l)) = self.map.iter().find(|(r, _)| r == real) { return l.clone(); }
        let n = self.map.iter().filter(|(_, l)| l.starts_with(kind)).count() + 1;
        let l = format!("{kind}_{n}");
        self.map.push((real.to_string(), l.clone()));
        l
    }

    /// Kopia ładunku z podmienionymi wartościami we wszystkich ciągach (klucze bez zmian).
    pub fn apply(&mut self, v: &Value) -> Value {
        match v {
            Value::String(s) => Value::String(self.apply_str(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.apply(x)).collect()),
            Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), self.apply(x))).collect()),
            x => x.clone(),
        }
    }

    pub fn apply_str(&mut self, s: &str) -> String {
        let mut out = s.to_string();
        // Host: pełna nazwa i jej krótka postać (przed pierwszą kropką), bez względu na wielkość liter.
        if let Some(h) = self.host.clone() {
            let short = h.split('.').next().unwrap_or("").to_string();
            for name in [h.clone(), short] {
                if name.len() < 3 || (name != h && name == h.split('.').next().unwrap_or("") && !h.contains('.')) { continue; }
                let mut from = 0;
                while let Some(i) = find_ci(&out, &name, from) {
                    let end = i + name.len();
                    if !host_match_ok(&out, i, end) { from = end; continue; }
                    let l = self.label(&name, "HOST");
                    out.replace_range(i..end, &l);
                    from = i + l.len();
                }
            }
        }
        // Ścieżki domowe: Windows nie rozróżnia wielkości liter (c:\users\Anna).
        for pre in HOME_PREFIXES {
            let mut from = 0;
            while let Some(i) = find_ci(&out, pre, from) {
                let start = i + pre.len();
                // segment ścieżki kończy się separatorem; wartość zmiennej także odstępem lub średnikiem
                let env = pre.ends_with('=');
                let end = out[start..].find(|c: char| matches!(c, '/' | '\\') || (env && (c == ';' || c == '&' || c.is_whitespace()))).map(|e| start + e).unwrap_or(out.len());
                let user = out[start..end].to_string();
                if user.is_empty() || NOT_USERS.iter().any(|n| n.eq_ignore_ascii_case(&user)) || self.map.iter().any(|(_, l)| *l == user) { from = end.max(start); continue; }
                let l = self.label(&user, "USER");
                out.replace_range(start..end, &l);
                from = start + l.len();
            }
        }
        // Wartości już poznane (np. użytkownik z wcześniejszej ścieżki) są podmieniane także poza ścieżką,
        // od najdłuższych. Gdy znana wartość jest częścią dłuższego tokenu (jkowalski_backup, jkowalski123),
        // maskowany jest cały token pod własną etykietą: wątpliwość rozstrzygamy na rzecz ukrycia.
        // Wyjątek: krótka wartość (do 5 znaków) otoczona literami, np. "ann" w "scanner", bo inaczej
        // znikałyby zwykłe słowa i nazwy funkcji potrzebne w analizie.
        let mut known = self.map.clone();
        known.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (real, label) in known {
            if real.len() < 3 { continue; }
            let word = |c: char| c.is_alphanumeric() || c == '_';
            let mut from = 0;
            while let Some(i) = find_ci(&out, &real, from) {
                let end = i + real.len();
                let (before, after) = (out[..i].chars().next_back(), out[end..].chars().next());
                if !before.map(word).unwrap_or(false) && !after.map(word).unwrap_or(false) {
                    out.replace_range(i..end, &label);
                    from = i + label.len();
                    continue;
                }
                // granice całego tokenu wokół dopasowania
                let ts = out[..i].char_indices().rev().take_while(|(_, c)| word(*c)).last().map(|(k, _)| k).unwrap_or(i);
                let te = end + out[end..].char_indices().find(|(_, c)| !word(*c)).map(|(k, _)| k).unwrap_or(out.len() - end);
                let token = out[ts..te].to_string();
                let in_letters = before.map(|c| c.is_alphabetic()).unwrap_or(false) || after.map(|c| c.is_alphabetic()).unwrap_or(false);
                // token będący etykietą (USER_2) albo zwykłe słowo zawierające krótką wartość: bez zmian
                if self.map.iter().any(|(_, l)| *l == token) || (real.len() <= 5 && in_letters) { from = end; continue; }
                let l = self.label(&token, "USER");
                out.replace_range(ts..te, &l);
                from = ts + l.len();
            }
        }
        let out = self.ipv4(&out);
        self.ipv6(&out)
    }

    /// Adresy IPv6: ciąg cyfr szesnastkowych i dwukropków (opcjonalnie w nawiasach kwadratowych),
    /// który parsuje się jako adres i ma co najmniej dwa dwukropki. Znaczniki czasu (12:34:56),
    /// adresy MAC i nazwy typu `std::string` nie są adresami i zostają.
    fn ipv6(&mut self, s: &str) -> String {
        let b = s.as_bytes();
        let part = |c: u8| c.is_ascii_hexdigit() || c == b':';
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            let boundary = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b':' || b[i - 1] == b'.' || b[i - 1] == b'_');
            if part(b[i]) && boundary {
                let mut j = i;
                while j < b.len() && part(b[j]) { j += 1; }
                let run = &s[i..j];
                let after_ok = j == b.len() || !(b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'.');
                let looks = run.matches(':').count() >= 2 && run.len() >= 3 && run.chars().any(|c| c.is_ascii_hexdigit() || run == "::");
                if after_ok && looks && run.parse::<std::net::Ipv6Addr>().is_ok() && (run.contains("::") || run.matches(':').count() == 7) {
                    out.push_str(&self.label(run, "IP"));
                } else { out.push_str(run); }
                i = j;
            } else {
                let ch = s[i..].chars().next().expect("znak");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out
    }

    fn ipv4(&mut self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_digit() && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.')) {
                let mut j = i;
                while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') { j += 1; }
                while b[j - 1] == b'.' { j -= 1; } // kropka kończąca zdanie nie należy do adresu
                let run = &s[i..j];
                let boundary = j == b.len() || !b[j].is_ascii_alphanumeric();
                let parts: Vec<&str> = run.split('.').collect();
                if boundary && parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)) {
                    out.push_str(&self.label(run, "IP"));
                } else { out.push_str(run); }
                i = j;
            } else {
                // kopiujemy cały znak UTF-8, nie pojedynczy bajt
                let ch = s[i..].chars().next().expect("znak");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out
    }

    /// Przywraca prawdziwe wartości w odpowiedzi modelu (tekst JSON). Wartość, która wymagałaby
    /// ucieczki w JSON, zostaje pod etykietą: odpowiedź modelu nie może zostać uszkodzona.
    pub fn reverse(&self, text: &str) -> String {
        let mut out = text.to_string();
        // dłuższe etykiety najpierw, żeby USER_1 nie nadpisał początku USER_10
        let mut m: Vec<&(String, String)> = self.map.iter().collect();
        m.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (real, label) in m {
            if real.chars().all(|c| !c.is_control() && c != '"' && c != '\\') { out = out.replace(label, real); }
        }
        out
    }
}

/// Czy dopasowanie nazwy hosta w `s[i..end]` wolno podmienić. Nazwa musi stać jako całe słowo
/// (inaczej host `win` psułby `Windows`), a nie jako zwykły składnik ścieżki (`/dev/shm` przy hoście
/// `dev`, `C:\\win\\x`). Wyjątki, w których składnik ścieżki jest nazwą hosta: `//host/` (adres URL)
/// i `\\\\host\\` (ścieżka UNC).
fn host_match_ok(s: &str, i: usize, end: usize) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    let before = s[..i].chars().next_back();
    let after = s[end..].chars().next();
    if before.map(word).unwrap_or(false) || after.map(word).unwrap_or(false) { return false; }
    let prev2 = { let mut it = s[..i].chars().rev(); it.next(); it.next() };
    match (before, after) {
        (Some('/'), Some('/')) | (Some('/'), None) => prev2 == Some('/'),
        (Some('\\'), Some('\\')) | (Some('\\'), None) => prev2 == Some('\\'),
        _ => true,
    }
}

/// Pierwsze wystąpienie `needle` w `hay` od pozycji `from`, bez względu na wielkość liter ASCII.
/// Zwrócona pozycja jest granicą znaku: dopasowanie zaczyna się i kończy bajtami wzorca.
fn find_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    if n.is_empty() || from > h.len() || h.len() - from < n.len() { return None; }
    (from..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n) && hay.is_char_boundary(i) && hay.is_char_boundary(i + n.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn replaces_host_users_and_ips_and_reverses() {
        let mut p = Pseudo::new("ws-finanse-07");
        let v = json!({ "backing": "/home/jkowalski/.cache/x.so", "win": "C:\\Users\\anna.nowak\\AppData\\a.dll",
            "strings": ["connect 10.20.30.40:443", "ws-finanse-07.corp", "/home/jkowalski/b", "/Users/Shared/x"], "score": 60, "id": "5:7f00:RWX" });
        let o = p.apply(&v);
        let s = o.to_string();
        for leak in ["jkowalski", "anna.nowak", "10.20.30.40", "ws-finanse-07"] { assert!(!s.contains(leak), "wyciek: {leak} w {s}"); }
        assert_eq!(o["backing"], "/home/USER_1/.cache/x.so");
        assert_eq!(o["win"], "C:\\Users\\USER_2\\AppData\\a.dll");
        assert_eq!(o["strings"][0], "connect IP_1:443");
        assert_eq!(o["strings"][2], "/home/USER_1/b", "ta sama wartość, ta sama etykieta");
        assert_eq!(o["strings"][3], "/Users/Shared/x");
        assert_eq!((o["score"].as_u64(), o["id"].as_str()), (Some(60), Some("5:7f00:RWX")));
        assert_eq!(p.replaced(), 4);
        assert_eq!(p.reverse("{\"summary\":\"USER_1 na HOST_1 łączy się z IP_1\"}"), "{\"summary\":\"jkowalski na ws-finanse-07 łączy się z 10.20.30.40\"}");
    }

    #[test]
    fn not_an_ip_is_left_alone() {
        let mut p = Pseudo::new("h");
        for s in ["wersja 1.2.3", "1.2.3.4.5", "999.1.1.1", "a1.2.3.4", "1.2.3.4x", "zażółć 12.5", "0x7f00.1"] {
            assert_eq!(p.apply_str(s), s);
        }
        assert_eq!(p.apply_str("(192.168.7.50)"), "(IP_1)");
        assert_eq!(p.apply_str("host 192.168.7.50."), "host IP_1.");
        assert_eq!(p.replaced(), 1);
    }

    #[test]
    fn reverse_never_breaks_json() {
        let mut p = Pseudo::new("host");
        assert_eq!(p.apply_str("/home/a\"b/x"), "/home/USER_1/x");
        assert_eq!(p.reverse("{\"s\":\"USER_1\"}"), "{\"s\":\"USER_1\"}");
        // dziesiąta etykieta nie może zostać rozcięta przez pierwszą
        let mut p = Pseudo::new("host");
        for i in 0..10 { p.apply_str(&format!("/home/u{i}/x")); }
        assert_eq!(p.reverse("USER_10 USER_1"), "u9 u0");
    }

    #[test]
    fn case_and_short_host_do_not_bypass() {
        let mut p = Pseudo::new("DESKTOP-AB12CD3.corp.example");
        for (i, leak) in [("c:\\users\\Anna.Nowak\\x.dll", "Anna.Nowak"), ("C:\\USERS\\jan\\y", "jan"), ("/HOME/ola/z", "ola"),
            ("host desktop-ab12cd3.CORP.example up", "desktop-ab12cd3"), ("\\\\DESKTOP-AB12CD3\\share", "DESKTOP-AB12CD3"), ("Desktop-Ab12cd3", "Desktop-Ab12cd3")] {
            let o = p.apply_str(i);
            assert!(!o.to_lowercase().contains(&leak.to_lowercase()), "wyciek {leak}: {o}");
        }
        assert_eq!(p.apply_str("C:\\Users\\PUBLIC\\a"), "C:\\Users\\PUBLIC\\a", "katalog wspólny zostaje");
        // kontrola: tekst bez hosta i ścieżek domowych nie jest ruszany, także z nie-ASCII
        assert_eq!(p.apply_str("zażółć /usr/lib/x.so desktop"), "zażółć /usr/lib/x.so desktop");
        // zapis z ukośnikami, zmienne środowiskowe i użytkownik stojący sam po wcześniejszym poznaniu
        let mut r = Pseudo::new("h");
        assert_eq!(r.apply_str("C:/Users/marek/a"), "C:/Users/USER_1/a");
        assert_eq!(r.apply_str("USERNAME=kasia;PATH=x"), "USERNAME=USER_2;PATH=x");
        assert_eq!(r.apply_str("login marek ok, Kasia też"), "login USER_1 ok, USER_2 też");
        // host bez kropki: jedna etykieta, nie dwie
        let mut q = Pseudo::new("lab-host");
        assert_eq!(q.apply_str("LAB-HOST i lab-host"), "HOST_1 i HOST_1");
        assert_eq!(q.replaced(), 1);
    }

    #[test]
    fn generic_host_name_does_not_break_paths_or_words() {
        let mut p = Pseudo::new("dev");
        for keep in ["/dev/shm/x", "/dev/null", "device", "devtools", "my-dev-box", "C:\\dev\\src"] { assert_eq!(p.apply_str(keep), keep, "{keep}"); }
        // nazwa hosta jako całe słowo, w adresie URL i w ścieżce UNC nadal jest podmieniana
        assert_eq!(p.apply_str("host dev odpowiada"), "host HOST_1 odpowiada");
        assert_eq!(p.apply_str("http://dev/api i dev.corp"), "http://HOST_1/api i HOST_1.corp");
        assert_eq!(p.apply_str("\\\\DEV\\share"), "\\\\HOST_1\\share");
        let mut w = Pseudo::new("win");
        assert_eq!(w.apply_str("C:\\Windows\\System32 na win"), "C:\\Windows\\System32 na HOST_1");
    }

    #[test]
    fn ipv6_is_masked_and_lookalikes_are_not() {
        let mut p = Pseudo::new("h");
        assert_eq!(p.apply_str("connect [fe80::1c2a:5ff:fe00:1]:443"), "connect [IP_1]:443");
        assert_eq!(p.apply_str("peer 2001:db8:0:0:0:0:0:5 i ::1"), "peer IP_2 i IP_3");
        assert_eq!(p.apply_str("znowu fe80::1c2a:5ff:fe00:1"), "znowu IP_1", "ta sama wartość, ta sama etykieta");
        for keep in ["12:34:56", "aa:bb:cc:dd:ee:ff", "std::string", "a::b::c", "Foo::bar()", "10:20", "::", "dead::beefy"] { assert_eq!(p.apply_str(keep), keep, "{keep}"); }
        assert_eq!(p.reverse("IP_2"), "2001:db8:0:0:0:0:0:5");
    }

    #[test]
    fn known_value_never_splits_a_longer_name() {
        let mut p = Pseudo::new("h");
        assert_eq!(p.apply_str("/home/ann/a"), "/home/USER_1/a");
        // "ann" jest już znane; dłuższa nazwa musi dostać własną etykietę w całości
        assert_eq!(p.apply_str("/home/annabel/x"), "/home/USER_2/x");
        assert_eq!(p.apply_str("C:\\Users\\ann.kowalska\\y i ann"), "C:\\Users\\USER_3\\y i USER_1");
        // segment tylko podobny do etykiety nie jest pomijany
        assert_eq!(p.apply_str("/home/USER_9x/z"), "/home/USER_4/z");
        // segment będący dokładnie istniejącą etykietą zostaje (tekst już przetworzony)
        assert_eq!(p.apply_str("/home/USER_2/x"), "/home/USER_2/x");
        // kontrola: krótka znana wartość wewnątrz zwykłego słowa nie jest ruszana
        assert_eq!(p.apply_str("planner, annex, scanner"), "planner, annex, scanner");
        assert_eq!(p.apply_str("(ann) Ann: ok"), "(USER_1) USER_1: ok");
    }

    #[test]
    fn known_value_inside_a_token_masks_the_whole_token() {
        let mut p = Pseudo::new("h");
        assert_eq!(p.apply_str("/home/jkowalski/a"), "/home/USER_1/a");
        for (i, leak) in [("backup jkowalski_backup.tar", "jkowalski"), ("konto jkowalski123", "jkowalski"), ("svc_JKowalski", "kowalski"),
            ("adminjkowalskiadm", "jkowalski"), ("x jkowalski2 i jkowalski_backup y", "jkowalski")] {
            let o = p.apply_str(i);
            assert!(!o.to_lowercase().contains(leak), "wyciek {leak}: {o}");
        }
        // ten sam token dostaje tę samą etykietę, a odpowiedź modelu da się odwrócić
        let o = p.apply_str("jkowalski_backup.tar");
        assert_eq!(p.reverse(&o), "jkowalski_backup.tar");
        // krótka wartość: z cyfrą lub podkreśleniem maskowana, w środku słowa nie
        let mut q = Pseudo::new("h");
        q.apply_str("/home/ann/a");
        assert_eq!(q.apply_str("ann_x ann42 channel"), "USER_2 USER_3 channel");
        // etykieta nie jest maskowana ponownie
        let mut r = Pseudo::new("h");
        r.apply_str("/home/user/a");
        assert_eq!(r.apply_str("/home/user/a i USER_1"), "/home/USER_1/a i USER_1");
    }
}
