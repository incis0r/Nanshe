//! Parser /proc/<pid>/maps. Czysta funkcja, testowalna na każdej platformie.
use nanshe_core::{Prot, Region, RegionKind};

use nanshe_core::MAX_REGIONS;

pub fn parse_maps(s: &str) -> Vec<Region> {
    s.lines().take(MAX_REGIONS).filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Region> {
    // start-end perms offset dev inode [ścieżka ze spacjami]
    let (fields, path) = header_fields(line)?;
    let range = fields[0];
    let perms = fields[1];

    let (a, b) = range.split_once('-')?;
    let base = u64::from_str_radix(a, 16).ok()?;
    let end = u64::from_str_radix(b, 16).ok()?;
    if end <= base { return None; }
    let prot = Prot::parse(perms)?;

    let (path, deleted) = match path.strip_suffix(" (deleted)") {
        Some(p) => (p, true),
        None => (path, false),
    };
    let (kind, backing, label) = if path.is_empty() {
        (RegionKind::Private, None, None)
    } else if path == "[heap]" {
        (RegionKind::Heap, None, Some(path.to_string()))
    } else if path == "[stack]" || path.starts_with("[stack:") {
        (RegionKind::Stack, None, Some(path.to_string()))
    } else if path.starts_with("[anon") {
        (RegionKind::Private, None, Some(path.to_string()))
    } else if path.starts_with('[') {
        (RegionKind::Unknown, None, Some(path.to_string()))
    } else if let Some(m) = path.strip_prefix("/memfd:") {
        (RegionKind::Mapped, Some(format!("memfd:{m}")), None)
    } else {
        (RegionKind::Mapped, Some(path.to_string()), None)
    };
    Some(Region { base, size: end - base, prot: Some(prot), kind, backing, backing_deleted: deleted, label, readable: prot.r() })
}

#[cfg(test)]
mod tests {
    use super::*;
    const M: &str = "\
55d0c3a00000-55d0c3a02000 r--p 00000000 fd:01 1234 /usr/bin/cat
55d0c3a02000-55d0c3a06000 r-xp 00002000 fd:01 1234 /usr/bin/cat
55d0c4b00000-55d0c4b21000 rw-p 00000000 00:00 0 [heap]
7f1000000000-7f1000010000 rwxp 00000000 00:00 0 
7f1000020000-7f1000021000 r-xs 00000000 00:01 99 /memfd:payload (deleted)
7f1000030000-7f1000031000 r-xp 00000000 fd:01 77 /tmp/my lib.so (deleted)
7f1000040000-7f1000041000 rw-p 00000000 00:00 0 [anon:scudo]
7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0 [stack]
7ffc00100000-7ffc00104000 r--p 00000000 00:00 0 [vvar]
7ffc00104000-7ffc00106000 r-xp 00000000 00:00 0 [vdso]
śmieci
zz-yy rwxp 0 0 0
2000-1000 rwxp 0 0 0
";
    #[test]
    fn padded_columns_preserve_paths() {
        let r = parse_maps("1000-2000\tr-xp  00001000  08:01   42   /tmp/a b.so");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].backing.as_deref(), Some("/tmp/a b.so"));
    }
    #[test]
    fn parses() {
        let r = parse_maps(M);
        assert_eq!(r.len(), 10, "błędne linie pomijane");
        assert_eq!(r[1].base, 0x55d0c3a02000);
        assert_eq!(r[1].size, 0x4000);
        assert_eq!(r[1].backing.as_deref(), Some("/usr/bin/cat"));
        assert_eq!(r[1].prot.unwrap().to_string(), "r-x");
        assert_eq!(r[2].kind, RegionKind::Heap);
        assert_eq!((r[3].kind, r[3].backing.clone(), r[3].prot.unwrap().to_string()), (RegionKind::Private, None, "rwx".into()));
        assert_eq!(r[4].backing.as_deref(), Some("memfd:payload"));
        assert!(r[4].backing_deleted);
        assert_eq!(r[5].backing.as_deref(), Some("/tmp/my lib.so"));
        assert!(r[5].backing_deleted);
        assert_eq!((r[6].kind, r[6].label.as_deref()), (RegionKind::Private, Some("[anon:scudo]")));
        assert_eq!(r[7].kind, RegionKind::Stack);
        assert_eq!(r[9].label.as_deref(), Some("[vdso]"));
        assert_eq!(r[9].kind, RegionKind::Unknown);
    }
}

/// smaps zawiera te same nagłówki co maps i liczniki kB dla każdego VMA.
pub fn parse_smaps(s: &str) -> Vec<nanshe_core::MappedRegion> {
    let mut out: Vec<nanshe_core::MappedRegion> = Vec::new();
    for line in s.lines() {
        if let Some(r) = parse_line(line) {
            if out.len() >= MAX_REGIONS { break; }
            let mut mapped: nanshe_core::MappedRegion = r.into();
            if let Some((fields, _)) = header_fields(line) {
                mapped.file_offset = u64::from_str_radix(fields[2], 16).ok().map(|v| format!("0x{v:x}"));
                if fields[4] != "0" { mapped.file_id = Some(format!("{}:{}", fields[3], fields[4])); }
                mapped.sharing = fields[1].as_bytes().get(3).and_then(|v| match v {
                    b'p' => Some("private/COW".into()), b's' => Some("shared".into()), _ => None,
                });
            }
            out.push(mapped);
        } else if let Some(r) = out.last_mut() {
            let mut fields = line.split_whitespace();
            let key = fields.next().unwrap_or("");
            if key != "Rss:" && key != "Pss:" { continue; }
            let bytes = fields.next().and_then(|v| v.parse::<u64>().ok())
                .filter(|_| fields.next() == Some("kB"))
                .and_then(|v| v.checked_mul(1024)).map(|v| v.to_string());
            if key == "Rss:" { r.rss = bytes; } else { r.pss = bytes; }
        }
    }
    out
}

#[cfg(test)]
mod smaps_tests {
    #[test]
    fn counters_are_per_mapping_and_missing_is_unknown() {
        let r = super::parse_smaps("1000-2000 r-xp 0000 00:00 1 /a lib.so (deleted)\nRss: 3 kB\nPss: 2 kB\n2000-3000 rw-p 0000 00:00 0\nRss: invalid kB\n");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].file_offset.as_deref(), Some("0x0"));
        assert_eq!(r[0].file_id.as_deref(), Some("00:00:1"));
        assert_eq!(r[0].sharing.as_deref(), Some("private/COW"));
        assert_eq!(r[0].rss.as_deref(), Some("3072"));
        assert_eq!(r[0].pss.as_deref(), Some("2048"));
        assert_eq!(r[0].backing.as_deref(), Some("/a lib.so"));
        assert!(r[0].backing_deleted);
        assert_eq!(r[1].rss, None);
        assert_eq!(r[1].pss, None);
    }
}

fn header_fields(mut line: &str) -> Option<([&str; 5], &str)> {
    let mut fields = [""; 5];
    for field in &mut fields {
        line = line.trim_start_matches(char::is_whitespace);
        if line.is_empty() { return None; }
        let end = line.find(char::is_whitespace).unwrap_or(line.len());
        *field = &line[..end];
        line = &line[end..];
    }
    Some((fields, line.trim_start_matches(char::is_whitespace)))
}

/// maps bez liczników zachowuje offset i tożsamość pliku tak samo jak smaps.
pub fn mapped_regions(s: &str) -> Vec<nanshe_core::MappedRegion> { parse_smaps(s) }
