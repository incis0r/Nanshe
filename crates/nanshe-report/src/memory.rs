//! Samodzielny raport HTML: dane celu nigdy nie są interpretowane jako HTML.
use nanshe_core::MemoryInventory;

pub fn render(inventory: &MemoryInventory) -> String {
    let data = serde_json::to_string(inventory).expect("serializacja inwentaryzacji")
        .replace('&', "\\u0026").replace('<', "\\u003c").replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029");
    include_str!("memory.html").replacen("__INVENTORY__", &data, 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hostile_metadata_cannot_close_data_script() {
        let i = nanshe_core::MemoryInventory { inventory_version: 1, timestamp: "t".into(),
            host: "</script><script>alert(1)</script>&".into(), os: "linux".into(), processes: vec![] };
        let html = super::render(&i);
        assert!(!html.contains(&i.host));
        let data = html.split("id=\"data\">").nth(1).unwrap().split("</script>").next().unwrap();
        let restored: nanshe_core::MemoryInventory = serde_json::from_str(data).unwrap();
        assert_eq!(restored.host, i.host);
    }
}
