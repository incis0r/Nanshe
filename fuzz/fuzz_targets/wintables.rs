//! Tablice systemowe Windows (połączenia TCP/UDP, uchwyty): bufory zwracane przez system, w których liczby
//! wierszy i pola pochodzą z badanej stacji.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_live::wintables;

fuzz_target!(|data: &[u8]| {
    let _ = wintables::tcp4(data);
    let _ = wintables::tcp6(data);
    let _ = wintables::udp4(data);
    let _ = wintables::udp6(data);
    let pid = data.first().copied().unwrap_or(0) as u32;
    let _ = wintables::handles_of(data, pid);
    let text = String::from_utf8_lossy(data);
    let _ = wintables::exe_in_system_dir(&text, &["C:\\Windows".to_string(), "C:\\Program Files".to_string()]);
    let _ = wintables::path_form_is_local(&text);
    let _ = wintables::owner_sid_trusted(&text);
    let _ = wintables::handle_kind(&text);
});
