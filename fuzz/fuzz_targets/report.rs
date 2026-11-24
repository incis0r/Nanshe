//! Generator raportu nad dowolnym plikiem wyniku: wynik skanu zawiera dane z badanej stacji (nazwy, ścieżki,
//! wiersze poleceń, bajty), a plik może pochodzić z innego źródła niż własny skaner.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lang = if data.len() & 1 == 1 { nanshe_core::lang::Lang::En } else { nanshe_core::lang::Lang::Pl };
    let _ = nanshe_report::build_report_lang(data, None, nanshe_core::Severity::Info, Some("f.json".into()), None, Some(lang));
    // ten sam plik jako oba wejścia raportu różnicowego
    let _ = nanshe_report::build_diff(data, data, nanshe_core::Severity::Suspicious, None, None, Some(lang));
});
