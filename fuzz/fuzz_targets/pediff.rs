//! Porównanie kodu w pamięci z plikiem PE: plik i pamięć pochodzą z badanej stacji.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_live::pediff;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 { return; }
    let base = u64::from_le_bytes(data[..8].try_into().unwrap());
    let rva = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let split = (u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize) % (data.len() - 15) + 16;
    let (file, mem) = data[16..].split_at(split - 16);
    if let Some(pe) = pediff::Pe::parse(file) {
        let _ = pe.expected(rva, mem.len().min(1 << 16), base);
        let _ = pe.expected(0, 4096, base);
    }
    let _ = pediff::diff(file, base, rva, mem);
    let _ = pediff::same_image_header(mem, file);
});
