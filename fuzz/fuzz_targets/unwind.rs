//! Odwijanie stosu wątku po tablicach wyjątków obrazu PE: nagłówek, tablica funkcji, informacje
//! o odwijaniu i stos pochodzą z pamięci badanego procesu.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nanshe_analyze::unwind::Unwinder;
use nanshe_core::{Prot, Region, RegionKind, ThreadRegs};

const IMG: u64 = 0x7ff0_0000_0000;
const STACK: u64 = 0x10_0000;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 { return; }
    let w = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as u64;
    let (head, rest) = data.split_at(8);
    let split = (w(6) as usize) % rest.len();
    let (image, stack) = rest.split_at(split);
    let reg = |base: u64, size: usize, kind, backing: Option<&str>| Region { base, size: size as u64, prot: Prot::parse("r-x"), kind, backing: backing.map(Into::into), backing_deleted: false, label: None, readable: true };
    let regions = vec![reg(STACK, stack.len(), RegionKind::Private, None), reg(IMG, image.len(), RegionKind::Image, Some("a.dll"))];
    let mem = |a: u64, b: &mut [u8]| {
        let (base, m) = if a >= IMG { (IMG, image) } else { (STACK, stack) };
        match a.checked_sub(base).map(|o| o as usize) {
            Some(o) if o <= m.len() && b.len() <= m.len() - o => { b.copy_from_slice(&m[o..o + b.len()]); true }
            _ => false,
        }
    };
    let mut gpr = [0u64; 16];
    gpr[4] = STACK + (w(2) & !7);
    gpr[5] = STACK + w(4);
    let _ = head;
    let mut un = Unwinder::new(&mem, &regions);
    let _ = un.foreign_return(&ThreadRegs { tid: 1, rip: IMG + w(0), gpr });
});
