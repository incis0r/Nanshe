use crate::{build_regions, regions_from_vads, walk_page_tables, walk_vads, GuestProc, Module, Symbols, Vad, VadOffsets};
use memflow::prelude::v1::{Address, ConnectorArgs, MemoryView, Os, PhysicalAddress, Pid, Process, ProcessInfo, ProcessState};
use memflow_win32::prelude::v1::{SymbolStore, Win32Kernel};
use nanshe_core::{tr, trf, Error, MemorySource, Region, Result, SourceInfo};
use memflow::cglue::forward::ForwardMut;
use std::cell::RefCell;
use std::rc::Rc;

/// Operacje na jądrze gościa bez nazywania typów biblioteki (są mocno parametryzowane).
trait Kernel {
    fn procs(&mut self) -> Result<Vec<ProcessInfo>>;
    /// Zakresy stron, moduły i znacznik, czy tablice stron przeczytano w całości.
    fn layout(&mut self, p: &ProcessInfo) -> Result<Layout>;
    fn read(&mut self, p: &ProcessInfo, addr: u64, buf: &mut [u8]) -> Result<usize>;
}

fn fail(what: &str, e: impl std::fmt::Display) -> Error { Error::Invalid(format!("{what}: {e}")) }

/// Nazwa pliku regionu mapowanego: węzeł VAD -> podsekcja -> obszar kontrolny -> obiekt pliku -> nazwa.
/// Każdy wskaźnik pochodzi z pamięci gościa: musi wskazywać pamięć jądra, a długość nazwy jest ograniczona.
/// Wynik dla danego obszaru kontrolnego jest zapamiętywany (wiele regionów wskazuje ten sam plik).
fn file_name<M: MemoryView>(mem: &mut M, v: &VadPaths, node: u64, seen: &mut std::collections::HashMap<u64, Option<String>>) -> Option<String> {
    let kernel = |a: u64| (a >= 0xffff_8000_0000_0000).then_some(a);
    let subsection = kernel(mem.read::<u64>(Address::from(node + v.subsection as u64)).ok()?)?;
    let control_area = kernel(mem.read::<u64>(Address::from(subsection + v.control_area as u64)).ok()?)?;
    if let Some(n) = seen.get(&control_area) { return n.clone(); }
    let name = (|| {
        // wskaźnik na obiekt pliku ma w młodszych 4 bitach licznik odwołań
        let file = kernel(mem.read::<u64>(Address::from(control_area + v.file_pointer as u64)).ok()? & !0xf)?;
        let len = mem.read::<u16>(Address::from(file + v.file_name as u64)).ok()? as usize;
        let buffer = kernel(mem.read::<u64>(Address::from(file + v.file_name as u64 + 8)).ok()?)?;
        if len == 0 || len % 2 != 0 { return None; }
        let mut raw = vec![0u8; len.min(MAX_FILE_NAME * 2)];
        mem.read_raw_into(Address::from(buffer), &mut raw).ok()?;
        let wide: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&wide)).filter(|s| !s.is_empty())
    })();
    seen.insert(control_area, name.clone());
    name
}

/// Adres tablic stron trybu użytkownika z pola UserDirectoryTableBase albo None, gdy proces ich nie ma.
pub(crate) fn user_dtb_root(field: Option<u64>) -> Option<u64> {
    field.map(|v| v & 0x000f_ffff_ffff_f000).filter(|a| *a != 0)
}

/// Jądro gościa razem z tym, czego biblioteka nie zna: położeniem adresu tablic stron trybu użytkownika.
struct WinKernel<T, V> { k: Win32Kernel<T, V>, user_dtb_offset: Option<usize>, vad: Option<VadPaths>,
    /// Tablice stron ostatnio czytanego procesu (pid i adres tablicy głównej), żeby nie czytać ich dla każdej strony od nowa.
    tables: std::collections::HashMap<u64, Option<Rc<[u64]>>>, tables_for: (u32, u64) }

/// Mapa regionów procesu gościa i to, na ile można jej ufać.
pub(crate) struct Layout {
    regions: Vec<Region>,
    /// Rodzaj regionów jest znany (z drzewa VAD albo z listy modułów).
    kinds_known: bool,
    /// Tablice stron i drzewo VAD przeczytane w całości.
    complete: bool,
    /// Regiony pochodzą z drzewa VAD jądra (false: z listy modułów programu ładującego).
    from_vad: bool,
}

/// Położenia pól potrzebnych do przejścia drzewa VAD i odczytania nazwy pliku, z pliku symboli jądra.
#[derive(Clone, Copy, Debug)]
struct VadPaths { vad_root: usize, tree: VadOffsets, subsection: usize, control_area: usize, file_pointer: usize, file_name: usize }

/// Nazwa pliku w obiekcie pliku jądra: najwyżej tyle znaków.
const MAX_FILE_NAME: usize = 520;

impl<T, V> Kernel for WinKernel<T, V>
where T: memflow::prelude::v1::PhysicalMemory + Clone + 'static, V: memflow::prelude::v1::VirtualTranslate2 + Clone + 'static {
    fn procs(&mut self) -> Result<Vec<ProcessInfo>> {
        self.k.process_info_list().map_err(|e| fail(tr!("lista procesów gościa", "guest process list"), e))
    }
    fn layout(&mut self, p: &ProcessInfo) -> Result<Layout> {
        if p.dtb1.is_null() { return Err(Error::Invalid(tr!("proces gościa nie ma tablic stron (kończy się albo jest procesem minimalnym)", "the guest process has no page tables (it is exiting or is a minimal process)").into())); }
        // Przy izolacji tablic stron jądra (ochrona przed Meltdown) proces bez uprawnień administratora ma dwa
        // zestawy tablic. W jądrowych cała przestrzeń użytkownika jest oznaczona jako niewykonywalna, więc
        // faktyczną ochronę stron widać tylko w tablicach trybu użytkownika (pole UserDirectoryTableBase).
        // Młodsze 12 bitów pola to znaczniki; proces z jednym zestawem tablic ma w nim sam znacznik (pomiar na
        // Windows 11 build 26100: wartość 1 dla procesów systemowych, adres z końcówką 001 dla pozostałych).
        let user_root = user_dtb_root(self.user_dtb_offset.and_then(|off| self.k.virt_mem.read::<u64>(p.address + off).ok()));
        let root = user_root.unwrap_or(p.dtb1.to_umem());
        let root_tables = root;
        let phys = self.k.virt_mem.phys_mem();
        let (ranges, complete) = walk_page_tables(root, |addr| {
            let mut raw = [0u8; 4096];
            phys.phys_read_into(PhysicalAddress::from(addr), &mut raw).ok()?;
            Some(raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
        });
        // Regiony z drzewa VAD jądra: prawdziwe granice, rodzaj i nazwa pliku każdego regionu, niezależnie od
        // listy modułów prowadzonej przez sam proces (która bywa niepełna albo nieczytelna).
        if let Some(v) = self.vad {
            if let Ok(root) = self.k.virt_mem.read::<u64>(p.address + v.vad_root) {
                let mem = &mut self.k.virt_mem;
                let (vads, tree_complete) = walk_vads(root, &v.tree, |addr, buf| mem.read_raw_into(Address::from(addr), buf).is_ok());
                if !vads.is_empty() {
                    let mut names: std::collections::HashMap<u64, Option<String>> = std::collections::HashMap::new();
                    let named: Vec<(Vad, Option<String>)> = vads.into_iter().map(|vad| {
                        let name = if vad.private { None } else { file_name(mem, &v, vad.node, &mut names) };
                        (vad, name)
                    }).collect();
                    let regions = regions_from_vads(&ranges, &named);
                    if std::env::var_os("NANSHE_VM_DEBUG").is_some() {
                        let x: Vec<&Region> = regions.iter().filter(|r| r.is_x()).collect();
                        let count = |k: nanshe_core::RegionKind| x.iter().filter(|r| r.kind == k).count();
                        eprintln!("DBG pid={} {} tables={root_tables:x} user_tables={} vads={} tree_complete={tree_complete} ranges={} exec: private={} image={} mapped={} unknown={}", p.pid, p.name, user_root.is_some(),
                            named.len(), ranges.len(), count(nanshe_core::RegionKind::Private), count(nanshe_core::RegionKind::Image), count(nanshe_core::RegionKind::Mapped), count(nanshe_core::RegionKind::Unknown));
                        for r in x.iter().filter(|r| r.kind != nanshe_core::RegionKind::Image).take(6) { eprintln!("DBG    {:x}+{:x} {:?} {:?} {:?}", r.base, r.size, r.kind, r.label, r.backing); }
                    }
                    return Ok(Layout { regions, kinds_known: true, complete: complete && tree_complete, from_vad: true });
                }
            }
        }
        let mut proc = self.k.process_by_info(p.clone()).map_err(|e| fail(tr!("proces gościa", "guest process"), e))?;
        // lista modułów bywa nieczytelna (strony wyrzucone z pamięci): wtedy regiony zostają bez nazw plików
        let modules: Vec<Module> = proc.module_list().unwrap_or_default().into_iter()
            .map(|m| Module { base: m.base.to_umem(), size: m.size, path: m.path.to_string() }).collect();
        Ok(Layout { regions: build_regions(&ranges, &modules), kinds_known: !modules.is_empty(), complete, from_vad: false })
    }
    fn read(&mut self, p: &ProcessInfo, addr: u64, buf: &mut [u8]) -> Result<usize> {
        // Własne tłumaczenie adresów zamiast bibliotecznego: te same tablice co przy budowie mapy (także tablice
        // trybu użytkownika) i strony przejściowe, których procesor nie uznaje za obecne, choć leżą w pamięci.
        let root = user_dtb_root(self.user_dtb_offset.and_then(|off| self.k.virt_mem.read::<u64>(p.address + off).ok())).unwrap_or(p.dtb1.to_umem());
        if self.tables_for != (p.pid, root) || self.tables.len() > 8192 { self.tables.clear(); self.tables_for = (p.pid, root); }
        let phys = self.k.virt_mem.phys_mem();
        let tables = &mut self.tables;
        let mut done = 0usize;
        let mut any = false;
        while done < buf.len() {
            let va = addr.wrapping_add(done as u64);
            let leaf = crate::leaf_entry(root, va, |a| {
                if let Some(t) = tables.get(&a) { return t.clone(); }
                let mut raw = [0u8; 4096];
                let t: Option<Rc<[u64]>> = phys.phys_read_into(PhysicalAddress::from(a), &mut raw).ok()
                    .map(|_| raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect());
                tables.insert(a, t.clone());
                t
            });
            // strona poza pamięcią fizyczną: zostaje wyzerowana, jak w odczycie częściowym skanu na żywo
            let Some((entry, page)) = leaf else { done += (4096 - (va & 4095) as usize).min(buf.len() - done); continue };
            let within = va & (page - 1);
            let step = ((page - within) as usize).min(buf.len() - done).min(1 << 20);
            for frame in crate::frame_candidates(entry) {
                let base = frame & !(page - 1);
                if phys.phys_read_into(PhysicalAddress::from(base + within), &mut buf[done..done + step]).is_ok() { any = true; break; }
            }
            done += step;
        }
        if any || buf.is_empty() { Ok(buf.len()) } else { Err(Error::Access(trf!("odczyt pamięci gościa pod adresem {addr:#x}: żadna strona nie leży w pamięci fizycznej", "guest memory read at {addr:#x}: no page is present in physical memory"))) }
    }
}

/// Otwarta maszyna wirtualna: jądro Windows znalezione w pamięci gościa.
pub struct Guest { kernel: Rc<RefCell<Box<dyn Kernel>>>, pub target: String }

/// `target`: nazwa maszyny (wartość `guest=` w wierszu poleceń QEMU, jak w libvirt) albo numer PID procesu QEMU.
pub fn open(target: &str, symbols: Symbols) -> Result<Guest> {
    let pid = match target.parse::<u32>() { Ok(p) => p, Err(_) => qemu_pid(target)? };
    let args: ConnectorArgs = pid.to_string().parse().map_err(|e| fail("QEMU", e))?;
    let mut connector = memflow_qemu::create_connector(&args).map_err(|e| Error::Access(trf!(
        "nie udało się otworzyć pamięci procesu QEMU {pid} ({e}); potrzebne są uprawnienia root na hoście",
        "could not open the memory of QEMU process {pid} ({e}); root privileges on the host are required")))?;
    // Nazwa pliku symboli i jego identyfikator pochodzą z pamięci gościa, a biblioteka składa z nich ścieżkę
    // w katalogu symboli (i adres pobierania). Jądro jest rozpoznawane raz: sprawdzone tu wartości są tymi samymi,
    // których używa dalsza część (bez drugiego odczytu, który gość mógłby w międzyczasie podmienić).
    let scanned = memflow_win32::prelude::v1::Win32KernelInfo::scanner((&mut connector).forward_mut()).scan()
        .map_err(|e| Error::Invalid(trf!("nie udało się znaleźć jądra Windows w pamięci gościa: {e}", "could not find the Windows kernel in guest memory: {e}")))?;
    check_symbol_id(scanned.kernel_guid.as_ref().map(|g| (g.file_name.as_str(), g.guid.as_str())))?;
    let mut store = SymbolStore::new();
    if let Some(d) = symbols.dir { store = store.cache_path(d); }
    // Bez zgody na pobieranie liczy się tylko katalog lokalny: adres serwera ma schemat, którego klient HTTP
    // nie obsługuje, więc żadne połączenie nie jest nawiązywane (także z usługą na tym samym hoście).
    if !symbols.fetch { store = store.base_url(NO_DOWNLOAD); }
    let arch = scanned.os_info.arch;
    // położenie pola z adresem tablic stron trybu użytkownika, z tego samego pliku symboli; brak pola albo
    // pliku nie przerywa pracy (starsze systemy nie mają tego pola), tylko wyłącza korzystanie z tych tablic
    let pdb = scanned.kernel_guid.as_ref().and_then(|g| store.load(g).ok());
    let field = |st: &str, name: &str| pdb.as_deref().and_then(|b| memflow_win32::offsets::pdb::PdbStruct::new(b, st).ok()).and_then(|k| k.find_field(name).map(|f| (f.offset, f.bit_offset as u32)));
    let user_dtb_offset = field("_KPROCESS", "UserDirectoryTableBase").map(|f| f.0);
    // położenia pól drzewa VAD; gdy którekolwiek jest nieznane, regiony powstają po staremu, z listy modułów
    let vad = (|| Some(VadPaths {
        vad_root: field("_EPROCESS", "VadRoot")?.0,
        tree: VadOffsets { left: 0, right: 8,
            start_vpn: field("_MMVAD_SHORT", "StartingVpn")?.0, end_vpn: field("_MMVAD_SHORT", "EndingVpn")?.0,
            start_high: field("_MMVAD_SHORT", "StartingVpnHigh")?.0, end_high: field("_MMVAD_SHORT", "EndingVpnHigh")?.0,
            flags: field("_MMVAD_SHORT", "u")?.0, type_bit: field("_MMVAD_FLAGS", "VadType")?.1, private_bit: field("_MMVAD_FLAGS", "PrivateMemory")?.1 },
        subsection: field("_MMVAD", "Subsection")?.0, control_area: field("_SUBSECTION", "ControlArea")?.0,
        file_pointer: field("_CONTROL_AREA", "FilePointer")?.0, file_name: field("_FILE_OBJECT", "FileName")?.0,
    }))();
    if std::env::var_os("NANSHE_VM_DEBUG").is_some() { eprintln!("DBG vad offsets: {vad:?} user_dtb: {user_dtb_offset:?}"); }
    let built = memflow_win32::offsets::offset_builder_with_kernel_info(&scanned).symbol_store(store).build().map(|offsets| {
        let phys = memflow::prelude::v1::CachedPhysicalMemory::builder(connector).arch(arch).build().unwrap();
        let vat = memflow::prelude::v1::CachedVirtualTranslate::builder(memflow::prelude::v1::DirectTranslate::new()).arch(arch).build().unwrap();
        WinKernel { k: Win32Kernel::new(phys, vat, offsets, scanned), user_dtb_offset, vad, tables: Default::default(), tables_for: (0, 0) }
    });
    let kernel = built.map_err(|e| Error::Invalid(if symbols.fetch {
        trf!("nie udało się rozpoznać jądra Windows w pamięci gościa: {e}", "could not identify the Windows kernel in guest memory: {e}")
    } else {
        trf!("nie udało się rozpoznać jądra Windows w pamięci gościa: {e}. Najczęstsza przyczyna: brak pliku symboli jądra w katalogu symboli; --fetch-symbols pozwala pobrać go z serwera symboli Microsoftu",
             "could not identify the Windows kernel in guest memory: {e}. The usual cause is a missing kernel symbol file in the symbol directory; --fetch-symbols allows downloading it from the Microsoft symbol server")
    }))?;
    let guest = Guest { kernel: Rc::new(RefCell::new(Box::new(kernel))), target: target.to_string() };
    // Bez właściwych symboli biblioteka potrafi przyjąć przesunięcia innej wersji jądra i zwrócić pustą albo
    // błędną listę procesów. Proces System ma w każdym Windows numer 4: jego brak oznacza złe symbole.
    if !guest.processes()?.iter().any(|p| p.pid == 4 && p.name == "System") {
        return Err(Error::Invalid(tr!("lista procesów gościa jest pusta albo nie zawiera procesu System: najpewniej brak właściwego pliku symboli jądra w katalogu symboli (--symbols); --fetch-symbols pozwala pobrać go z serwera symboli Microsoftu",
            "the guest process list is empty or lacks the System process: most likely the right kernel symbol file is missing from the symbol directory (--symbols); --fetch-symbols allows downloading it from the Microsoft symbol server").into()));
    }
    Ok(guest)
}

const NO_DOWNLOAD: &str = "pobieranie-wylaczone://brak";

/// Nazwa pliku symboli jądra i identyfikator wersji odczytane z gościa: tylko znaki, z których nie da się
/// zbudować ścieżki poza katalog symboli ani innego adresu pobierania.
pub(crate) fn check_symbol_id(id: Option<(&str, &str)>) -> Result<()> {
    let Some((file, guid)) = id else { return Ok(()) };
    let file_ok = !file.is_empty() && file.len() <= 64 && file.to_ascii_lowercase().ends_with(".pdb") && !file.starts_with('.')
        && file.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) && !file.contains("..");
    let guid_ok = (32..=40).contains(&guid.len()) && guid.chars().all(|c| c.is_ascii_hexdigit());
    if file_ok && guid_ok { Ok(()) } else {
        Err(Error::Invalid(tr!("gość podaje nieprawidłową nazwę albo identyfikator pliku symboli jądra; skan przerwany, bo te wartości trafiają do ścieżki pliku",
            "the guest reports an invalid kernel symbol file name or identifier; the scan was stopped because these values are used in a file path").into()))
    }
}

/// Konta systemowe mają numery poniżej tej wartości; maszyny libvirt działają jako root albo konto usługi.
const FIRST_USER_UID: u32 = 1000;

/// Wszystkie identyfikatory użytkownika procesu (rzeczywisty, efektywny, zapisany, plikowy) z `/proc/<pid>/status`
/// należą do kont systemowych. Właściciel katalogu `/proc/<pid>` się do tego nie nadaje: dla procesu, który
/// wyłączył zrzuty pamięci, jest nim root niezależnie od tego, kto proces uruchomił.
pub(crate) fn all_uids_system(status: &str) -> bool {
    let Some(line) = status.lines().find(|l| l.starts_with("Uid:")) else { return false };
    let ids: Vec<Option<u32>> = line[4..].split_whitespace().map(|v| v.parse().ok()).collect();
    ids.len() == 4 && ids.iter().all(|v| matches!(v, Some(u) if *u < FIRST_USER_UID))
}

/// Proces QEMU po nazwie gościa. Biblioteka rozpoznaje tylko programy o nazwie `qemu-system-*`,
/// a systemy z rodziny RHEL uruchamiają maszyny programem `qemu-kvm`, więc szukamy sami.
fn qemu_pid(name: &str) -> Result<u32> {
    let mut found = Vec::new();
    for e in std::fs::read_dir("/proc")?.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(raw) = std::fs::read(e.path().join("cmdline")) else { continue };
        let args: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
        if guest_name(&args).as_deref() != Some(name) { continue; }
        // argv[0] ustawia sam proces: liczy się plik programu wg jądra, z katalogu systemowego
        let exe = std::fs::read_link(e.path().join("exe")).ok();
        let real = exe.as_deref().and_then(|p| p.to_str()).map(|p| is_qemu_program(p.rsplit('/').next().unwrap_or("")) && ["/usr/", "/opt/", "/bin/", "/sbin/"].iter().any(|d| p.starts_with(d)) && !p.contains("/../")).unwrap_or(false);
        // maszyna uruchomiona przez zwykłego użytkownika nie jest wybierana po nazwie: nazwę gościa ustawia
        // ten, kto uruchamia QEMU, więc mógłby podstawić własną maszynę pod nazwę cudzej (PID można podać jawnie)
        let system_owned = std::fs::read_to_string(e.path().join("status")).map(|s| all_uids_system(&s)).unwrap_or(false);
        if real && system_owned { found.push(pid); }
    }
    match found.as_slice() {
        [p] => Ok(*p),
        [] => Err(Error::NotFound(trf!("maszyna wirtualna „{name}\" (brak procesu QEMU z taką nazwą gościa uruchomionego z konta systemowego; maszynę zwykłego użytkownika wskaż numerem PID)", "virtual machine \"{name}\" (no QEMU process with this guest name started by a system account; point at a user's machine by PID)"))),
        _ => Err(Error::Invalid(trf!("kilka procesów QEMU ma nazwę gościa „{name}\"; podaj numer PID procesu", "several QEMU processes have the guest name \"{name}\"; pass the process PID instead"))),
    }
}

/// Nazwa gościa z argumentów QEMU: `-name guest=NAZWA,...` albo `-name NAZWA`. Tylko dla programów QEMU.
pub(crate) fn guest_name(args: &[&[u8]]) -> Option<String> {
    let prog = std::str::from_utf8(args.first()?).ok()?.rsplit('/').next()?;
    if !is_qemu_program(prog) { return None; }
    let i = args.iter().position(|a| *a == b"-name")?;
    let v = std::str::from_utf8(args.get(i + 1)?).ok()?;
    let mut plain = None;
    for part in v.split(',') {
        match part.split_once('=') { Some(("guest", n)) => return Some(n.to_string()), None if plain.is_none() => plain = Some(part.to_string()), _ => {} }
    }
    plain
}

fn is_qemu_program(name: &str) -> bool { name.starts_with("qemu-system-") || name == "qemu-kvm" }

impl Guest {
    pub fn processes(&self) -> Result<Vec<GuestProc>> {
        Ok(self.infos()?.iter().map(|p| GuestProc { pid: p.pid, name: p.name.to_string(), path: p.path.to_string(), cmdline: p.command_line.to_string(), alive: matches!(p.state, ProcessState::Alive) }).collect())
    }
    fn infos(&self) -> Result<Vec<ProcessInfo>> { self.kernel.borrow_mut().procs() }
    /// Proces gościa jako źródło pamięci dla detektorów. Mapa regionów jest ustalana raz, przy otwarciu.
    pub fn process(&self, pid: u32) -> Result<GuestProcess> {
        let info = self.infos()?.into_iter().find(|p| p.pid == pid as Pid && matches!(p.state, ProcessState::Alive))
            .ok_or_else(|| Error::NotFound(trf!("proces gościa {pid}", "guest process {pid}")))?;
        let l = self.kernel.borrow_mut().layout(&info)?;
        Ok(GuestProcess { kernel: self.kernel.clone(), regions: l.regions, modules_known: l.kinds_known, tables_complete: l.complete, from_vad: l.from_vad, info })
    }
}

pub struct GuestProcess { kernel: Rc<RefCell<Box<dyn Kernel>>>, info: ProcessInfo, regions: Vec<Region>, pub modules_known: bool, pub tables_complete: bool,
    /// Regiony pochodzą z drzewa VAD jądra, a nie z listy modułów procesu.
    pub from_vad: bool }

impl GuestProcess {
    pub fn cmdline(&self) -> String { self.info.command_line.to_string() }
}

impl MemorySource for GuestProcess {
    fn info(&self) -> SourceInfo {
        let arch = format!("{:?}", self.info.proc_arch);
        let path = self.info.path.to_string();
        SourceInfo { os: "windows".into(), arch: if arch.contains("32") { "x86".into() } else { "x86_64".into() }, pid: Some(self.info.pid as u32), name: Some(self.info.name.to_string()),
            source_type: "vm".into(), exe: (!path.is_empty()).then_some(path), exe_deleted: false, exe_verified: false }
    }
    fn regions(&self) -> Result<Vec<Region>> { Ok(self.regions.clone()) }
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize> { self.kernel.borrow_mut().read(&self.info, addr, buf) }
}

#[cfg(test)]
mod tests {
    use super::guest_name;
    fn a(v: &[&'static str]) -> Vec<&'static [u8]> { v.iter().map(|s| s.as_bytes()).collect() }

    #[test]
    fn symbol_download_is_impossible_without_consent() {
        // katalog symboli pusty, pobieranie wyłączone: błąd bez próby połączenia (schemat nieobsługiwany przez klienta HTTP)
        let dir = std::env::temp_dir().join(format!("nanshe-sym-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = memflow_win32::prelude::v1::SymbolStore::new().cache_path(&dir).base_url(super::NO_DOWNLOAD);
        let guid = memflow_win32::prelude::v1::Win32Guid::new("ntkrnlmp.pdb", "00000000000000000000000000000000");
        let t = std::time::Instant::now();
        assert!(store.load(&guid).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.path().is_file()).count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symbol_identifiers_from_the_guest_cannot_form_a_path() {
        use super::check_symbol_id as c;
        assert!(c(None).is_ok());
        assert!(c(Some(("ntkrnlmp.pdb", "953A8DE880B0818C32DA2DEC1D79C2D91"))).is_ok());
        assert!(c(Some(("ntkrpamp.pdb", "0123456789abcdef0123456789abcdef1"))).is_ok());
        for (file, guid) in [("../../etc/x.pdb", "953A8DE880B0818C32DA2DEC1D79C2D91"), ("/etc/passwd", "953A8DE880B0818C32DA2DEC1D79C2D91"), ("a/b.pdb", "953A8DE880B0818C32DA2DEC1D79C2D91"),
            ("..pdb", "953A8DE880B0818C32DA2DEC1D79C2D91"), ("ntkrnlmp.exe", "953A8DE880B0818C32DA2DEC1D79C2D91"), ("", "953A8DE880B0818C32DA2DEC1D79C2D91"),
            ("ntkrnlmp.pdb", "../../../../tmp/x"), ("ntkrnlmp.pdb", "953A8DE880B0818C32DA2DEC1D79C2D9/"), ("ntkrnlmp.pdb", "abc"), ("ntkrnlmp.pdb", ""), ("nt krnl.pdb", "953A8DE880B0818C32DA2DEC1D79C2D91")] {
            assert!(c(Some((file, guid))).is_err(), "{file} {guid}");
        }
    }

    #[test]
    fn process_owner_is_read_from_all_four_user_ids() {
        use super::all_uids_system as f;
        assert!(f("Name:\tqemu-kvm\nUid:\t107\t107\t107\t107\nGid:\t107\t107\t107\t107\n"));
        assert!(f("Uid:\t0\t0\t0\t0\n"));
        // zwykły użytkownik na dowolnej pozycji, brak wiersza, niepełny albo nieliczbowy wiersz
        for bad in ["Uid:\t1000\t1000\t1000\t1000\n", "Uid:\t0\t1000\t0\t0\n", "Uid:\t107\t107\t107\t65534\n", "Name:\tx\n", "Uid:\t0\t0\n", "Uid:\t0\t0\t0\tx\n", ""] {
            assert!(!f(bad), "{bad:?}");
        }
    }

    #[test]
    fn user_page_tables_are_used_only_when_the_process_has_them() {
        use super::user_dtb_root as f;
        assert_eq!(f(Some(0x16de69001)), Some(0x16de69000));
        assert_eq!(f(Some(0x5d6b3000)), Some(0x5d6b3000));
        // sam znacznik, zero albo nieprzeczytane pole: proces ma jeden zestaw tablic
        assert_eq!((f(Some(1)), f(Some(0)), f(Some(0xfff)), f(None)), (None, None, None, None));
    }

    #[test]
    fn guest_name_is_read_from_qemu_arguments_only() {
        assert_eq!(guest_name(&a(&["/usr/libexec/qemu-kvm", "-name", "guest=dc01,debug-threads=on", "-S"])).as_deref(), Some("dc01"));
        assert_eq!(guest_name(&a(&["/usr/bin/qemu-system-x86_64", "-m", "4096", "-name", "debug-threads=on,guest=w11"])).as_deref(), Some("w11"));
        assert_eq!(guest_name(&a(&["qemu-system-x86_64", "-name", "plain"])).as_deref(), Some("plain"));
        // kontrole: inny program z takim samym argumentem, brak wartości, brak argumentu
        assert_eq!(guest_name(&a(&["/usr/bin/python3", "-name", "guest=dc01"])), None);
        assert_eq!(guest_name(&a(&["/usr/libexec/qemu-kvm", "-name"])), None);
        assert_eq!(guest_name(&a(&["/usr/libexec/qemu-kvm", "-m", "4096"])), None);
        assert_eq!(guest_name(&[]), None);
    }
}
