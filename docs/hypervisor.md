# Reading a Windows guest from the KVM host

Polish version: [pl/hiperwizor.md](pl/hiperwizor.md).

`nanshe vm` scans the processes of a running Windows virtual machine from the Linux host that runs it under KVM/QEMU. Nothing is installed or started inside the guest. The scanner reads the memory of the QEMU process on the host, finds the Windows kernel in it and walks the page tables of every guest process. The same detectors and the same report are used as for a live scan.

State: first version (0.4 preview). Measured on two guests so far, one of them against a live scan of the same system; see "What was measured". Results from this mode need more care than results of a live scan.

## Why

- A scan from inside Windows cannot open protected processes (LSASS, antivirus processes, core system processes), even as SYSTEM. From the host they are ordinary memory.
- Nothing runs in the guest, so there is nothing for code inside the guest to detect, block or tamper with at the moment of the scan.
- The guest is not paused and is not written to.

## Requirements

- Linux host with KVM/QEMU (libvirt or plain QEMU), x86_64 guest running 64-bit Windows.
- Root on the host (the scanner reads the memory of another process).
- A build with the `vm` feature: `cargo build --release -p nanshe-cli --features vm`. Default builds do not contain this code, and the command then stops with an error that says so. `scripts/build-linux-vm.sh` builds such an x86_64 binary in a container (linked against glibc 2.31, result in `dist/linux/nanshe-vm-x86_64`).
- The kernel symbol file (PDB) of the guest's Windows build; see "Kernel symbols".

## Usage

```sh
# list guest processes
sudo nanshe vm dc01 --ps --symbols ./symbols

# scan all guest processes and write the result
sudo nanshe vm dc01 --all --symbols ./symbols --json dc01.json
nanshe report dc01.json

# one process
sudo nanshe vm dc01 --pid 812 --symbols ./symbols --json lsass.json
```

The target is the guest name (the `guest=` value of QEMU's `-name` argument, which is the libvirt domain name) or the PID of the QEMU process. Both `qemu-system-*` and `qemu-kvm` (RHEL family) processes are recognised. When the target is a name, a process is accepted only if its program file as reported by the kernel (`/proc/<pid>/exe`, not the name the process gives itself) is such a program in `/usr/`, `/opt/`, `/bin/` or `/sbin/`; if no process or more than one matches, the scan stops with an error.

| Option | Meaning |
|---|---|
| `--ps` | list guest processes and exit |
| `--pid N` | scan one guest process (PID inside the guest) |
| `--all` | scan all guest processes |
| `--symbols <dir>` | directory with kernel symbol files |
| `--fetch-symbols` | allow downloading a missing symbol file (the only use of the network) |
| `--json <file>` | full result to a file (`-` means standard output) |
| `--min info\|suspicious\|high` | threshold for printing and for the exit code (default `suspicious`) |
| `--no-bytes` | without the byte preview in the result |
| `--max-region-mib N` | read limit for one region (default 64) |

The result has the same format as a live scan; the `source_type` field of each process is `vm`.

## Kernel symbols

The scanner needs the layout of kernel structures for the exact Windows build of the guest. It takes it from the kernel's symbol file, looked up in a local directory laid out as `<file.pdb>/<identifier>`, for example `symbols/ntkrnlmp.pdb/953A8DE880B0818C32DA2DEC1D79C2D91`.

- By default the scanner makes **no network connection**. If the file is missing, it stops with an error that says so. Without `--fetch-symbols` the symbol server address is replaced with one that the HTTP client cannot use, so no connection is attempted; a unit test checks this.
- `--fetch-symbols` allows downloading the missing file from the Microsoft symbol server into the symbol directory. This is the only network code in this feature, and it sends only the identifier of the kernel build. Run it once on a machine with network access, then copy the directory to the host.
- Without `--symbols` the directory is the user's cache directory (`~/.cache/memflow`).
- The symbol file name and build identifier are read from guest memory and become part of a file path and of the download address. The scanner accepts only a plain `*.pdb` name and a hexadecimal identifier, and stops otherwise.
- A guest selected by name must be a QEMU process started by a system account (root or a service account such as `qemu`). The guest name is set by whoever starts QEMU, so a machine started by an ordinary user is selected only by PID.

After opening the guest, the scanner checks that the process list contains the `System` process with PID 4. If it does not, the symbols do not match the kernel and the scan stops, instead of returning an empty or wrong result.

## What the result contains and what it does not

| | Live scan inside Windows | Scan from the host |
|---|---|---|
| Protected processes (LSASS, antivirus) | not accessible | scanned |
| Region list | from the memory manager (all reserved and committed regions) | region borders from the kernel VAD tree; only parts present in physical memory are examined (pages in the working set and transition pages) |
| Region protection | as set by the process | effective protection from the page tables, combined across levels as the processor does |
| Region type | private, mapped, image | private, mapped or image from the kernel VAD tree; from the process module list only when the VAD layout of the kernel is not known (older symbol files) |
| Files mapped as data | known, with path | known, with the path from the kernel file object (without the drive letter) |
| Comparison of code with the file on disk (`IMG-MOD`) | yes | no (the host does not see the guest's files) |
| Threads, network, open files, process tree | yes | no |
| Reduced weight for just-in-time runtimes | yes | no (the program file cannot be verified from the host) |

Consequences worth knowing before reading a report:

- **Region types come from the kernel, not from the process.** The VAD tree and the file objects are kernel structures, so a process cannot hide a library by editing its own module list, and an incomplete module list no longer produces false `X-PRIV` findings (measured: one process went from 430 such findings to 2, four others from hundreds to none). If the kernel symbol file lacks the VAD structures, the scanner falls back to the module list and says so in the result; the old weakness then applies.
- **Code the kernel cannot attribute is examined, not excused.** An executable page that no VAD entry describes is treated as private memory (label `[no VAD]`): unlinking a region from the tree is a known way to hide it. An image whose file cannot be named is treated as a mapping without a file (label `[image without file name]`, tag `X-MAP`): this is what a process started from a deleted or replaced file looks like. On the second guest 13 image regions had no readable name and two processes were flagged because of them; no page outside the VAD tree was seen on either guest. The cause of the unreadable names was not established, so such a finding needs a manual look rather than a conclusion.
- **Pages written out to the page file are not seen.** A region can be shorter than in a live scan, or missing. Transition pages (taken from the working set but still in physical memory) are read. On the second guest two processes flagged by a live scan eight hours earlier (`dwm.exe`, `ShellExperienceHost.exe`) had no private executable page in physical memory at the time of the later scan from the host; whether those pages were paged out or released was not established.
- **The guest keeps running during the scan,** so the result is not a consistent snapshot.
- **`HDR` in non-executable memory is reported only for regions the kernel marks as private.** Sections without a file and regions of unknown type are skipped, because files mapped as data start with an image header. Anti-malware engines keep many program images in private memory and are reported with many `HDR` findings (228 in `MsMpEng.exe` on the first guest).
- Just-in-time runtimes (.NET, antivirus engines) appear with full weight, as in a dump.

## What was measured

One guest, 2026-11-23: Windows Server 2025 domain controller (4 GiB RAM) on a Rocky Linux 9.8 host, QEMU started by libvirt.

- 96 guest processes listed and scanned in 9 seconds, 1.8 GiB read, guest running throughout.
- All processes were readable, including `lsass.exe`, `MsMpEng.exe`, `csrss.exe` and `LsaIso.exe`.
- 3 processes at `suspicious` or above: `Microsoft.ActiveDirectory.WebServices.exe` (.NET, `RWX` and `X-PRIV`), `MsMpEng.exe` (`RWX` and `X-PRIV`) and `LogonUI.exe` (two `X-PRIV` pages). Assessment: runtimes that generate code; none was verified manually.
- Not measured: other Windows versions, 32-bit processes, guests with memory ballooning or huge pages, VBS-enabled guests, load on a busy host.

Second guest, 2026-11-24: Windows 11 Enterprise LTSC (build 26100.9974, 4 GiB RAM) on the same host, compared with a live scan run inside the same guest about 90 minutes earlier.

- 137 to 162 guest processes per run, 18 to 34 seconds, no read errors. The live scan could not open 17 processes (among them `lsass.exe`, `MsMpEng.exe`, `csrss.exe`, `services.exe`); the scan from the host read all of them.
- The first runs on this guest were wrong in both directions: no executable page was seen in any process of an ordinary user. Cause: kernel page-table isolation. Such a process has two sets of page tables, and in the kernel set the whole user half is marked no-execute. The scanner now reads the user set (`UserDirectoryTableBase`) when the process has one. On the first guest every flagged process was a system process with a single set, so the fault did not show.
- After the fix, of 14 processes flagged by the live scan, 12 were also flagged from the host. For `TrueConf.exe`, 87 of the 101 flagged region addresses of the live scan were found again; for `QtWebEngineProcess.exe` the findings were the same apart from `IMG-MOD`. `dwm.exe` (57 `X-PRIV` regions in the live scan) and `ShellExperienceHost.exe` were not flagged from the host; the cause was not established.
- With regions taken from the VAD tree (later the same day) the false positives of the earlier runs disappeared: of the 14 processes flagged by the live scan, 12 were flagged from the host with the same tags apart from `IMG-MOD` (for example `QtWebEngineProcess.exe`: `X-PRIV` 6 and `ENT-X` 3 in both), no process was flagged from the host that the live scan had examined and not flagged, and `MsMpEng.exe`, which the live scan cannot open, was read. Region counts of JIT-heavy processes differ between the two scans, taken eight hours apart.
- Counts are not comparable one to one: the live scan counts regions, the scan from the host counts runs of present pages, so one region can appear as many findings.

## Implementation notes

- Crate `nanshe-vm`. Guest physical memory and the Windows kernel are located with the [memflow](https://github.com/memflow/memflow) library (MIT); process listing and module lists come from it.
- Page tables are walked and guest memory is read by Nanshe itself (`walk_page_tables`, `leaf_entry`), including transition pages and entries whose address bits Windows inverts on processors affected by L1TF. memflow 0.2.4 combines the write bit of page-table levels with "or" instead of "and", which makes every page look writable and every code page `RWX`, and it does not translate transition pages.
- A process under kernel page-table isolation has a second set of page tables for user mode; its address is read from `_KPROCESS.UserDirectoryTableBase` (offset from the same symbol file) and used when present.
- The guest is untrusted input. The page walk is bounded by the number of tables read (`MAX_TABLES`) and by the number of page ranges per process (`MAX_RANGES`); when a limit is reached the result for the process is marked incomplete. Both limits are tested, together with unreadable and self-referencing tables.

## Roadmap for this feature

- Prototype pages (shared pages not yet touched by the process) and pages in the page file.
- Other hypervisors (Proxmox uses QEMU and is expected to work; Hyper-V and VMware need a different way to reach guest memory) and Linux guests.
