# Reading a Windows guest from the KVM host

Polish version: [pl/hiperwizor.md](pl/hiperwizor.md).

`nanshe vm` scans the processes of a running Windows virtual machine from the Linux host that runs it under KVM/QEMU. Nothing is installed or started inside the guest. The scanner reads the memory of the QEMU process on the host, finds the Windows kernel in it and walks the page tables of every guest process. The same detectors and the same report are used as for a live scan.

State: first version (0.4 preview). Measured on one guest so far; see "What was measured".

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

After opening the guest, the scanner checks that the process list contains the `System` process with PID 4. If it does not, the symbols do not match the kernel and the scan stops, instead of returning an empty or wrong result.

## What the result contains and what it does not

| | Live scan inside Windows | Scan from the host |
|---|---|---|
| Protected processes (LSASS, antivirus) | not accessible | scanned |
| Region list | from the memory manager (all reserved and committed regions) | from page tables: only pages present in physical memory |
| Region protection | as set by the process | effective protection from the page tables, combined across levels as the processor does |
| Region type | private, mapped, image | image if inside a module of the process, otherwise private; unknown if the module list cannot be read |
| Files mapped as data | known, with path | not distinguishable from private memory |
| Comparison of code with the file on disk (`IMG-MOD`) | yes | no (the host does not see the guest's files) |
| Threads, network, open files, process tree | yes | no |
| Reduced weight for just-in-time runtimes | yes | no (the program file cannot be verified from the host) |

Consequences worth knowing before reading a report:

- **Pages swapped out are not seen.** A region can be shorter than in a live scan, or missing.
- **The guest keeps running during the scan,** so the result is not a consistent snapshot.
- **`HDR` is reported only in executable regions.** Files mapped as data start with an image header and cannot be told apart from private memory; on the measured guest this produced 466 such regions before the rule was added. A header in non-executable private memory is therefore not reported in this mode.
- **One page after each module is counted as part of it.** Windows Server 2025 maps one extra code page right after every image. A module's extent is its image size plus one page, rounded up to the 64 KiB allocation boundary. When an image ends exactly on a 64 KiB boundary, a separate one-page allocation placed right after it would not be distinguished.
- **Processes without a module list** (`System`, `Secure System`, `Registry`, and processes whose loader data is swapped out) have regions of unknown type: code without a file is not detected in them, and the report says so.
- Just-in-time runtimes (.NET, antivirus engines) appear with full weight, as in a dump.

## What was measured

One guest, 2026-11-23: Windows Server 2025 domain controller (4 GiB RAM) on a Rocky Linux 9.8 host, QEMU started by libvirt.

- 96 guest processes listed and scanned in 9 seconds, 1.8 GiB read, guest running throughout.
- All processes were readable, including `lsass.exe`, `MsMpEng.exe`, `csrss.exe` and `LsaIso.exe`.
- 3 processes at `suspicious` or above: `Microsoft.ActiveDirectory.WebServices.exe` (.NET, `RWX` and `X-PRIV`), `MsMpEng.exe` (`RWX` and `X-PRIV`) and `LogonUI.exe` (two `X-PRIV` pages). Assessment: runtimes that generate code; none was verified manually.
- Not measured: other Windows versions, 32-bit processes, guests with memory ballooning or huge pages, VBS-enabled guests, load on a busy host.

## Implementation notes

- Crate `nanshe-vm`. Guest physical memory and the Windows kernel are located with the [memflow](https://github.com/memflow/memflow) library (MIT); process listing and module lists come from it.
- Page tables are walked by Nanshe itself (`walk_page_tables`). memflow 0.2.4 combines the write bit of page-table levels with "or" instead of "and", which makes every page look writable and every code page `RWX`.
- The guest is untrusted input. The page walk is bounded by the number of tables read (`MAX_TABLES`) and by the number of page ranges per process (`MAX_RANGES`); when a limit is reached the result for the process is marked incomplete. Both limits are tested, together with unreadable and self-referencing tables.

## Roadmap for this feature

- Region list from the kernel's VAD tree (true region types, file names of mapped files, reserved regions).
- Transition and prototype pages (present in physical memory but not marked present in the page tables).
- Other hypervisors (Proxmox uses QEMU and is expected to work; Hyper-V and VMware need a different way to reach guest memory) and Linux guests.
