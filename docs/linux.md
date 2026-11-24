# Nanshe on Linux

Polish version: [pl/linux.md](pl/linux.md).

Status: supported. The unit and end-to-end tests were verified on aarch64 in a Debian 12 container (`rust:1-slim-bookworm`). Full live scans (`nanshe scan --all` as root, static binary) were run on 20 hosts of one lab on 2026-11-23 (19 x86_64, 1 arm64); a run of the end-to-end test suite on x86_64 is not recorded in this documentation.

A running Windows guest of a KVM/QEMU host can be scanned from that Linux host: see [hypervisor.md](hypervisor.md).

## Build

On a host without Rust the build runs in a container (podman):

```sh
scripts/dev.sh cargo build --release -p nanshe-cli                 # without network code
scripts/dev.sh cargo build --release -p nanshe-cli --features llm  # with the LLM layer
```

On a host with Rust (stable, edition 2021) use the same `cargo` commands without `scripts/dev.sh`. Binary: `target/release/nanshe`. There are no dependencies on system libraries other than libc; the font of the PDF report is embedded.

Two more build scripts:

```sh
scripts/dev.sh sh scripts/build-linux-static.sh   # static musl binaries for x86_64 and aarch64 (default features), in dist/linux
scripts/build-linux-vm.sh                         # x86_64 binary with the vm feature (glibc 2.31 or newer), see hypervisor.md
```

## Privileges

The scan reads `/proc/<pid>/maps` and `/proc/<pid>/mem`. One of the following is enough:

- root,
- `CAP_SYS_PTRACE`,
- the same user as the target and `kernel.yama.ptrace_scope=0`.

The result and the report state the scanner's privileges (root, `CAP_SYS_PTRACE`); a scan without full privileges is marked in the report with a warning on the first page.

Without privileges the process is reported as inaccessible, and the result as partial (exit code 3 with `--all`, 2 with `--pid`). In a container `--cap-add SYS_PTRACE` is needed (`scripts/dev.sh` does this).

The scanner stops nothing and writes nothing to the target: it does not use `ptrace(PTRACE_ATTACH)`.

## Usage

```sh
nanshe ps
nanshe scan --pid 1234 --json wynik.json      # summary on stderr, result in the file
nanshe scan --all --min high                  # whole host, severity "high" only
nanshe report wynik.json                      # wynik.report.md and wynik.report.pdf
nanshe explain wynik.json --url http://127.0.0.1:11434   # LLM interpretation + report
```

Exit codes of `scan`: 0 no findings at or above the `--min` threshold, 1 there are findings, 2 error, 3 partial result without findings.

Kernel threads are skipped in the process list of `scan --all`: they have no user memory. They are recognised by the `PF_KTHREAD` flag in `/proc/<pid>/stat`, not by name, so a process that merely names itself like a kernel thread is scanned normally.

## Detectors that work on Linux

| Tag | Points | Condition |
|---|---|---|
| `RWX` | 30 | writable and executable region |
| `X-PRIV` | 30 | executable anonymous memory (not backed by a file), outside kernel regions (`[vdso]` etc.) |
| `MEMFD` | 40/10 | executable `memfd:` mapping; 10 for `memfd:libffi` in a process that maps the system `libffi` library (see "Reduced weights") |
| `DEL-EXEC` | 30/10 | executable mapping of a file deleted from disk; 10 for a file deleted from a package directory (see "Reduced weights") |
| `X-TMP` | 30 | executable mapping of an existing file from `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`, `/run/user/`, `/var/lock/`, `/run/lock/` or `/dev/mqueue/` |
| `ENT-X` | 20/30 | high entropy in an executable region; 10 when it is single pages in ordinary code from a file |
| `HDR` | 40/10 | ELF/PE/Mach-O header in a region not backed by a file: at the start of a page in any region, and in executable regions also at any offset (ELF, PE); in executable regions also a header with a wiped signature, recognised by the ELF program header table or the PE section table; 10 in guest memory of a QEMU process (see "Reduced weights") |
| `THR-PRIV` | 40 | a thread waiting in a system call whose call instruction lies in memory not backed by a file (outside kernel regions) |
| `IMG-MOD` | 40 | an executable, non-writable file mapping has pages modified in memory (the `Anonymous` field in `smaps` greater than zero) whose contents differ from the file, or could not be compared with it |

`X-MAP` and `GUARD-X` apply to Windows only.

`THR-PRIV` and `IMG-MOD` are not subject to the reduction for JIT runtimes. `THR-PRIV` reads `/proc/<pid>/task/<tid>/syscall`: a thread that was computing something at the moment of the scan (not waiting in the kernel) is not evaluated. `IMG-MOD` compares the modified pages with the mapped file (opened through `/proc/<pid>/map_files`) and states the number of differing bytes and the address of the first one; a private copy with unchanged contents is not reported. When the contents could not be compared, the finding says so.

### Reduced weights

Introduced after full scans of 20 Linux hosts of one lab (2026-11-23). Each rule lowers one measured benign class to 10 points ("info"), keeps the finding visible with a description that names the reason, and has a unit test with controls that keep the full weight. A finding reduced this way does not by itself give the process priority P1.

| Tag | Reduced to 10 when | Stays at full weight when |
|---|---|---|
| `DEL-EXEC` | the deleted file was in `/usr/`, `/lib/`, `/lib64/`, `/opt/`, `/bin/`, `/sbin/` or `/snap/`, and the program file of the process is verified (owned by root, not writable by group or others, the same file the scanner sees) and not deleted. Description: usually a library updated on disk, the process uses the old version until restarted | the file was elsewhere (for example `/tmp`, a home directory, `/var/lib`), the path contains `/../`, or the program file is not verified (for example a process in a container, which has its own `/usr`) or is itself deleted |
| `HDR` | the header is in a non-executable region of at least 16 MiB in a process whose verified program file in a system directory is `qemu-system-*` or `qemu-kvm`. Description: most likely virtual machine memory. One entry per region | executable region, smaller region, other programs including other QEMU tools (`qemu-img`) |
| `MEMFD` | the mapping is named `memfd:libffi` and the process has a verified program file in a system directory and maps `libffi.so*` from `/usr/lib/`, `/usr/lib64/`, `/lib/` or `/lib64/` | any other name, a process without the system `libffi`, an unverified program file |

The mapping name and the paths are chosen by the process itself, which is why every rule additionally requires a verified program file. Known risk, as with the JIT allowlist: code injected into a process that meets the conditions inherits the reduction.

## SHA-256 hashes

The scan computes file hashes and stores them in the `files` field of the result (`--no-hashes` turns this off):

- the program file of every process, read through `/proc/<pid>/exe` (also when deleted from disk),
- the files mapped in processes with findings of severity "suspicious" or above, read through `/proc/<pid>/map_files/`, that is the file actually mapped, also a deleted one or a `memfd`.

Reading `map_files` requires full root privileges. Without them (for example a container with only `CAP_SYS_PTRACE`) the scanner opens the file by path and records a note in the result that for a process in a container this may be a different file; `memfd` and deleted files cannot be hashed in that case. Every region with a finding additionally has a hash of its content (`sha256` in the region). File limit: 512 MiB.

## System context

For a process with a finding of severity "suspicious" or above, the scan additionally collects, by reading `/proc` only:

| What | Source |
|---|---|
| parent, thread count, start time | `/proc/<pid>/stat`, `btime` from `/proc/stat` |
| command line, working directory | `cmdline`, `cwd` |
| user | `Uid` from `status`; name according to the scanner's `/etc/passwd` |
| program file: size, modification time, owner, mode, SHA-256 | `/proc/<pid>/exe`, that is the file actually running, also when deleted from disk |
| security characteristics | `TracerPid`, `CapEff`, `Seccomp`, `NoNewPrivs`, a root directory other than `/`, the variables `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` |
| ancestors (up to 16) and children (up to 50) | a picture of `/proc` taken once per scan |
| open descriptors (up to 200) | `/proc/<pid>/fd` |
| TCP/UDP sockets (IPv4, IPv6) and Unix sockets | `/proc/<pid>/net/*` matched by the socket inode; tables from the namespace of the examined process |
| full region map | `/proc/<pid>/maps` (the same one the detectors worked on) |

The rest of the process environment is not collected. `nanshe scan --no-context` disables the whole context and the map.

Limitations: this is the state at the moment of the scan (closed connections and exited processes are not visible); the user name of a process in a container may come from a different database than the scanner's `/etc/passwd`; the start time assumes 100 clock ticks per second; IPv6 addresses assume a little-endian architecture. The command line and paths go into the result without filtering of secrets.

## JIT allowlist

It reduces (divides by 3) the severity of `RWX`, `X-PRIV` and `ENT-X` for known JIT runtimes: `node`, `java`, `dotnet`, `firefox`, `firefox-esr`, `chrome`, `chromium`, `msedge`, `brave`, `electron`, `code`, `pwsh`, `powershell`, `qemu-system-x86_64`, `luajit`, and since the scans of 20 Linux hosts also `apache2`, `httpd`, `php`, `php-fpm`, `gjs`, `gjs-console`, `gnome-shell`, `gnome-terminal-server`, `python`, `uwsgi`. The file name is compared exactly and also without a trailing version number (`python3.14`, `php-fpm8.2`). It applies only when the program file indicated by the kernel (`/proc/<pid>/exe`):

- is not deleted,
- is in `/usr/`, `/opt/`, `/bin/`, `/sbin/` or `/snap/`,
- is owned by root and is not writable by group or others,
- is the same file (device and inode) that the scanner sees.

The process name alone reduces nothing.

## Known limitations and blind spots

Each item below has a sample in `tests/samples` and an expectation in `scripts/e2e.sh`:

- **R-X from a file outside temporary directories**: `X-TMP` covers only a list of world-writable directories (the sample `rx-file` in `/tmp` is detected). The same payload from a home directory or `/run/user/` remains invisible.
- **`X-TMP` false positives**: programs that unpack native libraries into `/tmp` (for example JNI in Java, PyInstaller, AppImage) will produce the severity "suspicious". The scale was not measured; the detector is not covered by the allowlist.
- **ELF header with a corrupted field and no program header table** (`hdr-corrupt`): `HDR` does not react, `X-PRIV` remains. A header whose signature was wiped while the program header table remained is detected by `HDR` in executable regions (`hdr-wiped`).
- **Header off a page boundary in non-executable data** (for example a payload in an RW buffer on the heap before the permissions are changed): invisible. This is a deliberate limitation: the program loader keeps on the stack a copy of the header of every library it loads, so searching at any offset in data produced `HDR` in every process (verified on the `clean` sample). In executable regions a header at an offset is detected (`hdr-offset`).
- **RWX with low entropy** (`rwx-lowent`): 60 points instead of 90, without `ENT-X`.
- A process with more than 1 048 576 regions: the first regions up to the limit are scanned, the findings are kept, and the result for the process is marked as incomplete (partial result).
- A region larger than `--max-region-mib` (64 by default) is read partially and marked as such.
- Processes in a different mount namespace (containers): the allowlist and the reduced weights do not cover them (the program file is not the same file for the scanner). The same holds for a process whose program file was replaced on disk by an update.
- Dumps: single-process dumps (core files) are analysed with `nanshe scan <dump-file>`, see the [version documentation](documentation-0.1.0.md), chapter 4; physical memory dumps are not.

## LLM layer and report

Common to all systems: [README](../README.md) and the [version documentation](documentation-0.1.0.md). Tests: [tests.md](tests.md).
