# Nanshe on Linux

Polish version: [pl/linux.md](pl/linux.md).

Status: supported. Verified on aarch64 in a Debian 12 container (`rust:1-slim-bookworm`). Linux x86_64: not verified yet.

## Build

On a host without Rust the build runs in a container (podman):

```sh
scripts/dev.sh cargo build --release -p nanshe-cli                 # without network code
scripts/dev.sh cargo build --release -p nanshe-cli --features llm  # with the LLM layer
```

On a host with Rust (stable, edition 2021) use the same `cargo` commands without `scripts/dev.sh`. Binary: `target/release/nanshe`. There are no dependencies on system libraries other than libc; the font of the PDF report is embedded.

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

## Detectors that work on Linux

| Tag | Points | Condition |
|---|---|---|
| `RWX` | 30 | writable and executable region |
| `X-PRIV` | 30 | executable anonymous memory (not backed by a file), outside kernel regions (`[vdso]` etc.) |
| `MEMFD` | 40 | executable `memfd:` mapping |
| `DEL-EXEC` | 30 | executable mapping of a file deleted from disk |
| `X-TMP` | 30 | executable mapping of an existing file from `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`, `/run/user/`, `/var/lock/`, `/run/lock/` or `/dev/mqueue/` |
| `ENT-X` | 20/30 | high entropy in an executable region; 10 when it is single pages in ordinary code from a file |
| `HDR` | 40 | ELF/PE/Mach-O header in a region not backed by a file: at the start of a page in any region, and in executable regions also at any offset (ELF, PE) |
| `THR-PRIV` | 40 | a thread waiting in a system call whose call instruction lies in memory not backed by a file (outside kernel regions) |
| `IMG-MOD` | 40 | an executable, non-writable file mapping has pages modified in memory (the `Anonymous` field in `smaps` greater than zero) |

`X-MAP` and `GUARD-X` apply to Windows only.

`THR-PRIV` and `IMG-MOD` are not subject to the reduction for JIT runtimes. `THR-PRIV` reads `/proc/<pid>/task/<tid>/syscall`: a thread that was computing something at the moment of the scan (not waiting in the kernel) is not evaluated. `IMG-MOD` says that the code was changed, but shows neither the differences nor the exact page.

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

It reduces (divides by 3) the severity of `RWX`, `X-PRIV` and `ENT-X` for known JIT runtimes. It applies only when the program file indicated by the kernel (`/proc/<pid>/exe`):

- is not deleted,
- is in `/usr/`, `/opt/`, `/bin/`, `/sbin/` or `/snap/`,
- is owned by root and is not writable by group or others,
- is the same file (device and inode) that the scanner sees.

The process name alone reduces nothing.

## Known limitations and blind spots

Each item below has a sample in `tests/samples` and an expectation in `scripts/e2e.sh`:

- **R-X from a file outside temporary directories**: `X-TMP` covers only a list of world-writable directories (the sample `rx-file` in `/tmp` is detected). The same payload from a home directory or `/run/user/` remains invisible.
- **`X-TMP` false positives**: programs that unpack native libraries into `/tmp` (for example JNI in Java, PyInstaller, AppImage) will produce the severity "suspicious". The scale was not measured; the detector is not covered by the allowlist.
- **ELF header with a corrupted field** (`hdr-corrupt`): `HDR` does not react, `X-PRIV` remains. Wiped signatures (stomping) are the planned `HDR-STRIP` detector.
- **Header off a page boundary in non-executable data** (for example a payload in an RW buffer on the heap before the permissions are changed): invisible. This is a deliberate limitation: the program loader keeps on the stack a copy of the header of every library it loads, so searching at any offset in data produced `HDR` in every process (verified on the `clean` sample). In executable regions a header at an offset is detected (`hdr-offset`).
- **RWX with low entropy** (`rwx-lowent`): 60 points instead of 90, without `ENT-X`.
- A process with more than 1 048 576 regions: the first regions up to the limit are scanned, the findings are kept, and the result for the process is marked as incomplete (partial result).
- A region larger than `--max-region-mib` (64 by default) is read partially and marked as such.
- Processes in a different mount namespace: the allowlist does not cover them (the program file is not the same file for the scanner).
- No dump analysis (stage M2).

## LLM layer and report

Common to all systems: [README](../README.md) and the [version documentation](documentation-0.1.0.md). Tests: [tests.md](tests.md).
