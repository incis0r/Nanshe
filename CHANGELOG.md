# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Detector `SHC`: code patterns typical of shellcode (finding its own address, direct system calls, known loader-stage prologues, reading the PEB, function-name hashing, copies of the kernel entry outside `ntdll`) in executable memory that does not come from a file on disk. Tuned on 20 Linux hosts, two Windows guests and a macOS workstation; see the detector tables in `docs/linux.md` and `docs/windows.md`.
- `nanshe vm`: reduced weight for just-in-time runtimes on kernel evidence (runtime library and main program are images on the guest's system volume, in their installation directories).
- Windows x64: call stacks of threads waiting in the kernel are unwound from the exception tables in the process memory; a stack that returns to memory not backed by a file gives `THR-PRIV` (executable memory: a taken-over thread; non-executable memory: code hidden while sleeping). Threads are not suspended. New samples `stack-rx` and `stack-masked`, fuzz target `unwind`.
- Windows: `X-TMP` also reports the code of a module image loaded from a temporary or public directory (`%TEMP%`, `C:\Windows\Temp`, `C:\Users\Public`, the recycle bin), which closes the documented `ximage` blind spot.
- Stack unwinding coverage in the result (field `stacks` per process) and in the report: threads read and not read, waiting, unwound to the bottom, returning outside modules, abandoned with the reason. Measured on the test host: 1773 of 1815 waiting threads unwound to the bottom, none abandoned.
- Thread call stacks are also unwound for minidumps (registers from the `ThreadList` stream) and for guests read from the hypervisor (registers from the trap frames of waiting threads in the guest kernel; only `rsp` and `rbp` are known there, and a frame that needs another register is given up).
- `nanshe vm`: pages of shared regions that the process does not have in its own page tables are read through the kernel's prototype page entries when they are in physical memory.
- Every region with a finding carries its reservation (`allocation`: base, size, number of regions) on Windows; recorded for analysis, not used by the score. The measurement is in `docs/windows.md`.
- Knowledge base: verification steps for `SHC` on Linux, Windows and macOS (disassembling the code at the address from the finding, strings, `pe-sieve`), descriptions of the sets `SHC+X-PRIV`, `RWX+SHC+X-PRIV`, `X-MAP+SHC` (Windows) and `MEMFD+SHC` (Linux).
- Report: applications built on the Chromium engine (Electron, Qt WebEngine, CEF) and programs that use WebView2 are recognised by the engine files mapped into memory. A program with an unknown name gets a description of its kind, and a process without the engine file takes the recognised runtime from another process of the same program file, with that process named. This changes the verification priority and the explanations, not the score. Limits are in `docs/knowledge-base.md`.
- Knowledge base, macOS: verification steps for `X-PRIV`, `ENT-X` and `SHC`, a description of `ENT-X` on code loaded from a file, descriptions of Steam, GnuPG, Node.js and Python processes and of cryptographic libraries.
- Knowledge base, Windows: descriptions of shell and service processes (`dwm.exe`, `logonui.exe`, `searchhost.exe`, `startmenuexperiencehost.exe`, `securityhealthservice.exe`, `spoolsv.exe`, `wmiprvse.exe`, `searchindexer.exe`, `fontdrvhost.exe`, `audiodg.exe`, `smartscreen.exe`, Active Directory Web Services and others) with their typical location and parent process, descriptions of interpreters (`python.exe`, `node.exe`, `java.exe`) and of common VPN, virtualisation and scanner software; a description of the set `ENT-X+IMG-MOD`.
- Fuzz targets for the Windows system tables, the handling of model responses and the report generator.
- macOS: process context (parents, children, user, start time, threads, command line), code signature state and notable entitlements in the result; reduced weight for JIT regions when the kernel-checked signature is valid, has a hardened runtime, the `allow-jit` entitlement and a publisher identity (a locally signed program gets none).

### Fixed

- Windows: threads that have already exited (their objects stay on the thread list while someone holds a handle) were counted as threads whose registers could not be read. They have no stack to examine and are no longer counted, so `unread` now shows real gaps in stack coverage.
- Knowledge base: the `pe-sieve` step for `SHC` named an option that does not exist (`/dump_mode`); the step now uses `/shellc 1` alone and describes the summary lines and the output directory as the tool prints them. The `objdump` step uses Intel syntax so that the output matches the description.
- Report: a JIT runtime recognised only in another process of the same program file no longer lowers the priority of a process that has an `SHC` finding of weight 30 or more; such a process gets P1.
- Knowledge base, macOS: process and library names written with capital letters (`WindowServer`, `Finder`, `JavaScriptCore`, `Electron Framework`, `Chromium Embedded Framework`) never matched, because lookups compare lower-cased text, and the expected location of the Spotlight processes never matched either. An application built on the Chromium Embedded Framework was therefore reported as a process without a known runtime (priority P1 instead of P2). A test now rejects such entries.
- Terminal output: control characters in text that comes from the scanned host or from a model (process names, paths, descriptions, error messages) are removed before printing, so a process name with an escape sequence cannot drive the terminal of the person reading the scan summary, `nanshe ps`, `nanshe vm --ps` or the `explain` printout.
- `nanshe vm`: the cache of page tables is bounded for every reader, including the reads of kernel structures.
- `nanshe vm`: physical reads are limited to the guest's memory size. An invalid page entry carries an extra high address bit, and for such an address the memory library returned success and zeros, so transition pages could be read as empty pages.

### Changed

- Printed summary of `scan` and `vm`: processes are ordered from the highest severity, regions with the same tags, permissions, score and source share one line, inaccessible processes are collected by cause, tag descriptions are printed once, sizes are given in KiB or MiB. New options: `--regions` (every region on its own line with entropy and descriptions) and `--color auto|always|never` (colours for a dark background, on a terminal only; `NO_COLOR` is honoured). The JSON result is unchanged; scripts that parsed the old text have to be adapted.
- English output is complete for the printed messages of `map`, `formats`, `explain`, `llm` and `cloud`, and the scan summary no longer prints the Polish abbreviation of "score".
- Windows: the message for a process that cannot be opened no longer repeats "access denied" after the error kind.
- `nanshe formats` lists the macOS live source and the `SHC` detector.
- `nanshe vm`: an executable page that no VAD entry describes is examined as private memory, and an image whose file cannot be named as a mapping without a file; kernel structures are read through Nanshe's own address translation, including transition pages.
- Fuzzing: the `pagetables` target runs the page walk with a limit of 128 tables instead of the scanner's limit. Inputs with a table that points at itself made every execution read more than a hundred thousand tables, which slowed the target down to about 70 executions per second; it now does about 4700. `walk_page_tables_limited` takes the limit as a parameter.

## [0.2.0] - 2026-11-24

Second release. Adds process dumps, a differential report, English output, the MSI installer, a first version of reading Windows guests from the KVM host, a first version of macOS live scanning and fuzzing of the parsers of untrusted data. The features marked "first version" are described with their measured limits in `docs/hypervisor.md` and `docs/macos.md`.

### Added

- Analysis of process memory dumps: Linux core files (64-bit ELF) and Windows minidumps (`nanshe scan <dump-file>`).
- `IMG-MOD` compares modified code pages with the file on disk (PE relocations applied on Windows) and reports the number of differing bytes and the address of the first one; a private copy with unchanged contents is no longer reported.
- `HDR` recognises image headers whose signatures were wiped, by the PE section table or the ELF program header table.
- Sample modes `patch`, `touch`, `hdr-wiped`, `pe-wiped` and end-to-end tests for dumps.
- `nanshe vm <guest>`: scan of the processes of a running Windows guest from the KVM/QEMU host, without an agent in the guest (optional `vm` build feature, crate `nanshe-vm`). Kernel symbols are read from a local directory; the network is used only with `--fetch-symbols`. The QEMU process of a guest is accepted only when its program file, as reported by the kernel, is `qemu-system-*` or `qemu-kvm` in a system directory; the number of page tables and of page ranges read per guest process is limited. First version, measured on one Windows Server 2025 guest, see `docs/hypervisor.md`. Region borders, types and file names come from the kernel VAD tree; protection comes from page tables read by Nanshe itself, including the user-mode tables of processes under kernel page-table isolation and transition pages.
- macOS: first version of live process scanning (region map and contents through Mach interfaces, recognition of the system library cache, `RWX`, `X-PRIV`, `ENT-X` and `HDR`), a macOS knowledge base with verification steps, samples and `scripts/e2e-macos.sh`. Access follows what macOS allows; see `docs/macos.md`. The memory map (`nanshe map`) works on macOS as well.
- Fuzzing of the parsers of untrusted data (`fuzz/`, `scripts/fuzz.sh`): process dumps, PE comparison, guest page tables, the Linux `maps` parser and the detectors; a short run of every target in CI.
- Report: processes of the same program (same program file and name) with the same set of findings, priority and severity share one overview row ("+N" next to the PID) and one chapter ("and N similar"); repeated scanner notes are listed once.
- `nanshe vm` validates the symbol file name and identifier reported by the guest before using them in a path, and selects a guest by name only among QEMU processes started by a system account.
- Linux: a program file counts as verified only for a process in the same user namespace as the scanner (a process in its own user namespace can build a private file system view without privileges), and the `memfd:libffi` reduction applies only to regions shaped like libffi trampoline tables (at most 64 KiB, not writable, low entropy, read in full).
- `nanshe vm` reads page protection from the user-mode page tables of processes under kernel page-table isolation; before, no executable page was seen in processes of ordinary users. Found by comparing with a live scan of the same guest.
- `scripts/build-linux-static.sh` (static musl binaries for x86_64 and aarch64) and `scripts/build-linux-vm.sh` (x86_64 binary with the `vm` feature).

### Changed

- `nanshe-vm`: the guest-reading code and the memflow libraries are behind the crate feature `guest` (enabled by the `vm` feature of the command-line tool); the page-table logic builds without them.
- HTTP client `ureq` updated from 2 to 3; the interpretation layer keeps the same behaviour (time limits, no redirects for cloud providers, the start of an error response in the message).
- Report: table-of-contents entries and finding rows of the address space map are links; command lines and verification commands are set off as code; priority and severity are colour-coded; verification steps explain how to read the result; model hypotheses show supporting and undermining arguments side by side; clearer confidence labels.
- Knowledge base: verification steps are objects with `do`, `cmd` and `look`.
- Detection tuning from full scans of 20 Linux hosts (processes to verify fell from 455 to 191, with no host change in between other than time):
  - `DEL-EXEC` for files deleted from package directories (`/usr`, `/lib`, `/lib64`, `/opt`, `/bin`, `/sbin`, `/snap`) has weight 10 and says that the library was updated and the process needs a restart, but only in a process whose own program file is verified and not deleted (a process in a container has its own `/usr`); otherwise, and for other deleted files, the weight stays 30.
  - `HDR` in a large (16 MiB or more) non-executable data region of a process whose verified program file is `qemu-system-*` or `qemu-kvm` is described as virtual machine memory (weight 10, one entry per region). Other QEMU tools, small regions and executable regions keep weight 40.
  - `MEMFD` named `memfd:libffi` in a process with a verified program file that maps the system `libffi` library has weight 10.
  - More just-in-time runtimes are recognised on Linux (`apache2`, `httpd`, `php`, `php-fpm`, `gjs`, `gjs-console`, `gnome-shell`, `gnome-terminal-server`, `python`, `uwsgi`), also when the file name carries a version number (`python3.14`). As before, only for a verified program file in a system directory.
  - A finding whose weight a detector has reduced (below 30) no longer forces the highest priority (P1).
  - For a source read from the hypervisor (`source_type` "vm"), `HDR` is reported only in executable regions.

### Fixed

- `nanshe vm`: a module address near the end of the number range, read from guest memory, overflowed the rounding of module extents and produced wrong module borders (found by fuzzing).
- Core files: a hostile file could make the scanner parse the same note block tens of thousands of times and grow its thread and file lists without bound (CPU and memory exhaustion from a 64 MiB file). Note blocks are now read once per file offset, all note blocks share one byte budget per file, and list limits are applied while the lists are built.
- End-to-end tests on Linux no longer depend on the architecture they were tuned on: tags that even the clean sample has on a platform are measured first and added to the expectations.
- Report: fields of a PE header located near the end of the 256-byte preview are now shown.
- Linux: kernel threads (recognised by the `PF_KTHREAD` flag, not by name) are skipped in the process list and no longer counted as inaccessible processes.

## [0.1.0] - 2026-11-23

First public release.

### Added

- Live process scanning on Linux (`/proc`) and Windows (Windows API), read-only.
- Eleven detectors: `RWX`, `X-PRIV`, `X-MAP`, `GUARD-X`, `MEMFD`, `DEL-EXEC`, `X-TMP`, `ENT-X`, `HDR`, `THR-PRIV`, `IMG-MOD`; scoring with reduced weight for recognised just-in-time runtimes.
- System context for flagged processes: command line, user, process tree, sockets, open files and handles, mapped files, SHA-256 hashes.
- Report in Markdown and PDF: executive summary, verification priority (P1 to P3), explanations from a knowledge base, address space map, process tree, memory-to-network diagram, table of contents.
- Differential report of two scans (`nanshe diff`).
- Polish and English output (`--lang pl|en`).
- Optional language-model interpretation (`nanshe explain`): local Ollama, cloud providers with explicit consent, data levels, secret filter, pseudonymisation.
- Interactive memory map (`nanshe map`).
- Windows installers: MSI and a zip package with a PowerShell installer.
