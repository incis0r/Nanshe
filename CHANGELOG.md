# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Analysis of process memory dumps: Linux core files (64-bit ELF) and Windows minidumps (`nanshe scan <dump-file>`).
- `IMG-MOD` compares modified code pages with the file on disk (PE relocations applied on Windows) and reports the number of differing bytes and the address of the first one; a private copy with unchanged contents is no longer reported.
- `HDR` recognises image headers whose signatures were wiped, by the PE section table or the ELF program header table.
- Sample modes `patch`, `touch`, `hdr-wiped`, `pe-wiped` and end-to-end tests for dumps.
- `nanshe vm <guest>`: scan of the processes of a running Windows guest from the KVM/QEMU host, without an agent in the guest (optional `vm` build feature, crate `nanshe-vm`). Kernel symbols are read from a local directory; the network is used only with `--fetch-symbols`. The QEMU process of a guest is accepted only when its program file, as reported by the kernel, is `qemu-system-*` or `qemu-kvm` in a system directory; the number of page tables and of page ranges read per guest process is limited. First version, measured on one Windows Server 2025 guest, see `docs/hypervisor.md`.
- Report: processes of the same program (same program file and name) with the same set of findings, priority and severity share one overview row ("+N" next to the PID) and one chapter ("and N similar"); repeated scanner notes are listed once.
- `scripts/build-linux-static.sh` (static musl binaries for x86_64 and aarch64) and `scripts/build-linux-vm.sh` (x86_64 binary with the `vm` feature).

### Changed

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
