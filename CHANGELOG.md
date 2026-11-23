# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Analysis of process memory dumps: Linux core files (64-bit ELF) and Windows minidumps (`nanshe scan <dump-file>`).
- `IMG-MOD` compares modified code pages with the file on disk (PE relocations applied on Windows) and reports the number of differing bytes and the address of the first one; a private copy with unchanged contents is no longer reported.
- `HDR` recognises image headers whose signatures were wiped, by the PE section table or the ELF program header table.
- Sample modes `patch`, `touch`, `hdr-wiped`, `pe-wiped` and end-to-end tests for dumps.

### Fixed

- Report: fields of a PE header located near the end of the 256-byte preview are now shown.

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
