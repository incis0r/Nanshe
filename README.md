<p align="center"><img src="img/logo/nanshe-logo.svg" alt="Nanshe" width="420"></p>

# Nanshe

Memory triage for live processes on Linux and Windows. Nanshe scans process memory, flags regions a human analyst should look at, and produces a self-contained report (Markdown and PDF) that explains each finding in plain language.

It is a triage tool, not a verdict engine: every finding is a hypothesis to verify, and the report says so.

Polish version of this file: [README.pl.md](README.pl.md).

## What it does

- **Detects** memory regions that are unusual for ordinary software: writable and executable memory, executable memory not backed by a file, high-entropy code, program images loaded without the OS loader, threads running from unbacked memory, modified library code, and more (11 detectors).
- **Collects context** for flagged processes: command line, user, parent chain, network sockets, open files and handles, mapped files, SHA-256 hashes.
- **Explains** each finding from a built-in knowledge base: what it means, benign and malicious explanations, how to verify it, related MITRE ATT&CK techniques.
- **Prioritises** processes (P1 to P3) with a stated rationale and a first step, and opens the report with an executive summary.
- **Compares** two scans of the same host (`nanshe diff`): new regions in running processes, new and exited processes, changes in sockets and mapped files.
- **Optionally interprets** findings with a language model (local Ollama by default; cloud only with explicit consent and reduced data).
- Works in **Polish and English** (`--lang pl|en`).

The scanner is read-only: it does not inject code, load drivers or modify the examined processes.

## Quick start

```sh
nanshe ps
nanshe scan --all --json result.json           # needs root (Linux) or an elevated administrator (Windows)
nanshe report result.json                      # result.report.md + result.report.pdf
nanshe --lang en scan --pid 1234 --json r.json # English descriptions and report
nanshe diff earlier.json later.json            # differential report
```

Exit codes of `scan`: 0 no findings at or above the threshold, 1 findings, 2 error, 3 partial result without findings.

The result file and the report contain unfiltered data from the examined host (command lines, paths, network addresses, bytes from memory). Treat them as evidence. `--no-bytes` omits byte previews and strings.

Example reports from a synthetic test sample: [docs/przyklady/](docs/przyklady/) (English: [docs/przyklady/en/](docs/przyklady/en/)).

## Language model layer (optional)

```sh
nanshe explain result.json --dry-run                       # shows exactly what would be sent
nanshe explain result.json --model gemma3:12b              # local Ollama
nanshe explain result.json --llm anthropic --allow-cloud   # cloud: explicit consent required
```

The model never changes scores or severity. Cloud providers receive metadata only by default (level `d0`); raw bytes never leave the host. Host names, user names in paths and IP addresses are replaced with labels before sending. Build with `--features llm` to include this layer; the default build contains no network code.

## Build and test

Linux (container, podman or docker):

```sh
scripts/dev.sh cargo test --workspace --features nanshe-cli/llm   # unit tests
scripts/dev.sh sh scripts/e2e.sh                                  # end-to-end: samples -> live scan
scripts/dev.sh cargo build --release -p nanshe-cli --features llm
```

Windows (native MSVC toolchain, elevated PowerShell):

```powershell
cargo build --release -p nanshe-cli -p nanshe-samples --features nanshe-cli/llm
powershell -ExecutionPolicy Bypass -File scripts\e2e.ps1 -Bin target\release -Out e2e-out
```

Windows packages: `scripts\package-msi.ps1` (MSI, WiX Toolset 3.14) and `scripts\package-windows.ps1` (zip with a PowerShell installer). See [docs/windows.md](docs/windows.md).

The Windows end-to-end and installer tests change the machine they run on (they start test samples, install and uninstall the product). Run them only on a dedicated test host.

## Documentation

The detailed documentation is currently in Polish:

- [docs/dokumentacja-0.1.0.md](docs/dokumentacja-0.1.0.md): full description of version 0.1.0 (capabilities, architecture, detectors, result file, report, security of the tool, what was tested, known limitations)
- [docs/linux.md](docs/linux.md), [docs/windows.md](docs/windows.md), [docs/macos.md](docs/macos.md): build, privileges, detectors and limitations per system
- [docs/baza-wiedzy.md](docs/baza-wiedzy.md): the knowledge base (`kb/`) and how to extend it
- [docs/testy.md](docs/testy.md): all tests, what they check and what they do not cover

## Known limitations

- Processes protected by the operating system (for example LSASS and anti-malware processes on Windows) and kernel memory are not examined.
- A scan is the state of memory at one moment; anything that happened before it is not visible.
- All test samples are synthetic. False-positive rates were measured on a single Windows host and on Linux containers only.
- macOS and FreeBSD are not supported yet. Memory dumps are not analysed yet.
- Binaries and installers are not digitally signed.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md); please do not open a public issue for security problems.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 HoneyLens.

The PDF report embeds the DejaVu fonts under their own license ([LICENSE-DejaVu.txt](crates/nanshe-report/fonts/LICENSE-DejaVu.txt)).
