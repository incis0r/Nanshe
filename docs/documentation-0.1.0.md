# Nanshe 0.1.0: documentation of the initial version

Polish version: [pl/dokumentacja-0.1.0.md](pl/dokumentacja-0.1.0.md).

As of 2026-11-22. This document describes what this version does, how it is built, what has been verified and what it cannot do. Details for the individual systems are in [linux.md](linux.md), [windows.md](windows.md) and [macos.md](macos.md), the description of the tests in [tests.md](tests.md) and the knowledge base in [knowledge-base.md](knowledge-base.md).

## 1. What it is for

Nanshe is a tool for memory triage of running processes. It points out memory regions that look unusual (code not backed by a file, writable code, code that looks encrypted, a program hidden in memory, a running thread in memory not backed by a file, modified library code), collects system context around them and assembles a report for an analyst from this.

What it is not:

- It does not issue an "infected / clean" verdict. Every finding is a question to be checked.
- It does not remove or block anything. It does not change the examined system (the exceptions are described in section 10).
- It does not replace a full analysis of a memory dump: it does not read kernel memory or protected processes.

## 2. What this version can do

| Area | Status |
|---|---|
| Scan of live processes | Linux and Windows; macOS and FreeBSD have no scan backend |
| Memory dump analysis | dumps of single processes: core file (Linux, 64-bit ELF) and minidump (Windows); physical memory dumps: none (planned) |
| Detectors | 11 tags: `RWX`, `X-PRIV`, `X-MAP`, `GUARD-X`, `MEMFD`, `DEL-EXEC`, `X-TMP`, `ENT-X`, `HDR`, `THR-PRIV`, `IMG-MOD` |
| System context | parents and children, command line, user, program file, sockets, open files and handles, security attributes |
| SHA-256 hashes | program files of all processes, files mapped in processes with findings, region contents |
| Interpretation by a language model | locally (Ollama) or in the cloud (Nous, Anthropic, Google, OpenAI) |
| Report | Markdown and PDF, with diagrams and explanations from the knowledge base |
| Memory map in the browser | `nanshe map` (inventory of metadata, without reading contents) |
| Installer | MSI package and a zip package with a PowerShell installer for Windows |

## 3. Architecture

The project is written in Rust and divided into eight crates (about 8,100 lines of code including tests):

| Crate | Role | Lines |
|---|---|---|
| `nanshe-core` | shared types: region, finding, scan result, process context; memory source interface | 446 |
| `nanshe-analyze` | entropy, detectors, scoring, reduction for JIT runtimes | 1,035 |
| `nanshe-live` | reading live processes: Linux (`/proc`), Windows (system API); system context; file hashes; comparison of code with the file on disk | 1,744 |
| `nanshe-dump` | process memory dumps as a source: ELF core file and Windows minidump | (new) |
| `nanshe-kb` | knowledge base for the report (content in `kb/*.json`) | 371 |
| `nanshe-report` | report model, Markdown, PDF written without external programs, memory map page | 2,227 |
| `nanshe-llm` | model layer: data selection, filters, pseudonymisation, providers, response validation | 1,749 |
| `nanshe-cli` | the `nanshe` program | 519 |
| `nanshe-samples` | the `nanshe-sample` program: harmless samples for tests | (not in the total) |

Design rules:

- **Detectors see only an abstraction.** The analysis works on the "memory source" interface (regions, reading, threads, modified code), not on the system. Thanks to this, the same detectors will work on dumps once such a backend is added.
- **Unsafe code in one place.** `unsafe` is present only in the Windows module of the `nanshe-live` crate (system API calls) and in the test samples; the other crates forbid it.
- **Network code only in the model layer.** A build without the `llm` feature contains no network code at all.
- **Deterministic result.** Two scans of the same state produce the same file (apart from the timestamp). The language model changes nothing in the scan result.
- **A partial result instead of none.** A region read error or an inaccessible process does not abort the scan; the result is marked as partial.

Data flow:

```text
process -> nanshe scan -> wynik.json -> nanshe report  -> wynik.report.md, wynik.report.pdf
                              |
                              +------> nanshe explain -> wynik.llm.json -> (report with interpretation)
```

## 4. Commands

| Command | What it does |
|---|---|
| `nanshe scan --pid N` | scan of one process |
| `nanshe scan --all` | scan of all accessible processes (except the scanner itself) |
| `nanshe scan dump-file` | analysis of a process memory dump with the same detectors |
| `nanshe report wynik.json` | Markdown and PDF report |
| `nanshe diff wczesniej.json pozniej.json` | differential report: what changed between two scans of the same host |
| `nanshe explain wynik.json` | interpretation by a language model, then the report |
| `nanshe map` | interactive memory map in the browser (metadata only) |
| `nanshe ps` | list of processes |
| `nanshe formats` | supported sources, detectors, state of the model layer |
| `nanshe llm check` | connectivity test with the model, without scan data |
| `nanshe cloud list providers` / `models` | built-in cloud providers and their models |

The most important `scan` options:

| Option | Meaning |
|---|---|
| `--json plik` | full result to a file (`-` means standard output) |
| `--min info\|suspicious\|high` | threshold for printing and for the exit code (default `suspicious`) |
| `--no-bytes` | without the byte preview and text strings in the result |
| `--no-context` | without system context and the full region map |
| `--no-hashes` | without file hashes |
| `--max-region-mib N` | read limit for one region (default 64) |
| `--heatmap` | entropy map of all regions that were read |

`scan` exit codes: 0 no findings at or above the threshold, 1 there are findings, 2 error, 3 partial result without findings.

The most important `report` options: `--llm plik` or `--no-llm`, `--md`, `--pdf`, `--min`, `--kb katalog` (your own knowledge base).

### Process memory dumps: `nanshe scan <file>`

`nanshe scan dump-file --json result.json` analyses a memory dump of a single process with the same detectors as a live scan. The format is recognised by the file signature.

| Format | How it is produced | What it contains |
|---|---|---|
| core file (64-bit ELF, x86_64 and aarch64) | `gcore <pid>` from the gdb package, or a kernel crash dump | regions with permissions, memory contents, names of mapped files, thread registers, the name and the start of the command line |
| minidump with full memory | Task Manager ("Create dump file"), `procdump -ma`, the `MiniDumpWriteDump` function | regions with permissions and type, memory contents, modules, thread start addresses |

Differences from a live scan:

- There is no system context (network, open files, process tree): a dump does not contain it. The report omits those parts and states that the source is a dump.
- The severity reduction for JIT runtimes is not applied, because the program file cannot be verified; a process with the .NET runtime or a browser will yield more findings than in a live scan.
- `IMG-MOD` does not work (there is nothing to compare the code with).
- A minidump has no file names for mappings other than modules. A core file written by the kernel usually does not contain unmodified file-backed code; content detectors cannot examine such regions, and the result records this.
- In a core file the vdso region (code supplied by the kernel) is recognised through the auxiliary vector and is not reported as a program without a file.

A dump file is untrusted data: every offset and every number from the headers is checked against the file length, entry counts are limited, and memory contents are read from the file only on demand. Dumping a protected process (for example LSASS) requires a tool that can do it; Nanshe does not include such a tool.

### Differential report: `nanshe diff`

`nanshe diff wczesniej.json pozniej.json` compares two scan results of the same host and writes a Markdown and PDF report (by default `<later result>.diff.md` and `.diff.pdf`; options `--md`, `--pdf`, `--min`). It answers the question "what has changed since the previous scan":

| Part | What it shows |
|---|---|
| Summary of changes | overall assessment and counts: new regions in running processes, new processes with findings, processes with changes, processes that disappeared, processes without changes |
| Changes in running processes | for a process present in both scans: regions that are new, changed (tags, score, permissions, size, content), that disappeared or fell below the threshold; outside memory: new and closed sockets, child processes, mapped files, a change of the program file hash |
| New processes with findings | processes that were not there before |
| Processes that disappeared | processes with findings that are absent from the later scan |
| Limitations of the comparison | the matching rules and what the comparison does not see |

The most important signal is a new region with a finding in a process that was already running at the earlier scan: code appeared while the process was running. It also has benign causes (JIT runtimes), so the report calls it a signal to verify, not evidence.

Rules: a process is "the same" when the PID, name, program file and start time match (a PID can be reused); regions are matched by start address; a change of content is detected by the SHA-256 hash of the region. The report warns when the results come from different hosts, when the system was restarted between the scans, when the scans were run with different privileges or when the files were given in reverse order. The comparison does not re-score anything and does not use a language model.

### Language: `--lang pl|en`

The `--lang` option (or the `NANSHE_LANG` variable) works for all commands and selects the language of the texts intended for a human:

| Command | What `--lang` changes |
|---|---|
| `scan` | descriptions stored in the result: finding rationales, names and values of process attributes, scanner notes, the description of the scanner privileges. The language is stored in the `lang` field of the result |
| `report` | the whole report text and the knowledge base. Without the option the report is produced in the language in which the scan was run |
| `explain` | the language in which the model writes rationales and summaries |

Tags, finding identifiers, result field names and scoring do not depend on the language.

A report entirely in English requires a scan with `--lang en`. A report in a language other than the scan will also be produced, but the descriptions stored in the result stay in the language of the scan, and the knowledge base explanations of process attributes may not appear; the report announces this in a boxed note at the beginning.

```sh
nanshe --lang en scan --all --json result.json
nanshe report result.json            # in English, because the scan was
```

The most important `explain` options: `--llm ollama|nous|anthropic|google|openai`, `--model`, `--allow-cloud`, `--data-level d0|d1|d2`, `--dry-run`, `--max-calls` (default 60), `--max-regions` (default 6 per process), `--key-file`, `--no-report`.

## 5. Detectors and scoring

Each detector adds points to a region. The sum of a region's points gives the severity: below 30 "info", 30-59 "suspicious", 60 and above "high". The severity of a process is the highest severity of its regions.

| Tag | Points | System | When |
|---|---|---|---|
| `RWX` | 30 | both | region writable and executable at the same time |
| `X-PRIV` | 30 | both | executable memory not backed by a file |
| `X-MAP` | 30 | Windows | executable section that is not a module image |
| `GUARD-X` | 30 | Windows | executable region behind a guard page; content deliberately not read |
| `MEMFD` | 40 | Linux | executable mapping of a file that exists only in memory |
| `DEL-EXEC` | 30 | Linux | executable mapping of a file deleted from disk |
| `X-TMP` | 30 | Linux | executable mapping of a file from a world-writable directory |
| `ENT-X` | 10 / 20 / 30 | both | high entropy in an executable region: 20 from 7.2, 30 from 7.8; 10 when it is single pages in ordinary code from a file |
| `HDR` | 40 | both | ELF, PE or Mach-O header in memory not backed by a file |
| `THR-PRIV` | 40 | both | thread located in memory not backed by a file |
| `IMG-MOD` | 10 / 40 | both | code in memory differs from the file on disk: 40 on Linux and for `amsi.dll`, `wldp.dll`, 10 for other Windows libraries. The finding states whether the contents were compared with the file |

Details that matter when assessing a result:

- **`HDR`** requires more than a signature: for ELF a valid file type, for PE a non-zero Machine field and 1-96 sections. At the start of a page it searches in every region not backed by a file except a non-executable stack; at an arbitrary offset only in executable regions. The reason for both restrictions is the same: the program loader keeps copies of library headers in ordinary data.
- **`THR-PRIV`** on Windows uses the thread start address, on Linux the address of the instruction from which the thread called the kernel (only for threads waiting in a system call).
- **`IMG-MOD`** works in two steps. First the backend establishes which file-backed code pages the process has written to (Linux: anonymous pages according to `smaps`; Windows: working-set pages that are no longer shared). Then it compares their contents with the file on disk: on Linux with the corresponding part of the file (opened through `/proc/<pid>/map_files`, and by path only when the device and inode match the process map), on Windows with the contents reconstructed from the PE file with relocations applied for the actual load address. The finding states the number of differing bytes and the address of the first one. A page that is merely a private copy with unchanged contents produces no finding. When the file cannot be opened, the finding says explicitly that the contents were not compared.
- **`HDR` with a wiped signature.** When there is no valid header at the start of a region (or of a page in an executable region), the detector also looks for a PE section table (at least two consistent entries, one of them executable) or an ELF program header table (at least two loadable segments, one of them executable). This is what a manually loaded image looks like after its format markers were removed so that it cannot be found by signature.

### Reduction for runtimes that create code on the fly

JIT runtimes (.NET, Java, JavaScript engines) constantly create regions that look like injected code. For a recognised runtime the points of `RWX`, `X-PRIV`, `X-MAP` (only sections not backed by a file) and `ENT-X` are divided by 3. The findings stay in the result with an annotation; `HDR`, `GUARD-X`, `THR-PRIV` and `IMG-MOD` are not reduced.

- **Linux:** by the program file. It must be named like a known runtime (among others `node`, `java`, `dotnet`, browsers), be located in a system directory, be owned by root, not be writable by others and be the same file that the scanner sees.
- **Windows:** by the loaded module. The program file must be located in a system directory (outside subdirectories writable by users) and be owned by a system account, and the runtime module (`clr.dll`, `coreclr.dll`, `msedge.dll`) must be loaded as an image from its installation directory.

A known risk of the reduction: code injected into a legitimate process with a JIT runtime inherits it. A private, writable and executable region with low entropy then drops to the "info" severity. The signal that this does not affect is `THR-PRIV`.

## 6. System context

For a process with a finding of "suspicious" severity or higher, the scan collects data from outside memory, by reading only:

| Data | Linux | Windows |
|---|---|---|
| parent, ancestors, children | yes | yes (with protection against a reused process number) |
| command line, start time, number of threads | yes | yes |
| user | yes | yes |
| program file: size, modification time, SHA-256 | yes (also when deleted from disk) | yes (local files) |
| owner and mode of the program file | yes | no |
| working directory | yes | no |
| TCP and UDP sockets (IPv4, IPv6) | yes, plus Unix sockets | yes |
| open files | descriptors (up to 200) | named handles: files, registry keys, sections, mutexes, handles to other processes (up to 300) |
| security attributes | ptrace, capabilities, seccomp, `LD_PRELOAD` and similar variables | integrity level, session |
| full region map | yes | yes |

The result also contains a description of the host (system, kernel or build version, boot time) and the privileges with which the scanner ran. A scan without full privileges is marked in the report with a warning on the first page.

## 7. Result file

The result is a single JSON file (`schema_version` 1). The most important fields:

| Field | Content |
|---|---|
| `host`, `timestamp`, `tool_version`, `partial` | scan header data; `partial` means a partial result |
| `host_info` | system, boot time, account and privileges of the scanner |
| `processes[]` | the result of each process |
| `processes[].info` | number, name, system, program file, whether the file is confirmed as a system file |
| `processes[].error` | reason for inaccessibility or for truncation of the map |
| `processes[].regions[]` | regions with findings: region description, points, severity, entropy, findings, entropy profile, text strings, SHA-256 of the content, reduction annotation |
| `processes[].regions[].findings[]` | tag, address, points, rationale, preview of up to 256 bytes |
| `processes[].layout` | full region map (only processes of "suspicious" severity or higher) |
| `processes[].context` | system context (only processes of "suspicious" severity or higher) |
| `files[]` | SHA-256 hashes of program files and mapped files |

The file contains data from the examined host without filtering: paths, command lines, network addresses, memory fragments. It must be treated as evidence. Fields unknown to an older version are skipped on loading, and missing ones take empty values, so a report can also be generated from an older result.

## 8. Interpretation by a language model

The `explain` command sends the model a description of every region with a finding and asks for ranked hypotheses with arguments for and against, and then for a correlation of the regions of the process and proposed steps. The result goes to a separate file and is clearly marked in the report as non-deterministic.

**How much data leaves (data level):**

| Level | What the model receives | Default for |
|---|---|---|
| `d0` | region metadata only: permissions, size, entropy, tags, points | the cloud |
| `d1` | additionally text strings after the secrets filter, process name, paths | a local model |
| `d2` | additionally raw bytes | never goes to the cloud |

**Safeguards before sending:**

- The cloud requires explicit consent with `--allow-cloud`; `--dry-run` shows exactly what would be sent.
- The secrets filter cuts out keys, tokens, passwords and high-entropy strings (level `d1`).
- The injection filter removes text that looks like an instruction for the model (from memory, the process name, paths, labels) and raises a flag in the result.
- Pseudonymisation for the cloud replaces the host name, user names in paths and IP addresses (v4 and v6) with labels, and restores the values in the response. This is a risk reduction, not a guarantee; for client data the safest level is `d0`.
- The model does not receive the system context or the memory map.

**Response checking:** the response must match the schema, refer only to existing findings and contain a rationale. A benign hypothesis cannot have the highest confidence. A response that does not meet the conditions is retried and then rejected with the reason recorded. A refusal or a provider error gives a partial result, without automatic switching to another model.

**Providers:** Ollama (local), Nous, Anthropic, Google, OpenAI. The key is supplied through an environment variable or a file; it does not end up in the result or in the logs.

Verified live: Ollama (`gemma3:12b`) and Nous (Claude models). The Anthropic, Google and OpenAI providers have only request-shape tests.

## 9. Report

The report is produced in two formats with the same content: Markdown and PDF. The PDF is written directly by the tool, with an embedded font (Polish characters, selectable text), and is reproducible: the same result gives the same file.

Layout (the main chapters are numbered):

1. Header: host, time, version, completeness, scanner privileges, document classification, SHA-256 of the result file, and warnings (the result is triage, not a verdict; the report contains data from the host; incomplete privileges, if applicable).
   After the header there is a table of contents of the main chapters; in the PDF with page numbers (the layout is computed twice: the first pass determines the pages of the chapters, the second writes them into the table of contents).
2. **Executive summary**: overall assessment in one paragraph, scope and completeness, number of processes by priority, the most important processes with a rationale, recommended actions and limitations of the assessment.
3. "How to read this report": introduction, meaning of the severities, description of each part.
4. Process overview: table with priorities, chart of tags, processes x tags matrix, a common tree of the processes with findings.
5. For each process (in priority order):
   - process data and **"Assessment"**: verification priority, rationale, first step,
   - "What this program is" (description from the knowledge base, comparison of the file location and the parent with the typical ones),
   - process tree, network, open files and handles, mapped files with descriptions and hashes,
   - address space map,
   - "What the findings mean": each set of tags once, with a benign and a worrying explanation, the technical basis and related MITRE ATT&CK techniques,
   - chart of region size x entropy and the "from memory to network" diagram,
   - details of at most 6 regions with the highest score: neighbours, entropy profile, byte preview, ELF or PE header fields, text strings, commands for checking the region, the model's interpretation.
6. "What this report does not cover": inaccessible processes, regions not read, missing data.
7. Glossary and legend.

The text has two layers. The description of each tag is understandable without a background in memory analysis, and next to it there is a layer for the experienced reader: the exact detector condition (page flags, data source) and a reference to the MITRE ATT&CK catalogue.

**Verification priority** orders the analyst's work and follows directly from the findings and the context:

| Priority | When |
|---|---|
| P1 | a tag that a just-in-time (JIT) runtime does not explain (`THR-PRIV`, `HDR`, `MEMFD`, `GUARD-X`, `IMG-MOD` in a security module), or "high" severity in a process without such a runtime recognised |
| P2 | "high" severity with a recognised runtime or without a memory map; "suspicious" severity in a program from outside the system directories |
| P3 | the rest |

The priority is not an assessment of maliciousness and does not change the scoring. High privileges of the process and connections to remote addresses are added to the rationale.

All content that comes from the examined system or from the model is neutralised in the report (it cannot insert markup or break a table). The report refuses to attach an interpretation that concerns a different result file.

The plain-language explanations come from the knowledge base in `kb/` (common, Linux, Windows). It can be replaced without rebuilding the program with the `--kb` option. The knowledge base only explains; it does not change the scoring.

## 10. Security of the tool itself

**The "read-only" rule.** The scanner does not write to the examined processes, does not stop them and does not inject code. On Linux it reads `/proc`. On Windows it opens processes with query and memory read rights.

Places where the tool does something more than passive reading:

| Place | What it does | Why |
|---|---|---|
| handles on Windows | opens the process with the right to duplicate handles and briefly duplicates a handle into itself without any rights | otherwise the type and name of the object cannot be determined |
| guard pages on Windows | deliberately does not read them | a read would clear the guard flag, that is, change the state of the process |
| `SeDebugPrivilege` | enables the privilege in its own token | without it only its own processes are visible |

**Untrusted data.** Process names, paths, memory content and model responses are treated as data controlled by an attacker: they do not affect the reduction of points (what counts is the file confirmed by the system, not the name), they do not reach the model without filters and they cannot change the layout of the report.

**Protection of the scanner:**

- Hashes are computed only for regular files: devices and pipes are not opened at all, a file is opened once, checked again after opening and read up to a limit of 512 MiB.
- On Windows the scanner does not open network paths given by the examined process (opening one would send the computer's credentials to a foreign server).
- Queries for handle names have a time limit; the scanner does not query pipe names at all.
- Limits: 64 MiB per region, 1,048,576 regions per process, limits on the number of recorded files, handles and strings.

**Installation on Windows.** The installer places the program in a directory writable only by administrators, and the results in a directory accessible only to administrators and the SYSTEM account. It refuses when the target directory has been planted beforehand (a link or a foreign owner), and it checks the hashes of the package files. The removal script applies the same checks before removing the directories.

## 11. Requirements and running

| | Linux | Windows |
|---|---|---|
| Privileges | root or `CAP_SYS_PTRACE` | elevated administrator |
| Build | `cargo build --release -p nanshe-cli --features llm` | the same, MSVC toolchain |
| Installation | copy of the binary | MSI package (`scripts\package-msi.ps1`) or the package from `scripts\package-windows.ps1` and `install.ps1`; described in [windows.md](windows.md) |
| Verified on | Debian 12, aarch64, in a container | Windows 11 Pro x64 (test host) |

A typical session:

```sh
nanshe scan --all --json wynik.json          # scan of the whole host
nanshe report wynik.json                     # report without the model
nanshe explain wynik.json --llm nous --allow-cloud --key-file klucz.txt   # interpretation and report
```

On a host without a scan backend (macOS) the commands that work on a result file are available: `report`, `explain`, `map --input`.

## 12. What has been verified

| Layer | Status |
|---|---|
| Unit tests | 110, all pass; written in pairs (a case and a control that differs in one property) |
| Tests on live samples, Linux | 17 static samples and 2 dynamic ones, plus assertions on the result, the report and the context |
| Tests on live samples, Windows | 16 static samples and 2 dynamic ones, plus assertions on the result, the report, the context and the handles |
| Windows installer | test of installation, refusals and uninstallation (result of the first run in [tests.md](tests.md)) |
| Local model and cloud | manual runs on samples and on a full scan of the test host |

Measurement on the Windows test host (240 processes, 2026-11-22):

- a full scan takes about 30 s and collects the hashes of 335 files,
- 18-20 processes are inaccessible (processes protected by the system), the same for an administrator and for the SYSTEM account,
- after the reduction for JIT runtimes, 5 processes remain with findings of "suspicious" severity or higher (before the reduction there were 20); all five are programs from outside the system directories,
- `THR-PRIV` raised no alert; `IMG-MOD` occurred benignly in 19 processes, hence the low score for ordinary libraries.

This is a measurement from one host. On servers, developer workstations and in containers the numbers will be different.

## 13. Known limitations

**What the tool does not see:**

- processes protected by the system (on Windows, among others, LSASS and antivirus processes) and kernel memory,
- code injected into a process with a JIT runtime, if it has no thread of its own, no high entropy and no header,
- a program header with wiped signatures,
- a header away from the start of a page in non-executable data,
- on Windows: an image section loaded from a file outside the system directories,
- on Linux: threads that were not waiting in the kernel at the moment of the scan,
- what happened before the scan: a scan is the state at one moment.

**What it does not do:**

- it does not analyse physical memory dumps (dumps of single processes are analysed),
- it does not observe a process over time (the differential report compares two states, but does not see what appeared and disappeared between the scans),
- it does not show what exactly was changed in library code,
- it does not check digital signatures or hashes in external databases,
- it does not scan macOS or FreeBSD.

**What has not been measured:**

- false positives beyond one Windows host and the samples on Linux,
- effectiveness on real malware (all samples are synthetic),
- the quality of model interpretations (there is no evaluation set; there are only observations from single runs),
- Linux on the x86_64 architecture.

**Release gaps:** no continuous integration and no fuzz testing of the parsers, no digital signature of the program or the installers. Available in English are the report, the knowledge base and the descriptions in the scan result; the command-line help (`--help`), the model layer messages in the terminal and the memory map (`nanshe map`) are in Polish only.

## 14. What next

The order agreed in the course of the work:

1. Analysis of physical memory dumps as a new source (the same detectors), with address translation through an existing library. Dumps of single processes are already supported.
2. Reading the memory of virtual machines from the hypervisor (gives access to protected processes without a trace in the examined system).
3. Comparison of modified code with the file on disk (showing what was changed) and detection of headers with wiped signatures.
4. Findings from context: a process with high privileges started from a directory writable by ordinary users.
5. Observation of a process over time.
6. macOS and FreeBSD backends.

## 15. License

Apache License 2.0, files `LICENSE` and `NOTICE` in the root directory. The libraries used by the program have permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode); the built-in DejaVu font has its own license (`crates/nanshe-report/fonts/LICENSE-DejaVu.txt`).
