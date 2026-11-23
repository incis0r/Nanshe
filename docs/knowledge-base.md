# Report knowledge base

Polish version: [pl/baza-wiedzy.md](pl/baza-wiedzy.md).

The report is meant to be understandable to a person (and to a language model) who does not deal with memory analysis every day. For that reason, next to the technical data it contains explanations in plain language. Their text is not hard-coded, it lives in data files in the `kb/` directory:

| File | Scope |
|---|---|
| `kb/common.json` | common to all systems: guide to the report, severities, the characteristics `RWX`, `X-PRIV`, `ENT-X`, `HDR`, the basic glossary |
| `kb/linux.json` | Linux: `MEMFD`, `DEL-EXEC`, `X-TMP`, verification commands, known processes and libraries, process characteristics from `/proc` |
| `kb/windows.json` | Windows: `X-MAP`, `GUARD-X`, verification commands, known processes and modules, handles, integrity levels |

The English version is in the `kb/en/` subdirectory (the same three files) and is used when the report is produced in English (`--lang en` or a scan performed in English). Both languages must have an identical structure: the same tags, combinations, verification steps, processes and modules; only the text differs. The test `english_base_mirrors_the_polish_one` enforces this, so every change in `kb/*.json` has to be repeated in `kb/en/*.json`. The keys in the `flags` section must match the names of the characteristics that the scanner writes in the given language (for example `poziom integralności` and `integrity level`).

macOS and FreeBSD do not have their own files yet: the report for them will use the common part. Adding a system means a new file `kb/<system>.json` and an entry in `crates/nanshe-kb/src/lib.rs` (the `SYSTEMS` constant and the `embedded` function).

The files are embedded in the binary at compile time. A newer or custom version can be pointed to without rebuilding:

```sh
nanshe report wynik.json --kb /path/to/kb        # or the NANSHE_KB_DIR variable
```

The directory must contain `common.json`; the system file is optional. For an English report the `en` subdirectory of the given directory is used, if it exists. A syntax error in the files stops report generation with a message, instead of silently falling back to the embedded base.

## What the base contributes to the report

| Part of the report | Where in the base | What it does |
|---|---|---|
| "How to read this report" | `guide`, `severity`, `sections` | an introduction without jargon, the meaning of the severities, a description of every part of the report |
| "What this program is" | `processes` | what a program with this name usually is; a comparison of the file location and the parent process with the typical ones, with a warning on a mismatch |
| "What the process attributes mean" | `flags` | an explanation of fields such as seccomp, CapEff, integrity level |
| "Files mapped into memory", description column | `modules` | what the library is; modules of JIT runtimes are always shown, because they explain findings |
| "What the findings mean in this process" | `combos`, `tags` | each combination of characteristics once: what it means, benign and worrying explanations, a hint that depends on whether the process contains a JIT runtime, the technical basis and related ATT&CK techniques |
| "Assessment" and "Executive summary" | `modules` (recognition of the JIT runtime), names of characteristics | the verification priority of the process with a justification; the priority rules are in the report code, the base supplies the names and the recognition of runtimes |
| "How to verify this region" | `verify` | steps: what to do, a ready-made command with the process number and the region addresses filled in, and a hint on how to read the result (what is ordinary, what should raise concern, what to do next) |
| "Processes and characteristics", "Region size and entropy", "SHA-256 hashes" | `sections` | a description of how to read the matrix, the scatter plot and the hash tables |
| "Glossary" and "Legend" | `terms`, `tags` | terms used in the report |

The tag glossary in the prompt to the model (the `en` field in `tags`) also comes from the base, so the report and the model use a single description.

## Rules the base follows

- **The base explains, it does not score.** Severities and findings are determined by the detectors alone. The warning "the file is in an unusual location" does not change the score of a region.
- **The process name is only a hint.** A process can name itself anything, so the description of a program always goes together with a check of the path and a reminder about the SHA-256 hash.
- **The report does not guess.** The hint about a JIT runtime appears only when the result contains the region map of the process. A combination of characteristics without its own description is assembled from the descriptions of the individual characteristics.
- **Every explanation has two sides.** A combination of characteristics must have at least one benign and one worrying explanation; a test enforces this.
- **Two layers.** Every characteristic has a description that can be understood without preparation (`meaning`, `why`) and a technical layer for the experienced reader (`tech`: the exact condition of the detector; `attack`: related MITRE ATT&CK techniques). The system-dependent technical layer lives in the system file and is merged with the common description. The references to ATT&CK are indicative, and the report says explicitly that a finding does not prove the use of a technique.
- **Plain language.** Sentences without industry abbreviations; terms that cannot be avoided are in the glossary. No long dashes (a test checks this).

## File format

Each file is a single JSON object. The system file is overlaid on the common one: objects are merged by key (the system entry wins), and lists are concatenated (system entries take precedence in lookups).

```json
{
  "tags":   { "RWX": { "name": "short name", "en": "definition for the model", "meaning": "what it is", "why": "why it matters",
                       "tech": "exact condition of the detector", "attack": ["T1055 Process Injection"] } },
  "combos": [ { "tags": ["RWX", "X-PRIV"], "title": "...", "meaning": "...",
                "benign": ["..."], "malicious": ["..."],
                "hints": [ { "runtime": true, "text": "... {runtime} ..." }, { "runtime": false, "text": "..." } ] } ],
  "verify": { "*": [{ "do": "what to do", "cmd": "command {pid} {start} {end} {start_plain} {size}", "look": "how to read the result" }], "HDR": [{ "do": "step for this tag only", "cmd": "", "look": "..." }] },
  "processes": [ { "names": ["svchost.exe"], "what": "...", "paths": ["\\windows\\system32\\svchost.exe"], "parents": ["services.exe"] } ],
  "modules":   [ { "names": ["clr.dll"], "what": "...", "runtime": ".NET Framework" } ],
  "flags":   { "seccomp": "explanation; the key is the beginning of the characteristic name" },
  "handles": { "file": "..." },
  "terms":   { "entropy": "..." }
}
```

- `combos.tags`: the exact set of characteristics of the region, order does not matter.
- `hints.runtime`: `true` shows the hint when the mapped files of the process include a module with the `runtime` field; `false`, when there is none.
- `processes.names` and `parents`: lower case. `paths`: lower case, without the drive letter. An entry without a trailing separator is the exact path of a file; with a trailing separator it means a file directly in that directory; with the suffix `**`, at any depth within it. On Windows the file must additionally be on the system drive (recorded in the scan result; when it is missing, `C:` is assumed). Empty lists mean no expectations and no assessment.
- `modules.names`: the beginning of the file name (lower case), for example `libssl` matches `libssl.so.3`.

## How to add an entry

1. Add the entry in the appropriate `kb/` file.
2. Run `scripts/dev.sh cargo test -p nanshe-kb -p nanshe-report`. The tests check, among other things, that every tag reported by the detectors of a given system has a description, that the combinations refer to known tags and are not duplicated, that every verification command has all of its fields filled in, and that the text contains no long dashes.
3. Generate a report from a sample and read the new fragment through the eyes of a person from outside the field.

## Limitations

- The content exists in Polish and English; every change has to be made in both versions.
- The descriptions of processes and modules are a few dozen of the most common items, not a software catalogue. A program not described in the base gets a note in the report that the lack of a description is not an assessment.
- The typical paths and parents apply to standard installations. A non-standard installation will produce a warning that has to be explained manually.
- The verification commands assume administrator access and the presence of the tools (gdb, Sysinternals, System Informer, pe-sieve); the report does not run them.
- The explanations describe typical cases and come from general knowledge, not from a measurement on a large number of hosts.
