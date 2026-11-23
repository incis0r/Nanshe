# Contributing to Nanshe

Thank you for considering a contribution. This file describes how to build, test and submit changes.

## Ground rules

- By submitting a contribution you agree that it is licensed under the Apache License 2.0 (see section 5 of [LICENSE](LICENSE)). There is no separate contributor agreement.
- Be respectful: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Never commit or attach real scan results, reports, memory dumps, credentials or API keys. Use the synthetic samples in `tests/samples`.

## Building and testing

Linux, in a container (podman by default):

```sh
scripts/dev.sh cargo test --workspace --features nanshe-cli/llm
scripts/dev.sh sh scripts/e2e.sh
```

Windows, natively with the MSVC toolchain, on a dedicated test host only (the end-to-end and installer tests start test samples, install and uninstall the product):

```powershell
cargo test --workspace --features nanshe-cli/llm
cargo build --release -p nanshe-cli -p nanshe-samples --features nanshe-cli/llm
powershell -ExecutionPolicy Bypass -File scripts\e2e.ps1 -Bin target\release -Out e2e-out
```

Continuous integration on GitHub runs the Linux unit and end-to-end tests in a container and the unit tests on Windows. It does not run the Windows end-to-end or installer tests; if your change touches Windows-specific code, say in the pull request how you tested it.

## What a good change looks like

- **One topic per pull request**, with commits that each make sense on their own. The history should show what changed and why; avoid mixing refactoring with behaviour changes.
- **Tests that can fail.** A new detector, parser or check comes with a test, and the test has a control case (an input for which the check must stay silent). Before submitting, break the code on purpose once and confirm the test fails.
- **Detectors** need a synthetic sample mode in `tests/samples` and an assertion in `scripts/e2e.sh` or `scripts/e2e.ps1`, plus a knowledge-base entry (see below). State the expected false positives.
- **Calibrated wording.** Reports say what was established, what is an assessment and what is unconfirmed. A finding is never described as proof of compromise.
- **Both languages.** Every text meant for a human goes through `tr!("po polsku", "in English")` or `trf!` from `nanshe-core`. A change in `kb/*.json` must be mirrored in `kb/en/*.json`; a test enforces the same structure. Do not use em dashes or en dashes in texts.
- **Read-only scanner.** The scanner must not write to, inject into or otherwise modify examined processes, and must not open paths that could send credentials to a remote host.
- **Unsafe code** is allowed only in the Windows backend of `nanshe-live`, each block with a `SAFETY` comment. Other crates use `#![forbid(unsafe_code)]`.
- **No network code** outside `nanshe-llm`; the default build must stay free of it.
- **Untrusted text** (process names, paths, strings from memory, model output) is escaped before it reaches a report and never interpreted.

## Project layout

| Path | Contents |
|---|---|
| `crates/nanshe-core` | shared types, the `MemorySource` trait, language selection |
| `crates/nanshe-analyze` | detectors and scoring |
| `crates/nanshe-live` | live process backends (Linux `/proc`, Windows API) and system context |
| `crates/nanshe-kb` | knowledge base loader; content in `kb/` and `kb/en/` |
| `crates/nanshe-report` | report model, Markdown and PDF renderers, differential report |
| `crates/nanshe-llm` | optional language-model layer |
| `crates/nanshe-cli` | the `nanshe` command |
| `tests/samples` | synthetic samples used by the end-to-end tests |
| `scripts/`, `packaging/` | build, test and packaging scripts |
| `docs/` | documentation in English; Polish versions in `docs/pl/` |

## Submitting

1. Open an issue first for larger changes, so the approach can be agreed before you invest time.
2. Fork, create a branch, make the change with tests and documentation.
3. Run the tests listed above and fill in the pull request template.
4. A maintainer reviews the change. Expect questions about test coverage and wording.

## Reporting bugs

Use the bug report template. Include `nanshe --version`, the operating system and architecture, the exact command, and what you expected. Reproduce with a synthetic sample when possible; never attach real scan data.
