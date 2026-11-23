# Security policy

Nanshe runs with high privileges (root or an elevated administrator) and reads memory of other processes. Text it processes (process names, paths, strings from memory, model output) is controlled by the examined system and must be treated as hostile. Vulnerabilities in the tool therefore matter, and reports are welcome.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

Until version 1.0, only the latest release receives fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- Preferred: GitHub private vulnerability reporting (the "Report a vulnerability" button on the Security tab of this repository).
- Alternatively: e-mail dariusz@honeylens.io with the subject "Nanshe security".

Include the version (`nanshe --version`), the operating system, what you observed and, if possible, steps to reproduce. Do not send memory dumps or scan results from production systems: they may contain secrets. A minimal synthetic reproduction is enough.

What to expect:

- acknowledgement within 5 working days,
- an assessment and a plan within 15 working days,
- credit in the release notes if you want it.

Please allow a fix to be released before publishing details. If 90 days pass without a fix, you are free to publish.

## In scope

- Memory safety or logic errors in the scanner, parsers (`/proc`, PE and ELF headers, Windows system tables) and report generators.
- Ways for an examined process to influence the scanner beyond its own findings: code execution, file writes, credential disclosure (for example by making the scanner open a network path), hangs, or hiding other findings.
- Injection through untrusted text into the Markdown or PDF report, or into prompts sent to a language model.
- Leaks of data to a language model beyond the documented data levels, or bypasses of the secret filter and pseudonymisation.
- Weaknesses in the Windows installers (permissions of installed files and directories, tampering with the package).

## Out of scope

- Detection gaps: malware that the detectors do not flag is a limitation, not a vulnerability. Open a regular issue, ideally with a synthetic sample.
- Findings that require an attacker who already has the privileges of the scanner.
- The quality of language-model interpretations.

## Handling of scan data

Result files and reports contain data from the examined host without filtering. Never attach real ones to public issues or pull requests.
