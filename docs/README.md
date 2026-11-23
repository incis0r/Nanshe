# Nanshe documentation

Polish versions of these documents are in [pl/](pl/).

## Start here

| Document | Read it when you want to |
|---|---|
| [documentation-0.1.0.md](documentation-0.1.0.md) | understand what version 0.1.0 does, how it is built, what was tested and what it cannot do |
| [examples/](examples/) | see what a report looks like before running anything |

## By operating system

| Document | Contents |
|---|---|
| [linux.md](linux.md) | build, required privileges, detectors and limitations on Linux |
| [windows.md](windows.md) | build, required privileges, detectors, measurements, installers (MSI and zip) and limitations on Windows |
| [macos.md](macos.md) | current state on macOS (analyst workstation only; live scanning is not supported yet) |

## Reference

| Document | Contents |
|---|---|
| [knowledge-base.md](knowledge-base.md) | the knowledge base in `kb/` and `kb/en/`: structure, how the report uses it, how to extend it |
| [tests.md](tests.md) | every test, what it checks, what the tests do not cover, and how to run them |

## Project files

| File | Contents |
|---|---|
| [../README.md](../README.md) | overview and quick start |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | how to build, test and submit changes |
| [../SECURITY.md](../SECURITY.md) | how to report a vulnerability |
| [../CHANGELOG.md](../CHANGELOG.md) | changes by version |

## Conventions used in the documents

- **Findings are hypotheses.** The tool points at memory regions worth a manual look; it does not decide whether a host is compromised.
- **Calibrated statements.** Documents distinguish what was measured, what is an assessment and what was not checked. Single observations are labelled as such.
- **Severity** of a region follows from the sum of points of its findings: below 30 `info`, 30 to 59 `suspicious`, 60 and above `high`.
- **Tags** such as `RWX` or `HDR` are stable identifiers of detectors and do not depend on the output language.
