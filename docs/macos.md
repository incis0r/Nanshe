# Nanshe on macOS and other systems

Polish version: [pl/macos.md](pl/macos.md).

Status: **scanning of live processes is not implemented** on macOS, FreeBSD or other systems apart from Linux and Windows. `nanshe scan` returns the error "unsupported" there.

A saved inventory from Linux/Windows can be opened as a local HTML atlas:

```sh
nanshe map --input host.memory.json
```

Running it without arguments tries to perform a live inventory, so on macOS it returns
a missing backend error. It does not generate substitute or synthetic system data.

## What a macOS host is for

As an analyst workstation: a scan result collected on Linux or Windows can be interpreted here and turned into a report. The commands `explain`, `report`, `llm check` and `cloud list` do not depend on the system, because they work on a JSON file.

Note: the native build on macOS was not verified (the project's workstation has no Rust). The verified route is a Linux container:

```sh
scripts/dev.sh cargo build --release -p nanshe-cli --features llm
scripts/dev.sh /target/release/nanshe report wynik.json
scripts/dev.sh /target/release/nanshe explain wynik.json --llm nous --allow-cloud --key-file .nous
```

`scripts/dev.sh` mounts the repository directory as `/src`, so the result files must be in the repository or in the `/target` volume. The files `*.llm.json`, `*.report.md` and `*.report.pdf` are in `.gitignore`, because they contain data from memory.

## Deployment and remote tests from macOS

- Windows: natively on a dedicated test host (`scripts\e2e.ps1`), described in [windows.md](windows.md).
- Linux: tests in a container, described in [tests.md](tests.md).

## Plan

The macOS backends (`mach_vm_region_recurse` + `mach_vm_read_overwrite`, with SIP restrictions) and FreeBSD are stage M3 in the roadmap ([documentation-0.1.0.md](documentation-0.1.0.md), chapter 14); no date set.
