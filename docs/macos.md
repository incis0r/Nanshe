# Nanshe on macOS

Polish version: [pl/macos.md](pl/macos.md).

Status: **first version of live process scanning** (new in 0.2.0). Built and tested natively on Apple Silicon (arm64), macOS 26. Intel Macs, older macOS versions and x86_64 processes running under Rosetta were not tested.

## Build

```sh
cargo build --release -p nanshe-cli            # add --features llm for the interpretation layer
cargo test --workspace --features nanshe-cli/llm
scripts/e2e-macos.sh                           # end-to-end tests with synthetic samples
```

## What access macOS gives

Reading the memory of another process requires its task port. macOS decides who gets it:

| Scanner runs as | Processes it can read |
|---|---|
| ordinary user, unsigned or plain adhoc binary | none (only the listing works) |
| ordinary user, binary signed locally with the debugger entitlement | processes of the same user that are not protected: own builds, many third-party applications without a hardened runtime |
| root | additionally processes of other users, with the same exceptions |
| anyone, with System Integrity Protection enabled | never: Apple system processes and programs with a hardened runtime that do not allow debugging |

Signing a local copy with the debugger entitlement (adhoc, no developer account needed):

```sh
codesign -f -s - --entitlements packaging/macos/debugger.entitlements target/release/nanshe
```

A process that cannot be opened is listed in the result as inaccessible, with the reason; the scan result is then marked as partial. On the development workstation (SIP enabled, ordinary user, entitlement as above) 25 of 788 processes were readable. This is a property of the system, not a defect to be worked around: Nanshe does not ask to disable SIP.

## What is examined

- **Region map** from the kernel (`mach_vm_region_recurse`): address, size, current protection, allocation tag. File names come from `proc_pidinfo` (`PROC_PIDREGIONPATHINFO`), checked to describe exactly the region asked about.
- **System libraries.** macOS maps all system libraries from one shared file (the dyld shared cache) at the same address in every process. Regions seen through that shared mapping are labelled `[dyld shared cache]`, are not reported as code without a file and are not read (over 1 GiB, identical everywhere). A page inside that range that was replaced privately is no longer part of the shared mapping and is examined like any private region.
- **Contents** read with `mach_vm_read_overwrite`, read-only.

`nanshe map` (the interactive memory map) works on macOS with the same access rules.

Detectors that apply: `RWX`, `X-PRIV`, `ENT-X`, `HDR` (Mach-O, PE and ELF headers in memory without a file) and `SHC` (on arm64: a direct system call, `svc #0x80` with the call number set just before it, in code without a file).

Notes for reading results:

- On Apple Silicon an ordinary program cannot have memory that is writable and executable at once. `RWX` therefore means a JIT region (`MAP_JIT`), which browsers, JavaScript runtimes and virtual machines legitimately have.
- **Reduced weight for JIT regions rests on evidence from the system, not on program names.** A process with a valid signature, a hardened runtime and the `allow-jit` entitlement is allowed by macOS itself to generate code; its JIT findings get a reduced weight (token `jit:macos-allow-jit`). All three facts are checked by the kernel and cannot be granted by the process to itself after start. A program without a hardened runtime (an own build, a locally signed tool) gets no reduction, because any such program may create a JIT region.

## Not implemented yet

- Network connections and open files of a process. Available now: parent and child processes, user, start time, thread count, command line, code signature state and notable entitlements.
- Thread start addresses (`THR-PRIV`) and comparison of code with the file on disk (`IMG-MOD`).
- Core dumps of macOS processes (Mach-O core files).
- A signed and notarised package.

## Tests

- Unit tests of the backend: the layout of the kernel structure, region classification, the exact-region rule for file names, and a scan of the test process itself (listing, map, reading own data and own code, the shared cache label).
- `scripts/e2e-macos.sh`: samples `clean`, `data-noise`, `rx-stage`, `rx-lowent`, `macho`, `jit`, `all`; refusal for a protected process; a missing process; Polish and English reports with macOS verification steps; a scan of all processes.
- Not covered: root, other users' processes, Intel Macs, Rosetta, real malware.

## As an analyst workstation

Independently of live scanning, a result collected on Linux or Windows can be interpreted and turned into a report here: `explain`, `report`, `diff`, `llm check` and `cloud list` do not depend on the scan backend.
