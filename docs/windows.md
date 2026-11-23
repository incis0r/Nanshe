# Nanshe on Windows

Polish version: [pl/windows.md](pl/windows.md).

Status: supported. Verified on Windows 11 Pro x64 (one test host), native MSVC build.

## Build

Required: Rust (toolchain `stable-x86_64-pc-windows-msvc`) and Visual Studio Build Tools with the C++ workload.

```powershell
cargo build --release -p nanshe-cli --features llm
# target\release\nanshe.exe
```

Run the end-to-end tests (`scripts\e2e.ps1`) and the installer tests only on a dedicated test host: they start samples, and install and remove the program.

## Installing from the package

The package is built on a host with the MSVC toolchain by the script `scripts\package-windows.ps1`; it produces `dist\nanshe-<version>-windows-x64.zip` with the program, the knowledge base, the installer and the hash list `SHA256SUMS`. After unpacking, in an administrator console:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1      # options: -InstallDir, -NoPath, -NoShortcut, -Quiet
```

The installer:

- checks the SHA-256 hashes of all files in the package and refuses when any of them does not match,
- installs to `C:\Program Files\Nanshe`; the directory is owned by Administrators, standard users have read access only, permission inheritance is disabled,
- creates `C:\ProgramData\Nanshe\wyniki`, accessible only to Administrators and SYSTEM (results and reports contain data from memory),
- refuses when either of these directories already exists and is a reparse point (junction or link), contains one, or is owned by a standard account (in `ProgramData` any user can create a directory); it checks both directories before changing anything,
- adds the program directory to the system `PATH`, creates a Start menu shortcut that runs as administrator, and an entry in "Programs and Features".

Removal: "Programs and Features" or `uninstall.ps1` from the program directory; results are kept unless `-RemoveData` is given. The removal script applies the same checks as the installer: it refuses when the directory is a reparse point, contains one, or is owned by a standard account.exe` is not digitally signed, so the system may show a warning on launch.

### MSI installer

The second, recommended form is a Windows Installer package: `nanshe-<version>-windows-x64.msi`. It is built by `scripts\package-msi.ps1` with WiX Toolset 3.14 (MS-RL license; it is used only for building and is not included in the package):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-msi.ps1 -Bin <directory with nanshe.exe> -Wix <directory with candle.exe> -Out dist
msiexec /i nanshe-0.1.0-windows-x64.msi            # with dialogs; silent: /qn /norestart
msiexec /x nanshe-0.1.0-windows-x64.msi /qn        # removal (or "Programs and Features")
```

The package:

- installs for all users to `C:\Program Files\Nanshe` (the program, the knowledge base in Polish and English, licenses, `README.md`),
- creates the directory `C:\Program Files\Nanshe\wyniki`, accessible only to Administrators and the SYSTEM account, without permission inheritance,
- adds the program directory to the system PATH variable and removes the entry on uninstall,
- adds the Start menu shortcut "Nanshe (administrator console)", which opens an elevated console in the results directory,
- shows the Apache 2.0 license before installation,
- replaces a previous version installed from MSI (fixed product family identifier),
- refuses to install when it detects a version installed with the `install.ps1` script (both methods use the same directory).

Differences from the script installer: the results directory is in `Program Files`, not in `ProgramData`. In `ProgramData` a standard user can prepare the directory before installation; the script checks for that, and the MSI package avoids the problem by choosing a location where a standard user cannot create anything. On uninstall the result files are kept.

The package and the program are not digitally signed: Windows will show an unknown publisher warning. The WiX files are not signed either, which is why the build script checks the SHA-256 hash of the WiX archive stored in the script (the hash comes from a single download of the official release; it was not compared with an independent source).

## Privileges

- Run as administrator (elevated). The tool enables `SeDebugPrivilege`; without it only the processes of the current user are visible, and the tool prints a warning.
- Protected processes (PPL, for example LSASS with `RunAsPPL`, antivirus services) are inaccessible to an administrator as well: they are recorded in the result as inaccessible, and the result is partial.
- The result and the report state the privileges the scanner ran with (account, integrity level, `SeDebugPrivilege`). A scan without elevation or without `SeDebugPrivilege` is marked in the report with a warning on the first page.
- The SYSTEM account gives no more than an elevated administrator: in two measurements on the test host (2026-11-22) both scans had the same number of inaccessible processes (18, then 20) and the same processes with findings. Protected processes require a different route (a memory dump or reading from the hypervisor).

The scanner uses `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`, `VirtualQueryEx` and `ReadProcessMemory`. It writes nothing to the target and injects no code.

## Guard pages (PAGE_GUARD)

Reading a guard page clears the flag, which means it changes the state of the examined process. For that reason the scanner does not read such pages.

- An executable region with a guard gets the tag `GUARD-X` (30 points), counts as unread, and the result is partial. The content detectors (`ENT-X`, `HDR`) did not check it, and the report says so explicitly.
- Ordinary stack guard pages (RW) are not counted: every thread has them.

## System context

For a process with a finding of severity "suspicious" or above, the scan additionally collects, using metadata queries only (`PROCESS_QUERY_LIMITED_INFORMATION`):

| What | Source |
|---|---|
| parent, thread count, children | `CreateToolhelp32Snapshot` snapshot |
| command line | `NtQueryInformationProcess(ProcessCommandLineInformation)`; the kernel copies it into the scanner's buffer |
| user, integrity level, elevation | process token (`TokenUser`, `TokenIntegrityLevel`, `TokenElevation`) |
| start time, session | `GetProcessTimes`, `ProcessIdToSessionId` |
| program file: size, modification time, SHA-256 | path from `QueryFullProcessImageNameW`, file read from disk |
| TCP/UDP sockets (IPv4, IPv6) with owner | `GetExtendedTcpTable`, `GetExtendedUdpTable` |
| open handles: the total count plus named disk files, registry keys, sections, mutexes and handles to other processes (up to 300) | `NtQuerySystemInformation(SystemExtendedHandleInformation)`, then type and name through a copy of the handle |
| full region map | `VirtualQueryEx` (the same one the detectors worked on) |

Handles: to learn the type and name of an object, the scanner opens the process with the `PROCESS_DUP_HANDLE` right and copies the handle to itself with no rights at all (`DuplicateHandle` with access 0; for handles to processes, with the metadata query right), then closes the copy. The state of the examined process does not change, but for a moment the object has one more reference. This is the only place where the scanner asks for a right other than read. Names are queried only for disk files and for objects other than files: a name query on a pipe can hang the thread, so pipes and sockets are recorded without a name. Every name query goes through a worker thread with a 500 ms limit; after the limit is exceeded three times, the handle list of the process is cut short with a note in the report. A handle to another process is described by its PID, its name and the rights that allow interfering with that process (memory write, memory operations, thread creation, handle duplication).

The PID of a parent can be reused after the parent exits, so a parent is accepted only when it was created before the child; otherwise the ancestor chain is cut off with a note in the report.

Not collected: working directory, owner of the program file, digital signature of the file, pipe names, handles of unnamed objects (apart from their count). Handles work only in the 64-bit version of the tool. Protected processes for which the system denies `PROCESS_DUP_HANDLE` have only the handle count reported. `nanshe scan --no-context` disables the whole context and the map.

## Usage

```powershell
nanshe ps
nanshe scan --pid 1234 --json wynik.json
nanshe scan --all --min high --json host.json
nanshe report wynik.json
```

## Detectors that work on Windows

| Tag | Points | Condition |
|---|---|---|
| `RWX` | 30 | `PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_WRITECOPY` page |
| `X-PRIV` | 30 | executable private memory (`MEM_PRIVATE`) |
| `X-MAP` | 30 | executable `MEM_MAPPED` mapping, that is a section that is not a module image |
| `GUARD-X` | 30 | executable region with `PAGE_GUARD`, content not read |
| `ENT-X` | 20/30 | high entropy in an executable region |
| `HDR` | 40 | PE header (`MZ` + `PE\0\0`, non-zero Machine field, 1-96 sections) in a region not backed by a file: at the start of a page in any region, and in executable regions also at any offset |
| `THR-PRIV` | 40 | the thread start address lies in memory not backed by a file |
| `IMG-MOD` | 10/40 | pages of an executable, non-writable module image are no longer shared with the file (copy on write); 40 for `amsi.dll` and `wldp.dll`, 10 for the rest |

`MEMFD` and `DEL-EXEC` apply to Linux only.

`THR-PRIV` and `IMG-MOD` are not subject to the reduction for JIT runtimes. The start address comes from `NtQueryInformationThread`, and the page state from `QueryWorkingSetEx` (both read-only). `IMG-MOD` evaluates only the pages present in the working set of the process and does not show what was changed.

Measurement on the test host (2026-11-22, 240 processes): `IMG-MOD` occurred in 28 regions of 19 processes, including `user32.dll` in 10 processes, `clr.dll` in 9, `ntdll.dll` in 3 (WebView2 processes) and the libraries of the monitoring agent. I did not examine the causes one by one; known benign sources are relocation of libraries without ASLR, Chromium sandbox hooks and the .NET runtime itself. That is why an ordinary library gets 10 points ("info", also together with `ENT-X` in the same code; at 20 points ten ordinary processes became "suspicious"), and only the script security modules (`amsi.dll`, `wldp.dll`), whose modification in memory is typical of bypasses, carry the full severity. `THR-PRIV` did not occur even once in this measurement.

## SHA-256 hashes

The scan computes file hashes and stores them in the `files` field of the result (`--no-hashes` turns this off): the program file of every process, and the files mapped in processes with findings of severity "suspicious" or above (opened by device path). Every region with a finding additionally has a hash of its content. File limit: 512 MiB. The digital signature of files is not checked.

## Baseline and noise

Measurement of `scan --all` on the test host (2026-11-21): 246 processes, 22 GB, 45 s; 18 processes inaccessible, 25 with "suspicious" or "high" regions. Almost all of the noise is JIT runtimes:

- .NET Framework: private RWX heaps in every process with `clr.dll` loaded, one RWX page in the `clr.dll` image, executable sections not backed by a file (`X-MAP`),
- V8 in Electron/WebView2 applications.

### Severity reduction for JIT runtimes

Measurement on the test host (2026-11-22, `scan --all`, 244 processes): before the change 20 processes had "suspicious" or "high" regions, after the change 5. What remained was an in-house tool run from outside the system directories and four `Teams.exe` processes from the user profile, that is programs outside the system directories; 14 processes have findings with the reduction note, and 213 of 222 program files meet the directory and owner condition. The result after tightening the conditions (owner, runtime directories) is the same. This is one host.

On Windows a JIT runtime is recognised by a loaded module, because .NET and WebView2 run inside arbitrary programs. The severity of `RWX`, `X-PRIV`, `X-MAP` and `ENT-X` is divided by 3 (the findings stay visible, with the note `jit:dotnet` or `jit:webview2`) when both conditions are met:

- the program file is in `%SystemRoot%`, `%ProgramFiles%` or `%ProgramFiles(x86)%` (values from the scanner's environment), outside the subdirectories in which a standard user can create files (`Temp`, `Tasks`, `Tracing`, `spool`, `debug` and a few others), and its owner is SYSTEM, the Administrators group or TrustedInstaller,
- the process contains a module image (`MEM_IMAGE`) of the runtime loaded from its installation directory at the root of the volume: `clr.dll` from `\Windows\Microsoft.NET\Framework*`, `coreclr.dll` from `\Program Files\dotnet\shared` or `\Program Files\WindowsApps`, `msedge.dll` from the EdgeWebView or Edge directories.

The first condition exists so that loading `clr.dll` into one's own program from `%TEMP%` or from `C:\Windows\Temp` is not enough. `HDR` and `GUARD-X` are not reduced, and `X-MAP` only for sections not backed by a file (this is how .NET maps generated code); an executable mapping of a file never gets the reduction.

Limitations of this reduction:

- Code injected into a legitimate .NET process inherits the reduction. A private RWX region with low entropy then drops from 60 to 20 points ("info") and disappears from the default view; with high entropy (30 points) or with an image header (60) it stays visible. `--min info` shows everything.
- The owner of the program file is checked, not the whole DACL: a file owned by Administrators but writable by everyone will pass the condition. The digital signature is not verified.
- Programs outside the system directories (for example Electron in the user profile) do not get the reduction, so they remain in the result.

## Known limitations and blind spots

Each item has a sample in `tests/samples` and an expectation in `scripts/e2e.ps1`:

- **`SEC_IMAGE` section from a file outside the system directories** (`ximage`): `MEM_IMAGE` regions are not scored, the payload is invisible.
- **PE header with a wiped signature** (`pe-corrupt`): `HDR` does not react, `X-PRIV` remains. This is typical behaviour of today's C2 tools; a `HDR-STRIP` detector is planned.
- **Header off a page boundary in non-executable data**: invisible (deliberately, because copies of headers in ordinary data are an everyday occurrence). In executable regions a header at an offset is detected (`pe-offset`).
- A process with more than 1 048 576 regions: the first regions up to the limit are scanned, the findings are kept, and the result for the process is marked as incomplete.
- **Payload behind a guard** (`guard-hide`): the content is invisible, but the region gets `GUARD-X` and `X-PRIV`.
- 32-bit processes (WOW64) are not distinguished from 64-bit ones.
- Between two scans of a live process the number of regions changes (pool threads), so the findings are repeatable, not the counters.
- Windows Defender did not react to the binaries or the samples (one observation, test host, 2026-11).

## LLM layer and report

They work the same as on Linux. From a Windows host to Ollama on the local network: `nanshe explain wynik.json --url http://<host>:11434 --insecure-llm` (plain HTTP only on a trusted network). Tests: [tests.md](tests.md).
