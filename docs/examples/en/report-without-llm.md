# Nanshe: memory triage report

host 1a3b4982fe9e \| scan 2026-11-23T12:08:46Z

| Field | Value |
|---|---|
| Host | 1a3b4982fe9e |
| Scan time | 2026-11-23T12:08:46Z |
| Tool | nanshe 0.1.0 |
| Processes | 1 scanned, 1 with findings at severity "suspicious" or above |
| Findings | 8 |
| Completeness | complete |
| Host operating system | Debian GNU/Linux 12 (bookworm), kernel/version 7.1.10-200.fc44.aarch64 |
| System boot | 2026-11-13T15:36:49Z |
| Scan run by | root (uid 0) |
| Scanner privileges | root; CAP\_SYS\_PTRACE: yes |
| Classification | Confidential: this document contains data from the examined host; share only with those conducting the analysis |
| Result file | scan-result.json |
| Result SHA-256 | d96d2b877596e77fd19ed00a943a1c04f4fe05ede37b3375c46138e8b7ec16c6 |

> This is a triage result, not a verdict. Findings point to places that merit manual analysis; their absence does not prove a process is clean. Process names, paths and descriptions come from the examined system and may be controlled by an attacker.

> The report contains unfiltered data from the examined host: command lines, paths, network addresses, bytes and text strings from memory. These may include passwords and keys. Treat this document as evidence.

**Contents**

- 1. Executive summary
- 2. How to read this report
- 3. Process overview
- 4. Process 2050: nanshe-sample
- 5. What this report does not cover
- 6. Glossary
- 7. Legend

## 1. Executive summary

Overall assessment. At least one process has characteristics that a known runtime does not explain. It requires verification first, before any changes are made on the host.

| Field | Value |
|---|---|
| Scope | 1 process(es) on host 1a3b4982fe9e, state as of 2026-11-23T12:08:46Z |
| Completeness | complete for processes accessible to the scanner |
| Processes to verify | 1 (P1: 1, P2: 0, P3: 0) at severity "suspicious" or above |

#### Key processes

| Priority | Process | Why |
|---|---|---|
| P1 | 2050 nanshe-sample | A characteristic is present that a just-in-time (JIT) runtime does not explain: HDR (an entire program hidden in memory), MEMFD (code from a file that exists only in memory). |

#### Recommended actions

- For P1 processes: secure a memory dump of the process and do not restart the host before verification is complete; memory is the only medium holding these traces.

Limitations of the assessment: the review concerns the state of memory at a single moment, does not cover processes protected by the system or kernel memory, and relies on characteristics that also have benign causes. Details are in the chapter "What this report does not cover".

## 2. How to read this report

This report presents the result of a review of the memory of running processes. It points out memory areas with characteristics that are unusual for ordinary software. It does not determine whether the host has been compromised: every finding is a hypothesis to verify.

A process keeps its code and data in separate areas of memory called regions. In a typical program, code comes from a file on disk and is not modified while the program runs. The tool looks for deviations from this rule: code with no source file, modifiable code, code that looks like encrypted data, a program image loaded without the operating system loader, a thread running from memory not backed by a file, and modified library code.

Such deviations occur in malware, but also in legitimate software: in browsers, in the .NET and Java runtimes, and in security products. For this reason every finding in the report comes with a benign explanation and a malicious explanation, an assessment in the context of the given process, and a way to verify it.

Recommended reading order: the executive summary, the process table with priorities, and then, for processes with priority P1 and P2, the parts "Assessment", "What this program is" and "What the findings mean". Region details are there to support verification. The glossary is at the end.

| Severity | Meaning |
|---|---|
| high | several characteristics in one region; to be verified first |
| suspicious | a characteristic that needs an explanation; it often has a benign cause |
| info | a single weak characteristic; requires no action unless there are additional indications |

| Report section | What it shows and what to look for |
|---|---|
| Executive summary | the key conclusions, the overall assessment and the recommended actions on one page. |
| Assessment | the verification priority of the process, the reasoning behind it and the first step. |
| Processes and characteristics | the table shows which characteristics occurred in which processes and how many times. The cell color is the highest severity. A process that has a characteristic absent from similar processes is worth examining first. |
| Process tree with findings | all processes with findings on a common tree: it shows whether they share a parent. |
| What this program is | what a program with this name usually is and whether it is located where it should be. A process can choose its own name, so what counts is the file path and its SHA-256 hash. |
| Process tree | who started the examined program (above) and what it started itself (below). An unusual parent process, for example a text editor starting a command line, is an important clue. |
| Network | connections and ports opened by the program at the time of the scan. The remote address shows who the program is talking to; the LISTEN state means it is waiting for incoming connections. |
| Open files and handles | files and other resources the program is currently using. Unusual items are listed first: files deleted from disk, files in temporary directories and access to other processes. |
| Files mapped into memory | libraries and files loaded into the program's memory. Files outside system directories, deleted files and files that exist only in memory are listed first. |
| Address space map | the entire memory of the program, starting from the lowest address. The color shows what is located at a given place; red and orange blocks are findings. It is worth looking at what lies next to a finding. |
| Region entropy profile | the bar shows how random the data is in successive parts of the region. Turquoise is ordinary code and data; orange and red are data that looks encrypted or packed. |
| Byte preview | the first bytes of the finding in hexadecimal, with the same bytes as characters on the right. It lets you tell text, code and random data apart at a glance. |
| Text strings in the region | readable strings found in the region: function names, paths, addresses. They often reveal what the code is for. |
| LLM interpretation | hypotheses of a language model based on the region data. This is an aid to reasoning, not proof; the model can be wrong and does not change the score. |
| Region size and entropy | each point is one region with a finding: size on the horizontal axis, randomness of the data on the vertical axis. Ordinary heaps of just-in-time compiled code sit low and close together; a point that is high up or far from the rest is an outlier region. |
| SHA-256 hashes | fingerprints of files and of region contents. The same hash means identical content, so it can be looked up in databases of known files or compared between hosts. |
| From memory to network | on the left the regions with findings, in the middle the process, on the right its network connections at the time of the scan. The diagram shows that the suspicious code and the connection are in the same process; it does not prove that this code opened the connection. |

## 3. Process overview

| Priority | PID | Process | Severity | Regions | Max pts | Tags |
|---|---|---|---|---|---|---|
| P1 | 2050 | nanshe-sample | high | 3 | 90 | ENT-X, HDR, MEMFD, RWX, X-PRIV |

Priority is the order of verification (P1 first), derived from the type of findings and the process context. It is not an assessment of maliciousness; the rationale is in the "Assessment" section of each process.

#### Findings by tag

| Tag | Count | Share |
|---|---|---|
| ENT-X | 2 | ████████████████████████ |
| X-PRIV | 2 | ████████████████████████ |
| HDR | 1 | ████████████ |
| MEMFD | 1 | ████████████ |
| RWX | 1 | ████████████ |

#### Processes and characteristics

Number of regions with a given characteristic in each process; the cell colour is the highest severity of such a region. A process with a characteristic that similar processes lack is worth examining first.

| Process | ENT-X | X-PRIV | HDR | MEMFD | RWX |
|---|---|---|---|---|---|
| 2050 nanshe-sample | 2 (high) | 2 (high) | 1 (high) | 1 (high) | 1 (high) |

## 4. Process 2050: nanshe-sample

| Field | Value |
|---|---|
| System | linux/aarch64 |
| Program file | /target/debug/nanshe-sample |
| Regions | 26 total, 0 not read, 2.7 MiB scanned |
| Command line | /target/debug/nanshe-sample ctx 60 |
| User | root (uid 0) |
| Started | 2026-11-23T12:08:45Z |
| Parent process | 1356 (sh) |
| Working directory | /src |
| Threads | 1 |
| Program file: metadata | 5.1 MiB, modified 2026-11-22T15:30:04Z, owner root (uid 0), mode 0755 |
| Program file: SHA-256 | b30029f0ef4af73cfdac3069fc66c732cf4ea1f2b8f453c7c29b75f33100ef67 |
| effective capabilities (CapEff) | 00000000800c05fb |
| seccomp | filter |
| no\_new\_privs | 0 |

### Assessment

| Field | Value |
|---|---|
| Verification priority | P1: verify first |
| Rationale | A characteristic is present that a just-in-time (JIT) runtime does not explain: HDR (an entire program hidden in memory), MEMFD (code from a file that exists only in memory). The program file is located outside system directories. The process runs with high privileges, so compromising it would mean control of the host. The process has connections to remote addresses at scan time. |
| First step | Secure a full memory dump of process 2050 before making any change on the host, then follow the steps in "How to verify this region" for the highest-scoring regions. |

### What this program is

A program named nanshe-sample is usually: Test program of the Nanshe tool. It deliberately creates in memory the patterns the detectors look for; it does not execute any of them.

- A program can set its own process name, so the above relies on the name only as a hint.

#### What the process attributes mean

- effective capabilities (CapEff) = 00000000800c05fb: 0000000000000000 means no additional privileges; all hexadecimal ones (e.g. 000001ffffffffff) means full administrator privileges
- seccomp = filter: "filter" means the program runs in a sandbox, which limits the impact of a possible compromise
- no\_new\_privs = 0: 1 means the program and its descendants cannot gain higher privileges

### Process tree

- 1 sh: sh -c cargo test --workspace --features nanshe-cli/llm 2&gt;&amp;1 \| grep -E "^test result: .\* \[1-9\]\[0-9\]\* passed\|FAI
  - 1356 sh: sh scripts/example.sh /src/docs/przyklady
    - => 2050 nanshe-sample: /target/debug/nanshe-sample ctx 60 (examined process)
      - 2052 nanshe-sample: /target/debug/nanshe-sample clean 600

### Network

| Protocol | Local address | Remote address | State |
|---|---|---|---|
| tcp | 127.0.0.1:42551 | - | LISTEN |
| tcp | 127.0.0.1:56108 | 127.0.0.1:42551 | ESTABLISHED |
| tcp | 127.0.0.1:42551 | 127.0.0.1:56108 | ESTABLISHED |

### Open files and handles

Total descriptors or handles: 9. Recorded with a name: 9 (memfd: 1, file: 3, socket: 3, pipe: 1, device: 1).

| No. | Type | Object | Notes |
|---|---|---|---|
| 0x3 | memfd | memfd:payload | in memory only |
| 0x1 | file | /src/docs/przyklady/sample.pid | outside system directories |
| 0x7 | file | /tmp/ns-ctx-2050.dat | temporary directory |
| 0x8 | file | /tmp/ns-ctx-2050.gone | deleted from disk, temporary directory |

### Files mapped into memory

| File | Size | Code | Notes and description |
|---|---|---|---|
| /target/debug/nanshe-sample | 456 KiB | yes | program file, outside system directories |
| memfd:payload | 8 KiB | yes | in memory only; file that exists only in RAM; it is not present on disk |
| /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | 172 KiB | yes | the program that loads libraries at startup; normal in every process |
| /usr/lib/aarch64-linux-gnu/libc.so.6 | 1.6 MiB | yes | core system library; almost every program has it |
| /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | 196 KiB | yes | compiler support library; normal |

#### SHA-256 hashes of files

| File | SHA-256 |
|---|---|
| nanshe-sample | b30029f0ef4af73cfdac3069fc66c732cf4ea1f2b8f453c7c29b75f33100ef67 |
| memfd:payload | none: file inaccessible: Operation not permitted (os error 1) |
| ld-linux-aarch64.so.1 | 17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df |
| libc.so.6 | e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0 |
| libgcc\_s.so.1 | 046856f95f4636f1fc7c3a12bf4f3cd5634c2fc5145c3fdf7395d4f349fa69c7 |

### Address space map

All 26 regions of the process from the lowest address. Adjacent mappings of the same file are merged into one row, long runs of ordinary mappings are collapsed, and large unused ranges are shown as gaps. Block height grows with size (logarithmic scale).

| Start | End | Size | Perms | Type | Contents | Notes |
|---|---|---|---|---|---|---|
| 0xaaaac1000000 | 0xaaaac1081000 | 456 KiB | r-x r-- rw- | code from file | /target/debug/nanshe-sample | mappings: 3 |
| 0xaaaac1081000 | 0xaaaaf1a5a000 | 777.8 MiB | - | gap | unused address range |  |
| 0xaaaaf1a5a000 | 0xaaaaf1a7b000 | 132 KiB | rw- | heap | \[heap\] |  |
| 0xaaaaf1a7b000 | 0xffff80350000 | 85.3 TiB | - | gap | unused address range |  |
| 0xffff80350000 | 0xffff80360000 | 64 KiB | rwx | FINDING (high) | anonymous memory | &lt;&lt;&lt; RWX, X-PRIV, ENT-X (90 pts) |
| 0xffff80360000 | 0xffff80502000 | 1.6 MiB | r-x --- r-- rw- | code from file | /usr/lib/aarch64-linux-gnu/libc.so.6 | mappings: 4 |
| 0xffff80502000 | 0xffff8050f000 | 52 KiB | rw- | anonymous memory | anonymous memory |  |
| 0xffff80510000 | 0xffff80541000 | 196 KiB | r-x --- r-- rw- | code from file | /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | mappings: 4 |
| 0xffff8054b000 | 0xffff80572000 | 156 KiB | r-x | code from file | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 |  |
| 0xffff80574000 | 0xffff80578000 | 16 KiB | r-x | FINDING (high) | anonymous memory | &lt;&lt;&lt; X-PRIV, HDR (70 pts) |
| 0xffff80578000 | 0xffff8057f000 | 28 KiB | --- rw- | anonymous memory | anonymous memory | mappings: 3 |
| 0xffff8057f000 | 0xffff80581000 | 8 KiB | r-x | FINDING (high) | memfd:payload | &lt;&lt;&lt; MEMFD, ENT-X (70 pts) |
| 0xffff80581000 | 0xffff80583000 | 8 KiB | rw- | anonymous memory | anonymous memory |  |
| 0xffff80583000 | 0xffff80587000 | 16 KiB | r-- | kernel region | \[vvar\] |  |
| 0xffff80587000 | 0xffff80589000 | 8 KiB | r-x | kernel region | \[vdso\] |  |
| 0xffff80589000 | 0xffff8058d000 | 16 KiB | r-- rw- | data from file | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | mappings: 2 |
| 0xffff8058d000 | 0xffffcf95b000 | 1.2 GiB | - | gap | unused address range |  |
| 0xffffcf95b000 | 0xffffcf97c000 | 132 KiB | rw- | stack | \[stack\] |  |

### What the findings mean in this process

#### ENT-X + RWX + X-PRIV: encrypted or packed code created at run time

Regions with this set of characteristics: 1; highest score: 90 pts.

A region not backed by a file, writable and executable, filled with data that looks random. This is the strongest combination of characteristics in this report.

- Benign explanation: Programs protected against copying and analysis (packers, game protection) unpack their code this way.
- Benign explanation: Less often: a JIT runtime keeping compressed data next to code.
- Malicious explanation: An encrypted payload that will be decoded and run in the same place. This is how loaders (stagers) and many remote access tools work.
- In this process: The absence of a JIT runtime in the process increases the severity of this finding.

Technical basis. ENT-X: Shannon entropy calculated per 4 KiB page on a scale of 0-8; thresholds 7.2 (high) and 7.8 (very high). In code backed by a file, isolated pages above the threshold carry reduced severity. RWX: Mapping with rwx permissions in /proc/&lt;pid&gt;/maps (PROT\_READ, PROT\_WRITE and PROT\_EXEC at the same time). X-PRIV: Executable mapping with no file path in /proc/&lt;pid&gt;/maps (anonymous memory), excluding kernel regions (\[vdso\] and similar).

Related MITRE ATT&amp;CK techniques (indicative; a finding does not prove the technique was used): T1027 Obfuscated Files or Information, T1027.002 Software Packing, T1055 Process Injection, T1620 Reflective Code Loading.

#### HDR + X-PRIV: program loaded into memory not backed by a file

Regions with this set of characteristics: 1; highest score: 70 pts.

Executable memory not backed by a file contains the header of a program or a library. Someone loaded an executable file manually, without the operating system loader.

- Benign explanation: Some security products, emulators and developer tools load libraries from memory.
- Benign explanation: A copy of the program's own file kept for integrity checking.
- Malicious explanation: Reflective loading: a library or a program delivered over the network and run without being written to disk. This is a typical technique of remote access tools.

Technical basis. HDR: An ELF header (with a valid file type), a PE header (MZ and PE signatures, non-zero Machine field, 1-96 sections) or a Mach-O header; checked at the start of a page in every region not backed by a file except a non-executable stack, and at any offset only in executable regions. X-PRIV: Executable mapping with no file path in /proc/&lt;pid&gt;/maps (anonymous memory), excluding kernel regions (\[vdso\] and similar).

Related MITRE ATT&amp;CK techniques (indicative; a finding does not prove the technique was used): T1055 Process Injection, T1620 Reflective Code Loading.

#### ENT-X + MEMFD: encrypted or packed code from a file that exists only in memory

Regions with this set of characteristics: 1; highest score: 70 pts.

Code is executed from a file that exists only in RAM, and its content appears random.

- Benign explanation: Rare. Some runtimes and sandboxes use memfd, but their code does not look encrypted.
- Malicious explanation: A program downloaded from the network and run without being written to disk, and additionally packed. This is the typical picture of fileless malware on Linux.

Technical basis. ENT-X: Shannon entropy calculated per 4 KiB page on a scale of 0-8; thresholds 7.2 (high) and 7.8 (very high). In code backed by a file, isolated pages above the threshold carry reduced severity. MEMFD: Executable mapping of an object created by memfd\_create (a /memfd:&lt;name&gt; entry in /proc/&lt;pid&gt;/maps).

Related MITRE ATT&amp;CK techniques (indicative; a finding does not prove the technique was used): T1027 Obfuscated Files or Information, T1027.002 Software Packing, T1620 Reflective Code Loading.

#### Region size and entropy

Each point is one of the 4 regions with a finding in this process (including severity "info"). A point high up (entropy of 7.2 or more) or far from the rest is an outlier region.

| Entropy \\ size | up to 16 KiB | up to 256 KiB | up to 4 MiB | above 4 MiB |
|---|---|---|---|---|
| very high (7.8 and above) | 1 | 1 | 1 | - |
| high (7.2-7.8) | - | - | - | - |
| medium (5-7.2) | - | - | - | - |
| low (below 5) | 1 | - | - | - |

### From memory to network

Regions with findings, the process and its network connections at scan time. The diagram shows that suspicious code and a connection coexist in one process; it does not prove that code from a given region opened the connection.

| Region in memory | Process | Network |
|---|---|---|
| 0xffff80350000 RWX, X-PRIV, ENT-X (90 pts) | =&gt; 2050 nanshe-sample, root (uid 0) =&gt; | tcp 127.0.0.1:56108 -&gt; 127.0.0.1:42551 (ESTABLISHED) |
| 0xffff80574000 X-PRIV, HDR (70 pts) |  | tcp 127.0.0.1:42551 -&gt; 127.0.0.1:56108 (ESTABLISHED) |
| 0xffff8057f000 MEMFD, ENT-X (70 pts) |  | listening tcp 127.0.0.1:42551 |

### Regions with findings

| Address | Size | Perms | Severity | Pts | Entropy | Tags | Source |
|---|---|---|---|---|---|---|---|
| 0xffff80350000 | 64 KiB | rwx | high | 90 | 7.96 | RWX, X-PRIV, ENT-X | no file |
| 0xffff80574000 | 16 KiB | r-x | high | 70 | 4.06 | X-PRIV, HDR | no file |
| 0xffff8057f000 | 8 KiB | r-x | high | 70 | 7.95 | MEMFD, ENT-X | memfd:payload |

### Region 0xffff80350000 (high, 90 pts)

In short: encrypted or packed code created at run time. The explanation is above, in the section "What the findings mean in this process".

- RWX: region both writable and executable
- X-PRIV: executable private/anonymous memory not backed by a file
- ENT-X: very high entropy in an executable region: max 7.96, pages above threshold: 16 of 16

| Field | Value |
|---|---|
| Address range | 0xffff80350000 - 0xffff80360000 (64 KiB, 64 KiB read) |
| Type and source | private memory; not backed by a file |
| Entropy | maximum 7.96, mean 7.95 (scale 0-8); zero pages: 0 |
| Content SHA-256 | 2e043edf3a68f7b9549ebdbc0770ec807dd4eaaa83f3aea3eb459103b1c3566e |
| Neighbour below | 0xaaaaf1a5a000 rw- \[heap\] (gap 85.3 TiB) |
| Neighbour above | 0xffff80360000 r-x /usr/lib/aarch64-linux-gnu/libc.so.6 (adjacent) |

#### Region entropy profile

```text
0xffff80350000 ████████████████ 0xffff80360000
```

Segment entropy (0-8): lowest 8.0, highest 8.0; 16 segments of 4 KiB.

#### Byte preview from 0xffff80350000

```text
0xffff80350000  00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41  ....LoadLibraryA
0xffff80350010  00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00  .GetProcAddress.
0xffff80350020  56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 ac a8 07  VirtualAlloc....
0xffff80350030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff80350040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff80350050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff80350060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff80350070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Text strings in the region

- LoadLibraryA
- GetProcAddress
- VirtualAlloc
- no}P=NHfQr

#### How to verify this region

- See what this region is in the process memory map: grep -n ffff80350000 /proc/2050/maps
- Save the region content to a file (requires gdb, pauses the process briefly): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff80350000.bin 0xffff80350000 0xffff80360000"
- Check who started the process and with what command: ps -o pid,ppid,user,lstart,cmd -p 2050
- Check whether the program has a JIT runtime: grep -E "libjvm\|libnode\|libv8\|libmono\|libcoreclr\|libjs" /proc/2050/maps
- After saving the region, compare its SHA-256 hash against databases of known files: sha256sum /tmp/region\_ffff80350000.bin

### Region 0xffff80574000 (high, 70 pts)

In short: program loaded into memory not backed by a file. The explanation is above, in the section "What the findings mean in this process".

- X-PRIV: executable private/anonymous memory not backed by a file
- HDR: ELF header in a region not backed by a file

| Field | Value |
|---|---|
| Address range | 0xffff80574000 - 0xffff80578000 (16 KiB, 16 KiB read) |
| Type and source | private memory; not backed by a file |
| Entropy | maximum 4.06, mean 2.85 (scale 0-8); zero pages: 0 |
| Content SHA-256 | 4063392c86a10c8e77471f136ce93dc116b19f38a46082e4b8b5078cc17fcb1b |
| Neighbour below | 0xffff8054b000 r-x /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 (gap 8 KiB) |
| Neighbour above | 0xffff80578000 --- anonymous memory (adjacent) |

#### Region entropy profile

```text
0xffff80574000 ▃▅▃▃ 0xffff80578000
```

Segment entropy (0-8): lowest 2.0, highest 4.1; 4 segments of 4 KiB.

#### Image header read from memory

| Field | Value |
|---|---|
| Format | ELF 64-bit, AArch64 |
| Type | library or PIE program (DYN) |
| Entry point | 0xb180 |
| Program / section headers | 10 / 41 |

#### Byte preview from 0xffff80574000

```text
0xffff80574000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
0xffff80574010  03 00 b7 00 01 00 00 00 80 b1 00 00 00 00 00 00  ................
0xffff80574020  40 00 00 00 00 00 00 00 a0 f3 50 00 00 00 00 00  @.........P.....
0xffff80574030  00 00 00 00 40 00 38 00 0a 00 40 00 29 00 28 00  ....@.8...@.).(.
0xffff80574040  06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00  ........@.......
0xffff80574050  40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  @.......@.......
0xffff80574060  30 02 00 00 00 00 00 00 30 02 00 00 00 00 00 00  0.......0.......
0xffff80574070  08 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00  ................
```

#### Text strings in the region

- /lib/ld-linux-aarch64.so.1
- \_ITM\_deregisterTMCloneTable
- \_\_gmon\_start\_\_
- \_ITM\_registerTMCloneTable
- \_Unwind\_Resume
- \_Unwind\_Backtrace
- \_Unwind\_GetLanguageSpecificData
- \_Unwind\_GetIPInfo
- \_Unwind\_GetDataRelBase
- \_Unwind\_GetRegionStart
- \_Unwind\_SetIP
- \_Unwind\_GetIP
- \_Unwind\_DeleteException
- \_Unwind\_RaiseException
- \_Unwind\_SetGR
- ... and 25 more in the result file

#### How to verify this region

- See what this region is in the process memory map: grep -n ffff80574000 /proc/2050/maps
- Save the region content to a file (requires gdb, pauses the process briefly): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff80574000.bin 0xffff80574000 0xffff80578000"
- Check who started the process and with what command: ps -o pid,ppid,user,lstart,cmd -p 2050
- After saving the region, check what kind of executable file it is: file /tmp/region\_ffff80574000.bin and readelf -h /tmp/region\_ffff80574000.bin

### Region 0xffff8057f000 (high, 70 pts)

In short: encrypted or packed code from a file that exists only in memory. The explanation is above, in the section "What the findings mean in this process".

- MEMFD: executable mapping memfd:payload
- ENT-X: very high entropy in an executable region: max 7.95, pages above threshold: 2 of 2

| Field | Value |
|---|---|
| Address range | 0xffff8057f000 - 0xffff80581000 (8 KiB, 8 KiB read) |
| Type and source | mapping; memfd:payload |
| Entropy | maximum 7.95, mean 7.95 (scale 0-8); zero pages: 0 |
| Content SHA-256 | b511e7d5ceda23c4c9555f760682f3089d78baf592641fdce4ceac79f973cc94 |
| Neighbour below | 0xffff8057d000 rw- anonymous memory (adjacent) |
| Neighbour above | 0xffff80581000 rw- anonymous memory (adjacent) |

#### Region entropy profile

```text
0xffff8057f000 ██ 0xffff80581000
```

Segment entropy (0-8): lowest 8.0, highest 8.0; 2 segments of 4 KiB.

#### Byte preview from 0xffff8057f000

```text
0xffff8057f000  ea 1c 58 d8 97 be 9d 50 12 c9 a7 6e 43 b5 af 76  ..X....P...nC..v
0xffff8057f010  c2 a0 72 7d 39 91 3d 65 90 d8 4f a3 7f c7 4f 6f  ..r}9.=e..O...Oo
0xffff8057f020  09 25 49 a6 b7 01 0d a5 40 3e 28 89 cd ac a8 07  .%I.....@>(.....
0xffff8057f030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff8057f040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff8057f050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff8057f060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff8057f070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Text strings in the region

- no}P=NHfQr

#### How to verify this region

- See what this region is in the process memory map: grep -n ffff8057f000 /proc/2050/maps
- Save the region content to a file (requires gdb, pauses the process briefly): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff8057f000.bin 0xffff8057f000 0xffff80581000"
- Check who started the process and with what command: ps -o pid,ppid,user,lstart,cmd -p 2050
- Find the memfd file descriptor and copy the whole file: ls -l /proc/2050/fd \| grep memfd, then cp /proc/2050/fd/NUMBER /tmp/memfd\_2050.bin
- After saving the region, compare its SHA-256 hash against databases of known files: sha256sum /tmp/region\_ffff8057f000.bin

## 5. What this report does not cover

- 1 regions with findings below severity "suspicious" were omitted; they are in the result file.
- The byte preview in the report is the first 128 bytes of a finding; the full 256 bytes are in the result file (JSON). The tool does not take a full dump of the region.
- System context is the state at scan time: connections closed earlier, child processes that have exited and deleted files are not visible. The report does not cover history (logs, audit trail).
- The scan covers process memory at scan time; it does not cover the kernel, the contents of files on disk or the contents of network traffic.
- The result file contains SHA-256 hashes of 5 files (programs of all processes and files mapped in processes with findings); the report shows only some. The report does not check hashes against external databases.
- The THR-PRIV finding relies on the thread start address (Windows) or on the place where waiting threads call the kernel (Linux); a thread that was computing at scan time is not assessed on Linux. IMG-MOD states that code from a file was changed in memory, but does not show the differences.
- No LLM interpretation (report built from deterministic data only).

## 6. Glossary

| Term | Meaning |
|---|---|
| process | a running program together with its memory; it has a PID number |
| PID | a number the system assigns to a process; after the process ends, the number may be reused |
| memory region | a contiguous piece of process memory with uniform permissions, for example the code of one library or the stack |
| permissions r, w, x | r: may be read, w: may be written, x: may be run as code; the notation rwx means all three at once |
| anonymous (private) memory | memory that does not come from a file; the program received it empty from the system and filled it itself |
| file mapping | a file from disk visible directly in process memory; this is how programs and libraries are loaded |
| entropy | a measure of data randomness on a scale of 0-8; text is around 4-5, ordinary code 5-6.5, encrypted and packed data above 7.5 |
| JIT (just-in-time compilation) | creating machine code while the program runs; .NET, Java and JavaScript engines do this |
| shellcode | short self-contained machine code injected into memory, usually in order to download and run the attacker's actual tool |
| reflective loading | loading a library or a program from memory, with no file on disk and without the operating system loader |
| packer | a tool that compresses or encrypts a program and attaches code that unpacks it at startup |
| code injection | placing and running one's own code in the memory of another process |
| SHA-256 | a hash (fingerprint) of a file; the same file always has the same hash, so it can be compared with databases of known files |
| stack and heap | memory areas for the program's working data; they normally should not be executable |
| partial result | the scan did not read everything, for example because the system denied access to some processes; the absence of findings in the unread part proves nothing |
| allowlist | known JIT runtimes for which the tool lowers the severity of findings typical of them; the findings remain in the result |
| thread | one of the parallel lines of execution in a process; every process has at least one |
| hook | overwriting the start of a function so that someone else's code runs first; both security products and malware do this |
| MITRE ATT&amp;CK | a public catalog of techniques used by attackers; identifiers such as T1055 make it possible to name a technique unambiguously |
| priority P1, P2, P3 | the order in which processes in this report should be verified: P1 first, P3 when convenient; it follows from the type of findings and the process context and is not a rating of maliciousness |
| /proc | the directory in which Linux exposes information about running processes; the tool only reads from it |
| memfd | a file created in RAM with the memfd\_create call; it is not present on disk |
| ELF | the format of executables and libraries on Linux; it starts with the bytes 7f 45 4c 46 |
| vdso | a small piece of kernel code inserted into every process; it is normal |
| capabilities | parts of administrator privileges granted to a process individually; the CapEff field shows the active ones |
| seccomp | a filter that restricts the system calls a process can make; when enabled, the program is running in a sandbox |
| LD\_PRELOAD | a variable that forces the specified library to be loaded before all others; sometimes used to replace functions |

The explanations in this report come from the tool's knowledge base (version 2026-11-22, system linux). They describe typical cases; they do not replace checking the specific process.

## 7. Legend

| Tag | Meaning |
|---|---|
| ENT-X | code that looks encrypted: The content of an executable region has a distribution close to random. Machine code has a clear structure and much lower entropy. |
| HDR | an entire program hidden in memory: Memory with no source file contains the header of an executable file or a library. This means that a program image was loaded without the operating system's loading mechanism. |
| MEMFD | code from a file that exists only in memory: The process executes code from a file created with the memfd\_create call. Such a file exists only in RAM and is never written to disk. |
| RWX | memory writable and executable at once: The memory region is writable and executable at the same time. In a typical program, code is available for reading and execution only. |
| X-PRIV | code with no file on disk: The process contains executable code that does not come from any file. The code was created in memory while the process was running. |

Region severity follows from the sum of points of its findings: below 30 "info", 30-59 "suspicious", 60 and above "high".

---

Triage, not a verdict.
