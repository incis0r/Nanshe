# Nanshe: memory triage report

host 6996d75bf01b \| scan 2026-11-23T14:46:32Z

| Field | Value |
|---|---|
| Host | 6996d75bf01b |
| Scan time | 2026-11-23T14:46:32Z |
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
| Result SHA-256 | 4a0b0804674a06aff3ffe85cc97a6e4ab6c828381709dd78bd5da6fce1e1ed67 |

> This is a triage result, not a verdict. Findings point to places that merit manual analysis; their absence does not prove a process is clean. Process names, paths and descriptions come from the examined system and may be controlled by an attacker.

> The report contains unfiltered data from the examined host: command lines, paths, network addresses, bytes and text strings from memory. These may include passwords and keys. Treat this document as evidence.

**Contents**

- [1. Executive summary](#ch-1)
- [2. How to read this report](#ch-2)
- [3. Process overview](#ch-3)
- [4. Process 678: nanshe-sample](#ch-4)
- [5. What this report does not cover](#ch-5)
- [6. Glossary](#ch-6)
- [7. Legend](#ch-7)

<a id="ch-1"></a>

## 1. Executive summary

Overall assessment. At least one process has characteristics that a known runtime does not explain. It requires verification first, before any changes are made on the host.

| Field | Value |
|---|---|
| Scope | 1 process(es) on host 6996d75bf01b, state as of 2026-11-23T14:46:32Z |
| Completeness | complete for processes accessible to the scanner |
| Processes to verify | 1 (P1: 1, P2: 0, P3: 0) at severity "suspicious" or above |

#### Key processes

| Priority | Process | Why |
|---|---|---|
| P1 | 678 nanshe-sample | A characteristic is present that a just-in-time (JIT) runtime does not explain: HDR (an entire program hidden in memory), MEMFD (code from a file that exists only in memory). |

#### Recommended actions

- For P1 processes: secure a memory dump of the process and do not restart the host before verification is complete; memory is the only medium holding these traces.

Limitations of the assessment: the review concerns the state of memory at a single moment, does not cover processes protected by the system or kernel memory, and relies on characteristics that also have benign causes. Details are in the chapter "What this report does not cover".

<a id="ch-2"></a>

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

<a id="ch-3"></a>

## 3. Process overview

| Priority | PID | Process | Severity | Regions | Max pts | Tags |
|---|---|---|---|---|---|---|
| P1 | 678 | nanshe-sample | high | 3 | 90 | ENT-X, HDR, MEMFD, RWX, X-PRIV |

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
| 678 nanshe-sample | 2 (high) | 2 (high) | 1 (high) | 1 (high) | 1 (high) |

<a id="ch-4"></a>

## 4. Process 678: nanshe-sample

| Field | Value |
|---|---|
| System | linux/aarch64 |
| Program file | /target/debug/nanshe-sample |
| Regions | 26 total, 0 not read, 2.7 MiB scanned |
| Command line | `/target/debug/nanshe-sample ctx 60` |
| User | root (uid 0) |
| Started | 2026-11-23T14:46:31Z |
| Parent process | 1 (sh) |
| Working directory | /src |
| Threads | 1 |
| Program file: metadata | 5.1 MiB, modified 2026-11-23T14:42:49Z, owner root (uid 0), mode 0755 |
| Program file: SHA-256 | e73e6df025136d2b02d1fc3a530130a62ed5fde9f234c994cb5770c207935dbb |
| effective capabilities (CapEff) | 00000000800c05fb |
| seccomp | filter |
| no\_new\_privs | 0 |

### Assessment

| Field | Value |
|---|---|
| Verification priority | P1: verify first |
| Rationale | A characteristic is present that a just-in-time (JIT) runtime does not explain: HDR (an entire program hidden in memory), MEMFD (code from a file that exists only in memory). The program file is located outside system directories. The process runs with high privileges, so compromising it would mean control of the host. The process has connections to remote addresses at scan time. |
| First step | Secure a full memory dump of process 678 before making any change on the host, then follow the steps in "How to verify this region" for the highest-scoring regions. |

### What this program is

A program named nanshe-sample is usually: Test program of the Nanshe tool. It deliberately creates in memory the patterns the detectors look for; it does not execute any of them.

- A program can set its own process name, so the above relies on the name only as a hint.

#### What the process attributes mean

- effective capabilities (CapEff) = 00000000800c05fb: 0000000000000000 means no additional privileges; all hexadecimal ones (e.g. 000001ffffffffff) means full administrator privileges
- seccomp = filter: "filter" means the program runs in a sandbox, which limits the impact of a possible compromise
- no\_new\_privs = 0: 1 means the program and its descendants cannot gain higher privileges

### Process tree

- 1 sh: sh scripts/example.sh /src/docs/examples
  - => 678 nanshe-sample: /target/debug/nanshe-sample ctx 60 (examined process)
    - 680 nanshe-sample: /target/debug/nanshe-sample clean 600

### Network

| Protocol | Local address | Remote address | State |
|---|---|---|---|
| tcp | 127.0.0.1:42603 | - | LISTEN |
| tcp | 127.0.0.1:37332 | 127.0.0.1:42603 | ESTABLISHED |
| tcp | 127.0.0.1:42603 | 127.0.0.1:37332 | ESTABLISHED |

### Open files and handles

Total descriptors or handles: 9. Recorded with a name: 9 (memfd: 1, file: 3, socket: 3, pipe: 1, device: 1).

| No. | Type | Object | Notes |
|---|---|---|---|
| 0x3 | memfd | memfd:payload | in memory only |
| 0x1 | file | /src/docs/examples/sample.pid | outside system directories |
| 0x7 | file | /tmp/ns-ctx-678.dat | temporary directory |
| 0x8 | file | /tmp/ns-ctx-678.gone | deleted from disk, temporary directory |

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
| nanshe-sample | e73e6df025136d2b02d1fc3a530130a62ed5fde9f234c994cb5770c207935dbb |
| memfd:payload | none: file inaccessible: Operation not permitted (os error 1) |
| ld-linux-aarch64.so.1 | 17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df |
| libc.so.6 | e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0 |
| libgcc\_s.so.1 | 046856f95f4636f1fc7c3a12bf4f3cd5634c2fc5145c3fdf7395d4f349fa69c7 |

### Address space map

All 26 regions of the process from the lowest address. Adjacent mappings of the same file are merged into one row, long runs of ordinary mappings are collapsed, and large unused ranges are shown as gaps. Block height grows with size (logarithmic scale).

| Start | End | Size | Perms | Type | Contents | Notes |
|---|---|---|---|---|---|---|
| 0xaaaace420000 | 0xaaaace4a1000 | 456 KiB | r-x r-- rw- | code from file | /target/debug/nanshe-sample | mappings: 3 |
| 0xaaaace4a1000 | 0xaaaae231a000 | 318.5 MiB | - | gap | unused address range |  |
| 0xaaaae231a000 | 0xaaaae233b000 | 132 KiB | rw- | heap | \[heap\] |  |
| 0xaaaae233b000 | 0xffffae2d0000 | 85.3 TiB | - | gap | unused address range |  |
| [0xffffae2d0000](#r-678-ffffae2d0000) | 0xffffae2e0000 | 64 KiB | rwx | FINDING (high) | anonymous memory | [&lt;&lt;&lt; RWX, X-PRIV, ENT-X (90 pts)](#r-678-ffffae2d0000) |
| 0xffffae2e0000 | 0xffffae482000 | 1.6 MiB | r-x --- r-- rw- | code from file | /usr/lib/aarch64-linux-gnu/libc.so.6 | mappings: 4 |
| 0xffffae482000 | 0xffffae48f000 | 52 KiB | rw- | anonymous memory | anonymous memory |  |
| 0xffffae490000 | 0xffffae4c1000 | 196 KiB | r-x --- r-- rw- | code from file | /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | mappings: 4 |
| 0xffffae4cf000 | 0xffffae4f6000 | 156 KiB | r-x | code from file | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 |  |
| [0xffffae4f8000](#r-678-ffffae4f8000) | 0xffffae4fc000 | 16 KiB | r-x | FINDING (high) | anonymous memory | [&lt;&lt;&lt; X-PRIV, HDR (70 pts)](#r-678-ffffae4f8000) |
| 0xffffae4fc000 | 0xffffae503000 | 28 KiB | --- rw- | anonymous memory | anonymous memory | mappings: 3 |
| [0xffffae503000](#r-678-ffffae503000) | 0xffffae505000 | 8 KiB | r-x | FINDING (high) | memfd:payload | [&lt;&lt;&lt; MEMFD, ENT-X (70 pts)](#r-678-ffffae503000) |
| 0xffffae505000 | 0xffffae507000 | 8 KiB | rw- | anonymous memory | anonymous memory |  |
| 0xffffae507000 | 0xffffae50b000 | 16 KiB | r-- | kernel region | \[vvar\] |  |
| 0xffffae50b000 | 0xffffae50d000 | 8 KiB | r-x | kernel region | \[vdso\] |  |
| 0xffffae50d000 | 0xffffae511000 | 16 KiB | r-- rw- | data from file | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | mappings: 2 |
| 0xffffae511000 | 0xffffd5fdd000 | 634.8 MiB | - | gap | unused address range |  |
| 0xffffd5fdd000 | 0xffffd5ffe000 | 132 KiB | rw- | stack | \[stack\] |  |

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
| 0xffffae2d0000 RWX, X-PRIV, ENT-X (90 pts) | =&gt; 678 nanshe-sample, root (uid 0) =&gt; | tcp 127.0.0.1:37332 -&gt; 127.0.0.1:42603 (ESTABLISHED) |
| 0xffffae4f8000 X-PRIV, HDR (70 pts) |  | tcp 127.0.0.1:42603 -&gt; 127.0.0.1:37332 (ESTABLISHED) |
| 0xffffae503000 MEMFD, ENT-X (70 pts) |  | listening tcp 127.0.0.1:42603 |

### Regions with findings

| Address | Size | Perms | Severity | Pts | Entropy | Tags | Source |
|---|---|---|---|---|---|---|---|
| 0xffffae2d0000 | 64 KiB | rwx | high | 90 | 7.96 | RWX, X-PRIV, ENT-X | no file |
| 0xffffae4f8000 | 16 KiB | r-x | high | 70 | 4.08 | X-PRIV, HDR | no file |
| 0xffffae503000 | 8 KiB | r-x | high | 70 | 7.95 | MEMFD, ENT-X | memfd:payload |

<a id="r-678-ffffae2d0000"></a>

### Region 0xffffae2d0000 (high, 90 pts)

In short: encrypted or packed code created at run time. The explanation is above, in the section "What the findings mean in this process".

- RWX: region both writable and executable
- X-PRIV: executable private/anonymous memory not backed by a file
- ENT-X: very high entropy in an executable region: max 7.96, pages above threshold: 16 of 16

| Field | Value |
|---|---|
| Address range | 0xffffae2d0000 - 0xffffae2e0000 (64 KiB, 64 KiB read) |
| Type and source | private memory; not backed by a file |
| Entropy | maximum 7.96, mean 7.95 (scale 0-8); zero pages: 0 |
| Content SHA-256 | 2e043edf3a68f7b9549ebdbc0770ec807dd4eaaa83f3aea3eb459103b1c3566e |
| Neighbour below | 0xaaaae231a000 rw- \[heap\] (gap 85.3 TiB) |
| Neighbour above | 0xffffae2e0000 r-x /usr/lib/aarch64-linux-gnu/libc.so.6 (adjacent) |

#### Region entropy profile

```text
0xffffae2d0000 ████████████████ 0xffffae2e0000
```

Segment entropy (0-8): lowest 8.0, highest 8.0; 16 segments of 4 KiB.

#### Byte preview from 0xffffae2d0000

```text
0xffffae2d0000  00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41  ....LoadLibraryA
0xffffae2d0010  00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00  .GetProcAddress.
0xffffae2d0020  56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 ac a8 07  VirtualAlloc....
0xffffae2d0030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffffae2d0040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffffae2d0050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffffae2d0060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffffae2d0070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Text strings in the region

- LoadLibraryA
- GetProcAddress
- VirtualAlloc
- no}P=NHfQr

#### How to verify this region

1. See what this memory region is in the process memory map
   `grep -n ffffae2d0000 /proc/678/maps`
   How to read the result: The output is one line: address range, permissions (e.g. r-xp, the letter x means executable code) and, at the end, a file path. Benign case: the line ends with the path of a library or program in a system directory such as /usr/lib. Be concerned if there is no path (memory not backed by a file), a memfd: entry, a (deleted) note, or a path in /tmp or /dev/shm together with the letter x in the permissions: in that case save the region to a file (next step).
2. Save the memory region content to a file (requires gdb, pauses the process briefly)
   `gdb -p 678 -batch -ex "dump memory /tmp/region_ffffae2d0000.bin 0xffffae2d0000 0xffffae2e0000"`
   How to read the result: Expected result: the command ends without an error and a file /tmp/region\_... appears, with a size equal to the size of the region. The messages "Operation not permitted" or "Cannot access memory" mean missing permissions (run as root) or that the region no longer exists: on their own they do not indicate a threat. The saved file is the input for the next steps and a piece of evidence, do not run it.
3. Check who started the process and with what command
   `ps -o pid,ppid,user,lstart,cmd -p 678`
   How to read the result: Look at the columns PPID (parent process), USER, STARTED (start time) and CMD (command). Benign case: the user and the command fit the role of this server, and PPID is 1 (systemd) or a known service manager. Be concerned if the command was started from /tmp or /dev/shm, if a shell (sh, bash) was started by a web server or a database, or if the start time matches the suspected incident: in that case check the parent process with the same command, using its PPID.
4. Check whether the program has a JIT runtime (a mechanism that creates code while running, e.g. Java, Node.js, .NET)
   `grep -E "libjvm¦libnode¦libv8¦libmono¦libcoreclr¦libjs" /proc/678/maps`
   How to read the result: If the command prints lines with the names of such libraries, the program creates code in memory itself, and a region that is both writable and executable is usually normal for it. No output means none of the typical JIT runtimes was found (the list is not complete), so such a region is harder to explain and is consistent with injected code. In that case save the region to a file and check it with the file and sha256sum commands.
5. After saving the memory region, compute its SHA-256 hash and compare it against databases of known files
   `sha256sum /tmp/region_ffffae2d0000.bin`
   How to read the result: The output is 64 hexadecimal characters (the hash, a fingerprint of the file): look it up in the file reputation database your organization uses, searching by the hash only, without uploading the file. No match is typical for a memory dump and settles nothing, while a match flagged as malicious suggests known malware. On a malicious match, or when other findings concern the same process, keep the file and hand it over for analysis.

<a id="r-678-ffffae4f8000"></a>

### Region 0xffffae4f8000 (high, 70 pts)

In short: program loaded into memory not backed by a file. The explanation is above, in the section "What the findings mean in this process".

- X-PRIV: executable private/anonymous memory not backed by a file
- HDR: ELF header in a region not backed by a file

| Field | Value |
|---|---|
| Address range | 0xffffae4f8000 - 0xffffae4fc000 (16 KiB, 16 KiB read) |
| Type and source | private memory; not backed by a file |
| Entropy | maximum 4.08, mean 2.83 (scale 0-8); zero pages: 0 |
| Content SHA-256 | 71b1a8c08ea742d8aabbbb45c2a2244a872e25ae13bc5af1adbeb0b50671b8ca |
| Neighbour below | 0xffffae4cf000 r-x /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 (gap 8 KiB) |
| Neighbour above | 0xffffae4fc000 --- anonymous memory (adjacent) |

#### Region entropy profile

```text
0xffffae4f8000 ▃▅▃▃ 0xffffae4fc000
```

Segment entropy (0-8): lowest 2.0, highest 4.1; 4 segments of 4 KiB.

#### Image header read from memory

| Field | Value |
|---|---|
| Format | ELF 64-bit, AArch64 |
| Type | library or PIE program (DYN) |
| Entry point | 0xb280 |
| Program / section headers | 10 / 41 |

#### Byte preview from 0xffffae4f8000

```text
0xffffae4f8000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
0xffffae4f8010  03 00 b7 00 01 00 00 00 80 b2 00 00 00 00 00 00  ................
0xffffae4f8020  40 00 00 00 00 00 00 00 58 07 52 00 00 00 00 00  @.......X.R.....
0xffffae4f8030  00 00 00 00 40 00 38 00 0a 00 40 00 29 00 28 00  ....@.8...@.).(.
0xffffae4f8040  06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00  ........@.......
0xffffae4f8050  40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  @.......@.......
0xffffae4f8060  30 02 00 00 00 00 00 00 30 02 00 00 00 00 00 00  0.......0.......
0xffffae4f8070  08 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00  ................
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

1. See what this memory region is in the process memory map
   `grep -n ffffae4f8000 /proc/678/maps`
   How to read the result: The output is one line: address range, permissions (e.g. r-xp, the letter x means executable code) and, at the end, a file path. Benign case: the line ends with the path of a library or program in a system directory such as /usr/lib. Be concerned if there is no path (memory not backed by a file), a memfd: entry, a (deleted) note, or a path in /tmp or /dev/shm together with the letter x in the permissions: in that case save the region to a file (next step).
2. Save the memory region content to a file (requires gdb, pauses the process briefly)
   `gdb -p 678 -batch -ex "dump memory /tmp/region_ffffae4f8000.bin 0xffffae4f8000 0xffffae4fc000"`
   How to read the result: Expected result: the command ends without an error and a file /tmp/region\_... appears, with a size equal to the size of the region. The messages "Operation not permitted" or "Cannot access memory" mean missing permissions (run as root) or that the region no longer exists: on their own they do not indicate a threat. The saved file is the input for the next steps and a piece of evidence, do not run it.
3. Check who started the process and with what command
   `ps -o pid,ppid,user,lstart,cmd -p 678`
   How to read the result: Look at the columns PPID (parent process), USER, STARTED (start time) and CMD (command). Benign case: the user and the command fit the role of this server, and PPID is 1 (systemd) or a known service manager. Be concerned if the command was started from /tmp or /dev/shm, if a shell (sh, bash) was started by a web server or a database, or if the start time matches the suspected incident: in that case check the parent process with the same command, using its PPID.
4. After saving the memory region, check what kind of executable file it is
   `file /tmp/region_ffffae4f8000.bin ; readelf -h /tmp/region_ffffae4f8000.bin`
   How to read the result: If file prints the word ELF (the format of Linux programs) and readelf shows a header without errors (fields Type, Machine, Entry point address), the region holds a whole program or library loaded without a file on disk, which suggests code loaded straight into memory. If file prints only "data" and readelf reports an error, it is just a fragment or an accidental resemblance and the finding is weaker. In the first case compute the file hash (sha256sum), keep the file as evidence and hand it over for analysis.

<a id="r-678-ffffae503000"></a>

### Region 0xffffae503000 (high, 70 pts)

In short: encrypted or packed code from a file that exists only in memory. The explanation is above, in the section "What the findings mean in this process".

- MEMFD: executable mapping memfd:payload
- ENT-X: very high entropy in an executable region: max 7.95, pages above threshold: 2 of 2

| Field | Value |
|---|---|
| Address range | 0xffffae503000 - 0xffffae505000 (8 KiB, 8 KiB read) |
| Type and source | mapping; memfd:payload |
| Entropy | maximum 7.95, mean 7.95 (scale 0-8); zero pages: 0 |
| Content SHA-256 | b511e7d5ceda23c4c9555f760682f3089d78baf592641fdce4ceac79f973cc94 |
| Neighbour below | 0xffffae501000 rw- anonymous memory (adjacent) |
| Neighbour above | 0xffffae505000 rw- anonymous memory (adjacent) |

#### Region entropy profile

```text
0xffffae503000 ██ 0xffffae505000
```

Segment entropy (0-8): lowest 8.0, highest 8.0; 2 segments of 4 KiB.

#### Byte preview from 0xffffae503000

```text
0xffffae503000  ea 1c 58 d8 97 be 9d 50 12 c9 a7 6e 43 b5 af 76  ..X....P...nC..v
0xffffae503010  c2 a0 72 7d 39 91 3d 65 90 d8 4f a3 7f c7 4f 6f  ..r}9.=e..O...Oo
0xffffae503020  09 25 49 a6 b7 01 0d a5 40 3e 28 89 cd ac a8 07  .%I.....@>(.....
0xffffae503030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffffae503040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffffae503050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffffae503060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffffae503070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Text strings in the region

- no}P=NHfQr

#### How to verify this region

1. See what this memory region is in the process memory map
   `grep -n ffffae503000 /proc/678/maps`
   How to read the result: The output is one line: address range, permissions (e.g. r-xp, the letter x means executable code) and, at the end, a file path. Benign case: the line ends with the path of a library or program in a system directory such as /usr/lib. Be concerned if there is no path (memory not backed by a file), a memfd: entry, a (deleted) note, or a path in /tmp or /dev/shm together with the letter x in the permissions: in that case save the region to a file (next step).
2. Save the memory region content to a file (requires gdb, pauses the process briefly)
   `gdb -p 678 -batch -ex "dump memory /tmp/region_ffffae503000.bin 0xffffae503000 0xffffae505000"`
   How to read the result: Expected result: the command ends without an error and a file /tmp/region\_... appears, with a size equal to the size of the region. The messages "Operation not permitted" or "Cannot access memory" mean missing permissions (run as root) or that the region no longer exists: on their own they do not indicate a threat. The saved file is the input for the next steps and a piece of evidence, do not run it.
3. Check who started the process and with what command
   `ps -o pid,ppid,user,lstart,cmd -p 678`
   How to read the result: Look at the columns PPID (parent process), USER, STARTED (start time) and CMD (command). Benign case: the user and the command fit the role of this server, and PPID is 1 (systemd) or a known service manager. Be concerned if the command was started from /tmp or /dev/shm, if a shell (sh, bash) was started by a web server or a database, or if the start time matches the suspected incident: in that case check the parent process with the same command, using its PPID.
4. Find the memfd file descriptor (a file that exists only in memory) and copy the whole file, replacing NUMBER with the descriptor number from the first command
   `ls -l /proc/678/fd ¦ grep memfd ; cp /proc/678/fd/NUMBER /tmp/memfd_678.bin`
   How to read the result: The first command prints lines like "5 -&gt; /memfd:name (deleted)": the number before the arrow is the descriptor number, and the (deleted) note is normal here. Benign case: the name points to a known use, e.g. graphics or sound buffers in programs with a graphical interface. Be concerned about an empty or random name in a server process: in that case check the copied file with the file command, and if it prints ELF (a program), this is consistent with running code without writing it to disk, so keep the file and hand it over for analysis.
5. After saving the memory region, compute its SHA-256 hash and compare it against databases of known files
   `sha256sum /tmp/region_ffffae503000.bin`
   How to read the result: The output is 64 hexadecimal characters (the hash, a fingerprint of the file): look it up in the file reputation database your organization uses, searching by the hash only, without uploading the file. No match is typical for a memory dump and settles nothing, while a match flagged as malicious suggests known malware. On a malicious match, or when other findings concern the same process, keep the file and hand it over for analysis.

<a id="ch-5"></a>

## 5. What this report does not cover

- 1 regions with findings below severity "suspicious" were omitted; they are in the result file.
- The byte preview in the report is the first 128 bytes of a finding; the full 256 bytes are in the result file (JSON). The tool does not take a full dump of the region.
- System context is the state at scan time: connections closed earlier, child processes that have exited and deleted files are not visible. The report does not cover history (logs, audit trail).
- The scan covers process memory at scan time; it does not cover the kernel, the contents of files on disk or the contents of network traffic.
- The result file contains SHA-256 hashes of 5 files (programs of all processes and files mapped in processes with findings); the report shows only some. The report does not check hashes against external databases.
- The THR-PRIV finding relies on the thread start address (Windows) or on the place where waiting threads call the kernel (Linux); a thread that was computing at scan time is not assessed on Linux. IMG-MOD states how many bytes of code differ from the file on disk and where the first one is; the preview shows the bytes from memory, without the file contents to compare against.
- No LLM interpretation (report built from deterministic data only).

<a id="ch-6"></a>

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

<a id="ch-7"></a>

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
