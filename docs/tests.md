# Nanshe tests

Polish version: [pl/testy.md](pl/testy.md).

Three layers: unit tests (logic, no live processes), end-to-end tests on live samples (Linux in a container, Windows on a dedicated test host) and live runs with models. The common rule: **every test must be able to fail**. That is why tests come in pairs: a case that must produce a result, and a control differing in one property that must not produce it.

## How to run

```sh
scripts/dev.sh cargo test --workspace --features nanshe-cli/llm   # unit tests (Linux, container)
scripts/dev.sh sh scripts/e2e.sh                                  # e2e Linux
powershell -ExecutionPolicy Bypass -File scripts\e2e.ps1 -Bin target\release -Out e2e-out   # e2e Windows, natively on the test host
```

Exit code of the e2e scripts: 0 when everything matches, 1 when anything deviates.

## Status as of 2026-11-24

| Layer | Result |
|---|---|
| Unit tests | 139 pass (analyze 26, core 3, dump 5, kb 7, live 20, llm 40, report 30, vm 8) |
| Hypervisor read (`nanshe vm`) | one live run against a Windows Server 2025 guest on KVM (see [hypervisor.md](hypervisor.md)); no automated end-to-end test |
| Full live scans, Linux | `nanshe scan --all` on 20 hosts of one lab (19 x86_64, 1 arm64), 2026-11-23, before and after the detection tuning; no process was verified manually |
| e2e Linux (aarch64, container) | 16 static samples, 2 dynamic and 8 groups of additional assertions |
| e2e Windows (test host, x64) | 14 samples, the context sample, 2 dynamic and 8 groups of additional assertions |
| Local model, live | `gemma3:12b` on a local Ollama |
| Cloud, live | Nous: `anthropic/claude-opus-5.5` (d0), `anthropic/claude-haiku-5.5` (d1) |
| Cloud without a live run | `anthropic`, `google`, `openai` directly: request shape tests only (no keys) |

A CI workflow is defined in `.github/workflows/ci.yml` (Linux unit and end-to-end tests in a container, unit tests and a release build on Windows); results of its runs are not recorded in this document. The unit tests of the `nanshe-vm` crate are part of the workspace run; the `nanshe` binary with the `vm` feature is not built there.

Not present: fuzzing of the `maps` parser, a recorded end-to-end run on Linux x86_64, a model quality evaluation set.

## Unit tests

### `nanshe-analyze` (detectors and scoring)

| Test | What it checks | Control |
|---|---|---|
| `clean_process_has_no_findings` | file-backed code and high-entropy RW data produce no findings | - |
| `rwx_anon_high_entropy_is_high` | RWX + anonymous + entropy gives three tags, severity "high" and a 256-byte preview | - |
| `each_condition_is_necessary` | removing one property (W, X, no file, entropy) switches off the tag that corresponds to it | this is a mutation test |
| `memfd_and_deleted` | `MEMFD` and `DEL-EXEC` on Linux | the absence of these tags on Windows is checked by `x_map_is_windows_only...` |
| `x_tmp_flags_exec_from_world_writable_dir` | `X-TMP` (30 points, "suspicious") for an executable mapping of a file from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm` | system directory, no execute permission, Windows: none; a deleted file gives only `DEL-EXEC` |
| `hdr_only_without_backing` | `HDR` for a header in a region without a file, with the page address | the same header in a file-backed region: none |
| `hdr_found_at_any_offset_with_same_validation` | in an executable region an ELF and PE header is detected at any offset, with the address and offset in the description | the same header in RW data, a corrupted ELF field, `MZ` without `PE`, Mach-O not at the start of a page, random data: none |
| `windows_jit_needs_verified_exe_and_system_runtime_image` | Windows: a JIT heap in a process with the system .NET drops from 60 to 20 points, `X-MAP` from 30 to 10, the findings stay visible with a fixed marker | a program outside the system directories, no runtime module, a file mapped as data, `clr.dll` from a user profile, from `\Windows\Temp`, from a subdirectory pretending to be `\Windows\` or from outside the runtime directory: no reduction; an executable file mapping (`X-MAP` with a file) is never reduced; a high-entropy payload stays "suspicious", and an image header is not reduced |
| `detectors::headers` (PE) | a PE header requires a non-zero Machine field and 1-96 sections | `MZ...PE` with a zero Machine or without sections: none |
| `thread_in_memory_without_a_file_is_flagged_at_full_weight` | `THR-PRIV` (40 points) for a thread located in memory without a file; in a process with a JIT runtime `X-PRIV` is reduced and `THR-PRIV` is not | a thread in file-backed code, no threads, the kernel region `[vdso]`: none |
| `modified_code_of_a_file_is_flagged_only_in_read_only_executable_mappings` | `IMG-MOD` for modified file-backed code: 40 points on Linux and for `amsi.dll` on Windows, 10 for an ordinary Windows library | no changes, zero bytes, data without execute permission, writable code, memory without a file: none |
| `region_limit_keeps_findings_and_marks_result_incomplete` | a map as long as the limit: findings from before the limit stay, the process result carries a truncation error | below the limit: full result, no error |
| `unreadable_region_does_not_allocate_its_full_size` | an unreadable 64 MiB region does not cause a 64 MiB allocation | - |
| `ent_x_in_file_backed_code_needs_large_share` | single high-entropy pages in file-backed code give 10 points, not 20/30 | a share above 25% of pages: full weight |
| `x_map_is_windows_only_and_needs_exec_mapped` | `X-MAP` for an executable `MEM_MAPPED` | without X, a module image, Linux: none |
| `guarded_exec_region_is_flagged_and_counted_unreadable` | `GUARD-X`, the region counted as unread, 0 bytes read despite a PE header in the data | the same region without the guard is read and gives `HDR`; a guard without X is not a finding |
| `jit_allowlist_lowers_but_shows` | the allowlist lowers the score from 60 to 20, the findings stay visible, the result carries the fixed marker `jit:node` | a file that is unverified, unknown, deleted or outside the trusted directories: no reduction, despite the process name `node` |
| `unreadable_region_is_counted_and_scan_continues` | a read error on one region does not abort the scan | - |
| `deterministic_and_no_bytes` | two scans of the same source give an identical result; `--no-bytes` removes the preview | - |
| `detectors::headers`, `entropy::bounds`, `entropy::pages_and_heat` | recognition of PE/ELF/Mach-O (including `MZ` without `PE`), entropy bounds 0-8, heat map | - |
| `profile_downsamples_with_max` | region entropy profile: at most 64 segments, the maximum counts within a segment | empty region: empty profile |
| `strings_found_in_ascii_and_utf16_and_noise_rejected` | ASCII and UTF-16LE text strings, without repetitions, with a count limit | a string of special characters only and a string shorter than 10 characters are rejected |

### `nanshe-live`

- `maps::parses`: the `/proc/<pid>/maps` parser, including names with spaces and the `(deleted)` suffix.
- System context, Linux (`sysctx`): `stat_with_hostile_name` (a process name with spaces and parentheses does not shift the `stat` fields), `status_and_cmdline`, `addresses_and_tables` (IPv4/IPv6 addresses and states from `/proc/net/tcp`; a row without an inode is skipped; Unix sockets with a name containing a space and without a name), `descriptors_users_and_loader_env` (descriptor kinds, the `(deleted)` suffix; from the environment only code-loading variables are taken, a variable holding a secret is not collected).
- Threads and modified code, Linux (`sysctx::thread_pc_and_modified_pages`): the instruction address from a thread's `syscall` file (a running thread and malformed data give no address) and the anonymous pages of mappings from `smaps` (a field without a mapping header is ignored). The same test covers the recognition of kernel threads by the `PF_KTHREAD` flag: a process that only names itself like a kernel thread, a name containing parentheses and truncated data are not treated as kernel threads.
- File hashes (`sysctx::hashing_opens_once_and_takes_only_regular_files`): the hash of known content; a directory, a missing file, a character device and a named pipe without a writer give no hash and do not hang the scan.
- Scanner privileges: `sysctx::scanner_privileges_from_status` (root with `CAP_SYS_PTRACE` full; root without it and an ordinary user limited) and `wintables::scanner_privileges_follow_integrity_and_debug_privilege` (high or system level with `SeDebugPrivilege` full; medium level or no `SeDebugPrivilege` limited).
- Network paths (`wintables::network_paths_are_never_treated_as_local`): UNC, `\Device\Mup`, `LanmanRedirector`, WebDAV and devices other than a disk volume are not treated as local.
- System context, Windows (`wintables`): `tcp_and_udp_tables` (socket tables with the owner, ports in network order; a counter larger than the data and a truncated buffer do not cause a panic), `handle_table_filtered_by_pid` (the system handle table filtered by PID, object kinds, rights to a foreign process; control: the metadata query right alone is not flagged), `exe_must_sit_under_a_system_root` (a program in a system directory; controls: `C:\temp`, a user profile, `C:\WindowsEvil`, another drive, a path with `..`, subdirectories of `\Windows` writable by users; file owner: SYSTEM and Administrators yes, an ordinary user and the Users group no), `time_and_integrity` (FILETIME time, integrity levels). The parsers work on a raw buffer, so these tests also pass on Linux; the API calls themselves are checked only by e2e on the Windows test host.
- `exe_trust_requires_every_condition`: the program file is trusted only when it meets all conditions at once (owner root, no write access for group and others, the same inode); changing one condition removes the trust.

### `nanshe-llm` (interpretation layer)

The backend is a mock in these tests, so no network is needed.

| Area | Tests | What they check |
|---|---|---|
| Run | `per_process_region_limit_skips_without_calls` (per-process region limit: the rest is skipped without a request; control without the limit), `happy_path_and_scan_untouched`, `backend_failure_gives_partial_result`, `correlation_and_call_limit`, `cache_reuses_valid_answer`, `dry_run_sends_nothing`, `oversized_prompt_refused_not_truncated` | the scan result is not modified; a backend failure gives a partial result; request limit; cache; `--dry-run` does not call the backend; an oversized request is refused, not truncated |
| Validator | `accepts_valid`, `rejects_each_violation`, `benign_is_never_established`, `explanation_without_reasoning_is_rejected`, `correlation_never_drops_regions`, `hallucinated_reference_retried_then_rejected` | a label and certainty outside the vocabulary, a reference to a non-existent finding, missing evidence, extra fields, a benign hypothesis with certainty "established", empty reasoning: each rejected separately; omitted regions are appended to the review order |
| Outgoing data | `d0_leaks_nothing_from_memory_or_user_paths`, `d1_redacts_secrets_d2_keeps`, `secrets_detected`, `strings_extracted`, `region_strings_reach_the_model_through_the_same_filters` | level d0 contains nothing from memory or user paths; d1 cuts out secrets (PEM keys, JWT, token prefixes of GitHub, GitLab, Slack, AWS, Google, Docker, credentials in addresses, high-entropy strings); d2 keeps them; a function name and an ordinary address are not a secret (control); strings from the whole region (also UTF-16) reach the model through the same secret and injection filters, and at level d0 they do not reach it at all |
| Injections | `injection_marked_and_removed`, `injection_marker_and_text_not_sent`, `process_controlled_fields_are_filtered` | text that looks like an instruction does not reach the model, the `LLM-INJECT` marker is raised; this also applies to the process name, paths and descriptions |
| Model address | `plain_http_only_to_loopback` | plain HTTP only to loopback; addresses with credentials, a query or parser tricks are rejected |
| Cloud: rules | `cloud_never_gets_d2`, `providers_built_in` | no `--allow-cloud` and level d2 mean a refusal, also when the caller skips the check; locally d2 is allowed (control); four providers, all `https` |
| Cloud: pseudonymization | `cloud_payload_pseudonymized_and_answer_reversed`, `replaces_host_users_and_ips_and_reverses`, `not_an_ip_is_left_alone`, `reverse_never_breaks_json`, `case_and_short_host_do_not_bypass`, `known_value_never_splits_a_longer_name`, `known_value_inside_a_token_masks_the_whole_token`, `retry_feedback_does_not_leak_restored_values`, `generic_host_name_does_not_break_paths_or_words`, `ipv6_is_masked_and_lookalikes_are_not` | the host, users in paths and IPv4 addresses do not leave; the answer has the values restored; without cloud mode the data goes unchanged (control); version numbers are not mistaken for addresses; different letter case and a short host name do not bypass the substitution; a known name inside a longer token (`jkowalski_backup`) masks the whole token; a short value inside an ordinary word (`ann` in `scanner`) stays (a control and at the same time a known gap); a retried request does not contain restored values; a host named `dev` or `win` does not break `/dev/shm` or `Windows`, but is substituted as a word, in a URL and in a UNC path; IPv6 addresses are substituted, while timestamps, MAC addresses and `std::string` are not |
| Cloud: requests | `openai_body_follows_supported_params`, `anthropic_body_has_no_sampling_params`, `strict_schema_drops_only_item_bounds`, `responses_parsed_and_failures_named`, `models_parsed_from_both_api_styles`, `key_from_file_must_be_a_single_token` | temperature, seed and schema are sent only when the model supports them; a refusal, a truncation and an empty answer have named errors; a key file with anything more than the key is rejected |

New in this version (analysis and live reading):

- `header_with_wiped_signature_is_recognised_by_its_tables` (analyze): a PE header without `MZ`, without `PE` or with the start of the page zeroed, and an ELF header without its signature, are recognised by the section table or the program header table; a header with its signature is not reported a second time; controls: a single section, no executable section, non-increasing addresses, random data, zeros, text containing section names, a single loadable segment.
- `wiped_header_is_reported_only_in_executable_regions` (analyze): a section table without a signature is reported only in an executable region; a copy of a file header on the heap and a wiped header in non-executable data are not (controls). The test was added after a measurement on the test host, where the earlier version raised two false alerts on the heap.
- `toc_page_numbers_are_stable_between_passes` (report) now also covers links: every table-of-contents entry is a link to its chapter, and anchor positions are the same in both layout passes.
- `modified_code_of_a_file_is_flagged_only_in_read_only_executable_mappings` (analyze) now also covers the result of the comparison with the file: the byte count and address in the description, 10 points for an ordinary Windows library and 40 for a security module; control: a comparison without differences produces no finding.
- `relocated_image_matches_the_file_and_a_patch_is_counted` (live, `pediff`): a PE image relocated to three different addresses does not differ from the file; five changed bytes are counted with the address of the first; controls: without applying relocations, and for a file without a relocation table, the differences are visible.
- `garbage_and_truncated_files_do_not_panic` (live, `pediff`): garbage, every truncation of the file and every header byte set to 0xff cause no crash; a damaged relocation table (a block outside the table, an unknown entry type) means no comparison after loading at a different address; a relocation directory declaring 4 GiB does not occupy the scanner (time limit in the test).
- `image_header_in_memory_must_match_the_file` (live, `pediff`): a header in memory with a changed load address matches the file; a different timestamp, section count, image size or checksum means a different file; a wiped header and a file that is not an image give no confirmation.
- Contents equal to a file whose identity is not confirmed do not suppress the finding (part of the `modified_code_of_a_file_...` test): 10 points remain, with a description saying that the identity of the file was not confirmed.
- `headers_decoded_and_garbage_ignored` (report) now covers a PE header at offset 0xf0 in a 256-byte preview (format, sections and timestamp are read without the file-kind field).

### `nanshe-dump` (process memory dumps)

| Test | What it checks |
|---|---|
| `core_file_gives_regions_threads_names_and_memory` | core file (x86_64 and aarch64): regions with permissions, file names from NT_FILE (including `memfd` and a deleted file), the stack recognised by a thread's stack pointer, vdso by the auxiliary vector (control: the same region without the entry gets no label), threads with the program counter, name, PID, program path; reading returns as much as the dump holds, stops at a gap, and missing content is an error, not zeros |
| `hostile_headers_do_not_panic_or_read_outside_the_file` | core file: a segment declaring content outside the file is clipped and recorded; a segment table outside the file, a wrong file type and a 32-bit dump give an error; every truncation of the file and a note whose size overflows the counter cause no crash |
| `minidump_gives_regions_modules_threads_and_memory` | minidump: regions with permissions and type as in a live scan, a module assigned to an image region, a guard page and a no-access page as unreadable, thread start addresses; reading crosses adjacent fragments and stops at a gap |
| `hostile_minidump_does_not_panic_or_read_outside_the_file` | minidump: every truncation of the file and every header or directory byte set to 0xff cause neither a crash nor a read outside the file; an implausible number of streams is an error |
| `unknown_or_short_files_are_rejected` | an empty file, a too-short file and a text file are rejected |

### `nanshe-kb` (knowledge base)

| Test | What it checks |
|---|---|
| `every_system_explains_every_tag_its_detectors_can_raise` | every tag that the detectors can raise on a given system has a name, a definition for the model, a meaning and a rationale; systems without their own file (macOS, FreeBSD) get the common part |
| `combos_reference_known_tags_and_are_unambiguous` | feature combinations refer to known tags, do not duplicate each other, have a benign and a concerning explanation; a Windows combination is not visible on Linux (control) |
| `text_is_plain_and_placeholders_are_filled` | no em dashes; the verification commands have the process number and addresses filled in, with no unfilled fields; a step of another tag does not appear (control) |
| `processes_modules_and_expectations` | `svchost.exe` in `System32` and with the parent `services.exe` is typical, in a user profile and with another parent it is not; a program without expectations is not assessed; `clrjit.dll` does not match the `clr.dll` pattern |
| `merge_and_external_directory` | the system file overrides the common entry; an external directory without `common.json` is an error, without a system file it gives the common part |
| `llm_glossary_covers_all_tags_in_stable_order` | the glossary for the model contains all tags in a fixed order |
| `english_base_mirrors_the_polish_one` | the English version of the base (`kb/en/`) has the same structure as the Polish one: the same tags, definitions for the model, ATT&CK references, feature combinations, numbers of verification steps, processes with paths and parents, modules; no Polish characters and no em dashes. Verified by mutation: removing one step from `kb/en/linux.json` fails the test |

### `nanshe-report` (report)

| Test | What it checks |
|---|---|
| `report_without_llm_lists_findings_and_gaps` | the content of the report without LLM: findings, partial result, inaccessible processes, regions skipped by the threshold; a process without findings and a region below the threshold have no section |
| `report_with_llm_marks_it_and_rejects_foreign_analysis` | LLM sections are marked; an interpretation of a different scan result (different SHA-256) is rejected; a threshold higher than the findings gives a message instead of an empty table |
| `untrusted_text_cannot_inject_markup`, `table_cell_cannot_break_the_row` | text from the examined process or from the model cannot insert Markdown/HTML markup or break a table |
| `structure_is_valid_and_offsets_point_at_objects` | PDF: header, the cross-reference table points at the right objects, two embedded fonts |
| `long_document_breaks_into_pages_and_is_deterministic` | a long document is split into pages; the same document gives an identical file |
| `toc_page_numbers_are_stable_between_passes` | table of contents in the PDF: chapter page numbers increase, and writing them into the table of contents does not shift the chapters (a second layout pass gives the same pages); a document without a table of contents renders in a single pass (control). Verified by mutation: a table of contents whose height depends on the page numbers fails the test |
| `long_token_is_broken_and_unknown_glyph_replaced` | a long string without spaces is broken; a character outside the font becomes a question mark |
| `map_merges_files_marks_findings_and_shows_gaps` | address space diagram: mappings of one file merged into a row, a finding has its own row, large gaps are shown as breaks; control: without a finding the same region is ordinary memory, without a region map there is no diagram |
| `long_map_is_collapsed_but_findings_and_neighbours_stay` | a map of 201 regions collapses to a few rows, the finding and its neighbours stay, the sum of sizes matches |
| `knowledge_base_explains_findings_in_plain_language` | the report contains the guide, a description of the feature combination with a benign and a concerning explanation, verification commands with the region addresses and the glossary; the hint about the JIT runtime changes after `libjvm` is added to the map, and without a region map it does not appear at all; a combination without its own description is composed from the single features |
| `overview_matrix_tree_scatter_and_hashes` | a processes x features matrix with the number of regions, a common tree with one root and a shared parent shown once, a scatter plot only for a process with at least three regions, the region hash and the hash of the mapped file in the report; control: a single process has no common tree, and a result without hashes says so explicitly |
| `flow_links_regions_process_and_sockets_without_overclaiming` | the "from memory to network" diagram: regions, the process with its user and sockets (remote before listening, Unix ones omitted), with a caveat in the caption; a process without sockets says so explicitly, without context there is no diagram |
| `report_states_scanner_privileges_and_warns_when_limited` | the report states the scanner privileges and warns when they are limited; with full privileges there is no warning |
| `priority_follows_findings_and_context_and_summary_is_calibrated` | verification priority: P1 for severity "high" without a JIT runtime and for features that JIT does not explain; P2 with a recognized runtime or without a memory map; P3 and P2 for severity "suspicious" depending on the location of the program. Summary for the decision maker: at P1 it recommends securing a dump, the absence of findings is not called clean, a scan without full privileges starts the recommendations with a repeat; main chapters numbered consecutively |
| `identity_check_flags_a_known_name_in_the_wrong_place` | `svchost.exe` in `System32` with the parent `services.exe`: no warnings; in a user profile with the parent `WINWORD.EXE`: two warnings; an unknown program: a note that there is no description, no warnings |
| `external_knowledge_base_replaces_the_embedded_one` | the directory given in the options replaces the embedded base; without it the embedded one is used (control) |
| `english_report_has_no_polish_text` | an English report (with and without LLM interpretation) from a scan without Polish data contains English headings and not a single line with Polish characters. Verified by mutation: Polish text in place of the English one fails the test |
| `report_language_follows_the_scan_unless_chosen` | without a language choice the report is produced in the language of the scan; a report in a language other than the scan starts with a note about it (in both directions), a single-language report does not have it (control); the language choice does not persist after the call |
| `new_region_in_a_running_process_is_the_headline` (differential report) | a new region with a finding in a process present in both scans is listed and enters the overall assessment; an unchanged region and a process without findings are not mentioned; control: comparing a result with itself gives no change at all |
| `reused_pid_is_a_new_process_not_a_change` | the same PID with a different start time or a different program file is a new process and a process that disappeared, not a change; without a start time in one of the results the PID, name and file decide |
| `changed_gone_and_threshold_crossings_are_told_apart` | a changed region (new features, score, a different content hash), a region that disappeared, a region that dropped below the threshold and a region that crossed the threshold are told apart; an unchanged region is not mentioned (control); with a lower threshold a threshold crossing is an ordinary change |
| `context_changes_and_scan_level_warnings` | changes outside memory: new and closed sockets, a new child process, a new mapped file, a different hash of the program file; unchanged items are not mentioned; warnings about different hosts, a system reboot and reversed file order appear only when there is a reason (control) |
| `english_differential_report_has_no_polish_text` | the differential report in English contains no Polish text |
| `headers_decoded_and_garbage_ignored` | ELF and PE header fields from the byte preview; controls: the `MZ` signature alone, a truncated ELF, random data, a PE header pointer outside the preview |

In addition, the PDF from a sample was opened with an external tool (`pypdf`: 5 pages, text with Polish characters extractable) and viewed after rendering.

### `nanshe-vm` (reading a guest from the hypervisor)

| Test | What it checks |
|---|---|
| `page_walk_combines_permissions_like_the_processor` | four-level page tables: write and user access need every level, no-execute needs one; kernel-only and absent pages are skipped; 2 MiB pages; adjacent pages with equal protection are merged; the kernel half is ignored |
| `page_walk_survives_unreadable_and_looping_tables` | a missing root table, an unreadable lower table (result marked incomplete), a table that points at itself (bounded by the table limit `MAX_TABLES`), tables whose protection changes on every page (the number of ranges is bounded by `MAX_RANGES` and the result is marked incomplete) and a table of the wrong length |
| `page_ranges_become_regions_split_at_module_borders` | ranges are merged and split at module borders; a module includes one page after its image, up to the 64 KiB boundary and no further; without a module list the region type is unknown |
| `empty_and_degenerate_input_gives_no_regions` | empty input, zero-sized ranges and modules, clipping at the end of user space |
| `symbol_identifiers_from_the_guest_cannot_form_a_path` | the symbol file name and identifier reported by the guest are accepted only as a plain `*.pdb` name and a hexadecimal string; path separators, `..`, other extensions and empty values are refused |
| `process_owner_is_read_from_all_four_user_ids` | a QEMU process counts as started by a system account only when all four user identifiers in its status file are below 1000; a missing, short or non-numeric line is refused |
| `guest_name_is_read_from_qemu_arguments_only` | the guest name is taken from `-name` of `qemu-system-*` and `qemu-kvm` only; other programs with the same argument are ignored |
| `symbol_download_is_impossible_without_consent` | with an empty symbol directory and downloading not allowed, loading kernel symbols fails quickly (under 2 seconds), without a connection attempt, and leaves no file in the directory |

The check that the QEMU process found by guest name runs a QEMU program file from a system directory (`/proc/<pid>/exe`) has no unit test.

Added with the tuning from lab scans: `lab_tuning_lowers_only_the_measured_benign_classes` (analyze; every reduced class with controls that keep full weight: `DEL-EXEC` outside package directories and in a process without a verified program file, `HDR` in a small or executable region and in a QEMU tool that is not a hypervisor (`qemu-img`), `MEMFD` under another name or without the system `libffi`; versioned file names on the JIT allowlist; the hypervisor-mode `HDR` rule) and `identical_processes_share_one_row_and_chapter` (report; grouping with controls for different programs and different sets of findings).

## End-to-end tests

The samples are the `nanshe-sample` program (`tests/samples`): it creates the memory layout that the detectors look for, prints `ready <pid>` and sleeps. **It executes nothing from the regions it creates.** For each sample the script checks three things: the scan exit code, the set of tags and repeatability (two scans of the same process). The dynamic samples (`churn`, `sleepmask`) are a separate family: they change the layout over time, see the subsection at the end of this chapter.

The difference between the systems: on Linux the whole JSON without the timestamp is compared, and the set of tags covers the whole process (hence `ENT-X` from the libc library in every sample). On Windows the findings without region counters are compared, and tags only from regions of severity "suspicious" and above.

### Linux (`scripts/e2e.sh`)

| Sample | What it does | Expected code | Expected tags |
|---|---|---|---|
| `clean` | nothing | 0 | `ENT-X` (libc background, 10 points) |
| `rwx` | anonymous RWX with high-entropy data | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `elf` | ELF header in anonymous R-X memory | 1 | `ENT-X`, `HDR`, `X-PRIV` |
| `memfd` | executable `memfd` mapping | 1 | `ENT-X`, `MEMFD` |
| `inject` | like `rwx`, with instruction text for the model in memory | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `data-noise` | high entropy in RW data (negative control) | 0 | `ENT-X` (background) |
| `rx-file` | R-X from a file in `/tmp`, low entropy | 1 | `ENT-X`, `X-TMP` (until 2026-11-22 a blind spot, code 0) |
| `rwx-lowent` | RWX with low-entropy code | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `rx-stage` | write to RW, then a change to R-X | 1 | `ENT-X`, `X-PRIV` |
| `hdr-corrupt` | ELF header with an out-of-range field | 1 | `ENT-X`, `X-PRIV`: `HDR` does not react |
| `hdr-offset` | ELF header in the middle of a page in an R-X region | 1 | `ENT-X`, `HDR`, `X-PRIV` (until 2026-11-22 `HDR` did not react) |
| `delexec` | executable mapping of a deleted file | 1 | `DEL-EXEC`, `ENT-X` |
| `execstack` | RWX stack | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `inject-memfd` | instruction for the model in the `memfd` name | 1 | `ENT-X`, `MEMFD` |
| `inject-path` | instruction for the model in the name of a deleted file | 1 | `DEL-EXEC`, `ENT-X` |
| `ctx` | like `all`, plus traces outside memory: a listening socket and a connection on 127.0.0.1, a file in `/tmp`, an open file deleted from disk, a child process | 1 | `ENT-X`, `HDR`, `MEMFD`, `RWX`, `X-PRIV` |

Additional assertions:

1. `scan --all` with the `all` sample ends with code 1.
2. A non-existent PID gives code 2.
3. `rwx` has a region with score 90 (control), `rwx-lowent` has 60 and does not have 90.
4. `explain --dry-run` for `inject`, `inject-memfd`, `inject-path`: the instruction text does not occur in the payload, and the `instruction_like_text_detected` marker is set.
5. `report` for `rwx`: the PDF file starts with `%PDF-`, the Markdown contains the tags and the process section; a report from a result without findings (control) has no process section and states that there are no findings.
6. System context (`ctx`): the result contains sockets in the `LISTEN` and `ESTABLISHED` states, both files of the sample (including the one marked as deleted), the ancestors, the command line of the process and of its child, the SHA-256 of the program file and the region map. The report contains the sections for the process tree, network, open files, mapped files, address space map, entropy profile and byte preview. Controls: a scan with `--no-context` and a scan of a process without findings (`clean`) have neither context nor map.
7. English version (`ctx`): a scan with `--lang en` writes `"lang": "en"`; the report from this result has English parts (summary, assessment, process tree, network, files, map, explanations of the process features from the knowledge base, verification steps) and neither the result nor the report contains Polish characters; a single-language report has no note about languages (control), and a report with `--lang pl` from an English scan is in Polish and has it. On its first run this assertion detected two untranslated descriptions next to the file hashes.
8. Differential report: two scans of the same `rwx` process give no new regions or processes (control); comparing the `rwx` result with the `elf` result shows one new process with findings (with the `HDR` tag) and one that disappeared; the English version has an English title; the PDF starts with `%PDF-`.
9. Process memory dump: a core file of the `ctx` and `clean` samples made with `gcore` gives the same tags as a live scan (only `ENT-X` for `clean`, so vdso is not reported); the report states that the source is a dump and has no network section; a file that is not a dump gives exit code 2. Without `gcore` the test is skipped with a message.
10. Library code change: the `patch` sample (one byte of an unused libc function changed in memory) gives `IMG-MOD` with the description of 1 byte; the `touch` sample (the same page written with the same contents) gives no finding (control).
11. Wiped signature: the `hdr-wiped` sample gives `HDR`; `hdr-corrupt` (no program header table) still does not (control).

### Windows (`scripts/e2e.ps1`, natively on a dedicated test host)

| Sample | What it does | Expected code | Tags of the payload region | Points |
|---|---|---|---|---|
| `clean` | nothing | 0 | none | - |
| `rwx` | private RWX, high entropy | 1 | `ENT-X`, `RWX`, `X-PRIV` | 90 |
| `pe` | PE header in private R-X memory | 1 | `HDR`, `X-PRIV` | 70 |
| `xmap` | executable section view without a file | 1 | `RWX`, `X-MAP` | 60 |
| `rx-stage` | write to RW, then R-X | 1 | `X-PRIV` | 30 |
| `thread` | a private R-X region and a thread with its start address in that region, created suspended (nothing executes) | 1 | `THR-PRIV`, `X-PRIV` | 70 |
| `inject` | like `rwx`, with an instruction for the model | 1 | `ENT-X`, `RWX`, `X-PRIV` | 90 |
| `data-noise` | high entropy in RW data (negative control) | 0 | none | - |
| `rwx-lowent` | RWX, low entropy | 1 | `RWX`, `X-PRIV` | 60 |
| `pe-corrupt` | `MZ` with the `PE` signature erased | 1 | `X-PRIV`: `HDR` does not react | 30 |
| `pe-offset` | PE header in the middle of a page in an R-X region | 1 | `HDR`, `X-PRIV` | 70 |
| `ximage` | a `SEC_IMAGE` section from a copy of the exe in `%TEMP%` | 0 | none: **documented blind spot** | - |
| `guard` | RWX with a guard | 1 | `GUARD-X`, `RWX`, `X-PRIV` | 90 |
| `guard-hide` | PE header behind a guard | 1 | `GUARD-X`, `X-PRIV`: `HDR` does not see the content | 60 |
| `inject-map` | instruction for the model in the name of the mapped file | 1 | `X-MAP` | 30 |

Additional assertions:

1. A non-existent PID gives code 2.
2. `explain --dry-run` for `inject` and `inject-map`: the instruction is cut off, the marker is set.
3. `rwx` has 90 points (control), `rwx-lowent` has 60 and does not have 90.
4. `guard-hide`: one unread region and a partial result; `pe` (control, the same payload without the guard): zero unread, full result.
5. `report`: as on Linux.
6. System context (the `ctx` sample: RWX, PE header, listening socket, connection on 127.0.0.1, child process): command line, user, start time, SHA-256 of the program file, ancestors, child, `LISTEN` and `ESTABLISHED` sockets, integrity level, region map, open handles (the sample file with its name, a handle to the child process with tampering rights, at least one registry key, the number of all handles greater than the number recorded); in the report the same sections as on Linux plus the decoded PE header format. Controls as on Linux.
7. English version: as on Linux, additionally the `integrity level` feature in the result, the description of the scanner privileges and a handle to another process with tampering rights in the English report.
8. Differential report: as on Linux (the `rwx` result compared with itself and with the `pe` result).
9. Process memory dump: a full minidump of the `rwx`, `pe`, `thread`, `guard` and `clean` samples, made with the system function `MiniDumpWriteDump`, gives the same tags as a live scan (none for `clean`); the process number and program name come from the dump; the report mentions the dump and has no network section.
10. Library code change: the `patch` sample (one byte of a function from `version.dll`) gives exactly one `IMG-MOD` finding in that library, 10 points, with the description of 1 byte; the `touch` sample (control) reports no difference: one informational finding remains, stating that the contents equal the file at this path, because the identity of the file cannot be confirmed on Windows.
11. Wiped signature: the `pe-wiped` sample gives `HDR`; `pe-corrupt` still does not (control).

Repeatability on Windows compares the regions with findings (with the entropy profile and strings), not the full region map or the context: these change between scans of a live process.

The `pe` / `guard-hide` pair also checks the "read only" rule: if the scanner read the guard page, the first scan would clear the flag, the second would find `HDR`, and the repeatability test would fail.

### Dynamic samples: `churn` and `sleepmask` (both systems)

The samples described so far are static: they build a memory layout and sleep. The dynamic samples change it over time: this is material for the future observation of changes (`--watch`) and at the same time a test that a scan performed at any moment of the process lifetime gives a consistent picture. Arguments: `<interval_s> <total_time_s>` (by default 3 and 60); after the total time they exit on their own.

The sample reports every change with a line `<mode> <round> <phase>` on stdout **after** performing it. The harness reads the output as it arrives, scans in the stable window between entries and compares the set of tags with the reference for the phase. The test fails when any phase gives different tags or does not occur within the declared time.

`churn`: a cycle of six phases (it allocates, changes permissions RW → R-X → RWX, adds and frees regions):

| Phase | Memory state | Linux tags | Windows tags |
|---|---|---|---|
| `quiet` | no sample regions | `ENT-X` | none |
| `stage-rw` | a new RW region with code (staging) | `ENT-X` | none |
| `stage-rx` | the same region after the change to R-X | `ENT-X`, `X-PRIV` | `X-PRIV` |
| `hdr` | adds a second R-X region with a header (ELF/PE) | `ENT-X`, `HDR`, `X-PRIV` | `HDR`, `X-PRIV` |
| `armed-rwx` | the first region after the change to RWX with noise | `ENT-X`, `HDR`, `RWX`, `X-PRIV` | `ENT-X`, `HDR`, `RWX`, `X-PRIV` |
| `cleanup` | both regions freed | `ENT-X` | none |

In the `armed-rwx` phase the region with the header still exists (it is freed only in `cleanup`), so `HDR` stays. This is intentional: the phase checks two parallel findings at the same time.

`sleepmask`: a simulation of sleep-time masking (MITRE T1027/T1140): one region alternating between `armed` (R-X with code: Linux `ENT-X`, `X-PRIV`; Windows `X-PRIV`) and `masked` (RW with high-entropy noise: background only, that is `ENT-X` on Linux and no tags on Windows). In the `masked` phase the finding disappears; a single scan that lands in this window does not tell the process apart from a clean one. This illustrates the limit of one-shot scanning and motivates observation over time.

### Windows installer (`scripts/test-installer.ps1`)

Run on the test host after the build; it changes the host (Program Files, ProgramData, PATH, registry) and cleans up after itself. It does not start when a Nanshe installation is already present on the host.

| Step | What it checks |
|---|---|
| package | `package-windows.ps1` creates a zip with the hash list and the knowledge base |
| modified package | after a character is appended to a knowledge base file the installer ends with code 1 and installs nothing |
| link | when `C:\ProgramData\Nanshe` is a link to another directory, the installer refuses, does not create the program directory and writes nothing into the link target |
| installation | code 0, the program runs from the installation directory, the knowledge base and the removal script are in place |
| permissions | program directory: users read only and nobody except Administrators and SYSTEM has write permission; results directory: only Administrators and SYSTEM; inheritance disabled |
| integration | system PATH, an entry in "Programs and Features", a Start menu shortcut |
| reinstallation | passes and does not duplicate the PATH entry |
| uninstallation with a link | with `-RemoveData` and a link planted in the results directory the script ends with code 1 and removes nothing (the file in the link target and the program stay) |
| uninstallation | the program, PATH, registry and shortcut removed, the file in the results directory stays; at the end the host is cleaned up |

Result on the test host (2026-11-22): all 16 steps passed, and the host was cleaned up after the test.

It does not check: the refusal for a directory owned by an ordinary account (the test runs as administrator, so there is no way to create it with a different owner), launching the Start menu shortcut, or behaviour on a Windows other than the test host.

### MSI installer (`scripts/test-msi.ps1`)

The test builds the package (with the ICE consistency check of the WiX tool), installs it silently on the test host, checks it and uninstalls it. Result from 2026-11-23: 18 of 18 steps; the ICE check was performed, one warning accepted deliberately (ICE61: the package also replaces the same version, because successive builds have the same number).

| Step | What it checks |
|---|---|
| build | the script ends with code 0 and the `.msi` file is created; on a build error the file is removed |
| silent installation | `msiexec /i ... /qn` ends with code 0; the program starts from the installation directory |
| files | the knowledge base in Polish and English, both licenses, the console launcher (`nanshe-console.cmd`) |
| program directory permissions | ordinary users have no write permission at all to the directory, to `nanshe.exe` or to the console launcher. Control of the check itself: a directory with write permission for users is detected (the first version of the check had too wide a mask and failed a correct installation) |
| results directory | entries only for Administrators and SYSTEM, inheritance disabled, owner Administrators |
| PATH, entry in "Programs and Features", shortcut | present after installation; the entry comes from Windows Installer, publisher HoneyLens |
| reinstallation | a second installation of the same package ends with code 0, one entry and a working program remain |
| uninstallation | code 0; the program, the base, the PATH entry, the entry in "Programs and Features" and the shortcut removed; the file in the results directory stays |
| cleanup | host without traces of the installation |

Not checked: installation with windows (license screen), operation of the shortcut (requires an interactive session and UAC consent), the refusal when a version installed by the script is present, an upgrade from a lower version number (there is no second version yet).

## Live runs with models

They are not part of the scripts (they require a network and a key, and the result is non-deterministic). Performed by hand on synthetic samples:

| Run | Result |
|---|---|
| `gemma3:12b`, local Ollama, d1 | interpretations formally valid; the sample with the injection did not change the hypothesis (a single observation) |
| Nous, `anthropic/claude-opus-5.5`, d0 | after the fix to the order of schema fields 4 of 4 runs complete; before the fix an empty answer skeleton every few requests |
| Nous, `anthropic/claude-haiku-5.5`, d1 | a complete set of interpretations, `.md` and `.pdf` report generated |
| Windows host -> Ollama on the local network | `llm check` and `explain` work from the Windows host |

These are observations, not a quality measurement: the trials are small, and an evaluation set for model quality does not exist yet.

## What the tests do not cover

- `THR-PRIV` on Linux in an end-to-end test: the samples execute nothing from the regions they create, and on Linux a thread address can be obtained only from a thread that is actually running there. The detector has unit tests; the reading of `/proc/<pid>/task/<tid>/syscall` was checked by hand in a container.
- `IMG-MOD` on a real code change: no sample patches a library. On the test host only the number of benign occurrences was measured.
- System context on real programs: the `ctx` sample has one socket, one child and a few files. Processes with thousands of descriptors, containers with their own network namespace and reuse of the parent PID on Windows were not exercised.
- The appearance of the diagrams for large processes: the address space map was viewed for the samples (26 regions on Linux); the collapsing of long maps is checked only by a unit test.
- Continuous observation over time: the dynamic samples (`churn`, `sleepmask`) report phases, and the scripts scan in the windows between them; the `--watch` mode that tracks changes of one process does not exist yet.
- `nanshe vm` in an automated test: it needs a KVM host with a running Windows guest. Checked by one manual run; 32-bit guest processes, other Windows versions and swapped-out pages were not exercised.
- Real malware: all samples are synthetic.
- False positives on real programs, apart from one `scan --all` measurement on the Windows test host (described in [windows.md](windows.md)). On Linux there are the full scans of 20 lab hosts (2026-11-23), which led to the reduced weights described in [linux.md](linux.md); the scale of `X-TMP` false positives was not evaluated in them.
- The tightness of the injection filter: the samples use a phrase that the filter knows; the test proves that the filter is connected to every channel, not that it cannot be bypassed.
- The `anthropic`, `google`, `openai` backends live.
- macOS and FreeBSD (no scan backend).

## Memory atlas (metadata inventory)

- `scripts/dev.sh cargo test --workspace --features nanshe-cli/llm`: the maps parser
  with whitespace-separated columns and paths with spaces; smaps with RSS/PSS,
  offset, device:inode, sharing mode and unknown counters;
  safe embedding of metadata in HTML (an attempt to close `script`).
- `node scripts/test-memory-view.cjs`: the view logic on a DOM model without a browser;
  grouping, filters, search, access errors, no processes, text labels
  and exact addresses above the Number precision range. It does not verify CSS or appearance.
- Linux smoke test: `nanshe map --pid <PID> --no-open --json host.memory.json`,
  then `nanshe map --input host.memory.json --no-open`. Checked on a shell
  process in a container, also a missing process (report with an error, code 3).

The live run on Windows and the visual HTML preview were not verified in this session.
The map does not replace the detector tests: it does not read memory bytes and does not perform detection.
