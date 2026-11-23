# Example reports

All files were produced by `nanshe report` from scans of the synthetic sample `nanshe-sample ctx` in a Linux container. The files without a language model can be regenerated with `scripts/dev.sh sh scripts/example.sh docs/examples`.

| File | Source |
|---|---|
| `en/report-without-llm.md`, `.pdf`, `en/scan-result.json` | English: scan of the `ctx` sample with `--lang en` and the report built from that result |
| `raport-bez-llm.md`, `.pdf` | Polish: scan of the `ctx` sample, current version of the tool, with SHA-256 hashes, charts and knowledge-base explanations |
| `wynik-skanu.json` | the result file from which `raport-bez-llm` was built |
| `raport-z-llm.md`, `.pdf` | Polish: an earlier scan of the same sample with a language-model interpretation (cloud model, data level d0). The interpretation is bound to that scan result, so this report has no file hashes |

The reports contain unfiltered data from the test container (paths, command lines, fragments of memory). Reports from real hosts must be treated as evidence and never published.
