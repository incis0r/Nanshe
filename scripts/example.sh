#!/bin/sh
# Generuje przykładowe wyniki i raporty z próbki syntetycznej (kontener Linux):
#   scripts/dev.sh sh scripts/example.sh <katalog>
# Powstają: wynik skanu i raport po polsku, wynik i raport po angielsku oraz raport różnicowy.
set -eu
OUT="${1:?podaj katalog wyników}"; mkdir -p "$OUT/en"
cargo build -q -p nanshe-cli -p nanshe-samples --features nanshe-cli/llm
N=/target/debug/nanshe; S=/target/debug/nanshe-sample
$S ctx 60 > "$OUT/sample.pid" & sleep 1
pid=$(awk '{print $2}' "$OUT/sample.pid")
$N scan --pid "$pid" --json "$OUT/wynik-skanu.json" 2>/dev/null || true
$N --lang en scan --pid "$pid" --json "$OUT/en/scan-result.json" 2>/dev/null || true
kill "$pid" 2>/dev/null || true
rm -f "$OUT/sample.pid"
$N report "$OUT/wynik-skanu.json" --no-llm --md "$OUT/raport-bez-llm.md" --pdf "$OUT/raport-bez-llm.pdf"
$N report "$OUT/en/scan-result.json" --no-llm --md "$OUT/en/report-without-llm.md" --pdf "$OUT/en/report-without-llm.pdf"
