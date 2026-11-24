#!/bin/sh
# Fuzzing parserów danych niezaufanych w kontenerze (kompilator nightly i cargo-fuzz są instalowane w kontenerze,
# nie na stacji). Użycie: scripts/fuzz.sh [sekundy na cel, domyślnie 60] [cele...]
# Cele: dump pediff pagetables maps detectors wintables llm report. Korpus i znalezione przypadki: fuzz/corpus, fuzz/artifacts.
set -eu
cd "$(dirname "$0")/.."
SECS="${1:-60}"; [ $# -gt 0 ] && shift
TARGETS="${*:-dump pediff pagetables maps detectors wintables llm report}"
podman run --rm -i --platform "linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -v "$PWD":/src -v nanshe-fuzz-target:/target -v nanshe-fuzz-cargo:/usr/local/cargo/registry -v nanshe-fuzz-rustup:/usr/local/rustup \
  -e CARGO_TARGET_DIR=/target -e SECS="$SECS" -e TARGETS="$TARGETS" -w /src docker.io/library/rust:1-bookworm sh -c '
    set -e
    rustup toolchain install nightly --profile minimal >/dev/null 2>&1 || { echo "instalacja kompilatora nightly nie powiodła się"; exit 1; }
    export PATH="/usr/local/rustup/fuzz-bin/bin:$PATH"
    command -v cargo-fuzz >/dev/null 2>&1 || cargo install cargo-fuzz --locked --root /usr/local/rustup/fuzz-bin >/tmp/install.log 2>&1 || { echo "instalacja cargo-fuzz nie powiodła się"; tail -5 /tmp/install.log; exit 1; }
    mkdir -p /tmp/seeds && NANSHE_FUZZ_SEEDS=/tmp/seeds cargo test -q -p nanshe-dump -p nanshe-live fuzz_seeds >/dev/null 2>&1 || true
    fail=0
    for t in $TARGETS; do
      mkdir -p fuzz/corpus/$t
      [ -d /tmp/seeds/$t ] && cp -n /tmp/seeds/$t/* fuzz/corpus/$t/ 2>/dev/null || true
      # raport: ziarnem jest prawdziwy plik wyniku z przykładów w repo
      if [ $t = report ]; then for f in docs/examples/*.json lab/przyklady/macos/probka.json; do [ -f "$f" ] && cp "$f" "fuzz/corpus/report/seed-$(basename "$f")" 2>/dev/null || true; done; fi
      limit=65536; [ $t = pagetables ] && limit=262144; [ $t = dump ] && limit=16384; [ $t = report ] && limit=262144
      if cargo +nightly fuzz run $t -- -max_total_time=$SECS -max_len=$limit -timeout=20 -rss_limit_mb=2048 -print_final_stats=1 > /target/fuzz-$t.log 2>&1; then res=OK; else res=FAIL; fail=1; fi
      echo "$t: $res | $(grep -E "stat::number_of_executed_units|stat::new_units_added" /target/fuzz-$t.log | tr "\n" " ") | cov $(grep -oE "cov: [0-9]+" /target/fuzz-$t.log | tail -1)"
      [ $res = OK ] || { grep -E "panicked|ERROR|SUMMARY|Test unit written|timeout|out-of-memory" /target/fuzz-$t.log | head -8; }
    done
    exit $fail'
