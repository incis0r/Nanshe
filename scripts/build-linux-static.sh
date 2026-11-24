#!/bin/sh
# Buduje statyczne binaria Nanshe dla Linuksa (x86_64 i aarch64, musl): jeden plik bez zależności,
# działa na każdej dystrybucji. Bez warstwy LLM (domyślny build bez kodu sieciowego).
# Uruchamiać w kontenerze: scripts/dev.sh sh scripts/build-linux-static.sh [katalog wyjściowy]
set -eu
OUT="${1:-/src/dist/linux}"; mkdir -p "$OUT"
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null
for a in x86_64 aarch64; do
  t=$a-unknown-linux-musl
  RUSTFLAGS="-C linker=rust-lld -C link-self-contained=yes -C target-feature=+crt-static" cargo build -q --release -p nanshe-cli --target $t
  cp "${CARGO_TARGET_DIR:-target}/$t/release/nanshe" "$OUT/nanshe-$a"
  echo "$OUT/nanshe-$a: $(sha256sum "$OUT/nanshe-$a" | cut -d' ' -f1)"
done
