#!/bin/sh
# Build i testy w kontenerze Linux (na stacji bez Rusta). Użycie: scripts/dev.sh <polecenie w kontenerze>
# Przykład: scripts/dev.sh cargo test --workspace --features nanshe-cli/llm
set -eu
cd "$(dirname "$0")/.."
exec podman run --rm -i --cap-add SYS_PTRACE \
  -v "$PWD":/src -v nanshe-target:/target -v nanshe-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -e NANSHE_OLLAMA_URL="${NANSHE_OLLAMA_URL:-http://127.0.0.1:11434}" \
  -w /src docker.io/library/rust:1-slim-bookworm "$@"
