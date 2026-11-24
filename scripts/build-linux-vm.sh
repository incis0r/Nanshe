#!/bin/sh
# Build binarium x86_64 z cechą "vm" (odczyt gościa Windows z hosta KVM) w kontenerze, także ze stacji
# o innej architekturze. Linkowany z glibc Debiana 11 (2.31), więc działa na hostach z glibc 2.31 i nowszym
# (RHEL/Rocky 9, Debian 11+, Ubuntu 20.04+, Proxmox 7+). Wynik: dist/linux/nanshe-vm-x86_64.
# Statyczny build musl nie jest tu używany: zależności tej cechy wymagają kompilatora C dla celu.
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist/linux
podman run --rm -i -v "$PWD":/src -v nanshe-vm-target:/target -v nanshe-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src docker.io/library/rust:1-slim-bullseye sh -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq gcc-x86-64-linux-gnu libc6-dev-amd64-cross >/dev/null
    rustup target add x86_64-unknown-linux-gnu >/dev/null
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
    cargo build --release -p nanshe-cli --features vm --target x86_64-unknown-linux-gnu
    cp /target/x86_64-unknown-linux-gnu/release/nanshe dist/linux/nanshe-vm-x86_64
    sha256sum dist/linux/nanshe-vm-x86_64'
