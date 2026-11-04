#!/usr/bin/env bash
# Builds the example service modules into scripts/examples/*.wasm.
set -euo pipefail
cd "$(dirname "$0")/.."

target="wasm32-unknown-unknown"
out_dir="scripts/examples"

for svc in echo counter hasher attest throttle; do
    cargo build -p tee-guest --release --target "$target" \
        --no-default-features --features "svc-${svc}"
    cp "target/${target}/release/tee_guest.wasm" "${out_dir}/${svc}.wasm"
    echo "built ${out_dir}/${svc}.wasm"
done
