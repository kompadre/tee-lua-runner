#!/usr/bin/env bash
# Stage 7: container → `nitro-cli build-enclave` → .eif + measurements
# manifest.
#
#   TEE_KEY=<hex32> bash deploy/nitro/build-eif.sh [output.eif]
#
# Outputs (gitignored): deploy/nitro/build/{root/,<name>.eif,<name>.manifest.json}
# The manifest records PCR0-2, the module measurement/capabilities and the
# public envelope key — the values `tpass attest --pcr0/…` and the EC2
# runbook consume. Manifests for releases are committed deliberately from
# tagged sources (AGENTS invariant 6), never by this script.
#
# Requirements: cargo (pinned toolchain), docker, nitro-cli (cargo install
# aws-nitro-enclaves-cli). No root: nitro-cli needs NITRO_CLI_BLOBS /
# NITRO_CLI_LOGS_PATH overrides outside /usr/share//var/log.
set -euo pipefail
cd "$(dirname "$0")/../.." # repo root

TEE_KEY="${TEE_KEY:-}"
if ! [[ "$TEE_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "TEE_KEY must be a 32-byte hex key (got: ${TEE_KEY:-<unset>})" >&2
    echo "generate one:  head -c32 /dev/urandom | xxd -p -c64" >&2
    exit 1
fi
command -v nitro-cli >/dev/null || {
    echo "nitro-cli not found — install: cargo install aws-nitro-enclaves-cli" >&2
    exit 1
}
command -v docker >/dev/null || {
    echo "docker not found" >&2
    exit 1
}

OUT="${OUT:-deploy/nitro/build}"
NAME="${NAME:-tee-runner}"
ROOT="${OUT}/root"
# Nitro blobs (kernel/init/nsm.ko): from a pinned clone of the Nitro CLI
# sources unless the operator points NITRO_CLI_BLOBS at an install.
BLOBS_SRC="${NITRO_CLI_BLOBS:-}"
if [ -z "$BLOBS_SRC" ]; then
    BLOBS_CACHE="${BLOBS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/tee-lua-runner/aws-nitro-enclaves-cli}"
    if [ ! -d "$BLOBS_CACHE/blobs/x86_64" ]; then
        git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-cli.git "$BLOBS_CACHE" >&2
    fi
    BLOBS_SRC="$BLOBS_CACHE/blobs/x86_64"
fi
[ -f "$BLOBS_SRC/bzImage" ] || {
    echo "Nitro blobs not found at $BLOBS_SRC" >&2
    exit 1
}
export NITRO_CLI_BLOBS="$BLOBS_SRC"
export NITRO_CLI_LOGS_PATH="${NITRO_CLI_LOGS_PATH:-$OUT/nitro-logs}"
export NITRO_CLI_ARTIFACTS="${NITRO_CLI_ARTIFACTS:-$OUT/nitro-artifacts}"
mkdir -p "$NITRO_CLI_LOGS_PATH" "$NITRO_CLI_ARTIFACTS" "$ROOT"

echo "[eif] building musl-static runner + guest artifacts"
cargo build --release --target x86_64-unknown-linux-musl -p runner-cli
bash scripts/build-guest-examples.sh >/dev/null

echo "[eif] measuring the guest module (manifest input)"
MEASURE_OUT="$(cargo run -q -p runner-cli -- measure scripts/examples/throttle.wasm)"
MEASUREMENT="$(sed -n 's/^measurement: //p' <<<"$MEASURE_OUT")"
CAPABILITIES="$(sed -n 's/^capabilities: //p' <<<"$MEASURE_OUT")"
TEE_PK="$(cargo run -q -p runner-cli -- tee-pk --tee-key "$TEE_KEY")"
echo "[eif] module measurement: $MEASUREMENT"

echo "[eif] staging container context"
cp target/x86_64-unknown-linux-musl/release/tee-runner "$ROOT/tee-runner"
cp scripts/examples/throttle.wasm "$ROOT/throttle.wasm"
cp deploy/nitro/Dockerfile "$ROOT/Dockerfile"

echo "[eif] building docker image"
IMAGE="${IMAGE:-${NAME}:eif}"
# SOURCE_DATE_EPOCH pins any timestamp-dependent docker inputs (belt-and-
# braces: PCRs were empirically stable across rebuilds with *and* without
# it — BuildKit already zeroes layer mtimes for our COPY-only Dockerfile).
# Set by CI to the last commit time.
SDE="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 1735689600)}"
docker build -q --build-arg SOURCE_DATE_EPOCH="$SDE" --build-arg TEE_KEY="$TEE_KEY" -t "$IMAGE" "$ROOT" >/dev/null

echo "[eif] converting to EIF (nitro-cli build-enclave)"
EIF="${1:-${OUT}/${NAME}.eif}"
BUILD_JSON="$(
    nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF" |
        # build-enclave prints chatter before the JSON object
        sed -n '/^{/,$p'
)"
echo "$BUILD_JSON" >"${EIF%.eif}.build.json"

echo "[eif] writing manifest"
GIT_REV="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$([ -n "$(git status --porcelain 2>/dev/null)" ] && echo true || echo false)"
TOOLCHAIN="$(rustc --version 2>/dev/null || echo unknown)"
NITRO_CLI_VERSION="$(nitro-cli --version 2>/dev/null || echo unknown)"
EIF_SHA="$(sha256sum "$EIF" | cut -d' ' -f1)"

# jq assembles the manifest from the build JSON + our measurements.
jq -n \
    --argjson build "$(cat "${EIF%.eif}.build.json")" \
    --arg eif "$(basename "$EIF")" \
    --arg eif_sha256 "$EIF_SHA" \
    --arg git_rev "$GIT_REV" \
    --argjson git_dirty "$GIT_DIRTY" \
    --arg toolchain "$TOOLCHAIN" \
    --arg nitro_cli "$NITRO_CLI_VERSION" \
    --arg module_id "throttle.wasm" \
    --arg measurement "$MEASUREMENT" \
    --arg capabilities "$CAPABILITIES" \
    --arg tee_pk "$TEE_PK" \
    --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        schema: "tee-lua-runner/measurements-manifest/1",
        built_at: $built_at,
        provenance: {
            git_rev: $git_rev,
            git_dirty: $git_dirty,
            toolchain: $toolchain,
            nitro_cli: $nitro_cli,
            eif: $eif,
            eif_sha256: $eif_sha256
        },
        measurements: $build.Measurements,
        module: {
            id: $module_id,
            measurement: $measurement,
            capabilities: $capabilities
        },
        envelope_key: { tee_pk: $tee_pk }
    }' >"${EIF%.eif}.manifest.json"

echo "[eif] EIF:      $EIF"
echo "[eif] manifest: ${EIF%.eif}.manifest.json"
jq '{measurements: {PCR0: .measurements.PCR0, PCR1: .measurements.PCR1, PCR2: .measurements.PCR2}, module: .module.measurement, envelope_key: .envelope_key.tee_pk}' \
    "${EIF%.eif}.manifest.json"
