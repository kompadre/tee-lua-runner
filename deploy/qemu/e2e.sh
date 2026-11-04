#!/usr/bin/env bash
# Stage 6 live validation: host NSM stand-in + QEMU guest + tpass over vsock.
#
# Exit criterion: a secret inserted from the host is recovered THROUGH the
# guest (vsock, guest CID 3) while attestation is signed by the host
# stand-in (vsock, CID 2) — the enclave architecture without real Nitro.
# Also the empirical JIT check: if `tee-runner serve` boots and serves in
# the guest, Cranelift JIT works there (pulley fallback unnecessary).
set -euo pipefail
cd "$(dirname "$0")/../.."

NSM_PORT="${NSM_PORT:-7777}"
GUEST_PORT="${GUEST_PORT:-5555}"
SEED="${SEED:-$(printf '77%.0s' $(seq 32))}" # stable demo root seed
PCR0="${PCR0:-$(printf 'ee%.0s' $(seq 32))}"
TEE_KEY="${TEE_KEY:-$(printf '2a%.0s' $(seq 32))}"
OUT="deploy/qemu/build"
STORE="$(mktemp -d "${TMPDIR:-/tmp}/tpass-qemu-XXXXXX")"
PASSPHRASE_FILE="$STORE/.pass"
echo "qemu-e2e-passphrase" > "$PASSPHRASE_FILE"

log() { echo "[e2e] $*"; }
fail() { echo "[e2e] FAILED: $*" >&2; exit 1; }

wait_for() { # file pattern timeout_seconds label
    local file="$1" pattern="$2" timeout="$3" label="$4"
    local tries=$((timeout * 2))
    while [ "$tries" -gt 0 ]; do
        if [ -f "$file" ] && grep -q "$pattern" "$file"; then
            return 0
        fi
        sleep 0.5
        tries=$((tries - 1))
    done
    fail "timeout waiting for ${label} (pattern: ${pattern}) in ${file}"
}

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null || true
    [ -n "${NSM_PID:-}" ] && kill "$NSM_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$STORE"
}
trap cleanup EXIT

log "building artifacts + rootfs"
bash scripts/build-guest-examples.sh >/dev/null
bash deploy/qemu/build-rootfs.sh >/dev/null

log "starting host NSM stand-in on vsock:${NSM_PORT}"
target/debug/tee-runner nsm-standin \
    --listen "vsock:${NSM_PORT}" \
    --seed-hex "$SEED" \
    --pcr0 "$PCR0" \
    --module-id qemu-e2e \
    >"$OUT/standin.log" 2>"$OUT/standin.err" &
NSM_PID=$!
wait_for "$OUT/standin.err" "nsm-standin trust root:" 10 "stand-in trust root"
ROOT="$(sed -n 's/.*trust root: //p' "$OUT/standin.err" | tr -d "\r" | head -1)"
log "stand-in trust root: ${ROOT}"

log "booting QEMU guest (kvm=$( [ -r /dev/kvm ] && echo yes || echo no ), cid=3)"
TEE_KEY="$TEE_KEY" NSM="vsock:2:${NSM_PORT}" LISTEN="$GUEST_PORT" \
    bash deploy/qemu/run.sh >"$OUT/boot.log" 2>&1 &
QEMU_PID=$!
wait_for "$OUT/boot.log" "listening on vsock" 90 "guest serve over vsock"
TEE_PK="$(sed -n 's/.*tee-pk: //p' "$OUT/boot.log" | tr -d "\r" | head -1)"
MEASUREMENT="$(sed -n 's/.*module measurement: //p' "$OUT/boot.log" | tr -d "\r" | head -1)"
log "guest tee-pk: ${TEE_PK}"
log "guest measurement: ${MEASUREMENT}"

TP=(target/debug/tpass --store "$STORE" --passphrase-file "$PASSPHRASE_FILE")

log "tpass init (dialing the guest over vsock:3:${GUEST_PORT})"
"${TP[@]}" init --server "vsock:3:${GUEST_PORT}" --tee-pk "$TEE_PK"

log "tpass attest --save (document signed by the host stand-in)"
"${TP[@]}" attest --root "$ROOT" --save | tee "$OUT/attest.txt"
grep -q "channel key: <none" "$OUT/attest.txt" && fail "channel key not bound into the document"

# The TOFU-pinned measurement must equal what the guest console reported.
CFG_MEAS="$(sed -n 's/.*"measurement_hex": "\(.*\)".*/\1/p' "$STORE/config.json" | head -1)"
[ "$CFG_MEAS" = "$MEASUREMENT" ] || fail "pinned measurement != console measurement"

log "insert + show through the guest"
echo "secret-through-the-hypervisor" | "${TP[@]}" insert guest-entry
SHOWN="$("${TP[@]}" show guest-entry)"
[ "$SHOWN" = "secret-through-the-hypervisor" ] || fail "show returned: ${SHOWN}"

log "audit ring (guest-side decisions, no secrets)"
"${TP[@]}" audit | tee "$OUT/audit.txt"
grep -q "fetch" "$OUT/audit.txt" || fail "audit ring has no fetch entries"

log "E2E OK — secret round-tripped through the QEMU guest over vsock"
