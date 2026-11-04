# Task entry points for tee-lua-runner.
#
# Purpose: a STABLE facade — docs, CI notes and agent instructions reference
# recipe names (`just gates`), not command lines, so tooling details never
# explode into every context that mentions them.
#
# CI (.github/workflows/ci.yml) runs the same commands verbatim to keep CI
# free of extra tool dependencies — keep both in sync.
#
# When a task needs real Rust logic (Stage 7: release manifests, PCR and
# measurement computation — where code can REUSE runner-core), migrate the
# recipe BODY to `cargo run -p xtask -- <name>`; callers and docs do not
# change. (xtask deliberately deferred until then — see SESSION.md.)

default: gates

# All quality gates: fmt, clippy -D warnings, every test suite.
gates: fmt lint test guest-tests throttle-tests

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

guest-tests:
    cargo test -p tee-guest --features svc-counter

throttle-tests:
    cargo test -p tee-guest --features svc-throttle

# Build every guest artifact into scripts/examples/*.wasm.
examples:
    ./scripts/build-guest-examples.sh

# Gates + artifacts: a complete local check.
ci: gates examples

# Print the capability manifest + measurement of a module.
measure file:
    cargo run -q -p runner-cli -- measure {{file}}

# --- QEMU enclave environment (Stage 6) ---

# Build the guest rootfs + initramfs (needs /dev/kvm-friendly host kernel).
qemu-build:
    bash deploy/qemu/build-rootfs.sh

# Boot the guest interactively on ttyS0 (Ctrl-A X quits QEMU).
qemu-run:
    bash deploy/qemu/run.sh

# Full Stage 6 validation: host NSM stand-in + QEMU guest + tpass over vsock.
qemu-demo:
    bash deploy/qemu/e2e.sh

# Handle one JSON request on stdin against a module.
run module *args:
    cargo run -q -p runner-cli -- run {{module}} {{args}}

# Serve length-prefixed frames (pass flags like --channel --tee-key <hex>).
serve module *args:
    cargo run -q -p runner-cli -- serve {{module}} {{args}}
