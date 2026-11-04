# tee-lua-runner

A minimal, attestable **WebAssembly** runner for TEE platforms (AWS Nitro
Enclaves first). Service logic ships as wasm guest modules whose **bytes are
bound into the attestation document**, together with the capability manifest
derived from their import section, so clients can verify exactly *which*
service and *which* host APIs run inside the enclave.

The reference workload is a pass-like password store with external throttling:
passwords are double-encrypted (`E_TEE(E_local(secret))`), and the TEE acts as
a **blind gatekeeper** — it unwraps only the outer envelope, checks the inner
ciphertext is addressed to the client's local key, and rate-limits/blacklists
per identity. It never sees plaintext and never persists request contents.

> History: the runner originally embedded Lua 5.4. It was pivoted to
> Wasmtime early (before attestation work) because engine-enforced limits
> (fuel/epoch/memory) replace hand-rolled ones, the import section *is* the
> capability manifest inside the hashed bytes, and guests can be written in
> any wasm-targeting language. The repo name is kept for now.

## Status

Stage table mirrors [`TODO.md`](TODO.md), which is authoritative.

| Stage | Scope | State |
|-------|-------|-------|
| 0 | Workspace, CI, toolchain pin | done |
| 1 | Runner core (Lua embedding) | done — superseded by 1b |
| 1b | Wasmtime engine pivot: validation, capability imports, measurement, budgets, guest SDK, host CLI | done |
| 2 | Attestation: COSE_Sign1 mock backend, client-side verification, trust root, `tee.attest` e2e | done |
| 3 | Crypto: local identities (Ed25519+X25519), HPKE envelopes `E_TEE(E_local(…))`, client↔enclave E2E channel | planned — **next** |
| 4 | Throttle & blacklist service as an attested guest module (rolling window, PoP, audit ring) | planned |
| 5 | `tpass` client CLI (init/attest/generate/insert/show/list/rm, keystore, zeroize) | planned |
| 6 | QEMU local enclave environment: vsock, NSM stand-in (same NSM API, two backends), rootfs | planned |
| 7 | EIF pipeline: container → `nitro-cli build-enclave` → measurements manifest, CI artifact, EC2 runbook | planned |
| 8 | Hardening backlog: fuzzing, sealed state, quotas, attested logs, benchmarks | planned |

## Layout

```
crates/
  runner-core    Wasmtime engine: module validation, capability linking,
                 script measurement, per-request budgets, host functions
  runner-cli     `tee-runner` host binary (measure / run / serve)
  tee-guest      guest SDK (ABI + typed host wrappers) + example services
  tee-attest     Attestor trait + backends (null + mock today; NSM later)
  tee-crypto     identities, envelopes, channel (Stage 3)
  tee-proto      wire messages and framing (Stage 3)
  client         `tpass` CLI (Stage 5)
  enclave-bin    `tee-enclave` entrypoint (Stage 6)
scripts/
  examples/      example service artifacts (*.wasm, built, not committed)
  build-guest-examples.sh
```

## Module model

A guest module must export:

* `memory`
* `alloc(size: i32) -> i32` — request-lifetime allocation
* `handle(req_ptr: i32, req_len: i32) -> i64` — packed `(len << 32) | ptr`
  of a JSON envelope: `{"ok":true,"response":...}` or
  `{"ok":false,"error":"..."}`

It declares capabilities by importing them — `log.log`, `state.get/set/delete/keys`,
`clock.unix_seconds`, `random.bytes`, `crypto.sha256/hmac_sha256/hkdf_sha256/ct_eq`,
`attest.attest` (uniform ABI `(ptr,len) -> i64`, JSON envelopes, binary as hex):

```rust
#[link(wasm_import_module = "state")]
extern "C" { #[link_name = "get"] fn state_get_raw(ptr: i32, len: i32) -> i64; }
```

* The import section is part of the hashed artifact: unknown modules, fields
  or signatures are load-time errors, and the manifest cannot drift from what
  the code does. `wasm-ld --gc-sections` drops unused imports, so only
  capabilities actually called appear (see `measure` output).
* No WASI: guests have **zero ambient authority** beyond linked imports.
* Budgets per request: deterministic **fuel** (uncatchable trap by
  construction), **epoch** wall-clock interruption, hard linear-memory cap
  (`StoreLimits`). Guest panic locations are embedded in artifacts, so
  artifact bytes depend on guest source lines — build guest sources from
  tagged commits when pinning measurements (release manifests, Stage 7).

## Documentation

- [`AGENTS.md`](AGENTS.md) — how to work here: conventions, commands, architecture invariants
- [`TODO.md`](TODO.md) — task board: stages, open design questions, backlog
- [`SESSION.md`](SESSION.md) — workbench for the current task + handoff log (gotchas, next step)
- [`CHANGELOG.md`](CHANGELOG.md) — user-visible history

## Development

```sh
cargo test --workspace                          # all runner + CLI tests
cargo test -p tee-guest --features svc-counter  # native guest service tests
./scripts/build-guest-examples.sh               # build example *.wasm

cargo run -p runner-cli -- measure scripts/examples/counter.wasm
echo '{"method":"incr"}' | cargo run -p runner-cli -- run scripts/examples/counter.wasm
cargo run -p runner-cli -- serve scripts/examples/counter.wasm --listen 127.0.0.1:7000

# Stage 2: attestation round trip
echo '{"method":"doc","nonce_hex":"0011"}' | \
  cargo run -p runner-cli -- run scripts/examples/attest.wasm --mock-attest
# stderr prints "mock-attest-root: <hex>"; verify the returned doc_hex:
cargo run -p runner-cli -- verify --root <hex> --doc <hex> --nonce 0011
```

`serve` speaks u32-big-endian-length-prefixed JSON frames and wraps responses
as `{"ok":true,"response":...}` / `{"ok":false,"error":...}`. Production
builds compile Wasmtime without `wat`: only binary wasm is accepted.

The toolchain (and the `wasm32-unknown-unknown` target) is pinned in
`rust-toolchain.toml` — reproducible builds matter for stable Nitro PCR values
and reproducible guest artifacts.
