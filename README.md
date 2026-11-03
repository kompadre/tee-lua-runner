# tee-lua-runner

A minimal, attestable Lua runner for TEE platforms (AWS Nitro Enclaves first).
Service logic lives in small Lua scripts whose **hash is bound into the
attestation document**, along with a capability manifest, so clients can verify
exactly *which* script and *which* host APIs run inside the enclave.

The reference workload is a pass-like password store with external throttling:
passwords are double-encrypted (`E_TEE(E_local(secret))`), and the TEE acts as
a **blind gatekeeper** — it unwraps only the outer envelope, checks the inner
ciphertext is addressed to the client's local key, and rate-limits/blacklists
per identity. It never sees plaintext and never persists request contents.

## Status

| Stage | Scope | State |
|-------|-------|-------|
| 0 | Workspace, CI, toolchain pin | done |
| 1 | Runner core: Lua sandbox, capabilities, measurement, limits, host CLI | done |
| 2 | Attestation: mock backend, client-side doc verification | planned |
| 3 | Crypto: identities, envelopes, client↔enclave channel | planned |
| 4 | Throttle & blacklist service as an attested Lua script | planned |
| 5 | `tpass` client CLI | planned |
| 6 | QEMU local enclave environment (vsock, NSM stand-in) | planned |
| 7 | EIF build pipeline for AWS Nitro | planned |

## Layout

```
crates/
  runner-core    Lua embed, sandbox, capability manifest, script measurement, limits
  runner-cli     `tee-runner` host binary (measure / run / serve)
  tee-attest     Attestor trait + backends (null today; mock + NSM later)
  tee-crypto     identities, envelopes, channel (Stage 3)
  tee-proto      wire messages and framing (Stage 3)
  client         `tpass` CLI (Stage 5)
  enclave-bin    `tee-enclave` entrypoint (Stage 6)
scripts/examples example service scripts
```

## Script model

A service script declares its capabilities in the header and exposes one
global `handle` function:

```lua
-- @capability state
-- @capability clock

function handle(req)           -- req: JSON-shaped table
    return { t = clock.unix_seconds() }
end
```

* Capabilities: `log`, `state`, `clock`, `random`, `crypto`, `attest`.
  Undeclared APIs are simply absent from the sandbox.
* The measurement is `SHA-256(domain || source || canonical-manifest)`, so any
  change to the script bytes or to the granted capability set changes the
  hash clients pin.
* The sandbox has no `io`/`os`/`debug`/`package`, no `load`/`dofile`/`print`,
  and runs each request under a wall-clock + memory budget that cannot be
  `pcall`-swallowed (the limit hook re-arms at stride 1 when it trips).

## Development

```sh
cargo test --workspace           # unit + integration tests
cargo run -p runner-cli -- measure scripts/examples/counter.lua
echo '{"method":"incr"}' | cargo run -p runner-cli -- run scripts/examples/counter.lua
cargo run -p runner-cli -- serve scripts/examples/counter.lua --listen 127.0.0.1:7000
```

`serve` speaks u32-big-endian-length-prefixed JSON frames and wraps responses
as `{"ok":true,"response":...}` / `{"ok":false,"error":...}`.

The toolchain is pinned in `rust-toolchain.toml` (reproducible builds matter
later for stable Nitro PCR values).
