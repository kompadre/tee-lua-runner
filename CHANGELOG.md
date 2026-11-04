# Changelog

Notable changes to this project, per `Keep a Changelog` conventions.
The project has not had a release yet; everything lives under `[Unreleased]`.

## [Unreleased]

### Added

- **QEMU local enclave environment (Stage 6)** — the enclave architecture
  without real Nitro, validated live end-to-end (`just qemu-demo`):
  - **Transports** (`tee-proto::transport`): `HOST:PORT` /
    `vsock:CID:PORT` (dial) / `vsock:PORT` (listen) with `Stream`/`Listener`
    enums (full TCP parity incl. timeouts). Native-only (cfg +
    target-gated — guests keep building).
  - **NSM-operation ABI** (`tee-attest`): `NsmRequest`/`NsmResponse`
    mirroring `GetAttestationDoc`'s fields (Stage 7: same fields over the
    `/dev/nsm` ioctl) + `NsmRemoteAttestor` (per-request dial; the
    `public_key` request field binds the channel key, like real NSM).
  - **`tee-runner nsm-standin`**: host-side "firmware" daemon — stable trust
    root from a seed, per-request `public_key` binding, malformed requests
    answered with error responses (never crashes).
  - **`tee-runner serve --nsm <addr>`**: remote attestation backend
    (mutually exclusive with `--mock-attest`) so the guest never self-signs;
    `tpass --server` accepts vsock addresses.
  - **`deploy/qemu/`**: guest `init` (console re-attach, dependency-ordered
    vsock module loads, kernel-cmdline config), `build-rootfs.sh`
    (static-busybox base via docker, release+stripped runner, host libs,
    decompressed modules, cpio), `run.sh` (KVM with TCG fallback,
    `vhost-vsock-pci`, guest CID 3), `e2e.sh` (full validation), and
    `just qemu-build` / `qemu-run` / `qemu-demo`.
  - Validation result: guest booted under KVM, served over vsock, attestation
    served by the host stand-in over a second vsock channel, tpass
    init → attest → insert → **show recovered the secret through the guest**,
    audit ring recorded `fetch ok`. Empirical JIT check **passed**
    (Cranelift runs in the guest; `pulley` fallback unnecessary — real
    Nitro kernel re-checked at Stage 7/EC2).
- **Client (Stage 5, `tpass`)**: pass-like CLI over the full protocol —
  - **Keystore at rest**: `TPASSKEY1 ‖ m,t,p ‖ salt ‖ nonce ‖ sealed`;
    Argon2id(passphrase, salt, params — recorded in-file) → ChaCha20Poly1305
    over `LocalIdentity::to_seed()`; public half stored beside it so
    **insert/generate need no passphrase**; `Zeroizing` everywhere;
    no-echo prompts (`rpassword`) or `--passphrase-file`.
  - **Session bootstrap**: plaintext `op:"attest"` challenge (freshness
    nonce; root + pinned measurement enforced) → channel key taken only
    from the *verified* document → channel-wrapped `fetch`/`revoke`/`audit`.
    `tee-proto` gains the shared **framing** module (u32-length codec, one
    source for server and client) and the attest request/response variants.
  - **Config pins** (`config.json`): server, trust root, measurement
    (trust-on-first-use via `attest --save`), TEE envelope key, discovered
    channel mode.
  - Commands: `init`, `attest`, `generate`, `insert`, `show`, `list`, `rm`,
    plus **`revoke`** (client path to the Stage 4 blacklist) and **`audit`**
    (audit-ring read side).
- `tee-guest` throttle service: `attest` capability + attest op (nonce →
  document binding module measurement and channel key).
- `tee-runner serve` (channel mode): plaintext frames are accepted **only**
  for `{"op":"attest"}` — everything else must ride the channel.
- Tests: client unit suite (keystore roundtrip / wrong passphrase /
  tampered & malformed keystores, config roundtrip, path-traversal-safe
  entry names, password generation) + **first-run full-system e2e** through
  real processes (init → attest TOFU + wrong-pin rejection → sealed insert →
  show through the gate → revoke → `[blacklisted]` → audit secret-free →
  plaintext-fetch refusal); `just gates` green (26 suites).
- Task runner: **`justfile` as a stable command facade** — recipes `gates`
  (all five quality gates, including the new `svc-throttle` gate),
  `guest-tests`, `throttle-tests`, `examples`, `ci`, and
  `measure`/`run`/`serve` with pass-through flags. Docs and instructions
  reference recipe names instead of command lines (context economy); CI keeps
  running the commands verbatim with sync comments in both files. `xtask`
  deliberately deferred to Stage 7 (task bodies will need real Rust logic —
  release manifests, PCR/measurement computation reusing runner-core); the
  facade means landing it later changes no docs or callers.
- **Throttle service (Stage 4)** — the reference workload as an attested
  guest module (`svc-throttle`, artifact `throttle.wasm`, 199 KB, manifest
  `log,state,clock,crypto,gate`):
  - **New host capabilities** in `runner-core`: `gate.unwrap` (blind-gatekeeper
    unwrap with the provisioned TEE X25519 key — the secret never enters
    guest memory; own capability module so hashing guests cannot unwrap) and
    `crypto.ed25519_verify` (PoP verification primitive). Host errors carry
    stable machine codes (`wrong_owner`, `decrypt_failed`, `malformed`,
    `not_provisioned`, `bad_request`) for service-side protocol mapping.
  - **`RunnerConfig`** (limits + attestor + tee_key) replacing the growing
    `build()` argument list.
  - **`tee-proto`**: JSON wire contract (`Request`/`Response`, typed
    `ErrorCode`s with `retry_after_ms`, `AuditEntry`) and the byte-stable
    **PoP message builders** — fetch PoP binds `sign_pk ‖ enc_pk ‖
    sha256(envelope)` (identity = both Stage 3 keys; no substitution).
  - **Service policy**: PoP → blacklist → rolling window (5 fetches/60 s per
    identity, monotonic-floor clock: `now = max(host_time, last_seen)` so
    rollback fails closed) → `gate.unwrap` → audit ring (256 entries, key ids
    + outcomes only, never secrets); bounded owner buckets (512, least-recent
    eviction) and blacklist capacity (256, fail-closed); policy constants sit
    at the top of the measured source.
  - `tee-runner --tee-key <hex32>` on run/serve, prints `tee-pk: <hex>`
    (stderr order: tee-pk, root, channel-pk, measurement).
  - **Serve-side channel nonce replay cache** (`NonceCache`, 4096-window):
    one wire nonce → one execution across connections; replayed messages
    close the connection without executing.
- Tests: 88 workspace + 8 throttle-service (native mock) + CI gate for
  `svc-throttle`; CLI e2e over the channel: sealed fetch → client decrypt,
  6th-fetch throttle with retry hint, PoP-gated revocation → hard refuse,
  audit ring without secrets, replay refusal.

- **Crypto (Stage 3, `tee-crypto`)**:
  - `LocalIdentity` / `PublicIdentity` — Ed25519 (identity + domain-separated
    proof-of-possession) with X25519 (envelope recipient), seed-based,
    zeroize-on-drop, `key_id()` for throttle/audit binding.
  - **RFC 9180 HPKE**, suite DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/
    ChaCha20Poly1305: base mode (envelopes, channel requests) and auth mode
    (channel responses), pinned against the official Appendix A.2/A.2.3 test
    vectors (key derivation, encapsulation, key schedule, nonces, ciphertexts).
  - **Blind-gatekeeper envelopes**: `seal_secret` = `E_TEE(E_local(secret))`
    with `tee_unwrap` (outer open + inner-recipient owner check, plaintext
    never in the TEE), AAD-bound recipient/TEE headers, self-describing inner
    layout. New deps: `x25519-dalek`, `chacha20poly1305`, `zeroize`.
  - **E2E channel** (one-shot request/response, CBOR records): requests
    HPKE-sealed to the enclave's channel key; responses **HPKE auth mode** so
    the enclave proves possession of its *attested* key (plain
    encrypt-to-public-key would let any wire observer forge responses);
    nonce echo + request-hash transcript binding; per-request client response
    keys.
- `tee-attest`: `MockAttestor::with_public_key` — binds an application key
  (the channel key) into the attestation payload's `public_key` field.
- `tee-runner serve --channel`: channel-wrapped frames (binary), prints
  `channel-pk: <hex>`; works with `--mock-attest` for the attested-channel
  flow (stderr order: root, channel-pk, measurement).
- Tests (68 workspace + 2 guest): RFC vectors, envelope owner-binding +
  exhaustive tamper scan, channel server-auth forgery rejection + exhaustive
  tamper scans both directions, PoP roundtrip/domain binding, and the CLI
  attested-channel e2e (channel key verified against the attestation document).

- **Attestation (Stage 2)**: `tee-attest` ships a COSE_Sign1 (RFC 9814) mock
  attestation backend — `MockAttestor` (Ed25519 test root, `generate` /
  `from_seed`), a Nitro-mirroring payload schema (`module_id`, `digest`,
  `pcrs`, `timestamp`, `nonce`, `user_data`, optional `public_key`,
  `algorithm`), and client-side `verify()` with pluggable `TrustRoot` and
  `Expectations` (freshness nonce + module-measurement binding) behind a
  typed `VerifyError`. Stage 7 swaps backend + trust root for the real
  NSM/AWS chain without changing the document shape or the verify entry
  point. New deps: `ciborium`, `ed25519-dalek`.
- `tee-runner`: `--mock-attest` on `run`/`serve` (prints
  `mock-attest-root: <hex>` to stderr; PCR0 = sha256 of the runner binary)
  and a `verify` subcommand acting as the reference client
  (`--root/--doc/--nonce/--user-data` → payload JSON, non-zero exit on any
  check failure).
- `tee-guest`: `svc-attest` example service — `{"method":"doc",
  "nonce_hex":…}` → `{"doc_hex":…}` (artifact `attest.wasm`).
- Doc pipeline: `AGENTS.md`/`TODO.md`/`SESSION.md`/`CHANGELOG.md` with the
  eviction contract (TODO → SESSION on task start → CHANGELOG on completion);
  README links them. *(ddfe357, dcc158e)*
- **AGENTS.md is user-owned (Instruction 0)**: agents modify it only when the
  user literally prescribes the change and its placement (scope: the AGENTS.md
  file proper; the rest of the stack stays agent-editable). Added together
  with a full doc-stack consistency audit — `TODO.md` declared source of
  truth for the stage table, README's status table mirrors it (stages 1/1b/8
  restored, "next" marker), stale wording fixed; AGENTS implementation
  specifics assessed stable and left in place per user decision.
- Cargo workspace (runner-core, runner-cli, tee-attest, tee-crypto, tee-proto,
  tee-guest, client, enclave-bin) with pinned toolchain
  (`rust-toolchain.toml`: rustc 1.99.1 + `wasm32-unknown-unknown`) and CI
  (fmt, clippy `-D warnings`, tests, guest service tests). *(604caf5)*
- **Runner core (Wasmtime engine)**: wasm module validation, import-derived
  capability manifest (known modules/fields, uniform host ABI, no WASI),
  module measurement
  (`SHA-256("tee-runner/module/v1" ‖ bytes ‖ canonical manifest)`), and
  per-request budgets: deterministic fuel, epoch wall-clock interruption,
  hard linear-memory cap (`StoreLimits`) + declared-memory floor check. *(6e4a92c)*
- **Guest SDK (`tee-guest`)**: `alloc`/`handle` JSON-envelope ABI, typed host
  wrappers (hex-on-the-wire), native mock backend, example services
  (`echo`, `counter`, `hasher`, `attest` — one wasm artifact per service). *(6e4a92c, Stage 2)*
- **`tee-runner` CLI**: `measure` (capability manifest + measurement),
  `run` (single JSON request), `serve` (u32-length-prefixed JSON frames with
  in-band `{"ok":…}` envelopes). *(604caf5, evolved 6e4a92c)*
- `tee-attest` baseline: `Attestor` trait + refusing `NullAttestor`. *(604caf5)*

### Fixed

- COSE_Sign1 documents are encoded with real CBOR **byte strings**: plain
  serde `&[u8]` serializes to an array of integers, which roundtrips
  self-consistently (tests pass) yet is not COSE. Byte strings are built via
  `ciborium::Value::Bytes`, and `document_has_cose_sign1_shape` pins the
  literal shape (bstr / empty map / bstr / 64-byte bstr).

### Changed

- **`serve` channel mode now refuses plaintext protocol traffic**: only
  `{"op":"attest"}` may arrive in the clear (it bootstraps the channel key;
  the client cannot wrap before verifying). The framing codec moved from
  `runner-cli` into `tee-proto` (single source for both sides). *(Stage 5)*
- **Resolved Stage 5 open question**: keystore format — Argon2id (params
  recorded in-file) + ChaCha20Poly1305 over the identity seed, magic
  `TPASSKEY1`. *(Stage 5)*
- **Resolved Stage 4 open questions**: rolling-window clock → host time with
  a monotonic floor (rollback fails closed; forward-jump resistance deferred
  to Stage 6 as Q1′); restart persistence → v1 in-memory state with the
  blacklist-durability gap recorded as Q2′ (Stage 8). *(Stage 4)*
- **Resolved Stage 3 open questions**: wire format → CBOR for
  envelopes/channel records (request payloads stay JSON until Stage 5
  re-evaluates); envelope construction → RFC 9180 HPKE with official vectors
  pinned (no hand-rolled ECIES). *(Stage 3)*
- **Script engine pivoted from Lua 5.4 to WebAssembly (Wasmtime 50)** after a
  measured evaluation: engine-enforced (uncatchable) limits replace
  hand-rolled hook enforcement, the hashed import section *is* the capability
  manifest, and guests gain zero ambient authority (no WASI). Guest modules
  are built from Rust via `wasm32-unknown-unknown`; example artifacts ~100 KB. *(6e4a92c)*
- Golden-test policy: tests pin formatting-invariant capability manifests;
  artifact hex is pinned only in release manifests (guest binaries embed
  panic-location strings, so bytes depend on guest source lines). *(6e4a92c)*

### Removed

- Lua embedding (mlua), `@capability` comment-manifest parser, hand-rolled
  budget hook machinery, and Lua example scripts — superseded by the Wasmtime
  engine. *(6e4a92c)*
