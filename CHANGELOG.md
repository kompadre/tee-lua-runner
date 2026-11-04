# Changelog

Notable changes to this project, per `Keep a Changelog` conventions.
The project has not had a release yet; everything lives under `[Unreleased]`.

## [Unreleased]

### Added

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
