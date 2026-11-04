# TODO.md — task board

Legend: `[x]` done · `[~]` in progress · `[ ]` pending. Stage detail lives in
`README.md`; conventions in `AGENTS.md`; recent outcomes in `SESSION.md`.

## Stages

| # | Scope | State |
|---|-------|-------|
| 0 | Workspace, CI, toolchain pin | [x] done |
| 1 | Runner core (Lua embedding) | [x] superseded by 1b |
| 1b | Wasmtime engine pivot: validation, capability imports, measurement, budgets, guest SDK, host CLI | [x] done |
| 2 | Attestation: COSE_Sign1 mock backend, client-side verification, trust root, `tee.attest` e2e | [ ] **next** |
| 3 | Crypto: local identities (Ed25519+X25519), HPKE envelopes `E_TEE(E_local(…))`, client↔enclave E2E channel | [ ] |
| 4 | Throttle & blacklist service as an attested guest module (rolling window, PoP, audit ring) | [ ] |
| 5 | `tpass` client CLI (init/attest/generate/insert/show/list/rm, keystore, zeroize) | [ ] |
| 6 | QEMU local enclave environment: vsock, NSM stand-in (same NSM API, two backends), rootfs | [ ] |
| 7 | EIF pipeline: container → `nitro-cli build-enclave` → measurements manifest, CI artifact, EC2 runbook | [ ] |
| 8 | Hardening backlog: fuzzing, sealed state, quotas, attested logs, benchmarks | [ ] |

## Stage 2 — task breakdown

- [ ] `tee-attest`: CBOR COSE_Sign1 codec (ciborium; protected header
      `{"alg":"EdDSA"}`, Sig_structure per RFC 9814)
- [ ] `tee-attest`: payload schema mirroring Nitro attestation docs
      (`module_id`, `digest`, `pcrs`, `timestamp`, `nonce`, `user_data`,
      `algorithm`, optional `public_key`)
- [ ] `tee-attest`: `MockAttestor` (Ed25519 test root, per-call timestamp)
      implementing the existing `Attestor` trait
- [ ] `tee-attest`: `verify()` — signature check (`verify_strict`), algorithm
      allowlist, nonce/user_data expectations, typed `VerifyError`
- [ ] `runner-cli`: `--mock-attest` flag (prints `mock-attest-root: <hex>` to
      stderr; PCR0 = sha256 of the runner binary)
- [ ] `tee-guest`: `svc-attest` example service (`{"method":"doc",
      "nonce_hex":…}` → `{"doc_hex":…}`) + build script entry
- [ ] `runner-cli`: `verify` subcommand (reference client: root hex, optional
      nonce/user-data expectations, prints payload JSON)
- [ ] Tests: sign/verify roundtrip, tamper, wrong root, nonce mismatch,
      user_data binding; CLI e2e (guest → host → doc → verify)
- [ ] Docs: README status row, SESSION/CHANGELOG updates, commit

## Open design questions (resolve before/during the named stage)

1. **Time source for the rolling window (Stage 4).** Enclaves have no
   trustworthy clock; host time is untrusted. Options: bounded host time +
   monotonic boot counter, external time attestation, or policy that tolerates
   clock jumps. *Thorniest correctness issue in the throttle design.*
2. **Throttle state across restarts (Stage 4).** In-memory (limits reset) vs
   sealed snapshot vs host-persisted encrypted state.
3. **Wire format (Stage 3).** CBOR/COSE (aligns with attestation docs) vs
   JSON during early bring-up. Current RPC is JSON; decide the envelope
   before `tpass` ships.
4. **Envelope construction (Stage 3).** RFC 9180 HPKE (recommended: standard
   vectors) vs hand-rolled ECIES.
5. **JIT inside Nitro enclaves (Stage 6).** Expect Cranelift's RWX mappings
   to work (enclaves are VMs, not SGX), but verify empirically; Wasmtime's
   `pulley` interpreter is the fallback if not.
6. **Repo name** still says "lua" (README notes the pivot). Rename when
   convenient — needs an explicit decision (AGENTS guardrail).

## Backlog (nice to have)

- [ ] Component model / WIT typed host interfaces (instead of JSON envelopes)
- [ ] Dual engine (Lua + wasm) behind a `ScriptEngine` trait — explicitly
      rejected for now (two sandboxes to audit); revisit only with a concrete
      need
- [ ] Fuel calibration measurements → sane `--fuel` default per service class
- [ ] `wasm-tools`-based artifact inspector for release verification UX
