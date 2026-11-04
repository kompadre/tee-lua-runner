# TODO.md — task board

Legend: `[x]` done · `[~]` in progress · `[ ]` pending. This stage table is
the source of truth for stage state (README mirrors it); conventions live in
`AGENTS.md`.

This file is the **queue**: only tasks not yet started get their breakdown
here. When a task starts, its breakdown and open questions are **evicted into
the current `SESSION.md` entry**; when it completes, detail moves from SESSION
into `CHANGELOG.md` and the stage row below gets ticked.

## Stages

| # | Scope | State |
|---|-------|-------|
| 0 | Workspace, CI, toolchain pin | [x] done |
| 1 | Runner core (Lua embedding) | [x] superseded by 1b |
| 1b | Wasmtime engine pivot: validation, capability imports, measurement, budgets, guest SDK, host CLI | [x] done |
| 2 | Attestation: COSE_Sign1 mock backend, client-side verification, trust root, `tee.attest` e2e | [x] done |
| 3 | Crypto: local identities (Ed25519+X25519), HPKE envelopes `E_TEE(E_local(…))`, client↔enclave E2E channel | [x] done |
| 4 | Throttle & blacklist service as an attested guest module (rolling window, PoP, audit ring) | [x] done |
| 5 | `tpass` client CLI (init/attest/generate/insert/show/list/rm, keystore, zeroize) | [x] done |
| 6 | QEMU local enclave environment: vsock, NSM stand-in (same NSM API, two backends), rootfs | [ ] **next** |
| 7 | EIF pipeline: container → `nitro-cli build-enclave` → measurements manifest, CI artifact, EC2 runbook | [ ] |
| 8 | Hardening backlog: fuzzing, sealed state, quotas, attested logs, benchmarks | [ ] |

<!-- Stage 3 breakdown + its open questions evicted to SESSION.md on start (2026-11-04). -->

<!-- Stage 4 breakdown + Q1/Q2 evicted to SESSION.md on start (2026-11-04);
     resolved for v1 there with carry-forwards Q1'/Q2'/envelope-key below. -->
<!-- Stage 5 breakdown (incl. keystore-format resolution) evicted to SESSION.md
     on start (2026-11-04). -->

## Open design questions (resolve before/during the named stage)

1. **Q1′ — attested time for the rolling window (Stage 6).** v1 (Session 5)
   uses host time with a monotonic floor (rollback fails closed), but a host
   that jumps its clock *forward* expires throttle windows early. Needs a
   trusted signal: boot counters, an attested-time oracle, or policy that
   tolerates jumps. *Thorniest correctness issue in the throttle design.*
2. **Q2′ — durable blacklist state (Stage 8).** v1 state is host in-memory:
   restarts reset throttle buckets *and blacklist*. Blacklist durability
   needs an AEAD-sealed snapshot (state integrity vs. the untrusted host).
3. **Both enclave keys in one attestation (Stage 6).** The payload has a
   single `public_key` field (used for the channel key); the envelope key
   needs attesting too — layout decision (combine, extend schema, or bind
   one via `user_data`).
4. **JIT inside Nitro enclaves (Stage 6).** Expect Cranelift's RWX mappings
   to work (enclaves are VMs, not SGX), but verify empirically; Wasmtime's
   `pulley` interpreter is the fallback if not.
5. **Repo name** still says "lua" (README notes the pivot). Rename when
   convenient — needs an explicit decision (AGENTS guardrail).

## Backlog (nice to have)

- [ ] Component model / WIT typed host interfaces (instead of JSON envelopes)
- [ ] Dual engine (Lua + wasm) behind a `ScriptEngine` trait — explicitly
      rejected for now (two sandboxes to audit); revisit only with a concrete
      need
- [ ] Fuel calibration measurements → sane `--fuel` default per service class
- [ ] `wasm-tools`-based artifact inspector for release verification UX
