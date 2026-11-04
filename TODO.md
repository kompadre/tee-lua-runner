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
| 6 | QEMU local enclave environment: vsock, NSM stand-in (same NSM API, two backends), rootfs | [x] done |
| 7 | EIF pipeline: container → `nitro-cli build-enclave` → measurements manifest, CI artifact, EC2 runbook | [x] done |
| 8 | Hardening backlog: fuzzing, sealed state, quotas, attested logs, benchmarks | [ ] **next** |

<!-- Stage 3 breakdown + its open questions evicted to SESSION.md on start (2026-11-04). -->

<!-- Stage 4 breakdown + Q1/Q2 evicted to SESSION.md on start (2026-11-04);
     resolved for v1 there with carry-forwards Q1'/Q2'/envelope-key below. -->
<!-- Stage 5 breakdown (incl. keystore-format resolution) evicted to SESSION.md
     on start (2026-11-04). -->
<!-- Stage 6 breakdown + its questions (JIT, both-keys slot, attested time)
     evicted to SESSION.md on start (2026-11-04). -->
<!-- Stage 7 breakdown (its own scope line had no sub-items) + carried
     questions Q1' and both-keys slot evicted to SESSION.md on start
     (2026-11-04). -->

## Open design questions (resolve before/during the named stage)

<!-- 1. Q1′ (attested time) evicted on Stage 7 start; RESOLVED there: defer
     adoption with kernel evidence (no RTC, KVM paravirt clock → parent-VM
     jumps don't reach the enclave) + empirical EC2 check in RUNBOOK §4. -->
1. **Q2′ — durable blacklist state (Stage 8).** v1 state is host in-memory:
   restarts reset throttle buckets *and blacklist*. Blacklist durability
   needs an AEAD-sealed snapshot (state integrity vs. the untrusted host).
<!-- 3. both-keys slot evicted on Stage 7 start; RESOLVED there: user_data =
     measurement ‖ tee_pk, channel key keeps the public_key slot.
     4. JIT empirically PASS at Stage 6 (QEMU); real-Nitro check is RUNBOOK §2. -->
2. **Repo name** still says "lua" (README notes the pivot). Rename when
   convenient — needs an explicit decision (AGENTS guardrail).

## Backlog (nice to have)

- [ ] Component model / WIT typed host interfaces (instead of JSON envelopes)
- [ ] Dual engine (Lua + wasm) behind a `ScriptEngine` trait — explicitly
      rejected for now (two sandboxes to audit); revisit only with a concrete
      need
- [ ] Fuel calibration measurements → sane `--fuel` default per service class
- [ ] `wasm-tools`-based artifact inspector for release verification UX
