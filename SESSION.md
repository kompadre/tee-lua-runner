# SESSION.md — workbench & handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (queue) first.

Role in the task flow: the **current task's detail lives here** (evicted from
`TODO.md` when the task starts) and is **evicted into `CHANGELOG.md` when the
task completes**, leaving a compact outcome line. Finished sessions remain as
chronology and gotchas.

---

## Session 3 — 2026-11-04 — doc set + Stage 2 (attestation mock)

**Stage context:** Stage 2 of `TODO.md`'s stage table — first step of the
attestation track (Stage 7 later swaps mock root/backend for real NSM +
AWS root chain without changing the document shape or verify entry point).

**Current task: Stage 2 — attestation mock** (evicted from TODO on start).
No open questions so far; two dependency decisions recorded below.

Breakdown:
- [~] `tee-attest`: CBOR COSE_Sign1 codec (ciborium; protected header
      `{"alg":"EdDSA"}`, Sig_structure per RFC 9814) — *in progress: deps
      added (`ciborium` 0.2, `ed25519-dalek` 2), crate skeleton written*
- [ ] `tee-attest`: payload schema mirroring Nitro attestation docs
      (`module_id`, `digest`, `pcrs`, `timestamp`, `nonce`, `user_data`,
      `algorithm`, optional `public_key`)
- [ ] `tee-attest`: `MockAttestor` (Ed25519 test root, per-call timestamp)
      implementing the existing `Attestor` trait
- [ ] `tee-attest`: `verify()` — signature check (`verify_strict`), nonce
      /user_data expectations, typed `VerifyError`
- [ ] `runner-cli`: `--mock-attest` flag (prints `mock-attest-root: <hex>` to
      stderr; PCR0 = sha256 of the runner binary)
- [ ] `tee-guest`: `svc-attest` example service (`{"method":"doc",
      "nonce_hex":…}` → `{"doc_hex":…}`) + build script entry
- [ ] `runner-cli`: `verify` subcommand (reference client: root hex, optional
      nonce/user-data expectations, prints payload JSON)
- [ ] Tests: sign/verify roundtrip, tamper, wrong root, nonce mismatch,
      user_data binding; CLI e2e (guest → host → doc → verify)
- [ ] Completion: gates green → evict this breakdown into CHANGELOG, tick
      Stage 2 in TODO, leave outcome line here → commit

**Decisions so far this session:**
- Doc set created with pipeline flow (AGENTS/TODO/SESSION/CHANGELOG +
  README links); committed `ddfe357`.
- New deps for `tee-attest` (both minimal, standard): `ciborium` (compact
  CBOR codec) + `ed25519-dalek` (canonical pure-Rust Ed25519).

**Next session starts at:** Stage 3 (crypto: identities, HPKE envelopes,
E2E channel) per `TODO.md`.

---

## Session 2 — 2026-11-04 — Wasmtime pivot (Stage 1b) [completed → CHANGELOG]

**Goal:** evaluate Lua → WASM pivot with measured data; execute it while the
sunk cost was still small (post-Stage 1, pre-Stage 2).

**Outcome:** pivot executed and committed `6e4a92c` — engine-enforced budgets
(fuel/epoch/StoreLimits), import-derived manifests, no WASI, `tee-guest` SDK
with example services. Release runner 10.1 MB (was 1.35 MB on Lua). Feature
detail lives in CHANGELOG `[Unreleased]`.

**Decisions & evidence:**
- Measured before deciding: minimal Wasmtime embed 7.9 MB / 107 deps; fuel
  probe confirmed *uncatchable* traps; Wasmtime pinned at v50
  (`cranelift` + `runtime` only; `wat` never in production builds).

**Gotchas discovered (save future sessions time):**
1. Wasmtime 50 has its **own `Error` type** (not anyhow) — use its
   `bail!`/`format_err!`; `anyhow` does not convert from it.
2. `wasmtime::ValType` implements **no PartialEq** → compare via `matches!`.
3. `func_wrap` closures need **explicit `Caller<'_, T>` annotations** to
   resolve `IntoFunc`, and must be `Send + Sync`.
4. **Import honesty:** a central host dispatch table pins *all* imports in the
   binary; wrappers must reference only their own import for `wasm-ld
   --gc-sections` to shrink the (hashed) manifest. Verified: echo `(none)`,
   counter `log,state,clock`, hasher `random,crypto`.
5. **Guest artifacts embed panic-location `file:line` strings** → artifact
   bytes shift when guest source lines move (this broke golden hex after
   `cargo fmt`). Clean rebuilds of the *same* source are byte-identical.
   Rule: pin capability manifests in tests; pin artifact hex only at release
   (Stage 7), from tagged sources.
6. Nested `cargo build` inside `cargo test` (example fixture builds) works
   fine; use `std::sync::Once` for it.

---

## Session 1 — 2026-11-03/04 — project start: Stage 0 + Stage 1 (Lua) [completed → CHANGELOG]

**Outcome:** workspace + CI + pinned toolchain; the original Lua 5.4 runner
core (sandbox, capability manifest, measurement, budget hooks) with 25 tests;
committed `604caf5`. Feature detail lives in CHANGELOG `[Unreleased]`; the
Lua implementation was superseded by Session 2.

**Decisions:** Rust (rustup stable pinned), blind-gatekeeper envelope model
(TEE never sees plaintext), script hash + capability manifest in
attestation, standalone `tpass` CLI (later), runner core first.

**Environment facts:** rustc/cargo **1.99.1** (pinned), rustup 1.29.3,
QEMU 10.0.13, Docker 29.9.2, gcc 14, **no nitro-cli yet**, host Go 1.26.3
(never used), system Lua 5.2/LuaJIT present but unused (historical).

**Handoff to session 2:** Lua runner green; pivot considered — see Session 2.
