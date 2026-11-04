# SESSION.md — workbench & handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (queue) first.

Role in the task flow: the **current task's detail lives here** (evicted from
`TODO.md` when the task starts) and is **evicted into `CHANGELOG.md` when the
task completes**, leaving a compact outcome line. Finished sessions remain as
chronology and gotchas.

---

## Session 3 — 2026-11-04 — doc set + Stage 2 (attestation mock) [completed → CHANGELOG]

**Outcome:** task pipeline established (AGENTS/TODO/SESSION/CHANGELOG with
eviction at both transitions, commits `ddfe357` + `dcc158e`). Stage 2 shipped
and committed `29a98ad`: COSE_Sign1 mock attestation end-to-end —
`tee-attest` (`MockAttestor`, payload schema, `verify` +
`TrustRoot`/`Expectations`), `tee-runner --mock-attest` + `verify`
subcommand, `svc-attest` guest service, 45+2 tests green (incl. exhaustive
byte-tamper scan and a shape-pinning test). Detail evicted to CHANGELOG
`[Unreleased]`.

**Decisions:** new deps for `tee-attest` (both minimal, standard):
`ciborium` (compact CBOR codec) + `ed25519-dalek` (canonical pure-Rust
Ed25519); mock payload mirrors Nitro fields and PCR0 binds the runner binary
(sha256 of the executable) so mock documents carry inspectable content.

**Gotcha added this session:**
7. serde serializes `&[u8]` as a **CBOR array of integers**, not a byte
   string — sign/parse stay self-consistent while silently producing
   non-COSE documents (roundtrip tests pass, external tools would reject).
   Build byte strings via `ciborium::Value::Bytes`; pin the literal shape in
   a test. (Discovered by eyeballing a hex dump, not by tests.)

**Detour (same session):** AGENTS gained **Instruction 0** — the file is
user-owned; agents modify it only when the user literally prescribes the
change and its placement (its task-flow table row updated to defer to it).
Full doc-stack audit performed; fixes: README stage table now mirrors TODO
(rows 1/1b/8 restored, "next" marker, TODO = source of truth), stale
`tee-attest` layout line, SESSION role wording in README, TODO header wording
+ stray blank, README Development gained the Stage 2 verify flow, CHANGELOG
gained the Instruction 0 entry. Proposal to move implementation details out of
AGENTS into SESSION → per user: *if everything is stable, leave them there* —
assessed stable-by-policy (toolchain pin, gates, invariants, guardrails all
change only via guarded decisions), so **AGENTS content stays as-is**; the one
self-expiring line (`nitro-cli` not yet installed) gets revisited at Stage 7
under Instruction 0.

**Working state:** the user **suspended Instruction 0 while documentation work
is in progress** — agents may edit AGENTS.md directly during this documentation
session. The suspension ends (Instruction 0 re-arms) when work returns to
code/stages; the rule itself remains in force otherwise.

**Next session starts at:** Stage 3 (crypto: Ed25519+X25519 identities, HPKE
envelopes `E_TEE(E_local(…))`, client↔enclave E2E channel) — its breakdown
gets evicted from `TODO.md` when started.

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
