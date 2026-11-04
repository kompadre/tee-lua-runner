# SESSION.md — workbench & handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (queue) first.

Role in the task flow: the **current task's detail lives here** (evicted from
`TODO.md` when the task starts) and is **evicted into `CHANGELOG.md` when the
task completes**, leaving a compact outcome line. Finished sessions remain as
chronology and gotchas.

---

## Session 5 — 2026-11-04 — Stage 4 (throttle & blacklist service) [completed → CHANGELOG]

**Stage context:** Stage 4 — the reference workload: the pass-like service's
external throttling as an *attested guest module*.

**Outcome:** shipped (commit below) — `gate.unwrap` + `crypto.ed25519_verify`
host capabilities (TEE secret stays host-side, never in guest memory),
`RunnerConfig`, `tee-proto` wire contract with byte-stable PoP messages, and
the `svc-throttle` service (PoP → blacklist → rolling window → gate → audit
ring) with policy constants in the measured source. Artifact `throttle.wasm`
199 KB, honest manifest `log,state,clock,crypto,gate`. 88 workspace + 2 + 8
tests green, incl. full CLI e2e over the channel (fetch→decrypt, 6th-fetch
throttle with retry hint, revocation, audit without secrets). Detail evicted
to CHANGELOG `[Unreleased]`.

**Decisions (with carry-forwards):**
- **Q1 (clock) resolved for v1:** host time + monotonic floor
  `now = max(host_time, last_seen)` — rollback fails closed. Forward-jump
  resistance impossible without trusted time → **Q1′ (Stage 6)**.
- **Q2 (persistence) resolved for v1:** host in-memory state; restarts reset
  buckets and blacklist → **Q2′ sealed blacklist snapshot (Stage 8)**.
- New carry-forward: attesting **both** enclave keys (payload has one
  `public_key`, used for the channel key) → **Stage 6 question**.
- Identity = *both* keys: PoP message binds `sign_pk ‖ enc_pk ‖
  sha256(envelope)` so neither key can be substituted independently; throttle
  buckets and blacklist keyed by `sign_pk`.
- Replay: content-based PoP (no server-challenge round-trip) is sufficient
  because the serve layer enforces **one wire nonce → one execution** —
  implemented in `server.rs` (`NonceCache`, bounded 4096-window: a replayed
  channel message opens but closes the connection without executing; the
  cache spans connections for the whole serve process). Test-pinned in the
  attested-channel e2e.
- New host capabilities: `gate.unwrap` (own capability module — wrapping
  must not ride on `crypto`, or any hashing guest could unwrap envelopes)
  and `crypto.ed25519_verify` (verification primitive; policy stays in the
  measured guest). Error bridge: host errors carry a stable `code`
  (`wrong_owner`, …) mapped by the service to protocol codes — no string
  matching.
- `runner-core` now depends on sibling `tee-crypto` + `ed25519-dalek`
  (in-tree, already vetted — not new external surface).

**Gotcha added this session:**
10. Native guest tests share `thread_local` mock state across the libtest
    worker pool (tests may run sequentially on one thread) → design tests
    with per-test unique keys and cap-invariant assertions instead of
    assuming fresh state.

**Working state / pending user action:**
- ~~AGENTS gates list amendment~~ — **resolved**: user prescribed the literal
  gate-5 line (`cargo test -p tee-guest --features svc-throttle    # gate 5
  (throttle service)`) and it was applied verbatim — the first exercised use
  of Instruction 0 (prescription honored exactly, nothing else touched).
- **Tooling decision (user prompt: just + xtask consideration):**
  - **Adopted `just`** as the stable facade (`justfile`: `gates` = the five
    gates, `examples`, `ci`, `measure`/`run`/`serve`). Docs/instructions can
    now say `just gates` instead of listing commands — the context-economy
    goal. CI mirrors the commands verbatim (sync comments both ways; CI stays
    dependency-free). Installed locally via `cargo install just --locked`.
  - **`xtask` deferred to Stage 7** with a concrete trigger: when a task
    body needs real Rust logic (release manifests, PCR/measurement
    computation — reusing `runner-core::measure_module`), recipes switch to
    `cargo run -p xtask -- <name>` **without changing any caller, doc, or CI
    line** — that facade property is why xtask-now would be premature
    scaffolding and just-now is not.

**Next session starts at:** Stage 5 (`tpass` client CLI: init/attest/
generate/insert/show/list/rm, keystore + zeroize) — breakdown and open
questions evicted from `TODO.md` when started. **Stage 5 open design
item:** keystore format (Argon2id KDF + AEAD; `to_seed`/`from_seed` hooks
exist in Stage 3's `LocalIdentity`).

---

## Session 4 — 2026-11-04 — Stage 3 (crypto) [completed → CHANGELOG]

**Stage context:** Stage 3 — local identities, HPKE envelopes, E2E channel.
First code stage after the documentation detour; Instruction 0 re-armed for it.

**Outcome:** `tee-crypto` shipped (commit below) — RFC 9180 HPKE (base +
auth) pinned against official A.2/A.2.3 vectors on first run, blind-gatekeeper
envelopes `E_TEE(E_local(…))`, one-shot channel with attested server
authentication, `LocalIdentity` (Ed25519+X25519, zeroize, PoP), `serve
--channel` with the channel key bound into the attestation's `public_key`.
68 workspace + 2 guest tests green, incl. exhaustive byte-tamper scans on
envelopes, channel requests and responses, and the attested-channel e2e.
Detail evicted to CHANGELOG `[Unreleased]`.

**Decisions:**
- Q3 wire format → **CBOR for envelopes/channel records** (ciborium);
  request/response *payloads* stay JSON until Stage 5 re-evaluates (carry
  forward, not a blocker).
- Q4 envelope construction → **RFC 9180 HPKE**
  (DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305, base mode), no
  hand-rolled ECIES; official vectors pinned in tests.
- **Responses use HPKE auth mode**: HPKE-sealing a response *to the client's
  key* authenticates nobody — any wire observer could forge it. Auth mode
  makes the enclave prove possession of its *attested* channel key instead,
  and mixes nonce + request-hash into info for transcript binding. (Found
  while mapping the channel, not in the original plan.)
- Envelope owner check: the inner envelope's recipient header is visible by
  design (the TEE must read it without opening the ciphertext) and is
  AAD-bound so swaps fail at the client's open.
- New deps: `x25519-dalek` (+`static_secrets`), `chacha20poly1305`,
  `zeroize` (AGENTS sanctions zeroize at Stage 3).

**Gotchas added this session:**
8. ciborium has **no `from_bytes`/`to_bytes`** — only `from_reader`/
   `into_writer` (hit twice now; see also gotcha7 for the `&[u8]` array trap).
9. `Hmac::new_from_slice` is ambiguous once `chacha20poly1305::aead::KeyInit`
   is in scope — use `<Hmac<Sha256> as Mac>::new_from_slice`.

**Next session starts at:** Stage 4 (throttle & blacklist service as an
attested guest module — rolling window, PoP, audit ring) — its breakdown and
open questions (rolling-window clock, restart persistence) get evicted from
`TODO.md` when started. *That stage also has to resolve the clock question
before its policy code is final.*

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
