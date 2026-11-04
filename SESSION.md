# SESSION.md — rolling handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (board) first;
this file answers "what happened and what's next".

---

## Session 3 — 2026-11-04 — doc set + Stage 2 (attestation mock)

**Goal:** establish the AGENTS/TODO/SESSION/CHANGELOG doc flow, then Stage 2.

**Delivered:**
- Doc set created: `AGENTS.md` (policy + task flow), `TODO.md` (board with
  Stage 2 breakdown and open questions), this file, `CHANGELOG.md`;
  README links them.
- Stage 2 (attestation mock): see entries below and TODO ticks.

**Next session starts at:** Stage 3 (crypto: identities, HPKE envelopes,
E2E channel) per `TODO.md`.

---

## Session 2 — 2026-11-04 — Wasmtime pivot (Stage 1b)

**Goal:** evaluate Lua → WASM pivot with measured data; execute it while the
sunk cost was still small (post-Stage 1, pre-Stage 2).

**Decisions & evidence:**
- Pivot approved after measurements: minimal Wasmtime embed = 7.9 MB release /
  107 deps; Lua runner was 1.35 MB; fuel loop-trap probe confirmed
  *uncatchable* limits. Final release runner with Wasmtime = **10.1 MB**.
- Wasmtime pinned at v50 (`wasmtime` workspace dep: `cranelift`, `runtime`
  only; no `wat` in production builds; `wat` is a dev-dependency for fixtures).

**Delivered:** `engine.rs` replaces `sandbox.rs`; `tee-guest` crate (ABI +
typed host wrappers + native mock + 3 example services); CLI on `.wasm`;
`rust-toolchain.toml` now pins the `wasm32-unknown-unknown` target;
`scripts/build-guest-examples.sh`; 34 tests green.

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

## Session 1 — 2026-11-03/04 — project start: Stage 0 + Stage 1 (Lua)

**Goal:** bootstrap and build the runner core first (user's milestone order).

**Decisions:** Rust (rustup stable pinned), blind-gatekeeper envelope model
(TEE never sees plaintext), script hash + capability manifest in attestation,
standalone `tpass` CLI (later), vertical slice deferred.

**Delivered (commit `604caf5`):** Cargo workspace (7 crates), CI
(fmt/clippy `-D warnings`/test), Lua 5.4 sandbox via mlua (vendored), `@capability`
manifest with hard errors, script measurement, per-request CPU/memory budget
with the **stride-1 hook re-arm trick** (so `pcall` cannot swallow limit
errors — test-proven), `tee-runner measure|run|serve` (length-prefixed JSON
frames), 25 tests.

**Environment facts:** rustc/cargo **1.99.1** (pinned), rustup 1.29.3,
QEMU 10.0.13, Docker 29.9.2, gcc 14, **no nitro-cli yet**, host Go 1.26.3
(never used), system Lua 5.2/LuaJIT present but unused (historical).

**Handoff to session 2:** Lua runner green; pivot considered — see Session 2.
