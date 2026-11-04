# AGENTS.md — how to work in this repository

Guidance for AI agents (and humans) contributing to **tee-lua-runner**.
Policy and conventions live here; state lives elsewhere (see Task flow).

## What this project is

A minimal, attestable **WebAssembly runner** (Wasmtime) for TEE platforms,
targeting AWS Nitro Enclaves, plus a pass-like password-store workload with
external throttling. The TEE is a **blind gatekeeper**: it must never see
plaintext passwords and never persist request contents. Service logic ships
as wasm guest modules whose bytes + capability manifest are bound into
attestation documents.

Read `README.md` for architecture; `docs` are linked there.

## Task flow (which doc when)

| Doc | Role | When to update |
|-----|------|----------------|
| `AGENTS.md` | Stable policy/conventions (this file) | Rarely; only when conventions actually change |
| `TODO.md` | Task board: stages, open questions, backlog | When picking up/finishing/adding tasks |
| `SESSION.md` | Rolling handoff log: last session's outcome, current state, gotchas | At the end of every working session |
| `CHANGELOG.md` | User-visible history (`Keep a Changelog`, `[Unreleased]`) | Whenever behavior/APIs/structure change |
| `README.md` | Human-facing overview | When architecture or workflows change |

**Loop:** read this file → take the next task from `TODO.md` → implement →
1. tick/annotate the task in `TODO.md` (promote open questions if discovered),
2. append a dated entry to `SESSION.md` (what changed, what to watch, next step),
3. add a `CHANGELOG.md` entry under `[Unreleased]` if user-visible,
4. run the gates (below) — all green — then commit.

Commit message style: `Area: concise summary` or `Stage N: …` with a body
explaining *why*, referencing issue-worthy facts (measured numbers, discoveries).

## Environment & commands

- Toolchain is **pinned** in `rust-toolchain.toml` (rustc 1.99.1 + the
  `wasm32-unknown-unknown` target). Do **not** bump it casually: toolchain
  pins feed reproducible guest artifacts and (Stage 7) stable PCR values.
  `rustup` manages everything; system `lua`/`luajit`/`go` on the box are not used.
- Docker and QEMU are available for Stage 6/7 work; `nitro-cli` is not yet
  installed (Stage 7).

```sh
cargo fmt --all -- --check                       # gate 1
cargo clippy --workspace --all-targets -- -D warnings   # gate 2
cargo test --workspace                            # gate 3
cargo test -p tee-guest --features svc-counter    # gate 4 (guest services)
./scripts/build-guest-examples.sh                 # build example *.wasm
cargo run -p runner-cli -- measure scripts/examples/counter.wasm
```

## Architecture invariants (do not break)

1. **Measure before trust.** `measurement = SHA-256(domain ‖ module bytes ‖
   canonical manifest)`. Never measure anything but the exact bytes that
   execute. Domain tags live in `runner-core::measure`; changing them is a
   breaking change (CHANGELOG + all pinned measurements).
2. **No WASI, ever.** Guests get zero ambient authority beyond explicitly
   linked capability imports. Adding an import module means: `HOST_IMPORTS`
   table, host handler, guest wrapper, tests — in that order.
3. **Honest manifests.** Guest host-call wrappers must reference *only their
   own import* (no central dispatch tables) so `wasm-ld --gc-sections` drops
   unused imports. A capability listed but unused = bug.
4. **Never hold the host ctx lock across a call into guest code** (guest
   `alloc` can re-enter host imports; `std::sync::Mutex` is not reentrant).
   See `engine.rs` module docs.
5. **Budgets are engine-enforced**: fuel + epoch + `StoreLimits`. Do not
   reintroduce guest-catchable limit mechanisms. `wat` must never be enabled
   for production builds (binary wasm only).
6. **Guest artifacts embed panic-location strings** → artifact bytes depend on
   guest source line numbers. Pin artifact measurements only from tagged
   sources (Stage 7 manifests), never from ad-hoc builds in tests.
7. **Blind gatekeeper**: Stage 3+ crypto must keep plaintext out of the TEE;
   envelope checks happen on ciphertext only. Never log secrets (keys,
   nonces beyond policy, payload contents).

## Code conventions

- Edition 2021, shared deps via `[workspace.dependencies]`.
- `unwrap()` only in tests; production paths return typed errors
  (`RunnerError`, `VerifyError`, `AttestError`, `anyhow` at CLI edge only).
- Tests: unit tests in-module (`#[cfg(test)]`), integration tests as
  `tests/*.rs`, wasm fixtures as inline `wat` strings (dev-only `wat` feature),
  golden values only where formatting-invariant (capability lines — not
  artifact hex; see invariant 6).
- Secrets in Rust: `zeroize` comes with Stage 3; until then keep secret-bearing
  values short-lived and avoid `Debug` on key material.

## Guardrails

- Do not commit guest `*.wasm` build outputs (gitignored), `target/`, or
  toolchain upgrades without an explicit decision.
- Do not weaken CI gates or disable clippy lints to get green; fix the code.
- Ask before: renaming the repo, changing the license posture, bumping the
  pinned toolchain, adding heavyweight dependencies to `runner-core` or
  `tee-attest`.
