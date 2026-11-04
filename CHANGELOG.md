# Changelog

Notable changes to this project, per `Keep a Changelog` conventions.
The project has not had a release yet; everything lives under `[Unreleased]`.

## [Unreleased]

### Added

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
  (`echo`, `counter`, `hasher` — one wasm artifact per service). *(6e4a92c)*
- **`tee-runner` CLI**: `measure` (capability manifest + measurement),
  `run` (single JSON request), `serve` (u32-length-prefixed JSON frames with
  in-band `{"ok":…}` envelopes). *(604caf5, evolved 6e4a92c)*
- `tee-attest` crate: `Attestor` trait + refusing `NullAttestor` (baseline
  for Stage 2 backends). *(604caf5)*
- Doc set: `AGENTS.md`, `TODO.md`, `SESSION.md`, `CHANGELOG.md` with the
  task-flow contract; README architecture overview.

### Changed

- **Script engine pivoted from Lua 5.4 to WebAssembly (Wasmtime 50)** after a
  measured evaluation: engine-enforced (uncatchable) limits replace hand-rolled
  hook enforcement, the hashed import section *is* the capability manifest,
  and guests gain zero ambient authority (no WASI). Guest modules are built
  from Rust via `wasm32-unknown-unknown`; example artifacts ~101 KB. *(6e4a92c)*
- Golden-test policy: tests pin formatting-invariant capability manifests;
  artifact hex is pinned only in release manifests (guest binaries embed
  panic-location strings, so bytes depend on guest source lines). *(6e4a92c)*

### Removed

- Lua embedding (mlua), `@capability` comment-manifest parser, hand-rolled
  budget hook machinery, and Lua example scripts — superseded by the Wasmtime
  engine. *(6e4a92c)*
