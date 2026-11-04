# SESSION.md — workbench & handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (queue) first.

Role in the task flow: the **current task's detail lives here** (evicted from
`TODO.md` when the task starts) and is **evicted into `CHANGELOG.md` when the
task completes**, leaving a compact outcome line. Finished sessions remain as
chronology and gotchas.

Compaction note (2026-11-04, after Stage 7): finished sessions were compacted
to outcome + environment facts + gotchas; every feature-level detail and
decision lives in `CHANGELOG.md`, stage state in `TODO.md`, policy in
`AGENTS.md`.

---

## Session 8 — 2026-11-04 — Stage 7 (EIF pipeline: container → nitro-cli → measurements) [completed → CHANGELOG, commit 5789182]

**Outcome:** shipped and validated — real Nitro document verification
(pinned AWS root fingerprint, ES384, chain + validity + tamper rejection;
hand-rolled `x509-parser`+`p384`, pure Rust, user decision: no `ring`),
`/dev/nsm` device backend (`NsmDeviceAttestor`, `serve --nsm` dual-mode),
both-keys resolution, PCR0 pinning (`tpass attest --pcr0` + manifest),
container → `nitro-cli build-enclave` → measurements manifest
(`just eif`), CI EIF artifact workflow, EC2 runbook (**written, not
executed** — user decision). Gates: fmt + clippy + **28 suites** + guest
gates; `just qemu-demo` re-passed after the both-keys change; full tpass
round-trip against the built container image.

**Resolved (detail in CHANGELOG):**
- **Both-keys**: `user_data = measurement ‖ tee_pk`; channel key keeps the
  single `public_key` slot. Client adopts the attested envelope key and
  cross-checks the config pin (mismatch → refuse).
- **Q1′ (attested time): defer with evidence** — Nitro blob kernel has no
  RTC + KVM paravirt clock → parent-VM clock jumps don't reach the
  enclave; v1 monotonic floor stays. Empirical EC2 check + fallback design:
  `deploy/nitro/RUNBOOK.md` §4.
- **Pin PCRs, not `eif_sha256`**: PCRs rebuild-stable per `TEE_KEY` (key
  is measurement-bound: changes PCR0+PCR2); the .eif has an uncovered
  build timestamp (~24-byte delta).

**Durable environment facts:**
- `nitro-cli 1.5.2` user-local (`cargo install aws-nitro-enclaves-cli`);
  rootless via `NITRO_CLI_BLOBS` + `NITRO_CLI_LOGS_PATH` +
  `NITRO_CLI_ARTIFACTS` (defaults need root → E19). Blobs cloned by
  `build-eif.sh` into `~/.cache/tee-lua-runner/…`.
- Build tooling present: Docker 29.9.2 (user in `docker` group), `jq`,
  `musl-gcc`, rustup target `x86_64-unknown-linux-musl` (toolchain pin
  unchanged — target add ≠ toolchain bump).
- Host: no root (sudo needs a password), user in `kvm` + `docker` groups;
  `aws` CLI present but credentials/region unverified — EC2 validation
  only on explicit opt-in (costs money).

**Next session starts at:** Stage 8 (Hardening backlog: fuzzing, sealed
state (Q2′), quotas, attested logs, benchmarks — plus executing
`deploy/nitro/RUNBOOK.md` on EC2 when opted in).

**Gotchas added this session:**
16. Determinism experiments must control `TEE_KEY`: my first PCR-rebuild
    comparison used different keys and "proved" non-determinism that
    wasn't there (the docker ENV key is measured, so different key →
    different PCR0/2 by design). Same-key control runs are mandatory.
17. `docker logs … 2>&1 > file` sends stderr to the *terminal*, not the
    file (redirection order) — looked like missing console output. Use
    `> file 2>&1`.
18. The Nitro CLI fails with `E19` before doing anything unless
    `NITRO_CLI_LOGS_PATH` points outside `/var/log` on rootless hosts
    (`NITRO_CLI_BLOBS`, `NITRO_CLI_ARTIFACTS` likewise).
19. `--nsm` is dual-mode: a path (`/dev/nsm`) selects the device ioctl,
    an address selects the stand-in; absence of `/dev/nsm` must fail serve
    loudly (test: `serve_device_nsm_fails_loudly_without_dev_nsm`).

---

## Session 7 — 2026-11-04 — Stage 6 (QEMU local enclave environment) [completed → CHANGELOG, commit 694a538]

**Outcome:** TCP/vsock transports (`tee-proto::transport`), NSM-operation
ABI mirror + `NsmRemoteAttestor`, `tee-runner nsm-standin` daemon,
`serve --nsm <addr>`, `deploy/qemu/` harness + `just qemu-*` recipes.
**`just qemu-demo` PASSED live**: secret round-tripped through the KVM
guest over vsock with stand-in-signed attestation; **JIT empirical check
PASS** (pulley unnecessary under QEMU; real-Nitro check left to Stage 7's
runbook). QEMU validation = just recipe, **not** a CI gate (Instruction 0
untouched). Gates: 27 suites.

**Environment facts that mattered:** `/dev/kvm` + `/dev/vhost-vsock`
readable (kvm group, no root); running kernel `6.12.113+deb13-amd64` with
matching vsock modules (`.xz` → decompress), virtio core builtin; static
docker busybox as guest base.

**Gotchas added this session:**
12. Never pack debug binaries into an initramfs: the debug `tee-runner` was
    **214 MB** (debuginfo) → "Initramfs unpacking failed: write error" in a
    384 MB guest. Pack release + `strip` the copy (release default now).
13. Initramfs `/dev/console` may not exist when the kernel execs `rdinit` →
    PID 1 gets `/dev/null` fds and **all userspace output vanishes while
    kernel printks still appear** (extremely misleading). Re-attach with
    `exec >/dev/console` *after* mounting devtmpfs.
14. Serial console output is CRLF → `tr -d '\r'` when parsing console text
    in scripts (bit my `tee-pk`/measurement comparisons).
15. Module load order: alphabetical can't resolve deps (`…transport` sorts
    before `…transport_common`; `vsock` last) and there is no `modules.dep`
    in an initramfs (`insmod` only) → explicit dependency order + multiple
    generic retry passes.

---

## Session 6 — 2026-11-04 — Stage 5 (`tpass` client CLI) [completed → CHANGELOG, commit 78844da]

**Outcome:** `tpass` — sealed keystore (`TPASSKEY1` format: Argon2id with
in-file params + ChaCha20Poly1305 over `LocalIdentity::to_seed()`),
attestation-bootstrap session (plaintext nonce challenge → verified
channel key → channel-wrapped requests), commands init/attest/generate/
insert/show/list/rm/revoke/audit; first full-system e2e through real
processes. Gates: 26 suites.

**Tooling (user decision, commit 47a97d0):** `justfile` adopted as the
stable command facade (CI mirrors raw commands with sync comments);
`xtask` deferred with trigger "Rust logic in recipes" — **never triggered**:
Stage 7 manifests used `tee-runner measure` + `jq`, facade held.

**Gotcha added this session:**
11. `Zeroizing<T>` does not coerce through to `&[u8]`-typed parameters —
    call `.as_bytes()` / `&*value` explicitly at API boundaries.

---

## Session 5 — 2026-11-04 — Stage 4 (throttle & blacklist service) [completed → CHANGELOG, commit ef5c811]

**Outcome:** `gate.unwrap` + `crypto.ed25519_verify` host capabilities
(TEE secret stays host-side), `tee-proto` wire contract with byte-stable
PoP messages, `svc-throttle` (PoP → blacklist → rolling window → gate →
audit ring; policy constants inside the measured source; `throttle.wasm`
199 KB). Full CLI e2e over the channel incl. 6th-fetch throttle with
retry hint and revocation. Clock: `now = max(host_time, last_seen)`
(rollback fails closed → carried as Q1′); persistence: host in-memory
(→ Q2′, Stage 8). **First exercised use of Instruction 0**: the user's
literal gate-5 line applied verbatim (in `AGENTS.md`).

**Gotcha added this session:**
10. Native guest tests share `thread_local` mock state across the libtest
    worker pool (tests may run sequentially on one thread) → design tests
    with per-test unique keys and cap-invariant assertions instead of
    assuming fresh state.

---

## Session 4 — 2026-11-04 — Stage 3 (crypto) [completed → CHANGELOG, commit 96e12e9]

**Outcome:** `tee-crypto` — RFC 9180 HPKE (base + auth) pinned against
official A.2/A.2.3 vectors, blind-gatekeeper envelopes `E_TEE(E_local(…))`,
one-shot channel with attested server authentication (responses use
**auth mode**: sealing to the client's key authenticates nobody — found
while mapping the channel), `LocalIdentity` (Ed25519+X25519, zeroize,
PoP), `serve --channel` with the channel key bound into the attestation's
`public_key`. Exhaustive byte-tamper scans. Q3 → CBOR wire records (JSON
payloads carried); Q4 → RFC 9180 HPKE, no hand-rolled ECIES.

**Gotchas added this session:**
8. ciborium has **no `from_bytes`/`to_bytes`** — only `from_reader`/
   `into_writer` (hit twice now; see also gotcha 7 for the `&[u8]` array trap).
9. `Hmac::new_from_slice` is ambiguous once `chacha20poly1305::aead::KeyInit`
   is in scope — use `<Hmac<Sha256> as Mac>::new_from_slice`.

---

## Session 3 — 2026-11-04 — doc set + Stage 2 (attestation mock) [completed → CHANGELOG, commits ddfe357/dcc158e (docs), 29a98ad (stage), 6543b9a (audit)]

**Outcome:** task pipeline established (AGENTS/TODO/SESSION/CHANGELOG with
eviction at both transitions). Stage 2 shipped: COSE_Sign1 mock
attestation end-to-end — `MockAttestor`, payload schema mirroring Nitro
fields, `verify` + `TrustRoot`/`Expectations`, `tee-runner --mock-attest`
+ `verify`, `svc-attest`, PCR0 binding the runner binary.

**Policy events:** AGENTS gained **Instruction 0** (file is user-owned;
agents modify only on literal prescription of change + placement). The
user **suspends it only while documentation work is in progress** and it
re-arms for code stages (armed ever since). User decision on the doc-stack
audit: AGENTS implementation details **stay put while stable**.

**Gotcha added this session:**
7. serde serializes `&[u8]` as a **CBOR array of integers**, not a byte
   string — sign/parse stay self-consistent while silently producing
   non-COSE documents (roundtrip tests pass, external tools would reject).
   Build byte strings via `ciborium::Value::Bytes`; pin the literal shape in
   a test. (Discovered by eyeballing a hex dump, not by tests.)

---

## Session 2 — 2026-11-04 — Wasmtime pivot (Stage 1b) [completed → CHANGELOG, commit 6e4a92c]

**Outcome:** Lua → WASM pivot executed while sunk cost was small:
engine-enforced budgets (fuel/epoch/`StoreLimits`, uncatchable), manifests
derived from the import section, no WASI, `tee-guest` SDK + example
services. Release runner 10.1 MB. Measured first (minimal embed 7.9 MB /
107 deps); wasmtime pinned at v50 (`cranelift`+`runtime` only; `wat` never
in production builds).

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

## Session 1 — 2026-11-03/04 — project start: Stage 0 + Stage 1 (Lua) [completed → CHANGELOG, commit 604caf5]

**Outcome:** workspace + CI + pinned toolchain (rustc 1.99.1); the original
Lua 5.4 runner core (sandbox, capability manifest, measurement, budget
hooks) with 25 tests. Superseded by Session 2's pivot. Standing decisions:
Rust, blind-gatekeeper envelope model (TEE never sees plaintext), script
hash + capability manifest in attestation, standalone `tpass` CLI.
