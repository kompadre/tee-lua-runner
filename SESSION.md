# SESSION.md — workbench & handoff log

Newest session first. Read `AGENTS.md` (policy) and `TODO.md` (queue) first.

Role in the task flow: the **current task's detail lives here** (evicted from
`TODO.md` when the task starts) and is **evicted into `CHANGELOG.md` when the
task completes**, leaving a compact outcome line. Finished sessions remain as
chronology and gotchas.

---

## Session 8 — 2026-11-04 — Stage 7 (EIF pipeline: container → nitro-cli → measurements) [completed → CHANGELOG]

**Stage context:** Stage 7 — EIF pipeline: container → `nitro-cli build-enclave`
→ measurements manifest, CI artifact, EC2 runbook. Instruction 0 armed.

**Empirical findings (recorded as they landed):**
- **TEE_KEY is measurement-bound**: two builds differing only in `TEE_KEY`
  produce different PCR0 **and** PCR2 (docker ENV → image config + rootfs);
  PCR1 = kernel+cmdline only (identical to the AWS hello example). The
  envelope key cannot be swapped without changing the pinned PCRs.
- **PCR reproducibility**: repeated full rebuilds with the same `TEE_KEY`
  yield byte-identical PCR0/1/2 — **with or without** `SOURCE_DATE_EPOCH`
  (BuildKit zeroes layer mtimes for our COPY-only Dockerfile; SDE is kept
  as belt-and-braces). Different `TEE_KEY` → different PCRs (key binding).
  The .eif file itself differs in ~24 bytes run-to-run (a header timestamp
  outside PCR coverage) → **pin PCRs, not eif_sha256**; the sha256 in the
  manifest is that artifact's identity, not a rebuild expectation.
  (First determinism test was confounded by differing TEE_KEYs — corrected
  by the nosde1/nosde2 same-key control.)
- **Nitro kernel**: `CONFIG_VSOCKETS=y` (builtin, no modules — unlike the
  QEMU init), **no RTC** (`CONFIG_RTC_CLASS is not set`) + KVM paravirt
  clock → enclave time is hypervisor-sourced (see Q1' below).
- `nitro-cli build-enclave` runs fully rootless with three env vars
  (`NITRO_CLI_BLOBS`, `NITRO_CLI_LOGS_PATH`, `NITRO_CLI_ARTIFACTS`).

**Environment facts (verified this session):**
- **`nitro-cli 1.5.2` installed user-locally** via
  `cargo install aws-nitro-enclaves-cli` (no root needed); blobs from the
  pinned `aws/aws-nitro-enclaves-cli` git clone (contains `blobs/x86_64/`:
  bzImage 4.14-based Nitro kernel, init, nsm.ko, linuxkit, cmdline).
  Three env vars make it root-free: `NITRO_CLI_BLOBS=<clone>/blobs/x86_64`,
  `NITRO_CLI_LOGS_PATH=<writable dir>` (default `/var/log/nitro_enclaves`
  → E19 without root), `NITRO_CLI_ARTIFACTS` (default `~/.nitro_cli`).
- **`nitro-cli build-enclave` validated live** on the official hello
  example → real PCR0/1/2 (SHA-512/384) printed. `build-enclave` runs on
  any Linux + Docker; only `run-enclave` needs the `nitro_enclaves`
  driver/allocator → **EC2 runbook scope** (host has no root).
- Docker 29.9.2 (user in `docker` group), `jq`, `musl-gcc`,
  `x86_64-unknown-linux-musl` rustup target added (pinned toolchain
  unchanged — target add is not a toolchain bump).
- Nitro `blobs/init` (PID 1 in the enclave) mounts proc/sys/dev, inserts
  `nsm.ko`, opens `/dev/nsm` — our container image only needs a CMD; the
  kernel cmdline is fixed by the blob (`reboot=k panic=30 pci=off
  nomodules console=ttyS0 …`) → **no kernel-cmdline config channel like
  QEMU's** — config must arrive another way (image ENV/CMD or generated).
- Host has `aws` CLI at /usr/local/bin (credentials/region unverified —
  EC2 validation only if the user opts in; costs money).

**Current task: Stage 7** (evicted from TODO on start, incl. carried questions):

Breakdown:
- [ ] **Environment**: install `nitro-cli` (AWS Nitro Enclaves CLI — apt/rpm,
      no root? decision point) + confirm Docker usable for EIF building;
      record versions. If local installation is impossible without root,
      decide what is scriptable/validatable offline vs. documented-only.
- [ ] **Container**: `deploy/nitro/` — Dockerfile that packs the guest
      (static-busybox base + release/stripped `tee-runner` + glibc libs +
      `throttle.wasm` + `/init` reused from the QEMU harness where possible;
      vsock module loading NOT needed — Nitro's kernel provides vsock
      natively) → image that `nitro-cli build-enclave` consumes.
- [ ] **Build pipeline**: script/`just` recipe: container → `nitro-cli
      build-enclave` → EIF + measurements output (PCR0/PCR1/PCR2, module
      measurements); guardrails: release build only, pinned toolchain
      (invariant 6: no ad-hoc measurement pinning).
- [ ] **Measurements manifest**: where PCR values live — release manifest
      file (e.g. `deploy/nitro/measurements.json` or per-tag manifest) with
      provenance (EIF digest, toolchain, git tag); format + update flow.
- [ ] **Real NSM backend**: `tee-attest` — `/dev/nsm` ioctl backend
      (behind the same `Attestor` trait; the Stage 6 `NsmRequest`/`NsmResponse`
      fields map onto `aws-nitro-enclaves-nsm-api`'s operation) + `serve
      --nsm /dev/nsm` support; document-format swap: Nitro attestation
      document (COSE_Sign1 with AWS cert chain) behind `verify()` with an
      AWS trust root — keep mock path working for tests.
- [ ] **Both-keys decision** (evicted question below): resolve with the
      real document format in hand.
- [ ] **CI artifact**: workflow job that builds the EIF (or validates
      measurements) and publishes artifacts — decide scope given CI has no
      KVM/nitro kernel module; keep CI green everywhere.
- [ ] **EC2 runbook**: docs for real deployment — instance setup, module
      load, `nitro-cli run-enclave`, vsock port mapping (enclave CID,
      parent VM), tpass connection flow, **real-Nitro JIT check** (last
      empirical unknown), attested-time observation (Q1′).
- [ ] **Completion**: gates → evict to CHANGELOG, tick TODO, README status,
      commit.

**Open questions evicted from TODO (addressed here):**
- **Q1′ — attested time (rolling window).** v1 = host time + monotonic
  floor; a host clock jump *forward* expires throttle windows early. The
  NSM document carries a `timestamp` — with the real hardware NSM it becomes
  trustworthy. Decide at Stage 7: adopt attested timestamp (with which
  fallback semantics?) or explicitly defer to Stage 8 with rationale.
  *Thorniest correctness issue in the throttle design.*
- **Both enclave keys in one attestation.** Stage 6 confirmed the NSM ABI
  has a single `public_key` slot (ours and Nitro's alike). Options: (a)
  bind envelope key via `user_data` composition, (b) reuse one keypair with
  strict domain separation, (c) signed key list in the document. Decide
  when the real document format is in hand; tee-pk stays config-pinned
  until then.
- **JIT check (carried from Stage 6):** empirical PASS under QEMU; the
  remaining caveat is the real Nitro kernel → verify during EC2 runbook
  validation.

**Decisions (Stage 7):**
- **Both-keys (evicted question resolved)**: option (a) — the NSM's single
  `public_key` slot keeps the per-boot **channel key**; the envelope key
  rides `user_data = measurement ‖ tee_pk` (64 bytes, NSM limit 512).
  Chosen over (b) reuse-one-keypair: the channel key must stay host-secret
  (generated per-boot inside the enclave) while the v1 envelope key *is*
  host-provisioned — merging would hand the host the channel key. (c)
  signed key-list: no advantage over composition for two keys.
  Consequences: engine composes; verifier matches a prefix with a length
  bound (`Expectations::with_user_data`); client extracts via
  `payload.tee_pk()`; `attest --save` adopts the attested key when
  unconfigured; `attested_session` **cross-checks** it against the config
  pin (mismatch → refuse).
- **Real-doc verification dependencies**: hand-rolled with `x509-parser`
  (parse only) + `p384` — **pure Rust, zero C codegen** (user decision: no
  `ring`). `aws-nitro-enclaves-nsm-api` only for the enclave-side
  `/dev/nsm` ioctl. `TrustRoot` gained a `Nitro` variant; `--root
  aws-nitro` keyword; dispatch by document alg (ES384 vs EdDSA).
- **Q1′ (attested time — evicted question resolved)**: **defer adoption,
  with evidence.** The Nitro blob kernel has no RTC
  (`CONFIG_RTC_CLASS is not set`) and uses KVM paravirt time → enclave
  clock is hypervisor-sourced, so the parent-VM clock-jump threat that
  motivated Q1′ does not transfer from QEMU to Nitro. v1 monotonic-floor
  stays; RUNBOOK §4 defines the empirical EC2 check (doc timestamp vs
  parent clock across a forced `date -s`) and the fallback design if it
  fails.
- **PCR0 pinning**: new `Expectations::with_pcr0` + `tpass attest --pcr0`
  + config `pcr0_hex`. Rationale: `user_data` (module measurement) is
  *self-reported by the runner* — a tampered runner could lie; PCR0 is
  the hardware anchor over runner + key + module. Manifest is its source.
  `tee-runner verify --pcr0` for manual checks.
- **Reproducibility**: pin **PCRs** (stable across rebuilds given the same
  `TEE_KEY`), never `eif_sha256` (a build timestamp outside PCR coverage
  leaves a ~24-byte run-to-run delta).
- **Scope**: EC2 runbook written, **not executed** (user decision);
  `nitro-cli` 1.5.2 installed user-locally via cargo, rootless via three
  env-var overrides.

**Validated this session (all live):**
1. `nitro-cli build-enclave` on the official hello example (real PCRs).
2. Full `just eif` → EIF + manifest (PCR0-2, module measurement, envelope
   key); repeated rebuilds → identical PCRs.
3. TEE_KEY ↔ PCR0/PCR2 binding (different key → different PCRs; same key →
   identical): key tamper breaks the manifest pin.
4. Real Nitro fixture verification: chain to pinned AWS root, ES384,
   expectations, expiry-at-current-time, tamper rejection (7 tests).
5. Container image: static runner boots in busybox-musl; full tpass
   round-trip (init → attest → insert → show → audit) against it;
   `--pcr0` accept/reject; in-container module measurement == manifest.
6. `just qemu-demo` still green after the both-keys change (regression).
7. Gates: fmt + clippy `-D warnings` + **28 suites** + both guest gates.

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

**Next session starts at:** Stage 8 (Hardening backlog: fuzzing, sealed
state (Q2′), quotas, attested logs, benchmarks — plus executing
`deploy/nitro/RUNBOOK.md` on EC2 when opted in).

---

## Session 7 — 2026-11-04 — Stage 6 (QEMU local enclave environment) [completed → CHANGELOG]

**Stage context:** Stage 6 — QEMU local enclave: vsock transports, NSM
stand-in (same NSM API, two backends), rootfs. Instruction 0 armed
(untouched: no new cargo gate — QEMU validation is `just qemu-demo`, not CI).

**Environment facts (verified this session):**
- `/dev/kvm` + `/dev/vhost-vsock` present and readable; user `alex` is in
  the `kvm` group → **no root/sudo needed** (sudo requires a password).
- Running kernel `6.12.113+deb13-amd64` with matching modules:
  `vsock.ko.xz`, `vmw_vsock_virtio_transport{,_common}.ko.xz`
  (`.xz` → decompress into initramfs with `xz -d`); **virtio core
  (ring/pci) is builtin** (=y) in the Debian kernel.
- `cpio`, host `busybox` (dynamic → use **docker busybox image, static**),
  `docker`, `xz`; boot the RUNNING kernel with its own module dir (vermagic).

**Outcome:** shipped and **validated live** (commit below):
- `tee-proto::transport` — `HOST:PORT` / `vsock:CID:PORT` (dial) /
  `vsock:PORT` (listen) + `Stream`/`Listener` enums with full parity
  (incl. timeouts); native-only (cfg + target-gated so guests still build).
- `tee-attest`: `NsmRequest`/`NsmResponse` NSM-operation ABI mirror (Stage 7
  = same fields over `/dev/nsm` ioctl) + `NsmRemoteAttestor` (per-request
  dial, `public_key` request field binds the channel key like real NSM).
- `tee-runner nsm-standin` — host "firmware": stable root from seed,
  per-request public_key via fresh-from-seed `MockAttestor`, survives bad
  requests with error responses (test-pinned).
- `tee-runner serve --nsm <addr>` — remote attestation backend (mutually
  exclusive with `--mock-attest`); tpass `--server` accepts vsock.
- `deploy/qemu/` — `init` (console re-attach, ordered module loads, kernel
  cmdline config), `build-rootfs.sh` (docker-busybox base, release+stripped
  runner, ldd libs, un-xz'd modules, cpio), `run.sh` (KVM, TCG fallback,
  `-device vhost-vsock-pci,guest-cid=3`), `e2e.sh` (full validation),
  `just qemu-build|qemu-run|qemu-demo`.
- **`just qemu-demo` PASSED**: guest booted in KVM, served over vsock
  (CID3), attestation signed by the host stand-in over vsock (CID2),
  tpass init → attest (TOFU pin == console measurement; channel key bound)
  → insert → **show recovered the secret through the guest** → audit ring
  shows `fetch ok`. **JIT empirical check: PASS** (Cranelift JIT works in
  the guest — `pulley` fallback unnecessary here; real-Nitro kernel still
  checked at Stage 7/EC2).

**Debug trail worth remembering (became gotchas 12–15):**
debug-binary initramfs bloat, vanished PID-1 output, serial CRLF, module
load ordering — see gotchas below.

**Decisions/limits:**
- QEMU validation is a `just` recipe, **not** a CI gate (needs KVM +
  vhost-vsock): no AGENTS gates change (Instruction 0 untouched).
- Stand-in speaks our NSM-operation JSON over the shared framing codec;
  Stage 7 swaps transport (ioctl) + document format (Nitro) behind the same
  request/response field set.
- Carry-forwards unchanged: both-keys slot + attested time → Stage 7 (the
  single `public_key` slot limitation was re-confirmed by the stand-in ABI).

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

**Next session starts at:** Stage 7 (EIF pipeline: container →
`nitro-cli build-enclave` → measurements manifest, CI artifact, EC2
runbook) — breakdown and remaining open questions (Q1′ attested time,
both-keys attestation slot, real JIT check) evicted from `TODO.md` when
started.

---

## Session 6 — 2026-11-04 — Stage 5 (`tpass` client CLI) [completed → CHANGELOG]

**Stage context:** Stage 5 — the `tpass` client CLI. Instruction 0 armed
(untouched this session: the gates list needed no change — client tests ride
gate 3 `cargo test --workspace`).

**Outcome:** `tpass` shipped (commit below) — the full client half of the
system: sealed keystore (Argon2id), config pins, the attestation-bootstrap
session (plaintext challenge → verified channel key → channel-wrapped
requests), and commands `init / attest / generate / insert / show / list /
rm / revoke / audit`. First-run system e2e through real processes: init →
attest with TOFU pin (+ wrong-measurement rejection) → insert sealed-at-rest
→ show recovering plaintext through the gate → wrong-passphrase fails before
network → generate/list → audit without secrets → revoke → `[blacklisted]`
refusal → rm → plaintext-fetch refused in channel mode. `just gates` all
green (26 suites). Detail evicted to CHANGELOG `[Unreleased]`.

**Decisions:**
- **Keystore format → `TPASSKEY1 ‖ m,t,p (3×u32 LE) ‖ salt(16) ‖
  nonce(12) ‖ sealed(80)`**: key = Argon2id(passphrase, salt, params) with
  params recorded in-file (old keystores stay unlockable after default
  changes); payload = `LocalIdentity::to_seed()` sealed with
  ChaCha20Poly1305 (AAD-bound to the magic). `Zeroizing` throughout; the
  public half lives beside it (`public.json`) so **insert/generate need no
  passphrase** — only show/revoke unlock the secret half.
- Session bootstrap = plaintext `op:"attest"` challenge (freshness nonce;
  root + optional pinned measurement enforced) — the only plaintext op
  accepted in channel mode; channel mode *discovered* from the verified
  document's `public_key` and persisted by `attest --save`.
- Config pins: `server`, `root_hex`, `measurement_hex` (TOFU on first
  attest), `tee_pk_hex` (envelope key — carried in config until Stage 6's
  both-keys-in-one-attestation question), `channel` flag.
- Scope additions (flagged per flow): `tpass revoke` (otherwise the Stage 4
  blacklist is unreachable from the client) and `tpass audit` (read side of
  the audit ring).
- New deps (client-only, small/standard): `argon2`, `rpassword`.

**Gotcha added this session:**
11. `Zeroizing<T>` does not coerce through to `&[u8]`-typed parameters —
    call `.as_bytes()` / `&*value` explicitly at API boundaries.

**Next session starts at:** Stage 6 (QEMU local enclave environment: vsock,
NSM stand-in with the same NSM API, rootfs) — breakdown and open questions
(Q1′ attested time, both-keys attestation, JIT empirical check) evicted from
`TODO.md` when started.

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
