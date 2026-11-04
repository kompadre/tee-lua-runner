# EC2 Nitro Enclaves runbook (Stage 7)

End-to-end procedure for running `tee-lua-runner`'s throttle service as a
**real AWS Nitro Enclave** and driving it with `tpass`. Written against
`nitro-cli 1.5.2`; validated locally up to the EIF (see §Validation
status), **not executed on EC2** — the EC2 steps below are the checked
procedure for the first real-hardware run.

Two phases, two machines:

```
[build machine: any Linux + docker + nitro-cli]        [EC2 parent instance]
  build-eif.sh → tee-runner.eif + manifest   ──copy──▶  nitro-cli run-enclave
                                                          │  enclave CID N
  tpass (anywhere that reaches the parent)  ──vsock──────▶│  serve: vsock:5555
```

## Prerequisites

- **Build machine** (or CI): Linux, docker, rustup (pinned toolchain from
  `rust-toolchain.toml`), and the Nitro CLI:

  ```sh
  cargo install aws-nitro-enclaves-cli --locked
  ```

  The CLI needs its blobs (enclave kernel/init/NSM module); `build-eif.sh`
  clones `aws/aws-nitro-enclaves-cli` into
  `~/.cache/tee-lua-runner/…` on first run, or set `NITRO_CLI_BLOBS` to an
  existing install. **No root required** — the script sets
  `NITRO_CLI_BLOBS`, `NITRO_CLI_LOGS_PATH`, `NITRO_CLI_ARTIFACTS`
  itself (the defaults `/usr/share/nitro_enclaves/…` and
  `/var/log/nitro_enclaves/…` need root and fail with `E19`).

- **EC2 parent instance**: an instance type that supports Nitro Enclaves
  (any `m5`, `c5`, `i3`, `r5`, … >= 2 vCPUs — **not** burstable `t3`, not
  bare metal, not 1-vCPU), launched with enclave option enabled:

  ```sh
  aws ec2 run-instances \
      --instance-type m5.xlarge \
      --image-id <amazon-linux-2023 ami> \
      --enclave-options Enabled=true \
      --key-name <your-key> \
      --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=tee-runner-parent}]'
  ```

  On the parent: install the CLI (AL2023: `sudo dnf install
  aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y`), add your user
  to `docker` and `ne` groups (re-login), preallocate resources:

  ```sh
  # /etc/nitro_enclaves/allocator.yaml → cpu_count: 2, memory_mib: 1600
  sudo systemctl enable --now nitro-enclaves-allocator
  sudo systemctl enable --now docker
  ```

## 1. Build the EIF (build machine)

```sh
TEE_KEY=$(head -c32 /dev/urandom | xxd -p -c64)   # save it! see Threat model
just eif "$TEE_KEY"
```

Outputs in `deploy/nitro/build/`:

| file | purpose |
|---|---|
| `tee-runner.eif` | enclave image (copy to the parent) |
| `tee-runner.manifest.json` | PCR0-2, module measurement, `tee_pk` |

The manifest is the client's trust input: `tpass attest --pcr0
<PCR0 from manifest>` pins the enclave image at the hardware level.

### Threat model notes (v1)

- **`TEE_KEY` is host-provisioned** (baked into the image ENV): the parent
  operator knows the envelope-unwrap secret. Same posture as the QEMU
  harness (kernel cmdline) — the blind-gatekeeper property that survives is
  *plaintext never enters the TEE* (inner layer stays sealed to the
  client's local key); outer-layer confidentiality against the host does
  **not**. Empirically, the key is measurement-bound: it sits in the docker
  ENV, so changing it changes PCR0 **and** PCR2 — a tampered key breaks the
  manifest pin. Generating the key inside the enclave (so the host never
  sees it) needs sealed persistence across restarts → Stage 8.
- **Pin PCRs, not `eif_sha256`**: PCRs are reproducible across rebuilds
  with the same `TEE_KEY`; the `.eif` file bytes carry a build timestamp
  outside PCR coverage, so the recorded sha256 identifies *that* artifact
  only.

## 2. Run the enclave (parent instance)

```sh
scp tee-runner.eif parent:/tmp/
ssh parent
nitro-cli run-enclave \
    --eif-path /tmp/tee-runner.eif \
    --cpu-count 2 \
    --memory 1600 \
    --enclave-cid 16 \
    --debug-mode        # first run only: enables `nitro-cli console`
nitro-cli describe-enclaves          # state: RUNNING, EnclaveCID: 16
```

The enclave boots the container CMD: `tee-runner serve … --listen
vsock:5555 --channel --nsm /dev/nsm`. Inside the enclave `/dev/nsm` is the
real Nitro Secure Module (the Nitro init inserts `nsm.ko` before PID 1) —
documents are genuine Nitro attestation documents signed by the AWS
Nitro Attestation PKI.

Confirm startup on the enclave console (state is only observable this way
while `--debug-mode` is on):

```sh
nitro-cli console --enclave-id "$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
# expect:
#   tee-pk: <hex>                 (== manifest envelope_key.tee_pk)
#   channel-pk: <hex>
#   module measurement: <hex>     (== manifest module.measurement)
#   listening on vsock:…:5555
```

**JIT check (empirical, real Nitro kernel):** if `listening on vsock:…`
appears, Cranelift JIT works inside the real enclave (QEMU already
confirmed it under `CONFIG_KVM_GUEST`; the Nitro kernel blob is also a KVM
guest). If the enclave dies before `listening`, capture the console and
fall back to building `tee-runner` with Wasmtime's `pulley` interpreter —
that is the only known contingency.

## 3. Drive it with tpass (from any machine that reaches the parent vsock)

`tpass` speaks vsock directly to the enclave CID. From the **parent
instance** (vsock to an enclave CID only works from the parent):

```sh
tpass --store ~/.tpass init \
    --server vsock:16:5555 \
    --tee-pk "$(jq -r .envelope_key.tee_pk tee-runner.manifest.json)"

tpass --store ~/.tpass attest \
    --root aws-nitro \
    --pcr0 "$(jq -r .measurements.PCR0 tee-runner.manifest.json)" \
    --save
```

`--root aws-nitro` selects the pinned AWS Nitro Enclaves Root G1
(fingerprint `64:1A:03:21:…:8F:79:BB:5B`, compiled into the verifier — no
out-of-band root exchange). The document's certificate chain, ES384
signature, freshness nonce, module measurement, PCR0, and the attested
envelope key are all checked; `--save` then pins them for later sessions.

Expected verification output includes `algorithm: ES384` and
`envelope key: <hex>` (must equal the manifest value — if it differs, the
EIF is not the one you built; stop).

```sh
echo 's3cr3t' | tpass --store ~/.tpass insert entry1
tpass --store ~/.tpass show entry1        # prints s3cr3t
tpass --store ~/.tpass audit              # guest-side decisions
```

Throttling runs inside the enclave (rolling window, blacklist, PoP) —
hammer `show` 6× within 60 s to see `server refused [throttled]` with a
`retry_after_ms` hint.

Terminate when done:

```sh
nitro-cli terminate-enclave --enclave-id <id>
```

## 4. Attested time (Q1′ — observed, not adopted)

The Nitro kernel blob has **no RTC** (`CONFIG_RTC_CLASS is not set`) and
uses the KVM paravirt clock: enclave wall-clock time is
hypervisor-sourced, *not* the parent VM's — so the v1 threat "parent jumps
its clock to expire throttle windows early" does **not** transfer from
QEMU (where the guest trusts host-provided time) to Nitro the same way.
The NSM document also carries a hypervisor `timestamp`.

**Validation step for the first EC2 run:** compare the attested
`timestamp` in the document (`tpass attest` prints it) against
`date -u +%s` on the parent at the same moment, and repeat after
`sudo date -s +2h` on the parent (if you have permission): if the enclave
document timestamp does not follow the parent's jump, the architecture
argument holds and the v1 monotonic-floor clock stays as-is. If it *does*
follow, adopt the attested timestamp as the throttle clock anchor (design
sketch: `max(host_time, attested_ts)` seeded from every `tpass attest`,
carried in guest state) — decide then, record in CHANGELOG.

## 5. Known limitations carried from earlier stages

- **Sealed blacklist/buckets (Q2′)**: restart resets throttle state —
  `run-enclave` restarts wipe it. Stage 8.
- **Single attested key slot**: the NSM `public_key` slot carries the
  per-boot channel key; the envelope key rides `user_data`
  (`measurement ‖ tee_pk`, both-keys decision recorded in Session 8).
- **CI artifact**: `.github/workflows/eif.yml` builds the EIF on
  manual dispatch / `v*` tags / pipeline-path pushes and uploads it with
  its manifest. CI uses the demo `TEE_KEY` (stable PCRs) unless the
  `TEE_KEY` secret is set — production images must be built with your own
  key (`just eif`).
