# Test fixtures (Stage 7)

- `nitro-attestation.cose` — a genuine NSM-signed attestation document
  (COSE_Sign1, ES384) captured from a live Nitro enclave, used with the
  `nitro_attest` crate's test data (aws-nitro-enclaves/nitro-attest,
  MIT). Its CA certificates were valid in January 2025; tests verify it at
  its own timestamp (`verify_at`) and pin expiry behavior separately.
- `aws-nitro-root.pem` — the AWS Nitro Enclaves Root G1 certificate from
  `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`
  (published by AWS for relying parties; fingerprint
  `64:1A:03:21:…:8F:79:BB:5B`). Used to pin the compiled-in fingerprint in
  `src/nitro.rs`.

Both files are test data only — never loaded by production code paths
(the pinned fingerprint is a constant in `src/nitro.rs`).
