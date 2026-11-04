# Enclave container image for `nitro-cli build-enclave` (Stage 7).
#
# Build context is assembled by `deploy/nitro/build-eif.sh` (gitignored
# staging inside `deploy/nitro/build/`): it copies the musl-static
# `tee-runner`, `throttle.wasm`, and this Dockerfile there before invoking
# `nitro-cli build-enclave --docker-dir`.
#
# Config channel: Docker ENV → the Nitro init reads the image's `/env` and
# passes it to PID 1's environment (there is no kernel-cmdline channel on
# Nitro, unlike the QEMU harness).
#
# TEE_KEY is a *build-time* secret: it lands inside the measured image
# (binds into PCR values, manifest records the public half only). Host-
# provisioned in v1 — same trust posture as QEMU's kernel cmdline — see
# RUNBOOK.md §Threat model.

FROM busybox:stable-musl

COPY tee-runner /usr/local/bin/tee-runner
COPY throttle.wasm /enclave/throttle.wasm

# Envelope-unwrap secret (hex, 32 bytes). Required: build-eif.sh refuses to
# build without it; an empty value makes `tee-runner` fail fast.
ARG TEE_KEY
ENV TEE_KEY=${TEE_KEY}
# Consumed by BuildKit for reproducible layer timestamps (see build-eif.sh).
ARG SOURCE_DATE_EPOCH
# Enclave-side vsock listen port (parent dials <enclave-cid>:<port>).
ENV LISTEN_PORT=5555

# sh -c expands ${LISTEN_PORT}; init execs this argv with the image ENV.
CMD ["/bin/sh", "-c", "exec /usr/local/bin/tee-runner serve /enclave/throttle.wasm --listen vsock:${LISTEN_PORT} --tee-key \"$TEE_KEY\" --channel --nsm /dev/nsm"]
