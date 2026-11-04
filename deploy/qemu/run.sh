#!/usr/bin/env bash
# Boots the QEMU enclave environment.
#
#   TEE_KEY=<hex32> NSM=vsock:2:<port> LISTEN=<port> ./deploy/qemu/run.sh
#
# Needs /dev/kvm and /dev/vhost-vsock readable (user in the `kvm` group);
# falls back to TCG without KVM. Guest CID is fixed at 3; host = CID 2.
set -euo pipefail
cd "$(dirname "$0")/../.." # repo root

OUT="deploy/qemu/build"
KREL="$(uname -r)"
KIMG="/boot/vmlinuz-${KREL}"

if [ ! -f "${OUT}/initramfs.cpio.gz" ]; then
    echo "initramfs missing — run deploy/qemu/build-rootfs.sh first" >&2
    exit 1
fi

TEE_KEY="${TEE_KEY:-$(printf '2a%.0s' $(seq 32))}" # [0x2a; 32]
LISTEN="${LISTEN:-5555}"
NSM="${NSM:-vsock:2:7777}"

QEMU_ARGS=()
if [ -r /dev/kvm ]; then
    QEMU_ARGS+=(-enable-kvm -cpu host)
else
    echo "[run] /dev/kvm unavailable — falling back to TCG (slower)" >&2
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}" \
    -m 384M -smp 2 -nographic -no-reboot \
    -kernel "${KIMG}" \
    -initrd "${OUT}/initramfs.cpio.gz" \
    -append "console=ttyS0 rdinit=/init panic=-1 teekey=${TEE_KEY} listen=${LISTEN} nsm=${NSM}" \
    -device vhost-vsock-pci,guest-cid=3
