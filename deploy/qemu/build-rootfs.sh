#!/usr/bin/env bash
# Builds deploy/qemu/build/{rootfs,initramfs.cpio.gz}: a minimal guest that
# runs `tee-runner serve` as init over vsock.
#
# Layout decision: initramfs (cpio.gz) + the RUNNING host kernel — no disks,
# no init system, vermagic-matched vsock modules. Base rootfs comes from the
# official static-busybox image (hermetic, no root required).
set -euo pipefail
cd "$(dirname "$0")/../.." # repo root

KREL="$(uname -r)"
KIMG="/boot/vmlinuz-${KREL}"
if [ ! -f "$KIMG" ]; then
    echo "kernel image not found: $KIMG" >&2
    exit 1
fi

OUT="deploy/qemu/build"
ROOTFS="${OUT}/rootfs"
# Release by default: debug binaries carry hundreds of MB of debuginfo, which
# once broke initramfs unpacking ("write error") inside a 384 MB guest.
PROFILE="${PROFILE:-release}"

rm -rf "${OUT}"
mkdir -p "${ROOTFS}/enclave" "${ROOTFS}/lib/modules"

echo "[rootfs] extracting static busybox base image"
cid="$(docker create busybox /bin/true)"
docker export "${cid}" | tar -x -C "${ROOTFS}"
docker rm -f "${cid}" >/dev/null

echo "[rootfs] building guest artifacts"
CARGO_FLAGS=()
if [ "${PROFILE}" = "release" ]; then
    CARGO_FLAGS+=(--release)
fi
cargo build "${CARGO_FLAGS[@]}" -p runner-cli
bash scripts/build-guest-examples.sh
cp "target/${PROFILE}/tee-runner" "${ROOTFS}/enclave/tee-runner"
# Belt and braces: never ship debuginfo into the initramfs.
strip "${ROOTFS}/enclave/tee-runner" 2>/dev/null || true
ls -la "${ROOTFS}/enclave/tee-runner"
cp scripts/examples/throttle.wasm "${ROOTFS}/enclave/throttle.wasm"

# The busybox image has no glibc: carry the runner's interpreter + libraries.
echo "[rootfs] copying dynamic loader + libraries"
{
    ldd "target/${PROFILE}/tee-runner" | awk '$1 ~ /^\// { print $1 } $3 ~ /^\// { print $3 }'
} | sort -u | while read -r lib; do
    cp --parents "${lib}" "${ROOTFS}/"
done

echo "[rootfs] copying vsock modules (xz -> ko)"
VMOD="/lib/modules/${KREL}/kernel/net/vmw_vsock"
for name in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do
    if [ -f "${VMOD}/${name}.ko.xz" ]; then
        xz -dc "${VMOD}/${name}.ko.xz" > "${ROOTFS}/lib/modules/${name}.ko"
    elif [ -f "${VMOD}/${name}.ko" ]; then
        cp "${VMOD}/${name}.ko" "${ROOTFS}/lib/modules/"
    else
        echo "missing vsock module: ${name}" >&2
        exit 1
    fi
done
# Virtio core (PCI transport for vhost-vsock-pci) if built as modules.
VIRTIO="/lib/modules/${KREL}/kernel/drivers/virtio"
if [ -d "${VIRTIO}" ]; then
    find "${VIRTIO}" -name '*.ko.xz' -o -name '*.ko' | while read -r mod; do
        case "$mod" in
            *.xz) xz -dc "$mod" > "${ROOTFS}/lib/modules/$(basename "${mod%.xz}")" ;;
            *) cp "$mod" "${ROOTFS}/lib/modules/" ;;
        esac
    done
fi

echo "[rootfs] installing init"
cp deploy/qemu/init "${ROOTFS}/init"
chmod +x "${ROOTFS}/init"

echo "[rootfs] packing initramfs"
(cd "${ROOTFS}" && find . | cpio -o -H newc --quiet) | gzip -9 > "${OUT}/initramfs.cpio.gz"

ls -la "${OUT}/initramfs.cpio.gz"
echo "[rootfs] done — boot with deploy/qemu/run.sh (needs /dev/kvm + /dev/vhost-vsock)"
