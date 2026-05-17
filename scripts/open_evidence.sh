#!/usr/bin/env bash
# open_evidence.sh — forensic-image-format-aware evidence opener (Stage 1).
#
# Detects the image format, exposes its filesystem read-only under
# /var/lib/ojuri/raw/<case_id>/, then hands off to the UNCHANGED
# scripts/mount_evidence.sh (Stage 2) which applies the kernel hardening
# (ro,noexec,nodev,nosuid) at /evidence/<case_id>/.
#
# Two-stage design (see docs/architecture/ARCHITECTURE.md §7):
#   Stage 1 (this script) = format handling.
#   Stage 2 (mount_evidence.sh, untouched) = hardening.
#
# Usage:  sudo ./open_evidence.sh <case_id> <image_path>
# Example: sudo ./open_evidence.sh rocba_test /cases/rocba/rocba-cdrive.e01
#
# Supported now : E01/EWF (.E01/.e01), raw (.dd/.img/.raw)
# Roadmap stubs : AFF4 (v0.4), VMDK/VHDX (v0.5)
#
# Idempotent: if the evidence (or an intermediate stage) is already mounted
# for this case_id, the script refuses and tells you to unmount first rather
# than corrupting state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOUNT_EVIDENCE="${SCRIPT_DIR}/mount_evidence.sh"

EWF_BASE="/var/lib/ojuri/ewf"
RAW_BASE="/var/lib/ojuri/raw"

# ---------------------------------------------------------------------------
# Argument parsing & validation
# ---------------------------------------------------------------------------
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <case_id> <image_path>" >&2
    echo "Example: $0 rocba_test /cases/rocba/rocba-cdrive.e01" >&2
    exit 2
fi

CASE_ID="$1"
IMAGE_PATH="$2"

# Whitelist validation on case_id: SAME pattern as mount_evidence.sh and the
# MCP primitives. Keeps a hostile case_id out of derived filesystem paths.
if ! [[ "$CASE_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
    echo "Error: case_id must match ^[A-Za-z0-9_-]{1,64}\$" >&2
    echo "Got: $CASE_ID" >&2
    exit 2
fi

# Image must exist and be a regular file (not a dir, device, or symlink-to-dir).
if [ ! -f "$IMAGE_PATH" ]; then
    echo "Error: image path does not exist or is not a regular file: $IMAGE_PATH" >&2
    exit 2
fi
IMAGE_PATH="$(readlink -f "$IMAGE_PATH")"

# Must be root: ewfmount, mount, and /evidence are all privileged.
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use sudo) — ewfmount and mount are privileged." >&2
    exit 2
fi

# Stage-2 script must be present and executable.
if [ ! -x "$MOUNT_EVIDENCE" ]; then
    echo "Error: Stage-2 script not found or not executable: $MOUNT_EVIDENCE" >&2
    exit 2
fi

EWF_DIR="${EWF_BASE}/${CASE_ID}"
RAW_DIR="${RAW_BASE}/${CASE_ID}"
EVIDENCE_DIR="/evidence/${CASE_ID}"

# ---------------------------------------------------------------------------
# Idempotency guard — refuse to clobber an existing mount for this case.
# ---------------------------------------------------------------------------
guard_already_mounted() {
    local mp="$1" label="$2"
    if mountpoint -q "$mp" 2>/dev/null; then
        echo "Error: $label already mounted at $mp for case '$CASE_ID'." >&2
        echo "Refusing to overwrite. Unmount the existing case first, e.g.:" >&2
        echo "  sudo umount ${EVIDENCE_DIR}" >&2
        echo "  sudo umount ${RAW_DIR}" >&2
        echo "  sudo umount ${EWF_DIR}   # E01 only" >&2
        exit 1
    fi
}

guard_already_mounted "$EVIDENCE_DIR" "Hardened evidence"
guard_already_mounted "$RAW_DIR" "Stage-1 raw filesystem"
guard_already_mounted "$EWF_DIR" "EWF FUSE image"

# ---------------------------------------------------------------------------
# Format detection (by extension, case-insensitive)
# ---------------------------------------------------------------------------
ext_lc="$(printf '%s' "${IMAGE_PATH##*.}" | tr '[:upper:]' '[:lower:]')"

# Robust read-only loop-mount of a single-volume image.
#   1. Try the kernel's default driver (clean images, any FS).
#   2. On failure, fall back to the in-kernel ntfs3 driver, which tolerates a
#      volume image whose recorded NTFS size slightly exceeds the imaged
#      sector count (a missing backup boot sector — common when a partition,
#      not a whole disk, was imaged). ntfs3 with 'ro' is non-modifying and
#      forensically safe; it performs no journal replay or recovery on a
#      read-only mount.
# All attempts are read-only (ro,noatime) — evidence is never written.
# Args: <source_device_or_image> <target_dir>. Returns non-zero with the
# captured error in $LOOP_MOUNT_ERR if every attempt fails.
LOOP_MOUNT_ERR=""
loop_mount_ro() {
    local src="$1" tgt="$2" rc

    set +e
    LOOP_MOUNT_ERR="$(mount -o ro,loop,noatime "$src" "$tgt" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "  (mounted via default driver)"
        return 0
    fi
    echo "  default-driver mount failed (rc=${rc}); trying kernel ntfs3 (ro)…"

    set +e
    LOOP_MOUNT_ERR="$(mount -t ntfs3 -o ro,noatime,loop "$src" "$tgt" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "  (mounted via kernel ntfs3 driver, read-only)"
        return 0
    fi
    return "$rc"
}

handoff_stage2() {
    echo ""
    echo "Stage 1 complete. Handing off to Stage 2 (hardening): $MOUNT_EVIDENCE"
    echo ""
    "$MOUNT_EVIDENCE" "$CASE_ID" "$RAW_DIR"
    echo ""
    echo "✓ Evidence mounted read-only at ${EVIDENCE_DIR}/"
    echo "Next step: compute the integrity baseline, then run MCP queries:"
    echo "  python3 ${SCRIPT_DIR}/baseline_evidence.py ${CASE_ID}"
}

open_e01() {
    echo "Detected format: E01 / EWF (EnCase). Backend: ewfmount."
    if ! command -v ewfmount >/dev/null 2>&1; then
        echo "Error: ewfmount not found. Install libewf-utils (see REQUIREMENTS.md)." >&2
        exit 2
    fi

    mkdir -p "$EWF_DIR" "$RAW_DIR"

    # (b) Expose the EWF set as a raw 'ewf1' device via FUSE. Inherently
    #     read-only — libewf provides no write path.
    echo "Running: ewfmount $IMAGE_PATH $EWF_DIR"
    set +e
    ewf_err="$(ewfmount "$IMAGE_PATH" "$EWF_DIR" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "Error: ewfmount failed (exit ${rc})." >&2
        echo "ewfmount output:" >&2
        echo "$ewf_err" >&2
        exit "$rc"
    fi

    # (c) Verify the FUSE mount actually exposed ewf1.
    if [ ! -e "${EWF_DIR}/ewf1" ]; then
        echo "Error: ewfmount returned success but ${EWF_DIR}/ewf1 is absent." >&2
        echo "Contents of ${EWF_DIR}:" >&2
        ls -la "$EWF_DIR" >&2 || true
        umount "$EWF_DIR" 2>/dev/null || true
        exit 1
    fi
    echo "✓ EWF exposed: ${EWF_DIR}/ewf1"

    # (e) Loop-mount the raw ewf1 volume read-only. noatime so even atime is
    #     not written. No -t: let the kernel detect (NTFS expected).
    echo "Mounting ${EWF_DIR}/ewf1 → $RAW_DIR (read-only)"
    set +e
    loop_mount_ro "${EWF_DIR}/ewf1" "$RAW_DIR"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "Error: loop-mount of ewf1 failed (exit ${rc})." >&2
        echo "mount output: $LOOP_MOUNT_ERR" >&2
        echo "Hint: if this is a full-disk image (not a single volume) the" >&2
        echo "kernel cannot mount it directly without a partition offset;" >&2
        echo "this opener expects a single-volume image (see ARCHITECTURE §7.2)." >&2
        umount "$EWF_DIR" 2>/dev/null || true
        exit "$rc"
    fi

    # (f) Verify.
    if ! mountpoint -q "$RAW_DIR"; then
        echo "Error: mount reported success but $RAW_DIR is not a mountpoint." >&2
        umount "$EWF_DIR" 2>/dev/null || true
        exit 1
    fi
    echo "✓ Filesystem mounted read-only: $RAW_DIR"

    handoff_stage2
}

open_raw() {
    echo "Detected format: raw image (.${ext_lc}). Backend: direct loop-mount."
    mkdir -p "$RAW_DIR"
    echo "Mounting $IMAGE_PATH → $RAW_DIR (read-only)"
    set +e
    loop_mount_ro "$IMAGE_PATH" "$RAW_DIR"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "Error: loop-mount of raw image failed (exit ${rc})." >&2
        echo "mount output: $LOOP_MOUNT_ERR" >&2
        echo "Hint: a full-disk raw image needs a partition offset; this" >&2
        echo "opener expects a single-volume image (see ARCHITECTURE §7.2)." >&2
        exit "$rc"
    fi
    if ! mountpoint -q "$RAW_DIR"; then
        echo "Error: mount reported success but $RAW_DIR is not a mountpoint." >&2
        exit 1
    fi
    echo "✓ Filesystem mounted read-only: $RAW_DIR"
    handoff_stage2
}

stub() {
    local fmt="$1" roadmap="$2"
    echo "Error: ${fmt} images are not yet supported." >&2
    echo "This is a known roadmap item (${roadmap}). See" >&2
    echo "docs/architecture/ARCHITECTURE.md §7.2 and REQUIREMENTS.md." >&2
    echo "Workaround today: convert to raw/E01, or extract the volume and" >&2
    echo "point Stage 2 (mount_evidence.sh) at the extracted directory." >&2
    exit 3
}

case "$ext_lc" in
    e01)
        open_e01
        ;;
    dd|img|raw)
        open_raw
        ;;
    aff|aff4)
        stub "AFF4" "roadmap v0.4"
        ;;
    vmdk)
        stub "VMDK" "roadmap v0.5"
        ;;
    vhdx)
        stub "VHDX" "roadmap v0.5"
        ;;
    *)
        echo "Error: unsupported or unrecognised image format: '.${ext_lc}'" >&2
        echo "Supported: .E01/.e01 (EWF), .dd/.img/.raw (raw)." >&2
        echo "Stubs (clear error): .aff/.aff4, .vmdk, .vhdx." >&2
        echo "See docs/architecture/ARCHITECTURE.md §7.2." >&2
        exit 2
        ;;
esac
