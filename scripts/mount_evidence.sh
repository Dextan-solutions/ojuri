#!/usr/bin/env bash
# mount_evidence.sh — bind-mount an extracted evidence directory tree read-only
# at /evidence/<case_id>/ with hardening flags (ro, noexec, nodev, nosuid).
#
# Usage: sudo ./mount_evidence.sh <case_id> <source_directory>
# Example: sudo ./mount_evidence.sh case_2026_001 /mnt/extracted_case
#
# Requires sudo because /evidence/ is owned by root and mount is privileged.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <case_id> <source_directory>" >&2
    echo "Example: $0 case_2026_001 /mnt/extracted_case" >&2
    exit 2
fi

CASE_ID="$1"
SOURCE_DIR="$2"

# Whitelist validation on case_id: same pattern we use in MCP primitives.
if ! [[ "$CASE_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
    echo "Error: case_id must match ^[A-Za-z0-9_-]{1,64}\$" >&2
    echo "Got: $CASE_ID" >&2
    exit 2
fi

# Validate source exists and is a directory.
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: source directory does not exist or is not a directory: $SOURCE_DIR" >&2
    exit 2
fi

# Canonicalize source path.
SOURCE_DIR="$(readlink -f "$SOURCE_DIR")"

MOUNT_POINT="/evidence/${CASE_ID}"

# Check we have root or sudo.
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use sudo)" >&2
    exit 2
fi

# Create mount point if it doesn't exist.
mkdir -p "$MOUNT_POINT"

# Refuse to overwrite an existing mount.
if mountpoint -q "$MOUNT_POINT"; then
    echo "Error: $MOUNT_POINT is already mounted. Unmount first with: sudo umount $MOUNT_POINT" >&2
    exit 1
fi

# Bind-mount with hardening flags.
# ro       — read-only at kernel level
# noexec   — no binary execution from the mount
# nodev    — no device files honoured
# nosuid   — no setuid/setgid bits honoured
echo "Mounting $SOURCE_DIR → $MOUNT_POINT (read-only)"
mount --bind "$SOURCE_DIR" "$MOUNT_POINT"
mount -o remount,ro,noexec,nodev,nosuid,bind "$MOUNT_POINT"

# Verify the mount actually became read-only.
if mount | grep -F "$MOUNT_POINT" | grep -q "ro,"; then
    echo "✓ Mounted read-only: $MOUNT_POINT"
else
    echo "✗ Mount completed but read-only flag not visible — investigate" >&2
    exit 1
fi

echo ""
echo "Next step: compute the baseline with:"
echo "  python3 ~/ojuri/scripts/baseline_evidence.py $CASE_ID"
