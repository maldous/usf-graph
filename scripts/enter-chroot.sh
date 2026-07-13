#!/usr/bin/env bash
# Host-side: enter the USF v2 chroot with a working directory of /usf.
# Sets up virtual filesystems with cleanup traps so host mounts are never left behind.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts -> usf -> v2 (the chroot root)
V2="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ ! -x "$V2/bin/bash" ]; then
  echo "error: no chroot found at $V2 (missing /bin/bash)" >&2
  exit 1
fi

# Re-exec under sudo if not already root (chroot + mounts require root).
if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

MOUNTED=()
cleanup() {
  local m
  for (( idx=${#MOUNTED[@]}-1 ; idx>=0 ; idx-- )); do
    umount -l "${MOUNTED[$idx]}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

try_mount() {
  # try_mount <mount-args...> <target>
  local target="${!#}"
  mkdir -p "$target"
  if mountpoint -q "$target"; then return 0; fi
  if mount "$@" 2>/dev/null; then MOUNTED+=("$target"); fi
}

try_mount -t proc  proc  "$V2/proc"
try_mount -t sysfs sysfs "$V2/sys"
try_mount --bind /dev      "$V2/dev"
try_mount --bind /dev/pts  "$V2/dev/pts"

# Give the chroot working DNS for any network use (best effort; restored on host by nothing —
# we only write inside the chroot's own /etc).
cp -f /etc/resolv.conf "$V2/etc/resolv.conf" 2>/dev/null || true

# Enter; working directory /usf. Not exec'd so the EXIT trap can unmount afterwards.
chroot "$V2" /bin/bash -c 'cd /usf && exec /bin/bash'
