#!/usr/bin/env bash
# tests/setup-test-devices.sh — Create mock loop devices for testing
# without requiring real hardware.

set -euo pipefail

COUNT=20
SIZE_GB=1
DEVICE_DIR="/tmp/securewipe-test"

while [[ $# -gt 0 ]]; do
    case $1 in
        --count) COUNT="$2"; shift 2 ;;
        --size)  SIZE_GB="$2"; shift 2 ;;
        --dir)   DEVICE_DIR="$2"; shift 2 ;;
        *) echo "Usage: $0 [--count N] [--size GB] [--dir PATH]"; exit 1 ;;
    esac
done

mkdir -p "$DEVICE_DIR"

echo "Creating ${COUNT} loop devices (${SIZE_GB}GB each) in ${DEVICE_DIR}..."

DEVICES=()
for i in $(seq 1 "$COUNT"); do
    img="${DEVICE_DIR}/test_disk_${i}.img"
    dd if=/dev/zero of="$img" bs=1M count=$((SIZE_GB * 1024)) status=none 2>/dev/null
    loop=$(losetup --find --show "$img")
    DEVICES+=("$loop")
    echo "  ✓ ${loop} → ${img}"
done

# Write device list to a file for use by stress-test.sh
printf '%s\n' "${DEVICES[@]}" > "${DEVICE_DIR}/devices.txt"

echo ""
echo "Done. ${COUNT} devices created."
echo "Device list: ${DEVICE_DIR}/devices.txt"
echo ""
echo "To clean up: losetup -D && rm -rf ${DEVICE_DIR}"
