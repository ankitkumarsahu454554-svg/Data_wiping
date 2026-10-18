#!/usr/bin/env bash
# tests/bench-verify.sh — Benchmark verification throughput
# Tests both full and sampled verification modes and reports MB/s.

set -euo pipefail

DEVICE=""
ITERATIONS=3
PATTERN="zeros"
OUTPUT_JSON=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --device)     DEVICE="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --pattern)    PATTERN="$2"; shift 2 ;;
        --json)       OUTPUT_JSON=true; shift ;;
        *) echo "Usage: $0 --device /dev/sdX [--iterations N] [--pattern zeros|ones|0xNN]"; exit 1 ;;
    esac
done

if [[ -z "$DEVICE" ]]; then
    echo "Error: --device is required"
    exit 1
fi

ENGINE="${WIPE_ENGINE:-../bin/wipe-engine}"
if [[ ! -x "$ENGINE" ]]; then
    ENGINE="./wipe-engine/target/release/wipe-engine"
fi

echo "Verification Benchmark"
echo "  Device:     $DEVICE"
echo "  Iterations: $ITERATIONS"
echo "  Pattern:    $PATTERN"
echo "  Engine:     $ENGINE"
echo ""

declare -a FULL_TIMES=()
declare -a SAMPLED_TIMES=()

for i in $(seq 1 "$ITERATIONS"); do
    echo "=== Iteration $i/$ITERATIONS ==="

    # Full verification
    echo -n "  Full verify:    "
    T1=$SECONDS
    "$ENGINE" verify "$DEVICE" --pattern "$PATTERN" --mode full 2>/dev/null
    T2=$SECONDS
    FULL_TIME=$((T2 - T1))
    FULL_TIMES+=("$FULL_TIME")
    echo "${FULL_TIME}s"

    # Sampled verification
    echo -n "  Sampled verify: "
    T1=$SECONDS
    "$ENGINE" verify "$DEVICE" --pattern "$PATTERN" --mode sampled 2>/dev/null
    T2=$SECONDS
    SAMPLED_TIME=$((T2 - T1))
    SAMPLED_TIMES+=("$SAMPLED_TIME")
    echo "${SAMPLED_TIME}s"
    echo ""
done

# Compute averages
SIZE_BYTES=$(blockdev --getsize64 "$DEVICE" 2>/dev/null || echo 0)
SIZE_GB=$(echo "scale=2; $SIZE_BYTES / 1000000000" | bc)

avg() {
    local arr=("$@")
    local sum=0
    for v in "${arr[@]}"; do sum=$((sum + v)); done
    echo $((sum / ${#arr[@]}))
}

FULL_AVG=$(avg "${FULL_TIMES[@]}")
SAMPLED_AVG=$(avg "${SAMPLED_TIMES[@]}")

if [[ $FULL_AVG -gt 0 ]]; then
    FULL_MBPS=$(echo "scale=1; $SIZE_BYTES / $FULL_AVG / 1000000" | bc)
else
    FULL_MBPS="N/A"
fi

if [[ $SAMPLED_AVG -gt 0 ]]; then
    SAMPLED_MBPS=$(echo "scale=1; ($SIZE_BYTES * 0.001) / $SAMPLED_AVG / 1000000" | bc)
else
    SAMPLED_MBPS="N/A"
fi

echo "Results"
echo "───────────────────────────────────────────"
echo "  Device size:         ${SIZE_GB} GB"
echo "  Full verify avg:     ${FULL_AVG}s (${FULL_MBPS} MB/s)"
echo "  Sampled verify avg:  ${SAMPLED_AVG}s (~${SAMPLED_MBPS} MB/s effective)"
echo "  Speedup (sampled):   $(echo "scale=1; $FULL_AVG / ($SAMPLED_AVG + 0.001)" | bc)×"

if [[ "$OUTPUT_JSON" == "true" ]]; then
    cat <<EOF
{
  "device": "$DEVICE",
  "size_bytes": $SIZE_BYTES,
  "iterations": $ITERATIONS,
  "full_verify_avg_secs": $FULL_AVG,
  "full_verify_mbps": "$FULL_MBPS",
  "sampled_verify_avg_secs": $SAMPLED_AVG,
  "sampled_verify_mbps": "$SAMPLED_MBPS"
}
EOF
fi
