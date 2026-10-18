#!/usr/bin/env bash
# tests/stress-test.sh — Multi-drive parallel wipe stress test
# Tests the system's ability to handle 20+ simultaneous wipe jobs.
# Requires: loop devices or real block devices listed in DEVICES env var.
# Usage: ./stress-test.sh [--drives N] [--algorithm ALG] [--verify MODE]

set -euo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────────────

NUM_DRIVES=20
ALGORITHM="zero-fill"       # Fast for stress testing
VERIFY_MODE="sampled"
SIZE_MB=512                  # Size of each test device (MB)
RESULTS_DIR="./stress-results/$(date +%Y%m%d_%H%M%S)"
BACKEND_URL="https://127.0.0.1:18443"
TOKEN=""
PARALLEL=20                  # Max concurrent jobs

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

# ─── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case $1 in
        --drives)    NUM_DRIVES="$2"; shift 2 ;;
        --algorithm) ALGORITHM="$2"; shift 2 ;;
        --verify)    VERIFY_MODE="$2"; shift 2 ;;
        --size-mb)   SIZE_MB="$2"; shift 2 ;;
        --parallel)  PARALLEL="$2"; shift 2 ;;
        --token)     TOKEN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--drives N] [--algorithm ALG] [--verify MODE]"
            echo "          [--size-mb MB] [--parallel N] [--token JWT]"
            exit 0 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

# ─── Prerequisite checks ──────────────────────────────────────────────────────

check_prereqs() {
    log "Checking prerequisites..."

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        err "Must run as root (raw disk access required)"
        exit 1
    fi

    # Required commands
    for cmd in losetup dd curl jq uuid-runtime bc; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing required command: $cmd"
            exit 1
        fi
    done

    # Backend must be running
    if ! curl -sk "${BACKEND_URL}/api/v1/health" &>/dev/null; then
        err "Backend not reachable at ${BACKEND_URL}"
        err "Start the backend first: ./bin/securewipe-backend"
        exit 1
    fi

    ok "Prerequisites OK"
}

# ─── Authentication ───────────────────────────────────────────────────────────

get_token() {
    if [[ -n "$TOKEN" ]]; then
        return
    fi

    log "Authenticating with backend..."
    # For stress tests, use a dedicated test user
    local response
    response=$(curl -sk -X POST "${BACKEND_URL}/api/v1/session" \
        -H 'Content-Type: application/json' \
        -d '{"username":"stress-test","password":"StressTest@2025!"}' 2>&1) || true

    TOKEN=$(echo "$response" | jq -r '.token // empty' 2>/dev/null || echo "")
    if [[ -z "$TOKEN" ]]; then
        warn "Could not authenticate. Continuing without auth (may fail)."
    else
        ok "Authenticated (token: ${TOKEN:0:20}...)"
    fi
}

# ─── Loop device setup ────────────────────────────────────────────────────────

declare -a LOOP_DEVICES=()
declare -a BACKING_FILES=()

setup_test_devices() {
    log "Setting up ${NUM_DRIVES} test loop devices (${SIZE_MB}MB each)..."
    mkdir -p /tmp/securewipe-test

    local max_loop
    max_loop=$(losetup -f | grep -oP '\d+' | head -1)
    # Ensure enough loop devices exist
    if [[ $(ls /dev/loop* 2>/dev/null | wc -l) -lt $((NUM_DRIVES + 5)) ]]; then
        log "Creating additional loop device nodes..."
        for i in $(seq "$max_loop" $((max_loop + NUM_DRIVES + 5))); do
            mknod -m 660 "/dev/loop${i}" b 7 "$i" 2>/dev/null || true
        done
    fi

    for i in $(seq 1 "$NUM_DRIVES"); do
        local backing="/tmp/securewipe-test/disk${i}.img"
        log "  Creating disk image ${i}/${NUM_DRIVES}: ${backing}"

        # Create sparse file for speed (actual I/O will materialize blocks)
        dd if=/dev/zero of="$backing" bs=1M count="$SIZE_MB" status=none

        # Attach loop device
        local loop
        loop=$(losetup --find --show "$backing")
        LOOP_DEVICES+=("$loop")
        BACKING_FILES+=("$backing")
        log "  → ${loop} (${SIZE_MB}MB)"
    done

    ok "Created ${#LOOP_DEVICES[@]} test devices"
}

teardown_test_devices() {
    log "Cleaning up test devices..."
    for loop in "${LOOP_DEVICES[@]}"; do
        losetup -d "$loop" 2>/dev/null || true
    done
    for backing in "${BACKING_FILES[@]}"; do
        rm -f "$backing"
    done
    ok "Cleanup complete"
}

# ─── Job submission ────────────────────────────────────────────────────────────

declare -A JOB_IDS

submit_jobs() {
    log "Submitting ${NUM_DRIVES} wipe jobs..."
    mkdir -p "$RESULTS_DIR"

    local submitted=0
    local failed=0

    for loop in "${LOOP_DEVICES[@]}"; do
        local job_payload
        job_payload=$(cat <<EOF
{
  "device_path": "${loop}",
  "algorithm": "${ALGORITHM}",
  "verification": "${VERIFY_MODE}",
  "disable_hpa": false,
  "restore_dco": false,
  "operator_id": "stress-test-$(hostname)"
}
EOF
)
        local response
        response=$(curl -sk -X POST "${BACKEND_URL}/api/v1/jobs" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer ${TOKEN}" \
            -d "$job_payload" 2>&1) || true

        local job_id
        job_id=$(echo "$response" | jq -r '.id // empty' 2>/dev/null || echo "")

        if [[ -n "$job_id" ]]; then
            JOB_IDS["$loop"]="$job_id"
            ok "  Submitted: ${loop} → job ${job_id}"
            submitted=$((submitted + 1))
        else
            err "  Failed to submit job for ${loop}: ${response}"
            failed=$((failed + 1))
        fi
    done

    log "Submitted: ${submitted}/${NUM_DRIVES}, Failed: ${failed}"
}

# ─── Progress monitoring ──────────────────────────────────────────────────────

monitor_jobs() {
    log "Monitoring ${#JOB_IDS[@]} jobs..."
    echo ""

    local start_time=$SECONDS
    local all_done=false

    while [[ "$all_done" == "false" ]]; do
        all_done=true
        local running=0 complete=0 failed=0

        printf "\r\033[K"  # clear line

        for loop in "${!JOB_IDS[@]}"; do
            local job_id="${JOB_IDS[$loop]}"
            local status_response
            status_response=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
                "${BACKEND_URL}/api/v1/jobs/${job_id}" 2>/dev/null) || continue

            local status progress
            status=$(echo "$status_response" | jq -r '.status // "unknown"')
            progress=$(echo "$status_response" | jq -r '.progress // 0')

            case "$status" in
                running|verifying)
                    running=$((running + 1))
                    all_done=false
                    ;;
                complete)
                    complete=$((complete + 1))
                    ;;
                failed|cancelled)
                    failed=$((failed + 1))
                    # Save failure details
                    echo "$status_response" > "${RESULTS_DIR}/failed_${job_id}.json"
                    ;;
                queued)
                    all_done=false
                    ;;
            esac
        done

        local elapsed=$((SECONDS - start_time))
        local total=${#JOB_IDS[@]}
        local done_count=$((complete + failed))
        local pct=0
        if [[ $total -gt 0 ]]; then
            pct=$((done_count * 100 / total))
        fi

        printf "${BOLD}Progress: [%3d%%] ${GREEN}%d complete${NC} | ${BLUE}%d running${NC} | ${RED}%d failed${NC} | ⏱ %ds${NC}" \
            "$pct" "$complete" "$running" "$failed" "$elapsed"

        if [[ "$all_done" == "false" ]]; then
            sleep 3
        fi
    done

    echo ""
    ok "All jobs finished"
}

# ─── Results collection ───────────────────────────────────────────────────────

collect_results() {
    log "Collecting results..."

    local total=0 passed=0 failed=0
    declare -A results

    for loop in "${!JOB_IDS[@]}"; do
        local job_id="${JOB_IDS[$loop]}"
        local response
        response=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
            "${BACKEND_URL}/api/v1/jobs/${job_id}" 2>/dev/null) || continue

        local status throughput duration bad_sectors
        status=$(echo "$response" | jq -r '.status')
        throughput=$(echo "$response" | jq -r '.throughput_mb_s // 0')
        duration=$(echo "$response" | jq -r '.duration_seconds // 0')
        bad_sectors=$(echo "$response" | jq -r '.bad_sectors // 0')

        echo "$response" > "${RESULTS_DIR}/job_${job_id}.json"
        total=$((total + 1))

        if [[ "$status" == "complete" ]]; then
            passed=$((passed + 1))
            results["$loop"]="PASS|${throughput}|${duration}|${bad_sectors}"
        else
            failed=$((failed + 1))
            local error
            error=$(echo "$response" | jq -r '.error_message // "unknown"')
            results["$loop"]="FAIL|0|0|${error}"
        fi
    done

    # ─── Summary report ─────────────────────────────────────────────────────
    local report_file="${RESULTS_DIR}/summary.txt"
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "   SecureWipe Enterprise — Stress Test Summary"
        echo "═══════════════════════════════════════════════════════════"
        echo "   Date:       $(date)"
        echo "   Algorithm:  ${ALGORITHM}"
        echo "   Verify:     ${VERIFY_MODE}"
        echo "   Drives:     ${total}"
        echo "   Parallel:   ${PARALLEL}"
        echo "───────────────────────────────────────────────────────────"
        printf "   %-12s  %-12s  %-10s  %-8s  %s\n" "DEVICE" "STATUS" "MB/s" "SECS" "BAD_SECTORS"
        echo "───────────────────────────────────────────────────────────"

        local total_throughput=0
        for loop in "${!results[@]}"; do
            IFS='|' read -r status tp dur bs <<< "${results[$loop]}"
            printf "   %-12s  %-12s  %-10s  %-8s  %s\n" "$loop" "$status" "$tp" "$dur" "$bs"
            if [[ "$status" == "PASS" ]] && [[ "$tp" != "0" ]]; then
                total_throughput=$(echo "$total_throughput + $tp" | bc)
            fi
        done

        echo "───────────────────────────────────────────────────────────"
        echo "   PASSED:           ${passed}/${total}"
        echo "   FAILED:           ${failed}/${total}"
        if [[ $passed -gt 0 ]]; then
            local avg_tp
            avg_tp=$(echo "scale=1; $total_throughput / $passed" | bc)
            local agg_tp
            agg_tp=$(echo "scale=0; $total_throughput / 1" | bc)
            echo "   Avg throughput:   ${avg_tp} MB/s"
            echo "   Total throughput: ${agg_tp} MB/s (aggregate)"
        fi
        echo "═══════════════════════════════════════════════════════════"
    } | tee "$report_file"

    log "Results saved to: ${RESULTS_DIR}/"

    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

# ─── System metrics ───────────────────────────────────────────────────────────

capture_system_metrics() {
    local metrics_file="${RESULTS_DIR}/system_metrics.txt"
    {
        echo "=== System at test start: $(date) ==="
        echo "--- CPU ---"
        nproc
        cat /proc/cpuinfo | grep 'model name' | head -1
        echo "--- Memory ---"
        free -h
        echo "--- I/O scheduler ---"
        for dev in "${LOOP_DEVICES[@]}"; do
            local d
            d=$(basename "$dev")
            echo "$d: $(cat /sys/block/${d}/queue/scheduler 2>/dev/null || echo 'N/A')"
        done
        echo "--- Kernel ---"
        uname -r
    } > "$metrics_file"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${BOLD}SecureWipe Enterprise — Stress Test${NC}"
    echo -e "Drives: ${NUM_DRIVES} | Algorithm: ${ALGORITHM} | Verify: ${VERIFY_MODE}"
    echo "──────────────────────────────────────────"
    echo ""

    check_prereqs
    get_token
    setup_test_devices

    # Trap for cleanup on exit
    trap teardown_test_devices EXIT

    mkdir -p "$RESULTS_DIR"
    capture_system_metrics

    local test_start=$SECONDS

    submit_jobs
    monitor_jobs

    local test_end=$SECONDS
    local total_time=$((test_end - test_start))

    if collect_results; then
        echo ""
        ok "Stress test PASSED in ${total_time}s"
        exit 0
    else
        echo ""
        err "Stress test FAILED in ${total_time}s (see ${RESULTS_DIR}/)"
        exit 1
    fi
}

main "$@"
