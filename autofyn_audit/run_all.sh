#!/usr/bin/env bash
# run_all.sh — Run the full audit PoC suite against the live target.
#
# Exit code semantics:
#   0  — harness ran to completion (all PoCs executed); review PASS/FAIL table for findings.
#   1  — harness infrastructure error (container not running, a PoC script crashed).
#
# A FAIL result means a real security finding was observed — that is valid audit
# output, NOT a harness error.  Read the table, not just the exit code.
#
# Usage:
#   bash autofyn_audit/run_all.sh
#   AUDIT_HOST_PORT=9000 bash autofyn_audit/run_all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/pins.sh
source "${SCRIPT_DIR}/lib/pins.sh"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

BASE_URL="http://127.0.0.1:${AUDIT_HOST_PORT}"
HEALTH_URL="${BASE_URL}/health"

# ── Infra health check ────────────────────────────────────────────────────────

log_info "Verifying target is healthy at ${HEALTH_URL} ..."
if ! curl -fsS --max-time 5 "${HEALTH_URL}" >/dev/null 2>&1; then
    log_err "Target is not healthy. Run: bash autofyn_audit/setup.sh"
    exit 1
fi
log_info "Target healthy. Running PoC suite..."
echo ""

# ── Run each PoC ──────────────────────────────────────────────────────────────
# Each PoC is self-contained and prints its own [[ AUDIT-RESULT ]] line(s).

POCS_DIR="${SCRIPT_DIR}/pocs"
ALL_RESULTS=()
HARNESS_FAILED=0

for poc_script in "${POCS_DIR}"/poc_*.sh; do
    poc_name="$(basename "$poc_script" .sh)"

    # poc_14 is the browser-driven PoC and requires Docker + a browser sidecar.
    # It is NOT part of this curl-only harness and must NOT change the
    # "6 PASS + 8 FAIL" tally.  Run it separately:
    #   bash autofyn_audit/pocs/poc_14_cors_exfil_browser.sh <BASE_URL>
    # (BASE_URL must be reachable from inside the Docker network, e.g.
    #  http://autofyn-audit-target:8000 — NOT a loopback address)
    case "${poc_name}" in
        poc_14_*)
            echo "──────────────────────────────────────────────────"
            echo "Skipping: ${poc_name}  (browser-driven; run separately — see header comment)"
            echo "──────────────────────────────────────────────────"
            echo ""
            continue
            ;;
    esac

    echo "──────────────────────────────────────────────────"
    echo "Running: ${poc_name}"
    echo "──────────────────────────────────────────────────"

    # Capture output while also streaming it.
    poc_output="$(bash "${poc_script}" "${BASE_URL}" 2>&1)" || {
        log_err "PoC ${poc_name} exited with error (harness failure)."
        HARNESS_FAILED=1
        echo "${poc_output}"
        continue
    }

    echo "${poc_output}"

    # Collect all AUDIT-RESULT lines from this PoC's output.
    while IFS= read -r line; do
        if [[ "$line" == *"[[ AUDIT-RESULT ]]"* ]]; then
            ALL_RESULTS+=("$line")
        fi
    done <<< "${poc_output}"

    echo ""
done

# ── Summary table ─────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  AUDIT RESULT SUMMARY"
echo "════════════════════════════════════════════════════════════════"
printf "  %-40s %-6s %s\n" "CHECK NAME" "STATUS" "DETAIL"
printf "  %-40s %-6s %s\n" "──────────────────────────────────────" "──────" "──────"

PASS_COUNT=0
FAIL_COUNT=0
HAS_FAIL=0

for result_line in "${ALL_RESULTS[@]}"; do
    # Format: [[ AUDIT-RESULT ]] NAME :: STATUS :: DETAIL
    name="${result_line#*\]\] }"
    name="${name%% ::*}"
    rest="${result_line#* :: }"
    status="${rest%% ::*}"
    detail="${rest#* :: }"

    printf "  %-40s %-6s %s\n" "$name" "$status" "$detail"

    if [[ "$status" == "PASS" ]]; then
        (( PASS_COUNT += 1 ))
    elif [[ "$status" == "FAIL" ]]; then
        (( FAIL_COUNT += 1 ))
        HAS_FAIL=1
    fi
done

echo "════════════════════════════════════════════════════════════════"
echo "  TOTAL: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL"
echo "════════════════════════════════════════════════════════════════"
echo ""

if (( HAS_FAIL == 1 )); then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!  REAL FINDING DETECTED — see audit_report.md for details   !!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""
fi

if (( HARNESS_FAILED == 1 )); then
    log_err "One or more PoC scripts encountered a harness error (see above)."
    exit 1
fi

exit 0
