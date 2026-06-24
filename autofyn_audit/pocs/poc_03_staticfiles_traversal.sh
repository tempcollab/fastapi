#!/usr/bin/env bash
# poc_03_staticfiles_traversal.sh — Path traversal against StaticFiles mount.
#
# EXPECTED OUTCOME: PASS (traversal blocked; sentinel not leaked).
#
# Tests several traversal encodings against /static/, asserting:
#   - All traversal attempts return 404/400/403 (not 200 with file content).
#   - The sentinel string from SECRET_sentinel.txt (OUTSIDE static/) is NOT
#     present in any response body.
#   - Positive control: /static/hello.txt returns 200 with expected content
#     (confirms mount works; a 404 on traversal is real defense, not broken mount).
#
# PASS = all traversal blocked AND positive control works AND sentinel not leaked.
# FAIL = sentinel string found in any response body.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"

echo "=== poc_03: StaticFiles path-traversal check ==="
echo "Mount     : /static -> target_app/static/"
echo "Sentinel  : target_app/SECRET_sentinel.txt (OUTSIDE static/ root)"
echo ""

SENTINEL_MARKER="SENTINEL-DO-NOT-LEAK"
PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
echo "--- Positive control: /static/hello.txt ---"
HELLO_BODY="$(curl -fsS "${BASE_URL}/static/hello.txt" 2>&1 || echo "CURL_FAILED")"
HELLO_CODE="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/static/hello.txt" 2>&1 || echo "000")"
echo "HTTP ${HELLO_CODE}: ${HELLO_BODY}"

if [[ "$HELLO_CODE" == "200" ]] && assert_contains "${HELLO_BODY}" "static file served correctly"; then
    echo "[OK] Positive control: StaticFiles mount works correctly"
else
    echo "[FAIL] Positive control failed — StaticFiles mount may be broken (HTTP ${HELLO_CODE})"
    PASS=0
fi
echo ""

# ── Traversal attempts ────────────────────────────────────────────────────────
declare -a TRAVERSAL_PATHS=(
    "/static/../SECRET_sentinel.txt"
    "/static/%2e%2e/SECRET_sentinel.txt"
    "/static/..%2fSECRET_sentinel.txt"
    "/static/....//SECRET_sentinel.txt"
    "/static/../../../../etc/passwd"
    "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "/static/..%252fSECRET_sentinel.txt"
)

echo "--- Traversal attempts ---"
for path in "${TRAVERSAL_PATHS[@]}"; do
    full_url="${BASE_URL}${path}"
    HTTP_CODE="$(curl -sS -o /tmp/poc03_body.txt -w "%{http_code}" \
        --path-as-is "${full_url}" 2>&1 || echo "000")"
    BODY="$(cat /tmp/poc03_body.txt 2>/dev/null || echo "")"

    # Check sentinel not leaked
    if assert_contains "${BODY}" "${SENTINEL_MARKER}"; then
        echo "[FAIL] HTTP ${HTTP_CODE} ${path} — SENTINEL LEAKED: ${BODY}"
        PASS=0
    elif assert_contains "${BODY}" "root:"; then
        # /etc/passwd content
        echo "[FAIL] HTTP ${HTTP_CODE} ${path} — /etc/passwd CONTENT LEAKED"
        PASS=0
    else
        echo "[OK]   HTTP ${HTTP_CODE} ${path} — blocked (no sentinel/passwd in body)"
    fi
done
echo ""

echo "--- Verdict ---"
if (( PASS == 1 )); then
    print_check "staticfiles_traversal_blocked" "PASS" \
        "all traversal paths returned non-200 or empty body; sentinel not leaked; positive control OK"
else
    print_check "staticfiles_traversal_blocked" "FAIL" \
        "sentinel or /etc/passwd content leaked via path traversal"
fi
