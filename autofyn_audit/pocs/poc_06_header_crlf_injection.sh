#!/usr/bin/env bash
# poc_06_header_crlf_injection.sh — CRLF / header injection via /redirect?url=...
#
# EXPECTED OUTCOME: PASS (CRLF injection blocked by Starlette URL encoding + uvicorn/h11
# header validation; no injected header materializes as a real response header).
#
# The /redirect endpoint returns RedirectResponse(url=url).
# Defense layers:
#   1. Starlette percent-encodes the Location header value (CR/LF become %0D/%0A).
#   2. uvicorn/h11 reject raw CR or LF characters in header field values with a 400.
# Either layer alone is sufficient to block CRLF injection; both are present.
#
# Attack: inject %0d%0a into the url parameter to attempt adding headers, e.g.:
#   url=/evil%0d%0aSet-Cookie:%20pwned=1
#   url=/evil%0d%0aX-Injected:%20yes
# These arrive as literal CRLF in the Python string (query string is URL-decoded by
# Starlette before the endpoint sees it). Starlette then re-encodes them into the
# Location value.
#
# Assertions:
#   - No "Set-Cookie: pwned" header line in the raw response.
#   - No "X-Injected:" header line in the raw response.
#   - Either a 3xx redirect OR a 4xx rejection (both are valid defenses).
#
# PASS = no injected header materialized as a real response header.
# FAIL = "Set-Cookie: pwned" or "X-Injected:" appears as an actual header line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
REDIRECT_URL="${BASE_URL}/redirect"

echo "=== poc_06: CRLF / header injection via /redirect?url=... ==="
echo "Endpoint : ${REDIRECT_URL}"
echo "Defense  : Starlette percent-encodes Location; uvicorn/h11 rejects raw CR/LF in headers"
echo ""

PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
# Confirms the endpoint is operational and returns a 3xx with Location: /health.
# -D - prints headers to stdout; -o /dev/null discards body; do NOT follow redirects.
echo "--- Positive control: /redirect?url=/health ---"
PC_HEADERS="$(curl -sS -D - -o /dev/null --max-time 10 \
    "${REDIRECT_URL}?url=%2Fhealth" 2>&1 || echo "CURL_FAILED")"
echo "Raw headers:"
echo "${PC_HEADERS}"
echo ""

PC_STATUS="$(echo "${PC_HEADERS}" | head -1 || echo "")"
echo "Status line: ${PC_STATUS}"

if assert_contains "${PC_HEADERS}" "Location"; then
    echo "[OK] Positive control: redirect endpoint returned a Location header"
else
    echo "[WARN] No Location header found — endpoint may not be returning a redirect"
    echo "       (Could be 4xx if /health is blocked; checking status code)"
    if assert_contains "${PC_STATUS}" " 3"; then
        echo "[OK] Status is 3xx — redirect working"
    else
        echo "[FAIL] Positive control: no 3xx and no Location header — endpoint may be broken"
        PASS=0
    fi
fi
echo ""

# ── Attack payloads ───────────────────────────────────────────────────────────
# Each payload encodes a CRLF sequence (%0d%0a) in the url parameter.
# The query string is URL-decoded by Starlette before the endpoint receives it,
# so the Python string contains literal CR+LF. Starlette must then re-encode or
# uvicorn/h11 must reject the header value.
#
# We capture the FULL raw response header block with -D - (dump headers to stdout).
# We do NOT follow redirects so we see the actual response to our request.

declare -a ATTACK_URLS=(
    "%2Fevil%0d%0aSet-Cookie:%20pwned=1"
    "%2Fevil%0d%0aX-Injected:%20yes"
    "%2Fevil%0d%0aSet-Cookie:%20pwned=1%0d%0aX-Other:%20injected"
)

declare -a ATTACK_LABELS=(
    "CRLF + Set-Cookie: pwned=1"
    "CRLF + X-Injected: yes"
    "CRLF + Set-Cookie + X-Other (chained)"
)

for i in "${!ATTACK_URLS[@]}"; do
    payload="${ATTACK_URLS[$i]}"
    label="${ATTACK_LABELS[$i]}"

    echo "--- Attack: ${label} ---"
    echo "Payload (url param value): ${payload}"

    RAW_RESP="$(curl -sS -D - -o /dev/null --max-time 10 \
        "${REDIRECT_URL}?url=${payload}" 2>&1 || echo "CURL_FAILED")"

    echo "Raw response headers:"
    echo "${RAW_RESP}"
    echo ""

    STATUS_LINE="$(echo "${RAW_RESP}" | head -1 || echo "")"
    echo "Status: ${STATUS_LINE}"

    # Primary assertion: injected headers must NOT appear as real header lines.
    # A header line is a standalone line starting with the header name.
    # We check for the specific injected header names.
    INJECTED_COOKIE="$(echo "${RAW_RESP}" | grep -i '^Set-Cookie:.*pwned' || echo "")"
    INJECTED_XHEADER="$(echo "${RAW_RESP}" | grep -i '^X-Injected:' || echo "")"

    if [[ -n "$INJECTED_COOKIE" ]]; then
        echo "[FAIL] INJECTED Set-Cookie header found: ${INJECTED_COOKIE}"
        PASS=0
    else
        echo "[OK] No 'Set-Cookie: pwned' header materialized"
    fi

    if [[ -n "$INJECTED_XHEADER" ]]; then
        echo "[FAIL] INJECTED X-Injected header found: ${INJECTED_XHEADER}"
        PASS=0
    else
        echo "[OK] No 'X-Injected:' header materialized"
    fi

    # Secondary: confirm the CRLF sequence was either encoded in Location or request rejected.
    # A 4xx response is also a valid defense (uvicorn/h11 rejected raw CR/LF).
    if assert_contains "${STATUS_LINE}" " 4" || assert_contains "${STATUS_LINE}" " 3"; then
        echo "[OK] Response is 3xx or 4xx — either redirect-with-encoding or rejection (both valid defenses)"
    else
        echo "[INFO] Unexpected status line: ${STATUS_LINE}"
    fi
    echo ""
done

# ── Verdict ───────────────────────────────────────────────────────────────────
echo "--- Verdict ---"
if (( PASS == 1 )); then
    print_check "header_crlf_injection_blocked" "PASS" \
        "no injected Set-Cookie or X-Injected header materialized; CRLF blocked by Starlette encoding and/or uvicorn/h11 validation"
else
    print_check "header_crlf_injection_blocked" "FAIL" \
        "injected header materialized as a real response header — CRLF injection succeeded"
fi
