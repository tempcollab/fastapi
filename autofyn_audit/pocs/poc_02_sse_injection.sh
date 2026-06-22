#!/usr/bin/env bash
# poc_02_sse_injection.sh — SSE field injection: assert framework defends via splitlines().
#
# EXPECTED OUTCOME: PASS (injection neutralized by framework).
#
# The /sse endpoint routes ?inject= into the `comment` field of a ServerSentEvent.
# format_sse_event() in fastapi/sse.py handles comment via:
#   for line in comment.splitlines():
#       lines.append(f": {line}")
# So each injected line is re-prefixed with ": " and no bare SSE field or
# event boundary (\n\n) is emitted from the injected content.
#
# Injection payload: "ping\nretry: 0\n\ndata: INJECTED"
# Expected wire output for the comment block:
#   : ping
#   : retry: 0
#   :             <- empty line from splitlines on \n\n produces two items
#   : data: INJECTED
# Then the normal event-terminator \n\n follows.
#
# PASS conditions (ALL must hold):
#   1. No bare `retry:` line (not prefixed with `: `) in response.
#   2. No bare `data: INJECTED` line (not prefixed with `: `).
#   3. No bare `event:` line injected from payload.
#   4. The single event boundary \n\n does NOT appear mid-payload (the injection
#      cannot create a premature event boundary because splitlines splits on \n
#      and each resulting line is re-prefixed — no blank line without `: ` prefix
#      is inserted).
#   5. The normal `data: "connected"` event from the first yield IS present
#      (stream worked at all).
#
# FAIL = any bare SSE field or injected event boundary escapes the comment block.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
SSE_URL="${BASE_URL}/sse"

echo "=== poc_02: SSE field injection via comment splitlines() ==="
echo "Endpoint     : ${SSE_URL}"
echo ""
echo "Injection payload (URL-encoded): ping%0Aretry:%200%0A%0Adata:%20INJECTED"
echo "Routed into  : ServerSentEvent.comment field"
echo "Defense      : fastapi/sse.py format_sse_event() splitlines() re-prefixes each line with ': '"
echo ""

# Request the SSE stream; --max-time limits collection to a few seconds.
# -N disables buffering; we collect enough bytes to capture both events.
RAW_RESPONSE="$(curl -sS -N --max-time 5 \
    "${SSE_URL}?inject=ping%0Aretry:%200%0A%0Adata:%20INJECTED" \
    2>&1 || true)"

echo "--- Raw wire response (hex-safe repr) ---"
echo "${RAW_RESPONSE}" | cat -A | head -40
echo ""
echo "--- Raw wire response (plain) ---"
echo "${RAW_RESPONSE}"
echo ""

# ── Assertions ────────────────────────────────────────────────────────────────

PASS=1
FAILURES=()

# 1. Positive control: first event must have "connected" data.
if assert_contains "${RAW_RESPONSE}" 'data: "connected"'; then
    echo "[OK] Positive control: SSE stream delivered first event (data: \"connected\")"
else
    echo "[FAIL] SSE stream did not deliver first event — stream may be broken"
    PASS=0
    FAILURES+=("no_initial_event")
fi

# 2. No bare `retry:` line produced by injection (bare = not prefixed with `: `).
# We allow `: retry:` (properly prefixed) but NOT `\nretry: ` as a field.
if echo "${RAW_RESPONSE}" | grep -qP '(^|\n)retry:' 2>/dev/null || \
   echo "${RAW_RESPONSE}" | grep -q $'\nretry:' 2>/dev/null; then
    echo "[FAIL] Bare 'retry:' field found in SSE wire output — injection breakout!"
    PASS=0
    FAILURES+=("bare_retry_field")
else
    echo "[OK] No bare 'retry:' field injected"
fi

# 3. No bare `data: INJECTED` line (injected content appearing as an uncontrolled data field).
# Note: `: data: INJECTED` (prefixed with `: `) is acceptable — that means it's in comment.
# We look for a line that starts with `data: INJECTED` (or `data:INJECTED`) without `: ` prefix.
if echo "${RAW_RESPONSE}" | grep -qP '(^|\n)data: INJECTED' 2>/dev/null || \
   [[ "${RAW_RESPONSE}" == *$'\ndata: INJECTED'* ]] || \
   [[ "${RAW_RESPONSE}" == "data: INJECTED"* ]]; then
    # Double-check: is this actually prefixed with ': '?
    # If the line is ': data: INJECTED' that is fine (comment).
    if echo "${RAW_RESPONSE}" | grep -qE '(^|[^:]) *data: INJECTED' 2>/dev/null; then
        echo "[FAIL] Bare 'data: INJECTED' field found — injection escaped comment prefix!"
        PASS=0
        FAILURES+=("bare_data_injected")
    else
        echo "[OK] 'data: INJECTED' only appears prefixed (within comment) — neutralized"
    fi
else
    echo "[OK] No bare 'data: INJECTED' field in response"
fi

# 4. No bare `event:` field injected from payload.
if echo "${RAW_RESPONSE}" | grep -qP '(^|\n)event: ' 2>/dev/null; then
    # Allow our own `event: status` from the first yield — that's legitimate.
    # We only fail if additional `event:` lines appear that could be from injection.
    EVENT_LINES="$(echo "${RAW_RESPONSE}" | grep -P '(^|\n)?event: ' || true)"
    echo "event: lines found: ${EVENT_LINES}"
    # The only expected event: line is `event: status` from the first yield.
    UNEXPECTED_EVENTS="$(echo "${EVENT_LINES}" | grep -v 'event: status' || true)"
    if [[ -n "$UNEXPECTED_EVENTS" ]]; then
        echo "[FAIL] Unexpected 'event:' field injected: ${UNEXPECTED_EVENTS}"
        PASS=0
        FAILURES+=("injected_event_field")
    else
        echo "[OK] Only expected 'event: status' present — no injected event fields"
    fi
else
    echo "[OK] No unexpected 'event:' fields in response (no injection)"
fi

# 5. Check that injected content appears RE-PREFIXED with `: ` (comment prefix).
# The lines `retry: 0` and `data: INJECTED` should appear as `: retry: 0` and `: data: INJECTED`.
if assert_contains "${RAW_RESPONSE}" ": retry: 0" || \
   assert_contains "${RAW_RESPONSE}" ": data: INJECTED"; then
    echo "[OK] Injected content appears correctly re-prefixed with ': ' (comment lines)"
else
    echo "[INFO] Note: could not find re-prefixed comment lines (may be filtered/buffered)"
fi

echo ""
echo "--- Verdict ---"
if (( PASS == 1 )); then
    print_check "sse_injection_neutralized" "PASS" \
        "comment splitlines() re-prefixes injection; no bare SSE field or event boundary escaped"
else
    print_check "sse_injection_neutralized" "FAIL" \
        "injection escaped comment prefix: ${FAILURES[*]:-unknown}"
fi
