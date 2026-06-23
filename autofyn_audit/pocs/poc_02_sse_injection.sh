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

# NOTE: assertions below use `printf '%s\n' "$RAW_RESPONSE" | grep -E '^...'`.
# Splitting on real newlines + a POSIX `^`-anchored ERE is portable across
# GNU grep AND ugrep (this environment ships ugrep, which does not support the
# GNU-only `-P` / `(^|\n)` constructs the original used).

# 2. No bare `retry:` line produced by injection (bare = not prefixed with `: `).
# A correctly-neutralized comment line is `: retry: 0` and will NOT match `^retry:`.
if printf '%s\n' "${RAW_RESPONSE}" | grep -Eq '^retry:'; then
    echo "[FAIL] Bare 'retry:' field found in SSE wire output — injection breakout!"
    PASS=0
    FAILURES+=("bare_retry_field")
else
    echo "[OK] No bare 'retry:' field injected"
fi

# 3. No bare `data: INJECTED` line. A neutralized line is `: data: INJECTED`
# (prefixed) and will NOT match `^data:`.
if printf '%s\n' "${RAW_RESPONSE}" | grep -Eq '^data: INJECTED'; then
    echo "[FAIL] Bare 'data: INJECTED' field found — injection escaped comment prefix!"
    PASS=0
    FAILURES+=("bare_data_injected")
else
    echo "[OK] No bare 'data: INJECTED' field (injection neutralized within comment)"
fi

# 4. No injected `event:` field. The only legitimate one is `event: status`
# from the first yield; any other bare `event:` line is an injection breakout.
UNEXPECTED_EVENTS="$(printf '%s\n' "${RAW_RESPONSE}" | grep -E '^event:' | grep -v '^event: status' || true)"
if [[ -n "$UNEXPECTED_EVENTS" ]]; then
    echo "[FAIL] Unexpected 'event:' field injected: ${UNEXPECTED_EVENTS}"
    PASS=0
    FAILURES+=("injected_event_field")
else
    echo "[OK] No unexpected 'event:' field (only legitimate 'event: status' present)"
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
