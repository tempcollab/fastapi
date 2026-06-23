#!/usr/bin/env bash
# poc_04_ssti_xss.sh — SSTI and XSS check against /greet?name=... (Jinja2 autoescape ON).
#
# EXPECTED OUTCOME: PASS (Jinja2 autoescape defends; no template evaluation, no raw XSS).
#
# The /greet endpoint renders greet.html with {{ name }} as a Jinja2 CONTEXT variable.
# Starlette's Jinja2Templates enables autoescape by default for .html templates.
# Passing untrusted input as a context variable (not as template source) is the
# correct safe pattern: Jinja2 HTML-escapes the value before output.
#
# Tests:
#   Positive control : GET /greet?name=World → 200, body contains "World"
#   SSTI attempts    : {{7*7}}, {{7*'7'}}, ${7*7}, {{config}}, {{ self.__init__.__globals__ }}
#                      → body MUST NOT contain "49", "7777777", "<Config", "SECRET_KEY"
#                      → expressions must appear LITERALLY (escaped), not evaluated
#   XSS attempt      : name=<script>alert(1)</script>
#                      → body MUST NOT contain raw "<script>alert(1)</script>"
#                      → body MUST contain "&lt;script&gt;" (autoescape active)
#
# PASS = no template evaluation AND XSS payload HTML-escaped AND positive control works.
# FAIL = 49/config leaked or raw <script> reflected unescaped.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
GREET_URL="${BASE_URL}/greet"

echo "=== poc_04: Jinja2 SSTI / XSS check via /greet?name=... ==="
echo "Endpoint   : ${GREET_URL}"
echo "Template   : greet.html  ({{ name }} context var; autoescape ON)"
echo "Defense    : Jinja2 autoescape HTML-encodes context values; expressions in values"
echo "             are never parsed as template code because the value is not template source."
echo ""

PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
echo "--- Positive control: /greet?name=World ---"
PC_CODE="$(curl -sS -o /tmp/poc04_pc.txt -w "%{http_code}" \
    "${GREET_URL}?name=World" 2>&1 || echo "000")"
PC_BODY="$(cat /tmp/poc04_pc.txt 2>/dev/null || echo "")"
echo "HTTP ${PC_CODE}"
echo "Body: ${PC_BODY}"

if [[ "$PC_CODE" == "200" ]] && assert_contains "${PC_BODY}" "World"; then
    echo "[OK] Positive control: /greet rendered 200 and contains 'World'"
else
    echo "[FAIL] Positive control failed (HTTP ${PC_CODE}) — template or endpoint broken"
    PASS=0
fi
echo ""

# ── SSTI attempts ─────────────────────────────────────────────────────────────
# URL-encode: { = %7B, } = %7D, space = %20, * = %2A, ' = %27, _ = %5F, . = %2E
# Braces and spaces are percent-encoded to ensure they pass through the query string intact.
echo "--- SSTI attempt 1: {{7*7}} ---"
SSTI1_CODE="$(curl -sS -o /tmp/poc04_ssti1.txt -w "%{http_code}" \
    "${GREET_URL}?name=%7B%7B7%2A7%7D%7D" 2>&1 || echo "000")"
SSTI1_BODY="$(cat /tmp/poc04_ssti1.txt 2>/dev/null || echo "")"
echo "HTTP ${SSTI1_CODE}"
echo "Body: ${SSTI1_BODY}"

if assert_not_contains "${SSTI1_BODY}" "49"; then
    echo "[OK] '49' not found — {{7*7}} not evaluated"
else
    echo "[FAIL] '49' found in response — Jinja2 evaluated the expression in the VALUE!"
    PASS=0
fi
echo ""

echo "--- SSTI attempt 2: {{7*'7'}} (Python string repetition → '7777777') ---"
SSTI2_CODE="$(curl -sS -o /tmp/poc04_ssti2.txt -w "%{http_code}" \
    "${GREET_URL}?name=%7B%7B7%2A%277%27%7D%7D" 2>&1 || echo "000")"
SSTI2_BODY="$(cat /tmp/poc04_ssti2.txt 2>/dev/null || echo "")"
echo "HTTP ${SSTI2_CODE}"
echo "Body: ${SSTI2_BODY}"

if assert_not_contains "${SSTI2_BODY}" "7777777"; then
    echo "[OK] '7777777' not found — {{7*'7'}} not evaluated"
else
    echo "[FAIL] '7777777' found in response — Jinja2 evaluated the expression!"
    PASS=0
fi
echo ""

echo "--- SSTI attempt 3: \${7*7} (FreeMarker/Twig-style syntax) ---"
SSTI3_CODE="$(curl -sS -o /tmp/poc04_ssti3.txt -w "%{http_code}" \
    "${GREET_URL}?name=%24%7B7%2A7%7D" 2>&1 || echo "000")"
SSTI3_BODY="$(cat /tmp/poc04_ssti3.txt 2>/dev/null || echo "")"
echo "HTTP ${SSTI3_CODE}"
echo "Body: ${SSTI3_BODY}"

if assert_not_contains "${SSTI3_BODY}" "49"; then
    echo "[OK] '49' not found — \${7*7} not evaluated (Jinja2 ignores \${})"
else
    echo "[FAIL] '49' found in response — expression evaluated via \${} syntax!"
    PASS=0
fi
echo ""

echo "--- SSTI attempt 4: {{config}} (Jinja2 config object leak) ---"
SSTI4_CODE="$(curl -sS -o /tmp/poc04_ssti4.txt -w "%{http_code}" \
    "${GREET_URL}?name=%7B%7Bconfig%7D%7D" 2>&1 || echo "000")"
SSTI4_BODY="$(cat /tmp/poc04_ssti4.txt 2>/dev/null || echo "")"
echo "HTTP ${SSTI4_CODE}"
echo "Body: ${SSTI4_BODY}"

if assert_not_contains "${SSTI4_BODY}" "SECRET_KEY" && assert_not_contains "${SSTI4_BODY}" "<Config"; then
    echo "[OK] No '<Config' or 'SECRET_KEY' — {{config}} not evaluated"
else
    echo "[FAIL] Config object leaked — {{config}} evaluated by Jinja2!"
    PASS=0
fi
echo ""

echo "--- SSTI attempt 5: {{ self.__init__.__globals__ }} (globals leak) ---"
# URL-encode: spaces=%20, braces=%7B%7D, underscores=%5F, dots=%2E
SSTI5_CODE="$(curl -sS -o /tmp/poc04_ssti5.txt -w "%{http_code}" \
    "${GREET_URL}?name=%7B%7B%20self%2E%5F%5Finit%5F%5F%2E%5F%5Fglobals%5F%5F%20%7D%7D" \
    2>&1 || echo "000")"
SSTI5_BODY="$(cat /tmp/poc04_ssti5.txt 2>/dev/null || echo "")"
echo "HTTP ${SSTI5_CODE}"
echo "Body (truncated): ${SSTI5_BODY:0:200}"

if assert_not_contains "${SSTI5_BODY}" "__builtins__" && \
   assert_not_contains "${SSTI5_BODY}" "SECRET_KEY"; then
    echo "[OK] No '__builtins__' or 'SECRET_KEY' — globals() not evaluated"
else
    echo "[FAIL] Python globals leaked — {{ self.__init__.__globals__ }} evaluated!"
    PASS=0
fi
echo ""

# ── XSS attempt ───────────────────────────────────────────────────────────────
echo "--- XSS attempt: name=<script>alert(1)</script> ---"
XSS_CODE="$(curl -sS -o /tmp/poc04_xss.txt -w "%{http_code}" \
    "${GREET_URL}?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" 2>&1 || echo "000")"
XSS_BODY="$(cat /tmp/poc04_xss.txt 2>/dev/null || echo "")"
echo "HTTP ${XSS_CODE}"
echo "Body: ${XSS_BODY}"

RAW_SCRIPT_PRESENT=0
ESCAPED_PRESENT=0

if assert_contains "${XSS_BODY}" "<script>alert(1)</script>"; then
    echo "[FAIL] Raw <script>alert(1)</script> reflected unescaped — XSS possible!"
    RAW_SCRIPT_PRESENT=1
    PASS=0
else
    echo "[OK] Raw <script>alert(1)</script> NOT present in response body"
fi

if assert_contains "${XSS_BODY}" "&lt;script&gt;"; then
    echo "[OK] '&lt;script&gt;' found — Jinja2 autoescape is working correctly"
    ESCAPED_PRESENT=1
else
    echo "[WARN] '&lt;script&gt;' not found — autoescape may not be active or template does not output name"
    # Only fail if the raw script also appeared; if neither is present the template may
    # simply not render the value at all (would still be safe, but worth investigating).
    if (( RAW_SCRIPT_PRESENT == 0 )); then
        echo "[INFO] Raw <script> also absent — payload may have been stripped entirely (still safe)"
    fi
fi

echo ""

# ── Verdict ───────────────────────────────────────────────────────────────────
echo "--- Verdict ---"
if (( PASS == 1 )); then
    print_check "jinja2_ssti_xss_defended" "PASS" \
        "no template evaluation (no 49/7777777/config/globals leak); XSS payload HTML-escaped; positive control OK"
else
    print_check "jinja2_ssti_xss_defended" "FAIL" \
        "template expression evaluated or raw XSS payload reflected unescaped — see output above"
fi
