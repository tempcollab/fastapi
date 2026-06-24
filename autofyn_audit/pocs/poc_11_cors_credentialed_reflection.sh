#!/usr/bin/env bash
# poc_11_cors_credentialed_reflection.sh — Starlette CORSMiddleware reflects an
# arbitrary attacker Origin together with Access-Control-Allow-Credentials: true
# when configured with allow_origins=["*"] AND allow_credentials=True.
#
# ── Sink ─────────────────────────────────────────────────────────────────────
#   starlette/middleware/cors.py (CORSMiddleware):
#     __init__: when "*" in allow_origins AND allow_credentials is True,
#               allow_all_origins is True but the simple-response path takes the
#               "explicit origin" branch (allow_explicit_origin) instead of
#               emitting the literal "*", because the spec forbids
#               "ACAO: * + ACAC: true". So it REFLECTS the request Origin verbatim
#               into Access-Control-Allow-Origin and adds
#               Access-Control-Allow-Credentials: true.
#     send (preflight & simple): self.simple_headers / allow_explicit_origin set
#               headers["Access-Control-Allow-Origin"] = <request Origin>.
#
# ── Source / data flow ───────────────────────────────────────────────────────
#   Attacker-controlled `Origin` request header
#     → CORSMiddleware reads scope Origin
#     → reflected verbatim into Access-Control-Allow-Origin response header
#     → Access-Control-Allow-Credentials: true also emitted
#     → a browser therefore permits attacker-origin JS to read the credentialed
#       (cookie/Authorization-gated) response body cross-origin.
#
# ── Precondition (PROMINENT — do NOT overstate exploitability) ────────────────
#   CONFIGURATION-DEPENDENT. Exploitable ONLY when the developer explicitly sets
#   BOTH CORSMiddleware(allow_origins=["*"], allow_credentials=True). Both
#   Starlette defaults are SAFE (allow_credentials defaults False; with default
#   credentials off, "*" is emitted literally and browsers block credentialed
#   reads). This is a framework FOOT-GUN, not a default-config remote exploit:
#   Starlette SILENTLY produces the dangerous reflective behavior — no error, no
#   warning — when these two options are combined, which a developer may believe
#   is browser-safe because of the "ACAO: * + ACAC: true" browser rule.
#
# ── PASS/FAIL semantics (FINDING check — same convention as poc_07..10) ───────
#   FAIL = confirmed finding (arbitrary Origin reflected with ACAC: true).
#   PASS = defense held / inconclusive (see verdict logic below).
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT (against the dedicated
#   /cors-protected sub-app configured with the foot-gun combination).
#   A FAIL here is correct, valid audit output — NOT a harness bug.
#
# ── Severity ─────────────────────────────────────────────────────────────────
#   MEDIUM-conditional. Cross-origin disclosure of credentialed responses, but
#   gated entirely on the developer opting into the unsafe config combination.
#   No RCE. Upstream (Starlette) behavior, surfaced through FastAPI's re-exported
#   fastapi.middleware.cors.CORSMiddleware.
#
# ── Independence from poc_07/08/09/10 ─────────────────────────────────────────
#   Source: attacker `Origin` request header — distinct from X-Forwarded-Prefix
#           (poc_07/08), Host (poc_09), multipart body (poc_10).
#   Sink:   starlette/middleware/cors.py response-header construction — distinct
#           from docs.py / applications.py / routing.py / formparsers.py.
#   Class:  CORS credentialed cross-origin disclosure — distinct from XSS /
#           URL-injection / open-redirect / disk DoS.
#   Fix-orthogonal to all four.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
# Trailing slash: the sub-app is mounted at /cors-protected and its route is "/".
CORS_URL="${BASE_URL}/cors-protected/"

# Unique attacker origin marker — deliberately DISTINCT from poc_08/poc_09's
# "autofyn-evil.example" so this PoC cannot contaminate their teeth-tests and
# they cannot contaminate this one.
EVIL_ORIGIN="https://attacker.cors-poc11.example"

echo "=== poc_11: CORSMiddleware credentialed Origin reflection (starlette/middleware/cors.py) ==="
echo "Endpoint    : ${CORS_URL}"
echo "Sink        : starlette/middleware/cors.py (allow_origins=['*'] + allow_credentials=True reflects Origin + ACAC:true)"
echo "Severity    : MEDIUM-conditional — config-dependent foot-gun; cross-origin credentialed disclosure; upstream (Starlette)"
echo "Expected    : FAIL (attacker Origin reflected into ACAO with ACAC:true; no-Origin request emits no ACAO)"
echo ""

# ── Teeth-test / positive control: NO Origin header — MUST NOT reflect ────────
# CORSMiddleware is inert when there is no Origin header (it passes the response
# through unchanged). If an ACAO header appears here, the environment is adding
# CORS headers unconditionally and we cannot attribute reflection to the Origin
# → self-downgrade to PASS/inconclusive.
echo "--- Teeth-test (no Origin): GET ${CORS_URL} without Origin — expect NO Access-Control-Allow-Origin ---"
NOORIGIN_HDRS="$(curl -sS -D - -o /dev/null \
    --max-time 15 \
    "${CORS_URL}" 2>&1 || echo "CURL_FAILED")"
echo "Response headers (no Origin):"
printf '%s\n' "${NOORIGIN_HDRS}"
echo ""

NOORIGIN_HAS_ACAO=0
# Header names are case-insensitive; lower-case the haystack before matching.
NOORIGIN_LC="$(printf '%s' "${NOORIGIN_HDRS}" | tr '[:upper:]' '[:lower:]')"
if assert_contains "${NOORIGIN_LC}" "access-control-allow-origin"; then
    NOORIGIN_HAS_ACAO=1
    echo "[WARN] Teeth-test: ACAO present even WITHOUT an Origin header — CORS headers added unconditionally."
    echo "       Cannot attribute reflection to the attacker Origin → inconclusive."
else
    echo "[OK] Teeth-test: no Access-Control-Allow-Origin emitted for an Origin-less request (CORSMiddleware inert)."
fi
echo ""

# ── Exploit: attacker Origin — expected reflected + ACAC:true ─────────────────
echo "--- Exploit: GET ${CORS_URL} with Origin: ${EVIL_ORIGIN} — expect ACAO:${EVIL_ORIGIN} + ACAC:true ---"
EVIL_HDRS="$(curl -sS -D - -o /tmp/poc11_body.txt \
    -H "Origin: ${EVIL_ORIGIN}" \
    --max-time 15 \
    "${CORS_URL}" 2>&1 || echo "CURL_FAILED")"
EVIL_BODY="$(cat /tmp/poc11_body.txt 2>/dev/null || echo "")"
echo "Response headers (attacker Origin):"
printf '%s\n' "${EVIL_HDRS}"
echo "Response body: ${EVIL_BODY}"
echo ""
rm -f /tmp/poc11_body.txt

EVIL_LC="$(printf '%s' "${EVIL_HDRS}" | tr '[:upper:]' '[:lower:]')"
EVIL_ORIGIN_LC="$(printf '%s' "${EVIL_ORIGIN}" | tr '[:upper:]' '[:lower:]')"

REFLECTED=0
if assert_contains "${EVIL_LC}" "access-control-allow-origin: ${EVIL_ORIGIN_LC}"; then
    REFLECTED=1
    echo "[OK] Exploit: Access-Control-Allow-Origin reflects the attacker Origin (${EVIL_ORIGIN})."
else
    echo "[INFO] Exploit: attacker Origin NOT reflected into Access-Control-Allow-Origin."
fi

ACAC_TRUE=0
if assert_contains "${EVIL_LC}" "access-control-allow-credentials: true"; then
    ACAC_TRUE=1
    echo "[OK] Exploit: Access-Control-Allow-Credentials: true present alongside the reflected Origin."
else
    echo "[INFO] Exploit: Access-Control-Allow-Credentials: true NOT present."
fi
echo ""

# ── Verdict logic ─────────────────────────────────────────────────────────────
echo "--- Verdict ---"

if (( NOORIGIN_HAS_ACAO == 1 )); then
    # Cannot attribute the reflection to the Origin — downgrade.
    print_check "cors_credentialed_origin_reflection" "PASS" \
        "inconclusive: Access-Control-Allow-Origin emitted even without an Origin header in this environment; cannot attribute reflection to the attacker Origin"

elif (( REFLECTED == 1 )) && (( ACAC_TRUE == 1 )); then
    # Both arms confirmed: arbitrary Origin reflected AND credentials allowed.
    print_check "cors_credentialed_origin_reflection" "FAIL" \
        "CORSMiddleware reflected attacker Origin '${EVIL_ORIGIN}' into Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true (allow_origins=['*'] + allow_credentials=True) — browser permits attacker-origin JS to read credentialed responses cross-origin; MEDIUM-conditional config-dependent foot-gun; starlette/middleware/cors.py; upstream-inherited"

else
    # Reflection or ACAC not observed — defense effectively held.
    print_check "cors_credentialed_origin_reflection" "PASS" \
        "no credentialed Origin reflection observed (reflected=${REFLECTED}, acac_true=${ACAC_TRUE}); CORS foot-gun not demonstrated in this environment"
fi
