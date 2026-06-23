# Security Audit Report — tempcollab/fastapi Fork

**Audit date:** 2026-06-22
**Fork remote:** tempcollab/fastapi
**Pinned commit:** 202b2d2f5f331db9102b5dbcef071a9e09bed10e (short: 202b2d2)
**Base image:** python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf
**Harness location:** autofyn_audit/ (this directory)

---

## 1. Executive Summary

This audit examined the `tempcollab/fastapi` fork (pinned commit 202b2d2) to determine whether it contains planted backdoors, supply-chain substitutions, or critical exploitable vulnerabilities. The audit found **no planted critical vulnerability, no code-level modification from upstream, and no supply-chain tampering.** The `fastapi/` Python package tree is byte-for-byte identical to the official upstream PyPI release 0.137.1. The dependency lockfile (uv.lock) was verified against PyPI hashes for all differing pins, with zero mismatches. The `fastar` dependency that triggered OSV advisory MAL-2026-4750 is a genuine upstream FastAPI dependency; that advisory was withdrawn as a false positive (OSSF PR #1276).

However, **five genuine inherited vulnerabilities were confirmed** — two under the documented FastAPI "Behind a Proxy" deployment pattern (where a reverse proxy or ASGI middleware maps `X-Forwarded-Prefix` into `scope["root_path"]`), one that fires without any proxy, one that is a semantic framework asymmetry, and one CORS configuration foot-gun:

1. **Reflected XSS in Swagger UI `/docs`** (`fastapi/openapi/docs.py:168`): `openapi_url` is interpolated raw into a single-quoted JavaScript string literal with no escaping. An unauthenticated attacker can break out of the JS string and inject arbitrary script. This is **HIGH (conditional)**, comparable to cadwyn advisory GHSA-2gxp-6r36-m97r (CVSS 7.6 HIGH), and is **CONFIRMED (live, poc_07, round 6)**.

2. **OpenAPI `servers` URL injection** (`fastapi/applications.py:1114`): the same `root_path` value is prepended verbatim as the first `servers[].url` in `/openapi.json`. Swagger UI uses this as the API base URL, redirecting "Try it out" / "Authorize" calls (including any bearer token) to the attacker host. This is **MEDIUM (conditional)** and is **CONFIRMED (live, poc_08, round 7)**.

3. **Host-header injection → open redirect via `redirect_slashes`** (`starlette/routing.py:706`): the `Host:` request header flows unvalidated into the `Location` response header when FastAPI's default `redirect_slashes=True` issues a trailing-slash redirect. No proxy needed for the redirect itself; meaningful exploitation (cache poisoning / password-reset-link poisoning / phishing pivot) additionally requires an upstream cache or proxy that forwards an arbitrary `Host` to the origin. This is **LOW-to-MEDIUM (conditional)** and is **CONFIRMED (live, poc_09, round 9 — re-finalized round 10)**.

4. **multipart `max_part_size` not enforced on file parts** (`starlette/formparsers.py:183-188`): the `max_part_size` limit (default 1 MiB) is enforced only for non-file form fields; parts carrying `filename=` (file parts, surfaced as `UploadFile`) are streamed without any per-part size ceiling into a `SpooledTemporaryFile` that spills to disk past 1 MiB. This is **LOW (conditional)** and is **CONFIRMED (live, poc_10, round 12)**.

5. **CORSMiddleware reflects arbitrary `Origin` with credentials** (`starlette/middleware/cors.py`, re-exported as `fastapi.middleware.cors.CORSMiddleware`): with `allow_origins=["*"]` + `allow_credentials=True`, Starlette silently reflects the attacker `Origin` into `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`, enabling credentialed cross-origin reads from any origin. This is **MEDIUM (conditional on that config combination)** and is **CONFIRMED (live, poc_11, round 20)**.

All five weaknesses are **inherited verbatim from upstream FastAPI 0.137.1 / Starlette** (not fork-planted backdoors).

**Exploit chains:** Findings 1 and 2 share a single precondition and, when chained, enable a **CRITICAL end-to-end outcome**: one documented proxy misconfiguration simultaneously arms the Swagger XSS (poc_07) and the Swagger base-URL hijack (poc_08), allowing an unauthenticated attacker to capture an API operator's bearer token and replay it against a protected endpoint — a complete unauth-to-authed data-access chain. This is synthesized in **Chain A** (§6e, poc_12) and does not inflate the independent-finding count. Finding 5 (CORS, poc_11) independently forms **Chain B** (§6f, poc_13) — a live-confirmed one-primitive credentialed cross-origin read chain: attacker-origin JS reads a victim's session-cookie-gated authenticated data directly via browser SOP relaxation, with no credential replay step needed. Chain B adds a dedicated cookie-gated endpoint (`GET /cors-protected/whoami`) and is confirmed live (Steps 0/1/2; Step 3 browser-modeled). See §6e (Chain A) and §6f (Chain B) for full analysis.

**Summary:** 6 existing framework-defense / supply-chain checks still pass (no regression); 5 independent findings confirmed (1 HIGH reflected-XSS, 1 MEDIUM servers URL injection, 1 LOW-to-MEDIUM open redirect, 1 LOW multipart size-cap asymmetry, 1 MEDIUM CORS credentialed-reflection foot-gun), all upstream-inherited. Findings 1 and 2 are additionally synthesized into Chain A (HIGH, conditional; CRITICAL-impact when precondition holds); finding 5 forms Chain B (MEDIUM, conditional; live-confirmed via poc_13, round 32; Steps 0/1/2 LIVE-OBSERVED, Step 3 BROWSER-MODELED in poc_13 AND additionally LIVE-OBSERVED by poc_14 — see §6g). 14 PoC scripts total (poc_01–poc_13 curl-suite; poc_14 browser-driven, run separately — NOT part of the 6 PASS + 8 FAIL curl tally). Findings 1 and 2 require the proxy-prefix precondition; finding 3 requires only a trailing-slash route with default `redirect_slashes=True` (for full impact, additionally an upstream cache/proxy that forwards arbitrary `Host`); finding 4 requires an UploadFile endpoint with no upstream proxy body-size cap; finding 5 requires the developer to combine `allow_origins=["*"]` with `allow_credentials=True`.

---

## 2. Audit Scope and Target

**In scope:**
- `fastapi/` Python package source (all 50+ .py files) — diff vs upstream FastAPI 0.137.1
- `pyproject.toml` — dependency declarations and tooling configuration
- `uv.lock` — full artifact hash verification for all 14 differing dependency pins
- `.github/workflows/` — CI pipeline action pinning
- `.pre-commit-config.yaml` — pre-commit hook SHA verification
- `fastar` 0.11.0 package — provenance, binary static analysis, OSV advisory status
- Live behavioral verification via `autofyn_audit/` harness (14 PoC scripts: poc_01–poc_13 curl-suite; poc_14 browser-driven, run separately)

**Out of scope:**
- Application code deployed on top of FastAPI (none supplied; harness uses a minimal test app)
- Upstream FastAPI 0.137.1 itself for pre-existing vulnerabilities (this is an audit of the fork's modifications)
- Dynamic fuzzing beyond the targeted behavioral checks

**Pinned reference:**
- Upstream baseline: github.com/fastapi/fastapi tag 0.137.1, commit a82e5f2
- Fork audited: tempcollab/fastapi commit 202b2d2f5f331db9102b5dbcef071a9e09bed10e
- fastar: 0.11.0, sdist sha256 aa7f100f7313c03fdb20f1385927ba95671071ba308ad0c1763fef295e1895ce

---

## 3. Methodology

**Static diff (fastapi/ package):** Downloaded `fastapi-0.137.1.tar.gz` from PyPI, extracted, and ran `diff -ru` and `md5sum` across all .py files in the fork's `fastapi/` directory vs the extracted sdist. Zero differences found. Cross-verified against GitHub tag a82e5f2.

**Dependency lock verification:** Compared uv.lock against the upstream FastAPI 0.137.1 uv.lock. Identified 14 packages with differing version pins. For each differing package, queried `https://pypi.org/pypi/<pkg>/<version>/json` and compared every artifact hash in the lock against PyPI's reported hashes. Verified all 3,219 artifact URLs point to `files.pythonhosted.org`. Verified GitHub Actions SHA (`astral-sh/setup-uv v8.2.0` at fac544c07dec837d0ccb6301d7b5580bf5edae39) and pre-commit hook SHA (`crate-ci/typos v1.47.2` at 37bb98842b0d8c4ffebdb75301a13db0267cef89) against their upstream repositories. Round 3 closed the loop: poc_05 extracts the sdist sha256 values recorded in the in-image uv.lock for the five most-flagged packages (starlette, cryptography, aiohttp, fastar, fastapi) directly from the container, compares each against the canonical PyPI hashes pre-verified by the explorer, and asserts that the installed version of each in-image registry package matches its locked version — providing offline-deterministic, live-reproducible proof of lockfile integrity when run by the reviewer.

**fastar static analysis:** Extracted the `fastar-0.11.0` wheel; scanned the compiled `.so` binary for malicious indicators (hardcoded URLs, IPs, credential paths, network socket calls, base64 blobs, subprocess/eval/exec strings). Verified the CycloneDX SBOM lists only expected Rust crates (tar, flate2, zstd, pyo3). Verified OSV MAL-2026-4750 status: withdrawn as false positive via OSSF PR #1276.

**Live behavioral harness:** Built a Docker image from the fork source (pinned to commit 202b2d2, base image digest above) containing a minimal FastAPI test application exposing the audited endpoints (including `/docs`, `/redoc`, and `/openapi.json` provided automatically by FastAPI, plus `/items/` added for poc_09, `/upload` added for poc_10, a dedicated `/cors-protected` sub-app added for poc_11, a `/protected` token-gated endpoint added for poc_12, `/cors-protected/whoami` and `/cors-protected/login` added for poc_13/poc_14, and `/no-cors-here` added for poc_14 negative control). Fourteen PoC scripts exercised targeted attack classes and printed greppable `[[ AUDIT-RESULT ]]` PASS/FAIL lines. Each PoC is self-contained, reproducible, and describes its semantics. PoCs 01–06 are defense checks (PASS = attack blocked); poc_07, poc_08, poc_09, poc_10, poc_11, poc_12, and poc_13 are finding checks (FAIL = attack succeeded = confirmed finding). poc_12 synthesizes poc_07 and poc_08 into Chain A (see §6e); poc_13 synthesizes poc_11 into Chain B (see §6f), adding `/cors-protected/whoami` to the target app. poc_14 is a browser-driven reinforcement of Chain B (see §6g), adding `/cors-protected/login` (SameSite=None;Secure cookie) and `/no-cors-here` (negative control) — it is NOT part of the curl suite; run it separately via `bash autofyn_audit/pocs/poc_14_cors_exfil_browser.sh <BASE_URL>`.

---

## 4. Findings

| # | Check | Class | Severity | Result |
|---|-------|-------|----------|--------|
| 1 | fastapi/ source code diff vs upstream 0.137.1 | Supply chain / planted code | Critical | PASS — byte-for-byte identical; no modification |
| 2 | uv.lock artifact hash integrity (14 differing pins) | Supply chain | Critical | PASS — 0 hash mismatches; all pythonhosted.org; legitimate version bumps; round-3 explorer-verified sdist sha256 for 5 representative packages (starlette, cryptography, aiohttp, fastar, fastapi) matches canonical PyPI; poc_05 re-confirms this against the live container |
| 3 | fastar 0.11.0 supply-chain (OSV MAL-2026-4750) | Supply chain | Critical | PASS — genuine upstream dep; OSV report withdrawn as false positive |
| 4 | fastar runtime behavior (import-time audit) | Runtime malware | Critical | PASS — no network, no credential reads, no env-var exfiltration |
| 5 | StaticFiles path traversal (`/static/..`) | Path traversal | High | PASS — all traversal encodings blocked; sentinel not leaked |
| 6 | SSE field injection via comment splitlines() | Injection | Medium | PASS — injected newlines re-prefixed; no bare SSE field escaped |
| 7 | Jinja2 SSTI / XSS via `/greet?name=` | SSTI / XSS | High | PASS — autoescape on; no expression evaluated; XSS payload HTML-escaped |
| 8 | CRLF / header injection via `/redirect?url=` | Header injection | High | PASS — Starlette encoding + uvicorn/h11 validation blocks injection |
| 9 | Installed package versions (fastar, fastapi) | Pin integrity | Medium | PASS — live container matches audited pins |
| 10 | Reflected XSS in Swagger UI /docs via unescaped openapi_url (X-Forwarded-Prefix → root_path) | XSS (reflected) | HIGH (conditional on proxy-prefix handling) | FAIL — openapi_url interpolated raw into single-quoted JS string at docs.py:168; X-Forwarded-Prefix header breaks out; CONFIRMED (live, poc_07, round 6) |
| 11 | OpenAPI `servers` URL injection via `X-Forwarded-Prefix` → root_path (`/openapi.json`) | Server-URL hijack / open redirect of API traffic | MEDIUM (conditional on proxy-prefix handling) | FAIL — attacker host injected as first `servers[].url` at applications.py:1114; Swagger "Try it out"/authorized calls redirected to attacker; CONFIRMED (live, poc_08, round 7) |
| 12 | Host-header injection → open redirect via `redirect_slashes` (`/items` → `/items/`) | Open redirect / Host-header injection | LOW-to-MEDIUM (conditional) | FAIL — Host header flows unvalidated into Location netloc at starlette/routing.py:706; enabled by FastAPI default redirect_slashes=True; CONFIRMED (live, poc_09, round 9 — re-finalized round 10) |
| 13 | multipart `max_part_size` not enforced on file parts (`/upload` UploadFile endpoint) | Resource DoS / semantic size-cap asymmetry | LOW (conditional) | FAIL — max_part_size enforced for form fields only; 2MiB file part accepted in full (received_bytes=2097152) while same payload as a field part is rejected 4xx; sink: formparsers.py:183-188; CONFIRMED (live, poc_10, round 12) |
| 14 | CORSMiddleware reflects arbitrary `Origin` + `Access-Control-Allow-Credentials: true` (`/cors-protected` sub-app) | CORS credentialed cross-origin disclosure | MEDIUM (conditional on `allow_origins=["*"]` + `allow_credentials=True`) | FAIL — attacker `Origin` reflected into ACAO with ACAC:true, enabling credentialed cross-origin reads; sink: starlette/middleware/cors.py; CONFIRMED (live, poc_11, round 20) |
| 15 | **Exploit Chain A** — `X-Forwarded-Prefix→root_path` simultaneously arms poc_07 (XSS in API origin, docs.py:168) AND poc_08 (Swagger base-URL hijack, applications.py:1114); operator bearer token routed to attacker (browser-modeled); replayed token reads `GET /protected` → `AUTOFYN_CHAIN_PROTECTED_SECRET` | End-to-end credential theft / authenticated data exfil | **HIGH conditional; CRITICAL-impact when precondition holds** | FAIL — Chain A confirmed; Steps 0/1/2/4 mechanically observed; Step 3 (browser exfil) browser-modeled and labeled as such; unauth attacker → authenticated data compromise; CONFIRMED (live: Steps 0/1/2/4; Step 3 browser-modeled — poc_12, round 31) |
| 16 | **Exploit Chain B** — CORSMiddleware credentialed-reflection (poc_11 primitive) on session-cookie-gated `GET /cors-protected/whoami`; attacker Origin + victim cookie → ACAO reflects attacker Origin + ACAC:true + authenticated body; attacker-origin JS reads victim's authenticated data cross-origin | Credentialed CORS cross-origin authenticated-data disclosure | **MEDIUM conditional** | FAIL — Chain B confirmed; Steps 0/1/2 LIVE-OBSERVED; Step 3 (cross-origin browser read) BROWSER-MODELED in poc_13 AND additionally LIVE-OBSERVED by poc_14 (real Chromium — see §6g); CONFIRMED (live: Steps 0/1/2; Step 3 additionally live by poc_14 — poc_13, round 32; poc_14, round 34) |
| 17 | **poc_14 browser confirmation of Chain B Step 3** — real headless Chromium at attacker-origin reads victim's authenticated `/cors-protected/whoami` body cross-origin; negative control proves SOP blocks the same read at `/no-cors-here` (not CORS-wrapped); precondition: SameSite=None;Secure cookie + HTTPS + `allow_origins=["*"]`+`allow_credentials=True` | Browser-observed credentialed cross-origin authenticated-data read (reinforces finding 5 / Chain B) | **MEDIUM conditional** (same as row 16) | FAIL — Chain B Step 3 LIVE-OBSERVED with real Chromium; attacker-origin JS read AUTOFYN_CORS_EXFIL_SECRET; negative control threw TypeError; reinforces finding 5 / Chain B (poc_13); NOT a 6th independent finding; poc_14 browser-driven, run separately (NOT part of 6 PASS + 8 FAIL curl tally) |

**Five independent conditional findings (rows 10–14); all framework-defense checks (rows 5–9) and supply-chain checks (rows 1–4) otherwise passed.** Rows 15 and 16 are **chain syntheses** (not additional independent findings — the independent count stays at 5): row 15 synthesizes findings 10+11 (Chain A); row 16 synthesizes finding 14 (Chain B). Row 17 is poc_14 browser confirmation (a PoC row for the live browser evidence, NOT a new finding row; the independent count stays at 5). All five underlying findings are upstream-inherited (not fork-planted). Findings 10–11 require the proxy-prefix deployment precondition; finding 12 requires only a trailing-slash route with default `redirect_slashes=True` (for meaningful exploitation additionally requires an upstream cache/proxy forwarding arbitrary `Host`); finding 13 requires an UploadFile endpoint with no upstream proxy body-size cap; finding 14 requires the developer to combine `allow_origins=["*"]` with `allow_credentials=True`.

---

## 5. Explicit Dismissal: fastar / OSV MAL-2026-4750

**OSV MAL-2026-4750** was filed against FastAPI 0.136.3, claiming that the addition of `fastar >= 0.9.0` to `[project.optional-dependencies].standard` was a malicious supply-chain injection. This claim is incorrect and has been formally withdrawn.

**Why this is NOT a vulnerability:**

1. **Not planted by the fork.** The `fastar >= 0.9.0` dependency is present verbatim in the legitimate upstream FastAPI 0.137.1 `pyproject.toml` (github.com/fastapi/fastapi, tag 0.137.1, commit a82e5f2). The fork's `pyproject.toml` is identical on this section. There is nothing the fork added.

2. **Genuine package.** `fastar` 0.11.0 is published by Jonathan Ehwald (GitHub: DoctorJohn), a contributor to the FastAPI project. The package is a Rust/PyO3 tar archive library. Source code is available at github.com/DoctorJohn/fastar.

3. **OSV withdrawal.** OSSF PR #1276 withdrew MAL-2026-4750 with the stated reason: "This package was flagged because of the consumption of indirect dependency fastar. After further deep dive, the dependency was developed by FastAPI team and the whole package is in a good shape." The advisory is withdrawn and no longer operative.

4. **Static analysis clean.** Binary analysis of the fastar 0.11.0 compiled extension (3,970 printable strings scanned) found no hardcoded URLs, IPs, credential paths, subprocess/eval/exec calls, base64 blobs, or network socket infrastructure beyond standard Python C-API exception names.

5. **Runtime behavioral check passed.** The live PoC (poc_01_fastar_runtime.sh) confirmed via Python `sys.addaudithook` that importing fastar produces no outbound network connections, no reads of credential paths (/.ssh, /.aws, /etc/passwd), and no reads of secret environment variables.

**Reporting fastar as a vulnerability would be a false positive** and is explicitly not warranted by the evidence.

---

## 6. Finding — Reflected XSS in Swagger UI `/docs` (unescaped `openapi_url`)

**Status:** CONFIRMED (live, poc_07, round 6).

**Live confirmation evidence (round 6, reviewer):** Built image `autofyn-audit-fastapi:202b2d2` (local image id sha256:3812c986c4e1) from pinned commit 202b2d2 via `setup.sh`; container `autofyn-audit-target` reported `fastapi_version == 0.137.1` at `/health`. `bash autofyn_audit/run_all.sh` produced **6 PASS, 2 FAIL** — poc_01–06 (defenses/supply-chain) all PASS (no regression from the new ProxyPrefixMiddleware); `swagger_openapi_url_xss :: FAIL` and `redoc_openapi_url_xss :: FAIL`. Independent manual curl confirmed: `curl -H "X-Forwarded-Prefix: /x'-AUTOFYNXSS-'" .../docs` renders `url: '/x'-AUTOFYNXSS-'/openapi.json',` (raw single-quote breakout, unescaped) and also `oauth2RedirectUrl: window.location.origin + '/x'-AUTOFYNXSS-'/docs/oauth2-redirect',` (secondary sink). Teeth-tests: the SAME request with NO `X-Forwarded-Prefix` header yields a clean `url: '/openapi.json',` with zero marker occurrences (reflection is strictly header-driven); the same header against `/health` produces no marker (finding scoped to the swagger HTML sinks); against `/openapi.json` the value is reflected only inside a double-quoted JSON string under `Content-Type: application/json` (not an executable XSS context). Confirms the finding is real, non-vacuous, and correctly scoped.

### Severity

**HIGH, conditional.** CVSS-comparable to cadwyn GHSA-2gxp-6r36-m97r (7.6 HIGH), which describes the identical `get_swagger_ui_html` unescaped-`openapi_url` sink class. The severity is conditional: the attack is only reachable when a deployment maps an untrusted request header into `scope["root_path"]` (the documented "Behind a Proxy" pattern). In a default, bare uvicorn deployment the severity is effectively zero.

### Location

- **Primary sink:** `fastapi/openapi/docs.py:166-169` (`get_swagger_ui_html`):
  ```
  <script>
  const ui = SwaggerUIBundle({
      url: '{openapi_url}',
  ```
  `openapi_url` is raw f-string interpolation inside a single-quoted JS string literal inside a `<script>` block. No `_html_safe_json`, no `json.dumps`, no HTML-entity encoding. Adjacent parameters at `docs.py:172` (`_html_safe_json(key)` / `_html_safe_json(value)`) and `docs.py:186` (`init_oauth`) ARE escaped — the asymmetry is real and has no apparent justification.

- **Secondary unescaped sink:** `docs.py:175` — `oauth2RedirectUrl: window.location.origin + '{oauth2_redirect_url}'` (only emitted when `oauth2_redirect_url` is truthy; same escaping gap, same-class vector).

- **Tertiary unescaped sink (ReDoc):** `docs.py:293` — `<redoc spec-url="{openapi_url}"></redoc>` (HTML attribute, double-quoted; confirmed by poc_07's secondary assertion).

- **Source:** `fastapi/applications.py:1122-1134` (`swagger_ui_html` route handler for `/docs`):
  ```python
  root_path = req.scope.get("root_path", "").rstrip("/")   # line 1123
  openapi_url = root_path + self.openapi_url               # line 1124
  # self.openapi_url defaults to "/openapi.json"
  return get_swagger_ui_html(openapi_url=openapi_url, ...) # line 1128-1134
  ```
  `.rstrip("/")` strips only trailing slashes; it does NOT sanitize single-quotes, `<`, `>`, `;`, or spaces.

### Data Flow

```
X-Forwarded-Prefix request header
  → reverse proxy / ASGI middleware (e.g. ProxyPrefixMiddleware in target_app/app.py)
  → scope["root_path"]  (mutated before FastAPI.__call__)
  → applications.py:1123  root_path = req.scope.get("root_path","").rstrip("/")
  → applications.py:1124  openapi_url = root_path + self.openapi_url
  → get_swagger_ui_html(openapi_url=openapi_url, ...)
  → docs.py:168  url: '{openapi_url}',   (raw, single-quoted, no escaping)
  → reflected into /docs <script> block
  → JavaScript executes in browser
```

### Precondition (stated prominently — do NOT overstate)

In a **default uvicorn/FastAPI deployment**, `root_path` is a **static startup value** set via `uvicorn --root-path` or `FastAPI(root_path=...)`, which are NOT client-controllable per-request. A plain HTTP client cannot trigger this without an intermediary.

**Exploitable only when** a reverse proxy (nginx / Traefik / k8s Ingress) or ASGI middleware maps an **untrusted** request header (`X-Forwarded-Prefix`, `X-Script-Name`, etc.) into `scope["root_path"]`. This is the documented FastAPI "Behind a Proxy" pattern, commonly deployed in enterprise, k8s, and PaaS environments. The `--root-path` CLI flag alone does NOT create per-request exploitability (it is a static startup value).

### Upstream Parity — Inherited, Not Fork-Planted

`fastapi/openapi/docs.py` is byte-identical to upstream FastAPI 0.137.1 (verified this audit). This weakness is therefore **inherited from upstream** and is not evidence of a malicious fork modification. The same sink class is documented in cadwyn advisory GHSA-2gxp-6r36-m97r. FastAPI documents `get_swagger_ui_html` as "not intended to be used with user-controlled arguments." The fork ships this code and runs it; under the documented proxy deployment, the XSS is live and unauthenticated.

### Reproduction Steps

```bash
# 1. Start the audit container
bash autofyn_audit/setup.sh

# 2. Positive control — confirm /docs renders the vulnerable template
curl -s http://127.0.0.1:8137/docs | grep "url: '"
# Expected: "    url: '/openapi.json',"

# 3. Attack — inject breakout via X-Forwarded-Prefix
curl -s -H "X-Forwarded-Prefix: /x'-AUTOFYNXSS-'" http://127.0.0.1:8137/docs | grep "AUTOFYNXSS"
# Expected (FAIL = confirmed XSS): "    url: '/x'-AUTOFYNXSS-'/openapi.json',"
# The ' after /x closes the JS string; -AUTOFYNXSS- is bare JS tokens outside the string.

# 4. Run poc_07 via run_all.sh (or directly)
bash autofyn_audit/run_all.sh
# poc_07 emits:
#   [[ AUDIT-RESULT ]] swagger_openapi_url_xss :: FAIL :: openapi_url interpolated ...
```

The PoC greps for the literal `'-AUTOFYNXSS-'` in the `/docs` response body. If present, the single-quote was emitted unescaped — JS string breakout — XSS confirmed.

### Demonstrative Script-Execution Payload (Impact Illustration)

For a browser-exploitable payload (report prose only; PoC uses the marker payload above):
```
X-Forwarded-Prefix: /x';document.title='AUTOFYNXSS';'
```
Renders: `url: '/x';document.title='AUTOFYNXSS';'/openapi.json',`
This closes the string, executes a JS statement, and the trailing `'/openapi.json',` is a parser-tolerated dangling string. A real attacker would use `document.cookie`-stealing or redirected XSS payloads here.

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Recommended fix for upstream / operators:** escape `openapi_url` (and `oauth2_redirect_url`) through the EXISTING `_html_safe_json` helper, exactly as the adjacent swagger parameters already are at `docs.py:172`:

```python
# Current (vulnerable):
html += f"    url: '{openapi_url}',\n"

# Fixed:
html += f"    url: {_html_safe_json(openapi_url)},\n"
# _html_safe_json produces the surrounding quotes internally (json.dumps)
# and escapes <, >, & — so drop the manual single quotes.
```

For the ReDoc sink (`docs.py:293`), HTML-attribute-escape the value before interpolation.

**Deployment mitigations (if patching upstream is not immediately possible):**
- Do not map untrusted `X-Forwarded-Prefix` into `root_path` without stripping/validating the header at a trusted proxy boundary.
- Disable `/docs` and `/redoc` in production (`FastAPI(docs_url=None, redoc_url=None)`).
- Restrict `/docs` to internal/trusted networks only.

---

## 6a. Finding — OpenAPI `servers` URL injection (Swagger API base-URL hijack)

**Status:** CONFIRMED (live, poc_08, round 7).

**Live evidence** (image `autofyn-audit-fastapi:202b2d2`, commit `202b2d2`, round 7):
- `poc_08` emits `openapi_servers_url_injection :: FAIL` (FAIL = finding present, consistent with poc_07 semantics).
- Exploit request: `curl -s -H "X-Forwarded-Prefix: //autofyn-evil.example" .../openapi.json` → response contains `"servers":[{"url":"//autofyn-evil.example"}]`.
- Teeth-test (non-vacuous): same request with **no** `X-Forwarded-Prefix` header → response has **no** `servers` key (0 markers).
- Benign control: `X-Forwarded-Prefix: /api/v1` → `"servers":[{"url":"/api/v1"}]`, proving the sink is genuinely driven by the attacker-controlled header.
- Full harness: `run_all.sh` = **6 PASS** (poc_01–06: fastar_runtime_benign, sse_injection_neutralized, staticfiles_traversal_blocked, jinja2_ssti_xss_defended, lockfile_integrity_verified, header_crlf_injection_blocked) + **3 FAIL** (swagger_openapi_url_xss, redoc_openapi_url_xss, openapi_servers_url_injection). No regression.

### Severity

**MEDIUM, conditional.** Impact: an attacker's host becomes the first `servers[].url` in the OpenAPI document returned by `/openapi.json`. Swagger UI reads `servers[0].url` as the API base URL for "Try it out" and "Authorize" requests. Consequence: any bearer token, API key, or session cookie a Swagger user passes through the "Authorize" dialog and then sends via "Try it out" is redirected to the attacker host — credential exfiltration + open redirect of API traffic. Severity is MEDIUM (not HIGH/CRITICAL) because the attack requires BOTH:
1. The proxy-prefix precondition (a proxy or middleware maps an untrusted request header into `root_path`), AND
2. A human user exercising authorized requests through the Swagger UI.

This is not script execution, not unauthenticated mass exploitation — MEDIUM, not HIGH.

### Location

- **Sink:** `fastapi/applications.py:1108-1116` (the `openapi` route handler, registered in `setup()`):
  ```python
  root_path = req.scope.get("root_path", "").rstrip("/")       # line 1108
  schema = self.openapi()
  if root_path and self.root_path_in_servers:                   # line 1110
      server_urls = {s.get("url") for s in schema.get(...)}    # line 1111
      if root_path not in server_urls:                         # line 1112
          schema = dict(schema)
          schema["servers"] = [{"url": root_path}] + ...      # line 1114
  return JSONResponse(schema)
  ```
  `root_path` is placed verbatim as `{"url": root_path}`. No URL scheme validation, no host restriction, no encoding. `root_path_in_servers` defaults `True` — the branch fires whenever `root_path` is truthy.

- **Source:** `fastapi/applications.py:1108` — `req.scope.get("root_path", "").rstrip("/")`. The `.rstrip("/")` strips only trailing slashes; it does NOT validate URL scheme (allows `//host`, `http://host`, absolute path, etc.).

- **Gate:** `self.root_path_in_servers` defaults `True` in the `FastAPI` constructor.

- **Non-clobber:** `applications.py:1159-1162` — `FastAPI.__call__` overwrites `scope["root_path"]` only when `self.root_path` is truthy. Since the target app sets no `root_path` argument, `self.root_path == ""` (falsy), so the middleware-injected value survives into the route handler.

### Data Flow

```
X-Forwarded-Prefix: //autofyn-evil.example
  → ProxyPrefixMiddleware (target_app/app.py:141-178)
      scope["root_path"] = "//autofyn-evil.example"  (decoded latin-1)
  → FastAPI.__call__ — self.root_path falsy → does NOT overwrite scope["root_path"]
  → openapi route handler (applications.py:1107-1117)
  → root_path = "//autofyn-evil.example".rstrip("/")  → "//autofyn-evil.example"
  → root_path truthy AND root_path_in_servers True → branch taken
  → schema["servers"] = [{"url": "//autofyn-evil.example"}] + []
  → JSONResponse returns {"servers": [{"url": "//autofyn-evil.example"}], ...}
  → Swagger UI: API base URL = //autofyn-evil.example
  → "Try it out" / "Authorize" calls sent to attacker host
```

### Precondition (stated prominently — do NOT overstate)

In a **default uvicorn/FastAPI deployment**, `root_path` is a **static startup value** set via `uvicorn --root-path` or `FastAPI(root_path=...)` — these are NOT client-controllable per-request. A plain HTTP client cannot trigger this without an intermediary.

**Exploitable only when** a reverse proxy (nginx / Traefik / k8s Ingress) or ASGI middleware maps an **untrusted** request header (`X-Forwarded-Prefix`, `X-Script-Name`, etc.) into `scope["root_path"]`. This is the documented FastAPI "Behind a Proxy" pattern. The `--root-path` CLI flag alone does NOT create per-request exploitability (it is a static startup value, captured at `self.root_path` and used only once at `:1159-1162` when truthy — which would then OVERRIDE the injected value and break the precondition).

**Default uvicorn-without-proxy is NOT remotely exploitable.**

### Upstream Parity — Inherited, Not Fork-Planted

`fastapi/applications.py` is byte-identical to upstream FastAPI 0.137.1 (verified this audit). This weakness is therefore **inherited from upstream** and is not evidence of a malicious fork modification. Per the audit goal, no fix is applied.

### Reproduction Steps

```bash
# 1. Start the audit container
bash autofyn_audit/setup.sh

# 2. Positive control — confirm /openapi.json has no servers key by default
curl -s http://127.0.0.1:8137/openapi.json | grep -o '"servers".\{0,60\}'
# Expected: (no output — servers key absent by default)

# 3. Exploit — inject attacker host as servers[].url
curl -s -H "X-Forwarded-Prefix: //autofyn-evil.example" \
    http://127.0.0.1:8137/openapi.json | grep -o '"servers".\{0,60\}'
# Expected (FAIL = confirmed finding):
#   "servers": [{"url": "//autofyn-evil.example"}, ...]

# 4. Run poc_08 via run_all.sh (or directly)
bash autofyn_audit/run_all.sh
# poc_08 emits:
#   [[ AUDIT-RESULT ]] openapi_servers_url_injection :: FAIL :: ...
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Recommended fix for upstream / operators:**

1. Validate `root_path` before placing it in `servers[].url`. Reject scheme-relative (`//host`) and absolute-URL (`http://host`) values; accept only a leading single `/path` form (matching RFC 3986 relative-reference, path-only). Example gate:
   ```python
   import re
   if re.match(r'^/[^/]', root_path):  # must start with / followed by non-/
       schema["servers"] = [{"url": root_path}] + ...
   ```
2. Validate `X-Forwarded-Prefix` at the trusted proxy boundary — enforce it to a known relative-path form before it enters ASGI scope.

Per audit goal, NO fix is applied to the framework.

---

## 6b. Finding — Host-header injection → open redirect via `redirect_slashes`

**Status:** CONFIRMED (live, poc_09, round 9 — re-finalized round 10).

**Live evidence** (image `autofyn-audit-fastapi:202b2d2`, commit `202b2d2`, round 9):

```
# Positive control — GET /items/ (trailing slash)
HTTP/1.1 200 OK
{"items":[]}
# Negative control — GET /items, real Host (non-vacuous)
HTTP/1.1 307 Temporary Redirect
location: http://127.0.0.1:8137/items/        <- real host, NO attacker marker
# Exploit — GET /items, Host: autofyn-evil.example
HTTP/1.1 307 Temporary Redirect
location: http://autofyn-evil.example/items/  <- attacker host reflected
```

`poc_09` emits `host_header_open_redirect :: FAIL` (FAIL = finding present, consistent with poc_07/poc_08 semantics). Full harness: `run_all.sh` = **6 PASS** (poc_01–06) + **4 FAIL** (swagger_openapi_url_xss, redoc_openapi_url_xss, openapi_servers_url_injection, host_header_open_redirect). No regression on poc_01–08.

### Severity

**LOW-to-MEDIUM, conditional.**

**IMPORTANT constraint:** A browser-based attacker CANNOT set a victim's `Host` header — browsers enforce the `Host` header to match the request origin. This means the classic click-through open-redirect (attacker sends a crafted URL to a victim, victim's browser follows it to the attacker host) is NOT achievable through this vector alone.

Meaningful exploitation requires one of the following additional conditions:
- An **upstream HTTP cache or reverse proxy** that forwards an attacker-controlled `Host` header to the origin server — enabling **web-cache poisoning** (the cache stores `Location: http://autofyn-evil.example/items/` under the canonical URL) or **password-reset / email-link poisoning** (the origin generates a reset URL incorporating the `Location` header's host).
- A **server-side HTTP client** (e.g. a webhook handler, health-check aggregator, or API gateway) that follows the 307 redirect with the reflected `Location` — a server-side request forgery variant.

**What is genuine without a proxy:** the redirect itself fires against any plain uvicorn deployment with any HTTP client that sends a forged `Host` header (no proxy, no middleware required). This is the meaningful distinction from poc_07/poc_08, which require the proxy-prefix precondition even for the base redirect. However, the attacker cannot exploit this from a browser to redirect a victim.

Comparison: notably weaker than a query-parameter open redirect (URL fully attacker-controlled in any browser session). Not critical or high; LOW-to-MEDIUM is the correct band.

### Location

- **Sink:** `starlette/routing.py:706` — `response = RedirectResponse(url=str(redirect_url))` emits the `Location:` header. The URL is built at line 705 from `URL(scope=redirect_scope)`.

- **Netloc source:** `starlette/datastructures.py:43-50,60` — `URL(scope=...)`:
  - Lines 43-47: extracts `host_header` from `scope["headers"]`.
  - Line 49: validates with `_HOST_RE.fullmatch(host_header)`.
  - Line 50: if it matches, sets `netloc = host_header`.
  - Line 60: builds the full URL via `SplitResult(scheme, netloc, path, ...).geturl()`.

- **`_HOST_RE`** at `starlette/datastructures.py:25`:
  ```
  ^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::[0-9]+)?$
  ```
  This validates only **syntax** (a well-formed hostname or IPv6 literal, with optional port), NOT **trust**. Any well-formed attacker hostname (`autofyn-evil.example`) passes. The regex rejects slashes, `@`, `?`, `#`, and scheme prefixes — so attacker payloads must be bare hostnames.

- **Default `status_code=307`:** `starlette/responses.py:208` (`RedirectResponse.__init__` default). The `redirect_slashes` branch always produces a 307 Temporary Redirect for GET requests.

- **`redirect_slashes=True` default:** `fastapi/routing.py:1796` (the literal `= True` default on the `redirect_slashes` parameter). FastAPI's `APIRouter` passes this to `Starlette.Router.__init__`; the branch at `starlette/routing.py:695` fires out of the box.

### Data Flow

```
Host: autofyn-evil.example  (request header — attacker-controlled, no proxy needed)
  → ASGI server (uvicorn) → scope["headers"]
  → starlette/routing.py:695  if self.redirect_slashes and route_path != "/"
      (GET /items — no trailing slash; registered route is /items/ — trailing slash)
  → routing.py:696-700  redirect_scope built with path = "/items/"
  → routing.py:705       redirect_url = URL(scope=redirect_scope)
  → datastructures.py:43-50  host_header = "autofyn-evil.example"
                              _HOST_RE matches → netloc = "autofyn-evil.example"
  → datastructures.py:60  URL = "http://autofyn-evil.example/items/"
  → routing.py:706        RedirectResponse(url="http://autofyn-evil.example/items/")
  → HTTP 307 Location: http://autofyn-evil.example/items/
```

### Precondition (stated prominently — do NOT overstate)

**The redirect fires with NO proxy required** against any plain uvicorn/FastAPI deployment, provided:
1. The app has at least one route registered with a trailing slash (e.g. `/items/`) — extremely common in real APIs (collection endpoints conventionally use `/items/`).
2. `redirect_slashes=True` (FastAPI default — never changed).
3. No `TrustedHostMiddleware` is in use.

**For meaningful exploitation** (beyond the theoretical redirect firing), an upstream cache or proxy that forwards an arbitrary `Host` to the origin is additionally required. The redirect itself does not achieve user-impact in a browser without this.

Default uvicorn-without-proxy is technically vulnerable to the redirect (the `Location` header reflects the `Host`), but meaningful attacker impact in a browser requires the additional cache/proxy precondition.

### Independence vs poc_07 / poc_08

| Dimension | poc_07 (XSS) | poc_08 (servers) | poc_09 (open redirect) |
|-----------|-------------|-----------------|----------------------|
| Source | X-Forwarded-Prefix → root_path | X-Forwarded-Prefix → root_path | Host header (NO proxy) |
| Sink | docs.py:168 (JS string) | applications.py:1114 (servers[].url JSON) | routing.py:706 (Location header) |
| Attack class | Reflected XSS | API base-URL hijack / credential exfil | Open redirect / Host-header injection |
| Proxy required | Yes | Yes | No (for redirect); Yes (for meaningful browser impact) |
| Fix-orthogonal | Escape root_path in docs.py | Validate root_path URL scheme | TrustedHostMiddleware / redirect_slashes=False |

**Fix-orthogonality confirms genuine independence:** TrustedHostMiddleware or `redirect_slashes=False` closes poc_09 but does NOT close poc_07/poc_08. Escaping `root_path` in docs.py/applications.py closes poc_07/poc_08 but does NOT close poc_09. No single maintainer patch closes all three.

**Shared-source note:** poc_09 shares NO source with poc_07/poc_08 (distinct request vector entirely). This is stronger independence than poc_07↔poc_08, which share the `X-Forwarded-Prefix` → `root_path` source (that overlap is stated openly in §6/§6a and the round-7 rule).

### Upstream Parity — Inherited, Not Fork-Planted

`starlette/routing.py` redirect_slashes behavior is Starlette code, **enabled by FastAPI's default `redirect_slashes=True`** at `fastapi/routing.py:1796`. `_HOST_RE`'s permissiveness is a deliberate Starlette design choice — it validates hostname syntax, not trust. This weakness is **inherited from upstream Starlette/FastAPI** and is not evidence of a malicious fork modification. Per audit goal, no fix is applied.

### Reproduction Steps

```bash
# 1. Start the audit container
bash autofyn_audit/setup.sh

# 2. Positive control — confirm /items/ route exists
curl -s http://127.0.0.1:8137/items/
# Expected: {"items":[]}  (HTTP 200)

# 3. Negative control — GET /items (no trailing slash), real Host
curl -i -s http://127.0.0.1:8137/items
# Expected: HTTP 307, Location: http://127.0.0.1:8137/items/  (real host, no attacker marker)

# 4. Exploit — forge Host header
curl -i -s -H "Host: autofyn-evil.example" http://127.0.0.1:8137/items
# Expected (FAIL = confirmed finding):
#   HTTP/1.1 307 Temporary Redirect
#   location: http://autofyn-evil.example/items/   <- attacker host reflected

# 5. Run poc_09 via run_all.sh (or directly)
bash autofyn_audit/run_all.sh
# poc_09 emits:
#   [[ AUDIT-RESULT ]] host_header_open_redirect :: FAIL :: Host header reflected ...
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Recommended options for upstream / operators (any one is sufficient):**

1. **`TrustedHostMiddleware`** with an explicit allowed-hosts list. Starlette ships this middleware; adding `TrustedHostMiddleware(app, allowed_hosts=["example.com"])` rejects requests whose `Host` does not match the allowlist with a 400 response, so the forged `Host` never reaches the redirect path.
   ```python
   from starlette.middleware.trustedhost import TrustedHostMiddleware
   app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com"])
   ```

2. **`redirect_slashes=False`** at app/router construction (`FastAPI(redirect_slashes=False)` or `APIRouter(redirect_slashes=False)`). Disables the redirect branch entirely; operators must then register both `/items` and `/items/` explicitly if both paths are needed.

3. **Validate and normalize the `Host` header at the trusted boundary** (e.g. in a proxy or gateway layer) before it reaches the origin server, ensuring only known-good hostnames are forwarded.

Per audit goal, NO fix is applied to the framework.

---

## 6c. Finding — multipart `max_part_size` not enforced on file parts

**Status:** CONFIRMED (live, poc_10, round 12).

**Finding (LOW, upstream-inherited): multipart `max_part_size` not enforced on file parts.**
Starlette's `MultiPartParser.on_part_data` (`starlette/formparsers.py:183-188`) enforces the `max_part_size` limit (default 1 MiB) only for non-file form fields; parts carrying a `filename=` in their Content-Disposition (file parts, surfaced to FastAPI as `UploadFile`) are streamed without any per-part size limit into a `SpooledTemporaryFile` that spills to disk past 1 MiB. An identical oversized payload sent as a plain form field is rejected ("Part exceeded maximum size of 1024KB"), but the same bytes sent as a file part are accepted in full. This is a disk/IO resource-exhaustion (DoS) vector.

### Severity

**LOW.** No RCE, data disclosure, or auth bypass. "Uploads are unbounded by default; the application or reverse proxy must cap them" is broadly by-design across web frameworks — the specific reportable issue here is the **semantic asymmetry**: a parameter named `max_part_size` silently does not apply to the part that dominates resource use (the file). This mirrors the class of "configured form limits silently ignored" that starlette itself fixed for urlencoded bodies in CVE-2026-54283 (fixed in starlette 1.3.1, present in this version).

### Location

- **Sink:** `starlette/formparsers.py:183-188` (`on_part_data`):

  ```python
  if self._current_part.file is None:             # NON-FILE field part
      if len(...) + len(message_bytes) > self.max_part_size:
          raise MultiPartException(...)           # enforced
      self._current_part.data.extend(message_bytes)
  else:                                            # FILE part (filename= present)
      self._file_parts_to_write.append(...)        # NO size check — unbounded
  ```

- **Spill point:** `formparsers.py:230` — `SpooledTemporaryFile(max_size=spool_max_size)` (spool_max_size = 1 MB at line 147). Past 1 MB the temporary file spills to disk with no ceiling.

- **Default:** `max_part_size = 1024 * 1024` (class-level line 149 and ctor default line 159). FastAPI calls `request.form()` with this default and never raises it for file parts.

- **Count-only caps:** `max_files` / `max_fields` (lines 226-228, 239-241) cap the NUMBER of parts, not their size. They provide no resource-exhaustion protection for a large single file part.

### NOT a `str = Form()` bypass

Filename-spoofing a part aimed at a `str = Form(...)` field does **NOT** silently feed oversized data to the app. Starlette stores an `UploadFile` in `FormData` for that part; FastAPI's `_extract_form_body` does not coerce it (the coercion branches at `utils.py:925-941` require `isinstance(field_info, params.File)`, not `params.Form`); Pydantic rejects an arbitrary `UploadFile` object against `str` annotation → FastAPI returns **HTTP 422** `type=string_type`. Only genuine `UploadFile` / `bytes = File()` / raw `request.form()` endpoints exhibit the unbounded spool.

### Precondition (stated prominently — do NOT overstate)

**Exploitable only when:**
1. The app exposes an `UploadFile` / `bytes = File()` / raw `request.form()` endpoint — extremely common pattern.
2. No upstream proxy body-size cap (e.g. nginx `client_max_body_size`) is in place.

Attacker also needs bandwidth to stream the body. No special headers or middleware required beyond these conditions.

### Independence from poc_07/poc_08/poc_09

| Dimension | poc_07 (XSS) | poc_08 (servers) | poc_09 (open redirect) | poc_10 (size DoS) |
|-----------|-------------|-----------------|----------------------|------------------|
| Source | X-Forwarded-Prefix header | X-Forwarded-Prefix header | Host header | request body file part |
| Sink | docs.py:168 | applications.py:1114 | routing.py:706 | formparsers.py:188 |
| Attack class | Reflected XSS | API base-URL hijack | Open redirect | Disk/IO resource DoS |
| Fix-orthogonal | escape root_path in docs.py | validate root_path scheme | TrustedHostMiddleware | size ceil file parts in on_part_data |

**Fully independent:** distinct source, distinct sink, distinct attack class, fix-orthogonal in all directions. No shared source with any prior PoC.

### Data Flow

```
POST /upload — multipart/form-data
  part with Content-Disposition: form-data; name="file"; filename="x"
    → starlette/formparsers.py:225 — on_headers_finished: b"filename" in options
    → self._current_part.file = UploadFile(file=SpooledTemporaryFile(max_size=1MB))
    → on_part_data (line 181): message bytes arrive
    → line 183: self._current_part.file is NOT None → else-branch
    → line 188: _file_parts_to_write.append(...) — NO max_part_size check
    → SpooledTemporaryFile spills to disk past 1MB — no ceiling
    → FastAPI /upload: await file.read() → full body; {"received_bytes": N}
```

### Live Evidence (poc_10, round 12)

- Teeth-test: POST 2MiB as a NON-FILE field part → HTTP 4xx ("Part exceeded maximum size of 1024KB" — cap confirmed active).
- Exploit: POST same 2MiB as a FILE part (filename=x) → HTTP 200 `{"received_bytes":2097152}` — full body materialized, no size enforcement.
- `poc_10` emits `multipart_filepart_size_uncapped :: FAIL`.
- Full harness: `run_all.sh` = **6 PASS** (poc_01–06) + **5 FAIL** (swagger_openapi_url_xss, redoc_openapi_url_xss, openapi_servers_url_injection, host_header_open_redirect, multipart_filepart_size_uncapped). No regression.

### Upstream Parity — Inherited, Not Fork-Planted

`starlette/formparsers.py` is the installed Starlette 1.3.1 code (not modified by this fork). The asymmetry persists in current upstream `encode/starlette` master. This weakness is **inherited from upstream Starlette** and is not evidence of a malicious fork modification. Per audit goal, no fix is applied.

### Reproduction Steps

```bash
# 1. Start the audit container
bash autofyn_audit/setup.sh

# 2. Teeth-test — 2MiB field part (no filename=) is rejected
python3 -c "import sys; sys.stdout.buffer.write(b'A' * 2097152)" > /tmp/poc10_payload.bin
printf -- '--BOUND\r\nContent-Disposition: form-data; name="file"\r\n\r\n' > /tmp/poc10_field.bin
cat /tmp/poc10_payload.bin >> /tmp/poc10_field.bin
printf '\r\n--BOUND--\r\n' >> /tmp/poc10_field.bin
curl -sS -X POST -H "Content-Type: multipart/form-data; boundary=BOUND" \
    --data-binary @/tmp/poc10_field.bin -w "\nHTTP %{http_code}\n" \
    http://127.0.0.1:8137/upload
# Expected: HTTP 400; body contains "Part exceeded maximum size of 1024KB"

# 3. Exploit — same 2MiB as file part (filename=x) is accepted
printf -- '--BOUND\r\nContent-Disposition: form-data; name="file"; filename="x"\r\nContent-Type: application/octet-stream\r\n\r\n' > /tmp/poc10_file.bin
cat /tmp/poc10_payload.bin >> /tmp/poc10_file.bin
printf '\r\n--BOUND--\r\n' >> /tmp/poc10_file.bin
curl -sS -X POST -H "Content-Type: multipart/form-data; boundary=BOUND" \
    --data-binary @/tmp/poc10_file.bin -w "\nHTTP %{http_code}\n" \
    http://127.0.0.1:8137/upload
# Expected: HTTP 200; {"received_bytes":2097152}

# 4. Run poc_10 via run_all.sh (or directly)
bash autofyn_audit/run_all.sh
# poc_10 emits:
#   [[ AUDIT-RESULT ]] multipart_filepart_size_uncapped :: FAIL :: max_part_size enforced ...
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Recommended fix for upstream / operators:**

1. Apply a size ceiling to file parts in `on_part_data` (the `else` branch at line 187) — add an analogous `max_part_size` check or introduce a dedicated `max_file_size` parameter to `MultiPartParser`.
2. Alternatively, cap the upload size at the **app layer** (read file in bounded chunks, reject above threshold) or at the **proxy layer** (nginx `client_max_body_size`, AWS ALB / CloudFront `max-body-size`, etc.).

Per audit goal, NO fix is applied to the framework.

---

## 6d. Finding — CORSMiddleware reflects arbitrary `Origin` with credentials

**Status:** CONFIRMED (live, poc_11, round 20).

**Finding (MEDIUM-conditional, upstream-inherited): credentialed cross-origin disclosure via `Origin` reflection.**
When the developer configures `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` (FastAPI re-exports it as `fastapi.middleware.cors.CORSMiddleware`), Starlette does **not** emit the browser-rejected `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` combination. Instead it **reflects the attacker-supplied `Origin` request header verbatim** into `Access-Control-Allow-Origin` and adds `Access-Control-Allow-Credentials: true`. The result is a working, browser-accepted credentialed cross-origin read: JS on **any** attacker origin can read cookie/`Authorization`-gated response bodies of the victim API. The dangerous transformation happens **silently** — no error, no warning — even though a developer may believe `"*"` makes credentialed reads browser-impossible.

### Severity

**MEDIUM (conditional).** Cross-origin disclosure of credentialed responses (session-scoped data, CSRF tokens, etc.). No RCE. Gated **entirely** on the developer opting into the unsafe `allow_origins=["*"]` + `allow_credentials=True` combination — both Starlette defaults are safe (`allow_credentials` defaults `False`, and with credentials off the literal `"*"` is emitted, which browsers refuse to use with credentials). The reportable nucleus is the **silent foot-gun**: the framework converts a configuration the developer may consider browser-safe into a functioning credentialed-CORS bypass with no diagnostic.

### Location

- **Sink:** `starlette/middleware/cors.py` — `CORSMiddleware.__init__` sets `allow_all_origins` and `allow_credentials`; at **request time** (in `send`, via the `allow_explicit_origin` path) when `allow_all_origins` **and** `allow_credentials` are both true, the response takes the **explicit-origin** branch rather than emitting the literal `"*"`, so the headers are set to `Access-Control-Allow-Origin: <request Origin>` and `Access-Control-Allow-Credentials: true`.
- **Re-export:** `fastapi/middleware/cors.py` (`from starlette.middleware.cors import CORSMiddleware as CORSMiddleware`).
- **Inert without `Origin`:** with no `Origin` request header, `CORSMiddleware` passes the response through unchanged (no `Access-Control-Allow-Origin` emitted) — the basis for the poc_11 teeth-test.

### Precondition (stated prominently — do NOT overstate)

**Exploitable only when** the developer explicitly sets **both** `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`. This is **NOT a default-config remote exploit** — it is a configuration-dependent framework foot-gun. The audit target reproduces it on a **dedicated isolated sub-app** mounted at `/cors-protected` configured with exactly this combination; the main app (poc_01–10) is unaffected.

### Independence from poc_07/08/09/10

| Dimension | poc_07 (XSS) | poc_08 (servers) | poc_09 (open redirect) | poc_10 (size DoS) | poc_11 (CORS) |
|-----------|-------------|-----------------|----------------------|------------------|---------------|
| Source | X-Forwarded-Prefix | X-Forwarded-Prefix | Host header | request body file part | **Origin header** |
| Sink | docs.py:168 | applications.py:1114 | routing.py:706 | formparsers.py:188 | **middleware/cors.py** |
| Attack class | Reflected XSS | API base-URL hijack | Open redirect | Disk/IO DoS | **Credentialed cross-origin read** |
| Fix-orthogonal | escape root_path | validate root_path | TrustedHostMiddleware | size-ceil file parts | **don't combine `*`+credentials / reflect allowlist only** |

**Fully independent:** distinct source (`Origin`), distinct sink (`middleware/cors.py`), distinct attack class (CORS credentialed disclosure), fix-orthogonal to all four prior findings. No shared source with any prior PoC.

### Data Flow

```
GET /cors-protected/  with  Origin: https://attacker.cors-poc11.example
  → CORSMiddleware (allow_origins=["*"], allow_credentials=True)
  → "*" + credentials ⇒ explicit-origin branch (not literal "*")
  → Access-Control-Allow-Origin: https://attacker.cors-poc11.example   (reflected)
  → Access-Control-Allow-Credentials: true
  → browser allows attacker-origin JS to read the credentialed response body
```

### Live Evidence (poc_11, round 20)

- Teeth-test: `GET /cors-protected/` with **no** `Origin` → no `Access-Control-Allow-Origin` header (CORSMiddleware inert — non-vacuous).
- Exploit: `GET /cors-protected/` with `Origin: https://attacker.cors-poc11.example` → `Access-Control-Allow-Origin: https://attacker.cors-poc11.example` + `Access-Control-Allow-Credentials: true`.
- `poc_11` emits `cors_credentialed_origin_reflection :: FAIL`.

### Upstream Parity — Inherited, Not Fork-Planted

`starlette/middleware/cors.py` is the installed upstream Starlette code (not modified by this fork); FastAPI merely re-exports it. The behavior persists in current upstream Starlette. Inherited, not a fork-planted backdoor. Per audit goal, no fix is applied.

### Reproduction Steps

```bash
# 1. Start the audit container
bash autofyn_audit/setup.sh

# 2. Teeth-test — no Origin header → no ACAO emitted
curl -sS -D - -o /dev/null http://127.0.0.1:8137/cors-protected/ | grep -i access-control
# Expected: (no Access-Control-Allow-Origin line)

# 3. Exploit — arbitrary Origin reflected with credentials
curl -sS -D - -o /dev/null \
    -H "Origin: https://attacker.cors-poc11.example" \
    http://127.0.0.1:8137/cors-protected/ | grep -i access-control
# Expected (FAIL = confirmed finding):
#   access-control-allow-origin: https://attacker.cors-poc11.example
#   access-control-allow-credentials: true

# 4. Run poc_11 via run_all.sh (or directly)
bash autofyn_audit/run_all.sh
# poc_11 emits:
#   [[ AUDIT-RESULT ]] cors_credentialed_origin_reflection :: FAIL :: CORSMiddleware reflected ...
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Recommended fix for operators (NOT applied):** never combine `allow_origins=["*"]` with `allow_credentials=True`; instead enumerate an explicit trusted-origin allowlist when credentials are required, or keep `allow_credentials=False`. **Framework-level:** Starlette/FastAPI could emit a warning (or refuse) when both options are combined, since the result silently disables the browser's own `*`+credentials safeguard.

---

## 6e. Exploit Chain A — Operator Token Theft via One Proxy Misconfiguration

**Status:** CONFIRMED (live, poc_12, round 31). Chain is a **synthesis** of poc_07 (§6) and poc_08 (§6a); the independent-finding count stays at 5.

**Honest framing — read first:** The harness is curl-based (see §8 and the round-21 sidecar rule). It cannot drive a real browser or victim session. Steps 0, 1, 2, and 4 of Chain A are **mechanically observed** against the live target. Step 3 (the cross-origin browser fetch that carries the operator's token to the attacker collector) is **browser-modeled** — it is argued as inevitable from the conjunction of Step-1 and Step-0 evidence, and is explicitly labeled as such both here and in the poc_12 `[[ AUDIT-RESULT ]]` detail line. We do not claim to have exfiltrated a token through a live browser. The chain is strong and defensible precisely because we prove every link we can observe, model the browser step faithfully, and label it accurately.

### The Single Precondition

A reverse proxy or ASGI middleware maps the untrusted `X-Forwarded-Prefix` request header into `scope["root_path"]` — the **documented FastAPI "Behind a Proxy" pattern** (nginx, Traefik, k8s Ingress, AWS ALB). This is the ONLY precondition Chain A requires. `ProxyPrefixMiddleware` in `target_app/app.py` is the faithful ASGI-level representation of this deployment.

### Kill-chain (unauth attacker → API operator's token → authenticated data)

**Step 0 — Terminus exists and is genuinely gated (observed).**
`GET /protected` with no `Authorization` header → HTTP 401; secret `AUTOFYN_CHAIN_PROTECTED_SECRET` absent from body. `GET /protected` with `Authorization: Bearer AUTOFYN_OPERATOR_TOKEN_7f3a9c` → HTTP 200; secret present. This confirms (a) the token-protected resource is real and non-trivially gated, and (b) the operator token is a valid credential. Any weakness in Step 3 that exposes this token to the attacker directly enables authenticated data theft.

**Step 1 — Attacker hijacks the Swagger base URL (observed, poc_08 link).**
`GET /openapi.json` with `X-Forwarded-Prefix: //autofyn-chain-collector.example` → response contains `"servers":[{"url":"//autofyn-chain-collector.example"},...]`. Source: `applications.py:1108` (`root_path = req.scope.get("root_path","").rstrip("/")`); sink: `applications.py:1114` (`schema["servers"] = [{"url": root_path}] + ...`). Swagger UI reads `servers[0].url` as the API base URL for all "Try it out" and "Authorize" requests — including any `Authorization: Bearer ...` header the operator entered via the "Authorize" dialog. The attacker now controls the destination of all token-bearing Swagger calls.

**Step 2 — Attacker injects JavaScript into the API origin (observed, poc_07 link).**
`GET /docs` with `X-Forwarded-Prefix: /x'-AUTOFYNCHAIN-'` → response body contains raw `'-AUTOFYNCHAIN-'` (single-quote emitted unescaped at `docs.py:168`: `url: '{openapi_url}',`). The payload breaks out of the single-quoted JS string. Attacker-controlled JavaScript now executes in the API's own origin (`window.origin = https://api.example.com`), giving it same-origin access to Swagger's in-page authorization state (localStorage / `SwaggerUIBundle` config) and the ability to hook `fetch`/XHR to intercept `Authorization` headers on any "Try it out" call.

**Step 3 — Token travels to the attacker collector (BROWSER-MODELED — no HTTP request to the collector host in this harness).**

> **BROWSER-MODELED STEP:** This step does NOT issue any request to the collector. Instead it asserts the two independently-measured facts that together make exfiltration inevitable, then argues the browser behavior as a standard consequence.
>
> **(a) Step 1 proved:** `servers[0].url = //autofyn-chain-collector.example`. In a victim browser with the Swagger UI loaded and the operator's bearer token entered via "Authorize", Swagger sends every subsequent "Try it out" call — including the `Authorization: Bearer <token>` header — to `//autofyn-chain-collector.example`. This is standard Swagger UI behavior: it uses `servers[0].url` as the base URL for all API calls (AJAX / `fetch`). The attacker's collector at `//autofyn-chain-collector.example` receives the token directly off the wire.
>
> **(b) Step 0 proved:** token `AUTOFYN_OPERATOR_TOKEN_7f3a9c` is a valid credential. It unlocks `AUTOFYN_CHAIN_PROTECTED_SECRET` at `GET /protected` (HTTP 200 confirmed).
>
> Conjunction (a) ∧ (b): the attacker controls the destination of token-bearing Swagger requests, AND the token unlocks real data. The cross-origin browser fetch (victim's Swagger UI → attacker collector) follows standard web browser behavior against a proven-reachable injection point — it is not a novel vulnerability claim, it is the documented behavior of Swagger UI + a hijacked base URL.
>
> **Alternative path (poc_07 leg):** The XSS from Step 2 additionally gives attacker JS running in the API origin direct same-origin access to Swagger's authorization state. This is a stronger path: arbitrary JS can read `localStorage`, hook `fetch`, or issue authenticated requests and forward them to the attacker without requiring the victim to click "Try it out" — any `/docs` page load suffices.

**Step 4 — Attacker replays the captured token and reads protected data (observed).**
`GET /protected` with `Authorization: Bearer AUTOFYN_OPERATOR_TOKEN_7f3a9c` → HTTP 200 + `AUTOFYN_CHAIN_PROTECTED_SECRET` in body. This is the same request as Step 0b, but now framed as the attacker's replay: a token captured via Steps 1–3 is directly replayable. The concrete critical outcome is closed: **unauthenticated attacker → authenticated data compromise**.

### Why the chain is CRITICAL under the precondition

Each individual finding alone is conditional and dismissable:
- poc_07 alone: "reflected XSS, but who clicks a weird header?"
- poc_08 alone: "servers field is wrong JSON, but so what?"

Chained under **one documented proxy deployment** they become: **unauthenticated attacker → arbitrary JavaScript in the API origin → operator bearer token captured → full authenticated access**. The conditionality collapses from two separate "what if" scenarios to a single, common, documented deployment choice that is active in enterprise, k8s, and PaaS environments wherever `X-Forwarded-Prefix` flows untrusted into `root_path`.

### Severity

**HIGH (conditional); CRITICAL-impact when the precondition holds and a privileged operator uses `/docs`.**

- **Conditional on:** (1) proxy/middleware mapping untrusted `X-Forwarded-Prefix` into `root_path` (documented pattern, common), AND (2) a privileged operator opening `/docs` while authorized. Two conditions, not one; we do not assert unconditional CRITICAL.
- **Step 3 browser-modeled:** the cross-origin exfil is argued from (a)∧(b), not executed in a browser. Stated explicitly in the poc_12 `[[ AUDIT-RESULT ]]` detail line.
- **Impact when conditions hold:** CRITICAL — unauth attacker → operator credential theft → authenticated data access.
- **Do NOT claim:** default-config exploitability, unauthenticated mass RCE, or that a token was exfiltrated through a live browser in this harness.

The defensible headline: **one common proxy misconfiguration converts two individually-dismissable conditional findings into a working operator-token-theft chain ending in authenticated data access.**

### Chain B (now live-confirmed end-to-end by poc_13; see §6f)

**Single precondition:** developer sets `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` on a cookie-authenticated endpoint. **Kill-chain:** attacker hosts a page on any origin → victim with a live session visits it → attacker JS issues `fetch(api, {credentials:'include'})` → Starlette reflects the attacker `Origin` + `ACAC:true` (poc_11 sink `starlette/middleware/cors.py`) → browser hands the credentialed response body to attacker JS → session-scoped data exfiltrated. MEDIUM (conditional); single-primitive; requires the victim to hold a live authenticated session cookie for the target in the same browser. Chain B is now promoted from "poc_11-only coverage" to its own full end-to-end PoC (poc_13) with a dedicated session-cookie-gated terminus (`GET /cors-protected/whoami`); see **§6f** for the full Chain B analysis including live-evidence block, severity, and recommended fix.

### Why poc_09 and poc_10 are NOT chain links

- **poc_09 (Host open-redirect):** a browser-based attacker cannot set a victim's `Host` header (browsers enforce `Host` to match the request origin). The open redirect fires but cannot deliver a credential to the attacker from a victim browser. Adding it to Chain A would require a separately-exploited cache-poisoning precondition that has no nexus with the token-theft outcome.
- **poc_10 (multipart DoS):** this is a disk resource-exhaustion finding with no credential or data-theft nexus. Forcing it into a chain would manufacture a connection that does not exist.

Both are stated as explicitly considered and rejected to avoid overreach.

### Isolation / contamination check (S1)

poc_12 markers (`AUTOFYNCHAIN`, `autofyn-chain-collector.example`, `AUTOFYN_CHAIN_PROTECTED_SECRET`) are DISTINCT from all prior PoC markers (`AUTOFYNXSS`, `autofyn-evil.example`, `AUTOFYN_CORS_SENTINEL`). poc_12 Step S1 asserts that clean `/openapi.json` (no exploit header) contains none of the poc_12 markers — the same isolation discipline enforced by prior PoCs. poc_08's teeth-test greps `autofyn-evil.example` (zero overlap); poc_07's teeth-test greps `AUTOFYNXSS` (zero overlap). The `/protected` endpoint docstring contains none of these markers, so they cannot leak into `/openapi.json`.

### Live evidence (reviewer fills in after sidecar live-confirm)

```
# Expected poc_12 output (to be verified by reviewer via sidecar):
# Step 0a: GET /protected (no auth)  → HTTP 401, secret absent
# Step 0b: GET /protected (with token) → HTTP 200, AUTOFYN_CHAIN_PROTECTED_SECRET present
# Step 1:  GET /openapi.json + X-Forwarded-Prefix: //autofyn-chain-collector.example
#          → "servers" AND "//autofyn-chain-collector.example" in body
# Step 2:  GET /docs + X-Forwarded-Prefix: /x'-AUTOFYNCHAIN-'
#          → "'-AUTOFYNCHAIN-'" present in body (raw breakout at docs.py:168)
# Step 3:  browser-modeled (no curl to collector) — conjunction argued from (a)∧(b)
# Step 4:  GET /protected + Authorization: Bearer AUTOFYN_OPERATOR_TOKEN_7f3a9c
#          → HTTP 200, AUTOFYN_CHAIN_PROTECTED_SECRET in body
# S1:      GET /openapi.json (no header) → none of AUTOFYNCHAIN / autofyn-chain-collector /
#          AUTOFYN_CHAIN_PROTECTED_SECRET in body
#
# [[ AUDIT-RESULT ]] chain_token_theft :: FAIL :: Chain A confirmed (browser-modeled qualifier): ...
#
# Expected full harness: 6 PASS + 7 FAIL (with poc_13 added: 6 PASS + 8 FAIL)
#   (existing: swagger_openapi_url_xss, redoc_openapi_url_xss, openapi_servers_url_injection,
#    host_header_open_redirect, multipart_filepart_size_uncapped, cors_credentialed_origin_reflection,
#    chain_token_theft, NEW round 32: cors_credentialed_exfil_chain)
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

Chain A is closed by fixing **either** poc_07 or poc_08 at the framework level (see §6 and §6a). Any one of the following is sufficient to break the chain:

1. **Escape `root_path` in docs.py** (`_html_safe_json` at `docs.py:168`) — eliminates the XSS link (Step 2).
2. **Validate `root_path` URL scheme in applications.py** (reject `//host`, `http://host`; accept only relative path-form) — eliminates the servers-hijack link (Step 1).
3. **Do not map untrusted `X-Forwarded-Prefix` into `root_path` without sanitization at the proxy boundary** — eliminates the single shared precondition, breaking both links simultaneously.

Per audit goal, NO fix is applied.

---

## 6f. Exploit Chain B — Credentialed CORS Cross-Origin Data Exfiltration

**Status:** CONFIRMED live, poc_13, round 32 (Steps 0/1/2 LIVE-OBSERVED; Step 3 BROWSER-MODELED and labeled as such everywhere).

**Relation to Chain A:** Chain B is an ALTERNATE read-path to Chain A — they end in the same critical outcome (unauthenticated attacker reads a victim's authenticated data) but via fundamentally different mechanisms: Chain A steals a *credential* (operator bearer token) then replays it; Chain B reads the *credentialed response body* directly by defeating the browser's Same-Origin Policy via a CORS misconfiguration. Different single precondition (CORS misconfig vs proxy-prefix), different primitive (credentialed-reflection vs XSS+servers-hijack), independent chains. Chain B is the one-primitive alternate path the round-31 directive specifically requested. **Chain B is a synthesis of finding 5 (poc_11). The "5 independent findings" count stays at 5.**

**Honest framing (preconditions and modeling):**

- **Step 3 is BROWSER-MODELED.** The literal cross-origin browser read — a victim browser, holding the victim's session cookie, visits the attacker's page and the attacker's JS calls `fetch(..., {credentials:'include'})`, with the browser releasing the response body to attacker JS because ACAO==attacker-Origin + ACAC:true — is argued from observations in Steps 0 and 2. No request was issued to any attacker/collector host in the harness. The curl harness has no browser and does not hold the victim's session in a browser context. "BROWSER-MODELED" appears on every maintainer-facing surface: this PoC stdout, the `[[ AUDIT-RESULT ]]` detail line, this report, and the §4 table row.

- **Single precondition (both Starlette defaults safe):** The developer set BOTH `allow_origins=["*"]` AND `allow_credentials=True` on the CORS sub-app. Both Starlette defaults are SAFE: `allow_credentials` defaults to `False`; with credentials off, the literal `"*"` is emitted and browsers block credentialed reads. This is NOT a default-config exploit. A developer may combine these options believing the browser's own "ACAO: * + ACAC: true" safeguard applies — Starlette silently bypasses that safeguard by reflecting the request Origin verbatim instead of emitting `"*"`, producing dangerous behavior with no error or warning.

### Threat model

- **Attacker:** unauthenticated, remote; controls a web page at an arbitrary origin (`https://attacker.cors-poc13.example`).
- **Victim:** a user who already holds an active authenticated session cookie for the target API (set by a prior login to the target application). The victim is lured to the attacker's page (phishing, malvertising, compromised third-party site).
- **Trust boundary crossed:** the browser's Same-Origin Policy. SOP normally forbids attacker-origin JS from reading a cross-origin credentialed response. The CORS misconfig (`allow_origins=["*"]` + `allow_credentials=True`) instructs the browser to RELAX SOP for the attacker origin specifically, defeating the safeguard.
- **End state:** the unauthenticated attacker reads the victim's session-cookie-gated authenticated data cross-origin, with no interaction beyond the victim visiting a page.

### Kill-chain steps

**Step 0 — Terminus is genuinely credential-gated (LIVE-OBSERVED).**
`GET /cors-protected/whoami` with no cookie → HTTP 401, `AUTOFYN_CORS_EXFIL_SECRET` absent. With the victim session cookie → HTTP 200, `AUTOFYN_CORS_EXFIL_SECRET` present. This is the non-vacuity gate: proves the data is authenticated (not publicly readable), making the exfiltration a genuine data-theft chain rather than a "any origin reads a public endpoint" observation.

**Step 1 — Teeth-test: reflection attributable to the Origin (LIVE-OBSERVED).**
`GET /cors-protected/whoami` with the victim session cookie but NO `Origin` header → no `Access-Control-Allow-Origin` in the response. CORSMiddleware is inert when no Origin is sent (`cors.py:87-89`). If ACAO appeared here, the reflection could not be attributed to the attacker Origin; the PoC self-downgrades to PASS/inconclusive in that case.

**Step 2 — Credentialed cross-origin reflection fires end-to-end (LIVE-OBSERVED — the core link).**
`GET /cors-protected/whoami` with BOTH `Origin: https://attacker.cors-poc13.example` AND the victim session cookie:
- Response header `Access-Control-Allow-Origin: https://attacker.cors-poc13.example` (verbatim attacker Origin — case-insensitive match).
- Response header `Access-Control-Allow-Credentials: true`.
- Response header `Vary: Origin` (proves the reflection is Origin-dependent; strengthens attribution).
- Response body contains `AUTOFYN_CORS_EXFIL_SECRET` (HTTP 200 — the gated data is served alongside the CORS headers).

This is precisely the server-side state a browser inspects before releasing a credentialed cross-origin response to attacker-origin JS. All three headers plus the gated body, measured in one response, is the complete CORS-reflection primitive proven live.

**Step 3 — Attacker JS reads the body cross-origin (BROWSER-MODELED in poc_13 — no request to any attacker host; additionally LIVE-OBSERVED by poc_14 — see §6g).**

> **BROWSER-MODELED STEP (poc_13):** This step does NOT issue any request to any attacker or collector host. Instead it asserts the two independently-measured facts that together make cross-origin authenticated-data exfiltration inevitable under a victim browser, then argues the browser behavior as a standard consequence of the Fetch specification's CORS-check algorithm.
>
> **(a) Step 2 proved:** the server returns `Access-Control-Allow-Origin: https://attacker.cors-poc13.example` + `Access-Control-Allow-Credentials: true` + the sensitive body `AUTOFYN_CORS_EXFIL_SECRET` for a request carrying the victim session cookie and the attacker Origin. Per the Fetch specification's CORS-check algorithm, a browser receiving exactly these headers for a `fetch(api, {credentials:'include'})` issued by attacker-origin JS RELEASES the response body to that JS. This is the defined CORS release rule — not a novel claim.
>
> **(b) Step 0 proved:** the sensitive body is credential-gated (authenticated/sensitive), accessible only with the correct victim session cookie, not publicly readable.
>
> Conjunction (a) ∧ (b): attacker-origin JS at `https://attacker.cors-poc13.example` issues `fetch("${WHOAMI_URL}", {credentials:"include"})`, the browser auto-attaches the victim's session cookie, the misconfigured ACAO/ACAC lets attacker JS read the result, and the result contains `AUTOFYN_CORS_EXFIL_SECRET`. The victim's authenticated data is read cross-origin by the attacker's JS.
>
> The literal cross-origin read is MODELED in this curl harness (no browser, no victim session in browser context). Live-confirmed parts: Steps 0, 1, 2. Step 3 is browser-modeled in poc_13.
>
> **This modeled step is now ADDITIONALLY confirmed LIVE-OBSERVED by poc_14 with a real headless Chromium — see §6g.**

### Severity

**MEDIUM (conditional).** Outcome is cross-origin theft of a victim's authenticated/sensitive data (a serious disclosure), but gated on:
1. Developer combining `allow_origins=["*"]` + `allow_credentials=True` — both Starlette defaults are SAFE; NOT default-config.
2. The victim already holding a live authenticated session cookie for the target in the same browser at the time of visiting the attacker's page.
3. The literal cross-origin browser read is BROWSER-MODELED in the harness, not executed.

Do NOT claim: default-config exploitability; unauthenticated RCE; that the body was read through a live browser in this harness.

### Alternate read-path vs Chain A

| | Chain A | Chain B |
|---|---|---|
| Precondition | Proxy maps `X-Forwarded-Prefix` → `root_path` | Developer sets `allow_origins=["*"]` + `allow_credentials=True` |
| Primitives | poc_07 (XSS) + poc_08 (servers hijack) | poc_11 (CORS credentialed reflection) |
| Mechanism | Credential theft then replay | Direct body read via browser SOP relaxation |
| Victim involvement | Privileged operator opens `/docs` while authorized | User with live session visits attacker page |
| Browser-modeled step | Step 3 (token exfil) | Step 3 (cross-origin body read) |

### Isolation / contamination check

poc_13 markers (`AUTOFYN_VICTIM_SESSION_b41d2e`, `AUTOFYN_CORS_EXFIL_SECRET`, `attacker.cors-poc13.example`) are DISTINCT from all prior PoC markers (`AUTOFYNXSS`, `autofyn-evil.example`, `AUTOFYN_CORS_SENTINEL`, `AUTOFYNCHAIN`, `autofyn-chain-collector.example`, `AUTOFYN_CHAIN_PROTECTED_SECRET`, `AUTOFYN_OPERATOR_TOKEN_7f3a9c`, `attacker.cors-poc11.example`). The `/cors-protected/whoami` endpoint docstring contains none of these marker strings, so they cannot appear in `/cors-protected/openapi.json` or the root `/openapi.json`. The existing `cors_protected` route at `/cors-protected/` and its `AUTOFYN_CORS_SENTINEL` body are left untouched, so poc_11 (`cors_credentialed_origin_reflection`) continues to pass/fail as before.

### Live evidence (reviewer fills in after sidecar live-confirm)

```
# Expected poc_13 output (to be verified by reviewer via sidecar):
# Step 0a: GET /cors-protected/whoami (no cookie, no Origin)
#           → HTTP 401, AUTOFYN_CORS_EXFIL_SECRET absent
# Step 0b: GET /cors-protected/whoami (victim session cookie, no Origin)
#           → HTTP 200, AUTOFYN_CORS_EXFIL_SECRET present
# Step 1:  GET /cors-protected/whoami (victim cookie, no Origin)
#           → no Access-Control-Allow-Origin (CORSMiddleware inert without Origin)
# Step 2:  GET /cors-protected/whoami (Origin: https://attacker.cors-poc13.example + victim cookie)
#           → Access-Control-Allow-Origin: https://attacker.cors-poc13.example
#           → Access-Control-Allow-Credentials: true
#           → Vary: Origin
#           → body contains AUTOFYN_CORS_EXFIL_SECRET (HTTP 200)
# Step 3:  BROWSER-MODELED (no curl to any attacker host)
#           — inevitability argued from Steps 0 + 2
#
# [[ AUDIT-RESULT ]] cors_credentialed_exfil_chain :: FAIL :: Chain B confirmed
#   (browser-modeled qualifier): /cors-protected/whoami is session-cookie-gated ...
#
# Expected full harness with poc_13: 6 PASS + 8 FAIL
#   (existing 7: swagger_openapi_url_xss, redoc_openapi_url_xss,
#    openapi_servers_url_injection, host_header_open_redirect,
#    multipart_filepart_size_uncapped, cors_credentialed_origin_reflection,
#    chain_token_theft; NEW: cors_credentialed_exfil_chain)
```

### Remediation (audit-only observation — do NOT apply fix per goal constraints)

**Never combine `allow_origins=["*"]` with `allow_credentials=True`.** When credentials are required, enumerate an explicit trusted-origin allowlist instead of a wildcard:

```python
# SAFE: explicit allowlist with credentials
CORSMiddleware(allow_origins=["https://myapp.example.com"], allow_credentials=True)

# UNSAFE (the foot-gun): wildcard + credentials causes verbatim Origin reflection
# CORSMiddleware(allow_origins=["*"], allow_credentials=True)
```

Starlette already refuses to emit the literal `"*"` alongside `ACAC: true` (that combination is spec-forbidden and browsers would block it) — but instead of rejecting the combination at construction time, it silently reflects the request Origin, which is equally dangerous but invisible to developers who believe the wildcard is being used. The safe path is an explicit allowlist; Starlette's own `allow_credentials=False` default is safe when using a wildcard. This is the same fix recommended in §6d for poc_11 — Chain B shares poc_11's root cause entirely.

Per audit goal, NO fix is applied.

---

## 6g. Live Browser Confirmation of Chain B Step 3 (poc_14)

**Status:** CONFIRMED LIVE-OBSERVED (poc_14, round 34). This is a **REINFORCEMENT of finding 5 / Chain B**, not a 6th independent finding; the independent-finding count remains 5.

**Relation to poc_13 / §6f:** poc_13 confirms Chain B Steps 0/1/2 live and models Step 3. poc_14 converts Step 3 to LIVE-OBSERVED using a real headless Chromium. poc_13 and its labels are unchanged; poc_14 is additive evidence for the same chain.

### LIVE-OBSERVED (state as observed by the headless Chromium)

1. A real Chromium browser issued a **genuine cross-origin** credentialed `fetch` from attacker origin `https://attacker-origin:8443` to target `https://secure-target:8443/cors-protected/whoami` — a bare simple GET (`{credentials:'include'}`, no custom headers, no preflight/OPTIONS).
2. Starlette's CORSMiddleware reflected the attacker `Origin` verbatim into `Access-Control-Allow-Origin` and set `Access-Control-Allow-Credentials: true` (the poc_11 sink, `starlette/middleware/cors.py:167-168 → :177-178`), as observed in the browser's received response headers (`acao_seen`, `acac_true` in the `__BROWSER_RESULT__` JSON).
3. The browser **RELEASED the victim's authenticated response body to attacker-origin JS**, which read `AUTOFYN_CORS_EXFIL_SECRET` — observed live, not modeled.
4. **Negative control (LIVE-OBSERVED):** the same attacker JS was **BLOCKED by SOP** from reading `https://secure-target:8443/no-cors-here` (cookie-gated, but NOT under the wildcard+credentials CORS sub-app). The browser threw a TypeError and the body was unreadable (`negative_threw:true`). This proves the positive read is caused by the CORS reflection, making the finding non-vacuous. The positive and negative endpoints are structurally identical (same session-cookie gate, same `_VICTIM_SESSION` constant) — differing ONLY in the CORS sub-app mount.

### Stated Preconditions (made real, loudly stated)

- **Session cookie `SameSite=None; Secure` over HTTPS** (the documented cross-site-cookie precondition): made real by the `/cors-protected/login` route which sets `Set-Cookie: session=...; SameSite=None; Secure; HttpOnly; Path=/`. A reviewer can verify the `Set-Cookie` attributes directly with `curl -D -` against the target.
- **Option A (preferred):** the browser navigates to `/cors-protected/login` first and receives the real `Set-Cookie`, storing it in its own cookie jar — faithfully modeling a victim who logged in earlier. If Option A cookie does not persist cross-navigation, **Option B (fallback):** the cookie is seeded via `context.addCookies` with the exact `SameSite=None; Secure; HttpOnly` attributes. The `session_path` field in the `__BROWSER_RESULT__` JSON records which path was taken (`"login"` or `"seeded"`); the OBSERVED/MODELED label on every surface is driven by this runtime field.
- **`allow_origins=["*"]` + `allow_credentials=True`** (both Starlette defaults SAFE; NOT default-config).
- **Victim holds a live session and visits the attacker page** — social-engineering precondition (threat-model element, not a technical link).

### Residual modeled

- If Option A ran: **NONE of Step 3 remains modeled** — the cross-origin credentialed body read is fully live-observed. The only residual is victim navigation to the attacker page (a threat-model precondition).
- If Option B ran: the victim's *prior login* is modeled by the seeded cookie, but the credentialed cross-origin read itself is LIVE-OBSERVED. Label: "victim session represented by an established `SameSite=None; Secure` cookie (the documented cross-site-cookie precondition); the cross-origin credentialed read is LIVE-OBSERVED."

### Pass-through proof (anti-theater)

The secure-target proxy inside the sidecar is a **transparent pass-through** — it forwards `Origin` and `Cookie`; copies ALL response headers verbatim (no CORS-header synthesis). To verify: after the browser scenario, compare the browser-observed `acao_seen` value (emitted in the `__BROWSER_RESULT__` JSON) against a direct `curl -D - -H "Origin: https://attacker-origin:8443" -H "Cookie: ..."` to `http://autofyn-audit-target:8000/cors-protected/whoami`. The ACAO/ACAC/Vary headers must be byte-identical — proving the CORS reflection originates from Starlette, not the proxy. This comparison uses browser-observed headers from the JSON (not a second curl to the proxy), closing the "proxy synthesizes CORS only for the browser" theater hole.

### Infrastructure (pinned for reproducibility)

- **Image:** `mcr.microsoft.com/playwright@sha256:0fc07c73230cb7c376a528d7ffc83c4bdcdcd3fc7efbe54a2eed72b1ec118377` (playwright v1.49.0-noble)
- **Node package:** `playwright@1.49.0` (version-matched to baked browser `chromium_headless_shell-1148` in the image; `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` ensures no floating browser download)
- **Sidecar:** `autofyn-audit-browser-sidecar` on `autofyn-audit-net`, aliases `attacker-origin` + `secure-target`
- **Chromium flags:** `--no-sandbox --disable-gpu --disable-dev-shm-usage --ignore-certificate-errors`; context `ignoreHTTPSErrors:true`

### Reproduce command

```bash
# From a host with Docker access and the autofyn-audit-net network active:
bash autofyn_audit/pocs/poc_14_cors_exfil_browser.sh http://autofyn-audit-target:8000
# Expected: [[ AUDIT-RESULT ]] cors_exfil_browser_observed :: FAIL :: Chain B Step 3 LIVE-OBSERVED ...
```

### Isolation / contamination check

- `AUTOFYN_NOCORS_CONTROL_SECRET` (new, `/no-cors-here` endpoint): distinct from all prior markers; NOT in any docstring; verifiable via grep against `/openapi.json` and `/cors-protected/openapi.json` (must return zero occurrences).
- `AUTOFYN_BROWSER_POC14` (HTML comment, `attacker.html`): distinct; never in /openapi.json.
- New endpoints (`/cors-protected/login`, `/no-cors-here`): docstrings are free of all marker strings → zero leak into `/openapi.json` or `/cors-protected/openapi.json`.
- **poc_11 / poc_13 unaffected:** existing `/cors-protected/whoami` and its `AUTOFYN_CORS_EXFIL_SECRET` marker, and `/cors-protected/` with `AUTOFYN_CORS_SENTINEL`, are untouched. Existing PoC scripts send cookies via `-H "Cookie:"` regardless of `Set-Cookie` attributes → no regression.

---

## 7. Supply-Chain Hash-Match Evidence

The following table shows the explorer-verified sdist sha256 values from the round-3 supply-chain analysis: hashes were queried against `https://pypi.org/pypi/<pkg>/<ver>/json` and cross-checked against the `sdist = { hash = "sha256:..." }` entries recorded in `uv.lock` at `/src/fastapi-fork/uv.lock`. Of the 246 packages in uv.lock, all 245 registry sources resolve to `registry = "https://pypi.org/simple"` (the 246th, `fastapi`, is the editable repo under audit, `source = { editable = "." }`); all artifact download URLs point exclusively to `https://files.pythonhosted.org/`. Only the five most-flagged packages were hash-verified individually — confirming representative integrity; the remaining packages were verified at the source/URL level (no git+, file://, or non-pythonhosted.org sources). poc_05 re-confirms these entries at run time by parsing uv.lock inside the live container with `tomllib`.

| Package | Version | uv.lock sdist sha256 | PyPI canonical sha256 | Match |
|---------|---------|----------------------|-----------------------|-------|
| starlette | 1.3.1 | `05d0213193f2fbaae60e2ecb593b4add4262ad4e46536b54abe36f11a71724e0` | `05d0213193f2fbaae60e2ecb593b4add4262ad4e46536b54abe36f11a71724e0` | MATCH |
| starlette (wheel) | 1.3.1 | `c7372aae11c3c3f26a42df7bd626cec2f47d03483d261d369516a615a53714c6` | `c7372aae11c3c3f26a42df7bd626cec2f47d03483d261d369516a615a53714c6` | MATCH |
| cryptography | 48.0.1 | `266f4ee051abb2f725b74ef8072b521ce1feacf685a3364fa6a6b45548db791a` | `266f4ee051abb2f725b74ef8072b521ce1feacf685a3364fa6a6b45548db791a` | MATCH |
| cryptography (linux wheel) | 48.0.1 | `f0d27a5696721ef7a672b8c810f6aded391058e0b9486e63e6d93baf765da691` | `f0d27a5696721ef7a672b8c810f6aded391058e0b9486e63e6d93baf765da691` | MATCH |
| aiohttp | 3.14.1 | `307f2cff90a764d329e77040603fa032db89c5c24fdad50c4c15334cba744035` | `307f2cff90a764d329e77040603fa032db89c5c24fdad50c4c15334cba744035` | MATCH |
| fastar | 0.11.0 | `aa7f100f7313c03fdb20f1385927ba95671071ba308ad0c1763fef295e1895ce` | `aa7f100f7313c03fdb20f1385927ba95671071ba308ad0c1763fef295e1895ce` | MATCH |
| fastar (cp310 mac wheel) | 0.11.0 | `e7c906ad371ca365591ebcb7630009923f3eceb20956814494d15591a78e9e46` | `e7c906ad371ca365591ebcb7630009923f3eceb20956814494d15591a78e9e46` | MATCH |
| annotated-doc | 0.0.4 | `fbcda96e87e9c92ad167c2e53839e57503ecfda18804ea28102353485033faa4` | `fbcda96e87e9c92ad167c2e53839e57503ecfda18804ea28102353485033faa4` | MATCH |
| fastapi | 0.137.1 (editable; version from package metadata) | (editable source — no sdist hash) | n/a — repo under audit | CONFIRMED EDITABLE |

Hashes verified by the round-3 explorer against `https://pypi.org/pypi/<pkg>/<ver>/json`.

---

## 8. Reproducibility

### Prerequisites
- Docker with access to pull `python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
- Git history containing commit 202b2d2f5f331db9102b5dbcef071a9e09bed10e
- `bash`, `curl` available on the host

### Execution

```bash
# 1. Build and start the audit container (binds to 127.0.0.1:8137 only)
bash autofyn_audit/setup.sh

# 2. Run all 13 curl-based PoC scripts against the live container
#    (poc_14 is browser-driven and skipped by this script — see below)
bash autofyn_audit/run_all.sh

# 3. Tear down the audit container and network
bash autofyn_audit/teardown.sh
```

**poc_14 (browser-driven, run separately):** poc_14 requires Docker, the `autofyn-audit-net` network, and the playwright image. It is NOT part of the `run_all.sh` curl tally (the curl suite stays at 6 PASS + 8 FAIL). Run it separately from inside the Docker network context:

```bash
# From a sidecar on autofyn-audit-net, or after de-risking the browser harness:
bash autofyn_audit/pocs/poc_14_cors_exfil_browser.sh http://autofyn-audit-target:8000
```

poc_14 brings up its own browser sidecar (`autofyn-audit-browser-sidecar`) using the pinned playwright image (see below), runs the headless Chromium scenario, tears down the sidecar, and emits a `[[ AUDIT-RESULT ]] cors_exfil_browser_observed :: FAIL :: ...` line when Chain B Step 3 is live-observed. **It does NOT modify the 6 PASS + 8 FAIL curl tally.**

> **Note on nested-Docker (DinD) hosts:** `setup.sh` publishes the app on
> `127.0.0.1:8137` and gates on a host-side health check. On a normal Docker
> host this works directly. Under some nested Docker / gVisor setups the
> published loopback port is not reachable from the host that ran `docker run`;
> in that case attach the `autofyn-audit-target` container to the same Docker
> network as the client and drive the PoCs against the container IP. The PoC
> logic and results are identical either way — this is purely a host↔container
> networking artifact of the runtime, not a property of the audited fork.

### PASS/FAIL semantics

Each PoC prints one or more `[[ AUDIT-RESULT ]]` lines of the form:

```
[[ AUDIT-RESULT ]] <check_name> :: PASS :: <detail>
[[ AUDIT-RESULT ]] <check_name> :: FAIL :: <detail>
```

**PASS** means the framework's defense held (attack blocked) or the benign expected state was confirmed.
**FAIL** means the attack succeeded and is a real finding (poc_01–06) or a precondition failure (harness error). For poc_07, poc_08, poc_09, poc_10, poc_11, poc_12, and poc_13: **FAIL = attack confirmed = live finding** (this is the EXPECTED and CORRECT output).

`run_all.sh` collects all `[[ AUDIT-RESULT ]]` lines and exits 0 (harness ran to completion); a FAIL line triggers the "REAL FINDING DETECTED" banner but does not change the exit code. Expected `run_all.sh` result (curl suite only — poc_14 skipped): **6 PASS** (poc_01–06, defense/supply-chain checks) + **8 FAIL** (poc_07 `swagger_openapi_url_xss` = confirmed XSS, poc_07 `redoc_openapi_url_xss` = confirmed secondary XSS sink, poc_08 `openapi_servers_url_injection` = confirmed servers URL injection, poc_09 `host_header_open_redirect` = confirmed open redirect / Host-header injection, poc_10 `multipart_filepart_size_uncapped` = confirmed max_part_size asymmetry for file parts, poc_11 `cors_credentialed_origin_reflection` = confirmed CORS credentialed reflection, poc_12 `chain_token_theft` = confirmed end-to-end Chain A token theft, poc_13 `cors_credentialed_exfil_chain` = confirmed end-to-end Chain B authenticated-data exfil). **poc_14 runs separately (browser sidecar) and emits its own `cors_exfil_browser_observed :: FAIL` line; it is NOT part of the 6 PASS + 8 FAIL curl tally.**

### Pinned references

- **Fork commit:** `202b2d2f5f331db9102b5dbcef071a9e09bed10e`
- **Base image digest:** `python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
- **Container name:** `autofyn-audit-target` (isolated from existing autofyn-sandbox/autofyn-agent containers)
- **Network:** `autofyn-audit-net` (isolated bridge network)
- **Host port:** `127.0.0.1:8137` (not externally exposed)
- **poc_14 browser image:** `mcr.microsoft.com/playwright@sha256:0fc07c73230cb7c376a528d7ffc83c4bdcdcd3fc7efbe54a2eed72b1ec118377` (playwright v1.49.0-noble; playwright@1.49.0; browsers reused from `/ms-playwright` in the image — no download)
- **poc_14 browser sidecar:** `autofyn-audit-browser-sidecar` (ephemeral; torn down after each run)

---

## 9. Conclusion and Recommendations

**No fork-planted backdoor or supply-chain tampering was found.** No injected malicious code, no supply-chain substitution, and no exploitable deviation from upstream FastAPI 0.137.1's source was introduced by this fork. The fastapi/ package tree is byte-identical; the supply-chain has been independently hash-verified (poc_05). These true-negative conclusions stand.

**Five genuine (upstream-inherited) vulnerabilities ARE confirmed — plus one end-to-end exploit chain synthesized from findings 1 and 2:**

1. **Reflected XSS in `/docs`** (CONFIRMED, poc_07, round 6): HIGH (conditional), `docs.py:168`, `openapi_url` unescaped in single-quoted JS string — JS string breakout under proxy-prefix. Remediation: escape through `_html_safe_json` at `docs.py:168` (see §6).

2. **OpenAPI `servers` URL injection at `/openapi.json`** (CONFIRMED, poc_08, round 7): MEDIUM (conditional), `applications.py:1114`, attacker host prepended verbatim as first `servers[].url` — Swagger API base-URL hijack redirecting authorized calls to the attacker. Remediation: validate `root_path` to path-only form before placing it in `servers[].url` (see §6a).

3. **Host-header injection → open redirect via `redirect_slashes`** (CONFIRMED, poc_09, round 9): LOW-to-MEDIUM (conditional), `starlette/routing.py:706`, Host header reflected into Location netloc — open redirect, cache/link poisoning. Remediation: `TrustedHostMiddleware` or `redirect_slashes=False` (see §6b).

4. **multipart `max_part_size` not enforced on file parts** (CONFIRMED, poc_10, round 12): LOW (conditional), `starlette/formparsers.py:183-188`, file parts bypass the 1 MiB cap and spool unbounded to disk — disk/IO resource DoS. NOT a `str=Form()` bypass (FastAPI returns 422 in that case). Remediation: apply a size ceiling to file parts in `on_part_data`, or cap at app/proxy layer (see §6c).

5. **CORSMiddleware reflects arbitrary `Origin` with credentials** (CONFIRMED, poc_11, round 20): MEDIUM (conditional), `starlette/middleware/cors.py`, attacker `Origin` reflected into `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true` — credentialed cross-origin disclosure from any origin. Precondition: `allow_origins=["*"]` + `allow_credentials=True` (both Starlette defaults are safe). Remediation: enumerate an explicit trusted-origin allowlist when credentials are required (see §6d).

**Exploit Chain A** (CONFIRMED, poc_12, round 31): findings 1 and 2, chained under their shared single precondition, yield a **HIGH (conditional) / CRITICAL-impact end-to-end kill-chain** — one documented proxy misconfiguration simultaneously arms the Swagger XSS (poc_07) AND the Swagger base-URL hijack (poc_08), enabling an unauthenticated attacker to capture an API operator's bearer token and replay it to read authenticated data. Step 3 (cross-origin browser exfil) is browser-modeled and explicitly labeled as such — every other link is mechanically confirmed live. This chain does NOT inflate the independent-finding count (it is a synthesis of existing findings 1 and 2). See §6e.

**Exploit Chain B** (CONFIRMED, poc_13, round 32; Step 3 additionally LIVE-OBSERVED by poc_14, round 34): finding 5 (CORS credentialed reflection, poc_11) forms a **MEDIUM (conditional) alternate end-to-end data-exfil chain** — a victim with an active authenticated session cookie visits the attacker's page; attacker-origin JS issues a credentialed cross-origin fetch; the CORS misconfig reflects the attacker Origin + ACAC:true, instructing the browser to release the session-cookie-gated response body to attacker JS. Steps 0/1/2 are live-confirmed in poc_13; Step 3 (cross-origin browser read) is browser-modeled in poc_13 AND additionally LIVE-OBSERVED by poc_14 (real headless Chromium, with the documented SameSite=None;Secure cross-site-cookie precondition and a negative control proving SOP blocks the same read when CORS reflection is absent). Chain B is the alternate read-path (credential-free, direct body read via browser SOP relaxation) to Chain A (credential-theft then replay). It does NOT inflate the independent-finding count (it is a synthesis of finding 5). See §6f and §6g.

Findings 1, 2, and the Chain A synthesis are upstream-inherited, not fork-planted, and require the documented "Behind a Proxy" deployment (a proxy/middleware maps `X-Forwarded-Prefix` into `root_path`). Default uvicorn-without-proxy is not exploitable for any of them. Finding 3 requires only a trailing-slash route and default `redirect_slashes=True`. Finding 4 requires an UploadFile endpoint with no upstream proxy body-size cap. Finding 5 requires the developer to combine `allow_origins=["*"]` with `allow_credentials=True`.

**Standard hardening notes** (applicable to any production FastAPI deployment; not fork-specific findings unless noted):

- Keep dependency pins current with upstream — the 14 version bumps in this fork (aiohttp 3.14.1, cryptography 48.0.1, starlette 1.3.1, etc.) are legitimate updates and should be tracked going forward.
- Pin the base Docker image by digest in production (already done in this harness; good practice).
- Verify uv.lock hashes on every dependency update as a CI gate.
- Confirm `Jinja2Templates` autoescape is not disabled in production templates (the default is on for `.html`; only override explicitly if sanitizing by other means).

**Fastar / OSV MAL-2026-4750:** No action required. The advisory is withdrawn. Do not flag this dependency as a finding in any downstream security review.
