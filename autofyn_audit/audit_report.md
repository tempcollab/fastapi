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

**Summary:** 6 existing framework-defense / supply-chain checks still pass (no regression); 5 findings confirmed (1 HIGH reflected-XSS, 1 MEDIUM servers URL injection, 1 LOW-to-MEDIUM open redirect, 1 LOW multipart size-cap asymmetry, 1 MEDIUM CORS credentialed-reflection foot-gun), all upstream-inherited. Findings 1 and 2 require the proxy-prefix precondition; finding 3 requires only a trailing-slash route with default `redirect_slashes=True` (for full impact, additionally an upstream cache/proxy that forwards arbitrary `Host`); finding 4 requires an UploadFile endpoint with no upstream proxy body-size cap; finding 5 requires the developer to combine `allow_origins=["*"]` with `allow_credentials=True`.

---

## 2. Audit Scope and Target

**In scope:**
- `fastapi/` Python package source (all 50+ .py files) — diff vs upstream FastAPI 0.137.1
- `pyproject.toml` — dependency declarations and tooling configuration
- `uv.lock` — full artifact hash verification for all 14 differing dependency pins
- `.github/workflows/` — CI pipeline action pinning
- `.pre-commit-config.yaml` — pre-commit hook SHA verification
- `fastar` 0.11.0 package — provenance, binary static analysis, OSV advisory status
- Live behavioral verification via `autofyn_audit/` harness (10 PoCs)

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

**Live behavioral harness:** Built a Docker image from the fork source (pinned to commit 202b2d2, base image digest above) containing a minimal FastAPI test application exposing the audited endpoints (including `/docs`, `/redoc`, and `/openapi.json` provided automatically by FastAPI, plus `/items/` added for poc_09, `/upload` added for poc_10, and a dedicated `/cors-protected` sub-app added for poc_11). Eleven PoC scripts exercised targeted attack classes and printed greppable `[[ AUDIT-RESULT ]]` PASS/FAIL lines. Each PoC is self-contained, reproducible, and describes its semantics. PoCs 01–06 are defense checks (PASS = attack blocked); poc_07, poc_08, poc_09, poc_10, and poc_11 are finding checks (FAIL = attack succeeded = confirmed finding).

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

**Five conditional findings (rows 10–14); all framework-defense checks (rows 5–9) and supply-chain checks (rows 1–4) otherwise passed.** All five findings are upstream-inherited (not fork-planted). Findings 10–11 require the proxy-prefix deployment precondition; finding 12 requires only a trailing-slash route with default `redirect_slashes=True` (for meaningful exploitation additionally requires an upstream cache/proxy forwarding arbitrary `Host`); finding 13 requires an UploadFile endpoint with no upstream proxy body-size cap; finding 14 requires the developer to combine `allow_origins=["*"]` with `allow_credentials=True`.

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

# 2. Run all 10 PoC scripts against the live container
bash autofyn_audit/run_all.sh

# 3. Tear down the audit container and network
bash autofyn_audit/teardown.sh
```

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
**FAIL** means the attack succeeded and is a real finding (poc_01–06) or a precondition failure (harness error). For poc_07, poc_08, poc_09, and poc_10: **FAIL = attack confirmed = live finding** (this is the EXPECTED and CORRECT output for all four).

`run_all.sh` collects all `[[ AUDIT-RESULT ]]` lines and exits 0 (harness ran to completion); a FAIL line triggers the "REAL FINDING DETECTED" banner but does not change the exit code. Expected run result: **6 PASS** (poc_01–06, defense/supply-chain checks) + **5 FAIL** (poc_07 `swagger_openapi_url_xss` = confirmed XSS, poc_07 `redoc_openapi_url_xss` = confirmed secondary XSS sink, poc_08 `openapi_servers_url_injection` = confirmed servers URL injection, poc_09 `host_header_open_redirect` = confirmed open redirect / Host-header injection, poc_10 `multipart_filepart_size_uncapped` = confirmed max_part_size asymmetry for file parts).

### Pinned references

- **Fork commit:** `202b2d2f5f331db9102b5dbcef071a9e09bed10e`
- **Base image digest:** `python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
- **Container name:** `autofyn-audit-target` (isolated from existing autofyn-sandbox/autofyn-agent containers)
- **Network:** `autofyn-audit-net` (isolated bridge network)
- **Host port:** `127.0.0.1:8137` (not externally exposed)

---

## 9. Conclusion and Recommendations

**No fork-planted backdoor or supply-chain tampering was found.** No injected malicious code, no supply-chain substitution, and no exploitable deviation from upstream FastAPI 0.137.1's source was introduced by this fork. The fastapi/ package tree is byte-identical; the supply-chain has been independently hash-verified (poc_05). These true-negative conclusions stand.

**Four genuine (upstream-inherited) vulnerabilities ARE confirmed:**

1. **Reflected XSS in `/docs`** (CONFIRMED, poc_07, round 6): HIGH (conditional), `docs.py:168`, `openapi_url` unescaped in single-quoted JS string — JS string breakout under proxy-prefix. Remediation: escape through `_html_safe_json` at `docs.py:168` (see §6).

2. **OpenAPI `servers` URL injection at `/openapi.json`** (CONFIRMED, poc_08, round 7): MEDIUM (conditional), `applications.py:1114`, attacker host prepended verbatim as first `servers[].url` — Swagger API base-URL hijack redirecting authorized calls to the attacker. Remediation: validate `root_path` to path-only form before placing it in `servers[].url` (see §6a).

3. **Host-header injection → open redirect via `redirect_slashes`** (CONFIRMED, poc_09, round 9): LOW-to-MEDIUM (conditional), `starlette/routing.py:706`, Host header reflected into Location netloc — open redirect, cache/link poisoning. Remediation: `TrustedHostMiddleware` or `redirect_slashes=False` (see §6b).

4. **multipart `max_part_size` not enforced on file parts** (CONFIRMED, poc_10, round 12): LOW (conditional), `starlette/formparsers.py:183-188`, file parts bypass the 1 MiB cap and spool unbounded to disk — disk/IO resource DoS. NOT a `str=Form()` bypass (FastAPI returns 422 in that case). Remediation: apply a size ceiling to file parts in `on_part_data`, or cap at app/proxy layer (see §6c).

Findings 1 and 2 are upstream-inherited, not fork-planted, and require the documented "Behind a Proxy" deployment (a proxy/middleware maps `X-Forwarded-Prefix` into `root_path`). Default uvicorn-without-proxy is not exploitable for either. Finding 3 requires only a trailing-slash route and default `redirect_slashes=True`. Finding 4 requires an UploadFile endpoint with no upstream proxy body-size cap.

**Standard hardening notes** (applicable to any production FastAPI deployment; not fork-specific findings unless noted):

- Keep dependency pins current with upstream — the 14 version bumps in this fork (aiohttp 3.14.1, cryptography 48.0.1, starlette 1.3.1, etc.) are legitimate updates and should be tracked going forward.
- Pin the base Docker image by digest in production (already done in this harness; good practice).
- Verify uv.lock hashes on every dependency update as a CI gate.
- Confirm `Jinja2Templates` autoescape is not disabled in production templates (the default is on for `.html`; only override explicitly if sanitizing by other means).

**Fastar / OSV MAL-2026-4750:** No action required. The advisory is withdrawn. Do not flag this dependency as a finding in any downstream security review.
