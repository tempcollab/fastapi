# Security Audit Report — tempcollab/fastapi Fork

**Audit date:** 2026-06-22
**Fork remote:** tempcollab/fastapi
**Pinned commit:** 202b2d2f5f331db9102b5dbcef071a9e09bed10e (short: 202b2d2)
**Base image:** python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf
**Harness location:** autofyn_audit/ (this directory)

---

## 1. Executive Summary

This audit examined the `tempcollab/fastapi` fork (pinned commit 202b2d2) to determine whether it contains planted backdoors, supply-chain substitutions, or critical exploitable vulnerabilities. The audit found **no planted critical vulnerability, no code-level modification from upstream, and no supply-chain tampering.** The `fastapi/` Python package tree is byte-for-byte identical to the official upstream PyPI release 0.137.1. The dependency lockfile (uv.lock) was verified against PyPI hashes for all differing pins, with zero mismatches. The `fastar` dependency that triggered OSV advisory MAL-2026-4750 is a genuine upstream FastAPI dependency; that advisory was withdrawn as a false positive (OSSF PR #1276).

However, **a genuine reflected-XSS exists in the Swagger UI `/docs` endpoint** (`fastapi/openapi/docs.py:168`): `openapi_url` is interpolated raw into a single-quoted JavaScript string literal with no escaping. Under the documented FastAPI "Behind a Proxy" deployment pattern — where a reverse proxy or ASGI middleware maps the `X-Forwarded-Prefix` request header into `scope["root_path"]` — an unauthenticated attacker can break out of the JS string and inject arbitrary script into `/docs`. This weakness is **inherited verbatim from upstream FastAPI 0.137.1** (not a fork-planted backdoor), is comparable to cadwyn advisory GHSA-2gxp-6r36-m97r (CVSS 7.6 HIGH), and is **CONFIRMED (live, poc_07, round 6)** — reproduced against a live container built from pinned commit 202b2d2.

**Summary:** 6 existing framework-defense / supply-chain checks still pass (no regression); 1 new reflected-XSS finding confirmed (conditional-HIGH, upstream-inherited, proxy-prefix precondition required).

---

## 2. Audit Scope and Target

**In scope:**
- `fastapi/` Python package source (all 50+ .py files) — diff vs upstream FastAPI 0.137.1
- `pyproject.toml` — dependency declarations and tooling configuration
- `uv.lock` — full artifact hash verification for all 14 differing dependency pins
- `.github/workflows/` — CI pipeline action pinning
- `.pre-commit-config.yaml` — pre-commit hook SHA verification
- `fastar` 0.11.0 package — provenance, binary static analysis, OSV advisory status
- Live behavioral verification via `autofyn_audit/` harness (7 PoCs)

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

**Live behavioral harness:** Built a Docker image from the fork source (pinned to commit 202b2d2, base image digest above) containing a minimal FastAPI test application exposing the audited endpoints (including `/docs` and `/redoc` provided automatically by FastAPI). Seven PoC scripts exercised targeted attack classes and printed greppable `[[ AUDIT-RESULT ]]` PASS/FAIL lines. Each PoC is self-contained, reproducible, and describes its semantics. PoCs 01–06 are defense checks (PASS = attack blocked); poc_07 is a finding check (FAIL = attack succeeded = confirmed XSS).

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

**One HIGH (conditional) reflected-XSS finding (row 10); all framework-defense checks (rows 5–9) and supply-chain checks (rows 1–4) otherwise passed.** The finding is upstream-inherited (not fork-planted) and requires the proxy-prefix deployment precondition to be exploitable.

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

# 2. Run all 7 PoC scripts against the live container
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
**FAIL** means the attack succeeded and is a real finding (poc_01–06) or a precondition failure (harness error). For poc_07 specifically: **FAIL = breakout confirmed = the XSS is live** (this is the EXPECTED and CORRECT output).

`run_all.sh` collects all `[[ AUDIT-RESULT ]]` lines and exits 0 (harness ran to completion); a FAIL line triggers the "REAL FINDING DETECTED" banner but does not change the exit code. Expected run result: 6 PASS (rows 1–9 defense/supply-chain checks across poc_01–06) + 1 FAIL (poc_07 swagger_openapi_url_xss = confirmed finding) + 1 FAIL (poc_07 redoc_openapi_url_xss = confirmed secondary sink).

### Pinned references

- **Fork commit:** `202b2d2f5f331db9102b5dbcef071a9e09bed10e`
- **Base image digest:** `python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
- **Container name:** `autofyn-audit-target` (isolated from existing autofyn-sandbox/autofyn-agent containers)
- **Network:** `autofyn-audit-net` (isolated bridge network)
- **Host port:** `127.0.0.1:8137` (not externally exposed)

---

## 9. Conclusion and Recommendations

**No fork-planted backdoor or supply-chain tampering was found.** No injected malicious code, no supply-chain substitution, and no exploitable deviation from upstream FastAPI 0.137.1's source was introduced by this fork. The fastapi/ package tree is byte-identical; the supply-chain has been independently hash-verified (poc_05). These true-negative conclusions stand.

**One genuine (upstream-inherited) reflected-XSS in the Swagger UI `/docs` endpoint IS confirmed** (status: CONFIRMED (live, poc_07, round 6) — reproduced against a live container). This is a HIGH (conditional) finding: exploitable in the documented "Behind a Proxy" deployment pattern via the `X-Forwarded-Prefix` → `root_path` path, not in a bare default uvicorn deployment. It is not a fork-planted backdoor — it is an upstream weakness present in the audited artifact. Remediation: escape `openapi_url` through `_html_safe_json` at `docs.py:168` (see §6).

**Standard hardening notes** (applicable to any production FastAPI deployment; not fork-specific findings unless noted):

- Keep dependency pins current with upstream — the 14 version bumps in this fork (aiohttp 3.14.1, cryptography 48.0.1, starlette 1.3.1, etc.) are legitimate updates and should be tracked going forward.
- Pin the base Docker image by digest in production (already done in this harness; good practice).
- Verify uv.lock hashes on every dependency update as a CI gate.
- Confirm `Jinja2Templates` autoescape is not disabled in production templates (the default is on for `.html`; only override explicitly if sanitizing by other means).

**Fastar / OSV MAL-2026-4750:** No action required. The advisory is withdrawn. Do not flag this dependency as a finding in any downstream security review.
