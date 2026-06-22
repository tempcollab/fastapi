# SPEC — `autofyn_audit/` Reproducible Security Audit Harness

**Spec review: required** (creates ~14 new files, new module, defines a public run interface).

---

## Intent

Build a fully reproducible, self-contained audit harness under `autofyn_audit/` that (1) builds and starts a LIVE instance of THIS fork (tempcollab/fastapi at commit `202b2d2`) inside a pinned Docker container, (2) runs a suite of real-HTTP PoC/verification scripts against a live target FastAPI app exercising the realistic attack surface, each printing clear `PASS`/`FAIL`, and (3) tears everything down cleanly. The harness records the audit conclusion HONESTLY: no planted critical vuln was found; `fastar` is explicitly documented as an evaluated-and-dismissed false positive. The whole suite must run with:

```
bash autofyn_audit/setup.sh && bash autofyn_audit/run_all.sh && bash autofyn_audit/teardown.sh
```

We AUDIT only — we do NOT modify any `fastapi/` source or fix anything.

---

## Critical context the dev MUST internalize (read the three explorer reports)

Read `/tmp/round-1/diff-analysis.md`, `/tmp/round-1/code-deepdive.md`, `/tmp/round-1/fastar-supplychain.md`. Established facts that constrain this deliverable:

- The `fastapi/` package tree is BYTE-IDENTICAL to genuine upstream FastAPI 0.137.1. No code-level planted vuln.
- `fastar` is a GENUINE upstream FastAPI dependency (legit Rust tar lib by the FastAPI team). OSV `MAL-2026-4750` was WITHDRAWN as a FALSE POSITIVE (OSSF PR #1276). **We MUST NOT report fastar as a vulnerability.** The fastar PoC exists to EMPIRICALLY DEMONSTRATE it is benign and pre-empt the false positive — its EXPECTED OUTCOME IS BENIGN, and "benign" counts as a PASS for that check (PASS = "behaved as expected", see PASS/FAIL semantics below).
- SSE code (`fastapi/sse.py`) is identical to upstream; injection concerns are upstream-wide, defense-in-depth only, require app misuse. NOT standalone critical, NOT planted. PoCs for SSE must HONESTLY show the framework's `splitlines()` mitigation defends the default routing path.
- StaticFiles / Jinja2 path-traversal & SSTI: these are tests of whether the framework + a correctly-written app correctly DEFEND. Expected outcome = DEFENDED (attack blocked). That is a PASS.
- A 4th check (uv.lock dependency-pin integrity) is running concurrently; its result is UNKNOWN. Design a PLACEHOLDER PoC slot (`poc_05_lockfile_finding`) that fits EITHER a confirmed-CRITICAL finding OR a clean "no finding". Default state = "no finding / informational".

**Bottom line for the report:** the calibrated conclusion is currently "No planted critical vulnerability confirmed; fastar false positive explicitly dismissed." Do NOT manufacture findings. Accuracy over volume.

---

## Pinned values (RECORD THESE VERBATIM — already verified by the architect)

- **Base image:** `python:3.12-slim-bookworm`
- **Image digest (manifest, portable/multi-arch):** `sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
  - Pin form to use everywhere: `python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
  - This is the multi-arch manifest-list digest reported by both `docker pull` and `RepoDigests`; portable across amd64/arm64. (Verified arch in this env = arm64.)
- **Fork commit (pin everywhere):** `202b2d2f5f331db9102b5dbcef071a9e09bed10e` (short `202b2d2`)
- **Remote:** `tempcollab/fastapi`
- **fastar pin:** `fastar==0.11.0`, sdist sha256 `aa7f100f7313c03fdb20f1385927ba95671071ba308ad0c1763fef295e1895ce`
- **Claimed version:** `0.137.1`

Put ALL pins in one shell file `autofyn_audit/lib/pins.sh` (sourced by every script). Single source of truth — never hardcode a pin twice.

---

## Container / network naming (MUST be unique; never touch existing infra)

Existing containers `autofyn-sandbox*`, `autofyn-agent`, `autofyn-dashboard`, `autofyn-db` MUST NOT be touched. Use a dedicated prefix and a fixed unique suffix so re-runs are idempotent:

- Image tag (built): `autofyn-audit-fastapi:202b2d2`
- Container name: `autofyn-audit-target`
- Docker network: `autofyn-audit-net`
- Host port published for the live app: `8137` -> container `8000` (uvicorn). Make the host port overridable via env `AUDIT_HOST_PORT` (default `8137`) in `pins.sh`, but bind container side to `127.0.0.1:${AUDIT_HOST_PORT}:8000` so the app is only reachable from localhost.

teardown and setup must `docker rm -f autofyn-audit-target` / `docker network rm autofyn-audit-net` guarded so they NEVER match the protected names (we only ever reference our exact unique names — never a wildcard `docker ps` kill).

---

## File layout under `autofyn_audit/`

```
autofyn_audit/
  README.md                      # how to run, what each piece does, pins table
  setup.sh                       # build image (pinned base + fork @202b2d2), start container+app, wait healthy
  run_all.sh                     # run every PoC against live app; print PASS/FAIL table; exit code reflects harness health
  teardown.sh                    # remove our container + network + built image; never touch protected infra
  Dockerfile                     # FROM pinned digest; install fork from pinned commit; copy target app
  lib/
    pins.sh                      # ALL pinned constants + names + ports (single source of truth)
    common.sh                    # shared bash helpers: logging, http_get/http_post via curl, pass/fail printers, wait_for_health, in_container exec wrapper
  target_app/
    app.py                       # the live FastAPI target app (uvicorn entrypoint: app:app)
    requirements.txt             # app-only runtime extras NOT already pulled by fastapi[standard] (e.g. none/sse-starlette? see Design)
    static/                      # files served by StaticFiles mount
      hello.txt                  # benign file used to prove StaticFiles serves in-root files
    templates/
      greet.html                 # Jinja2 template with {{ name }} for SSTI test (autoescaped)
    SECRET_sentinel.txt          # sentinel file placed OUTSIDE the static root, to prove path traversal is BLOCKED
  pocs/
    poc_01_fastar_runtime.sh     # install fastar in container, strace `import fastar` for network/secret-file/env access -> expect BENIGN
    poc_02_sse_injection.sh      # hit SSE endpoint with newline payload; assert framework splitlines() prevents event/field breakout
    poc_03_staticfiles_traversal.sh  # attempt ../ path traversal on StaticFiles mount; assert 404/blocked, sentinel NOT leaked
    poc_04_jinja2_ssti.sh        # send SSTI payload to template endpoint; assert autoescape blocks execution/reflection
    poc_05_lockfile_finding.sh   # PLACEHOLDER: uv.lock pin-integrity check result slot (default: informational/no-finding)
    poc_06_header_injection.sh   # send CRLF in a reflected header/redirect param; assert Starlette/uvicorn strips/blocks CRLF
  audit_report.md                # the honest deliverable report (structure defined below)
```

> Builder may merge `requirements.txt` into the Dockerfile if the app needs no extra deps beyond `fastapi[standard]`. Keep the file only if extra deps are genuinely needed.

---

## Design

### Single source of truth: `lib/pins.sh`
Plain `bash` variable assignments, no logic. Exports: `BASE_IMAGE_DIGEST`, `FORK_REMOTE`, `FORK_COMMIT`, `FASTAR_VERSION`, `FASTAR_SHA256`, `IMAGE_TAG`, `CONTAINER_NAME`, `NETWORK_NAME`, `AUDIT_HOST_PORT` (default 8137), `CLAIMED_VERSION`. Every other script does `source "$(dirname "$0")/lib/pins.sh"` (resolve to absolute via a small canonicalization helper in common.sh).

### `lib/common.sh`
Reusable helpers (sourced, not executed). Provide:
- `log_info/log_warn/log_err` — prefixed stderr logging.
- `print_check NAME STATUS DETAIL` — emits one normalized result line: `[[ AUDIT-RESULT ]] <NAME> :: <PASS|FAIL> :: <DETAIL>`. `run_all.sh` greps these to build the summary table. PASS/FAIL semantics below.
- `wait_for_health URL TIMEOUT_SECS` — poll `curl -fsS` until 200 or timeout; return non-zero on timeout.
- `dexec ...` — wrapper for `docker exec autofyn-audit-target ...` so PoCs that need in-container actions (strace, pip install fastar) don't repeat the name.
- `assert_contains HAYSTACK NEEDLE` / `assert_not_contains` — string assertions returning 0/1.
- A guard that REFUSES to operate on any container/network whose name is not exactly our pinned unique name (defensive: hardcode the allowed names, abort if a caller passes anything else).

### PASS/FAIL semantics (define clearly in README + common.sh header)
Each PoC asserts an EXPECTED security outcome and prints PASS when reality matches expectation:
- For DEFENSE checks (traversal, SSTI, header injection, SSE breakout): **PASS = attack was correctly BLOCKED/defended.** FAIL = attack succeeded (would be a real finding).
- For the fastar BENIGN check: **PASS = no malicious runtime behavior observed (no outbound network, no secret-file read, no env exfil during import).** FAIL = malicious behavior observed.
- For the lockfile placeholder: **PASS = matches the recorded expected state** (default "no finding"). If the concurrent uv.lock check later confirms a CRITICAL, the dev/reviewer flips its `EXPECTED_FINDING` flag and the script asserts the finding reproduces.
- `run_all.sh` overall exit code: `0` if all PoCs ran to completion and the harness itself was healthy (regardless of individual PASS/FAIL), non-zero only if the harness/infra broke (container didn't start, a PoC errored). Rationale: a FAIL means "a real vuln was found" — that is valid audit output, not a harness error. Make this explicit in README so a reviewer reads the table, not just the exit code.

### `Dockerfile`
- `FROM python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf`
- Install system tools needed by PoCs INSIDE the container: `strace`, `curl`, `git`, `ca-certificates`. (slim image lacks these.) Pin nothing extra beyond apt's default for these audit tools, but `apt-get update && apt-get install -y --no-install-recommends ...` then clean lists.
- Install the fork at the pinned commit. TWO acceptable methods — pick the **build-from-working-tree** method as PRIMARY (most faithful to "THIS fork at THIS commit", avoids depending on remote availability), with a documented fallback:
  - PRIMARY: `COPY` the repo working tree into the image is NOT desired (we don't want the whole monorepo + audit folder recursively). Instead, in `setup.sh`, create a clean export of the fork source via `git archive 202b2d2...` from the repo root into a build context, then `pip install` it. Simpler and recommended: in the Dockerfile, `pip install "git+https://<token? no>"` is fragile. **Chosen approach:** `setup.sh` runs `git -C <repo-root> archive --format=tar 202b2d2f5...` piped into a staging dir `autofyn_audit/.build/fork_src/`, and the Dockerfile does `COPY .build/fork_src/ /src/fastapi-fork/` then `pip install "/src/fastapi-fork[standard]"`. This pins the exact commit content, installs `fastar` via the `[standard]` extra (realistic), and needs no network for the fork itself.
  - Record the installed version: Dockerfile final step `RUN python -c "import fastapi; print(fastapi.__version__)"` and assert it equals `0.137.1`.
- Copy `target_app/` into `/app`.
- Expose 8000. Default `CMD` runs uvicorn: `uvicorn app:app --host 0.0.0.0 --port 8000 --app-dir /app`.
- IMPORTANT for reproducibility note: `pip install` of transitive deps still hits PyPI at build time (network is available). Pin what we directly control (base image, fork commit, fastar version). Document in README that transitive resolution is governed by the fork's own `uv.lock`/version constraints; we do not re-pin all of PyPI (out of scope, and the explorer reports already covered lockfile integrity separately).

### `setup.sh` (idempotent)
1. `source lib/pins.sh` + `lib/common.sh`.
2. Pre-flight: assert `docker` present; assert we are NOT about to touch protected names.
3. Clean any prior run: `docker rm -f autofyn-audit-target` (ignore error), `docker network rm autofyn-audit-net` (ignore error). NEVER wildcard.
4. Stage fork source: `git -C <REPO_ROOT> archive 202b2d2... | tar -x -C autofyn_audit/.build/fork_src/`. Resolve `<REPO_ROOT>` dynamically (`git -C "$(dirname "$0")/.." rev-parse --show-toplevel`). Verify the archived commit equals the pin (`git rev-parse` check); abort if HEAD content doesn't include that commit.
5. `docker network create autofyn-audit-net` (if absent).
6. `docker build -t autofyn-audit-fastapi:202b2d2 -f autofyn_audit/Dockerfile autofyn_audit/` (build context = `autofyn_audit/` so `.build/fork_src` and `target_app/` are reachable).
7. `docker run -d --name autofyn-audit-target --network autofyn-audit-net -p 127.0.0.1:${AUDIT_HOST_PORT}:8000 autofyn-audit-fastapi:202b2d2`.
8. `wait_for_health http://127.0.0.1:${AUDIT_HOST_PORT}/health 60`. Abort with clear error if unhealthy (dump `docker logs autofyn-audit-target`).
9. Print "SETUP OK" + the live base URL.
- `set -euo pipefail`. Add a `.gitignore` inside `autofyn_audit/` (or `.build/` entry) so the staged fork source is not committed.

### `run_all.sh`
1. `source` pins + common.
2. Re-verify health (fail fast with guidance to run setup.sh if down).
3. Run each `pocs/poc_*.sh` in sorted order, passing the base URL `http://127.0.0.1:${AUDIT_HOST_PORT}` as `$1`. Each PoC is self-contained, emits exactly one (or a small fixed number of) `[[ AUDIT-RESULT ]]` line(s) via `print_check`, plus human-readable evidence to stdout.
4. Collect all `[[ AUDIT-RESULT ]]` lines, print a final summary table: NAME | STATUS | DETAIL.
5. Print counts: `<n> PASS, <m> FAIL`. Exit 0 unless the harness itself errored (see PASS/FAIL semantics). If any PoC emits FAIL, ALSO print a prominent banner "REAL FINDING DETECTED — see report" so it isn't missed.

### `teardown.sh`
1. `source` pins + common.
2. `docker rm -f autofyn-audit-target` (exact name only), `docker network rm autofyn-audit-net`, `docker rmi autofyn-audit-fastapi:202b2d2` (ignore-if-missing each).
3. Remove `autofyn_audit/.build/`.
4. Guard: refuse to remove anything whose name isn't our exact pinned name. Print "TEARDOWN OK".

---

## Target app — `target_app/app.py`

A small REALISTIC FastAPI app that gives every PoC a live endpoint to hit. Use only the installed fork + its `[standard]` extras (jinja2, python-multipart come with `[standard]`; StaticFiles & Jinja2Templates ship in fastapi/starlette). The SSE endpoint uses the fork's OWN `fastapi.sse` module (the non-standard-but-identical-to-upstream file) so we exercise the real fork surface.

Endpoints (keep each minimal, well-commented, NO intentional vulnerabilities beyond what we are testing the framework's defense of):

- `GET /health` -> `{"status":"ok","fastapi_version": fastapi.__version__}`. Used by `wait_for_health`.
- `GET /echo?msg=...` -> returns `{"echo": msg}` as JSON (tests reflected input handling / that JSON encoding neutralizes payloads).
- `GET /greet?name=...` -> renders `templates/greet.html` via `Jinja2Templates` with `{{ name }}`. Autoescape ON (Starlette default). This is the SSTI/XSS-reflection target. The template MUST use `{{ name }}` (a context variable), NOT string-format the user input INTO the template source — i.e. the app is written CORRECTLY; the PoC proves the framework defends. (If the app rendered `Template(user_input)` that would be app-level SSTI, not a framework finding — do NOT do that.)
- StaticFiles mount: `app.mount("/static", StaticFiles(directory="static"), name="static")`. Serves `static/hello.txt`. The traversal PoC tries to escape to `SECRET_sentinel.txt` (which lives OUTSIDE `static/`, at app root) and must FAIL.
- `GET /sse` -> an SSE endpoint using the fork's `fastapi.sse` (`EventSourceResponse` / `ServerSentEvent` or the route `response_class`/generator pattern as the fork supports — dev: read `fastapi/sse.py` and `fastapi/routing.py` SSE path to use the correct public API). It yields an event whose `comment` (and/or `data`) is taken from a query param `?inject=...`, so the PoC can attempt newline/field-injection and observe the framework's `splitlines()` sanitization on the wire. The app must route user input through the SUPPORTED `ServerSentEvent`/generator path (the safe default path), NOT call `format_sse_event(id=...)` directly with raw user input. Rationale: we are auditing the FORK's default behavior; the "call format_sse_event directly" case is documented in the report as a defense-in-depth note, not demonstrated as a live framework break.
- `GET /redirect?url=...` -> returns a `RedirectResponse(url=url)` (or sets a header from input). Target for CRLF/header-injection PoC; assert Starlette/uvicorn rejects/strips CRLF so no header split occurs.

Keep `app.py` under ~120 lines, heavily commented to state WHAT each endpoint demonstrates and WHY it is written safely.

`templates/greet.html`: minimal HTML containing `Hello, {{ name }}!`.
`static/hello.txt`: `static file served correctly`.
`SECRET_sentinel.txt` (app root, NOT under static/): `SENTINEL-DO-NOT-LEAK-<random-marker>` — the PoC greps for this marker in traversal responses; its presence anywhere in an HTTP response body = FAIL (leak).

---

## PoC scripts — behavior & PASS/FAIL each

All PoCs: `set -euo pipefail`, take base URL as `$1`, source `lib/common.sh` for `print_check`/`assert_*`, make REAL requests with `curl`, print captured evidence, emit one `[[ AUDIT-RESULT ]]` line.

1. **`poc_01_fastar_runtime.sh`** (in-container, behavioral; EXPECTED BENIGN)
   - `dexec pip install "fastar==0.11.0"` (already present via [standard], but assert it imports).
   - `dexec strace -f -e trace=network,connect,sendto,socket,openat python -c "import fastar; import fastar as _; print('imported')"` (or split network/file traces into two runs for clarity).
   - Parse strace output for: outbound `connect()` to non-local addrs, reads of `~/.ssh`, `~/.aws`, `/etc/passwd`, `/proc/self/environ`, secret env access.
   - PASS = none of the above observed (benign). FAIL = any observed.
   - Print a one-line honest note: "fastar is a legitimate upstream FastAPI dependency; OSV MAL-2026-4750 withdrawn as false positive. This check empirically confirms benign runtime behavior." Emit `[[ AUDIT-RESULT ]] fastar_runtime_benign :: PASS :: no network/secret/env access during import`.
   - Robustness: if `strace` cannot attach in this container runtime (gVisor/seccomp), the PoC must DETECT that, print a clear DEGRADED note, and still emit a result line marked `PASS` with detail "strace unavailable; falling back to static SBOM + import side-effect check (no network sockets opened)". Provide the fallback: run import under a Python `socket`/`open` audit hook (`sys.addaudithook`) capturing `socket.connect`, `open` of sensitive paths, and `os.environ` reads — pure-Python, no ptrace needed. PREFER the audithook method as PRIMARY since it is sandbox-portable; use strace as corroboration when available.

2. **`poc_02_sse_injection.sh`** (live HTTP; EXPECTED DEFENDED)
   - `curl -N "http://.../sse?inject=ping%0Aretry:%200%0A%0Adata:%20INJECTED"` (URL-encoded newlines).
   - Capture raw wire bytes. Assert the injected `retry:`/`data:` lines appear ONLY as comment lines (prefixed `: `) or are otherwise neutralized, and that NO standalone `data: INJECTED` field and NO premature `\n\n` event boundary was produced from the injected segment.
   - PASS = injection neutralized by framework `splitlines()`/validators (no field/event breakout). FAIL = a real injected `data:`/`event:` field or new event boundary appears.
   - Print the raw wire bytes as evidence.

3. **`poc_03_staticfiles_traversal.sh`** (live HTTP; EXPECTED BLOCKED)
   - Try several encodings: `/static/../SECRET_sentinel.txt`, `/static/%2e%2e/SECRET_sentinel.txt`, `/static/..%2fSECRET_sentinel.txt`, `/static/....//SECRET_sentinel.txt`, plus a deep `../../../../etc/passwd` attempt.
   - Assert each returns 404/400/forbidden AND the sentinel marker / `root:` (from /etc/passwd) does NOT appear in any response body.
   - Also do a positive control: `GET /static/hello.txt` returns 200 with expected content (proves the mount works, so a 404 on traversal is real defense, not a broken mount).
   - PASS = all traversal blocked AND positive control works. FAIL = sentinel or passwd content leaked.

4. **`poc_04_jinja2_ssti.sh`** (live HTTP; EXPECTED DEFENDED)
   - `curl "http://.../greet?name=%7B%7B7*7%7D%7D"` (`{{7*7}}`) and a payload like `{{config}}` / `{{''.__class__}}`.
   - Assert response does NOT contain `49` (no expression evaluation) and the payload is HTML-escaped (`{{7*7}}` reflected literally / escaped). i.e. autoescape + context-variable rendering defends.
   - Also send an XSS payload `<script>alert(1)</script>` and assert it is HTML-escaped in output.
   - PASS = no evaluation, payload escaped. FAIL = `49` present (SSTI) or unescaped `<script>` (XSS).

5. **`poc_05_lockfile_finding.sh`** (PLACEHOLDER; default INFORMATIONAL)
   - Top of file: `EXPECTED_FINDING=${LOCKFILE_FINDING:-none}` env-overridable flag.
   - Default (`none`): print "uv.lock dependency-pin integrity: assessed by separate static check; no confirmed CRITICAL pin-substitution finding at audit time." Emit `[[ AUDIT-RESULT ]] lockfile_pin_integrity :: PASS :: no confirmed finding (informational)`.
   - If `EXPECTED_FINDING=critical`: the script must assert the specific reproducible behavior the concurrent check surfaces (e.g. a substituted package hash mismatch). Leave a clearly-marked `# >>> FILL IN when uv.lock check confirms <<<` block with a worked example (verify an installed package's wheel hash against the uv.lock-recorded hash inside the container via `dexec pip hash` / `pip download` comparison) so a reviewer can drop in the concrete assertion. Do NOT fabricate a finding now.
   - This keeps the suite green-by-default and ready to host a real finding without restructuring.

6. **`poc_06_header_injection.sh`** (live HTTP; EXPECTED BLOCKED)
   - `curl -i "http://.../redirect?url=%0d%0aSet-Cookie:%20pwned=1"` and a `%0d%0aX-Injected:%201` variant.
   - Capture full response headers. Assert NO `Set-Cookie: pwned` / `X-Injected` header was injected (Starlette/uvicorn reject CRLF in header values; expect 400 or a sanitized Location).
   - PASS = no header split. FAIL = injected header present.

---

## `audit_report.md` structure (HONEST, calibrated, no fluff)

The dev writes this as the human deliverable. Sections:

1. **Scope & Target** — repo (tempcollab/fastapi), pinned commit `202b2d2…`, claimed version `0.137.1`, pinned base image digest, audit date, "audit only — no fixes" statement.
2. **Methodology** —
   - Upstream-diff method: fork compared byte-for-byte against genuine FastAPI 0.137.1 (PyPI sdist + GitHub tag `0.137.1` commit a82e5f2) -> `fastapi/` tree identical.
   - Live dynamic testing: pinned Docker container running the fork, real-HTTP PoCs against a target app exercising SSE, StaticFiles, Jinja2, redirect/header, echo surfaces.
   - Reproducibility: `setup.sh` / `run_all.sh` / `teardown.sh`, all pins listed.
3. **Confirmed Findings** — a table. **Currently EMPTY / "None confirmed at CRITICAL or HIGH."** State plainly: no planted critical vulnerability was confirmed against the live instance. (Leave the table format ready so the lockfile slot can add a row if the concurrent check confirms one.)
4. **Defense Verification Results** — table of the live PoCs and their outcomes (traversal BLOCKED, SSTI DEFENDED, SSE injection NEUTRALIZED, header injection BLOCKED), each with the reproduction command and the live evidence (response snippet). Frame these as "the framework + correctly-written app correctly defend."
5. **Evaluated and Dismissed (False Positives)** — MANDATORY section. Document:
   - **`fastar` (OSV MAL-2026-4750)** — explain it IS a genuine upstream FastAPI dependency (present verbatim in upstream 0.137.1 `[standard]` extra), maintained by the FastAPI team, OSV report WITHDRAWN as false positive (cite OSSF issue #1274 / PR #1276), static binary analysis clean (no C2/exfil), AND our live `poc_01` behavioral check confirms benign import. Severity: NONE. State explicitly we are NOT reporting it, and WHY, so maintainers see we assessed it correctly.
   - **SSE `comment`/`raw_data`/`format_sse_event(id=)` newline handling** — upstream-identical code; default routing path is defended by `splitlines()`/validators (proven live in `poc_02`). Note the defense-in-depth observation that an app calling `format_sse_event(id=user_input)` DIRECTLY with raw input could inject — this is an app-usage caveat, NOT a framework vulnerability. Severity: INFORMATIONAL.
   - **Benign fork diffs** — pyproject reformatting, `# ty: ignore` script comments, setup-uv version bump — none security-relevant.
6. **Reproducibility Appendix** — the exact pins table (image digest, commit, fastar version+hash), the one-line run command, container/network names, and how to read PASS/FAIL.
7. **Conclusion** — calibrated: "No planted critical/high vulnerability confirmed in this fork. The fork is functionally identical to upstream FastAPI 0.137.1; the fastar dependency is a verified false positive. Defenses against common web attack classes were live-verified."

Tone: factual, no overstatement, no padding. Severity strictly calibrated (CVSS-style if a real finding emerges; otherwise "None confirmed").

---

## Constraints

- **No fixes / no edits to `fastapi/` source.** Audit only. The harness installs the fork read-only.
- **Never touch protected containers/networks** (`autofyn-sandbox*`, `autofyn-agent`, `autofyn-dashboard`, `autofyn-db`). Only ever reference our exact pinned names; teardown/setup must hardcode-guard against any other name.
- **Pin everything** as listed; pins live ONLY in `lib/pins.sh`.
- **Bind app to 127.0.0.1** on the host port (no external exposure).
- **Fail fast, no layered fallbacks that hide errors.** Exception: the fastar PoC's strace->audithook fallback is an explicit, documented capability-detection (gVisor may block ptrace), NOT an error-swallowing fallback — it must LOG which method it used. Every other "ignore error" is only for idempotent cleanup (`rm -f` style) and must be scoped to our exact resource names.
- **No secrets in the harness.** The sentinel file contains a marker, not a real secret. Do not embed `GIT_TOKEN`/`CLAUDE_CODE_OAUTH_TOKEN`. Fork source is staged via local `git archive` (no token-bearing URL).
- **PASS/FAIL must be unambiguous and machine-greppable** via the `[[ AUDIT-RESULT ]]` line format.
- `set -euo pipefail` in every executable script; all paths absolute or resolved relative to the script's own dir.
- Keep `app.py` < ~120 lines; each PoC focused and < ~80 lines.
- **Do NOT manufacture findings.** If nothing is found, the report says so. Accuracy over volume is the scored metric.

---

## Read list (dev)

- `/tmp/round-1/diff-analysis.md`, `/tmp/round-1/code-deepdive.md`, `/tmp/round-1/fastar-supplychain.md` (the established evidence — do not re-litigate).
- `/home/agentuser/repo/fastapi/sse.py` and the SSE path in `/home/agentuser/repo/fastapi/routing.py` (to use the correct public SSE API in `app.py` and craft `poc_02`).
- `/home/agentuser/repo/pyproject.toml` (lines around 59-79: the `[standard]` extra incl. `fastar`) and `uv.lock` around the `fastar` entry (lines ~1451+).
- `/home/agentuser/repo/fastapi/staticfiles.py`, `fastapi/templating.py` (thin re-exports — confirm the public symbols used by `app.py`).

## Build order

1. `lib/pins.sh`, `lib/common.sh` (foundation).
2. `target_app/` (app.py + templates/static/sentinel).
3. `Dockerfile`.
4. `setup.sh`, then `teardown.sh`.
5. `pocs/*` (01–06).
6. `run_all.sh` (wires PoCs together).
7. `audit_report.md`, `README.md`.

## Eval (round-specific)

- `bash autofyn_audit/setup.sh` exits 0, container `autofyn-audit-target` healthy, `GET /health` returns `fastapi_version == 0.137.1`.
- `bash autofyn_audit/run_all.sh` prints a result table; with no real finding, ALL 6 checks show `PASS` (defenses hold / fastar benign / lockfile informational). Exit code 0.
- `bash autofyn_audit/teardown.sh` removes ONLY our named container/network/image and `.build/`; protected containers still present afterward (`docker ps -a` still lists `autofyn-agent`, `autofyn-sandbox`).
- `audit_report.md` contains the mandatory "Evaluated and Dismissed (False Positives)" section naming fastar + OSV MAL-2026-4750 withdrawal, and a Confirmed Findings section honestly stating none confirmed.
- No edits to any file under `/home/agentuser/repo/fastapi/`.
- (Reviewer does the LIVE run — builder just produces files; do NOT have the builder start containers in a loop.)
