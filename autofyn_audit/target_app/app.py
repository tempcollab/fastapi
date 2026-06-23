"""
target_app/app.py — Minimal realistic FastAPI app for security audit harness.

Each endpoint is written SAFELY and exercises a specific security surface:
  /health      — liveness probe used by setup.sh wait_for_health
  /echo        — reflected JSON (tests JSON encoding neutralizes payloads)
  /greet       — Jinja2 template rendering with autoescape ON (SSTI/XSS target)
  /static      — StaticFiles mount (path-traversal target)
  /sse         — SSE streaming via fork's fastapi.sse (injection target)
  /redirect    — RedirectResponse from query param (CRLF-injection target)
  /docs        — Swagger UI (reflected-XSS target via unescaped openapi_url, poc_07)
  /items/      — Collection route registered WITH trailing slash (poc_09 target:
                 requesting /items triggers redirect_slashes redirect whose Location
                 netloc is taken from the Host header — starlette/routing.py:695-706)
  /upload      — UploadFile endpoint (poc_10 target: demonstrates that max_part_size
                 is enforced for form fields but NOT for file parts in starlette's
                 MultiPartParser — formparsers.py:183-188)

Design intent:
  - No intentional vulnerabilities; PoCs test FRAMEWORK defenses, not app bugs.
    Exception: ProxyPrefixMiddleware below is the DOCUMENTED "Behind a Proxy"
    deployment precondition required to make the /docs openapi_url XSS reachable.
  - Uses Path(__file__).parent for all directory refs — CWD-independent.
  - Uses the fork's own fastapi.sse module to exercise the real fork surface.
"""

from pathlib import Path
from typing import Any, Awaitable, Callable, MutableMapping

import fastapi
from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fastapi.sse import EventSourceResponse, ServerSentEvent

# All directory references resolved relative to this file — never CWD-dependent.
_HERE = Path(__file__).parent

_fastapi_app = FastAPI(title="autofyn-audit-target", version="0.0.1")

# ── Static files ──────────────────────────────────────────────────────────────
# Serves only files inside _HERE/static/.
# SECRET_sentinel.txt lives at _HERE (outside static/) — traversal must NOT reach it.
_fastapi_app.mount(
    "/static",
    StaticFiles(directory=str(_HERE / "static")),
    name="static",
)

# ── Templates (Jinja2, autoescape ON — Starlette default) ────────────────────
templates = Jinja2Templates(directory=str(_HERE / "templates"))


# ── Endpoints ─────────────────────────────────────────────────────────────────


@_fastapi_app.get("/health")
async def health() -> JSONResponse:
    """Liveness probe. Returns fastapi version so setup.sh can assert the pin."""
    return JSONResponse(
        {"status": "ok", "fastapi_version": fastapi.__version__}
    )


@_fastapi_app.get("/echo")
async def echo(msg: str = "") -> JSONResponse:
    """Return user input as JSON. JSON encoding neutralizes injection payloads."""
    return JSONResponse({"echo": msg})


@_fastapi_app.get("/greet")
async def greet(name: str, request: Request) -> fastapi.responses.HTMLResponse:
    """Render greet.html with {{ name }} context variable.
    Jinja2 autoescape is ON (Starlette default) — framework defends against SSTI/XSS.
    NOTE: name is passed as a template *context variable*, NOT interpolated into
    the template source — this is the CORRECT usage pattern for a safe app.
    """
    return templates.TemplateResponse(
        request, "greet.html", {"name": name}
    )


@_fastapi_app.get("/sse", response_class=EventSourceResponse)
async def sse_endpoint(inject: str = ""):
    """SSE endpoint exercising the fork's fastapi.sse serialization path.

    The ?inject= query parameter is placed into the `comment` field of a
    ServerSentEvent, which routes through format_sse_event()'s splitlines()
    sanitization path.  The PoC (poc_02) asserts that newline-injected content
    is re-prefixed with ': ' on each line so no bare SSE field or event
    boundary escapes.

    Using `comment` specifically because:
    - `event` / `id` raise ValueError on newlines (different defense path).
    - `comment` / `data` / `raw_data` use splitlines() re-prefixing (the path
      we want to demonstrate and verify live).

    NOTE: the endpoint callable is itself an async generator (it `yield`s
    directly). The fork's SSE routing path checks `dependant.is_async_gen_callable`
    (routing.py:538); returning an inner generator would make this endpoint a
    coroutine function instead, which the SSE producer cannot iterate.
    """
    # Static data event first — confirms SSE stream is working.
    yield ServerSentEvent(data="connected", event="status")
    # The injection target: user input in the comment field.
    yield ServerSentEvent(comment=inject if inject else "ping")


@_fastapi_app.get("/redirect")
async def redirect(url: str = "/") -> RedirectResponse:
    """Redirect to the provided URL.
    Target for CRLF/header-injection test (poc_06).
    Starlette encodes the Location value; uvicorn/h11 reject raw CRLF in headers.
    """
    return RedirectResponse(url=url)


@_fastapi_app.get("/items/")
async def items() -> JSONResponse:
    """Route registered WITH a trailing slash. Requesting /items (no slash)
    triggers Starlette's redirect_slashes redirect (routing.py:695-706), whose
    Location netloc is taken from the Host header — poc_09 target.

    Trailing-slash collection routes are extremely common in real FastAPI apps;
    this is a representative realistic route. The vulnerability is in the
    framework's redirect behavior (Host header to Location netloc), not in the
    app. This route does NOT affect the other PoCs (different paths; they do not
    forge the Host header poc_09 uses).
    """
    return JSONResponse({"items": []})


@_fastapi_app.post("/upload")
async def upload(file: UploadFile = File(...)) -> JSONResponse:
    """Idiomatic UploadFile endpoint; demonstrates framework gap that max_part_size
    is not applied to file parts (poc_10). The app does not, and per framework design
    cannot via this param, cap the file size.

    Starlette's MultiPartParser.on_part_data (formparsers.py:183-188) enforces
    max_part_size only for non-file (field) parts; file parts — those carrying a
    filename= in their Content-Disposition — are written to a SpooledTemporaryFile
    with no per-part size ceiling. The same 2MiB payload sent as a field is rejected
    with "Part exceeded maximum size of 1024KB"; sent as a file part it is accepted
    in full. This is the semantic asymmetry confirmed by poc_10.

    This endpoint sends and receives no special headers and does NOT touch the
    X-Forwarded-Prefix / root_path path (poc_07/08) or the Host-header/redirect_slashes
    path (poc_09). It is fully independent of those PoCs.
    """
    content = await file.read()
    return JSONResponse({"received_bytes": len(content)})


# ── Proxy-prefix middleware (PRECONDITION for poc_07) ─────────────────────────
#
# Faithful representation of the documented FastAPI "Behind a Proxy" deployment
# (proxies like nginx/traefik/k8s-ingress set X-Forwarded-Prefix; this middleware
# maps it to scope["root_path"]).  This is the PRECONDITION for the /docs
# openapi_url XSS — the framework sink (docs.py:168) is reached only when something
# maps an untrusted request value into root_path.
#
# Implementation notes:
#   - Pure ASGI middleware: wraps the ASGI callable directly, mutating scope BEFORE
#     FastAPI.__call__ is invoked.  This is more faithful than BaseHTTPMiddleware
#     (which runs inside the ASGI chain AFTER FastAPI.__call__ builds its Request).
#   - When X-Forwarded-Prefix is absent the scope is left ENTIRELY unchanged, so
#     poc_01–poc_06 (which send no such header) are completely unaffected.
#   - FastAPI.__call__ at applications.py:1159-1162 overwrites scope["root_path"]
#     only when self.root_path is truthy; _fastapi_app has no root_path arg so
#     self.root_path == "" (falsy) and will NOT clobber the injected value.
#   - The module-level name `app` is rebound to this wrapper LAST so that
#     `uvicorn app:app` resolves to the outermost ASGI callable.  All decorators
#     (@_fastapi_app.get / .mount) ran against the FastAPI instance at definition
#     time and remain correctly registered.

_ASGIScope = MutableMapping[str, Any]
_ASGIReceive = Callable[[], Awaitable[MutableMapping[str, Any]]]
_ASGISend = Callable[[MutableMapping[str, Any]], Awaitable[None]]


class ProxyPrefixMiddleware:
    """Map X-Forwarded-Prefix request header into scope["root_path"].

    This is the documented FastAPI "Behind a Proxy" pattern (see FastAPI docs:
    "Behind a Proxy / Behind a Load Balancer").  Reverse proxies such as nginx,
    Traefik, and Kubernetes ingress controllers set this header to signal the
    path prefix at which the application is mounted.  Mapping it to root_path
    is the recommended ASGI-level handling for that signal.

    AUDIT NOTE: This middleware is the PRECONDITION for the reflected-XSS
    confirmed by poc_07.  Without something (this middleware or a real proxy)
    mapping X-Forwarded-Prefix into root_path, the /docs openapi_url sink
    (fastapi/openapi/docs.py:168) is not reachable with attacker-controlled
    input in a default uvicorn deployment.
    """

    def __init__(self, asgi_app: Any) -> None:
        self._app = asgi_app

    async def __call__(
        self,
        scope: _ASGIScope,
        receive: _ASGIReceive,
        send: _ASGISend,
    ) -> None:
        if scope["type"] == "http":
            headers: dict[bytes, bytes] = dict(scope.get("headers") or [])
            prefix_bytes = headers.get(b"x-forwarded-prefix")
            if prefix_bytes is not None:
                # Mutate a COPY of scope so the original mapping is not shared.
                scope = dict(scope)
                scope["root_path"] = prefix_bytes.decode("latin-1")
        await self._app(scope, receive, send)


# Rebind `app` to the outermost ASGI callable so `uvicorn app:app` resolves
# to the wrapper.  This MUST be the last statement touching `app`.
app = ProxyPrefixMiddleware(_fastapi_app)
