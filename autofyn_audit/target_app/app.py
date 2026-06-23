"""
target_app/app.py — Minimal realistic FastAPI app for security audit harness.

Each endpoint is written SAFELY and exercises a specific security surface:
  /health      — liveness probe used by setup.sh wait_for_health
  /echo        — reflected JSON (tests JSON encoding neutralizes payloads)
  /greet       — Jinja2 template rendering with autoescape ON (SSTI/XSS target)
  /static      — StaticFiles mount (path-traversal target)
  /sse         — SSE streaming via fork's fastapi.sse (injection target)
  /redirect    — RedirectResponse from query param (CRLF-injection target)

Design intent:
  - No intentional vulnerabilities; PoCs test FRAMEWORK defenses, not app bugs.
  - Uses Path(__file__).parent for all directory refs — CWD-independent.
  - Uses the fork's own fastapi.sse module to exercise the real fork surface.
"""

from pathlib import Path

import fastapi
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fastapi.sse import EventSourceResponse, ServerSentEvent

# All directory references resolved relative to this file — never CWD-dependent.
_HERE = Path(__file__).parent

app = FastAPI(title="autofyn-audit-target", version="0.0.1")

# ── Static files ──────────────────────────────────────────────────────────────
# Serves only files inside _HERE/static/.
# SECRET_sentinel.txt lives at _HERE (outside static/) — traversal must NOT reach it.
app.mount(
    "/static",
    StaticFiles(directory=str(_HERE / "static")),
    name="static",
)

# ── Templates (Jinja2, autoescape ON — Starlette default) ────────────────────
templates = Jinja2Templates(directory=str(_HERE / "templates"))


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> JSONResponse:
    """Liveness probe. Returns fastapi version so setup.sh can assert the pin."""
    return JSONResponse(
        {"status": "ok", "fastapi_version": fastapi.__version__}
    )


@app.get("/echo")
async def echo(msg: str = "") -> JSONResponse:
    """Return user input as JSON. JSON encoding neutralizes injection payloads."""
    return JSONResponse({"echo": msg})


@app.get("/greet")
async def greet(name: str, request: Request) -> fastapi.responses.HTMLResponse:
    """Render greet.html with {{ name }} context variable.
    Jinja2 autoescape is ON (Starlette default) — framework defends against SSTI/XSS.
    NOTE: name is passed as a template *context variable*, NOT interpolated into
    the template source — this is the CORRECT usage pattern for a safe app.
    """
    return templates.TemplateResponse(
        request, "greet.html", {"name": name}
    )


@app.get("/sse", response_class=EventSourceResponse)
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


@app.get("/redirect")
async def redirect(url: str = "/") -> RedirectResponse:
    """Redirect to the provided URL.
    Target for CRLF/header-injection test (poc_06).
    Starlette encodes the Location value; uvicorn/h11 reject raw CRLF in headers.
    """
    return RedirectResponse(url=url)
