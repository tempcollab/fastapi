# Dockerfile — autofyn-audit-target
#
# Pinned base image (multi-arch manifest-list digest, portable amd64/arm64):
#   python:3.12-slim-bookworm @ sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf
#
# Fork installed from local git-archive export of commit 202b2d2f5f331db9102b5dbcef071a9e09bed10e
# staged by setup.sh into .build/fork_src/ before `docker build`.
#
# Correction #1 (spec-review): WORKDIR /app set explicitly so relative static/
# and templates/ paths resolve even if uvicorn --app-dir is used.
# app.py additionally uses Path(__file__).parent for absolute resolution.
#
# Correction #2 (spec-review): fastar pinned explicitly to 0.11.0 AFTER the
# [standard] install, overriding any newer resolution from PyPI.

FROM python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf

# Install system-level audit tools used by PoC scripts inside the container.
# strace: network/file syscall tracing for poc_01 (falls back to Python audithook)
# curl: HTTP requests from within the container if needed
# git / ca-certificates: general audit utilities
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strace \
        curl \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the staged fork source (git-archive export by setup.sh).
# Build context is autofyn_audit/, so .build/fork_src/ is reachable.
COPY .build/fork_src/ /src/fastapi-fork/

# Install the fork with its [standard] extra.
# fastar >= 0.9.0 is declared in [standard]; pip may resolve a newer version.
# We immediately re-pin to the audited 0.11.0 to ensure build, PoC, and
# pins.sh all reference the same binary (Correction #2).
RUN pip install --no-cache-dir "/src/fastapi-fork[standard]" \
    && pip install --no-cache-dir "fastar==0.11.0"

# Assert the installed version matches the pinned fork commit claim.
RUN python -c "import fastapi; v = fastapi.__version__; print('fastapi version:', v); assert v == '0.137.1', f'Expected 0.137.1 but got {v!r}'"

# Correction #1 (spec-review): Set WORKDIR so the process CWD matches /app.
# app.py also uses Path(__file__).parent for absolute directory resolution,
# making it robust regardless of launch method.
WORKDIR /app

# Copy the target application.
COPY target_app/ /app/

EXPOSE 8000

# Run uvicorn. --app-dir /app prepends /app to sys.path so `app:app` resolves.
# WORKDIR /app ensures relative paths also resolve correctly as a belt-and-suspenders measure.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
