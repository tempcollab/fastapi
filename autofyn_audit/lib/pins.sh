#!/usr/bin/env bash
# lib/pins.sh — Single source of truth for ALL pinned constants.
# Source this file from every other script; never hardcode a pin twice.

# Base image: python:3.12-slim-bookworm (multi-arch manifest-list digest,
# portable across amd64/arm64 — verified 2026-06-22)
BASE_IMAGE_DIGEST="python@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf"

# Fork remote and pinned commit
FORK_REMOTE="tempcollab/fastapi"
FORK_COMMIT="202b2d2f5f331db9102b5dbcef071a9e09bed10e"
FORK_COMMIT_SHORT="202b2d2"

# Claimed FastAPI version installed from this commit
CLAIMED_VERSION="0.137.1"

# fastar: audited version and its sdist SHA-256 (from PyPI / uv.lock confirmed)
FASTAR_VERSION="0.11.0"
FASTAR_SHA256="aa7f100f7313c03fdb20f1385927ba95671071ba308ad0c1763fef295e1895ce"

# Docker resource names — ALL unique with autofyn-audit- prefix.
# NEVER touch: autofyn-sandbox*, autofyn-agent, autofyn-dashboard, autofyn-db
IMAGE_TAG="autofyn-audit-fastapi:202b2d2"
CONTAINER_NAME="autofyn-audit-target"
NETWORK_NAME="autofyn-audit-net"

# Host port (overridable). App is bound to 127.0.0.1 only (no external exposure).
AUDIT_HOST_PORT="${AUDIT_HOST_PORT:-8137}"

# Health-check timeout in seconds (overridable via env)
AUDIT_HEALTH_TIMEOUT="${AUDIT_HEALTH_TIMEOUT:-90}"

# ── poc_14 browser sidecar pins ───────────────────────────────────────────────
# Pinned playwright image — pull by digest for reproducibility.
PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright:v1.49.0-noble"
PLAYWRIGHT_IMAGE_DIGEST="sha256:0fc07c73230cb7c376a528d7ffc83c4bdcdcd3fc7efbe54a2eed72b1ec118377"
PLAYWRIGHT_VERSION="1.49.0"
# Sidecar name used by poc_14; NEVER touch protected containers.
BROWSER_SIDECAR_NAME="autofyn-audit-browser-sidecar"

# poc_14 pre-flight / pass-through curl image — pinned by digest for reproducibility.
# Runs as a throwaway sidecar on autofyn-audit-net so curls reach autofyn-audit-target
# by name (the invoking shell cannot reach the target under gVisor/DinD).
# Digest resolved by orchestrator this round: docker pull curlimages/curl:8.11.1
# and docker inspect --format '{{index .RepoDigests 0}}'.
POC14_CURL_IMAGE="curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
