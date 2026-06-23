#!/usr/bin/env bash
# lib/common.sh — Shared bash helpers for the autofyn_audit harness.
#
# PASS/FAIL semantics (sourced throughout):
#   DEFENSE checks (traversal, SSTI, header injection, SSE breakout):
#     PASS = attack correctly BLOCKED/defended.  FAIL = attack succeeded (real finding).
#   BENIGN checks (fastar):
#     PASS = no malicious runtime behavior observed.  FAIL = malicious behavior observed.
#   INFORMATIONAL (lockfile):
#     PASS = matches recorded expected state.
#
# run_all.sh exit code reflects HARNESS health, not individual PASS/FAIL findings.

# Guard: ONLY our exact pinned resource names may be operated on.
# Call this before any docker command that references a container/network/image.
_ALLOWED_CONTAINER="autofyn-audit-target"
_ALLOWED_NETWORK="autofyn-audit-net"
_ALLOWED_IMAGE_PREFIX="autofyn-audit-fastapi:"

assert_safe_resource_name() {
    local kind="$1"
    local name="$2"
    case "$kind" in
        container)
            if [[ "$name" != "$_ALLOWED_CONTAINER" ]]; then
                log_err "SAFETY GUARD: refusing to operate on container '$name' (allowed: '$_ALLOWED_CONTAINER')"
                exit 2
            fi
            ;;
        network)
            if [[ "$name" != "$_ALLOWED_NETWORK" ]]; then
                log_err "SAFETY GUARD: refusing to operate on network '$name' (allowed: '$_ALLOWED_NETWORK')"
                exit 2
            fi
            ;;
        image)
            if [[ "$name" != autofyn-audit-fastapi:* ]]; then
                log_err "SAFETY GUARD: refusing to operate on image '$name' (must start with 'autofyn-audit-fastapi:')"
                exit 2
            fi
            ;;
        *)
            log_err "SAFETY GUARD: unknown resource kind '$kind'"
            exit 2
            ;;
    esac
}

# ── Logging helpers (stderr) ──────────────────────────────────────────────────

log_info() {
    echo "[INFO]  $*" >&2
}

log_warn() {
    echo "[WARN]  $*" >&2
}

log_err() {
    echo "[ERROR] $*" >&2
}

# ── Result printer ────────────────────────────────────────────────────────────
# Emits the canonical greppable result line used by run_all.sh.
# Usage: print_check NAME STATUS DETAIL
#   NAME   — identifier (no spaces; e.g. fastar_runtime_benign)
#   STATUS — PASS or FAIL
#   DETAIL — free-text explanation
print_check() {
    local name="$1"
    local status="$2"
    local detail="$3"
    echo "[[ AUDIT-RESULT ]] ${name} :: ${status} :: ${detail}"
}

# ── Health check ─────────────────────────────────────────────────────────────
# Usage: wait_for_health URL TIMEOUT_SECS
# Returns 0 on first 200 response, 1 on timeout.
wait_for_health() {
    local url="$1"
    local timeout_secs="$2"
    local elapsed=0
    local interval=2

    log_info "Waiting up to ${timeout_secs}s for ${url} ..."
    while (( elapsed < timeout_secs )); do
        if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
            log_info "Health check passed after ${elapsed}s"
            return 0
        fi
        sleep "$interval"
        (( elapsed += interval ))
    done

    log_err "Health check timed out after ${timeout_secs}s for ${url}"
    return 1
}

# ── In-container exec wrapper ─────────────────────────────────────────────────
# Usage: dexec [docker exec flags] CMD ARGS...
# Always targets our exact pinned container name.
dexec() {
    assert_safe_resource_name container "$CONTAINER_NAME"
    # -i keeps stdin open so piped stdin / heredocs (e.g. `python3 -`) work.
    docker exec -i "$CONTAINER_NAME" "$@"
}

# ── String assertions ─────────────────────────────────────────────────────────
# Return 0 (success/true) or 1 (failure/false).

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    fi
    return 1
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "$haystack" != *"$needle"* ]]; then
        return 0
    fi
    return 1
}
