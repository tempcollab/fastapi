#!/usr/bin/env bash
# setup.sh — Build and start the autofyn-audit-target container.
#
# Idempotent: cleans prior run, stages fork source, builds image, starts container,
# waits for health.  Applies HARD GUARDS against touching protected infra.
#
# Usage:
#   bash autofyn_audit/setup.sh
#   AUDIT_HOST_PORT=9000 bash autofyn_audit/setup.sh   # override port
#   AUDIT_HEALTH_TIMEOUT=120 bash autofyn_audit/setup.sh  # override health timeout
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source pins (single source of truth) and common helpers.
# shellcheck source=lib/pins.sh
source "${SCRIPT_DIR}/lib/pins.sh"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ── Pre-flight checks ─────────────────────────────────────────────────────────

if ! command -v docker >/dev/null 2>&1; then
    log_err "docker not found in PATH — cannot proceed."
    exit 1
fi

# Safety: assert we will ONLY touch our own named resources.
assert_safe_resource_name container "$CONTAINER_NAME"
assert_safe_resource_name network "$NETWORK_NAME"
assert_safe_resource_name image "$IMAGE_TAG"

# Resolve the repo root (autofyn_audit/ lives one level below repo root).
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && git rev-parse --show-toplevel 2>/dev/null || echo "")"
if [[ -z "$REPO_ROOT" ]]; then
    log_err "Cannot determine repo root via git rev-parse. Are we inside a git repo?"
    exit 1
fi
log_info "Repo root: ${REPO_ROOT}"

# Verify the pinned commit is reachable in this checkout (not shallow/detached).
if ! git -C "${REPO_ROOT}" cat-file -e "${FORK_COMMIT}^{commit}" 2>/dev/null; then
    log_err "Pinned commit ${FORK_COMMIT} is NOT reachable in this checkout."
    log_err "Ensure you are running on a full (non-shallow) clone that contains ${FORK_COMMIT}."
    exit 1
fi
log_info "Pinned commit ${FORK_COMMIT} verified reachable."

# ── Clean prior run (idempotent) ──────────────────────────────────────────────
# Only reference our exact named resources — never a wildcard kill.

log_info "Cleaning any prior autofyn-audit run..."
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker network rm "${NETWORK_NAME}" 2>/dev/null || true

# ── Stage fork source via git archive ─────────────────────────────────────────
# This stages the exact commit content locally; no token-bearing URL needed.

FORK_SRC_DIR="${SCRIPT_DIR}/.build/fork_src"
log_info "Staging fork source at commit ${FORK_COMMIT} into ${FORK_SRC_DIR}..."
rm -rf "${FORK_SRC_DIR}"
mkdir -p "${FORK_SRC_DIR}"

if ! git -C "${REPO_ROOT}" archive "${FORK_COMMIT}" | tar -x -C "${FORK_SRC_DIR}"; then
    log_err "git archive of commit ${FORK_COMMIT} failed."
    log_err "Ensure the commit exists and git is available."
    exit 1
fi
log_info "Fork source staged: $(find "${FORK_SRC_DIR}" -maxdepth 1 | wc -l | tr -d ' ') top-level entries."

# ── Create Docker network ─────────────────────────────────────────────────────

if ! docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
    log_info "Creating Docker network ${NETWORK_NAME}..."
    docker network create "${NETWORK_NAME}"
else
    log_info "Docker network ${NETWORK_NAME} already exists."
fi

# ── Build image ───────────────────────────────────────────────────────────────
# Build context = autofyn_audit/ so .build/fork_src/ and target_app/ are reachable.
# If the base image digest is not available, docker build will print a clear error.

log_info "Building image ${IMAGE_TAG} from ${SCRIPT_DIR}/Dockerfile ..."
log_info "(Base image: ${BASE_IMAGE_DIGEST})"
if ! docker build \
        -t "${IMAGE_TAG}" \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}"; then
    log_err "docker build failed."
    log_err "If the base image digest could not be pulled, verify network access and"
    log_err "that digest sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf"
    log_err "is resolvable as a multi-arch manifest for your platform."
    exit 1
fi
log_info "Image built: ${IMAGE_TAG}"

# ── Start container ───────────────────────────────────────────────────────────
# Bound to 127.0.0.1 only — no external exposure.

log_info "Starting container ${CONTAINER_NAME} on 127.0.0.1:${AUDIT_HOST_PORT}:8000 ..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    --network "${NETWORK_NAME}" \
    -p "127.0.0.1:${AUDIT_HOST_PORT}:8000" \
    "${IMAGE_TAG}"

# ── Wait for healthy ──────────────────────────────────────────────────────────

BASE_URL="http://127.0.0.1:${AUDIT_HOST_PORT}"
HEALTH_URL="${BASE_URL}/health"

if ! wait_for_health "${HEALTH_URL}" "${AUDIT_HEALTH_TIMEOUT}"; then
    log_err "App did not become healthy within ${AUDIT_HEALTH_TIMEOUT}s."
    log_err "Container logs:"
    docker logs "${CONTAINER_NAME}" >&2
    exit 1
fi

# Assert the fastapi version reported by the running app matches the pin.
REPORTED_VERSION="$(curl -fsS "${HEALTH_URL}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['fastapi_version'])")"
if [[ "$REPORTED_VERSION" != "$CLAIMED_VERSION" ]]; then
    log_err "Version mismatch: expected ${CLAIMED_VERSION}, got ${REPORTED_VERSION}"
    exit 1
fi
log_info "Confirmed fastapi_version == ${REPORTED_VERSION}"

echo ""
echo "SETUP OK — live target at ${BASE_URL}"
echo "  Container : ${CONTAINER_NAME}"
echo "  Image     : ${IMAGE_TAG}"
echo "  Commit    : ${FORK_COMMIT}"
