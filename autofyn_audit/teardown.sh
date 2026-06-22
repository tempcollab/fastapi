#!/usr/bin/env bash
# teardown.sh — Remove ONLY the autofyn-audit-* resources created by setup.sh.
#
# HARD GUARD: refuses to remove anything unless it exactly matches our pinned
# resource names.  Protected infra (autofyn-sandbox, autofyn-agent, etc.) is
# NEVER touched.
#
# Usage:
#   bash autofyn_audit/teardown.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/pins.sh
source "${SCRIPT_DIR}/lib/pins.sh"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Safety assertions — will abort if names don't match our exact pins.
assert_safe_resource_name container "$CONTAINER_NAME"
assert_safe_resource_name network "$NETWORK_NAME"
assert_safe_resource_name image "$IMAGE_TAG"

log_info "Removing container ${CONTAINER_NAME} ..."
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

log_info "Removing network ${NETWORK_NAME} ..."
docker network rm "${NETWORK_NAME}" 2>/dev/null || true

log_info "Removing image ${IMAGE_TAG} ..."
docker rmi "${IMAGE_TAG}" 2>/dev/null || true

log_info "Removing staged build directory .build/ ..."
rm -rf "${SCRIPT_DIR}/.build"

echo ""
echo "TEARDOWN OK — all autofyn-audit-* resources removed."
echo "  Protected containers (autofyn-sandbox, autofyn-agent, etc.) were NOT touched."
