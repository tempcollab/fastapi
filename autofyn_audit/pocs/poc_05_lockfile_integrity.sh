#!/usr/bin/env bash
# poc_05_lockfile_integrity.sh — INFORMATIONAL: uv.lock integrity + installed version check.
#
# EXPECTED OUTCOME: PASS (installed packages match audited pins; lockfile verified clean).
#
# Context:
#   Full static lockfile integrity verification was completed in round 1 (see
#   autofyn_audit/../tmp/round-1/uvlock-integrity.md). Key findings:
#     - All 3,219 artifact URLs in uv.lock point to files.pythonhosted.org only.
#     - 14 packages differ from upstream FastAPI 0.137.1; ALL are legitimate version
#       bumps present on real PyPI with matching SHA-256 hashes (0 mismatches).
#     - GitHub Actions and pre-commit hook SHAs verified against real upstream repos.
#     - No git+, file://, or non-PyPI sources found.
#   VERDICT (static): NO supply-chain tampering detected.
#
# This PoC performs a lightweight LIVE re-confirmation of the most critical pins
# observable at runtime — the installed fastar and fastapi versions inside the
# running container — and asserts they match the audited values in pins.sh.
#
# PASS = fastar==${FASTAR_VERSION} installed AND fastapi==${CLAIMED_VERSION} installed
#        (matches audited pins; static lockfile verification found CLEAN).
# FAIL = version mismatch (would itself be a supply-chain finding).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"

echo "=== poc_05: uv.lock integrity + installed version verification ==="
echo "fastar pin   : ${FASTAR_VERSION}"
echo "fastapi pin  : ${CLAIMED_VERSION}"
echo ""
echo "NOTE: Full static lockfile hash verification (all 14 differing pins vs PyPI)"
echo "was performed in round 1 and found CLEAN. This check is INFORMATIONAL —"
echo "it confirms the live container matches the audited static state."
echo "See: round-1/uvlock-integrity.md"
echo ""

PASS=1

# ── fastar version check ──────────────────────────────────────────────────────
echo "--- Checking installed fastar version ---"
FASTAR_INSTALLED="$(dexec pip show fastar 2>/dev/null \
    | grep '^Version:' \
    | awk '{print $2}' \
    || echo "NOT_FOUND")"
echo "Expected : ${FASTAR_VERSION}"
echo "Installed: ${FASTAR_INSTALLED}"

if [[ "$FASTAR_INSTALLED" == "$FASTAR_VERSION" ]]; then
    echo "[OK] fastar version matches audited pin (${FASTAR_VERSION})"
else
    echo "[FAIL] fastar version mismatch: expected ${FASTAR_VERSION}, got ${FASTAR_INSTALLED}"
    PASS=0
fi
echo ""

# ── fastapi version check ─────────────────────────────────────────────────────
echo "--- Checking installed fastapi version ---"
FASTAPI_INSTALLED="$(dexec python3 -c \
    "import fastapi; print(fastapi.__version__)" \
    2>/dev/null || echo "NOT_FOUND")"
echo "Expected : ${CLAIMED_VERSION}"
echo "Installed: ${FASTAPI_INSTALLED}"

if [[ "$FASTAPI_INSTALLED" == "$CLAIMED_VERSION" ]]; then
    echo "[OK] fastapi version matches audited pin (${CLAIMED_VERSION})"
else
    echo "[FAIL] fastapi version mismatch: expected ${CLAIMED_VERSION}, got ${FASTAPI_INSTALLED}"
    PASS=0
fi
echo ""

# ── Static analysis summary (informational) ───────────────────────────────────
echo "--- Static lockfile integrity summary (round-1 result) ---"
echo "Packages with differing versions (fork vs upstream 0.137.1): 14"
echo "Non-pythonhosted.org artifact URLs: 0"
echo "Hash mismatches vs PyPI: 0"
echo "GitHub Actions SHA substitutions: 0 (astral-sh/setup-uv v8.1.0 -> v8.2.0 verified)"
echo "OSV MAL-2026-4750 (fastar): WITHDRAWN as false positive (OSSF PR #1276)"
echo "Result: NO supply-chain tampering detected in the uv.lock."
echo ""

# ── Verdict ───────────────────────────────────────────────────────────────────
echo "--- Verdict ---"
if (( PASS == 1 )); then
    print_check "lockfile_integrity_verified" "PASS" \
        "fastar==${FASTAR_VERSION} and fastapi==${CLAIMED_VERSION} confirmed installed; static lockfile verification found 0 hash mismatches across all 14 differing pins (round-1/uvlock-integrity.md)"
else
    print_check "lockfile_integrity_verified" "FAIL" \
        "installed version mismatch — expected fastar=${FASTAR_VERSION} fastapi=${CLAIMED_VERSION}; see output above"
fi
