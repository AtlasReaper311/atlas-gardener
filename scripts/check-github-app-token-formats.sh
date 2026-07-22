#!/usr/bin/env bash
set -eu
set -o pipefail

umask 077

# PART 0 // Fixed compatibility boundary
readonly OWNER="AtlasReaper311"
readonly TARGET_FULL="${1:-AtlasReaper311/atlas-dora}"
readonly TARGET_OWNER="${TARGET_FULL%%/*}"
readonly TARGET_NAME="${TARGET_FULL#*/}"
readonly KEY_PATH="${2:-${HOME}/.config/atlas-gardener/keys/w37-canary.private-key.pem}"
readonly API_ROOT="https://api.github.com"
readonly API_VERSION="2026-03-10"
readonly WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/atlas-gardener-token-formats.XXXXXX")"

CURRENT_TOKEN=""
CURRENT_TOKEN_REVOKED="1"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

base64url_text() {
  python3 - "$1" <<'PY_B64'
import base64
import sys

value = sys.argv[1].encode("utf-8")
print(base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii"), end="")
PY_B64
}

revoke_current_token() {
  if [ -z "${CURRENT_TOKEN}" ]; then
    return 0
  fi
  if [ "${CURRENT_TOKEN_REVOKED}" = "1" ]; then
    return 0
  fi

  local token_config
  token_config="${WORK_ROOT}/curl-token-revoke.conf"

  printf '%s\n' 'silent' > "${token_config}"
  printf '%s\n' 'show-error' >> "${token_config}"
  printf '%s\n' 'location' >> "${token_config}"
  printf 'header = "Accept: application/vnd.github+json"\n' >> "${token_config}"
  printf 'header = "Authorization: Bearer %s"\n' "${CURRENT_TOKEN}" >> "${token_config}"
  printf 'header = "X-GitHub-Api-Version: %s"\n' "${API_VERSION}" >> "${token_config}"
  chmod 600 "${token_config}"

  set +e
  curl --request DELETE --config "${token_config}" "${API_ROOT}/installation/token" >/dev/null
  local revoke_status
  revoke_status="$?"
  set -e

  rm -f "${token_config}"
  CURRENT_TOKEN=""
  CURRENT_TOKEN_REVOKED="1"

  if [ "${revoke_status}" -ne 0 ]; then
    fail "installation token revocation failed"
  fi
}

cleanup() {
  local status
  status="$?"
  trap - EXIT INT TERM HUP
  set +e
  revoke_current_token
  rm -rf "${WORK_ROOT}"
  exit "${status}"
}

trap cleanup EXIT INT TERM HUP

mint_and_probe() {
  local override
  local expected_dot_count
  local label
  local request_path
  local response_path
  local token_config
  local repository_path
  local dot_count
  local token_length

  override="$1"
  expected_dot_count="$2"
  label="$3"
  request_path="${WORK_ROOT}/token-request-${override}.json"
  response_path="${WORK_ROOT}/token-response-${override}.json"
  token_config="${WORK_ROOT}/curl-token-${override}.conf"
  repository_path="${WORK_ROOT}/repository-${override}.json"

  cat > "${request_path}" <<JSON
{
  "repositories": [
    "${TARGET_NAME}"
  ],
  "permissions": {
    "contents": "write",
    "metadata": "read",
    "pull_requests": "write"
  }
}
JSON

  curl --request POST \
    --config "${JWT_CONFIG}" \
    --header "X-GitHub-Stateless-S2S-Token: ${override}" \
    --data-binary "@${request_path}" \
    "${API_ROOT}/app/installations/${INSTALLATION_ID}/access_tokens" > "${response_path}"

  jq -e '.permissions == {"contents":"write","metadata":"read","pull_requests":"write"}' "${response_path}" >/dev/null
  jq -e '.repositories | length == 1' "${response_path}" >/dev/null
  jq -e --arg repository "${TARGET_FULL}" '.repositories[0].full_name == $repository' "${response_path}" >/dev/null

  CURRENT_TOKEN="$(jq -er '.token' "${response_path}")"
  CURRENT_TOKEN_REVOKED="0"

  case "${CURRENT_TOKEN}" in
    ghs_*)
      ;;
    *)
      fail "${label} token did not retain the ghs_ prefix"
      ;;
  esac

  dot_count="$(python3 - "${CURRENT_TOKEN}" <<'PY_DOTS'
import sys
print(sys.argv[1].count("."))
PY_DOTS
)"
  token_length="${#CURRENT_TOKEN}"

  if [ "${dot_count}" -ne "${expected_dot_count}" ]; then
    fail "${label} token had ${dot_count} dots; expected ${expected_dot_count}"
  fi

  printf '%s\n' 'silent' > "${token_config}"
  printf '%s\n' 'show-error' >> "${token_config}"
  printf '%s\n' 'fail' >> "${token_config}"
  printf '%s\n' 'location' >> "${token_config}"
  printf 'header = "Accept: application/vnd.github+json"\n' >> "${token_config}"
  printf 'header = "Authorization: Bearer %s"\n' "${CURRENT_TOKEN}" >> "${token_config}"
  printf 'header = "X-GitHub-Api-Version: %s"\n' "${API_VERSION}" >> "${token_config}"
  chmod 600 "${token_config}"

  curl --config "${token_config}" "${API_ROOT}/repos/${TARGET_FULL}" > "${repository_path}"
  jq -e --arg repository "${TARGET_FULL}" '.full_name == $repository' "${repository_path}" >/dev/null

  printf 'PASS: %s token authenticated successfully (length %s, dots %s)\n' "${label}" "${token_length}" "${dot_count}"

  revoke_current_token
  rm -f "${request_path}"
  rm -f "${response_path}"
  rm -f "${token_config}"
  rm -f "${repository_path}"
}

# PART 1 // Validate local prerequisites
printf '\nPART 1 // Validate GitHub App token compatibility prerequisites\n'

require_command curl
require_command jq
require_command openssl
require_command python3

if [ "${TARGET_OWNER}" != "${OWNER}" ]; then
  fail "target repository must belong to ${OWNER}"
fi
if [ "${TARGET_NAME}" = "${TARGET_FULL}" ]; then
  fail "target repository must use owner/name form"
fi
if [ ! -f "${KEY_PATH}" ]; then
  fail "GitHub App private key not found at ${KEY_PATH}"
fi

chmod 600 "${KEY_PATH}"
if ! openssl pkey -in "${KEY_PATH}" -check -noout >/dev/null 2>&1; then
  fail "GitHub App private key could not be validated"
fi

APP_ID="${ATLAS_GARDENER_APP_ID:-}"
if [ -z "${APP_ID}" ]; then
  printf 'Enter the GitHub App ID shown on the App settings page: '
  read -r APP_ID
fi
case "${APP_ID}" in
  ''|*[!0-9]*)
    fail "GitHub App ID must contain digits only"
    ;;
esac

printf 'PASS: local prerequisites validated\n'

# PART 2 // Authenticate as the App without exposing credentials
printf '\nPART 2 // Authenticate as the GitHub App\n'

readonly NOW_EPOCH="$(date +%s)"
readonly JWT_IAT="$((NOW_EPOCH - 60))"
readonly JWT_EXP="$((NOW_EPOCH + 540))"
readonly JWT_HEADER_JSON='{"alg":"RS256","typ":"JWT"}'
readonly JWT_PAYLOAD_JSON="$(printf '{"iat":%s,"exp":%s,"iss":"%s"}' "${JWT_IAT}" "${JWT_EXP}" "${APP_ID}")"
readonly JWT_HEADER="$(base64url_text "${JWT_HEADER_JSON}")"
readonly JWT_PAYLOAD="$(base64url_text "${JWT_PAYLOAD_JSON}")"
readonly JWT_UNSIGNED="${JWT_HEADER}.${JWT_PAYLOAD}"
readonly JWT_UNSIGNED_PATH="${WORK_ROOT}/jwt-unsigned.txt"
readonly JWT_SIGNATURE_PATH="${WORK_ROOT}/jwt-signature.bin"

printf '%s' "${JWT_UNSIGNED}" > "${JWT_UNSIGNED_PATH}"
openssl dgst -sha256 -sign "${KEY_PATH}" -out "${JWT_SIGNATURE_PATH}" "${JWT_UNSIGNED_PATH}"
readonly JWT_SIGNATURE="$(python3 - "${JWT_SIGNATURE_PATH}" <<'PY_SIG'
import base64
import sys
from pathlib import Path

value = Path(sys.argv[1]).read_bytes()
print(base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii"), end="")
PY_SIG
)"
APP_JWT="${JWT_UNSIGNED}.${JWT_SIGNATURE}"

readonly JWT_CONFIG="${WORK_ROOT}/curl-jwt.conf"
readonly APP_INFO_PATH="${WORK_ROOT}/app.json"
readonly INSTALLATION_PATH="${WORK_ROOT}/installation.json"

printf '%s\n' 'silent' > "${JWT_CONFIG}"
printf '%s\n' 'show-error' >> "${JWT_CONFIG}"
printf '%s\n' 'fail' >> "${JWT_CONFIG}"
printf '%s\n' 'location' >> "${JWT_CONFIG}"
printf 'header = "Accept: application/vnd.github+json"\n' >> "${JWT_CONFIG}"
printf 'header = "Authorization: Bearer %s"\n' "${APP_JWT}" >> "${JWT_CONFIG}"
printf 'header = "X-GitHub-Api-Version: %s"\n' "${API_VERSION}" >> "${JWT_CONFIG}"
printf 'header = "Content-Type: application/json"\n' >> "${JWT_CONFIG}"
chmod 600 "${JWT_CONFIG}"

curl --config "${JWT_CONFIG}" "${API_ROOT}/app" > "${APP_INFO_PATH}"
if [ "$(jq -r '.id' "${APP_INFO_PATH}")" != "${APP_ID}" ]; then
  fail "private key and App ID identify different GitHub Apps"
fi

readonly APP_SLUG="$(jq -r '.slug' "${APP_INFO_PATH}")"
printf 'PASS: authenticated as %s\n' "${APP_SLUG}"

# PART 3 // Confirm installation and permission boundaries
printf '\nPART 3 // Validate installation scope and permissions\n'

curl --config "${JWT_CONFIG}" "${API_ROOT}/repos/${TARGET_FULL}/installation" > "${INSTALLATION_PATH}"

jq -e --arg owner "${OWNER}" '.account.login == $owner' "${INSTALLATION_PATH}" >/dev/null
jq -e '.repository_selection == "selected"' "${INSTALLATION_PATH}" >/dev/null
jq -e '.permissions == {"contents":"write","metadata":"read","pull_requests":"write"}' "${INSTALLATION_PATH}" >/dev/null

if [ "$(jq -r '.app_id' "${INSTALLATION_PATH}")" != "${APP_ID}" ]; then
  fail "target installation belongs to a different GitHub App"
fi

readonly INSTALLATION_ID="$(jq -r '.id' "${INSTALLATION_PATH}")"
printf 'PASS: selected-repository installation with exact Gardener permissions\n'

# PART 4 // Force and validate both GitHub token formats
printf '\nPART 4 // Probe stateless and classic installation tokens\n'

mint_and_probe "enabled" "2" "stateless"
mint_and_probe "disabled" "0" "classic"

rm -f "${JWT_CONFIG}"
unset APP_JWT

printf '\nPASS: GitHub App installation token compatibility verified for both formats\n'
printf 'Routine token minting should omit the temporary override header.\n'
