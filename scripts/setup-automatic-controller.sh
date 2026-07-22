#!/usr/bin/env bash
set -eu
set -o pipefail

umask 077

readonly OWNER="AtlasReaper311"
readonly GARDENER_REPOSITORY="AtlasReaper311/atlas-gardener"
readonly PERSONAL_ROOT="${HOME}/Personal"
readonly GARDENER_ROOT="${PERSONAL_ROOT}/atlas-gardener"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# PART 0 // Safety boundary
#
# Run this file only after the atlas-infra, atlas-gardener, and atlas-dep-audit
# source PRs are merged in dependency order and their main branches are green.
# This script stores configuration in disabled mode. It does not enable the
# controller schedule, the audit handoff, target repository callers, or native
# repository auto-merge.

printf '\nPART 0 // Validate local operator context\n'

require_command gh
require_command git

if [ ! -d "${GARDENER_ROOT}/.git" ]; then
  fail "atlas-gardener is not available at ${GARDENER_ROOT}"
fi

cd "${GARDENER_ROOT}"

git status --short

test -z "$(git status --porcelain=v1)" || fail "atlas-gardener worktree is dirty"

git switch main

git pull --ff-only

gh auth status

test "$(gh api user --jq .login)" = "${OWNER}" || fail "GitHub CLI is not authenticated as ${OWNER}"

printf 'PASS: operator context validated\n'

# PART 1 // Store the non-secret GitHub App identifier

printf '\nPART 1 // Store GitHub App ID as a repository variable\n'

printf 'Enter the numeric Atlas Gardener GitHub App ID: '
read -r APP_ID

case "${APP_ID}" in
  ''|*[!0-9]*)
    fail "GitHub App ID must contain digits only"
    ;;
esac

gh variable set ATLAS_GARDENER_APP_ID --repo "${GARDENER_REPOSITORY}" --body "${APP_ID}"

unset APP_ID

printf 'PASS: GitHub App ID stored\n'

# PART 2 // Store secrets through GitHub CLI interactive prompts
#
# The following commands prompt for secret values without placing them in this
# file, shell history, pull requests, issues, logs, or chat. Paste each value
# only into the GitHub CLI prompt.

printf '\nPART 2 // Store GitHub App private key\n'

gh secret set ATLAS_GARDENER_APP_PRIVATE_KEY --repo "${GARDENER_REPOSITORY}"

printf '\nPART 2 // Store atlas-notify token\n'

gh secret set NOTIFY_TOKEN --repo "${GARDENER_REPOSITORY}"

printf 'PASS: controller secrets stored through interactive prompts\n'

# PART 3 // Install the kill switch in its safe state

printf '\nPART 3 // Set disabled controller state\n'

gh variable set ATLAS_GARDENER_MODE --repo "${GARDENER_REPOSITORY}" --body "disabled"

gh variable set ATLAS_GARDENER_WRITE_GATE --repo "${GARDENER_REPOSITORY}" --body "disabled"

printf 'PASS: controller mode and write gate are disabled\n'

# PART 4 // Manual GitHub dashboard actions after separate rollout approval
#
# Do not perform these actions during source setup.
#
# 1. In atlas-dep-audit, add ATLAS_GARDENER_HANDOFF_ENABLED=false.
# 2. Keep the Atlas Gardener GitHub App in selected-repository mode.
# 3. Confirm App permissions remain Metadata read, Contents write, and Pull requests write.
# 4. Merge reviewed target caller PRs beginning with AtlasReaper311/atlas-dora.
# 5. Enable GitHub native auto-merge only on the approved canary repository.
# 6. Confirm the target caller pins immutable merged atlas-infra and atlas-gardener commits.
# 7. Confirm required_checks_json exactly matches the target repository's required CI checks.
# 8. Move through disabled, observe, pr-only, and automerge-low-risk as separate rollout stages.

# PART 5 // Verification

printf '\nPART 5 // Verify stored non-secret state\n'

gh variable list --repo "${GARDENER_REPOSITORY}"

gh secret list --repo "${GARDENER_REPOSITORY}"

CURRENT_MODE="$(gh variable get ATLAS_GARDENER_MODE --repo "${GARDENER_REPOSITORY}")"

test "${CURRENT_MODE}" = "disabled" || fail "controller mode is not disabled"

CURRENT_GATE="$(gh variable get ATLAS_GARDENER_WRITE_GATE --repo "${GARDENER_REPOSITORY}")"

test "${CURRENT_GATE}" = "disabled" || fail "controller write gate is not disabled"

unset CURRENT_MODE

unset CURRENT_GATE

printf '\nSOURCE SETUP COMPLETE: credentials are stored and all runtime writes remain disabled.\n'
