# Target-owned Gardener gate caller

The reusable merge gate is inert until an approved target repository adds a caller pinned to an immutable merged Atlas Gardener commit and an immutable merged Atlas Infra authority commit.

A target caller has this shape:

```yaml
name: Gardener remediation gate

on:
  pull_request:
    types: [opened, reopened, synchronize, ready_for_review]

permissions:
  contents: read

concurrency:
  group: gardener-remediation-${{ github.repository }}-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  gardener:
    uses: AtlasReaper311/atlas-gardener/.github/workflows/gardener-automerge-gate.yml@<immutable-gardener-commit>
    permissions:
      contents: write
      pull-requests: write
      checks: read
      statuses: read
    with:
      enabled: ${{ vars.ATLAS_GARDENER_AUTOMERGE_ENABLED == 'true' }}
      expected_app_login: <exact-github-app-bot-login>
      required_checks_json: '["<exact-required-check-name>"]'
      authority_ref: <immutable-atlas-infra-commit>
```

The placeholders are rollout-time values and must not be committed until the corresponding source PRs are merged and the target repository has been inspected.

## Required-check rule

`required_checks_json` must contain the exact target-native CI checks that validate the remediation commit. It must not contain the Gardener gate job itself. Including the gate in its own dependency list creates a self-waiting cycle and is refused during review.

The list must be:

- non-empty;
- sorted;
- unique;
- exact, including capitalization;
- limited to checks that run on every Gardener pull request;
- reviewed again whenever the target repository renames or restructures CI.

Missing checks never count as success. Failed, cancelled, skipped, stale, timed-out, pending, and unknown check states prevent automatic merge.

## Repository variables

The target caller is disabled unless:

```text
ATLAS_GARDENER_AUTOMERGE_ENABLED=true
```

This target-local opt-in is separate from the central controller mode and write gate. Automatic merge therefore requires all three controls:

1. central mode `automerge-low-risk`;
2. central write gate `enabled`;
3. target auto-merge variable `true`.

GitHub native auto-merge must also be enabled in the target repository settings as a separate owner-approved action.

## Rollout order

Install callers only after the authority and controller PRs merge. Start with `AtlasReaper311/atlas-dora`, validate one real `.gitignore`-only remediation, then expand through reviewed repository batches. Adding a caller source file does not prove the repository setting, required checks, App installation, or live canary.
