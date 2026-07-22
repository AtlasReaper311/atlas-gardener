# Automatic remediation controller

Atlas Gardener 0.4 adds a separate non-interactive controller while preserving the existing manual CLI confirmation path. Merging this source does not enable live operation. The scheduled workflow defaults to `disabled`, requires an independent write gate for write modes, and has no target repository callers until separate reviewed rollout pull requests add them.

## Trust chain

The controller accepts only an attested public Finding bundle from `AtlasReaper311/atlas-dep-audit/.github/workflows/audit.yml`. The workflow verifies the artifact attestation before passing the bundle to Python. Gardener then validates the closed Finding schema, canonical fingerprints, producer identity, source run, source commit, Atlas Infra authority commit, policy digest, bundle digest, repository base snapshots, age, expiry, sorted uniqueness, and public-only declaration.

Findings are data. No Finding, evidence field, repository path, or proposal string is passed to a shell. Git operations use fixed argument arrays. GitHub network operations use explicit method-and-path allowlists.

## Modes

The effective mode is the intersection of committed Atlas Infra policy and repository variables:

- `disabled`: validate authority and emit evidence without fetching a bundle, reading secrets, minting tokens, or writing to targets;
- `observe`: verify the bundle, classify Findings, create deterministic proposals and plans locally, then report without target writes;
- `pr-only`: create deterministic draft pull requests after the independent write gate is enabled;
- `automerge-low-risk`: create ready pull requests only for exact approved low-risk `.gitignore` additions; all other supported plans remain drafts or are refused.

`pr-only` and `automerge-low-risk` require `ATLAS_GARDENER_WRITE_GATE=enabled`. Missing and unknown values fail closed.

## Credential boundary

`ATLAS_GARDENER_APP_ID` is a non-secret repository variable. `ATLAS_GARDENER_APP_PRIVATE_KEY` and `NOTIFY_TOKEN` are Actions secrets entered through GitHub CLI or the GitHub dashboard. The controller writes the private key to a mode-0600 temporary file only long enough to sign an App JWT.

For each target operation Gardener:

1. resolves the App installation for the exact repository;
2. requests one installation token restricted to that repository;
3. requests exactly Metadata read, Contents write, and Pull requests write;
4. performs one lookup or pull-request publication operation;
5. explicitly revokes the token;
6. records mint and revoke status without the token value.

Classic opaque and stateless installation-token formats are treated as bearer strings. Token payloads and dot counts are never interpreted.

## Deterministic identity and idempotence

The remediation key binds:

- repository;
- rule ID;
- Finding fingerprint;
- fixer ID;
- fixer version;
- exact target base SHA.

The key determines the `gardener/` branch namespace and appears inside the signed approval marker stored in the pull-request body. Before creating Git objects Gardener searches all pull requests on that deterministic branch. A matching open pull request is an idempotent success. A matching merged pull request is recorded as already remediated. Multiple matches, an unexplained existing branch, base drift, classification drift, policy drift, patch drift, expiry, or an unexpected commit fail closed. Gardener never force-pushes.

## Automatic merge boundary

The central GitHub App does not merge. Each approved target repository calls the immutable reusable workflow `gardener-automerge-gate.yml` with its repository-scoped `GITHUB_TOKEN`.

The target gate requires:

- exact approved App bot author;
- open, ready pull request;
- deterministic `gardener/` branch;
- one valid approval marker;
- current policy and coverage digests;
- exact base branch and base SHA;
- exact one-commit head SHA;
- unexpired `automerge-low-risk` approval;
- exact low-risk fixer;
- exactly one `.gitignore` file in mode `100644`;
- additions only;
- no more than two approved lines;
- every configured required check present and successful.

The initial approved lines are `.DS_Store`, `__pycache__/`, and `*.py[cod]`, selected by fixer. Missing checks are never success. Failed, pending, skipped, cancelled, stale, timed-out, or unknown checks prevent automatic merge. When eligible, the target workflow enables GitHub native squash auto-merge and branch deletion. It never bypasses repository protection.

## Evidence and notifications

Every controller run writes one bounded JSON artifact with 30-day retention containing run identity, mode, write-gate state, policy and coverage digests, bundle digest, Finding fingerprints, proposals, plans, refusals, pull-request outcomes, token mint and revoke status, notifications, and an evidence digest. Credential values and sensitive file contents are excluded.

Notifications use the existing authenticated Atlas Notify `alert` envelope with `signal_class=cicd`. The controller emits consolidated state outcomes rather than one message per internal action.

## Scheduling

The weekly public audit remains Monday at 08:41 UTC. Gardener is scheduled daily at 10:15 UTC. Monday can ingest a fresh attested bundle; later daily runs reconcile deterministic pull-request outcomes. The Finding bundle expires after 36 hours, so a delayed Monday audit can be consumed on Tuesday without allowing an old weekly result to replay indefinitely.

The schedule exists in source but live writes remain disabled until the repository variables, secrets, audit handoff, target caller, native auto-merge setting, and staged rollout are separately approved.

## Rollback

Immediate stop:

1. set `ATLAS_GARDENER_WRITE_GATE=disabled`;
2. set `ATLAS_GARDENER_MODE=disabled`;
3. disable native auto-merge on any open Gardener pull request;
4. close unexpected Gardener pull requests;
5. rotate the App private key only when compromise is suspected;
6. remove selected repositories from the App installation when containment requires it;
7. revert any merged housekeeping commit through a reviewed target pull request.

Restore through disabled, observe, pr-only canary, automerge-low-risk canary, limited batch, then all verified public runtime repositories. A merged workflow or green dry run does not prove live completion.
