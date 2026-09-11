# Automatic remediation controller

Atlas Gardener 0.4 adds a separate non-interactive controller while preserving the existing manual CLI confirmation path. Merging this source does not enable live operation. The scheduled workflow defaults to `disabled`, requires an independent write gate for write modes, and has no target repository callers until separate reviewed rollout pull requests add them.

## Trust chain

The controller accepts only an attested public Finding bundle from `AtlasReaper311/atlas-dep-audit/.github/workflows/audit.yml`. The workflow verifies the artifact attestation before passing the bundle to Python. Gardener then validates the closed Finding schema, canonical fingerprints, producer identity, source run, source commit, Atlas Infra authority commit, policy digest, bundle digest, repository base snapshots, age, expiry, sorted uniqueness, and public-only declaration.

Findings are data. No Finding, evidence field, repository path, or proposal string is passed to a shell. Git operations use fixed argument arrays. GitHub network operations use explicit method-and-path allowlists.

A valid Finding with `remediation.eligible=false` remains part of the evidence stream but is not a remediation failure. After repository classification and snapshot checks, the controller records it as a non-actionable observation and does not select a fixer, clone the target, mint a token, or create a pull request. A Finding marked remediation-eligible that cannot be processed still fails closed as a refusal.

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

The key determines the primary `gardener/` branch namespace and appears inside the signed approval marker stored in the pull-request body. Before creating Git objects Gardener searches all pull requests on that deterministic branch.

A matching open pull request is idempotent only when its signed approval binds the exact current plan and patch. A matching merged pull request is already remediated only under the same condition. A matching exact closed-unmerged pull request remains closed and is not recreated.

When a closed-unmerged proposal carries the same remediation key but an obsolete plan or patch, Gardener may select one deterministic replacement branch of the form `gardener/<fixer-id>-<first-12-key-hex>-r-<first-12-patch-hex>`. The replacement plan digest is recomputed after branch selection. Gardener leaves the obsolete branch and pull request untouched, then applies the same exact-state idempotence rules to the replacement branch.

A conflicting open or merged proposal, multiple matching pull requests, an unexplained existing branch, approval mismatch, base drift, classification drift, policy drift, expiry, or an unexpected commit fails closed. Gardener never force-pushes, reopens, retargets, deletes, or rewrites an obsolete proposal branch.

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

Dependency and container fixers remain review-required draft-PR-only. Closed-proposal replacement does not make them eligible for native automatic merge.

## Evidence and notifications

Every controller run writes one bounded JSON artifact with 30-day retention containing run identity, mode, write-gate state, policy and coverage digests, bundle digest, Finding fingerprints, non-actionable Finding observations, proposals, plans, refusals, pull-request outcomes, token mint and revoke status, notifications, and an evidence digest. Credential values and sensitive file contents are excluded.

When a replacement branch is selected, the recorded plan digest is updated to the replacement plan before publication so controller evidence and the signed approval refer to the same reviewed plan.

Notifications use the existing authenticated Atlas Notify `alert` envelope with `signal_class=gardener`. The controller emits consolidated state outcomes rather than one message per internal action. Non-actionable observations are reported as informational counts, not remediation refusals. A warning-level `remediation_refused` notification is reserved for Findings that fail controller validation or an attempted supported remediation. Atlas Notify must configure `GARDENER_WEBHOOK_URL` for a dedicated Gardener channel; otherwise this class falls back to the default webhook.

## Scheduling

The weekly public audit runs on Monday at `08:41 UTC`. Gardener reconciles the resulting attested bundle on Monday at `10:15 UTC`. Manual dispatch remains available for an owner-approved exceptional run. The controller does not run daily because the Finding bundle expires after thirty-six hours; a daily controller against a weekly producer would spend most of the week rejecting stale evidence.

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
