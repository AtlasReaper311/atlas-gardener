# GitHub pull-request model

Atlas Gardener separates proposal generation, remote plan approval, GitHub mutation, repository-owned validation, merge, and deployment.

The current Wave 3.7 source implements the first bounded GitHub App adapter. It can turn one reviewed remediation proposal into one exact commit and one draft pull request. It stops there.

## Current v1 permission contract

Selected repositories only:

- Metadata: read
- Contents: read and write
- Pull requests: read and write

Explicitly excluded:

- Administration;
- Actions write;
- Checks;
- Secrets;
- Variables;
- Environments;
- Deployments;
- Issues;
- Packages;
- Members;
- Billing;
- organization-wide installation;
- merge or approval authority.

The adapter consumes a short-lived installation token. It does not read a GitHub App private key or mint its own token.

## Current v1 file boundary

The v1 adapter refuses `.github/workflows/**` proposals. This keeps its provider permission set fixed and prevents a proposal from silently requiring workflow-write authority.

A future workflow-capable version may be considered only after:

1. a separate contract records that the reviewed proposal touches workflow files;
2. the exact workflow permission requirement is represented in the plan digest;
3. provider installation scope is separately approved;
4. tests prove non-workflow plans cannot request or use that permission;
5. the rollout remains branch plus exact commit plus draft PR, then stop.

The current v1 adapter must not be widened in place through an undocumented permission change.

## Plan and apply behaviour

One proposal fingerprint and fixer produces one deterministic branch and one canonical plan digest.

Before apply, Gardener rechecks:

- repository identity;
- lifecycle, scope, and provenance;
- classification fingerprint;
- clean local checkout;
- local base branch and commit;
- remote base commit;
- branch non-existence;
- expiry;
- exact approved plan digest.

The apply phase uses a small Git Data API allowlist to create reviewed blobs, one tree, one commit, one branch, and one draft pull request. It has no merge, approval, workflow-dispatch, settings, secret, deployment, branch-deletion, or non-GitHub provider endpoint.

## Credential boundary

Potential provider-side identifiers are:

- `ATLAS_GARDENER_APP_ID`, non-secret;
- `ATLAS_GARDENER_INSTALLATION_ID`, non-secret;
- a GitHub App private key held only by the approved external token broker.

Gardener receives only the resulting short-lived installation token through `ATLAS_GARDENER_INSTALLATION_TOKEN`.

No personal access token, Cloudflare token, deployment credential, webhook secret, or billing credential belongs in a finding, proposal, plan, log, fixture, issue, or pull request.

## Current owner-executed rollout exception

The separate Dependabot rollout is an owner-run local process, not the unattended GitHub App model. It consumes a digest-bound plan and a fine-grained token restricted to selected repositories. It does not grant the GitHub App additional authority.

## Merge and deployment boundary

Gardener never merges, approves, deploys, or changes repository settings. Repository owners review the draft PR and native checks. Merge and any production rollout remain separate owner-approved actions.
