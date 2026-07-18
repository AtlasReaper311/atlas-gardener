# Future GitHub pull-request model

Phase 2 stops before GitHub integration. A later approved phase may add a
GitHub App that turns an already reviewed proposal into a uniquely named branch
and draft pull request. It must regenerate the patch, run target-native checks,
attach bounded evidence, and stop. It must not merge, approve runs, deploy,
delete branches, or bypass branch protection.

## Exact future repository permissions

Dry-run installation, selected repositories only:

- Metadata: read
- Contents: read
- Actions: read

PR mode, manually enabled on selected repositories only:

- Metadata: read
- Contents: read and write
- Pull requests: read and write
- Workflows: read and write only for a separately approved proposal touching
  `.github/workflows/**`

Explicitly excluded: Administration, Secrets, Environments, Deployments,
Actions write, Issues write, Packages write, Members, Billing, merge authority,
and organization-wide installation.

## Future configuration and secret names

- `ATLAS_GARDENER_APP_ID`: non-secret GitHub App identifier
- `ATLAS_GARDENER_INSTALLATION_ID`: non-secret selected installation identifier
- `ATLAS_GARDENER_PRIVATE_KEY`: private-key secret used only to mint short-lived
  installation tokens

No personal access token, GitHub secret value reader, Cloudflare token,
deployment credential, webhook secret, or billing credential is required.
Provider values must never enter a Finding, proposal, evidence summary, log, or
test fixture.

## Current owner-executed rollout exception

The approved Dependabot rollout is not an unattended integration. The owner
runs it locally against a digest-bound plan and confirms every repository. It
uses a new fine-grained PAT restricted to selected repositories with Contents,
Pull requests, and Workflows write permissions. It may create only
`chore/dependabot-rollout` and a draft pull request. It cannot merge, deploy, or
change repository settings. The future unattended model above still requires a
GitHub App and does not reuse this local token.

## Pull-request behavior

One fingerprint and fixer type produces one draft PR. Branch names and commit
messages must be deterministic and collision-bounded. Repeated runs update no
open proposal unless the reviewed patch digest still matches. All remediation
remains human-reviewed, with no automatic merge or deployment.
