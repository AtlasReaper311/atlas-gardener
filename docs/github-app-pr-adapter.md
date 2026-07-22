# GitHub App draft-PR adapter

Wave 3.7 adds the final controlled write seam to Atlas Gardener: an exact reviewed proposal can be converted into a deterministic remote PR plan and, after a separate owner approval, applied with a short-lived GitHub App installation token.

The adapter stops at a draft pull request. It does not approve or merge the PR, deploy anything, change repository settings or secrets, or mutate Cloudflare, Home Assistant, Open WebUI, Ollama, or another provider.

## Two-step workflow

First build the remote plan offline from an already reviewed `RemediationProposal` and a clean checkout at the exact target base commit:

```bash
atlas-gardener github-app-pr-plan \
  --proposal /tmp/proposal.json \
  --repo ~/Personal/example-repository \
  --output /tmp/github-app-pr-plan.json
```

The planner re-validates the proposal, re-runs the deterministic fixer, requires the same file list and patch digest, checks that the repository is clean, verifies the GitHub origin, records the exact base SHA and base blob SHAs, and computes a new canonical plan digest.

Review that plan before any network operation.

A dry review of the stored plan is still provider-free:

```bash
atlas-gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --dry-run
```

The summary deliberately omits file contents and credentials while retaining the exact file hashes, target repository, base SHA, branch, requested permission set, and plan digest.

## Apply gate

Application requires all of the following:

1. the exact reviewed plan file;
2. the exact `--approved-plan-digest` from that plan;
3. an interactive confirmation;
4. a short-lived GitHub App installation token supplied through the approved external broker in `ATLAS_GARDENER_INSTALLATION_TOKEN`;
5. the remote base branch still pointing at the exact reviewed base SHA;
6. the deterministic `gardener/...` branch not already existing.

Example shape after an approved token has been injected into the process environment:

```bash
atlas-gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --approved-plan-digest sha256:<reviewed-digest> \
  --apply
```

Do not paste the installation token into the command, repository, issue, pull request, chat, or shell history. The adapter reads it only from the process environment and never prints it.

## Permission contract

The remote plan accepts only this GitHub App permission set:

```text
Metadata: read
Contents: write
Pull requests: write
```

No Actions, Checks, Administration, Environments, Secrets, Deployments, Issues, or Organization permission is requested by the adapter.

The adapter intentionally does not poll native PR checks because doing so would widen the App permission surface. Repository-owned `pull_request` workflows run normally when the draft PR opens. Their results remain visible in GitHub for the human reviewer.

## Exact remote sequence

After all preflight checks pass, the only GitHub REST mutations are:

1. create `refs/heads/gardener/...` from the exact reviewed base SHA;
2. write or delete only the reviewed one-to-five files using the exact base blob SHA where required;
3. open one draft pull request from that branch to the reviewed base branch;
4. stop.

The adapter has no merge endpoint, auto-merge endpoint, review-approval endpoint, repository-settings endpoint, secret endpoint, workflow-dispatch endpoint, or provider-write endpoint.

If a remote write fails after the branch was created, the adapter fails and leaves the partial Gardener branch for explicit owner inspection. It does not silently delete or rewrite remote history as cleanup.

## Token broker boundary

Atlas Gardener does not mint installation tokens and does not read a GitHub App private key.

App creation, App installation, private-key custody, and short-lived installation-token minting belong to the provider-side credential boundary. They must be configured separately through an approved secret mechanism. This keeps private-key material outside the repository and outside the Gardener process that handles remediation content.

The current source is therefore ready to consume an ephemeral App installation token, but no GitHub App has been created or installed by this source change.

## Plan integrity

The v1 remote plan records:

- exact repository;
- exact base branch and 40-character base commit;
- deterministic Gardener branch;
- original proposal/finding/patch identities;
- one-to-five exact file operations;
- base blob SHA for replacement/deletion;
- before/after SHA-256 fingerprints;
- UTF-8 after content for reviewed create/replace operations;
- validation plan inherited from the reviewed remediation proposal;
- expiry;
- exact permission requirement;
- `stop_after = draft-pull-request`.

Changing any of those values invalidates the plan digest.

## Safety refusals

The adapter refuses, among other cases:

- non-Atlas repository targets;
- origin/directory identity disagreement;
- dirty worktrees;
- expired proposals or plans;
- changed deterministic patch digest;
- more than five changed files;
- unsafe, binary, credential-like, or path-escaping files;
- remote base-branch drift;
- existing Gardener branch;
- digest mismatch;
- missing or implausibly short installation token;
- unexpected permission declarations;
- non-draft stop semantics.

## Provider rollout remains separate

Merging the source adapter does not create or install a GitHub App and does not grant any new permission to Atlas Gardener.

A later provider rollout, if approved, must create the App with only the permission contract above, install it only on the intended Atlas repositories, store its private key through the approved secret mechanism, and provide an external short-lived token broker. That provider action remains outside source merge authority.
