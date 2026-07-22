# GitHub App provider rollout checklist

This checklist is the provider-side gate for the Atlas Gardener GitHub App draft-PR adapter. Completing the source adapter does not create, install, configure, or activate a GitHub App.

The provider rollout remains a separate owner-approved operation.

## Preconditions

Before any provider action:

- `atlas-gardener` source CI is green on the exact adapter revision;
- the adapter remains dry-run by default;
- the exact permission contract is unchanged;
- the adapter still stops after opening one draft pull request;
- no merge, approval, workflow-dispatch, settings, secret-management, deployment, or non-GitHub provider endpoint exists in the adapter;
- the selected canary repository has normal pull-request validation on its default branch;
- the selected canary change is non-production, reversible, bounded to the reviewed Gardener proposal, and does not touch secret-bearing material.

## App permission contract

Create the App with only:

```text
Metadata: read
Contents: write
Pull requests: write
```

Do not grant:

- Administration;
- Actions;
- Checks;
- Deployments;
- Environments;
- Issues;
- Members or organization administration;
- Secrets;
- Variables;
- Webhooks that trigger Gardener execution;
- any Cloudflare, Home Assistant, Open WebUI, Ollama, or other provider permission.

Repository-owned pull-request checks run independently after the draft PR opens. Gardener does not need permission to approve, override, or rerun them.

## Installation scope

Install the App only on explicitly selected Atlas repositories.

Do not grant account-wide access by default. Add repositories individually as the controlled-write model is proven.

The first installation should cover one canary repository only.

## Private-key custody

The GitHub App private key must remain outside repository source and outside normal Gardener proposal artefacts.

Do not paste the key into chat, a GitHub issue, a pull request, a shell command, or a checked-in configuration file.

Private-key custody belongs to the approved credential boundary that mints short-lived installation tokens. Gardener consumes only the resulting ephemeral installation token.

## Token broker

The broker must:

- authenticate as the approved GitHub App;
- request an installation token for the intended installation only;
- keep the token lifetime short;
- expose the token to the Gardener process only through the approved ephemeral environment boundary;
- never write the token into the PR plan, logs, files, Git configuration, issue text, or PR body;
- stop minting tokens when the App or installation is disabled.

The Gardener process expects the ephemeral value in:

```text
ATLAS_GARDENER_INSTALLATION_TOKEN
```

The variable name is not a repository secret requirement. How the broker injects the value is a provider/host decision and must be reviewed separately.

## Canary sequence

For the first live canary:

1. generate a normal Gardener remediation proposal offline;
2. review the proposal and its exact patch digest;
3. generate `github-app-pr-plan` from a clean checkout at the exact default-branch commit;
4. review the remote plan, file hashes, base SHA, deterministic branch, expiry, and permission declaration;
5. record the exact plan digest approved for the canary;
6. obtain one short-lived installation token through the approved broker;
7. run `github-app-pr --dry-run` and compare the summary with the reviewed plan;
8. run `github-app-pr --apply --approved-plan-digest <exact-reviewed-digest>` and complete the interactive confirmation;
9. confirm that exactly one `gardener/...` branch was created;
10. confirm that exactly the reviewed files changed;
11. confirm that one draft pull request was opened;
12. confirm that repository-owned pull-request checks started normally;
13. confirm that Gardener stopped without approving, merging, deploying, changing repository settings, or dispatching a workflow;
14. inspect GitHub audit evidence for the App installation and token use;
15. leave merge or closure of the draft PR as a separate human decision.

## Failure handling

If the canary fails after the remote branch is created:

- stop;
- do not automatically delete the branch;
- do not rewrite branch history;
- inspect the exact remote state and GitHub audit evidence;
- revoke or disable the installation if credential behaviour is uncertain;
- treat any exposed private key or installation token as compromised and rotate or revoke it;
- document the failure before another canary.

## Acceptance criteria

The provider rollout is proven only when the canary demonstrates all of the following:

- App access is limited to the intended repository installation;
- the App has only Metadata read, Contents write, and Pull requests write;
- a short-lived installation token was used;
- the reviewed base SHA was enforced;
- only the deterministic Gardener branch was created;
- only the reviewed files changed;
- the pull request was created as draft;
- native repository validation ran independently;
- Gardener performed no merge, approval, deployment, settings, secret, workflow-dispatch, or non-GitHub provider mutation.

Until those conditions are proven, the GitHub App adapter is source-complete but provider-inactive.
