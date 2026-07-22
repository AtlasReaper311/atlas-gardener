# GitHub App provider rollout checklist

This checklist is the provider-side gate for the Atlas Gardener GitHub App draft-PR adapter. Source completion does not create, install, configure, or activate a GitHub App.

## Preconditions

Before any provider action:

- PR source CI is green on the exact adapter revision;
- the adapter remains dry-run by default;
- the transport still uses an exact method-and-path allowlist;
- the adapter creates one commit and one draft pull request, then stops;
- workflow-file proposals remain refused in v1;
- the permission contract remains unchanged;
- the selected canary repository has normal pull-request validation;
- the canary proposal is low-risk, reversible, non-production, and does not touch credentials or workflows.

## App permission contract

Create the App with only:

```text
Metadata: read
Contents: write
Pull requests: write
```

Do not grant Administration, Actions, Checks, Deployments, Environments, Issues, Secrets, Variables, Members, Billing, organization administration, or account-wide installation.

Do not configure a webhook that automatically starts Gardener.

## Installation scope

Install the App on one explicitly selected canary repository only. Add no other repository until the canary evidence is reviewed.

Do not include deprecated, archived, or external-derived repositories. Unknown repositories remain ineligible.

## Private-key custody and token broker

The GitHub App private key must remain outside repository source, Gardener plans, issue text, pull requests, shell history, and chat.

The external broker must:

- authenticate as the approved App;
- mint a token for the intended installation only;
- keep token lifetime short;
- inject the token only through the approved ephemeral environment boundary;
- never persist or print it;
- stop minting tokens when the App or installation is disabled.

Gardener expects the ephemeral value in:

```text
ATLAS_GARDENER_INSTALLATION_TOKEN
```

## Canary sequence

1. Select a low-risk non-workflow Gardener proposal.
2. Confirm the repository is not deprecated, archived, or external-derived.
3. Generate the proposal from current source.
4. Review its exact patch digest, risk, validation, rollback, and expiry.
5. Generate `github-app-pr-plan` from a clean checkout on the exact default-branch commit.
6. Review the target classification fingerprint, base SHA, file modes, blob SHAs, file hashes, deterministic branch, permission declaration, and plan digest.
7. Obtain one short-lived installation token through the approved broker.
8. Run `github-app-pr --dry-run` and compare the summary with the reviewed plan.
9. Run `github-app-pr --apply` with the exact `--repo` and approved plan digest.
10. Complete the interactive confirmation.
11. Confirm the App created one deterministic branch.
12. Confirm the branch contains exactly one new commit.
13. Confirm the commit has the reviewed base SHA as its only parent.
14. Confirm exactly the reviewed files and modes changed.
15. Confirm one draft pull request opened.
16. Confirm the PR body contains the required evidence and no private data.
17. Confirm repository-owned checks started normally.
18. Confirm Gardener performed no approval, merge, deployment, workflow dispatch, settings change, secret action, branch deletion, or non-GitHub provider mutation.
19. Inspect GitHub audit evidence for the installation and token use.
20. Leave merge or closure of the canary PR as a separate human decision.

## Failure handling

If the canary fails:

- stop immediately;
- do not retry with wider permissions;
- do not automatically delete or rewrite a branch;
- inspect the exact GitHub state and audit evidence;
- disable the installation if credential behaviour is uncertain;
- revoke or rotate any exposed key or token;
- record the failure before another canary.

If failure occurs before branch creation, unreferenced Git blobs, trees, or commits may remain for GitHub garbage collection. Gardener does not perform cleanup writes.

## Acceptance criteria

Provider rollout is verified only when:

- the App is installed on the intended canary repository only;
- permissions are exactly Metadata read, Contents write, and Pull requests write;
- one short-lived installation token was used;
- target classification and exact base SHA were revalidated;
- one deterministic branch was created;
- the branch contains one exact reviewed commit;
- one draft pull request was opened;
- native PR validation ran independently;
- no merge, approval, deployment, workflow dispatch, settings, secret, branch-deletion, or non-GitHub provider operation occurred.

Until then, the adapter is source-complete but provider-inactive.
