# GitHub App draft-PR adapter

Wave 3.7 adds the final controlled write seam to Atlas Gardener. It converts one reviewed `RemediationProposal` into a deterministic remote plan and can apply that exact plan with a short-lived GitHub App installation token.

The adapter stops after opening one draft pull request. It cannot approve, merge, deploy, dispatch workflows, alter repository settings, read secrets, or mutate Cloudflare, Home Assistant, Open WebUI, Ollama, or another provider.

## Source and provider states

The implementation has four separate states:

1. source complete and CI green;
2. GitHub App created and installed on selected repositories;
3. one bounded canary draft PR verified;
4. additional repository coverage explicitly approved and added.

A merged source PR proves only the first state. It does not create or activate a GitHub App. The initial `atlas-dora` canary verified the third state; wider installation coverage remains a separate selected-repository rollout.

## Build the exact plan

Generate the remote plan from a clean checkout on the exact target base commit:

```bash
atlas-gardener github-app-pr-plan \
  --proposal /tmp/proposal.json \
  --repo ~/Personal/example-repository \
  --output /tmp/github-app-pr-plan.json
```

The planner:

- validates the authoritative proposal contract;
- regenerates the deterministic fixer;
- requires the same file list and patch digest;
- rechecks lifecycle, scope, and provenance;
- rejects deprecated, archived, and external-derived targets;
- records the target classification fingerprint;
- requires a clean checkout on the named base branch;
- records the exact base commit, file modes, base blob SHAs, and preimage/postimage digests;
- rejects binary, symlink, secret-bearing, credential-like, and path-escaping output;
- rejects `.github/workflows/**` in v1;
- computes one canonical plan digest.

Unknown classification fails closed. Private repositories use source-owned `.atlas/governance.json`; public runtime repositories use the local authoritative Atlas Infra registry.

## Review without network access

```bash
atlas-gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --result-output /tmp/github-app-pr-summary.json \
  --dry-run
```

The summary contains identities, hashes, risk, expiry, target classification fingerprint, permission requirements, and file paths. It omits file contents and credentials. `--result-output` writes one pure JSON document for `jq` and other machine consumers; human-readable prompts are not mixed into that receipt.

## Apply gate

Application requires:

1. the exact reviewed plan;
2. the exact approved plan digest;
3. the clean target checkout through `--repo`;
4. target classification still matching the reviewed fingerprint;
5. local and remote base branches still pointing at the reviewed commit;
6. the deterministic Gardener branch not existing;
7. interactive confirmation;
8. a short-lived token in `ATLAS_GARDENER_INSTALLATION_TOKEN`.

```bash
atlas-gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --repo ~/Personal/example-repository \
  --approved-plan-digest sha256:<reviewed-digest> \
  --result-output /tmp/github-app-pr-result.json \
  --apply
```

Do not put the token in the command, repository, issue, pull request, chat, or shell history.

## Installation token compatibility

Installation tokens are treated as opaque bearer strings. Gardener does not impose a maximum or exact token length, decode a token payload, depend on a fixed dot count during normal operation, or persist the token. This supports both classic opaque `ghs_` values and GitHub's longer stateless `ghs_` JWT-format values.

Before expanding an App installation, verify both formats against one already-approved repository:

```bash
bash scripts/check-github-app-token-formats.sh \
  AtlasReaper311/atlas-dora
```

The compatibility probe:

- forces one stateless token with GitHub's temporary per-request override;
- forces one classic token with the corresponding temporary override;
- restricts each token to the named repository and the exact Gardener permissions;
- authenticates one read-only repository request with each token;
- prints only token length and format classification, never the token;
- revokes each token immediately;
- leaves routine token minting without the temporary override header.

The override header is a migration test mechanism, not a permanent production dependency.

## Permission contract

The v1 adapter accepts only:

```text
Metadata: read
Contents: write
Pull requests: write
```

It does not request Actions, Checks, Administration, Environments, Deployments, Issues, Secrets, Variables, Members, Billing, or organization administration.

Workflow-file proposals are refused in v1. Supporting them later requires a separate reviewed contract and a separately enabled GitHub App permission boundary. The current adapter never silently widens its permission set.

## Exact remote sequence

After all checks pass, the bounded GitHub REST transport can perform only:

1. read the exact base ref;
2. prove the deterministic branch does not exist;
3. read the exact base commit tree;
4. create reviewed file blobs;
5. create one tree from the exact base tree;
6. create one commit with the reviewed base commit as its only parent;
7. recheck the remote base ref;
8. create the deterministic branch at that one commit;
9. open one draft pull request;
10. stop.

The transport has an explicit method-and-path allowlist, a 30-second request timeout, and a one-megabyte response limit. It has no Contents API loop, merge endpoint, review endpoint, workflow-dispatch endpoint, settings endpoint, branch-deletion endpoint, or provider endpoint.

Creating blobs, a tree, and a commit before the branch avoids a partially modified remote branch. If the base moves during preparation, Gardener refuses before creating the branch or pull request. Unreferenced Git objects may remain for normal GitHub garbage collection; Gardener does not perform cleanup writes.

## Draft PR evidence

The generated pull request body records:

- finding fingerprint;
- fixer ID and version;
- proposal ID;
- plan digest;
- patch digest;
- risk class;
- expiry;
- exact files and modes;
- repository-owned validation mapping;
- rollback instructions;
- an explicit statement that no approval, merge, deployment, workflow dispatch, settings change, secret action, or non-GitHub provider mutation occurred.

## Provider coverage remains separate

The verified `atlas-dora` canary proves the bounded write path. Adding more repositories to the App installation must still use GitHub's selected-repository mode, derive eligibility from current authoritative classification, preserve the exact permission contract, and leave each proposed change behind the same plan review and confirmation gates.
