# GitHub App draft-PR adapter

Wave 3.7 adds the final controlled write seam to Atlas Gardener. It converts one reviewed `RemediationProposal` into a deterministic remote plan and can apply that exact plan with a short-lived GitHub App installation token.

The adapter stops after opening one draft pull request. It cannot approve, merge, deploy, dispatch workflows, alter repository settings, read secrets, or mutate Cloudflare, Home Assistant, Open WebUI, Ollama, or another provider.

## Source and provider states

The implementation has three separate states:

1. source complete and CI green;
2. GitHub App created and installed on one selected repository;
3. one bounded canary draft PR verified.

A merged source PR proves only the first state. It does not create or activate a GitHub App.

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
  --dry-run
```

The summary contains identities, hashes, risk, expiry, target classification fingerprint, permission requirements, and file paths. It omits file contents and credentials.

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
  --apply
```

Do not put the token in the command, repository, issue, pull request, chat, or shell history.

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

## Provider rollout remains separate

A later owner-approved provider rollout must create the GitHub App, limit installation to one canary repository, keep private-key custody outside Gardener, mint one short-lived installation token, and verify one draft PR against the provider rollout checklist.
