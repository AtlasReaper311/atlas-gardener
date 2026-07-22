# Verifying an autonomous Gardener canary

Use `scripts/verify_gardener_canary.py` after one bounded `automerge-low-risk` run has completed. The verifier reads structured GitHub API data and does not depend on combined Actions log text.

## Evidence checked

The verifier requires:

- the exact pull request number, Gardener head SHA, merge SHA, and target repository;
- a merged, one-commit Gardener App pull request changing only one `.gitignore` line;
- a successful pull-request-triggered gate run on the exact reviewed head;
- successful `gardener / Validate Gardener automatic merge` and `Gardener native auto-merge barrier` jobs;
- successful `Revalidate the automatic approval` and `Enable native squash auto-merge` steps;
- a skipped `Revoke workflow-owned auto-merge after refusal` step;
- the expected immutable Gardener and Atlas Infra pins in the target-owned caller;
- a merge commit authored by the approved Gardener App and limited to the same one-line `.gitignore` change;
- exactly one `.DS_Store` rule on target `main`;
- repository native auto-merge returned to `false`;
- every Gardener rollout variable returned to its disabled value.

Unrelated skipped jobs, including the Dependabot review policy on non-Dependabot pull requests, are ignored. GitHub's REST-style `<app>[bot]` and GraphQL-style `app/<app>` actor representations are normalised to the same App slug.

## Command

```bash
python3 scripts/verify_gardener_canary.py \
  --repository AtlasReaper311/atlas-dora \
  --pull-request 30 \
  --gate-run 29964113312 \
  --head-sha 2d24e6450f45869835c9694b940018bb5b54a48b \
  --merge-sha 542e1647698c07e1fcdc83d84b4b508298f071d1 \
  --app-login 'atlas-gardener-w37-atlasreaper[bot]' \
  --gardener-ref 8cc8455d40bcf4777be082dbd69434772e2bad96 \
  --authority-ref 6689de2c7ccd9264348c75bed99745021f88f191 \
  --output /tmp/gardener-canary-verification.json
```

The command requires an authenticated GitHub CLI session with read access to the three control repositories and the target repository. It performs no GitHub write, workflow dispatch, provider action, or secret read.

## Interpretation

A `verified` report proves that the reviewed target workflow armed GitHub native squash auto-merge, its independent barrier observed the armed request, GitHub merged the exact Gardener proposal, and the rollout returned to the disabled safety baseline.

It does not prove deployment, runtime health, notification delivery, or any non-GitHub provider state. Those remain separate evidence gates.
