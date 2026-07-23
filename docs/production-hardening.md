# Gardener production hardening

The autonomous canary and bounded `specular-sonify` rollout prove the GitHub control path. They do not by themselves authorize continuous production operation.

## Scheduled cadence

The public audit produces an attested Finding bundle on Monday at `08:41 UTC`. The controller reconciles that bundle on Monday at `10:15 UTC`. Manual dispatch remains available for an owner-approved exceptional run.

The controller no longer runs daily because the Finding bundle expires after thirty-six hours. A daily controller against a weekly producer would spend most of the week refusing stale evidence.

## Target readiness

Before enabling a repository, run `scripts/verify_gardener_target_readiness.py` against the committed `atlas-infra/policy/gardener-target-readiness.json` policy. The verifier is read-only and requires:

- the exact pinned Gardener gate and Atlas Infra authority;
- the approved Gardener App identity;
- both gate jobs scoped to `gardener/` branches;
- squash merge enabled;
- repository native auto-merge disabled at rest;
- `ATLAS_GARDENER_AUTOMERGE_ENABLED=false` at rest;
- the repository's declared CI check required on `main`;
- `Gardener native auto-merge barrier` required on `main`.

Example:

```bash
python3 scripts/verify_gardener_target_readiness.py \
  --policy ../atlas-infra/policy/gardener-target-readiness.json \
  --gardener-ref GARDENER_MERGED_SHA \
  --authority-ref AUTHORITY_MERGED_SHA \
  --repository AtlasReaper311/specular-sonify \
  --output /tmp/specular-sonify-readiness.json
```

The merged SHAs must be supplied explicitly. A source branch commit may be used for draft CI, but production rollout must pin the final merged commits.

## Completed rollout evidence

Use `scripts/verify_gardener_production_rollout.py` for completed automatic runs. It binds workflow jobs to the exact Actions `run_attempt`, reuses the exact patch and disabled-baseline checks, and requires one deployment classification:

- `automatic`: a successful push-triggered deployment run bound to the merge SHA is required;
- `manual`: deployment remains a separate provider boundary;
- `not-applicable`: the merge has no runtime deployment contract, such as a `.gitignore`-only change in a repository without push deployment.

Example for the completed `specular-sonify` proof:

```bash
python3 scripts/verify_gardener_production_rollout.py \
  --repository AtlasReaper311/specular-sonify \
  --pull-request 9 \
  --gate-run 29972390426 \
  --head-sha 2daa1b41a2aa832dba1e8260cc8febac32d8d3d9 \
  --merge-sha 33ebfca292c6a099f3face8b04f244942d19f2dc \
  --app-login 'atlas-gardener-w37-atlasreaper[bot]' \
  --gardener-ref 8cc8455d40bcf4777be082dbd69434772e2bad96 \
  --authority-ref 6689de2c7ccd9264348c75bed99745021f88f191 \
  --deployment-classification not-applicable \
  --output /tmp/specular-sonify-production-proof.json
```

These tools perform GitHub reads only. They do not change variables, branch protection, repository settings, workflow state, secrets, deployment state, or another provider.
