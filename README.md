<div align="center">
  <img src="https://raw.githubusercontent.com/AtlasReaper311/AtlasReaper311/main/atlas-icon-dark-256.png" width="88" alt="Atlas Systems"/>
</div>

# atlas-gardener

```
┌─────────────────────────────────────────────┐
│  ATLAS SYSTEMS // atlas-gardener            │
│  bounded remediation proposals              │
└─────────────────────────────────────────────┘
```

[![CI](https://github.com/AtlasReaper311/atlas-gardener/actions/workflows/ci.yml/badge.svg)](https://github.com/AtlasReaper311/atlas-gardener/actions)
![Python](https://img.shields.io/badge/python-3.12-f5a623?style=flat-square&labelColor=0a0a0f)
![Safety](https://img.shields.io/badge/write%20boundary-PR%20only-4ade80?style=flat-square&labelColor=0a0a0f)
![Cost](https://img.shields.io/badge/cost-%C2%A30-aaa9a0?style=flat-square&labelColor=0a0a0f)

`atlas-gardener` is the Atlas Systems PR-only remediation planner and guarded
local rollout executor. Its original flow consumes schema-valid Phase 1
`Finding` records and emits deterministic `RemediationProposal` JSON. The
separate Dependabot rollout command consumes an owner-reviewed, digest-bound
plan and can create one branch and draft pull request per confirmed repository.

The repository is the correct ownership boundary because future pull-request
write access crosses repository trust boundaries. `atlas-infra` remains the
contract and public policy authority, and `atlas-dep-audit` remains a Finding
producer and contract-assurance consumer.

## Safety posture

Dry-run is always the default. The only local write path is `apply --apply`, and
it accepts disposable repositories containing `.atlas-gardener-fixture` or a
real local repository explicitly passed with `--allow-local-target`. A real
target must be clean, classified, and on a named branch other than `main`.

Repository eligibility is classification-driven. Gardener resolves a private
real target from its source-owned `.atlas/governance.json`. It resolves a public
runtime target from the authoritative sibling `atlas-infra/policy/estate-registry.json`
or from `ATLAS_GARDENER_INFRA_ROOT` when that root is explicitly supplied.
Unknown real targets fail closed. Gardener does not carry a public list of
private repository identities.

The engine hard-codes these boundaries:

- no direct `main` edits, merge, deploy, secret, billing, branch-protection,
  GitHub environment, or Cloudflare change;
- no arbitrary shell or HTTP capability and no command execution from a
  Finding or proposal;
- no dependency or lockfile fixer;
- no deprecated, archived, or external-derived repository remediation;
- one fixer type, at most five files, and at most 200 changed lines per
  proposal;
- repository-relative UTF-8 text edits only, with traversal, escaping symlink,
  binary, dirty-worktree, stale-preimage, and digest refusals;
- the only binary deletions are exact `.DS_Store` and Python cache artifacts in
  an allowlisted fixer; their contents are never interpreted;
- action pins come only from an explicitly supplied local mapping. The program
  never resolves action SHAs from the network.

The Dependabot rollout phase adds stricter controls: an immutable approved plan
digest, classification validation at execution time, a clean and current
default branch, live default-branch drift checks, bounded files, fixed action
replacements, one `y/N` prompt per repository, and draft pull requests only. It
cannot merge, deploy, modify settings, or bypass branch protection. The public
supply-chain audit repository remains an explicit rollout exclusion because it
owns the dependency-assurance mechanism being changed.

See [the threat model](docs/threat-model.md) and the
[refusal and rollback runbook](docs/runbooks/refusal-and-rollback.md).

## Requirements and local installation

- Python 3.11 or newer
- Git for read-only branch and worktree checks
- a local `atlas-infra/contracts/v1` checkout

There are no runtime dependencies. Install without resolving anything from the
network:

```bash
python3 -m pip install --no-deps --no-build-isolation -e .
```

For source-tree development, use `PYTHONPATH=src` as shown below.

## Classification inputs

Gardener never decides that an unknown repository is safe to modify.

For a source-owned private repository, the local target must contain a valid
`.atlas/governance.json` whose repository identity matches the target,
`visibility` is `private`, `estate_membership` is `internal`, and
`public_projection` is `false`. Lifecycle and provenance then feed the normal
remediation safety checks.

For an approved public runtime, Gardener reads the public registry from a local
`atlas-infra` checkout. The default discovery path is a sibling checkout. Set
`ATLAS_GARDENER_INFRA_ROOT` only when the authoritative checkout lives elsewhere.

A public non-runtime repository without an authoritative classification source
is currently refused rather than assigned an inferred lifecycle or provenance.
That limitation is deliberate.

## CLI

The contract path is discovered from `ATLAS_GARDENER_CONTRACTS`, an explicit
`--contracts-root`, or a sibling `atlas-infra/contracts/v1` checkout.

```bash
PYTHONPATH=src python3 -m atlas_gardener scan \
  --findings examples/finding.workflow-timeout.json \
  --estate-root /path/to/disposable/estate \
  --output scan-report.json \
  --contracts-root ../atlas-infra/contracts/v1

PYTHONPATH=src python3 -m atlas_gardener propose \
  --finding examples/finding.workflow-timeout.json \
  --repo /path/to/disposable/estate/example-repository \
  --output proposal.json \
  --contracts-root ../atlas-infra/contracts/v1

PYTHONPATH=src python3 -m atlas_gardener apply \
  --proposal proposal.json \
  --repo /path/to/disposable/estate/example-repository \
  --dry-run \
  --contracts-root ../atlas-infra/contracts/v1

PYTHONPATH=src python3 -m atlas_gardener doctor \
  --contracts-root ../atlas-infra/contracts/v1
PYTHONPATH=src python3 -m atlas_gardener version
```

After generating and reviewing the plan in `atlas-infra`, preview the complete
estate change from the directory containing the local repository clones:

```bash
PYTHONPATH=src python3 -m atlas_gardener dependabot-rollout \
  --plan /tmp/dependabot-rollout-plan/rollout-plan.json \
  --plan-root /tmp/dependabot-rollout-plan \
  --estate-root /Users/atlasreaper/Personal \
  --dry-run
```

Apply requires a fine-grained token in `ATLAS_DEPENDABOT_WRITE_TOKEN`, scoped
to the exact eligible repositories with `Contents: write`, `Pull requests:
write`, and `Workflows: write`. Workflow write is required only because the
reviewed rollout can create `.github/workflows/dependabot-automerge.yml`. The
token is used only by child processes and is not stored in Git configuration.

`apply` without either mode flag is still dry-run. Actual fixture mutation
requires `apply --apply`. A real local target additionally requires
`--allow-local-target`; this flag does not bypass classification, cleanliness,
branch, path, digest, file-count, or line-count checks.

## Finding ingestion and output

A Finding file or every `*.json` file below a supplied directory is loaded as
UTF-8 JSON, validated against `finding.schema.json`, and checked against the
canonical `fingerprint-rules.json`. Any invalid file fails the entire ingestion
before output is written. Valid Findings are deduplicated by fingerprint and
sorted by fingerprint.

Every individual proposal conforms to
`remediation-proposal.schema.json`, including canonical `proposal_id`, affected
files, risk, fixer identity/version, inert validation commands, rollback, and
expiry. The v1 contract has no `evidence_summary` property and rejects unknown
fields. To preserve conformance, `propose` writes the redacted summary beside
the proposal as `<output-stem>.evidence.json`; `scan` places the same bounded
records in `evidence_summaries`. This is an explicit local evidence sidecar, not
a replacement contract.

## Allowlisted fixers

- `macos-metadata-ignore`
- `python-cache-ignore`
- `workflow-timeout`
- `workflow-permissions`
- `action-pin-plan`

Their exact eligibility and conservative refusal behavior are documented in
[allowed fixers](docs/allowed-fixers.md). New fixers must follow the
[safe extension procedure](docs/adding-a-fixer.md).

## Validation

```bash
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m atlas_gardener doctor \
  --contracts-root ../atlas-infra/contracts/v1
git diff --check
```

CI uses only pinned GitHub-owned actions, checks out the authoritative
`atlas-infra` contracts, and runs the same standard-library checks. It uploads
no artifact and therefore needs no artifact-retention setting.

## Current boundaries

The general remediation flow does not create branches or pull requests,
schedule estate scans, integrate with `atlas-notify`, discover action pins,
parse arbitrary YAML, or run target repository validation commands. The
Dependabot rollout is a narrow, owner-executed exception with fixed inputs and
outputs. The future unattended GitHub model is documented in
[future GitHub PR model](docs/future-github-pr-model.md).

## Ownership and licence

Owner: Atlas Reaper / `AtlasReaper311`. The code is MIT licensed. See
[ownership](docs/ownership.md) for component and contract responsibilities.

## How it fits into Atlas Systems

`atlas-gardener` is the bounded remediation proposal layer. It can turn validated findings into reviewable changes while `atlas-infra` remains the policy authority and repository owners retain merge and deployment authority.

The transferable principle is to separate detection, proposal, approval, and production mutation so automation cannot silently acquire more authority than its evidence warrants.

---

Part of [atlas-systems.uk](https://atlas-systems.uk) · MIT License
