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

`atlas-gardener` is the Atlas Systems PR-only remediation planner and guarded rollout executor. It consumes schema-valid `Finding` records, emits deterministic `RemediationProposal` JSON, and keeps every write path behind a separate reviewed plan and explicit confirmation.

Two controlled write seams exist:

- an owner-run Dependabot rollout that creates bounded review branches and draft PRs from an approved estate plan;
- a Wave 3.7 GitHub App adapter that can create one exact commit and one draft PR from one reviewed remediation proposal.

`atlas-infra` remains the contract and public policy authority. `atlas-dep-audit` remains a finding producer and contract-assurance consumer. Repository owners retain merge and deployment authority.

## Safety posture

Dry-run is always the default. Local proposal application accepts disposable repositories containing `.atlas-gardener-fixture` or a real local repository explicitly passed with `--allow-local-target`. A real target must be clean, classified, and on a named branch other than `main`.

Repository eligibility is classification-driven. Gardener resolves a private real target from its source-owned `.atlas/governance.json`. It resolves a public runtime target from the authoritative sibling `atlas-infra/policy/estate-registry.json` or from `ATLAS_GARDENER_INFRA_ROOT` when that root is explicitly supplied. Unknown real targets fail closed. Gardener does not carry a public list of private repository identities.

The engine hard-codes these boundaries:

- no direct `main` edits, merge, deploy, secret, billing, branch-protection, GitHub environment, or Cloudflare change;
- no arbitrary shell or HTTP capability and no command execution from a finding or proposal;
- the GitHub App apply seam can call only its exact GitHub REST method-and-path allowlist;
- no dependency or lockfile fixer;
- no deprecated, archived, or external-derived repository remediation;
- one fixer type, at most five files, and at most 200 changed lines per proposal;
- repository-relative UTF-8 text edits only, with traversal, escaping symlink, binary, dirty-worktree, stale-preimage, and digest refusals;
- the only binary deletions are exact `.DS_Store` and Python cache artifacts in an allowlisted local fixer;
- action pins come only from an explicitly supplied local mapping.

The Dependabot rollout adds an immutable approved plan digest, classification validation at execution time, a clean and current default branch, live default-branch drift checks, bounded files, fixed action replacements, one `y/N` prompt per repository, and draft pull requests only. It cannot merge, deploy, modify settings, or bypass branch protection.

The GitHub App adapter adds an exact target classification fingerprint, exact base commit and blob identities, a second remote base check, a bounded Git Data API transport, one commit, one deterministic branch, and one draft PR. It refuses workflow files in v1 rather than widening App permissions silently.

See [the threat model](docs/threat-model.md), the [GitHub App adapter](docs/github-app-pr-adapter.md), and the [refusal and rollback runbook](docs/runbooks/refusal-and-rollback.md).

## Requirements and local installation

- Python 3.11 or newer
- Git for branch and worktree checks
- a local `atlas-infra/contracts/v1` checkout

There are no runtime dependencies. Install without resolving anything from the network:

```bash
python3 -m pip install --no-deps --no-build-isolation -e .
```

For source-tree development, use `PYTHONPATH=src` as shown below.

## Classification inputs

Gardener never decides that an unknown repository is safe to modify.

For a source-owned private repository, the local target must contain a valid `.atlas/governance.json` whose repository identity matches the target, `visibility` is `private`, `estate_membership` is `internal`, and `public_projection` is `false`. Lifecycle and provenance then feed the normal remediation safety checks.

For an approved public runtime, Gardener reads the public registry from a local `atlas-infra` checkout. The default discovery path is a sibling checkout. Set `ATLAS_GARDENER_INFRA_ROOT` only when the authoritative checkout lives elsewhere.

A public non-runtime repository without an authoritative classification source is refused rather than assigned an inferred lifecycle or provenance.

## Proposal CLI

The contract path is discovered from `ATLAS_GARDENER_CONTRACTS`, an explicit `--contracts-root`, or a sibling `atlas-infra/contracts/v1` checkout.

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

`apply` without either mode flag is dry-run. Actual fixture mutation requires `apply --apply`. A real local target additionally requires `--allow-local-target`; this flag does not bypass classification, cleanliness, branch, path, digest, file-count, or line-count checks.

## Dependabot rollout CLI

Preview the approved estate change from the directory containing the local repository clones:

```bash
PYTHONPATH=src python3 -m atlas_gardener dependabot-rollout \
  --plan /tmp/dependabot-rollout-plan/rollout-plan.json \
  --plan-root /tmp/dependabot-rollout-plan \
  --estate-root /Users/atlasreaper/Personal \
  --dry-run
```

Apply requires a fine-grained token in `ATLAS_DEPENDABOT_WRITE_TOKEN`, scoped to the exact eligible repositories with `Contents: write`, `Pull requests: write`, and `Workflows: write`. Workflow write is required only because the reviewed rollout can create `.github/workflows/dependabot-automerge.yml`. The token is used only by child processes and is not stored in Git configuration.

## GitHub App draft-PR CLI

Build the exact remote plan offline:

```bash
PYTHONPATH=src python3 -m atlas_gardener github-app-pr-plan \
  --proposal /tmp/proposal.json \
  --repo /Users/atlasreaper/Personal/example-repository \
  --output /tmp/github-app-pr-plan.json \
  --contracts-root ../atlas-infra/contracts/v1
```

Review it without network access:

```bash
PYTHONPATH=src python3 -m atlas_gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --dry-run
```

Provider apply requires the exact target checkout, approved digest, interactive confirmation, and a short-lived installation token injected through `ATLAS_GARDENER_INSTALLATION_TOKEN`:

```bash
PYTHONPATH=src python3 -m atlas_gardener github-app-pr \
  --plan /tmp/github-app-pr-plan.json \
  --repo /Users/atlasreaper/Personal/example-repository \
  --approved-plan-digest sha256:<reviewed-digest> \
  --apply
```

Do not paste the token into the command, source, chat, issue text, or pull request. App creation, installation, private-key custody, token minting, and the first canary remain separate owner-approved provider steps.

## Finding ingestion and output

A finding file or every `*.json` file below a supplied directory is loaded as UTF-8 JSON, validated against `finding.schema.json`, and checked against the canonical `fingerprint-rules.json`. Any invalid file fails the entire ingestion before output is written. Valid findings are deduplicated by fingerprint and sorted by fingerprint.

Every proposal conforms to `remediation-proposal.schema.json`, including canonical `proposal_id`, affected files, risk, fixer identity/version, inert validation commands, rollback, and expiry. The v1 contract has no `evidence_summary` property and rejects unknown fields. `propose` writes the redacted summary beside the proposal as `<output-stem>.evidence.json`; `scan` places the same bounded records in `evidence_summaries`.

## Allowlisted fixers

- `macos-metadata-ignore`
- `python-cache-ignore`
- `workflow-timeout`
- `workflow-permissions`
- `action-pin-plan`

Their exact eligibility and refusal behaviour are documented in [allowed fixers](docs/allowed-fixers.md). New fixers must follow the [safe extension procedure](docs/adding-a-fixer.md).

The GitHub App v1 adapter refuses any proposal whose affected path is below `.github/workflows/`. Those fixers remain usable for offline proposal review and the separately approved owner-run rollout, but not through the current App permission boundary.

## Validation

```bash
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m atlas_gardener doctor \
  --contracts-root ../atlas-infra/contracts/v1
git diff --check
```

CI uses only pinned GitHub-owned actions, checks out the authoritative `atlas-infra` contracts, and runs the same standard-library checks. It uploads no artifact.

## Current boundaries

The general proposal flow does not schedule estate scans, integrate with `atlas-notify`, discover action pins, parse arbitrary YAML, or execute target validation commands. Validation commands remain inert evidence for repository-owned PR checks.

The Dependabot rollout is a narrow owner-executed exception. The GitHub App adapter is a separately bounded source seam whose provider activation is not implied by merge. Its exact current and future permission model is documented in [GitHub pull-request model](docs/future-github-pr-model.md).

## Ownership and licence

Owner: Atlas Reaper / `AtlasReaper311`. The code is MIT licensed. See [ownership](docs/ownership.md) for component and contract responsibilities.

## How it fits into Atlas Systems

`atlas-gardener` is the bounded remediation proposal layer. It can turn validated findings into reviewable changes while `atlas-infra` remains the policy authority and repository owners retain merge and deployment authority.

The transferable principle is to separate detection, proposal, approval, repository mutation, validation, merge, and production rollout so automation cannot silently acquire more authority than its evidence warrants.

---

Part of [atlas-systems.uk](https://atlas-systems.uk) · MIT License
