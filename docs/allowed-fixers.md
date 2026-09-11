# Allowed fixers

Every proposal has one fixer ID and version. A fixer either returns one bounded, deterministic plan or a clear refusal; it never partially proposes a change. Runtime file paths must also match the selected fixer's `allowed_path_patterns` in accepted Atlas Infra policy.

## `macos-metadata-ignore`

Adds `.DS_Store` to the root `.gitignore` when absent and proposes deletion of discovered `.DS_Store` files. A real dirty worktree is accepted only when every dirty path is exactly a `.DS_Store` file. Binary deletion is allowed only for this exact metadata name.

## `python-cache-ignore`

Adds `__pycache__/` and `*.py[cod]` to the root `.gitignore` when absent. Cache artifact deletion is locally applicable only in a marked fixture or with the explicit real-local-target flag and every other safety check.

## `workflow-timeout`

Accepts only a `.github/workflows/*.yml` or `.yaml` location. It finds a single simple top-level `jobs` block and inserts `timeout-minutes: 15` after one simple `runs-on` value in each job that lacks a timeout. Existing timeouts are preserved. Reusable-workflow jobs and complex/multiline runner declarations are refused because a line edit cannot prove their semantics.

## `workflow-permissions`

Adds only top-level read permissions. The workflow is refused if it already has top-level or job-level permissions, uses secrets, `pull_request_target`, arbitrary network commands, unknown remote actions, deployment, release, publishing, issue/PR writing, or environment mutation.

## `action-pin-plan`

Replaces mutable `owner/repository@tag` action references only when an explicit local map contains the exact reference and a 40-character lowercase Git commit SHA. The readable original tag is retained as a comment. Existing immutable SHAs and local actions are unchanged. If any required mapping is absent, the whole proposal is refused and network resolution remains deferred.

The map format is shown in `examples/action-pins.json`.

## `npm-security-update`

Consumes only a validated `dependency-update` remediation input with `ecosystem=npm`. The candidate must represent a direct dependency, a strict three-part current and target version, a strictly newer same-major target, and at least one vulnerability identifier. The source must be a `package.json` with a matching adjacent `package-lock.json`.

The current direct declaration must be unique and use the exact audited version, optionally with `^` or `~`. The fixer replaces it with the exact bounded target version and regenerates only `package-lock.json` with lifecycle scripts, audit, funding, and update-notifier behavior disabled. The subprocess receives a reduced environment without repository/provider credentials. The generated lockfile must resolve the direct package to the exact target or the proposal is refused.

The global five-file and 200-line plan limits still apply. Large lockfile churn therefore fails closed. This fixer is review-required and cannot automatically merge.

## `npm-lock-security-remediation`

Consumes only a validated ADR-0016 `npm-lock-security-remediation` candidate. It is limited to one matching `package.json` / lockfile-v3 `package-lock.json` pair and pinned npm `10.9.3`.

The candidate binds direct updates and/or transitive lock-graph updates, vulnerability identifiers, exact parent constraints for transitive nodes, and target SHA-256 digests for both manifest and lockfile. Gardener independently verifies every preimage and constraint, regenerates with the accepted npm pin and lifecycle scripts disabled, and requires the generated file digests to match the producer candidate exactly.

A bounded OSV check then verifies that every vulnerability identifier claimed by the candidate is absent from the regenerated lock graph. If npm output, target digests, parent constraints, package versions, OSV evidence, or the expected changed-file set disagrees with the candidate, the fixer refuses the proposal.

This fixer is review-required and cannot automatically merge.

## `python-security-pin`

Consumes only a validated `dependency-update` remediation input with `ecosystem=PyPI`. It is limited to a unique exact `==` declaration in `requirements.txt`. PEP 508 extras and trailing markers/comments are preserved while only the version token changes to the newer same-major target. Ambiguous declarations, range constraints, unsupported packaging files, major upgrades, and malformed versions are refused.

This fixer is review-required and cannot automatically merge.

## `container-digest-pin`

Consumes only a validated `container-digest-pin` remediation input. It is limited to one simple Dockerfile `FROM <reference>` preimage and replaces that reference with `<reference>@sha256:<digest>`. Named build stages, already digest-pinned references, ambiguous/multiple matches, malformed digests, and non-Dockerfile paths are refused.

Digest resolution belongs to `atlas-dep-audit`; Gardener receives and verifies the structured immutable digest rather than resolving provider state during proposal generation. This fixer is review-required and cannot automatically merge.

## Merge boundary

Only the existing `.gitignore` housekeeping class can satisfy `automatic_merge_eligible`. `npm-security-update`, `npm-lock-security-remediation`, `python-security-pin`, and `container-digest-pin` may be proposed in `pr-only` or `automerge-low-risk`, but their pull requests remain draft and require human review. `automerge-low-risk` does not expand their authority.
