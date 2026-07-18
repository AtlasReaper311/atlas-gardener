# Threat model

## Assets and trust boundaries

The protected assets are target repository contents, default branches,
workflow permissions, provider configuration, credentials, and the integrity
of review evidence. Findings, evidence summaries, workflow files, local pins
files, repository paths, and proposal JSON are untrusted inputs.

`atlas-infra/contracts/v1` is the schema and identity authority. The general
remediation engine remains local. The separately approved Dependabot rollout
may contact only GitHub through fixed Git and `gh` invocations after validating
the reviewed plan. Cloudflare, package registries, arbitrary URLs, and
production environments remain outside the boundary.

## Threats and controls

| Threat | Control |
|---|---|
| Malformed or spoofed Finding | Closed-schema validation plus canonical fingerprint recomputation; one invalid input aborts ingestion |
| Duplicate or order-dependent output | Fingerprint deduplication, canonical JSON, sorted paths, stable expiry derived from `detected_at` |
| Command injection | Findings and proposals are never passed to a shell; only fixed Git argument arrays are executed for local safety inspection |
| SSRF or unbounded network access | No HTTP client or generic URL operation exists; action resolution is local-map-only |
| Path traversal | Absolute paths and `..` components are refused; resolved paths must remain below the target root |
| Symlink escape | Existing and missing-path resolution checks the resolved common root; directory walking does not follow symlinked directories |
| Binary or encoding ambiguity | Modified files must be UTF-8 text; only exact metadata/cache artifact deletion has a narrow binary exception |
| Dirty or stale target | Real worktrees must be clean except exact `.DS_Store` metadata; apply rechecks every preimage and patch digest |
| Direct default-branch change | Actual local apply refuses `main` and detached real worktrees |
| Scope or supply-chain expansion | Five fixed fixer IDs, five-file and 200-line limits, no dependency or lockfile fixer |
| Dangerous workflow permission reduction | Permissions fixer refuses deploy, release, publishing, issue/PR writing, environment mutation, secrets, network commands, unknown actions, and privileged PR triggers |
| Mutable action substitution | Pins require an explicit local v1 map and a full lowercase 40-character commit SHA; absent mappings refuse |
| Upstream or retired code mutation | Deprecated, archived, external-derived, unknown real repositories, and all `simple-proxy` Findings are refused |
| Proposal replay against drift | Proposal expiry, files list, regenerated change plan, patch digest, and current preimages are revalidated |
| Estate rollout drift | Apply compares every local HEAD with the live default branch before any write and refuses the entire run on a mismatch |
| Broad rollout approval | There is no confirm-all option; every repository requires a separate `y` confirmation |
| Credential persistence | A purpose-specific fine-grained PAT is supplied by environment and passed only to child processes; Git configuration is not changed |

## Explicit non-goals

The project has no secret API, provider token, merge path, deployment path,
provider configuration API, branch protection API, package upgrade, lockfile
generator, arbitrary YAML parser, arbitrary command runner, or arbitrary HTTP
client. The rollout PR writer is limited to reviewed Dependabot files and exact
GitHub Action pin replacements.

## Residual risks

The workflow fixers intentionally support a conservative line-oriented YAML
subset. Valid but complex YAML may be refused. A human must inspect every
proposal, run target-native validation, and decide whether to commit it. The
evidence sidecar is locally defined because the v1 RemediationProposal schema
does not contain an evidence-summary field.
