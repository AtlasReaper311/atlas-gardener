# Threat model

## Assets and trust boundaries

The protected assets are target repository contents, default branches, workflow permissions, provider configuration, credentials, and the integrity of remediation evidence. Findings, Finding bundles, attestations, evidence summaries, workflow files, repository paths, source-owned governance, public registry data, proposals, plans, pull-request bodies, and status checks are untrusted until validated.

`atlas-infra/contracts/v1` and `policy/gardener-automation.json` are the schema, identity, classification, risk, mode, and path authorities. Public runtime classification comes only from the checked-out immutable Atlas Infra registry and verified GitHub App coverage policy. Private repositories remain source-owned and are excluded from the public automatic controller.

The manual remediation path remains interactive and receives an externally minted installation token. The automatic controller has a separate trust chain: an attested public-only bundle from the exact Atlas Dep Audit workflow, an immutable Atlas Infra authority checkout, a policy-bound AutomationApproval, one repository-restricted App token, one deterministic pull request, and a target-owned merge gate. Cloudflare, package registries, arbitrary URLs, production deployments, repository settings, and non-GitHub providers remain outside the controller boundary.

## Threats and controls

| Threat | Control |
|---|---|
| Malformed or spoofed Finding | Closed-schema validation, unknown-field rejection, canonical fingerprint recomputation, and sorted fingerprint uniqueness |
| Forged cross-repository handoff | GitHub artifact attestation verification plus exact producer repository, workflow, run, commit, authority commit, policy digest, bundle digest, age, and expiry checks |
| Private repository disclosure | Public-only bundle contract; private findings remain in the authenticated source repository and are not listed in public policy or evidence |
| Finding command injection | Findings are data only; no Finding or proposal string becomes a command, URL, ref, environment-variable name, or shell fragment |
| Duplicate or replayed remediation | Remediation key binds repository, rule, Finding fingerprint, fixer version, and base SHA; existing open and merged PRs are detected before mutation |
| Stale target or base drift | Bundle snapshot, local checkout, proposal preimage, plan base SHA, remote base ref, approval base SHA, and target gate base ref must all agree |
| Policy or classification drift | Policy, coverage, classification, proposal, plan, patch, and approval digests are independently bound and rechecked |
| Branch collision or owner-branch overwrite | Dedicated deterministic `gardener/` namespace, branch non-existence check, no force-push, and refusal of unexplained branches |
| Unexpected pull-request commits | Approval binds the exact prepared commit; the target gate requires one commit and the exact current head SHA |
| Dangerous file expansion | Automatic merge is limited to one normal `.gitignore` file, at most two allowlisted added lines, with no deletion, binary, symlink, generated output, workflow, source, dependency, lockfile, deployment, infrastructure, or credential path |
| Missing or failed CI treated as success | Target caller supplies a sorted non-empty required-check list; every check must be present and successful; pending, failed, skipped, cancelled, stale, timed-out, and unknown states refuse |
| Central credential gains merge authority | Gardener App transport has no merge, approval, workflow, settings, branch-deletion, or provider endpoint; native auto-merge is enabled only by the target repository workflow token |
| Overbroad App token | Each installation token is restricted to one named repository and the exact Metadata read, Contents write, and Pull requests write permission set |
| Credential persistence or leakage | App private key exists only in an Actions secret and a mode-0600 temporary file; JWTs and installation tokens are never written to evidence, logs, PRs, issues, or chat; tokens are explicitly revoked |
| Scheduled write activation by source merge | Committed default is `disabled`; write modes also require `ATLAS_GARDENER_WRITE_GATE=enabled`; missing and unknown values fail closed |
| Concurrent duplicate mutation | One controller concurrency group and deterministic per-PR target-gate concurrency prevent overlapping operations |
| Notification storm | One consolidated controller outcome is emitted per run; bounded evidence records internal steps without one notification per step |
| Path traversal or symlink escape | Absolute paths, `..`, unsafe refs, escaping symlinks, unsupported modes, binary output, and non-UTF-8 output are refused |
| Unapproved or retired repository | Only active or production, original, verified public-coverage repositories are eligible; archived, deprecated, experimental, external-derived, malformed, unknown, and out-of-coverage targets fail closed |

## Explicit non-goals

Gardener does not edit arbitrary files from AI-generated instructions, upgrade dependencies, regenerate lockfiles, deploy applications, alter branch protection, change repository settings, approve pull requests, dispatch workflows, read repository secrets, mutate Cloudflare, or operate on the private estate through the public controller.

Workflow timeout, workflow permission, and action pin proposals remain review-only. The first automatic merge policy covers only approved `.gitignore` housekeeping additions. Source merging does not constitute live rollout.

## Residual risks

The existing App permission `pull_requests: write` can technically authorize merge-related GitHub API operations even though Gardener's transports refuse those endpoints. The code allowlist, target-owned merge design, repository-restricted tokens, immutable workflow pins, independent write gate, evidence, and selected-repository installation therefore remain security controls rather than conveniences.

A compromised controller workflow could create commits and pull requests in selected repositories within the App's existing permissions. Attested inputs, exact authority pins, one-operation tokens, no force-push, base rechecks, target-required CI, and native branch protection reduce that impact but do not eliminate it.

The target gate depends on correctly configured required-check names and GitHub native auto-merge settings. Missing names fail closed. Repository setting changes, target caller installation, secret setup, mode transitions, and canary rollout require separate owner approval.
