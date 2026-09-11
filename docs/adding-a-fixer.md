# Add a fixer safely

1. Start from one Finding `rule_id` and one remediation type. Do not overload an existing ID with unrelated behavior.
2. Prove the correct owner is `atlas-gardener` and obtain accepted Atlas Infra authority before widening scope. ADR-0015 permits bounded direct dependency security updates and Docker Hub digest pinning. ADR-0016 additionally permits bounded npm lock-graph security remediation. Application logic, provider configuration, arbitrary package upgrades, major-version upgrades, unsupported packaging formats, and ambiguous metadata remain out of scope unless separately authorised.
3. Require structured remediation input whenever the change needs a dependency target, lock-graph operation, package-manager toolchain pin, vulnerability postcondition, or container digest. Finding text remains evidence and must never become shell syntax, a provider mutation, a ref name, or an unbounded command.
4. Add one deterministic plan builder. Resolve every candidate through the repository path guard, reject escaping symlinks and binary edits, and return sorted `FileChange` records.
5. Validate every planned path against the selected fixer's `allowed_path_patterns` from accepted Atlas Infra policy before any target token is minted or PR write is attempted.
6. For npm graph remediation, independently verify the exact manifest/lock preimage, direct-parent or transitive constraints, same-major targets, pinned npm version, regenerated target digests, and post-regeneration vulnerability absence. Any disagreement with the producer candidate fails closed.
7. Keep one fixer per proposal and remain within the five-file and 200-line plan bounds unless accepted Infra authority says otherwise. Refuse larger or ambiguous patches.
8. Dependency/container fixers are review-required. They may create draft PRs in `pr-only` or `automerge-low-risk` mode but cannot enter native automatic merge.
9. Add happy-path, refusal, malicious-path, deterministic regeneration, proposal-schema, path-authority, postcondition, and local-apply tests. External resolution should use an injectable seam so tests do not depend on live network state.
10. Run compile, unit, CLI, schema, determinism, idempotency, workflow-policy, CodeQL, and `git diff --check` validation before review.

Changing proposal identity fields, fingerprint rules, v1 contract shape, fixer path authority, package-manager execution authority, or automatic-merge authority requires an `atlas-infra` compatibility/authority change before Gardener source implementation.
