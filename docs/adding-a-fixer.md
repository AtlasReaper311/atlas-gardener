# Add a fixer safely

1. Start from one Finding `rule_id` and one remediation type. Do not overload an
   existing ID with new behavior.
2. Prove the correct owner is `atlas-gardener`; application logic, dependency
   upgrades, generated lockfiles, provider configuration, and ambiguous
   metadata remain out of scope.
3. Add the rule-to-fixer mapping and one deterministic plan builder. Do not add
   shell execution, HTTP access, dynamic imports, `eval`, or executable content
   from a Finding.
4. Resolve every candidate through the repository path guard, reject escaping
   symlinks and binary edits, and return sorted `FileChange` records.
5. Keep one fixer per proposal and remain within the five-file and 200-line
   bounds. If a safe patch needs more, refuse and ask for a human-owned change.
6. Add happy-path, refusal, malicious-path, binary, deterministic, second-run,
   proposal-schema, and local-apply tests.
7. Document eligibility, failure modes, target-native validation, and rollback.
8. Run compile, unit, CLI, schema, determinism, idempotency, workflow-policy,
   and `git diff --check` validation before review.

Changing proposal identity fields, fingerprint rules, or the v1 schema requires
an `atlas-infra` compatibility review and is not a Gardener-only change.
