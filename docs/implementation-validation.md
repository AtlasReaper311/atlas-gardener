# Expanded Gardener validation

Repository-native validation for the ADR-0016 implementation is the existing pull-request CI bound to accepted Atlas Infra authority `9ac88f38c2fa370d566421f0909db85b25a309ea`.

The branch must pass immutable-authority validators, Python compilation, repository-isolated tests, automation policy and bundle tests, ADR-0016 npm graph fixer tests, write-target tests, automatic-merge refusal/success tests, controller tests, CLI doctor, shell syntax validation, and `git diff --check` before merge review.

The scheduled controller additionally compiles and executes the expanded automation, remediation-input, npm graph, and security-fixer tests before processing a live bundle. A green source run does not imply a live Gardener remediation occurred.

The npm graph fixer must independently reproduce the exact producer-bound manifest/lock digests with npm `10.9.3`, lifecycle scripts disabled, exact parent constraints, fixer-specific path authority, and a bounded OSV post-regeneration check. Any disagreement fails closed. The fixer remains review-required and draft-PR-only; ADR-0016 does not expand native automatic merge.
