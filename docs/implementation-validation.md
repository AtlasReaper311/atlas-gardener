# Expanded Gardener validation

Repository-native validation for the ADR-0015 implementation is the existing pull-request CI bound to accepted Atlas Infra authority `11e7a727590aa5376e766416b1e6a83fb6fd98ef`.

The branch must pass immutable-authority validators, Python compilation, repository-isolated tests, automation policy and bundle tests, write-target tests, automatic-merge refusal/success tests, controller tests, CLI doctor, shell syntax validation, and `git diff --check` before merge review.

The scheduled controller additionally compiles and executes the expanded automation, remediation-input, and security-fixer tests before processing a live bundle. A green source run does not imply a live Gardener remediation occurred.
