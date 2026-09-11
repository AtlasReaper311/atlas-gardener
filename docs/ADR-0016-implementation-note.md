# ADR-0016 implementation note

This branch implements accepted Atlas Infra authority `9ac88f38c2fa370d566421f0909db85b25a309ea` without expanding provider permissions, target repository coverage, workflow-dispatch authority, or native automatic merge.

The implementation adds the review-required `npm-lock-security-remediation` fixer. The fixer accepts only the structured candidate defined by ADR-0016, binds one matching `package.json` / lockfile-v3 `package-lock.json` pair, requires npm `10.9.3`, validates every direct and transitive preimage, validates exact parent constraints for transitive targets, disables lifecycle scripts, independently regenerates the graph, compares producer target digests, and reruns a bounded OSV check before a ChangePlan can be published.

The existing `npm-security-update`, `python-security-pin`, and `container-digest-pin` fixers remain review-required. `macos-metadata-ignore` and `python-cache-ignore` remain the only automatic-merge classes.

A merged source implementation is not rollout evidence. Fresh Finding publication, controller execution, target PR creation, target merges, deployment, and live verification remain separate authority gates.
