# ADR-0015 implementation note

This branch implements accepted Atlas Infra authority `11e7a727590aa5376e766416b1e6a83fb6fd98ef` without expanding provider permissions, target write scope, or native automatic-merge authority.

The implementation adds structured candidate routing for direct npm and `requirements.txt` security remediation plus Dockerfile digest pinning. These fixers remain review-required and may only produce draft pull requests in write-enabled controller modes. Existing `.gitignore` housekeeping remains the only native automatic-merge class.

Candidate target versions and digests are bound into `RemediationProposal.remediation_input` so proposal regeneration does not re-resolve mutable external state. Every generated file must match the selected fixer's accepted `allowed_path_patterns` before target credentials can be used.

The source branch does not merge, dispatch workflows, change repository variables or secrets, publish a Finding bundle, or perform live remediation.
