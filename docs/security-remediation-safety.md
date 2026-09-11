# Security remediation safety invariants

Accepted ADR-0015 introduced three review-required fixer IDs: `npm-security-update`, `python-security-pin`, and `container-digest-pin`. Accepted ADR-0016 adds the review-required `npm-lock-security-remediation` graph fixer without changing automatic-merge authority.

- Every structured candidate is contract-validated and then independently revalidated by the selected fixer.
- Direct dependency targets remain strict, newer, same-major versions and identify the vulnerabilities they address.
- ADR-0016 npm graph candidates bind one `package.json` / `package-lock.json` pair, the exact npm toolchain version, direct and/or transitive operations, vulnerability identifiers, parent constraints, and target manifest/lock SHA-256 digests.
- npm graph regeneration uses pinned npm `10.9.3`, package-lock-only mode, disabled lifecycle scripts, disabled audit/funding/update-notifier behavior, and a reduced subprocess environment without repository/provider credentials.
- Direct graph operations must match the declared manifest section/specifier and exact lockfile preimage. Transitive operations must match the exact lockfile package path and every recorded parent constraint.
- Regeneration must reproduce the candidate target manifest and lockfile digests exactly. Any mismatch fails closed.
- A bounded post-regeneration OSV check must show that every vulnerability identifier claimed by the candidate is absent. Network failure, malformed OSV data, or a still-present vulnerability fails closed.
- Python remediation changes exactly one matching version token in `requirements.txt` while preserving extras, markers, comments, and surrounding text.
- Container remediation changes exactly one simple Dockerfile `FROM` reference and never resolves a digest itself.
- Proposal regeneration consumes the candidate bound in `remediation_input`, preventing later external resolution from changing the reviewed patch.
- Every planned file must match the accepted path patterns for the selected fixer before write credentials can be used.
- All dependency/container fixers, including `npm-lock-security-remediation`, remain draft-PR-only and cannot pass the native automatic-merge gate. Housekeeping remains the only automatic-merge class.
