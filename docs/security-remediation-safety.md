# Security remediation safety invariants

Accepted ADR-0015 permits three new review-required fixer IDs: `npm-security-update`, `python-security-pin`, and `container-digest-pin`.

- Each candidate is contract-validated and version/digest-validated again by the selected fixer.
- Dependency targets must be strict, newer, same-major versions and include at least one vulnerability identifier.
- npm lockfile regeneration uses a fixed argument vector with scripts, audit, funding, and update-notifier behavior disabled. Finding-controlled package names and versions are conveyed through bounded file preimages, not command arguments.
- npm receives a reduced subprocess environment without repository/provider credentials.
- Python remediation changes exactly one matching version token in `requirements.txt` while preserving extras, markers, comments, and surrounding text.
- Container remediation changes exactly one simple Dockerfile `FROM` reference and never resolves a digest itself.
- Proposal regeneration consumes the candidate bound in `remediation_input`, preventing later external resolution from changing the reviewed patch.
- Every planned file must match the accepted path patterns for the selected fixer before write credentials can be used.
- All three new fixers remain draft-PR-only and cannot pass the native automatic-merge gate.
