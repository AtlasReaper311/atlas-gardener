# Ownership

| Concern | Owner |
|---|---|
| Contract meaning, schemas, fingerprints, compatibility | `AtlasReaper311/atlas-infra` |
| Public runtime classification and public policy | `AtlasReaper311/atlas-infra` |
| Private repository classification | The authenticated source repository through `.atlas/governance.json` |
| Finding production and contract assurance integration | `AtlasReaper311/atlas-dep-audit` |
| Fixer allowlist, proposal planning, local apply safety | `AtlasReaper311/atlas-gardener` |
| Target repository behavior and native validation | The target repository owner |
| Future GitHub App installation and PR review | Atlas Reaper / `AtlasReaper311` |

The owner is responsible for reviewing every patch and target-native validation
result. Gardener never becomes the authority for application logic, production
deployment, credentials, billing, Cloudflare configuration, or default-branch
changes.

This repository uses the MIT licence and copies no implementation from a
private or external-derived repository.
