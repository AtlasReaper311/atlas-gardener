# Refusal and rollback runbook

## Triage a refusal

1. Read the exact refusal reason; do not weaken or bypass the guard.
2. Confirm the Finding validates against the current local
   `atlas-infra/contracts/v1` and its fingerprint is canonical.
3. Confirm repository classification comes from an approved source. Public
   runtime classification comes from the authoritative local `atlas-infra`
   registry. Private classification comes from source-owned
   `.atlas/governance.json`. Deprecated, archived, external-derived, malformed,
   and unknown real targets remain excluded.
4. Confirm the target is the repository named by the Finding, the path stays
   below its root, and no symlink escapes it.
5. For a real target, use a named non-`main` branch and make the worktree clean.
   The only dirty exception is exact `.DS_Store` metadata for that fixer.
6. For action pins, review and explicitly pass a local v1 pins map. Do not query
   the network from Gardener.
7. If the workflow syntax or required permission is complex, make a separate
   human-owned repository change instead of expanding the fixer.

## Local fixture rollback

Before apply, the proposal is only JSON and rollback is deleting the uncommitted
output. After a fixture apply, restore the disposable fixture from its test
setup or delete and recreate the fixture directory.

## Real local branch rollback

Actual real-local apply requires explicit `--allow-local-target` and a
non-`main` branch. Review `git diff` first. To roll back, restore only the
reviewed affected files from the branch base or delete the unmerged local
branch after changing away from it. Do not reset, force-push, or delete a remote
branch as part of this runbook.

## Future draft-PR rollback

Close the unmerged draft PR and manually delete its proposal branch. The default
branch remains unchanged. Disable the App installation or workflow if repeated
unsafe proposals occur, then retain the Finding and refusal evidence for
diagnosis.
