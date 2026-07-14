# Allowed fixers

Every proposal has one fixer ID and version. A fixer either returns one bounded,
deterministic plan or a clear refusal; it never partially proposes a change.

## `macos-metadata-ignore`

Adds `.DS_Store` to the root `.gitignore` when absent and proposes deletion of
discovered `.DS_Store` files. A real dirty worktree is accepted only when every
dirty path is exactly a `.DS_Store` file. Binary deletion is allowed only for
this exact metadata name.

## `python-cache-ignore`

Adds `__pycache__/` and `*.py[cod]` to the root `.gitignore` when absent. Cache
artifact deletion is locally applicable only in a marked fixture or with the
explicit real-local-target flag and every other safety check. It does not
generate or update a lockfile.

## `workflow-timeout`

Accepts only a `.github/workflows/*.yml` or `.yaml` location. It finds a single
simple top-level `jobs` block and inserts `timeout-minutes: 15` after one simple
`runs-on` value in each job that lacks a timeout. Existing timeouts are
preserved. Reusable-workflow jobs and complex/multiline runner declarations are
refused because a line edit cannot prove their semantics.

## `workflow-permissions`

Adds only top-level:

```yaml
permissions:
  contents: read
```

The workflow is refused if it already has top-level or job-level permissions,
uses secrets, `pull_request_target`, arbitrary network commands, unknown remote
actions, deployment, release, publishing, issue/PR writing, or environment
mutation. This deliberately prefers refusal over changing workflow behavior.

## `action-pin-plan`

Replaces mutable `owner/repository@tag` action references only when an explicit
local map contains the exact reference and a 40-character lowercase Git commit
SHA. The readable original tag is retained as a comment. Existing immutable
SHAs and local actions are unchanged. If any required mapping is absent, the
whole proposal is refused and network resolution remains deferred.

The map format is shown in `examples/action-pins.json`.
