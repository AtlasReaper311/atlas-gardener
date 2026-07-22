# Disabled controller smoke test

Use this smoke test immediately after controller source changes and before configuring credentials, handoff publication, target callers, or native auto-merge.

## Safety state

The repository variables must be absent or set to:

```text
ATLAS_GARDENER_MODE=disabled
ATLAS_GARDENER_WRITE_GATE=disabled
```

No GitHub App identifier, private key, or notification token is required for this test.

## Run

From `AtlasReaper311/atlas-gardener`:

1. Open **Actions**.
2. Select **Atlas Gardener controller**.
3. Run the workflow on `main`.

## Expected result

The workflow must:

- validate the pinned Atlas Infra authority;
- resolve `disabled` mode;
- skip Finding bundle retrieval and attestation;
- run the disabled controller path;
- upload `controller-evidence/controller.json`;
- create no target branch, pull request, token, or merge action.

The successful artifact uses `atlas-gardener/controller-evidence/v1` and records `mode=disabled`, `write_gate_enabled=false`, an empty pull-request list, and an empty token list.

If controller startup or execution fails, the entrypoint must still write `atlas-gardener/controller-error-evidence/v1` to the same artifact path before returning a failure exit code. The error reason is bounded and credential values are not included.

Node runtime and `punycode` deprecation messages emitted by GitHub-maintained JavaScript actions are warnings. A Python traceback, non-zero controller step, or missing evidence artifact is a real failure.
