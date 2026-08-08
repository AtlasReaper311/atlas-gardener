# Provider guard Wave 2A validation

This documentation-only change validates the Atlas Systems default-branch provider guard on `atlas-gardener`.

Expected protected path:

- pull requests required for the default branch;
- native required context `test`;
- deletion blocked;
- non-fast-forward updates blocked;
- zero required approvals;
- no bypass actors.

This file does not change Gardener controller logic, repository variables, write targets, secrets, workflows, provider settings, deployment state, or automation authority.
