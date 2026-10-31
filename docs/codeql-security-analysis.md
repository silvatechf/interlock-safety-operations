# CodeQL security analysis

## Workflow

The `.github/workflows/codeql.yml` workflow runs CodeQL analysis for Python:

- On pull requests targeting `main`.
- On pushes to `main`.
- Weekly on Monday.
- Manually through GitHub Actions.

The workflow uses the CodeQL Action v4.39.1 release, pinned to its verified commit SHA. The checkout action is also pinned to the reviewed commit used by the CI workflow.

## Analysis configuration

- Language: Python.
- Build mode: `none`, appropriate for this interpreted Python project.
- Query suite: `security-extended`.
- Results are uploaded to GitHub Code Scanning using the minimum job permissions required for analysis.

The workflow is intentionally limited to Python. It does not claim coverage of infrastructure, runtime configuration, dependencies, secrets, or operational deployments.

## Operating policy

Review CodeQL findings in the repository's Security tab and triage them before changing code. Distinguish true positives, false positives, and accepted risks; document any accepted risk with a rationale and scope.

Do not make CodeQL a required merge check until the workflow has completed successfully on the default branch and its published check name has been confirmed in a pull request.

## Maintenance

Dependabot is configured to check GitHub Actions weekly. Review updates to the pinned CodeQL Action and checkout SHAs deliberately, confirm the upstream release and commit, and keep the version comments synchronized with the pins.
