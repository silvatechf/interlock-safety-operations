# CI supply-chain and secret-scanning maintenance

## GitHub Actions pinning

Workflow actions are pinned to full commit SHAs rather than mutable version tags. A version comment records the release reviewed for each SHA. The comment is explanatory; the commit SHA is the actual reference used by GitHub Actions.

When updating an action:

1. Identify the intended upstream release and verify its tag resolves to the exact commit SHA in the upstream repository.
2. Review the release notes and any relevant security advisories.
3. Change the full SHA and its version comment together in a pull request.
4. Require the normal CI checks to pass on the exact pull-request head, then confirm the post-merge workflow succeeds.
5. Do not use a version tag alone as the workflow reference.

Pinning improves reproducibility and reduces exposure to a tag being moved, but it does not prove an action is safe. Review updates regularly; a pinned old version can still contain vulnerabilities.

## Secret scanning

GitGuardian secret scanning has reported a successful check on a recent pull request. Keep that check enabled and review its result on future pull requests. This repository workflow does not replace provider-side secret scanning.

Never put real credentials, access tokens, private keys, or production data into commits, tests, fixtures, issues, or logs. Use synthetic values in demonstrations. If a credential is exposed, revoke or rotate it immediately; deleting the text from a later commit does not invalidate the credential or guarantee removal from history.

## Scope

These controls improve repository hygiene only. They do not establish operational safety, certification, or production readiness for Sentinel Interlock.
