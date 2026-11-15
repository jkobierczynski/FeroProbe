# Repository rulesets

These JSON files are GitHub rulesets for this repository. They are not
applied automatically: import them once under
**Settings → Rules → Rulesets → New ruleset → Import a ruleset**.

| File | What it protects |
|---|---|
| `protect-main.json` | The default branch: no deletion or force-push, changes only through a pull request (merge, squash and rebase merges all allowed), and the four CI jobs from `ci.yml` (`ubuntu-latest`, `macos-latest`, `windows-latest` and `ubuntu-latest (root, raw sockets)`) must pass on an up-to-date branch. No approving review is required, so the solo maintainer can merge their own PRs. Repository admins can bypass only by merging a pull request, never by pushing directly. |
| `protect-tags.json` | Release tags `v*`: once created they cannot be moved or deleted by anyone except repository admins. Pushing a `v*` tag still triggers `release.yml` as before. |

The `nmap-diff` job is deliberately not required: it only runs on pull
requests that touch `scripts/nmap-diff/` or its workflow, so requiring it
would block every other pull request forever.

If a CI job is renamed in `.github/workflows/ci.yml` (the `check` job is
named after its matrix OS), update the `required_status_checks` list in
`protect-main.json` and the ruleset on GitHub, or pull requests will wait
forever for a check that never runs.
