# Repository governance notes

This repository is designed to be safe to clone and run locally, and safe to review in public.

## Forking policy (best-effort)

This repo attempts to disable/restrict forking using the GitHub REST API when a suitable token is available.

Important limitation:
- GitHub only allows changing `allow_forking` for **organization-owned** repositories. For **user-owned** repositories, the API returns HTTP 422 and the setting cannot be changed programmatically.

When the platform does not allow disabling forks, the closest enforceable alternative is:
- keep secrets out of the repository (and out of git history)
- run secret scanning in CI
- document licensing terms clearly

