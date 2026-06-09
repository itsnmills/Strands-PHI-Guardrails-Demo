# Branch Normalization Plan

This repository now uses `main` as the default public branch.

Current state:

- `main` is the canonical branch for README, security policy, CI, and release work.
- `master` remains on the remote only as a compatibility pointer for older links.
- New issues, pull requests, CI runs, and release tags should target `main`.

Planned cleanup:

1. Keep `master` untouched until public references and local clones have moved to `main`.
2. Confirm no README badges, demos, portfolio links, or downstream scripts point to `master`.
3. Delete the remote `master` branch only after that link audit is clean.
4. If a legacy link must remain stable, replace `master` with a permanent redirect note before deletion.

Do not use either branch to publish real PHI, credentials, private URLs, contracts, logs, patient details, or incident details.
