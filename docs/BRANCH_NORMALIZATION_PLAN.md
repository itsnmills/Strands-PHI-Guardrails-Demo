# Branch Normalization Plan

GitHub now reports `main` as the default branch, but this local checkout and the
remote still carried a stale `master` branch. Treat `main` as the public source
of truth before publishing future hardening work.

## Current State

- Default branch: `main`
- Stale branch: `master`
- `main` contains the CI and security hygiene baseline.
- `master` contains an older README tightening commit and should not receive new
  public work.

## Safe Normalization Steps

1. Keep `main` as the default branch in GitHub.
2. Move any useful README-only wording from `master` into a PR targeting `main`.
3. Confirm `git ls-remote --heads origin` shows no required commits unique to
   `master`.
4. Protect `main` with PR and CI requirements before deleting or archiving
   `master`.
5. Delete `master` only after the public README, SECURITY.md, LICENSE, CI, and
   release checklist all live on `main`.

## Do Not

- Do not force-push `main`.
- Do not keep publishing fixes to `master`.
- Do not delete `master` until the unique commit review is recorded.
