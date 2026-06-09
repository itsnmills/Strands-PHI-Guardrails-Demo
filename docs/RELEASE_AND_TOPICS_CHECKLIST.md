# Release and Topics Checklist

Use this checklist before cutting the first public Strands PHI Guardrails Demo
release.

## Release Criteria

- `python -m pytest -q tests` passes locally and in GitHub Actions.
- `SECURITY.md` states that reports must not contain PHI, credentials, secrets,
  live patient/practice data, raw logs, or customer screenshots.
- README wording stays demo-scoped: no HIPAA certification, legal advice,
  production authorization, breach determination, or compliance guarantee.
- `LICENSE` is present.
- `main` is the only branch used for public release work.

## Suggested Topics

- `healthcare-ai`
- `phi`
- `guardrails`
- `hipaa`
- `strands-agents`
- `rbac`
- `local-first`
- `velari`

## Suggested Release

- Tag: `v0.1.0`
- Title: `v0.1.0 Guardrails Demo Baseline`
- Notes: mention deterministic RBAC, purpose-of-use checks, BAA-status gating,
  PHI-pattern evals, local-first demo scope, and the Small Practice Security Kit
  companion link.
