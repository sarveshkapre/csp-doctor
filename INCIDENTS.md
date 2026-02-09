# Incidents

## 2026-02-01 - GitHub Actions secret scan failures on CI

- Status: resolved
- Impact:
  - CI runs failed despite passing tests/build, blocking merge confidence.
  - Affected runs: `21557309835` (push), `21557279550` (pull_request).
- Root cause:
  - `actions/checkout` used shallow history (`fetch-depth: 1`), so gitleaks commit range resolution failed on push scans.
  - gitleaks PR scan required `GITHUB_TOKEN`, but workflow did not pass it in the action environment.
- Fix:
  - Set checkout to full history (`fetch-depth: 0`).
  - Pass `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` to `gitleaks/gitleaks-action@v2`.
- Evidence:
  - `.github/workflows/ci.yml`
  - GitHub Actions run logs:
    - https://github.com/sarveshkapre/csp-doctor/actions/runs/21557309835
    - https://github.com/sarveshkapre/csp-doctor/actions/runs/21557279550
- Prevention rules:
  - For secret scanning actions that diff commits, avoid shallow checkouts unless the scanner explicitly supports them.
  - For PR scan actions that depend on API access, set required tokens explicitly in workflow `env`.
  - Treat old failing runs as unresolved until both push and PR paths pass after workflow changes.
