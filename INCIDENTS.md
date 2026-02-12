# Incidents

## 2026-02-09 - `diff --baseline-out` wrote a snapshot of the proposed policy

- Status: resolved
- Impact:
  - Baseline snapshots could be anchored to the wrong policy, leading to confusing diffs and potentially hiding regressions.
- Root cause:
  - The CLI wrote the baseline snapshot using the proposed `--csp` value instead of the baseline input used for the diff.
- Fix:
  - Write `--baseline-out` from the baseline policy (or copy/emit the loaded baseline snapshot) and add a regression test.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
- Prevention rules:
  - Any CLI flag that writes artifacts must have a regression test asserting the artifact matches the documented semantics.

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

### 2026-02-12T20:01:26Z | Codex execution failure
- Date: 2026-02-12T20:01:26Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-2.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:04:55Z | Codex execution failure
- Date: 2026-02-12T20:04:55Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-3.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:08:24Z | Codex execution failure
- Date: 2026-02-12T20:08:24Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-4.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:11:50Z | Codex execution failure
- Date: 2026-02-12T20:11:50Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-5.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:15:20Z | Codex execution failure
- Date: 2026-02-12T20:15:20Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-6.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:18:51Z | Codex execution failure
- Date: 2026-02-12T20:18:51Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-7.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:22:17Z | Codex execution failure
- Date: 2026-02-12T20:22:17Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-csp-doctor-cycle-8.log
- Commit: pending
- Confidence: medium
