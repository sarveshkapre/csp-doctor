# Project Memory

## Decision Log

### 2026-02-09 - Add profile-based CSP analysis modes
- Decision: Add `--profile` support with `strict`, `recommended`, and `legacy` modes for `analyze`, `report`, and `diff`.
- Why: Teams need different rollout strictness levels without forking rules or editing code.
- Evidence:
  - `src/csp_doctor/core.py`
  - `src/csp_doctor/cli.py`
  - `tests/test_core.py`
  - `tests/test_cli.py`
- Commit: `ffbcef16b6e5d26cf1b9d7130bede65960fe8d91`
- Confidence: high
- Trust label: validated-local
- Follow-ups:
  - Add configurable suppressions/waivers for rule-level exceptions.

### 2026-02-09 - Baseline snapshots must preserve analysis profile
- Decision: Store `profile` in baseline JSON snapshots and reject profile mismatches when diffing.
- Why: Comparing findings generated under different strictness profiles can hide or invent regressions.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
- Commit: `ffbcef16b6e5d26cf1b9d7130bede65960fe8d91`
- Confidence: high
- Trust label: validated-local
- Follow-ups:
  - Consider bumping to `schemaVersion` 2 if baseline metadata expands further.

### 2026-02-09 - CSP duplicate directives follow browser-first semantics
- Decision: Ignore duplicate directives after the first occurrence in parser output.
- Why: Browsers ignore later duplicates; matching this behavior prevents analysis drift.
- Evidence:
  - `src/csp_doctor/core.py`
  - `tests/test_core.py`
- Commit: `ffbcef16b6e5d26cf1b9d7130bede65960fe8d91`
- Confidence: high
- Trust label: validated-local
- Follow-ups:
  - Add explicit duplicate-directive findings to improve operator visibility.

### 2026-02-09 - Add duplicate-directive findings and suppression controls
- Decision: Add duplicate-directive warnings to `analyze` results and add `--suppress` / `--suppress-file` to filter known-acceptable findings in `analyze`, `report`, and `diff`.
- Why: Duplicates are a common misconfiguration that can silently change browser behavior; suppressions reduce noise for teams with intentional exceptions.
- Evidence:
  - `src/csp_doctor/core.py`
  - `src/csp_doctor/cli.py`
  - `tests/test_core.py`
  - `tests/test_cli.py`
- Commit: `ae08f8a1489c83a4a7a734e31c72122e4a6360c6`
- Confidence: high
- Trust label: validated-local
- Follow-ups:
  - Consider surfacing suppressed counts in JSON output once schemas support optional metadata.

### 2026-02-09 - Fix baseline snapshot output semantics for diff
- Decision: Make `diff --baseline-out` write a snapshot of the baseline policy used for the diff (or copy/emit the loaded baseline snapshot), not the proposed policy.
- Why: Incorrect baselines cause confusing diff results and can hide regressions by anchoring comparisons to the wrong policy.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
- Commit: `ae08f8a1489c83a4a7a734e31c72122e4a6360c6`
- Confidence: high
- Trust label: validated-local

### 2026-02-09 - Add `--fail-on` severity thresholds for CI gating
- Decision: Add `--fail-on` to `analyze`, `diff`, and `report` to exit non-zero when findings meet a severity threshold.
- Why: CI gating needs an ergonomic, stable exit-code contract without parsing text output.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: `78523a85b617a143ead3540e4694186ba0e973b5`
- Confidence: high
- Trust label: validated-local
- Follow-ups:
  - Consider adding `--fail-on` docs guidance for diff-vs-analyze gating tradeoffs.

### 2026-02-09 - Add `--output` for analyze/diff machine outputs
- Decision: Add `--output` for `analyze` (JSON/SARIF) and `diff` (JSON) to write artifacts directly to a file.
- Why: Shell redirection is fragile in some CI environments and complicates artifact handling.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: `45a829d5b7c4bb67079462b7507cf85943aeae6c`
- Confidence: high
- Trust label: validated-local

### 2026-02-09 - Add CI integration docs and suppression template; bump to 0.1.15
- Decision: Ship CI copy/paste snippets and a suppression template, and bump the package version to reflect new CLI capabilities.
- Why: Adoption improves when CI onboarding and “known exception” workflows are documented and easy to start.
- Evidence:
  - `docs/CI.md`
  - `docs/csp-doctor.suppressions.example`
  - `README.md`
  - `docs/CHANGELOG.md`
  - `pyproject.toml`
  - `src/csp_doctor/__init__.py`
- Commit: `1523e07ed039581184dac211ffabfbb67165b91b`
- Confidence: high
- Trust label: validated-local

### 2026-02-09 - Add `explain` command for finding keys
- Decision: Add `csp-doctor explain <key>` (plus `--list` and `--format json`) to provide a stable “what does this finding mean?” surface.
- Why: Finding keys are machine-friendly; teams need an ergonomic way to understand and triage a specific key without digging through code.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: `9dde069a565f2ce27f74b040a5db6ae1689434bd`
- Confidence: high
- Trust label: trusted

### 2026-02-09 - Add environment metadata to baseline snapshots
- Decision: Allow baseline JSON snapshots to include an optional `environment` label (staging/prod) and support enforcing it during `diff` via `--baseline-env`.
- Why: Long-lived baselines are easy to mix up; environment labels prevent comparing the wrong baseline and reduce rollout mistakes.
- Evidence:
  - `src/csp_doctor/core.py`
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: `d7e6acdf7936cfec243d7e5ae2a27af276351854`
- Confidence: medium
- Trust label: trusted

### 2026-02-09 - Add optional PDF export for HTML reports
- Decision: Support `report --format pdf` via an opt-in dependency extra (`.[pdf]`) while keeping default installs lightweight.
- Why: PDF is a common artifact format for security reviews, but bundling a renderer by default would increase install size and platform complexity.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `pyproject.toml`
  - `README.md`
- Commit: `7cf6041f013d0ecd28ce05cd2df829feb93bcc40`
- Confidence: medium
- Trust label: trusted

### 2026-02-10 - Summarize CSP violation reports to aid rollout tuning
- Decision: Add a `violations` command (text/JSON) that summarizes CSP violation report samples, and add an optional `rollout --violations-file` path to embed that summary into rollout output.
- Why: Teams need fast feedback loops during Report-Only rollout; violation summaries reduce triage time and make allowlist decisions more evidence-driven.
- Evidence:
  - `src/csp_doctor/violations.py`
  - `src/csp_doctor/cli.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: `e9f9e38e55afab0c39fcf04e8a98d159e7dbf8fd`
- Confidence: medium
- Trust label: validated-local

### 2026-02-10 - Add JSON report format and publish schema
- Decision: Add `report --format json` and publish its schema via `schema --kind report`.
- Why: CI and security tooling often want a single machine-readable artifact aligned with the HTML report without needing to parse text or recompute analysis.
- Evidence:
  - `src/csp_doctor/cli.py`
  - `src/csp_doctor/schema.py`
  - `tests/test_cli.py`
  - `README.md`
- Commit: TBD
- Confidence: medium
- Trust label: validated-local

### 2026-02-10 - Add local `make security` to match CI (bandit + pip-audit)
- Decision: Add `make security` and include bandit/pip-audit in `.[dev]`, keeping CI aligned with the same dependency set.
- Why: Local reproducibility reduces CI-only failures and makes security checks part of the default contributor workflow.
- Evidence:
  - `Makefile`
  - `pyproject.toml`
  - `.github/workflows/ci.yml`
- Commit: TBD
- Confidence: high
- Trust label: validated-local

## Mistakes And Fixes

### 2026-02-09 - `diff --baseline-out` wrote the wrong policy
- Root cause: The CLI wrote a baseline snapshot from the proposed `--csp` input instead of the baseline input.
- Fix: Use the baseline policy (or loaded baseline snapshot) when writing `--baseline-out`, and add a regression test.
- Prevention rule: For any CLI flag that writes an artifact, add a test that proves the artifact matches the flag’s documented semantics.
- Commit: `ae08f8a1489c83a4a7a734e31c72122e4a6360c6`
- Trust label: validated-local

### 2026-02-09 - CI SAST (bandit) failure due to `assert`
- Root cause: Bandit flags `assert` usage in non-test code (B101), even when the assertion is “unreachable” in normal CLI flows.
- Fix: Replace the assertion with explicit control flow that produces a non-optional baseline text.
- Prevention rule: Avoid `assert` in runtime code paths; prefer explicit error handling or locally-scoped, non-optional variables.
- Commit: `d1e7cd91bbdb6f1b1c026358a7a84a69057a1d27`
- Trust label: validated-local

## Verification Evidence

### 2026-02-09
- `make check` (pass)
- `.venv/bin/python -m ruff check src tests` (pass)
- `.venv/bin/python -m mypy src` (pass)
- `.venv/bin/python -m pytest` (pass)
- `.venv/bin/python -m build` (pass)
- `gh run watch 21813632527 --exit-status` (pass)
- `gh run watch 21827657646 --exit-status` (pass)
- `gh run watch 21844807730 --exit-status` (pass)
- `gh run watch 21844920673 --exit-status` (pass)
- `gh run watch 21844956937 --exit-status` (pass)
- `gh run watch 21844984742 --exit-status` (pass)
- Smoke:
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'; default-src https://example.com" --format json` (pass: duplicate-directive finding present)
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'" --suppress missing-frame-ancestors --format json` (pass: suppressed key absent)
  - `.venv/bin/python -m csp_doctor diff --baseline "default-src 'self'" --csp "default-src *" --baseline-out <tmp> --format json` (pass: baseline snapshot captured baseline values)
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'" --format sarif --output /tmp/csp-doctor.sarif --fail-on high` (pass: file written, exit 0)
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'" --format json --output /tmp/csp-doctor.json --fail-on medium` (pass: expected exit 1 with file written)
  - `.venv/bin/python -m csp_doctor diff --baseline "default-src 'self'; report-uri /csp" --csp "default-src 'self'" --format json --output /tmp/csp-diff.json --fail-on medium` (pass: expected exit 1 with file written)
  - `.venv/bin/python -m csp_doctor explain missing-reporting --format json` (pass)
  - `.venv/bin/python -m csp_doctor diff --baseline "default-src 'self'" --csp "default-src 'self'" --baseline-env staging --baseline-out /tmp/csp-baseline-staging.json --format json` (pass: snapshot includes environment)
  - `.venv/bin/python -m csp_doctor report --csp "default-src 'self'" --output /tmp/csp-report.html` (pass: file written)
  - `.venv/bin/pip install -e ".[pdf]"` (pass)
  - `.venv/bin/python -m csp_doctor report --csp "default-src 'self'" --format pdf --output /tmp/csp-report.pdf` (pass: PDF written)

### 2026-02-10
- `gh auth status` (fail: token invalid in keyring; unable to query issues/runs)
- `make check` (pass)
- `.venv/bin/python -m csp_doctor violations --file <tmp> --format json` (pass)
- `.venv/bin/python -m csp_doctor rollout --csp "default-src 'self'" --violations-file <tmp>` (pass)
- `.venv/bin/python -m csp_doctor report --csp "default-src 'self'" --format json` (pass)
- `.venv/bin/python -m csp_doctor schema --kind report` (pass)
- `.venv/bin/python -m pip install -e ".[dev]"` (pass)
- `make security` (pass: bandit ok; pip-audit ok with local package skipped)

## Market Scan (Bounded)

### 2026-02-09
- Sources (untrusted/web):
  - https://csp-evaluator.withgoogle.com/
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  - https://report-uri.com/home/generate
  - https://securityheaders.com/
- Expectations (untrusted/web):
  - Clear validation and human-readable explanations of risks.
  - Easy “report-only first” workflows and reporting endpoint guidance.
  - Outputs suitable for CI and security tooling (for example SARIF or JSON).

### 2026-02-09 (additional signals)
- Sources (untrusted/web):
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri
- Expectations (untrusted/web):
  - Report-only rollout should be first-class and the tool should guide reporting plumbing.
  - Reporting guidance should account for the `report-uri` deprecation and the newer Reporting API (`report-to`, `Reporting-Endpoints`).

### 2026-02-10
- Sources (untrusted/web):
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/report-uri
  - https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
  - https://owasp.org/index.php/OWASP_Secure_Headers_Project
  - https://docs.report-uri.com/setup/csp/
- Expectations (untrusted/web):
  - Violation reporting needs to account for `report-uri` deprecation and the Reporting API (`report-to`, `Reporting-Endpoints`).
  - Rollout workflows benefit from fast violation triage (top directives, top blocked origins) rather than only static policy linting.
