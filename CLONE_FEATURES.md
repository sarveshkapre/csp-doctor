# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1: Add duplicate-directive warning findings (while preserving first-directive parsing semantics).
- [ ] P2: Add optional PDF export for HTML reports.
- [ ] P2: Add configurable finding suppressions/waivers for known-acceptable policy exceptions.

## Implemented
- [x] 2026-02-09: Fix GitHub Actions secret scan failures by fetching full git history (`actions/checkout fetch-depth: 0`). Evidence: `.github/workflows/ci.yml`, CI root-cause log from run `#21557309835`.
- [x] 2026-02-09: Expand CSP analysis coverage with `missing-form-action` detection. Evidence: `src/csp_doctor/core.py`, `tests/test_core.py`.
- [x] 2026-02-09: Add `analyze --format sarif` output for security pipeline interoperability. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, smoke file `/tmp/csp-doctor.sarif`.
- [x] 2026-02-09: Harden baseline JSON snapshot validation with strict directive/finding shape checks and explicit errors. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`.
- [x] 2026-02-09: Refresh product/docs metadata for shipped behavior and version bump to `0.1.12`. Evidence: `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`, `docs/PROJECT.md`, `pyproject.toml`, `src/csp_doctor/__init__.py`.
- [x] 2026-02-09: Fix GitHub Actions PR gitleaks reliability by passing `GITHUB_TOKEN` to secret scan step. Evidence: `.github/workflows/ci.yml`.
- [x] 2026-02-09: Add risk profiles (`strict`/`recommended`/`legacy`) for `analyze`, `report`, and `diff` to tune finding strictness. Evidence: `src/csp_doctor/core.py`, `src/csp_doctor/cli.py`, `tests/test_core.py`, `tests/test_cli.py`.
- [x] 2026-02-09: Persist baseline snapshot profile metadata and fail closed on profile mismatch during `diff --baseline-json`. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, smoke output `/tmp/csp-baseline-legacy.json`.
- [x] 2026-02-09: Align CSP parsing with browser semantics by ignoring duplicate directives after first occurrence. Evidence: `src/csp_doctor/core.py`, `tests/test_core.py`.
- [x] 2026-02-09: Publish GitHub Code Scanning SARIF integration guidance and expose from README. Evidence: `docs/CODE_SCANNING.md`, `README.md`.
- [x] 2026-02-09: Create persistent automation records for decisions and incidents. Evidence: `PROJECT_MEMORY.md`, `INCIDENTS.md`.

## Insights
- `gitleaks/gitleaks-action@v2` can fail with ambiguous revision errors on push scans when checkout is shallow; full history avoids false CI failures.
- Baseline snapshot loading should fail closed on malformed data to avoid silent analysis drift in `diff` workflows.
- SARIF output is a low-cost, high-leverage format addition for adoption in enterprise security/devsecops pipelines.
- gitleaks pull-request scans require `GITHUB_TOKEN` in action environment; otherwise scans fail even when code quality checks pass.
- CSP diff baselines must bind to a risk profile to keep comparisons semantically stable across strictness modes.
- Duplicate CSP directives should follow browser-first semantics (first directive wins) to avoid false confidence from overwritten parser state.

## Notes
- This file is maintained by the autonomous clone loop.
