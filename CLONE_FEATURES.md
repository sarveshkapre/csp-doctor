# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P2: Add optional PDF export for HTML reports.
- [ ] P2: Add `--output` for `analyze`/`diff` machine outputs (JSON/SARIF) to mirror `report --output`.
- [ ] P2: Add pipeline integration snippets for common CI systems beyond GitHub Actions (GitLab CI, CircleCI, etc.).
- [ ] P3: Add `--fail-on` severity threshold to make CI gating ergonomic.
- [ ] P3: Add `explain` surface for finding keys (e.g. `csp-doctor explain missing-reporting`).
- [ ] P3: Document and template a suppression file format (`csp-doctor.suppressions`).
- [ ] P3: Add baseline snapshots with environment metadata (staging/prod) for long-lived tracking.

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
- [x] 2026-02-09: Add duplicate-directive warning findings while preserving browser-first semantics. Evidence: `src/csp_doctor/core.py`, `tests/test_core.py`.
- [x] 2026-02-09: Add finding suppressions (`--suppress`, `--suppress-file`) for `analyze`, `report`, and `diff`. Evidence: `src/csp_doctor/cli.py`, `README.md`, `tests/test_cli.py`.
- [x] 2026-02-09: Fix `diff --baseline-out` to snapshot the baseline policy used for the diff. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`.
- [x] 2026-02-09: Prefer `.venv/bin/python` automatically in `make` targets when a local venv exists. Evidence: `Makefile`.
- [x] 2026-02-09: Publish GitHub Code Scanning SARIF integration guidance and expose from README. Evidence: `docs/CODE_SCANNING.md`, `README.md`.
- [x] 2026-02-09: Create persistent automation records for decisions and incidents. Evidence: `PROJECT_MEMORY.md`, `INCIDENTS.md`.

## Insights
- `gitleaks/gitleaks-action@v2` can fail with ambiguous revision errors on push scans when checkout is shallow; full history avoids false CI failures.
- Baseline snapshot loading should fail closed on malformed data to avoid silent analysis drift in `diff` workflows.
- SARIF output is a low-cost, high-leverage format addition for adoption in enterprise security/devsecops pipelines.
- gitleaks pull-request scans require `GITHUB_TOKEN` in action environment; otherwise scans fail even when code quality checks pass.
- CSP diff baselines must bind to a risk profile to keep comparisons semantically stable across strictness modes.
- Duplicate CSP directives should follow browser-first semantics (first directive wins) to avoid false confidence from overwritten parser state.
- (untrusted/web) Comparable tools frequently surface: policy evaluation, reporting endpoint guidance, and rollout workflow helpers.

## Notes
- This file is maintained by the autonomous clone loop.
