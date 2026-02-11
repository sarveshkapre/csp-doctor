# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Session Prioritization (2026-02-09)
- Selected: Fix `diff --baseline-out` baseline snapshot semantics. Score: impact high, effort low, risk low, confidence high.
- Selected: Finding suppressions (`--suppress`, `--suppress-file`). Score: impact high, effort medium, risk low, confidence high.
- Selected: Duplicate-directive warning findings. Score: impact medium, effort low, risk low, confidence high.

## Session Prioritization (cycle 3 - 2026-02-09)
- Selected: Add `--fail-on` severity thresholds for CI gating on `analyze`/`diff`/`report`. Score: impact high, effort low, risk low, confidence high.
- Selected: Add `--output` for `analyze`/`diff` machine outputs (JSON/SARIF) to mirror `report --output`. Score: impact high, effort low, risk low, confidence high.
- Selected: Add CI pipeline integration snippets beyond GitHub Actions. Score: impact medium, effort low, risk low, confidence high.
- Selected: Document a suppression file format and ship a starter template. Score: impact medium, effort low, risk low, confidence high.

## Session Prioritization (cycle 5 - 2026-02-09)
- Selected: Add optional PDF export for `report` output (`--format pdf`). Score: impact high, effort medium, strategic fit high, differentiation medium, risk medium, confidence medium.
- Selected: Add `explain` command for finding keys (with JSON/text output and `--list`). Score: impact high, effort low, strategic fit high, differentiation medium, risk low, confidence high.
- Selected: Add baseline snapshot environment metadata (staging/prod tracking) with optional mismatch enforcement in `diff`. Score: impact medium, effort medium, strategic fit high, differentiation low, risk low, confidence medium.

## Session Prioritization (cycle 1 - 2026-02-10)
- Selected: Add optional CSP violation report import (file path) to summarize violations and aid rollout tuning. Score: impact high, effort medium, strategic fit high, differentiation medium, risk low, confidence medium.
- Selected: Add `make security` target (bandit + pip-audit) to match CI locally. Score: impact medium, effort low, strategic fit high, differentiation low, risk low, confidence high.
- Selected: Improve HTML report print stylesheet/pagination for better manual "Print to PDF" flows. Score: impact medium, effort low, strategic fit medium, differentiation low, risk low, confidence high.
- Selected: Add `report --format json` (plus schema) to export directives/findings in a single machine-readable artifact aligned with HTML report. Score: impact medium, effort medium, strategic fit high, differentiation low, risk low, confidence medium.

## Session Prioritization (cycle 1 - 2026-02-11)
- Selected: Add `report --violations-file` support to surface violation summaries in HTML and JSON outputs. Score: impact high, effort medium, strategic fit high, differentiation medium, risk low, confidence high.
- Selected: Expand `violations` parser coverage for common wrapped export shapes (`reports`/`violations`/`events`) and JSON-string bodies. Score: impact high, effort medium, strategic fit high, differentiation medium, risk low, confidence medium.
- Selected: Add regression tests and smoke paths for new report/violations workflows. Score: impact high, effort low, strategic fit high, differentiation low, risk low, confidence high.
- Considered but deferred: baseline update workflow (`diff --baseline-update ...`) because report+violations gaps are higher PMF impact for current roadmap.

## Candidate Features To Do
- [ ] P2: Add first-class baseline update workflow (`diff --baseline-update ...`) for long-lived snapshots.
- [ ] P2: Add optional `violations --fail-on-skipped` to fail CI on malformed/unrecognized samples.
- [ ] P2: Include optional `suppressed_count` metadata in JSON outputs where schema allows.
- [ ] P3: Expand analyzer coverage for `frame-src`/`worker-src`/`manifest-src` parity checks.
- [ ] P3: Add directive-level remediation hints in `report` JSON for automation pipelines.
- [ ] P3: Add explicit Reporting API guidance for `Reporting-Endpoints` and deprecation posture in docs.
- [ ] P3: Improve baseline snapshot forward-compatibility workflow (schema migration helper).
- [ ] P3: Add a streaming NDJSON parser mode for large violation datasets.
- [ ] P4: Add a lightweight benchmark target for parser/analyzer throughput regression checks.
- [ ] P4: Add an optional pre-commit profile to run lint/typecheck/test quickly before push.
- [ ] P4: Add end-to-end fixture corpus for real-world CSP/violation samples.

## Implemented
- [x] 2026-02-11: Add `report --violations-file` support (plus `--violations-top`, `--violations-top-origins`) to embed violation summaries in HTML and JSON report output. Evidence: `src/csp_doctor/cli.py`, `src/csp_doctor/schema.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-11: Expand violation parser coverage for wrapped exports (`reports`/`violations`/`events`) and JSON-string bodies. Evidence: `src/csp_doctor/violations.py`, `tests/test_violations.py`, `tests/test_cli.py`.
- [x] 2026-02-11: Validate `violations --top`/`--top-origins` and report equivalents as positive integers. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`.
- [x] 2026-02-10: Summarize CSP violation reports via `csp-doctor violations` (text/JSON) and optionally embed summaries into `rollout` output (`--violations-file`). Evidence: `src/csp_doctor/violations.py`, `src/csp_doctor/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-10: Add `report --format json` and publish schema via `schema --kind report`. Evidence: `src/csp_doctor/cli.py`, `src/csp_doctor/schema.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-10: Improve HTML report print stylesheet/pagination for better manual "Print to PDF". Evidence: `src/csp_doctor/cli.py`.
- [x] 2026-02-10: Add `make security` target (bandit + pip-audit) to match CI locally, and align CI install to dev extras. Evidence: `Makefile`, `pyproject.toml`, `.github/workflows/ci.yml`.
- [x] 2026-02-09: Add `explain` command for finding keys (`csp-doctor explain <key>`, `--list`, `--format json`). Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09: Add baseline snapshot environment metadata and mismatch enforcement (`diff --baseline-env`). Evidence: `src/csp_doctor/core.py`, `src/csp_doctor/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09: Add optional PDF export for `report` output (`report --format pdf --output ...`) via optional dependency extra. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, `pyproject.toml`, `README.md`.
- [x] 2026-02-09: Add `--fail-on` severity thresholds for CI gating on `analyze`, `diff`, and `report`. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09: Add `--output` for `analyze` (JSON/SARIF) and `diff` (JSON) to write artifacts without shell redirection. Evidence: `src/csp_doctor/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09: Add CI integration snippets beyond GitHub Actions. Evidence: `docs/CI.md`, `docs/ROADMAP.md`, `README.md`.
- [x] 2026-02-09: Add a suppression file template. Evidence: `docs/csp-doctor.suppressions.example`, `README.md`.
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
- Optional PDF export is best shipped as an opt-in dependency extra to keep the default install lightweight; error paths should be explicit and actionable when the extra isn't installed.
- (untrusted/web) Comparable tools frequently surface: policy evaluation, reporting endpoint guidance, and rollout workflow helpers.
- (untrusted/web) Competitive baseline expects clear policy diagnostics plus rollout telemetry: Google CSP Evaluator emphasizes bypass/policy checks (`https://csp-evaluator.withgoogle.com/`), Report URI emphasizes report ingestion and triage workflows (`https://docs.report-uri.com/setup/csp/`), and SecurityHeaders highlights security-grade style reporting UX (`https://securityheaders.com/about/faq/`).
- (untrusted/web) Modern rollout UX should support both legacy `report-uri` and Reporting API semantics, matching MDN guidance (`https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/report-uri`).

## Notes
- This file is maintained by the autonomous clone loop.
- 2026-02-10: Maintenance refactor: de-duplicated CLI finding counts/summaries and HTML row rendering helpers (no behavior change). Evidence: `src/csp_doctor/cli.py`, `src/csp_doctor/core.py`, `PROJECT_MEMORY.md`.
