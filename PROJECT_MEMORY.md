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

## Mistakes And Fixes

### 2026-02-09 - `diff --baseline-out` wrote the wrong policy
- Root cause: The CLI wrote a baseline snapshot from the proposed `--csp` input instead of the baseline input.
- Fix: Use the baseline policy (or loaded baseline snapshot) when writing `--baseline-out`, and add a regression test.
- Prevention rule: For any CLI flag that writes an artifact, add a test that proves the artifact matches the flag’s documented semantics.
- Commit: `ae08f8a1489c83a4a7a734e31c72122e4a6360c6`
- Trust label: validated-local

## Verification Evidence

### 2026-02-09
- `make check` (pass)
- `.venv/bin/python -m ruff check src tests` (pass)
- `.venv/bin/python -m mypy src` (pass)
- `.venv/bin/python -m pytest` (pass)
- `.venv/bin/python -m build` (pass)
- Smoke:
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'; default-src https://example.com" --format json` (pass: duplicate-directive finding present)
  - `.venv/bin/python -m csp_doctor analyze --csp "default-src 'self'" --suppress missing-frame-ancestors --format json` (pass: suppressed key absent)
  - `.venv/bin/python -m csp_doctor diff --baseline "default-src 'self'" --csp "default-src *" --baseline-out <tmp> --format json` (pass: baseline snapshot captured baseline values)
