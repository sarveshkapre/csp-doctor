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
