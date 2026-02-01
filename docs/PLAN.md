# PLAN

## Goal
Ship a local-first CLI that inspects CSP headers, highlights risky patterns, and outputs a safe rollout plan plus a report-only header value.

## Stack
- Python 3.11
- Stdlib CLI (argparse)
- Ruff + mypy + pytest

Rationale: minimal dependencies, easy to audit, fast to run locally.

## Architecture
- `csp_doctor.core`: parsing, analysis, rollout logic.
- `csp_doctor.cli`: CLI entrypoint and output formatting.

## MVP checklist
- [x] Parse CSP directives and sources
- [x] Detect risky directives (unsafe-inline/eval, wildcards, missing defaults)
- [x] Report-only header generator
- [x] Rollout plan output
- [x] CLI JSON output for analysis
- [x] Tests for parsing and report-only output

## Risks
- CSP semantics are nuanced and browser-specific.
- Report-To requires a separate response header; users may misconfigure.
- Overly aggressive findings may produce false positives.

## Security notes
- No network activity or file writes beyond explicit input.
- Analysis is advisory; users should validate in staging.
