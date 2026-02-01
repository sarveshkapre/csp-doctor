# PLAN

## One-line pitch
Local-first CLI to audit a CSP, highlight risk, and generate a safe rollout plan.

## Goal
Ship a local-first CLI that inspects CSP headers, highlights risky patterns, and outputs a safe rollout plan plus a report-only header value.

## Commands
See `docs/PROJECT.md`.

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
- [x] Flag missing modern hardening directives (frame-ancestors, base-uri, object-src)
- [x] Report-only header generator
- [x] Rollout plan output
- [x] CLI JSON output for analysis
- [x] Tests for parsing, stdin input, and report-only output

## Shipped (2026-02-01)
- Support stdin input (`--stdin` / `--csp -`) and header-line input (`Content-Security-Policy: ...`).
- Improve text UX: severity summary + optional color; report-only can emit a full header line.
- Add `diff` command to compare a CSP against a baseline.
- Add `schema` command to publish JSON Schema for machine-readable outputs.
- Add CSP Level 3 checks for `require-trusted-types-for` and `trusted-types`.
- Add Report-To header template generation for report-only workflows.

## Next
- Add baseline input/output file format (JSON in/out).

## Risks
- CSP semantics are nuanced and browser-specific.
- Report-To requires a separate response header; users may misconfigure.
- Overly aggressive findings may produce false positives.

## Security notes
- No network activity or file writes beyond explicit input.
- Analysis is advisory; users should validate in staging.
