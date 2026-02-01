# PLAN

## One-line pitch
Local-first CLI to audit a CSP, highlight risk, and generate a safe rollout plan.

## Features
- Parse CSP values (or header lines) into directives and sources
- Risk analysis with actionable findings
- Rollout checklist generation
- Report-Only policy generator (optional full header output)
- Machine-readable JSON output (`analyze --format json`)

## Top risks / unknowns
- CSP semantics are nuanced and browser-specific; false positives are possible.
- Report-To requires a separate `Report-To` header; users may misconfigure.
- Recommendations must stay conservative to avoid breaking sites.

## Commands
See `docs/PROJECT.md`.

## Shipped (2026-02-01)
- Stdin support (`--stdin` / `--csp -`) and header-line input parsing.
- New hardening checks (frame-ancestors, base-uri, object-src, upgrade-insecure-requests).
- Text output polish (severity summary + optional color) and `report-only --full-header`.
- New `diff` command to compare a CSP against a baseline.
- New `schema` command to publish JSON Schema for JSON outputs.
- New CSP Level 3 checks for `require-trusted-types-for` and `trusted-types`.
- New Report-To header template helper for report-only workflows.
- New baseline JSON snapshot support for diff comparisons.
- New `normalize` command for stable, sorted CSP output.
- New HTML report export via `report` command.
