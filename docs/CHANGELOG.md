# CHANGELOG

## v0.1.4 - 2026-02-01
- Add CSP Level 3 checks for `require-trusted-types-for` and `trusted-types`.

## v0.1.3 - 2026-02-01
- Add `schema` command to print JSON Schema for `analyze --format json` and `diff --format json`.

## v0.1.2 - 2026-02-01
- Add `diff` command to compare a CSP against a baseline (directive + finding changes).

## v0.1.1 - 2026-02-01
- Accept header-line input (e.g. `Content-Security-Policy: ...`) and stdin (`--stdin` / `--csp -`).
- Improve analysis coverage (frame-ancestors, base-uri, object-src, upgrade-insecure-requests).
- Polished text output: severity summary + optional color; report-only can emit a full header line.

## v0.1.0 - 2026-02-01
- Initial CLI with CSP parsing, risk analysis, rollout plan, and report-only generator.
