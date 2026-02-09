# CHANGELOG

## v0.1.15 - 2026-02-09
- Add `--fail-on` severity thresholds for CI gating on `analyze`, `diff`, and `report`.
- Add `--output` for `analyze` (JSON/SARIF) and `diff` (JSON) to write artifacts without shell redirection.
- Add CI integration snippets beyond GitHub Actions (`docs/CI.md`).
- Add a suppression file template (`docs/csp-doctor.suppressions.example`).

## v0.1.14 - 2026-02-09
- Add configurable finding suppressions (`--suppress`, `--suppress-file`) for `analyze`, `report`, and `diff`.
- Add duplicate-directive warning findings while preserving browser-first parsing (first directive wins).
- Fix `diff --baseline-out` to snapshot the baseline policy used for the diff (not the proposed policy).
- Make `make check` use `.venv/bin/python` automatically when a local venv exists.

## v0.1.13 - 2026-02-09
- Add configurable analysis risk profiles (`strict`, `recommended`, `legacy`) for `analyze`, `report`, and `diff`.
- Persist baseline snapshot `profile` metadata and fail closed on profile mismatches when diffing from JSON snapshots.
- Align CSP parsing with browser behavior by ignoring duplicate directives after the first occurrence.
- Add SARIF upload guidance for GitHub Code Scanning (`docs/CODE_SCANNING.md`) and link from README.
- Fix PR CI secret scanning reliability by passing `GITHUB_TOKEN` to `gitleaks/gitleaks-action@v2`.

## v0.1.12 - 2026-02-09
- Fix GitHub Actions secret scan reliability by fetching full git history in CI checkout.
- Expand analyzer coverage with a `missing-form-action` finding.
- Add `analyze --format sarif` for security pipeline interoperability.
- Harden diff baseline JSON loading with strict shape/type validation.

## v0.1.11 - 2026-02-01
- Add report templates (classic, glass, minimal) for HTML export.

## v0.1.10 - 2026-02-01
- Add baseline snapshot schema versioning for diff comparisons.

## v0.1.9 - 2026-02-01
- Add color presets for CLI severity labels and report theme controls.

## v0.1.8 - 2026-02-01
- Add HTML report export via `report` command.

## v0.1.7 - 2026-02-01
- Add `normalize` command to sort directives and sources for stable CSP output.

## v0.1.6 - 2026-02-01
- Add baseline JSON snapshots for diff comparisons (`diff --baseline-out`, `diff --baseline-json`).

## v0.1.5 - 2026-02-01
- Add Report-To header template generation for report-only workflows.

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
