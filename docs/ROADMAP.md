# ROADMAP

## Now
- Add a first-class baseline update workflow (`diff --baseline-update ...`) for teams managing long-lived snapshots.

## Next
- Keep expanding `violations` parsing coverage with additional real-world schema variants while preserving strict-by-default behavior.

## Later
- Expand analyzer coverage for `frame-src`/`worker-src`/`manifest-src` parity checks.

## Done (recent)
- 2026-02-11: Add `report --violations-file` support to embed violation summaries in HTML/JSON reports.
- 2026-02-11: Expand violation parsing support for wrapped exports (`reports`/`violations`/`events`) and JSON-string bodies.
- 2026-02-10: Add `report --format json` output and publish a JSON Schema via `schema --kind report`.
- 2026-02-10: Improve HTML report print stylesheet/pagination for better manual "Print to PDF".
- 2026-02-10: Add `make security` target (bandit + pip-audit) to match CI locally.
- 2026-02-10: Add optional import path for CSP violation report samples to aid rollout tuning.
- 2026-02-09: Add optional PDF export for `report` output (`--format pdf`).
- 2026-02-09: Add `explain` command for finding keys (`csp-doctor explain ...`).
- 2026-02-09: Add baseline snapshot environment metadata (`diff --baseline-env ...`).
- 2026-02-09: Add configurable finding suppressions/waivers (`--suppress`, `--suppress-file`).
- 2026-02-09: Add duplicate-directive warning findings (while preserving browser-first parsing behavior).
- 2026-02-09: Add `--fail-on` severity thresholds for CI gating.
- 2026-02-09: Add pipeline integration snippets for CI systems beyond GitHub Actions.
