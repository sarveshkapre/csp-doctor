# ROADMAP

## Now
- Optionally surface violation summaries in `report` output (HTML/JSON) to aid rollout triage.

## Next
- Expand `violations` parsing coverage with more real-world schema variants (while staying strict by default).

## Later
- Add a first-class baseline update workflow (`diff --baseline-update ...`) for teams managing long-lived snapshots.

## Done (recent)
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
