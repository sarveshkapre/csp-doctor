# ROADMAP

## Now
- Optional import path for CSP violation report samples to aid rollout tuning.

## Next
- Print stylesheet / pagination improvements for HTML reports (for better manual "Print to PDF").
- Add a `make security` target (bandit + pip-audit) to match CI locally.

## Later
- Add `report --format json` to export directives/findings in a single artifact aligned with HTML report.

## Done (recent)
- 2026-02-09: Add optional PDF export for `report` output (`--format pdf`).
- 2026-02-09: Add `explain` command for finding keys (`csp-doctor explain ...`).
- 2026-02-09: Add baseline snapshot environment metadata (`diff --baseline-env ...`).
- 2026-02-09: Add configurable finding suppressions/waivers (`--suppress`, `--suppress-file`).
- 2026-02-09: Add duplicate-directive warning findings (while preserving browser-first parsing behavior).
- 2026-02-09: Add `--fail-on` severity thresholds for CI gating.
- 2026-02-09: Add pipeline integration snippets for CI systems beyond GitHub Actions.
