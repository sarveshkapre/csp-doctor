# ROADMAP

## Now
- Add optional PDF export for HTML reports.

## Next
- Policy baselines with environment-specific metadata (staging/prod tracking).
- Optional import path for CSP violation report samples to aid rollout tuning.

## Later
- Add `explain` surface for finding keys (e.g. `csp-doctor explain missing-reporting`).

## Done (recent)
- 2026-02-09: Add configurable finding suppressions/waivers (`--suppress`, `--suppress-file`).
- 2026-02-09: Add duplicate-directive warning findings (while preserving browser-first parsing behavior).
- 2026-02-09: Add `--fail-on` severity thresholds for CI gating.
- 2026-02-09: Add pipeline integration snippets for CI systems beyond GitHub Actions.
