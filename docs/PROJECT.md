# PROJECT

## Commands
- Setup: `make setup`
- Dev: `make dev`
- Test: `make test`
- Lint: `make lint`
- Typecheck: `make typecheck`
- Build: `make build`
- Quality gate: `make check`
- Release: `make release`

## Next 3 improvements
1. Optional import path for CSP violation report samples to aid rollout tuning.
2. Print stylesheet / pagination improvements for HTML reports (for better manual "Print to PDF").
3. Add a `make security` target (bandit + pip-audit) to match CI locally.
