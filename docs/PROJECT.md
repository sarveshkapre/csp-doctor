# PROJECT

## Commands
- Setup: `make setup`
- Dev: `make dev`
- Test: `make test`
- Lint: `make lint`
- Typecheck: `make typecheck`
- Security: `make security`
- Build: `make build`
- Quality gate: `make check`
- Release: `make release`

## Next 3 improvements
1. Optionally surface violation summaries in `report` output (HTML/JSON) to aid rollout triage.
2. Expand `violations` parsing coverage with more real-world schema variants (while staying strict by default).
3. Add a baseline update workflow for teams managing long-lived snapshots.
