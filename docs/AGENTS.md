# AGENTS

## Working agreements
- Default to the smallest safe change.
- Keep the CLI local-first and dependency-light.
- Update docs/CHANGELOG.md for user-visible changes.

## Commands
- Setup: `make setup`
- Tests: `make test`
- Lint: `make lint`
- Typecheck: `make typecheck`
- Security: `make security`
- Build: `make build`
- Quality gate: `make check`

## Conventions
- Python 3.11+
- Runtime dependencies should stay optional.
- Prefer pure standard library unless a dependency is clearly justified.
