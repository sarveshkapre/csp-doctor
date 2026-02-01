# CSP Doctor

CSP Doctor is a local-first CLI that analyzes Content-Security-Policy headers and generates a safe rollout plan, including a report-only policy you can deploy to gather violations before enforcement.

## Why
- Spot risky CSP patterns (unsafe-inline, wildcard sources, missing defaults).
- Create a practical rollout checklist for teams.
- Generate a report-only header in seconds.

## Quickstart

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]

csp-doctor analyze --csp "default-src 'self'; script-src 'self'"
```

## Examples

Analyze a policy:

```bash
csp-doctor analyze --csp "default-src 'self'; script-src 'self' cdn.example.com"
```

Generate a rollout plan:

```bash
csp-doctor rollout --csp "default-src 'self'; script-src 'self'"
```

Generate a report-only header:

```bash
csp-doctor report-only --csp "default-src 'self'; script-src 'self'" --report-uri /csp-report
```

## Docker

```bash
docker build -t csp-doctor .
docker run --rm csp-doctor analyze --csp "default-src 'self'"
```

## Documentation

All project docs (plan, roadmap, security, contributing, etc.) live in `docs/`.

## Security

This tool does not make network calls. You are responsible for validating and testing CSP changes in your environment before enforcement.

## License

MIT
