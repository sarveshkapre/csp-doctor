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

Tip: You can also paste a full header line (e.g. `Content-Security-Policy: ...`) or pipe via stdin:

```bash
echo "Content-Security-Policy: default-src 'self'; script-src 'self'" | csp-doctor analyze --stdin
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

Normalize a CSP for stable diffs:

```bash
csp-doctor normalize --csp "script-src cdn.example.com 'self'; default-src 'self'"
```

Pick a color preset for CLI output:

```bash
csp-doctor analyze --csp "default-src 'self'" --color-preset vivid
```

Export an HTML report:

```bash
csp-doctor report --csp "default-src 'self'" --output report.html
```

Pick a report theme (light/dark/system):

```bash
csp-doctor report --csp "default-src 'self'" --theme dark --output report.html
```

Diff a proposed CSP against a baseline:

```bash
csp-doctor diff --baseline-file baseline.txt --csp "default-src 'self'; frame-ancestors 'none'"
```

Save a baseline snapshot and reuse it later:

```bash
csp-doctor diff --baseline "default-src 'self'" --csp "default-src 'self'" --baseline-out baseline.json
csp-doctor diff --baseline-json baseline.json --csp "default-src 'self'; frame-ancestors 'none'"
```

Print JSON Schema for machine-readable outputs:

```bash
csp-doctor schema --kind all
```

Generate a report-only header:

```bash
csp-doctor report-only --csp "default-src 'self'; script-src 'self'" --report-uri /csp-report
```

Generate a Report-To header template alongside report-only output:

```bash
csp-doctor report-only --csp "default-src 'self'" --report-to-group csp \
  --report-to-endpoint https://example.com/csp-report --report-to-header
```

Emit a copy/paste-ready Report-Only header line:

```bash
csp-doctor report-only --csp "default-src 'self'" --report-uri /csp-report --full-header
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
