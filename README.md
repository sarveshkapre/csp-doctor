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

Tune findings for your rollout stage:

```bash
csp-doctor analyze --csp "default-src 'self'; script-src 'self'" --profile strict
```

Suppress known-acceptable findings:

```bash
csp-doctor analyze --csp "default-src 'self'" --suppress missing-reporting
```

Suppress findings via a file:

```bash
csp-doctor analyze --csp "default-src 'self'" --suppress-file docs/csp-doctor.suppressions.example
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

Export findings as SARIF for security tooling:

```bash
csp-doctor analyze --csp "default-src 'self'" --format sarif --output csp-doctor.sarif
```

Publish SARIF to GitHub Code Scanning:

See `docs/CODE_SCANNING.md` for a copy/paste workflow snippet.

Gate CI on finding severity:

```bash
csp-doctor analyze --csp "default-src 'self'" --format sarif --output csp-doctor.sarif --fail-on medium
```

Export an HTML report:

```bash
csp-doctor report --csp "default-src 'self'" --output report.html
```

Export a PDF report (optional dependency):

```bash
pip install -e .[pdf]
csp-doctor report --csp "default-src 'self'" --format pdf --output report.pdf
```

Pick a report theme (light/dark/system):

```bash
csp-doctor report --csp "default-src 'self'" --theme dark --output report.html
```

Pick a report template (classic/glass/minimal):

```bash
csp-doctor report --csp "default-src 'self'" --template glass --output report.html
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

Baseline snapshots include a `schemaVersion` field for future compatibility.

Optionally label baseline snapshots with an environment (staging/prod) and enforce it when loading:

```bash
csp-doctor diff --baseline "default-src 'self'" --csp "default-src 'self'" --baseline-env staging --baseline-out baseline.json
csp-doctor diff --baseline-json baseline.json --baseline-env staging --csp "default-src 'self'; frame-ancestors 'none'"
```

Print JSON Schema for machine-readable outputs:

```bash
csp-doctor schema --kind all
```

Explain a finding key (and list known keys/patterns):

```bash
csp-doctor explain missing-reporting
csp-doctor explain --list
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
