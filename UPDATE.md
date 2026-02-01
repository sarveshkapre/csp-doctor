# UPDATE

## What shipped
- `analyze`: accepts CSP via stdin (`--stdin` / `--csp -`) and header-line input (e.g. `Content-Security-Policy: ...`).
- Improved analysis coverage: flags missing `frame-ancestors`, `base-uri`, `object-src`, and `upgrade-insecure-requests`.
- Polished CLI text output: severity summary + optional color (`analyze --color auto|always|never`).
- New `diff` command to compare a CSP against a baseline (`diff --baseline-file ...`).
- New `schema` command for JSON output schemas (`schema --kind all`).
- New CSP Level 3 checks for `require-trusted-types-for` and `trusted-types`.
- New Report-To header template generation for report-only workflows.
- `report-only`: new `--full-header` for a copy/paste-ready header line.

## How to verify
```bash
make check
```

## Notes
- Working directly on `main` (no PR created/updated).
