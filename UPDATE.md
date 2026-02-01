# UPDATE

## What shipped
- `analyze`: accepts CSP via stdin (`--stdin` / `--csp -`) and header-line input (e.g. `Content-Security-Policy: ...`).
- Improved analysis coverage: flags missing `frame-ancestors`, `base-uri`, `object-src`, and `upgrade-insecure-requests`.
- Polished CLI text output: severity summary + optional color (`analyze --color auto|always|never`).
- `report-only`: new `--full-header` for a copy/paste-ready header line.

## How to verify
```bash
make check
```

## PR instructions
PR: https://github.com/sarveshkapre/csp-doctor/pull/1
