# SARIF Upload Guide

Use `csp-doctor` SARIF output with GitHub Code Scanning so CSP findings show in the repository Security tab.

## Local generation

```bash
csp-doctor analyze --csp "default-src 'self'" --format sarif > csp-doctor.sarif
```

## GitHub Actions example

```yaml
name: CSP Doctor Scan

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  csp-doctor:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install csp-doctor
        run: |
          python -m pip install --upgrade pip
          pip install csp-doctor

      - name: Generate SARIF
        run: |
          csp-doctor analyze \
            --csp "default-src 'self'; script-src 'self'" \
            --profile recommended \
            --format sarif > csp-doctor.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: csp-doctor.sarif
```

## Notes

- The workflow needs `security-events: write` to upload SARIF.
- For repository policies stored in files, replace `--csp "..."`
  with `--file path/to/policy.txt`.
