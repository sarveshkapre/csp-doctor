# CI Integration

This page provides copy/paste-friendly snippets for running `csp-doctor` in CI.

## Recommended pattern

1. Store a baseline CSP snapshot in-repo (or generate it from a known-good policy).
2. In CI, diff a proposed policy against the baseline.
3. Gate only on regressions (added findings and severity escalations) using `--fail-on`.

Examples:

```bash
# One-time (or during intentional baseline updates)
csp-doctor diff --baseline-file baseline.txt --csp "default-src 'self'" --baseline-out baseline.json

# CI gating for a proposed policy
csp-doctor diff --baseline-json baseline.json --csp "$PROPOSED_CSP" --format json --output csp-diff.json --fail-on medium

# Optional: produce a single JSON artifact aligned with the HTML report
csp-doctor report --csp "$PROPOSED_CSP" --format json --output csp-report.json
```

If you prefer gating on the full set of findings (not just regressions), use `analyze`:

```bash
csp-doctor analyze --csp "$PROPOSED_CSP" --format sarif --output csp-doctor.sarif --fail-on medium
```

## GitLab CI

```yaml
stages: [test]

csp_doctor:
  image: python:3.11-slim
  stage: test
  script:
    - python -m pip install --upgrade pip
    - pip install csp-doctor
    # Prefer diff-based gating if you have a baseline snapshot committed.
    - csp-doctor diff --baseline-json baseline.json --csp "$PROPOSED_CSP" --format json --output csp-diff.json --fail-on medium
  artifacts:
    when: always
    paths:
      - csp-diff.json
```

## CircleCI

```yaml
version: 2.1

jobs:
  csp_doctor:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install csp-doctor
          command: |
            python -m pip install --upgrade pip
            pip install csp-doctor
      - run:
          name: CSP diff gate
          command: |
            csp-doctor diff --baseline-json baseline.json --csp "$PROPOSED_CSP" --format json --output csp-diff.json --fail-on medium
      - store_artifacts:
          path: csp-diff.json
          destination: csp-diff.json
```

## Notes

- `--fail-on` exits with code `1` when the threshold is met.
- `diff --fail-on` considers only regressions: added findings and severity escalations.
- `analyze --fail-on` considers the full set of findings after suppressions.
