# SECURITY

## Reporting
If you discover a security issue, please open a private disclosure channel or email the maintainer.

## Threat model (summary)
- Input is untrusted policy text; parsing must be robust.
- Output is advisory; incorrect recommendations could cause CSP breakage.

## Mitigations
- Strict parsing with clear error messages.
- Conservative defaults and guidance.
