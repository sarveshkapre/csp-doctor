from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    key: str
    severity: str
    title: str
    detail: str
    evidence: str | None = None


@dataclass(frozen=True)
class AnalysisResult:
    directives: dict[str, list[str]]
    findings: list[Finding]


def parse_csp(policy: str) -> dict[str, list[str]]:
    cleaned = policy.strip().strip(";")
    if not cleaned:
        return {}

    directives: dict[str, list[str]] = {}
    for raw in cleaned.split(";"):
        part = raw.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = [token.strip() for token in tokens[1:]]
        directives[name] = values
    return directives


def analyze_policy(policy: str) -> AnalysisResult:
    directives = parse_csp(policy)
    findings: list[Finding] = []

    if not directives:
        findings.append(
            Finding(
                key="empty-policy",
                severity="high",
                title="Empty CSP",
                detail="No directives detected; CSP is effectively disabled.",
            )
        )
        return AnalysisResult(directives=directives, findings=findings)

    if "default-src" not in directives:
        findings.append(
            Finding(
                key="missing-default-src",
                severity="high",
                title="Missing default-src",
                detail="Without default-src, browsers fall back to permissive defaults.",
            )
        )

    for directive, values in directives.items():
        findings.extend(_analyze_directive(directive, values))

    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(
            Finding(
                key="missing-reporting",
                severity="medium",
                title="No reporting endpoint configured",
                detail=(
                    "Add report-uri or report-to to capture violations during rollout."
                ),
            )
        )

    return AnalysisResult(directives=directives, findings=findings)


def rollout_plan(directives: dict[str, list[str]]) -> list[str]:
    plan = [
        "Inventory current CSP usage and collect baseline violations.",
        "Deploy the policy in Report-Only mode for at least 7 days.",
        "Triage violations: allow only required sources, remove noise.",
        "Harden high-risk directives (script-src, object-src, base-uri).",
        "Roll out enforced CSP with monitoring and rollback plan.",
    ]

    if "report-uri" not in directives and "report-to" not in directives:
        plan.insert(
            1,
            "Stand up a reporting endpoint (report-uri or report-to) before rollout.",
        )
    return plan


def generate_report_only(
    directives: dict[str, list[str]],
    *,
    report_uri: str | None,
    report_to_group: str | None,
) -> tuple[str, list[str]]:
    updated = {key: list(values) for key, values in directives.items()}
    notes: list[str] = []

    if report_to_group:
        updated["report-to"] = [report_to_group]
        notes.append(
            "Add a Report-To header JSON configuration matching the group name."
        )
    elif report_uri:
        updated["report-uri"] = [report_uri]
    else:
        notes.append("No reporting endpoint provided; violations will be lost.")

    header = serialize_policy(updated)
    return header, notes


def serialize_policy(directives: dict[str, Iterable[str]]) -> str:
    parts: list[str] = []
    for directive, values in directives.items():
        joined = " ".join(values).strip()
        if joined:
            parts.append(f"{directive} {joined}")
        else:
            parts.append(directive)
    return "; ".join(parts)


def _analyze_directive(directive: str, values: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    lower_values = [value.lower() for value in values]

    if "'unsafe-inline'" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-unsafe-inline",
                severity="high",
                title="unsafe-inline enabled",
                detail=(
                    "Inline scripts/styles can bypass CSP and enable XSS."
                ),
                evidence=directive,
            )
        )

    if "'unsafe-eval'" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-unsafe-eval",
                severity="high",
                title="unsafe-eval enabled",
                detail="Eval-like APIs are allowed; prefer hashes or nonces.",
                evidence=directive,
            )
        )

    if "*" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-wildcard",
                severity="medium",
                title="Wildcard source",
                detail="Wildcard sources allow unexpected origins.",
                evidence=directive,
            )
        )

    if "http:" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-http-scheme",
                severity="medium",
                title="HTTP scheme allowed",
                detail="Allowing http: weakens transport security.",
                evidence=directive,
            )
        )

    if "data:" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-data-scheme",
                severity="medium",
                title="data: scheme allowed",
                detail="data: can embed executable content.",
                evidence=directive,
            )
        )

    if "blob:" in lower_values:
        findings.append(
            Finding(
                key=f"{directive}-blob-scheme",
                severity="low",
                title="blob: scheme allowed",
                detail="blob: can be abused if combined with other weaknesses.",
                evidence=directive,
            )
        )

    if directive == "script-src":
        if not any(value.startswith("'nonce-") for value in lower_values) and not any(
            value.startswith("'sha") for value in lower_values
        ):
            findings.append(
                Finding(
                    key="script-src-missing-nonce-hash",
                    severity="medium",
                    title="No nonces or hashes",
                    detail="Prefer nonces/hashes for inline script allowances.",
                    evidence=directive,
                )
            )
        if "'strict-dynamic'" not in lower_values and "strict-dynamic" not in lower_values:
            findings.append(
                Finding(
                    key="script-src-missing-strict-dynamic",
                    severity="low",
                    title="No strict-dynamic",
                    detail="Consider strict-dynamic for modern script loading patterns.",
                    evidence=directive,
                )
            )

    if directive == "object-src" and "'none'" not in lower_values:
        findings.append(
            Finding(
                key="object-src-not-none",
                severity="medium",
                title="object-src not set to 'none'",
                detail="Plugins are rarely needed; set object-src 'none' if possible.",
                evidence=directive,
            )
        )

    if directive == "base-uri" and "'none'" not in lower_values:
        findings.append(
            Finding(
                key="base-uri-not-none",
                severity="low",
                title="base-uri not restricted",
                detail="Restrict base-uri to prevent tag injection abuse.",
                evidence=directive,
            )
        )

    return findings
