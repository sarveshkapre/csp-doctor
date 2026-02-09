from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal, cast

RiskProfile = Literal["strict", "recommended", "legacy"]
RISK_PROFILES: tuple[RiskProfile, ...] = ("strict", "recommended", "legacy")


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


@dataclass(frozen=True)
class DiffResult:
    baseline_directives: dict[str, list[str]]
    directives: dict[str, list[str]]
    added_directives: list[str]
    removed_directives: list[str]
    changed_directives: dict[str, dict[str, list[str]]]
    added_findings: list[Finding]
    removed_findings: list[Finding]
    severity_changes: list[dict[str, str]]


@dataclass(frozen=True)
class BaselineSnapshot:
    directives: dict[str, list[str]]
    findings: list[Finding]
    profile: RiskProfile = "recommended"

def normalize_policy_input(text: str) -> str:
    """Normalize various CSP input forms into a raw policy string.

    Accepts either a CSP value (e.g. "default-src 'self'; ...") or a header line
    (e.g. "Content-Security-Policy: default-src 'self'; ...").
    """

    stripped = text.strip()
    if not stripped:
        return ""

    header_names = {
        "content-security-policy",
        "content-security-policy-report-only",
    }

    for line in stripped.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() in header_names:
            return value.strip()

    lower = stripped.lower()
    for header_prefix in (
        "content-security-policy-report-only:",
        "content-security-policy:",
    ):
        index = lower.find(header_prefix)
        if index != -1:
            return stripped[index + len(header_prefix) :].strip()

    return stripped


def parse_csp(policy: str) -> dict[str, list[str]]:
    cleaned = normalize_policy_input(policy).strip().strip(";")
    if not cleaned:
        return {}

    directives: dict[str, list[str]] = {}
    for raw in cleaned.split(";"):
        part = raw.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        if name in directives:
            # Browsers ignore duplicate directives after the first occurrence.
            continue
        values = [token.strip() for token in tokens[1:]]
        directives[name] = values
    return directives


def analyze_policy(policy: str, *, profile: RiskProfile = "recommended") -> AnalysisResult:
    resolved_profile = _validate_risk_profile(profile)
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

    default_values = [value.lower() for value in directives.get("default-src", [])]

    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                key="missing-frame-ancestors",
                severity="medium",
                title="Missing frame-ancestors",
                detail=(
                    "Without frame-ancestors, your site may be embeddable and vulnerable to "
                    "clickjacking."
                ),
            )
        )

    if "object-src" not in directives:
        severity = "low" if "'none'" in default_values else "medium"
        findings.append(
            Finding(
                key="missing-object-src",
                severity=severity,
                title="Missing object-src",
                detail="Prefer setting object-src 'none' to disable plugins.",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                key="missing-base-uri",
                severity="low",
                title="Missing base-uri",
                detail="Restrict base-uri (often base-uri 'none') to reduce tag injection abuse.",
            )
        )

    if "form-action" not in directives:
        findings.append(
            Finding(
                key="missing-form-action",
                severity="medium",
                title="Missing form-action",
                detail=(
                    "Set form-action to trusted origins (for example 'self') to reduce form "
                    "post hijacking risk."
                ),
            )
        )

    if "upgrade-insecure-requests" not in directives:
        findings.append(
            Finding(
                key="missing-upgrade-insecure-requests",
                severity="low",
                title="Missing upgrade-insecure-requests",
                detail="Consider upgrade-insecure-requests to reduce mixed-content risk.",
            )
        )

    if "require-trusted-types-for" not in directives:
        findings.append(
            Finding(
                key="missing-require-trusted-types-for",
                severity="medium",
                title="Missing require-trusted-types-for",
                detail=(
                    "Consider require-trusted-types-for 'script' to reduce DOM XSS risk."
                ),
            )
        )

    if "trusted-types" not in directives:
        findings.append(
            Finding(
                key="missing-trusted-types",
                severity="low",
                title="Missing trusted-types",
                detail="Define trusted-types policies to harden script sinks.",
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

    findings = _apply_risk_profile(findings, profile=resolved_profile)
    return AnalysisResult(directives=directives, findings=findings)


def diff_policies(
    *,
    baseline_policy: str,
    policy: str,
    profile: RiskProfile = "recommended",
) -> DiffResult:
    resolved_profile = _validate_risk_profile(profile)
    baseline = analyze_policy(baseline_policy, profile=resolved_profile)
    baseline_directives = baseline.directives

    return diff_against_snapshot(
        snapshot=BaselineSnapshot(
            directives=baseline_directives,
            findings=baseline.findings,
            profile=resolved_profile,
        ),
        policy=policy,
        profile=resolved_profile,
    )


def create_baseline_snapshot(
    policy: str,
    *,
    profile: RiskProfile = "recommended",
) -> BaselineSnapshot:
    resolved_profile = _validate_risk_profile(profile)
    result = analyze_policy(policy, profile=resolved_profile)
    return BaselineSnapshot(
        directives=result.directives,
        findings=result.findings,
        profile=resolved_profile,
    )


def diff_against_snapshot(
    *,
    snapshot: BaselineSnapshot,
    policy: str,
    profile: RiskProfile | None = None,
) -> DiffResult:
    snapshot_profile = _validate_risk_profile(snapshot.profile)
    resolved_profile = snapshot_profile if profile is None else _validate_risk_profile(profile)
    current = analyze_policy(policy, profile=resolved_profile)
    baseline_directives = snapshot.directives
    directives = current.directives

    baseline_keys = set(baseline_directives)
    current_keys = set(directives)

    added_directives = sorted(current_keys - baseline_keys)
    removed_directives = sorted(baseline_keys - current_keys)

    changed_directives: dict[str, dict[str, list[str]]] = {}
    for key in sorted(baseline_keys & current_keys):
        before_values = baseline_directives[key]
        after_values = directives[key]
        if before_values == after_values:
            continue
        before_set = set(before_values)
        after_set = set(after_values)
        changed_directives[key] = {
            "added": sorted(after_set - before_set),
            "removed": sorted(before_set - after_set),
            "before": list(before_values),
            "after": list(after_values),
        }

    baseline_findings = {finding.key: finding for finding in snapshot.findings}
    current_findings = {finding.key: finding for finding in current.findings}

    added_keys = sorted(set(current_findings) - set(baseline_findings))
    removed_keys = sorted(set(baseline_findings) - set(current_findings))

    added_findings = [current_findings[key] for key in added_keys]
    removed_findings = [baseline_findings[key] for key in removed_keys]

    severity_changes: list[dict[str, str]] = []
    for key in sorted(set(baseline_findings) & set(current_findings)):
        before_finding = baseline_findings[key]
        after_finding = current_findings[key]
        if before_finding.severity != after_finding.severity:
            severity_changes.append(
                {
                    "key": key,
                    "from": before_finding.severity,
                    "to": after_finding.severity,
                    "title": after_finding.title,
                }
            )

    return DiffResult(
        baseline_directives=baseline_directives,
        directives=directives,
        added_directives=added_directives,
        removed_directives=removed_directives,
        changed_directives=changed_directives,
        added_findings=added_findings,
        removed_findings=removed_findings,
        severity_changes=severity_changes,
    )


_PROFILE_DISABLED_KEYS: dict[RiskProfile, set[str]] = {
    "strict": set(),
    "recommended": set(),
    "legacy": {
        "missing-require-trusted-types-for",
        "missing-trusted-types",
        "script-src-missing-strict-dynamic",
        "missing-upgrade-insecure-requests",
    },
}

_PROFILE_SEVERITY_OVERRIDES: dict[RiskProfile, dict[str, str]] = {
    "strict": {
        "missing-frame-ancestors": "high",
        "missing-object-src": "high",
        "missing-base-uri": "medium",
        "missing-form-action": "high",
        "missing-upgrade-insecure-requests": "medium",
        "missing-require-trusted-types-for": "high",
        "missing-trusted-types": "medium",
        "script-src-missing-nonce-hash": "high",
        "script-src-missing-strict-dynamic": "medium",
    },
    "recommended": {},
    "legacy": {
        "missing-form-action": "low",
        "script-src-missing-nonce-hash": "low",
    },
}


def _validate_risk_profile(profile: str) -> RiskProfile:
    if profile not in RISK_PROFILES:
        values = ", ".join(RISK_PROFILES)
        raise ValueError(f"Unsupported profile '{profile}'. Expected one of: {values}")
    return cast(RiskProfile, profile)


def _apply_risk_profile(findings: list[Finding], *, profile: RiskProfile) -> list[Finding]:
    if profile == "recommended":
        return findings

    disabled = _PROFILE_DISABLED_KEYS[profile]
    adjusted: list[Finding] = []
    for finding in findings:
        if finding.key in disabled:
            continue

        severity = _severity_for_profile(finding=finding, profile=profile)
        if severity == finding.severity:
            adjusted.append(finding)
            continue

        adjusted.append(
            Finding(
                key=finding.key,
                severity=severity,
                title=finding.title,
                detail=finding.detail,
                evidence=finding.evidence,
            )
        )

    return adjusted


def _severity_for_profile(*, finding: Finding, profile: RiskProfile) -> str:
    explicit = _PROFILE_SEVERITY_OVERRIDES[profile].get(finding.key)
    if explicit:
        return explicit

    if profile == "strict":
        if finding.key.endswith(("-wildcard", "-http-scheme", "-data-scheme")):
            return "high"
        if finding.key.endswith("-blob-scheme"):
            return "medium"

    return finding.severity


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
    report_to_endpoints: list[str] | None = None,
    report_to_max_age: int | None = None,
    report_to_include_subdomains: bool = False,
) -> tuple[str, list[str]]:
    updated = {key: list(values) for key, values in directives.items()}
    notes: list[str] = []
    report_to_header: str | None = None

    if report_to_group:
        updated["report-to"] = [report_to_group]
        report_to_header = build_report_to_header(
            report_to_group,
            endpoints=report_to_endpoints,
            max_age=report_to_max_age,
            include_subdomains=report_to_include_subdomains,
        )
        if report_to_header:
            notes.append("Add the Report-To header below to enable reporting.")
        else:
            notes.append(
                "Add a Report-To header JSON configuration matching the group name."
            )
    elif report_uri:
        updated["report-uri"] = [report_uri]
    else:
        notes.append("No reporting endpoint provided; violations will be lost.")

    header = serialize_policy(updated)
    if report_to_header:
        notes.append(report_to_header)
    return header, notes


def build_report_to_header(
    group: str,
    *,
    endpoints: list[str] | None,
    max_age: int | None,
    include_subdomains: bool = False,
) -> str | None:
    if not group:
        return None
    if not endpoints:
        return None

    max_age_value = max_age if max_age is not None else 10886400
    payload = {
        "group": group,
        "max_age": max_age_value,
        "endpoints": [{"url": endpoint} for endpoint in endpoints],
    }
    if include_subdomains:
        payload["include_subdomains"] = True

    return f"Report-To: {json.dumps(payload, separators=(',', ':'))}"


def serialize_policy(directives: Mapping[str, Iterable[str]]) -> str:
    parts: list[str] = []
    for directive, values in directives.items():
        joined = " ".join(values).strip()
        if joined:
            parts.append(f"{directive} {joined}")
        else:
            parts.append(directive)
    return "; ".join(parts)


def normalize_policy(
    policy: str,
    *,
    sort_sources: bool = True,
    sort_directives: bool = True,
) -> str:
    directives = parse_csp(policy)
    items = directives.items()
    ordered_items = sorted(items, key=lambda item: item[0]) if sort_directives else items

    normalized: dict[str, list[str]] = {}
    for directive, values in ordered_items:
        if sort_sources:
            normalized[directive] = sorted(values)
        else:
            normalized[directive] = list(values)

    return serialize_policy(normalized)


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
