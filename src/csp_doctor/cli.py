from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Literal, cast

from csp_doctor.core import (
    RISK_PROFILES,
    BaselineSnapshot,
    DiffResult,
    Finding,
    RiskProfile,
    analyze_policy,
    build_report_to_header,
    create_baseline_snapshot,
    diff_against_snapshot,
    diff_policies,
    generate_report_only,
    normalize_policy,
    rollout_plan,
)
from csp_doctor.schema import get_schema
from csp_doctor.style import COLOR_PRESETS, REPORT_TEMPLATES, THEME_OVERRIDES, ThemeName
from csp_doctor.violations import load_violation_events, summarize_violation_events


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="csp-doctor",
        description="Analyze CSP headers and generate rollout guidance.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a CSP policy")
    _add_csp_input_args(analyze_parser)
    analyze_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize text output (JSON is never colorized)",
    )
    analyze_parser.add_argument(
        "--color-preset",
        choices=sorted(COLOR_PRESETS),
        default="default",
        help="Color preset for severity labels",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (text/json/sarif)",
    )
    analyze_parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON/SARIF output to this file (defaults to stdout)",
    )
    _add_profile_arg(analyze_parser)
    _add_suppression_args(analyze_parser)
    _add_fail_on_arg(analyze_parser)

    rollout_parser = subparsers.add_parser(
        "rollout", help="Generate a CSP rollout plan"
    )
    _add_csp_input_args(rollout_parser)
    rollout_parser.add_argument(
        "--violations-file",
        type=Path,
        help=(
            "Path to CSP violation report samples (JSON or newline-delimited JSON) to "
            "summarize and aid rollout tuning"
        ),
    )

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Normalize a CSP by sorting directives and sources",
    )
    _add_csp_input_args(normalize_parser)
    normalize_parser.add_argument(
        "--keep-order",
        action="store_true",
        help="Preserve original directive/source order",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Generate an HTML report for a CSP analysis",
    )
    _add_csp_input_args(report_parser)
    report_parser.add_argument(
        "--output",
        type=Path,
        help="Write report output (HTML/JSON) to this file (defaults to stdout)",
    )
    report_parser.add_argument(
        "--format",
        choices=["html", "pdf", "json"],
        default="html",
        help="Output format (html/pdf/json)",
    )
    report_parser.add_argument(
        "--theme",
        choices=["system", "light", "dark"],
        default="system",
        help="Theme for HTML report",
    )
    report_parser.add_argument(
        "--template",
        choices=sorted(REPORT_TEMPLATES),
        default="classic",
        help="Report HTML template style",
    )
    _add_profile_arg(report_parser)
    _add_suppression_args(report_parser)
    _add_fail_on_arg(report_parser)

    schema_parser = subparsers.add_parser(
        "schema",
        help="Print JSON Schema for csp-doctor JSON outputs",
    )
    schema_parser.add_argument(
        "--kind",
        choices=["all", "analyze", "diff", "report"],
        default="all",
        help="Which schema to print",
    )

    explain_parser = subparsers.add_parser(
        "explain",
        help="Explain a finding key (use --list to see common keys)",
    )
    explain_parser.add_argument(
        "key",
        nargs="?",
        help="Finding key to explain (example: missing-reporting)",
    )
    explain_parser.add_argument(
        "--list",
        action="store_true",
        help="List known finding keys and key patterns",
    )
    explain_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    explain_parser.add_argument(
        "--profile",
        choices=list(RISK_PROFILES),
        default="recommended",
        help="Profile to explain under (affects severity and suppression)",
    )

    violations_parser = subparsers.add_parser(
        "violations",
        help="Summarize CSP violation report samples (legacy report-uri and Reporting API)",
    )
    violations_parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="Path to a JSON/NDJSON file containing CSP violation report objects",
    )
    violations_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    violations_parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top directives to show",
    )
    violations_parser.add_argument(
        "--top-origins",
        type=int,
        default=5,
        help="Number of top blocked origins to show per directive",
    )

    diff_parser = subparsers.add_parser(
        "diff",
        help="Diff a CSP against a baseline (useful for rollout hardening)",
    )
    _add_csp_input_args(diff_parser)
    diff_parser.add_argument(
        "--baseline",
        help="Baseline CSP policy string (or header line)",
    )
    diff_parser.add_argument(
        "--baseline-file",
        type=Path,
        help="Path to a file containing the baseline CSP value",
    )
    diff_parser.add_argument(
        "--baseline-json",
        type=Path,
        help="Path to a baseline JSON snapshot file",
    )
    diff_parser.add_argument(
        "--baseline-out",
        type=Path,
        help="Write a baseline JSON snapshot to this path",
    )
    diff_parser.add_argument(
        "--baseline-env",
        help=(
            "Environment label for baseline snapshots (written to --baseline-out, and if "
            "used with --baseline-json it must match the snapshot's environment)"
        ),
    )
    diff_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    diff_parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON output to this file (defaults to stdout)",
    )
    diff_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize text output (JSON is never colorized)",
    )
    diff_parser.add_argument(
        "--color-preset",
        choices=sorted(COLOR_PRESETS),
        default="default",
        help="Color preset for severity labels",
    )
    _add_profile_arg(diff_parser)
    _add_suppression_args(diff_parser)
    _add_fail_on_arg(diff_parser)

    report_only_parser = subparsers.add_parser(
        "report-only", help="Generate a Report-Only CSP header"
    )
    _add_csp_input_args(report_only_parser)
    report_only_parser.add_argument(
        "--report-uri",
        help="Report URI endpoint (report-uri directive)",
    )
    report_only_parser.add_argument(
        "--report-to-group",
        help="Report-To group name (report-to directive)",
    )
    report_only_parser.add_argument(
        "--report-to-endpoint",
        action="append",
        help="Report-To endpoint URL (repeatable)",
    )
    report_only_parser.add_argument(
        "--report-to-max-age",
        type=int,
        help="Report-To max_age in seconds (default: 10886400)",
    )
    report_only_parser.add_argument(
        "--report-to-include-subdomains",
        action="store_true",
        help="Set include_subdomains for Report-To",
    )
    report_only_parser.add_argument(
        "--report-to-header",
        action="store_true",
        help="Print the Report-To header JSON (requires --report-to-endpoint)",
    )
    report_only_parser.add_argument(
        "--full-header",
        action="store_true",
        help="Emit a full header line (Content-Security-Policy-Report-Only: ...)",
    )

    args = parser.parse_args()

    if args.command == "schema":
        kind = cast(Literal["all", "analyze", "diff", "report"], args.kind)
        schema = get_schema(kind)
        print(json.dumps(schema, indent=2))
        return

    if args.command == "explain":
        _handle_explain(args)
        return

    if args.command == "violations":
        _handle_violations(args)
        return

    policy = _load_policy(args)

    if args.command == "analyze":
        profile = _get_profile(args)
        analysis_result = analyze_policy(policy, profile=profile)
        suppressions = _load_suppressions(args)
        findings, suppressed_count = _apply_suppressions(
            analysis_result.findings, suppressions
        )
        if args.output and args.format == "text":
            print("--output requires --format json or sarif", file=sys.stderr)
            raise SystemExit(2)
        if args.format == "json":
            payload = {
                "directives": analysis_result.directives,
                "findings": [asdict(finding) for finding in findings],
            }
            rendered = json.dumps(payload, indent=2) + "\n"
            if args.output:
                _write_output_file(cast(Path, args.output), rendered)
            else:
                print(rendered, end="")
            _enforce_fail_on_findings(args.fail_on, findings)
            return
        if args.format == "sarif":
            sarif_payload = _build_sarif_report(
                policy=policy,
                directives=analysis_result.directives,
                findings=findings,
            )
            rendered = json.dumps(sarif_payload, indent=2) + "\n"
            if args.output:
                _write_output_file(cast(Path, args.output), rendered)
            else:
                print(rendered, end="")
            _enforce_fail_on_findings(args.fail_on, findings)
            return
        _print_analysis(
            analysis_result.directives,
            findings,
            color=_should_color(args.color),
            color_preset=args.color_preset,
            suppressed_count=suppressed_count,
        )
        _enforce_fail_on_findings(args.fail_on, findings)
        return

    if args.command == "rollout":
        directives = analyze_policy(policy).directives
        plan = rollout_plan(directives)
        _print_rollout(plan)
        violations_file = cast(Path | None, getattr(args, "violations_file", None))
        if violations_file:
            _print_violations_for_rollout(violations_file)
        return

    if args.command == "normalize":
        normalized = normalize_policy(
            policy,
            sort_sources=not args.keep_order,
            sort_directives=not args.keep_order,
        )
        print(normalized)
        return

    if args.command == "report":
        profile = _get_profile(args)
        analysis_result = analyze_policy(policy, profile=profile)
        suppressions = _load_suppressions(args)
        findings, _suppressed_count = _apply_suppressions(
            analysis_result.findings, suppressions
        )
        report_format = cast(str, args.format)
        if report_format == "json":
            report_payload = _build_report_json(
                policy=policy,
                directives=analysis_result.directives,
                findings=findings,
                profile=profile,
                theme=cast(ThemeName, args.theme),
                template=args.template,
            )
            rendered = json.dumps(report_payload, indent=2) + "\n"
            if args.output:
                _write_output_file(cast(Path, args.output), rendered)
            else:
                print(rendered, end="")
        elif report_format == "pdf":
            if not args.output:
                print("--format pdf requires --output", file=sys.stderr)
                raise SystemExit(2)
            html = _render_html_report(
                policy=policy,
                directives=analysis_result.directives,
                findings=findings,
                theme=cast(ThemeName, args.theme),
                template=args.template,
            )
            pdf_bytes = _render_pdf_from_html(html)
            _write_output_bytes(cast(Path, args.output), pdf_bytes)
        else:
            html = _render_html_report(
                policy=policy,
                directives=analysis_result.directives,
                findings=findings,
                theme=cast(ThemeName, args.theme),
                template=args.template,
            )
            if args.output:
                _write_output_file(cast(Path, args.output), html)
            else:
                print(html)
        _enforce_fail_on_findings(args.fail_on, findings)
        return

    if args.command == "diff":
        profile = _get_profile(args)
        baseline_env = cast(str | None, getattr(args, "baseline_env", None))
        snapshot = _load_baseline_snapshot(
            args,
            expected_profile=profile,
            expected_environment=baseline_env,
        )
        baseline_policy: str | None = None
        if snapshot:
            diff_result = diff_against_snapshot(
                snapshot=snapshot,
                policy=policy,
                profile=profile,
            )
        else:
            baseline_policy = _load_baseline_policy(args)
            diff_result = diff_policies(
                baseline_policy=baseline_policy,
                policy=policy,
                profile=profile,
            )

        suppressions = _load_suppressions(args)
        diff_result = _apply_suppressions_to_diff(diff_result, suppressions)

        if args.output and args.format != "json":
            print("--output requires --format json", file=sys.stderr)
            raise SystemExit(2)

        if args.baseline_out:
            output_path = cast(Path, args.baseline_out)
            if snapshot:
                _write_baseline_snapshot_from_snapshot(output_path, snapshot)
            else:
                baseline_text = (
                    baseline_policy
                    if baseline_policy is not None
                    else _load_baseline_policy(args)
                )
                _write_baseline_snapshot(
                    output_path,
                    baseline_text,
                    profile=profile,
                    environment=baseline_env,
                )

        if args.format == "json":
            payload = {
                "baseline_directives": diff_result.baseline_directives,
                "directives": diff_result.directives,
                "added_directives": diff_result.added_directives,
                "removed_directives": diff_result.removed_directives,
                "changed_directives": diff_result.changed_directives,
                "added_findings": [
                    asdict(finding) for finding in diff_result.added_findings
                ],
                "removed_findings": [
                    asdict(finding) for finding in diff_result.removed_findings
                ],
                "severity_changes": diff_result.severity_changes,
            }
            rendered = json.dumps(payload, indent=2) + "\n"
            if args.output:
                _write_output_file(cast(Path, args.output), rendered)
            else:
                print(rendered, end="")
            _enforce_fail_on_diff(args.fail_on, diff_result)
            return
        _print_diff(
            diff_result,
            color=_should_color(args.color),
            color_preset=args.color_preset,
        )
        _enforce_fail_on_diff(args.fail_on, diff_result)
        return

    if args.command == "report-only":
        if args.report_to_header and not args.report_to_group:
            print(
                "Provide --report-to-group when using --report-to-header",
                file=sys.stderr,
            )
            raise SystemExit(2)
        directives = analyze_policy(policy).directives
        header, notes = generate_report_only(
            directives,
            report_uri=args.report_uri,
            report_to_group=args.report_to_group,
            report_to_endpoints=args.report_to_endpoint,
            report_to_max_age=args.report_to_max_age,
            report_to_include_subdomains=args.report_to_include_subdomains,
        )
        _print_report_only(header, notes, full_header=args.full_header)
        if args.report_to_header:
            _print_report_to_header_only(
                report_to_group=args.report_to_group,
                report_to_endpoints=args.report_to_endpoint,
                report_to_max_age=args.report_to_max_age,
                report_to_include_subdomains=args.report_to_include_subdomains,
            )
        return

    parser.error("Unknown command")


def _add_csp_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--csp", help="CSP policy string")
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to a file containing the CSP header value",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read CSP from stdin (equivalent to --csp -)",
    )


def _add_profile_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        choices=list(RISK_PROFILES),
        default="recommended",
        help="Risk profile for finding severity and coverage",
    )


def _add_suppression_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--suppress",
        action="append",
        default=[],
        help="Suppress a finding by key (repeatable)",
    )
    parser.add_argument(
        "--suppress-file",
        type=Path,
        help="Read suppressions from a file (one key per line; supports # comments)",
    )


def _add_fail_on_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="none",
        help=(
            "Exit non-zero if findings at/above this severity are present. "
            "For diff: only considers added findings and severity escalations."
        ),
    )


def _load_suppressions(args: argparse.Namespace) -> set[str]:
    suppressions: set[str] = set()

    raw = getattr(args, "suppress", [])
    if isinstance(raw, list):
        for item in raw:
            if not item:
                continue
            key = str(item).strip()
            if key:
                suppressions.add(key)

    suppress_file = getattr(args, "suppress_file", None)
    if suppress_file:
        file_path = cast(Path, suppress_file)
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Failed to read {file_path}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        for line in content.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if stripped:
                suppressions.add(stripped)

    return suppressions


def _apply_suppressions(
    findings: list[Finding],
    suppressions: set[str],
) -> tuple[list[Finding], int]:
    if not suppressions:
        return findings, 0
    filtered = [finding for finding in findings if finding.key not in suppressions]
    return filtered, len(findings) - len(filtered)


def _apply_suppressions_to_diff(diff: DiffResult, suppressions: set[str]) -> DiffResult:
    if not suppressions:
        return diff

    added = [finding for finding in diff.added_findings if finding.key not in suppressions]
    removed = [
        finding for finding in diff.removed_findings if finding.key not in suppressions
    ]
    severity_changes = [
        item for item in diff.severity_changes if item.get("key") not in suppressions
    ]

    return DiffResult(
        baseline_directives=diff.baseline_directives,
        directives=diff.directives,
        added_directives=diff.added_directives,
        removed_directives=diff.removed_directives,
        changed_directives=diff.changed_directives,
        added_findings=added,
        removed_findings=removed,
        severity_changes=severity_changes,
    )


def _severity_rank(value: str) -> int:
    ranks = {"low": 1, "medium": 2, "high": 3}
    return ranks.get(value, 0)


def _fail_on_rank(value: str) -> int:
    if value == "none":
        return 99
    return _severity_rank(value)


def _enforce_fail_on_findings(fail_on: str, findings: list[Finding]) -> None:
    threshold = _fail_on_rank(fail_on)
    if threshold >= 90:
        return

    violating = [finding for finding in findings if _severity_rank(finding.severity) >= threshold]
    if not violating:
        return

    print(
        f"Failing (--fail-on {fail_on}): {len(violating)} finding(s) at/above threshold.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _enforce_fail_on_diff(fail_on: str, diff: DiffResult) -> None:
    threshold = _fail_on_rank(fail_on)
    if threshold >= 90:
        return

    added = [
        finding
        for finding in diff.added_findings
        if _severity_rank(finding.severity) >= threshold
    ]

    escalations: list[dict[str, str]] = []
    for item in diff.severity_changes:
        before = item.get("from")
        after = item.get("to")
        if not before or not after:
            continue
        before_rank = _severity_rank(before)
        after_rank = _severity_rank(after)
        if after_rank <= before_rank:
            continue
        if after_rank < threshold:
            continue
        escalations.append(item)

    if not added and not escalations:
        return

    print(
        (
            f"Failing (--fail-on {fail_on}): "
            f"{len(added)} added finding(s) and {len(escalations)} severity escalation(s) "
            "at/above threshold."
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)


def _get_profile(args: argparse.Namespace) -> RiskProfile:
    return cast(RiskProfile, getattr(args, "profile", "recommended"))


def _load_policy(args: argparse.Namespace) -> str:
    if args.csp == "-":
        return sys.stdin.read()
    if args.csp:
        return cast(str, args.csp)
    if args.file:
        file_path = cast(Path, args.file)
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Failed to read {args.file}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    if getattr(args, "stdin", False):
        return sys.stdin.read()
    print("Provide --csp, --file, or --stdin", file=sys.stderr)
    raise SystemExit(2)


_EXPLAIN_KEY_TEMPLATES: tuple[str, ...] = (
    "duplicate-directive-<directive>",
    "<directive>-unsafe-inline",
    "<directive>-unsafe-eval",
    "<directive>-wildcard",
    "<directive>-http-scheme",
    "<directive>-data-scheme",
    "<directive>-blob-scheme",
)


def _explain_known_keys() -> list[str]:
    # Keep in sync with csp_doctor.core finding emission logic.
    fixed = [
        "empty-policy",
        "missing-default-src",
        "missing-frame-ancestors",
        "missing-object-src",
        "missing-base-uri",
        "missing-form-action",
        "missing-upgrade-insecure-requests",
        "missing-require-trusted-types-for",
        "missing-trusted-types",
        "missing-reporting",
        "script-src-missing-nonce-hash",
        "script-src-missing-strict-dynamic",
        "object-src-not-none",
        "base-uri-not-none",
    ]
    return sorted(set(fixed + list(_EXPLAIN_KEY_TEMPLATES)))


def _policy_for_explain_key(key: str) -> str | None:
    if key == "empty-policy":
        return ""

    # Defaults that trigger "missing-*" checks + script-src checks.
    if key in {
        "missing-default-src",
        "missing-frame-ancestors",
        "missing-object-src",
        "missing-base-uri",
        "missing-form-action",
        "missing-upgrade-insecure-requests",
        "missing-require-trusted-types-for",
        "missing-trusted-types",
        "missing-reporting",
        "script-src-missing-nonce-hash",
        "script-src-missing-strict-dynamic",
    }:
        return "script-src 'self'"

    if key == "object-src-not-none":
        return "default-src 'self'; object-src https://example.com"

    if key == "base-uri-not-none":
        return "default-src 'self'; base-uri https://example.com"

    if key.startswith("duplicate-directive-"):
        directive = key.removeprefix("duplicate-directive-").strip()
        if not directive:
            return None
        return f"default-src 'self'; {directive} 'self'; {directive} https://example.com"

    for suffix, token in (
        ("-unsafe-inline", "'unsafe-inline'"),
        ("-unsafe-eval", "'unsafe-eval'"),
        ("-wildcard", "*"),
        ("-http-scheme", "http:"),
        ("-data-scheme", "data:"),
        ("-blob-scheme", "blob:"),
    ):
        if key.endswith(suffix):
            directive = key[: -len(suffix)].strip()
            if not directive:
                return None
            return f"default-src 'self'; {directive} {token}"

    return None


def _handle_explain(args: argparse.Namespace) -> None:
    fmt = cast(str, args.format)
    profile = cast(RiskProfile, args.profile)

    if getattr(args, "list", False):
        keys = _explain_known_keys()
        if fmt == "json":
            print(json.dumps({"keys": keys}, indent=2))
            return
        print("\n".join(keys))
        return

    key = cast(str | None, getattr(args, "key", None))
    if not key:
        print("Provide a finding key or use --list", file=sys.stderr)
        raise SystemExit(2)

    policy = _policy_for_explain_key(key)
    if policy is None:
        print(f"Unknown finding key: {key}. Use 'csp-doctor explain --list'.", file=sys.stderr)
        raise SystemExit(2)

    result = analyze_policy(policy, profile=profile)
    finding = next((item for item in result.findings if item.key == key), None)
    note: str | None = None
    emitted = True

    if finding is None and profile != "recommended":
        # Some profiles intentionally suppress findings (for example legacy).
        recommended = analyze_policy(policy, profile="recommended")
        finding = next((item for item in recommended.findings if item.key == key), None)
        if finding is not None:
            emitted = False
            note = f"Not emitted under profile '{profile}'."

    if finding is None:
        print(f"Unknown finding key: {key}. Use 'csp-doctor explain --list'.", file=sys.stderr)
        raise SystemExit(2)

    payload: dict[str, object] = {
        "key": finding.key,
        "profile": profile,
        "emitted": emitted,
        "severity": finding.severity,
        "title": finding.title,
        "detail": finding.detail,
        "evidence": finding.evidence,
    }
    if note:
        payload["note"] = note

    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return

    print(f"Key: {finding.key}")
    print(f"Profile: {profile}")
    print(f"Emitted: {emitted}")
    print(f"Severity: {finding.severity}")
    print(f"Title: {finding.title}")
    print(f"Detail: {finding.detail}")
    if finding.evidence:
        print(f"Evidence: {finding.evidence}")
    if note:
        print(f"Note: {note}")


def _handle_violations(args: argparse.Namespace) -> None:
    path = cast(Path, args.file)
    try:
        events, skipped = load_violation_events(path)
    except OSError as exc:
        print(f"Failed to read {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if not events and skipped:
        print(f"No valid violation reports found in {path}.", file=sys.stderr)
        raise SystemExit(1)

    summary = summarize_violation_events(
        events,
        top_directives=int(args.top),
        top_origins_per_directive=int(args.top_origins),
    )

    if args.format == "json":
        payload = {
            "file": str(path),
            "skipped": skipped,
            **summary,
        }
        print(json.dumps(payload, indent=2))
        return

    _print_violations_summary_text(
        path=path,
        summary=summary,
        skipped=skipped,
    )


def _print_violations_for_rollout(path: Path) -> None:
    try:
        events, skipped = load_violation_events(path)
    except OSError as exc:
        print(f"\nViolations summary: failed to read {path}: {exc}", file=sys.stderr)
        return

    if not events and skipped:
        print(f"\nViolations summary: no valid reports found in {path}.", file=sys.stderr)
        return

    summary = summarize_violation_events(events)
    print()
    _print_violations_summary_text(path=path, summary=summary, skipped=skipped)


def _print_violations_summary_text(
    *,
    path: Path,
    summary: dict[str, object],
    skipped: int,
) -> None:
    total_raw = summary.get("total_events", 0)
    total = total_raw if isinstance(total_raw, int) else 0
    directives = summary.get("directives", [])
    print("Observed CSP violations\n")
    print(f"Source: {path}")
    print(f"Valid events: {total}")
    if skipped:
        print(f"Skipped: {skipped} invalid/unrecognized record(s)")

    if not directives:
        print("\nTop directives: (none)")
        return

    print("\nTop directives:")
    for item in cast(list[dict[str, object]], directives):
        directive = str(item.get("directive", "") or "")
        count_raw = item.get("count", 0)
        count = count_raw if isinstance(count_raw, int) else 0
        print(f"- {directive}: {count}")
        origins = item.get("top_blocked_origins", [])
        for origin_item in cast(list[dict[str, object]], origins):
            origin = str(origin_item.get("origin", "") or "")
            origin_count_raw = origin_item.get("count", 0)
            origin_count = origin_count_raw if isinstance(origin_count_raw, int) else 0
            if origin:
                print(f"  - {origin}: {origin_count}")


def _load_baseline_policy(args: argparse.Namespace) -> str:
    baseline = getattr(args, "baseline", None)
    baseline_file = getattr(args, "baseline_file", None)

    if baseline:
        return cast(str, baseline)
    if baseline_file:
        file_path = cast(Path, baseline_file)
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Failed to read {file_path}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

    print("Provide --baseline or --baseline-file", file=sys.stderr)
    raise SystemExit(2)


def _load_baseline_snapshot(
    args: argparse.Namespace,
    *,
    expected_profile: RiskProfile,
    expected_environment: str | None,
) -> BaselineSnapshot | None:
    baseline_json = getattr(args, "baseline_json", None)
    if not baseline_json:
        return None

    file_path = cast(Path, baseline_json)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Failed to read {file_path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {file_path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    schema_version = payload.get("schemaVersion", 1)
    if schema_version != 1:
        print(f"Unsupported baseline schemaVersion: {schema_version}", file=sys.stderr)
        raise SystemExit(2)

    try:
        snapshot_profile = _validate_baseline_profile(payload.get("profile", "recommended"))
    except ValueError as exc:
        print(f"Invalid baseline snapshot: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if snapshot_profile != expected_profile:
        print(
            (
                "Baseline snapshot profile mismatch: "
                f"snapshot={snapshot_profile}, requested={expected_profile}"
            ),
            file=sys.stderr,
        )
        raise SystemExit(2)

    environment_value = payload.get("environment")
    environment: str | None = None
    if environment_value is not None:
        if not isinstance(environment_value, str):
            print("Invalid baseline snapshot: environment must be a string", file=sys.stderr)
            raise SystemExit(2)
        environment = environment_value

    if expected_environment:
        if environment is None:
            print(
                (
                    "Baseline snapshot environment missing: "
                    f"expected={expected_environment}"
                ),
                file=sys.stderr,
            )
            raise SystemExit(2)
        if environment != expected_environment:
            print(
                (
                    "Baseline snapshot environment mismatch: "
                    f"snapshot={environment}, expected={expected_environment}"
                ),
                file=sys.stderr,
            )
            raise SystemExit(2)

    try:
        directives = _validate_baseline_directives(payload.get("directives"))
        snapshot_findings = _validate_baseline_findings(payload.get("findings"))
    except ValueError as exc:
        print(f"Invalid baseline snapshot: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    return BaselineSnapshot(
        directives=directives,
        findings=snapshot_findings,
        profile=snapshot_profile,
        environment=environment,
    )


def _write_baseline_snapshot(
    path: Path,
    policy: str,
    *,
    profile: RiskProfile,
    environment: str | None,
) -> None:
    snapshot = create_baseline_snapshot(policy, profile=profile, environment=environment)
    payload = _baseline_snapshot_payload(snapshot)
    try:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _write_baseline_snapshot_from_snapshot(path: Path, snapshot: BaselineSnapshot) -> None:
    payload = _baseline_snapshot_payload(snapshot)
    try:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _baseline_snapshot_payload(snapshot: BaselineSnapshot) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "profile": snapshot.profile,
        "directives": snapshot.directives,
        "findings": [asdict(finding) for finding in snapshot.findings],
    }
    if snapshot.environment is not None:
        payload["environment"] = snapshot.environment
    return payload


def _validate_baseline_directives(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise ValueError("directives must be an object")

    directives: dict[str, list[str]] = {}
    for key, sources in value.items():
        if not isinstance(key, str):
            raise ValueError("directive names must be strings")
        if not isinstance(sources, list) or not all(
            isinstance(source, str) for source in sources
        ):
            raise ValueError(f"directive '{key}' must contain a list of strings")
        directives[key] = list(sources)

    return directives


def _validate_baseline_findings(value: object) -> list[Finding]:
    if not isinstance(value, list):
        raise ValueError("findings must be an array")

    findings: list[Finding] = []
    allowed_severities = {"high", "medium", "low"}
    required_fields = ("key", "severity", "title", "detail")

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"finding at index {index} must be an object")

        missing = [field for field in required_fields if field not in item]
        if missing:
            raise ValueError(
                f"finding at index {index} is missing required fields: {', '.join(missing)}"
            )

        key = item["key"]
        severity = item["severity"]
        title = item["title"]
        detail = item["detail"]
        evidence = item.get("evidence")

        if not all(isinstance(field, str) for field in (key, severity, title, detail)):
            raise ValueError(f"finding at index {index} has non-string required fields")
        if severity not in allowed_severities:
            raise ValueError(
                f"finding at index {index} has unsupported severity '{severity}'"
            )
        if evidence is not None and not isinstance(evidence, str):
            raise ValueError(f"finding at index {index} has non-string evidence")

        findings.append(
            Finding(
                key=key,
                severity=severity,
                title=title,
                detail=detail,
                evidence=evidence,
            )
        )

    return findings


def _validate_baseline_profile(value: object) -> RiskProfile:
    if not isinstance(value, str):
        raise ValueError("profile must be a string")
    if value not in RISK_PROFILES:
        expected = ", ".join(RISK_PROFILES)
        raise ValueError(f"profile must be one of: {expected}")
    return cast(RiskProfile, value)


def _write_output_file(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _write_output_bytes(path: Path, content: bytes) -> None:
    try:
        path.write_bytes(content)
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _render_pdf_from_html(html: str) -> bytes:
    try:
        module = importlib.import_module("weasyprint")
        html_cls = module.HTML
    except Exception as exc:
        print(
            "PDF export requires the optional 'weasyprint' dependency. "
            "Install with: pip install csp-doctor[pdf]",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    try:
        rendered = html_cls(string=html).write_pdf()
        return cast(bytes, rendered)
    except Exception as exc:
        print(f"Failed to render PDF: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _print_analysis(
    directives: dict[str, list[str]],
    findings: list[Finding],
    *,
    color: bool,
    color_preset: str,
    suppressed_count: int = 0,
) -> None:
    print("CSP Doctor analysis\n")
    print("Directives:")
    if not directives:
        print("- (none)")
    else:
        for directive in sorted(directives):
            values = directives[directive]
            rendered = " ".join(values) if values else "(no sources)"
            print(f"- {directive}: {rendered}")

    if not findings:
        print("\nFindings: none")
        return

    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    print("\nFindings:")
    summary = ", ".join(
        f"{counts[key]} {key}" for key in ("high", "medium", "low") if counts[key]
    )
    if summary:
        print(f"({len(findings)} total: {summary})\n")
    if suppressed_count:
        print(f"(suppressed {suppressed_count} finding(s))\n")

    severity_order = {"high": 0, "medium": 1, "low": 2}
    for finding in sorted(
        findings,
        key=lambda item: (severity_order.get(item.severity, 9), item.title),
    ):
        label = finding.severity.upper()
        label = _color_severity_label(
            label,
            finding.severity,
            enabled=color,
            preset=color_preset,
        )
        evidence = f" ({finding.evidence})" if finding.evidence else ""
        print(f"- [{label}] {finding.title}{evidence}\n  {finding.detail}")


def _build_sarif_report(
    *,
    policy: str,
    directives: dict[str, list[str]],
    findings: list[Finding],
) -> dict[str, object]:
    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in findings:
        rule_id = f"csp-doctor/{finding.key}"
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.detail},
                "help": {"text": finding.detail},
                "properties": {
                    "security-severity": _sarif_security_score(finding.severity),
                    "precision": "very-high",
                    "tags": ["security", "csp", finding.severity],
                },
            }

        message = finding.detail
        if finding.evidence:
            message = f"{message} Evidence: {finding.evidence}"

        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level_for_severity(finding.severity),
                "message": {"text": message},
                "properties": {"severity": finding.severity},
            }
        )

    return {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "csp-doctor",
                        "informationUri": "https://github.com/sarveshkapre/csp-doctor",
                        "rules": [rules_by_id[key] for key in sorted(rules_by_id)],
                    }
                },
                "results": results,
                "properties": {
                    "policy": policy.strip(),
                    "directiveCount": len(directives),
                    "findingCount": len(findings),
                },
            }
        ],
    }


def _sarif_level_for_severity(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_security_score(severity: str) -> str:
    if severity == "high":
        return "9.0"
    if severity == "medium":
        return "6.0"
    return "3.0"


def _print_rollout(plan: list[str]) -> None:
    print("CSP rollout plan:\n")
    for index, step in enumerate(plan, start=1):
        print(f"{index}. {step}")


def _print_report_only(header: str, notes: list[str], *, full_header: bool) -> None:
    print("Report-Only header value:\n")
    if full_header:
        print(f"Content-Security-Policy-Report-Only: {header}")
    else:
        print(header)
    if notes:
        print("\nNotes:")
        for note in notes:
            if note.startswith("Report-To:"):
                print(note)
            else:
                print(f"- {note}")


def _print_report_to_header_only(
    *,
    report_to_group: str | None,
    report_to_endpoints: list[str] | None,
    report_to_max_age: int | None,
    report_to_include_subdomains: bool,
) -> None:
    if not report_to_group:
        print("\nReport-To header:\n")
        print("Provide --report-to-group to generate a Report-To header.")
        return

    header = build_report_to_header(
        report_to_group,
        endpoints=report_to_endpoints,
        max_age=report_to_max_age,
        include_subdomains=report_to_include_subdomains,
    )
    print("\nReport-To header:\n")
    if header:
        print(header)
    else:
        print("Provide --report-to-endpoint to generate a Report-To header.")


def _render_html_report(
    *,
    policy: str,
    directives: dict[str, list[str]],
    findings: list[Finding],
    theme: ThemeName = "system",
    template: str = "classic",
) -> str:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    severity_order = {"high": 0, "medium": 1, "low": 2}
    sorted_findings = sorted(
        findings,
        key=lambda item: (severity_order.get(item.severity, 9), item.title),
    )

    directives_rows = "\n".join(
        f"<tr><td>{escape(name)}</td><td>{escape(' '.join(values) or '(no sources)')}</td></tr>"
        for name, values in sorted(directives.items())
    )
    findings_rows = "\n".join(
        (
            "<tr>"
            f"<td class=\"sev {escape(finding.severity)}\">{escape(finding.severity.upper())}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.detail)}</td>"
            f"<td>{escape(finding.evidence or '')}</td>"
            "</tr>"
        )
        for finding in sorted_findings
    )

    summary = ", ".join(
        f"{counts[key]} {key}" for key in ("high", "medium", "low") if counts[key]
    ) or "no findings"

    theme_vars = THEME_OVERRIDES.get(theme, {})
    theme_css = "\n      ".join(f"{key}: {value};" for key, value in theme_vars.items())
    template_css = REPORT_TEMPLATES.get(template, REPORT_TEMPLATES["classic"])["css"]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CSP Doctor Report</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f6f7fb;
      --card: #ffffff;
      --text: #111827;
      --muted: #6b7280;
      --border: #e5e7eb;
      --high: #b91c1c;
      --medium: #b45309;
      --low: #2563eb;
      {theme_css}
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b0f19;
        --card: #111827;
        --text: #f9fafb;
        --muted: #9ca3af;
        --border: #1f2937;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .container {{
      max-width: 960px;
      margin: 32px auto;
      padding: 0 20px 48px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px 24px;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
      margin-bottom: 20px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; }}
    .muted {{ color: var(--muted); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    .sev.high {{ color: var(--high); font-weight: 700; }}
    .sev.medium {{ color: var(--medium); font-weight: 700; }}
    .sev.low {{ color: var(--low); font-weight: 700; }}
    code {{
      background: rgba(148, 163, 184, 0.15);
      padding: 2px 6px;
      border-radius: 6px;
      display: block;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    @media print {{
      @page {{ margin: 12mm; }}
      :root {{
        color-scheme: light;
        --bg: #ffffff;
        --card: #ffffff;
        --text: #111827;
        --muted: #374151;
        --border: #d1d5db;
      }}
      body {{
        background: #ffffff;
      }}
      .container {{
        max-width: none;
        margin: 0;
        padding: 0;
      }}
      .card {{
        box-shadow: none;
        border-radius: 12px;
        page-break-inside: avoid;
        break-inside: avoid;
      }}
      table {{
        font-size: 12px;
      }}
      thead {{
        display: table-header-group;
      }}
      tr {{
        page-break-inside: avoid;
        break-inside: avoid;
      }}
    }}
{template_css}
  </style>
</head>
<body data-theme="{escape(theme)}" data-template="{escape(template)}">
  <div class="container">
    <div class="card">
      <h1>CSP Doctor Report</h1>
      <div class="muted">Summary: {escape(summary)}</div>
    </div>
    <div class="card">
      <h2>Policy</h2>
      <code>{escape(policy.strip()) or "(empty)"}</code>
    </div>
    <div class="card">
      <h2>Directives</h2>
      <table>
        <thead>
          <tr><th>Directive</th><th>Sources</th></tr>
        </thead>
        <tbody>
          {directives_rows or '<tr><td colspan="2">(none)</td></tr>'}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Title</th><th>Detail</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {findings_rows or '<tr><td colspan="4">(none)</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


def _build_report_json(
    *,
    policy: str,
    directives: dict[str, list[str]],
    findings: list[Finding],
    profile: RiskProfile,
    theme: ThemeName,
    template: str,
) -> dict[str, object]:
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    summary = ", ".join(
        f"{counts[key]} {key}" for key in ("high", "medium", "low") if counts[key]
    ) or "no findings"

    return {
        "policy": policy.strip(),
        "profile": profile,
        "theme": theme,
        "template": template,
        "directives": directives,
        "findings": [asdict(finding) for finding in findings],
        "counts": counts,
        "summary": summary,
    }


def _print_diff(
    diff: DiffResult,
    *,
    color: bool,
    color_preset: str = "default",
) -> None:

    print("CSP diff\n")

    print("Directive changes:")
    if not (diff.added_directives or diff.removed_directives or diff.changed_directives):
        print("- (none)")
    else:
        for directive in diff.added_directives:
            print(f"- + {directive}")
        for directive in diff.removed_directives:
            print(f"- - {directive}")
        for directive in sorted(diff.changed_directives):
            change = diff.changed_directives[directive]
            added = change["added"]
            removed = change["removed"]
            details: list[str] = []
            if added:
                details.append(f"+{' '.join(added)}")
            if removed:
                details.append(f"-{' '.join(removed)}")
            rendered = (" " + " ".join(details)) if details else ""
            print(f"- ~ {directive}{rendered}")

    print("\nFinding changes:")
    if not (diff.added_findings or diff.removed_findings or diff.severity_changes):
        print("- (none)")
        return

    severity_order = {"high": 0, "medium": 1, "low": 2}

    if diff.added_findings:
        print("- New findings:")
        for finding in sorted(
            diff.added_findings,
            key=lambda item: (severity_order.get(item.severity, 9), item.title),
        ):
            label = _color_severity_label(
                finding.severity.upper(),
                finding.severity,
                enabled=color,
                preset=color_preset,
            )
            print(f"  - [{label}] {finding.title} ({finding.key})")

    if diff.removed_findings:
        print("- Resolved findings:")
        for finding in sorted(
            diff.removed_findings,
            key=lambda item: (severity_order.get(item.severity, 9), item.title),
        ):
            label = _color_severity_label(
                finding.severity.upper(),
                finding.severity,
                enabled=color,
                preset=color_preset,
            )
            print(f"  - [{label}] {finding.title} ({finding.key})")

    if diff.severity_changes:
        print("- Severity changes:")
        for item in diff.severity_changes:
            from_label = _color_severity_label(
                item["from"].upper(),
                item["from"],
                enabled=color,
                preset=color_preset,
            )
            to_label = _color_severity_label(
                item["to"].upper(),
                item["to"],
                enabled=color,
                preset=color_preset,
            )
            title = item["title"]
            key = item["key"]
            print(f"  - {title} ({key}): {from_label} -> {to_label}")


def _should_color(mode: str) -> bool:
    if mode == "never":
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def _color_severity_label(
    label: str,
    severity: str,
    *,
    enabled: bool,
    preset: str = "default",
) -> str:
    if not enabled:
        return label

    colors = COLOR_PRESETS.get(preset, COLOR_PRESETS["default"])
    if severity == "high":
        return f"\033[{colors['high']}m{label}\033[0m"
    if severity == "medium":
        return f"\033[{colors['medium']}m{label}\033[0m"
    if severity == "low":
        return f"\033[{colors['low']}m{label}\033[0m"
    return label


if __name__ == "__main__":
    main()
