from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import cast

from csp_doctor.core import (
    DiffResult,
    Finding,
    analyze_policy,
    diff_policies,
    generate_report_only,
    rollout_plan,
)


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
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )

    rollout_parser = subparsers.add_parser(
        "rollout", help="Generate a CSP rollout plan"
    )
    _add_csp_input_args(rollout_parser)

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
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    diff_parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize text output (JSON is never colorized)",
    )

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
        "--full-header",
        action="store_true",
        help="Emit a full header line (Content-Security-Policy-Report-Only: ...)",
    )

    args = parser.parse_args()
    policy = _load_policy(args)

    if args.command == "analyze":
        analysis_result = analyze_policy(policy)
        if args.format == "json":
            payload = {
                "directives": analysis_result.directives,
                "findings": [asdict(finding) for finding in analysis_result.findings],
            }
            print(json.dumps(payload, indent=2))
            return
        _print_analysis(
            analysis_result.directives,
            analysis_result.findings,
            color=_should_color(args.color),
        )
        return

    if args.command == "rollout":
        directives = analyze_policy(policy).directives
        plan = rollout_plan(directives)
        _print_rollout(plan)
        return

    if args.command == "diff":
        baseline_policy = _load_baseline_policy(args)
        diff_result = diff_policies(baseline_policy=baseline_policy, policy=policy)
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
            print(json.dumps(payload, indent=2))
            return
        _print_diff(diff_result, color=_should_color(args.color))
        return

    if args.command == "report-only":
        directives = analyze_policy(policy).directives
        header, notes = generate_report_only(
            directives,
            report_uri=args.report_uri,
            report_to_group=args.report_to_group,
        )
        _print_report_only(header, notes, full_header=args.full_header)
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


def _print_analysis(
    directives: dict[str, list[str]],
    findings: list[Finding],
    *,
    color: bool,
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

    severity_order = {"high": 0, "medium": 1, "low": 2}
    for finding in sorted(
        findings,
        key=lambda item: (severity_order.get(item.severity, 9), item.title),
    ):
        label = finding.severity.upper()
        label = _color_severity_label(label, finding.severity, enabled=color)
        evidence = f" ({finding.evidence})" if finding.evidence else ""
        print(f"- [{label}] {finding.title}{evidence}\n  {finding.detail}")


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
            print(f"- {note}")


def _print_diff(diff: DiffResult, *, color: bool) -> None:

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
            )
            print(f"  - [{label}] {finding.title} ({finding.key})")

    if diff.severity_changes:
        print("- Severity changes:")
        for item in diff.severity_changes:
            from_label = _color_severity_label(
                item["from"].upper(),
                item["from"],
                enabled=color,
            )
            to_label = _color_severity_label(
                item["to"].upper(),
                item["to"],
                enabled=color,
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


def _color_severity_label(label: str, severity: str, *, enabled: bool) -> str:
    if not enabled:
        return label

    if severity == "high":
        return f"\033[31m{label}\033[0m"
    if severity == "medium":
        return f"\033[33m{label}\033[0m"
    if severity == "low":
        return f"\033[36m{label}\033[0m"
    return label


if __name__ == "__main__":
    main()
