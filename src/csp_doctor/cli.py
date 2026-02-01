from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Literal, cast

from csp_doctor.core import (
    BaselineSnapshot,
    DiffResult,
    Finding,
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
        help="Write HTML report to this file (defaults to stdout)",
    )

    schema_parser = subparsers.add_parser(
        "schema",
        help="Print JSON Schema for csp-doctor JSON outputs",
    )
    schema_parser.add_argument(
        "--kind",
        choices=["all", "analyze", "diff"],
        default="all",
        help="Which schema to print",
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
        kind = cast(Literal["all", "analyze", "diff"], args.kind)
        schema = get_schema(kind)
        print(json.dumps(schema, indent=2))
        return

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

    if args.command == "normalize":
        normalized = normalize_policy(
            policy,
            sort_sources=not args.keep_order,
            sort_directives=not args.keep_order,
        )
        print(normalized)
        return

    if args.command == "report":
        analysis_result = analyze_policy(policy)
        html = _render_html_report(
            policy=policy,
            directives=analysis_result.directives,
            findings=analysis_result.findings,
        )
        if args.output:
            _write_output_file(cast(Path, args.output), html)
        else:
            print(html)
        return

    if args.command == "diff":
        snapshot = _load_baseline_snapshot(args)
        if snapshot:
            diff_result = diff_against_snapshot(snapshot=snapshot, policy=policy)
        else:
            baseline_policy = _load_baseline_policy(args)
            diff_result = diff_policies(baseline_policy=baseline_policy, policy=policy)

        if args.baseline_out:
            _write_baseline_snapshot(cast(Path, args.baseline_out), policy)

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


def _load_baseline_snapshot(args: argparse.Namespace) -> BaselineSnapshot | None:
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

    directives = payload.get("directives")
    findings = payload.get("findings")
    if not isinstance(directives, dict) or not isinstance(findings, list):
        print("Baseline JSON must include directives and findings", file=sys.stderr)
        raise SystemExit(2)

    snapshot_findings: list[Finding] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        snapshot_findings.append(
            Finding(
                key=str(item.get("key", "")),
                severity=str(item.get("severity", "")),
                title=str(item.get("title", "")),
                detail=str(item.get("detail", "")),
                evidence=item.get("evidence"),
            )
        )

    return BaselineSnapshot(directives=directives, findings=snapshot_findings)


def _write_baseline_snapshot(path: Path, policy: str) -> None:
    snapshot = create_baseline_snapshot(policy)
    payload = {
        "directives": snapshot.directives,
        "findings": [asdict(finding) for finding in snapshot.findings],
    }
    try:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _write_output_file(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


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
    }}
  </style>
</head>
<body>
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
