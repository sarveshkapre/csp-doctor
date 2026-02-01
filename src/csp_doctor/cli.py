from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from csp_doctor.core import Finding, analyze_policy, generate_report_only, rollout_plan


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="csp-doctor",
        description="Analyze CSP headers and generate rollout guidance.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a CSP policy")
    _add_csp_input_args(analyze_parser)
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

    args = parser.parse_args()
    policy = _load_policy(args)

    if args.command == "analyze":
        result = analyze_policy(policy)
        if args.format == "json":
            payload = {
                "directives": result.directives,
                "findings": [asdict(finding) for finding in result.findings],
            }
            print(json.dumps(payload, indent=2))
            return
        _print_analysis(result.directives, result.findings)
        return

    if args.command == "rollout":
        directives = analyze_policy(policy).directives
        plan = rollout_plan(directives)
        _print_rollout(plan)
        return

    if args.command == "report-only":
        directives = analyze_policy(policy).directives
        header, notes = generate_report_only(
            directives,
            report_uri=args.report_uri,
            report_to_group=args.report_to_group,
        )
        _print_report_only(header, notes)
        return

    parser.error("Unknown command")


def _add_csp_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--csp", help="CSP policy string")
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to a file containing the CSP header value",
    )


def _load_policy(args: argparse.Namespace) -> str:
    if args.csp:
        return args.csp
    if args.file:
        try:
            return args.file.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Failed to read {args.file}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    print("Provide --csp or --file", file=sys.stderr)
    raise SystemExit(2)


def _print_analysis(directives: dict[str, list[str]], findings: list[Finding]) -> None:
    print("CSP Doctor analysis\n")
    print("Directives:")
    for directive, values in directives.items():
        rendered = " ".join(values) if values else "(no sources)"
        print(f"- {directive}: {rendered}")

    if not findings:
        print("\nFindings: none")
        return

    print("\nFindings:")
    for finding in findings:
        evidence = f" ({finding.evidence})" if finding.evidence else ""
        print(f"- [{finding.severity}] {finding.title}{evidence}\n  {finding.detail}")


def _print_rollout(plan: list[str]) -> None:
    print("CSP rollout plan:\n")
    for index, step in enumerate(plan, start=1):
        print(f"{index}. {step}")


def _print_report_only(header: str, notes: list[str]) -> None:
    print("Report-Only header value:\n")
    print(header)
    if notes:
        print("\nNotes:")
        for note in notes:
            print(f"- {note}")


if __name__ == "__main__":
    main()
