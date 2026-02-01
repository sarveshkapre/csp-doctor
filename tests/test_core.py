from csp_doctor.core import (
    analyze_policy,
    build_report_to_header,
    diff_policies,
    generate_report_only,
    normalize_policy,
    parse_csp,
)


def test_parse_csp_basic():
    policy = "default-src 'self'; script-src 'self' cdn.example.com"
    directives = parse_csp(policy)
    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == ["'self'", "cdn.example.com"]


def test_parse_csp_accepts_header_line():
    policy = "Content-Security-Policy: default-src 'self'; script-src 'self'"
    directives = parse_csp(policy)
    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == ["'self'"]


def test_analyze_policy_missing_default():
    result = analyze_policy("script-src 'self'")
    assert any(finding.key == "missing-default-src" for finding in result.findings)


def test_analyze_policy_flags_missing_frame_ancestors():
    result = analyze_policy("default-src 'self'")
    assert any(
        finding.key == "missing-frame-ancestors" for finding in result.findings
    )


def test_analyze_policy_flags_missing_trusted_types() -> None:
    result = analyze_policy("default-src 'self'")
    assert any(
        finding.key == "missing-require-trusted-types-for"
        for finding in result.findings
    )
    assert any(finding.key == "missing-trusted-types" for finding in result.findings)


def test_generate_report_only_adds_report_uri():
    directives = parse_csp("default-src 'self'")
    header, notes = generate_report_only(
        directives,
        report_uri="/csp",
        report_to_group=None,
    )
    assert "report-uri /csp" in header
    assert notes == []


def test_generate_report_only_adds_report_to_header_note() -> None:
    directives = parse_csp("default-src 'self'")
    header, notes = generate_report_only(
        directives,
        report_uri=None,
        report_to_group="csp",
        report_to_endpoints=["https://example.com/csp-report"],
    )
    assert "report-to csp" in header
    assert any(note.startswith("Report-To:") for note in notes)


def test_normalize_policy_sorts_directives_and_sources() -> None:
    policy = "script-src cdn.example.com 'self'; default-src 'self'"
    normalized = normalize_policy(policy)
    assert normalized == "default-src 'self'; script-src 'self' cdn.example.com"


def test_diff_policies_finds_added_directive_and_findings() -> None:
    baseline = "default-src 'self'"
    current = "default-src 'self'; frame-ancestors 'none'; report-uri /csp"
    diff = diff_policies(baseline_policy=baseline, policy=current)
    assert "frame-ancestors" in diff.added_directives
    assert any(
        finding.key == "missing-reporting" for finding in diff.removed_findings
    )


def test_build_report_to_header() -> None:
    header = build_report_to_header(
        "csp",
        endpoints=["https://example.com/csp-report"],
        max_age=3600,
        include_subdomains=True,
    )
    assert header is not None
    assert header.startswith("Report-To: ")
    assert '"group":"csp"' in header
    assert '"max_age":3600' in header
    assert '"include_subdomains":true' in header
