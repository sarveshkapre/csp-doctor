from csp_doctor.core import analyze_policy, generate_report_only, parse_csp


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


def test_generate_report_only_adds_report_uri():
    directives = parse_csp("default-src 'self'")
    header, notes = generate_report_only(
        directives,
        report_uri="/csp",
        report_to_group=None,
    )
    assert "report-uri /csp" in header
    assert notes == []
