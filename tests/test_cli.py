import json
import subprocess
import sys


def test_cli_analyze_writes_output_file(tmp_path) -> None:
    output_path = tmp_path / "analysis.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ""
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "directives" in payload


def test_cli_analyze_rejects_output_for_text_format(tmp_path) -> None:
    output_path = tmp_path / "analysis.txt"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--format",
            "text",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "--output requires" in proc.stderr


def test_cli_analyze_reads_stdin_dash() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "-",
            "--format",
            "json",
        ],
        input="default-src 'self'; script-src 'self'",
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["directives"]["default-src"] == ["'self'"]


def test_cli_analyze_reads_stdin_flag() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--stdin",
            "--format",
            "json",
        ],
        input="default-src 'self'",
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "default-src" in payload["directives"]


def test_cli_analyze_outputs_sarif() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--format",
            "sarif",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "csp-doctor"
    assert payload["runs"][0]["results"]


def test_cli_analyze_legacy_profile_suppresses_modern_findings() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'; script-src 'self'",
            "--profile",
            "legacy",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    keys = {finding["key"] for finding in payload["findings"]}
    assert "missing-require-trusted-types-for" not in keys
    assert "missing-trusted-types" not in keys
    assert "script-src-missing-strict-dynamic" not in keys


def test_cli_analyze_supports_finding_suppressions() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--suppress",
            "missing-frame-ancestors",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    keys = {finding["key"] for finding in payload["findings"]}
    assert "missing-frame-ancestors" not in keys


def test_cli_analyze_fail_on_thresholds() -> None:
    proc_high = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--fail-on",
            "high",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc_high.returncode == 0, proc_high.stderr
    json.loads(proc_high.stdout)

    proc_med = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "analyze",
            "--csp",
            "default-src 'self'",
            "--fail-on",
            "medium",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc_med.returncode == 1
    json.loads(proc_med.stdout)
    assert "Failing" in proc_med.stderr


def test_cli_diff_outputs_json() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'; frame-ancestors 'none'",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "baseline_directives" in payload
    assert "added_directives" in payload


def test_cli_diff_fail_on_thresholds_only_considers_regressions() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'; report-uri /csp",
            "--csp",
            "default-src 'self'",
            "--fail-on",
            "medium",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    keys = {finding["key"] for finding in payload["added_findings"]}
    assert "missing-reporting" in keys

    proc_high = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'; report-uri /csp",
            "--csp",
            "default-src 'self'",
            "--fail-on",
            "high",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc_high.returncode == 0, proc_high.stderr
    json.loads(proc_high.stdout)


def test_cli_diff_writes_output_file(tmp_path) -> None:
    output_path = tmp_path / "diff.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'; frame-ancestors 'none'",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ""
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["added_directives"] == ["frame-ancestors"]


def test_cli_diff_supports_finding_suppressions() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'; report-uri /csp",
            "--suppress",
            "missing-reporting",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    keys = {finding["key"] for finding in payload["removed_findings"]}
    assert "missing-reporting" not in keys


def test_cli_schema_outputs_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "csp_doctor", "schema", "--kind", "analyze"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["title"].startswith("csp-doctor analyze")


def test_cli_explain_outputs_json() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "explain",
            "missing-reporting",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["key"] == "missing-reporting"
    assert payload["title"]
    assert payload["detail"]


def test_cli_diff_writes_baseline_json(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'",
            "--baseline-out",
            str(baseline_path),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(baseline_path.read_text())
    assert payload["schemaVersion"] == 1
    assert payload["profile"] == "recommended"
    assert "directives" in payload


def test_cli_diff_writes_baseline_environment(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'",
            "--baseline-env",
            "staging",
            "--baseline-out",
            str(baseline_path),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(baseline_path.read_text())
    assert payload["environment"] == "staging"


def test_cli_diff_rejects_baseline_environment_mismatch(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "profile": "recommended",
                "environment": "prod",
                "directives": {"default-src": ["'self'"]},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline-json",
            str(baseline_path),
            "--baseline-env",
            "staging",
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "environment mismatch" in proc.stderr


def test_cli_diff_baseline_out_snapshots_baseline_policy(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src *",
            "--baseline-out",
            str(baseline_path),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(baseline_path.read_text())
    assert payload["directives"]["default-src"] == ["'self'"]


def test_cli_diff_writes_profile_to_baseline_json(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline",
            "default-src 'self'",
            "--csp",
            "default-src 'self'",
            "--baseline-out",
            str(baseline_path),
            "--profile",
            "strict",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(baseline_path.read_text())
    assert payload["profile"] == "strict"


def test_cli_diff_rejects_unknown_schema_version(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "directives": {"default-src": ["'self'"]},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline-json",
            str(baseline_path),
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "schemaVersion" in proc.stderr


def test_cli_diff_rejects_baseline_profile_mismatch(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "profile": "strict",
                "directives": {"default-src": ["'self'"]},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline-json",
            str(baseline_path),
            "--profile",
            "recommended",
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "profile mismatch" in proc.stderr


def test_cli_diff_rejects_invalid_baseline_directives(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "directives": {"default-src": "'self'"},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline-json",
            str(baseline_path),
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "Invalid baseline snapshot" in proc.stderr


def test_cli_diff_rejects_invalid_baseline_findings(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "directives": {"default-src": ["'self'"]},
                "findings": [
                    {
                        "key": "example",
                        "severity": "critical",
                        "title": "Title",
                        "detail": "Detail",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "diff",
            "--baseline-json",
            str(baseline_path),
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "unsupported severity" in proc.stderr


def test_cli_normalize_outputs_sorted_policy() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "normalize",
            "--csp",
            "script-src cdn.example.com 'self'; default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        proc.stdout.strip()
        == "default-src 'self'; script-src 'self' cdn.example.com"
    )


def test_cli_report_outputs_html() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "<html" in proc.stdout
    assert "CSP Doctor Report" in proc.stdout


def test_cli_report_fail_on_thresholds() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--fail-on",
            "medium",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "<html" in proc.stdout


def test_cli_report_writes_file(tmp_path) -> None:
    output_path = tmp_path / "report.html"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert output_path.exists()


def test_cli_report_pdf_requires_output() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--format",
            "pdf",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "requires --output" in proc.stderr


def test_cli_report_writes_pdf_file_or_explains_dependency(tmp_path) -> None:
    output_path = tmp_path / "report.pdf"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--format",
            "pdf",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode == 0:
        data = output_path.read_bytes()
        assert data.startswith(b"%PDF"), "expected a PDF file header"
        return

    assert proc.returncode in (1, 2)
    stderr = proc.stderr.lower()
    assert "weasyprint" in stderr or "render pdf" in stderr


def test_cli_report_theme_dark() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--theme",
            "dark",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert 'data-theme="dark"' in proc.stdout


def test_cli_report_template_glass() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "csp_doctor",
            "report",
            "--csp",
            "default-src 'self'",
            "--template",
            "glass",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert 'data-template="glass"' in proc.stdout
