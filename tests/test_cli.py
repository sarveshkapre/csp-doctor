import json
import subprocess
import sys


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
    assert "directives" in payload


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
