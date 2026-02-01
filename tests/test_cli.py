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
    assert "directives" in payload


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
