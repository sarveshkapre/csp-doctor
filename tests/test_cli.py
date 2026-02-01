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
