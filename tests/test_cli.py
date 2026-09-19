"""Tests for the CLI argument parsing in main.py."""

import os
import subprocess
import sys
from pathlib import Path

MAIN_PY = Path(__file__).parent.parent / "main.py"

def test_cli_modules_and_skip_mutually_exclusive():
    """Test that passing both --modules and --skip raises an error."""
    result = subprocess.run(
        [sys.executable, str(MAIN_PY), "example.com", "--modules", "whois_dns", "--skip", "subdomain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode != 0
    assert "Cannot specify both --modules and --skip" in result.stderr

def test_cli_invalid_module_allowlist():
    """Test that passing an invalid module to --modules raises an error."""
    result = subprocess.run(
        [sys.executable, str(MAIN_PY), "example.com", "--modules", "whois_dns,foobar"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode != 0
    assert "Invalid module(s) specified in --modules: foobar" in result.stderr
    assert "Valid modules are:" in result.stderr
    assert "whois_dns" in result.stderr

def test_cli_invalid_module_denylist():
    """Test that passing an invalid module to --skip raises an error."""
    result = subprocess.run(
        [sys.executable, str(MAIN_PY), "example.com", "--skip", "foobar"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode != 0
    assert "Invalid module(s) specified in --skip: foobar" in result.stderr
    assert "Valid modules are:" in result.stderr
    assert "whois_dns" in result.stderr

def test_cli_mock_mode():
    """Test that --mock bypasses normal module validation."""
    # Since --mock runs the mock module, we can just ensure it doesn't crash on module validation.
    result = subprocess.run(
        [sys.executable, str(MAIN_PY), "example.com", "--mock", "--no-confirm"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0
