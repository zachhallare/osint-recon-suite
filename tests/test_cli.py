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

from unittest.mock import patch, MagicMock
from osint_recon.main import cli

@patch("sys.argv", ["recon-suite", "example.com"])
@patch("osint_recon.main.asyncio.run")
@patch("osint_recon.main.main", new_callable=MagicMock)
def test_cli_entry_point_success(mock_main, mock_run):
    """Test that cli() successfully runs the main coroutine."""
    assert cli() == 0
    mock_run.assert_called_once_with(mock_main.return_value)


@patch("sys.argv", ["recon-suite", "example.com"])
@patch("osint_recon.main.asyncio.run")
@patch("osint_recon.main.main", new_callable=MagicMock)
def test_cli_entry_point_keyboard_interrupt(mock_main, mock_run):
    """Test that cli() handles KeyboardInterrupt gracefully."""
    mock_run.side_effect = KeyboardInterrupt()
    assert cli() == 130


@patch("sys.argv", ["recon-suite", "example.com"])
@patch("osint_recon.main.asyncio.run")
@patch("osint_recon.main.main", new_callable=MagicMock)
def test_cli_entry_point_exception(mock_main, mock_run):
    """Test that cli() handles generic exceptions gracefully."""
    mock_run.side_effect = Exception("Test error")
    assert cli() == 1

@patch("sys.argv", ["recon-suite"])
@patch("osint_recon.main.interactive_menu")
def test_cli_bare_invocation_calls_menu(mock_menu):
    mock_menu.return_value = 0
    assert cli() == 0
    mock_menu.assert_called_once()

@patch("sys.argv", ["recon-suite", "example.com"])
@patch("osint_recon.main.interactive_menu")
@patch("osint_recon.main.asyncio.run")
@patch("osint_recon.main.main", new_callable=MagicMock)
def test_cli_with_args_bypasses_menu(mock_main, mock_run, mock_menu):
    assert cli() == 0
    mock_menu.assert_not_called()
    mock_run.assert_called_once()

@patch("rich.prompt.Confirm.ask")
@patch("rich.prompt.Prompt.ask")
@patch("osint_recon.main.asyncio.run")
@patch("osint_recon.main.main", new_callable=MagicMock)
def test_interactive_menu_scan_option(mock_main, mock_run, mock_ask, mock_confirm):
    mock_ask.side_effect = ["1", "example.com"]
    mock_confirm.side_effect = [True, False] # mock=True, html=False
    from osint_recon.main import interactive_menu
    assert interactive_menu() == 0
    mock_run.assert_called_once()
    assert sys.argv == ["recon-suite", "example.com", "--mock", "--no-html"]

from unittest.mock import AsyncMock

@patch("osint_recon.resolvers.resolve_target")
@patch("rich.prompt.Confirm.ask")
@patch("rich.prompt.Prompt.ask")
def test_interactive_menu_scan_prompts_authorization(mock_ask, mock_confirm, mock_resolve):
    mock_resolve.return_value = ("example.com", "Example Inc", False)
    mock_ask.side_effect = ["1", "example.com"]
    # 1. mock=True, 2. html=False. Then main() runs, which prompts auth (3. Confirm scan? -> True)
    mock_confirm.side_effect = [True, False, True] 
    
    from osint_recon.main import interactive_menu
    assert interactive_menu() == 0
    
    assert mock_confirm.call_count == 3
    assert "Confirm scan" in str(mock_confirm.call_args_list[2])

@patch("osint_recon.console.console.print")
@patch("rich.prompt.Prompt.ask")
@patch("osint_recon.database.Database")
def test_interactive_menu_history_empty_state(mock_db_class, mock_ask, mock_print):
    mock_ask.side_effect = ["2", "", "0"]
    mock_db = mock_db_class.return_value.__enter__.return_value
    mock_db.get_all_scan_runs.return_value = []
    
    from osint_recon.main import interactive_menu
    assert interactive_menu() == 0
    mock_db.get_all_scan_runs.assert_called_once()
    mock_print.assert_any_call("  [dim]No scan history found.[/dim]\n")

@patch("rich.prompt.Prompt.ask")
@patch("osint_recon.database.Database")
def test_interactive_menu_uninstall_option(mock_db_class, mock_ask):
    mock_ask.side_effect = ["3", "DELETE", "", "0"]
    mock_db = mock_db_class.return_value.__enter__.return_value
    
    from osint_recon.main import interactive_menu
    assert interactive_menu() == 0
    mock_db.delete_all_data.assert_called_once()

@patch("rich.prompt.Prompt.ask")
@patch("osint_recon.database.Database")
def test_interactive_menu_uninstall_option_decline(mock_db_class, mock_ask):
    mock_ask.side_effect = ["3", "NO", "", "0"]
    mock_db = mock_db_class.return_value.__enter__.return_value
    
    from osint_recon.main import interactive_menu
    assert interactive_menu() == 0
    mock_db.delete_all_data.assert_not_called()
