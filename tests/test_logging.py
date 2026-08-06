"""
Regression tests for logurich integration.
"""

from __future__ import annotations

import re
import runpy
import subprocess
import sys
import textwrap
from pathlib import Path

import logurich
import pytest
from click.testing import CliRunner
from logurich import LogurichLogger, init_logger, rich_set_console, shutdown_logger
from rich.console import Console

from cyvest.cli import cli
from cyvest.cli import logger as cli_logger
from cyvest.cyvest import logger as facade_logger
from cyvest.investigation import logger as investigation_logger
from cyvest.shared import logger as shared_logger

REPO_ROOT = Path(__file__).resolve().parents[1]


def _strip_ansi(text: str) -> str:
    """Remove ANSI color codes for easier assertions."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _bind_rich_to_captured_stderr() -> None:
    """Point Rich output to pytest's currently captured stderr."""
    rich_set_console(Console(file=sys.stderr, markup=True, force_terminal=True))


def test_internal_loggers_use_v1_adapters() -> None:
    """Modules using Logurich methods should expose v1 logger adapters."""
    assert all(
        isinstance(logger, LogurichLogger)
        for logger in (cli_logger, facade_logger, investigation_logger, shared_logger)
    )


def test_logurich_context_helpers_use_v1_names() -> None:
    """Ambient context helpers should expose only their final v1 names."""
    assert callable(logurich.global_context)
    assert callable(logurich.global_clear_context)
    assert not hasattr(logurich, "global_context_configure")
    assert not hasattr(logurich, "clear_context")


def test_cli_exposes_v1_console_option() -> None:
    """The CLI should expose the v1 output selector and reject the removed flag."""
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "--logger-console" in result.output
    assert "--logger-rich" not in result.output


def test_level_by_module_uses_cyvest_module_names(capfd: pytest.CaptureFixture[str]) -> None:
    """Module-specific log levels should match real cyvest module paths."""
    shutdown_logger()
    _bind_rich_to_captured_stderr()
    capfd.readouterr()

    try:
        init_logger("INFO", level_by_module={"cyvest.shared": "DEBUG"}, enqueue=False)
        shared_logger.debug("shared-debug-marker")
        investigation_logger.debug("investigation-debug-marker")

        output = _strip_ansi(capfd.readouterr().err)

        assert "shared-debug-marker" in output
        assert "investigation-debug-marker" not in output
    finally:
        shutdown_logger()


@pytest.mark.parametrize(
    ("script_name", "expected_marker"),
    [
        ("01_email_basic.py", "Temporary output directory:"),
        ("02_urls_and_ips.py", "Temporary output directory:"),
        ("03_merge_demo.py", "Temporary output directory:"),
        ("06_compare_investigations.py", "Example complete!"),
    ],
)
def test_direct_run_examples_support_logging(
    script_name: str,
    expected_marker: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Direct-run examples should initialize logging and support Logurich methods."""
    shutdown_logger()
    _bind_rich_to_captured_stderr()
    capfd.readouterr()

    try:
        runpy.run_path(str(REPO_ROOT / "examples" / script_name), run_name="__main__")
        shutdown_logger()

        output = _strip_ansi(capfd.readouterr().err)

        assert expected_marker in output
    finally:
        shutdown_logger()


def test_cyvest_default_display_helpers_work_without_explicit_logurich_import() -> None:
    """Default rich display helpers should work for plain `from cyvest import Cyvest` users."""
    script = textwrap.dedent(
        """
        from cyvest import Cyvest

        actual = Cyvest()
        expected = Cyvest()

        actual.display_summary(show_graph=False)
        actual.display_statistics()
        actual.display_diff(expected=expected)

        print("ok")
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
