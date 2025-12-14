"""
Tests for the Click-based CLI.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from cyvest import Cyvest, Level
from cyvest.cli import cli
from cyvest.io_serialization import save_investigation_json


def _strip_ansi(text: str) -> str:
    """Remove ANSI color codes for easier assertions."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _write_sample(tmp_path: Path) -> Path:
    """Create a sample investigation JSON file for CLI tests."""
    from decimal import Decimal

    cv = Cyvest()
    observable = cv.observable("url", "https://example.com", internal=False).with_ti(
        "virustotal", score=Decimal("6.0"), level=Level.MALICIOUS
    )
    cv.check("url_check", "network", "Validate URL").link_observable(observable).with_score(Decimal("6.0"))

    sample_path = tmp_path / "sample.json"
    save_investigation_json(cv, sample_path)
    return sample_path


def test_cli_show_displays_summary(tmp_path: Path) -> None:
    """CLI 'show' command prints summary and optional stats."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["show", str(sample), "--no-graph"])
    assert result.exit_code == 0


def test_cli_stats_detailed(tmp_path: Path) -> None:
    """CLI 'stats' command shows overview and detail sections."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["stats", str(sample), "--detailed"])
    assert result.exit_code == 0


def test_cli_export_writes_files(tmp_path: Path) -> None:
    """CLI 'export' command writes both JSON and Markdown outputs."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()
    md_output = tmp_path / "report.md"
    json_output = tmp_path / "report.json"

    result_md = runner.invoke(cli, ["export", str(sample), "-o", str(md_output)])
    assert result_md.exit_code == 0
    assert md_output.exists()

    result_json = runner.invoke(cli, ["export", str(sample), "-o", str(json_output), "--format", "json"])
    assert result_json.exit_code == 0
    assert json_output.exists()


def test_cli_merge_requires_multiple_inputs(tmp_path: Path) -> None:
    """CLI 'merge' command validates the number of inputs."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["merge", str(sample), "-o", str(tmp_path / "out.json")])
    assert result.exit_code != 0
    assert "Provide at least two input files." in _strip_ansi(result.output)

    result_ok = runner.invoke(
        cli,
        [
            "merge",
            str(sample),
            str(sample),
            "-o",
            str(tmp_path / "out.json"),
        ],
    )
    assert result_ok.exit_code == 0


def test_display_summary_exclude_levels() -> None:
    """Test that display_summary omits selected levels."""
    from decimal import Decimal
    from io import StringIO

    from rich.console import Console

    from cyvest.io_rich import display_summary

    cv = Cyvest()

    # Create observables and checks at different levels
    # Score ranges: MALICIOUS >= 5.0, SUSPICIOUS 3.0-5.0, NOTABLE < 3.0, INFO = 0.0
    # Note: Checks with observables are now automatically upgraded from NONE to INFO
    obs_malicious = cv.observable("url", "https://malicious.com", internal=False)
    obs_suspicious = cv.observable("url", "https://suspicious.com", internal=False)
    obs_info = cv.observable("url", "https://info.com", internal=False)

    cv.check("malicious_check", "network", "Malicious URL").link_observable(obs_malicious).with_score(
        Decimal("6.0")
    )  # MALICIOUS
    cv.check("suspicious_check", "network", "Suspicious URL").link_observable(obs_suspicious).with_score(
        Decimal("4.0")
    )  # SUSPICIOUS
    cv.check("info_check", "network", "Info URL").link_observable(obs_info).with_score(Decimal("0.0"))  # INFO
    # Create a check without observable (Level.NONE - no auto-upgrade without observable)
    cv.check("none_check", "network", "None check without observable")

    # Default excludes Level.NONE
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False)
    output_default = output.getvalue()

    assert "malicious_check" in output_default
    assert "suspicious_check" in output_default
    assert "info_check" in output_default
    assert "none_check" not in output_default
    assert "excluding: NONE" in output_default

    # Exclude INFO and SUSPICIOUS along with NONE
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False, exclude_levels=[Level.INFO, Level.SUSPICIOUS])
    output_excluding_info = output.getvalue()

    assert "malicious_check" in output_excluding_info
    assert "suspicious_check" not in output_excluding_info
    assert "info_check" not in output_excluding_info
    assert "none_check" not in output_excluding_info

    # Allow displaying all checks when exclusions are cleared
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False, exclude_levels=[])
    output_all = output.getvalue()

    assert "malicious_check" in output_all
    assert "suspicious_check" in output_all
    assert "info_check" in output_all
    assert "none_check" in output_all


def test_display_summary_score_history_table() -> None:
    """display_summary shows observable score history when requested."""
    from decimal import Decimal
    from io import StringIO

    from rich.console import Console

    from cyvest.io_rich import display_summary

    cv = Cyvest()
    obs = cv.observable("url", "https://example.com", internal=False)
    obs.with_ti("virustotal", score=Decimal("6.0"), level=Level.MALICIOUS)
    cv.check("score-check", "test", "Score check").with_score(Decimal("1.0"), reason="initial").with_score(
        Decimal("2.0"), reason="bump"
    )

    output = StringIO()
    console = Console(file=output, width=140)
    display_summary(cv, console.print, show_graph=False, show_score_history=True)
    rendered = output.getvalue()

    assert "Score History" in rendered
    assert "Threat intel update from virustotal" in rendered
    assert "bump" in rendered
