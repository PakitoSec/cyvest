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
    observable = (
        cv.observable("url", "https://example.com", internal=False)
        .with_ti("virustotal", score=Decimal("6.0"), level=Level.MALICIOUS)
    )
    cv.check("url_check", "network", "Validate URL").link_observable(observable.get()).with_score(Decimal("6.0"))

    sample_path = tmp_path / "sample.json"
    save_investigation_json(cv, sample_path)
    return sample_path


def test_cli_show_displays_summary(tmp_path: Path) -> None:
    """CLI 'show' command prints summary and optional stats."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["show", str(sample), "--no-graph"])
    assert result.exit_code == 0

    output = _strip_ansi(result.output)
    assert "Investigation Report" in output
    assert "GLOBAL SCORE" in output

    stats_result = runner.invoke(cli, ["show", str(sample), "--stats", "--no-graph"])
    assert stats_result.exit_code == 0
    assert "Observable Statistics" in _strip_ansi(stats_result.output)


def test_cli_stats_detailed(tmp_path: Path) -> None:
    """CLI 'stats' command shows overview and detail sections."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["stats", str(sample), "--detailed"])
    assert result.exit_code == 0

    output = _strip_ansi(result.output)
    assert "Observable Statistics" in output
    assert "Check Statistics" in output


def test_cli_export_writes_files(tmp_path: Path) -> None:
    """CLI 'export' command writes both JSON and Markdown outputs."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()
    md_output = tmp_path / "report.md"
    json_output = tmp_path / "report.json"

    result_md = runner.invoke(cli, ["export", str(sample), "-o", str(md_output)])
    assert result_md.exit_code == 0
    assert md_output.exists()

    result_json = runner.invoke(
        cli, ["export", str(sample), "-o", str(json_output), "--format", "json"]
    )
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
    assert "Merge complete" in _strip_ansi(result_ok.output) or "Saved merged investigation" in _strip_ansi(result_ok.output)
