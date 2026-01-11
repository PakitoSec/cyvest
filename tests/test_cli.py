"""
Tests for the Click-based CLI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from cyvest import Cyvest

cli = pytest.importorskip("cyvest.cli").cli


def _strip_ansi(text: str) -> str:
    """Remove ANSI color codes for easier assertions."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _write_sample(tmp_path: Path) -> Path:
    """Create a sample investigation JSON file for CLI tests."""
    from decimal import Decimal

    cv = Cyvest()
    observable = cv.observable(Cyvest.OBS.URL, "https://example.com", internal=False).with_ti(
        "virustotal", score=Decimal("6.0"), level=Cyvest.LVL.MALICIOUS
    )
    cv.check("url_check", "network", "Validate URL").link_observable(observable).with_score(Decimal("6.0"))

    sample_path = tmp_path / "sample.json"
    cv.io_save_json(sample_path)
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
    obs_malicious = cv.observable(Cyvest.OBS.URL, "https://malicious.com", internal=False)
    obs_suspicious = cv.observable(Cyvest.OBS.URL, "https://suspicious.com", internal=False)
    obs_info = cv.observable(Cyvest.OBS.URL, "https://info.com", internal=False)

    cv.check("malicious_check", "network", "Malicious URL").link_observable(obs_malicious).with_score(
        Decimal("6.0")
    )  # MALICIOUS
    cv.check("suspicious_check", "network", "Suspicious URL").link_observable(obs_suspicious).with_score(
        Decimal("4.0")
    )  # SUSPICIOUS
    cv.check("info_check", "network", "Info URL").link_observable(obs_info).with_score(Decimal("0.0"))  # INFO
    # Create a check without observable (Cyvest.LVL.NONE - no auto-upgrade without observable)
    cv.check("none_check", "network", "None check without observable")

    # Default excludes Cyvest.LVL.NONE
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
    display_summary(cv, console.print, show_graph=False, exclude_levels=[Cyvest.LVL.INFO, Cyvest.LVL.SUSPICIOUS])
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


def test_display_summary_audit_log_table() -> None:
    """display_summary shows audit log when requested."""
    from decimal import Decimal
    from io import StringIO

    from rich.console import Console

    from cyvest.io_rich import display_summary

    cv = Cyvest()
    obs = cv.observable(Cyvest.OBS.URL, "https://example.com", internal=False)
    obs.with_ti("virustotal", score=Decimal("6.0"), level=Cyvest.LVL.MALICIOUS)
    cv.check("score-check", "test", "Score check").with_score(Decimal("1.0"), reason="initial").with_score(
        Decimal("2.0"), reason="bump"
    )

    output = StringIO()
    console = Console(file=output, width=140)
    display_summary(cv, console.print, show_graph=False, show_audit_log=True)
    rendered = output.getvalue()

    assert "Audit Log" in rendered
    assert "virustotal" in rendered


def test_cli_diff_no_differences(tmp_path: Path) -> None:
    """CLI 'diff' command succeeds for identical investigations."""
    from decimal import Decimal

    cv = Cyvest()
    cv.check("test-check", "test", "Test check").with_score(Decimal("1.0"))

    file1 = tmp_path / "inv1.json"
    file2 = tmp_path / "inv2.json"
    cv.io_save_json(file1)
    cv.io_save_json(file2)

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(file1), str(file2)])

    assert result.exit_code == 0


def test_cli_diff_with_differences(tmp_path: Path) -> None:
    """CLI 'diff' command succeeds when differences exist."""
    from decimal import Decimal

    from cyvest.compare import compare_investigations

    # Create actual investigation
    actual = Cyvest(investigation_name="actual")
    actual.check("check-a", "test", "Check A").with_score(Decimal("2.0"))
    actual.check("check-new", "test", "New check").with_score(Decimal("1.0"))

    # Create expected investigation
    expected = Cyvest(investigation_name="expected")
    expected.check("check-a", "test", "Check A").with_score(Decimal("1.0"))
    expected.check("check-old", "test", "Old check").with_score(Decimal("1.0"))

    actual_file = tmp_path / "actual.json"
    expected_file = tmp_path / "expected.json"
    actual.io_save_json(actual_file)
    expected.io_save_json(expected_file)

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(actual_file), str(expected_file)])

    assert result.exit_code == 0

    # Verify differences using the compare module directly
    diffs = compare_investigations(actual, expected)
    assert len(diffs) == 3  # Added, Removed, Mismatch
    diff_keys = {d.key for d in diffs}
    assert "chk:check-new" in diff_keys
    assert "chk:check-old" in diff_keys
    assert "chk:check-a" in diff_keys


def test_cli_diff_with_rules_file(tmp_path: Path) -> None:
    """CLI 'diff' command applies tolerance rules from file."""
    import json
    from decimal import Decimal

    from cyvest.compare import ExpectedResult, compare_investigations

    # Create investigations with different scores
    actual = Cyvest(investigation_name="actual")
    actual.check("tolerant-check", "test", "Tolerant check").with_score(Decimal("1.5"))

    expected = Cyvest(investigation_name="expected")
    expected.check("tolerant-check", "test", "Tolerant check").with_score(Decimal("1.0"))

    actual_file = tmp_path / "actual.json"
    expected_file = tmp_path / "expected.json"
    actual.io_save_json(actual_file)
    expected.io_save_json(expected_file)

    # Create rules file that tolerates the difference
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps([{"check_name": "tolerant-check", "score": ">= 1.0"}]),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(actual_file), str(expected_file), "-r", str(rules_file)])

    assert result.exit_code == 0

    # Verify tolerance rules work
    rules = [ExpectedResult(check_name="tolerant-check", score=">= 1.0")]
    diffs = compare_investigations(actual, expected, result_expected=rules)
    assert len(diffs) == 0  # No differences with tolerance
