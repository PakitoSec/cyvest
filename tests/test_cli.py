"""
Tests for the Click-based CLI.
"""

from __future__ import annotations

import json
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
    cv.finding("url_finding", "network", "Validate URL").link_observable(observable).with_score(Decimal("6.0"))

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


def test_cli_stats_overview_accepts_statistics_schema(tmp_path: Path) -> None:
    """CLI 'stats' overview accepts the Pydantic statistics model returned by Cyvest."""
    sample = _write_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["stats", str(sample)])

    assert result.exit_code == 0
    assert result.exception is None


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


def test_cli_migrate_writes_v6_document(tmp_path: Path) -> None:
    """CLI 'migrate' rewrites a v5 document to the strict v6 schema."""
    sample = _write_sample(tmp_path)
    source = json.loads(sample.read_text(encoding="utf-8"))
    source["schema_version"] = "5.4.1"

    source["checks"] = {}
    finding_key_map: dict[str, str] = {}
    for finding_key, finding in source.pop("findings").items():
        check_key = finding_key.replace("fnd:", "chk:", 1)
        finding_key_map[finding_key] = check_key
        finding["check_name"] = finding.pop("finding_name")
        finding["key"] = check_key
        finding.pop("evidence_links", None)
        source["checks"][check_key] = finding
    source.pop("evidences", None)

    for tag in source.get("tags", {}).values():
        tag["checks"] = [finding_key_map.get(key, key) for key in tag.pop("findings", [])]

    v5_path = tmp_path / "v5.json"
    output_path = tmp_path / "v6.json"
    v5_path.write_text(json.dumps(source), encoding="utf-8")

    result = CliRunner().invoke(cli, ["migrate", str(v5_path), "-o", str(output_path)])

    assert result.exit_code == 0
    migrated = json.loads(output_path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "6.0.0"
    assert migrated["evidences"] == {}
    assert "checks" not in migrated
    assert migrated["findings"]
    assert all(key.startswith("fnd:") for key in migrated["findings"])


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

    # Create observables and findings at different levels
    # Score ranges: MALICIOUS >= 5.0, SUSPICIOUS 3.0-5.0, NOTABLE < 3.0, INFO = 0.0
    # Note: Findings with observables are now automatically upgraded from NONE to INFO
    obs_malicious = cv.observable(Cyvest.OBS.URL, "https://malicious.com", internal=False)
    obs_suspicious = cv.observable(Cyvest.OBS.URL, "https://suspicious.com", internal=False)
    obs_info = cv.observable(Cyvest.OBS.URL, "https://info.com", internal=False)

    cv.finding("malicious_finding", "network", "Malicious URL").link_observable(obs_malicious).with_score(
        Decimal("6.0")
    )  # MALICIOUS
    cv.finding("suspicious_finding", "network", "Suspicious URL").link_observable(obs_suspicious).with_score(
        Decimal("4.0")
    )  # SUSPICIOUS
    cv.finding("info_finding", "network", "Info URL").link_observable(obs_info).with_score(Decimal("0.0"))  # INFO
    # Create a finding without observable (Cyvest.LVL.NONE - no auto-upgrade without observable)
    cv.finding("none_finding", "network", "None finding without observable")

    # Default excludes Cyvest.LVL.NONE
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False)
    output_default = output.getvalue()

    assert "malicious_finding" in output_default
    assert "suspicious_finding" in output_default
    assert "info_finding" in output_default
    assert "none_finding" not in output_default
    assert "excluding: NONE" in output_default

    # Exclude INFO and SUSPICIOUS along with NONE
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False, exclude_levels=[Cyvest.LVL.INFO, Cyvest.LVL.SUSPICIOUS])
    output_excluding_info = output.getvalue()

    assert "malicious_finding" in output_excluding_info
    assert "suspicious_finding" not in output_excluding_info
    assert "info_finding" not in output_excluding_info
    assert "none_finding" not in output_excluding_info

    # Allow displaying all findings when exclusions are cleared
    output = StringIO()
    console = Console(file=output, width=120)
    display_summary(cv, console.print, show_graph=False, exclude_levels=[])
    output_all = output.getvalue()

    assert "malicious_finding" in output_all
    assert "suspicious_finding" in output_all
    assert "info_finding" in output_all
    assert "none_finding" in output_all


def test_display_summary_audit_log_table() -> None:
    """display_summary shows audit log when requested."""
    from decimal import Decimal
    from io import StringIO

    from rich.console import Console

    from cyvest.io_rich import display_summary

    cv = Cyvest()
    obs = cv.observable(Cyvest.OBS.URL, "https://example.com", internal=False)
    obs.with_ti("virustotal", score=Decimal("6.0"), level=Cyvest.LVL.MALICIOUS)
    cv.finding("score-finding", "test", "Score finding").with_score(Decimal("1.0"), reason="initial").with_score(
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
    cv.finding("test-finding", "test", "Test finding").with_score(Decimal("1.0"))

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
    actual.finding("finding-a", "test", "Finding A").with_score(Decimal("2.0"))
    actual.finding("finding-new", "test", "New finding").with_score(Decimal("1.0"))

    # Create expected investigation
    expected = Cyvest(investigation_name="expected")
    expected.finding("finding-a", "test", "Finding A").with_score(Decimal("1.0"))
    expected.finding("finding-old", "test", "Old finding").with_score(Decimal("1.0"))

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
    assert "fnd:finding-new" in diff_keys
    assert "fnd:finding-old" in diff_keys
    assert "fnd:finding-a" in diff_keys


def test_cli_diff_with_rules_file(tmp_path: Path) -> None:
    """CLI 'diff' command applies tolerance rules from file."""
    import json
    from decimal import Decimal

    from cyvest.compare import ExpectedResult, compare_investigations

    # Create investigations with different scores
    actual = Cyvest(investigation_name="actual")
    actual.finding("tolerant-finding", "test", "Tolerant finding").with_score(Decimal("1.5"))

    expected = Cyvest(investigation_name="expected")
    expected.finding("tolerant-finding", "test", "Tolerant finding").with_score(Decimal("1.0"))

    actual_file = tmp_path / "actual.json"
    expected_file = tmp_path / "expected.json"
    actual.io_save_json(actual_file)
    expected.io_save_json(expected_file)

    # Create rules file that tolerates the difference
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps([{"finding_name": "tolerant-finding", "score": ">= 1.0"}]),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(actual_file), str(expected_file), "-r", str(rules_file)])

    assert result.exit_code == 0

    # Verify tolerance rules work
    rules = [ExpectedResult(finding_name="tolerant-finding", score=">= 1.0")]
    diffs = compare_investigations(actual, expected, result_expected=rules)
    assert len(diffs) == 0  # No differences with tolerance


def _write_detailed_sample(tmp_path: Path) -> Path:
    """Create a detailed sample investigation for query tests."""
    from decimal import Decimal

    cv = Cyvest()

    # Create observables with relationships
    domain_obs = cv.observable(Cyvest.OBS.DOMAIN, "example.com", internal=False)
    ip_obs = cv.observable(Cyvest.OBS.IPV4, "192.168.1.1", internal=True)

    # Add threat intel to domain
    domain_obs.with_ti(
        "virustotal",
        score=Decimal("6.0"),
        level=Cyvest.LVL.MALICIOUS,
        comment="Detected by 10/70 engines",
        extra={"positives": 10, "total": 70},
        taxonomies=[{"level": Cyvest.LVL.MALICIOUS, "name": "verdict", "value": "malicious"}],
    )
    domain_obs.with_ti(
        "urlscan",
        score=Decimal("3.5"),
        level=Cyvest.LVL.SUSPICIOUS,
        comment="Phishing detected",
    )

    # Add relationship
    domain_obs.relate_to(ip_obs, Cyvest.REL.RELATED_TO, Cyvest.DIR.OUTBOUND)

    # Create finding linked to domain
    finding = cv.finding("domain-finding", "network", "Domain validation finding")
    finding.link_observable(domain_obs)
    finding.with_score(Decimal("6.0"))

    sample_path = tmp_path / "detailed_sample.json"
    cv.io_save_json(sample_path)
    return sample_path


def test_cli_query_finding(tmp_path: Path) -> None:
    """CLI 'query' command displays finding information."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "--key", "fnd:domain-finding"])
    assert result.exit_code == 0


def test_cli_query_observable(tmp_path: Path) -> None:
    """CLI 'query' command displays observable information with score breakdown."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "-k", "obs:domain:example.com"])
    assert result.exit_code == 0


def test_cli_query_observable_with_depth(tmp_path: Path) -> None:
    """CLI 'query' command respects depth parameter."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "-k", "obs:domain:example.com", "--depth", "2"])
    assert result.exit_code == 0


def test_cli_query_threat_intel(tmp_path: Path) -> None:
    """CLI 'query' command displays threat intel information."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "-k", "ti:virustotal:obs:domain:example.com"])
    assert result.exit_code == 0


def test_cli_query_invalid_key(tmp_path: Path) -> None:
    """CLI 'query' command rejects invalid key formats."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "-k", "invalid-key"])
    assert result.exit_code != 0
    assert "Invalid key format" in result.output


def test_cli_query_not_found(tmp_path: Path) -> None:
    """CLI 'query' command handles missing objects gracefully."""
    sample = _write_detailed_sample(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["query", str(sample), "-k", "fnd:nonexistent"])
    assert result.exit_code != 0
    assert "not found" in result.output


# =============================================================================
# Extract Command Markdown Format Tests
# =============================================================================


class TestExtractMarkdownFormat:
    """Tests for extract command markdown output formats."""

    def test_extract_format_markdown(self, tmp_path: Path) -> None:
        """Extract command outputs markdown format."""
        runner = CliRunner()
        input_text = "Visit https://example.com or email admin@test.org"
        output_file = tmp_path / "output.md"

        result = runner.invoke(cli, ["extract", "--format", "markdown", "-o", str(output_file)], input=input_text)
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "- URL" in content
        assert "- EMAIL" in content

    def test_extract_format_markdown_table(self, tmp_path: Path) -> None:
        """Extract command outputs markdown table format."""
        runner = CliRunner()
        input_text = "IP: 192.168.1.1"
        output_file = tmp_path / "output.md"

        result = runner.invoke(cli, ["extract", "--format", "markdown-table", "-o", str(output_file)], input=input_text)
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "| Type | Value | Defanged |" in content
        assert "| IPV4 |" in content

    def test_extract_markdown_with_title(self, tmp_path: Path) -> None:
        """Extract command adds title header to markdown output."""
        runner = CliRunner()
        input_text = "https://example.com"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown", "--title", "Threat IOCs", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "## Threat IOCs" in content

    def test_extract_markdown_group_by_type(self, tmp_path: Path) -> None:
        """Extract command groups by type in markdown output."""
        runner = CliRunner()
        input_text = "URL: https://a.com Email: test@example.com IP: 1.2.3.4"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown", "--group-by-type", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        # Should have type headers
        assert "### IPV4" in content or "### URL" in content

    def test_extract_markdown_include_original(self, tmp_path: Path) -> None:
        """Extract command includes original text in markdown output."""
        runner = CliRunner()
        input_text = "Malicious: hxxps://evil[.]com"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown", "--include-original", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "Original:" in content
        assert "hxxps://evil[.]com" in content

    def test_extract_markdown_defang_output(self, tmp_path: Path) -> None:
        """Extract command defangs values in markdown output."""
        runner = CliRunner()
        input_text = "https://malware.com/payload"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown", "--defang-output", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "hxxps://" in content
        assert "[.]" in content

    def test_extract_markdown_table_defang_output(self, tmp_path: Path) -> None:
        """Extract command defangs values in markdown table output."""
        runner = CliRunner()
        input_text = "admin@malware.com"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown-table", "--defang-output", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "[@]" in content
        assert "[.]" in content

    def test_extract_markdown_table_with_title(self, tmp_path: Path) -> None:
        """Extract command adds title header to markdown table output."""
        runner = CliRunner()
        input_text = "192.168.1.1"
        output_file = tmp_path / "output.md"

        result = runner.invoke(
            cli,
            ["extract", "--format", "markdown-table", "--title", "Network IOCs", "-o", str(output_file)],
            input=input_text,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "## Network IOCs" in content
        assert "| Type | Value | Defanged |" in content
