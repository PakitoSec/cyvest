"""
The command line.

Assertions favour exit codes and files on disk over terminal output: the rendering is Rich's
business and changes with the terminal width, whereas "did it write a valid document" does not.
When the message itself is the contract, it is read from ``caplog`` — the CLI speaks through the
logger, not through Click's stdout.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

from cyvest import Cyvest
from cyvest.cli import cli
from cyvest.evaluation.engines.basic import BasicEngine
from cyvest.evaluation.engines.registry import available_engines, register_engine
from tests.test_serialization import V6_DOCUMENT


@pytest.fixture(autouse=True)
def _capture_cli_logs(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger="cyvest.cli")
    return caplog


@pytest.fixture(scope="session")
def second_engine() -> str:
    """A second registered engine, so "engines are pluggable" is tested rather than asserted."""
    engine_id = "parity-v1"
    if engine_id not in available_engines():

        class ParityEngine(BasicEngine):
            engine_id = "parity-v1"

        register_engine(ParityEngine())
    return engine_id


@pytest.fixture
def runner() -> CliRunner:
    # Rich wraps to the terminal width; pin it so substring assertions are not width-dependent.
    return CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def case(tmp_path: Path) -> Path:
    """A small investigation on disk: one scored URL, one finding, one allowlisted IP."""
    cv = Cyvest(investigation_name="IR-1", investigation_id="inv-1")
    url = cv.observable(cv.OBS.URL, "https://evil.test").with_ti("virustotal", 6.0)
    ip = cv.observable(cv.OBS.IPV4, "203.0.113.50")
    cv.observable_add_relation(url.key, ip.key, cv.REL.PIVOT)
    finding = cv.finding("phishing_page", "Phishing page", weight=4.0)
    cv.finding_link_observable(finding.key, url.key)
    ip.allowlist(justification="Corporate egress")

    path = tmp_path / "case.json"
    cv.io_save_json(path)
    return path


@pytest.fixture
def other_case(tmp_path: Path) -> Path:
    cv = Cyvest(investigation_name="IR-2", investigation_id="inv-2")
    cv.observable(cv.OBS.DOMAIN, "evil.test").with_ti("misp", 2.0)
    cv.finding("lookalike_domain", "Lookalike", weight=2.0)

    path = tmp_path / "other.json"
    cv.io_save_json(path)
    return path


class TestInspection:
    def test_show_renders_an_investigation(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["show", str(case)])
        assert result.exit_code == 0, result.output

    def test_show_accepts_both_graph_and_stats(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["show", str(case), "--stats", "--no-graph"])
        assert result.exit_code == 0, result.output

    def test_stats_reports_the_engine_alongside_the_score(
        self, runner: CliRunner, case: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A score without its engine is not interpretable, so the overview states both."""
        result = runner.invoke(cli, ["stats", str(case)])
        assert result.exit_code == 0, result.output
        assert "basic-v1" in caplog.text

    def test_stats_detailed_renders_the_tables(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["stats", str(case), "--detailed"])
        assert result.exit_code == 0, result.output

    def test_explain_names_the_contributions(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["explain", str(case), "obs:url:https://evil.test"])
        assert result.exit_code == 0, result.output
        assert "virustotal" in result.output

    def test_explain_refuses_an_unknown_key(self, runner: CliRunner, case: Path) -> None:
        """An empty table would read as "nothing contributed", which is not what a typo means."""
        result = runner.invoke(cli, ["explain", str(case), "obs:url:not-in-the-case"])
        assert result.exit_code != 0
        assert "Unknown key" in result.output

    def test_timeline_runs_on_both_clocks(self, runner: CliRunner, case: Path) -> None:
        for basis in ("occurred", "asserted"):
            result = runner.invoke(cli, ["timeline", str(case), "--time", basis])
            assert result.exit_code == 0, result.output

    def test_timeline_can_be_narrowed_to_key_moments(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["timeline", str(case), "--key-only"])
        assert result.exit_code == 0, result.output


class TestEngines:
    def test_engines_lists_the_registry_and_its_aliases(
        self, runner: CliRunner, caplog: pytest.LogCaptureFixture
    ) -> None:
        result = runner.invoke(cli, ["engines"])
        assert result.exit_code == 0, result.output
        assert "basic-v1" in caplog.text
        assert "basic → basic-v1" in caplog.text

    def test_an_unknown_engine_is_refused_rather_than_ignored(self, runner: CliRunner, case: Path) -> None:
        result = runner.invoke(cli, ["show", str(case), "--engine", "no-such-engine"])
        assert result.exit_code != 0

    def test_the_stored_report_never_influences_what_python_prints(
        self, runner: CliRunner, case: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        The serialized report exists for consumers without an engine, not as an authority.

        Loading drops it and re-derives from the facts, so tampering with it must change nothing.
        """
        document = json.loads(case.read_text(encoding="utf-8"))
        document["report"]["investigation"]["score"] = 999.0
        case.write_text(json.dumps(document), encoding="utf-8")

        result = runner.invoke(cli, ["stats", str(case)])

        assert result.exit_code == 0, result.output
        assert "999" not in caplog.text

    def test_the_report_names_the_engine_that_produced_it(
        self, runner: CliRunner, case: Path, second_engine: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        result = runner.invoke(cli, ["stats", str(case), "--engine", second_engine])

        assert result.exit_code == 0, result.output
        assert second_engine in caplog.text


class TestPolicy:
    def test_policy_show_without_a_file_describes_the_default(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["policy", "show"])
        assert result.exit_code == 0, result.output

    def test_policy_show_with_a_file_states_what_produced_it(
        self, runner: CliRunner, case: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        result = runner.invoke(cli, ["policy", "show", str(case)])
        assert result.exit_code == 0, result.output
        assert "default-v1" in caplog.text


class TestMerge:
    def test_merging_two_files_writes_a_readable_document(
        self, runner: CliRunner, case: Path, other_case: Path, tmp_path: Path
    ) -> None:
        output = tmp_path / "merged.json"
        result = runner.invoke(cli, ["merge", str(case), str(other_case), "-o", str(output)])

        assert result.exit_code == 0, result.output
        merged = Cyvest.io_load_json(output)
        assert "obs:url:https://evil.test" in merged.observable_get_all()
        assert "obs:domain:evil.test" in merged.observable_get_all()

    def test_merging_is_idempotent_through_the_cli_too(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        output = tmp_path / "merged.json"
        runner.invoke(cli, ["merge", str(case), str(case), "-o", str(output)])

        once = Cyvest.io_load_json(case)
        twice = Cyvest.io_load_json(output)
        assert twice.get_global_score() == once.get_global_score()

    def test_a_single_input_is_not_a_merge(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["merge", str(case), "-o", str(tmp_path / "merged.json")])
        assert result.exit_code != 0
        assert "at least two" in result.output


class TestExport:
    def test_export_to_markdown(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        output = tmp_path / "report.md"
        result = runner.invoke(cli, ["export", str(case), "-o", str(output)])

        assert result.exit_code == 0, result.output
        assert "Phishing page" in output.read_text(encoding="utf-8")

    def test_export_to_json_stays_loadable(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        output = tmp_path / "copy.json"
        result = runner.invoke(cli, ["export", str(case), "-o", str(output), "-f", "json"])

        assert result.exit_code == 0, result.output
        assert Cyvest.io_load_json(output).get_global_score() == Cyvest.io_load_json(case).get_global_score()


class TestSchema:
    def test_schema_writes_the_investigation_contract(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "schema.json"
        result = runner.invoke(cli, ["schema", "-o", str(output)])

        assert result.exit_code == 0, result.output
        assert json.loads(output.read_text(encoding="utf-8"))["$id"].endswith("investigation-7.json")

    def test_schema_can_emit_the_signal_contract_instead(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "signal.json"
        result = runner.invoke(cli, ["schema", "--which", "signal", "-o", str(output)])

        assert result.exit_code == 0, result.output
        assert json.loads(output.read_text(encoding="utf-8"))["$id"].endswith("signal-7.json")

    def test_schema_goes_to_stdout_without_an_output_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["schema"])
        assert result.exit_code == 0, result.output


class TestMigrate:
    def _write_v6(self, tmp_path: Path) -> Path:
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(V6_DOCUMENT), encoding="utf-8")
        return path

    def test_a_v6_document_is_detected_and_migrated(self, runner: CliRunner, tmp_path: Path) -> None:
        source = self._write_v6(tmp_path)
        output = tmp_path / "migrated.json"
        result = runner.invoke(cli, ["migrate", str(source), "-o", str(output)])

        assert result.exit_code == 0, result.output
        assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "7.0.0"
        assert Cyvest.io_load_json(output).get_global_score() == 6.0

    def test_an_explicit_from_that_disagrees_with_the_file_is_refused(self, runner: CliRunner, tmp_path: Path) -> None:
        """Being wrong about the source version is a mistake worth stopping on, not guessing past."""
        source = self._write_v6(tmp_path)
        result = runner.invoke(cli, ["migrate", str(source), "-o", str(tmp_path / "x.json"), "--from", "5"])

        assert result.exit_code != 0
        assert "looks like schema" in result.output

    def test_a_current_document_needs_no_migration(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        output = tmp_path / "same.json"
        result = runner.invoke(cli, ["migrate", str(case), "-o", str(output)])

        assert result.exit_code == 0, result.output
        assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "7.0.0"


class TestDiff:
    def test_two_identical_files_differ_in_nothing(
        self, runner: CliRunner, case: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        result = runner.invoke(cli, ["diff", str(case), str(case)])
        assert result.exit_code == 0, result.output
        assert "No differences" in caplog.text

    def test_a_changed_score_is_reported(self, runner: CliRunner, case: Path, other_case: Path) -> None:
        result = runner.invoke(cli, ["diff", str(case), str(other_case)])
        assert result.exit_code == 0, result.output

    def test_tolerance_rules_are_read_from_a_file(
        self, runner: CliRunner, case: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(json.dumps([{"rule_id": "phishing_page", "score": "> 900"}]), encoding="utf-8")

        result = runner.invoke(cli, ["diff", str(case), str(case), "--rules", str(rules)])
        assert result.exit_code == 0, result.output
        assert "No differences" not in caplog.text

    def test_comparing_across_engines_stops_with_an_actionable_message(
        self, runner: CliRunner, case: Path, tmp_path: Path, second_engine: str
    ) -> None:
        foreign = tmp_path / "foreign.json"
        document = json.loads(case.read_text(encoding="utf-8"))
        document["header"]["engine_id"] = second_engine
        foreign.write_text(json.dumps(document), encoding="utf-8")

        result = runner.invoke(cli, ["diff", str(case), str(foreign)])
        assert result.exit_code != 0
        assert "--engine" in result.output

    def test_and_re_deriving_both_with_one_engine_makes_them_comparable_again(
        self, runner: CliRunner, case: Path, tmp_path: Path, second_engine: str
    ) -> None:
        foreign = tmp_path / "foreign.json"
        document = json.loads(case.read_text(encoding="utf-8"))
        document["header"]["engine_id"] = second_engine
        foreign.write_text(json.dumps(document), encoding="utf-8")

        result = runner.invoke(cli, ["diff", str(case), str(foreign), "--engine", "basic-v1"])
        assert result.exit_code == 0, result.output


class TestGuards:
    def test_a_missing_file_is_refused_by_click(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["show", str(tmp_path / "nope.json")])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_a_document_from_a_newer_library_is_refused(self, runner: CliRunner, case: Path, tmp_path: Path) -> None:
        """Reading forward only: a 7.0 library must not guess at a 7.1 document."""
        future = tmp_path / "future.json"
        document = json.loads(case.read_text(encoding="utf-8"))
        document["schema_version"] = "7.1.0"
        future.write_text(json.dumps(document), encoding="utf-8")

        result = runner.invoke(cli, ["show", str(future)])
        assert result.exit_code != 0
