"""
What the analyst actually sees.

Rendering had no tests at all, which is how ``ObservableType.DOMAIN`` reached every table, every
graph node, every markdown export and every timeline entry of the reference examples. These tests
read the rendered text rather than the model, because that is the only place the defect existed.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from cyvest import Cyvest
from cyvest.compare import ExpectedResult, compare_investigations
from cyvest.enums import Effect, ObservableSubtype, ObservableType, Salience, Verdict
from cyvest.io.render import (
    build_diff,
    build_explanation,
    build_graph,
    build_statistics,
    build_summary,
    build_timeline,
)
from cyvest.io.serialization import generate_markdown_report


def render(renderable: object) -> str:
    console = Console(file=io.StringIO(), width=200, no_color=True)
    console.print(renderable)
    return console.file.getvalue()


def styles_of(renderable: object, text: str) -> set[str]:
    """Styles applied to every segment whose text is exactly ``text`` (colour is not in the string)."""
    console = Console(file=io.StringIO(), width=200)
    return {str(segment.style) for segment in console.render(renderable) if segment.text.strip() == text}


def case() -> Cyvest:
    cv = Cyvest(root_data={"case": "IR-1"}, investigation_name="IR-1")
    url = cv.observable(cv.OBS.URL, "https://bad.example/x", internal=False)
    url.with_ti("virustotal", weight=8.0)
    domain = cv.observable(cv.OBS.DOMAIN, "bad.example", internal=False)
    cv.observable_add_relation(url.key, domain.key, cv.REL.EXTRACTION)
    cv.finding_create("url_analysis", "URL in body", weight=3.0)
    cv.finalize_relationships()
    return cv


class TestEnumRendering:
    """
    A bare ``str, Enum`` renders its repr, and does so *differently* depending on the interpreter:
    ``str()`` is wrong everywhere, while an f-string is right on 3.10 and wrong on 3.11+.
    """

    @pytest.mark.parametrize("member", list(ObservableType) + list(ObservableSubtype))
    def test_a_displayed_enum_renders_as_its_value(self, member: ObservableType) -> None:
        assert str(member) == member.value
        assert f"{member}" == member.value

    def test_the_summary_table_shows_the_type_not_the_repr(self) -> None:
        output = render(build_summary(case()._investigation, show_observables=True))
        assert "ObservableType." not in output
        assert "url" in output


class TestSummaryLayout:
    """One table read top to bottom, grouped by verdict, ending on the global score."""

    def test_sections_appear_in_reading_order(self) -> None:
        cv = case()
        cv.finding("url_analysis").tagged(cv.tag("body", "Body"))
        cv.evidence_create("enrichment", content={"a": 1}, external_id="from-enrich")

        output = render(build_summary(cv._investigation))

        sections = ("FINDINGS:", "TAGS:", "EVIDENCES:", "STATISTICS", "GLOBAL SCORE")
        positions = [output.index(section) for section in sections]
        assert positions == sorted(positions)

    def test_an_empty_section_is_left_out(self) -> None:
        assert "EVIDENCES:" not in render(build_summary(case()._investigation))

    def test_findings_are_grouped_by_verdict_strongest_first(self) -> None:
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("benign", "benign rule", weight=-1.0)
        cv.finding_create("bad", "bad rule", weight=8.0)

        output = render(build_summary(cv._investigation))

        assert output.index("MALICIOUS: 1 finding(s)") < output.index("SAFE: 1 finding(s)")
        assert output.index("bad") < output.index("benign")

    def test_findings_are_listed_by_rule_id_unless_names_are_asked_for(self) -> None:
        """A rule id is what an analyst greps for; the name is prose."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("bad", "bad rule", weight=8.0)

        assert "bad rule" not in render(build_summary(cv._investigation))
        assert "bad rule" in render(build_summary(cv._investigation, show_rule_ids=False))

    def test_observables_stay_out_unless_asked_for(self) -> None:
        """They are the inputs: a hundred relay domains would push the score off the screen."""
        investigation = case()._investigation

        assert "OBSERVABLES:" not in render(build_summary(investigation))
        assert "OBSERVABLES:" in render(build_summary(investigation, show_observables=True))

    def test_the_global_score_is_the_last_row(self) -> None:
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("bad", "bad rule", weight=8.0)

        output = render(build_summary(cv._investigation))

        assert "GLOBAL SCORE" in output
        assert output.index("GLOBAL SCORE") > output.index("bad")

    def test_a_rule_that_concluded_nothing_is_still_listed(self) -> None:
        """Asserting a finding is a deliberate act: v6 hid these as level ``NONE``, v7 shows them."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("bad", "bad rule", weight=8.0)
        cv.finding_create("quiet", "quiet rule")

        output = render(build_summary(cv._investigation))

        assert "quiet" in output
        assert "Total findings: 2" in output

    def test_a_stance_keeps_a_finding_visible(self) -> None:
        """Hiding it would hide the analyst's act along with it."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding("quiet", "quiet rule").dismiss("out of scope", decided_by="alice")

        assert "quiet" in render(build_summary(cv._investigation))

    def test_the_graph_shows_the_type_not_the_repr(self) -> None:
        output = render(build_graph(case()._investigation))
        assert "ObservableType." not in output
        assert "domain" in output

    def test_the_graph_hangs_below_the_summary_by_default(self) -> None:
        """The table gives the score, the graph gives what produced it; v6 printed both."""
        output = render(build_summary(case()._investigation))

        assert "bad.example" in output
        assert "extraction \u2192" in output
        assert "bad.example" not in render(build_summary(case()._investigation, show_graph=False))

    def test_the_graph_names_the_findings_that_fired_on_a_node(self) -> None:
        cv = case()
        cv.finding("url_analysis").link_observable(cv.observable(cv.OBS.URL, "https://bad.example/x"))

        assert "[fnd:url_analysis]" in render(build_graph(cv._investigation))

    def test_a_node_does_not_inherit_the_dim_of_its_relation(self) -> None:
        """Rich propagates the base style of a ``Text`` to everything appended to it."""
        styles = styles_of(build_graph(case()._investigation), "domain bad.example")

        assert styles
        assert not any("dim" in style for style in styles)

    def test_a_score_carries_the_colour_of_its_band(self) -> None:
        """A number read against the wrong band is worse than no number at all."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("bad", "bad rule", weight=8.0)
        cv.finding_create("benign", "benign rule", weight=-1.0)

        summary = build_summary(cv._investigation)

        assert styles_of(summary, "8.00") == {"red"}
        assert styles_of(summary, "-1.00") == {"bright_green"}

    def test_the_markdown_export_shows_the_type_not_the_repr(self) -> None:
        markdown = generate_markdown_report(case()._investigation)
        assert "ObservableType." not in markdown
        assert "| url |" in markdown

    def test_the_timeline_shows_the_type_not_the_repr(self) -> None:
        entries = case().timeline(min_salience=Salience.BACKGROUND)
        titles = [entry.title for entry in entries if entry.kind == "observable"]
        assert titles
        assert not any("ObservableType." in title for title in titles)
        assert "url https://bad.example/x" in titles


class TestMarkdownTrimming:
    """A report handed to a model is mostly noise budget, so it can be trimmed."""

    @staticmethod
    def _case() -> Cyvest:
        cv = Cyvest(investigation_name="IR-1")
        cv.finding("quiet", "quiet rule")
        cv.finding("loud", "loud rule").with_weight(5.0)
        cv.observable(ObservableType.DOMAIN, "bad.example")
        return cv

    def test_every_finding_is_listed(self) -> None:
        markdown = generate_markdown_report(self._case()._investigation)
        assert "loud rule" in markdown
        assert "quiet rule" in markdown

    def test_the_observable_table_can_be_dropped(self) -> None:
        markdown = generate_markdown_report(self._case()._investigation, include_observables=False)
        assert "## Observables" not in markdown
        assert "bad.example" not in markdown
        assert "loud rule" in markdown


class TestDiffEffectColumn:
    """The effect is only worth the width when it is what differs."""

    @staticmethod
    def _additive() -> Cyvest:
        cv = Cyvest(investigation_name="case")
        cv.finding_create("analyst-call", verdict=Verdict.SUSPICIOUS, weight=4.0)
        return cv

    def test_the_diff_nests_observables_and_signals_under_the_finding(self) -> None:
        """A score says something moved; only the tree says what moved it."""
        cv = Cyvest(investigation_name="case")
        url = cv.observable(cv.OBS.URL, "https://bad.example/x", internal=False)
        url.with_ti("virustotal", weight=8.0)
        cv.finding_create("url_analysis", weight=3.0).link_observable(url)

        table = render(build_diff(compare_investigations(cv, Cyvest(investigation_name="case"))))
        assert "\u2514\u2500\u2500 https://bad.example/x" in table
        assert "    \u2514\u2500\u2500 virustotal" in table
        assert "+ 1 added | - 0 removed | \u2717 0 mismatch" in table

    def test_a_score_rule_alone_does_not_mention_the_effect(self) -> None:
        rules = [ExpectedResult(rule_id="analyst-call", score="> 10")]
        table = render(build_diff(compare_investigations(self._additive(), result_expected=rules)))
        assert "additive" not in table

    def test_a_conclusion_read_as_a_term_says_so(self) -> None:
        expected = Cyvest(investigation_name="case")
        expected.conclusion("analyst-call", verdict=Verdict.MALICIOUS)
        table = render(build_diff(compare_investigations(self._additive(), expected)))
        assert "floor" in table
        assert "additive" in table

    def test_a_pinned_effect_that_is_met_stays_quiet(self) -> None:
        rules = [ExpectedResult(rule_id="analyst-call", effect=Effect.ADDITIVE, score="> 10")]
        table = render(build_diff(compare_investigations(self._additive(), result_expected=rules)))
        assert "additive" not in table


class TestExplanation:
    def test_the_explanation_names_the_source_of_each_contribution(self) -> None:
        table = render(build_explanation(case()._investigation, "obs:url:https://bad.example/x"))
        assert "virustotal" in table


class TestPrinterRouting:
    """A caller-supplied printer keeps every renderer on one stream; a console would interleave."""

    @pytest.mark.parametrize(
        "call",
        [
            lambda cv, printer: cv.display_summary(printer=printer),
            lambda cv, printer: cv.display_statistics(printer=printer),
            lambda cv, printer: cv.display_timeline(printer=printer),
            lambda cv, printer: cv.display_explanation("fnd:url_analysis", printer=printer),
            lambda cv, printer: cv.display_diff(printer=printer),
        ],
    )
    def test_the_renderable_goes_to_the_printer_not_the_console(self, call, capsys) -> None:
        captured: list[object] = []
        call(case(), captured.append)
        assert len(captured) == 1
        assert capsys.readouterr().out == ""


class TestEmptyInvestigation:
    """A renderer that raises on an empty investigation fails exactly when nothing was found."""

    @pytest.mark.parametrize("build", [build_summary, build_graph, build_statistics])
    def test_rendering_an_empty_investigation_does_not_raise(self, build) -> None:
        assert render(build(Cyvest(root_data={})._investigation)) is not None

    def test_the_timeline_of_an_empty_investigation_does_not_raise(self) -> None:
        assert render(build_timeline(Cyvest(root_data={})._investigation)) is not None

    def test_the_markdown_of_an_empty_investigation_does_not_raise(self) -> None:
        assert "#" in generate_markdown_report(Cyvest(root_data={})._investigation)
