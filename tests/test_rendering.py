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
from cyvest.enums import ObservableSubtype, ObservableType, Salience
from cyvest.io.render import build_graph, build_statistics, build_summary, build_timeline
from cyvest.io.serialization import generate_markdown_report


def render(renderable: object) -> str:
    console = Console(file=io.StringIO(), width=200, no_color=True)
    console.print(renderable)
    return console.file.getvalue()


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
        assert output.index("bad rule") < output.index("benign rule")

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
        assert output.index("GLOBAL SCORE") > output.index("bad rule")

    def test_a_rule_that_concluded_nothing_is_counted_not_listed(self) -> None:
        """v6 called this level ``NONE``; forty of them bury the one rule that fired."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding_create("bad", "bad rule", weight=8.0)
        cv.finding_create("quiet", "quiet rule")

        output = render(build_summary(cv._investigation))

        assert "quiet rule" not in output
        assert "excluding 1 silent" in output
        assert "quiet rule" in render(build_summary(cv._investigation, show_silent=True))

    def test_a_stance_keeps_a_silent_finding_visible(self) -> None:
        """Hiding it would hide the analyst's act along with it."""
        cv = Cyvest(investigation_name="IR-1")
        cv.finding("quiet", "quiet rule").dismiss("out of scope", decided_by="alice")

        assert "quiet rule" in render(build_summary(cv._investigation))

    def test_the_graph_shows_the_type_not_the_repr(self) -> None:
        output = render(build_graph(case()._investigation))
        assert "ObservableType." not in output
        assert "domain" in output

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


class TestEmptyInvestigation:
    """A renderer that raises on an empty investigation fails exactly when nothing was found."""

    @pytest.mark.parametrize("build", [build_summary, build_graph, build_statistics])
    def test_rendering_an_empty_investigation_does_not_raise(self, build) -> None:
        assert render(build(Cyvest(root_data={})._investigation)) is not None

    def test_the_timeline_of_an_empty_investigation_does_not_raise(self) -> None:
        assert render(build_timeline(Cyvest(root_data={})._investigation)) is not None

    def test_the_markdown_of_an_empty_investigation_does_not_raise(self) -> None:
        assert "#" in generate_markdown_report(Cyvest(root_data={})._investigation)
