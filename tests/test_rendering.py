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
        output = render(build_summary(case()._investigation))
        assert "ObservableType." not in output
        assert "url" in output

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
