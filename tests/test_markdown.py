"""The model's Markdown report: content, truncation, determinism."""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone

import pytest

from cyvest import Cyvest, render_llm_summary
from cyvest.io.markdown import (
    contradictions,
    explain_text,
    findings_markdown,
    observables_markdown,
    possible_duplicates,
    timeline_markdown,
)

BUILD = """
from cyvest import Cyvest, AutoLink
cv = Cyvest(root_data={"case": "det"}, investigation_name="det", investigation_id="det", auto_link=AutoLink())
for i in range(40):
    cv.observable(cv.OBS.URL, f"http://host{i}.example/p").with_ti("vt", float(i % 9))
for i in range(35):
    cv.finding(f"rule-{i}", f"Rule {i}", verdict="SUSPICIOUS", weight=float(i % 7)).link_observable(f"obs:url:http://host{i}.example/p")
cv.finding("benign", verdict="SAFE").link_observable("obs:url:http://host3.example/p")
cv.observable("obs:url:http://host5.example/p".split(":", 1)[1].split(":", 1)[0], "http://host5.example/p").allowlist("known")
cv.conclusion("triage-verdict", verdict="MALICIOUS", comment="done")
"""


def _case() -> Cyvest:
    namespace: dict = {}
    exec(BUILD, namespace)  # noqa: S102 - the same code runs in the subprocesses below
    return namespace["cv"]


class TestSummary:
    def test_sections_and_truncation(self) -> None:
        text = render_llm_summary(_case(), max_findings=10, max_observables=5)
        assert text.startswith("# Investigation `det`")
        assert "## Conclusions" in text and "`fnd:triage-verdict` → **MALICIOUS**" in text
        assert "… 26 more findings" in text
        assert "… 75 more observables" in text
        assert "**REFUTE** by cyvest: known" in text
        assert "## Contradictions" in text and "`obs:url:http://host3.example/p` is called inculpatory" in text

    def test_conclusions_stay_out_of_the_findings_table(self) -> None:
        cv = _case()
        assert "triage-verdict" not in findings_markdown(cv)
        assert "triage-verdict" in findings_markdown(cv, status="conclusions")
        assert findings_markdown(Cyvest()) == "_no findings_"

    def test_observables_can_be_filtered(self) -> None:
        cv = _case()
        assert observables_markdown(cv, obs_type="ipv4") == "_no observables_"
        strong = observables_markdown(cv, min_abs_score=8.0, limit=None)
        assert strong.count("\n| `") == 4  # the signals sit on host8, host17, host26 and host35 urls

    def test_explain_text_and_unknown_keys(self) -> None:
        cv = _case()
        assert "extraction → obs:domain:host7.example" in explain_text(cv, "obs:url:http://host7.example/p")
        with pytest.raises(KeyError):
            explain_text(cv, "obs:ipv4:9.9.9.9")

    def test_findings_show_their_date_and_tactic_and_the_timeline_flags_undated_facts(self) -> None:
        cv = Cyvest()
        when = datetime(2026, 8, 7, 10, tzinfo=timezone.utc)
        cv.finding("beacon", "Beacon", verdict="SUSPICIOUS", tactic="command-and-control", occurred_at=when)
        cv.finding("undated", "Later", verdict="NOTABLE")
        table = findings_markdown(cv)
        assert "| occurred_at | tactic |" in table
        assert "| 2026-08-07T10:00:00Z | command-and-control | Beacon |" in table
        timeline = timeline_markdown(cv)
        assert "2026-08-07T10:00:00+00:00 [finding] Beacon" in timeline and "tactic: `command-and-control`" in timeline
        assert "(asserted) [finding] Later" in timeline

    def test_contradictions_only_report_real_disagreements(self) -> None:
        cv = Cyvest()
        cv.finding("a", verdict="MALICIOUS").link_observable(cv.observable(cv.OBS.DOMAIN, "x.example"))
        assert contradictions(cv) == []

    def test_possible_duplicates_pair_same_polarity_findings_on_overlapping_observables(self) -> None:
        cv = Cyvest()
        host = cv.observable(cv.OBS.IPV4, "203.0.113.5")
        user = cv.observable(cv.OBS.DOMAIN, "corp.example")
        other = cv.observable(cv.OBS.DOMAIN, "elsewhere.example")
        cv.finding("splunk-bruteforce", verdict="SUSPICIOUS").link_observable(host).link_observable(user)
        edr = cv.finding("edr-bruteforce", verdict="MALICIOUS").link_observable(host).link_observable(user)
        edr.link_observable(other)
        lines = possible_duplicates(cv)
        assert lines == [
            "`fnd:edr-bruteforce` and `fnd:splunk-bruteforce` are both inculpatory and share 2 of 3 observables "
            "(`obs:domain:corp.example`, `obs:ipv4:203.0.113.5`)"
        ]
        assert "## Possible duplicates" in render_llm_summary(cv)
        assert possible_duplicates(cv, threshold=0.8) == []

    def test_possible_duplicates_ignore_disagreements_refuted_findings_and_conclusions(self) -> None:
        cv = Cyvest()
        host = cv.observable(cv.OBS.IPV4, "203.0.113.5")
        cv.finding("bad", verdict="MALICIOUS").link_observable(host)
        cv.finding("fine", verdict="SAFE").link_observable(host)
        cv.conclusion("triage-verdict", verdict="MALICIOUS").link_observable(host)
        assert possible_duplicates(cv) == []
        assert any("exculpatory by `fnd:fine`" in line for line in contradictions(cv))
        cv.finding("bad-again", verdict="SUSPICIOUS").link_observable(host)
        assert len(possible_duplicates(cv)) == 1
        cv.decision_create("fnd:bad-again", "REFUTE", "same behaviour as fnd:bad")
        assert possible_duplicates(cv) == []
        assert "## Possible duplicates" not in render_llm_summary(cv)

    def test_the_summary_is_identical_under_different_hash_seeds(self) -> None:
        program = BUILD + "\nfrom cyvest import render_llm_summary\nprint(render_llm_summary(cv))\n"
        outputs = {
            subprocess.run(  # noqa: S603
                [sys.executable, "-c", program],
                check=True,
                capture_output=True,
                text=True,
                env={"PYTHONHASHSEED": seed},
            ).stdout
            for seed in ("1", "42")
        }
        assert len(outputs) == 1
