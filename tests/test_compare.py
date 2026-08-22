"""
Comparison between investigations.

The point of these tests is less the arithmetic than the two properties that make a comparison
trustworthy: identity converges across investigations (otherwise every finding is reported as
added *and* removed), and a comparison across engines is refused rather than silently wrong.
"""

from __future__ import annotations

import pytest

from cyvest import Cyvest
from cyvest.compare import (
    DiffStatus,
    EngineMismatchError,
    ExpectedResult,
    compare_investigations,
    evaluate_score_rule,
    parse_score_rule,
)
from cyvest.enums import Verdict


def _investigation(*, weight: float) -> Cyvest:
    cv = Cyvest(investigation_name="case")
    url = cv.observable_create("url", "https://evil.test")
    cv.finding_create("phishing-page", weight=weight)
    cv.finding_link_observable("fnd:phishing-page:" + cv._investigation.root_key, url.key)
    return cv


class TestScoreRules:
    def test_a_rule_is_parsed_into_an_operator_and_a_threshold(self) -> None:
        assert parse_score_rule(">= 1.5") == (">=", 1.5)
        assert parse_score_rule("< -2") == ("<", -2.0)

    def test_an_unparsable_rule_is_rejected_rather_than_ignored(self) -> None:
        with pytest.raises(ValueError, match="Invalid score rule"):
            parse_score_rule("roughly 3")

    def test_a_rule_expresses_a_band_not_an_equality(self) -> None:
        assert evaluate_score_rule(2.0, ">= 1.0")
        assert not evaluate_score_rule(0.5, ">= 1.0")


class TestExpectedResult:
    def test_a_rule_must_name_its_target(self) -> None:
        with pytest.raises(ValueError, match="rule_id or key"):
            ExpectedResult(score=">= 1")

    def test_a_missing_finding_is_a_removal(self) -> None:
        cv = _investigation(weight=4.0)
        diffs = compare_investigations(cv, result_expected=[ExpectedResult(rule_id="never-fired", score="> 0")])
        assert [d.status for d in diffs] == [DiffStatus.REMOVED]

    def test_a_missing_finding_can_be_tolerated(self) -> None:
        cv = _investigation(weight=4.0)
        diffs = compare_investigations(
            cv,
            result_expected=[ExpectedResult(rule_id="never-fired", score="> 0", ignore={DiffStatus.REMOVED})],
        )
        assert diffs == []

    def test_a_score_within_the_band_raises_no_difference(self) -> None:
        cv = _investigation(weight=4.0)
        diffs = compare_investigations(
            cv,
            result_expected=[ExpectedResult(rule_id="phishing-page", score=">= 1.0", verdict=Verdict.SUSPICIOUS)],
        )
        assert diffs == []

    def test_a_score_outside_the_band_is_a_mismatch(self) -> None:
        cv = _investigation(weight=4.0)
        diffs = compare_investigations(cv, result_expected=[ExpectedResult(rule_id="phishing-page", score="> 8")])
        assert [d.status for d in diffs] == [DiffStatus.MISMATCH]
        assert diffs[0].expected_score_rule == "> 8"
        assert diffs[0].actual_score == pytest.approx(4.0)


class TestInvestigationDiff:
    def test_two_identical_investigations_differ_in_nothing(self) -> None:
        assert compare_investigations(_investigation(weight=4.0), _investigation(weight=4.0)) == []

    def test_identity_converges_so_a_changed_score_is_a_mismatch_not_an_add_and_a_remove(self) -> None:
        diffs = compare_investigations(_investigation(weight=7.0), _investigation(weight=4.0))
        assert [d.status for d in diffs] == [DiffStatus.MISMATCH]
        assert diffs[0].expected_score == pytest.approx(4.0)
        assert diffs[0].actual_score == pytest.approx(7.0)

    def test_a_finding_present_on_one_side_only_is_reported_as_such(self) -> None:
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        actual.finding_create("extra-rule", weight=2.0)
        diffs = compare_investigations(actual, expected)
        assert [d.status for d in diffs] == [DiffStatus.ADDED]
        assert diffs[0].rule_id == "extra-rule"

        reversed_diffs = compare_investigations(expected, actual)
        assert [d.status for d in reversed_diffs] == [DiffStatus.REMOVED]

    def test_a_mismatch_carries_the_observables_that_explain_it(self) -> None:
        actual, expected = _investigation(weight=1.0), _investigation(weight=1.0)
        actual.observable_get("obs:url:https://evil.test").with_ti("VirusTotal", 6.0)
        diffs = compare_investigations(actual, expected)
        assert diffs[0].observable_diffs
        diff = diffs[0].observable_diffs[0]
        assert diff.value == "https://evil.test"
        assert diff.actual_score > (diff.expected_score or 0.0)


class TestEngineMismatch:
    def test_comparing_across_engines_is_refused(self) -> None:
        actual = _investigation(weight=4.0)
        expected = _investigation(weight=4.0)
        object.__setattr__(expected.get_report(), "engine_id", "bayesian-v1")
        with pytest.raises(EngineMismatchError, match="not on the same scale"):
            compare_investigations(actual, expected)

    def test_the_caller_may_take_responsibility_for_it(self) -> None:
        actual = _investigation(weight=4.0)
        expected = _investigation(weight=4.0)
        object.__setattr__(expected.get_report(), "engine_id", "bayesian-v1")
        assert compare_investigations(actual, expected, allow_engine_mismatch=True) == []
