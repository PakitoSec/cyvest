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
    cv.finding_link_observable("fnd:phishing-page", url.key)
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


class TestToleranceRules:
    """
    Rules are tolerances **on** the structural diff, not a second opinion beside it.

    Run as an independent pass, they could only ever add rows: a satisfied band never loosened
    anything, a violated one reported the same key twice, and ``ignore={ADDED}`` was unreachable
    because rules never met the structural comparison at all.
    """

    def _pair(self) -> tuple[Cyvest, Cyvest]:
        return _investigation(weight=7.0), _investigation(weight=4.0)

    def test_a_satisfied_band_suppresses_the_exact_value_mismatch(self) -> None:
        actual, expected = self._pair()
        assert compare_investigations(actual, expected) != []
        rules = [ExpectedResult(rule_id="phishing-page", score="< 9.0")]
        assert compare_investigations(actual, expected, rules) == []

    def test_a_violated_band_reports_the_key_once_carrying_the_rule(self) -> None:
        actual, expected = self._pair()
        rules = [ExpectedResult(rule_id="phishing-page", score="< 0.1")]
        diffs = compare_investigations(actual, expected, rules)
        assert [d.status for d in diffs] == [DiffStatus.MISMATCH]
        assert diffs[0].expected_score_rule == "< 0.1"

    def test_a_satisfied_verdict_also_tolerates(self) -> None:
        actual, expected = self._pair()
        rules = [ExpectedResult(rule_id="phishing-page", verdict=Verdict.MALICIOUS)]
        assert compare_investigations(actual, expected, rules) == []

    def test_a_rule_stating_nothing_tolerates_nothing(self) -> None:
        """Otherwise naming a target would silence every difference on it."""
        actual, expected = self._pair()
        rules = [ExpectedResult(rule_id="phishing-page")]
        assert [d.status for d in compare_investigations(actual, expected, rules)] == [DiffStatus.MISMATCH]

    def test_ignore_drops_a_mismatch(self) -> None:
        actual, expected = self._pair()
        rules = [ExpectedResult(rule_id="phishing-page", ignore={DiffStatus.MISMATCH})]
        assert compare_investigations(actual, expected, rules) == []

    def test_ignore_drops_an_added_finding(self) -> None:
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        actual.finding_create("extra-rule", weight=2.0)
        assert [d.status for d in compare_investigations(actual, expected)] == [DiffStatus.ADDED]
        rules = [ExpectedResult(rule_id="extra-rule", ignore={DiffStatus.ADDED})]
        assert compare_investigations(actual, expected, rules) == []

    def test_ignore_drops_a_removed_finding(self) -> None:
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        expected.finding_create("gone-rule", weight=2.0)
        assert [d.status for d in compare_investigations(actual, expected)] == [DiffStatus.REMOVED]
        rules = [ExpectedResult(rule_id="gone-rule", ignore={DiffStatus.REMOVED})]
        assert compare_investigations(actual, expected, rules) == []

    def test_a_rule_matching_nothing_is_still_reported_once(self) -> None:
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        rules = [ExpectedResult(rule_id="never-fired", score="> 1")]
        diffs = compare_investigations(actual, expected, rules)
        assert [d.status for d in diffs] == [DiffStatus.REMOVED]
        assert diffs[0].rule_id == "never-fired"

    def test_rules_alone_still_assert_against_the_actual(self) -> None:
        """With no reference investigation, a rule is an assertion rather than a tolerance."""
        actual = _investigation(weight=4.0)
        assert compare_investigations(actual, None, [ExpectedResult(rule_id="phishing-page", score="> 1")]) == []
        violated = compare_investigations(actual, None, [ExpectedResult(rule_id="phishing-page", score="> 99")])
        assert [d.status for d in violated] == [DiffStatus.MISMATCH]

    def test_a_violated_rule_is_reported_even_when_the_two_agree(self) -> None:
        """
        The case a tolerance rule is least able to catch by eye, and the one that was dropped.

        Marking a rule consumed as soon as it *matched* a key meant that two investigations
        agreeing on a finding left every branch of the comparison unentered — so the rule was
        never evaluated, here or in the pass that follows. Agreement is not correctness: both
        sides can be wrong together, which is precisely what a band is asked to detect.
        """
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        assert compare_investigations(actual, expected) == []

        rules = [ExpectedResult(rule_id="phishing-page", score="< 0.1")]
        diffs = compare_investigations(actual, expected, rules)
        assert [d.status for d in diffs] == [DiffStatus.MISMATCH]
        assert diffs[0].expected_score_rule == "< 0.1"

    def test_a_satisfied_rule_stays_silent_when_the_two_agree(self) -> None:
        actual, expected = _investigation(weight=4.0), _investigation(weight=4.0)
        rules = [ExpectedResult(rule_id="phishing-page", score=">= 1.0")]
        assert compare_investigations(actual, expected, rules) == []

    @pytest.mark.parametrize("status", [DiffStatus.ADDED, DiffStatus.REMOVED, DiffStatus.MISMATCH])
    def test_a_settled_key_is_never_reported_twice(self, status: DiffStatus) -> None:
        """The rule has had its say through the structural row; running it again would duplicate."""
        actual, expected = _investigation(weight=7.0), _investigation(weight=4.0)
        if status is DiffStatus.ADDED:
            actual.finding_create("solo-rule", weight=2.0)
        elif status is DiffStatus.REMOVED:
            expected.finding_create("solo-rule", weight=2.0)
        rule_id = "phishing-page" if status is DiffStatus.MISMATCH else "solo-rule"

        rules = [ExpectedResult(rule_id=rule_id, score="< 0.1")]
        diffs = [d for d in compare_investigations(actual, expected, rules) if d.rule_id == rule_id]
        assert len(diffs) == 1, diffs
        assert diffs[0].status is status


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
