"""
Tests for the Cyvest comparison module.
"""

from decimal import Decimal
from io import StringIO

import pytest
from rich.console import Console

from cyvest import Cyvest, Level
from cyvest.compare import (
    DiffItem,
    DiffStatus,
    ExpectedResult,
    ObservableDiff,
    ThreatIntelDiff,
    compare_investigations,
    evaluate_score_rule,
    parse_score_rule,
)
from cyvest.io_rich import display_diff


class TestParseScoreRule:
    """Tests for score rule parsing."""

    def test_parse_greater_equal(self) -> None:
        operator, value = parse_score_rule(">= 0.01")
        assert operator == ">="
        assert value == Decimal("0.01")

    def test_parse_less_than(self) -> None:
        operator, value = parse_score_rule("< 3")
        assert operator == "<"
        assert value == Decimal("3")

    def test_parse_equal(self) -> None:
        operator, value = parse_score_rule("== 1.0")
        assert operator == "=="
        assert value == Decimal("1.0")

    def test_parse_not_equal(self) -> None:
        operator, value = parse_score_rule("!= 5.5")
        assert operator == "!="
        assert value == Decimal("5.5")

    def test_parse_greater_than(self) -> None:
        operator, value = parse_score_rule("> 2")
        assert operator == ">"
        assert value == Decimal("2")

    def test_parse_less_equal(self) -> None:
        operator, value = parse_score_rule("<= 10")
        assert operator == "<="
        assert value == Decimal("10")

    def test_parse_negative_value(self) -> None:
        operator, value = parse_score_rule(">= -1")
        assert operator == ">="
        assert value == Decimal("-1")

    def test_parse_with_spaces(self) -> None:
        operator, value = parse_score_rule("  >=   0.5  ")
        assert operator == ">="
        assert value == Decimal("0.5")

    def test_parse_invalid_rule(self) -> None:
        with pytest.raises(ValueError, match="Invalid score rule"):
            parse_score_rule("invalid")

    def test_parse_missing_operator(self) -> None:
        with pytest.raises(ValueError, match="Invalid score rule"):
            parse_score_rule("0.5")


class TestEvaluateScoreRule:
    """Tests for score rule evaluation."""

    def test_greater_equal_true(self) -> None:
        assert evaluate_score_rule(Decimal("1.0"), ">= 0.5") is True

    def test_greater_equal_exact(self) -> None:
        assert evaluate_score_rule(Decimal("0.5"), ">= 0.5") is True

    def test_greater_equal_false(self) -> None:
        assert evaluate_score_rule(Decimal("0.4"), ">= 0.5") is False

    def test_less_than_true(self) -> None:
        assert evaluate_score_rule(Decimal("2.0"), "< 3") is True

    def test_less_than_false(self) -> None:
        assert evaluate_score_rule(Decimal("3.0"), "< 3") is False

    def test_equal_true(self) -> None:
        assert evaluate_score_rule(Decimal("1.0"), "== 1.0") is True

    def test_equal_false(self) -> None:
        assert evaluate_score_rule(Decimal("1.1"), "== 1.0") is False

    def test_not_equal_true(self) -> None:
        assert evaluate_score_rule(Decimal("1.1"), "!= 1.0") is True

    def test_not_equal_false(self) -> None:
        assert evaluate_score_rule(Decimal("1.0"), "!= 1.0") is False


class TestExpectedResult:
    """Tests for ExpectedResult model validation."""

    def test_create_with_key(self) -> None:
        rule = ExpectedResult(key="fnd:test-finding", level=Level.NOTABLE, score=">= 1.0")
        assert rule.key == "fnd:test-finding"
        assert rule.level == Level.NOTABLE
        assert rule.score == ">= 1.0"

    def test_create_with_finding_name(self) -> None:
        rule = ExpectedResult(finding_name="test-finding", score=">= 1.0")
        assert rule.finding_name == "test-finding"
        assert rule.key == "fnd:test-finding"  # Derived from finding_name

    def test_create_without_key_or_name_fails(self) -> None:
        with pytest.raises(ValueError, match="Either finding_name or key must be provided"):
            ExpectedResult(level=Level.NOTABLE, score=">= 1.0")

    def test_create_with_both_key_and_name(self) -> None:
        rule = ExpectedResult(finding_name="my-finding", key="fnd:custom-key", score=">= 1.0")
        assert rule.finding_name == "my-finding"
        assert rule.key == "fnd:custom-key"  # Provided key takes precedence

    def test_create_with_ignore(self) -> None:
        rule = ExpectedResult(finding_name="test-finding", ignore={DiffStatus.ADDED, DiffStatus.REMOVED})
        assert rule.ignore == {DiffStatus.ADDED, DiffStatus.REMOVED}

    def test_create_with_ignore_single_status(self) -> None:
        rule = ExpectedResult(finding_name="test-finding", ignore={DiffStatus.MISMATCH})
        assert rule.ignore == {DiffStatus.MISMATCH}


class TestCompareInvestigations:
    """Tests for compare_investigations function."""

    def test_no_differences_same_investigation(self) -> None:
        cv1 = Cyvest()
        cv1.finding_create("test-finding", "Test description", score=Decimal("1.0"), level=Level.NOTABLE)

        cv2 = Cyvest()
        cv2.finding_create("test-finding", "Test description", score=Decimal("1.0"), level=Level.NOTABLE)

        diffs = compare_investigations(cv1, cv2)
        assert len(diffs) == 0

    def test_finding_added(self) -> None:
        expected = Cyvest()

        actual = Cyvest()
        actual.finding_create("new-finding", "New finding", score=Decimal("1.0"), level=Level.NOTABLE)

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.ADDED
        assert diffs[0].key == "fnd:new-finding"

    def test_finding_removed(self) -> None:
        expected = Cyvest()
        expected.finding_create("old-finding", "Old finding", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.REMOVED
        assert diffs[0].key == "fnd:old-finding"

    def test_finding_mismatch_score(self) -> None:
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.MISMATCH
        assert diffs[0].expected_score == Decimal("1.0")
        assert diffs[0].actual_score == Decimal("2.0")

    def test_finding_mismatch_level(self) -> None:
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.SUSPICIOUS)

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.MISMATCH
        assert diffs[0].expected_level == Level.NOTABLE
        assert diffs[0].actual_level == Level.SUSPICIOUS

    def test_tolerance_rule_satisfied(self) -> None:
        """Test that tolerance rules can mark differences as OK."""
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.11"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("1.07"), level=Level.NOTABLE)

        # Without tolerance rule - should be a mismatch
        diffs_no_rule = compare_investigations(actual, expected)
        assert len(diffs_no_rule) == 1
        assert diffs_no_rule[0].status == DiffStatus.MISMATCH

        # With tolerance rule - should be OK
        rules = [ExpectedResult(key="fnd:test-finding", score=">= 1.0")]
        diffs_with_rule = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs_with_rule) == 0

    def test_tolerance_rule_violated(self) -> None:
        """Test that violations of tolerance rules are still flagged."""
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.11"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("0.5"), level=Level.NOTABLE)

        rules = [ExpectedResult(key="fnd:test-finding", score=">= 1.0")]
        diffs = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.MISMATCH
        assert diffs[0].expected_score_rule == ">= 1.0"

    def test_observable_diffs_included(self) -> None:
        """Test that observable diffs are populated."""
        expected = Cyvest()
        expected_finding = expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)
        expected_obs = expected.observable_create(Cyvest.OBS.DOMAIN, "example.com")
        expected_finding.link_observable(expected_obs)

        actual = Cyvest()
        actual_finding = actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)
        actual_obs = actual.observable_create(Cyvest.OBS.DOMAIN, "example.com")
        actual_finding.link_observable(actual_obs)

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert len(diffs[0].observable_diffs) == 1
        obs_diff = diffs[0].observable_diffs[0]
        assert obs_diff.value == "example.com"
        assert obs_diff.obs_type == "domain"

    def test_threat_intel_diffs_included(self) -> None:
        """Test that threat intel diffs are populated."""
        expected = Cyvest()
        expected_finding = expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)
        expected_obs = expected.observable_create(Cyvest.OBS.DOMAIN, "example.com")
        expected_obs.with_ti("VirusTotal", score=Decimal("0.0"), level=Level.INFO)
        expected_finding.link_observable(expected_obs)

        actual = Cyvest()
        actual_finding = actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)
        actual_obs = actual.observable_create(Cyvest.OBS.DOMAIN, "example.com")
        actual_obs.with_ti("VirusTotal", score=Decimal("1.0"), level=Level.NOTABLE)
        actual_finding.link_observable(actual_obs)

        diffs = compare_investigations(actual, expected)
        assert len(diffs) == 1
        assert len(diffs[0].observable_diffs) == 1
        obs_diff = diffs[0].observable_diffs[0]
        assert len(obs_diff.threat_intel_diffs) == 1
        ti_diff = obs_diff.threat_intel_diffs[0]
        assert ti_diff.source == "VirusTotal"
        assert ti_diff.expected_score == Decimal("0.0")
        assert ti_diff.actual_score == Decimal("1.0")

    def test_ignore_added_finding(self) -> None:
        """Test that ignore={ADDED} suppresses ADDED diffs."""
        expected = Cyvest()

        actual = Cyvest()
        actual.finding_create("new-finding", "New finding", score=Decimal("1.0"), level=Level.NOTABLE)

        # Without ignore rule - should be ADDED
        diffs_no_rule = compare_investigations(actual, expected)
        assert len(diffs_no_rule) == 1
        assert diffs_no_rule[0].status == DiffStatus.ADDED

        # With ignore rule - should be suppressed
        rules = [ExpectedResult(finding_name="new-finding", ignore={DiffStatus.ADDED})]
        diffs_with_rule = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs_with_rule) == 0

    def test_ignore_removed_finding(self) -> None:
        """Test that ignore={REMOVED} suppresses REMOVED diffs."""
        expected = Cyvest()
        expected.finding_create("old-finding", "Old finding", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()

        # Without ignore rule - should be REMOVED
        diffs_no_rule = compare_investigations(actual, expected)
        assert len(diffs_no_rule) == 1
        assert diffs_no_rule[0].status == DiffStatus.REMOVED

        # With ignore rule - should be suppressed
        rules = [ExpectedResult(finding_name="old-finding", ignore={DiffStatus.REMOVED})]
        diffs_with_rule = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs_with_rule) == 0

    def test_ignore_mismatch_finding(self) -> None:
        """Test that ignore={MISMATCH} suppresses MISMATCH diffs."""
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)

        # Without ignore rule - should be MISMATCH
        diffs_no_rule = compare_investigations(actual, expected)
        assert len(diffs_no_rule) == 1
        assert diffs_no_rule[0].status == DiffStatus.MISMATCH

        # With ignore rule - should be suppressed
        rules = [ExpectedResult(finding_name="test-finding", ignore={DiffStatus.MISMATCH})]
        diffs_with_rule = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs_with_rule) == 0

    def test_ignore_multiple_statuses(self) -> None:
        """Test that ignore with multiple statuses works correctly."""
        expected = Cyvest()
        expected.finding_create("removed-finding", "Removed", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("added-finding", "Added", score=Decimal("1.0"), level=Level.NOTABLE)

        # Create rules that ignore both ADDED and REMOVED
        rules = [
            ExpectedResult(finding_name="added-finding", ignore={DiffStatus.ADDED, DiffStatus.REMOVED}),
            ExpectedResult(finding_name="removed-finding", ignore={DiffStatus.ADDED, DiffStatus.REMOVED}),
        ]
        diffs = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs) == 0

    def test_ignore_does_not_affect_other_statuses(self) -> None:
        """Test that ignoring ADDED doesn't suppress REMOVED or MISMATCH."""
        expected = Cyvest()
        expected.finding_create("removed-finding", "Removed", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("added-finding", "Added", score=Decimal("1.0"), level=Level.NOTABLE)

        # Rule ignores ADDED only - should not affect REMOVED
        rules = [
            ExpectedResult(finding_name="added-finding", ignore={DiffStatus.ADDED}),
            ExpectedResult(finding_name="removed-finding", ignore={DiffStatus.ADDED}),  # Wrong status
        ]
        diffs = compare_investigations(actual, expected, result_expected=rules)
        # ADDED is suppressed, REMOVED is NOT suppressed
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.REMOVED

    def test_ignore_all_statuses(self) -> None:
        """Test that ignore with all statuses suppresses everything for that finding."""
        expected = Cyvest()
        expected.finding_create("volatile-finding", "Volatile", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("volatile-finding", "Volatile", score=Decimal("2.0"), level=Level.SUSPICIOUS)

        # Ignore all statuses
        rules = [
            ExpectedResult(
                finding_name="volatile-finding",
                ignore={DiffStatus.ADDED, DiffStatus.REMOVED, DiffStatus.MISMATCH},
            )
        ]
        diffs = compare_investigations(actual, expected, result_expected=rules)
        assert len(diffs) == 0


class TestDisplayDiff:
    """Tests for display_diff function."""

    def test_display_empty_diff(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)
        display_diff([], console.print, title="Empty Diff")
        rendered = output.getvalue()
        assert "Empty Diff" in rendered

    def test_display_added_finding(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)

        diffs = [
            DiffItem(
                status=DiffStatus.ADDED,
                key="fnd:new-finding",
                finding_name="new-finding",
                actual_level=Level.NOTABLE,
                actual_score=Decimal("0.02"),
            )
        ]
        display_diff(diffs, console.print, title="Test Diff")
        rendered = output.getvalue()
        assert "fnd:new-finding" in rendered
        assert "+" in rendered

    def test_display_removed_finding(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)

        diffs = [
            DiffItem(
                status=DiffStatus.REMOVED,
                key="fnd:old-finding",
                finding_name="old-finding",
                expected_level=Level.SUSPICIOUS,
                expected_score=Decimal("1.0"),
            )
        ]
        display_diff(diffs, console.print, title="Test Diff")
        rendered = output.getvalue()
        assert "fnd:old-finding" in rendered
        assert "-" in rendered

    def test_display_mismatch_with_rule(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)

        diffs = [
            DiffItem(
                status=DiffStatus.MISMATCH,
                key="fnd:roger-ai",
                finding_name="roger-ai",
                expected_level=Level.SUSPICIOUS,
                expected_score=Decimal("1.11"),
                expected_score_rule="== 1.11",
                actual_level=Level.SUSPICIOUS,
                actual_score=Decimal("1.07"),
            )
        ]
        display_diff(diffs, console.print, title="Test Diff")
        rendered = output.getvalue()
        assert "fnd:roger-ai" in rendered
        # The ✗ character for mismatch
        assert "\u2717" in rendered or "✗" in rendered

    def test_display_with_observable_tree(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)

        diffs = [
            DiffItem(
                status=DiffStatus.ADDED,
                key="fnd:domain-finding",
                finding_name="domain-finding",
                actual_level=Level.NOTABLE,
                actual_score=Decimal("0.02"),
                observable_diffs=[
                    ObservableDiff(
                        observable_key="obs:domain:example.com",
                        obs_type="domain",
                        value="example.com",
                        actual_level=Level.INFO,
                        actual_score=Decimal("0.0"),
                        threat_intel_diffs=[
                            ThreatIntelDiff(
                                source="VirusTotal",
                                actual_level=Level.INFO,
                                actual_score=Decimal("0.0"),
                            )
                        ],
                    )
                ],
            )
        ]
        display_diff(diffs, console.print, title="Test Diff")
        rendered = output.getvalue()
        assert "example.com" in rendered
        assert "VirusTotal" in rendered


class TestCyvestCompareMethod:
    """Tests for Cyvest.compare() and display_diff() methods."""

    def test_cyvest_compare_method(self) -> None:
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)

        diffs = actual.compare(expected=expected)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.MISMATCH

    def test_cyvest_compare_with_rules(self) -> None:
        expected = Cyvest()
        expected.finding_create("test-finding", "Test", score=Decimal("1.0"), level=Level.NOTABLE)

        actual = Cyvest()
        actual.finding_create("test-finding", "Test", score=Decimal("2.0"), level=Level.NOTABLE)

        rules = [ExpectedResult(key="fnd:test-finding", score=">= 1.0")]
        diffs = actual.compare(expected=expected, result_expected=rules)
        assert len(diffs) == 0
