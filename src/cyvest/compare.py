"""
Comparison module for Cyvest investigations.

Provides functionality to compare two investigations with optional tolerance rules,
identifying differences in checks, observables, and threat intelligence.
"""

from __future__ import annotations

import re
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, model_validator

from cyvest.keys import generate_check_key
from cyvest.levels import Level

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest
    from cyvest.proxies import CheckProxy


class DiffStatus(str, Enum):
    """Status indicating the type of difference found."""

    ADDED = "+"
    REMOVED = "-"
    MISMATCH = "\u2717"  # ✗


class ExpectedResult(BaseModel):
    """Tolerance rule for a specific check."""

    check_name: str | None = None
    key: str | None = None
    level: Level | None = None
    score: str | None = None  # Tolerance rule: ">= 0.01", "< 3", "== 1.0"
    ignore: set[DiffStatus] | None = None  # Statuses to ignore: ADDED, REMOVED, MISMATCH

    @model_validator(mode="after")
    def validate_key_or_name(self) -> ExpectedResult:
        if not self.check_name and not self.key:
            raise ValueError("Either check_name or key must be provided")
        # Derive key from check_name if not provided
        if self.check_name and not self.key:
            self.key = generate_check_key(self.check_name)
        return self

    model_config = {"extra": "forbid"}


class ThreatIntelDiff(BaseModel):
    """Diff info for threat intel attached to an observable."""

    source: str
    expected_score: Decimal | None = None
    expected_level: Level | None = None
    actual_score: Decimal | None = None
    actual_level: Level | None = None


class ObservableDiff(BaseModel):
    """Diff info for an observable linked to a check."""

    observable_key: str
    obs_type: str
    value: str
    expected_score: Decimal | None = None
    expected_level: Level | None = None
    actual_score: Decimal | None = None
    actual_level: Level | None = None
    threat_intel_diffs: list[ThreatIntelDiff] = Field(default_factory=list)


class DiffItem(BaseModel):
    """A single difference found between investigations."""

    status: DiffStatus
    key: str
    check_name: str
    # Expected values (from expected investigation or rule)
    expected_level: Level | None = None
    expected_score: Decimal | None = None
    expected_score_rule: str | None = None  # e.g., ">= 1.0"
    # Actual values
    actual_level: Level | None = None
    actual_score: Decimal | None = None
    # Linked observables with their diffs
    observable_diffs: list[ObservableDiff] = Field(default_factory=list)


def parse_score_rule(rule: str) -> tuple[str, Decimal]:
    """
    Parse score rule like '>= 0.01' into (operator, value).

    Args:
        rule: A score rule string (e.g., ">= 0.01", "< 3", "== 1.0")

    Returns:
        Tuple of (operator, threshold)

    Raises:
        ValueError: If the rule format is invalid
    """
    match = re.match(r"(>=|<=|>|<|==|!=)\s*(-?\d+\.?\d*)", rule.strip())
    if not match:
        raise ValueError(f"Invalid score rule: {rule}")
    return match.group(1), Decimal(match.group(2))


def evaluate_score_rule(actual_score: Decimal, rule: str) -> bool:
    """
    Check if actual_score satisfies the rule.

    Args:
        actual_score: The score to evaluate
        rule: A score rule string (e.g., ">= 0.01")

    Returns:
        True if the score satisfies the rule, False otherwise
    """
    operator, threshold = parse_score_rule(rule)
    ops = {
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        "<": lambda a, b: a < b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }
    return ops[operator](actual_score, threshold)


def compare_investigations(
    actual: Cyvest,
    expected: Cyvest | None = None,
    result_expected: list[ExpectedResult] | None = None,
) -> list[DiffItem]:
    """
    Compare two investigations with optional tolerance rules.

    Args:
        actual: The investigation to validate (actual results)
        expected: The reference investigation (expected results), optional
        result_expected: Tolerance rules for specific checks

    Returns:
        List of DiffItem for all differences found
    """
    diffs: list[DiffItem] = []
    rules = {r.key: r for r in (result_expected or [])}

    actual_checks = actual.check_get_all()
    expected_checks = expected.check_get_all() if expected else {}

    all_keys = set(actual_checks.keys()) | set(expected_checks.keys())

    for key in sorted(all_keys):
        actual_check = actual_checks.get(key)
        expected_check = expected_checks.get(key)
        rule = rules.get(key)

        if actual_check and not expected_check:
            # Check added in actual - skip if rule ignores ADDED
            if rule and rule.ignore and DiffStatus.ADDED in rule.ignore:
                continue
            diffs.append(
                _create_diff_item(
                    status=DiffStatus.ADDED,
                    actual_check=actual_check,
                    actual_cv=actual,
                    expected_cv=expected,
                )
            )
        elif expected_check and not actual_check:
            # Check removed from actual - skip if rule ignores REMOVED
            if rule and rule.ignore and DiffStatus.REMOVED in rule.ignore:
                continue
            diffs.append(
                _create_diff_item(
                    status=DiffStatus.REMOVED,
                    expected_check=expected_check,
                    rule=rule,
                    expected_cv=expected,
                )
            )
        else:
            # Check exists in both - compare values
            if _is_mismatch(expected_check, actual_check, rule):
                # Skip if rule ignores MISMATCH
                if rule and rule.ignore and DiffStatus.MISMATCH in rule.ignore:
                    continue
                diffs.append(
                    _create_diff_item(
                        status=DiffStatus.MISMATCH,
                        expected_check=expected_check,
                        actual_check=actual_check,
                        rule=rule,
                        actual_cv=actual,
                        expected_cv=expected,
                    )
                )

    return diffs


def _is_mismatch(
    expected: CheckProxy,
    actual: CheckProxy,
    rule: ExpectedResult | None,
) -> bool:
    """Check if there's a mismatch, considering tolerance rules."""
    # If scores and levels are equal, no mismatch
    if expected.score == actual.score and expected.level == actual.level:
        return False

    # If there's a tolerance rule with score condition
    if rule and rule.score:
        # If actual satisfies the rule, it's OK (not a mismatch)
        if evaluate_score_rule(actual.score, rule.score):
            return False

    # Scores/levels differ and no tolerance allows it
    return True


def _create_diff_item(
    status: DiffStatus,
    actual_check: CheckProxy | None = None,
    expected_check: CheckProxy | None = None,
    rule: ExpectedResult | None = None,
    actual_cv: Cyvest | None = None,
    expected_cv: Cyvest | None = None,
) -> DiffItem:
    """Create a DiffItem with observable and threat intel context."""
    check = actual_check or expected_check

    # Build observable diffs from linked observables
    observable_diffs: list[ObservableDiff] = []

    # Collect observable keys from both checks
    obs_keys: set[str] = set()
    if actual_check:
        obs_keys.update(link.observable_key for link in actual_check.observable_links)
    if expected_check:
        obs_keys.update(link.observable_key for link in expected_check.observable_links)

    for obs_key in sorted(obs_keys):
        actual_obs = actual_cv.observable_get(obs_key) if actual_cv else None
        expected_obs = expected_cv.observable_get(obs_key) if expected_cv else None
        obs = actual_obs or expected_obs

        if not obs:
            continue

        # Build threat intel diffs for this observable
        ti_diffs: list[ThreatIntelDiff] = []
        ti_sources: set[str] = set()

        if actual_obs:
            ti_sources.update(ti.source for ti in actual_obs.threat_intels)
        if expected_obs:
            ti_sources.update(ti.source for ti in expected_obs.threat_intels)

        for source in sorted(ti_sources):
            actual_ti = (
                next(
                    (ti for ti in actual_obs.threat_intels if ti.source == source),
                    None,
                )
                if actual_obs
                else None
            )
            expected_ti = (
                next(
                    (ti for ti in expected_obs.threat_intels if ti.source == source),
                    None,
                )
                if expected_obs
                else None
            )

            ti_diffs.append(
                ThreatIntelDiff(
                    source=source,
                    expected_score=expected_ti.score if expected_ti else None,
                    expected_level=expected_ti.level if expected_ti else None,
                    actual_score=actual_ti.score if actual_ti else None,
                    actual_level=actual_ti.level if actual_ti else None,
                )
            )

        observable_diffs.append(
            ObservableDiff(
                observable_key=obs_key,
                obs_type=str(obs.obs_type.value if hasattr(obs.obs_type, "value") else obs.obs_type),
                value=obs.value,
                expected_score=expected_obs.score if expected_obs else None,
                expected_level=expected_obs.level if expected_obs else None,
                actual_score=actual_obs.score if actual_obs else None,
                actual_level=actual_obs.level if actual_obs else None,
                threat_intel_diffs=ti_diffs,
            )
        )

    return DiffItem(
        status=status,
        key=check.key,
        check_name=check.check_name,
        expected_level=expected_check.level if expected_check else (rule.level if rule else None),
        expected_score=expected_check.score if expected_check else None,
        expected_score_rule=rule.score if rule else None,
        actual_level=actual_check.level if actual_check else None,
        actual_score=actual_check.score if actual_check else None,
        observable_diffs=observable_diffs,
    )
