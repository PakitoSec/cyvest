"""
Comparing two investigations.

Purely structural: this module reads the two reports and never re-derives a score. It also
refuses to compare results produced by different engines — a `basic-v1` score and a future
`bayesian-v1` score are not on the same scale, so a diff between them would be meaningless.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyvest.enums import Verdict

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest
    from cyvest.evaluation.report import FindingResult

_RULE = re.compile(r"(>=|<=|>|<|==|!=)\s*(-?\d+\.?\d*)")

_OPERATORS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


class EngineMismatchError(RuntimeError):
    """Raised when two investigations were scored by different engines."""


class DiffStatus(str, Enum):
    ADDED = "+"
    REMOVED = "-"
    MISMATCH = "\u2717"


class ExpectedResult(BaseModel):
    """
    A tolerance rule for one finding.

    ``verdict`` pins the conclusion; ``score`` expresses a band (``">= 0.01"``, ``"< 3"``), which
    is what makes a test survive a policy tweak that shifts magnitudes without changing meaning.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str | None = None
    key: str | None = None
    verdict: Verdict | None = None
    score: str | None = None
    ignore: set[DiffStatus] | None = None

    @model_validator(mode="after")
    def _need_a_target(self) -> ExpectedResult:
        if not self.rule_id and not self.key:
            raise ValueError("Either rule_id or key must be provided")
        return self

    def matches(self, key: str, rule_id: str) -> bool:
        return self.key == key if self.key else self.rule_id == rule_id


class ObservableDiff(BaseModel):
    """How one linked observable differs between the two runs."""

    model_config = ConfigDict(frozen=True)

    observable_key: str
    value: str = ""
    expected_score: float | None = None
    expected_verdict: Verdict | None = None
    actual_score: float | None = None
    actual_verdict: Verdict | None = None


class DiffItem(BaseModel):
    """A single difference between two investigations."""

    model_config = ConfigDict(frozen=True)

    status: DiffStatus
    key: str
    rule_id: str = ""
    expected_verdict: Verdict | None = None
    expected_score: float | None = None
    expected_score_rule: str | None = None
    actual_verdict: Verdict | None = None
    actual_score: float | None = None
    observable_diffs: tuple[ObservableDiff, ...] = Field(default=())


def parse_score_rule(rule: str) -> tuple[str, float]:
    match = _RULE.match(rule.strip())
    if not match:
        raise ValueError(f"Invalid score rule: {rule}")
    return match.group(1), float(match.group(2))


def evaluate_score_rule(actual_score: float, rule: str) -> bool:
    operator, threshold = parse_score_rule(rule)
    return _OPERATORS[operator](actual_score, threshold)


def _observable_diffs(actual: Cyvest, expected: Cyvest, finding_key: str) -> tuple[ObservableDiff, ...]:
    finding = actual._investigation.get_finding(finding_key)
    if finding is None:
        return ()
    diffs: list[ObservableDiff] = []
    for link in finding.observable_links:
        actual_result = actual.get_report().observable(link.observable_key)
        expected_result = expected.get_report().observable(link.observable_key)
        if actual_result is None and expected_result is None:
            continue
        if actual_result and expected_result and actual_result.score == expected_result.score:
            continue
        observable = actual._investigation.get_observable(link.observable_key)
        diffs.append(
            ObservableDiff(
                observable_key=link.observable_key,
                value=observable.value if observable else "",
                expected_score=expected_result.score if expected_result else None,
                expected_verdict=expected_result.verdict if expected_result else None,
                actual_score=actual_result.score if actual_result else None,
                actual_verdict=actual_result.verdict if actual_result else None,
            )
        )
    return tuple(diffs)


def compare_investigations(
    actual: Cyvest,
    expected: Cyvest | None = None,
    result_expected: list[ExpectedResult] | None = None,
    *,
    allow_engine_mismatch: bool = False,
) -> list[DiffItem]:
    """
    Diff two investigations, or check one against tolerance rules.

    The two are not independent passes. When an ``expected`` investigation is given, the rules act
    as **tolerances on that diff**: a rule its subject satisfies suppresses the exact-value
    mismatch, and ``ignore`` drops a whole status. Run side by side instead, rules could only ever
    add rows — a band rule would never loosen anything, a violated one would report the same key
    twice, and ``ignore={ADDED}`` would be unreachable.

    With no ``expected``, the rules stand alone as assertions on ``actual``.

    Raises :class:`EngineMismatchError` when the two reports come from different engines, unless
    the caller says otherwise — scores from different engines are not comparable.
    """
    actual_report = actual.get_report()
    rules = result_expected or []

    if expected is None:
        return [diff for rule in rules for diff in _check_rule(actual, rule)]

    expected_report = expected.get_report()
    if not allow_engine_mismatch and actual_report.engine_id != expected_report.engine_id:
        raise EngineMismatchError(
            f"Cannot compare a {actual_report.engine_id} report with a {expected_report.engine_id} one; "
            "scores from different engines are not on the same scale."
        )

    return _diff_against_investigation(actual, expected, rules)


def _rule_for(rules: list[ExpectedResult], key: str, rule_id: str) -> ExpectedResult | None:
    return next((rule for rule in rules if rule.matches(key, rule_id)), None)


def _ignores(rule: ExpectedResult | None, status: DiffStatus) -> bool:
    return rule is not None and rule.ignore is not None and status in rule.ignore


def _rule_tolerates(rule: ExpectedResult | None, result: FindingResult | None) -> bool:
    """
    Whether a rule vouches for the actual result, making the exact-value mismatch irrelevant.

    A rule that states nothing tolerates nothing: ``ignore`` is the way to wave a difference
    through, and a bare target would otherwise silence every mismatch on it.
    """
    if rule is None or result is None or (rule.score is None and rule.verdict is None):
        return False
    score_ok = rule.score is None or (result.score is not None and evaluate_score_rule(result.score, rule.score))
    verdict_ok = rule.verdict is None or result.verdict is rule.verdict
    return score_ok and verdict_ok


def _diff_against_investigation(
    actual: Cyvest,
    expected: Cyvest,
    rules: list[ExpectedResult] | None = None,
) -> list[DiffItem]:
    diffs: list[DiffItem] = []
    rules = rules or []
    actual_findings = actual._investigation.get_all_findings()
    expected_findings = expected._investigation.get_all_findings()
    # Tracked by identity: two rules may carry the same content and still be two rules.
    consumed: set[int] = set()

    for key in sorted(set(actual_findings) | set(expected_findings)):
        in_actual, in_expected = key in actual_findings, key in expected_findings
        actual_result = actual.get_report().finding(key)
        expected_result = expected.get_report().finding(key)
        finding = actual_findings.get(key) or expected_findings[key]
        rule = _rule_for(rules, key, finding.rule_id)
        if rule is not None:
            consumed.add(id(rule))

        if in_actual and not in_expected:
            if _ignores(rule, DiffStatus.ADDED):
                continue
            diffs.append(
                DiffItem(
                    status=DiffStatus.ADDED,
                    key=key,
                    rule_id=actual_findings[key].rule_id,
                    actual_score=actual_result.score if actual_result else None,
                    actual_verdict=actual_result.verdict if actual_result else None,
                )
            )
        elif in_expected and not in_actual:
            if _ignores(rule, DiffStatus.REMOVED):
                continue
            diffs.append(
                DiffItem(
                    status=DiffStatus.REMOVED,
                    key=key,
                    rule_id=expected_findings[key].rule_id,
                    expected_score=expected_result.score if expected_result else None,
                    expected_verdict=expected_result.verdict if expected_result else None,
                    expected_score_rule=rule.score if rule else None,
                )
            )
        elif (
            actual_result
            and expected_result
            and (actual_result.score != expected_result.score or actual_result.verdict is not expected_result.verdict)
        ):
            if _ignores(rule, DiffStatus.MISMATCH) or _rule_tolerates(rule, actual_result):
                continue
            diffs.append(
                DiffItem(
                    status=DiffStatus.MISMATCH,
                    key=key,
                    rule_id=actual_findings[key].rule_id,
                    expected_score=expected_result.score,
                    expected_verdict=expected_result.verdict,
                    expected_score_rule=rule.score if rule else None,
                    actual_score=actual_result.score,
                    actual_verdict=actual_result.verdict,
                    observable_diffs=_observable_diffs(actual, expected, key),
                )
            )

    # A rule that matched nothing on either side still expected something: report it once.
    for rule in rules:
        if id(rule) not in consumed:
            diffs.extend(_check_rule(actual, rule))
    return diffs


def _check_rule(actual: Cyvest, rule: ExpectedResult) -> list[DiffItem]:
    findings = actual._investigation.get_all_findings()
    matched = [key for key, finding in findings.items() if rule.matches(key, finding.rule_id)]

    if not matched:
        if rule.ignore and DiffStatus.REMOVED in rule.ignore:
            return []
        return [
            DiffItem(
                status=DiffStatus.REMOVED,
                key=rule.key or rule.rule_id or "",
                rule_id=rule.rule_id or "",
                expected_verdict=rule.verdict,
                expected_score_rule=rule.score,
            )
        ]

    diffs: list[DiffItem] = []
    for key in matched:
        result = actual.get_report().finding(key)
        if result is None:
            continue
        score_ok = rule.score is None or (result.score is not None and evaluate_score_rule(result.score, rule.score))
        verdict_ok = rule.verdict is None or result.verdict is rule.verdict
        if score_ok and verdict_ok:
            continue
        if rule.ignore and DiffStatus.MISMATCH in rule.ignore:
            continue
        diffs.append(
            DiffItem(
                status=DiffStatus.MISMATCH,
                key=key,
                rule_id=findings[key].rule_id,
                expected_verdict=rule.verdict,
                expected_score_rule=rule.score,
                actual_score=result.score,
                actual_verdict=result.verdict,
            )
        )
    return diffs


__all__ = [
    "DiffItem",
    "DiffStatus",
    "EngineMismatchError",
    "ExpectedResult",
    "ObservableDiff",
    "compare_investigations",
    "evaluate_score_rule",
    "parse_score_rule",
]
