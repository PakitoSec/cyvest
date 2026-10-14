"""
The investigation as a model may read it: the facts, never the computation.

``render_llm_summary`` shows scores and verdicts the engine derived. A harness that wants the
model to judge on the material rather than anchor on a number renders the facts instead: what was
recorded, what it cites, what was decided and where the findings disagree. Signals are shown only
for the observables the harness lets through.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from cyvest.cyvest import Cyvest

#: The fact families of a serialized document, plus the top-level decisions.
FACT_FAMILIES: tuple[str, ...] = ("observables", "relations", "signals", "evidences", "findings", "decisions")


def _cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _when(value: Any) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value is not None else ""


def _signals_visible(rule: Callable[[str], bool] | Iterable[str] | None) -> Callable[[str], bool]:
    if rule is None:
        return lambda _key: False
    if callable(rule):
        return rule
    allowed = frozenset(rule)
    return lambda key: key in allowed


def _findings(cv: Cyvest, limit: int) -> list[str]:
    rows = []
    for key, finding in sorted(cv.finding_get_all().items()):
        decision = cv.decision_get(key)
        rows.append(
            f"| `{key}` | {finding.verdict.value} | {_when(finding.occurred_at)} "
            f"| {finding.tactic.value if finding.tactic is not None else ''} "
            f"| {', '.join(f'`{e}`' for e in sorted(finding.evidence_keys))} "
            f"| {', '.join(f'`{link.observable_key}`' for link in finding.observable_links)} "
            f"| {decision.kind.value if decision else ''} | {_cell(finding.name)} |"
        )
    if not rows:
        return ["_no findings_"]
    header = [
        "| key | verdict | occurred_at | tactic | evidence | observables | decision | name |",
        "|---|---|---|---|---|---|---|---|",
    ]
    extra = [f"_… {len(rows) - limit} more findings_"] if len(rows) > limit else []
    return header + rows[:limit] + extra


def _observables(cv: Cyvest, limit: int, visible: Callable[[str], bool]) -> list[str]:
    root = cv.root().key
    rows = []
    for key, observable in sorted(cv.observable_get_all().items()):
        if key == root:
            continue
        signals = ""
        if visible(key):
            signals = ", ".join(
                f"{_cell(signal.source.name)}: {signal.verdict.value}" for signal in observable.threat_intels
            )
        decision = cv.decision_get(key)
        rows.append(
            f"| `{key}` | `{_cell(observable.value)}` | {'yes' if observable.internal else ''} "
            f"| {signals} | {decision.kind.value if decision else ''} |"
        )
    if not rows:
        return ["_no observables_"]
    header = ["| key | value | internal | signals | decision |", "|---|---|---|---|---|"]
    extra = [f"_… {len(rows) - limit} more observables_"] if len(rows) > limit else []
    return header + rows[:limit] + extra


def _disagreements(cv: Cyvest) -> list[str]:
    """Findings of opposite polarity about the same observable: the asserted verdicts only, no score."""
    by_observable: dict[str, list[tuple[str, int]]] = {}
    for key, finding in sorted(cv.finding_get_all().items()):
        if cv.decision_get(key) is not None:
            continue
        for link in finding.observable_links:
            by_observable.setdefault(link.observable_key, []).append((key, finding.verdict.polarity))
    lines = []
    for observable_key, claims in sorted(by_observable.items()):
        positive = [key for key, polarity in claims if polarity > 0]
        negative = [key for key, polarity in claims if polarity < 0]
        if positive and negative:
            lines.append(
                f"`{observable_key}`: {', '.join(f'`{k}`' for k in positive)} against "
                f"{', '.join(f'`{k}`' for k in negative)}"
            )
    return lines


def facts_status(
    cv: Cyvest,
    *,
    signals_for: Callable[[str], bool] | Iterable[str] | None = None,
    max_findings: int = 30,
    max_observables: int = 40,
) -> str:
    """
    The facts of the investigation in compact Markdown, without any score or computed verdict.

    ``signals_for`` decides which observables show their signals (a predicate or a set of keys);
    by default none do. Deterministic: two identical documents render identically.
    """
    visible = _signals_visible(signals_for)
    decisions = cv.decision_get_all()
    lines = [
        f"- {len(cv.finding_get_all())} findings, {len(cv.observable_get_all()) - 1} observables, "
        f"{len(cv.evidence_get_all())} evidences, {len(decisions)} decisions",
        "",
        "### Findings",
        *_findings(cv, max_findings),
        "",
        "### Observables",
        *_observables(cv, max_observables, visible),
    ]
    if decisions:
        lines += ["", "### Decisions"]
        lines += [f"- `{d.target_key}` {d.kind.value}: {_cell(d.justification)}" for _k, d in sorted(decisions.items())]
    disagreements = _disagreements(cv)
    if disagreements:
        lines += ["", "### Disagreements", *(f"- {line}" for line in disagreements)]
    return "\n".join(lines)


def _keys(document: Mapping[str, Any] | None) -> dict[str, set[str]]:
    document = document or {}
    facts = document.get("facts") or {}
    out = {name: set(facts.get(name) or {}) for name in FACT_FAMILIES if name != "decisions"}
    out["decisions"] = set(document.get("decisions") or {})
    return out


def ledger_delta(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """The keys each fact family gained between two serialized documents (families without news omitted)."""
    old, new = _keys(before), _keys(after)
    return {name: sorted(new[name] - old[name]) for name in FACT_FAMILIES if new[name] - old[name]}


def missing_references(
    cv: Cyvest,
    *,
    evidence_keys: Iterable[str] = (),
    observable_keys: Iterable[str] = (),
    finding_keys: Iterable[str] = (),
) -> list[str]:
    """The cited keys that do not exist in the investigation, in the order given."""
    missing = [key for key in evidence_keys if cv.evidence_get(key) is None]
    missing += [key for key in observable_keys if cv.observable_get(key) is None]
    missing += [key for key in finding_keys if cv.finding_get(key) is None]
    return missing


__all__ = ["FACT_FAMILIES", "facts_status", "ledger_delta", "missing_references"]
