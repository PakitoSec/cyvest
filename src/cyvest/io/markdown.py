"""
Markdown renderings of an investigation — one module, two readers.

An analyst and a language model want the same facts laid out differently. The analyst reads names
and values, every finding, sorted by key, once. The model needs the **keys** it will quote back in
a tool call, the strongest items first and the rest truncated, the conclusions apart, the
contradictions spelled out — and a text that does not change between two identical states, so a
provider's prompt cache keeps hitting it. Both renderings select and sort through the same helpers
here, so they cannot drift on what a table contains; only the shape of a row differs.

Everything is derived from the report and sorted explicitly: the same investigation renders to the
same text under any hash seed.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal

from cyvest.enums import DecisionKind, Effect, Status, Verdict
from cyvest.evaluation.report import FindingResult, ObservableResult
from cyvest.facts import Finding, Observable
from cyvest.investigation import Investigation

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest

FindingFilter = Literal["all", "evaluated", "pending", "conclusions"]
Source = "Cyvest | Investigation"


def _investigation_of(source: Cyvest | Investigation) -> Investigation:
    return source if isinstance(source, Investigation) else source._investigation


def _score(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def _type_name(observable: Observable) -> str:
    return str(getattr(observable.obs_type, "value", observable.obs_type))


def _truncated(lines: list[str], limit: int | None, noun: str) -> list[str]:
    if limit is None or len(lines) <= limit:
        return lines
    return [*lines[:limit], f"… {len(lines) - limit} more {noun}"]


# --------------------------------------------------------------------------- selection


def _findings(
    investigation: Investigation,
    *,
    status: FindingFilter = "all",
    sort: Literal["key", "score"] = "key",
) -> list[tuple[str, Finding, FindingResult | None]]:
    """Findings with their result, filtered and ordered. ``score`` order is strongest first, key breaks ties."""
    report = investigation.report
    rows = []
    for key, finding in investigation.get_all_findings().items():
        concludes = finding.effect is not Effect.ADDITIVE
        if status == "conclusions" and not concludes:
            continue
        if status != "conclusions" and status != "all" and concludes:
            continue
        if status == "evaluated" and finding.status is not Status.EVALUATED:
            continue
        if status == "pending" and finding.status is not Status.PENDING:
            continue
        rows.append((key, finding, report.finding(key)))
    if sort == "score":
        return sorted(rows, key=lambda row: (-abs(row[2].score or 0.0) if row[2] else 0.0, row[0]))
    return sorted(rows, key=lambda row: row[0])


def _observables(
    investigation: Investigation,
    *,
    include_root: bool = False,
    obs_type: str | None = None,
    min_abs_score: float = 0.0,
    sort: Literal["key", "score"] = "key",
) -> list[tuple[str, Observable, ObservableResult | None]]:
    report = investigation.report
    root_key = investigation.root_key
    wanted = obs_type.strip().lower() if obs_type else None
    rows = []
    for key, observable in investigation.get_all_observables().items():
        if key == root_key and not include_root:
            continue
        if wanted is not None and _type_name(observable) != wanted:
            continue
        result = report.observable(key)
        score = result.score if result is not None and result.score is not None else 0.0
        if abs(score) < min_abs_score:
            continue
        rows.append((key, observable, result))
    if sort == "score":
        return sorted(rows, key=lambda row: (-abs(row[2].score or 0.0) if row[2] else 0.0, row[0]))
    return sorted(rows, key=lambda row: row[0])


# --------------------------------------------------------------------------- the human report


def generate_markdown_report(
    source: Cyvest | Investigation,
    *,
    include_tags: bool = True,
    include_observables: bool = True,
) -> str:
    """
    The analyst's report: names and values, every finding, sorted by key.

    Every figure comes from the report, and each one travels with the engine that produced it —
    comparing scores across engines is meaningless, so the id is never dropped. The observable
    table can be dropped entirely when the reader does not need it.
    """
    investigation = _investigation_of(source)
    report = investigation.report
    header = investigation.store.header
    lines: list[str] = [
        f"# {header.name or header.investigation_id}",
        "",
        f"- **Score**: {report.investigation.score:.2f} ({report.investigation.verdict.value})",
        f"- **Engine**: `{report.engine_id}` · policy `{report.policy_version}`",
        f"- **Opened**: {header.opened_at.isoformat()}",
        "",
    ]

    decisions = investigation.get_all_decisions()
    if decisions:
        lines += ["## Decisions", "", "| Target | Kind | By | Justification |", "|---|---|---|---|"]
        for decision in decisions.values():
            lines.append(
                f"| `{decision.target_key}` | {decision.kind.value} | {decision.source.name} "
                f"| {decision.justification or ''} |"
            )
        lines.append("")

    lines += ["## Findings", "", "| Rule | Score | Verdict | Status |", "|---|---|---|---|"]
    for _key, finding, result in _findings(investigation):
        if result is None:
            continue
        lines.append(
            f"| {finding.name or finding.rule_id} | {_score(result.score)} | {result.verdict.value} "
            f"| {result.status.value} |"
        )
    lines.append("")

    if include_observables:
        lines += ["## Observables", "", "| Type | Value | Score | Verdict |", "|---|---|---|---|"]
        for _key, observable, result in _observables(investigation):
            score = _score(None if result is None else result.score)
            verdict = result.verdict.value if result else Verdict.INFO.value
            lines.append(f"| {_type_name(observable)} | `{observable.value}` | {score} | {verdict} |")
        lines.append("")

    if include_tags and investigation.get_all_tags():
        lines += ["## Tags", "", "| Tag | Aggregated score |", "|---|---|"]
        for tag in sorted(investigation.get_all_tags().values(), key=lambda t: t.name):
            lines.append(f"| {tag.name} | {investigation.get_tag_aggregated_score(tag.name):.2f} |")
        lines.append("")

    return "\n".join(lines)


def save_investigation_markdown(
    source: Cyvest | Investigation,
    filepath: str | Path,
    *,
    include_tags: bool = True,
    include_observables: bool = True,
) -> str:
    report = generate_markdown_report(source, include_tags=include_tags, include_observables=include_observables)
    Path(filepath).write_text(report.rstrip("\n") + "\n", encoding="utf-8")
    return str(filepath)


# --------------------------------------------------------------------------- the model's report


def findings_markdown(
    source: Cyvest | Investigation, *, status: FindingFilter = "all", limit: int | None = None
) -> str:
    """
    Findings for a model, strongest first:
    `key | rule_id | verdict | score | status | #obs | occurred_at | tactic | name`.

    ``occurred_at`` and ``tactic`` are shown so the model sees what it already dated and tagged,
    and re-asserts a finding rather than adding a twin.
    """
    investigation = _investigation_of(source)
    rows = []
    for key, finding, result in _findings(investigation, status=status, sort="score"):
        if status == "all" and finding.effect is not Effect.ADDITIVE:
            continue  # conclusions have their own section; see render_llm_summary
        score = _score(None if result is None else result.score)
        occurred = finding.occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ") if finding.occurred_at is not None else ""
        tactic = finding.tactic.value if finding.tactic is not None else ""
        rows.append(
            f"| `{key}` | {finding.rule_id} | {finding.verdict.value} | {score} | {finding.status.value} "
            f"| {len(finding.observable_links)} | {occurred} | {tactic} | {finding.name or ''} |"
        )
    if not rows:
        return "_no findings_"
    header = [
        "| key | rule_id | verdict | score | status | #obs | occurred_at | tactic | name |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    return "\n".join(header + _truncated(rows, limit, "findings"))


def observables_markdown(
    source: Cyvest | Investigation,
    *,
    obs_type: str | None = None,
    min_abs_score: float = 0.0,
    limit: int | None = 50,
    include_root: bool = False,
) -> str:
    """Observables for a model, strongest first: `key | type | value | verdict | score | #signals | decision`."""
    investigation = _investigation_of(source)
    rows = []
    for key, observable, result in _observables(
        investigation, include_root=include_root, obs_type=obs_type, min_abs_score=min_abs_score, sort="score"
    ):
        decision = investigation.get_decision(key)
        verdict = result.verdict.value if result else Verdict.INFO.value
        rows.append(
            f"| `{key}` | {_type_name(observable)} | `{observable.value}` | {verdict} "
            f"| {_score(None if result is None else result.score)} "
            f"| {len(investigation.store.signals_for(key))} | {decision.kind.value if decision else ''} |"
        )
    if not rows:
        return "_no observables_"
    header = ["| key | type | value | verdict | score | #signals | decision |", "|---|---|---|---|---|---|---|"]
    return "\n".join(header + _truncated(rows, limit, "observables"))


def decisions_markdown(source: Cyvest | Investigation) -> str:
    investigation = _investigation_of(source)
    decisions = investigation.get_all_decisions()
    if not decisions:
        return "_no decisions_"
    return "\n".join(
        f"- `{decision.target_key}` **{decision.kind.value}** by {decision.source.name}: {decision.justification or ''}"
        for _key, decision in sorted(decisions.items())
    )


def contradictions(source: Cyvest | Investigation) -> list[str]:
    """
    Where the facts disagree with each other.

    Two findings of opposite polarity linked to the same observable, and findings whose own
    verdict was overridden by what their observables scored. Neither is an error — both are what a
    reviewer should read first.
    """
    investigation = _investigation_of(source)
    by_observable: dict[str, list[tuple[str, int]]] = {}
    lines: list[str] = []
    for key, finding, result in _findings(investigation):
        for link in finding.observable_links:
            by_observable.setdefault(link.observable_key, []).append((key, finding.verdict.polarity))
        if result is not None and result.own_term_suppressed and result.verdict is not finding.verdict:
            lines.append(
                f"`{key}` asserts {finding.verdict.value} but its linked observables scored "
                f"{result.verdict.value}; the observables won"
            )
    for observable_key in sorted(by_observable):
        entries = by_observable[observable_key]
        positive = sorted(key for key, polarity in entries if polarity > 0)
        negative = sorted(key for key, polarity in entries if polarity < 0)
        if positive and negative:
            lines.append(
                f"`{observable_key}` is called inculpatory by {', '.join(f'`{k}`' for k in positive)} "
                f"and exculpatory by {', '.join(f'`{k}`' for k in negative)}"
            )
    return lines


def possible_duplicates(source: Cyvest | Investigation, *, threshold: float = 0.5) -> list[str]:
    """
    Findings that may say the same thing twice.

    Two evaluated, additive findings of the same non-neutral polarity whose linked observables
    overlap at or above ``threshold`` (Jaccard). Only a hint: a brute force and a lateral movement
    on one host share every observable and are two findings — so nothing is merged here. The
    reviewer decides, and refutes the redundant one so it stops counting; the global score is a sum
    over findings, so a duplicate counts twice until then. Findings already refuted are left out.
    """
    investigation = _investigation_of(source)
    store = investigation.store
    candidates: list[tuple[str, int, frozenset[str]]] = []
    for key, finding, _result in _findings(investigation, status="evaluated"):
        decision = store.decision_for(key)
        if decision is not None and decision.kind is DecisionKind.REFUTE:
            continue
        keys = frozenset(link.observable_key for link in finding.observable_links)
        if finding.verdict.polarity == 0 or not keys:
            continue
        candidates.append((key, finding.verdict.polarity, keys))
    lines: list[str] = []
    for index, (key_a, polarity, keys_a) in enumerate(candidates):
        for key_b, polarity_b, keys_b in candidates[index + 1 :]:
            if polarity != polarity_b:
                continue
            shared = keys_a & keys_b
            if not shared or len(shared) / len(keys_a | keys_b) < threshold:
                continue
            stance = "inculpatory" if polarity > 0 else "exculpatory"
            listed = sorted(shared)
            shown = ", ".join(f"`{k}`" for k in listed[:5]) + (f", … {len(listed) - 5} more" if len(listed) > 5 else "")
            lines.append(
                f"`{key_a}` and `{key_b}` are both {stance} and share {len(shared)} of "
                f"{len(keys_a | keys_b)} observables ({shown})"
            )
    return lines


def explain_text(source: Cyvest | Investigation, key: str) -> str:
    """The contributions behind a finding or an observable, one per line. Unknown key raises."""
    investigation = _investigation_of(source)
    contributions = investigation.explain(key)
    report = investigation.report
    result = report.finding(key) or report.observable(key)
    lines = [f"`{key}`: {result.verdict.value} {_score(result.score)}" if result else f"`{key}`"]
    if not contributions:
        lines.append("- no contribution")
    for contribution in contributions:
        retained = "" if contribution.retained else " (not retained)"
        detail = f" — {contribution.detail}" if contribution.detail else ""
        lines.append(
            f"- {contribution.label}: {contribution.value:+.2f}{retained} from `{contribution.source_key}`{detail}"
        )
    return "\n".join(lines)


def timeline_markdown(source: Cyvest | Investigation, *, limit: int | None = 50) -> str:
    """
    The timeline on the ``occurred`` axis, oldest first.

    An undated fact is placed at its assertion time and marked ``(asserted)``: the model must not
    read the moment it wrote a finding as the moment the activity happened.
    """
    entries = _investigation_of(source).timeline()
    if not entries:
        return "_empty timeline_"
    lines = []
    for entry in entries:
        subject = f" (`{entry.subject_key}`)" if entry.subject_key else ""
        when = entry.when.isoformat() if entry.dated else f"{entry.when.isoformat()} (asserted)"
        tactic = f" — tactic: `{entry.tactic.value}`" if entry.tactic is not None else ""
        lines.append(f"- {when} [{entry.kind}] {entry.title}{subject}{tactic}")
    return "\n".join(_truncated(lines, limit, "entries"))


def render_llm_summary(
    source: Cyvest | Investigation,
    *,
    max_findings: int = 30,
    max_observables: int = 30,
    include_root: bool = False,
) -> str:
    """
    The model's report: the whole investigation on one screen — score, conclusions, findings,
    observables, decisions, contradictions, possible duplicates, pending work — with the keys a tool call needs.
    Meant for a system prompt block, refreshed on every model call; no timestamp, so two identical
    states render identically.
    """
    investigation = _investigation_of(source)
    report = investigation.report
    header = investigation.store.header
    findings = investigation.get_all_findings()
    conclusions = _findings(investigation, status="conclusions")
    observable_count = sum(1 for key in investigation.get_all_observables() if key != investigation.root_key)
    total = report.investigation
    signal_count = len(investigation.get_all_threat_intels())
    decision_count = len(investigation.get_all_decisions())

    lines = [
        f"# Investigation `{header.name or header.investigation_id}`",
        f"- Score **{total.score if total.score is not None else 0.0:.2f}** → verdict **{total.verdict.value}** "
        f"(engine `{report.engine_id}`, policy `{report.policy_version}`)",
        f"- {observable_count} observables, {len(findings) - len(conclusions)} findings, "
        f"{len(conclusions)} conclusions, {signal_count} signals, {decision_count} decisions",
        "",
        "## Conclusions",
    ]
    if conclusions:
        for key, finding, _result in conclusions:
            lines.append(
                f"- `{key}` → **{finding.verdict.value}** ({finding.effect.value}, confidence {finding.confidence:.2f})"
                + (f" — {finding.name}" if finding.name else "")
            )
    else:
        lines.append("_none recorded_")
    lines += ["", "## Findings", findings_markdown(investigation, limit=max_findings)]
    lines += [
        "",
        "## Observables",
        observables_markdown(investigation, limit=max_observables, include_root=include_root),
    ]
    lines += ["", "## Decisions", decisions_markdown(investigation)]
    issues = contradictions(investigation)
    lines += ["", "## Contradictions"]
    lines += [f"- {issue}" for issue in issues] if issues else ["_none_"]
    duplicates = possible_duplicates(investigation)
    if duplicates:
        lines += ["", "## Possible duplicates", *(f"- {line}" for line in duplicates)]
    pending = [key for key, _finding, _result in _findings(investigation, status="pending")]
    if pending:
        lines += ["", "## Pending findings", *(f"- `{key}`" for key in pending)]
    return "\n".join(lines)


__all__ = [
    "FindingFilter",
    "contradictions",
    "decisions_markdown",
    "explain_text",
    "findings_markdown",
    "generate_markdown_report",
    "observables_markdown",
    "possible_duplicates",
    "render_llm_summary",
    "save_investigation_markdown",
    "timeline_markdown",
]
