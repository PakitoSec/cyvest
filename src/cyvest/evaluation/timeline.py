"""
Timeline: a projection of the fact log, never a stored state.

Nothing here is persisted, so it cannot desynchronize from the facts and merging needs no
dedicated logic — a union of facts *is* a union of events.

Bitemporal: ``occurred_at`` is when the world moved, ``asserted_at`` when the analysis did. The
caller picks which axis to read. Salience is derived from the report; there is no field to fill
in, which is what keeps it honest.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import Salience, Status, Tactic, Verdict
from cyvest.evaluation.report import Report
from cyvest.facts.base import Fact
from cyvest.facts.decision import Decision, decision_label
from cyvest.facts.evidence import Evidence
from cyvest.facts.finding import Finding
from cyvest.facts.observable import Observable
from cyvest.facts.relation import Relation
from cyvest.facts.signal import ObservableSignal
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.policy import DEFAULT_POLICY, Policy

TimeBasis = Literal["occurred", "asserted"]


class TimelineEntry(BaseModel):
    """
    A report object, never a fact. Rebuilt on demand from the log.

    ``dated`` says whether the fact carried an ``occurred_at`` of its own. On the ``occurred``
    axis an undated fact is placed at its ``asserted_at`` — a fallback, not an observation — and
    a consumer building an incident chronology rather than an investigation log filters on it.
    ``tactic`` is read from the fact when its family carries one (findings).
    """

    model_config = ConfigDict(frozen=True)

    when: datetime = Field(...)
    time_basis: TimeBasis = Field(...)
    kind: str = Field(...)
    title: str = Field(...)
    subject_key: str = Field(default="")
    refs: tuple[str, ...] = Field(default=())
    salience: Salience = Field(default=Salience.BACKGROUND)
    dated: bool = Field(default=False)
    tactic: Tactic | None = Field(default=None)


def _timestamp(fact: Fact, basis: TimeBasis) -> datetime:
    if basis == "asserted":
        return fact.asserted_at
    return fact.occurred_at or fact.asserted_at


def _describe(fact: Fact) -> tuple[str, str, str]:
    """Return ``(kind, title, subject_key)`` for a fact."""
    if isinstance(fact, ObservableSignal):
        return "signal", f"{fact.source.name} → {fact.verdict.value}", fact.subject_key
    if isinstance(fact, Finding):
        # A finding names no subject; the first observable it links is the closest thing to one.
        links = fact.observable_links
        return "finding", fact.name or fact.rule_id, links[0].observable_key if links else fact.key
    if isinstance(fact, Decision):
        return "decision", f"{decision_label(fact)} · {fact.justification}".strip(" ·"), fact.target_key
    if isinstance(fact, Relation):
        return "relation", f"{fact.kind.value} → {fact.target_key}", fact.source_key
    if isinstance(fact, Evidence):
        return "evidence", fact.title or fact.evidence_type, fact.key
    if isinstance(fact, Observable):
        return "observable", f"{fact.obs_type} {fact.value}", fact.key
    return "fact", fact.key, fact.key


def _salience_of(fact: Fact, report: Report, policy: Policy, first_signals: set[str]) -> Salience:
    """
    Derive how much attention a fact deserves.

    A decision is a human act, so it is always worth showing. Everything else earns its place by
    having moved the needle.
    """
    if isinstance(fact, Decision):
        return Salience.KEY

    if isinstance(fact, Finding):
        result = report.finding(fact.key)
        if result is not None and result.status is Status.EVALUATED and result.score is not None:
            if abs(result.score) >= policy.salience_threshold:
                return Salience.KEY
            if result.score != 0.0:
                return Salience.NOTABLE
        # A dated finding is a chronology claim — the very thing a timeline exists to show — even
        # when it weighs nothing: a neutral event of the incident is an INFO finding with a date.
        return Salience.NOTABLE if fact.occurred_at is not None else Salience.BACKGROUND

    if isinstance(fact, ObservableSignal):
        if fact.key in first_signals:
            return Salience.NOTABLE
        contribution = _contribution_of(fact.key, report)
        if contribution is not None and abs(contribution) >= policy.salience_threshold:
            return Salience.KEY
        return Salience.BACKGROUND if contribution in (None, 0.0) else Salience.NOTABLE

    return Salience.BACKGROUND


def _contribution_of(fact_key: str, report: Report) -> float | None:
    for result in report.observables.values():
        for contribution in result.contributions:
            if contribution.source_key == fact_key:
                return contribution.value
    return None


def _first_signal_keys(store: FactStore) -> set[str]:
    firsts: set[str] = set()
    for observable_key in store.observables:
        signals = sorted(store.signals_for(observable_key), key=lambda s: s.seq)
        if signals:
            firsts.add(signals[0].key)
    return firsts


def _verdict_change_entries(
    store: FactStore,
    policy: Policy,
    evaluator: Callable[[FactStore, Policy], Report],
    basis: TimeBasis,
) -> list[TimelineEntry]:
    """
    Forward sweep over ``seq`` prefixes, replaying the store one fact at a time.

    Costs ``O(#facts × (V+E))``, hence the opt-in. Without fact versioning (deferred to 7.2) a
    re-asserted fact carries its final ``seq``, so reconstructed transitions are exact as long as
    facts are not rewritten — the common case.
    """
    entries: list[TimelineEntry] = []
    ordered = sorted(store.all_facts(), key=lambda f: f.seq)
    replay = FactStore(InvestigationHeader(**store.header.model_dump()))
    previous: dict[str, Verdict] = {}

    for fact in ordered:
        replay.append(fact)
        report = evaluator(replay, policy)
        for result in report.observables.values():
            before = previous.get(result.key)
            if before is not None and before is not result.verdict:
                entries.append(
                    TimelineEntry(
                        when=_timestamp(fact, basis),
                        time_basis=basis,
                        kind="verdict_change",
                        title=f"{before.value} → {result.verdict.value}",
                        subject_key=result.key,
                        refs=(fact.key,),
                        salience=Salience.KEY,
                        dated=fact.occurred_at is not None,
                    )
                )
            previous[result.key] = result.verdict

    return entries


def build_timeline(
    store: FactStore,
    report: Report,
    *,
    time: TimeBasis = "occurred",
    since: datetime | None = None,
    until: datetime | None = None,
    entity_key: str | None = None,
    min_salience: Salience = Salience.NOTABLE,
    policy: Policy | None = None,
    track_verdict_changes: bool = False,
    evaluator: Callable[[FactStore, Policy], Report] | None = None,
) -> list[TimelineEntry]:
    """
    Project the fact log onto an ordered list of entries.

    ``since``/``until`` are explicit parameters rather than a default window: this module lives
    under ``evaluation/`` and never reads the clock.
    """
    resolved_policy = policy or DEFAULT_POLICY
    first_signals = _first_signal_keys(store)

    entries: list[TimelineEntry] = []
    for fact in store.all_facts():
        kind, title, subject_key = _describe(fact)
        entries.append(
            TimelineEntry(
                when=_timestamp(fact, time),
                time_basis=time,
                kind=kind,
                title=title,
                subject_key=subject_key,
                refs=(fact.key,),
                salience=_salience_of(fact, report, resolved_policy, first_signals),
                dated=fact.occurred_at is not None,
                tactic=fact.tactic if isinstance(fact, Finding) else None,
            )
        )

    if track_verdict_changes and evaluator is not None:
        entries.extend(_verdict_change_entries(store, resolved_policy, evaluator, time))

    return sorted(_filter(entries, since, until, entity_key, min_salience), key=lambda e: (e.when, e.kind))


def _filter(
    entries: Iterable[TimelineEntry],
    since: datetime | None,
    until: datetime | None,
    entity_key: str | None,
    min_salience: Salience,
) -> list[TimelineEntry]:
    kept: list[TimelineEntry] = []
    for entry in entries:
        if since is not None and entry.when < since:
            continue
        if until is not None and entry.when > until:
            continue
        if entity_key is not None and entity_key not in (entry.subject_key, *entry.refs):
            continue
        if entry.salience.rank < min_salience.rank:
            continue
        kept.append(entry)
    return kept


__all__ = ["TimeBasis", "TimelineEntry", "build_timeline"]
