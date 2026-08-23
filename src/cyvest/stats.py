"""
Statistics, computed rather than accumulated.

v6 kept counters up to date through ``register_*`` calls, which meant the numbers could drift
from the facts. Here everything is derived from the store and the report on demand, so drift is
impossible by construction.

Counts follow the same exclusion rule as the score: a finding whose status is not ``EVALUATED``
— or one that was dismissed — stays visible but leaves both the numerator *and* the denominator.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import DecisionKind, Verdict
from cyvest.evaluation.report import Report
from cyvest.facts.observable import Observable
from cyvest.facts.signal import ThreatIntel
from cyvest.facts.store import FactStore

# Bands used to summarize confidence; boundaries match the Confidence ordinals.
_CONFIDENCE_BANDS = (("low", 0.5), ("medium", 0.85), ("high", 1.01))


class StatisticsSchema(BaseModel):
    """A snapshot of the investigation's shape."""

    model_config = ConfigDict(frozen=True)

    total_observables: int = Field(default=0)
    internal_observables: int = Field(default=0)
    external_observables: int = Field(default=0)
    allowlisted_observables: int = Field(default=0)
    observables_by_type: dict[str, int] = Field(default_factory=dict)
    observables_by_verdict: dict[Verdict, int] = Field(default_factory=dict)

    total_findings: int = Field(default=0)
    evaluated_findings: int = Field(default=0)
    findings_by_verdict: dict[Verdict, int] = Field(default_factory=dict)
    findings_by_confidence_band: dict[str, int] = Field(default_factory=dict)

    total_signals: int = Field(default=0)
    signals_by_source: dict[str, int] = Field(default_factory=dict)
    signals_by_verdict: dict[Verdict, int] = Field(default_factory=dict)

    total_evidences: int = Field(default=0)
    evidences_by_type: dict[str, int] = Field(default_factory=dict)

    total_relations: int = Field(default=0)
    relations_by_kind: dict[str, int] = Field(default_factory=dict)

    total_decisions: int = Field(default=0)
    decisions_by_kind: dict[DecisionKind, int] = Field(default_factory=dict)

    total_tags: int = Field(default=0)


def _confidence_band(confidence: float) -> str:
    for name, ceiling in _CONFIDENCE_BANDS:
        if confidence < ceiling:
            return name
    return _CONFIDENCE_BANDS[-1][0]


class InvestigationStats:
    """Read-only view computing counts from a store and its report."""

    def __init__(self, store: FactStore, report: Report) -> None:
        self.store = store
        self.report = report

    # --- observables

    def get_total_observable_count(self) -> int:
        return len(self.store.observables)

    def get_internal_observable_count(self) -> int:
        return sum(1 for obs in self.store.observables.values() if obs.internal)

    def get_external_observable_count(self) -> int:
        return sum(1 for obs in self.store.observables.values() if not obs.internal)

    def get_allowlisted_observable_count(self) -> int:
        return sum(
            1
            for key in self.store.observables
            if any(d.kind is DecisionKind.ALLOWLISTED for d in self.store.decisions_for(key))
        )

    def get_observable_count_by_type(self) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for observable in self.store.observables.values():
            counter[self._type_of(observable)] += 1
        return dict(counter)

    def get_observable_count_by_verdict(self, obs_type: str | None = None) -> dict[Verdict, int]:
        counter: Counter[Verdict] = Counter()
        for key, observable in self.store.observables.items():
            if obs_type is not None and self._type_of(observable) != obs_type:
                continue
            result = self.report.observable(key)
            counter[result.verdict if result is not None else Verdict.INFO] += 1
        return dict(counter)

    def get_observable_count_by_type_and_verdict(self) -> dict[str, dict[Verdict, int]]:
        nested: dict[str, Counter[Verdict]] = defaultdict(Counter)
        for key, observable in self.store.observables.items():
            result = self.report.observable(key)
            nested[self._type_of(observable)][result.verdict if result is not None else Verdict.INFO] += 1
        return {obs_type: dict(counts) for obs_type, counts in nested.items()}

    def get_observables_by_verdict(self, verdict: Verdict) -> list[Observable]:
        return [
            observable
            for key, observable in self.store.observables.items()
            if (result := self.report.observable(key)) is not None and result.verdict is verdict
        ]

    def get_observables_by_type(self, obs_type: str) -> list[Observable]:
        return [obs for obs in self.store.observables.values() if self._type_of(obs) == obs_type]

    # --- findings

    def get_total_finding_count(self) -> int:
        return len(self.store.findings)

    def get_applied_finding_count(self) -> int:
        """Findings that actually take part — the denominator of every ratio."""
        return sum(1 for result in self.report.findings.values() if result.counted)

    def get_finding_count_by_verdict(self) -> dict[Verdict, int]:
        counter: Counter[Verdict] = Counter()
        for result in self.report.findings.values():
            if result.counted:
                counter[result.verdict] += 1
        return dict(counter)

    def get_finding_keys_by_verdict(self) -> dict[Verdict, list[str]]:
        grouped: dict[Verdict, list[str]] = defaultdict(list)
        for key, result in self.report.findings.items():
            if result.counted:
                grouped[result.verdict].append(key)
        return dict(grouped)

    def get_finding_count_by_confidence_band(self) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for result in self.report.findings.values():
            if result.counted:
                counter[_confidence_band(result.confidence)] += 1
        return dict(counter)

    # --- signals

    def get_signal_count(self) -> int:
        return len(self.store.signals)

    def get_signal_count_by_source(self) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for signal in self.store.signals.values():
            counter[signal.source.name] += 1
        return dict(counter)

    def get_signal_count_by_verdict(self) -> dict[Verdict, int]:
        counter: Counter[Verdict] = Counter()
        for signal in self.store.signals.values():
            counter[signal.verdict] += 1
        return dict(counter)

    def get_threat_intels_by_source(self, source: str) -> list[ThreatIntel]:
        return [
            signal
            for signal in self.store.signals.values()
            if isinstance(signal, ThreatIntel) and signal.source.name == source
        ]

    # --- the rest

    def get_evidence_count_by_type(self) -> dict[str, int]:
        return dict(Counter(evidence.evidence_type for evidence in self.store.evidences.values()))

    def get_relation_count_by_kind(self) -> dict[str, int]:
        return dict(Counter(relation.kind.value for relation in self.store.relations.values()))

    def get_decision_count_by_kind(self) -> dict[DecisionKind, int]:
        return dict(Counter(decision.kind for decision in self.store.decisions.values()))

    def get_tag_count(self) -> int:
        return len(self.store.tags)

    def get_summary(self) -> StatisticsSchema:
        return StatisticsSchema(
            total_observables=self.get_total_observable_count(),
            internal_observables=self.get_internal_observable_count(),
            external_observables=self.get_external_observable_count(),
            allowlisted_observables=self.get_allowlisted_observable_count(),
            observables_by_type=self.get_observable_count_by_type(),
            observables_by_verdict=self.get_observable_count_by_verdict(),
            total_findings=self.get_total_finding_count(),
            evaluated_findings=self.get_applied_finding_count(),
            findings_by_verdict=self.get_finding_count_by_verdict(),
            findings_by_confidence_band=self.get_finding_count_by_confidence_band(),
            total_signals=self.get_signal_count(),
            signals_by_source=self.get_signal_count_by_source(),
            signals_by_verdict=self.get_signal_count_by_verdict(),
            total_evidences=len(self.store.evidences),
            evidences_by_type=self.get_evidence_count_by_type(),
            total_relations=len(self.store.relations),
            relations_by_kind=self.get_relation_count_by_kind(),
            total_decisions=len(self.store.decisions),
            decisions_by_kind=self.get_decision_count_by_kind(),
            total_tags=self.get_tag_count(),
        )

    @staticmethod
    def _type_of(observable: Observable) -> str:
        return str(observable.obs_type)


__all__ = ["InvestigationStats", "StatisticsSchema"]
