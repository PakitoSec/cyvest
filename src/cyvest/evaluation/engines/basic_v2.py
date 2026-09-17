"""Local basic scores with investigation-wide deduplication of retained fact origins."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import fsum

from cyvest.enums import Aggregation, Effect, LinkBasis
from cyvest.evaluation.combine import NEG_INF
from cyvest.evaluation.engines.basic import _Evaluation
from cyvest.evaluation.report import Contribution, FindingResult, Report, round_half_up
from cyvest.facts.decision import Decision
from cyvest.facts.finding import Finding, ObservableLink
from cyvest.facts.relation import Relation
from cyvest.facts.store import FactStore
from cyvest.policy import Policy


@dataclass(frozen=True)
class _Origin:
    key: str
    value: float
    path: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Derivation:
    score: float = 0.0
    origins: tuple[_Origin, ...] = ()
    shared_origin_keys: frozenset[str] = frozenset()


def _strongest(origins: list[_Origin]) -> tuple[_Origin, ...]:
    """Keep signed extremes per origin, including when a later edge reverses the sign."""
    retained: dict[tuple[str, bool], _Origin] = {}
    for origin in origins:
        identity = (origin.key, origin.value < 0)
        previous = retained.get(identity)
        if previous is None or (-abs(origin.value), -origin.value, origin.path) < (
            -abs(previous.value),
            -previous.value,
            previous.path,
        ):
            retained[identity] = origin
    return tuple(retained[key] for key in sorted(retained))


def _best(candidates: list[_Derivation], default: float = NEG_INF) -> _Derivation:
    return min(
        candidates,
        key=lambda candidate: (
            -candidate.score,
            tuple((origin.key, origin.value, origin.path) for origin in candidate.origins),
        ),
        default=_Derivation(default),
    )


class BasicV2Engine:
    """The strongest effective contribution of each retained origin counts once."""

    engine_id = "basic-v2"
    experimental = False

    def evaluate(self, store: FactStore, policy: Policy) -> Report:
        return _ProvenanceEvaluation(store, policy, self.engine_id).run()


class _ProvenanceEvaluation(_Evaluation):
    def __init__(self, store: FactStore, policy: Policy, engine_id: str) -> None:
        super().__init__(store, policy, engine_id)
        self._observables: dict[str, _Derivation] = {}
        self._pins: dict[ObservableLink, _Derivation] = {}
        self._findings: dict[str, _Derivation] = {}

    @staticmethod
    def _bounded(derivation: _Derivation, decision: Decision | None, score: float) -> _Derivation:
        if decision is not None and score != derivation.score:
            return _Derivation(score, (_Origin(decision.key, score),))
        return derivation

    def _combine_observable(
        self,
        observable_key: str,
        signals: list[tuple[str, float]],
        children: list[tuple[Relation, float]],
    ) -> float:
        score = super()._combine_observable(observable_key, signals, children)
        own = [_Derivation(value, (_Origin(key, value),)) for key, value in signals]
        propagated = []
        for relation, value in children:
            child = self._observables.get(relation.target_key, _Derivation())
            origins = tuple(
                _Origin(
                    origin.key,
                    origin.value * relation.confidence * self.policy.attenuation.get(relation.kind, 1.0),
                    (relation.key, *origin.path),
                )
                for origin in child.origins
            )
            propagated.append(_Derivation(value, origins, child.shared_origin_keys))
        if self.policy.aggregation is Aggregation.SUM:
            origins = [*_best(own, default=0.0).origins]
            origins.extend(origin for child in propagated for origin in child.origins)
            occurrences = Counter(origin.key for origin in origins if origin.value != 0.0)
            shared = frozenset(key for key, count in occurrences.items() if count > 1) | frozenset(
                key for child in propagated for key in child.shared_origin_keys
            )
            derivation = _Derivation(score, _strongest(origins), shared)
        else:
            derivation = _best([*own, *propagated], default=0.0)
        self._observables[observable_key] = derivation
        return score

    def _compute_observable(self, observable_key: str) -> float:
        score = super()._compute_observable(observable_key)
        self._observables[observable_key] = self._bounded(
            self._observables[observable_key], self.store.decision_for(observable_key), score
        )
        return score

    def _combine_pinned(self, link: ObservableLink, values: list[tuple[str, float]]) -> float:
        derivation = _best([_Derivation(value, (_Origin(key, value),)) for key, value in values])
        self._pins[link] = derivation
        return derivation.score

    def _pinned_value(self, link: ObservableLink) -> tuple[float, list[Contribution]]:
        score, contributions = super()._pinned_value(link)
        self._pins[link] = self._bounded(self._pins[link], self.store.decision_for(link.observable_key), score)
        return score, contributions

    def _combine_finding(self, finding: Finding, own_term: float, links: list[tuple[ObservableLink, float]]) -> float:
        candidates = []
        for link, _ in links:
            derivation = self._pins[link] if link.basis is LinkBasis.SIGNALS else self._observables[link.observable_key]
            candidates.append(
                _Derivation(
                    derivation.score,
                    tuple(
                        _Origin(origin.key, origin.value, (link.observable_key, *origin.path))
                        for origin in derivation.origins
                    ),
                    derivation.shared_origin_keys,
                )
            )
        selected = _best(candidates)
        if own_term > selected.score:
            selected = _Derivation(own_term, (_Origin(finding.key, own_term),))
        if selected.score == NEG_INF:
            selected = _Derivation()
        self._findings[finding.key] = selected
        return selected.score

    def finding_result(self, finding: Finding) -> FindingResult:
        result = super().finding_result(finding)
        if finding.key in self._findings:
            decision = self.store.decision_for(finding.key)
            derivation = self._findings[finding.key]
            score = self._bound(derivation.score, decision.kind) if decision is not None else derivation.score
            self._findings[finding.key] = self._bounded(derivation, decision, score)
        return result

    def _aggregate_findings(self, results: dict[str, FindingResult]) -> tuple[float, list[Contribution]]:
        occurrences: dict[str, list[_Origin]] = {}
        for key in sorted(results):
            result = results[key]
            if not result.counted or result.effect is not Effect.ADDITIVE:
                continue
            for origin in self._findings[key].origins:
                occurrences.setdefault(origin.key, []).append(_Origin(origin.key, origin.value, (key, *origin.path)))

        contributions = []
        credits = []
        finding_credits: dict[str, list[float]] = {}
        credited_findings: set[str] = set()
        shared_findings: set[str] = set()
        for key in sorted(occurrences):
            candidates = sorted(occurrences[key], key=lambda origin: (-abs(origin.value), -origin.value, origin.path))
            for index, origin in enumerate(candidates):
                value = round_half_up(origin.value, self.policy.output_precision)
                retained = index == 0
                finding_key = origin.path[0]
                if retained:
                    credits.append(value)
                    finding_credits.setdefault(finding_key, []).append(value)
                if value != 0.0:
                    (credited_findings if retained else shared_findings).add(finding_key)
                contributions.append(
                    Contribution(
                        source_key=key,
                        label="origin" if retained else "shared origin",
                        value=value,
                        retained=retained,
                        detail=("via " if retained else "already credited; via ") + " -> ".join(origin.path),
                    )
                )
        for key, result in results.items():
            if not result.counted or result.effect is not Effect.ADDITIVE:
                continue
            derivation = self._findings[key]
            shared = key in shared_findings or any(
                origin.key in derivation.shared_origin_keys
                and round_half_up(origin.value, self.policy.output_precision) != 0.0
                for origin in derivation.origins
            )
            if key in credited_findings:
                status = "partial" if shared else "credited"
            else:
                status = "shared" if shared else "neutral"
            results[key] = result.model_copy(
                update={
                    "contribution_score": round_half_up(
                        fsum(finding_credits.get(key, [])), self.policy.output_precision
                    ),
                    "contribution_status": status,
                }
            )
        return fsum(credits), contributions


__all__ = ["BasicV2Engine"]
