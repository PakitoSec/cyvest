"""
``basic-v1`` — the reference engine, and the only one shipped in v7.

Additive, readable by any analyst, and **iso-v6 with default parameters**: migrated documents
reproduce their v6 numbers exactly. The v7 break is structural (model, API, schema), not numeric.

Pure by construction: nothing here reads the clock, so a document evaluated today and in ten
years yields the same report.
"""

from __future__ import annotations

from cyvest.enums import DecisionKind, Effect, Scope, Status, Verdict
from cyvest.evaluation.combine import NEG_INF, bounded_max, combine
from cyvest.evaluation.projection import score_floor_for, verdict_from_score
from cyvest.evaluation.report import (
    Contribution,
    FindingResult,
    InvestigationResult,
    ObservableResult,
    Report,
    ResolvedScope,
    observable_index,
    round_half_up,
)
from cyvest.facts.finding import Finding
from cyvest.facts.signal import ObservableSignal
from cyvest.facts.store import FactStore
from cyvest.policy import Policy


class BasicEngine:
    """Sum of findings, each backed by the strongest of its own claim and its observables.

    Conclusions (``Effect.FLOOR``) sit outside that sum: once it is settled, they raise the total
    to the floor of the verdict they assert.
    """

    engine_id = "basic-v1"
    experimental = False

    def evaluate(self, store: FactStore, policy: Policy) -> Report:
        return _Evaluation(store, policy, self.engine_id).run()


class _Evaluation:
    """One evaluation pass. Holds the memo tables so the engine itself stays stateless."""

    def __init__(self, store: FactStore, policy: Policy, engine_id: str = BasicEngine.engine_id) -> None:
        self.store = store
        self.policy = policy
        # Carried, not hardcoded: a report must name the engine that actually produced it, or
        # `compare_investigations` would happily diff two incomparable scales.
        self.engine_id = engine_id
        self.observable_results: dict[str, ObservableResult] = {}
        self._memo: dict[tuple[str, ResolvedScope], float] = {}

    # --- signals -------------------------------------------------------------------------

    def _signal_score(self, signal: ObservableSignal) -> float:
        weight = self.policy.resolve_weight(verdict=signal.verdict, weight=signal.weight)
        return signal.verdict.polarity * weight * signal.confidence

    def _visible(self, fragment_id: str, scope: ResolvedScope) -> bool:
        return scope.fragment_id is None or fragment_id == scope.fragment_id

    # --- observables ---------------------------------------------------------------------

    def observable_score(self, observable_key: str, scope: ResolvedScope) -> float:
        memo_key = (observable_key, scope)
        cached = self._memo.get(memo_key)
        if cached is not None:
            return cached
        # Placeholder breaks cycles: a node being visited contributes nothing to itself.
        self._memo[memo_key] = 0.0
        score = self._compute_observable(observable_key, scope)
        self._memo[memo_key] = score
        return score

    def _compute_observable(self, observable_key: str, scope: ResolvedScope) -> float:
        contributions: list[Contribution] = []
        signal_scores: list[float] = []
        child_scores: list[float] = []

        for signal in self.store.signals_for(observable_key):
            if not self._visible(signal.fragment_id, scope):
                continue
            value = self._signal_score(signal)
            signal_scores.append(value)
            contributions.append(
                Contribution(
                    source_key=signal.key,
                    label=f"{signal.source.name} · {signal.verdict.value}",
                    value=value,
                )
            )

        for relation in self.store.child_relations(observable_key):
            if not relation.propagates or not self._visible(relation.fragment_id, scope):
                continue
            # The root is a presentation anchor, not evidence: it never feeds score upward.
            if relation.target_key == self.store.header.root_key:
                continue
            attenuation = self.policy.attenuation.get(relation.kind, 1.0)
            child = self.observable_score(relation.target_key, scope)
            value = child * relation.confidence * attenuation
            child_scores.append(value)
            contributions.append(
                Contribution(
                    source_key=relation.key,
                    label=f"{relation.kind.value} → {relation.target_key}",
                    value=value,
                )
            )

        score = combine(signal_scores, child_scores, self.policy.aggregation)
        suppressed = False

        for decision in self.store.decisions_for(observable_key):
            if decision.kind is DecisionKind.ALLOWLISTED:
                bounded = min(score, self.policy.allowlist_ceiling)
            elif decision.kind is DecisionKind.BLOCKLISTED:
                bounded = max(score, self.policy.blocklist_floor)
            else:
                continue
            if bounded != score:
                suppressed = True
                contributions = [c.model_copy(update={"retained": False}) for c in contributions]
            contributions.append(
                Contribution(
                    source_key=decision.key,
                    label=f"decision · {decision.kind.value}",
                    value=bounded,
                    detail=decision.justification or "",
                )
            )
            score = bounded

        self._record_observable(observable_key, scope, score, contributions, suppressed)
        return score

    def _record_observable(
        self,
        observable_key: str,
        scope: ResolvedScope,
        score: float,
        contributions: list[Contribution],
        suppressed: bool,
    ) -> None:
        self.observable_results[observable_index(observable_key, scope)] = ObservableResult(
            key=observable_key,
            scope=scope,
            score=round_half_up(score, self.policy.output_precision),
            verdict=verdict_from_score(score),
            contributions=tuple(contributions),
            suppressed_by_decision=suppressed,
        )

    # --- findings ------------------------------------------------------------------------

    def _resolve_scope(self, finding: Finding, link_scope: Scope) -> ResolvedScope:
        if link_scope is Scope.ALL:
            return ResolvedScope.all()
        return ResolvedScope.own(finding.fragment_id)

    def finding_result(self, finding: Finding) -> FindingResult:
        decisions = {d.kind: d for d in self.store.decisions_for(finding.key)}

        dismissed = decisions.get(DecisionKind.DISMISSED)
        if dismissed is not None:
            return FindingResult(
                key=finding.key,
                status=Status.NOT_APPLICABLE,
                counted=False,
                score=None,
                verdict=finding.verdict,
                confidence=finding.confidence,
                suppressed_by_decision=True,
                contributions=(
                    Contribution(
                        source_key=dismissed.key,
                        label="decision · DISMISSED",
                        value=0.0,
                        retained=False,
                        detail=dismissed.justification or "",
                    ),
                ),
            )

        if finding.status is not Status.EVALUATED:
            return FindingResult(
                key=finding.key,
                status=finding.status,
                counted=False,
                score=None,
                verdict=finding.verdict,
                confidence=finding.confidence,
            )

        confirmed = decisions.get(DecisionKind.CONFIRMED)
        if confirmed is not None:
            score = self.policy.confirmed_floor
            return FindingResult(
                key=finding.key,
                status=finding.status,
                score=round_half_up(score, self.policy.output_precision),
                verdict=verdict_from_score(score),
                confidence=finding.confidence,
                suppressed_by_decision=True,
                contributions=(
                    Contribution(
                        source_key=confirmed.key,
                        label="decision · CONFIRMED",
                        value=score,
                        detail=confirmed.justification or "",
                    ),
                ),
            )

        if finding.effect is Effect.FLOOR:
            return self._conclusion_result(finding)

        contributions: list[Contribution] = []

        own_term = NEG_INF
        if finding.verdict is not Verdict.INFO:
            weight = self.policy.resolve_weight(verdict=finding.verdict, weight=finding.weight)
            own_term = finding.verdict.polarity * weight * finding.confidence
            contributions.append(
                Contribution(
                    source_key=finding.key,
                    label=f"rule floor · {finding.verdict.value}",
                    value=own_term,
                )
            )

        link_values: list[float] = []
        for link in finding.observable_links:
            scope = self._resolve_scope(finding, link.scope)
            value = self.observable_score(link.observable_key, scope)
            link_values.append(value)
            contributions.append(
                Contribution(
                    source_key=link.observable_key,
                    label=f"link · {scope}",
                    value=value,
                )
            )

        propagated = bounded_max(link_values)
        score = max(own_term, propagated)
        if score == NEG_INF:
            score = 0.0

        own_suppressed = own_term != NEG_INF and propagated > own_term
        if own_suppressed:
            contributions = [
                c.model_copy(update={"retained": False, "detail": "outweighed by a linked observable"})
                if c.source_key == finding.key
                else c
                for c in contributions
            ]

        return FindingResult(
            key=finding.key,
            status=finding.status,
            score=round_half_up(score, self.policy.output_precision),
            verdict=verdict_from_score(score),
            confidence=finding.confidence,
            contributions=tuple(contributions),
            own_term_suppressed=own_suppressed,
        )

    # --- conclusions ---------------------------------------------------------------------

    def _conclusion_result(self, finding: Finding) -> FindingResult:
        """
        A conclusion has no magnitude: ``score`` is ``None``, not ``0.0``.

        ``0.0`` would read as a neutral term of the sum, which is precisely what a conclusion is
        not. Its effect is applied on the total by :meth:`_apply_floors` and reported there.
        """
        contributions = [
            Contribution(
                source_key=finding.key,
                label=f"conclusion · {finding.verdict.value}",
                value=0.0,
                detail="floor applied on the investigation total",
            )
        ]
        # Links stay documentary: propagating them would push the total past "just enough".
        contributions.extend(
            Contribution(
                source_key=link.observable_key,
                label=f"link · {self._resolve_scope(finding, link.scope)}",
                value=0.0,
                retained=False,
                detail="documentary link",
            )
            for link in finding.observable_links
        )
        return FindingResult(
            key=finding.key,
            status=finding.status,
            effect=Effect.FLOOR,
            score=None,
            verdict=finding.verdict,
            confidence=finding.confidence,
            contributions=tuple(contributions),
        )

    def _apply_floors(
        self,
        total: float,
        results: dict[str, FindingResult],
    ) -> tuple[float, list[Contribution]]:
        """Raise ``total`` to the floor each conclusion asserts, weakest first."""
        pending: list[tuple[float, str, str]] = []
        for key, result in results.items():
            if result.effect is not Effect.FLOOR or not result.counted:
                continue
            target = score_floor_for(result.verdict, epsilon=10**-self.policy.output_precision)
            if target is None:  # pragma: no cover - Finding rejects floorless verdicts
                continue
            pending.append((target, self.store.findings[key].seq, key))

        contributions: list[Contribution] = []
        for target, _seq, key in sorted(pending):
            before = total
            # `max` rather than `total += target - total`: the latter is not exact in binary
            # floating point, and landing at 4.999999999999999 would report SUSPICIOUS.
            total = max(total, target)
            applied = total - before
            contributions.append(
                Contribution(
                    source_key=key,
                    label=f"conclusion floor · {results[key].verdict.value}",
                    value=round_half_up(applied, self.policy.output_precision),
                    retained=applied > 0.0,
                    detail=(
                        f"target {target}, total was {round_half_up(before, self.policy.output_precision)}"
                        if applied > 0.0
                        else "verdict already reached"
                    ),
                )
            )
        return total, contributions

    # --- entry point ---------------------------------------------------------------------

    def run(self) -> Report:
        finding_results: dict[str, FindingResult] = {}
        total = 0.0
        confidences: list[float] = []

        for finding in self.store.findings.values():
            result = self.finding_result(finding)
            finding_results[finding.key] = result
            # `counted` alone governs the denominator; a conclusion takes part without a score.
            if not result.counted:
                continue
            confidences.append(result.confidence)
            if result.score is not None:
                total += result.score

        contributions = [
            Contribution(source_key=key, label="finding", value=result.score or 0.0)
            for key, result in finding_results.items()
            if result.counted and result.effect is Effect.ADDITIVE
        ]
        total, floor_contributions = self._apply_floors(total, finding_results)
        contributions.extend(floor_contributions)

        # Every observable gets a result in the global scope, even when no finding links it.
        for observable_key in self.store.observables:
            self.observable_score(observable_key, ResolvedScope.all())

        mean_confidence = sum(confidences) / len(confidences) if confidences else 1.0

        return Report(
            engine_id=self.engine_id,
            policy_version=self.policy.version,
            investigation=InvestigationResult(
                key=self.store.header.investigation_id,
                score=round_half_up(total, self.policy.output_precision),
                verdict=verdict_from_score(total),
                confidence=mean_confidence,
                contributions=tuple(contributions),
            ),
            findings=finding_results,
            observables=dict(self.observable_results),
        )


__all__ = ["BasicEngine"]
