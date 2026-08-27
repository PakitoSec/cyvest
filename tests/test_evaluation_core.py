"""Core evaluation tests: the reference scenario, the finding's three levels, and the projection."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyvest.enums import DecisionKind, Effect, Scope, SourceClass, Status, Verdict, Weight
from cyvest.evaluation import ResolvedScope, evaluate
from cyvest.evaluation.combine import NEG_INF
from cyvest.evaluation.projection import score_floor_for, verdict_from_score
from cyvest.facts import Decision, Finding, Observable, ObservableLink, SourceRef, ThreatIntel
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.investigation import Investigation
from cyvest.policy import DEFAULT_POLICY, Policy

URL = "hxxp://bad.example/x"


def make_store(fragment_id: str = "f1") -> FactStore:
    return FactStore(InvestigationHeader(investigation_id=fragment_id, fragment_ids=(fragment_id,)))


def source(name: str = "analyst", source_class: SourceClass = SourceClass.VENDOR_FEED) -> SourceRef:
    return SourceRef(name=name, source_class=source_class)


def add_url(store: FactStore, fragment_id: str) -> Observable:
    observable = Observable(type="url", value=URL, source=source(), fragment_id=fragment_id)
    store.append(observable)
    return observable


class TestReferenceScenario:
    """The hand-drawn requirement: F1 keeps its value while the observable keeps evolving."""

    @staticmethod
    def _fragment(fragment_id: str, source_name: str, weight: float, rule_id: str):
        store = make_store(fragment_id)
        url = add_url(store, fragment_id)
        store.append(
            ThreatIntel(
                subject_key=url.key,
                verdict=Verdict.MALICIOUS,
                weight=weight,
                source=source(source_name),
                fragment_id=fragment_id,
            )
        )
        finding = Finding(
            rule_id=rule_id,
            subject_key=url.key,
            source=source(source_name),
            fragment_id=fragment_id,
            observable_links=[ObservableLink(observable_key=url.key, scope=Scope.OWN_FRAGMENT)],
        )
        store.append(finding)
        return store, url.key, finding.key

    def test_local_scope_keeps_each_finding_at_its_own_value(self) -> None:
        i1, url_key, f1 = self._fragment("i1", "proofpoint", 2.0, "url_in_body")
        i2, _, f2 = self._fragment("i2", "virustotal", 3.0, "url_reputation")

        report = evaluate(i1.union(i2))

        assert report.finding(f1).score == 2.0
        assert report.finding(f2).score == 3.0
        assert report.observable(url_key).score == 3.0
        assert report.investigation.score == 5.0

    def test_same_observable_under_two_local_scopes_yields_two_results(self) -> None:
        """Fails if the report indexes on the raw scope label instead of the resolved one."""
        i1, url_key, _ = self._fragment("i1", "proofpoint", 2.0, "url_in_body")
        i2, _, _ = self._fragment("i2", "virustotal", 3.0, "url_reputation")

        report = evaluate(i1.union(i2))

        assert report.observable(url_key, ResolvedScope.own("i1")).score == 2.0
        assert report.observable(url_key, ResolvedScope.own("i2")).score == 3.0

    def test_global_scope_lets_the_finding_rise(self) -> None:
        i1, url_key, f1 = self._fragment("i1", "proofpoint", 2.0, "url_in_body")
        i2, _, _ = self._fragment("i2", "virustotal", 3.0, "url_reputation")
        merged = i1.union(i2)
        finding = merged.findings[f1]
        merged.findings[f1] = finding.model_copy(
            update={"observable_links": (ObservableLink(observable_key=url_key, scope=Scope.ALL),)}
        )

        assert evaluate(merged).finding(f1).score == 3.0


class TestFindingLevels:
    """Observables are the normal source of a score; the rule is a floor; a decision overrides."""

    def _linked_finding(self, store: FactStore, url: Observable, **kwargs) -> Finding:
        finding = Finding(
            rule_id="rule",
            subject_key=url.key,
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, scope=Scope.ALL)],
            **kwargs,
        )
        store.append(finding)
        return finding

    def test_neutral_finding_relays_its_observables(self) -> None:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=4.0, source=source(), fragment_id="f1")
        )
        finding = self._linked_finding(store, url, verdict=Verdict.INFO, weight=Weight.HIGH)

        assert evaluate(store).finding(finding.key).score == 4.0

    def test_neutral_finding_without_links_scores_zero(self) -> None:
        """A high weight asserts nothing on its own: only the verdict creates maliciousness."""
        store = make_store()
        finding = Finding(
            rule_id="rule",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.INFO,
            weight=Weight.HIGH,
        )
        store.append(finding)

        assert evaluate(store).finding(finding.key).score == 0.0

    def test_verdict_alone_is_enough(self) -> None:
        """Asserting MALICIOUS without a weight must report MALICIOUS, not INFO."""
        store = make_store()
        finding = Finding(
            rule_id="ceo_impersonation",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
        )
        store.append(finding)

        result = evaluate(store).finding(finding.key)
        assert result.score == Weight.HIGH.value
        assert result.verdict is Verdict.MALICIOUS

    def test_exculpatory_finding_without_links_stays_negative(self) -> None:
        """Guards the ``-inf`` neutral: a zero neutral would clamp this to 0."""
        store = make_store()
        finding = Finding(
            rule_id="spf_pass",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.SAFE,
            weight=Weight.MEDIUM,
        )
        store.append(finding)

        result = evaluate(store).finding(finding.key)
        assert result.score == -Weight.MEDIUM.value
        assert result.verdict is Verdict.SAFE

    def test_exculpatory_finding_cannot_whitewash_a_malicious_observable(self) -> None:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=3.0, source=source(), fragment_id="f1")
        )
        finding = self._linked_finding(store, url, verdict=Verdict.SAFE, weight=Weight.MEDIUM)

        result = evaluate(store).finding(finding.key)
        assert result.score == 3.0
        assert result.own_term_suppressed is True

    def test_rule_floor_wins_over_a_weaker_observable(self) -> None:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.NOTABLE, weight=1.0, source=source(), fragment_id="f1")
        )
        finding = self._linked_finding(store, url, verdict=Verdict.SUSPICIOUS, weight=Weight.MEDIUM)

        result = evaluate(store).finding(finding.key)
        assert result.score == Weight.MEDIUM.value
        assert result.own_term_suppressed is False


class TestDecisions:
    def test_upholding_forces_malicious_against_clean_observables(self) -> None:
        store = make_store()
        url = add_url(store, "f1")
        finding = Finding(
            rule_id="rule",
            subject_key=url.key,
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, scope=Scope.ALL)],
        )
        store.append(finding)
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.UPHOLD,
                justification="confirmé par l'analyse mémoire",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        result = evaluate(store).finding(finding.key)
        assert result.verdict is Verdict.MALICIOUS
        assert result.suppressed_by_decision is True

    def test_refuting_leaves_the_finding_visible_but_uncounted(self) -> None:
        store = make_store()
        finding = Finding(
            rule_id="rule",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
        )
        store.append(finding)
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.REFUTE,
                justification="faux positif connu",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        report = evaluate(store)
        assert report.finding(finding.key) is not None
        assert report.finding(finding.key).counted is False
        assert report.investigation.score == 0.0

    def test_refuted_observable_derives_to_safe_without_a_forced_verdict(self) -> None:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        store.append(
            Decision(
                target_key=url.key,
                kind=DecisionKind.REFUTE,
                justification="infrastructure d'authentification interne",
                source=source("rssi", SourceClass.ORG_POLICY),
                fragment_id="f1",
            )
        )

        result = evaluate(store).observable(url.key)
        assert result.score == -1.0
        assert result.verdict is Verdict.SAFE
        assert result.suppressed_by_decision is True

    def test_a_decision_targets_an_observable_or_a_finding(self) -> None:
        """The family is the target's business — but it still has to be one that can be decided."""
        with pytest.raises(ValueError, match="observable or a finding"):
            Decision(
                target_key="tag:phishing",
                kind=DecisionKind.UPHOLD,
                justification="peu importe",
                source=source(),
                fragment_id="f1",
            )

    def test_every_kind_is_valid_on_every_decidable_family(self) -> None:
        """No combination to forbid: that is the point of taking the family out of the kind."""
        for target in ("obs:url:x", "fnd:r:obs:url:x"):
            for kind in DecisionKind:
                decision = Decision(
                    target_key=target,
                    kind=kind,
                    justification="motif",
                    source=source(),
                    fragment_id="f1",
                )
                assert decision.key == f"dec:{target}"

    def test_a_decision_requires_a_reason(self) -> None:
        """An override nobody has to justify is an override nobody can audit."""
        with pytest.raises(ValueError):
            Decision(
                target_key="obs:url:x",
                kind=DecisionKind.REFUTE,
                justification="",
                source=source(),
                fragment_id="f1",
            )

    def test_the_counterfactual_survives_an_override(self) -> None:
        """
        An overridden result must still show what the evidence alone produced.

        The engine used to short-circuit on a decided finding and never compute the natural
        score, so the report could not say what had been overruled — only that something was.
        """
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        finding = Finding(
            rule_id="rule",
            subject_key=url.key,
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, scope=Scope.ALL)],
        )
        store.append(finding)
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.REFUTE,
                justification="faux positif connu",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        contributions = evaluate(store).finding(finding.key).contributions
        link = next(c for c in contributions if c.source_key == url.key)
        assert link.value == 8.0
        assert link.retained is False


class TestVacating:
    """
    Withdrawing a stance is an act of its own.

    Asserting the opposite one would say something different — and usually false — and an
    append-only model cannot express a retraction by deletion.
    """

    @staticmethod
    def _refuted_url() -> tuple[FactStore, str]:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        store.append(
            Decision(
                target_key=url.key,
                kind=DecisionKind.REFUTE,
                justification="infra interne",
                occurred_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
                source=source("rssi", SourceClass.ORG_POLICY),
                fragment_id="f1",
            )
        )
        return store, url.key

    def test_vacating_restores_the_computed_value(self) -> None:
        store, url_key = self._refuted_url()
        assert evaluate(store).observable(url_key).score == -1.0

        store.append(
            Decision(
                target_key=url_key,
                kind=DecisionKind.VACATED,
                justification="le domaine n'est plus géré par la RSSI",
                occurred_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
                source=source("soc-lead", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        result = evaluate(store).observable(url_key)
        assert result.score == 8.0
        assert result.verdict is Verdict.MALICIOUS
        assert result.suppressed_by_decision is False

    def test_a_vacated_stance_stays_in_the_report(self) -> None:
        """Un-deciding is itself a decision: the analyst must see that someone withdrew."""
        store, url_key = self._refuted_url()
        store.append(
            Decision(
                target_key=url_key,
                kind=DecisionKind.VACATED,
                justification="plus dans le périmètre",
                occurred_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
                source=source("soc-lead", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        contributions = evaluate(store).observable(url_key).contributions
        vacated = next(c for c in contributions if c.source_key.startswith("dec:"))
        assert vacated.retained is False
        assert "stance withdrawn" in vacated.detail
        assert "plus dans le périmètre" in vacated.detail

    def test_a_vacated_finding_is_counted_again(self) -> None:
        store = make_store()
        finding = Finding(
            rule_id="rule",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
        )
        store.append(finding)
        for kind, when in (
            (DecisionKind.REFUTE, datetime(2026, 1, 15, tzinfo=timezone.utc)),
            (DecisionKind.VACATED, datetime(2026, 6, 15, tzinfo=timezone.utc)),
        ):
            store.append(
                Decision(
                    target_key=finding.key,
                    kind=kind,
                    justification="motif",
                    occurred_at=when,
                    source=source("alice", SourceClass.ORG_ANALYST),
                    fragment_id="f1",
                )
            )

        result = evaluate(store).finding(finding.key)
        assert result.counted is True
        assert result.status is Status.EVALUATED


class TestContradictoryDecisions:
    """
    A target holds one stance, whatever it says.

    The kind is content, not identity, so two opposite calls share a key and the store's own
    merge law settles them by freshness — the same law every other fact obeys. Keying on the kind
    let them coexist and forced the engine to arbitrate them itself, duplicating that law.
    """

    JANUARY = datetime(2026, 1, 15, tzinfo=timezone.utc)
    JUNE = datetime(2026, 6, 15, tzinfo=timezone.utc)

    def _bounded(self, fresher: DecisionKind) -> tuple[FactStore, str]:
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        for kind in (DecisionKind.REFUTE, DecisionKind.UPHOLD):
            store.append(
                Decision(
                    target_key=url.key,
                    kind=kind,
                    justification="motif",
                    occurred_at=self.JUNE if kind is fresher else self.JANUARY,
                    source=source("rssi", SourceClass.ORG_POLICY),
                    fragment_id="f1",
                )
            )
        return store, url.key

    def test_one_target_holds_exactly_one_decision(self) -> None:
        store, url_key = self._bounded(DecisionKind.UPHOLD)
        assert len(store.decisions) == 1
        assert store.decision_for(url_key) is store.decisions[f"dec:{url_key}"]

    def test_the_freshest_stance_wins_on_an_observable(self) -> None:
        store, url_key = self._bounded(DecisionKind.UPHOLD)
        result = evaluate(store).observable(url_key)
        assert result.score == 9.0
        assert result.verdict is Verdict.MALICIOUS

    def test_the_opposite_stance_wins_when_it_is_the_fresher_one(self) -> None:
        store, url_key = self._bounded(DecisionKind.REFUTE)
        result = evaluate(store).observable(url_key)
        assert result.score == -1.0
        assert result.verdict is Verdict.SAFE

    def _forced(self, fresher: DecisionKind) -> tuple[FactStore, str]:
        store = make_store()
        finding = Finding(
            rule_id="rule",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.NOTABLE,
        )
        store.append(finding)
        for kind in (DecisionKind.UPHOLD, DecisionKind.REFUTE):
            store.append(
                Decision(
                    target_key=finding.key,
                    kind=kind,
                    justification="motif",
                    occurred_at=self.JUNE if kind is fresher else self.JANUARY,
                    source=source("alice", SourceClass.ORG_ANALYST),
                    fragment_id="f1",
                )
            )
        return store, finding.key

    def test_a_fresher_confirmation_outranks_an_older_dismissal(self) -> None:
        """Precedence used to be hardcoded: DISMISSED always won, however stale it was."""
        store, finding_key = self._forced(DecisionKind.UPHOLD)
        result = evaluate(store).finding(finding_key)
        assert result.counted is True
        assert result.verdict is Verdict.MALICIOUS

    def test_a_fresher_dismissal_outranks_an_older_confirmation(self) -> None:
        store, finding_key = self._forced(DecisionKind.REFUTE)
        result = evaluate(store).finding(finding_key)
        assert result.counted is False
        assert result.status is Status.NOT_APPLICABLE


class TestStatus:
    def test_non_evaluated_finding_is_visible_but_excluded(self) -> None:
        store = make_store()
        finding = Finding(
            rule_id="rule",
            subject_key="obs:url:none",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
            status=Status.NOT_APPLICABLE,
        )
        store.append(finding)

        report = evaluate(store)
        assert report.finding(finding.key).status is Status.NOT_APPLICABLE
        assert report.finding(finding.key).counted is False
        assert report.investigation.score == 0.0


class TestConclusions:
    """
    A conclusion raises the total to the verdict it asserts, and no further.

    Meant for an analysis that already read the other findings — an LLM most of the time — so it
    must neither double-count what it just read nor be able to inflate past its own claim.
    """

    @staticmethod
    def _conclusion(store: FactStore, rule_id: str = "ai_review", **kwargs) -> Finding:
        finding = Finding(
            rule_id=rule_id,
            subject_key="inv:f1",
            source=source("llm", SourceClass.INTERNAL_TOOL),
            fragment_id="f1",
            effect=Effect.FLOOR,
            **kwargs,
        )
        store.append(finding)
        return finding

    @staticmethod
    def _additive(store: FactStore, weight: float, rule_id: str = "base") -> Finding:
        finding = Finding(
            rule_id=rule_id,
            subject_key="inv:f1",
            source=source(),
            fragment_id="f1",
            verdict=Verdict.SUSPICIOUS,
            weight=weight,
            status=Status.EVALUATED,
        )
        store.append(finding)
        return finding

    @staticmethod
    def _floor_of(report, key: str) -> float:
        contributions = [
            c
            for c in report.investigation.contributions
            if c.source_key == key and c.label.startswith("conclusion floor")
        ]
        assert len(contributions) == 1
        return contributions[0].value

    def test_a_lone_conclusion_lands_exactly_on_the_floor_of_its_verdict(self) -> None:
        store = make_store()
        conclusion = self._conclusion(store, verdict=Verdict.MALICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 5.0
        assert report.investigation.verdict is Verdict.MALICIOUS
        assert self._floor_of(report, conclusion.key) == 5.0

    def test_it_only_adds_what_the_other_findings_are_missing(self) -> None:
        store = make_store()
        self._additive(store, 3.2)
        conclusion = self._conclusion(store, verdict=Verdict.MALICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 5.0
        assert self._floor_of(report, conclusion.key) == 1.8

    def test_it_adds_nothing_once_the_verdict_is_already_reached(self) -> None:
        store = make_store()
        self._additive(store, 6.0)
        conclusion = self._conclusion(store, verdict=Verdict.MALICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 6.0
        assert self._floor_of(report, conclusion.key) == 0.0

    def test_a_notable_conclusion_lands_inside_its_open_band(self) -> None:
        """``NOTABLE`` is ``]0, 3[``: it has no closed lower bound, so the floor is an epsilon."""
        store = make_store()
        self._conclusion(store, verdict=Verdict.NOTABLE)

        report = evaluate(store)
        assert 0.0 < report.investigation.score < 3.0
        assert report.investigation.verdict is Verdict.NOTABLE

    def test_a_conclusion_never_lowers_the_total(self) -> None:
        store = make_store()
        self._additive(store, 6.0)
        self._conclusion(store, verdict=Verdict.SUSPICIOUS)

        assert evaluate(store).investigation.score == 6.0

    def test_the_finding_itself_carries_no_score_whatever_the_base(self) -> None:
        """The property the whole design rests on: a conclusion is not a term of the sum."""
        for base in (0.0, 3.2, 6.0):
            store = make_store()
            if base:
                self._additive(store, base)
            conclusion = self._conclusion(store, verdict=Verdict.MALICIOUS)

            result = evaluate(store).finding(conclusion.key)
            assert result.score is None
            assert result.counted is True
            assert result.effect is Effect.FLOOR
            # The asserted verdict, not ``verdict_from_score(None)``.
            assert result.verdict is Verdict.MALICIOUS

    def test_an_unrelated_finding_does_not_move_the_conclusion_result(self) -> None:
        """Guards the diff: adding a finding must not rewrite a conclusion nobody touched."""
        alone = make_store()
        conclusion = self._conclusion(alone, verdict=Verdict.MALICIOUS)

        crowded = make_store()
        self._additive(crowded, 3.2)
        self._conclusion(crowded, verdict=Verdict.MALICIOUS)

        assert evaluate(alone).finding(conclusion.key) == evaluate(crowded).finding(conclusion.key)

    def test_conclusions_never_compound(self) -> None:
        """Two analysers agreeing must not double the score, or plugging in a third would inflate."""
        store = make_store()
        first = self._conclusion(store, "ai_a", verdict=Verdict.MALICIOUS)
        second = self._conclusion(store, "ai_b", verdict=Verdict.MALICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 5.0
        assert self._floor_of(report, first.key) + self._floor_of(report, second.key) == 5.0

    def test_several_conclusions_are_credited_by_ascending_target(self) -> None:
        store = make_store()
        self._additive(store, 1.0)
        strong = self._conclusion(store, "ai_strong", verdict=Verdict.MALICIOUS)
        weak = self._conclusion(store, "ai_weak", verdict=Verdict.SUSPICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 5.0
        assert self._floor_of(report, weak.key) == 2.0
        assert self._floor_of(report, strong.key) == 2.0

    def test_the_total_does_not_depend_on_insertion_order(self) -> None:
        forward, backward = make_store(), make_store()
        for store, order in ((forward, ("ai_a", "ai_b")), (backward, ("ai_b", "ai_a"))):
            self._conclusion(store, order[0], verdict=Verdict.SUSPICIOUS)
            self._conclusion(store, order[1], verdict=Verdict.MALICIOUS)

        assert evaluate(forward).investigation.score == evaluate(backward).investigation.score == 5.0

    def test_confidence_does_not_dampen_the_floor(self) -> None:
        """Dampening would make a conclusion miss the very verdict it asserts."""
        store = make_store()
        self._conclusion(store, verdict=Verdict.MALICIOUS, confidence=0.3)

        report = evaluate(store)
        assert report.investigation.score == 5.0
        assert report.investigation.verdict is Verdict.MALICIOUS

    def test_a_conclusion_still_weighs_on_the_global_confidence(self) -> None:
        store = make_store()
        self._additive(store, 4.0)
        self._conclusion(store, verdict=Verdict.MALICIOUS, confidence=0.5)

        assert evaluate(store).investigation.confidence == 0.75

    def test_linked_observables_stay_documentary(self) -> None:
        """Propagating them would push the total past 'just enough'."""
        store = make_store()
        url = add_url(store, "f1")
        store.append(
            ThreatIntel(subject_key=url.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        conclusion = self._conclusion(
            store,
            verdict=Verdict.SUSPICIOUS,
            observable_links=[ObservableLink(observable_key=url.key, scope=Scope.ALL)],
        )

        report = evaluate(store)
        assert report.investigation.score == 3.0
        links = [c for c in report.finding(conclusion.key).contributions if c.label.startswith("link")]
        assert links and not any(c.retained for c in links)

    def test_refuting_cancels_the_floor_entirely(self) -> None:
        store = make_store()
        conclusion = self._conclusion(store, verdict=Verdict.MALICIOUS)
        store.append(
            Decision(
                target_key=conclusion.key,
                kind=DecisionKind.REFUTE,
                justification="l'analyse s'appuyait sur un artefact effacé depuis",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        report = evaluate(store)
        assert report.finding(conclusion.key).counted is False
        assert report.investigation.score == 0.0

    def test_upholding_a_conclusion_cannot_raise_what_has_no_magnitude(self) -> None:
        """
        A conclusion already asserts its verdict; upholding it adds nothing to raise.

        The engine used to answer this by turning the conclusion into an additive finding scored
        at the floor — silently changing its ``effect`` and double-counting what it had read.
        """
        store = make_store()
        conclusion = self._conclusion(store, verdict=Verdict.SUSPICIOUS)
        store.append(
            Decision(
                target_key=conclusion.key,
                kind=DecisionKind.UPHOLD,
                justification="revue par le RSSI",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        report = evaluate(store)
        result = report.finding(conclusion.key)
        assert result.effect is Effect.FLOOR
        assert result.score is None
        assert result.counted is True
        assert report.investigation.score == 3.0

    def test_a_non_evaluated_conclusion_applies_nothing(self) -> None:
        store = make_store()
        self._conclusion(store, verdict=Verdict.MALICIOUS, status=Status.NOT_APPLICABLE)

        assert evaluate(store).investigation.score == 0.0

    def test_a_conclusion_must_assert_a_verdict_that_has_a_floor(self) -> None:
        store = make_store()
        for verdict in (Verdict.SAFE, Verdict.INFO):
            with pytest.raises(ValueError, match="must assert a verdict that has a floor"):
                self._conclusion(store, verdict=verdict)

    def test_a_conclusion_refuses_a_weight(self) -> None:
        """Silently ignoring it would leave a number in the document that changes nothing."""
        store = make_store()
        with pytest.raises(ValueError, match="never from a weight"):
            self._conclusion(store, verdict=Verdict.MALICIOUS, weight=8.0)


class TestJudgmentInvariants:
    """
    Guards that only hold because ``supersede`` rebuilds through the model.

    While an edit was a bare ``model_copy``, every one of these was reachable, and each caller
    had to restate the rule by hand to stay safe.
    """

    def test_a_weight_cannot_be_negative(self) -> None:
        """Direction is the verdict's job: a signed weight makes a fact contradict its own score."""
        with pytest.raises(ValueError, match="greater than or equal to 0"):
            Finding(
                rule_id="rule",
                subject_key="obs:url:none",
                source=source(),
                fragment_id="f1",
                verdict=Verdict.MALICIOUS,
                weight=-3.0,
            )

    def test_an_edit_cannot_reach_a_state_construction_refuses(self) -> None:
        investigation = Investigation()
        finding = Finding(
            rule_id="rule",
            subject_key=investigation.root_key,
            source=source(),
            fragment_id=investigation.fragment_id,
            verdict=Verdict.MALICIOUS,
            weight=3.0,
        )
        investigation.append(finding)

        with pytest.raises(ValueError, match="greater than or equal to 0"):
            investigation.supersede(finding, weight=-3.0)

    def test_an_edit_preserves_identity(self) -> None:
        """Rebuilding must not re-derive a key and orphan the fact it supersedes."""
        investigation = Investigation()
        finding = Finding(
            rule_id="rule",
            subject_key=investigation.root_key,
            source=source(),
            fragment_id=investigation.fragment_id,
            verdict=Verdict.SUSPICIOUS,
        )
        investigation.append(finding)

        updated = investigation.supersede(finding, comment="revu")
        assert updated.key == finding.key
        assert updated.seq != finding.seq
        assert investigation.get_finding(finding.key).comment == "revu"


class TestWeightResolution:
    """
    The order in which a magnitude is settled.

    Pinned because the documentation once stated the opposite: a policy that could overrule a
    stated weight would put us back to v6, where the displayed value and the computed one were
    free to disagree.
    """

    def _policy(self, **overrides) -> Policy:
        return DEFAULT_POLICY.model_copy(update=overrides)

    def test_a_stated_weight_wins_over_the_policy_default(self) -> None:
        resolved = DEFAULT_POLICY.resolve_weight(verdict=Verdict.MALICIOUS, weight=6.0)
        assert resolved == 6.0

    def test_zero_is_a_weight_not_an_absence(self) -> None:
        """Only ``None`` hands the decision to the policy; ``0.0`` is an assertion."""
        resolved = DEFAULT_POLICY.resolve_weight(verdict=Verdict.MALICIOUS, weight=0.0)
        assert resolved == 0.0

    def test_the_assumed_magnitude_applies_when_the_fact_states_nothing(self) -> None:
        resolved = DEFAULT_POLICY.resolve_weight(verdict=Verdict.MALICIOUS, weight=None)
        assert resolved == Weight.HIGH.value

    def test_retuning_a_default_recalibrates_every_fact_that_states_no_weight(self) -> None:
        """The one retuning axis left, and the only one that stays coherent across verdicts."""
        policy = self._policy(
            default_weight_by_verdict={**DEFAULT_POLICY.default_weight_by_verdict, Verdict.MALICIOUS: 8.5}
        )
        assert policy.resolve_weight(verdict=Verdict.MALICIOUS, weight=None) == 8.5
        assert policy.resolve_weight(verdict=Verdict.SAFE, weight=None) == Weight.LOW.value


class TestVerdictFromScore:
    """The projection is v6's ``get_level_from_score``; boundaries are the contract."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (-0.1, Verdict.SAFE),
            (0.0, Verdict.INFO),
            (0.01, Verdict.NOTABLE),
            (2.99, Verdict.NOTABLE),
            (3.0, Verdict.SUSPICIOUS),
            (4.99, Verdict.SUSPICIOUS),
            (5.0, Verdict.MALICIOUS),
        ],
    )
    def test_bands(self, score: float, expected: Verdict) -> None:
        assert verdict_from_score(score) is expected

    def test_polarity_agrees_with_the_bands(self) -> None:
        assert Verdict.SAFE.polarity == -1
        assert Verdict.INFO.polarity == 0
        assert all(v.polarity == 1 for v in (Verdict.NOTABLE, Verdict.SUSPICIOUS, Verdict.MALICIOUS))

    def test_neutral_element_is_not_zero(self) -> None:
        assert NEG_INF < 0.0

    @pytest.mark.parametrize("verdict", [Verdict.NOTABLE, Verdict.SUSPICIOUS, Verdict.MALICIOUS])
    def test_the_floor_of_a_verdict_reads_back_as_that_verdict(self, verdict: Verdict) -> None:
        """``score_floor_for`` is the inverse of ``verdict_from_score`` — a drift breaks conclusions."""
        assert verdict_from_score(score_floor_for(verdict, epsilon=0.01)) is verdict

    def test_verdicts_below_zero_have_no_floor(self) -> None:
        assert score_floor_for(Verdict.SAFE, epsilon=0.01) is None
        assert score_floor_for(Verdict.INFO, epsilon=0.01) is None
