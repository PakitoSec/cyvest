"""Core evaluation tests: the reference scenario, the finding's three levels, and the projection."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyvest.enums import (
    Aggregation,
    DecisionKind,
    Effect,
    LinkBasis,
    RelationKind,
    SourceClass,
    Status,
    Verdict,
    Weight,
)
from cyvest.evaluation import evaluate
from cyvest.evaluation.combine import NEG_INF
from cyvest.evaluation.projection import score_floor_for, verdict_from_score
from cyvest.facts import Decision, Finding, Observable, ObservableLink, Relation, SourceRef, ThreatIntel
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


class TestProvenanceDedup:
    @staticmethod
    def domain_case(count: int = 3, weight: float = 0.5, verdict: Verdict = Verdict.NOTABLE):
        store = make_store()
        domain = Observable(type="host", subtype="fqdn", value="example.com", source=source(), fragment_id="f1")
        store.append(domain)
        signal = ThreatIntel(
            subject_key=domain.key, verdict=verdict, weight=weight, source=source("feed"), fragment_id="f1"
        )
        store.append(signal)
        urls = []
        findings = []
        for index in range(count):
            url = Observable(type="url", value=f"https://example.com/{index}", source=source(), fragment_id="f1")
            store.append(url)
            store.append(
                Relation(
                    source_key=url.key,
                    target_key=domain.key,
                    kind=RelationKind.EXTRACTION,
                    source=source(),
                    fragment_id="f1",
                )
            )
            finding = Finding(
                rule_id=f"url-{index}",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=url.key)],
            )
            store.append(finding)
            urls.append(url)
            findings.append(finding)
        return store, domain, signal, urls, findings

    @pytest.mark.parametrize("count", [1, 3, 10, 100])
    @pytest.mark.parametrize("engine", ["basic", "basic-v1"])
    def test_provenance_shared_domain_counts_once(self, count: int, engine: str) -> None:
        store, _, _, urls, findings = self.domain_case(count)

        report = evaluate(store, engine=engine)

        assert all(report.observable(url.key).score == 0.5 for url in urls)
        assert all(report.finding(finding.key).score == 0.5 for finding in findings)
        assert report.investigation.score == (count * 0.5 if engine == "basic-v1" else 0.5)

    def test_provenance_default_and_explanation(self) -> None:
        store, _, signal, _, findings = self.domain_case()
        report = evaluate(store)

        assert report.engine_id == "basic-v2"
        assert report.investigation.score == 0.5
        terms = report.investigation.contributions
        assert [term.source_key for term in terms] == [signal.key] * 3
        assert [term.retained for term in terms] == [True, False, False]
        assert sum(term.value for term in terms if term.retained) == report.investigation.score
        assert all(any(finding.key in term.detail for term in terms) for finding in findings)
        assert all(report.finding(finding.key).counted for finding in findings)
        results = [report.finding(finding.key) for finding in findings]
        assert [result.contribution_score for result in results] == [0.5, 0.0, 0.0]
        assert [result.contribution_status for result in results] == ["credited", "shared", "shared"]

    @pytest.mark.parametrize("weight", [0.2, 0.5, 0.7])
    def test_provenance_own_claim_obeys_max(self, weight: float) -> None:
        store, _, _, urls, _ = self.domain_case()
        finding = Finding(
            rule_id="independent",
            verdict=Verdict.NOTABLE,
            weight=weight,
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=urls[0].key)],
        )
        store.append(finding)

        report = evaluate(store)

        assert report.finding(finding.key).score == max(0.5, weight)
        assert report.investigation.score == (1.2 if weight > 0.5 else 0.5)

    @pytest.mark.parametrize("verdict, amount", [(Verdict.NOTABLE, 0.7), (Verdict.SAFE, -0.7)])
    def test_contribution_partially_shared_finding(self, verdict: Verdict, amount: float) -> None:
        store, _, _, urls, findings = self.domain_case(2)
        store.append(
            ThreatIntel(subject_key=urls[1].key, verdict=verdict, weight=0.7, source=source(), fragment_id="f1")
        )
        report = evaluate(store, policy=Policy(aggregation=Aggregation.SUM))
        partial = report.finding(findings[1].key)
        assert partial.contribution_score == amount
        assert partial.contribution_status == "partial"
        assert sum(result.contribution_score for result in report.findings.values()) == pytest.approx(
            report.investigation.score
        )

    def test_contribution_cancelling_origins_are_not_neutral(self) -> None:
        store, _, _, urls, findings = self.domain_case(1)
        store.append(
            ThreatIntel(subject_key=urls[0].key, verdict=Verdict.SAFE, weight=0.5, source=source(), fragment_id="f1")
        )
        result = evaluate(store, policy=Policy(aggregation=Aggregation.SUM)).finding(findings[0].key)
        assert result.score == result.contribution_score == 0.0
        assert result.contribution_status == "credited"

    @pytest.mark.parametrize("attenuation, expected", [(0.0, "credited"), (0.002, "credited"), (0.5, "partial")])
    def test_contribution_ignores_shared_origins_with_no_numeric_effect(
        self, attenuation: float, expected: str
    ) -> None:
        store, _, _, urls, _ = self.domain_case(2)
        hub = Observable(type="url", value="https://hub.example/", source=source(), fragment_id="f1")
        parent = Observable(type="url", value="https://parent.example/", source=source(), fragment_id="f1")
        store.extend([hub, parent])
        for url in urls:
            store.append(
                Relation(
                    source_key=hub.key,
                    target_key=url.key,
                    kind=RelationKind.EXTRACTION,
                    source=source(),
                    fragment_id="f1",
                )
            )
        store.append(
            Relation(
                source_key=parent.key, target_key=hub.key, kind=RelationKind.PIVOT, source=source(), fragment_id="f1"
            )
        )
        store.append(
            ThreatIntel(subject_key=parent.key, verdict=Verdict.NOTABLE, weight=0.7, source=source(), fragment_id="f1")
        )
        store.append(
            Finding(
                rule_id="parent",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=parent.key)],
            )
        )
        policy = Policy(
            aggregation=Aggregation.SUM, attenuation={RelationKind.EXTRACTION: 1.0, RelationKind.PIVOT: attenuation}
        )
        result = evaluate(store, policy=policy).finding("fnd:parent")
        assert result.contribution_score == 0.7
        assert result.contribution_status == expected

    @pytest.mark.parametrize("engine", ["basic-v1", "basic-v2"])
    def test_contribution_excluded_neutral_and_conclusion_deltas(self, engine: str) -> None:
        store = make_store()
        for finding in (
            Finding(rule_id="neutral", source=source(), fragment_id="f1"),
            Finding(rule_id="pending", status=Status.PENDING, source=source(), fragment_id="f1"),
            Finding(rule_id="dismissed", verdict=Verdict.MALICIOUS, source=source(), fragment_id="f1"),
            Finding(rule_id="floor", effect=Effect.FLOOR, verdict=Verdict.MALICIOUS, source=source(), fragment_id="f1"),
            Finding(
                rule_id="redundant", effect=Effect.FLOOR, verdict=Verdict.MALICIOUS, source=source(), fragment_id="f1"
            ),
            Finding(rule_id="ceiling", effect=Effect.CEILING, verdict=Verdict.INFO, source=source(), fragment_id="f1"),
        ):
            store.append(finding)
        store.append(
            Decision(
                target_key="fnd:dismissed",
                kind=DecisionKind.REFUTE,
                justification="dismissed",
                source=source(),
                fragment_id="f1",
            )
        )
        report = evaluate(store, engine=engine)
        expected = {
            "neutral": (0.0, "neutral"),
            "pending": (0.0, "excluded"),
            "dismissed": (0.0, "excluded"),
            "floor": (5.0, "credited"),
            "redundant": (0.0, "neutral"),
            "ceiling": (-5.0, "credited"),
        }
        for rule_id, credit in expected.items():
            result = report.finding(f"fnd:{rule_id}")
            assert (result.contribution_score, result.contribution_status) == credit
        assert (
            sum(result.contribution_score for result in report.findings.values()) == report.investigation.score == 0.0
        )

    def test_contribution_missing_legacy_attribution_is_unknown(self) -> None:
        from cyvest.evaluation.report import FindingResult

        result = FindingResult(key="fnd:legacy", score=0.5)
        assert result.contribution_score is None
        assert result.contribution_status is None

    def test_provenance_distinct_signals_from_same_vendor_still_add(self) -> None:
        store, _, _, urls, _ = self.domain_case()
        local = ThreatIntel(
            subject_key=urls[0].key,
            verdict=Verdict.NOTABLE,
            weight=0.7,
            source=source("feed"),
            fragment_id="f1",
        )
        store.append(local)

        assert evaluate(store).investigation.score == 1.2

    def test_provenance_equal_values_on_distinct_subjects_still_add(self) -> None:
        store, _, _, _, _ = self.domain_case()
        domain = Observable(type="host", subtype="fqdn", value="other.example", source=source(), fragment_id="f1")
        store.append(domain)
        store.append(
            ThreatIntel(
                subject_key=domain.key,
                verdict=Verdict.NOTABLE,
                weight=0.5,
                source=source("feed"),
                fragment_id="f1",
            )
        )
        store.append(
            Finding(
                rule_id="other",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=domain.key)],
            )
        )
        assert evaluate(store).investigation.score == 1.0

    @pytest.mark.parametrize("verdict, expected", [(Verdict.NOTABLE, 0.5), (Verdict.SAFE, -0.5)])
    def test_provenance_attenuation_keeps_strongest_magnitude(self, verdict: Verdict, expected: float) -> None:
        store, domain, _, _, _ = self.domain_case(verdict=verdict)
        parent = Observable(type="url", value="https://another.example/", source=source(), fragment_id="f1")
        store.append(parent)
        store.append(
            Relation(
                source_key=parent.key,
                target_key=domain.key,
                kind=RelationKind.PIVOT,
                confidence=0.5,
                source=source(),
                fragment_id="f1",
            )
        )
        store.append(
            Finding(
                rule_id="attenuated",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=parent.key)],
            )
        )

        report = evaluate(store)

        assert report.observable(parent.key).score == expected / 2
        assert report.investigation.score == expected

    @pytest.mark.parametrize(
        "kind, expected",
        [
            (DecisionKind.UPHOLD, 9.0),
            (DecisionKind.REFUTE, -1.0),
            (DecisionKind.VACATED, 0.5),
        ],
    )
    def test_provenance_shared_observable_decision(self, kind: DecisionKind, expected: float) -> None:
        store, domain, signal, _, _ = self.domain_case()
        decision = Decision(
            target_key=domain.key, kind=kind, justification="reviewed", source=source(), fragment_id="f1"
        )
        store.append(decision)
        report = evaluate(store)

        assert report.investigation.score == expected
        assert {term.source_key for term in report.investigation.contributions} == {
            signal.key if kind is DecisionKind.VACATED else decision.key
        }

    @pytest.mark.parametrize(
        "kind, expected",
        [
            (DecisionKind.UPHOLD, 9.5),
            (DecisionKind.REFUTE, 0.5),
            (DecisionKind.VACATED, 0.5),
        ],
    )
    def test_provenance_finding_decision(self, kind: DecisionKind, expected: float) -> None:
        store, _, _, _, findings = self.domain_case()
        store.append(
            Decision(target_key=findings[0].key, kind=kind, justification="reviewed", source=source(), fragment_id="f1")
        )
        report = evaluate(store)
        assert report.investigation.score == expected
        assert report.finding(findings[0].key).counted is (kind is not DecisionKind.REFUTE)

    def test_provenance_unchanged_decision_does_not_replace_signal(self) -> None:
        store, domain, signal, _, _ = self.domain_case(weight=10.0)
        store.append(
            Decision(
                target_key=domain.key,
                kind=DecisionKind.UPHOLD,
                justification="reviewed",
                source=source(),
                fragment_id="f1",
            )
        )
        report = evaluate(store)
        assert report.investigation.score == 10.0
        assert {term.source_key for term in report.investigation.contributions} == {signal.key}

    def test_provenance_pinned_and_observable_links_share_origin(self) -> None:
        store, domain, signal, _, _ = self.domain_case()
        store.append(
            Finding(
                rule_id="pinned",
                source=source(),
                fragment_id="f1",
                observable_links=[
                    ObservableLink(
                        observable_key=domain.key,
                        basis=LinkBasis.SIGNALS,
                        signal_keys=(signal.key,),
                    )
                ],
            )
        )
        assert evaluate(store).investigation.score == 0.5

    @pytest.mark.parametrize("aggregation", [Aggregation.MAX, Aggregation.SUM])
    def test_provenance_diamond_keeps_local_formula(self, aggregation: Aggregation) -> None:
        store, _, _, urls, _ = self.domain_case()
        hub = Observable(type="url", value="https://hub.example/", source=source(), fragment_id="f1")
        store.append(hub)
        for url in urls:
            store.append(
                Relation(
                    source_key=hub.key,
                    target_key=url.key,
                    kind=RelationKind.EXTRACTION,
                    source=source(),
                    fragment_id="f1",
                )
            )
        store.append(
            Finding(
                rule_id="hub",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=hub.key)],
            )
        )
        report = evaluate(store, policy=Policy(aggregation=aggregation))

        assert report.findings["fnd:hub"].score == (1.5 if aggregation is Aggregation.SUM else 0.5)
        assert report.investigation.score == 0.5

    @pytest.mark.parametrize("weight, expected", [(0.004, 0.0), (0.005, 0.01), (2.995, 3.0), (4.995, 5.0)])
    def test_provenance_rounds_after_reduction(self, weight: float, expected: float) -> None:
        store, _, _, _, _ = self.domain_case(weight=weight)
        report = evaluate(store)
        assert report.investigation.score == expected
        assert report.investigation.verdict is verdict_from_score(expected)

    def test_provenance_order_and_fragment_invariance(self) -> None:
        store, _, _, _, _ = self.domain_case()
        reversed_store = FactStore(store.header)
        for fact in reversed(list(store.all_facts())):
            reversed_store.append(fact)
        assert evaluate(store).investigation == evaluate(reversed_store).investigation

        left, _, _ = TestMergeScenario._fragment("i1", "feed-a", 0.5, "rule-a")
        right, _, _ = TestMergeScenario._fragment("i2", "feed-b", 0.5, "rule-b")
        first = evaluate(left.union(right))
        second = evaluate(right.union(left))
        assert first.investigation.score == second.investigation.score == 0.5
        assert first.investigation.contributions == second.investigation.contributions

    def test_provenance_conclusions_apply_after_dedup(self) -> None:
        store, _, _, _, _ = self.domain_case(10)
        store.append(
            Finding(
                rule_id="floor",
                verdict=Verdict.SUSPICIOUS,
                effect=Effect.FLOOR,
                source=source(),
                fragment_id="f1",
            )
        )
        assert evaluate(store).investigation.score == 3.0
        store.append(
            Finding(
                rule_id="ceiling",
                verdict=Verdict.NOTABLE,
                effect=Effect.CEILING,
                source=source(),
                fragment_id="f1",
            )
        )
        assert evaluate(store).investigation.score == 2.99

    def test_provenance_external_ids_and_pins_keep_distinct_facts(self) -> None:
        store, domain, _, _, _ = self.domain_case()
        second = ThreatIntel(
            subject_key=domain.key,
            verdict=Verdict.NOTABLE,
            weight=0.5,
            source=source("feed"),
            fragment_id="f1",
            external_id="second-observation",
        )
        store.append(second)
        store.append(
            Finding(
                rule_id="second",
                source=source(),
                fragment_id="f1",
                observable_links=[
                    ObservableLink(
                        observable_key=domain.key,
                        basis=LinkBasis.SIGNALS,
                        signal_keys=(second.key,),
                    )
                ],
            )
        )
        assert evaluate(store).investigation.score == 1.0

    def test_provenance_suppressed_domain_is_not_resurrected(self) -> None:
        store, _, signal, urls, _ = self.domain_case()
        for url in urls:
            store.append(
                ThreatIntel(
                    subject_key=url.key, verdict=Verdict.NOTABLE, weight=0.7, source=source("feed"), fragment_id="f1"
                )
            )
        report = evaluate(store)
        assert report.investigation.score == 2.1
        assert all(term.source_key != signal.key for term in report.investigation.contributions)

    def test_provenance_one_finding_with_many_links(self) -> None:
        store, _, _, urls, _ = self.domain_case()
        single = FactStore(store.header)
        single.extend(fact for fact in store.all_facts() if not isinstance(fact, Finding))
        single.append(
            Finding(
                rule_id="all-urls",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=url.key) for url in urls],
            )
        )
        report = evaluate(single)
        assert report.investigation.score == 0.5
        assert len(report.investigation.contributions) == 1

    def test_provenance_sum_keeps_distinct_origins_but_deduplicates_shared_domain(self) -> None:
        store, _, _, urls, _ = self.domain_case()
        store.append(
            ThreatIntel(subject_key=urls[0].key, verdict=Verdict.NOTABLE, weight=0.7, source=source(), fragment_id="f1")
        )
        report = evaluate(store, policy=Policy(aggregation=Aggregation.SUM))
        assert report.observable(urls[0].key).score == 1.2
        assert report.investigation.score == 1.2

    def test_provenance_signed_sum_routes_can_be_reversed(self) -> None:
        store, domain, _, _, _ = self.domain_case(count=0)
        hub = Observable(type="url", value="https://hub.example", source=source(), fragment_id="f1")
        parent = Observable(type="url", value="https://parent.example", source=source(), fragment_id="f1")
        store.extend([hub, parent])
        for kind in (RelationKind.EXTRACTION, RelationKind.PIVOT):
            store.append(
                Relation(source_key=hub.key, target_key=domain.key, kind=kind, source=source(), fragment_id="f1")
            )
        store.append(
            Relation(
                source_key=parent.key, target_key=hub.key, kind=RelationKind.PIVOT, source=source(), fragment_id="f1"
            )
        )
        store.append(
            Finding(
                rule_id="parent",
                source=source(),
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=parent.key)],
            )
        )
        policy = Policy(
            aggregation=Aggregation.SUM, attenuation={RelationKind.EXTRACTION: 1.0, RelationKind.PIVOT: -1.0}
        )
        report = evaluate(store, policy=policy)
        assert report.observable(parent.key).score == 0.0
        assert report.investigation.score == 0.5


class TestMergeScenario:
    """
    Merging accumulates on the observable and adds terms to the total.

    v7.0 briefly damped this with a ``FRAGMENT`` basis, so a finding only saw its own worker's
    facts. It was dropped: it damped a merged total but never a local one, so the same two rules
    scored 10 or 16 depending on how the run was threaded. A finding that must hold its value now
    says so explicitly, by pinning.
    """

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
            source=source(source_name),
            fragment_id=fragment_id,
            observable_links=[ObservableLink(observable_key=url.key)],
        )
        store.append(finding)
        return store, url.key, finding.key

    def test_every_finding_reads_the_merged_observable(self) -> None:
        i1, url_key, f1 = self._fragment("i1", "proofpoint", 2.0, "url_in_body")
        i2, _, f2 = self._fragment("i2", "virustotal", 3.0, "url_reputation")

        report = evaluate(i1.union(i2), engine="basic-v1")

        assert report.finding(f1).score == 3.0
        assert report.finding(f2).score == 3.0
        assert report.observable(url_key).score == 3.0
        assert report.investigation.score == 6.0

    def test_an_observable_yields_exactly_one_result(self) -> None:
        """The graph holds every fact anyone contributed; it is the links that filter."""
        i1, url_key, _ = self._fragment("i1", "proofpoint", 2.0, "url_in_body")
        i2, _, _ = self._fragment("i2", "virustotal", 3.0, "url_reputation")

        report = evaluate(i1.union(i2))

        assert [key for key in report.observables if key.startswith(url_key)] == [url_key]

    def test_the_damping_is_the_same_within_one_fragment(self) -> None:
        """What made ``FRAGMENT`` indefensible: identical rules, identical total, either way."""
        merged_across = evaluate(
            self._fragment("i1", "proofpoint", 2.0, "url_in_body")[0].union(
                self._fragment("i2", "virustotal", 3.0, "url_reputation")[0]
            )
        )

        store, url, _, _ = _one_fragment_two_feeds()
        assert evaluate(store).investigation.score == merged_across.investigation.score


def _one_fragment_two_feeds():
    """The same two feeds and two rules, fetched by a single worker."""
    store = make_store("f1")
    url = add_url(store, "f1")
    findings = []
    for source_name, weight, rule_id in (("proofpoint", 2.0, "url_in_body"), ("virustotal", 3.0, "url_reputation")):
        store.append(
            ThreatIntel(
                subject_key=url.key,
                verdict=Verdict.MALICIOUS,
                weight=weight,
                source=source(source_name),
                fragment_id="f1",
            )
        )
        finding = Finding(
            rule_id=rule_id,
            source=source(source_name),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key)],
        )
        store.append(finding)
        findings.append(finding)
    return store, url, *findings


class TestPinnedBasis:
    """
    A finding that fetched its own intel must hold that value, whoever enriches the observable
    next — and whether or not that enrichment ran in the same worker.
    """

    @staticmethod
    def _case(fragment_id: str = "f1"):
        store = make_store(fragment_id)
        url = add_url(store, fragment_id)
        trap = ThreatIntel(
            subject_key=url.key,
            verdict=Verdict.SUSPICIOUS,
            weight=4.0,
            source=source("proofpoint-trap"),
            fragment_id=fragment_id,
        )
        store.append(trap)
        finding = Finding(
            rule_id="pp-trap-hit",
            source=source("proofpoint-trap"),
            fragment_id=fragment_id,
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.SIGNALS, signal_keys=(trap.key,))],
        )
        store.append(finding)
        return store, url, trap, finding

    def _generic_intel(self, store: FactStore, url: Observable, fragment_id: str) -> None:
        store.append(
            ThreatIntel(
                subject_key=url.key,
                verdict=Verdict.MALICIOUS,
                weight=6.0,
                source=source("urlhaus"),
                fragment_id=fragment_id,
            )
        )

    def test_generic_intel_in_the_same_fragment_does_not_move_it(self) -> None:
        """One worker fetching several feeds — the case no fragment filter could ever cover."""
        store, url, _, finding = self._case()
        self._generic_intel(store, url, "f1")

        report = evaluate(store)
        assert report.finding(finding.key).score == 4.0
        assert report.observable(url.key).score == 6.0

    def test_generic_intel_in_another_fragment_does_not_move_it(self) -> None:
        store, url, _, finding = self._case("i1")
        other = make_store("i2")
        other_url = add_url(other, "i2")
        self._generic_intel(other, other_url, "i2")

        report = evaluate(store.union(other))
        assert report.finding(finding.key).score == 4.0

    def test_a_malicious_child_does_not_reach_a_pinned_finding(self) -> None:
        store, url, _, finding = self._case()
        ip = Observable(type="ipv4", value="203.0.113.7", source=source(), fragment_id="f1")
        store.append(ip)
        store.append(
            ThreatIntel(subject_key=ip.key, verdict=Verdict.MALICIOUS, weight=8.0, source=source(), fragment_id="f1")
        )
        store.append(
            Relation(
                source_key=url.key,
                target_key=ip.key,
                kind=RelationKind.EXTRACTION,
                source=source(),
                fragment_id="f1",
            )
        )

        report = evaluate(store)
        assert report.finding(finding.key).score == 4.0
        assert report.observable(url.key).score == 8.0

    def test_it_follows_a_re_assertion_of_the_pinned_signal(self) -> None:
        """Pinning resolves at evaluation, so a re-fetch moves the finding with its own source."""
        store, url, _, finding = self._case()
        store.append(
            ThreatIntel(
                subject_key=url.key,
                verdict=Verdict.MALICIOUS,
                weight=7.0,
                source=source("proofpoint-trap"),
                fragment_id="f1",
            )
        )

        assert evaluate(store).finding(finding.key).score == 7.0

    def test_a_refute_on_the_observable_still_caps_it(self) -> None:
        """Pinning narrows the evidence, it does not launder an analyst's stance."""
        store, url, _, finding = self._case()
        store.append(
            Decision(
                target_key=url.key,
                kind=DecisionKind.REFUTE,
                justification="internal sandbox",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        assert evaluate(store).finding(finding.key).score == DEFAULT_POLICY.refute_ceiling

    def test_contributions_name_the_pinned_signal(self) -> None:
        store, _, trap, finding = self._case()

        contributions = evaluate(store).finding(finding.key).contributions
        pin = next(c for c in contributions if c.label.startswith("pin"))
        assert pin.source_key == trap.key
        assert pin.label == "pin · proofpoint-trap · SUSPICIOUS"
        assert pin.value == 4.0

    def test_an_absent_pinned_signal_is_reported_not_raised(self) -> None:
        """A fragment can carry the link before the signal it pins has merged in."""
        store = make_store()
        url = add_url(store, "f1")
        finding = Finding(
            rule_id="pp-trap-hit",
            source=source("proofpoint-trap"),
            fragment_id="f1",
            observable_links=[
                ObservableLink(observable_key=url.key, basis=LinkBasis.SIGNALS, signal_keys=("sig:absent:x",))
            ],
        )
        store.append(finding)

        result = evaluate(store).finding(finding.key)
        unresolved = next(c for c in result.contributions if c.label == "pin · unresolved")
        assert unresolved.retained is False
        assert result.score == 0.0

    def test_the_rule_floor_still_wins_when_it_is_stronger(self) -> None:
        store, url, trap, _ = self._case()
        strong = Finding(
            rule_id="strong",
            source=source("proofpoint-trap"),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
            weight=9.0,
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.SIGNALS, signal_keys=(trap.key,))],
        )
        store.append(strong)

        assert evaluate(store).finding(strong.key).score == 9.0


class TestFindingLevels:
    """Observables are the normal source of a score; the rule is a floor; a decision overrides."""

    def _linked_finding(self, store: FactStore, url: Observable, **kwargs) -> Finding:
        finding = Finding(
            rule_id="rule",
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
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
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
        )
        store.append(finding)
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.UPHOLD,
                justification="confirmed by memory analysis",
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
            source=source(),
            fragment_id="f1",
            verdict=Verdict.MALICIOUS,
        )
        store.append(finding)
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.REFUTE,
                justification="known false positive",
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
                justification="internal authentication infrastructure",
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
                justification="does not matter",
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
                    justification="reason",
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
            source=source(),
            fragment_id="f1",
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
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
                justification="internal infra",
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
                justification="the domain is no longer owned by the CISO",
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
                justification="out of scope now",
                occurred_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
                source=source("soc-lead", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        contributions = evaluate(store).observable(url_key).contributions
        vacated = next(c for c in contributions if c.source_key.startswith("dec:"))
        assert vacated.retained is False
        assert "stance withdrawn" in vacated.detail
        assert "out of scope now" in vacated.detail

    def test_a_vacated_finding_is_counted_again(self) -> None:
        store = make_store()
        finding = Finding(
            rule_id="rule",
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
                    justification="reason",
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
                    justification="reason",
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
                    justification="reason",
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

    @staticmethod
    def _ceiling_of(report, key: str) -> float:
        contributions = [
            c
            for c in report.investigation.contributions
            if c.source_key == key and c.label.startswith("conclusion ceiling")
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
        """The local conclusion is unchanged; only its global credit depends on other findings."""
        alone = make_store()
        conclusion = self._conclusion(alone, verdict=Verdict.MALICIOUS)

        crowded = make_store()
        self._additive(crowded, 3.2)
        self._conclusion(crowded, verdict=Verdict.MALICIOUS)

        first = evaluate(alone).finding(conclusion.key)
        second = evaluate(crowded).finding(conclusion.key)
        attribution = {"contribution_score", "contribution_status"}
        assert first.model_dump(exclude=attribution) == second.model_dump(exclude=attribution)
        assert first.contribution_score == 5.0
        assert second.contribution_score == 1.8

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
            observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
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
                justification="the analysis relied on an artefact deleted since",
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
                justification="reviewed by the CISO",
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


class TestCeilingConclusions:
    """
    A ceiling lowers the total to the verdict it asserts, and no further.

    This is what states a **declared benign context** — an awareness campaign, a sanctioned
    pentest, an authorised scanner. Without it the model could force a case up but never down,
    and the only way to say "whatever the evidence, this is benign" would be to guess a large
    negative weight.
    """

    @staticmethod
    def _ceiling(store: FactStore, rule_id: str = "campaign", **kwargs) -> Finding:
        finding = Finding(
            rule_id=rule_id,
            source=source("psat", SourceClass.INTERNAL_TOOL),
            fragment_id="f1",
            effect=Effect.CEILING,
            **kwargs,
        )
        store.append(finding)
        return finding

    def test_it_brings_a_malicious_total_down_into_the_safe_band(self) -> None:
        store = make_store()
        TestConclusions._additive(store, 8.0)
        ceiling = self._ceiling(store, verdict=Verdict.SAFE)

        report = evaluate(store)
        assert report.investigation.verdict is Verdict.SAFE
        assert report.investigation.score < 0.0
        assert TestConclusions._ceiling_of(report, ceiling.key) < 0.0

    def test_it_only_removes_what_exceeds_the_verdict(self) -> None:
        store = make_store()
        TestConclusions._additive(store, 8.0)
        ceiling = self._ceiling(store, verdict=Verdict.INFO)

        report = evaluate(store)
        assert report.investigation.score == 0.0
        assert TestConclusions._ceiling_of(report, ceiling.key) == -8.0

    def test_it_removes_nothing_once_the_total_is_already_below(self) -> None:
        store = make_store()
        TestConclusions._additive(store, 1.0)
        ceiling = self._ceiling(store, verdict=Verdict.SUSPICIOUS)

        report = evaluate(store)
        assert report.investigation.score == 1.0
        assert TestConclusions._ceiling_of(report, ceiling.key) == 0.0

    def test_the_finding_itself_carries_no_score(self) -> None:
        store = make_store()
        TestConclusions._additive(store, 8.0)
        ceiling = self._ceiling(store, verdict=Verdict.SAFE)

        result = evaluate(store).finding(ceiling.key)
        assert result.score is None
        assert result.counted is True
        assert result.effect is Effect.CEILING
        assert result.verdict is Verdict.SAFE

    def test_ceilings_never_compound(self) -> None:
        """Two sources agreeing the case is benign must not drive the total twice as low."""
        store = make_store()
        TestConclusions._additive(store, 8.0)
        first = self._ceiling(store, "psat", verdict=Verdict.INFO)
        second = self._ceiling(store, "knowbe4", verdict=Verdict.INFO)

        report = evaluate(store)
        assert report.investigation.score == 0.0
        assert TestConclusions._ceiling_of(report, first.key) + TestConclusions._ceiling_of(report, second.key) == -8.0

    def test_a_ceiling_outranks_a_floor(self) -> None:
        """A campaign that happens to contain a malicious-looking URL is still a campaign."""
        store = make_store()
        TestConclusions._additive(store, 2.0)
        TestConclusions._conclusion(store, "ai_review", verdict=Verdict.MALICIOUS)
        self._ceiling(store, verdict=Verdict.SAFE)

        report = evaluate(store)
        assert report.investigation.verdict is Verdict.SAFE

    def test_the_total_does_not_depend_on_insertion_order(self) -> None:
        forward, backward = make_store(), make_store()
        for store, reverse in ((forward, False), (backward, True)):
            steps = [
                lambda s: TestConclusions._additive(s, 8.0),
                lambda s: TestConclusions._conclusion(s, "ai_review", verdict=Verdict.MALICIOUS),
                lambda s: self._ceiling(s, verdict=Verdict.SAFE),
            ]
            for step in reversed(steps) if reverse else steps:
                step(store)

        assert evaluate(forward).investigation.score == evaluate(backward).investigation.score

    def test_refuting_a_ceiling_restores_the_computed_total(self) -> None:
        store = make_store()
        TestConclusions._additive(store, 8.0)
        ceiling = self._ceiling(store, verdict=Verdict.SAFE)
        store.append(
            Decision(
                target_key=ceiling.key,
                kind=DecisionKind.REFUTE,
                justification="the campaign it invoked never took place",
                source=source("alice", SourceClass.ORG_ANALYST),
                fragment_id="f1",
            )
        )

        report = evaluate(store)
        assert report.finding(ceiling.key).counted is False
        assert report.investigation.score == 8.0

    def test_a_malicious_ceiling_is_refused(self) -> None:
        """``MALICIOUS`` is unbounded above: capping there could never lower anything."""
        with pytest.raises(ValueError, match="may only de-escalate"):
            Finding(
                rule_id="campaign",
                source=source(),
                fragment_id="f1",
                effect=Effect.CEILING,
                verdict=Verdict.MALICIOUS,
            )

    def test_weighting_a_ceiling_is_refused(self) -> None:
        with pytest.raises(ValueError, match="never from a weight"):
            Finding(
                rule_id="campaign",
                source=source(),
                fragment_id="f1",
                effect=Effect.CEILING,
                verdict=Verdict.SAFE,
                weight=4.0,
            )


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
                source=source(),
                fragment_id="f1",
                verdict=Verdict.MALICIOUS,
                weight=-3.0,
            )

    def test_an_edit_cannot_reach_a_state_construction_refuses(self) -> None:
        investigation = Investigation()
        finding = Finding(
            rule_id="rule",
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
