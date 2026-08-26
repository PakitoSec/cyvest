"""The orchestrator: facts in, report out, cache invalidated on every append."""

from __future__ import annotations

import pytest

from cyvest.enums import DecisionKind, ObservableType, RelationKind, Scope, SourceClass, Verdict, Weight
from cyvest.evaluation import ResolvedScope
from cyvest.facts import Finding, Observable, SourceRef, Tag, ThreatIntel
from cyvest.investigation import Investigation

FEED = SourceRef(name="virustotal", source_class=SourceClass.VENDOR_FEED)


def url(inv: Investigation, value: str) -> Observable:
    return inv.add_observable(Observable(type="url", value=value, source=FEED, fragment_id=inv.fragment_id))


def intel(inv: Investigation, obs: Observable, weight: float, source: SourceRef = FEED) -> ThreatIntel:
    return inv.add_threat_intel(
        ThreatIntel(
            subject_key=obs.key,
            verdict=Verdict.MALICIOUS,
            weight=weight,
            source=source,
            fragment_id=inv.fragment_id,
        )
    )


def finding(inv: Investigation, rule_id: str, obs: Observable, **kwargs) -> Finding:
    return inv.add_finding(
        Finding(rule_id=rule_id, subject_key=obs.key, source=FEED, fragment_id=inv.fragment_id, **kwargs)
    )


class TestRoot:
    def test_the_root_is_identified_by_the_header_not_by_its_value(self) -> None:
        inv = Investigation()
        assert inv.store.header.root_key == inv.get_root().key
        assert inv.get_root().value != "root"

    def test_a_genuine_observable_named_root_does_not_collide(self) -> None:
        inv = Investigation()
        impostor = inv.add_observable(
            Observable(type="user", subtype="username", namespace="corp", value="root", source=FEED, fragment_id="f")
        )
        assert impostor.key != inv.store.header.root_key

    def test_the_root_never_feeds_score_upward(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 6.0)
        inv.add_relation(target, inv.get_root(), RelationKind.EXTRACTION)
        assert inv.report.observable(target.key).score == 6.0

    def test_root_type_must_be_file_or_artifact(self) -> None:
        assert Investigation(root_type="artifact").get_root().obs_type is ObservableType.ARTIFACT
        with pytest.raises(ValueError, match="root_type must be"):
            Investigation(root_type="url")


class TestReportCache:
    def test_the_cache_is_dropped_when_a_fact_lands(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        finding(inv, "r", target, observable_links=[{"observable_key": target.key, "scope": Scope.ALL}])
        assert inv.get_global_score() == 0.0

        intel(inv, target, 6.0)
        assert inv.get_global_score() == 6.0

    def test_reevaluate_does_not_touch_the_cached_report(self) -> None:
        from cyvest.policy import Policy

        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 6.0)
        finding(inv, "r", target, observable_links=[{"observable_key": target.key, "scope": Scope.ALL}])

        baseline = inv.get_global_score()
        other = inv.reevaluate(policy=Policy(output_precision=0))
        assert other.investigation.score == 6.0
        assert inv.get_global_score() == baseline


class TestFacts:
    def test_superseding_keeps_the_key_and_wins_on_freshness(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        first = finding(inv, "r", target)
        updated = inv.supersede(first, comment="revu")

        assert updated.key == first.key
        assert inv.get_finding(first.key).comment == "revu"
        assert len(inv.get_all_findings()) == 1

    def test_linking_an_observable_is_idempotent(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r", target)
        inv.link_finding_observable(created.key, target.key)
        inv.link_finding_observable(created.key, target.key)
        assert len(inv.get_finding(created.key).observable_links) == 1

    def test_linking_the_same_observable_under_two_scopes_keeps_both(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r", target)
        inv.link_finding_observable(created.key, target.key, Scope.OWN_FRAGMENT)
        inv.link_finding_observable(created.key, target.key, Scope.ALL)
        assert len(inv.get_finding(created.key).observable_links) == 2

    def test_linking_an_unknown_key_fails_loudly(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r", target)
        with pytest.raises(KeyError, match="Unknown observable"):
            inv.link_finding_observable(created.key, "obs:url:ghost")


class TestTags:
    def test_adding_a_leaf_materializes_its_ancestors(self) -> None:
        inv = Investigation()
        inv.add_tag(Tag(name="header:auth:dkim", source=FEED, fragment_id=inv.fragment_id))
        names = {tag.name for tag in inv.get_all_tags().values()}
        assert {"header", "header:auth", "header:auth:dkim"} <= names

    def test_aggregation_walks_descendants_and_reads_the_report(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 6.0)
        leaf = finding(inv, "r", target, observable_links=[{"observable_key": target.key, "scope": Scope.ALL}])

        inv.add_tag(Tag(name="header:auth:dkim", source=FEED, fragment_id=inv.fragment_id))
        inv.add_finding_to_tag("tag:header:auth:dkim", leaf.key)

        assert inv.get_tag_aggregated_score("header") == 6.0
        assert inv.get_tag_direct_score("header") == 0.0
        assert inv.get_tag_aggregated_verdict("header") is Verdict.MALICIOUS


class TestDecisions:
    def test_allowlisting_an_observable_derives_to_safe(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 8.0)
        inv.add_decision(target.key, DecisionKind.REFUTE, "CDN partenaire")

        result = inv.report.observable(target.key)
        assert result.verdict is Verdict.SAFE
        assert result.suppressed_by_decision is True

    def test_confirming_a_finding_forces_malicious(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r", target, observable_links=[{"observable_key": target.key, "scope": Scope.ALL}])
        inv.add_decision(created.key, DecisionKind.UPHOLD, "confirmé par l'analyse mémoire")
        assert inv.get_global_verdict() is Verdict.MALICIOUS


class TestFinalizeRelationships:
    def test_orphan_components_are_attached_to_the_root(self) -> None:
        inv = Investigation()
        parent = url(inv, "hxxp://parent")
        child = url(inv, "hxxp://child")
        inv.add_relation(parent, child, RelationKind.EXTRACTION)
        intel(inv, child, 6.0)

        assert inv.report.observable(inv.get_root().key).score == 0.0
        inv.finalize_relationships()
        assert inv.report.observable(inv.get_root().key).score == 0.0
        assert any(rel.source_key == inv.get_root().key for rel in inv.get_all_relations().values())


class TestMerge:
    def test_merging_is_a_store_union(self) -> None:
        left = Investigation(investigation_id="i1")
        right = Investigation(investigation_id="i2")

        target = url(left, "hxxp://a")
        intel(left, target, 2.0, SourceRef(name="proofpoint", source_class=SourceClass.VENDOR_FEED))
        f1 = finding(left, "url_in_body", target, observable_links=[{"observable_key": target.key}])

        target2 = url(right, "hxxp://a")
        intel(right, target2, 3.0, SourceRef(name="virustotal", source_class=SourceClass.VENDOR_FEED))
        f2 = finding(right, "url_reputation", target2, observable_links=[{"observable_key": target2.key}])

        left.merge_investigation(right)

        assert left.report.finding(f1.key).score == 2.0
        assert left.report.finding(f2.key).score == 3.0
        assert left.report.observable(target.key).score == 3.0
        assert left.get_global_score() == 5.0

    def test_merging_twice_changes_nothing(self) -> None:
        left = Investigation(investigation_id="i1")
        right = Investigation(investigation_id="i2")
        url(right, "hxxp://a")

        left.merge_investigation(right)
        first = left.get_global_score()
        count = len(left.get_all_observables())
        left.merge_investigation(right)

        assert left.get_global_score() == first
        assert len(left.get_all_observables()) == count


class TestExplain:
    def test_contributions_name_what_moved_the_needle(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 6.0)
        created = finding(
            inv,
            "r",
            target,
            verdict=Verdict.SAFE,
            weight=Weight.MEDIUM,
            observable_links=[{"observable_key": target.key, "scope": Scope.ALL}],
        )

        labels = {c.label: c for c in inv.explain(created.key)}
        floor = next(c for label, c in labels.items() if label.startswith("rule floor"))
        assert floor.retained is False
        assert inv.report.finding(created.key).own_term_suppressed is True

    def test_scope_resolution_is_visible_in_the_report(self) -> None:
        inv = Investigation(investigation_id="i1")
        target = url(inv, "hxxp://a")
        intel(inv, target, 4.0)
        finding(inv, "r", target, observable_links=[{"observable_key": target.key, "scope": Scope.OWN_FRAGMENT}])

        assert inv.report.observable(target.key, ResolvedScope.own("i1")).score == 4.0
