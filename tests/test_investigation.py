"""The orchestrator: facts in, report out, cache invalidated on every append."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyvest.enums import DecisionKind, LinkBasis, ObservableType, RelationKind, SourceClass, Tactic, Verdict, Weight
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


def finding(inv: Investigation, rule_id: str, **kwargs) -> Finding:
    return inv.add_finding(Finding(rule_id=rule_id, source=FEED, fragment_id=inv.fragment_id, **kwargs))


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
        finding(inv, "r", observable_links=[{"observable_key": target.key, "basis": LinkBasis.OBSERVABLE}])
        assert inv.get_global_score() == 0.0

        intel(inv, target, 6.0)
        assert inv.get_global_score() == 6.0

    def test_reevaluate_does_not_touch_the_cached_report(self) -> None:
        from cyvest.policy import Policy

        inv = Investigation()
        target = url(inv, "hxxp://a")
        intel(inv, target, 6.0)
        finding(inv, "r", observable_links=[{"observable_key": target.key, "basis": LinkBasis.OBSERVABLE}])

        baseline = inv.get_global_score()
        other = inv.reevaluate(policy=Policy(output_precision=0))
        assert other.investigation.score == 6.0
        assert inv.get_global_score() == baseline


class TestFacts:
    def test_superseding_keeps_the_key_and_wins_on_freshness(self) -> None:
        inv = Investigation()
        first = finding(inv, "r")
        updated = inv.supersede(first, comment="revu")

        assert updated.key == first.key
        assert inv.get_finding(first.key).comment == "revu"
        assert len(inv.get_all_findings()) == 1

    def test_linking_an_observable_is_idempotent(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r")
        inv.link_finding_observable(created.key, target.key)
        inv.link_finding_observable(created.key, target.key)
        assert len(inv.get_finding(created.key).observable_links) == 1

    def test_linking_the_same_observable_under_two_bases_keeps_both(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r")
        inv.link_finding_observable(created.key, target.key, LinkBasis.NONE)
        inv.link_finding_observable(created.key, target.key, LinkBasis.OBSERVABLE)
        assert len(inv.get_finding(created.key).observable_links) == 2

    def test_linking_an_unknown_key_fails_loudly(self) -> None:
        inv = Investigation()
        created = finding(inv, "r")
        with pytest.raises(KeyError, match="Unknown observable"):
            inv.link_finding_observable(created.key, "obs:url:ghost")

    def test_an_undated_update_does_not_erase_the_date_or_the_tactic(self) -> None:
        """
        A re-assertion without ``occurred_at`` ranks at its own ``asserted_at``, later than any past
        ``occurred_at``, so it would win the merge and silently lose the date. The facade keeps it.
        """
        when = datetime(2026, 8, 7, 10, tzinfo=timezone.utc)
        inv = Investigation()
        finding(inv, "r", occurred_at=when, tactic=Tactic.EXECUTION)
        updated = finding(inv, "r", comment="revisited", verdict=Verdict.SUSPICIOUS)
        assert updated.comment == "revisited" and updated.verdict is Verdict.SUSPICIOUS
        assert updated.occurred_at == when and updated.tactic is Tactic.EXECUTION
        assert len(inv.get_all_findings()) == 1

    def test_a_dated_update_replaces_the_date_and_the_tactic(self) -> None:
        inv = Investigation()
        finding(inv, "r", occurred_at=datetime(2026, 8, 7, tzinfo=timezone.utc), tactic=Tactic.EXECUTION)
        later = datetime(2026, 8, 8, tzinfo=timezone.utc)
        updated = finding(inv, "r", occurred_at=later, tactic=Tactic.PERSISTENCE)
        assert updated.occurred_at == later and updated.tactic is Tactic.PERSISTENCE


class TestPinning:
    """``pin`` derives the observable from the signal, so the two can never disagree."""

    @staticmethod
    def _case():
        inv = Investigation()
        target = url(inv, "hxxp://a")
        trap = intel(inv, target, 4.0, SourceRef(name="proofpoint-trap", source_class=SourceClass.VENDOR_FEED))
        created = finding(inv, "r")
        return inv, target, trap, created

    def test_it_builds_the_same_link_as_the_long_form(self) -> None:
        inv, target, trap, created = self._case()
        inv.pin_finding_signals(created.key, trap.key)
        pinned = inv.get_finding(created.key).observable_links[0]

        other = Investigation()
        other_target = url(other, "hxxp://a")
        other_trap = intel(
            other, other_target, 4.0, SourceRef(name="proofpoint-trap", source_class=SourceClass.VENDOR_FEED)
        )
        other_created = finding(other, "r")
        other.link_finding_observable(other_created.key, other_target.key, LinkBasis.SIGNALS, [other_trap.key])

        assert pinned == other.get_finding(other_created.key).observable_links[0]

    def test_the_observable_is_derived_from_the_signal(self) -> None:
        inv, target, trap, created = self._case()
        inv.pin_finding_signals(created.key, trap.key)
        link = inv.get_finding(created.key).observable_links[0]

        assert link.observable_key == target.key
        assert link.basis is LinkBasis.SIGNALS
        assert link.signal_keys == (trap.key,)

    def test_it_accepts_the_signal_itself_or_its_key(self) -> None:
        inv, _, trap, created = self._case()
        inv.pin_finding_signals(created.key, trap)
        assert inv.get_finding(created.key).observable_links[0].signal_keys == (trap.key,)

    def test_signals_about_different_observables_are_refused(self) -> None:
        inv, _, trap, created = self._case()
        elsewhere = url(inv, "hxxp://b")
        other = intel(inv, elsewhere, 5.0)

        with pytest.raises(ValueError, match="different observables"):
            inv.pin_finding_signals(created.key, trap, other)

    def test_pinning_nothing_is_refused(self) -> None:
        inv, _, _, created = self._case()
        with pytest.raises(ValueError, match="at least one signal"):
            inv.pin_finding_signals(created.key)

    def test_an_unknown_signal_fails_loudly(self) -> None:
        inv, _, _, created = self._case()
        with pytest.raises(KeyError, match="Unknown signal"):
            inv.pin_finding_signals(created.key, "sig:ghost:obs:url:hxxp://a")

    def test_a_signal_about_another_observable_is_refused_in_the_long_form(self) -> None:
        inv, target, _, created = self._case()
        elsewhere = url(inv, "hxxp://b")
        other = intel(inv, elsewhere, 5.0)

        with pytest.raises(ValueError, match="a pinned link may only name signals"):
            inv.link_finding_observable(created.key, target.key, LinkBasis.SIGNALS, [other.key])

    def test_naming_signals_without_the_signals_basis_is_refused(self) -> None:
        inv, target, trap, created = self._case()
        with pytest.raises(ValueError, match="only applies to the SIGNALS basis"):
            inv.link_finding_observable(created.key, target.key, LinkBasis.OBSERVABLE, [trap.key])

    def test_the_signals_basis_needs_at_least_one_signal(self) -> None:
        inv, target, _, created = self._case()
        with pytest.raises(ValueError, match="must name at least one"):
            inv.link_finding_observable(created.key, target.key, LinkBasis.SIGNALS)


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
        leaf = finding(inv, "r", observable_links=[{"observable_key": target.key, "basis": LinkBasis.OBSERVABLE}])

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
        inv.add_decision(target.key, DecisionKind.REFUTE, "Partner CDN")

        result = inv.report.observable(target.key)
        assert result.verdict is Verdict.SAFE
        assert result.suppressed_by_decision is True

    def test_confirming_a_finding_forces_malicious(self) -> None:
        inv = Investigation()
        target = url(inv, "hxxp://a")
        created = finding(inv, "r", observable_links=[{"observable_key": target.key, "basis": LinkBasis.OBSERVABLE}])
        inv.add_decision(created.key, DecisionKind.UPHOLD, "confirmed by memory analysis")
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
        f1 = finding(left, "url_in_body", observable_links=[{"observable_key": target.key}])

        target2 = url(right, "hxxp://a")
        intel(right, target2, 3.0, SourceRef(name="virustotal", source_class=SourceClass.VENDOR_FEED))
        f2 = finding(right, "url_reputation", observable_links=[{"observable_key": target2.key}])

        left.merge_investigation(right)

        # Both findings read the merged observable: the graph is shared, only pins narrow it.
        assert left.report.finding(f1.key).score == 3.0
        assert left.report.finding(f2.key).score == 3.0
        assert left.report.observable(target.key).score == 3.0
        assert left.get_global_score() == 6.0

    def test_a_pinned_finding_survives_the_merge_unchanged(self) -> None:
        left = Investigation(investigation_id="i1")
        right = Investigation(investigation_id="i2")

        target = url(left, "hxxp://a")
        pinned_intel = intel(left, target, 2.0, SourceRef(name="proofpoint", source_class=SourceClass.VENDOR_FEED))
        f1 = finding(left, "url_in_body")
        left.pin_finding_signals(f1.key, pinned_intel.key)

        target2 = url(right, "hxxp://a")
        intel(right, target2, 3.0, SourceRef(name="virustotal", source_class=SourceClass.VENDOR_FEED))

        left.merge_investigation(right)

        assert left.report.finding(f1.key).score == 2.0
        assert left.report.observable(target.key).score == 3.0

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
            verdict=Verdict.SAFE,
            weight=Weight.MEDIUM,
            observable_links=[{"observable_key": target.key, "basis": LinkBasis.OBSERVABLE}],
        )

        labels = {c.label: c for c in inv.explain(created.key)}
        floor = next(c for label, c in labels.items() if label.startswith("rule floor"))
        assert floor.retained is False
        assert inv.report.finding(created.key).own_term_suppressed is True

    def test_the_basis_is_visible_in_the_report(self) -> None:
        inv = Investigation(investigation_id="i1")
        target = url(inv, "hxxp://a")
        intel(inv, target, 4.0)
        created = finding(inv, "r", observable_links=[{"observable_key": target.key}])

        link = next(c for c in inv.explain(created.key) if c.label.startswith("link"))
        assert link.label == "link · observable"
        assert inv.report.observable(target.key).score == 4.0
