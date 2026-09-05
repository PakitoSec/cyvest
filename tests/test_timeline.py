"""Timeline: a projection of the log, with salience derived rather than declared."""

from __future__ import annotations

from datetime import datetime, timezone

from cyvest.enums import DecisionKind, LinkBasis, Salience, SourceClass, Tactic, Verdict
from cyvest.evaluation import evaluate
from cyvest.evaluation.timeline import build_timeline
from cyvest.facts import Decision, Finding, Observable, ObservableLink, SourceRef, ThreatIntel
from cyvest.facts.store import FactStore, InvestigationHeader

SRC = SourceRef(name="feed", source_class=SourceClass.VENDOR_FEED)
ANALYST = SourceRef(name="alice", source_class=SourceClass.ORG_ANALYST)

JANUARY = datetime(2026, 1, 15, tzinfo=timezone.utc)
MARCH = datetime(2026, 3, 15, tzinfo=timezone.utc)
JUNE = datetime(2026, 6, 15, tzinfo=timezone.utc)


def build() -> tuple[FactStore, Observable, Finding]:
    store = FactStore(InvestigationHeader(investigation_id="inv", fragment_ids=("f1",)))
    url = Observable(type="url", value="hxxp://bad.example", source=SRC, fragment_id="f1", asserted_at=JANUARY)
    store.append(url)
    store.append(
        ThreatIntel(
            subject_key=url.key,
            verdict=Verdict.MALICIOUS,
            weight=6.0,
            observed_at=MARCH,
            asserted_at=MARCH,
            source=SRC,
            fragment_id="f1",
        )
    )
    finding = Finding(
        rule_id="url_in_body",
        name="URL in body",
        source=SRC,
        fragment_id="f1",
        asserted_at=MARCH,
        observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
    )
    store.append(finding)
    return store, url, finding


class TestTimeline:
    def test_entries_are_ordered_and_filtered_by_salience(self) -> None:
        store, _, _ = build()
        entries = build_timeline(store, evaluate(store))
        assert entries == sorted(entries, key=lambda e: (e.when, e.kind))
        assert all(entry.salience.rank >= Salience.NOTABLE.rank for entry in entries)

    def test_a_decision_is_always_salient(self) -> None:
        store, url, _ = build()
        store.append(
            Decision(
                target_key=url.key,
                kind=DecisionKind.REFUTE,
                justification="Partner CDN",
                occurred_at=JUNE,
                asserted_at=JUNE,
                source=ANALYST,
                fragment_id="f1",
            )
        )
        entries = build_timeline(store, evaluate(store), min_salience=Salience.KEY)
        decisions = [entry for entry in entries if entry.kind == "decision"]
        assert len(decisions) == 1
        assert decisions[0].salience is Salience.KEY
        assert "Partner CDN" in decisions[0].title

    def test_a_decision_is_titled_in_the_analyst_s_words(self) -> None:
        """
        The model keeps one axis; the reader gets two.

        ``REFUTE`` on an observable is what an analyst calls *allowlisting*, and on a finding what
        they call *dismissing*. Collapsing the enum is only defensible if that vocabulary survives
        where it is read, so the label is rebuilt from the intent and the target's family.
        """
        store, url, finding = build()
        store.append(
            Decision(
                target_key=url.key,
                kind=DecisionKind.REFUTE,
                justification="Partner CDN",
                occurred_at=JUNE,
                asserted_at=JUNE,
                source=ANALYST,
                fragment_id="f1",
            )
        )
        store.append(
            Decision(
                target_key=finding.key,
                kind=DecisionKind.REFUTE,
                justification="Known false positive",
                occurred_at=JUNE,
                asserted_at=JUNE,
                source=ANALYST,
                fragment_id="f1",
            )
        )
        titles = {
            entry.subject_key: entry.title
            for entry in build_timeline(store, evaluate(store), min_salience=Salience.KEY)
            if entry.kind == "decision"
        }
        assert titles[url.key] == "ALLOWLISTED · Partner CDN"
        assert titles[finding.key] == "DISMISSED · Known false positive"

    def test_the_time_basis_switches_the_axis(self) -> None:
        store = FactStore(InvestigationHeader(investigation_id="inv", fragment_ids=("f1",)))
        url = Observable(type="url", value="hxxp://a", source=SRC, fragment_id="f1")
        store.append(url)
        store.append(
            ThreatIntel(
                subject_key=url.key,
                verdict=Verdict.MALICIOUS,
                weight=6.0,
                observed_at=JANUARY,
                asserted_at=JUNE,
                source=SRC,
                fragment_id="f1",
            )
        )
        report = evaluate(store)
        occurred = build_timeline(store, report, time="occurred", min_salience=Salience.BACKGROUND)
        asserted = build_timeline(store, report, time="asserted", min_salience=Salience.BACKGROUND)

        signal_occurred = next(e for e in occurred if e.kind == "signal")
        signal_asserted = next(e for e in asserted if e.kind == "signal")
        assert signal_occurred.when == JANUARY
        assert signal_asserted.when == JUNE

    def test_window_and_entity_filters(self) -> None:
        store, url, _ = build()
        report = evaluate(store)
        assert build_timeline(store, report, since=JUNE) == []
        assert all(
            url.key in (entry.subject_key, *entry.refs)
            for entry in build_timeline(store, report, entity_key=url.key, min_salience=Salience.BACKGROUND)
        )

    def test_verdict_changes_are_opt_in(self) -> None:
        store, url, _ = build()
        report = evaluate(store)

        without = build_timeline(store, report)
        assert not any(entry.kind == "verdict_change" for entry in without)

        with_changes = build_timeline(
            store,
            report,
            track_verdict_changes=True,
            evaluator=lambda facts, policy: evaluate(facts, policy),
            min_salience=Salience.KEY,
        )
        changes = [entry for entry in with_changes if entry.kind == "verdict_change"]
        assert changes
        assert changes[0].subject_key == url.key
        assert "MALICIOUS" in changes[0].title

    def test_nothing_is_persisted_on_the_facts(self) -> None:
        store, _, _ = build()
        build_timeline(store, evaluate(store))
        assert all(not hasattr(fact, "salience") for fact in store.all_facts())

    def test_a_dated_finding_is_placed_at_its_occurrence_and_carries_its_tactic(self) -> None:
        store, url, _ = build()
        store.append(
            Finding(
                rule_id="beacon",
                name="Beacon to the C2",
                verdict=Verdict.SUSPICIOUS,
                tactic=Tactic.COMMAND_AND_CONTROL,
                occurred_at=JANUARY,
                asserted_at=JUNE,
                source=SRC,
                fragment_id="f1",
                observable_links=[ObservableLink(observable_key=url.key, basis=LinkBasis.OBSERVABLE)],
            )
        )
        report = evaluate(store)
        occurred = {e.title: e for e in build_timeline(store, report, min_salience=Salience.BACKGROUND)}
        beacon = occurred["Beacon to the C2"]
        assert beacon.when == JANUARY and beacon.dated and beacon.tactic is Tactic.COMMAND_AND_CONTROL

        # The undated finding of the fixture falls back to its assertion time, and says so.
        undated = occurred["URL in body"]
        assert undated.when == MARCH and not undated.dated and undated.tactic is None

        by_assertion = build_timeline(store, report, time="asserted", min_salience=Salience.BACKGROUND)
        asserted = {e.title: e for e in by_assertion}
        assert asserted["Beacon to the C2"].when == JUNE and asserted["Beacon to the C2"].dated

    def test_a_dated_finding_is_notable_even_when_it_weighs_nothing(self) -> None:
        """A neutral event of the incident is an INFO finding with a date: the chronology must show it."""
        store, _, _ = build()
        store.append(
            Finding(
                rule_id="login",
                name="jdoe logged in from the VPN",
                verdict=Verdict.INFO,
                occurred_at=JANUARY,
                asserted_at=JUNE,
                source=SRC,
                fragment_id="f1",
            )
        )
        titles = [entry.title for entry in build_timeline(store, evaluate(store))]
        assert "jdoe logged in from the VPN" in titles
