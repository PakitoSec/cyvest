"""Statistics and the shared context: both computed from the store, never accumulated."""

from __future__ import annotations

import asyncio
import threading

import pytest

from cyvest import Cyvest, Verdict
from cyvest.investigation import FrozenInvestigationError
from cyvest.shared import SharedInvestigationContext
from cyvest.stats import InvestigationStats


def stats_of(cv: Cyvest) -> InvestigationStats:
    return InvestigationStats(cv._investigation.store, cv.get_report())


def seeded_case() -> Cyvest:
    cv = Cyvest()
    url = cv.observable(cv.OBS.URL, "hxxp://bad.example", internal=False)
    ip = cv.observable(cv.OBS.IPV4, "10.0.0.5", internal=True)
    cv.observable_add_threat_intel(url, "virustotal", verdict=cv.VERDICT.MALICIOUS, weight=6.0)
    cv.observable_add_relation(ip, url, cv.REL.EXTRACTION)
    cv.finding("url_in_body").link_observable(url, cv.BASIS.OBSERVABLE)
    cv.tag_create("phishing")
    cv.evidence_create("enrichment", title="whois", content={"registrar": "x"})
    return cv


class TestStatistics:
    def test_counts_are_derived_from_the_store(self) -> None:
        stats = stats_of(seeded_case())
        summary = stats.get_summary()

        assert summary.total_observables == 3  # root, url, ip
        assert summary.internal_observables == 1
        assert summary.total_signals == 1
        assert summary.total_relations == 1
        assert summary.total_evidences == 1
        assert summary.total_tags == 1

    def test_verdicts_come_from_the_report_not_from_stored_levels(self) -> None:
        cv = seeded_case()
        summary = stats_of(cv).get_summary()
        assert summary.observables_by_verdict[Verdict.MALICIOUS] == 2  # the url and its parent
        assert summary.findings_by_verdict[Verdict.MALICIOUS] == 1

    def test_a_dismissed_finding_leaves_the_denominator(self) -> None:
        cv = seeded_case()
        before = stats_of(cv).get_applied_finding_count()

        next(iter(cv.finding_get_all().values())).dismiss("false positive")
        after = stats_of(cv).get_applied_finding_count()

        assert before == 1
        assert after == 0
        assert stats_of(cv).get_total_finding_count() == 1  # still visible

    def test_allowlisted_observables_are_counted_through_decisions(self) -> None:
        cv = seeded_case()
        url = cv.observable_get(cv.OBS.URL, "hxxp://bad.example")
        assert stats_of(cv).get_allowlisted_observable_count() == 0

        cv.decision_create(url, cv.DECISION.REFUTE, "internal infra")
        assert stats_of(cv).get_allowlisted_observable_count() == 1

    def test_confidence_bands_summarize_findings(self) -> None:
        cv = Cyvest()
        cv.finding("a", verdict=cv.VERDICT.MALICIOUS, confidence=cv.CONF.LOW)
        cv.finding("b", verdict=cv.VERDICT.MALICIOUS, confidence=cv.CONF.HIGH)
        bands = stats_of(cv).get_finding_count_by_confidence_band()
        assert bands == {"low": 1, "high": 1}

    def test_counts_follow_the_facts_without_registration(self) -> None:
        """v6 needed register_* calls, so counters could drift; here they cannot."""
        cv = seeded_case()
        assert stats_of(cv).get_total_observable_count() == 3
        cv.observable(cv.OBS.DOMAIN, "late.example")
        assert stats_of(cv).get_total_observable_count() == 4


class TestSharedContext:
    def test_workers_contribute_their_own_fragments(self) -> None:
        context = SharedInvestigationContext(root_data={"case": "IR-1"})

        with context.task(fragment_id="i1") as worker:
            url = worker.observable(worker.OBS.URL, "hxxp://bad.example/x")
            worker.observable_add_threat_intel(url, "proofpoint", verdict=worker.VERDICT.MALICIOUS, weight=2.0)
            worker.finding("url_in_body").link_observable(url)

        with context.task(fragment_id="i2") as worker:
            url = worker.observable(worker.OBS.URL, "hxxp://bad.example/x")
            worker.observable_add_threat_intel(url, "virustotal", verdict=worker.VERDICT.MALICIOUS, weight=3.0)
            worker.finding("url_reputation").link_observable(url)

        # Reconciled facts are shared, so both findings read the same observable.
        snapshot = context.snapshot()
        assert snapshot.get_global_score() == 6.0
        assert snapshot.get_global_verdict() is Verdict.MALICIOUS

    def test_reconciling_twice_is_harmless(self) -> None:
        context = SharedInvestigationContext()
        worker = context.create_cyvest(fragment_id="i1")
        worker.observable(worker.OBS.URL, "hxxp://bad.example")

        context.reconcile(worker)
        first = len(context.snapshot().observable_get_all())
        context.reconcile(worker)

        assert len(context.snapshot().observable_get_all()) == first

    def test_reconcile_order_does_not_matter(self) -> None:
        def build(fragment_id: str, value: str) -> Cyvest:
            context = SharedInvestigationContext(investigation_id="shared")
            worker = context.create_cyvest(fragment_id=fragment_id)
            worker.observable(worker.OBS.URL, value)
            return worker

        left, right = build("i1", "hxxp://a"), build("i2", "hxxp://b")

        forward = SharedInvestigationContext(investigation_id="shared")
        forward.reconcile(left)
        forward.reconcile(right)

        backward = SharedInvestigationContext(investigation_id="shared")
        backward.reconcile(right)
        backward.reconcile(left)

        assert sorted(forward.snapshot().observable_get_all()) == sorted(backward.snapshot().observable_get_all())

    def test_a_failing_task_still_contributes_what_it_gathered(self) -> None:
        context = SharedInvestigationContext()
        with pytest.raises(RuntimeError):
            with context.task(fragment_id="i1") as worker:
                worker.observable(worker.OBS.URL, "hxxp://partial")
                raise RuntimeError("analysis blew up")

        assert any("partial" in obs.value for obs in context.snapshot().observable_get_all().values())

    def test_a_failing_task_can_be_told_to_contribute_nothing(self) -> None:
        context = SharedInvestigationContext()
        with pytest.raises(RuntimeError):
            with context.task(fragment_id="i1", reconcile_on_error=False) as worker:
                worker.observable(worker.OBS.URL, "hxxp://partial")
                raise RuntimeError("analysis blew up")

        assert not any("partial" in obs.value for obs in context.snapshot().observable_get_all().values())

    def test_the_reconciled_whole_reads_through_the_ordinary_facade(self) -> None:
        context = SharedInvestigationContext()
        with context.task() as worker:
            url = worker.observable(worker.OBS.URL, "hxxp://bad.example")
            worker.observable_add_threat_intel(url, "virustotal", verdict=worker.VERDICT.MALICIOUS, weight=6.0)
            worker.finding("r").link_observable(url, worker.BASIS.OBSERVABLE)

        assert context.snapshot().get_global_score() == 6.0

    def test_a_snapshot_holds_still_while_workers_keep_arriving(self) -> None:
        """The point of a snapshot: several reads of one task cannot straddle two states."""
        context = SharedInvestigationContext()
        with context.task(fragment_id="first") as worker:
            worker.observable(worker.OBS.URL, "hxxp://first")

        snapshot = context.snapshot()
        before = len(snapshot.observable_get_all())

        with context.task(fragment_id="second") as worker:
            worker.observable(worker.OBS.URL, "hxxp://second")

        assert len(snapshot.observable_get_all()) == before
        assert len(context.snapshot().observable_get_all()) == before + 1

    def test_a_snapshot_refuses_to_be_written_to(self) -> None:
        context = SharedInvestigationContext()
        snapshot = context.snapshot()

        with pytest.raises(FrozenInvestigationError):
            snapshot.observable(snapshot.OBS.URL, "hxxp://nowhere")

    def test_concurrent_reconciles_never_tear_a_read(self) -> None:
        context = SharedInvestigationContext()
        stop = threading.Event()
        seen: list[int] = []
        failures: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    snapshot = context.snapshot()
                    observables = snapshot.observable_get_all()
                    # The report must describe the very facts just listed, not a later store.
                    assert all(snapshot.observable_result(key) is not None for key in observables)
                    seen.append(len(observables))
            except BaseException as error:  # noqa: BLE001 - reported on the main thread
                failures.append(error)

        watcher = threading.Thread(target=reader)
        watcher.start()
        try:
            for index in range(40):
                with context.task(fragment_id=f"w{index}") as worker:
                    worker.observable(worker.OBS.URL, f"hxxp://host{index}")
        finally:
            stop.set()
            watcher.join()

        assert not failures
        assert seen == sorted(seen)  # a snapshot never goes backwards
        assert len(context.snapshot().observable_get_all()) == 41  # the root plus 40 workers

    def test_async_tasks_reconcile_off_the_event_loop(self) -> None:
        context = SharedInvestigationContext()

        async def worker(index: int) -> None:
            async with context.atask(fragment_id=f"w{index}") as cv:
                cv.observable(cv.OBS.URL, f"hxxp://host{index}")

        async def run() -> Cyvest:
            await asyncio.gather(*(worker(index) for index in range(5)))
            return await context.asnapshot()

        snapshot = asyncio.run(run())
        assert len(snapshot.observable_get_all()) == 6  # the root plus five workers
