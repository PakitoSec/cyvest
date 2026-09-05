"""
One law of merging, checked at every level it is exposed: store, investigation, shared context,
serialized document. Commutative, associative, idempotent — header included — and refusing what
is not one case.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyvest import (
    Cyvest,
    EngineMismatchError,
    MergeReport,
    PolicyMismatchError,
    RootMismatchError,
    merge_documents,
)
from cyvest.facts.store import InvestigationHeader
from cyvest.shared import SharedInvestigationContext

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _header(investigation_id: str, *, opened_at: datetime = T0, name: str = "", **fields) -> InvestigationHeader:
    return InvestigationHeader(
        investigation_id=investigation_id,
        name=name,
        root_key="obs:file:__cyvest_root__",
        opened_at=opened_at,
        fragment_ids=(investigation_id,),
        **fields,
    )


def _case(investigation_id: str, *, name: str = "", opened_at: datetime | None = None) -> Cyvest:
    cv = Cyvest(investigation_id=investigation_id, investigation_name=name)
    if opened_at is not None:
        cv._investigation.store.header = cv._investigation.store.header.model_copy(update={"opened_at": opened_at})
    cv.observable(cv.OBS.DOMAIN, f"{investigation_id}.example").with_ti("vt", 4.0)
    cv.finding(f"rule-{investigation_id}", verdict="SUSPICIOUS").link_observable(
        f"obs:domain:{investigation_id}.example"
    )
    return cv


def _facts(cv: Cyvest) -> set[str]:
    return {fact.key for fact in cv._investigation.store.all_facts()} - {cv.root().key}


class TestHeaderLaw:
    def test_the_investigation_opened_first_gives_its_identity_and_name(self) -> None:
        older = _header("old", opened_at=T0, name="Old")
        newer = _header("new", opened_at=T0 + timedelta(hours=1), name="New")
        merged = older.merge(newer)
        assert merged == newer.merge(older)
        assert (merged.investigation_id, merged.name, merged.opened_at) == ("old", "Old", T0)
        assert merged.fragment_ids == ("new", "old")

    def test_an_empty_name_is_filled_from_the_other_side(self) -> None:
        assert _header("a", name="").merge(_header("b", name="B")).name == "B"

    def test_a_tie_on_opening_time_is_broken_on_the_id(self) -> None:
        assert _header("b").merge(_header("a")).investigation_id == "a"

    def test_associative_on_the_header_too(self) -> None:
        a = _header("a", opened_at=T0 + timedelta(hours=2))
        b = _header("b")
        c = _header("c", opened_at=T0 + timedelta(hours=1))
        assert a.merge(b).merge(c) == a.merge(b.merge(c)) == c.merge(a).merge(b)

    def test_two_engines_are_refused(self) -> None:
        with pytest.raises(EngineMismatchError, match="not on the same scale"):
            _header("a").merge(_header("b", engine_id="bayesian-v1"))

    def test_two_policies_are_refused(self) -> None:
        with pytest.raises(PolicyMismatchError):
            _header("a").merge(_header("b", policy_version="custom-v1"))

    def test_two_roots_are_refused(self) -> None:
        other = _header("b").model_copy(update={"root_key": "obs:artifact:__cyvest_root__"})
        with pytest.raises(RootMismatchError):
            _header("a").merge(other)


class TestStoreLaw:
    def test_union_is_commutative_header_included(self) -> None:
        a, b = _case("a", name="A"), _case("b", opened_at=T0 - timedelta(days=1))
        ab = a._investigation.store.union(b._investigation.store)
        ba = b._investigation.store.union(a._investigation.store)
        assert ab.header == ba.header
        assert ab.header.investigation_id == "b" and ab.header.name == "A"
        assert {f.key: f for f in ab.all_facts()} == {f.key: f for f in ba.all_facts()}

    def test_the_report_is_told_from_the_receiver_side_and_ignores_the_root(self) -> None:
        a, b = _case("a"), _case("b")
        a_store, b_store = a._investigation.store, b._investigation.store
        report = a_store.report_merge(b_store, a_store.union(b_store))
        assert isinstance(report, MergeReport)
        assert set(report.added) == _facts(b)
        assert report.kept == () and report.superseded == ()
        assert report.fragments == ("b",) and report.changed


class TestInvestigationLaw:
    def test_merge_reports_what_changed_and_is_idempotent(self) -> None:
        a, b = _case("a"), _case("b")
        first = a.merge_investigation(b)
        assert set(first.added) == _facts(b) and first.changed
        second = a.merge_investigation(b)
        assert second.added == () and second.superseded == () and not second.changed
        assert set(second.kept) == _facts(b)

    def test_the_fresher_assertion_supersedes_and_is_reported(self) -> None:
        a, b = _case("a"), Cyvest(investigation_id="b")
        b.finding("rule-a", verdict="MALICIOUS")
        report = a.merge_investigation(b)
        assert report.superseded == ("fnd:rule-a",)
        assert a.finding_get("fnd:rule-a").verdict is a.VERDICT.MALICIOUS

    def test_the_receiver_may_take_the_older_identity_but_keeps_its_fragment(self) -> None:
        a, b = _case("a"), _case("b", opened_at=T0 - timedelta(days=1))
        a.merge_investigation(b)
        assert a.investigation_id == "b"
        a.observable(a.OBS.IPV4, "203.0.113.5")
        assert a._investigation.get_observable("obs:ipv4:203.0.113.5").fragment_id == "a"

    def test_engine_mismatch_is_refused_unless_reevaluation_is_asked(self) -> None:
        a, b = _case("a"), _case("b")
        b._investigation.store.header = b._investigation.store.header.model_copy(update={"engine_id": "other-v1"})
        with pytest.raises(EngineMismatchError):
            a.merge_investigation(b)
        report = a.merge_investigation(b, on_engine_mismatch="reevaluate")
        assert report.changed
        assert a.get_report().engine_id == "basic-v1"
        assert a.io_to_dict()["engine_id"] == "basic-v1"

    def test_two_roots_do_not_merge(self) -> None:
        with pytest.raises(RootMismatchError):
            Cyvest(root_type="file").merge_investigation(Cyvest(root_type="artifact"))


class TestSharedContextLaw:
    def test_reconcile_uses_the_same_header_law(self) -> None:
        context = SharedInvestigationContext(investigation_id="main", investigation_name="Main")
        with context.task(fragment_id="w1") as worker:
            worker.observable(worker.OBS.DOMAIN, "w1.example")
        with context.task(fragment_id="w2") as worker:
            worker.observable(worker.OBS.DOMAIN, "w2.example")
        header = context.snapshot()._investigation.store.header
        assert header.investigation_id == "main" and header.name == "Main"
        assert header.fragment_ids == ("main", "w1", "w2")

    def test_reconcile_refuses_another_engine(self) -> None:
        context = SharedInvestigationContext(investigation_id="main")
        stranger = Cyvest(investigation_id="x")
        stranger._investigation.store.header = stranger._investigation.store.header.model_copy(
            update={"engine_id": "other-v1"}
        )
        with pytest.raises(EngineMismatchError):
            context.reconcile(stranger)


class TestDocumentLaw:
    @staticmethod
    def _branch(base: dict, rule_id: str, verdict: str = "SUSPICIOUS") -> dict:
        cv = Cyvest.io_load_dict(base)
        cv.finding(rule_id, rule_id, verdict=verdict).link_observable("obs:domain:base.example")
        return cv.io_to_dict()

    def test_none_and_empty_are_identities(self) -> None:
        base = _case("base").io_to_dict()
        assert merge_documents(None, None) is None
        assert merge_documents({}, None) is None
        assert merge_documents(None, base) is base
        assert merge_documents(base, {}) is base

    def test_identical_and_subsuming_documents_skip_the_load(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cyvest.io.serialization as serialization

        base = _case("base").io_to_dict()
        grown = self._branch(base, "a")
        monkeypatch.setattr(serialization, "load_investigation_dict", lambda *a, **k: pytest.fail("loaded"))
        assert merge_documents(base, base) is base
        assert merge_documents(base, dict(base)) is base
        assert merge_documents(base, grown) is grown
        assert merge_documents(grown, base) is grown

    def test_divergent_branches_obey_the_laws(self) -> None:
        base = _case("base").io_to_dict()
        a, b, c = self._branch(base, "a"), self._branch(base, "b"), self._branch(base, "c")
        ab = merge_documents(a, b)
        assert set(ab["facts"]["findings"]) >= {"fnd:a", "fnd:b"}
        assert ab == merge_documents(b, a)
        assert merge_documents(ab, a) == ab
        assert merge_documents(merge_documents(a, b), c) == merge_documents(a, merge_documents(b, c))
        assert ab["report"]["investigation"]["score"] == Cyvest.io_load_dict(ab).get_global_score()

    def test_the_freshest_assertion_wins_either_way(self) -> None:
        base = self._branch(_case("base").io_to_dict(), "a", verdict="INFO")
        revised = self._branch(base, "a", verdict="MALICIOUS")
        merged = merge_documents(base, revised)
        assert merged["facts"]["findings"]["fnd:a"]["verdict"] == "MALICIOUS"
        assert merge_documents(revised, base) == merged

    def test_two_investigations_keep_the_older_identity_whatever_the_order(self) -> None:
        first = _case("first", name="First", opened_at=T0).io_to_dict()
        second = _case("second", name="Second", opened_at=T0 + timedelta(hours=1)).io_to_dict()
        merged = merge_documents(second, first)
        assert merged == merge_documents(first, second)
        assert merged["header"]["investigation_id"] == "first" and merged["header"]["name"] == "First"
        assert merged["header"]["fragment_ids"] == ["first", "second"]
