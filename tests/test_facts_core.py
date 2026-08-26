"""Identity and merge laws: one key table, one merge law, verified as laws rather than cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyvest import keys
from cyvest.enums import DecisionKind, RelationKind, SourceClass, Verdict
from cyvest.facts import Decision, Finding, Observable, Relation, SourceRef, Tag, ThreatIntel
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.ulid import decode_ulid_timestamp, generate_ulid

SRC = SourceRef(name="virustotal", source_class=SourceClass.VENDOR_FEED)


def store(fragment_id: str = "f1") -> FactStore:
    return FactStore(InvestigationHeader(investigation_id="inv", fragment_ids=(fragment_id,)))


def observable(fragment_id: str = "f1", value: str = "1.2.3.4") -> Observable:
    return Observable(type="ipv4", value=value, source=SRC, fragment_id=fragment_id)


class TestKeyTable:
    def test_observable_identity_is_the_quadruplet(self) -> None:
        a = Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="a")
        b = Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="b")
        assert a.key == b.key

    def test_signal_key_is_byte_identical_to_v6(self) -> None:
        obs = observable()
        signal = ThreatIntel(subject_key=obs.key, source=SRC, fragment_id="f1")
        assert signal.key == f"ti:virustotal:{obs.key}"

    def test_external_id_is_an_opt_in_discriminant(self) -> None:
        obs = observable()
        default = ThreatIntel(subject_key=obs.key, source=SRC, fragment_id="f1")
        historical = ThreatIntel(subject_key=obs.key, source=SRC, fragment_id="f1", external_id="2024-05-01")
        assert default.key != historical.key

    def test_finding_identity_includes_its_subject(self) -> None:
        """v6 keyed on the name alone, which is why it needed origin_investigation_id."""
        first = Finding(rule_id="r", subject_key="obs:url:a", source=SRC, fragment_id="f1")
        second = Finding(rule_id="r", subject_key="obs:url:b", source=SRC, fragment_id="f1")
        assert first.key != second.key

    def test_relation_key_carries_direction(self) -> None:
        forward = Relation(
            source_key="obs:url:a", target_key="obs:url:b", kind=RelationKind.EXTRACTION, source=SRC, fragment_id="f1"
        )
        backward = Relation(
            source_key="obs:url:b", target_key="obs:url:a", kind=RelationKind.EXTRACTION, source=SRC, fragment_id="f1"
        )
        assert forward.key != backward.key

    def test_decision_identity_is_its_target_alone(self) -> None:
        """
        The kind is content, not identity: one target holds one stance.

        Keying on the kind too let ``UPHOLD`` and ``REFUTE`` coexist on the same target and made
        the engine arbitrate what the merge law already settles.
        """
        first = Decision(
            target_key="obs:url:a", kind=DecisionKind.REFUTE, justification="a", source=SRC, fragment_id="f1"
        )
        second = Decision(
            target_key="obs:url:a", kind=DecisionKind.UPHOLD, justification="b", source=SRC, fragment_id="f2"
        )
        assert first.key == second.key == "dec:obs:url:a"

    def test_no_raw_content_enters_a_key(self) -> None:
        """A volatile payload field must not change identity."""
        obs = observable()
        quiet = ThreatIntel(subject_key=obs.key, source=SRC, fragment_id="f1", payload={"quota": 10})
        noisy = ThreatIntel(subject_key=obs.key, source=SRC, fragment_id="f1", payload={"quota": 9})
        assert quiet.key == noisy.key


class TestEnvelope:
    def test_seq_is_generated_from_asserted_at(self) -> None:
        moment = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        fact = observable()
        aligned = Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="f1", asserted_at=moment)
        assert abs(decode_ulid_timestamp(aligned.seq) - int(moment.timestamp() * 1000)) < 1000
        assert fact.seq != aligned.seq

    def test_inconsistent_seq_is_rejected(self) -> None:
        moment = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        stale_seq = generate_ulid(timestamp_ms=int((moment - timedelta(days=30)).timestamp() * 1000))
        with pytest.raises(ValueError, match="disagrees with asserted_at"):
            Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="f1", asserted_at=moment, seq=stale_seq)


class TestMergeLaws:
    @staticmethod
    def _signal(fragment_id: str, weight: float, observed_at: datetime) -> ThreatIntel:
        return ThreatIntel(
            subject_key=observable().key,
            verdict=Verdict.MALICIOUS,
            weight=weight,
            observed_at=observed_at,
            source=SRC,
            fragment_id=fragment_id,
        )

    def _stores(self) -> tuple[FactStore, FactStore]:
        left, right = store("a"), store("b")
        left.append(observable("a"))
        right.append(observable("b", value="5.6.7.8"))
        left.append(Tag(name="phishing", finding_keys=("fnd:x:obs:url:a",), source=SRC, fragment_id="a"))
        right.append(Tag(name="phishing", finding_keys=("fnd:y:obs:url:b",), source=SRC, fragment_id="b"))
        return left, right

    def test_idempotent(self) -> None:
        left, right = self._stores()
        once = left.union(right)
        twice = left.union(left.union(right))
        assert sorted(f.key for f in once.all_facts()) == sorted(f.key for f in twice.all_facts())

    def test_commutative(self) -> None:
        left, right = self._stores()
        assert sorted(f.key for f in left.union(right).all_facts()) == sorted(
            f.key for f in right.union(left).all_facts()
        )

    def test_associative(self) -> None:
        left, right = self._stores()
        third = store("c")
        third.append(observable("c", value="9.9.9.9"))
        assert sorted(f.key for f in left.union(right).union(third).all_facts()) == sorted(
            f.key for f in left.union(right.union(third)).all_facts()
        )

    def test_re_asserting_a_fact_creates_no_duplicate(self) -> None:
        target = store()
        obs = observable()
        target.append(obs)
        target.append(obs)
        assert len(target.observables) == 1

    def test_freshest_observation_wins_not_the_largest(self) -> None:
        """v6 took the max, so a score could never come back down. v7 lets it."""
        target = store()
        old = self._signal("f1", weight=9.0, observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        fresh = self._signal("f1", weight=1.0, observed_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
        target.append(old)
        target.append(fresh)
        assert target.signals[fresh.key].weight == 1.0

    def test_a_late_worker_asserting_stale_data_does_not_win(self) -> None:
        target = store()
        fresh = self._signal("f1", weight=1.0, observed_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
        target.append(fresh)
        stale_but_late = ThreatIntel(
            subject_key=observable().key,
            verdict=Verdict.MALICIOUS,
            weight=9.0,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            asserted_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
            source=SRC,
            fragment_id="f1",
        )
        target.append(stale_but_late)
        assert target.signals[fresh.key].weight == 1.0

    def test_tag_finding_keys_union_instead_of_overwriting(self) -> None:
        left, right = self._stores()
        merged = left.union(right)
        tag = merged.tags[keys.generate_tag_key("phishing")]
        assert set(tag.finding_keys) == {"fnd:x:obs:url:a", "fnd:y:obs:url:b"}

    def test_observable_occurrences_merge_as_counters(self) -> None:
        left, right = store("a"), store("b")
        left.append(Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="a", occurrences={"a": 2}))
        right.append(Observable(type="ipv4", value="1.2.3.4", source=SRC, fragment_id="b", occurrences={"b": 3}))
        merged = left.union(right)
        assert merged.observables[observable().key].occurrence_count == 5
