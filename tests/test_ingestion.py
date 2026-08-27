"""
Ingesting the same external response twice.

The property under test is the one that makes a distributed pipeline safe: re-ingesting an API
response must not double a signal, and nothing volatile in the raw body may influence identity.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from cyvest import Cyvest, ObservableIdentity, ObservableResolution, ObservableResolver, Policy
from cyvest.enums import SourceClass, Verdict, Weight
from cyvest.facts import Observable
from cyvest.schema.signal import SIGNAL_SCHEMA_VERSION


def _response(**overrides: object) -> dict[str, object]:
    payload = {
        "source": "virustotal",
        "verdict": "MALICIOUS",
        "weight": 6.0,
        "comment": "12/70 engines",
        "payload": {"requested_at": "2026-01-01T00:00:00Z", "quota_left": 4211},
    }
    payload.update(overrides)
    return payload


class TestContract:
    def test_a_verdict_alone_is_enough(self) -> None:
        draft = Cyvest.io_load_signal({"source": "misp", "verdict": "SAFE"})
        assert draft["verdict"] is Verdict.SAFE
        assert "weight" not in draft

    def test_a_weight_alone_is_enough_and_implies_the_verdict(self) -> None:
        draft = Cyvest.io_load_signal({"source": "vt", "weight": 6.0})
        assert draft["verdict"] is Verdict.MALICIOUS
        assert draft["weight"] == pytest.approx(6.0)

    def test_an_unknown_field_is_rejected_at_the_boundary(self) -> None:
        """A typo must fail loudly here rather than become a signal that quietly scores zero."""
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal({"source": "vt", "verdit": "MALICIOUS"})

    def test_a_nameless_source_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal({"source": "", "verdict": "MALICIOUS"})

    def test_a_confidence_outside_the_unit_range_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal({"source": "vt", "verdict": "MALICIOUS", "confidence": 1.5})

    def test_the_source_class_survives_ingestion(self) -> None:
        draft = Cyvest.io_load_signal(_response(source_class="internal_tool"))
        assert draft["source_class"] is SourceClass.INTERNAL_TOOL

    def test_an_envelope_from_an_earlier_patch_is_accepted(self) -> None:
        assert Cyvest.io_load_signal(_response(schema_version="7.0.0"))["source"] == "virustotal"

    def test_an_envelope_from_a_newer_minor_is_refused(self) -> None:
        """Accepting it would silently drop the fields that minor added."""
        with pytest.raises(ValidationError, match="newer than this library"):
            Cyvest.io_load_signal(_response(schema_version="7.1.0"))

    def test_an_envelope_from_another_major_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal(_response(schema_version="6.0.0"))


class TestIdempotence:
    def test_ingesting_the_same_response_twice_yields_one_signal(self) -> None:
        cv = Cyvest()
        url = cv.observable_create("url", "https://evil.test")
        url.with_ti(Cyvest.io_load_signal(_response()))
        url.with_ti(Cyvest.io_load_signal(_response()))

        assert len(cv._investigation.store.signals) == 1

    def test_a_volatile_field_in_the_payload_does_not_split_identity(self) -> None:
        cv = Cyvest()
        url = cv.observable_create("url", "https://evil.test")
        url.with_ti(Cyvest.io_load_signal(_response()))
        url.with_ti(
            Cyvest.io_load_signal(_response(payload={"requested_at": "2026-06-30T12:00:00Z", "quota_left": 17}))
        )

        assert len(cv._investigation.store.signals) == 1

    def test_an_external_id_is_how_you_keep_history_on_purpose(self) -> None:
        cv = Cyvest()
        url = cv.observable_create("url", "https://evil.test")
        url.with_ti(Cyvest.io_load_signal(_response(external_id="scan-march", weight=6.0)))
        url.with_ti(Cyvest.io_load_signal(_response(external_id="scan-june", weight=2.0)))

        assert len(cv._investigation.store.signals) == 2

    def test_a_reclassification_replaces_the_verdict_rather_than_stacking(self) -> None:
        """v6 took the max, so a score could never come back down; v7 lets the fresher one win."""
        cv = Cyvest()
        url = cv.observable_create("url", "https://evil.test")
        url.with_ti(Cyvest.io_load_signal(_response(weight=6.0)))
        url.with_ti(Cyvest.io_load_signal(_response(verdict="SAFE", weight=1.0)))

        assert len(cv._investigation.store.signals) == 1
        assert cv.get_report().observable(url.key).score == pytest.approx(-1.0)


class TestEmission:
    """
    The producing half of the contract.

    ``io_load_signal`` guards the door; ``io_dump_signal`` is what a connector calls on the other
    side of it, so whatever it emits must survive ``json.dumps`` and walk back in unchanged.
    """

    def test_an_emitted_envelope_is_json_serialisable(self) -> None:
        payload = Cyvest.io_dump_signal("virustotal", verdict="MALICIOUS", comment="12/70 engines")
        assert json.loads(json.dumps(payload)) == payload

    def test_an_emitted_envelope_states_the_contract_it_honours(self) -> None:
        """The two keys ``as_draft`` strips are exactly the two a payload in flight needs."""
        payload = Cyvest.io_dump_signal("virustotal", weight=6.0)
        assert payload["schema_version"] == SIGNAL_SCHEMA_VERSION
        assert payload["kind"] == "threat_intel"

    def test_an_emitted_envelope_validates_against_the_committed_contract(self) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        committed = json.loads(Path("schema/cyvest.signal.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(Cyvest.io_dump_signal("virustotal", weight=6.0, payload={"scan": 12}), committed)

    def test_emitting_then_ingesting_round_trips(self) -> None:
        cv = Cyvest()
        url = cv.observable_create("url", "https://evil.test")
        wire = json.dumps(Cyvest.io_dump_signal("virustotal", weight=6.0, comment="12/70 engines"))
        url.with_ti(Cyvest.io_load_signal(json.loads(wire)))

        assert len(cv._investigation.store.signals) == 1
        assert cv.get_report().observable(url.key).score == pytest.approx(6.0)

    def test_a_verdict_alone_leaves_with_the_weight_of_its_band(self) -> None:
        assert Cyvest.io_dump_signal("misp", verdict="SAFE")["weight"] == pytest.approx(Weight.LOW.value)

    def test_a_weight_alone_leaves_with_the_verdict_of_its_band(self) -> None:
        assert Cyvest.io_dump_signal("vt", weight=6.0)["verdict"] == Verdict.MALICIOUS.value

    def test_a_negative_weight_is_emitted_as_a_safe_magnitude(self) -> None:
        """Polarity belongs to the verdict, so the wire carries a magnitude, never a signed score."""
        payload = Cyvest.io_dump_signal("vt", weight=-2.0)
        assert (payload["verdict"], payload["weight"]) == (Verdict.SAFE.value, pytest.approx(2.0))

    def test_a_custom_policy_recalibrates_the_completed_weight(self) -> None:
        """The producer's bands travel with the payload — that is why they are an argument."""
        policy = Policy(weight_by_verdict={**Policy().weight_by_verdict, Verdict.MALICIOUS: 9.5})
        assert Cyvest.io_dump_signal("vt", verdict="MALICIOUS", policy=policy)["weight"] == pytest.approx(9.5)

    def test_a_producer_typo_is_rejected_before_the_wire(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_dump_signal("vt", verdit="MALICIOUS")

    def test_an_observation_time_is_emitted_as_an_iso_string(self) -> None:
        payload = Cyvest.io_dump_signal("vt", weight=6.0, observed_at=datetime(2026, 3, 1, 9, 12, tzinfo=timezone.utc))
        assert payload["observed_at"].startswith("2026-03-01T09:12:00")

    def test_taxonomies_are_emitted_as_a_list(self) -> None:
        payload = Cyvest.io_dump_signal("vt", weight=6.0, taxonomies=("malware-type:trojan",))
        assert payload["taxonomies"] == ["malware-type:trojan"]

    def test_an_absent_field_is_left_out_rather_than_sent_as_null(self) -> None:
        payload = Cyvest.io_dump_signal("vt", weight=6.0)
        assert "external_id" not in payload and "observed_at" not in payload


class TestAliasCounts:
    """
    An alias keeps its own tally.

    ``ObservableAlias.counts`` was never written, so ``count`` answered ``0`` where v6 answered at
    least ``1``, and the CRDT merge in ``FactStore._merge_aliases`` folded empty dicts forever.
    """

    @staticmethod
    def _lowercasing_email() -> ObservableResolver:
        return ObservableResolver(
            name="lowercase-email",
            source_types={("email", None)},
            resolve=lambda alias: ObservableResolution(
                identity=ObservableIdentity(type="email", value=alias.value.lower())
            ),
        )

    def _canonical(self, *spellings: str) -> Observable:
        cv = Cyvest()
        cv.observable_resolver_register(self._lowercasing_email())
        for spelling in spellings:
            cv.observable_create("email", spelling)
        return next(o for o in cv._investigation.store.observables.values() if str(o.obs_type) == "email")

    def test_an_alias_records_at_least_one_occurrence(self) -> None:
        observable = self._canonical("Alice@Example.com")
        assert [alias.count for alias in observable.aliases] == [1]

    def test_each_spelling_is_tallied_separately(self) -> None:
        observable = self._canonical("Alice@Example.com", "ALICE@example.com", "Alice@Example.com")
        counts = {alias.value: alias.count for alias in observable.aliases}
        assert counts == {"Alice@Example.com": 2, "ALICE@example.com": 1}

    def test_the_alias_tallies_add_up_to_the_observable_occurrences(self) -> None:
        observable = self._canonical("Alice@Example.com", "ALICE@example.com", "Alice@Example.com")
        assert sum(alias.count for alias in observable.aliases) == observable.occurrence_count

    def test_re_merging_a_fragment_does_not_inflate_the_tally(self) -> None:
        """Counters are per fragment and merged by max, so a union stays idempotent."""
        cv = Cyvest(investigation_id="inv-1")
        cv.observable_resolver_register(self._lowercasing_email())
        cv.observable_create("email", "Alice@Example.com")
        cv._investigation.merge_investigation(cv._investigation)
        observable = next(o for o in cv._investigation.store.observables.values() if str(o.obs_type) == "email")
        assert [alias.count for alias in observable.aliases] == [1]
