"""
Ingesting the same external response twice.

The property under test is the one that makes a distributed pipeline safe: re-ingesting an API
response must not double a signal, and nothing volatile in the raw body may influence identity.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from cyvest import Cyvest, ObservableIdentity, ObservableResolution, ObservableResolver, Policy, SignalEnvelope
from cyvest.enums import SourceClass, Verdict, Weight
from cyvest.facts import Observable
from cyvest.schema.signal import SIGNAL_SCHEMA_VERSION


def _response(**overrides: object) -> dict[str, object]:
    payload = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "kind": "threat_intel",
        "source": "virustotal",
        "verdict": "MALICIOUS",
        "weight": 6.0,
        "confidence": 1.0,
        "comment": "12/70 engines",
        "payload": {"requested_at": "2026-01-01T00:00:00Z", "quota_left": 4211},
    }
    payload.update(overrides)
    return payload


class TestContract:
    @pytest.mark.parametrize("judgment", [{}, {"verdict": "SAFE"}, {"weight": 6.0}])
    def test_partial_inputs_are_not_completed_on_ingestion(self, judgment) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal({"source": "vt", **judgment})

    def test_an_unknown_field_is_rejected_at_the_boundary(self) -> None:
        """A typo must fail loudly here rather than become a signal that quietly scores zero."""
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal(_response(verdit="MALICIOUS"))

    def test_a_nameless_source_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal(_response(source=""))

    def test_a_confidence_outside_the_unit_range_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal(_response(confidence=1.5))

    def test_the_source_class_survives_ingestion(self) -> None:
        draft = Cyvest.io_load_signal(_response(source_class="internal_tool"))
        assert draft["source_class"] is SourceClass.INTERNAL_TOOL

    def test_an_envelope_from_an_earlier_patch_is_accepted(self) -> None:
        assert Cyvest.io_load_signal(_response(schema_version="7.0.0"))["source"] == "virustotal"

    def test_an_envelope_from_a_newer_minor_is_refused(self) -> None:
        """Accepting it would silently drop the fields that minor added."""
        with pytest.raises(ValidationError, match="newer than this library"):
            Cyvest.io_load_signal(_response(schema_version="7.3.0"))

    def test_an_envelope_from_another_major_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_load_signal(_response(schema_version="6.0.0"))


def _read_signal_json(payload):
    return SignalEnvelope.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("reader", [SignalEnvelope.model_validate, _read_signal_json, Cyvest.io_load_signal])
class TestNativeContract:
    @pytest.mark.parametrize("version", ["7.0.0", "7.1.0", "7.2.0"])
    @pytest.mark.parametrize("field", ["schema_version", "kind", "source", "verdict", "weight", "confidence"])
    def test_missing_fields_are_rejected_for_every_readable_version(self, reader, version, field) -> None:
        payload = _response(schema_version=version)
        del payload[field]
        with pytest.raises(ValidationError) as exc:
            reader(payload)
        assert any(error["loc"] == (field,) and error["type"] == "missing" for error in exc.value.errors())

    @pytest.mark.parametrize("field", ["weight", "confidence"])
    @pytest.mark.parametrize("value", [None, True, False, "0.5", float("nan"), float("inf"), -float("inf")])
    def test_numbers_are_explicit_finite_and_not_coerced(self, reader, field, value) -> None:
        with pytest.raises(ValidationError) as exc:
            reader(_response(**{field: value}))
        assert any(error["loc"] == (field,) for error in exc.value.errors())

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("source", ""),
            ("source", " \t\n"),
            ("source", b"vt"),
            ("verdict", None),
            ("weight", -1),
            ("confidence", 0),
            ("confidence", -0.1),
            ("confidence", 1.1),
            ("kind", "finding"),
            ("unexpected", "value"),
        ],
    )
    def test_invalid_metadata_is_rejected(self, reader, field, value) -> None:
        if isinstance(value, bytes) and reader is _read_signal_json:
            pytest.skip("Bytes are not JSON values")
        with pytest.raises(ValidationError):
            reader(_response(**{field: value}))

    @pytest.mark.parametrize("version", ["7.0.0", "7.1.0", "7.2.0"])
    @pytest.mark.parametrize(
        ("verdict", "weight", "confidence"), [("SAFE", 3, 0.4), ("INFO", 0, 1), ("SUSPICIOUS", 2, 1)]
    )
    def test_explicit_judgment_and_opaque_payload_are_preserved(
        self, reader, version, verdict, weight, confidence
    ) -> None:
        payload = _response(
            schema_version=version,
            verdict=verdict,
            weight=weight,
            confidence=confidence,
            source=" vt ",
            payload={"arbitrary": {"raw": [None, True, 42]}, "weight": "not a judgment"},
        )
        original = deepcopy(payload)
        result = reader(payload)
        draft = result.as_draft() if isinstance(result, SignalEnvelope) else result
        assert draft["verdict"] is Verdict(verdict)
        assert draft["weight"] == weight
        assert draft["confidence"] == confidence
        assert draft["source"] == " vt "
        assert draft["payload"] == payload["payload"]
        assert payload == original

    def test_payload_is_not_a_gt_specific_contract(self, reader) -> None:
        payload = _response()
        del payload["payload"]
        result = reader(payload)
        draft = result.as_draft() if isinstance(result, SignalEnvelope) else result
        assert draft["payload"] == {}


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


class TestPublishedSignalSchema:
    @pytest.mark.parametrize("field", ["schema_version", "kind", "source", "verdict", "weight", "confidence"])
    def test_required_fields_are_published(self, field) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        schema = SignalEnvelope.model_json_schema()
        payload = _response()
        del payload[field]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(payload, schema)

    @pytest.mark.parametrize(
        ("field", "value"),
        [("source", " \t"), ("weight", -1), ("weight", True), ("weight", "6"), ("confidence", True), ("verdict", None)],
    )
    def test_constraints_are_published(self, field, value) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(_response(**{field: value}), SignalEnvelope.model_json_schema())


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
        """The producer's calibration travels with the payload — that is why it is an argument."""
        policy = Policy(default_weight_by_verdict={**Policy().default_weight_by_verdict, Verdict.MALICIOUS: 9.5})
        assert Cyvest.io_dump_signal("vt", verdict="MALICIOUS", policy=policy)["weight"] == pytest.approx(9.5)

    def test_a_producer_typo_is_rejected_before_the_wire(self) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_dump_signal("vt", verdit="MALICIOUS")

    @pytest.mark.parametrize("field", ["weight", "confidence"])
    @pytest.mark.parametrize("value", [True, False, "0.5", float("nan"), float("inf"), -float("inf")])
    def test_invalid_numbers_are_rejected_before_completion(self, field, value) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_dump_signal("vt", **{field: value})

    @pytest.mark.parametrize("source", ["", " \t\n", b"vt"])
    def test_invalid_sources_are_rejected(self, source) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_dump_signal(source, weight=6.0)

    @pytest.mark.parametrize("verdict", ["SAFE", "MALICIOUS"])
    def test_a_signed_weight_with_an_explicit_verdict_is_rejected(self, verdict) -> None:
        with pytest.raises(ValidationError):
            Cyvest.io_dump_signal("vt", verdict=verdict, weight=-2.0)

    def test_explicit_judgment_is_not_recalibrated(self) -> None:
        payload = Cyvest.io_dump_signal("vt", verdict="SUSPICIOUS", weight=2, confidence=0.4)
        signal = SignalEnvelope.model_validate(payload)
        assert (signal.verdict, signal.weight, signal.confidence) == (Verdict.SUSPICIOUS, 2, 0.4)

    def test_no_judgment_is_completed_only_by_the_producer_helper(self) -> None:
        signal = SignalEnvelope.model_validate(Cyvest.io_dump_signal("vt"))
        assert (signal.verdict, signal.weight, signal.confidence) == (Verdict.INFO, 0.0, 1.0)

    def test_an_observation_time_is_emitted_as_an_iso_string(self) -> None:
        payload = Cyvest.io_dump_signal("vt", weight=6.0, observed_at=datetime(2026, 3, 1, 9, 12, tzinfo=timezone.utc))
        assert payload["observed_at"].startswith("2026-03-01T09:12:00")

    def test_legacy_text_taxonomies_are_emitted_as_structured_entries(self) -> None:
        payload = Cyvest.io_dump_signal("vt", weight=6.0, taxonomies=("malware-type:trojan",))
        assert payload["taxonomies"] == [{"name": "malware-type:trojan", "value": "", "verdict": "INFO"}]

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
