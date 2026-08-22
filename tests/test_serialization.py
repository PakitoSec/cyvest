"""The serialized boundary: round-trip, upward compatibility, and parity with v6 numbers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyvest import Cyvest, Verdict
from cyvest.io_serialization import (
    SCHEMA_VERSION,
    detect_schema_version,
    investigation_to_dict,
    load_investigation_dict,
    migrate_to_current,
)


def build_case() -> Cyvest:
    cv = Cyvest(root_data={"case": "IR-1"}, investigation_name="IR-1", investigation_id="inv-1")
    url = cv.observable(cv.OBS.URL, "hxxp://bad.example/x")
    ip = cv.observable(cv.OBS.IPV4, "203.0.113.50")
    cv.observable_add_threat_intel(url, "virustotal", verdict=cv.VERDICT.MALICIOUS, weight=6.0)
    cv.observable_add_relation(ip, url, cv.REL.EXTRACTION)
    cv.finding("url_in_body", "URL in body", subject=url).link_observable(url, cv.SCOPE.ALL)
    cv.tag_create("phishing")
    cv.evidence_create("enrichment", title="whois", content={"registrar": "x"})
    cv.decision_create(ip, cv.DECISION.ALLOWLISTED, justification="infra interne", decided_by="alice")
    return cv


class TestRoundTrip:
    def test_save_load_save_is_idempotent(self) -> None:
        first = investigation_to_dict(build_case()._investigation)
        reloaded = load_investigation_dict(first)
        second = investigation_to_dict(reloaded)
        assert first == second

    def test_the_report_is_always_present(self) -> None:
        document = investigation_to_dict(build_case()._investigation)
        assert "report" in document
        assert document["report"]["engine_id"] == "basic-v1"

    def test_facts_stay_maps_keyed_by_their_semantic_key(self) -> None:
        """7.2 will add ``facts.history``; turning these maps into lists would break every document."""
        facts = investigation_to_dict(build_case()._investigation)["facts"]
        for name in ("observables", "relations", "signals", "evidences", "findings"):
            assert isinstance(facts[name], dict)
        assert facts["events"] == {}

    def test_signals_carry_their_discriminator(self) -> None:
        signals = investigation_to_dict(build_case()._investigation)["facts"]["signals"]
        assert all(signal["kind"] == "threat_intel" for signal in signals.values())

    def test_scores_survive_the_json_boundary(self) -> None:
        original = build_case()
        document = json.loads(json.dumps(investigation_to_dict(original._investigation)))
        reloaded = load_investigation_dict(document)
        assert reloaded.get_global_score() == original.get_global_score()
        assert reloaded.get_global_verdict() is original.get_global_verdict()

    def test_a_conclusion_survives_the_json_boundary(self) -> None:
        original = build_case()
        original.conclusion("ai_review", "Analyse IA", verdict=Verdict.MALICIOUS)
        document = json.loads(json.dumps(investigation_to_dict(original._investigation)))

        reloaded = load_investigation_dict(document)
        assert reloaded.get_global_score() == original.get_global_score() == 6.0
        assert all(f["effect"] in ("ADDITIVE", "FLOOR") for f in document["facts"]["findings"].values())

    def test_a_document_without_effect_reads_back_as_additive(self) -> None:
        """Every v6 document is in that case: the field is additive by construction."""
        document = investigation_to_dict(build_case()._investigation)
        for finding in document["facts"]["findings"].values():
            del finding["effect"]

        reloaded = load_investigation_dict(document)
        assert all(f.effect.value == "ADDITIVE" for f in reloaded.store.findings.values())


class TestUpwardCompatibility:
    def test_a_current_document_loads(self) -> None:
        assert load_investigation_dict(investigation_to_dict(build_case()._investigation)) is not None

    def test_a_newer_document_is_refused(self) -> None:
        document = investigation_to_dict(build_case()._investigation)
        document["schema_version"] = "7.1.0"
        with pytest.raises(ValueError, match="upgrade cyvest"):
            load_investigation_dict(document, migrate=True)

    def test_an_older_document_needs_an_explicit_migration(self) -> None:
        with pytest.raises(ValueError, match="migrate"):
            load_investigation_dict({"schema_version": "6.0.0", "observables": {}})

    def test_version_detection_treats_anything_unversioned_as_v5(self) -> None:
        assert detect_schema_version({}) == "5"
        assert detect_schema_version({"schema_version": "6.0.0"}) == "6.0.0"
        assert detect_schema_version({"schema_version": SCHEMA_VERSION}) == SCHEMA_VERSION


V6_DOCUMENT = {
    "schema_version": "6.0.0",
    "investigation_id": "inv-v6",
    "investigation_name": "legacy",
    "observables": {
        "obs:file:root": {"type": "file", "value": "root", "score": 0.0, "level": "INFO", "internal": False},
        "obs:url:hxxp://bad.example": {
            "type": "url",
            "value": "hxxp://bad.example",
            "score": 6.0,
            "level": "MALICIOUS",
            "internal": False,
        },
        "obs:ipv4:203.0.113.50": {
            "type": "ipv4",
            "value": "203.0.113.50",
            "score": 0.0,
            "level": "INFO",
            "internal": False,
            "whitelisted": True,
        },
    },
    "threat_intels": {
        "ti:virustotal:obs:url:hxxp://bad.example": {
            "source": "virustotal",
            "observable_key": "obs:url:hxxp://bad.example",
            "score": 6.0,
            "level": "MALICIOUS",
        }
    },
    "findings": {
        "fnd:url_in_body": {
            "finding_name": "url_in_body",
            "description": "URL in body",
            "score": 6.0,
            "level": "MALICIOUS",
            "observable_links": [
                {"observable_key": "obs:url:hxxp://bad.example", "propagation_mode": "GLOBAL"},
            ],
        }
    },
    "tags": {},
    "enrichments": {},
    "evidences": {},
}


class TestMigrationV6:
    def _migrated(self, document: dict | None = None) -> Cyvest:
        migrated = migrate_to_current(document or json.loads(json.dumps(V6_DOCUMENT)))
        facade = Cyvest.__new__(Cyvest)
        facade._investigation = load_investigation_dict(migrated)
        facade._observable_resolvers = []
        return facade

    def test_numbers_are_preserved_exactly(self) -> None:
        """The parity net: basic-v1 on migrated data reproduces the v6 figures."""
        migrated = self._migrated()
        assert migrated.observable_get("obs:url:hxxp://bad.example").score == 6.0
        assert migrated.get_global_score() == 6.0
        assert migrated.get_global_verdict() is Verdict.MALICIOUS

    def test_threat_intel_keys_are_unchanged(self) -> None:
        migrated = self._migrated()
        assert "ti:virustotal:obs:url:hxxp://bad.example" in migrated._investigation.store.signals

    def test_a_negative_score_keeps_its_sign(self) -> None:
        """Migrating from the level would flip this to +2; the score is authoritative."""
        document = json.loads(json.dumps(V6_DOCUMENT))
        document["threat_intels"]["ti:virustotal:obs:url:hxxp://bad.example"].update(
            {"score": -2.0, "level": "TRUSTED"}
        )
        document["findings"]["fnd:url_in_body"].update({"score": -2.0, "level": "TRUSTED"})

        migrated = self._migrated(document)
        assert migrated.observable_get("obs:url:hxxp://bad.example").score == -2.0

    def test_a_level_contradicting_its_score_does_not_win(self) -> None:
        """v6 keeps an explicit level whatever the score; only the score ever propagated."""
        document = json.loads(json.dumps(V6_DOCUMENT))
        document["threat_intels"]["ti:virustotal:obs:url:hxxp://bad.example"].update({"score": 3.0, "level": "SAFE"})

        migrated = self._migrated(document)
        assert migrated.observable_get("obs:url:hxxp://bad.example").score == 3.0

    def test_propagation_mode_maps_one_to_one(self) -> None:
        migrated = self._migrated()
        finding = next(iter(migrated.finding_get_all().values()))
        assert finding.observable_links[0].scope.value == "ALL"

    def test_whitelisted_becomes_an_operative_decision(self) -> None:
        """Documented parity exception: v6 ignored the flag when scoring, v7 applies it."""
        migrated = self._migrated()
        ip = migrated.observable_get("obs:ipv4:203.0.113.50")
        assert ip.allowlisted is True
        assert ip.verdict is Verdict.SAFE

    def test_the_root_is_recognized_through_the_header(self) -> None:
        migrated = self._migrated()
        assert migrated._investigation.store.header.root_key == "obs:file:root"


class TestRelationDirection:
    def _relation(self, direction: str, relationship_type: str):
        document = json.loads(json.dumps(V6_DOCUMENT))
        # Drop the allowlist here: it would clamp the score and hide what this test measures.
        document["observables"]["obs:ipv4:203.0.113.50"].pop("whitelisted", None)
        document["observables"]["obs:ipv4:203.0.113.50"]["relationships"] = [
            {
                "target_key": "obs:url:hxxp://bad.example",
                "relationship_type": relationship_type,
                "direction": direction,
            }
        ]
        investigation = load_investigation_dict(migrate_to_current(document))
        return next(iter(investigation.store.relations.values())), investigation

    def test_outbound_keeps_the_type_and_the_order(self) -> None:
        relation, _ = self._relation("outbound", "extraction")
        assert relation.source_key == "obs:ipv4:203.0.113.50"
        assert relation.kind.value == "extraction"

    def test_inbound_swaps_the_keys(self) -> None:
        relation, _ = self._relation("inbound", "extraction")
        assert relation.source_key == "obs:url:hxxp://bad.example"
        assert relation.target_key == "obs:ipv4:203.0.113.50"

    def test_bidirectional_extraction_still_propagates_nothing(self) -> None:
        """The trap: reading the type first would make this propagate, silently breaking parity."""
        relation, investigation = self._relation("bidirectional", "extraction")
        assert relation.kind.value == "related-to"
        assert investigation.report.observable("obs:ipv4:203.0.113.50").score == 0.0


class TestMigrationChain:
    def test_a_v5_document_reaches_v7_in_one_call(self) -> None:
        v5 = {
            "investigation_id": "inv-v5",
            "observables": {"obs:url:hxxp://old.example": {"type": "url", "value": "hxxp://old.example", "score": 4.0}},
            "findings": {},
            "threat_intels": {},
            "stats": {"anything": 1},
        }
        migrated = migrate_to_current(v5)
        assert migrated["schema_version"] == SCHEMA_VERSION
        assert load_investigation_dict(migrated) is not None


class TestCommittedSchema:
    def test_the_committed_schema_matches_the_models(self) -> None:
        """Without this check, the Python models and the generated TS types drift in silence."""
        from cyvest.io_schema import get_investigation_schema

        committed = json.loads(Path("schema/cyvest.schema.json").read_text(encoding="utf-8"))
        assert committed == get_investigation_schema(), "run scripts/generate.sh — schema is stale"

    def test_a_produced_document_validates_against_the_committed_schema(self) -> None:
        """
        The schema being fresh is not enough: the *document* must satisfy it.

        This caught a dump emitting ``obs_type`` where the schema declares ``type`` — a drift only
        a JS consumer would otherwise have hit.
        """
        jsonschema = pytest.importorskip("jsonschema")
        committed = json.loads(Path("schema/cyvest.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(investigation_to_dict(build_case()._investigation), committed)

    def test_the_schema_id_is_versioned(self) -> None:
        from cyvest.io_schema import get_investigation_schema

        assert get_investigation_schema()["$id"].endswith("investigation-7.json")

    def test_the_report_is_a_required_key(self) -> None:
        from cyvest.io_schema import get_investigation_schema

        assert "report" in get_investigation_schema()["required"]

    def test_the_committed_signal_contract_matches_the_model(self) -> None:
        """Producers validate against the committed file, so a silent drift breaks them, not us."""
        from cyvest.io_schema import get_signal_schema

        committed = json.loads(Path("schema/cyvest.signal.schema.json").read_text(encoding="utf-8"))
        assert committed == get_signal_schema(), "run scripts/generate.sh — signal schema is stale"

    def test_a_signal_payload_validates_against_the_committed_contract(self) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        committed = json.loads(Path("schema/cyvest.signal.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(
            {"source": "virustotal", "verdict": "MALICIOUS", "weight": 6.0, "payload": {"scan": 12}},
            committed,
        )
