"""The serialized boundary: round-trip, upward compatibility, and parity with v6 numbers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyvest import Cyvest, Verdict
from cyvest.io.serialization import (
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
    cv.finding("url_in_body", "URL in body").link_observable(url, cv.BASIS.OBSERVABLE)
    cv.tag_create("phishing")
    cv.evidence_create("enrichment", title="whois", content={"registrar": "x"})
    cv.decision_create(ip, cv.DECISION.REFUTE, "internal infra", decided_by="alice")
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
        assert set(facts) == {"observables", "relations", "signals", "evidences", "findings"}
        assert all(isinstance(collection, dict) for collection in facts.values())

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
        original.conclusion("ai_review", "AI review", verdict=Verdict.MALICIOUS)
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

    def test_a_patch_release_of_the_same_minor_loads_untouched(self) -> None:
        document = investigation_to_dict(build_case()._investigation)
        document["schema_version"] = "7.0.99"
        assert load_investigation_dict(document) is not None

    def test_a_later_minor_library_reads_an_earlier_minor_document(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The invariant a 7.1 release must honour: no migration, no opt-in flag, just a read."""
        import cyvest.io.serialization as serialization

        monkeypatch.setattr(serialization, "SCHEMA_VERSION", "7.1.0")
        document = investigation_to_dict(build_case()._investigation)
        assert document["schema_version"] == "7.0.0"
        assert serialization.load_investigation_dict(document) is not None

    def test_an_older_document_needs_an_explicit_migration(self) -> None:
        with pytest.raises(ValueError, match="migrate"):
            load_investigation_dict({"schema_version": "6.0.0", "observables": {}})

    def test_version_detection_treats_anything_unversioned_as_v5(self) -> None:
        assert detect_schema_version({}) == "5"
        assert detect_schema_version({"schema_version": "6.0.0"}) == "6.0.0"
        assert detect_schema_version({"schema_version": SCHEMA_VERSION}) == SCHEMA_VERSION

    def test_a_document_from_another_major_is_never_mistaken_for_a_readable_one(self) -> None:
        document = investigation_to_dict(build_case()._investigation)
        document["schema_version"] = "8.0.0"
        with pytest.raises(ValueError, match="upgrade cyvest"):
            load_investigation_dict(document)


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

    def test_threat_intel_keys_are_rebuilt_under_the_signal_prefix(self) -> None:
        migrated = self._migrated()
        assert "sig:virustotal:obs:url:hxxp://bad.example" in migrated._investigation.store.signals

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
        assert finding.observable_links[0].basis.value == "OBSERVABLE"

    def test_whitelisted_becomes_an_operative_decision(self) -> None:
        """Documented parity exception: v6 ignored the flag when scoring, v7 applies it."""
        migrated = self._migrated()
        ip = migrated.observable_get("obs:ipv4:203.0.113.50")
        assert ip.allowlisted is True
        assert ip.verdict is Verdict.SAFE

    def test_the_root_is_recognized_through_the_header(self) -> None:
        migrated = self._migrated()
        assert migrated._investigation.store.header.root_key == "obs:file:root"

    def test_every_migrated_fact_gets_its_own_seq(self) -> None:
        """One shared ULID would leave every migrated fact tied with every other on merge."""
        facts = list(self._migrated()._investigation.store.all_facts())
        assert len({fact.seq for fact in facts}) == len(facts)


class TestMigrationFragments:
    """
    ``origin_investigation_id`` decides what an imported link scores on.

    v6 gated a ``LOCAL_ONLY`` link on ``origin_investigation_id == investigation_id``, so an
    imported one was simply inert; v7 states that as ``LinkBasis.NONE``, resolved once at import.
    Reading it as a live link would make links that scored nothing in v6 start propagating and
    quietly inflate the score of any merged investigation.
    """

    def _document(self, origin: str, propagation: str = "LOCAL_ONLY") -> dict:
        document = json.loads(json.dumps(V6_DOCUMENT))
        document["findings"]["fnd:url_in_body"].update(
            {
                "origin_investigation_id": origin,
                "score": 2.0,
                "level": "NOTABLE",
                "observable_links": [{"observable_key": "obs:url:hxxp://bad.example", "propagation_mode": propagation}],
            }
        )
        return document

    def _migrated(self, document: dict) -> Cyvest:
        facade = Cyvest.__new__(Cyvest)
        facade._investigation = load_investigation_dict(migrate_to_current(document))
        facade._observable_resolvers = []
        return facade

    def test_a_finding_keeps_the_fragment_it_came_from(self) -> None:
        store = self._migrated(self._document("fragment-proofpoint"))._investigation.store
        finding = next(iter(store.findings.values()))
        assert finding.fragment_id == "fragment-proofpoint"
        assert "fragment-proofpoint" in store.header.fragment_ids

    def test_an_imported_local_link_does_not_start_propagating(self) -> None:
        """The observable is worth 6.0, but a foreign fragment only sees its own 2.0."""
        migrated = self._migrated(self._document("fragment-proofpoint"))
        assert migrated.get_global_score() == 2.0

    def test_a_native_local_link_still_propagates(self) -> None:
        """Same document, same link: only the origin differs, and it is what decides."""
        migrated = self._migrated(self._document("inv-v6"))
        assert migrated.get_global_score() == 6.0


class TestMigrationWhitelists:
    def _migrated(self, document: dict) -> Cyvest:
        facade = Cyvest.__new__(Cyvest)
        facade._investigation = load_investigation_dict(migrate_to_current(document))
        facade._observable_resolvers = []
        return facade

    def _document(self) -> dict:
        document = json.loads(json.dumps(V6_DOCUMENT))
        document["whitelists"] = [
            {"identifier": "SOC-TICKET-42", "name": "False positive", "justification": "cleared by L2"},
            {"identifier": "obs:url:hxxp://bad.example", "name": "Known good", "justification": "corporate"},
        ]
        return document

    def test_an_entry_naming_an_observable_becomes_a_decision_on_it(self) -> None:
        decisions = self._migrated(self._document())._investigation.store.decisions
        assert decisions["dec:obs:url:hxxp://bad.example"].justification == "corporate"

    def _legacy_evidence(self, document: dict):
        evidences = self._migrated(document)._investigation.store.evidences
        return next(e for e in evidences.values() if e.evidence_type == "legacy_whitelist")

    def test_an_unplaceable_entry_is_kept_as_evidence(self) -> None:
        """Its identifier names no observable, and v7 has no investigation-level decision."""
        entries = self._legacy_evidence(self._document()).content
        assert [entry["identifier"] for entry in entries] == ["SOC-TICKET-42"]
        assert entries[0]["name"] == "False positive"
        assert entries[0]["justification"] == "cleared by L2"

    def test_an_unplaceable_entry_does_not_bound_the_root(self) -> None:
        """
        ``REFUTE`` caps its target and unretains every contribution on it.

        Parking a ticket reference on the root manufactured a verdict nobody asserted — out of a
        string that had no scoring effect in v6 either. The migrated score must not move.
        """
        plain = self._migrated(json.loads(json.dumps(V6_DOCUMENT)))
        with_notes = self._migrated(self._document())

        root_key = plain._investigation.store.header.root_key
        assert "dec:" + root_key not in with_notes._investigation.store.decisions

        root_result = with_notes.get_report().observable(root_key)
        assert root_result.suppressed_by_decision is False
        assert root_result.score == plain.get_report().observable(root_key).score

    def test_several_unplaceable_entries_are_all_kept(self) -> None:
        """They used to share one decision key, which silently dropped all but the last."""
        document = json.loads(json.dumps(V6_DOCUMENT))
        document["whitelists"] = [
            {"identifier": "SOC-1", "name": "first", "justification": ""},
            {"identifier": "SOC-2", "name": "second", "justification": ""},
        ]
        entries = self._legacy_evidence(document).content
        assert [entry["identifier"] for entry in entries] == ["SOC-1", "SOC-2"]


class TestMigrationKeyTranslation:
    """
    v6 keys are not always what v7 regenerates, and every cross-reference must follow.

    v7 normalizes an observable's value, so `obs:domain:EVIL.com` is re-keyed to
    `obs:domain:evil.com`. Reusing the v6 key verbatim left signals, relations, finding links and
    whitelist entries pointing at an observable that no longer exists — silently, since a
    dangling key raises nothing. The propagation those references carried simply vanished, and
    the migrated score stopped matching v6, which is the one promise this migration makes.
    """

    def _document(self, *, whitelist: bool = True) -> dict:
        document = {
            "schema_version": "6.0.0",
            "investigation_id": "inv-x",
            "investigation_name": "case",
            "observables": {
                "obs:domain:EVIL.com": {
                    "type": "domain",
                    "value": "EVIL.com",
                    "occurrence_count": 1,
                    "relationships": [
                        {
                            "target_key": "obs:url:hxxp://x",
                            "relationship_type": "extraction",
                            "direction": "outbound",
                        }
                    ],
                },
                "obs:url:hxxp://x": {"type": "url", "value": "hxxp://x", "occurrence_count": 1},
            },
            "findings": {
                "fnd:f": {
                    "finding_name": "f",
                    "score": 3.0,
                    "level": "NOTABLE",
                    "observable_links": [{"observable_key": "obs:domain:EVIL.com", "propagation_mode": "GLOBAL"}],
                }
            },
            "threat_intels": {
                "ti:vt:obs:domain:EVIL.com": {
                    "observable_key": "obs:domain:EVIL.com",
                    "source": "vt",
                    "score": 5.0,
                    "level": "MALICIOUS",
                }
            },
            "tags": {"tag:t": {"name": "t", "findings": [{"key": "fnd:f"}]}},
            "whitelists": [{"identifier": "obs:domain:EVIL.com", "name": "n", "justification": "j"}],
        }
        if not whitelist:
            document["whitelists"] = []
        return document

    def _migrated(self, *, whitelist: bool = True):
        return load_investigation_dict(migrate_to_current(self._document(whitelist=whitelist)))

    def test_the_observable_is_re_keyed(self) -> None:
        assert "obs:domain:evil.com" in self._migrated().store.observables

    def test_a_signal_follows_its_observable(self) -> None:
        store = self._migrated().store
        assert [s.subject_key for s in store.signals.values()] == ["obs:domain:evil.com"]
        assert store.signals_for("obs:domain:evil.com") != []

    def test_a_relation_follows_both_ends(self) -> None:
        store = self._migrated().store
        relation = next(iter(store.relations.values()))
        assert relation.source_key == "obs:domain:evil.com"
        assert relation.target_key == "obs:url:hxxp://x"

    def test_a_finding_link_follows_its_observable(self) -> None:
        store = self._migrated().store
        finding = next(iter(store.findings.values()))
        assert [link.observable_key for link in finding.observable_links] == ["obs:domain:evil.com"]

    def test_a_tag_follows_its_re_keyed_finding(self) -> None:
        """v6 keyed a finding on its name; v7 keys it on its `rule_id`, through the same map."""
        store = self._migrated().store
        tag = next(iter(store.tags.values()))
        assert set(tag.finding_keys) == set(store.findings)

    def test_a_whitelist_entry_finds_its_re_keyed_observable(self) -> None:
        store = self._migrated().store
        assert "dec:obs:domain:evil.com" in store.decisions

    def test_the_score_still_reflects_the_signal(self) -> None:
        """
        The whole point: a detached signal propagates nothing and the total silently drops.

        Read without the whitelist entry, so the number under test is the signal reaching its
        observable rather than the allowlist ceiling that entry now correctly applies.
        """
        investigation = self._migrated(whitelist=False)
        assert investigation.report.observable("obs:domain:evil.com").score == 5.0
        assert investigation.report.investigation.score == 5.0

    def test_the_whitelist_entry_now_actually_bounds_its_observable(self) -> None:
        """It matched nothing while the key was stale, so the ceiling was never applied."""
        bounded = self._migrated().report.observable("obs:domain:evil.com")
        assert bounded.suppressed_by_decision is True
        assert bounded.score < self._migrated(whitelist=False).report.observable("obs:domain:evil.com").score


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
    V5_DOCUMENT = {
        "investigation_id": "inv-v5",
        "observables": {"obs:url:hxxp://old.example": {"type": "url", "value": "hxxp://old.example", "score": 4.0}},
        "findings": {},
        "threat_intels": {},
        "stats": {"anything": 1},
    }

    def _v5(self) -> dict:
        return json.loads(json.dumps(self.V5_DOCUMENT))

    def test_a_v5_document_reaches_v7_in_one_call(self) -> None:
        migrated = migrate_to_current(self._v5())
        assert migrated["schema_version"] == SCHEMA_VERSION
        assert load_investigation_dict(migrated) is not None

    def test_an_unversioned_document_loads_through_migrate(self) -> None:
        """
        The readability check runs *before* the migration, and it used to unpack a version into
        two parts unconditionally. An unversioned document detects as bare ``"5"``, so every v5
        file crashed on load — including the documented ``migrate=True`` path.
        """
        investigation = load_investigation_dict(self._v5(), migrate=True)
        assert "obs:url:hxxp://old.example" in investigation.store.observables

    def test_an_unversioned_document_without_migrate_says_so(self) -> None:
        with pytest.raises(ValueError, match="Document schema is 5"):
            load_investigation_dict(self._v5())


class TestCommittedSchema:
    def test_the_committed_schema_matches_the_models(self) -> None:
        """Without this check, the Python models and the generated TS types drift in silence."""
        from cyvest.schema import get_investigation_schema

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
        from cyvest.schema import get_investigation_schema

        assert get_investigation_schema()["$id"].endswith("investigation-7.json")

    def test_the_report_is_a_required_key(self) -> None:
        from cyvest.schema import get_investigation_schema

        assert "report" in get_investigation_schema()["required"]

    def test_the_committed_signal_contract_matches_the_model(self) -> None:
        """Producers validate against the committed file, so a silent drift breaks them, not us."""
        from cyvest.schema import get_signal_schema

        committed = json.loads(Path("schema/cyvest.signal.schema.json").read_text(encoding="utf-8"))
        assert committed == get_signal_schema(), "run scripts/generate.sh — signal schema is stale"

    def test_a_signal_payload_validates_against_the_committed_contract(self) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        committed = json.loads(Path("schema/cyvest.signal.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(
            {"source": "virustotal", "verdict": "MALICIOUS", "weight": 6.0, "payload": {"scan": 12}},
            committed,
        )
