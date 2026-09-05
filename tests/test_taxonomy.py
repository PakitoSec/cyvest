"""Structured taxonomies describe a signal; their verdicts never score."""

from __future__ import annotations

import json
from copy import deepcopy
from io import StringIO
from pathlib import Path

import pytest
from pydantic import ValidationError
from rich.console import Console

from cyvest import Cyvest, Operation, Taxonomy, Verdict, apply_operations
from cyvest.facts import ThreatIntel
from cyvest.investigation import FrozenInvestigationError
from cyvest.io.markdown import generate_markdown_report
from cyvest.io.render import build_graph
from cyvest.io.serialization import investigation_to_dict, load_investigation_dict, migrate_to_current


def case():
    cv = Cyvest(investigation_id="taxonomy-case")
    url = cv.observable("url", "https://example.test")
    cv.observable_add_relation(cv.root(), url, cv.REL.EXTRACTION)
    signal = cv.observable_add_threat_intel(url, "vendor", verdict=Verdict.NOTABLE, weight=2.0)
    cv.finding("url-reputation").link_observable(url)
    return cv, url, signal


class TestTaxonomy:
    def test_factory_returns_an_immutable_descriptive_object(self) -> None:
        entry = Cyvest.taxonomy(name="engine", value="clean", verdict="SAFE")
        assert isinstance(entry, Taxonomy)
        assert entry.model_dump(mode="json") == {"name": "engine", "value": "clean", "verdict": "SAFE"}
        assert set(Taxonomy.model_fields) == {"name", "value", "verdict"}
        with pytest.raises(ValidationError, match="frozen"):
            entry.value = "changed"

    def test_default_verdict_is_information_only(self) -> None:
        assert Taxonomy(name="family", value="unknown").verdict is Verdict.INFO

    @pytest.mark.parametrize(
        "fields",
        [
            {"name": "engine"},
            {"name": "engine", "value": 12},
            {"name": "engine", "value": "x", "verdict": "wrong"},
            {"name": "engine", "value": "x", "weight": 99},
        ],
    )
    def test_invalid_metadata_is_rejected(self, fields: dict) -> None:
        with pytest.raises(ValidationError):
            Taxonomy.model_validate(fields)

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_taxonomy_verdict_never_changes_any_report_result(self, verdict: Verdict) -> None:
        cv, url, signal = case()
        before = cv.get_report()
        signal.add_taxonomy(name="classification", value="description", verdict=verdict)
        assert cv.get_report() == before
        assert signal.verdict is Verdict.NOTABLE
        assert signal.weight == 2.0
        assert url.score == cv.get_global_score() == 2.0
        signal.remove_taxonomy("classification")
        assert cv.get_report() == before

    def test_add_updates_by_name_without_mutating_the_previous_fact(self) -> None:
        cv, _, signal = case()
        first = cv.taxonomy(name="engine", value="old", verdict=Verdict.MALICIOUS)
        assert signal.add_taxonomy(first) is signal
        old_fact = cv._investigation.get_threat_intel(signal.key)
        signal.add_taxonomy(name="other", value="kept")
        cv.threat_intel_add_taxonomy(signal.key, name="engine", value="clean", verdict=Verdict.SAFE)
        assert [(t.name, t.value) for t in signal.taxonomies] == [("engine", "clean"), ("other", "kept")]
        assert old_fact.taxonomies == (first,)
        assert signal.taxonomies[0].verdict is Verdict.SAFE

    def test_readding_and_removing_absent_names_are_noops(self) -> None:
        cv, _, signal = case()
        entry = cv.taxonomy(name="engine", value="clean")
        cv.threat_intel_add_taxonomy(signal.key, entry)
        before = cv._investigation.get_threat_intel(signal.key)
        report = cv.get_report()
        signal.add_taxonomy(entry).remove_taxonomy("absent")
        assert cv._investigation.get_threat_intel(signal.key) is before
        assert cv.get_report() is report
        cv.threat_intel_remove_taxonomy(signal.key, "engine")
        assert signal.taxonomies == ()

    def test_legacy_add_and_remove_remain_supported(self) -> None:
        cv, _, signal = case()
        cv.threat_intel_add_taxonomy(signal.key, "malware-type:trojan")
        assert signal.taxonomies == (Taxonomy(name="malware-type:trojan", value=""),)
        cv.threat_intel_remove_taxonomy(signal.key, "malware-type:trojan")
        assert signal.taxonomies == ()

    def test_missing_signal_and_ambiguous_arguments_are_rejected(self) -> None:
        cv, _, signal = case()
        with pytest.raises(KeyError):
            cv.threat_intel_add_taxonomy("missing", name="engine", value="x")
        with pytest.raises(KeyError):
            cv.threat_intel_remove_taxonomy("missing", "engine")
        with pytest.raises(ValueError, match="not both"):
            signal.add_taxonomy("legacy", name="engine")
        with pytest.raises(ValueError, match="name"):
            signal.add_taxonomy()

    def test_duplicate_names_are_rejected_on_construction_and_ingestion(self) -> None:
        entries = [Taxonomy(name="engine", value="one"), Taxonomy(name="engine", value="two")]
        cv, url, _ = case()
        with pytest.raises(ValidationError, match="Duplicate taxonomy name"):
            cv.observable_add_threat_intel(url, "other", taxonomies=entries)
        with pytest.raises(ValidationError, match="Duplicate taxonomy name"):
            Cyvest.io_dump_signal("other", taxonomies=entries)

    def test_snapshot_cannot_be_modified_through_taxonomies(self) -> None:
        cv, _, signal = case()
        cv._investigation.frozen = True
        with pytest.raises(FrozenInvestigationError):
            signal.add_taxonomy(name="engine", value="x")


class TestTaxonomyBoundaries:
    def test_object_dict_and_legacy_string_inputs_round_trip(self) -> None:
        cv, url, _ = case()
        entries = [
            cv.taxonomy(name="engine", value="clean", verdict=Verdict.SAFE),
            {"name": "family", "value": "trojan", "verdict": "MALICIOUS"},
            "unstructured:legacy:text",
        ]
        signal = cv.observable_add_threat_intel(url, "other", taxonomies=entries)
        document = json.loads(json.dumps(cv.io_to_dict()))
        loaded = load_investigation_dict(document)
        assert loaded.get_threat_intel(signal.key).taxonomies == signal.taxonomies
        assert investigation_to_dict(loaded) == document

    def test_external_envelope_preserves_metadata_and_signal_judgment(self) -> None:
        entry = Cyvest.taxonomy(name="engine", value="clean", verdict=Verdict.SAFE)
        wire = Cyvest.io_dump_signal("vendor", verdict=Verdict.MALICIOUS, weight=6.0, taxonomies=(entry,))
        assert wire["schema_version"] == "7.1.0"
        assert wire["taxonomies"] == [entry.model_dump(mode="json")]
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads(Path("schema/cyvest.signal.schema.json").read_text())
        jsonschema.validate(wire, schema)
        cv, url, _ = case()
        url.with_ti(Cyvest.io_load_signal(json.loads(json.dumps(wire))))
        assert url.signal("vendor").taxonomies == (entry,)
        assert url.score == 6.0
        schema = json.loads(Path("schema/cyvest.schema.json").read_text())
        jsonschema.validate(cv.io_to_dict(), schema)

    def test_drafts_and_operations_preserve_structured_entries(self) -> None:
        cv, url, _ = case()
        entry = cv.taxonomy(name="family", value="example", verdict=Verdict.MALICIOUS)
        url.with_ti(cv.threat_intel_draft("draft", taxonomies=(entry,)))
        assert url.signal("draft").taxonomies == (entry,)
        result = apply_operations(
            cv,
            [
                Operation.model_validate(
                    {
                        "op": "threat_intel",
                        "observable": url.key,
                        "source": "batch",
                        "taxonomies": [entry.model_dump(mode="json")],
                    }
                )
            ],
        )
        assert result.ok, result.errors
        assert url.signal("batch").taxonomies == (entry,)
        assert url.signal("batch").verdict is Verdict.INFO

    def test_7_0_documents_and_envelopes_are_read_without_opt_in(self) -> None:
        cv, _, signal = case()
        document = cv.io_to_dict()
        document["schema_version"] = "7.0.99"
        document["facts"]["signals"][signal.key]["taxonomies"] = ["legacy:whole:text"]
        original = deepcopy(document)
        expected = (Taxonomy(name="legacy:whole:text", value=""),)
        loaded = load_investigation_dict(document)
        assert loaded.get_threat_intel(signal.key).taxonomies == expected
        assert loaded.report == cv.get_report()
        assert document == original
        migrated = migrate_to_current(document)
        assert migrated["schema_version"] == "7.1.0"
        assert migrated["facts"]["signals"][signal.key]["taxonomies"] == [expected[0].model_dump(mode="json")]
        assert migrate_to_current(migrated) == migrated
        draft = Cyvest.io_load_signal({"schema_version": "7.0.0", "source": "old", "taxonomies": ["legacy:whole:text"]})
        obs = cv.observable("url", "https://old.example")
        obs.with_ti(draft)
        assert obs.signal("old").taxonomies == expected

    @pytest.mark.parametrize(
        ("level", "verdict"),
        [("SAFE", Verdict.SAFE), ("TRUSTED", Verdict.SAFE), ("NONE", Verdict.INFO), ("MALICIOUS", Verdict.MALICIOUS)],
    )
    def test_v6_migration_preserves_all_metadata(self, level: str, verdict: Verdict) -> None:
        document = {
            "schema_version": "6.0.0",
            "investigation_id": "v6-taxonomies",
            "observables": {"obs:url:https://example.test": {"type": "url", "value": "https://example.test"}},
            "threat_intels": {
                "ti:vendor:obs:url:https://example.test": {
                    "observable_key": "obs:url:https://example.test",
                    "source": "vendor",
                    "score": 2.0,
                    "taxonomies": [{"name": "engine", "value": "[original]", "level": level}],
                }
            },
        }
        loaded = load_investigation_dict(document, migrate=True)
        signal = next(iter(loaded.store.signals.values()))
        assert isinstance(signal, ThreatIntel)
        assert signal.taxonomies == (Taxonomy(name="engine", value="[original]", verdict=verdict),)
        assert loaded.report.observable(signal.subject_key).score == 2.0

    def test_merge_keeps_the_latest_structured_metadata(self) -> None:
        cv, _, signal = case()
        signal.add_taxonomy(name="engine", value="old", verdict=Verdict.MALICIOUS)
        old = load_investigation_dict(cv.io_to_dict())
        signal.add_taxonomy(name="engine", value="clean", verdict=Verdict.SAFE)
        old.merge_investigation(cv._investigation)
        assert old.get_threat_intel(signal.key).taxonomies == signal.taxonomies
        assert old.get_global_score() == cv.get_global_score() == 2.0

    def test_human_renderings_keep_name_value_and_descriptive_verdict(self) -> None:
        cv, _, signal = case()
        signal.add_taxonomy(name="[engine]", value="[clean]", verdict=Verdict.SAFE)
        output = StringIO()
        Console(file=output, width=200, color_system=None).print(build_graph(cv._investigation))
        text = output.getvalue()
        assert "SAFE [engine]: [clean]" in text
        assert "vendor" in text
        markdown = generate_markdown_report(cv)
        assert "Taxonomies (descriptive only)" in markdown
        assert "[engine] | [clean] | SAFE" in markdown
