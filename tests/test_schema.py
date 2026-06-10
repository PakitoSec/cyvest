"""
Tests for the JSON Schema generator and CLI command.
"""

from __future__ import annotations

import pytest

from cyvest import Cyvest
from cyvest.io_schema import get_investigation_schema
from cyvest.model import Finding, Observable, Tag, ThreatIntel
from cyvest.model_schema import InvestigationSchema


def _sample_investigation() -> Cyvest:
    """Create a minimal investigation for schema validation."""
    cv = Cyvest()
    obs = cv.observable(Cyvest.OBS.DOMAIN, "example.com", internal=False)
    cv.finding("domain_finding", "network", "Validate domain").link_observable(obs)
    return cv


def test_schema_validates_serialized_output() -> None:
    """Schema accepts data produced by the serializer."""
    jsonschema = pytest.importorskip("jsonschema")
    Draft202012Validator = jsonschema.Draft202012Validator
    schema = get_investigation_schema()
    validator = Draft202012Validator(schema)
    investigation_schema = _sample_investigation().io_to_invest()

    # Validate the model_dump() output (dict) against JSON schema
    validator.validate(investigation_schema.model_dump(mode="json", by_alias=True))


def test_level_required_in_serialization_schema() -> None:
    """level stays required in generated schemas to satisfy TS generation."""

    def _resolve_root(schema: dict) -> dict:
        if "$ref" in schema and "$defs" in schema and schema["$ref"].startswith("#/$defs/"):
            name = schema["$ref"].split("/")[-1]
            return schema["$defs"][name]
        return schema

    for model in (Observable, Finding, ThreatIntel):
        schema = _resolve_root(model.model_json_schema(mode="serialization"))
        required = set(schema.get("required", []))
        assert {"level", "key", "comment", "extra"} <= required
        if model is Observable:
            assert {"score", "threat_intels", "relationships", "internal", "whitelisted"} <= required
        if model is Finding:
            assert {"origin_investigation_id", "observable_links", "score"} <= required


def test_tag_direct_level_schema() -> None:
    """direct_level is exposed as a Level enum in the schema."""
    schema = Tag.model_json_schema(mode="serialization")

    # If Pydantic emits a root $ref (common for self-recursive models), follow it.
    if "$ref" in schema:
        ref = schema["$ref"]  # e.g. "#/$defs/Tag"
        name = ref.rsplit("/", 1)[-1]
        schema = schema["$defs"][name]

    direct_level_schema = schema["properties"]["direct_level"]

    assert {"direct_level", "findings", "key"} <= set(schema["properties"])
    assert {"findings", "key"} <= set(schema.get("required", []))

    def _has_level(subschema: dict[str, object]) -> bool:
        if "$ref" in subschema:
            return str(subschema["$ref"]).endswith("Level")
        if "enum" in subschema:
            return set(subschema["enum"]) >= {level.value for level in Cyvest.LVL}
        return False

    if "allOf" in direct_level_schema:
        assert any(_has_level(subschema) for subschema in direct_level_schema["allOf"])
    else:
        assert _has_level(direct_level_schema)


def test_investigation_schema_level_required_and_defaults() -> None:
    """InvestigationSchema required fields stay required in schema while defaulting at runtime."""
    schema = InvestigationSchema.model_json_schema(mode="serialization")
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = schema["$defs"][name]

    required = set(schema.get("required", []))
    assert {
        "investigation_id",
        "level",
        "whitelists",
        "observables",
        "findings",
        "evidences",
        "threat_intels",
        "enrichments",
        "tags",
    } <= required

    inst = InvestigationSchema.model_validate(
        {
            "investigation_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "score": 0.0,
            "whitelisted": False,
            "stats": {
                "total_observables": 0,
                "internal_observables": 0,
                "external_observables": 0,
                "whitelisted_observables": 0,
                "observables_by_type": {},
                "observables_by_level": {},
                "observables_by_type_and_level": {},
                "total_findings": 0,
                "applied_findings": 0,
                "findings_by_level": {},
                "total_evidences": 0,
                "evidences_by_type": {},
                "evidences_by_source": {},
                "total_threat_intel": 0,
                "threat_intel_by_source": {},
                "threat_intel_by_level": {},
                "total_tags": 0,
            },
            "data_extraction": {"root_type": None, "score_mode_obs": "max"},
        }
    )
    assert inst.level == Cyvest.LVL.NONE
    assert inst.whitelists == []
    assert inst.observables == {}
    assert inst.findings == {}
    assert inst.evidences == {}
    assert inst.threat_intels == {}
    assert inst.enrichments == {}
    assert inst.tags == {}
