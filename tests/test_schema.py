"""
Tests for the JSON Schema generator and CLI command.
"""

from __future__ import annotations

import pytest

from cyvest import Cyvest
from cyvest.io_schema import get_investigation_schema
from cyvest.levels import Level
from cyvest.model import Check, Container, Observable, ThreatIntel
from cyvest.model_schema import InvestigationSchema


def _sample_investigation() -> Cyvest:
    """Create a minimal investigation for schema validation."""
    cv = Cyvest()
    obs = cv.observable("domain-name", "example.com", internal=False)
    cv.check("domain_check", "network", "Validate domain").link_observable(obs)
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

    for model in (Observable, Check, ThreatIntel):
        schema = _resolve_root(model.model_json_schema(mode="serialization"))
        required = set(schema.get("required", []))
        assert {"level", "key", "comment", "extra"} <= required
        if model is Observable:
            assert {"score", "threat_intels", "relationships", "internal", "whitelisted"} <= required
        if model is Check:
            assert {"origin_investigation_id", "observable_links", "score"} <= required


def test_container_aggregated_level_schema() -> None:
    """aggregated_level is exposed as a Level enum in the schema."""
    schema = Container.model_json_schema(mode="serialization")

    # If Pydantic emits a root $ref (common for self-recursive models), follow it.
    if "$ref" in schema:
        ref = schema["$ref"]  # e.g. "#/$defs/Container"
        name = ref.rsplit("/", 1)[-1]
        schema = schema["$defs"][name]

    agg_level_schema = schema["properties"]["aggregated_level"]

    assert {"aggregated_level", "sub_containers", "checks", "key"} <= set(schema["properties"])
    assert {"sub_containers", "checks", "key"} <= set(schema.get("required", []))

    def _has_level(subschema: dict[str, object]) -> bool:
        if "$ref" in subschema:
            return str(subschema["$ref"]).endswith("Level")
        if "enum" in subschema:
            return set(subschema["enum"]) >= {level.value for level in Level}
        return False

    if "allOf" in agg_level_schema:
        assert any(_has_level(subschema) for subschema in agg_level_schema["allOf"])
    else:
        assert _has_level(agg_level_schema)


def test_investigation_schema_level_required_and_defaults() -> None:
    """InvestigationSchema required fields stay required in schema while defaulting at runtime."""
    schema = InvestigationSchema.model_json_schema(mode="serialization")
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = schema["$defs"][name]

    required = set(schema.get("required", []))
    assert {
        "investigation_id",
        "started_at",
        "level",
        "whitelists",
        "observables",
        "checks",
        "checks_by_level",
        "threat_intels",
        "enrichments",
        "containers",
    } <= required

    inst = InvestigationSchema.model_validate(
        {
            "investigation_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "started_at": "2020-01-01T00:00:00+00:00",
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
                "total_checks": 0,
                "applied_checks": 0,
                "checks_by_scope": {},
                "checks_by_level": {},
                "total_threat_intel": 0,
                "threat_intel_by_source": {},
                "threat_intel_by_level": {},
                "total_containers": 0,
            },
            "stats_checks": {"checks": 0, "applied": 0},
            "data_extraction": {"root_type": None, "score_mode": "max"},
        }
    )
    assert inst.level == Level.NONE
    assert inst.whitelists == []
    assert inst.observables == {}
    assert inst.checks == {}
    assert inst.checks_by_level == {}
    assert inst.threat_intels == {}
    assert inst.enrichments == {}
    assert inst.containers == {}
