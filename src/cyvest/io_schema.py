"""
JSON Schema definition for serialized Cyvest investigations.

The schema mirrors the structure emitted by `serialize_investigation` in
`cyvest.io_serialization` so consumers can validate exports or generate
typed bindings.

This module uses Pydantic's `model_json_schema(mode='serialization')` to generate
schemas that match the actual serialized output (respecting field_serializer decorators).
"""

from __future__ import annotations

from typing import Any

from cyvest.model_schema import InvestigationSchema
from cyvest.signal_schema import SignalEnvelope


def get_investigation_schema() -> dict[str, Any]:
    """
    Get the JSON Schema for serialized investigations.

    Generates a JSON Schema (Draft 2020-12) that describes the output of
    `serialize_investigation()`. The schema uses Pydantic's `model_json_schema`
    with `mode='serialization'`, which respects field_serializer decorators and
    matches the actual `model_dump()` output structure.

    The returned schema automatically includes all referenced entity types
    (Observable, Finding, ThreatIntel, Enrichment, Tag, InvestigationWhitelist)
    in the `$defs` section.

    Returns:
        dict[str, Any]: Schema dictionary compliant with JSON Schema Draft 2020-12.
    """
    return InvestigationSchema.model_json_schema(mode="serialization", by_alias=True)


def get_signal_schema() -> dict[str, Any]:
    """
    The contract an external system fills in to hand Cyvest a signal.

    Generated in ``validation`` mode, unlike the investigation schema: this one describes what a
    producer must send, not what Cyvest emits.
    """
    return SignalEnvelope.model_json_schema(mode="validation", by_alias=True)
