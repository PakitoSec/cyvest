"""
The published contracts: what a document looks like, and what a producer must send.

``investigation`` is the shape Cyvest **emits**, ``signal`` the shape it **accepts**. The JSON
Schema generators live here rather than beside them because both answer the same question from
the outside — "what do I validate against?" — and both are derived, never hand-written.

Generation goes through Pydantic's ``model_json_schema``, so ``field_serializer`` decorators are
respected and the schema matches the real payload rather than the declared types.
"""

from __future__ import annotations

from typing import Any

from cyvest.schema.investigation import (
    SCHEMA_ID,
    SCHEMA_VERSION,
    SCHEMA_VERSION_PATTERN,
    FactsSchema,
    InvestigationSchema,
)
from cyvest.schema.signal import (
    SIGNAL_SCHEMA_ID,
    SIGNAL_SCHEMA_VERSION,
    SIGNAL_SCHEMA_VERSION_PATTERN,
    SignalEnvelope,
)


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


__all__ = [
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "SCHEMA_VERSION_PATTERN",
    "SIGNAL_SCHEMA_ID",
    "SIGNAL_SCHEMA_VERSION",
    "SIGNAL_SCHEMA_VERSION_PATTERN",
    "FactsSchema",
    "InvestigationSchema",
    "SignalEnvelope",
    "get_investigation_schema",
    "get_signal_schema",
]
