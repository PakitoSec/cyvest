"""
Tests for the JSON Schema generator and CLI command.
"""

from __future__ import annotations

from jsonschema import Draft202012Validator

from cyvest import Cyvest
from cyvest.io_schema import get_investigation_schema
from cyvest.io_serialization import serialize_investigation


def _sample_investigation() -> Cyvest:
    """Create a minimal investigation for schema validation."""
    cv = Cyvest()
    obs = cv.observable("domain-name", "example.com", internal=False)
    cv.check("domain_check", "network", "Validate domain").link_observable(obs)
    return cv


def test_schema_validates_serialized_output() -> None:
    """Schema accepts data produced by the serializer."""
    schema = get_investigation_schema()
    validator = Draft202012Validator(schema)
    data = serialize_investigation(_sample_investigation())

    validator.validate(data)
