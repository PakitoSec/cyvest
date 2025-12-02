"""
Tests for the JSON Schema generator and CLI command.
"""

from __future__ import annotations

import json

from click.testing import CliRunner
from jsonschema import Draft202012Validator

from cyvest import Cyvest
from cyvest.cli import cli
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


def test_cli_schema_outputs_valid_json() -> None:
    """CLI schema command emits valid JSON Schema."""
    runner = CliRunner()
    result = runner.invoke(cli, ["schema"])

    assert result.exit_code == 0
    schema = json.loads(result.output)
    Draft202012Validator.check_schema(schema)
