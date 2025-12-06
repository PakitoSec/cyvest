"""
JSON Schema definition for serialized Cyvest investigations.

The schema mirrors the structure emitted by `serialize_investigation` in
`cyvest.io_serialization` so consumers can validate exports or generate
typed bindings.
"""

from __future__ import annotations

from typing import Any

from cyvest.levels import Level
from cyvest.model import CheckScorePolicy, ObservableType, RelationshipDirection, RelationshipType
from cyvest.score import ScoreMode


def get_investigation_schema() -> dict[str, Any]:
    """
    Build the JSON Schema describing serialized investigations.

    Returns:
        Schema dictionary compliant with JSON Schema Draft 2020-12.
    """
    level_names = [level.name for level in Level]
    score_modes = [mode.value for mode in ScoreMode]
    score_policies = [policy.value for policy in CheckScorePolicy]
    relationship_directions = [direction.value for direction in RelationshipDirection]
    relationship_types = [rel.value for rel in RelationshipType]
    observable_types = [obs.value for obs in ObservableType]

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://cyvest.io/schema/investigation.json",
        "title": "Cyvest Investigation",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "score",
            "level",
            "whitelisted",
            "whitelists",
            "observables",
            "checks",
            "checks_by_level",
            "threat_intels",
            "enrichments",
            "containers",
            "stats",
            "stats_checks",
            "data_extraction",
        ],
        "properties": {
            "score": {"type": "number"},
            "level": {"$ref": "#/$defs/level"},
            "whitelisted": {"type": "boolean"},
            "whitelists": {
                "type": "array",
                "items": {"$ref": "#/$defs/whitelist"},
                "default": [],
            },
            "observables": {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/observable"},
                "default": {},
            },
            "checks": {
                "type": "object",
                "additionalProperties": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/check"},
                    "default": [],
                },
                "default": {},
            },
            "checks_by_level": {
                "type": "object",
                "additionalProperties": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "default": {},
            },
            "threat_intels": {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/threat_intel"},
                "default": {},
            },
            "enrichments": {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/enrichment"},
                "default": {},
            },
            "containers": {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/container"},
                "default": {},
            },
            "stats": {"$ref": "#/$defs/statistics"},
            "stats_checks": {"$ref": "#/$defs/stats_checks"},
            "data_extraction": {"$ref": "#/$defs/data_extraction"},
        },
        "$defs": {
            # Reusable enum types
            "level": {
                "type": "string",
                "enum": level_names,
                "description": "Security level classification from NONE (lowest) to MALICIOUS (highest).",
            },
            "relationship_direction": {
                "type": "string",
                "enum": relationship_directions,
                "description": "Direction of a relationship between observables.",
            },
            "score_policy": {
                "type": "string",
                "enum": score_policies,
                "description": "Score computation policy: 'auto' calculates from level, 'manual' uses explicit score.",
            },
            "score_mode": {
                "type": "string",
                "enum": score_modes,
                "description": "Score aggregation mode: 'max' takes highest score, 'sum' adds all scores.",
            },
            # Complex types
            "whitelist": {
                "type": "object",
                "required": ["identifier", "name"],
                "properties": {
                    "identifier": {"type": "string"},
                    "name": {"type": "string"},
                    "justification": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
            "relationship": {
                "type": "object",
                "required": ["target_key", "relationship_type", "direction"],
                "properties": {
                    "target_key": {"type": "string"},
                    "relationship_type": {
                        "type": "string",
                        "description": "Relationship label; defaults to related-to.",
                        "examples": relationship_types,
                    },
                    "direction": {"$ref": "#/$defs/relationship_direction"},
                },
                "additionalProperties": False,
            },
            "observable": {
                "type": "object",
                "required": [
                    "key",
                    "type",
                    "value",
                    "internal",
                    "whitelisted",
                    "comment",
                    "extra",
                    "score",
                    "level",
                    "relationships",
                    "threat_intels",
                    "generated_by_checks",
                ],
                "properties": {
                    "key": {"type": "string"},
                    "type": {
                        "type": "string",
                        "description": "Observable type (e.g., ipv4-addr, url). Custom values are allowed.",
                        "examples": observable_types,
                    },
                    "value": {"type": "string"},
                    "internal": {"type": "boolean"},
                    "whitelisted": {"type": "boolean"},
                    "comment": {"type": "string"},
                    "extra": {"type": ["object", "null"], "default": {}},
                    "score": {"type": "number"},
                    "level": {"$ref": "#/$defs/level"},
                    "relationships": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/relationship"},
                        "default": [],
                    },
                    "threat_intels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "generated_by_checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
            "check": {
                "type": "object",
                "required": [
                    "key",
                    "check_id",
                    "scope",
                    "description",
                    "comment",
                    "extra",
                    "score",
                    "level",
                    "score_policy",
                    "observables",
                ],
                "properties": {
                    "key": {"type": "string"},
                    "check_id": {"type": "string"},
                    "scope": {"type": "string"},
                    "description": {"type": "string"},
                    "comment": {"type": "string"},
                    "extra": {"type": ["object", "null"], "default": {}},
                    "score": {"type": "number"},
                    "level": {"$ref": "#/$defs/level"},
                    "score_policy": {"$ref": "#/$defs/score_policy"},
                    "observables": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
            "threat_intel": {
                "type": "object",
                "required": [
                    "key",
                    "source",
                    "observable_key",
                    "comment",
                    "extra",
                    "score",
                    "level",
                    "taxonomies",
                ],
                "properties": {
                    "key": {"type": "string"},
                    "source": {"type": "string"},
                    "observable_key": {"type": "string"},
                    "comment": {"type": "string"},
                    "extra": {"type": ["object", "null"], "default": {}},
                    "score": {"type": "number"},
                    "level": {"$ref": "#/$defs/level"},
                    "taxonomies": {
                        "type": "array",
                        "items": {"type": "object"},
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
            "enrichment": {
                "type": "object",
                "required": ["key", "name", "data", "context"],
                "properties": {
                    "key": {"type": "string"},
                    "name": {"type": "string"},
                    "data": {"type": "object"},
                    "context": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "container": {
                "type": "object",
                "required": [
                    "key",
                    "path",
                    "description",
                    "checks",
                    "sub_containers",
                    "aggregated_score",
                    "aggregated_level",
                ],
                "properties": {
                    "key": {"type": "string"},
                    "path": {"type": "string"},
                    "description": {"type": "string"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "sub_containers": {
                        "type": "object",
                        "additionalProperties": {"$ref": "#/$defs/container"},
                        "default": {},
                    },
                    "aggregated_score": {"type": "number"},
                    "aggregated_level": {"$ref": "#/$defs/level"},
                },
                "additionalProperties": False,
            },
            "statistics": {
                "type": "object",
                "required": [
                    "total_observables",
                    "internal_observables",
                    "external_observables",
                    "whitelisted_observables",
                    "observables_by_type",
                    "observables_by_level",
                    "observables_by_type_and_level",
                    "total_checks",
                    "applied_checks",
                    "checks_by_scope",
                    "checks_by_level",
                    "total_threat_intel",
                    "threat_intel_by_source",
                    "threat_intel_by_level",
                    "total_containers",
                ],
                "properties": {
                    "total_observables": {"type": "integer", "minimum": 0},
                    "internal_observables": {"type": "integer", "minimum": 0},
                    "external_observables": {"type": "integer", "minimum": 0},
                    "whitelisted_observables": {"type": "integer", "minimum": 0},
                    "observables_by_type": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "observables_by_level": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "observables_by_type_and_level": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "integer", "minimum": 0},
                            "default": {},
                        },
                        "default": {},
                    },
                    "total_checks": {"type": "integer", "minimum": 0},
                    "applied_checks": {"type": "integer", "minimum": 0},
                    "checks_by_scope": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "checks_by_level": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "total_threat_intel": {"type": "integer", "minimum": 0},
                    "threat_intel_by_source": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "threat_intel_by_level": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                        "default": {},
                    },
                    "total_containers": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
            "stats_checks": {
                "type": "object",
                "required": ["checks", "applied"],
                "properties": {
                    "checks": {"type": "integer", "minimum": 0},
                    "applied": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
            "data_extraction": {
                "type": "object",
                "required": ["root_type", "score_mode"],
                "properties": {
                    "root_type": {
                        "type": ["string", "null"],
                        "description": "Root observable type used during data extraction.",
                        "examples": observable_types,
                    },
                    "score_mode": {"$ref": "#/$defs/score_mode"},
                },
                "additionalProperties": False,
            },
        },
    }
