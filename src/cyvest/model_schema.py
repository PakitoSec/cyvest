"""
The serialized shape of an investigation.

Two decisions govern this module.

The document is **self-contained**: ``report`` is always present and required, so a JavaScript
consumer reads results instead of reimplementing an engine. The size overhead is accepted.

The document is **read forward only**: a 7.1 library reads a 7.0 document, a 7.0 library refuses
a 7.1 one. That is what lets ``additionalProperties`` stay locked and parsing stay strict.

Design constraint for 7.2: fact collections stay maps ``{key: object}``. Superseded versions will
go into a sibling ``facts.history`` key — turning a map into ``{key: [objects]}`` would break
every existing document.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyvest.evaluation.report import Report
from cyvest.facts.decision import Decision
from cyvest.facts.evidence import Evidence
from cyvest.facts.finding import Finding
from cyvest.facts.observable import Observable
from cyvest.facts.relation import Relation
from cyvest.facts.signal import ThreatIntel
from cyvest.facts.store import InvestigationHeader
from cyvest.facts.tag import Tag

SCHEMA_VERSION = "7.0.0"
SCHEMA_ID = "https://cyvest.io/schema/investigation-7.json"

# The schema only guards the major: pinning the exact version here would make every 7.x release
# refuse the documents written by the previous one. The minor window is enforced at load time by
# ``io_serialization._check_readable``, which ajv and pydantic cannot express.
SCHEMA_VERSION_PATTERN = rf"^{SCHEMA_VERSION.split('.')[0]}\.\d+\.\d+$"


class FactsSchema(BaseModel):
    """The fact collections, each keyed by its semantic key."""

    model_config = ConfigDict(extra="forbid")

    observables: dict[str, Observable] = Field(default_factory=dict)
    relations: dict[str, Relation] = Field(default_factory=dict)
    # Discriminated on ``kind`` from day one: adding the discriminator later would force a
    # migration of every serialized document.
    signals: dict[str, ThreatIntel] = Field(default_factory=dict)
    evidences: dict[str, Evidence] = Field(default_factory=dict)
    findings: dict[str, Finding] = Field(default_factory=dict)
    # Reserved for imported EDR/SIEM timelines. Costs an empty dict, states the intent.
    events: dict[str, Any] = Field(default_factory=dict)


class InvestigationSchema(BaseModel):
    """A complete serialized investigation."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"$id": SCHEMA_ID})

    schema_version: str = Field(default=SCHEMA_VERSION, pattern=SCHEMA_VERSION_PATTERN)
    header: InvestigationHeader = Field(...)
    policy_version: str = Field(default="default-v1")
    engine_id: str = Field(default="basic-v1")

    facts: FactsSchema = Field(default_factory=FactsSchema)
    decisions: dict[str, Decision] = Field(default_factory=dict)
    tags: dict[str, Tag] = Field(default_factory=dict)

    report: Report = Field(...)


__all__ = ["SCHEMA_ID", "SCHEMA_VERSION", "SCHEMA_VERSION_PATTERN", "FactsSchema", "InvestigationSchema"]
