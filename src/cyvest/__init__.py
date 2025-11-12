"""
Cyvest - Cybersecurity Investigation Framework

A Python framework for building, analyzing, and structuring cybersecurity investigations
programmatically with automatic scoring, level calculation, and rich reporting capabilities.
"""

# Import DSL to activate monkey-patching
import cyvest.dsl  # noqa: F401
from cyvest.cyvest import Cyvest
from cyvest.levels import Level
from cyvest.model import (
    Check,
    Container,
    Enrichment,
    Observable,
    ObservableType,
    Relationship,
    RelationshipDirection,
    RelationshipType,
    ThreatIntel,
)

__version__ = "0.1.0"

__all__ = [
    "Cyvest",
    "Level",
    "Check",
    "Observable",
    "ObservableType",
    "Relationship",
    "RelationshipDirection",
    "RelationshipType",
    "ThreatIntel",
    "Enrichment",
    "Container",
]
