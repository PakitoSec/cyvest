"""
Cyvest - Cybersecurity Investigation Framework

A Python framework for building, analyzing, and structuring cybersecurity investigations
programmatically with automatic scoring, level calculation, and rich reporting capabilities.
"""

from logurich import logger

from cyvest.compare import (
    DiffItem,
    DiffStatus,
    ExpectedResult,
    ObservableDiff,
    ThreatIntelDiff,
    compare_investigations,
)
from cyvest.cyvest import Cyvest
from cyvest.levels import Level
from cyvest.model import Check, Enrichment, InvestigationWhitelist, Observable, Tag, Taxonomy, ThreatIntel
from cyvest.model_enums import ObservableType, RelationshipDirection, RelationshipType
from cyvest.proxies import CheckProxy, EnrichmentProxy, ObservableProxy, TagProxy, ThreatIntelProxy

__version__ = "5.1.3"

logger.disable("cyvest")

__all__ = [
    # Core class
    "Cyvest",
    # Enums
    "Level",
    "ObservableType",
    "RelationshipDirection",
    "RelationshipType",
    # Proxies
    "CheckProxy",
    "ObservableProxy",
    "ThreatIntelProxy",
    "EnrichmentProxy",
    "TagProxy",
    # Models
    "Tag",
    "Enrichment",
    "InvestigationWhitelist",
    "Check",
    "Observable",
    "ThreatIntel",
    "Taxonomy",
    # Comparison module
    "compare_investigations",
    "ExpectedResult",
    "DiffItem",
    "DiffStatus",
    "ObservableDiff",
    "ThreatIntelDiff",
]
