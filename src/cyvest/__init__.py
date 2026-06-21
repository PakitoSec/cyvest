"""
Cyvest - Cybersecurity Investigation Framework

A Python framework for building, analyzing, and structuring cybersecurity investigations
programmatically with automatic scoring, level calculation, and rich reporting capabilities.
"""

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
from cyvest.model import (
    Enrichment,
    Evidence,
    Finding,
    InvestigationWhitelist,
    Observable,
    ObservableAlias,
    ObservableIdentity,
    Tag,
    Taxonomy,
    ThreatIntel,
)
from cyvest.model_enums import ObservableSubtype, ObservableType, RelationshipDirection, RelationshipType
from cyvest.proxies import EnrichmentProxy, EvidenceProxy, FindingProxy, ObservableProxy, TagProxy, ThreatIntelProxy
from cyvest.resolvers import ObservableResolver

__version__ = "6.1.0"

__all__ = [
    # Core class
    "Cyvest",
    # Enums
    "Level",
    "ObservableType",
    "ObservableSubtype",
    "RelationshipDirection",
    "RelationshipType",
    # Proxies
    "FindingProxy",
    "EvidenceProxy",
    "ObservableProxy",
    "ThreatIntelProxy",
    "EnrichmentProxy",
    "TagProxy",
    # Models
    "Tag",
    "Enrichment",
    "InvestigationWhitelist",
    "Finding",
    "Evidence",
    "Observable",
    "ObservableAlias",
    "ObservableIdentity",
    "ObservableResolver",
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
