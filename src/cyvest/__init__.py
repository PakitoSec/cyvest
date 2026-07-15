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
from cyvest.resolvers import ObservableResolution, ObservableResolver
from cyvest.semantics import (
    RelationshipApplyResult,
    RelationshipContext,
    RelationshipContextEdge,
    RelationshipContextObservable,
    RelationshipDefinition,
    RelationshipFamily,
    RelationshipOperation,
    RelationshipPlan,
    RelationshipPlanPreview,
    RelationshipProposal,
    RelationshipValidationIssue,
    build_relationship_context,
    get_graph_revision,
    get_relationship_catalog,
    get_relationship_plan_digest,
    validate_relationship_plan,
)

__version__ = "6.1.2"

__all__ = [
    # Core class
    "Cyvest",
    # Enums
    "Level",
    "ObservableType",
    "ObservableSubtype",
    "RelationshipDirection",
    "RelationshipType",
    "RelationshipDefinition",
    "RelationshipApplyResult",
    "RelationshipContext",
    "RelationshipContextEdge",
    "RelationshipContextObservable",
    "RelationshipFamily",
    "RelationshipOperation",
    "RelationshipPlan",
    "RelationshipPlanPreview",
    "RelationshipProposal",
    "RelationshipValidationIssue",
    "build_relationship_context",
    "get_graph_revision",
    "get_relationship_plan_digest",
    "get_relationship_catalog",
    "validate_relationship_plan",
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
    "ObservableResolution",
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
