"""
Cyvest - Cybersecurity Investigation Framework

A Python framework for building, analyzing, and structuring cybersecurity investigations
programmatically with automatic scoring, level calculation, and rich reporting capabilities.
"""

from logurich import logger

from cyvest.cyvest import Cyvest
from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, InvestigationWhitelist, Observable, Taxonomy, ThreatIntel
from cyvest.model_enums import ObservableType, RelationshipDirection, RelationshipType
from cyvest.proxies import CheckProxy, ContainerProxy, EnrichmentProxy, ObservableProxy, ThreatIntelProxy

__version__ = "4.2.0"

logger.disable("cyvest")

__all__ = [
    "Cyvest",
    "Level",
    "ObservableType",
    "RelationshipDirection",
    "RelationshipType",
    "CheckProxy",
    "ObservableProxy",
    "ThreatIntelProxy",
    "EnrichmentProxy",
    "ContainerProxy",
    "Container",
    "Enrichment",
    "InvestigationWhitelist",
    "Check",
    "Observable",
    "ThreatIntel",
    "Taxonomy",
]
