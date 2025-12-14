"""
Shared enum types for Cyvest models.

This module intentionally contains only enums (no Pydantic models) so it can be
imported by both ``cyvest.model`` and ``cyvest.score`` without creating circular
import dependencies.
"""

from __future__ import annotations

from enum import Enum


class ObservableType(str, Enum):
    """Cyber observable types."""

    # Network observables
    IPV4_ADDR = "ipv4-addr"
    IPV6_ADDR = "ipv6-addr"
    DOMAIN_NAME = "domain-name"
    URL = "url"
    NETWORK_TRAFFIC = "network-traffic"
    MAC_ADDR = "mac-addr"

    # File observables
    FILE = "file"
    DIRECTORY = "directory"

    # Email observables
    EMAIL_ADDR = "email-addr"
    EMAIL_MESSAGE = "email-message"
    EMAIL_MIME_PART = "email-mime-part"

    # Identity and account
    USER_ACCOUNT = "user-account"

    # System observables
    PROCESS = "process"
    SOFTWARE = "software"
    WINDOWS_REGISTRY_KEY = "windows-registry-key"

    # Artifact observables
    ARTIFACT = "artifact"

    # Autonomous System
    AUTONOMOUS_SYSTEM = "autonomous-system"

    # Mutex
    MUTEX = "mutex"

    # X509 Certificate
    X509_CERTIFICATE = "x509-certificate"


class RelationshipDirection(str, Enum):
    """Direction of a relationship between observables."""

    OUTBOUND = "outbound"  # Source → Target
    INBOUND = "inbound"  # Source ← Target
    BIDIRECTIONAL = "bidirectional"  # Source ↔ Target


class RelationshipType(str, Enum):
    """Relationship types supported by Cyvest."""

    RELATED_TO = "related-to"

    def get_default_direction(self) -> RelationshipDirection:
        """
        Get the default direction for this relationship type.
        """
        return RelationshipDirection.BIDIRECTIONAL


class CheckScorePolicy(str, Enum):
    """Controls how a check reacts to linked observables."""

    AUTO = "auto"  # Default: observables can update the check score/level
    MANUAL = "manual"  # Score/level only change via explicit check updates
