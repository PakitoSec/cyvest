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

    @classmethod
    def normalize_root_type(cls, root_type: ObservableType | str | None) -> ObservableType:
        if root_type is None:
            return cls.FILE
        if isinstance(root_type, cls):
            normalized = root_type
        elif isinstance(root_type, str):
            try:
                normalized = cls(root_type.lower())
            except ValueError as exc:
                raise ValueError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT") from exc
        else:
            raise TypeError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT")

        if normalized not in (cls.FILE, cls.ARTIFACT):
            raise ValueError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT")
        return normalized


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


class PropagationMode(str, Enum):
    """Controls how a Check↔Observable link propagates across merged investigations."""

    LOCAL_ONLY = "LOCAL_ONLY"
    GLOBAL = "GLOBAL"
