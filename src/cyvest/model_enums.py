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

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILE = "file"
    ARTIFACT = "artifact"
    HOST = "host"
    PROCESS = "process"
    USER = "user"
    COMMAND_LINE = "command_line"
    CLOUD_RESOURCE = "cloud_resource"

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


class ObservableSubtype(str, Enum):
    """Built-in observable representations."""

    USER_EMAIL = "email"
    USER_SID = "sid"
    USER_UPN = "upn"
    USER_OKTA_ID = "okta_id"
    USER_USERNAME = "username"
    USER_UID = "uid"
    HOST_HOSTNAME = "hostname"
    HOST_FQDN = "fqdn"
    HOST_NETBIOS = "netbios"
    HOST_DEVICE_ID = "device_id"
    PROCESS_PID = "pid"
    PROCESS_GUID = "process_guid"
    FILE_PATH = "path"
    CLOUD_AWS_ARN = "aws_arn"
    CLOUD_AZURE_RESOURCE_ID = "azure_resource_id"
    CLOUD_GCP_RESOURCE_NAME = "gcp_resource_name"


class RelationshipDirection(str, Enum):
    """Direction of a relationship between observables."""

    OUTBOUND = "outbound"  # Source → Target
    INBOUND = "inbound"  # Source ← Target
    BIDIRECTIONAL = "bidirectional"  # Source ↔ Target


class RelationshipType(str, Enum):
    """
    Relationship types supported by Cyvest.

    The vocabulary describes the analyst pivot that produced the target from the
    source, not an ontology of the entities themselves.
    """

    # The target was extracted from the source (URL in an email, hash of a file).
    EXTRACTION = "extraction"
    # The target was obtained by enriching the source (DNS, whois, threat intel, sandbox).
    PIVOT = "pivot"
    # The observables correlate but the deduction mechanism is not established.
    RELATED_TO = "related-to"

    def get_default_direction(self) -> RelationshipDirection:
        """
        Get the default direction for this relationship type.
        """
        if self is RelationshipType.RELATED_TO:
            return RelationshipDirection.BIDIRECTIONAL
        return RelationshipDirection.OUTBOUND


class PropagationMode(str, Enum):
    """Controls how a Finding↔Observable link propagates across merged investigations."""

    LOCAL_ONLY = "LOCAL_ONLY"
    GLOBAL = "GLOBAL"
