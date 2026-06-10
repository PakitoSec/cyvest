"""
Key generation utilities for Cyvest objects.

Provides deterministic, unique key generation for all object types.
Keys are used for object identification, retrieval, and merging.
"""

import hashlib
import json
from typing import Any
from urllib.parse import quote

from cyvest.model_enums import ObservableSubtype, ObservableType

_MAX_READABLE_OBSERVABLE_IDENTITY_BYTES = 128


def _normalize_value(value: str) -> str:
    """
    Normalize a string value for consistent key generation.

    Args:
        value: The value to normalize

    Returns:
        Normalized lowercase string
    """
    return value.strip().lower()


def _hash_dict(data: dict[str, Any]) -> str:
    """
    Create a deterministic hash from a dictionary.

    Args:
        data: Dictionary to hash

    Returns:
        SHA256 hash of the sorted dictionary items
    """
    # Sort keys for deterministic ordering
    sorted_items = sorted(data.items())
    content = str(sorted_items)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def normalize_observable_value(obs_type: str, value: str, subtype: str | None = None) -> str:
    """Normalize an observable value for identity without changing its display value."""
    normalized_type = _normalize_value(obs_type)
    normalized_subtype = _normalize_value(subtype) if subtype else None
    stripped = value.strip()

    if normalized_type == ObservableType.COMMAND_LINE.value:
        return stripped
    if normalized_type in {ObservableType.EMAIL.value, ObservableType.HOST.value}:
        return stripped.lower()
    if normalized_type == ObservableType.USER.value and normalized_subtype in {
        ObservableSubtype.USER_EMAIL.value,
        ObservableSubtype.USER_UPN.value,
    }:
        return stripped.lower()
    if normalized_subtype in {
        ObservableSubtype.USER_UID.value,
        ObservableSubtype.PROCESS_PID.value,
    }:
        try:
            return str(int(stripped, 10))
        except ValueError as exc:
            raise ValueError(f"{normalized_subtype} observable values must be base-10 integers") from exc
    return stripped


def generate_observable_key(
    obs_type: str,
    value: str,
    subtype: str | None = None,
    namespace: str | None = None,
) -> str:
    """
    Generate a unique key for an observable.

    Format: obs:{type}:{normalized_value}

    Args:
        obs_type: Type of observable (ipv4, ipv6, url, domain, hash, email, etc.)
        value: Value of the observable

    Returns:
        Unique observable key
    """
    normalized_type = _normalize_value(obs_type)
    normalized_subtype = _normalize_value(subtype) if subtype else None
    normalized_namespace = namespace.strip().lower() if namespace else None
    normalized_value = normalize_observable_value(normalized_type, value, normalized_subtype)
    identity = json.dumps(
        {
            "namespace": normalized_namespace,
            "subtype": normalized_subtype,
            "type": normalized_type,
            "value": normalized_value,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if (
        normalized_type == ObservableType.COMMAND_LINE.value
        or len(identity.encode("utf-8")) > _MAX_READABLE_OBSERVABLE_IDENTITY_BYTES
    ):
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return f"obs:{normalized_type}:sha256:{digest}"

    if normalized_subtype is None and normalized_namespace is None:
        return f"obs:{normalized_type}:{normalized_value.lower()}"

    parts = ["obs", quote(normalized_type, safe="._-")]
    parts.append(quote(normalized_subtype, safe="._-") if normalized_subtype else "_")
    if normalized_namespace is not None:
        parts.append(quote(normalized_namespace, safe="._-@"))
    parts.append(quote(normalized_value, safe="._-@/\\"))
    return ":".join(parts)


def generate_finding_key(finding_name: str) -> str:
    """
    Generate a unique key for a finding.

    Format: fnd:{finding_name}

    Args:
        finding_name: Name of the finding

    Returns:
        Unique finding key
    """
    normalized_name = _normalize_value(finding_name)
    return f"fnd:{normalized_name}"


def generate_evidence_key(
    *,
    source: str,
    external_id: str | None,
    evidence_type: str,
    content: Any = None,
    uri: str | None = None,
) -> str:
    """Generate a deterministic evidence key."""
    normalized_source = _normalize_value(source)
    if external_id:
        normalized_external_id = external_id.strip()
        readable = f"evd:{quote(normalized_source, safe='._-')}:{quote(normalized_external_id, safe='._-@/')}"
        if len(readable.encode("utf-8")) <= 128:
            return readable
        digest = hashlib.sha256(f"{normalized_source}\0{normalized_external_id}".encode()).hexdigest()
        return f"evd:{normalized_source}:sha256:{digest}"

    payload = json.dumps(
        {
            "content": content,
            "source": normalized_source,
            "type": evidence_type.strip().lower(),
            "uri": uri,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return f"evd:sha256:{hashlib.sha256(payload.encode()).hexdigest()}"


def generate_threat_intel_key(source: str, observable_key: str) -> str:
    """
    Generate a unique key for threat intelligence.

    Format: ti:{normalized_source}:{observable_key}

    Args:
        source: Name of the threat intel source
        observable_key: Key of the related observable

    Returns:
        Unique threat intel key
    """
    normalized_source = _normalize_value(source)
    return f"ti:{normalized_source}:{observable_key}"


def generate_enrichment_key(name: str, context: str = "") -> str:
    """
    Generate a unique key for an enrichment.

    Format: enr:{name}:{context_hash}

    Args:
        name: Name of the enrichment
        context: Optional context string

    Returns:
        Unique enrichment key
    """
    normalized_name = _normalize_value(name)
    if context:
        context_hash = hashlib.sha256(context.encode()).hexdigest()[:8]
        return f"enr:{normalized_name}:{context_hash}"
    return f"enr:{normalized_name}"


def generate_tag_key(name: str) -> str:
    """
    Generate a unique key for a tag.

    Format: tag:{normalized_name}

    Args:
        name: Name of the tag (uses : as hierarchy delimiter)

    Returns:
        Unique tag key
    """
    normalized_name = _normalize_value(name)
    return f"tag:{normalized_name}"


def get_tag_ancestors(name: str) -> list[str]:
    """
    Get all ancestor tag names from a hierarchical tag name.

    Uses ":" as the hierarchy delimiter.

    Args:
        name: Tag name (e.g., "header:auth:dkim")

    Returns:
        List of ancestor names (e.g., ["header", "header:auth"])
    """
    parts = name.split(":")
    return [":".join(parts[: i + 1]) for i in range(len(parts) - 1)]


def is_tag_child_of(child_name: str, parent_name: str) -> bool:
    """
    Check if a tag is a direct child of another tag.

    Args:
        child_name: Potential child tag name
        parent_name: Potential parent tag name

    Returns:
        True if child_name is a direct child of parent_name
    """
    if not child_name.startswith(parent_name + ":"):
        return False
    remaining = child_name[len(parent_name) + 1 :]
    return ":" not in remaining


def is_tag_descendant_of(descendant_name: str, ancestor_name: str) -> bool:
    """
    Check if a tag is a descendant (child, grandchild, etc.) of another tag.

    Args:
        descendant_name: Potential descendant tag name
        ancestor_name: Potential ancestor tag name

    Returns:
        True if descendant_name is a descendant of ancestor_name
    """
    return descendant_name.startswith(ancestor_name + ":")


def parse_key_type(key: str) -> str | None:
    """
    Extract the type prefix from a key.

    Args:
        key: The key to parse

    Returns:
        Type prefix (obs, fnd, evd, ti, enr, tag) or None if invalid
    """
    if ":" in key:
        return key.split(":", 1)[0]
    return None


def parse_observable_key(key: str) -> tuple[str, str] | None:
    """
    Parse an observable key into its type and value.

    Format: obs:{type}:{normalized_value}

    Args:
        key: Observable key to parse

    Returns:
        Tuple of (observable type, value) or None if invalid
    """
    if parse_key_type(key) != "obs":
        return None

    parts = key.split(":", 2)
    if len(parts) != 3:
        return None

    _, obs_type, value = parts
    if not obs_type or not value:
        return None

    return obs_type, value


def validate_key(key: str, expected_type: str | None = None) -> bool:
    """
    Validate a key format and optionally finding its type.

    Args:
        key: The key to validate
        expected_type: Optional expected type prefix

    Returns:
        True if valid, False otherwise
    """
    if not key or ":" not in key:
        return False

    key_type = parse_key_type(key)
    if key_type not in ("obs", "fnd", "evd", "ti", "enr", "tag"):
        return False

    if expected_type and key_type != expected_type:
        return False

    return True
