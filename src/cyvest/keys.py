"""
Key generation utilities for Cyvest objects.

Provides deterministic, unique key generation for all object types.
Keys are used for object identification, retrieval, and merging.
"""

import hashlib
from typing import Any


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


def generate_observable_key(obs_type: str, value: str) -> str:
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
    normalized_value = _normalize_value(value)
    return f"obs:{normalized_type}:{normalized_value}"


def generate_check_key(check_name: str) -> str:
    """
    Generate a unique key for a check.

    Format: chk:{check_name}

    Args:
        check_name: Name of the check

    Returns:
        Unique check key
    """
    normalized_name = _normalize_value(check_name)
    return f"chk:{normalized_name}"


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
        Type prefix (obs, chk, ti, enr, tag) or None if invalid
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
    Validate a key format and optionally check its type.

    Args:
        key: The key to validate
        expected_type: Optional expected type prefix

    Returns:
        True if valid, False otherwise
    """
    if not key or ":" not in key:
        return False

    key_type = parse_key_type(key)
    if key_type not in ("obs", "chk", "ti", "enr", "tag"):
        return False

    if expected_type and key_type != expected_type:
        return False

    return True
