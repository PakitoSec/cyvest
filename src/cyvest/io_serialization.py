"""
Serialization and deserialization for Cyvest investigations.

Provides JSON export/import and Markdown generation for LLM consumption.
"""

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from cyvest.cyvest import Cyvest
from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel


def _decimal_to_float(obj: Any) -> Any:
    """Convert Decimal objects to float for JSON serialization."""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def serialize_observable(obs: Observable) -> dict[str, Any]:
    """
    Serialize an observable to a dictionary.

    Args:
        obs: Observable to serialize

    Returns:
        Dictionary representation
    """
    return {
        "key": obs.key,
        "type": obs.obs_type,
        "value": obs.value,
        "internal": obs.internal,
        "whitelisted": obs.whitelisted,
        "comment": obs.comment,
        "extra": obs.extra,
        "score": float(obs.score),
        "level": obs.level.name,
        "relationships": [
            {"target_key": rel.target_key, "relationship_type": rel.relationship_type}
            for rel in obs.relationships
        ],
        "threat_intels": [ti.key for ti in obs.threat_intels],
        "generated_by_checks": obs._generated_by_checks,
    }


def serialize_check(check: Check) -> dict[str, Any]:
    """
    Serialize a check to a dictionary.

    Args:
        check: Check to serialize

    Returns:
        Dictionary representation
    """
    return {
        "key": check.key,
        "check_id": check.check_id,
        "scope": check.scope,
        "description": check.description,
        "comment": check.comment,
        "extra": check.extra,
        "score": float(check.score),
        "level": check.level.name,
        "observables": [obs.key for obs in check.observables],
    }


def serialize_threat_intel(ti: ThreatIntel) -> dict[str, Any]:
    """
    Serialize threat intel to a dictionary.

    Args:
        ti: Threat intel to serialize

    Returns:
        Dictionary representation
    """
    return {
        "key": ti.key,
        "source": ti.source,
        "observable_key": ti.observable_key,
        "comment": ti.comment,
        "extra": ti.extra,
        "score": float(ti.score),
        "level": ti.level.name,
        "taxonomies": ti.taxonomies,
    }


def serialize_enrichment(enrichment: Enrichment) -> dict[str, Any]:
    """
    Serialize an enrichment to a dictionary.

    Args:
        enrichment: Enrichment to serialize

    Returns:
        Dictionary representation
    """
    return {
        "key": enrichment.key,
        "name": enrichment.name,
        "data": enrichment.data,
        "context": enrichment.context,
    }


def serialize_container(container: Container) -> dict[str, Any]:
    """
    Serialize a container to a dictionary.

    Args:
        container: Container to serialize

    Returns:
        Dictionary representation
    """
    return {
        "key": container.key,
        "path": container.path,
        "description": container.description,
        "checks": [check.key for check in container.checks],
        "sub_containers": {key: serialize_container(sub) for key, sub in container.sub_containers.items()},
        "aggregated_score": float(container.get_aggregated_score()),
        "aggregated_level": container.get_aggregated_level().name,
    }


def serialize_investigation(cv: Cyvest) -> dict[str, Any]:
    """
    Serialize a complete investigation to a dictionary.

    Args:
        cv: Cyvest investigation to serialize

    Returns:
        Dictionary representation suitable for JSON export
    """
    # Build checks organized by scope and containers
    checks_by_scope: dict[str, list[dict[str, Any]]] = {}
    for check in cv.get_all_checks().values():
        scope = check.scope
        if scope not in checks_by_scope:
            checks_by_scope[scope] = []
        checks_by_scope[scope].append(serialize_check(check))

    # Build checks organized by level
    checks_by_level: dict[str, list[str]] = {}
    for check in cv.get_all_checks().values():
        level_name = check.level.name
        if level_name not in checks_by_level:
            checks_by_level[level_name] = []
        checks_by_level[level_name].append(check.key)

    # Build observable graph (root observables with their children)
    def build_obs_tree(obs: Observable, visited: set[str]) -> dict[str, Any]:
        if obs.key in visited:
            return {}
        visited.add(obs.key)

        children = []
        for rel in obs.relationships:
            child_obs = cv.observable_get(rel.target_key)
            if child_obs:
                child_tree = build_obs_tree(child_obs, visited)
                if child_tree:
                    children.append(child_tree)

        return {
            **serialize_observable(obs),
            "observables_children": children,
        }

    root = cv.observable_get_root()
    graph = [build_obs_tree(root, set())] if root else []

    return {
        "score": float(cv.get_global_score()),
        "level": cv.get_global_level().name,
        "observables": {key: serialize_observable(obs) for key, obs in cv.get_all_observables().items()},
        "checks": checks_by_scope,
        "checks_by_level": checks_by_level,
        "threat_intels": {key: serialize_threat_intel(ti) for key, ti in cv.get_all_threat_intels().items()},
        "enrichments": {key: serialize_enrichment(enr) for key, enr in cv.get_all_enrichments().items()},
        "containers": {key: serialize_container(ctr) for key, ctr in cv.get_all_containers().items()},
        "graph": graph,
        "stats": cv.get_statistics(),
        "stats_checks": {
            "checks": len(cv.get_all_checks()),
            "applied": sum(1 for c in cv.get_all_checks().values() if c.level != Level.NONE),
        },
        "data_extraction": {"root_type": cv.observable_get_root().obs_type if cv.observable_get_root() else None},
    }


def save_investigation_json(cv: Cyvest, filepath: str | Path) -> None:
    """
    Save an investigation to a JSON file.

    Args:
        cv: Cyvest investigation to save
        filepath: Path to save the JSON file
    """
    data = serialize_investigation(cv)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=_decimal_to_float)


def generate_markdown_report(cv: Cyvest) -> str:
    """
    Generate a Markdown report of the investigation for LLM consumption.

    Args:
        cv: Cyvest investigation

    Returns:
        Markdown formatted report
    """
    lines = []

    # Header
    lines.append("# Cybersecurity Investigation Report")
    lines.append("")
    lines.append(f"**Global Score:** {cv.get_global_score()}")
    lines.append(f"**Global Level:** {cv.get_global_level().name}")
    lines.append("")

    # Statistics
    lines.append("## Statistics")
    lines.append("")
    stats = cv.get_statistics()
    lines.append(f"- **Total Observables:** {stats['total_observables']}")
    lines.append(f"- **Internal Observables:** {stats['internal_observables']}")
    lines.append(f"- **External Observables:** {stats['external_observables']}")
    lines.append(f"- **Whitelisted Observables:** {stats['whitelisted_observables']}")
    lines.append(f"- **Total Checks:** {stats['total_checks']}")
    lines.append(f"- **Applied Checks:** {stats['applied_checks']}")
    lines.append(f"- **Total Threat Intel:** {stats['total_threat_intel']}")
    lines.append("")

    # Observables by Type and Level
    lines.append("### Observables by Type and Level")
    lines.append("")
    for obs_type, levels in stats.get("observables_by_type_and_level", {}).items():
        lines.append(f"**{obs_type.upper()}:**")
        for level, count in levels.items():
            lines.append(f"  - {level}: {count}")
    lines.append("")

    # Checks by Scope
    lines.append("## Checks by Scope")
    lines.append("")
    for scope, _count in cv.get_statistics().get("checks_by_scope", {}).items():
        lines.append(f"### {scope}")
        lines.append("")
        for check in cv.get_all_checks().values():
            if check.scope == scope and check.level != Level.NONE:
                lines.append(f"- **{check.check_id}** (Score: {check.score}, Level: {check.level.name})")
                lines.append(f"  - Description: {check.description}")
                if check.comment:
                    lines.append(f"  - Comment: {check.comment}")
        lines.append("")

    # Observables
    lines.append("## Observables")
    lines.append("")
    for obs in cv.get_all_observables().values():
        lines.append(f"### {obs.obs_type}: {obs.value}")
        lines.append(f"- **Key:** {obs.key}")
        lines.append(f"- **Score:** {obs.score}")
        lines.append(f"- **Level:** {obs.level.name}")
        lines.append(f"- **Internal:** {obs.internal}")
        lines.append(f"- **Whitelisted:** {obs.whitelisted}")
        if obs.comment:
            lines.append(f"- **Comment:** {obs.comment}")
        if obs.relationships:
            lines.append("- **Relationships:**")
            for rel in obs.relationships:
                lines.append(f"  - {rel.relationship_type} -> {rel.target_key}")
        if obs.threat_intels:
            lines.append("- **Threat Intelligence:**")
            for ti in obs.threat_intels:
                lines.append(f"  - {ti.source}: Score {ti.score}, Level {ti.level.name}")
                if ti.comment:
                    lines.append(f"    - {ti.comment}")
        lines.append("")

    # Enrichments
    if cv.get_all_enrichments():
        lines.append("## Enrichments")
        lines.append("")
        for enr in cv.get_all_enrichments().values():
            lines.append(f"### {enr.name}")
            if enr.context:
                lines.append(f"- **Context:** {enr.context}")
            lines.append(f"- **Data:** {json.dumps(enr.data, indent=2)}")
            lines.append("")

    # Containers
    if cv.get_all_containers():
        lines.append("## Containers")
        lines.append("")
        for ctr in cv.get_all_containers().values():
            lines.append(f"### {ctr.path}")
            lines.append(f"- **Description:** {ctr.description}")
            lines.append(f"- **Aggregated Score:** {ctr.get_aggregated_score()}")
            lines.append(f"- **Aggregated Level:** {ctr.get_aggregated_level().name}")
            lines.append(f"- **Checks:** {len(ctr.checks)}")
            lines.append(f"- **Sub-containers:** {len(ctr.sub_containers)}")
            lines.append("")

    return "\n".join(lines)


def save_investigation_markdown(cv: Cyvest, filepath: str | Path) -> None:
    """
    Save an investigation as a Markdown report.

    Args:
        cv: Cyvest investigation to save
        filepath: Path to save the Markdown file
    """
    markdown = generate_markdown_report(cv)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(markdown)
