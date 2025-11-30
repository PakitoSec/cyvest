"""
Serialization and deserialization for Cyvest investigations.

Provides JSON export/import and Markdown generation for LLM consumption.
"""

import json
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyvest.levels import Level, normalize_level
from cyvest.model import Check, CheckScorePolicy, Container, Enrichment, Observable, Relationship, ThreatIntel
from cyvest.score import ScoreMode

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest


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
            {
                "target_key": rel.target_key,
                "relationship_type": rel.relationship_type,
                "direction": rel.direction if isinstance(rel.direction, str) else rel.direction.value,
            }
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
        "score_policy": check.score_policy.value,
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


def serialize_investigation(cv: "Cyvest") -> dict[str, Any]:
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

    root = cv.observable_get_root()
    root_type_value = None
    if root:
        root_type_value = root.obs_type.value if hasattr(root.obs_type, "value") else str(root.obs_type)

    score_mode_value = ScoreMode.MAX.value
    score_mode = getattr(getattr(cv, "_investigation", None), "_score_engine", None)
    if score_mode and hasattr(score_mode, "_score_mode"):
        mode = score_mode._score_mode
        score_mode_value = mode.value if hasattr(mode, "value") else str(mode)

    return {
        "score": float(cv.get_global_score()),
        "level": cv.get_global_level().name,
        "whitelisted": cv.investigation_is_whitelisted(),
        "whitelists": [
            {
                "identifier": entry.identifier,
                "name": entry.name,
                "justification": entry.justification,
            }
            for entry in cv.investigation_get_whitelists()
        ],
        "observables": {key: serialize_observable(obs) for key, obs in cv.get_all_observables().items()},
        "checks": checks_by_scope,
        "checks_by_level": checks_by_level,
        "threat_intels": {key: serialize_threat_intel(ti) for key, ti in cv.get_all_threat_intels().items()},
        "enrichments": {key: serialize_enrichment(enr) for key, enr in cv.get_all_enrichments().items()},
        "containers": {key: serialize_container(ctr) for key, ctr in cv.get_all_containers().items()},
        "stats": cv.get_statistics(),
        "stats_checks": {
            "checks": len(cv.get_all_checks()),
            "applied": sum(1 for c in cv.get_all_checks().values() if c.level != Level.NONE),
        },
        "data_extraction": {
            "root_type": root_type_value,
            "score_mode": score_mode_value,
        },
    }


def save_investigation_json(cv: "Cyvest", filepath: str | Path) -> None:
    """
    Save an investigation to a JSON file.

    Args:
        cv: Cyvest investigation to save
        filepath: Path to save the JSON file
    """
    data = serialize_investigation(cv)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=_decimal_to_float)


def generate_markdown_report(
    cv: "Cyvest",
    include_containers: bool = False,
    include_enrichments: bool = False,
    include_observables: bool = True,
) -> str:
    """
    Generate a Markdown report of the investigation for LLM consumption.

    Args:
        cv: Cyvest investigation
        include_containers: Include containers section in the report (default: False)
        include_enrichments: Include enrichments section in the report (default: False)
        include_observables: Include observables section in the report (default: True)

    Returns:
        Markdown formatted report
    """
    lines = []

    # Header
    lines.append("# Cybersecurity Investigation Report")
    lines.append("")
    lines.append(f"**Global Score:** {cv.get_global_score()}")
    lines.append(f"**Global Level:** {cv.get_global_level().name}")
    whitelists = cv.investigation_get_whitelists()
    whitelist_status = "Yes" if whitelists else "No"
    lines.append(f"**Whitelisted Investigation:** {whitelist_status}")
    if whitelists:
        lines.append(f"**Whitelist Entries:** {len(whitelists)}")
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

    # Whitelists
    if whitelists:
        lines.append("## Whitelists")
        lines.append("")
        for entry in whitelists:
            lines.append(f"- **{entry.identifier}** - {entry.name}")
            if entry.justification:
                lines.append(f"  - Justification: {entry.justification}")
        lines.append("")

    # Checks by Scope
    lines.append("## Checks by Scope")
    lines.append("")
    for scope, _count in cv.get_statistics().get("checks_by_scope", {}).items():
        lines.append(f"### {scope}")
        lines.append("")
        for check in cv.get_all_checks().values():
            if check.scope == scope and check.level != Level.NONE:
                lines.append(f"- **{check.check_id}**: Score: {check.score}, Level: {check.level.name}")
                lines.append(f"  - Description: {check.description}")
                if check.comment:
                    lines.append(f"  - Comment: {check.comment}")
        lines.append("")

    # Observables
    if include_observables and cv.get_all_observables():
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
                    direction_symbol = {
                        "outbound": "→",
                        "inbound": "←",
                        "bidirectional": "↔",
                    }.get(rel.direction if isinstance(rel.direction, str) else rel.direction.value, "→")
                    lines.append(f"  - {rel.relationship_type} {direction_symbol} {rel.target_key}")
            if obs.threat_intels:
                lines.append("- **Threat Intelligence:**")
                for ti in obs.threat_intels:
                    lines.append(f"  - {ti.source}: Score {ti.score}, Level {ti.level.name}")
                    if ti.comment:
                        lines.append(f"    - {ti.comment}")
            lines.append("")

    # Enrichments
    if include_enrichments and cv.get_all_enrichments():
        lines.append("## Enrichments")
        lines.append("")
        for enr in cv.get_all_enrichments().values():
            lines.append(f"### {enr.name}")
            if enr.context:
                lines.append(f"- **Context:** {enr.context}")
            lines.append(f"- **Data:** {json.dumps(enr.data, indent=2)}")
            lines.append("")

    # Containers
    if include_containers and cv.get_all_containers():
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


def save_investigation_markdown(
    cv: "Cyvest",
    filepath: str | Path,
    include_containers: bool = False,
    include_enrichments: bool = False,
    include_observables: bool = True,
) -> None:
    """
    Save an investigation as a Markdown report.

    Args:
        cv: Cyvest investigation to save
        filepath: Path to save the Markdown file
        include_containers: Include containers section in the report (default: False)
        include_enrichments: Include enrichments section in the report (default: False)
        include_observables: Include observables section in the report (default: True)
    """
    markdown = generate_markdown_report(cv, include_containers, include_enrichments, include_observables)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(markdown)


def load_investigation_json(filepath: str | Path) -> "Cyvest":
    """
    Load an investigation from a JSON file into a Cyvest object.

    Args:
        filepath: Path to the JSON file

    Returns:
        Reconstructed Cyvest investigation
    """
    from cyvest.cyvest import Cyvest
    from cyvest.investigation import Investigation

    with open(filepath, encoding="utf-8") as handle:
        data = json.load(handle)

    data_payload = data.get("data")
    extraction = data.get("data_extraction", {})

    root_type_raw = extraction.get("root_type")
    root_type = "file"
    if root_type_raw:
        root_type = root_type_raw.value if hasattr(root_type_raw, "value") else str(root_type_raw)
    if root_type not in ("file", "artifact"):
        root_type = "file"

    score_mode_raw = extraction.get("score_mode")
    try:
        score_mode = ScoreMode(score_mode_raw) if score_mode_raw else ScoreMode.MAX
    except (TypeError, ValueError):
        score_mode = ScoreMode.MAX

    cv = Cyvest(data=data_payload, root_type=root_type, score_mode=score_mode)

    # Reset internal state to avoid default root pollution
    cv._investigation = Investigation(data_payload, root_type=root_type, score_mode=score_mode)
    whitelists = data.get("whitelists") or []
    for whitelist_info in whitelists:
        try:
            cv._investigation.add_whitelist(
                whitelist_info.get("identifier", ""),
                whitelist_info.get("name", ""),
                whitelist_info.get("justification"),
            )
        except ValueError:
            continue
    # Backward compatibility for older exports
    if data.get("whitelisted") and not cv._investigation.is_whitelisted():
        cv._investigation.add_whitelist("default", "Whitelisted", data.get("whitelisted_reason"))

    def _level_from_name(name: str | None, default: Level) -> Level:
        if not name:
            return default
        try:
            return normalize_level(name)
        except (TypeError, ValueError):
            return default

    # Observables
    for obs_info in data.get("observables", {}).values():
        obs = Observable(
            obs_type=obs_info.get("type", "unknown"),
            value=obs_info.get("value", ""),
            internal=obs_info.get("internal", True),
            whitelisted=obs_info.get("whitelisted", False),
            comment=obs_info.get("comment", ""),
            extra=obs_info.get("extra", {}),
            score=Decimal(str(obs_info.get("score", 0))),
            level=_level_from_name(obs_info.get("level"), Level.INFO),
        )
        obs.key = obs_info.get("key", obs.key)
        obs.relationships = [
            Relationship(
                target_key=rel.get("target_key", ""),
                relationship_type=rel.get("relationship_type", "related-to"),
                direction=rel.get("direction", "outbound"),
            )
            for rel in obs_info.get("relationships", [])
        ]
        obs._generated_by_checks = obs_info.get("generated_by_checks", [])
        cv._investigation.add_observable(obs)

    # Threat intel
    for ti_info in data.get("threat_intels", {}).values():
        ti = ThreatIntel(
            source=ti_info.get("source", ""),
            observable_key=ti_info.get("observable_key", ""),
            comment=ti_info.get("comment", ""),
            extra=ti_info.get("extra", {}),
            score=Decimal(str(ti_info.get("score", 0))),
            level=_level_from_name(ti_info.get("level"), Level.INFO),
            taxonomies=ti_info.get("taxonomies", []),
        )
        ti.key = ti_info.get("key", ti.key)
        observable = cv._investigation.get_observable(ti.observable_key)
        if observable:
            cv._investigation.add_threat_intel(ti, observable)

    # Checks
    for scope_checks in data.get("checks", {}).values():
        for check_info in scope_checks:
            check = Check(
                check_id=check_info.get("check_id", ""),
                scope=check_info.get("scope", ""),
                description=check_info.get("description", ""),
                comment=check_info.get("comment", ""),
                extra=check_info.get("extra", {}),
                score=Decimal(str(check_info.get("score", 0))),
                level=_level_from_name(check_info.get("level"), Level.NONE),
                score_policy=check_info.get("score_policy", CheckScorePolicy.AUTO),
            )
            check.key = check_info.get("key", check.key)
            observable_keys = check_info.get("observables", [])
            for obs_key in observable_keys:
                observable = cv._investigation.get_observable(obs_key)
                if observable:
                    check.add_observable(observable)
            cv._investigation.add_check(check)

    # Enrichments
    for enr_info in data.get("enrichments", {}).values():
        enrichment = Enrichment(
            name=enr_info.get("name", ""), data=enr_info.get("data", {}), context=enr_info.get("context", "")
        )
        enrichment.key = enr_info.get("key", enrichment.key)
        cv._investigation.add_enrichment(enrichment)

    # Containers
    def build_container(container_info: dict[str, Any]) -> Container:
        container = Container(path=container_info.get("path", ""), description=container_info.get("description", ""))
        container.key = container_info.get("key", container.key)

        container = cv._investigation.add_container(container)

        for check_key in container_info.get("checks", []):
            check = cv._investigation.get_check(check_key)
            if check:
                container.add_check(check)

        for sub_info in container_info.get("sub_containers", {}).values():
            sub_container = build_container(sub_info)
            container.add_sub_container(sub_container)

        return container

    for container_info in data.get("containers", {}).values():
        build_container(container_info)

    # Note: Root observable is managed by Investigation, no need to set it here

    return cv
