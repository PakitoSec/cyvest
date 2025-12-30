"""
Serialization and deserialization for Cyvest investigations.

Provides JSON export/import and Markdown generation for LLM consumption.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyvest.levels import Level, normalize_level
from cyvest.model import AuditEvent, Check, Container, Enrichment, Observable, Relationship, ThreatIntel
from cyvest.model_enums import ObservableType
from cyvest.model_schema import InvestigationSchema
from cyvest.score import ScoreMode

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest
    from cyvest.investigation import Investigation


def serialize_investigation(inv: Investigation) -> InvestigationSchema:
    """
    Serialize a complete investigation to an InvestigationSchema.

    Uses InvestigationSchema for validation and automatic serialization via
    Pydantic's field_serializer decorators.

    Args:
        inv: Investigation to serialize

    Returns:
        InvestigationSchema instance (use .model_dump() for dict)
    """
    inv._refresh_check_links()
    observables = dict(inv.get_all_observables())
    threat_intels = dict(inv.get_all_threat_intels())
    enrichments = dict(inv.get_all_enrichments())
    containers = dict(inv.get_all_containers())

    # Build checks organized by scope (resolve proxies)
    checks_by_scope: dict[str, list[Check]] = {}
    for check in inv.get_all_checks().values():
        if check.scope not in checks_by_scope:
            checks_by_scope[check.scope] = []
        checks_by_scope[check.scope].append(check)

    # Build checks organized by level
    checks_by_level: dict[str, list[str]] = {}
    for check in inv.get_all_checks().values():
        if check.level.name not in checks_by_level:
            checks_by_level[check.level.name] = []
        checks_by_level[check.level.name].append(check.key)

    # Get root type
    root = inv.get_root()
    root_type_value = root.obs_type.value

    # Build and validate using Pydantic model
    started_at = getattr(inv, "_started_at", None)
    if not isinstance(started_at, datetime):
        started_at = datetime.now(timezone.utc)
    elif started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    else:
        started_at = started_at.astimezone(timezone.utc)

    investigation = InvestigationSchema(
        investigation_id=inv.investigation_id,
        investigation_name=inv.investigation_name,
        started_at=started_at,
        score=inv.get_global_score(),
        level=inv.get_global_level(),
        whitelisted=inv.is_whitelisted(),
        whitelists=list(inv.get_whitelists()),
        event_log=inv.get_event_log(),
        observables=observables,
        checks=checks_by_scope,
        checks_by_level=checks_by_level,
        threat_intels=threat_intels,
        enrichments=enrichments,
        containers=containers,
        stats=inv.get_statistics(),
        data_extraction={
            "root_type": root_type_value,
            "score_mode_obs": inv._score_engine._score_mode_obs.value,
        },
    )

    return investigation


def save_investigation_json(inv: Investigation, filepath: str | Path) -> None:
    """
    Save an investigation to a JSON file.

    Args:
        inv: Investigation to save
        filepath: Path to save the JSON file
    """
    data = serialize_investigation(inv)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(data.model_dump_json(indent=2, by_alias=True))


def generate_markdown_report(
    inv: Investigation,
    include_containers: bool = False,
    include_enrichments: bool = False,
    include_observables: bool = True,
) -> str:
    """
    Generate a Markdown report of the investigation for LLM consumption.

    Args:
        inv: Investigation
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
    if getattr(inv, "investigation_name", None):
        lines.append(f"**Investigation Name:** {inv.investigation_name}")
    lines.append(f"**Global Score:** {inv.get_global_score():.2f}")
    lines.append(f"**Global Level:** {inv.get_global_level().name}")
    whitelists = inv.get_whitelists()
    whitelist_status = "Yes" if whitelists else "No"
    lines.append(f"**Whitelisted Investigation:** {whitelist_status}")
    if whitelists:
        lines.append(f"**Whitelist Entries:** {len(whitelists)}")
    lines.append("")

    # Statistics
    lines.append("## Statistics")
    lines.append("")
    stats = inv.get_statistics()
    lines.append(f"- **Total Observables:** {stats.total_observables}")
    lines.append(f"- **Internal Observables:** {stats.internal_observables}")
    lines.append(f"- **External Observables:** {stats.external_observables}")
    lines.append(f"- **Whitelisted Observables:** {stats.whitelisted_observables}")
    lines.append(f"- **Total Checks:** {stats.total_checks}")
    lines.append(f"- **Applied Checks:** {stats.applied_checks}")
    lines.append(f"- **Total Threat Intel:** {stats.total_threat_intel}")
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
    for scope, _count in inv.get_statistics().checks_by_scope.items():
        lines.append(f"### {scope}")
        lines.append("")
        for check in inv.get_all_checks().values():
            if check.scope == scope and check.level != Level.NONE:
                lines.append(f"- **{check.check_id}**: Score: {check.score_display}, Level: {check.level.name}")
                lines.append(f"  - Description: {check.description}")
                if check.comment:
                    lines.append(f"  - Comment: {check.comment}")
        lines.append("")

    # Observables
    if include_observables and inv.get_all_observables():
        lines.append("## Observables")
        lines.append("")
        for obs in inv.get_all_observables().values():
            lines.append(f"### {obs.obs_type}: {obs.value}")
            lines.append(f"- **Key:** {obs.key}")
            lines.append(f"- **Score:** {obs.score_display}")
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
                    lines.append(f"  - {ti.source}: Score {ti.score_display}, Level {ti.level.name}")
                    if ti.comment:
                        lines.append(f"    - {ti.comment}")
            lines.append("")

    # Enrichments
    if include_enrichments and inv.get_all_enrichments():
        lines.append("## Enrichments")
        lines.append("")
        for enr in inv.get_all_enrichments().values():
            lines.append(f"### {enr.name}")
            if enr.context:
                lines.append(f"- **Context:** {enr.context}")
            lines.append(f"- **Data:** {json.dumps(enr.data, indent=2)}")
            lines.append("")

    # Containers
    if include_containers and inv.get_all_containers():
        lines.append("## Containers")
        lines.append("")
        for ctr in inv.get_all_containers().values():
            lines.append(f"### {ctr.path}")
            lines.append(f"- **Description:** {ctr.description}")
            lines.append(f"- **Aggregated Score:** {ctr.get_aggregated_score():.2f}")
            lines.append(f"- **Aggregated Level:** {ctr.get_aggregated_level().name}")
            lines.append(f"- **Checks:** {len(ctr.checks)}")
            lines.append(f"- **Sub-containers:** {len(ctr.sub_containers)}")
            lines.append("")

    return "\n".join(lines)


def save_investigation_markdown(
    inv: Investigation,
    filepath: str | Path,
    include_containers: bool = False,
    include_enrichments: bool = False,
    include_observables: bool = True,
) -> None:
    """
    Save an investigation as a Markdown report.

    Args:
        inv: Investigation to save
        filepath: Path to save the Markdown file
        include_containers: Include containers section in the report (default: False)
        include_enrichments: Include enrichments section in the report (default: False)
        include_observables: Include observables section in the report (default: True)
    """
    markdown = generate_markdown_report(inv, include_containers, include_enrichments, include_observables)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(markdown)


def load_investigation_json(filepath: str | Path) -> Cyvest:
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

    investigation_id = data.get("investigation_id")
    if not isinstance(investigation_id, str) or not investigation_id.strip():
        raise ValueError("Serialized investigation must include 'investigation_id'.")

    root_data = data.get("root_data")
    extraction = data.get("data_extraction", {})

    root_type_raw = extraction.get("root_type")
    try:
        root_type = ObservableType.normalize_root_type(root_type_raw)
    except (TypeError, ValueError):
        root_type = ObservableType.FILE

    score_mode_raw = extraction.get("score_mode_obs")
    try:
        score_mode = ScoreMode(score_mode_raw) if score_mode_raw else ScoreMode.MAX
    except (TypeError, ValueError):
        score_mode = ScoreMode.MAX

    cv = Cyvest(root_data=root_data, root_type=root_type, score_mode_obs=score_mode)

    # Reset internal state to avoid default root pollution
    cv._investigation = Investigation(
        root_data,
        root_type=root_type,
        score_mode_obs=score_mode,
        investigation_id=investigation_id,
    )
    cv._investigation._audit_enabled = False
    cv._investigation._event_log = []

    investigation_name = data.get("investigation_name")
    if isinstance(investigation_name, str):
        cv._investigation.investigation_name = investigation_name

    started_at_raw = data.get("started_at")
    if isinstance(started_at_raw, str) and started_at_raw.strip():
        started_at_candidate = started_at_raw.strip()
        if started_at_candidate.endswith("Z"):
            started_at_candidate = started_at_candidate[:-1] + "+00:00"
        try:
            started_at = datetime.fromisoformat(started_at_candidate)
        except ValueError:
            started_at = None
        if isinstance(started_at, datetime):
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            else:
                started_at = started_at.astimezone(timezone.utc)
            cv._investigation._started_at = started_at

    # Load whitelists using Pydantic validation
    whitelists = data.get("whitelists") or []
    for whitelist_info in whitelists:
        try:
            identifier = str(whitelist_info.get("identifier", "")).strip()
            name = str(whitelist_info.get("name", "")).strip()
            if identifier and name:
                cv._investigation.add_whitelist(
                    identifier,
                    name,
                    whitelist_info.get("justification"),
                )
        except ValueError:
            continue

    # Observables - leverage Pydantic model_validate (two-pass so root can merge after others exist)
    new_root_key = cv._investigation.get_root().key
    root_obs_info: dict[str, Any] | None = None
    other_obs_infos: list[dict[str, Any]] = []
    for obs_info in data.get("observables", {}).values():
        obs_key = obs_info.get("key", "")
        if obs_key == new_root_key:
            root_obs_info = obs_info
            continue
        other_obs_infos.append(obs_info)

    for obs_info in other_obs_infos:
        # Prepare data for Pydantic validation
        obs_data = {
            "obs_type": obs_info.get("type", "unknown"),
            "value": obs_info.get("value", ""),
            "internal": obs_info.get("internal", True),
            "whitelisted": obs_info.get("whitelisted", False),
            "comment": obs_info.get("comment", ""),
            "extra": obs_info.get("extra", {}),
            "score": Decimal(str(obs_info.get("score", 0))),
            "level": obs_info.get("level", "INFO"),
            "key": obs_info.get("key", ""),
            "relationships": [Relationship.model_validate(rel) for rel in obs_info.get("relationships", [])],
        }
        obs = Observable.model_validate(obs_data)
        cv._investigation.add_observable(obs)

    if root_obs_info is not None:
        # Merge serialized root into the live root (preserves relationships, etc.).
        root_data = {
            "obs_type": root_obs_info.get("type", root_type),
            "value": "root",
            "internal": root_obs_info.get("internal", False),
            "whitelisted": root_obs_info.get("whitelisted", False),
            "comment": root_obs_info.get("comment", ""),
            "extra": root_obs_info.get("extra", root_data),
            "score": Decimal(str(root_obs_info.get("score", 0))),
            "level": root_obs_info.get("level", "INFO"),
            "key": new_root_key,
            "relationships": [Relationship.model_validate(rel) for rel in root_obs_info.get("relationships", [])],
        }
        root_obs = Observable.model_validate(root_data)
        cv._investigation.add_observable(root_obs)

    # Threat intel - leverage Pydantic model_validate
    for ti_info in data.get("threat_intels", {}).values():
        raw_taxonomies = ti_info.get("taxonomies", []) or []
        normalized_taxonomies: list[Any] = []
        for taxonomy in raw_taxonomies:
            if isinstance(taxonomy, dict) and "level" in taxonomy:
                taxonomy = dict(taxonomy)
                taxonomy["level"] = normalize_level(taxonomy["level"])
            normalized_taxonomies.append(taxonomy)

        ti_data = {
            "source": ti_info.get("source", ""),
            "observable_key": ti_info.get("observable_key", ""),
            "comment": ti_info.get("comment", ""),
            "extra": ti_info.get("extra", {}),
            "score": Decimal(str(ti_info.get("score", 0))),
            "level": ti_info.get("level", "INFO"),
            "taxonomies": normalized_taxonomies,
            "key": ti_info.get("key", ""),
        }
        ti = ThreatIntel.model_validate(ti_data)
        observable = cv._investigation.get_observable(ti.observable_key)
        if observable:
            cv._investigation.add_threat_intel(ti, observable)

    # Checks - leverage Pydantic model_validate
    for scope_checks in data.get("checks", {}).values():
        for check_info in scope_checks:
            raw_links = check_info.get("observable_links", []) or []
            normalized_links = []
            for link in raw_links:
                if isinstance(link, dict):
                    normalized_links.append(
                        {
                            "observable_key": link.get("observable_key", ""),
                            "propagation_mode": link.get("propagation_mode", "LOCAL_ONLY"),
                        }
                    )
                else:
                    normalized_links.append(link)
            check_data = {
                "check_id": check_info.get("check_id", ""),
                "scope": check_info.get("scope", ""),
                "description": check_info.get("description", ""),
                "comment": check_info.get("comment", ""),
                "extra": check_info.get("extra", {}),
                "score": Decimal(str(check_info.get("score", 0))),
                "level": check_info.get("level", "NONE"),
                "origin_investigation_id": check_info.get("origin_investigation_id")
                or cv._investigation.investigation_id,
                "observable_links": normalized_links,
                "key": check_info.get("key", ""),
            }
            check = Check.model_validate(check_data)
            cv._investigation.add_check(check)

    # Enrichments - leverage Pydantic model_validate
    for enr_info in data.get("enrichments", {}).values():
        enr_data = {
            "name": enr_info.get("name", ""),
            "data": enr_info.get("data", {}),
            "context": enr_info.get("context", ""),
            "key": enr_info.get("key", ""),
        }
        enrichment = Enrichment.model_validate(enr_data)
        cv._investigation.add_enrichment(enrichment)

    # Containers
    def build_container(container_info: dict[str, Any]) -> Container:
        container_data = {
            "path": container_info.get("path", ""),
            "description": container_info.get("description", ""),
            "key": container_info.get("key", ""),
        }
        container = Container.model_validate(container_data)
        container = cv._investigation.add_container(container)

        for check_key in container_info.get("checks", []):
            check = cv._investigation.get_check(check_key)
            if check:
                cv._investigation.add_check_to_container(container.key, check.key)

        for sub_info in container_info.get("sub_containers", {}).values():
            sub_container = build_container(sub_info)
            cv._investigation.add_sub_container(container.key, sub_container.key)

        return container

    for container_info in data.get("containers", {}).values():
        build_container(container_info)

    cv._investigation._refresh_check_links()

    event_log = []
    for event_info in data.get("event_log", []) or []:
        try:
            event_log.append(AuditEvent.model_validate(event_info))
        except Exception:
            continue
    cv._investigation._event_log = event_log
    cv._investigation._audit_enabled = True

    return cv
