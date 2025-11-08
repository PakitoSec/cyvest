from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from .models import Container, Level, Observable, ResultCheck, ThreatIntel

if TYPE_CHECKING:
    from .visitors import Report


def _to_json_threat_intel(ti: ThreatIntel) -> dict[str, Any]:
    return {
        "name": ti.name,
        "analyzer": ti.name,
        "display_name": ti.display_name,
        "score": ti.score,
        "level": ti.level.name,
        "comment": ti.comment,
        "extra": ti.extra,
        "taxonomies": ti.taxonomies,
    }


def _observable_to_json(
    report: Report,
    observable: Observable,
    *,
    max_deep_child: int | None,
    max_deep_parent: int | None,
) -> dict[str, Any]:
    def _rec(
        obj: Observable,
        deep_child: int | None,
        deep_parent: int | None,
        already_seen: list[str] | None = None,
    ) -> dict[str, Any]:
        if already_seen is None:
            already_seen = []
        threat_intel_json = {k: _to_json_threat_intel(v) for k, v in obj.threat_intels.items()}
        if obj.full_key in already_seen:
            return {
                "full_key": obj.full_key,
                "score": obj.score,
                "level": obj.level.name,
                "obs_type": obj.obs_type.name,
                "obs_value": obj.obs_value,
                "whitelisted": obj.whitelisted,
                "threat_intels": threat_intel_json,
                "observables_children": [child for child in obj.observables_children],
                "observables_parents": [parent for parent in obj.observables_parents],
                "generated_by": list(obj.generated_by),
            }
        new_seen = [*already_seen, obj.full_key]
        if deep_child is not None:
            if (max_deep_child is not None and deep_child >= max_deep_child) or deep_child < 0:
                observables_children: list[Any] = [child for child in obj.observables_children]
            else:
                rec_deep_child = deep_child + 1 if deep_child is not None else None
                observables_children = [
                    _rec(child, rec_deep_child, -1, new_seen) for child in obj.observables_children.values()
                ]
        else:
            observables_children = [_rec(child, None, -1, new_seen) for child in obj.observables_children.values()]
        if deep_parent is not None:
            if (max_deep_parent is not None and deep_parent >= max_deep_parent) or deep_parent < 0:
                observables_parents: list[Any] = [parent for parent in obj.observables_parents]
            else:
                rec_deep_parent = deep_parent + 1 if deep_parent is not None else None
                observables_parents = [
                    _rec(parent, -1, rec_deep_parent, new_seen) for parent in obj.observables_parents.values()
                ]
        else:
            observables_parents = [_rec(parent, -1, None, new_seen) for parent in obj.observables_parents.values()]
        return {
            "full_key": obj.full_key,
            "score": obj.score,
            "level": obj.level.name,
            "obs_type": obj.obs_type.name,
            "obs_value": obj.obs_value,
            "whitelisted": obj.whitelisted,
            "threat_intels": threat_intel_json,
            "observables_children": observables_children,
            "observables_parents": observables_parents,
            "generated_by": list(obj.generated_by),
        }

    if max_deep_child is None:
        start_child = None
    else:
        start_child = -1 if max_deep_child < 0 else 0
    if max_deep_parent is None:
        start_parent = None
    else:
        start_parent = -1 if max_deep_parent < 0 else 0
    return _rec(observable, start_child, start_parent)


def _result_check_to_json(report: Report, rc: ResultCheck) -> dict[str, Any]:
    observables_json = [
        _observable_to_json(report, observable, max_deep_child=2, max_deep_parent=1)
        for observable in rc.observables.values()
    ]
    return {
        "full_key": rc.full_key,
        "short_key": rc.short_key,
        "scope": rc.scope.name if rc.scope else "UNKNOWN",
        "path": rc.path,
        "identifier": rc.identifier,
        "score": rc.score,
        "level": rc.level.name,
        "description": rc.description,
        "details": rc.details,
        "observables": observables_json,
    }


def _container_to_json(report: Report, container: Container) -> dict[str, Any]:
    payload = {
        "full_key": container.full_key,
        "scope": container.scope.name if container.scope else "UNKNOWN",
        "path": container.path,
        "identifier": container.identifier,
        "score": container.score,
        "level": container.level.name,
        "description": container.description,
        "details": container.details,
        "nb_checks": container.nb_checks,
        "container": {},
    }
    for child in container.children:
        _insert_node(report, payload["container"], child)
    return payload


def _insert_node(report: Report, target: dict[str, Any], node: Container | ResultCheck) -> None:
    if isinstance(node, Container):
        serialized = _container_to_json(report, node)
    else:
        serialized = _result_check_to_json(report, node)
    if node.identifier:
        bucket = target.setdefault(node.path, [])
        bucket.append(serialized)
    else:
        target[node.path] = serialized


def report_to_json(report: Report) -> dict[str, Any]:
    data = dict(report.json)
    data.pop("@meta", None)

    checks_root: dict[str, Any] = {}
    for scope_name, nodes in report.tree.iter_roots():
        scope_dict: dict[str, Any] = {}
        for node in nodes:
            _insert_node(report, scope_dict, node)
        checks_root[scope_name] = scope_dict

    result_checks = list(report.tree.result_checks())
    applied_checks = [rc for rc in result_checks if rc.level > Level.NONE]

    checks_by_level: dict[str, list[str]] = {}
    grouped = defaultdict(list)
    for rc in result_checks:
        grouped[rc.level.name].append((rc.score, rc.full_key))
    for level_name, entries in grouped.items():
        entries.sort(key=lambda item: item[0], reverse=True)
        checks_by_level[level_name] = [full_key for _, full_key in entries]

    json_graph = [
        _observable_to_json(report, observable, max_deep_child=None, max_deep_parent=-1)
        for observable in report.observable_graph.root_observables()
    ]

    return {
        "score": report.global_score,
        "level": report.global_level.name,
        "stats": report.reduce_stats({}),
        "stats_checks": {
            "applied": len(applied_checks),
            "checks": len(result_checks),
            "obs": len(report.observables),
            "enrichments": len(report.enrichments),
        },
        "checks_by_level": checks_by_level,
        "checks": checks_root,
        "graph": json_graph,
        "data": data,
        "annotations": report.annotations,
    }


def reduce_report_json(json_report: dict[str, Any]) -> dict[str, Any]:
    checks_root = json_report.get("checks", {})
    flattened_checks: dict[str, Any] = {}
    if isinstance(checks_root, dict):
        _reduce_report_rec(checks_root, delete_none=True, all_checks=flattened_checks)
    json_report["checks"] = flattened_checks
    json_report.pop("graph", None)
    json_report.pop("html_report", None)
    return json_report


def _reduce_report_rec(container, delete_none=False, all_checks=None):
    if all_checks is None:
        all_checks = {}
    to_remove = []
    for key, value in container.items():
        if isinstance(value, list):
            to_remove_in_list = []
            for data in value:
                if data["level"] == "NONE" and delete_none is True:
                    to_remove_in_list.append(key)
                elif "container" in data:
                    _reduce_report_rec(data["container"], delete_none=delete_none, all_checks=all_checks)
                else:
                    all_checks[data["full_key"]] = data
                    for obs in data["observables"]:
                        obs["observables_children"] = [
                            child_obs["full_key"] for child_obs in obs["observables_children"]
                        ]
                        obs["observables_parents"] = [
                            parent_obs["full_key"] for parent_obs in obs["observables_parents"]
                        ]
                        for ti in obs["threat_intels"].values():
                            ti.pop("extra", None)
            for entry in to_remove_in_list:
                value.remove(entry)
        else:
            if value["level"] == "NONE" and delete_none is True:
                to_remove.append(key)
            elif "container" in value:
                _reduce_report_rec(value["container"], delete_none=delete_none, all_checks=all_checks)
            else:
                all_checks[value["full_key"]] = value
    for key in to_remove:
        del container[key]
