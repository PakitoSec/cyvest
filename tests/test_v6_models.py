from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyvest import Cyvest, ObservableSubtype, ObservableType
from cyvest.io_serialization import load_investigation_dict, migrate_v5_to_v6
from cyvest.model import Evidence, Observable


def test_email_and_user_email_are_distinct_semantic_observables() -> None:
    cv = Cyvest()

    address = cv.observable(ObservableType.EMAIL, "User@Example.COM")
    account = cv.observable(
        ObservableType.USER,
        "User@Example.COM",
        subtype=ObservableSubtype.USER_EMAIL,
    )

    assert address.key == "obs:email:user@example.com"
    assert account.key == "obs:user:email:user@example.com"
    assert address.key != account.key


def test_scoped_observable_subtypes_require_namespace() -> None:
    with pytest.raises(ValueError, match="requires a namespace"):
        Observable(
            obs_type=ObservableType.PROCESS,
            subtype=ObservableSubtype.PROCESS_PID,
            value="0042",
        )

    process = Observable(
        obs_type=ObservableType.PROCESS,
        subtype=ObservableSubtype.PROCESS_PID,
        namespace="host-01",
        value="0042",
    )
    assert process.key == "obs:process:pid:host-01:42"

    file_path = Observable(
        obs_type=ObservableType.FILE,
        subtype=ObservableSubtype.FILE_PATH,
        namespace="host-01",
        value="/opt/Agent/agent.exe",
    )
    assert file_path.key.startswith("obs:file:path:host-01:")


def test_image_path_is_not_a_process_subtype() -> None:
    with pytest.raises(ValueError, match="not valid"):
        Observable(
            obs_type=ObservableType.PROCESS,
            subtype=ObservableSubtype.FILE_PATH,
            namespace="host-01",
            value="/usr/bin/bash",
        )


def test_command_line_keys_are_sha256_based() -> None:
    command = Observable(
        obs_type=ObservableType.COMMAND_LINE,
        value="powershell.exe -EncodedCommand AAAA",
    )

    assert command.key.startswith("obs:command_line:sha256:")
    assert len(command.key.rsplit(":", 1)[-1]) == 64


def test_evidence_many_to_many_links_survive_roundtrip() -> None:
    cv = Cyvest(investigation_id="01ARZ3NDEKTSV4RRFFQ69G5FAV")
    evidence = cv.evidence(
        "edr_event",
        "Process creation",
        "example-edr",
        external_id="event-42",
        content={"pid": 42, "image": "/usr/bin/bash"},
        captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    first = cv.finding("suspicious-process", "Suspicious process").link_evidence(evidence)
    second = cv.finding("unexpected-shell", "Unexpected shell").link_evidence(evidence)

    assert evidence.finding_links == sorted([first.key, second.key])

    loaded = load_investigation_dict(cv.io_to_dict())
    loaded_evidence = loaded.evidence_get(evidence.key)
    assert loaded_evidence is not None
    assert loaded_evidence.finding_links == sorted([first.key, second.key])


def test_evidence_conflict_is_rejected() -> None:
    cv = Cyvest()
    cv.evidence(
        "event",
        "Original",
        "sensor",
        external_id="42",
        content={"value": "a"},
    )

    with pytest.raises(ValueError, match="Evidence conflict"):
        cv.evidence(
            "event",
            "Conflicting",
            "sensor",
            external_id="42",
            content={"value": "b"},
        )


def test_content_addressed_evidence_is_deterministic() -> None:
    first = Evidence(
        evidence_type="log",
        title="First",
        source="sensor",
        content={"b": 2, "a": 1},
    )
    second = Evidence(
        evidence_type="log",
        title="Second",
        source="sensor",
        content={"a": 1, "b": 2},
    )
    assert first.key == second.key


def test_migrate_v5_to_v6_rewrites_findings_and_preserves_email() -> None:
    v5 = {
        "investigation_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "investigation_name": "legacy",
        "score": 0,
        "level": "NONE",
        "whitelisted": False,
        "whitelists": [],
        "audit_log": [],
        "observables": {
            "obs:file:root": {
                "type": "file",
                "value": "root",
                "internal": False,
                "whitelisted": False,
                "comment": "",
                "extra": {},
                "score": 0,
                "level": "INFO",
                "threat_intels": [],
                "relationships": [],
                "key": "obs:file:root",
            },
            "obs:email:user@example.com": {
                "type": "email",
                "value": "User@Example.COM",
                "internal": False,
                "whitelisted": False,
                "comment": "",
                "extra": {},
                "score": 0,
                "level": "INFO",
                "threat_intels": [],
                "relationships": [],
                "key": "obs:email:user@example.com",
            },
        },
        "checks": {
            "chk:sender": {
                "check_name": "sender",
                "description": "Sender analysis",
                "comment": "",
                "extra": {},
                "score": 0,
                "level": "INFO",
                "origin_investigation_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "observable_links": [
                    {
                        "observable_key": "obs:email:user@example.com",
                        "propagation_mode": "LOCAL_ONLY",
                    }
                ],
                "key": "chk:sender",
            }
        },
        "threat_intels": {},
        "enrichments": {},
        "tags": {
            "tag:email": {
                "name": "email",
                "description": "",
                "checks": ["chk:sender"],
                "key": "tag:email",
            }
        },
        "data_extraction": {"root_type": "file", "score_mode_obs": "max"},
    }

    migrated = migrate_v5_to_v6(v5)

    assert migrated["schema_version"] == "6.0.0"
    assert "fnd:sender" in migrated["findings"]
    assert migrated["findings"]["fnd:sender"]["evidence_links"] == []
    assert migrated["tags"]["tag:email"]["findings"] == ["fnd:sender"]
    assert migrated["observables"]["obs:email:user@example.com"]["type"] == "email"
    assert migrated["evidences"] == {}
