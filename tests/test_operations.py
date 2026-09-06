"""Batched operations: per-op requirements, ref resolution, all-or-nothing application."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import get_args

import pytest

from cyvest import AutoLink, Cyvest, Operation, Tactic, aapply_operations, apply_operations
from cyvest.facts import ObservableIdentity
from cyvest.operations import DATED_OPS, TacticName, parse_when, validate_operations
from cyvest.resolvers import ObservableResolver

WHEN = "2026-08-07T10:00:00Z"
WHEN_DT = datetime(2026, 8, 7, 10, 0, tzinfo=timezone.utc)


def _op(**fields: object) -> Operation:
    return Operation.model_validate(fields)


class TestValidation:
    @pytest.mark.parametrize(
        ("fields", "message"),
        [
            ({"op": "finding"}, "requires rule_id"),
            ({"op": "threat_intel", "observable": "obs:ipv4:1.1.1.1"}, "requires source"),
            ({"op": "evidence", "evidence_type": "log", "title": "t"}, "content_text or uri"),
            ({"op": "conclusion", "rule_id": "final", "verdict": "MALICIOUS", "weight": 3.0}, "takes no weight"),
            ({"op": "finding", "rule_id": "Bad Rule"}, "kebab-case"),
            ({"op": "finding", "rule_id": "ok", "ref": "1bad"}, "ref"),
            ({"op": "finding", "rule_id": "ok", "extra_json": "[1]"}, "JSON object"),
            ({"op": "observable", "type": "ipv4", "value": "1.1.1.1", "occurred_at": WHEN}, "takes no occurred_at"),
            ({"op": "conclusion", "rule_id": "final", "verdict": "SAFE", "occurred_at": WHEN}, "takes no occurred_at"),
            ({"op": "finding", "rule_id": "ok", "occurred_at": "yesterday at ten"}, "not ISO 8601"),
            ({"op": "evidence", "evidence_type": "log", "title": "t", "uri": "x", "tactic": "impact"}, "no tactic"),
            ({"op": "finding", "rule_id": "ok", "tactic": "TA0001"}, "tactic"),
        ],
    )
    def test_per_op_requirements(self, fields: dict, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            Operation.model_validate(fields)

    def test_the_tactic_literal_cannot_drift_from_the_enum(self) -> None:
        assert set(get_args(TacticName)) == {tactic.value for tactic in Tactic}

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (WHEN, WHEN_DT),
            ("2026-08-07T10:00:00+00:00", WHEN_DT),
            ("2026-08-07T12:00:00+02:00", WHEN_DT),
            ("2026-08-07T10:00:00", WHEN_DT),  # naive reads as UTC
            (" 2026-08-07 10:00:00z ", WHEN_DT),
        ],
    )
    def test_when_is_read_as_utc(self, text: str, expected: datetime) -> None:
        assert parse_when(text) == expected

    def test_refs_must_be_defined_earlier_by_the_right_kind(self) -> None:
        cv = Cyvest()
        errors = validate_operations(
            cv,
            [
                _op(op="link_observable", finding="$f", observable="$o"),
                _op(op="finding", ref="f", rule_id="r"),
                _op(op="link_observable", finding="$f", observable="$f"),
                _op(op="finding", ref="f", rule_id="r2"),
            ],
        )
        assert sorted(error.message for error in errors) == sorted(
            [
                "finding references undefined $f",
                "observable references undefined $o",
                "observable expects observable, $f is a finding",
                "ref $f is defined twice",
            ]
        )

    def test_literal_keys_are_not_checked_before_the_batch_runs(self) -> None:
        assert validate_operations(Cyvest(), [_op(op="threat_intel", observable="obs:ipv4:1.1.1.1", source="vt")]) == []


class TestApply:
    def test_a_batch_creates_and_links_through_refs(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        result = apply_operations(
            cv,
            [
                _op(op="observable", ref="url", type="url", value="hxxp://evil[.]example/x"),
                _op(
                    op="threat_intel",
                    observable="obs:domain:evil.example",
                    source="virustotal",
                    verdict="MALICIOUS",
                    weight=7,
                ),
                _op(
                    op="evidence",
                    ref="e",
                    evidence_type="log_line",
                    title="proxy",
                    content_text="GET /x",
                    source="splunk",
                ),
                _op(op="finding", ref="f", rule_id="url-in-body", name="URL in body", verdict="SUSPICIOUS"),
                _op(op="link_observable", finding="$f", observable="$url"),
                _op(op="link_evidence", finding="$f", evidence="$e"),
                _op(
                    op="relation",
                    parent="$url",
                    child="obs:domain:evil.example",
                    relation_kind="related-to",
                    comment="hosts",
                ),
                _op(op="decision", target="$url", kind="UPHOLD", justification="confirmed by the analyst"),
                _op(op="conclusion", rule_id="triage-verdict", verdict="MALICIOUS", comment="corroborated"),
            ],
        )
        assert result.ok, result.errors
        assert [applied.ref for applied in result.applied[:4]] == ["url", None, "e", "f"]
        finding = cv.finding_get("fnd:url-in-body")
        assert finding.observable_links[0].observable_key == "obs:url:hxxp://evil[.]example/x"
        assert finding.evidence_keys == (result.applied[2].key,)
        assert cv.decision_get("obs:url:hxxp://evil[.]example/x").kind is cv.DECISION.UPHOLD
        assert cv.finding_get("fnd:triage-verdict").is_conclusion
        assert cv.get_global_verdict() is cv.VERDICT.MALICIOUS

    def test_dated_operations_reach_the_facts(self) -> None:
        """Every op in ``DATED_OPS`` lands its ``occurred_at`` on the fact, under that family's own name."""
        cv = Cyvest()
        result = apply_operations(
            cv,
            [
                _op(op="observable", ref="ip", type="ipv4", value="9.9.9.9"),
                _op(op="observable", ref="dom", type="domain", value="c2.example"),
                _op(op="threat_intel", observable="$ip", source="vt", verdict="MALICIOUS", occurred_at=WHEN),
                _op(op="evidence", ref="e", evidence_type="log", title="t", content_text="x", occurred_at=WHEN),
                _op(
                    op="finding",
                    ref="f",
                    rule_id="beacon",
                    name="Beacon to `c2.example`",
                    verdict="SUSPICIOUS",
                    tactic="command-and-control",
                    occurred_at=WHEN,
                ),
                _op(op="relation", parent="$ip", child="$dom", relation_kind="pivot", occurred_at=WHEN),
                _op(op="decision", target="$dom", kind="UPHOLD", justification="seen", occurred_at=WHEN),
            ],
        )
        assert result.ok, result.errors
        assert set(DATED_OPS) == {"finding", "evidence", "threat_intel", "relation", "decision"}
        finding = cv.finding_get("fnd:beacon")
        assert finding.occurred_at == WHEN_DT and finding.tactic is Tactic.COMMAND_AND_CONTROL
        assert cv.evidence_get(result.applied[3].key).captured_at == WHEN_DT
        assert cv.decision_get("obs:domain:c2.example").decided_at == WHEN_DT
        signal = next(iter(cv.observable_get("obs:ipv4:9.9.9.9").threat_intels))
        assert signal.observed_at == WHEN_DT
        (relation,) = cv.relation_get_all().values()
        assert relation.observed_at == WHEN_DT
        # The timeline reads the dates and the tactic; the batch never wrote either to a timeline.
        (entry,) = [entry for entry in cv.timeline() if entry.kind == "finding"]
        assert entry.when == WHEN_DT and entry.dated and entry.tactic is Tactic.COMMAND_AND_CONTROL

    def test_an_undated_update_keeps_the_date_and_the_tactic(self) -> None:
        cv = Cyvest()
        assert apply_operations(
            cv, [_op(op="finding", rule_id="r", verdict="NOTABLE", tactic="execution", occurred_at=WHEN)]
        ).ok
        assert apply_operations(cv, [_op(op="finding", rule_id="r", verdict="SUSPICIOUS", comment="revisited")]).ok
        finding = cv.finding_get("fnd:r")
        assert finding.verdict is cv.VERDICT.SUSPICIOUS
        assert finding.occurred_at == WHEN_DT and finding.tactic is Tactic.EXECUTION

    def test_a_failure_anywhere_leaves_the_investigation_untouched(self) -> None:
        cv = Cyvest()
        cv.observable(cv.OBS.DOMAIN, "kept.example")
        before = cv.io_to_dict()
        result = apply_operations(
            cv,
            [
                _op(op="observable", type="ipv4", value="9.9.9.9"),
                _op(op="finding", rule_id="late"),
                _op(op="decision", target="obs:ipv4:1.1.1.1", kind="REFUTE", justification="missing target"),
            ],
        )
        assert not result.ok
        assert result.errors[0].index == 2
        assert "Unknown observable or finding" in result.errors[0].message
        assert cv.io_to_dict()["facts"] == before["facts"]
        assert cv.observable_get("ipv4", "9.9.9.9") is None

    def test_static_errors_are_all_reported_and_nothing_runs(self) -> None:
        cv = Cyvest()
        result = apply_operations(
            cv,
            [_op(op="observable", type="ipv4", value="9.9.9.9"), _op(op="link_evidence", finding="$f", evidence="$e")],
        )
        assert not result.ok and len(result.errors) == 2
        assert cv.observable_get("ipv4", "9.9.9.9") is None

    def test_returned_keys_are_in_the_store(self) -> None:
        cv = Cyvest()
        result = apply_operations(
            cv, [_op(op="observable", type="ipv4", value="9.9.9.9"), _op(op="finding", rule_id="r")]
        )
        for applied in result.applied:
            assert cv.observable_get(applied.key) or cv.finding_get(applied.key)

    @pytest.mark.anyio
    async def test_async_apply_goes_through_the_resolvers(self) -> None:
        async def resolve(alias):  # noqa: ANN001, ANN202
            return ObservableIdentity(type="user", subtype="username", namespace="corp", value=alias.value.upper())

        cv = Cyvest()
        cv.observable_resolver_register(
            ObservableResolver(name="dir", source_types={("user", "username")}, aresolve=resolve)
        )
        result = await aapply_operations(
            cv, [_op(op="observable", type="user", subtype="username", namespace="default", value="jdoe")]
        )
        assert result.ok
        assert result.applied[0].key == "obs:user:username:corp:JDOE"

    def test_sync_apply_reports_an_async_resolver_instead_of_hanging(self) -> None:
        async def resolve(alias):  # noqa: ANN001, ANN202
            return None

        cv = Cyvest()
        cv.observable_resolver_register(
            ObservableResolver(name="dir", source_types={("user", "username")}, aresolve=resolve)
        )
        result = apply_operations(
            cv, [_op(op="observable", type="user", subtype="username", namespace="d", value="jdoe")]
        )
        assert not result.ok and "async" in result.errors[0].message


class TestObservableIdentity:
    def test_a_type_that_needs_a_subtype_gets_it_inferred(self) -> None:
        cv = Cyvest()
        result = apply_operations(
            cv,
            [
                _op(op="observable", type="file", value="msedge.exe"),
                _op(op="observable", type="host", value="W5CD409G987"),
                _op(op="observable", type="host", value="wks.corp.example"),
                _op(op="observable", type="user", value="OX1155"),
            ],
        )
        assert result.ok, result.errors
        observables = [o for o in cv.observable_get_all().values() if o.value != "__cyvest_root__"]
        identities = {o.value: (o.subtype, o.namespace) for o in observables}
        assert identities["msedge.exe"][0] is not None and identities["msedge.exe"][0].value == "path"
        assert identities["W5CD409G987"][0].value == "hostname"
        assert identities["wks.corp.example"][0].value == "fqdn"
        assert identities["OX1155"][0].value == "username"

    def test_a_stated_subtype_is_not_overridden(self) -> None:
        cv = Cyvest()
        result = apply_operations(cv, [_op(op="observable", type="file", subtype="sha256", value="a" * 64)])
        assert result.ok, result.errors
        assert result.applied[0].key == f"obs:file:sha256:{'a' * 64}"

    def test_recording_an_existing_observable_keeps_what_it_already_carries(self) -> None:
        cv = Cyvest()
        cv.observable_create(
            "host",
            "W5CD409G987",
            subtype="hostname",
            namespace="default",
            internal=True,
            comment="workstation, Marseille",
        )
        result = apply_operations(cv, [_op(op="observable", type="host", value="W5CD409G987")])
        assert result.ok, result.errors
        host = cv.observable_get(result.applied[0].key)
        assert host.internal is True
        assert host.comment == "workstation, Marseille"
