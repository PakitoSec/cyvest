"""The agent seam: captured evidence, a facts-only view and reference checks."""

from __future__ import annotations

from cyvest import Cyvest
from cyvest.agent import facts_status, ledger_delta, missing_references, record_tool_output


def _case() -> tuple[Cyvest, str, str]:
    cv = Cyvest()
    ip = cv.observable_create("ipv4", "203.0.113.7", internal=False)
    cv.observable_add_threat_intel(ip.key, "virustotal", verdict="MALICIOUS")
    evidence = record_tool_output(
        cv, source="splunk", call_id="toolu_01", tool="run_query", title="Logons", output=[{"src": "203.0.113.7"}]
    )
    finding = cv.finding_create("logon-from-ip", "Logon from 203.0.113.7", "seen", verdict="SUSPICIOUS")
    cv.finding_link_evidence(finding.key, evidence.key)
    cv.finding_link_observable(finding.key, ip.key)
    return cv, ip.key, evidence.key


def test_a_replayed_tool_call_is_one_evidence_and_big_outputs_are_bounded() -> None:
    cv, _ip, key = _case()
    assert key == "evd:splunk:toolu_01"
    record_tool_output(cv, source="splunk", call_id="toolu_01", tool="run_query", title="Logons", output=[{"x": 1}])
    assert len(cv.evidence_get_all()) == 1
    big = record_tool_output(
        cv, source="splunk", call_id="toolu_02", tool="q", title="Big", output="a" * 50, max_chars=10
    )
    assert big.content["truncated"] is True and len(big.content["output"]) == 10


def test_the_status_shows_facts_but_neither_score_nor_hidden_signals() -> None:
    cv, ip, evidence = _case()
    hidden = facts_status(cv)
    assert "logon-from-ip" in hidden and evidence in hidden
    assert "virustotal" not in hidden and "score" not in hidden.lower()
    assert "virustotal: MALICIOUS" in facts_status(cv, signals_for={ip})


def test_the_delta_and_reference_checks_name_keys() -> None:
    cv, ip, evidence = _case()
    before = cv.io_to_dict()
    finding = cv.finding_create("benign-admin", "Admin task", "ok", verdict="SAFE")
    cv.finding_link_observable(finding.key, ip)
    assert ledger_delta(before, cv.io_to_dict()) == {"findings": [finding.key]}
    assert "Disagreements" in facts_status(cv)
    assert missing_references(cv, evidence_keys=[evidence, "evd:splunk:nope"], observable_keys=[ip]) == [
        "evd:splunk:nope"
    ]
