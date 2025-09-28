from cyvest import Action, Level, ObsType, ThreatIntel


def test_action_records_high_risk_intel():
    action = Action(level_threshold=Level.SUSPICIOUS)

    threat_intel = ThreatIntel(
        name="sandbox",
        display_name="Sandbox",
        obs_value="artifact.exe",
        obs_type=ObsType.FILE,
        score=7.5,
        level=Level.MALICIOUS,
        extra={"source": "sandbox", "whitelisted": False},
    )

    recorded = action.visit_threat_intel(threat_intel)

    assert recorded is threat_intel
    assert len(action.actions) == 1
    entry = action.actions[0]
    assert entry["impact"] == Level.MALICIOUS.name
    assert "artifact.exe" in entry["description"]


def test_action_threshold_filters_lower_levels():
    action = Action(level_threshold=Level.MALICIOUS)

    benign_intel = ThreatIntel(
        name="intel",
        display_name="Intel",
        obs_value="artifact.exe",
        obs_type=ObsType.FILE,
        score=1.0,
        level=Level.SUSPICIOUS,
    )

    action.visit_threat_intel(benign_intel)

    assert action.actions == []
