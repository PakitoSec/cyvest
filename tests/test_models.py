import pytest

from cyvest import Container, Level, Observable, ObsType, Report, ResultCheck, Scope


def build_report(*, graph: bool = False) -> Report:
    return Report(graph=graph)


def test_result_check_update_promotes_score():
    rc_low = ResultCheck(path="body/url", scope=Scope.BODY, level=Level.NOTABLE, score=2)
    rc_high = ResultCheck(path="body/url", scope=Scope.BODY, level=Level.MALICIOUS, score=8)

    rc_low.update(rc_high)

    assert rc_low.score == pytest.approx(8.0)
    assert rc_low.level is Level.MALICIOUS


def test_observable_tracks_highest_threat_intel():
    observable = Observable(ObsType.URL, "http://example.test")
    observable.attach_intel(name="vt", score=6, level=Level.SUSPICIOUS)

    observable.attach_intel(name="vt_update", score=8, level=Level.MALICIOUS)

    assert observable.score == pytest.approx(8.0)
    assert observable.level is Level.MALICIOUS


def test_report_merges_duplicate_checks_and_observables():
    report = build_report()

    first = ResultCheck.create(path="urls", scope=Scope.BODY, description="First link")
    first.add_observable_chain(
        [
            {
                "obs_type": ObsType.URL,
                "value": "http://alpha.test",
                "intel": {"name": "url", "score": 3, "level": Level.SUSPICIOUS},
            }
        ]
    )
    first.accept(report)

    followup = ResultCheck.create(path="urls", scope=Scope.BODY, description="Domain follow-up")
    followup.add_observable_chain(
        [
            {
                "obs_type": ObsType.DOMAIN,
                "value": "alpha.test",
                "intel": {"name": "domain", "score": 5, "level": Level.MALICIOUS},
            }
        ]
    )
    followup.accept(report)

    result = report.to_json()

    body_checks = result["checks"][Scope.BODY.name]
    merged = body_checks["urls"]

    assert merged["score"] == 5.0
    assert merged["level"] == Level.MALICIOUS.name
    assert {obs["obs_type"] for obs in merged["observables"]} == {"URL", "DOMAIN"}
    assert result["stats_checks"] == {"applied": 1, "checks": 1, "enrichments": 0, "obs": 2}
    assert result["checks_by_level"] == {Level.MALICIOUS.name: [merged["full_key"]]}
    assert result["score"] == 5.0
    assert result["level"] == Level.MALICIOUS.name


def test_container_aggregates_child_score_and_counts():
    report = build_report()

    container = Container("body_section", scope=Scope.BODY, level=Level.NONE)
    malicious = ResultCheck.create("urls", scope=Scope.BODY, description="Malicious link")
    obs = Observable(ObsType.URL, "http://bad.test")
    obs.attach_intel(name="sandbox", score=10, level=Level.MALICIOUS)
    malicious.add_observable(obs)
    benign = ResultCheck.create("domains", scope=Scope.BODY, description="Benign domain")
    container.contain(malicious)
    container.contain(benign)

    container.accept(report)
    result = report.to_json()

    section = result["checks"][Scope.BODY.name]["body_section"]

    assert section["level"] == Level.MALICIOUS.name
    assert section["score"] == 10
    assert section["nb_checks"] == 2
    assert set(section["container"].keys()) == {"urls", "domains"}
    assert result["score"] == 10.0
    assert result["level"] == Level.MALICIOUS.name


def test_container_rejects_scope_mismatch():
    container = Container("body_section", scope=Scope.BODY, level=Level.NONE)
    check = ResultCheck("urls", scope=Scope.HEADER, level=Level.INFO)

    with pytest.raises(ValueError):
        container.contain(check)


def test_child_observable_score_propagates_to_parent():
    parent = Observable(ObsType.DOMAIN, "alpha.test")
    child = Observable(ObsType.URL, "http://alpha.test")
    parent.add_observable_children(child)

    child.attach_intel(name="intel", score=6, level=Level.MALICIOUS)

    assert child.score == pytest.approx(6.0)
    assert parent.score == pytest.approx(6.0)
    assert parent.level is Level.MALICIOUS


def test_result_check_create_defaults():
    rc = ResultCheck.create("path", scope=Scope.BODY)

    assert rc.level is Level.INFO
    assert rc.score == 0.0


def test_add_observable_chain_builds_nested_structure():
    rc = ResultCheck.create("links", scope=Scope.BODY)
    root = rc.add_observable_chain(
        [
            {"obs_type": ObsType.URL, "value": "http://root.example"},
            {"obs_type": ObsType.DOMAIN, "value": "root.example"},
            {
                "obs_type": ObsType.IP,
                "value": "198.51.100.10",
                "intel": {"name": "geo", "score": 2, "level": Level.NOTABLE},
            },
        ]
    )

    assert root.obs_type is ObsType.URL
    assert "IP.198.51.100.10" in root.observables_children["DOMAIN.root.example"].observables_children
