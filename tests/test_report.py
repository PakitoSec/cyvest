from cyvest import (
    Level,
    Observable,
    ObsType,
    Report,
    ResultCheck,
    Scope,
)


def build_report(*, graph: bool = False) -> Report:
    return Report(graph=graph)


def test_report_collects_checks_into_json():
    report = build_report()

    check = ResultCheck.create(
        path="urls",
        scope=Scope.BODY,
        description="Suspicious URL detected",
    )
    observable = Observable(ObsType.URL, "http://malicious.test")
    observable.attach_intel(name="sandbox", score=5, level=Level.MALICIOUS)
    check.add_observable(observable)

    check.accept(report)

    result = report.to_json()

    assert result["score"] == 5.0
    assert result["level"] == Level.MALICIOUS.name
    body_checks = result["checks"][Scope.BODY.name]
    assert "urls" in body_checks
    assert body_checks["urls"]["observables"]
    assert result["stats_checks"]["checks"] == 1


def test_report_marks_whitelisted_observable():
    report = build_report()

    observable = Observable(ObsType.URL, "https://example.whitelisted")
    observable.attach_intel(name="allowlist", score=0.0, level=Level.TRUSTED, extra={"whitelisted": True})
    observable.accept(report)

    assert report.is_whitelisted(ObsType.URL, "https://example.whitelisted") is True

    json_data = report.to_json()
    obs_json = next((o for o in json_data["graph"] if o["obs_value"] == "https://example.whitelisted"), None)
    assert obs_json is not None
    assert obs_json["whitelisted"] is True
