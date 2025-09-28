from cyvest import Container, Level, ObsType, ReportBuilder, ResultCheck, Scope


def test_report_builder_creates_nested_structure():
    builder = ReportBuilder(graph=True)

    with builder.container("body", scope=Scope.BODY, description="Body analysis") as body:
        check = body.add_check("links", identifier="http://example.test", description="Link under review")
        root = check.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "http://example.test",
                    "intel": {"name": "url_intel", "score": 6, "level": Level.MALICIOUS},
                },
                {
                    "obs_type": ObsType.DOMAIN,
                    "value": "example.test",
                    "intel": {"name": "domain_intel", "score": 4, "level": Level.SUSPICIOUS},
                },
            ]
        )
        assert root.obs_type is ObsType.URL

        with body.container("subsection", description="Nested scope") as subsection:
            sub_check = subsection.add_check("indicator")
            sub_check.add_observable_chain(
                [
                    {
                        "obs_type": ObsType.IP,
                        "value": "198.51.100.5",
                        "intel": {
                            "name": "ip_intel",
                            "score": 3,
                            "level": Level.NOTABLE,
                        },
                    }
                ]
            )

    report = builder.build()
    json_data = report.to_json()

    body_section = json_data["checks"][Scope.BODY.name]["body"]
    assert body_section["nb_checks"] == 2
    links_list = body_section["container"]["links"]
    assert isinstance(links_list, list)
    assert links_list[0]["observables"][0]["obs_value"] == "http://example.test"
    assert Scope.BODY.name in json_data["checks"]


def test_report_builder_supports_root_checks():
    builder = ReportBuilder()
    builder.add_check(
        "alert",
        scope=Scope.BODY,
        description="Root level check",
        observable_chain=[
            {
                "obs_type": ObsType.URL,
                "value": "http://root.example",
                "intel": {
                    "name": "root",
                    "score": 2,
                    "level": Level.NOTABLE,
                },
            }
        ],
    )

    report = builder.build()
    json_data = report.to_json()

    assert json_data["checks"][Scope.BODY.name]["alert"]["observables"][0]["obs_value"] == "http://root.example"


def test_report_builder_add_existing_nodes():
    builder = ReportBuilder()

    container = Container("async", scope=Scope.BODY, description="Async section")
    check = ResultCheck.create("ioc", scope=Scope.BODY, description="Async IOC")
    check.add_observable_chain(
        [
            {
                "obs_type": ObsType.IP,
                "value": "203.0.113.55",
                "intel": {"name": "async_ip", "score": 4, "level": Level.SUSPICIOUS},
            }
        ]
    )
    container.contain(check)

    builder.add_existing(container)
    report = builder.build()
    json_data = report.to_json()

    async_container = json_data["checks"][Scope.BODY.name]["async"]
    assert async_container["nb_checks"] == 1
    assert async_container["container"]["ioc"]["observables"][0]["obs_value"] == "203.0.113.55"
