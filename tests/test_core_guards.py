"""The core refuses a fact about nothing, and the helpers the agent layer leans on."""

from __future__ import annotations

import pytest

from cyvest import (
    Cyvest,
    InvestigationSpec,
    ObservableSubtype,
    ObservableType,
    Verdict,
    identity_is_complete,
    infer_observable_identity,
)
from cyvest.integrations.langchain.prompts import build_tools_prompt
from cyvest.keys import slugify
from cyvest.shared import SharedInvestigationContext


class TestTargetsMustExist:
    def test_a_signal_about_an_unknown_observable_is_refused(self) -> None:
        with pytest.raises(KeyError, match="Unknown observable"):
            Cyvest().observable_add_threat_intel("obs:ipv4:9.9.9.9", "vt", verdict="MALICIOUS")

    def test_a_relation_to_an_unknown_observable_is_refused(self) -> None:
        cv = Cyvest()
        known = cv.observable(cv.OBS.DOMAIN, "a.example")
        with pytest.raises(KeyError, match="Unknown observable"):
            cv.observable_add_relation(known, "obs:ipv4:9.9.9.9")

    def test_a_decision_on_an_unknown_target_is_refused(self) -> None:
        with pytest.raises(KeyError, match="Unknown observable or finding"):
            Cyvest().decision_create("fnd:nope", "REFUTE", "because")

    def test_linking_unknown_evidence_is_refused(self) -> None:
        cv = Cyvest()
        finding = cv.finding("r")
        with pytest.raises(KeyError, match="Unknown evidence"):
            cv.finding_link_evidence(finding.key, "evd:nope")


class TestResolveSwitch:
    def test_resolve_false_bypasses_the_resolvers(self) -> None:
        from cyvest import ObservableIdentity, ObservableResolver

        cv = Cyvest()
        cv.observable_resolver_register(
            ObservableResolver(
                name="upper",
                source_types={("domain", None)},
                resolve=lambda alias: ObservableIdentity(type="domain", value=alias.value.upper()),
            )
        )
        assert cv.observable("domain", "a.example").value == "A.EXAMPLE"
        assert cv.observable("domain", "b.example", resolve=False).value == "b.example"

    def test_resolve_false_never_touches_an_async_resolver(self) -> None:
        from cyvest import ObservableResolver

        async def boom(alias):  # noqa: ANN001, ANN202
            raise AssertionError("resolver consulted")

        cv = Cyvest()
        cv.observable_resolver_register(ObservableResolver(name="dir", source_types={("domain", None)}, aresolve=boom))
        with pytest.raises(RuntimeError, match="async"):
            cv.observable("domain", "a.example")
        assert cv.observable("domain", "a.example", resolve=False).key == "obs:domain:a.example"


class TestInvestigationSpec:
    def test_new_and_load_apply_the_same_configuration(self) -> None:
        seen: list[str] = []
        spec = InvestigationSpec(
            {"case": "x"},
            root_type="artifact",
            investigation_id="x",
            configure=lambda cv: seen.append(cv.investigation_id),
        )
        fresh = spec.new()
        loaded = spec.load(fresh.io_to_dict())
        worker = spec.new(investigation_id="w1", investigation_name="Worker")
        assert (fresh.investigation_id, loaded.investigation_id, worker.investigation_id) == ("x", "x", "w1")
        assert worker.investigation_get_name() == "Worker"
        assert seen == ["x", "x", "w1"]

    def test_the_shared_context_builds_its_workers_from_a_spec(self) -> None:
        context = SharedInvestigationContext(root_type="artifact", investigation_id="main")
        assert isinstance(context.spec, InvestigationSpec)
        with context.task(fragment_id="w") as worker:
            assert worker.root().key == context.snapshot().root().key
            assert worker._investigation.store.header.engine_id == "basic-v1"


class TestHelpers:
    def test_verdict_rank_orders_the_scale(self) -> None:
        assert [member.rank for member in Verdict] == [0, 1, 2, 3, 4]
        assert max((Verdict.NOTABLE, Verdict.SAFE), key=lambda v: v.rank) is Verdict.NOTABLE

    def test_slugify(self) -> None:
        assert slugify("URL In Body!") == "url-in-body"
        assert slugify("  finding--Splunk_auth ") == "finding-splunk-auth"
        assert slugify("###", fallback="finding") == "finding"

    @pytest.mark.parametrize(
        ("obs_type", "value", "subtype", "namespace"),
        [
            ("host", "srv01.corp.example", ObservableSubtype.HOST_FQDN, None),
            ("host", "SRV01", ObservableSubtype.HOST_HOSTNAME, "default"),
            ("user", "alice@corp.example", ObservableSubtype.USER_EMAIL, None),
            ("user", "S-1-5-21-1", ObservableSubtype.USER_SID, None),
            ("user", "alice", ObservableSubtype.USER_USERNAME, "default"),
            ("process", "1234", ObservableSubtype.PROCESS_PID, "default"),
            ("process", "12345678-1234-1234-1234-123456789abc", ObservableSubtype.PROCESS_GUID, None),
            ("process", "powershell.exe", None, None),
            ("file", "/tmp/x", ObservableSubtype.FILE_PATH, "default"),
            ("cloud_resource", "arn:aws:s3:::b", ObservableSubtype.CLOUD_AWS_ARN, None),
            ("cloud_resource", "/subscriptions/0/rg", ObservableSubtype.CLOUD_AZURE_RESOURCE_ID, None),
            ("cloud_resource", "//compute.googleapis.com/p", ObservableSubtype.CLOUD_GCP_RESOURCE_NAME, None),
            ("ipv4", "203.0.113.5", None, None),
        ],
    )
    def test_infer_observable_identity(self, obs_type: str, value: str, subtype, namespace) -> None:  # noqa: ANN001
        assert infer_observable_identity(obs_type, value) == (obs_type, subtype, namespace)

    def test_an_inferred_identity_builds_a_valid_observable_or_says_it_cannot(self) -> None:
        cv = Cyvest()
        for obs_type, value in (("host", "SRV01"), ("user", "alice"), ("file", "/tmp/x"), ("domain", "a.example")):
            kind, subtype, namespace = infer_observable_identity(obs_type, value)
            assert identity_is_complete(kind, subtype)
            cv.observable(kind, value, subtype=subtype, namespace=namespace)
        assert not identity_is_complete(ObservableType.PROCESS, None)
        assert identity_is_complete(ObservableType.DOMAIN, None)

    def test_the_prompt_quotes_the_enums_not_literals(self) -> None:
        prompt = build_tools_prompt()
        assert "SAFE < INFO < NOTABLE < SUSPICIOUS < MALICIOUS" in prompt
        assert "LOW 1.5, MEDIUM 4, HIGH 7" in prompt and "LOW 0.3, MEDIUM 0.65, HIGH 1" in prompt
