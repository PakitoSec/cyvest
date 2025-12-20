"""
Tests for proxy helper mutators.
"""

from decimal import Decimal

import pytest

from cyvest import Cyvest


def test_observable_proxy_update_metadata() -> None:
    """ObservableProxy.update_metadata should patch safe fields in place."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://example.com")

    obs.update_metadata(
        comment="Investigated",
        internal=False,
        whitelisted=True,
        extra={"ticket": "INC-42"},
    )
    assert obs.comment == "Investigated"
    assert obs.internal is False
    assert obs.whitelisted is True
    assert obs.extra["ticket"] == "INC-42"

    # Merge extra values by default
    obs.update_metadata(extra={"ticket": "INC-99", "owner": "SOC"})
    assert obs.extra["ticket"] == "INC-99"
    assert obs.extra["owner"] == "SOC"

    # Replace dictionary when requested
    obs.update_metadata(extra={"only": "new"}, merge_extra=False)
    assert obs.extra == {"only": "new"}


def test_check_proxy_update_metadata() -> None:
    """CheckProxy.update_metadata should allow comment/description/extra updates."""
    cv = Cyvest()
    check = cv.check_create("check-id", "scope", "Initial description")

    check.update_metadata(comment="Updated comment", description="New description", extra={"k": "v"})
    assert check.comment == "Updated comment"
    assert check.description == "New description"
    assert check.extra == {"k": "v"}

    check.update_metadata(extra={"k": "override"}, merge_extra=False)
    assert check.extra == {"k": "override"}


def test_threat_intel_proxy_update_metadata() -> None:
    """ThreatIntelProxy.update_metadata should allow comment/level/extra."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "example.com")
    ti = cv.observable_add_threat_intel(
        obs.key,
        source="vt",
        score=Decimal("4.2"),
        comment="Initial",
        extra={"confidence": "low"},
    )
    assert ti is not None

    ti.update_metadata(comment="Escalated", level=Cyvest.LVL.MALICIOUS, extra={"confidence": "high"})
    assert ti.comment == "Escalated"
    assert ti.level == Cyvest.LVL.MALICIOUS
    assert ti.extra["confidence"] == "high"


def test_enrichment_proxy_update_metadata() -> None:
    """EnrichmentProxy.update_metadata should merge/replace context data."""
    cv = Cyvest()
    enrichment = cv.enrichment_create("metadata", {"host": {"ip": "10.0.0.1"}}, context="initial")

    enrichment.update_metadata(context="refined", data={"owner": "team"})
    assert enrichment.context == "refined"
    assert enrichment.data["owner"] == "team"
    assert enrichment.data["host"] == {"ip": "10.0.0.1"}

    enrichment.update_metadata(data={"host": {"ip": "10.0.0.2"}}, merge_data=False)
    assert enrichment.data == {"host": {"ip": "10.0.0.2"}}


def test_container_proxy_update_metadata() -> None:
    """ContainerProxy.update_metadata should update description."""
    cv = Cyvest()
    container = cv.container_create("path", "old description")

    container.update_metadata(description="new description")
    assert container.description == "new description"


def test_proxy_dir_exposes_public_fields() -> None:
    """Proxies should list readable dataclass fields for IDE auto-completion."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    check = cv.check_create("check-id", "scope", "desc")
    container = cv.container_create("root")
    ti = cv.observable_add_threat_intel(obs.key, source="vt", score=Decimal("1"), comment="c")
    enrichment = cv.enrichment_create("metadata", {"k": "v"}, context="ctx")
    assert ti is not None

    expectations = {
        obs: {
            "obs_type",
            "value",
            "internal",
            "whitelisted",
            "comment",
            "extra",
            "score",
            "level",
            "check_links",
            "key",
        },
        check: {
            "check_id",
            "scope",
            "description",
            "comment",
            "extra",
            "score",
            "level",
            "origin_investigation_id",
            "observable_links",
            "key",
        },
        container: {
            "path",
            "description",
            "checks",
            "sub_containers",
            "key",
        },
        ti: {
            "source",
            "observable_key",
            "comment",
            "extra",
            "score",
            "level",
            "taxonomies",
            "key",
        },
        enrichment: {"name", "data", "context", "key"},
    }

    for proxy, fields in expectations.items():
        entries = set(dir(proxy))
        assert fields.issubset(entries)
        assert "_score_history" not in entries

    with pytest.raises(AttributeError):
        _ = obs._score_history  # type: ignore[attr-defined]


def test_proxy_public_fields_are_deep_copied() -> None:
    """Mutable model data exposed through proxies should be defensive copies."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "example.com")
    check = cv.check_create("check-id", "scope", "desc")
    linked_check = cv.check_link_observable(check.key, obs.key)
    assert linked_check is not None

    container = cv.container_create("root")
    container.add_check(check)

    ti = cv.observable_add_threat_intel(obs.key, source="vt", score=Decimal("2.5"), taxonomies=[{"k": "v"}])
    assert ti is not None

    enrichment = cv.enrichment_create("metadata", {"host": {"ip": "10.0.0.1"}}, context="ctx")

    extra_copy = obs.extra
    extra_copy["owner"] = "secops"
    assert "owner" not in obs.extra

    links_copy = check.observable_links
    assert len(links_copy) == 1
    links_copy.clear()
    assert len(check.observable_links) == 1

    checks_copy = container.checks
    checks_copy.clear()
    assert len(container.checks) == 1

    taxonomies_copy = ti.taxonomies
    taxonomies_copy.append({"new": "value"})
    assert ti.taxonomies == [{"k": "v"}]

    data_copy = enrichment.data
    data_copy["host"]["ip"] = "10.0.0.2"
    assert enrichment.data["host"]["ip"] == "10.0.0.1"

    linked_copy = obs.check_links
    assert check.key in linked_copy
    linked_copy.append("another-check")
    assert obs.check_links == [check.key]
