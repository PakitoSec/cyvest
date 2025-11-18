"""
Tests for proxy helper mutators.
"""

from decimal import Decimal

from cyvest import Cyvest, Level


def test_observable_proxy_update_metadata() -> None:
    """ObservableProxy.update_metadata should patch safe fields in place."""
    cv = Cyvest()
    obs = cv.observable_create("url", "https://example.com")

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
    obs = cv.observable_create("domain-name", "example.com")
    ti = cv.observable_add_threat_intel(
        obs.key,
        source="vt",
        score=Decimal("4.2"),
        comment="Initial",
        extra={"confidence": "low"},
    )
    assert ti is not None

    ti.update_metadata(comment="Escalated", level=Level.MALICIOUS, extra={"confidence": "high"})
    assert ti.comment == "Escalated"
    assert ti.level == Level.MALICIOUS
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
