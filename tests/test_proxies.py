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


def test_finding_proxy_update_metadata() -> None:
    """FindingProxy.update_metadata should allow comment/description/extra updates."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "Initial description")

    finding.update_metadata(comment="Updated comment", description="New description", extra={"k": "v"})
    assert finding.comment == "Updated comment"
    assert finding.description == "New description"
    assert finding.extra == {"k": "v"}

    finding.update_metadata(extra={"k": "override"}, merge_extra=False)
    assert finding.extra == {"k": "override"}


def test_threat_intel_proxy_update_metadata() -> None:
    """ThreatIntelProxy.update_metadata should allow comment/extra."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    ti = cv.observable_add_threat_intel(
        obs.key,
        source="vt",
        score=Decimal("4.2"),
        comment="Initial",
        extra={"confidence": "low"},
    )
    assert ti is not None

    ti.update_metadata(comment="Escalated", extra={"confidence": "high"})
    ti.set_level(Cyvest.LVL.MALICIOUS)
    assert ti.comment == "Escalated"
    assert ti.level == Cyvest.LVL.MALICIOUS
    assert ti.extra["confidence"] == "high"


def test_threat_intel_proxy_taxonomy_mutators() -> None:
    """ThreatIntelProxy should add/replace/remove taxonomies by name."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    ti = cv.observable_add_threat_intel(
        obs.key,
        source="vt",
        score=Decimal("4.2"),
        taxonomies=[{"level": Cyvest.LVL.INFO, "name": "malware-type", "value": "trojan"}],
    )
    assert ti is not None

    ti.add_taxonomy(level=Cyvest.LVL.SUSPICIOUS, name="confidence", value="low")
    assert {taxonomy.name for taxonomy in ti.taxonomies} == {"malware-type", "confidence"}

    ti.add_taxonomy(level=Cyvest.LVL.SUSPICIOUS, name="confidence", value="high")
    confidence = [taxonomy for taxonomy in ti.taxonomies if taxonomy.name == "confidence"][0]
    assert confidence.value == "high"

    ti.remove_taxonomy("confidence")
    assert {taxonomy.name for taxonomy in ti.taxonomies} == {"malware-type"}


def test_observable_proxy_with_ti_draft() -> None:
    """ObservableProxy.with_ti_draft should attach draft threat intel entries."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    draft = cv.threat_intel_draft(source="vt", score=Decimal("4.2"))

    bound = obs.with_ti_draft(draft)
    assert draft.observable_key == obs.key
    assert draft.key.startswith("ti:")
    assert bound.key == draft.key
    assert {ti.key for ti in obs.threat_intels} == {draft.key}


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


def test_tag_proxy_update_metadata() -> None:
    """TagProxy.update_metadata should update description."""
    cv = Cyvest()
    tag = cv.tag_create("tagname", "old description")

    tag.update_metadata(description="new description")
    assert tag.description == "new description"


def test_proxy_dir_exposes_public_fields() -> None:
    """Proxies should list readable dataclass fields for IDE auto-completion."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    finding = cv.finding_create("finding-id", "scope", "desc")
    tag = cv.tag_create("root")
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
            "finding_links",
            "key",
        },
        finding: {
            "finding_name",
            "description",
            "comment",
            "extra",
            "score",
            "level",
            "origin_investigation_id",
            "observable_links",
            "key",
        },
        tag: {
            "name",
            "description",
            "findings",
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
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    finding = cv.finding_create("finding-id", "scope", "desc")
    linked_finding = cv.finding_link_observable(finding.key, obs.key)
    assert linked_finding is not None

    tag = cv.tag_create("root")
    tag.add_finding(finding)

    ti = cv.observable_add_threat_intel(
        obs.key,
        source="vt",
        score=Decimal("2.5"),
        taxonomies=[{"level": Cyvest.LVL.INFO, "name": "malware-type", "value": "trojan"}],
    )
    assert ti is not None

    enrichment = cv.enrichment_create("metadata", {"host": {"ip": "10.0.0.1"}}, context="ctx")

    extra_copy = obs.extra
    extra_copy["owner"] = "secops"
    assert "owner" not in obs.extra

    links_copy = finding.observable_links
    assert len(links_copy) == 1
    links_copy.clear()
    assert len(finding.observable_links) == 1

    findings_copy = tag.findings
    findings_copy.clear()
    assert len(tag.findings) == 1

    taxonomies_copy = ti.taxonomies
    taxonomies_copy.append({"level": Cyvest.LVL.SUSPICIOUS, "name": "confidence", "value": "low"})
    assert len(ti.taxonomies) == 1
    assert ti.taxonomies[0].name == "malware-type"

    data_copy = enrichment.data
    data_copy["host"]["ip"] = "10.0.0.2"
    assert enrichment.data["host"]["ip"] == "10.0.0.1"

    linked_copy = obs.finding_links
    assert finding.key in linked_copy
    linked_copy.append("another-finding")
    assert obs.finding_links == [finding.key]


def test_finding_proxy_tagged_with_string_auto_creates() -> None:
    """FindingProxy.tagged should auto-create tags from strings."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")

    finding.tagged("network")

    tag = cv.tag_get("network")
    assert tag is not None
    assert tag.name == "network"
    assert finding.key in [c.key for c in tag.findings]


def test_finding_proxy_tagged_with_multiple_strings() -> None:
    """FindingProxy.tagged should accept multiple string tags."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")

    finding.tagged("network", "suspicious", "c2:detection")

    assert cv.tag_get("network") is not None
    assert cv.tag_get("suspicious") is not None
    assert cv.tag_get("c2:detection") is not None
    # Hierarchy auto-created
    assert cv.tag_get("c2") is not None


def test_finding_proxy_tagged_with_tag_proxy() -> None:
    """FindingProxy.tagged should accept TagProxy objects."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")
    tag = cv.tag_create("analysis", "Analysis tag")

    finding.tagged(tag)

    assert finding.key in [c.key for c in tag.findings]


def test_finding_proxy_tagged_mixed_types() -> None:
    """FindingProxy.tagged should accept a mix of strings and TagProxy."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")
    existing_tag = cv.tag_create("existing", "Existing tag")

    finding.tagged(existing_tag, "new_tag", "another:nested")

    assert finding.key in [c.key for c in existing_tag.findings]
    assert cv.tag_get("new_tag") is not None
    assert cv.tag_get("another:nested") is not None
    assert cv.tag_get("another") is not None


def test_finding_proxy_tagged_returns_self() -> None:
    """FindingProxy.tagged should return self for chaining."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")

    result = finding.tagged("network").tagged("suspicious")

    assert result is finding


def test_finding_proxy_tagged_invalid_type_raises() -> None:
    """FindingProxy.tagged should raise TypeError for invalid input."""
    cv = Cyvest()
    finding = cv.finding_create("finding-id", "scope", "desc")

    with pytest.raises(TypeError, match="Tag must provide a key"):
        finding.tagged(123)  # type: ignore[arg-type]
