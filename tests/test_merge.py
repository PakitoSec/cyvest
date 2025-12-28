"""
Tests for merge.
"""

from decimal import Decimal

from cyvest import Cyvest


def test_merge_local_check() -> None:
    cv_child = Cyvest()
    cv_child.check("C1", "full", "test").link_observable(
        cv_child.observable(cv_child.OBS.DOMAIN, "example.com").with_ti("VT", score=2)
    )

    main_inv = Cyvest()
    main_inv.check("C2", "full", "test").link_observable(
        main_inv.observable(main_inv.OBS.DOMAIN, "example.com").with_ti("OTX", score=4)
    )

    main_inv.merge_investigation(cv_child)

    c1 = main_inv.check_get("C1", "full")
    c2 = main_inv.check_get("C2", "full")
    o = main_inv.observable_get(Cyvest.OBS.DOMAIN, "example.com")
    global_score = main_inv.get_global_score()

    assert c1.score == 2
    assert c2.score == 4
    assert o.score == 4
    assert global_score == 6


def test_merge_global_check() -> None:
    cv_child = Cyvest()
    cv_child.check("C1", "full", "test").link_observable(
        cv_child.observable(cv_child.OBS.DOMAIN, "example.com").with_ti("VT", score=2),
        propagation_mode=cv_child.PROP.GLOBAL,
    )

    main_inv = Cyvest()
    main_inv.check("C2", "full", "test").link_observable(
        main_inv.observable(main_inv.OBS.DOMAIN, "example.com").with_ti("OTX", score=4)
    )

    main_inv.merge_investigation(cv_child)

    c1 = main_inv.check_get("C1", "full")
    c2 = main_inv.check_get("C2", "full")
    o = main_inv.observable_get(Cyvest.OBS.DOMAIN, "example.com")
    global_score = main_inv.get_global_score()

    assert c1.score == 4
    assert c2.score == 4
    assert o.score == 4
    assert global_score == 8


def test_merge_local_check_multiple_child() -> None:
    cv_child = Cyvest()
    cv_child.check("C1", "full", "test").link_observable(
        cv_child.observable(Cyvest.OBS.DOMAIN, "example.com").with_ti("VT", score=2)
    )

    cv_child2 = Cyvest()
    cv_child2.check("C1", "full", "test").link_observable(
        cv_child2.observable(Cyvest.OBS.DOMAIN, "example.com").with_ti("VT", score=5)
    )

    main_inv = Cyvest()
    main_inv.merge_investigation(cv_child)
    main_inv.merge_investigation(cv_child2)

    c1 = main_inv.check_get("C1", "full")
    o = main_inv.observable_get(Cyvest.OBS.DOMAIN, "example.com")
    global_score = main_inv.get_global_score()

    assert c1.score == 5
    assert o.score == 5
    assert global_score == 5


def test_local_only_link_does_not_affect_foreign_check() -> None:
    cv_main = Cyvest()
    cv_other = Cyvest()

    foreign_check = cv_other.check_create("foreign", "scope", "Created in other investigation")

    cv_main.merge_investigation(cv_other)

    obs = cv_main.observable_create(Cyvest.OBS.IPV4, "10.0.0.50")
    cv_main.observable_add_threat_intel(obs.key, source="source1", score=Decimal("9.0"))

    cv_main.check_link_observable(foreign_check.key, obs.key)

    loaded_foreign = cv_main.check_get(foreign_check.key)
    assert loaded_foreign is not None
    assert loaded_foreign.score == Decimal("0")
    assert loaded_foreign.level == Cyvest.LVL.NONE


def test_global_link_can_affect_foreign_check() -> None:
    cv_main = Cyvest()
    cv_other = Cyvest()

    foreign_check = cv_other.check_create("foreign", "scope", "Created in other investigation")
    cv_main.merge_investigation(cv_other)

    obs = cv_main.observable_create(Cyvest.OBS.IPV4, "10.0.0.52")
    cv_main.observable_add_threat_intel(obs.key, source="source1", score=Decimal("9.0"))

    cv_main.check_link_observable(foreign_check.key, obs.key, propagation_mode="GLOBAL")

    loaded_foreign = cv_main.check_get(foreign_check.key)
    assert loaded_foreign is not None
    assert loaded_foreign.score == Decimal("9.0")
    assert loaded_foreign.level == Cyvest.LVL.MALICIOUS


def test_check_reconciliation_preserves_origin_and_links() -> None:
    """Merging the same check key keeps the original check origin and merges links."""
    cv1 = Cyvest()
    cv2 = Cyvest()

    cv1_id = cv1._investigation.investigation_id

    obs1 = cv1.observable_create(Cyvest.OBS.IPV4, "10.0.0.60")
    cv1.observable_add_threat_intel(obs1.key, source="s1", score=Decimal("4.0"))
    check1 = cv1.check_create("recon", "scope", "Same semantic check")
    cv1.check_link_observable(check1.key, obs1.key)

    obs2 = cv2.observable_create(Cyvest.OBS.IPV4, "10.0.0.61")
    cv2.observable_add_threat_intel(obs2.key, source="s2", score=Decimal("9.0"))
    check2 = cv2.check_create("recon", "scope", "Same semantic check")
    cv2.check_link_observable(check2.key, obs2.key)

    cv1.merge_investigation(cv2)

    merged = cv1.check_get(check1.key)
    assert merged is not None
    assert merged.origin_investigation_id == cv1_id

    merged_keys = {link.observable_key for link in merged.observable_links}
    assert {obs1.key, obs2.key} <= merged_keys

    # Both links are effective after reconciliation, so the check takes the max score.
    assert merged.score == Decimal("9.0")
    assert merged.level == Cyvest.LVL.MALICIOUS


def test_foreign_check_global_updates_local_only_freezes_after_merge() -> None:
    """Foreign checks update via GLOBAL links but ignore LOCAL_ONLY changes after merges."""
    cv_main = Cyvest()
    cv_other = Cyvest()

    foreign_check = cv_other.check_create("foreign", "scope", "Created in other investigation")
    cv_main.merge_investigation(cv_other)

    obs_local = cv_main.observable_create(Cyvest.OBS.IPV4, "10.0.0.51")
    cv_main.observable_add_threat_intel(obs_local.key, source="source1", score=Decimal("2.0"))
    cv_main.check_link_observable(foreign_check.key, obs_local.key)

    obs_global = cv_main.observable_create(Cyvest.OBS.IPV4, "10.0.0.52")
    cv_main.observable_add_threat_intel(obs_global.key, source="source1", score=Decimal("4.0"))
    cv_main.check_link_observable(foreign_check.key, obs_global.key, propagation_mode="GLOBAL")

    merged_check = cv_main.check_get(foreign_check.key)
    assert merged_check is not None
    assert merged_check.score == Decimal("4.0")
    assert merged_check.level == Cyvest.LVL.SUSPICIOUS

    cv_later = Cyvest()
    obs_local_later = cv_later.observable_create(Cyvest.OBS.IPV4, "10.0.0.51")
    cv_later.observable_add_threat_intel(obs_local_later.key, source="source2", score=Decimal("8.0"))
    obs_global_later = cv_later.observable_create(Cyvest.OBS.IPV4, "10.0.0.52")
    cv_later.observable_add_threat_intel(obs_global_later.key, source="source2", score=Decimal("6.0"))
    cv_main.merge_investigation(cv_later)

    merged_check = cv_main.check_get(foreign_check.key)
    assert merged_check is not None
    assert merged_check.score == Decimal("6.0")
    assert merged_check.level == Cyvest.LVL.MALICIOUS
