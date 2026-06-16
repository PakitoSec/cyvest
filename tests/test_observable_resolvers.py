"""Tests for Cyvest observable identity resolvers."""

from __future__ import annotations

import asyncio

import pytest

from cyvest import Cyvest, ObservableAlias, ObservableIdentity, ObservableResolver


def _okta_identity(value: str = "123") -> ObservableIdentity:
    return ObservableIdentity(
        obs_type=Cyvest.OBS.USER,
        subtype=Cyvest.SUB.USER_UID,
        namespace="okta",
        value=value,
    )


def _resolver(name: str, resolved: ObservableIdentity | None) -> ObservableResolver:
    return ObservableResolver(
        name=name,
        source_types={
            (Cyvest.OBS.USER, Cyvest.SUB.USER_EMAIL),
            (Cyvest.OBS.USER, Cyvest.SUB.USER_USERNAME),
        },
        resolve=lambda alias: resolved,
    )


def test_observable_alias_and_identity_validation() -> None:
    alias = ObservableAlias(
        obs_type="USER",
        subtype="EMAIL",
        value="Alice@Example.COM",
    )
    identity = ObservableIdentity(
        obs_type=Cyvest.OBS.USER,
        subtype=Cyvest.SUB.USER_UID,
        namespace="okta",
        value="123",
    )

    assert alias.obs_type == Cyvest.OBS.USER
    assert alias.subtype == Cyvest.SUB.USER_EMAIL
    assert alias.namespace is None
    assert alias.count == 1
    assert identity.obs_type == Cyvest.OBS.USER

    with pytest.raises(ValueError, match="requires a namespace"):
        ObservableAlias(obs_type=Cyvest.OBS.USER, subtype=Cyvest.SUB.USER_USERNAME, value="alice")


def test_sync_resolver_canonicalizes_aliases_and_counts() -> None:
    cv = Cyvest()
    cv.observable_resolver_register(_resolver("okta-user-id", _okta_identity()))

    email_obs = cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)
    username_obs = cv.observable_create(
        Cyvest.OBS.USER,
        "alice",
        subtype=Cyvest.SUB.USER_USERNAME,
        namespace="windows",
    )

    assert email_obs.key == username_obs.key
    assert email_obs.subtype == Cyvest.SUB.USER_UID
    assert email_obs.namespace == "okta"
    assert email_obs.value == "123"
    assert email_obs.occurrence_count == 2
    assert len(email_obs.aliases) == 2
    alias_keys = {
        (alias.obs_type, alias.subtype, alias.namespace, alias.value, alias.count) for alias in email_obs.aliases
    }
    assert (Cyvest.OBS.USER, Cyvest.SUB.USER_EMAIL, None, "alice@example.com", 1) in alias_keys
    assert (Cyvest.OBS.USER, Cyvest.SUB.USER_USERNAME, "windows", "alice", 1) in alias_keys

    non_root_observables = [obs for obs in cv.observable_get_all().values() if obs.value != "root"]
    assert len(non_root_observables) == 1


def test_resolver_fallback_creates_source_observable() -> None:
    cv = Cyvest()
    cv.observable_resolver_register(_resolver("missing-okta-user", None))

    obs = cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)

    assert obs.obs_type == Cyvest.OBS.USER
    assert obs.subtype == Cyvest.SUB.USER_EMAIL
    assert obs.value == "alice@example.com"
    assert obs.aliases == []
    assert obs.occurrence_count == 1


def test_resolver_ordering_first_non_none_wins() -> None:
    cv = Cyvest()
    cv.observable_resolver_register(_resolver("first", _okta_identity("123")))
    cv.observable_resolver_register(_resolver("second", _okta_identity("456")))

    obs = cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)

    assert obs.value == "123"


def test_resolver_registration_is_per_instance_and_replaceable() -> None:
    cv1 = Cyvest()
    cv2 = Cyvest()
    cv1.observable_resolver_register(_resolver("okta", _okta_identity("123")))

    assert [resolver.name for resolver in cv1.observable_resolver_get_all()] == ["okta"]
    assert cv2.observable_resolver_get_all() == ()

    with pytest.raises(ValueError, match="already registered"):
        cv1.observable_resolver_register(_resolver("okta", _okta_identity("456")))

    cv1.observable_resolver_register(_resolver("okta", _okta_identity("456")), replace=True)
    assert cv1.observable_resolver_unregister("okta") is True
    assert cv1.observable_resolver_unregister("okta") is False
    assert cv1.observable_resolver_get_all() == ()

    cv1.observable_resolver_register(_resolver("okta", _okta_identity("123")))
    cv1.observable_resolver_clear()
    assert cv1.observable_resolver_get_all() == ()


def test_observable_create_raises_for_applicable_async_resolver() -> None:
    async def resolve(alias: ObservableAlias) -> ObservableIdentity | None:
        return _okta_identity()

    cv = Cyvest()
    cv.observable_resolver_register(
        ObservableResolver(
            name="async-okta",
            source_types={(Cyvest.OBS.USER, Cyvest.SUB.USER_EMAIL)},
            aresolve=resolve,
        )
    )

    with pytest.raises(RuntimeError, match="observable_acreate"):
        cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)


def test_observable_acreate_supports_async_resolver() -> None:
    async def run() -> None:
        async def resolve(alias: ObservableAlias) -> ObservableIdentity | None:
            await asyncio.sleep(0)
            return _okta_identity()

        cv = Cyvest()
        cv.observable_resolver_register(
            ObservableResolver(
                name="async-okta",
                source_types={(Cyvest.OBS.USER, Cyvest.SUB.USER_EMAIL)},
                aresolve=resolve,
            )
        )

        obs = await cv.observable_acreate(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)
        assert obs.subtype == Cyvest.SUB.USER_UID
        assert obs.namespace == "okta"
        assert obs.aliases[0].value == "alice@example.com"

    asyncio.run(run())


def test_repeated_canonical_creations_merge_occurrence_and_alias_counts() -> None:
    cv = Cyvest()
    cv.observable_resolver_register(_resolver("okta-user-id", _okta_identity()))

    cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)
    obs = cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)

    assert obs.occurrence_count == 2
    assert len(obs.aliases) == 1
    assert obs.aliases[0].count == 2


def test_investigation_merge_combines_occurrences_and_aliases() -> None:
    cv1 = Cyvest()
    cv2 = Cyvest()
    cv1.observable_resolver_register(_resolver("okta-user-id", _okta_identity()))
    cv2.observable_resolver_register(_resolver("okta-user-id", _okta_identity()))

    obs1 = cv1.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)
    cv2.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)
    cv2.observable_create(
        Cyvest.OBS.USER,
        "alice",
        subtype=Cyvest.SUB.USER_USERNAME,
        namespace="windows",
    )

    cv1.merge_investigation(cv2)
    merged = cv1.observable_get(obs1.key)

    assert merged is not None
    assert merged.occurrence_count == 3
    alias_counts = {(alias.subtype, alias.namespace, alias.value): alias.count for alias in merged.aliases}
    assert alias_counts[(Cyvest.SUB.USER_EMAIL, None, "alice@example.com")] == 2
    assert alias_counts[(Cyvest.SUB.USER_USERNAME, "windows", "alice")] == 1


def test_aliases_and_occurrence_count_survive_json_roundtrip(tmp_path) -> None:
    cv = Cyvest()
    cv.observable_resolver_register(_resolver("okta-user-id", _okta_identity()))
    obs = cv.observable_create(Cyvest.OBS.USER, "alice@example.com", subtype=Cyvest.SUB.USER_EMAIL)

    path = tmp_path / "canonical.json"
    cv.io_save_json(path)
    loaded = Cyvest.io_load_json(path)
    loaded_obs = loaded.observable_get(obs.key)

    assert loaded_obs is not None
    assert loaded_obs.occurrence_count == 1
    assert len(loaded_obs.aliases) == 1
    assert loaded_obs.aliases[0].subtype == Cyvest.SUB.USER_EMAIL


def test_root_occurrence_count_is_not_incremented_by_json_load(tmp_path) -> None:
    cv = Cyvest()
    root = cv.observable_get_root()
    assert root.occurrence_count == 1

    path = tmp_path / "root.json"
    cv.io_save_json(path)
    loaded = Cyvest.io_load_json(path)

    assert loaded.observable_get_root().occurrence_count == 1
