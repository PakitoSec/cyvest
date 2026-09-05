"""
Structural auto-link: the observables an observable *contains*, linked as soon as it is created.

A URL contains a host and an e-mail address contains a domain. Stating those edges by hand is
tedious and, worse, inconsistent — one analyst draws them, the next does not, and the same intel
on the same domain then scores two investigations differently. This module derives them once,
deterministically, under an attributable source.

The derived edge is an :attr:`RelationKind.EXTRACTION` from the container (parent) to the
contained (child). Under the default policy that kind propagates with attenuation ``1.0``, so a
malicious domain makes the URL that carries it malicious — which is what an analyst means when
they say a URL "points at" a bad domain. Because of that scoring consequence the feature is
opt-in: ``Cyvest(auto_link=AutoLink())``.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import ObservableType, RelationKind, SourceClass
from cyvest.extract import refang
from cyvest.facts.base import SourceRef

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest
    from cyvest.proxies import ObservableProxy

#: Who asserts a derived relation. Distinct from the default source so a report can tell an edge
#: the analyst drew from one the library inferred.
AUTOLINK_SOURCE = SourceRef(name="cyvest.autolink", source_class=SourceClass.INTERNAL_TOOL)


class AutoLink(BaseModel):
    """
    Which links to draw automatically.

    ``AutoLink()`` enables every rule; disable one explicitly when it does not fit a case. Only the
    structural rule exists today, so the object is mostly a place for the next one to land without
    changing every signature that takes it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: URL → host (domain, IPv4 or IPv6) and e-mail → domain, as ``EXTRACTION`` edges.
    structural: bool = Field(default=True)
    #: The derived child takes the parent's ``internal`` flag; otherwise it is external.
    inherit_internal: bool = Field(default=True)
    #: Comment written on every derived relation.
    comment: str = Field(default="structural derivation")


def _coerce_type(obs_type: ObservableType | str) -> ObservableType | None:
    if isinstance(obs_type, ObservableType):
        return obs_type
    try:
        return ObservableType(str(obs_type).strip().lower())
    except ValueError:
        return None


def _host_of(url: str) -> tuple[ObservableType, str] | None:
    """The host a URL names, typed — or ``None`` when there is no usable host."""
    text = refang(url.strip())
    # A scheme-less "evil.example/path" has no netloc for urlsplit; give it one.
    if "://" not in text:
        text = f"//{text}"
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # ``localhost`` or a bare NetBIOS name is not an indicator worth a fact of its own.
        return (ObservableType.DOMAIN, host) if "." in host else None
    return (ObservableType.IPV4 if address.version == 4 else ObservableType.IPV6), str(address)


def derive_structural(obs_type: ObservableType | str, value: str) -> list[tuple[ObservableType, str]]:
    """
    The observables structurally contained in ``value``.

    Pure: no store, no side effect. Returns an empty list for every type that contains nothing —
    domains, addresses, hashes — which is also what bounds the recursion when the derived child is
    created through the same path.
    """
    kind = _coerce_type(obs_type)
    if kind is ObservableType.URL:
        host = _host_of(value)
        return [host] if host is not None else []
    if kind is ObservableType.EMAIL:
        _local, separator, domain = refang(value.strip()).rpartition("@")
        domain = domain.strip().lower().rstrip(".")
        return [(ObservableType.DOMAIN, domain)] if separator and "." in domain else []
    return []


def apply_structural_links(cv: Cyvest, proxy: ObservableProxy, config: AutoLink) -> list[ObservableProxy]:
    """
    Create the observables ``proxy`` contains and link them to it.

    Children are created with ``resolve=False``: a domain or an address is already canonical, and
    a resolver registered for another type must not be consulted — nor fail, if it is async — on
    the library's behalf.
    """
    if not config.structural:
        return []
    children: list[ObservableProxy] = []
    internal = proxy.internal if config.inherit_internal else False
    for child_type, child_value in derive_structural(proxy.obs_type, proxy.value):
        child = cv.observable_create(child_type, child_value, internal=internal, resolve=False)
        cv.observable_add_relation(
            proxy,
            child,
            RelationKind.EXTRACTION,
            confidence=1.0,
            comment=config.comment,
            asserted_by=AUTOLINK_SOURCE,
        )
        children.append(child)
    return children


def backfill_structural_links(cv: Cyvest, config: AutoLink | None = None) -> int:
    """
    Apply the structural rule to every observable already in the investigation.

    For an investigation built before auto-link was switched on, or loaded from a document.
    Idempotent — keys are deterministic — and returns the number of relations added.
    """
    rules = config or cv.auto_link or AutoLink()
    if not rules.structural:
        return 0
    before = len(cv.relation_get_all())
    root_key = cv.root().key
    for key, proxy in sorted(cv.observable_get_all().items()):
        if key == root_key:
            continue
        apply_structural_links(cv, proxy, rules)
    return len(cv.relation_get_all()) - before


__all__ = ["AUTOLINK_SOURCE", "AutoLink", "apply_structural_links", "backfill_structural_links", "derive_structural"]
