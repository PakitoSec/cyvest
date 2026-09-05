"""Structural auto-link: derived edges, their attribution, and their effect on the score."""

from __future__ import annotations

from cyvest import AutoLink, Cyvest, ObservableType, RelationKind
from cyvest.autolink import AUTOLINK_SOURCE, backfill_structural_links, derive_structural
from cyvest.shared import SharedInvestigationContext

URL = "hxxp://Evil[.]Example/login"


class TestDerivation:
    def test_url_with_domain_host(self) -> None:
        assert derive_structural("url", "https://Evil.Example./path?q=1") == [(ObservableType.DOMAIN, "evil.example")]

    def test_url_with_ipv4_host(self) -> None:
        assert derive_structural(ObservableType.URL, "http://203.0.113.5:8080/x") == [
            (ObservableType.IPV4, "203.0.113.5")
        ]

    def test_url_with_ipv6_host(self) -> None:
        assert derive_structural("url", "http://[2001:db8::1]/x") == [(ObservableType.IPV6, "2001:db8::1")]

    def test_defanged_and_scheme_less_urls(self) -> None:
        assert derive_structural("url", URL) == [(ObservableType.DOMAIN, "evil.example")]
        assert derive_structural("url", "evil.example/path") == [(ObservableType.DOMAIN, "evil.example")]

    def test_email_derives_its_domain(self) -> None:
        assert derive_structural("email", "Alice@Corp.Example") == [(ObservableType.DOMAIN, "corp.example")]
        assert derive_structural("email", "alice[at]corp[.]example") == [(ObservableType.DOMAIN, "corp.example")]

    def test_other_types_and_unusable_hosts_derive_nothing(self) -> None:
        assert derive_structural("domain", "evil.example") == []
        assert derive_structural("ipv4", "203.0.113.5") == []
        assert derive_structural("hash", "d41d8cd98f00b204e9800998ecf8427e") == []
        assert derive_structural("url", "http://localhost/x") == []
        assert derive_structural("email", "not-an-address") == []


class TestApplication:
    def test_disabled_by_default(self) -> None:
        cv = Cyvest()
        cv.observable(cv.OBS.URL, URL)
        assert cv.relation_get_all() == {}
        assert len(cv.observable_get_all()) == 2

    def test_relation_is_an_extraction_from_parent_to_child_attributed_to_autolink(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        url = cv.observable(cv.OBS.URL, URL)
        domain = cv.observable_get(cv.OBS.DOMAIN, "evil.example")
        assert domain is not None
        (relation,) = cv.relation_get_all().values()
        assert relation.source_key == url.key
        assert relation.target_key == domain.key
        assert relation.kind is RelationKind.EXTRACTION
        assert relation.source == AUTOLINK_SOURCE

    def test_recreating_the_parent_is_idempotent(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        cv.observable(cv.OBS.URL, URL)
        cv.observable(cv.OBS.URL, URL)
        assert len(cv.relation_get_all()) == 1
        assert cv.observable_get(cv.OBS.DOMAIN, "evil.example").occurrence_count == 1

    def test_child_inherits_the_internal_flag_unless_told_otherwise(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        cv.observable(cv.OBS.EMAIL, "alice@corp.example", internal=True)
        assert cv.observable_get(cv.OBS.DOMAIN, "corp.example").internal is True

        cv = Cyvest(auto_link=AutoLink(inherit_internal=False))
        cv.observable(cv.OBS.EMAIL, "alice@corp.example", internal=True)
        assert cv.observable_get(cv.OBS.DOMAIN, "corp.example").internal is False

    def test_the_child_score_propagates_to_the_url(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        url = cv.observable(cv.OBS.URL, URL)
        cv.observable_get(cv.OBS.DOMAIN, "evil.example").with_ti("virustotal", 7.0)
        assert url.score == 7.0
        assert url.verdict is cv.VERDICT.MALICIOUS

    def test_the_setting_is_not_a_fact_but_the_edge_is(self) -> None:
        cv = Cyvest(auto_link=AutoLink())
        cv.observable(cv.OBS.URL, URL)
        loaded = Cyvest.io_load_dict(cv.io_to_dict())
        assert loaded.auto_link is None
        (relation,) = loaded.relation_get_all().values()
        assert relation.source.name == "cyvest.autolink"
        assert Cyvest.io_load_dict(cv.io_to_dict(), auto_link=AutoLink()).auto_link == AutoLink()

    def test_shared_context_hands_the_setting_to_every_worker(self) -> None:
        context = SharedInvestigationContext(auto_link=AutoLink())
        with context.task() as worker:
            worker.observable(worker.OBS.URL, URL)
        assert len(context.snapshot().relation_get_all()) == 1

    def test_backfill_links_what_was_created_before(self) -> None:
        cv = Cyvest()
        cv.observable(cv.OBS.URL, URL)
        cv.observable(cv.OBS.EMAIL, "alice@corp.example")
        assert backfill_structural_links(cv) == 2
        assert backfill_structural_links(cv) == 0
        assert backfill_structural_links(cv, AutoLink(structural=False)) == 0
