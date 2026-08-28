"""The public facade, exercised the way a caller actually uses it."""

from __future__ import annotations

import pytest

from cyvest import Cyvest, Verdict


def build_email_case() -> Cyvest:
    cv = Cyvest(root_data={"type": "email"}, investigation_name="IR-2431")
    url = cv.observable_create(cv.OBS.URL, "hxxp://bad.example/x")
    cv.observable_add_threat_intel(url, "virustotal", verdict=cv.VERDICT.MALICIOUS, weight=6.0)
    finding = cv.finding_create("url_in_body", "URL in body")
    cv.finding_link_observable(finding.key, url.key, cv.BASIS.OBSERVABLE)
    return cv


class TestFacade:
    def test_a_full_case_scores_end_to_end(self) -> None:
        cv = build_email_case()
        assert cv.get_global_score() == 6.0
        assert cv.get_global_verdict() is Verdict.MALICIOUS

    def test_the_root_is_reachable_and_scores_nothing(self) -> None:
        cv = build_email_case()
        assert cv.root().key == cv.observable_get_root().key
        assert cv.root().score == 0.0

    def test_observables_are_deduplicated_by_identity(self) -> None:
        cv = Cyvest()
        first = cv.observable_create(cv.OBS.IPV4, "1.2.3.4")
        second = cv.observable_create(cv.OBS.IPV4, "1.2.3.4")
        assert first.key == second.key
        assert len(cv.observable_get_all()) == 2  # the root plus this one

    def test_observable_get_accepts_a_key_or_an_identity(self) -> None:
        cv = Cyvest()
        created = cv.observable_create(cv.OBS.DOMAIN, "bad.example")
        assert cv.observable_get(created.key).key == created.key
        assert cv.observable_get(cv.OBS.DOMAIN, "bad.example").key == created.key
        assert cv.observable_get(cv.OBS.DOMAIN, "unknown.example") is None

    def test_proxies_refuse_assignment(self) -> None:
        cv = build_email_case()
        with pytest.raises(AttributeError, match="read-only"):
            cv.root().value = "tampered"


class TestFluentDsl:
    def test_chaining_reads_like_the_analysis(self) -> None:
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://bad.example")
        url.with_ti(cv.threat_intel_draft("proofpoint", verdict=cv.VERDICT.MALICIOUS, weight=cv.WEIGHT.HIGH))

        cv.tag_create("phishing")
        finding = cv.finding("url_in_body", "URL in body")
        finding.link_observable(url, cv.BASIS.OBSERVABLE).tagged("tag:phishing")

        assert cv.get_global_verdict() is Verdict.MALICIOUS
        assert cv.tag_get("phishing").aggregated_score == cv.WEIGHT.HIGH.value

    def test_relations_need_no_direction_argument(self) -> None:
        cv = Cyvest()
        parent = cv.observable(cv.OBS.FILE, "invoice.pdf", subtype="path", namespace="host-1")
        child = cv.observable(cv.OBS.URL, "hxxp://bad.example")
        cv.observable_add_threat_intel(child, "virustotal", verdict=cv.VERDICT.MALICIOUS, weight=6.0)
        parent.relate_to(child, cv.REL.EXTRACTION)

        assert parent.score == 6.0

    def test_describe_fills_in_the_story_without_touching_the_judgment(self) -> None:
        """A rule usually creates its finding before it knows the answer."""
        cv = Cyvest()
        finding = cv.finding("spf", "SPF", comment="pending").with_weight(3.0)

        finding.describe(comment="> Sending IP is not authorized", extra={"raw": "fail"})

        assert finding.comment == "> Sending IP is not authorized"
        assert finding.extra == {"raw": "fail"}
        assert finding.name == "SPF"
        assert finding.score == 3.0
        assert finding.verdict is Verdict.SUSPICIOUS

    def test_describe_leaves_omitted_fields_alone(self) -> None:
        cv = Cyvest()
        finding = cv.finding("spf", "SPF", comment="pending", extra={"raw": "fail"})

        finding.describe(name="SPF check")

        assert finding.name == "SPF check"
        assert finding.comment == "pending"
        assert finding.extra == {"raw": "fail"}


class TestDecisions:
    def test_allowlisting_reads_as_a_declared_act(self) -> None:
        """The fluent path must carry the attribution, or the short path is the untraceable one."""
        cv = build_email_case()
        url = cv.observable_get(cv.OBS.URL, "hxxp://bad.example/x")
        url.allowlist("Partner CDN", decided_by="alice")

        decision = cv.decision_get(url)
        assert decision.decided_by == "alice"
        assert decision.justification == "Partner CDN"
        assert url.verdict is Verdict.SAFE
        assert url.allowlisted is True

    def test_vacating_gives_the_computation_back(self) -> None:
        cv = build_email_case()
        url = cv.observable_get(cv.OBS.URL, "hxxp://bad.example/x")
        computed = url.score

        url.allowlist("Partner CDN", decided_by="alice")
        assert url.score == -1.0

        url.vacate("out of scope now", decided_by="soc-lead")
        assert url.score == computed
        assert url.allowlisted is False
        assert url.vacated is True

    def test_a_kind_carried_as_data_needs_no_named_verb(self) -> None:
        """The path for code replaying a feed, where the stance is a variable."""
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://unknown.example")
        url.decide(cv.DECISION.UPHOLD, "imported from the group blocklist", decided_by="feed")

        assert url.blocklisted is True
        assert url.verdict is Verdict.MALICIOUS

    def test_confirming_a_finding_beats_a_clean_graph(self) -> None:
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://unknown.example")
        finding = cv.finding("manual", "Analyst").link_observable(url, cv.BASIS.OBSERVABLE)
        finding.confirm("confirmed by memory analysis")

        assert cv.get_global_verdict() is Verdict.MALICIOUS
        assert finding.confirmed is True

    def test_dismissing_keeps_it_visible_but_uncounted(self) -> None:
        cv = build_email_case()
        finding = next(iter(cv.finding_get_all().values()))
        finding.dismiss("false positive")

        assert cv.finding_get(finding.key) is not None
        assert cv.get_global_score() == 0.0
        assert finding.dismissed is True


class TestPinning:
    """The reference scenario, through the fluent API."""

    @staticmethod
    def _case():
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://bad.example/x")
        trap = cv.observable_add_threat_intel(url, "proofpoint-trap", verdict=cv.VERDICT.SUSPICIOUS, weight=4.0)
        return cv, url, trap

    def test_a_pinned_finding_holds_while_the_observable_rises(self) -> None:
        cv, url, trap = self._case()
        pinned = cv.finding("pp-trap-hit", "TRAP").pin(trap)
        rising = cv.finding("url-reputation", "Reputation").link_observable(url, cv.BASIS.OBSERVABLE)

        cv.observable_add_threat_intel(url, "urlhaus", verdict=cv.VERDICT.MALICIOUS, weight=6.0)

        assert pinned.score == 4.0
        assert rising.score == 6.0

    def test_pin_accepts_a_signal_recovered_from_the_observable(self) -> None:
        cv, url, _ = self._case()
        finding = cv.finding("pp-trap-hit", "TRAP").pin(url.signal("proofpoint-trap"))
        assert finding.score == 4.0

    def test_pin_chains(self) -> None:
        cv, url, trap = self._case()
        cv.tag_create("phishing")
        finding = cv.finding("pp-trap-hit", "TRAP").pin(trap).tagged("tag:phishing")
        assert finding.score == 4.0


class TestVerdictSemantics:
    def test_asserted_and_computed_verdicts_are_distinct(self) -> None:
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://bad.example")
        cv.observable_add_threat_intel(url, "virustotal", verdict=cv.VERDICT.MALICIOUS, weight=6.0)
        finding = cv.finding("spf_pass", "SPF valide", verdict=cv.VERDICT.SAFE, weight=4.0)
        finding.link_observable(url, cv.BASIS.OBSERVABLE)

        assert finding.verdict is Verdict.SAFE
        assert finding.computed_verdict is Verdict.MALICIOUS
        assert finding.own_term_suppressed is True

    def test_stating_a_verdict_alone_is_enough(self) -> None:
        cv = Cyvest()
        cv.finding("ceo_impersonation", "Usurpation", verdict=cv.VERDICT.MALICIOUS)
        assert cv.get_global_verdict() is Verdict.MALICIOUS

    def test_stating_a_weight_alone_is_enough_through_the_fluent_path_too(self) -> None:
        """
        ``with_weight`` used to leave the verdict at ``INFO``, which claims nothing.

        The finding then scored 0 despite carrying a weight — the same footgun the facade already
        avoided, reached through the other door.
        """
        cv = Cyvest()
        finding = cv.finding("suspicious_macro").with_weight(8.5)

        result = cv.get_report().finding(finding.key)
        assert result.score == pytest.approx(8.5)
        assert result.verdict is Verdict.MALICIOUS


class TestConclusions:
    """The facade's entry point for an analysis that concludes rather than accumulates."""

    def test_a_conclusion_tops_the_total_up_to_its_verdict(self) -> None:
        cv = Cyvest()
        cv.finding("spf_fail", "SPF failure", verdict=cv.VERDICT.SUSPICIOUS, weight=3.2)
        conclusion = cv.conclusion("ai_review", "AI review", verdict=cv.VERDICT.MALICIOUS)

        assert cv.get_global_score() == 5.0
        assert conclusion.is_conclusion is True
        assert conclusion.effect is cv.EFFECT.FLOOR
        assert conclusion.applied_bound == pytest.approx(1.8)

    def test_a_safe_conclusion_brings_the_total_down_to_its_verdict(self) -> None:
        """A declared benign context — an awareness campaign — neutralises what the rules found."""
        cv = Cyvest()
        cv.finding("spf_fail", "SPF failure", verdict=cv.VERDICT.MALICIOUS, weight=8.0)
        conclusion = cv.conclusion("awareness_campaign", "Awareness campaign", verdict=cv.VERDICT.SAFE)

        assert cv.get_global_verdict() is cv.VERDICT.SAFE
        assert cv.get_global_score() < 0.0
        assert conclusion.effect is cv.EFFECT.CEILING
        assert conclusion.applied_bound < 0.0

    def test_a_conclusion_that_changes_nothing_says_so(self) -> None:
        cv = Cyvest()
        cv.finding("known_malware", "Known malware", verdict=cv.VERDICT.MALICIOUS, weight=8.0)
        conclusion = cv.conclusion("ai_review", "AI review", verdict=cv.VERDICT.MALICIOUS)

        assert cv.get_global_score() == 8.0
        assert conclusion.applied_bound == 0.0

    def test_a_conclusion_has_no_score_of_its_own(self) -> None:
        cv = Cyvest()
        conclusion = cv.conclusion("ai_review", verdict=cv.VERDICT.MALICIOUS)

        assert cv.get_report().finding(conclusion.key).score is None
        assert conclusion.applied_bound == 5.0

    def test_weighting_a_conclusion_is_refused(self) -> None:
        cv = Cyvest()
        conclusion = cv.conclusion("ai_review", verdict=cv.VERDICT.MALICIOUS)

        with pytest.raises(ValueError, match="never from a weight"):
            conclusion.with_weight(8.5)

    def test_but_changing_a_weight_never_flips_a_stated_conclusion(self) -> None:
        cv = Cyvest()
        finding = cv.finding("known_good", verdict=cv.VERDICT.SAFE).with_weight(2.0)

        assert cv.get_report().finding(finding.key).score == pytest.approx(-2.0)
        assert finding.verdict is Verdict.SAFE

    def test_a_verdict_worth_nothing_is_expressible_and_visible(self) -> None:
        """
        v6 allowed the same statement but displayed only the label.

        Here the divergence is readable in three places: the asserted verdict, the computed one,
        and a named contribution worth zero.
        """
        cv = Cyvest()
        finding = cv.finding("ai_analysis", verdict=cv.VERDICT.MALICIOUS, weight=0.0)

        result = cv.get_report().finding(finding.key)
        assert finding.verdict is Verdict.MALICIOUS
        assert finding.computed_verdict is Verdict.INFO
        assert result.score == pytest.approx(0.0)
        assert [(c.label, c.value) for c in result.contributions] == [("rule floor · MALICIOUS", 0.0)]

    def test_an_analyst_verdict_on_an_observable_stays_attributable(self) -> None:
        cv = Cyvest()
        url = cv.observable(cv.OBS.URL, "hxxp://bad.example")
        signal = cv.observable_set_verdict(url, cv.VERDICT.SUSPICIOUS, source="alice")

        assert signal.source == "alice"
        assert url.verdict is Verdict.SUSPICIOUS


class TestMerge:
    def test_the_reference_scenario_through_the_facade(self) -> None:
        left = Cyvest(investigation_id="i1")
        url_left = left.observable(left.OBS.URL, "hxxp://bad.example/x")
        trap = left.observable_add_threat_intel(url_left, "proofpoint", verdict=left.VERDICT.MALICIOUS, weight=2.0)
        f1 = left.finding("url_in_body").pin(trap)
        f_open = left.finding("url_open").link_observable(url_left)

        right = Cyvest(investigation_id="i2")
        url_right = right.observable(right.OBS.URL, "hxxp://bad.example/x")
        right.observable_add_threat_intel(url_right, "virustotal", verdict=right.VERDICT.MALICIOUS, weight=3.0)
        f2 = right.finding("url_reputation").link_observable(url_right)

        left.merge_investigation(right)

        assert left.finding_get(f1.key).score == 2.0  # pinned: holds
        assert left.finding_get(f_open.key).score == 3.0  # open: rises
        assert left.finding_get(f2.key).score == 3.0
        assert left.observable_get(url_left.key).score == 3.0

    def test_seeing_an_artifact_twice_counts_twice(self) -> None:
        cv = Cyvest()
        cv.observable_create("url", "https://x.test")
        cv.observable_create("url", "https://x.test")
        observable = cv.observable_create("url", "https://x.test")

        assert observable.occurrence_count == 3

    def test_but_re_merging_a_fragment_does_not_inflate_the_tally(self) -> None:
        """
        Occurrence counters are per fragment and merged by max.

        Without that, a pipeline that merges the same fragment twice would report an artifact as
        twice as prevalent as it is — and merging would stop being idempotent.
        """
        fragment = Cyvest(investigation_id="frag-1")
        fragment.observable_create("url", "https://y.test")
        fragment.observable_create("url", "https://y.test")

        target = Cyvest(investigation_id="target")
        target.merge_investigation(fragment)
        target.merge_investigation(fragment)

        assert target.observable_get("obs:url:https://y.test").occurrence_count == 2


class TestEngines:
    def test_the_registry_is_exposed_and_resolves_aliases(self) -> None:
        assert Cyvest.ENGINES()["basic"] == "basic-v1"

    def test_the_report_records_the_resolved_engine_id(self) -> None:
        assert Cyvest(engine="basic").get_report().engine_id == "basic-v1"
