"""
Guards on the evaluation layer itself: purity, the engine registry, scopes and relations.

The purity check is static rather than behavioural because the failure mode it prevents — an
engine quietly consulting the clock — only shows up years later, when an archived report stops
matching the document it came from.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cyvest.enums import Aggregation, DecisionKind, RelationKind, Scope, SourceClass, Verdict
from cyvest.evaluation import ResolvedScope, evaluate
from cyvest.evaluation.engines import available_aliases, get_engine, resolve_engine_alias
from cyvest.facts import Finding, Observable, ObservableLink, Relation, SourceRef, Tag, ThreatIntel
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.investigation import Investigation
from cyvest.io_serialization import save_investigation_json
from cyvest.policy import DEFAULT_POLICY, Policy

SRC = SourceRef(name="feed", source_class=SourceClass.VENDOR_FEED)
EVALUATION_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "cyvest" / "evaluation"

CLOCK_CALLS = {"now", "utcnow", "today", "time", "monotonic", "perf_counter"}


def store(fragment_id: str = "f1") -> FactStore:
    return FactStore(InvestigationHeader(investigation_id="inv", fragment_ids=(fragment_id,)))


def observable(store_: FactStore, value: str, fragment_id: str = "f1") -> Observable:
    obs = Observable(type="url", value=value, source=SRC, fragment_id=fragment_id)
    store_.append(obs)
    return obs


def intel(
    store_: FactStore,
    obs: Observable,
    weight: float,
    fragment_id: str = "f1",
    source_name: str = "feed",
) -> ThreatIntel:
    signal = ThreatIntel(
        subject_key=obs.key,
        verdict=Verdict.MALICIOUS,
        weight=weight,
        source=SourceRef(name=source_name, source_class=SourceClass.VENDOR_FEED),
        fragment_id=fragment_id,
    )
    store_.append(signal)
    return signal


class TestPurity:
    def test_no_module_under_evaluation_reads_the_clock(self) -> None:
        offenders: list[str] = []
        for path in EVALUATION_PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in CLOCK_CALLS:
                        offenders.append(f"{path.name}:{node.lineno} → {node.func.attr}()")
        assert offenders == [], f"evaluation/ must not read the clock: {offenders}"

    def test_the_same_store_evaluates_identically_twice(self) -> None:
        target = store()
        obs = observable(target, "hxxp://a")
        intel(target, obs, 4.0)
        assert evaluate(target).model_dump() == evaluate(target).model_dump()


class TestDeterminism:
    """
    Iteration order must never reach the report.

    The adjacency indexes are sets, so before they were sorted the very same document could yield
    a different verdict from one interpreter run to the next — precisely what the archived-report
    invariant forbids. ``test_the_same_store_evaluates_identically_twice`` could not catch it:
    set iteration is stable *within* a process, so the failure only appears across processes.
    """

    REPORT_SCRIPT = (
        "import sys; from cyvest import Cyvest; print(Cyvest.io_load_json(sys.argv[1]).get_report().model_dump_json())"
    )

    def test_accessors_return_facts_in_a_stable_order(self) -> None:
        target = store()
        hub = observable(target, "hxxp://hub")
        signals = [intel(target, hub, 1.0 + index, source_name=f"feed-{index}") for index in range(12)]
        expected = [fact.key for fact in sorted(signals, key=lambda fact: (fact.seq, fact.key))]
        assert [fact.key for fact in target.signals_for(hub.key)] == expected

    def _document(self, path: Path) -> None:
        investigation = Investigation(root_data={}, investigation_id="inv-determinism")
        hub = investigation.add_observable(
            Observable(type="url", value="hxxp://hub", source=SRC, fragment_id="inv-determinism")
        )
        for index in range(12):
            investigation.append(
                ThreatIntel(
                    subject_key=hub.key,
                    verdict=Verdict.MALICIOUS,
                    weight=1.0 + index * 0.1,
                    confidence=0.7 + index * 0.01,
                    source=SourceRef(name=f"feed-{index}", source_class=SourceClass.VENDOR_FEED),
                    fragment_id="inv-determinism",
                )
            )
        for index in range(12):
            child = investigation.add_observable(
                Observable(
                    type="domain",
                    value=f"child{index}.example",
                    source=SRC,
                    fragment_id="inv-determinism",
                )
            )
            investigation.append(
                ThreatIntel(
                    subject_key=child.key,
                    verdict=Verdict.SUSPICIOUS,
                    weight=0.3 + index * 0.11,
                    source=SourceRef(name=f"child-feed-{index}", source_class=SourceClass.VENDOR_FEED),
                    fragment_id="inv-determinism",
                )
            )
            investigation.add_relation(hub, child, RelationKind.EXTRACTION, confidence=0.9)
        # Two contradictory stances on one target: the branch that used to depend on iteration
        # order. They now share a key, so the merge law settles them before evaluation ever runs.
        investigation.add_decision(hub.key, DecisionKind.REFUTE, "a")
        investigation.add_decision(hub.key, DecisionKind.UPHOLD, "b")
        save_investigation_json(investigation, path)

    def _report_under_hash_seed(self, path: Path, seed: str) -> str:
        completed = subprocess.run(
            [sys.executable, "-c", self.REPORT_SCRIPT, str(path)],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        return completed.stdout

    def test_a_saved_document_reports_the_same_under_any_hash_seed(self, tmp_path: Path) -> None:
        document = tmp_path / "case.json"
        self._document(document)
        reports = {self._report_under_hash_seed(document, seed) for seed in ("0", "1", "2", "3")}
        assert len(reports) == 1, "the same document produced different reports across interpreter runs"


class TestEngineRegistry:
    def test_alias_resolves_to_the_versioned_id(self) -> None:
        assert resolve_engine_alias("basic") == "basic-v1"
        assert "basic" in available_aliases()

    def test_a_versioned_id_resolves_to_itself(self) -> None:
        assert resolve_engine_alias("basic-v1") == "basic-v1"

    def test_the_report_records_the_resolved_id_never_the_alias(self) -> None:
        target = store()
        observable(target, "hxxp://a")
        assert evaluate(target, engine="basic").engine_id == "basic-v1"

    def test_unknown_engine_fails_explicitly(self) -> None:
        with pytest.raises(KeyError, match="Unknown scoring engine"):
            get_engine("bayesian-v1")

    def test_basic_v1_is_stable(self) -> None:
        assert get_engine("basic-v1").experimental is False


class TestLinkScope:
    def test_a_finding_may_mix_scopes_on_one_observable(self) -> None:
        left = store("i1")
        url = observable(left, "hxxp://a", "i1")
        intel(left, url, 2.0, "i1", source_name="proofpoint")
        finding = Finding(
            rule_id="mixed",
            subject_key=url.key,
            source=SRC,
            fragment_id="i1",
            observable_links=[
                ObservableLink(observable_key=url.key, scope=Scope.OWN_FRAGMENT),
                ObservableLink(observable_key=url.key, scope=Scope.ALL),
            ],
        )
        left.append(finding)

        right = store("i2")
        url2 = observable(right, "hxxp://a", "i2")
        intel(right, url2, 5.0, "i2", source_name="virustotal")

        report = evaluate(left.union(right))
        # The ALL link sees both fragments and wins over the local one.
        assert report.finding(finding.key).score == 5.0
        assert report.observable(url.key, ResolvedScope.own("i1")).score == 2.0

    def test_links_dedupe_on_key_and_scope_not_on_key_alone(self) -> None:
        finding = Finding(
            rule_id="r",
            subject_key="obs:url:a",
            source=SRC,
            fragment_id="f1",
            observable_links=[
                ObservableLink(observable_key="obs:url:a", scope=Scope.OWN_FRAGMENT),
                ObservableLink(observable_key="obs:url:a", scope=Scope.ALL),
                ObservableLink(observable_key="obs:url:a", scope=Scope.ALL),
            ],
        )
        assert len(finding.observable_links) == 2


class TestRelationDirection:
    def _chain(self, kind: RelationKind, aggregation: Aggregation = Aggregation.MAX) -> float:
        target = store()
        parent = observable(target, "hxxp://parent")
        child = observable(target, "hxxp://child")
        intel(target, child, 4.0)
        target.append(Relation(source_key=parent.key, target_key=child.key, kind=kind, source=SRC, fragment_id="f1"))
        report = evaluate(target, policy=Policy(aggregation=aggregation))
        return report.observable(parent.key).score

    def test_extraction_propagates_from_source_to_target(self) -> None:
        assert self._chain(RelationKind.EXTRACTION) == 4.0

    def test_pivot_propagates(self) -> None:
        assert self._chain(RelationKind.PIVOT) == 4.0

    def test_related_to_is_excluded_from_propagation(self) -> None:
        assert self._chain(RelationKind.RELATED_TO) == 0.0

    def test_attenuation_is_applied_per_kind(self) -> None:
        target = store()
        parent = observable(target, "hxxp://parent")
        child = observable(target, "hxxp://child")
        intel(target, child, 4.0)
        target.append(
            Relation(
                source_key=parent.key,
                target_key=child.key,
                kind=RelationKind.PIVOT,
                source=SRC,
                fragment_id="f1",
            )
        )
        policy = Policy(attenuation={**DEFAULT_POLICY.attenuation, RelationKind.PIVOT: 0.5})
        assert evaluate(target, policy=policy).observable(parent.key).score == 2.0

    def test_relation_confidence_modulates_the_child_contribution(self) -> None:
        target = store()
        parent = observable(target, "hxxp://parent")
        child = observable(target, "hxxp://child")
        intel(target, child, 4.0)
        target.append(
            Relation(
                source_key=parent.key,
                target_key=child.key,
                kind=RelationKind.EXTRACTION,
                confidence=0.5,
                source=SRC,
                fragment_id="f1",
            )
        )
        assert evaluate(target).observable(parent.key).score == 2.0

    def test_sum_mode_adds_children_on_top_of_the_strongest_signal(self) -> None:
        target = store()
        parent = observable(target, "hxxp://parent")
        intel(target, parent, 1.0)
        child = observable(target, "hxxp://child")
        intel(target, child, 4.0)
        target.append(
            Relation(
                source_key=parent.key,
                target_key=child.key,
                kind=RelationKind.EXTRACTION,
                source=SRC,
                fragment_id="f1",
            )
        )
        assert evaluate(target, policy=Policy(aggregation=Aggregation.SUM)).observable(parent.key).score == 5.0

    def test_a_cycle_does_not_recurse_forever(self) -> None:
        target = store()
        a = observable(target, "hxxp://a")
        b = observable(target, "hxxp://b")
        intel(target, b, 4.0)
        forward = Relation(source_key=a.key, target_key=b.key, kind=RelationKind.PIVOT, source=SRC, fragment_id="f1")
        backward = Relation(source_key=b.key, target_key=a.key, kind=RelationKind.PIVOT, source=SRC, fragment_id="f1")
        target.append(forward)
        target.append(backward)
        assert evaluate(target).observable(a.key).score == 4.0


class TestTagHierarchy:
    def test_ancestors_follow_the_delimiter(self) -> None:
        tag = Tag(name="header:auth:dkim", source=SRC, fragment_id="f1")
        assert tag.ancestors == ["header", "header:auth"]

    def test_finding_keys_are_deduped(self) -> None:
        tag = Tag(name="phishing", finding_keys=("a", "a", "b"), source=SRC, fragment_id="f1")
        assert tag.finding_keys == ("a", "b")
