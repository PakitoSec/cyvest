# Migration 6.x → 7.0

Version 7 is a rewrite of the model, not a coat of paint. The public API changed almost
everywhere, and there is **no compatibility layer**: 7.0 was written before 6.x was published, so
nothing is deprecated — things simply moved.

Reading an old **document** is still supported: `cyvest migrate` and `Cyvest.io_load_json(...,
migrate=True)` walk a 5.x or 6.x file up to the current schema.

---

## 1. The one idea behind the rewrite

In v6, a score was **stored**. `Observable.score`, `Finding.score`, `investigation.score` were
fields, mutated in place by propagation passes. That made two things impossible:

- **Auditing a number.** Nothing recorded *why* an observable ended at 4.7, only that it did.
- **Merging honestly.** Two investigations touching the same observable had to reconcile stored
  aggregates, which is why v6 needed `origin_investigation_id` to keep merged findings apart.

In v7, facts are immutable and **every derived number lives in the report**:

```python
cv = Cyvest(investigation_name="case")
url = cv.observable_create("url", "https://evil.test")
url.with_ti("VirusTotal", 6.0)

cv.get_report().observable(url.key).score      # derived, never stored
cv.get_report().observable(url.key).contributions  # and here is why
```

A serialized investigation still **carries** its report — that is what lets the JS SDK stay
read-only and never reimplement a scoring rule — but the report is an output, recomputed by
`reevaluate()` whenever the policy or the engine changes.

!!! note "A magnitude from a source is still a fact"
    "VirusTotal returned 6" is an observation, not an aggregate. It stays a first-class field
    (`weight`), never buried in a payload. The v6 mistake was storing *aggregated* scores, not
    storing reported ones.

---

## 2. Renamings at a glance

| v6 | v7 | Note |
|---|---|---|
| `Level` | `Verdict` | Same five useful values; see §3 |
| `Enrichment` | `Evidence` | Never scored in v6 either; the name now says so |
| `Relationship` (embedded in the observable) | `Relation` (standalone fact) | §5 |
| `score` (on facts) | `weight` | A magnitude *asserted*, not derived |
| `score` (derived) | `report.*.score` | §1 |
| `whitelisted` | `Decision(REFUTE)` | §6 |
| `origin_investigation_id` | `fragment_id` (on the finding) | Carried over, because it *is* the fragment; §7 |
| `propagation_mode` | `ObservableLink.basis` | Still **per link**, not per finding |
| `observable_add_relationship` | `observable_add_relation` | |
| `enrichment_create` | `evidence_create` | |
| `get_global_level` | `get_global_verdict` | |
| `get_statistics` | `statistics()` | Computed on demand, nothing registered |
| `io_load_threat_intel_draft` | `io_load_signal` | Declared contract, strict validation; §10 |
| `cyvest.io_serialization` / `io_schema` / `io_rich` | `cyvest.io.*` / `cyvest.schema.*` | Import paths only; §8 |
| *(new)* | `Finding.effect` | Defaults to `ADDITIVE`; a migrated v6 document is numerically unchanged. See §4 |

---

## 3. `Level` and `Verdict` merged

v6 had seven levels, two of which were not levels at all:

- `NONE` meant "nothing was said" — now expressed by the absence of a fact.
- `TRUSTED` had **two lives**: a *computed* one (any score below zero) and an *asserted* one
  (`whitelisted=True`). Only the first is a verdict; the second is a decision (§6).

v7 keeps five values, aligned exactly on v6's score bands, so a migrated document keeps its
labels:

| Verdict | Score band | Polarity |
|---|---|---|
| `SAFE` | `< 0` | −1 |
| `INFO` | `= 0` | 0 |
| `NOTABLE` | `]0, 3[` | +1 |
| `SUSPICIOUS` | `[3, 5[` | +1 |
| `MALICIOUS` | `>= 5` | +1 |

`projection.py` reduces to one function, `verdict_from_score()`, which **is** v6's
`get_level_from_score`.

```python
# v6
from cyvest import Level
observable.with_ti("VirusTotal", score=Decimal("6.0"), level=Level.MALICIOUS)

# v7 — either half implies the other
observable.with_ti("VirusTotal", 6.0)
observable.with_ti("VirusTotal", verdict=Verdict.MALICIOUS)
```

---

## 4. Weight, confidence, verdict

A judgment now has three separable parts, where v6 had one number:

- **`verdict`** — *what* is claimed (the direction).
- **`weight`** — *how much* it is worth (the magnitude).
- **`confidence`** — *how sure* the source is (0–1), which scales the weight.

Stating one of `verdict` / `weight` is enough; the other is supplied at evaluation time. A weight
alone yields the verdict of its band (`finding_create("phishing", weight=8.5)` → `MALICIOUS`,
score `8.5`). A verdict alone leaves the weight unset on the fact, and the engine falls back on
`policy.default_weight_by_verdict` — so
`finding_create("phishing", verdict=Verdict.MALICIOUS)` scores `7.0` under the default policy, and
follows the policy if you change it.

### Conclusions have no weight at all

v7 adds a fourth possibility that v6 could not express: a finding that renders a verdict on the
case after reading the others — an AI review, most of the time. In v6 the only way to record it
was to guess a score, which either double-counted the evidence the analysis had just read or
undershot its own conclusion.

```python
cv.conclusion("ai_review", "Analyse IA", verdict=cv.VERDICT.MALICIOUS)
```

Such a finding carries `effect=FLOOR`: it raises the total just enough to reach `MALICIOUS`, and
adds nothing if the case is already there. It takes no `weight` — its magnitude *is* the bound of
its verdict — and stating one raises.

A conclusion may also point the other way. `verdict=SAFE` carries `effect=CEILING` and *lowers*
the total to the band it asserts — the declared benign context v6 could not express either:

```python
cv.conclusion("awareness_campaign", "Campagne PSAT", verdict=cv.VERDICT.SAFE)
```

The direction is never passed, it follows the verdict; ceilings apply after floors. See
[conclusions](scoring-model.md#conclusions-a-finding-that-concludes-instead-of-accumulating).

Every finding coming from a v6 document is `ADDITIVE`, so migration changes no number.

---

## 5. Relations became facts

In v6 a relationship lived **inside** the source observable and carried a `direction`
(`outbound` / `inbound` / `bidirectional`). Two consequences: merging two investigations meant
merging lists inside objects, and `EXTRACTION` + `BIDIRECTIONAL` expressed something incoherent —
an extraction that is also its own parent.

In v7 a `Relation` is a standalone fact with `source_key`, `target_key` and a `kind`. Direction is
implied: **source is the parent, target is the child**.

```python
cv.observable_add_relation(email.key, url.key, cv.REL.EXTRACTION)
```

| kind | Propagates score |
|---|---|
| `extraction` | yes |
| `pivot` | yes |
| `related-to` | **no** — symmetric, and deliberately inert |

The migration maps `bidirectional` to `related-to`, which loses propagation on those edges. That
is intentional: an edge that pointed both ways had no defensible propagation semantics.

---

## 6. The allowlist became operative

This is a **behaviour change**, not just a rename. In v6, `whitelisted` was recorded and
displayed, but it never entered the score: the string `whitelisted` appears nowhere in v6's
`score.py`. An allowlisted observable with a `MALICIOUS` intel still scored `MALICIOUS`.

In v7 a `Decision` **bounds** the derivation:

| Decision | Target | Effect |
|---|---|---|
| `REFUTE` | observable | caps the observable at `policy.refute_ceiling` (`-1.0`) |
| `UPHOLD` | observable | floors the observable at `policy.uphold_floor` (`9.0`) |
| `UPHOLD` | finding | floors the finding at `policy.uphold_floor` (`9.0`) |
| `REFUTE` | finding | removes the finding from the total |
| `VACATED` | either | retracts an earlier decision; the natural score stands |

The kind carries the **intent**; the target key already carries the family, so the analyst's words
— *allowlisted*, *blocklisted*, *confirmed*, *dismissed* — are rebuilt for display rather than
enumerated in the model. The façade still speaks them:

```python
url.allowlist("Corporate sandbox", decided_by="rssi")
cv.get_report().observable(url.key).score   # <= -1.0, whatever the intel says
```

**A migrated v6 investigation containing whitelisted observables will therefore score lower than
it did in v6.** That is the intended correction.

A decision carries `target_key`, `kind` and a **required** `justification`. Who decided and when
come from the `Fact` envelope (`source`, `asserted_at`), like every other fact.

### Investigation-level whitelists

v6 also had whitelist entries on the investigation itself, whose `identifier` was a free-form
string. Those that name an observable become a `REFUTE` decision on it, which is what v6
meant by them.

The rest name nothing v7 can bound — a ticket reference, an analyst note. They are kept as
**evidence** (`evidence_type="legacy_whitelist"`), one entry per record, and deliberately *not* as
a decision on the root: `REFUTE` caps its target's score and marks every contribution on it
unretained, so anchoring them there would manufacture a verdict nobody asserted, out of a string
that had no scoring effect in v6 either.

What migration cannot guess, you state. When such an entry did mean *"this whole case is a known
benign context"* — an awareness campaign, a sanctioned pentest, an authorised scanner — the v7
form is a **ceiling conclusion**, which bounds the investigation total the way `REFUTE` bounds an
observable:

```python
cv.conclusion("awareness_campaign", "Campagne PSAT", verdict=cv.VERDICT.SAFE)
```

Do **not** model it as a finding with a large negative weight: a weight is a term of the sum, so
enough inculpatory findings climb back over it. A ceiling caps.

!!! note "Gating is not scoring"
    v6's `is_whitelisted()` was often read mid-run to skip expensive enrichment. That is an
    orchestration decision, not a fact about the case, and v7 exposes no equivalent on purpose:
    reading it means evaluating the whole store on every call. Keep the flag in your own
    orchestrator and let the conclusion carry the score and the audit trail.

### Keys are regenerated, and every reference follows

v7 normalizes an observable's value, so a v6 `obs:domain:EVIL.com` is re-keyed to
`obs:domain:evil.com`. The migration therefore translates *every* cross-reference — relations on
both ends, threat-intel subjects, finding links, tag members and whitelist identifiers — through
the map it builds while regenerating the observables. A reference it cannot place is left as it
was rather than rewritten.

Findings keep the shape v6 gave them: `fnd:{name}` becomes `fnd:{rule_id}`, the same string under
a new name, so a tag's members go through the same translation as a formality.

Signals change prefix: v6's `ti:{source}:{observable_key}` becomes `sig:{source}:{observable_key}`.
The prefix names the *family*, not its first member — `ThreatIntel` is one signal kind among the
ones to come, and `ti:` would have locked the namespace behind it. The migration regenerates these
keys, so nothing in a v6 document needs to be rewritten by hand.

### Two contradictory decisions on one target

A decision is keyed `dec:{target_key}`, so **one target holds exactly one stance**. Asserting the
opposite kind does not create a second fact competing at evaluation time — it replaces the first
one through the ordinary merge law: **the freshest assertion wins**, on `occurred_at or
asserted_at` then `seq`. To withdraw a stance without asserting its opposite, use `VACATED`.

---

## 7. Merging, and why a score can now go down

Merging is a **union of immutable facts**. It is idempotent, commutative and associative — merging
the same fragment twice changes nothing, and merge order does not matter.

When two fragments assert the *same* fact differently, the conflict is settled by **freshness**:
the most recently asserted wins. v6 resolved conflicts by `max`, so a score could only ever rise.

!!! warning "A rescinded verdict now lowers the score"
    If VirusTotal said `MALICIOUS` on Monday and `SAFE` on Tuesday, v6 kept Monday. v7 keeps
    Tuesday. This is the point — but it means a re-run can legitimately reduce a score.

Identity no longer needs `origin_investigation_id`, because a finding's identity is its `rule_id`:
reusing it is one finding, in any number of investigations. A rule that must fire once per
observable says so with `external_id=observable.key`.

The origin itself is **not** dropped, though: it becomes the finding's `fragment_id`, which keeps
every migrated fact attributable to the investigation that asserted it.

It also decides, **at import time**, what each link scores on. v6 gated a `LOCAL_ONLY` link on
`origin_investigation_id == investigation_id`: an imported one was simply inert. So:

| v6 `propagation_mode` | origin | v7 `ObservableLink.basis` |
|---|---|---|
| `GLOBAL` | any | `OBSERVABLE` |
| `LOCAL_ONLY` | matches the document | `OBSERVABLE` |
| `LOCAL_ONLY` | foreign | `NONE` — inert, exactly as in v6 |

Reading an imported `LOCAL_ONLY` link as a live one would make links that scored nothing in v6
start propagating, silently raising the score of any merged investigation. The third basis,
`SIGNALS`, has no v6 counterpart and is never produced by migration.

### What v6 could not state

A finding that scores on the intel **it** fetched, whatever else lands on the observable
afterwards — including intel fetched moments later by the very same worker:

```python
trap = cv.observable_add_threat_intel(url, "proofpoint-trap", verdict=cv.VERDICT.SUSPICIOUS, weight=4.0)
cv.finding("pp-trap-hit").pin(trap)
```

!!! warning "A merged total is a sum, and it is not damped"
    Merging two investigations that both flag the same URL yields two findings, both reading the
    merged observable, so the total is the sum of both. v6's `LOCAL_ONLY` damped this by accident
    of topology — it depended on which investigation had produced the finding. If a finding must
    hold its own value, pin it; that is explicit and survives any refactoring of your workers.

---

## 8. Serialization

```json
{
  "schema_version": "7.0.0",
  "header": { "investigation_id": "...", "root_key": "obs:file:__cyvest_root__", "...": "..." },
  "policy_version": "default-v1",
  "engine_id": "basic-v1",
  "facts": { "observables": {}, "relations": {}, "signals": {}, "evidences": {}, "findings": {} },
  "decisions": {},
  "tags": {},
  "report": { "...": "..." }
}
```

- Facts moved under `facts.*`, still as maps keyed by fact key.
- `report` is **required**: a document without one would force every consumer to reimplement the
  engine.
- Signals carry a `kind` discriminator, so future scoring inputs can join `ThreatIntel` without
  breaking the schema.

### Migrating a file

```bash
cyvest migrate old.json -o new.json          # detects 5.x or 6.x automatically
cyvest migrate old.json -o new.json --from 6
```

```python
cv = Cyvest.io_load_json("old.json", migrate=True)
```

Migration is a chain of pure dict-to-dict steps, so a 5.x document passes through 6.0 on its way
to 7.0. Loading a **newer** document than the library understands is refused rather than guessed
at.

### Module prefixes became packages

`io_` and `_schema` were both packages waiting to happen, like `facts/` and `evaluation/` before
them. The split follows the boundary itself: `schema/` declares the *shapes* that cross it, `io/`
moves the data.

| v6 | v7 |
|---|---|
| `cyvest.io_serialization` | `cyvest.io.serialization` |
| `cyvest.io_rich` | `cyvest.io.render` |
| `cyvest.model_schema` | `cyvest.schema.investigation` |
| `cyvest.signal_schema` | `cyvest.schema.signal` |
| `cyvest.io_schema` | `cyvest.schema` (the `get_*_schema()` generators) |

Contents are unchanged — only the import paths move. Three notes:

- `cyvest.io` does **not** shadow the standard library `io`; Python 3 resolves imports absolutely,
  so a module doing `import io` still gets the stdlib one.
- `cyvest/io/__init__.py` re-exports nothing on purpose. `render` pulls in `rich`, and the facade
  imports `serialization` lazily, so writing a JSON file must not drag a terminal renderer in.
  Import the submodule you need.
- `cyvest/schema/__init__.py` *does* re-export, and hosts the JSON Schema generators that used to
  sit in `io_schema`. Generating a schema and declaring one are the same concern seen from two
  sides, and neither costs an import the library was not already paying.

Nothing exported from the `cyvest` root moved: `SignalEnvelope` and `SIGNAL_SCHEMA_VERSION` are
still `from cyvest import ...`. Facade methods (`io_save_json`, `display_summary`, …) keep their
names too — they were never the module path.

---

## 9. Scoring engines

Evaluation is now pluggable. `basic-v1` reproduces v6's arithmetic; the engine that produced a
report is recorded in it.

```bash
cyvest engines
cyvest show case.json --engine basic-v1     # evaluate with another engine
```

Because scores from two engines are not on the same scale, `compare_investigations` **refuses** to
diff reports from different engines unless you pass `allow_engine_mismatch=True`.

---

## 10. Ingesting from an external system

`io_load_threat_intel_draft` and its tolerant parsing are replaced by a **published contract**:

```python
# v6
ti = Cyvest.io_load_threat_intel_draft(
    report,
    preprocessor=normalise_vendor_payload,
    safe_getter=lambda d: d.get("extra", {}).get("task_name", ""),
    safe_values=["MISP.analyzer.DBWarningList"],
)
obs.with_ti_draft(ti)

# v7
obs.with_ti(Cyvest.io_load_signal(report))
```

`safe_getter` / `safe_values` are gone: they existed only because v6 had no way to say *benign*.
A source now answers `verdict: "SAFE"`.

Validation is strict — an unknown field raises instead of producing a signal that quietly scores
zero. Publish the schema to your producers with:

```bash
cyvest schema --which signal -o schema/cyvest.signal.schema.json
```

See [External Signals](external-signals.md).

---

## 11. The JavaScript SDK

`@cyvest/cyvest-js` is now **read-only by construction**: it parses, validates and queries, and it
never recomputes a score — every derived value is read from `report`.

| v6 | v7 |
|---|---|
| `investigation.observables` | `getAllObservables(inv)` |
| `observable.level` | `getObservableVerdict(inv, key)` |
| `observable.score` | `getObservableScore(inv, key)` |
| `observable.relationships` | `getAllRelations(inv)` / `getRelationsForObservable(inv, key)` |
| `edge.direction` | *(gone)* — `source_key` is the parent |
| `VERDICT_COLORS` | `VERDICT_HEX_COLORS` for the web, `VERDICT_TERMINAL_STYLES` for the CLI |
| `CyvestInvestigation` | `Investigation` |
| `parseFindingKey`, `parseThreatIntelKey` | *(gone)* — see below |

`Level` disappeared along the same axis as in Python, taking `LEVEL_ORDER`, `LEVEL_COLORS`,
`compareLevels`, `getLevelFromScore`, `getEntityLevel` and their siblings with it; the `Verdict`
equivalents replace them one for one.

### Key parsing is gone

`parseFindingKey` and `parseThreatIntelKey` were removed rather than updated. A v7 key may embed
an `external_id` — `fnd:{rule_id}:{external_id}` — and `rule_id`, `source` and the subject may
themselves contain `:`, so the result cannot be split back apart unambiguously. Python
deliberately exposes no equivalent: a key is an identity token, not a record. Read the fact from
the document instead.

`parseObservableKey` stays, with the same caveat it has always had on both sides: it is only
reliable for the simple `obs:{type}:{value}` form.

---

## 12. Command line

| v6 | v7 |
|---|---|
| `cyvest query file.json -k KEY` | `cyvest explain file.json KEY` |
| `cyvest migrate` (5→6 only) | `cyvest migrate --from auto` |
| — | `cyvest timeline`, `cyvest engines`, `cyvest policy show` |
| — | `--engine` on every command that shows a number |

---

## 13. Two ergonomic traps worth knowing

**Semantic keys merge silently.** Facts are identified by meaning, not by call site. Two
investigations querying VirusTotal about the same URL produce **one** signal, not two — which is
usually what you want, and is what makes merging idempotent. When you genuinely need to keep two
otherwise-identical facts apart, give them an `external_id`:

```python
url.with_ti("VirusTotal", 6.0, external_id="scan-2024-03-01")
url.with_ti("VirusTotal", 2.0, external_id="scan-2024-06-01")
```

The same applies to findings: reusing a `rule_id` updates that finding rather than adding one.

**A finding is identified by its rule alone.** Like v6, but without `origin_investigation_id` to
split it per investigation. `finding_create("rule")` called in two investigations of different
cases is **one** finding once they are merged. A rule that fires per observable — or that must
stay distinct across cases — says so explicitly:

```python
cv.finding("url_reputation", external_id=url.key).link_observable(url)
```
