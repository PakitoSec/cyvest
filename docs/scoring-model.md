# The scoring model

Cyvest separates **what happened** from **what it is worth**. Facts are immutable and carry no
derived value; a *report* is computed from them by an *engine*, under a *policy*.

```python
cv.get_report()          # the whole derivation
cv.get_global_score()    # its headline number
cv.explain(key)          # the terms that produced one number
```

Nothing is cached in the facts, so re-running with another engine or another policy is a
one-liner:

```python
cv.reevaluate(engine="basic-v1", policy=my_policy)
```

---

## The three parts of a judgment

Any statement — an intel signal, a finding, an analyst verdict — carries up to three things:

| Field | Question it answers | Range |
|---|---|---|
| `verdict` | *What* is claimed | `SAFE` … `MALICIOUS` |
| `weight` | *How much* it is worth | a float |
| `confidence` | *How sure* the source is | `0.0` – `1.0` |

The verdict contributes only its **polarity** — `SAFE` pulls down (−1), `INFO` is inert (0), the
other three push up (+1). The magnitude comes from the weight, scaled by confidence:

$$
s_{\text{signal}} = \text{polarity}(\text{verdict}) \times w \times c
$$

Stating one of `verdict` / `weight` is enough. A weight implies the verdict of its band; a verdict
with no weight is resolved at evaluation time from `policy.weight_by_verdict`, which means the
same fact can be worth more or less under a different policy — as it should be.

### Where the weight comes from

`policy.resolve_weight()` takes the first that applies:

1. **the weight stated on the fact** — a source that returns a number is believed;
2. `weight_by_verdict[verdict]` — the band representative of the verdict.

The fact wins over the policy, deliberately: "VirusTotal returned 6" is an observation, and a
policy that could silently rewrite it would put us back to v6, where the displayed value and the
computed one could disagree. The policy fills gaps; it does not overrule.

Retuning the five band representatives is the one lever the policy offers, and it stays coherent
by construction: it moves every verdict on the same scale, so an exculpatory conclusion and an
inculpatory one never drift apart. Earlier drafts also allowed per-rule and per-source defaults;
they were dropped because, keyed on the rule or the feed alone, they applied one magnitude to
that rule's `SAFE` and `MALICIOUS` conclusions alike.

The practical consequence is worth stating plainly: **you cannot down-weight a noisy feed that
reports its own magnitudes** by editing the policy. Either the connector stops sending a weight —
and the band representative then applies — or you attenuate elsewhere.

!!! note "A weight is never negative"
    Direction is the verdict's job alone. A signed weight would let a fact read `MALICIOUS` while
    scoring `SAFE`, so the model refuses it. The builders accept a negative number as shorthand:
    it names an exculpatory verdict and stores the magnitude unsigned.

!!! note "Zero is a weight, not an absence"
    `weight=0.0` is honoured as stated; only `None` hands the decision to the policy. Asserting
    `verdict=MALICIOUS` with `weight=0.0` is therefore expressible, and the report shows it for
    what it is: an asserted verdict of `MALICIOUS`, a computed verdict of `INFO`, and a named
    contribution worth `0.0`. v6 allowed the same statement but displayed only the label.

---

## An observable's score

An observable is worth the strongest thing said about it, or propagated to it:

```
score(observable, scope) = combine(own signals, children's contributions)
```

`combine` follows `policy.aggregation`:

- **`MAX`** (default) — the maximum across signals and children. Ten mediocre signals never add up
  to one strong one.
- **`SUM`** — the strongest signal, plus the children on top.

A child contributes through its edge:

$$
s_{\text{child}} = s(\text{target}) \times c_{\text{relation}} \times a_{\text{kind}}
$$

with `a` from `policy.attenuation`. `related-to` has attenuation `0.0`, which is the formal way of
saying a symmetric association carries no blame.

!!! note "Cycles terminate"
    An observable being evaluated contributes `0.0` to itself, so a cyclic graph converges instead
    of recursing forever.

The **root** observable is a presentation anchor, never evidence: it is skipped when walking
children, so attaching an orphan to the root cannot inflate anything.

---

## A finding's score

A finding takes the **best** of what it asserts itself and what its observables tell it:

```
s_finding = max(own term, propagated term)
```

- **own term** = `polarity(verdict) × weight × confidence`, or `−∞` when the verdict is `INFO`
  (a finding that claims nothing should not floor its observables' evidence at zero);
- **propagated term** = the maximum score among the linked observables, each read **in its own
  resolved scope**, or `−∞` when the finding links nothing.

When both are absent the finding scores `0.0`.

!!! warning "The neutral element is −∞, not 0"
    Using `0` would silently floor every negative score, turning an exculpatory `SAFE` into a
    neutral one.

The report records `own_term_suppressed` when propagation beat the finding's own claim — useful
when someone asks why a finding weighted 2 is showing 6.

---

## Scope: why a finding can hold its value

Each `ObservableLink` carries a **scope**, resolved before lookup:

| Scope | The finding sees |
|---|---|
| `OWN_FRAGMENT` (default) | the observable as scored **within the finding's own fragment** |
| `ALL` | the observable as scored across every merged fragment |

This is what makes merging non-destructive. Merge an investigation from ProofPoint (finding worth
2) with one from VirusTotal (finding worth 3), both pointing at the same URL:

```
F1 = 2     F2 = 3     observable = 3     total = 5
```

F1 keeps its own value even though the URL rose to 3, because its link only sees the ProofPoint
fragment. Opt into the global view per link:

```python
cv.finding_link_observable(finding.key, url.key, scope=cv.SCOPE.ALL)
```

Scope is deliberately **per link**, not a flag on the finding: one finding may mix scopes, and may
even link the same observable twice with two different ones.

---

## Decisions bound the derivation

An analyst does not argue with the arithmetic — they overrule it. A `Decision` clamps a result
rather than adding a term:

| Decision | Effect |
|---|---|
| `ALLOWLISTED` | `min(score, policy.allowlist_ceiling)` — default `-1.0` |
| `BLOCKLISTED` | `max(score, policy.blocklist_floor)` — default `9.0` |
| `CONFIRMED` | the finding is pinned at `policy.confirmed_floor` |
| `DISMISSED` | the finding is excluded from the total |

```python
url.allowlist(justification="Corporate sandbox")
finding.dismiss(justification="Known false positive on this tenant")
```

Because a decision is a fact like any other, it merges, it is timestamped, and it says who decided
— the `Fact` envelope carries `source` and `asserted_at`, so the decision itself only needs
`target_key`, `kind` and an optional `justification`.

A dismissed finding stays in the report with `counted = False`. Deleting it would erase the fact
that someone looked.

Two contradictory decisions may sit on one target — `ALLOWLISTED` and `BLOCKLISTED` carry
different keys, as do `CONFIRMED` and `DISMISSED`. They are settled the way every conflict is
settled in v7: **the freshest wins**, ranked on `occurred_at or asserted_at` then `seq`. The loser
is reported as an unretained contribution rather than dropped, so the disagreement stays visible.

---

## Conclusions: a finding that concludes instead of accumulating

Some findings do not bring new evidence — they render a **verdict on the whole case** after
reading everything else. An LLM review is the typical one. Adding such a claim as an ordinary
finding is wrong in both directions: a weight of `7.0` on a total already at `8.0` double-counts
the very evidence the analysis just read, and a weight of `1.5` undershoots its own conclusion.

A finding whose `effect` is `FLOOR` — a **conclusion** — is not a term of the sum. It raises the
total *just enough* to reach the verdict it asserts, and adds nothing when that verdict is already
reached:

$$
\text{total} = \max(\text{total}, \text{floor}(\text{verdict}))
$$

```python
cv.finding("spf_fail", "SPF invalide", verdict=cv.VERDICT.SUSPICIOUS, weight=3.2)
conclusion = cv.conclusion("ai_review", "Analyse IA", verdict=cv.VERDICT.MALICIOUS)

cv.get_global_score()       # 5.0 — the floor of MALICIOUS
conclusion.applied_floor    # 1.8 — all it had to add
```

The floors are the lower bounds of the same bands as everywhere else: `5.0` for `MALICIOUS`, `3.0`
for `SUSPICIOUS`, and an epsilon for `NOTABLE`, whose band `]0, 3[` has no closed bound. `SAFE`
and `INFO` have no floor at all, so asserting one on a conclusion is **refused at construction**
rather than silently doing nothing — a conclusion may only escalate.

For the same reason a conclusion **takes no weight**: its magnitude *is* the floor of its verdict.

### What a conclusion looks like in the report

The finding itself has **no score** — `None`, not `0.0`, which would read as a neutral term of a
sum it never joined. It is still `counted`, because it does take part in the evaluation, and its
confidence still weighs on the investigation's mean confidence.

The lift appears where it actually happened, as a contribution of the investigation result:

```python
[c for c in cv.get_report().investigation.contributions if c.label.startswith("conclusion floor")]
```

This is deliberate. Were the lift stored on the finding, adding an unrelated finding elsewhere
would rewrite a conclusion nobody touched — noise in every diff and every timeline — and a tag
holding the conclusion would inherit a score that depends on findings outside it.

Two more consequences worth knowing:

- **linked observables stay documentary.** A conclusion may link the observables it reasoned about,
  and the report shows them, but they propagate nothing: letting them would push the total past
  "just enough";
- **confidence does not dampen the floor.** Scaling it would make a conclusion miss the very
  verdict it asserts — a `MALICIOUS` claim at `0.8` confidence would land on `4.0`, which reads
  `SUSPICIOUS`.

### Several conclusions

Conclusions are applied weakest first, each credited with the step it clears. On a base of `1.0`,
with one `SUSPICIOUS` and one `MALICIOUS` conclusion:

| Conclusion | Floor | Total before | Adds | Total after |
|---|---|---|---|---|
| `SUSPICIOUS` | `3.0` | `1.0` | `2.0` | `3.0` |
| `MALICIOUS` | `5.0` | `3.0` | `2.0` | `5.0` |

Three properties follow:

- **the final total does not depend on the order** — it is always `max(base, highest floor)`; only
  the attribution between conclusions follows the sort;
- **conclusions never compound** — two `MALICIOUS` conclusions give `5.0`, not `10.0`. This is what
  makes it safe to plug several analysers into the same investigation;
- **the strongest wins, without a vote** — there is no averaging and no consensus rule, in keeping
  with the `max` used everywhere else in the engine.

When two conclusions share the same floor, one is credited with the whole lift and the other with
`0.0`. Which one is settled by `seq`, so it is stable for a given document but not predictable
from the order you created them in — only the sum of the credits is meaningful.

!!! warning "One over-confident analyser is enough"
    Confidence does not attenuate, so a lone `MALICIOUS` conclusion asserted at `0.3` still floors
    the investigation at `5.0`, even against three `NOTABLE` ones. There is no confidence
    threshold in the policy: the recourse is a `DISMISSED` decision, which is a declared act and
    stays in the record.

A `DISMISSED` conclusion applies nothing, a `CONFIRMED` one is pinned at `policy.confirmed_floor`
like any other finding, and anything other than `EVALUATED` is excluded — a conclusion is a finding
first.

---

## From score to verdict

The global verdict is the projection of the total onto the same bands used everywhere else:

| Score | Verdict |
|---|---|
| `< 0` | `SAFE` |
| `= 0` | `INFO` |
| `]0, 3[` | `NOTABLE` |
| `[3, 5[` | `SUSPICIOUS` |
| `>= 5` | `MALICIOUS` |

---

## Auditing a number

Every score in the report comes with the terms that produced it:

```python
for contribution in cv.get_report().observable(url.key).contributions:
    print(contribution.label, contribution.value, contribution.retained)
```

```bash
cyvest explain case.json obs:url:https://evil.test
```

A contribution names its `source_key`, so a number in the report can always be traced back to the
fact that caused it — including edges, which is how the graph knows which relations actually
carried score.

---

## Engines

`basic-v1` implements everything above and reproduces v6's arithmetic. The engine that produced a
report is recorded in it, and comparing reports from two engines is refused by default: their
scores are not on the same scale.

```bash
cyvest engines
cyvest show case.json --engine basic-v1
```

The report a document carries is for consumers that have no engine — the JavaScript SDK, chiefly.
Python discards it on load and re-derives from the facts, so the two can never silently disagree.

!!! note "The evaluator never reads the clock"
    Nothing under `evaluation/` may call `now()` — enforced by a test that walks the AST. An
    archived report must produce the same numbers next year; ageing belongs to display.
