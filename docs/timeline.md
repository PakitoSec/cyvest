# Timeline

A timeline is a **projection of the fact log**, never a stored state. Nothing is appended to an
event table as you work, so the chronology cannot drift from the facts — and merging needs no
special logic, because a union of facts *is* a union of events.

```python
for entry in cv.timeline():
    print(entry.when, entry.kind, entry.title, entry.salience)
```

```bash
cyvest timeline case.json
cyvest timeline case.json --key-only --time asserted
```

---

## Two clocks

Every fact carries two timestamps, and they answer different questions:

| Field | Meaning |
|---|---|
| `occurred_at` | when the world moved — the email was sent, the process ran |
| `asserted_at` | when the analysis moved — the feed answered, the analyst decided |

The caller picks the axis:

```python
cv.timeline(time="occurred")   # default: the story of the incident
cv.timeline(time="asserted")   # the story of the investigation
```

Reading the `asserted` axis is how you answer *"what did we know, and when did we know it?"* —
including the uncomfortable case where a signal about Monday's event only arrived on Friday.

When a fact has no `occurred_at`, the `occurred` axis falls back to `asserted_at`: an unknown
event time is better approximated by the moment it was recorded than dropped.

---

## Salience is derived, not declared

There is no "importance" field to fill in, which is precisely what keeps it honest. Salience is
read from the report:

| Salience | Earned by |
|---|---|
| `KEY` | any **decision** — a human act is always worth showing; a **finding** or a **signal** whose weight reaches `policy.salience_threshold` |
| `NOTABLE` | a fact that moved the number without reaching the threshold; the **first** signal on an observable, which is when it entered the picture |
| `BACKGROUND` | everything else |

Filter to the spine of the investigation:

```python
from cyvest.enums import Salience

cv.timeline(min_salience=Salience.KEY)
```

!!! note "The default already hides the noise"
    `min_salience` defaults to `NOTABLE`, so a plain `cv.timeline()` shows signals, findings and
    decisions that mattered — not every observable and relation you created. Pass
    `min_salience=Salience.BACKGROUND` to see the complete log.

Because salience comes from the report, changing the policy changes what the timeline emphasises —
without touching a single fact.

---

## Verdict changes

The moments that matter most are usually the transitions: when an observable *became* suspicious.
Reconstructing them means replaying the store fact by fact, so it is opt-in:

```python
cv.timeline(track_verdict_changes=True)
```

This adds `verdict_change` entries — `NOTABLE → MALICIOUS` — each referencing the fact that caused
the transition, all at `KEY` salience.

!!! warning "It costs a full replay"
    The sweep is `O(#facts × (V+E))`: the report is recomputed at every prefix. Fine for a case,
    not for a dashboard over a thousand investigations.

Transitions are exact as long as facts are not rewritten. A re-asserted fact carries its final
`seq`, so its earlier value is not in the log; per-fact history is deferred to a later version.

---

## What ends up in the timeline

Every fact type contributes, described in the terms an analyst would use — subject to the salience
filter above, which is why observables and relations rarely show up unaided:

| Kind | Title |
|---|---|
| `signal` | `VirusTotal → MALICIOUS` |
| `finding` | the finding's name, or its rule id |
| `decision` | `ALLOWLISTED · Corporate sandbox` |
| `relation` | `extraction → obs:url:…` |
| `evidence` | the evidence title, or its type |
| `observable` | `url https://evil.test` |
| `verdict_change` | `NOTABLE → MALICIOUS` (opt-in) |

Each entry carries `subject_key` and `refs`, so a timeline row can be followed back into the graph
or into `explain`.
