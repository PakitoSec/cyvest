# Shared Investigation Context

Several workers, one case. `SharedInvestigationContext` lets concurrent tasks — threads or asyncio
— contribute to a single investigation without stepping on each other.

```python
from cyvest import Cyvest
from cyvest.shared import SharedInvestigationContext
```

---

## Why it is almost boring now

In v6 this was a delicate piece of machinery: a mutable object graph behind a global lock, deep
copied on every read, because two workers mutating the same observable would corrupt it.

In v7 none of that is necessary. Facts are immutable, and reconciling is `store.union()` —
idempotent, commutative and associative. So:

- arrival **order does not matter**;
- reconciling the same worker **twice is harmless**;
- a read needs no lock on the object graph, because nothing mutates in place.

The one lock that remains guards a fold and a snapshot swap.

---

## Basic usage

```python
main = Cyvest(root_data=incident, root_type=Cyvest.OBS.ARTIFACT)
shared = main.shared_context()

def worker(shared: SharedInvestigationContext) -> None:
    with shared.task() as cv:
        data = cv.root().extra
        cv.observable(cv.OBS.EMAIL, data["sender"])
```

`task()` hands out a worker-local `Cyvest` and reconciles it on exit — **including when the body
raises**, so a failing worker still contributes what it managed to establish. When a half-finished
fragment is worse than none, say so:

```python
with shared.task(fragment_id="virustotal", reconcile_on_error=False) as cv:
    ...
```

You can also build the context directly:

```python
shared = SharedInvestigationContext(
    root_data=incident,
    root_type=Cyvest.OBS.ARTIFACT,
    investigation_name="INC-4242",
)
```

Or wrap an investigation you already have:

```python
shared = SharedInvestigationContext.from_investigation(cv._investigation)
```

---

## Fragments and attribution

Each worker gets its own **fragment id**, and every fact it appends carries it. That is what keeps
the log attributable after reconciliation: the report can still say who established what, and the
per-fragment occurrence counters merge without inflating a tally.

What a fragment does **not** do is filter scoring. Reconciled facts are shared, so a finding
linking an observable reads everything anyone contributed to it:

```python
with shared.task(fragment_id="virustotal-worker") as cv:
    url = cv.observable(cv.OBS.URL, "https://evil.test").with_ti("virustotal", 3.0)
    finding = cv.finding("url_reputation")
    cv.finding_link_observable(finding.key, url.key)   # reads the merged observable
```

When a rule must score on the intel **it** fetched, and on nothing else, it says so — regardless
of which worker ran it:

```python
with shared.task(fragment_id="proofpoint-worker") as cv:
    url = cv.observable(cv.OBS.URL, "https://evil.test")
    trap = cv.observable_add_threat_intel(url, "proofpoint-trap", verdict=cv.VERDICT.SUSPICIOUS, weight=4.0)
    cv.observable_add_threat_intel(url, "urlhaus", verdict=cv.VERDICT.MALICIOUS, weight=6.0)

    cv.finding("pp-trap-hit").pin(trap)   # stays at 4.0
```

See [basis](scoring-model.md#basis-what-a-link-scores-on).

---

## Reading across tasks

A worker can consult what other workers have already established. Reads go through a **snapshot**:
a frozen view of the union, exposed as the ordinary `Cyvest` facade.

```python
def bodies_url(shared: SharedInvestigationContext) -> None:
    with shared.task() as cv:
        domain = shared.snapshot().observable_get("obs:domain:malicious.com")
        if domain is not None:
            url = cv.observable(cv.OBS.URL, "https://malicious.com/login")
            cv.observable_add_relation(url.key, domain.key, cv.REL.PIVOT)
```

Take it once and reuse it. A rule that consults a finding, then an observable, then the report
would otherwise be handed three different states, and score something that never existed:

```python
snapshot = shared.snapshot()

urls = [o for o in snapshot.observable_get_all().values() if o.obs_type is Cyvest.OBS.URL]
worst = max((o.score for o in urls), default=0.0)   # the score describes the very facts listed
```

A snapshot is read-only: writing to it raises `FrozenInvestigationError` rather than dropping the
fact silently. Contributions go through the worker, results come from the snapshot.

Reads take keys, not `(type, value)` pairs — keys are deterministic, so a worker can compute one
without asking anybody. The identity components work too, exactly as on any `Cyvest`:

```python
snapshot.observable_get("obs:domain:malicious.com")
snapshot.observable_get(Cyvest.OBS.DOMAIN, "malicious.com")
snapshot.finding_get("fnd:url_reputation")
snapshot.evidence_get("evd:sha256:…")
```

---

## Order matters again the moment you read

Reconciliation is commutative. **Production is not.** As soon as a worker branches on a shared
read — the `if domain is not None` above — its output depends on who happened to finish first. The
union is still deterministic; the facts fed into it are not.

So prefer two phases:

1. **collect** — workers run independently, never reading the shared state, and the result does not
   depend on scheduling;
2. **derive** — one pass over the union takes a single snapshot and writes what needs the whole
   picture.

Cross-task reads during phase 1 are supported, and sometimes the pragmatic answer. Just know that
they are what trades determinism for latency, not the merge.

---

## Asyncio

`atask` scopes a worker and reconciles it off the event loop; `asnapshot` does the same for the
read side. Reads *on* a snapshot are plain dictionary lookups and stay synchronous.

```python
async with shared.atask(fragment_id="worker-1") as cv:
    cv.observable(cv.OBS.URL, "https://evil.test")

snapshot = await shared.asnapshot()
score = snapshot.get_global_score()
verdict = snapshot.get_global_verdict()
observable = snapshot.observable_get("obs:url:https://evil.test")
```

---

## Results

A snapshot is the reconciled whole, through the facade you already know:

```python
cv = shared.snapshot()

cv.get_global_score()
cv.get_global_verdict()
cv.reevaluate(engine="basic-v1")   # re-derive without touching facts
cv.display_summary(show_graph=True)
cv.io_save_json("investigation.json")
```

One call left on the context itself, because it writes:

```python
shared.finalize_relationships()   # attach orphaned components to the root
```

---

## API summary

| Method | Purpose |
|---|---|
| `create_cyvest(*, fragment_id=…)` | a worker-local `Cyvest`; usable as a context manager |
| `task(*, fragment_id=…, reconcile_on_error=True)` | scoped worker, reconciled on exit |
| `atask(*, fragment_id=…, reconcile_on_error=True)` | async equivalent |
| `reconcile(source)` / `areconcile(source)` | fold a fragment in under the same header law as `union`; safe to call twice |
| `snapshot()` / `asnapshot()` | a frozen `Cyvest` over the union — the whole read API |
| `finalize_relationships()` | connect orphans to the root |
| `from_investigation(investigation)` | wrap an existing investigation |
