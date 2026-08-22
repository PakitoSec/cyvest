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

The one lock that remains protects a single dict swap.

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
raises**, so a failing worker still contributes what it managed to establish.

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

## Fragments and scope

Each worker gets its own **fragment id**, and that is not an implementation detail: it is what
gives `Scope.OWN_FRAGMENT` its meaning.

```python
with shared.task(fragment_id="virustotal-worker") as cv:
    url = cv.observable(cv.OBS.URL, "https://evil.test").with_ti("virustotal", 3.0)
    finding = cv.finding("url_reputation")
    cv.finding_link_observable(finding.key, url.key)   # sees only this fragment
```

A finding created in a fragment sees, by default, only what that fragment established. So when a
second worker raises the same URL to 7, the first worker's finding **keeps its own value** — which
is exactly the behaviour you want when two feeds disagree and you need to know who said what.

Opt into the merged view per link:

```python
cv.finding_link_observable(finding.key, url.key, scope=cv.SCOPE.ALL)
```

See [scope](scoring-model.md#scope-why-a-finding-can-hold-its-value).

---

## Reading across tasks

A worker can consult what other workers have already established:

```python
def bodies_url(shared: SharedInvestigationContext) -> None:
    with shared.task() as cv:
        domain = shared.observable_get("obs:domain:malicious.com")
        if domain is not None:
            url = cv.observable(cv.OBS.URL, "https://malicious.com/login")
            cv.observable_add_relation(url.key, domain.key, cv.REL.PIVOT)
```

Reads take keys, not `(type, value)` pairs — keys are deterministic, so a worker can compute one
without asking anybody:

```python
shared.observable_get("obs:domain:malicious.com")
shared.observables_list_by_type(Cyvest.OBS.URL)
shared.finding_get("fnd:url_reputation:obs:url:https://evil.test")
shared.evidence_get("evd:sha256:…")
```

---

## Asyncio

Every read has an `a…` twin that runs the critical section in a worker thread, so the event loop
is never blocked:

```python
cv = await shared.acreate_cyvest(fragment_id="worker-1")
...
await shared.areconcile(cv)

score = await shared.aget_global_score()
verdict = await shared.aget_global_verdict()
observable = await shared.observable_aget("obs:url:https://evil.test")
```

---

## Results

The shared context exposes the reconciled whole:

```python
shared.report                 # the derived report
shared.get_global_score()
shared.get_global_verdict()
shared.evaluate(engine="basic-v1")   # re-derive without touching facts

shared.finalize_relationships()      # attach orphaned components to the root
```

When you want the ordinary facade over the merged result:

```python
cv = shared.as_cyvest()
cv.display_summary(show_graph=True)
cv.io_save_json("investigation.json")
```

---

## API summary

| Method | Purpose |
|---|---|
| `create_cyvest(*, fragment_id=…)` | a worker-local `Cyvest`; usable as a context manager |
| `acreate_cyvest(*, fragment_id=…)` | async equivalent |
| `task(*, fragment_id=…)` | scoped worker, reconciled on exit even on error |
| `reconcile(source)` / `areconcile(source)` | fold a fragment in; safe to call twice |
| `store`, `header`, `report` | the reconciled state |
| `evaluate(*, policy=…, engine=…)` | re-derive a report |
| `get_global_score()` / `get_global_verdict()` | headline results (`a…` variants available) |
| `observable_get(key)`, `observables_list_by_type(type)` | reads (`a…` variants available) |
| `finding_get(key)`, `evidence_get(key)` | reads (`a…` variants available) |
| `finalize_relationships()` | connect orphans to the root |
| `as_cyvest()` | the ordinary facade over the whole |
| `from_investigation(investigation)` | wrap an existing investigation |
