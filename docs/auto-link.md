# Auto-Link

Some edges are not analysis, they are arithmetic: a URL *contains* a host, an e-mail address
*contains* a domain. `AutoLink` draws those edges the moment the containing observable is created,
under a source of its own, so two analysts — or two agents — building the same case end up with the
same graph.

```python
from cyvest import AutoLink, Cyvest

cv = Cyvest(root_data={"case": "IR-2431"}, auto_link=AutoLink())
url = cv.observable(cv.OBS.URL, "hxxp://evil[.]example/login")

cv.observable_get(cv.OBS.DOMAIN, "evil.example")   # created for you
cv.relation_get_all()                              # one EXTRACTION edge: url → domain
```

---

## What is derived

| Parent | Child | Edge |
|---|---|---|
| `url` | its host: a `domain`, an `ipv4` or an `ipv6` | `EXTRACTION`, parent → child |
| `email` | the domain after `@` | `EXTRACTION`, parent → child |

The value is refanged first, so `hxxp://evil[.]example` and `https://evil.example` derive the same
domain. A URL whose host is not an indicator — `localhost`, a bare NetBIOS name — derives nothing.
Domains, addresses and hashes contain nothing, which is what bounds the recursion.

Every derived relation carries `source.name == "cyvest.autolink"`, so a report can tell an edge
the library inferred from one an analyst drew.

---

## Why it changes the score

Under the default policy `EXTRACTION` propagates with attenuation `1.0`: the child's score flows
to the parent unchanged. Give the domain a malicious signal and the URL becomes malicious too.

```python
cv.observable_get(cv.OBS.DOMAIN, "evil.example").with_ti("virustotal", 7.0)
url.score      # 7.0 — propagated through the derived edge
```

That is usually what "this URL points at a bad domain" means, and it is why the feature is opt-in
rather than the default. See [Scoring Model](scoring-model.md) for the propagation rule.

---

## Options

```python
AutoLink()                          # every rule on — today, the structural one
AutoLink(structural=False)          # off, while keeping the object around for future rules
AutoLink(inherit_internal=False)    # derived children are always external
AutoLink(comment="derived")         # the comment written on every derived relation
```

`inherit_internal` defaults to `True`: the domain of an internal mailbox is an internal domain.

---

## Where the setting lives

`AutoLink` is a facade setting, not a fact. It is not serialized: a document loaded with
`Cyvest.io_load_dict(data)` comes back with `auto_link=None`, and you pass it again if the loaded
investigation should keep deriving — `Cyvest.io_load_dict(data, auto_link=AutoLink())`. The
relations already derived are facts and travel with the document.

A `SharedInvestigationContext` hands its `auto_link` to every worker it creates, so the derived
edges are the same whichever task first saw the observable.

Investigations built before the option was switched on can be caught up:

```python
from cyvest.autolink import backfill_structural_links

backfill_structural_links(cv)       # returns the number of relations added; idempotent
```

---

## API summary

| Name | Purpose |
|---|---|
| `AutoLink(structural=True, inherit_internal=True, comment=…)` | the rules to apply |
| `Cyvest(..., auto_link=AutoLink())` | apply them on every observable created through this facade |
| `Cyvest.io_load_dict(data, auto_link=…)` / `io_load_json` | keep deriving on a loaded document |
| `SharedInvestigationContext(..., auto_link=…)` | propagate to every worker |
| `derive_structural(obs_type, value)` | the pure derivation, no store involved |
| `cv.observable_create(..., resolve=False)` | create an identity as given, without the resolvers — what auto-link uses for the derived children |
| `backfill_structural_links(cv, config=None)` | derive for everything already in the store |
| `cv.relation_get_all()` | every relation, keyed |
| `AUTOLINK_SOURCE` | the `SourceRef` derived relations are attributed to |
