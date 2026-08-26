# Core Concepts

Cyvest models an investigation as an **append-only log of immutable facts**, plus a **report**
derived from them. Understanding that split explains most of the API.

```
facts  ──(engine + policy)──▶  report
 ▲                               │
 │ you append                    │ you read
 └───────────────────────────────┘
```

Nothing you write carries a computed score, and nothing in the report is stored on a fact. This is
what makes an investigation auditable, mergeable, and re-scorable under a different policy.

For the arithmetic itself, see [the scoring model](../scoring-model.md).

---

## The facts

Every fact shares an envelope: a deterministic `key`, a `seq` (ULID) fixing its order, an
`asserted_at` and optional `occurred_at`, a `source`, and the `fragment_id` it belongs to.

### Observables

Artifacts under investigation — URLs, addresses, hashes, users, processes.

```python
url = cv.observable_create(cv.OBS.URL, "https://fake-bank-login.com", internal=False)
```

| Field | Meaning |
|---|---|
| `type` / `subtype` / `namespace` | the vocabulary — use `cv.OBS.*` and `cv.SUB.*` |
| `value` | the artifact itself, normalized |
| `internal` | yours, or someone else's |
| `occurrences` | how often it was seen, counted **per fragment** |
| `aliases` | other identities that resolved to this one |

Creating the same observable twice returns the same fact and increments its occurrence counter.
Counters are per fragment and merged by max, so re-merging a fragment never inflates a tally.

**Observable types:**

```python
Cyvest.OBS.IPV4      Cyvest.OBS.IPV6      Cyvest.OBS.DOMAIN    Cyvest.OBS.URL
Cyvest.OBS.HASH      Cyvest.OBS.EMAIL     Cyvest.OBS.FILE      Cyvest.OBS.ARTIFACT
Cyvest.OBS.USER      Cyvest.OBS.PROCESS   Cyvest.OBS.COMMAND_LINE
```

### Signals

What a source said about an observable. `ThreatIntel` is the first member of an open family
(`ObservableSignal`), discriminated by `kind`, so new scoring inputs can be added without breaking
the schema.

```python
url.with_ti("virustotal", 8.5, comment="Known phishing site")
url.with_ti("misp", verdict=cv.VERDICT.SAFE)
```

A signal carries `verdict`, `weight` and `confidence` — *what*, *how much*, *how sure*. Its
identity is `(source, observable)`: two runs asking VirusTotal about the same URL produce one
signal, not two. Pass an `external_id` when you need to keep successive scans apart.

### Relations

A link between two observables, and a fact in its own right — not a list inside an object.

```python
cv.observable_add_relation(email.key, url.key, cv.REL.EXTRACTION)
```

Direction is implied: **source is the parent, target is the child**. There is no direction flag.

| Kind | Meaning | Propagates |
|---|---|---|
| `EXTRACTION` | the child was extracted from the parent | yes |
| `PIVOT` | the analyst pivoted from parent to child | yes |
| `RELATED_TO` | symmetric association | **no** |

A relation also carries a `confidence`, which scales what it propagates — and, in the graph view,
how solid the edge looks.

### Findings

The outcome of a rule: a detection, a reputation lookup, an analyst conclusion.

```python
finding = cv.finding_create("url_analysis", "Analyze URLs in email", weight=8.5)
cv.finding_link_observable(finding.key, url.key)
```

Identity is `(rule_id, subject_key)`. The same rule on two observables gives two findings; the
same rule on the same observable gives one, across any number of investigations — which is why v7
has no `origin_investigation_id`.

A finding with no explicit `subject` is anchored to the **root observable**, whose key is identical
in every investigation, so a conclusion about the case survives a merge.

Each link carries a **scope** (`OWN_FRAGMENT` by default), which is what lets a finding hold its
value while the observable it points at keeps evolving. See
[scope](../scoring-model.md#scope-why-a-finding-can-hold-its-value).

Two axes govern how a finding takes part in the total: `status` says **whether** it does, `effect`
says **how**. `ADDITIVE` — the default — makes it a term of the sum.

### Conclusions

A finding whose `effect` is `FLOOR`: it renders a verdict on the case after reading the other
findings, typically an AI review. Rather than adding a magnitude, it raises the total just enough
to reach the verdict it asserts, and adds nothing when that verdict is already reached.

```python
cv.conclusion("ai_review", "Analyse IA", verdict=cv.VERDICT.MALICIOUS)
```

Several conclusions never compound, so plugging in a second analyser cannot inflate the case. See
[conclusions](../scoring-model.md#conclusions-a-finding-that-concludes-instead-of-accumulating).

### Evidence

Structured material attached to the case — email headers, WHOIS records, DNS answers, a sandbox
report. Evidence is **never scored**; it is there to be read.

```python
cv.evidence_create("enrichment", title="email_headers", content={"spf": "fail"})
cv.finding_link_evidence(finding.key, evidence.key)
```

### Decisions

A human overruling the arithmetic. A decision **bounds** a result rather than adding a term.

```python
url.allowlist("Corporate sandbox", decided_by="ciso")
url.blocklist("Confirmed C2", decided_by="analyst-3")
finding.confirm("Reproduced in sandbox", decided_by="analyst-3")
finding.dismiss("Known false positive", decided_by="analyst-3")
url.vacate("No longer owned by the RSSI", decided_by="soc-lead")
```

Under those four verbs the model holds two intents — `UPHOLD` and `REFUTE` — plus `VACATED` to
withdraw a stance. What each does follows from the family of the target, which the key already
says; the vocabulary lives on the façade, where it reads naturally.

When the kind is a variable rather than something you know as you write — replaying a feed,
importing a corporate list — use `decide`:

```python
url.decide(cv.DECISION.REFUTE, entry.reason, decided_by=entry.owner, occurred_at=entry.decided_at)
```

The decision itself holds only `target_key`, `kind` and a `justification`; who decided and when
come from the fact envelope. The justification is required — an override nobody has to justify is
an override nobody can audit. A dismissed finding stays visible with `counted = False` — erasing it
would erase the fact that someone looked.

Reading back is a single lookup, since one target holds one stance:

```python
url.decision        # Decision | None
url.allowlisted     # and .blocklisted, .vacated, .decided
```

### Tags

Group findings into workstreams, with automatic hierarchy.

```python
cv.finding("c2_detection", "Detect C2").tagged("network", "suspicious")
cv.tag_get_children("network:analysis")
```

Creating `header:auth:dkim` auto-creates `header` and `header:auth`. A tag's aggregated score sums
only the findings that are actually **counted**.

---

## Keys

Every fact has a deterministic key, which is what makes merging work without coordination:

- **Observable**: `obs:{type}:{normalized_value}`, or `obs:{type}:{subtype}:{namespace}:{value}`
- **Finding**: `fnd:{rule_id}:{subject_key}`
- **Signal**: `ti:{source}:{observable_key}`
- **Relation**: `rel:{kind}:{source_key}>{target_key}`
- **Evidence**: `evd:{source}:{external_id}`, or `evd:sha256:{digest}` for inline content
- **Decision**: `dec:{target_key}` — one stance per target, whatever it says
- **Tag**: `tag:{name}`

Getters accept either a key or its components:

```python
obs = cv.observable_get(cv.OBS.URL, "https://malicious.com")
obs = cv.observable_get("obs:url:https://malicious.com")
```

`COMMAND_LINE` values and identities longer than 128 bytes use deterministic SHA-256 keys. `EMAIL`
represents an address, while `USER/email` represents a user *account*. Executable paths use
`FILE/path` and can be related to a `PROCESS/pid`.

!!! warning "Keys are semantic, so facts merge silently"
    Reusing a `rule_id` on the same subject updates that finding rather than adding one. This is
    usually what you want — it is what makes merging idempotent — but it surprises people once.

---

## Observable canonicalisation

Some raw identifiers describe the same real-world entity: `USER/email alice@example.com` and
`USER/username/windows alice` may both be the Okta user `USER/uid/okta 123`.

Register a resolver so `observable_create()` resolves identities before creating the fact:

```python
from cyvest import Cyvest, ObservableAlias, ObservableIdentity, ObservableResolver

cv = Cyvest()

def resolve_user_to_okta(alias: ObservableAlias) -> ObservableIdentity | None:
    lookup = {
        ("email", None, "alice@example.com"): "123",
        ("username", "windows", "alice"): "123",
    }
    subtype = alias.subtype.value if hasattr(alias.subtype, "value") else alias.subtype
    okta_uid = lookup.get((subtype, alias.namespace, alias.value.lower()))
    if okta_uid is None:
        return None

    return ObservableIdentity(
        obs_type=cv.OBS.USER,
        subtype=cv.SUB.USER_UID,
        namespace="okta",
        value=okta_uid,
    )

cv.observable_resolver_register(
    ObservableResolver(
        name="okta-user-id",
        source_types={
            (cv.OBS.USER, cv.SUB.USER_EMAIL),
            (cv.OBS.USER, cv.SUB.USER_USERNAME),
        },
        resolve=resolve_user_to_okta,
    )
)

email = cv.observable_create(cv.OBS.USER, "alice@example.com", subtype=cv.SUB.USER_EMAIL)
username = cv.observable_create(
    cv.OBS.USER, "alice", subtype=cv.SUB.USER_USERNAME, namespace="windows"
)

assert email.key == username.key
assert email.subtype == cv.SUB.USER_UID
assert email.value == "123"
assert email.occurrence_count == 2
```

The original identities are kept as `aliases`, so nothing is lost. Resolver metadata lives under
`observable.extra["resolver_data"][resolver.name]`; dictionaries merge recursively across repeated
creations and merges, while scalars and lists are replaced.

---

## The root observable

Every investigation has a root: an anchor representing the case itself.

```python
cv = Cyvest(root_type=cv.OBS.ARTIFACT, root_data={"ticket": "INC-4242"})
root = cv.observable_get_root()
```

Two properties matter:

- **The root is never evidence.** It is skipped when walking children, so attaching things to it
  cannot inflate anything.
- **Its key is the same in every investigation** (`obs:{type}:__cyvest_root__`). That is what lets
  case-level findings survive a merge.

`finalize_relationships()` walks the graph and attaches orphaned components to the root, using
`RELATED_TO` — the one kind that carries no score. The investigation becomes connected without
anyone claiming a causal link.

---

## Merging

Merging is a **union of facts**: idempotent, commutative, associative.

```python
main.merge_investigation(other)
```

```bash
cyvest merge a.json b.json -o merged.json
```

When two fragments assert the same fact differently, freshness decides — observation time
outranking assertion time, so a slow worker cannot overwrite fresher data with stale data.

!!! warning "A score can go down"
    v6 resolved conflicts with `max`, so scores only ever rose. In v7, if a feed reclassifies a URL
    as clean, the clean verdict wins. That is the point, but it means a re-run can lower a score.

Fragments also give **scope** its meaning: each source of facts has its own `fragment_id`, and a
finding's links look, by default, only at what its own fragment established.

---

## Statistics

Counts are computed on demand from the store and the report — nothing is registered as you build.

```python
stats = cv.statistics()
stats.total_observables
stats.findings_by_verdict
stats.allowlisted_observables
```

---

## Next Steps

- Follow the [Quick Start](quickstart.md) end to end
- Understand how numbers are produced in [the scoring model](../scoring-model.md)
- Read a case chronologically with the [timeline](../timeline.md)
- Run several workers against one case with the
  [Shared Investigation Context](../shared-investigation-context.md)
