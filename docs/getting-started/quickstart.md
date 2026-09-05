# Quick Start

Model a complete investigation, link observables, and produce a shareable report in minutes.

---

## 1. Create your first investigation

```python
from cyvest import Cyvest

cv = Cyvest(root_data={"type": "email_analysis"})
phishing_url = cv.observable_create(
    cv.OBS.URL,
    "https://fake-bank-login.com",
    internal=False,
)

cv.observable_add_threat_intel(
    phishing_url.key,
    source="virustotal",
    weight=8.5,
    comment="Known phishing site",
)

url_finding = cv.finding_create(
    "url_analysis",
    "Analyze URLs in email",
    weight=8.5,
)
cv.finding_link_observable(url_finding.key, phishing_url.key)

print(cv.get_global_score(), cv.get_global_verdict())
```

Note what is **not** happening here: no score is stored anywhere. `get_global_score()` derives it
from the facts, so the same investigation re-evaluated under another policy yields another number
without any fact changing. See [the scoring model](../scoring-model.md).

!!! tip "State the verdict, or the weight, or both"
    `weight=8.5` implies `MALICIOUS`; `verdict=cv.VERDICT.MALICIOUS` implies a weight taken from
    the policy. You only need the half you actually know.

!!! tip "Deterministic investigation IDs"
    For reproducible reports that enable diffing between runs, pass a custom `investigation_id`:
    ```python
    cv = Cyvest(root_data={"type": "email"}, investigation_id="email-analysis-v1")
    ```
    Without this parameter, a unique ULID is auto-generated for each run.

!!! note "Immutable facts, thin proxies"
    `observable_create`, `finding_create` and the fluent helpers return proxies
    (`ObservableProxy`, `FindingProxy`, …) over immutable facts. Mutating helpers append a new
    fact rather than editing one in place, which is what makes the log auditable.

---

## 2. Use the fluent API for expressiveness {: #using-the-fluent-api }

```python
from cyvest import Cyvest

cv = Cyvest()
url = (
    cv.observable(cv.OBS.URL, "https://malicious.com", internal=False)
    .with_ti("virustotal", 8.5)
    .with_ti("misp", verdict=cv.VERDICT.SUSPICIOUS)
)

(
    cv.finding("url_finding", "Finding suspicious URL")
    .link_observable(url)
    .with_weight(8.5)
)
```

`with_ti` returns the observable, so calls chain. Two intels from the **same source** on the same
observable are one fact, not two — pass an `external_id` when you genuinely need to keep both:

```python
url.with_ti("virustotal", 8.5, external_id="scan-2024-03")
url.with_ti("virustotal", 2.0, external_id="scan-2024-06")
```

---

## 3. Capture relationships with intent

A relation is a standalone fact: **source is the parent, target is the child**. There is no
direction flag to set.

```python
from cyvest import Cyvest

cv = Cyvest()
email = cv.observable_create(cv.OBS.FILE, "invoice.eml")
url = cv.observable_create(cv.OBS.URL, "http://c2-server.com")
ip = cv.observable_create(cv.OBS.IPV4, "192.0.2.100", internal=False)

# The URL was extracted from the email; the IP was found by pivoting on the URL.
cv.observable_add_relation(email.key, url.key, cv.REL.EXTRACTION)
cv.observable_add_relation(url.key, ip.key, cv.REL.PIVOT)

# A symmetric association that should carry no blame.
host1 = cv.observable_create(cv.OBS.IPV4, "10.0.1.10", internal=True)
host2 = cv.observable_create(cv.OBS.IPV4, "10.0.1.20", internal=True)
cv.observable_add_relation(host1.key, host2.key, cv.REL.RELATED_TO)
```

| Kind | Propagates score |
|---|---|
| `EXTRACTION` | yes — the child came out of the parent |
| `PIVOT` | yes — the analyst went looking and found it |
| `RELATED_TO` | **no** — symmetric, deliberately inert |

Choosing `RELATED_TO` is a real decision: it keeps the graph connected without claiming the two
observables share guilt.

---

## 4. Organize workstreams with tags

```python
cv = Cyvest()

# Simple: pass tag names directly (auto-creates tags)
(
    cv.finding("c2_detection", "Detect C2 communication")
    .tagged("network", "suspicious")
)

# With description: create the tag first
network_tag = cv.tag("network:analysis", "Network telemetry")
(
    cv.finding("ids_east", "IDS signals from east DC")
    .tagged(network_tag, "network:analysis:east_dc")
)

children = cv.tag_get_children("network:analysis")
```

Creating `header:auth:dkim` auto-creates `header` and `header:auth`.

---

## 5. Record an analyst decision

Judgment overrules arithmetic — and stays a fact, so it merges and it is dated.

```python
url.allowlist("Corporate sandbox", decided_by="rssi")        # caps the score
finding.dismiss("Known false positive", decided_by="alice")  # excluded from the total
url.vacate("No longer in scope", decided_by="soc-lead")      # back to the computed value
```

A dismissed finding remains in the report with `counted = False`. Deleting it would erase the fact
that someone looked at it. The justification is required, and `decided_by` travels on the fluent
path — the shortest way to decide is also the one that records who did.

---

## 6. Export and share {: #exporting-results }

```python
cv.display_summary(show_graph=True)
cv.display_statistics()
cv.display_explanation(url.key)   # why this observable scores what it scores
cv.display_timeline()

cv.io_save_json("investigation.json")
cv.io_save_markdown("report.md")
```

Each `display_*` uses the active `logurich` logger automatically when `logurich.init_logger()` has
been called. Otherwise it prints on a `rich.Console`. An explicit `printer` — a callable taking
one renderable — always overrides the automatic choice:

```python
cv.display_summary(printer=lambda renderable: logger.rich("INFO", renderable, width=150))
```

From the shell:

```bash
cyvest show investigation.json --stats
cyvest explain investigation.json obs:url:https://malicious.com
cyvest timeline investigation.json --key-only
```

!!! note "The exported document carries its report"
    A serialized investigation includes `report`, `policy_version` and `engine_id`. That is what
    lets the JavaScript SDK display scores without reimplementing a single rule — and what lets
    you tell whether two files are even comparable.

---

## Next Steps

- Understand how numbers are produced in [the scoring model](../scoring-model.md)
- Read the chronology of a case with the [timeline](../timeline.md)
- Explore concurrency via [Shared Investigation Context](../shared-investigation-context.md)
- Browse the `examples/` directory for end-to-end scenarios
