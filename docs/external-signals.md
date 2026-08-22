# External signals

Most facts in an investigation come from somewhere else: a reputation feed, a sandbox, a SIEM
rule, another team's playbook. `io_load_signal` is the door those systems come through, and it is
deliberately a narrow one.

```python
from cyvest import Cyvest

response = fetch_from_virustotal(url)          # your connector's job
draft = Cyvest.io_load_signal(response)         # validated against the contract
observable.with_ti(draft)                       # attached to a subject
```

---

## The contract

A producer fills in an envelope, not a stored fact — it does not know which observable the
judgment will land on, and it has no business inventing a key.

```json
{
  "schema_version": "7.0.0",
  "source": "virustotal",
  "source_class": "vendor_feed",
  "verdict": "MALICIOUS",
  "weight": 6.0,
  "confidence": 1.0,
  "observed_at": "2026-03-01T09:12:00Z",
  "comment": "12/70 engines",
  "taxonomies": ["malware-type:trojan"],
  "payload": {"scan_id": "…", "requested_at": "…", "quota_left": 4211}
}
```

| Field | Required | Meaning |
|---|---|---|
| `source` | yes | who is speaking |
| `source_class` | no | what kind of speaker (`vendor_feed`, `internal_tool`, `analyst`, …) |
| `verdict` | see below | what is claimed |
| `weight` | see below | how much it is worth |
| `confidence` | no | how sure the source is, in `]0, 1]` |
| `observed_at` | no | when the source observed it — what merge conflicts are settled on |
| `external_id` | no | discriminant when you want to keep history |
| `comment`, `taxonomies` | no | display material |
| `payload` | no | the raw response, kept as-is |

**Either `verdict` or `weight` is enough.** They are two halves of the same scale, so the missing
one is completed from the score bands: `weight: 6.0` implies `MALICIOUS`, and `verdict: "SAFE"`
alone leaves the weight to the policy.

Publish the machine-readable contract to your producers:

```bash
cyvest schema --which signal -o schema/cyvest.signal.schema.json
```

---

## Strict on purpose

There is no tolerant parsing and no `preprocessor` hook. An unknown field, a nameless source or a
confidence of `1.5` raises at the boundary:

```python
Cyvest.io_load_signal({"source": "vt", "verdit": "MALICIOUS"})
# ValidationError: Extra inputs are not permitted [type=extra_forbidden]
```

That is the point. A typo that is silently ignored becomes a signal that scores zero, and a
finding that quietly under-reports is worse than a pipeline that stops.

!!! note "`safe_getter` and `safe_values` are gone"
    Those v6 hooks existed only because v6 had no way to say *benign*: you had to detect a
    warning-list response by inspecting a task name and force the score to zero. A source now
    answers `verdict: "SAFE"`, and the negative polarity does the rest.

---

## Idempotence

A signal's identity is `(source, observable)` — unchanged since v6. Re-ingesting the same response
updates one fact instead of piling up duplicates:

```python
url.with_ti(Cyvest.io_load_signal(response))
url.with_ti(Cyvest.io_load_signal(response))   # still one signal
```

**Nothing raw enters an identity.** The response body lives in `payload`, so a request timestamp,
a quota counter or a correlation id changing between two calls has no effect at all — which is
what makes a retry, a replay or a duplicated queue message harmless.

### Keeping history is a deliberate act

When you *want* two scans from the same source to coexist, say so:

```python
url.with_ti(Cyvest.io_load_signal({**response, "external_id": "scan-2026-03"}))
url.with_ti(Cyvest.io_load_signal({**response, "external_id": "scan-2026-06"}))
```

### A source may change its mind

Conflicts on one key are settled by freshness, observation time outranking assertion time:

```python
url.with_ti(Cyvest.io_load_signal({"source": "vt", "weight": 6.0}))
url.with_ti(Cyvest.io_load_signal({"source": "vt", "verdict": "SAFE", "weight": 1.0}))

cv.get_report().observable(url.key).score   # -1.0
```

!!! warning "A score can go down"
    v6 merged threat intel with `max`, so a reclassification to *clean* never took effect. In v7
    the fresher verdict wins. Connectors that replay history must therefore send `observed_at`,
    otherwise a slow worker delivering an old scan late would overwrite a newer one.

---

## Distributed ingestion

Each worker builds its own fragment and reconciles it; union does the rest.

```python
shared = main.shared_context()

def virustotal_worker(shared, url_value):
    with shared.task(fragment_id="virustotal") as cv:
        url = cv.observable(cv.OBS.URL, url_value)
        url.with_ti(Cyvest.io_load_signal(fetch_from_virustotal(url_value)))
```

Three properties make this safe without coordination:

- **order does not matter** — merging is commutative and associative;
- **a retry is free** — reconciling twice changes nothing;
- **a partial failure still contributes** — `task()` reconciles even when the body raises.

And because each worker has its own `fragment_id`, a finding it creates sees only its own
fragment by default. When VirusTotal later raises the same URL, the ProofPoint worker's finding
keeps its own value — you can still tell who said what. See
[scope](scoring-model.md#scope-why-a-finding-can-hold-its-value).

---

## Archiving the raw response

By default the body stays in `payload`, which is enough for auditing one signal. Promote it to
`Evidence` when a single response feeds several facts — a verdict, a resolved IP, a redirect
chain — and you want them all pointing at the same material:

```python
evidence = cv.evidence_create("api_response", title="VirusTotal /url/report", content=response)
cv.finding_link_evidence(finding.key, evidence.key)
```

Evidence is never scored. It is there to be read.
