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
  "schema_version": "7.2.0",
  "kind": "threat_intel",
  "source": "virustotal",
  "source_class": "vendor_feed",
  "verdict": "MALICIOUS",
  "weight": 6.0,
  "confidence": 1.0,
  "observed_at": "2026-03-01T09:12:00Z",
  "comment": "12/70 engines",
  "taxonomies": [{"name": "malware-type", "value": "trojan", "verdict": "MALICIOUS"}],
  "payload": {"scan_id": "…", "requested_at": "…", "quota_left": 4211}
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | the signal contract version (`7.2.0`) |
| `kind` | yes | must be `threat_intel` |
| `source` | yes | who is speaking; a string containing a non-whitespace character |
| `source_class` | no | what kind of speaker (`vendor_feed`, `internal_tool`, `analyst`, …) |
| `verdict` | yes | the explicit judgment; cannot be null |
| `weight` | yes | a finite, non-negative numeric magnitude |
| `confidence` | yes | a finite number in `]0, 1]` |
| `observed_at` | no | when the source observed it — what merge conflicts are settled on |
| `external_id` | no | discriminant when you want to keep history |
| `comment`, `taxonomies` | no | display material |
| `payload` | no | the raw response, kept as-is |

**An envelope carries a complete judgment.** `SignalEnvelope.model_validate` and `io_load_signal`
never infer a verdict, choose a weight or fill in confidence. Integers and floats are accepted;
booleans, numeric strings, `NaN` and infinities are not. A `SAFE` verdict carries a non-negative
weight too: polarity belongs to the verdict. Explicit verdicts and weights are not recalibrated
to match a score band.

Use `Cyvest.io_dump_signal` at the producer when only a verdict or a signed score is available.
It completes the judgment **before** emitting a validated envelope.

Publish the machine-readable contract to your producers:

```bash
cyvest schema --which signal -o schema/cyvest.signal.schema.json
```

---

## Emitting an envelope

A producer that runs Python does not have to assemble the JSON by hand. `io_dump_signal`
validates its construction inputs, completes the judgment and validates the resulting envelope:

```python
import json

from cyvest import Cyvest

payload = Cyvest.io_dump_signal(
    "virustotal",
    verdict="MALICIOUS",
    comment="12/70 engines",
    observed_at=scan.completed_at,
    taxonomies=(Cyvest.taxonomy(name="malware-type", value="trojan", verdict="MALICIOUS"),),
    payload=raw_response,
)

requests.post("https://soar.internal/signals", data=json.dumps(payload))
```

The result is the wire form, not the in-process draft `threat_intel_draft` returns: it carries
`schema_version` and `kind`, and renders enums, datetimes and tuples as JSON, so it goes straight
through `json.dumps`. A typo raises here, in the producer's own pipeline, which is where a
producer's mistake belongs.

**Both halves of the judgment are always emitted.** An envelope in flight has no consumer policy
to fall back on, so a stated `verdict` leaves with the magnitude its producer assumes, and a
stated `weight` leaves with the verdict of its band:

```python
Cyvest.io_dump_signal("misp", verdict="SAFE")["weight"]    # 1.5
Cyvest.io_dump_signal("vt", weight=6.0)["verdict"]         # "MALICIOUS"
Cyvest.io_dump_signal("vt", weight=-2.0)                   # SAFE, weight 2.0
```

Polarity belongs to the verdict, so the wire always carries a magnitude, never a signed score.

!!! note "Completing pins the producer's calibration"
    `io_dump_signal` resolves the missing magnitude before the payload leaves, fixing it at the
    producer's calibration. That is what makes an archived envelope replayable. Pass `policy=`
    when the defaults are not yours. A signed weight without a verdict is construction shorthand
    (`-2.0` becomes `SAFE`, weight `2.0`); a negative weight alongside an explicit verdict is
    rejected. For local, policy-dependent judgments use `observable.with_ti` or
    `Cyvest.threat_intel_draft`, not an incomplete transport envelope.

---

## Descriptive taxonomies

Since 7.1, `Taxonomy` carries `name`, `value` and `verdict` (default `INFO`). It is an immutable
value object, **not a scoring judgment**: no weight or confidence, no propagation, no effect on
the signal, observable, finding or investigation score. Different entries on the same signal
may carry different descriptive verdicts.

```python
from cyvest import Cyvest, Taxonomy, Verdict

cv = Cyvest()
url = cv.observable("url", "https://example.test")
entry = cv.taxonomy(name="engine", value="clean", verdict=Verdict.SAFE)
ti = cv.observable_add_threat_intel(
  url, "vendor", verdict=Verdict.MALICIOUS, weight=6.0, taxonomies=(entry,)
)
ti.add_taxonomy(name="family", value="trojan", verdict=Verdict.MALICIOUS)
ti.taxonomies[0].value  # "clean"
ti.remove_taxonomy("engine")
url.score  # still 6.0
```

Constructing `Taxonomy(...)` directly is equivalent to `cv.taxonomy(...)`. Dictionaries are
accepted at ingestion too. Names are unique per signal; `add_taxonomy` updates an existing
name in place in the tuple, while `remove_taxonomy` removes by name. The façade exposes the
same operations as `threat_intel_add_taxonomy` and `threat_intel_remove_taxonomy`.

The 7.1 investigation and signal schemas serialize entries as objects. Older 7.0 text entries
remain readable: the entire string becomes `name`, with `value=""` and `verdict=INFO`. No
separator is guessed. Loading needs no migration flag; saving or `cyvest migrate` emits the
structured form. The old `level` of a v6 taxonomy becomes `verdict` during migration, preserving
its `name` and `value`; information already discarded by a previous 7.0 migration cannot be
recovered.

## Strict on purpose

There is no tolerant parsing and no `preprocessor` hook. An unknown field, a blank source, an
incomplete judgment or a confidence of `1.5` raises at the boundary:

```python
response = Cyvest.io_dump_signal("vt", verdict="MALICIOUS")
Cyvest.io_load_signal({**response, "verdit": "MALICIOUS"})
# ValidationError: Extra inputs are not permitted [type=extra_forbidden]
```

That is the point. A typo that is silently ignored becomes a signal that scores zero, and a
finding that quietly under-reports is worse than a pipeline that stops.

Connectors that need the typed envelope can call `SignalEnvelope.model_validate(response)`
directly. Cyvest owns all generic validation; the connector validates only its application
payload (for example GT's `data`, `data_type`, `task_name` and `raw_result`). Cyvest neither
interprets those payload fields nor classifies transport status messages as signals.

### Upgrading to 7.2

The signal schema is now `7.2.0`; the investigation schema stays `7.1.0`. Python and JavaScript
package versions are `7.2.0`.

**The reader is deliberately stricter than 7.0/7.1.** Previously missing envelope fields could
receive defaults, and ingestion could derive the judgment. All six required fields must now
be present, even on envelopes labelled `7.0.x` or `7.1.x`. Complete older envelopes remain
readable, including legacy text taxonomies; unknown future minor versions are rejected.

Update producers that assemble partial dictionaries to use `io_dump_signal`, or emit the full
contract themselves. Earlier `io_dump_signal` output already carries the required fields;
it remains readable if its values satisfy the stricter constraints. Do not run received native
envelopes through the construction helper to hide missing fields or repair invalid judgments.

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
first = Cyvest.io_dump_signal("vt", weight=6.0)
later = Cyvest.io_dump_signal("vt", verdict="SAFE", weight=1.0)
url.with_ti(Cyvest.io_load_signal(first))
url.with_ti(Cyvest.io_load_signal(later))

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
- **a partial failure still contributes** — `task()` reconciles even when the body raises, unless
  you pass `reconcile_on_error=False`.

And because each worker has its own `fragment_id`, every fact stays attributable to the feed that
asserted it. When a rule must report the verdict *it* fetched rather than whatever the observable
accumulates next, it pins itself to that signal. See
[basis](scoring-model.md#basis-what-a-link-scores-on).

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
