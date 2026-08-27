# Cyvest

[![PyPI](https://img.shields.io/pypi/v/cyvest.svg)](https://pypi.org/project/cyvest/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Cyvest is a Python library and CLI for representing cybersecurity investigations as structured,
serializable data.

An investigation is an **append-only log of immutable facts** — observables, relations, signals,
evidence, findings, decisions, tags — plus a **report** derived from them. No score is ever stored
on a fact, which is what makes an investigation auditable, mergeable, and re-scorable under a
different policy.

```
facts  ──(engine + policy)──▶  report
```

Cyvest 7 uses `schema_version: "7.0.0"`. Existing 6.x integrations should follow the
[migration guide](docs/migration-v6-to-v7.md) — the API changed almost everywhere, and there is no
compatibility layer.

**[Read the documentation](https://pakitosec.github.io/cyvest/)** for the model, the scoring
semantics and the design rationale. This README is a tour of the API.

## Installation

```bash
uv add cyvest                    # or: pip install cyvest
uvx --from cyvest cyvest --help  # the CLI ships with the package
```

## Quick Start

```python
from cyvest import Cyvest

cv = Cyvest(investigation_name="email-analysis")

url = (
    cv.observable(cv.OBS.URL, "https://phishing-site.com", internal=False)
    .with_ti("virustotal", 8.5, comment="Known phishing site")
)
cv.observable_add_relation(cv.root().key, url.key, cv.REL.EXTRACTION)

evidence = cv.evidence(
    "sandbox_report",
    title="URL detonation report",
    source="internal-sandbox",
    external_id="report-4242",
    content={"verdict": "malicious"},
)

(
    cv.finding("url_analysis", "Analyze suspicious URL")
    .link_observable(url)
    .link_evidence(evidence)
    .with_weight(8.5)
)

print(cv.get_global_score(), cv.get_global_verdict())
cv.display_explanation(url.key)          # and why
cv.io_save_json("investigation.json")
```

Pass an explicit `investigation_id` when you want reproducible reports you can diff between runs.

---

# Features

One snippet per capability, picking up where the Quick Start left off. Each link points to the page
explaining why it works that way.

## Observables and threat intel

```python
url = cv.observable(cv.OBS.URL, "https://bad.com", internal=False)

url.with_ti("virustotal", 8.5)                    # weight → verdict from the score bands
url.with_ti("misp", verdict=cv.VERDICT.SAFE)      # verdict → weight from the policy
url.with_ti("otx", 6.0, confidence=0.4, taxonomies=["phishing"])

url.score, url.verdict, url.threat_intels, url.contributions
```

Stating either the verdict or the weight is enough; the other is derived.
→ [Concepts](docs/getting-started/concepts.md)

## Relations

```python
domain = cv.observable(cv.OBS.DOMAIN, "bad.com")
domain.relate_to(url, cv.REL.EXTRACTION)
domain.relate_to(ip, cv.REL.PIVOT, confidence=0.7)
domain.relate_to(other, cv.REL.RELATED_TO)        # context only, propagates nothing
```

`source` is the parent, `target` the child; the kind implies the direction.
→ [Scoring Model](docs/scoring-model.md)

## Findings, evidence and tags

```python
evidence = cv.evidence("sandbox_report", title="Detonation", content={"verdict": "malicious"})

(
    cv.finding("phishing_page", "Credential harvesting page")
    .link_observable(url)
    .link_evidence(evidence)
    .with_weight(8.5)
    .tagged("attack:phishing")                    # tags nest through ':'
)

cv.tag("attack").aggregated_score, cv.tag("attack").descendants()
```

→ [Concepts](docs/getting-started/concepts.md)

## Conclusions

```python
cv.conclusion("analyst_call", "Confirmed phishing", verdict=cv.VERDICT.MALICIOUS)
```

A conclusion raises the total to the verdict it asserts instead of adding a term — no weight is
accepted. → [Scoring Model](docs/scoring-model.md)

## Decisions

```python
url.allowlist("Corporate sandbox", decided_by="rssi")        # caps the score
ip.blocklist("Confirmed C2", decided_by="soc")               # raises to the policy floor
finding.dismiss("Known false positive", decided_by="alice")  # excluded from the total
finding.confirm("Reviewed and valid", decided_by="bob")
finding.vacate("Stance withdrawn", decided_by="bob")         # back to the computed value

url.allowlisted, finding.dismissed, finding.suppressed_by_decision
```

A decision bounds a result rather than adding a term, and stays a fact — dated, attributed,
mergeable. `justification` is required.

## Scope

```python
cv.finding("rule", "…").link_observable(url, scope=cv.SCOPE.ALL)
```

Each finding-to-observable link carries a scope, `OWN_FRAGMENT` by default, so a finding holds its
own value even when the observable rises in another fragment.
→ [Scoring Model](docs/scoring-model.md)

## Ingesting external signals

```python
response = fetch_from_virustotal(url_value)      # your connector's job
url.with_ti(Cyvest.io_load_signal(response))
```

Validated against a published contract, strictly, so a typo fails at the boundary instead of
becoming a signal that quietly scores zero. Re-ingesting the same response is a no-op.
Producers get the other half — `Cyvest.io_dump_signal("virustotal", weight=6.0)` builds the
JSON payload and fails on their side rather than the consumer's.
→ [External Signals](docs/external-signals.md)

## Policy and engines

```python
from cyvest import DEFAULT_POLICY, Cyvest

policy = DEFAULT_POLICY.model_copy(update={"uphold_floor": 7.0, "version": "strict-v1"})
cv = Cyvest(policy=policy, engine="basic-v1")

cv.reevaluate(policy=policy)                     # replay the same facts differently
Cyvest.ENGINES()                                 # registered engines and their aliases
```

The report is always re-derived from the facts, never read from the document.

## Timeline and statistics

```python
from cyvest import Salience

for entry in cv.timeline(time="asserted", min_salience=Salience.KEY):
    print(entry.when, entry.kind, entry.title)

cv.statistics()
cv.display_timeline()
cv.display_statistics()
```

→ [Timeline](docs/timeline.md)

## Merging and parallel work

```python
main.merge_investigation(other)                  # idempotent, commutative, associative

shared = main.shared_context()

def worker(shared):
    with shared.task() as cv:
        cv.observable(cv.OBS.EMAIL, "sender@example.com")

print(shared.get_global_score(), shared.get_global_verdict())
```

Reconciling is a union of facts, so arrival order does not matter and reconciling twice is
harmless. → [Shared Investigation Context](docs/shared-investigation-context.md)

## Comparing investigations

```python
from cyvest import ExpectedResult, compare_investigations

diffs = compare_investigations(
    actual,
    result_expected=[ExpectedResult(rule_id="phishing-page", score=">= 3.0")],
)
```

Tolerance rules express a **band**, so a test survives a policy tweak that shifts magnitudes without
changing conclusions. → [Comparing Investigations](docs/comparing-investigations.md)

## Serialization

```python
cv.io_save_json("investigation.json")
cv.io_save_markdown("report.md")
data = cv.io_to_dict()

cv = Cyvest.io_load_json("investigation.json")
cv = Cyvest.io_load_json("v6-document.json", migrate=True)
```

A versioned JSON schema, generated TypeScript types, and migration from 5.x and 6.x.

## Rich output

```python
cv.display_summary(show_graph=True)
cv.display_explanation(url.key)                  # every number, with the terms behind it
cv.display_diff(expected)                        # or result_expected=[...]
```

## Extracting IOCs

```python
from cyvest.extract import defang, extract_all, extract_from_url, observables_to_markdown

observables = extract_all("Contact evil@example.com via hxxps://bad[.]com")
markdown = observables_to_markdown(observables)
safe_text = defang("https://malware.com")        # -> hxxps://malware[.]com
```

→ [Observable Extraction](docs/observable-extraction.md)

---

## CLI

```bash
# Inspect
cyvest show investigation.json --stats
cyvest stats investigation.json --detailed
cyvest explain investigation.json obs:url:https://phishing-site.com
cyvest timeline investigation.json --key-only

# Compose
cyvest merge inv1.json inv2.json inv3.json -o merged.json
cyvest diff actual.json expected.json --rules tolerances.json

# Convert
cyvest export investigation.json -o report.md -f markdown
cyvest migrate old.json -o new.json              # detects 5.x or 6.x
cyvest schema -o ./schema/cyvest.schema.json
cyvest schema --which signal -o ./schema/cyvest.signal.schema.json

# Evaluation
cyvest engines
cyvest policy show investigation.json
cyvest show investigation.json --engine basic-v1

# Extraction
echo "IP: 192[.]168[.]1[.]1, URL: hxxps://evil[.]com" | cyvest extract
cyvest extract report.txt -t url -t ip -t hash -f json -o iocs.json
cyvest extract --from-url https://example.com/ioc-feed.txt
cyvest extract -R < defanged_iocs.txt            # keep the defanged form
```

The Python side always re-derives the report from the facts on load, so a stale or hand-edited
`report` block never influences what the CLI prints; `--engine` chooses which engine does it.

## Examples

| File | Shows |
| --- | --- |
| `01_email_basic.py` | a minimal email investigation |
| `02_urls_and_ips.py` | observables, relations, threat intel |
| `03_merge_demo.py` | merging investigations from several sources |
| `04_email.py` | a realistic phishing case |
| `05_graph_dataset.py` | a dataset for the graph visualisation |
| `06_compare_investigations.py` | diffing and tolerance rules |
| `07_conclusion.py` | conclusions and analyst calls |

## JavaScript packages

A PNPM workspace under `js/`:

- `@cyvest/cyvest-js` — types, schema validation and query helpers. **Read-only by construction**:
  it never recomputes a score, it reads the `report` the document carries.
- `@cyvest/cyvest-vis` — React component for the force-directed observable graph (Cytoscape +
  `d3-force`).
- `@cyvest/cyvest-app` — Vite demo bundling the packages with sample investigations.

→ [JavaScript Packages](docs/js-packages.md)

## Development

```bash
git clone https://github.com/PakitoSec/cyvest.git && cd cyvest
uv sync --all-groups

uv run pytest -q                   # tests
uv run pytest --cov=cyvest         # with coverage
uv run ruff format src tests       # format
uv run ruff check src tests        # lint

bash scripts/generate.sh           # schema, TS types, fixtures and JS builds
uv run --group docs mkdocs serve   # docs preview
```

→ [Contributing](docs/contributing.md)

## License

MIT — see the LICENSE file.
