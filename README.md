# Cyvest

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

## Main capabilities

| Area | Functionality |
| --- | --- |
| Data model | Typed observables, relations, findings, evidence, threat intelligence, decisions, tags |
| Scoring | Pluggable engines; every number comes with the terms that produced it |
| Composition | Union-based merging (idempotent, commutative, associative), shared context for parallel tasks, investigation diffing |
| Serialization | Versioned JSON schema, JSON/Markdown export, migration from 5.x and 6.x, generated TypeScript types |
| Tooling | CLI inspection, explanation, timeline, statistics, IOC extraction, Rich output |

Cyvest 7 uses `schema_version: "7.0.0"`. Existing 6.x integrations should follow the
[migration guide](docs/migration-v6-to-v7.md) — the API changed almost everywhere, and there is no
compatibility layer.

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/PakitoSec/cyvest.git
cd cyvest
uv sync
uv pip install -e .
```

### Using pip

```bash
pip install -e .
```

Graph visualization is provided by the `@cyvest/cyvest-vis` React package, see
[docs/js-packages.md](docs/js-packages.md).

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

## Core concepts in one minute

**Facts are immutable and semantically keyed.** An observable is `obs:{type}:{value}`, a finding is
`fnd:{rule_id}:{subject_key}`. Creating the "same" fact twice updates one fact rather than adding
two — which is exactly what makes merging idempotent, and what surprises people once.

**A judgment has three parts.** `verdict` (what is claimed), `weight` (how much it is worth),
`confidence` (how sure the source is). Stating either the verdict or the weight is enough; the
other is derived from the score bands.

```python
url.with_ti("virustotal", 8.5)                      # weight → MALICIOUS
url.with_ti("misp", verdict=cv.VERDICT.SAFE)        # verdict → weight from policy
```

**Relations are facts, and direction is implied.** `source_key` is the parent, `target_key` the
child; there is no direction flag. `EXTRACTION` and `PIVOT` propagate score, `RELATED_TO`
deliberately does not.

**Decisions overrule the arithmetic.** They bound a result instead of adding a term, and they stay
facts — dated, attributed, mergeable.

```python
url.allowlist(justification="Corporate sandbox")     # caps the score
finding.dismiss(justification="Known false positive") # excluded from the total
```

**Scope keeps merges honest.** Each finding-to-observable link carries a scope, `OWN_FRAGMENT` by
default, so a finding holds its own value even when the observable it points at rises in another
fragment.

See [Core Concepts](docs/getting-started/concepts.md) and
[the scoring model](docs/scoring-model.md).

## Ingesting from external systems

```python
response = fetch_from_virustotal(url_value)      # your connector's job
observable.with_ti(Cyvest.io_load_signal(response))
```

`io_load_signal` validates against a published contract — strictly, so a typo fails at the
boundary instead of becoming a signal that quietly scores zero. Re-ingesting the same response is
a no-op: nothing raw enters an identity, so a request timestamp or a quota counter cannot turn one
signal into two.

```bash
cyvest schema --which signal -o schema/cyvest.signal.schema.json
```

See [External Signals](docs/external-signals.md).

## Parallel work

```python
main = Cyvest(root_data=incident)
shared = main.shared_context()

def worker(shared):
    with shared.task() as cv:
        cv.observable(cv.OBS.EMAIL, "sender@example.com")

# ... run workers concurrently ...
print(shared.get_global_score(), shared.get_global_verdict())
```

Reconciling is a union of facts, so arrival order does not matter and reconciling twice is
harmless. See [Shared Investigation Context](docs/shared-investigation-context.md).

## Comparing investigations

```python
from cyvest import ExpectedResult, compare_investigations

diffs = compare_investigations(
    actual,
    result_expected=[ExpectedResult(rule_id="phishing-page", score=">= 3.0")],
)
```

Tolerance rules express a **band**, so a test survives a policy tweak that shifts magnitudes
without changing conclusions. Comparing reports produced by two different engines is refused by
default. See [Comparing Investigations](docs/comparing-investigations.md).

## CLI usage

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
cyvest migrate old.json -o new.json          # detects 5.x or 6.x
cyvest schema -o ./schema/cyvest.schema.json
cyvest schema --which signal -o ./schema/cyvest.signal.schema.json

# Evaluation
cyvest engines
cyvest policy show investigation.json
cyvest show investigation.json --engine basic-v1   # evaluate with another engine
```

The Python side always re-derives the report from the facts on load, so a stale or hand-edited
`report` block never influences what the CLI prints; `--engine` chooses which engine does it.

### Observable extraction

Extract IOCs from raw text, markdown, or web pages:

```bash
echo "Malicious IP: 192[.]168[.]1[.]1, URL: hxxps://evil[.]com/malware" | cyvest extract
cyvest extract threat_report.txt -t url -t ip -t hash
cyvest extract report.txt -f json -o extracted.json
cyvest extract report.txt --format markdown --title "Threat IOCs"
cyvest extract --from-url https://example.com/ioc-feed.txt
cyvest extract -R < defanged_iocs.txt          # keep the defanged form
```

```python
from cyvest.extract import defang, extract_all, extract_from_url, observables_to_markdown

observables = extract_all("Contact evil@example.com via hxxps://bad[.]com")
markdown = observables_to_markdown(observables)
safe_text = defang("https://malware.com")      # -> hxxps://malware[.]com
```

See [Observable Extraction](docs/observable-extraction.md).

## Examples

The `examples/` directory contains end-to-end scenarios:

| File | Shows |
| --- | --- |
| `01_email_basic.py` | a minimal email investigation |
| `02_urls_and_ips.py` | observables, relations, threat intel |
| `03_merge_demo.py` | merging investigations from several sources |
| `04_email.py` | a realistic phishing case |
| `05_graph_dataset.py` | a dataset for the graph visualisation |
| `06_compare_investigations.py` | diffing and tolerance rules |

## Development

```bash
uv sync --all-extras

uv run pytest -q --no-cov          # tests
uv run pytest --cov=cyvest         # with coverage
uv run ruff format src tests       # format
uv run ruff check src tests        # lint
```

Regenerate the schema, TypeScript types, fixtures and JS builds in one go:

```bash
bash scripts/generate.sh
```

## Documentation

```bash
uv sync --group docs
uv run --group docs mkdocs serve
uv run --group docs mkdocs build --strict
```

## JavaScript packages

A PNPM workspace under `js/` with three packages:

- `@cyvest/cyvest-js`: types, schema validation and query helpers. **Read-only by construction**:
  it never recomputes a score, it reads the `report` the document carries.
- `@cyvest/cyvest-vis`: React component for the force-directed observable graph (Cytoscape +
  `d3-force`).
- `@cyvest/cyvest-app`: Vite demo bundling the packages with sample investigations.

See [docs/js-packages.md](docs/js-packages.md).

## Contributing

Changes should include focused tests and pass the Python and JavaScript validation commands
documented in [CONTRIBUTING](docs/contributing.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
