# Cyvest - Cybersecurity Investigation Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Cyvest** is a Python framework for building, analyzing, and structuring cybersecurity investigations programmatically. It provides automatic scoring, level calculation, relationship tracking, and rich reporting capabilities.

## Features

- 🔍 **Structured Investigation Modeling**: Model investigations with observables, checks, threat intelligence, and enrichments
- 📊 **Automatic Scoring**: Dynamic score calculation and propagation through investigation hierarchy
- 🎯 **Level Classification**: Automatic security level assignment (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- 🔗 **Relationship Tracking**: Lightweight relationship modeling between observables
- 🏷️ **Typed Helpers**: Built-in enums for observable types and relationships with autocomplete
- 📈 **Real-time Statistics**: Live metrics and aggregations throughout the investigation
- 🔄 **Investigation Merging**: Combine investigations from multiple threads or processes
- 🧵 **Multi-Threading Support**: Advanced thread-safe shared context available via `cyvest.shared`
- 💾 **Multiple Export Formats**: JSON and Markdown output for reporting and LLM consumption
- 🎨 **Rich Console Output**: Beautiful terminal displays with the Rich library
- 🧩 **Fluent helpers**: Convenient API with method chaining for rapid development

## Installation

### Using uv (recommended)

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/PakitoSec/cyvest.git
cd cyvest

# Install dependencies
uv sync

# Install in development mode
uv pip install -e .
```

### Using pip

```bash
pip install -e .
```

>  Install the optional visualization extra with\
> `pip install "cyvest[visualization]"` (or `uv pip install -e ".[visualization]"`).

## Quick Start

```python
from decimal import Decimal
from cyvest import Cyvest

# Create an investigation (root_data becomes the root observable extra)
cv = Cyvest(root_data={"type": "email"})

# Create observables
url = (
    cv.observable(cv.OBS.URL, "https://phishing-site.com", internal=False)
    .with_ti("virustotal", score=Decimal("8.5"), level=cv.LVL.MALICIOUS)
    .relate_to(cv.root(), cv.REL.RELATED_TO)
)

# Create checks
check = cv.check("url_analysis", "email_body", "Analyze suspicious URL")
check.link_observable(url)
check.with_score(Decimal("8.5"), "Malicious URL detected")

# Display results
print(f"Global Score: {cv.get_global_score()}")
print(f"Global Level: {cv.get_global_level()}")

# Export
cv.io_save_json("investigation.json")
```

### Model Proxies

Cyvest only exposes immutable model proxies. Helpers like `observable_create`, `check_create`, and the
fluent `cv.observable()`/`cv.check()` convenience methods return `ObservableProxy`, `CheckProxy`, `ContainerProxy`, etc.
These proxies reflect the live investigation state but raise `AttributeError` if you try to assign to their attributes.
All mutations are routed through the Investigation layer, so use the facade helpers (`cv.observable_set_level`,
`cv.check_update_score`, `cv.observable_add_threat_intel`) or the built-in fluent methods on the proxies themselves
(`with_ti`, `relate_to`, `link_observable`, `with_score`, …) so the score engine and audit log stay consistent.

Mutation helpers that reference existing objects (for example, `cv.observable_add_relationship`,
`cv.check_link_observable`, `cv.container_add_check`) raise `KeyError` when a key is missing.

Safe metadata fields like `comment`, `extra`, or `internal` can be updated through the proxies without breaking score
consistency:

```python
url_obs.update_metadata(comment="triaged", internal=False, extra={"ticket": "INC-4242"})
check.update_metadata(description="New scope", extra={"playbook": "url-analysis"})
```

Dictionary fields merge by default; pass `merge_extra=False` (or `merge_data=False` for enrichments) to overwrite them.

### Threat Intel Drafts

When the observable is unknown yet, create a draft and attach it later:

```python
draft = cv.threat_intel_draft("vt", score=Decimal("4.2"), comment="Initial lookup")
obs = cv.observable(cv.OBS.DOMAIN, "example.com")
obs.with_ti_draft(draft)
```

Drafts are plain `ThreatIntel` objects with no `observable_key` yet; attaching generates the key.

## Core Concepts

### Observables

Observables represent cyber artifacts (URLs, IPs, domains, hashes, files, etc.).

```python
from cyvest import Cyvest

cv = Cyvest()

url_obs = cv.observable_create(cv.OBS.URL, "https://malicious.com", internal=False)

ip_obs = cv.observable_create(cv.OBS.IPV4_ADDR, "192.0.2.1", internal=False)

cv.observable_add_relationship(
    url_obs,  # Can pass ObservableProxy directly
    ip_obs,   # Or use .key for string keys
    cv.REL.RELATED_TO,
    cv.DIR.BIDIRECTIONAL,
)
```

Cyvest exposes enums for observable types and relationships via the facade (`cv.OBS`, `cv.REL`, `cv.DIR`)
so IDEs can autocomplete the official vocabulary without extra imports.

### Checks

Checks represent verification steps in your investigation:

```python
check = cv.check_create(
    check_id="malware_detection",
    scope="endpoint",
    description="Verify file hash against threat intel",
    score=Decimal("8.0"),
    level=cv.LVL.MALICIOUS
)

# Link observables to checks
cv.check_link_observable(check.key, file_hash_obs.key)
```

### Threat Intelligence

Threat intelligence provides verdicts from external sources:

```python
cv.observable_add_threat_intel(
    observable.key,
    source="virustotal",
    score=Decimal("7.5"),
    level=cv.LVL.SUSPICIOUS,
    comment="15/70 vendors flagged as malicious",
    taxonomies=[cv.taxonomy(level=cv.LVL.MALICIOUS, name="scan", value="trojan")]
)
```

Taxonomies are unique by name per threat intel entry. Use the fluent helpers to add or remove them:

```python
ti = cv.observable_add_threat_intel(observable.key, source="vt", score=Decimal("7.5"))
ti.add_taxonomy(level=cv.LVL.SUSPICIOUS, name="confidence", value="medium")
ti.remove_taxonomy("confidence")
```

### Containers

Containers organize checks hierarchically:

```python
with cv.container("network_analysis") as network:
    with network.sub_container("c2_detection") as c2:
        check = cv.check("beacon_detection", "network", "Detect C2 beacons")
        c2.add_check(check)
```

### Lookup Helpers

Use facade getters with either key strings or component parameters:

```python
url_obs = cv.observable_create(cv.OBS.URL, "https://malicious.com")
same_url = cv.observable_get(cv.OBS.URL, "https://malicious.com")
same_url_by_key = cv.observable_get(url_obs.key)

check = cv.check_create("malware_detection", "endpoint", "Verify file hash")
same_check = cv.check_get("malware_detection", "endpoint")
same_check_by_key = cv.check_get(check.key)

container = cv.container_create("network_analysis")
same_container = cv.container_get("network_analysis")
same_container_by_key = cv.container_get(container.key)

enrichment = cv.enrichment_create("whois", {"registrar": "Example Inc"})
same_enrichment = cv.enrichment_get("whois")
same_enrichment_by_key = cv.enrichment_get(enrichment.key)
```

Low-level `Investigation` getters accept keys only; use the facade for component-based lookups.

### Multi-Threaded Investigations

**Advanced Feature**: Use `Cyvest.shared_context()` (or `SharedInvestigationContext` from `cyvest.shared`) for safe parallel task execution with automatic observable sharing:

```python
from cyvest import Cyvest
from concurrent.futures import ThreadPoolExecutor, as_completed

def email_analysis(shared_context):
    # create_cyvest() yields a task-local Cyvest that auto-merges on context exit
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        cy.observable(cy.OBS.DOMAIN_NAME, data.get("domain"))

# Create shared context
main_cy = Cyvest(root_data=email_data, root_type=Cyvest.OBS.ARTIFACT)
shared = main_cy.shared_context()

# Run tasks in parallel - they can reference each other's observables
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(email_analysis, shared) for _ in tasks]
    for future in as_completed(futures):
        future.result()  # Auto-reconciled

# Get merged investigation (same object passed to shared_context)
final_cy = main_cy
```

See `examples/04_email.py` for a complete multi-threaded investigation example.

### Scoring & Levels

Scores and levels are automatically calculated and propagated:

- **Threat Intel → Observable**: Observable score = **max** of all threat intel scores (not sum)
- **Observable Hierarchy**: Parent observable scores include child observable scores based on relationship direction:
  - **OUTBOUND relationships**: target scores propagate to source (source is parent)
  - **INBOUND relationships**: source scores propagate to target (target is parent)
  - **BIDIRECTIONAL relationships**: no hierarchical propagation
- **Observable → Check (provenance-aware)**: Check score/level only considers observables reachable through *effective* links (`observable_links`)
  - A link is effective when `propagation_mode="GLOBAL"` or when the check's `origin_investigation_id` matches the current investigation id
- **Check → Global**: All check scores sum to global investigation score

Observable score aggregation is configurable via `score_mode_obs`:

```python
from cyvest import Cyvest
from cyvest.score import ScoreMode

cv = Cyvest(score_mode_obs=ScoreMode.MAX)  # default
cv = Cyvest(score_mode_obs=ScoreMode.SUM)  # accumulative children
```

**Provenance model**

- `Investigation.investigation_id` is a stable ULID included in exports.
- Checks keep a *canonical origin* (`origin_investigation_id`) for LOCAL_ONLY propagation; it is compared against the current investigation id.

**Audit log**

- All meaningful changes (including score/level changes) are recorded in the investigation-level audit log.
- Per-object histories are not stored; use `cv.investigation_get_audit_log()` to review changes.

To force cross-investigation propagation for a specific link, use a GLOBAL link:

```python
cv.check_link_observable(check.key, observable.key, propagation_mode="GLOBAL")
# or fluent:
cv.check("id", "scope", "desc").link_observable(observable, propagation_mode="GLOBAL")
```

Score to Level mapping:

- `< 0.0` → TRUSTED
- `== 0.0` → INFO
- `< 3.0` → NOTABLE
- `< 5.0` → SUSPICIOUS
- `>= 5.0` → MALICIOUS

**SAFE Level Protection:**

The SAFE level has special protection for trusted/whitelisted observables:

```python
# Mark a known-good domain as SAFE
trusted = cv.observable_create(
    cv.OBS.DOMAIN_NAME,
    "trusted.example.com",
    level=cv.LVL.SAFE
)

# Adding low-score threat intel won't downgrade to TRUSTED or INFO
cv.observable_add_threat_intel(trusted.key, "source1", score=Decimal("0"))
# Level stays SAFE, score updates to 0

# But high-score threat intel can still upgrade to MALICIOUS if warranted
cv.observable_add_threat_intel(trusted.key, "source2", score=Decimal("6.0"))
# Level upgrades to MALICIOUS, score updates to 6.0

# Threat intel with SAFE level can also mark observables as SAFE
uncertain = cv.observable_create(cv.OBS.DOMAIN_NAME, "example.com")
cv.observable_add_threat_intel(
    uncertain.key,
    "whitelist_service",
    score=Decimal("0"),
    level=cv.LVL.SAFE
)
# Observable upgraded to SAFE level with automatic downgrade protection
```

SAFE observables:
- Cannot be downgraded to lower levels (NONE, TRUSTED, INFO)
- Can be upgraded to higher levels (NOTABLE, SUSPICIOUS, MALICIOUS)
- Score values still update based on threat intelligence
- Protection is preserved during investigation merges
- Can be marked SAFE by threat intel sources (e.g., whitelists, reputation databases)

SAFE checks:
- Automatically inherit SAFE level when linked to SAFE observables (if all other observables are ≤ SAFE)
- Can still upgrade to higher levels when NOTABLE/SUSPICIOUS/MALICIOUS observables are linked

**Root Observable Barrier:**

The root observable (the investigation's entry point with `value="root"`) acts as a special barrier to prevent cross-contamination:
Its key is derived from type + value (e.g. `obs:file:root` or `obs:artifact:root`).

**Barrier as Child** - When root appears as a child of other observables, it is **skipped** in their score calculations.

**Barrier as Parent** - Root's propagation is asymmetric:
- Root **CAN** be updated when children change (aggregates child scores)
- Root **does NOT** propagate upward beyond itself (stops recursive propagation)
- Root **DOES** propagate to checks normally

This design enables flexible investigation structures while preventing unintended score contamination.

## Examples

See the `examples/` directory for complete examples:

- **01_email_basic.py**: Basic email phishing investigation
- **02_urls_and_ips.py**: Network investigation with URLs and IPs
- **03_merge_demo.py**: Multi-process investigation merging
- **04_email.py**: Multi-threaded investigation with SharedInvestigationContext
- **05_visualization.py**: Interactive HTML visualization showcasing scores, levels, and relationship flows

Run an example:

```bash
python examples/01_email_basic.py
python examples/04_email.py
python examples/05_visualization.py
```

## CLI Usage

Cyvest includes a command-line interface for working with investigation files:

```bash
# Display investigation
cyvest show investigation.json --graph

# Show statistics
cyvest stats investigation.json --detailed

# Export to markdown
cyvest export investigation.json -o report.md -f markdown

# Merge investigations with automatic deduplication
cyvest merge inv1.json inv2.json inv3.json -o merged.json

# Merge with statistics display
cyvest merge inv1.json inv2.json -o merged.json --stats

# Merge and display rich summary
cyvest merge inv1.json inv2.json -o merged.json -f rich --stats

# Generate an interactive visualization (requires visualization extra)
cyvest visualize investigation.json --min-level SUSPICIOUS --group-by-type

# Output the JSON Schema describing serialized investigations and generate types
uv run cyvest schema -o ./schema/cyvest.schema.json && pnpm -C js/packages/cyvest-js run generate:types
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
uv sync --all-extras

# Run tests
pytest

# Run tests with coverage
pytest --cov=cyvest --cov-report=html

# Format code
ruff format .

# Lint code
ruff check .
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_score.py

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=cyvest
```

## Documentation

Build the documentation with MkDocs:

```bash
# Install docs dependencies
uv sync --all-extras

# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build
```

## JavaScript packages

The repo includes a PNPM workspace under `js/` with three packages:

- `@cyvest/cyvest-js`: TypeScript types, schema validation, and helpers for Cyvest investigations.
- `@cyvest/cyvest-vis`: React components for graph visualization (depends on `@cyvest/cyvest-js`).
- `@cyvest/cyvest-app`: Vite demo that bundles the JS packages with sample investigations.

The JS packages track the generated schema; serialized investigations should include fields like
`investigation_id`, `investigation_name`, `started_at`, `score_display`, `check_links`, and
`observable_links`.

See `docs/js-packages.md` for workspace commands and usage snippets.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Use Cases

Cyvest is designed for:

- **Security Operations Centers (SOCs)**: Automate investigation workflows
- **Incident Response**: Structure and document incident investigations
- **Threat Hunting**: Build repeatable hunting methodologies
- **Malware Analysis**: Track relationships between artifacts
- **Phishing Analysis**: Analyze emails and linked resources
- **Integration**: Combine results from multiple security tools

## Architecture Highlights

- **Concurrency**: Advanced `SharedInvestigationContext` (via `cyvest.shared`) enables safe parallel task execution
- **Deterministic Keys**: Same objects always generate same keys for merging
- **Score Propagation**: Automatic hierarchical score calculation
- **Flexible Export**: JSON for storage, Markdown for LLM analysis
- **Audit Trail**: Score change history for debugging

## Future Enhancements

- Database persistence layer
- Additional export formats (PDF, HTML)
