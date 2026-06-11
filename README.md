# Cyvest

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Cyvest is a Python library and CLI for representing cybersecurity investigations
as structured, serializable data.

An investigation contains observables and their relationships, Findings,
supporting Evidence, threat intelligence, enrichments, and tags. Cyvest maintains
deterministic keys, calculates scores and security levels, and records mutations
in an audit log.

## Main capabilities

| Area | Functionality |
| --- | --- |
| Data model | Typed observables, Findings, Evidence, threat intelligence, enrichments, tags, and relationships |
| Scoring | Configurable score aggregation and level propagation across observable and Finding links |
| Composition | Deterministic merging, shared context for parallel tasks, and investigation comparison |
| Serialization | Versioned JSON schema, JSON/Markdown export, migration from v5, and generated TypeScript types |
| Tooling | CLI inspection, statistics, IOC extraction, Rich output, and optional graph visualization |

Cyvest 6 uses a strict `schema_version: "6.0.0"`. Existing v5 integrations
should follow the [migration guide](docs/migration-v5-to-v6.md).

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

The optional visualization dependencies are available with:

```bash
pip install -e ".[visualization]"
```

## Quick Start

```python
from decimal import Decimal

from cyvest import Cyvest

cv = Cyvest(investigation_name="email-analysis")

url = (
    cv.observable(cv.OBS.URL, "https://phishing-site.com", internal=False)
    .with_ti("virustotal", score=Decimal("8.5"), level=cv.LVL.MALICIOUS)
    .relate_to(cv.root(), cv.REL.RELATED_TO)
)

evidence = cv.evidence(
    "sandbox_report",
    "URL detonation report",
    "internal-sandbox",
    external_id="report-4242",
    content={"verdict": "malicious"},
)

(
    cv.finding("url_analysis", "Analyze suspicious URL")
    .link_observable(url)
    .link_evidence(evidence)
    .with_score(Decimal("8.5"), reason="Malicious URL detected")
)

print(cv.get_global_score(), cv.get_global_level())
cv.io_save_json("investigation.json")
```

Public model objects are exposed through read-only proxies. Mutations use the
facade or fluent methods so score propagation, reverse links, and the audit log
remain consistent.

For deterministic reports and comparisons, pass an explicit
`investigation_id` when creating the investigation.

### Model Proxies

Helpers such as `observable_create`, `finding_create`, `cv.observable()`, and
`cv.finding()` return live read-only proxies. Use their mutation methods or the
equivalent `Cyvest` facade methods:

```python
url_obs.update_metadata(comment="triaged", internal=False, extra={"ticket": "INC-4242"})
finding.update_metadata(description="New scope", extra={"playbook": "url-analysis"})
finding.set_level(cv.LVL.SAFE, reason="Verified clean")
```

Missing referenced objects raise `KeyError`. Dictionary metadata merges by
default; use `merge_extra=False` or `merge_data=False` to replace it.

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

ip_obs = cv.observable_create(cv.OBS.IPV4, "192.0.2.1", internal=False)

cv.observable_add_relationship(
    url_obs,  # Can pass ObservableProxy directly
    ip_obs,   # Or use .key for string keys
    cv.REL.RELATED_TO,
    cv.DIR.BIDIRECTIONAL,
)
```

Cyvest exposes enums for observable types and relationships via the facade (`cv.OBS`, `cv.REL`, `cv.DIR`)
so IDEs can autocomplete the official vocabulary without extra imports.

Broad entity types use a subtype and, for locally scoped identifiers, a namespace:

```python
account = cv.observable(cv.OBS.USER, "alice@example.com", subtype=cv.SUB.USER_EMAIL)
host = cv.observable(
    cv.OBS.HOST,
    "WKSTN-42",
    subtype=cv.SUB.HOST_HOSTNAME,
    namespace="corp.example",
)
process = cv.observable(
    cv.OBS.PROCESS,
    "4242",
    subtype=cv.SUB.PROCESS_PID,
    namespace=host.key,
)
executable = cv.observable(
    cv.OBS.FILE,
    r"C:\Windows\System32\cmd.exe",
    subtype=cv.SUB.FILE_PATH,
    namespace=host.key,
)
process.relate_to(executable, cv.REL.RELATED_TO)
```

`EMAIL` remains an address observable. `USER/email` asserts that the value identifies an account. Both may coexist
with the same value and can be related explicitly. A process image path is modeled as `FILE/path`, not as a
`PROCESS` subtype.

### Findings

Findings represent verification steps in your investigation:

```python
finding = cv.finding_create(
    finding_name="malware_detection",
    description="Verify file hash against threat intel",
    score=Decimal("8.0"),
    level=cv.LVL.MALICIOUS
)

# Link observables to findings
cv.finding_link_observable(finding.key, file_hash_obs.key)
```

### Evidences

Evidence is structured supporting material reusable by multiple findings. The source of truth is
`Finding.evidence_links`; `Evidence.finding_links` is rebuilt for navigation and UI use.

```python
event = cv.evidence(
    "edr_event",
    "Suspicious process creation",
    "example-edr",
    external_id="event-4242",
    content={"pid": 4242, "parent_pid": 1200},
)

cv.finding("suspicious_process", "Suspicious process").link_evidence(event)
cv.finding("unexpected_shell", "Unexpected shell").link_evidence(event)
```

Evidence has no score or level and does not affect score propagation.

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

### Tags

Tags organize findings with automatic hierarchy based on `:` delimiter:

```python
# Simple: pass tag names directly (auto-creates tags)
finding = cv.finding("beacon_detection", "Detect C2 beacons")
finding.tagged("network", "c2:detection", "suspicious")

# With description: create tag first, then reference it
tag = cv.tag("network:c2:detection", "C2 Detection Findings")
finding.tagged(tag)

# Query hierarchy
children = cv.tag_get_children("network")  # ["network:c2"]
descendants = cv.tag_get_descendants("network")  # ["network:c2", "network:c2:detection"]
```

### Lookup Helpers

Use facade getters with either key strings or component parameters:

```python
url_obs = cv.observable_create(cv.OBS.URL, "https://malicious.com")
same_url = cv.observable_get(cv.OBS.URL, "https://malicious.com")
same_url_by_key = cv.observable_get(url_obs.key)

finding = cv.finding_create("malware_detection", "Verify file hash")
same_finding_by_key = cv.finding_get(finding.key)

tag = cv.tag_create("network:analysis")
same_tag = cv.tag_get("network:analysis")
same_tag_by_key = cv.tag_get(tag.key)

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
        cy.observable(cy.OBS.DOMAIN, data.get("domain"))

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
- **Observable → Finding (provenance-aware)**: Finding score/level only considers observables reachable through *effective* links (`observable_links`)
  - A link is effective when `propagation_mode="GLOBAL"` or when the finding's `origin_investigation_id` matches the current investigation id
- **Finding → Global**: All finding scores sum to global investigation score

Observable score aggregation is configurable via `score_mode_obs`:

```python
from cyvest import Cyvest
from cyvest.score import ScoreMode

cv = Cyvest(score_mode_obs=ScoreMode.MAX)  # default
cv = Cyvest(score_mode_obs=ScoreMode.SUM)  # accumulative children
```

**Provenance model**

- `Investigation.investigation_id` is a stable ULID included in exports.
- Findings keep a *canonical origin* (`origin_investigation_id`) for LOCAL_ONLY propagation; it is compared against the current investigation id.

**Audit log**

- All meaningful changes (including score/level changes) are recorded in the investigation-level audit log.
- Per-object histories are not stored; use `cv.investigation_get_audit_log()` to review changes.
- For compact, deterministic JSON output (useful for testing/diffing), exclude the audit log:
  ```python
  cv.io_save_json("output.json", include_audit_log=False)  # audit_log: null
  cv.io_to_invest(include_audit_log=False)  # schema.audit_log is None
  ```

To force cross-investigation propagation for a specific link, use a GLOBAL link:

```python
cv.finding_link_observable(finding.key, observable.key, propagation_mode="GLOBAL")
# or fluent:
cv.finding("id", "scope", "desc").link_observable(observable, propagation_mode="GLOBAL")
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
    cv.OBS.DOMAIN,
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
uncertain = cv.observable_create(cv.OBS.DOMAIN, "example.com")
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

SAFE findings:
- Automatically inherit SAFE level when linked to SAFE observables (if all other observables are ≤ SAFE)
- Can still upgrade to higher levels when NOTABLE/SUSPICIOUS/MALICIOUS observables are linked

**Root Observable Barrier:**

The root observable (the investigation's entry point with `value="root"`) acts as a special barrier to prevent cross-contamination:
Its key is derived from type + value (e.g. `obs:file:root` or `obs:artifact:root`).

**Barrier as Child** - When root appears as a child of other observables, it is **skipped** in their score calculations.

**Barrier as Parent** - Root's propagation is asymmetric:
- Root **CAN** be updated when children change (aggregates child scores)
- Root **does NOT** propagate upward beyond itself (stops recursive propagation)
- Root **DOES** propagate to findings normally

This design enables flexible investigation structures while preventing unintended score contamination.

### Comparing Investigations

Compare two investigations to identify differences in findings, observables, and threat intelligence:

```python
from decimal import Decimal
from cyvest import Cyvest, ExpectedResult, Level, compare_investigations
from cyvest.io_rich import display_diff

# Create expected and actual investigations
expected = Cyvest(investigation_name="expected")
expected.finding_create("domain-finding", "Verify domain", score=Decimal("1.0"))

actual = Cyvest(investigation_name="actual")
actual.finding_create("domain-finding", "Verify domain", score=Decimal("2.0"))
actual.finding_create("new-finding", "New detection", score=Decimal("1.5"))

# Compare investigations
diffs = compare_investigations(actual, expected)
# diffs contains:
#   - MISMATCH for domain-finding (score changed 1.0 -> 2.0)
#   - ADDED for new-finding
```

**Tolerance Rules**

Use `result_expected` rules to define acceptable score variations:

```python
# Define tolerance rules
rules = [
    # Accept any score >= 1.0 for this finding
    ExpectedResult(finding_name="domain-finding", score=">= 1.0"),
    # Accept any score < 3.0 for roger-ai
    ExpectedResult(key="fnd:roger-ai", level=Level.SUSPICIOUS, score="< 3.0"),
]

# Compare with tolerance - findings satisfying rules are not flagged as diffs
diffs = compare_investigations(actual, expected, result_expected=rules)
```

Supported operators: `>=`, `<=`, `>`, `<`, `==`, `!=`

**Visual Diff Display**

Display differences in a rich table format:

```python
from cyvest.io_rich import display_diff
from logurich import logger

# Display diff table with tree structure showing observables and threat intel
display_diff(diffs, lambda r: logger.rich("INFO", r), title="Investigation Diff")
```

Output:
```
╭────────────────────────────────────────────────┬────────────────────┬─────────────────┬────────╮
│ Key                                            │      Expected      │     Actual      │ Status │
├────────────────────────────────────────────────┼────────────────────┼─────────────────┼────────┤
│ fnd:new-finding                                  │         -          │  NOTABLE 1.50   │   +    │
│ └── domain: example.com                        │         -          │   INFO 0.00     │        │
│     └── VirusTotal                             │         -          │   INFO 0.00     │        │
├────────────────────────────────────────────────┼────────────────────┼─────────────────┼────────┤
│ fnd:domain-finding                               │   NOTABLE 1.00     │  NOTABLE 2.00   │   ✗    │
╰────────────────────────────────────────────────┴────────────────────┴─────────────────┴────────╯
```

Status symbols: `+` (added), `-` (removed), `✗` (mismatch)

**Convenience Methods**

Use methods directly on Cyvest objects:

```python
# Compare and get diff items
diffs = actual.compare(expected=expected, result_expected=rules)

# Compare and display in one call
actual.display_diff(expected=expected, title="My Investigation Diff")
```

## Examples

See the `examples/` directory for complete examples:

- **01_email_basic.py**: Basic email phishing investigation
- **02_urls_and_ips.py**: Network investigation with URLs and IPs
- **03_merge_demo.py**: Multi-process investigation merging
- **04_email.py**: Multi-threaded investigation with SharedInvestigationContext
- **05_visualization.py**: Interactive HTML visualization showcasing scores, levels, and relationship flows
- **06_compare_investigations.py**: Compare investigations with tolerance rules and visual diff output

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

# Extract observables (IOCs) from text
echo "Check IP 192.168.1.1 and https://evil.com" | cyvest extract
cyvest extract report.txt -t url -t ip -o iocs.txt
cyvest extract --from-url https://example.com/indicators.txt -f json

# Output the JSON Schema describing serialized investigations and generate types
uv run cyvest schema -o ./schema/cyvest.schema.json && pnpm -C js/packages/cyvest-js run generate:types
```

### Observable Extraction

Extract cyber observables (IOCs) from raw text, markdown, or web pages:

```bash
# From stdin (pipe text)
echo "Malicious IP: 192[.]168[.]1[.]1, URL: hxxps://evil[.]com/malware" | cyvest extract

# From file
cyvest extract threat_report.txt

# Filter by type
cyvest extract report.txt -t url -t ip -t hash

# Output as JSON
cyvest extract report.txt -f json -o extracted.json

# Markdown output for LLM consumption
cyvest extract report.txt --format markdown --title "Threat IOCs"
cyvest extract report.txt --format markdown-table --defang-output

# Fetch from URL and extract
cyvest extract --from-url https://example.com/ioc-feed.txt

# Keep defanged format (don't refang)
cyvest extract -R < defanged_iocs.txt
```

**Supported observable types:**

| Type | Description | Examples |
|------|-------------|----------|
| `url` | URLs with various schemes | http, https, ftp, sftp, tcp, udp |
| `ip` / `ipv4` / `ipv6` | IP addresses | 192.168.1.1, 2001:db8::1 |
| `email` | Email addresses | user@example.com |
| `hash` | Cryptographic hashes | MD5, SHA1, SHA256, SHA512 |
| `domain` | Domain names | example.com |

**Defanged indicator support:**

- URLs: `hxxp://`, `hxxps://`, `[.]`, `[/]`
- IPs: `192[.]168[.]1[.]1`, `10(dot)0(dot)0(dot)1`
- Emails: `user[@]example.com`, `user at example.com`

**Programmatic usage:**

```python
from cyvest.extract import (
    extract_all,
    extract_from_url,
    refang,
    defang,
    observables_to_markdown,
    observables_to_markdown_table,
)

# Extract from text
text = "Check IP 192[.]168[.]1[.]1 and hxxps://evil[.]com"
observables = extract_all(text)
for obs in observables:
    print(f"{obs.obs_type.value}: {obs.value} (count: {obs.count})")

# Generate markdown for LLM consumption
md = observables_to_markdown(observables, title="Extracted IOCs", group_by_type=True)
print(md)

# Generate compact markdown table
table = observables_to_markdown_table(observables, defang_values=True)
print(table)

# Extract from URL
observables = extract_from_url("https://example.com/ioc-feed.txt")

# Refang/defang utilities
safe_text = defang("https://malware.com")  # -> hxxps://malware[.]com
original = refang("hxxps://malware[.]com")  # -> https://malware.com
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
uv sync --group docs
uv run --group docs mkdocs serve
uv run --group docs mkdocs build --strict
```

## JavaScript packages

The repo includes a PNPM workspace under `js/` with three packages:

- `@cyvest/cyvest-js`: TypeScript types, schema validation, and helpers for Cyvest investigations.
- `@cyvest/cyvest-vis`: React component for the force-directed observable graph (Cytoscape + `d3-force`).
- `@cyvest/cyvest-app`: Vite demo that bundles the JS packages with sample investigations.

The JS packages track the generated schema; serialized investigations should include fields like
`investigation_id`, `investigation_name`, `audit_log`, `score_display`, `finding_links`, and
`observable_links`. The investigation start time is recorded as an `INVESTIGATION_STARTED` event
in the `audit_log`.

See `docs/js-packages.md` for workspace commands and usage snippets.

## Contributing

Changes should include focused tests and pass the Python and JavaScript
validation commands documented in [CONTRIBUTING](docs/contributing.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
