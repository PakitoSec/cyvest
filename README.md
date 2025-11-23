# Cyvest - Cybersecurity Investigation Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Cyvest** is a Python framework for building, analyzing, and structuring cybersecurity investigations programmatically. It provides automatic scoring, level calculation, relationship tracking, and rich reporting capabilities.

## Features

- 🔍 **Structured Investigation Modeling**: Model investigations with observables, checks, threat intelligence, and enrichments
- 📊 **Automatic Scoring**: Dynamic score calculation and propagation through investigation hierarchy
- 🎯 **Level Classification**: Automatic security level assignment (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- 🔗 **Relationship Tracking**: STIX2-compliant relationship modeling between observables
- 🏷️ **STIX2 Type Support**: Built-in enums for STIX2 Observable and Relationship types with autocomplete
- 📈 **Real-time Statistics**: Live metrics and aggregations throughout the investigation
- 🔄 **Investigation Merging**: Combine investigations from multiple threads or processes
- 🧵 **Multi-Threading Support**: Advanced thread-safe shared context available via `cyvest.investigation` module
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
from cyvest import Cyvest, Level, ObservableType, RelationshipType

# Create an investigation
with Cyvest(data={"type": "email"}) as cv:
    # Create observables with STIX2 types
    url = (
        cv.observable(ObservableType.URL, "https://phishing-site.com", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=Level.MALICIOUS)
        .relate_to(cv.root(), RelationshipType.RELATED_TO)
    )

    # Create checks
    check = cv.check("url_analysis", "email_body", "Analyze suspicious URL")
    check.link_observable(url)
    check.with_score(Decimal("8.5"), "Malicious URL detected")

    # Display results
    print(f"Global Score: {cv.get_global_score()}")
    print(f"Global Level: {cv.get_global_level()}")

    # Export
    from cyvest.io_serialization import save_investigation_json
    save_investigation_json(cv, "investigation.json")
```

### Model Proxies

Cyvest only exposes immutable model proxies. Helpers like `observable_create`, `check_create`, and the
fluent `cv.observable()`/`cv.check()` convenience methods return `ObservableProxy`, `CheckProxy`, `ContainerProxy`, etc.
These proxies reflect the live investigation state but raise `AttributeError` if you try to assign to their attributes.
Use the facade helpers (`cv.observable_set_level`, `cv.check_update_score`, `cv.observable_add_threat_intel`) or the
built-in fluent methods on the proxies themselves (`with_ti`, `relate_to`, `link_observable`, `with_score`, …) so the
score engine runs automatically.

Safe metadata fields like `comment`, `extra`, or `internal` can be updated through the proxies without breaking score
consistency:

```python
url_obs.update_metadata(comment="triaged", internal=False, extra={"ticket": "INC-4242"})
check.update_metadata(description="New scope", extra={"playbook": "url-analysis"})
```

Dictionary fields merge by default; pass `merge_extra=False` (or `merge_data=False` for enrichments) to overwrite them.

## Core Concepts

### Observables

Observables represent cyber artifacts (URLs, IPs, domains, hashes, files, etc.). Use STIX2-compliant types for standardization:

```python
from cyvest import ObservableType, RelationshipType

# Create observable with STIX2 type enum
url_obs = cv.observable_create(
    ObservableType.URL,
    "https://malicious.com",
    internal=False
)

# Or use strings (backward compatible)
ip_obs = cv.observable_create("ipv4-addr", "192.0.2.1", internal=False)

# Add threat intelligence
cv.observable_add_threat_intel(
    url_obs.key,
    source="virustotal",
    score=Decimal("9.0"),
    level=Level.MALICIOUS,
    comment="Detected as malware distribution site"
)

# Create relationships with STIX2 relationship types
# Accepts observable proxies or string keys
cv.observable_add_relationship(
    url_obs,  # Can pass ObservableProxy directly
    ip_obs,   # Or use .key for string keys
    RelationshipType.RESOLVES_TO
)
```

**Available STIX2 Observable Types:**

- Network: `IPV4_ADDR`, `IPV6_ADDR`, `DOMAIN_NAME`, `URL`, `MAC_ADDR`, `NETWORK_TRAFFIC`
- Email: `EMAIL_ADDR`, `EMAIL_MESSAGE`, `EMAIL_MIME_PART`
- File: `FILE`, `DIRECTORY`, `ARTIFACT`
- System: `PROCESS`, `SOFTWARE`, `USER_ACCOUNT`, `WINDOWS_REGISTRY_KEY`
- Other: `AUTONOMOUS_SYSTEM`, `MUTEX`, `X509_CERTIFICATE`

**Available STIX2 Relationship Types:**

- Network: `RESOLVES_TO`, `BELONGS_TO`, `COMMUNICATES_WITH`
- File: `CONTAINS`, `DOWNLOADED`, `DROPPED`
- Email: `FROM`, `SENDER`, `TO`, `CC`, `BCC`
- Process: `CREATED`, `OPENED`, `PARENT`, `CHILD`
- General: `RELATED_TO`, `DERIVED_FROM`, `DUPLICATE_OF`

**Relationship Direction:**

Relationships support directional semantics with **automatic semantic defaults** that determine **hierarchical score propagation**:

```python
from cyvest import RelationshipType, RelationshipDirection

# Automatically gets OUTBOUND (domain → IP)
# IP is a child of domain, IP's score propagates UP to domain
# Accepts observable proxies directly
cv.observable_add_relationship(domain, ip, RelationshipType.RESOLVES_TO)

# Automatically gets INBOUND (file ← URL)
# URL is parent of file, file's score propagates UP to URL
cv.observable_add_relationship(malware, url, RelationshipType.DOWNLOADED)

# Automatically gets BIDIRECTIONAL (host ↔ host)
# No hierarchical propagation - scores remain independent
cv.observable_add_relationship(host1, host2, RelationshipType.COMMUNICATES_WITH)

# Can override semantic defaults if needed
cv.observable_add_relationship(
    domain, ip,  # Accepts observable proxies
    RelationshipType.RESOLVES_TO,
    RelationshipDirection.INBOUND  # explicit override
)
```

**Direction-Based Hierarchical Scoring:**

Relationship directions define parent-child hierarchies for score propagation:

- **OUTBOUND (→)**: `source → target` — Target is a **child** of source
  - Source's score includes child's score: `score = max(TI_scores, child_scores)`
  - Example: `domain → IP` means IP score flows up to domain

- **INBOUND (←)**: `source ← target` — Target is a **parent** of source
  - Target's score includes source's score
  - Example: `file ← URL` means file score flows up to URL

- **BIDIRECTIONAL (↔)**: `source ↔ target` — **No hierarchy**
  - Scores do NOT propagate between observables
  - Each maintains independent score from its own threat intel
  - Example: `host1 ↔ host2` keeps separate scores

**Semantic Default Directions:**

Each relationship type has an intuitive default direction:
- **OUTBOUND (→)**: `RESOLVES_TO`, `BELONGS_TO`, `CONTAINS`, `TO`, `CC`, `BCC`, `CREATED`, `OPENED`, `PARENT`, `VALUES`
- **INBOUND (←)**: `DOWNLOADED`, `DROPPED`, `FROM`, `SENDER`, `CHILD`, `DERIVED_FROM`
- **BIDIRECTIONAL (↔)**: `COMMUNICATES_WITH`, `RELATED_TO`, `DUPLICATE_OF`

Direction symbols appear in visualizations, markdown exports, and determine score flow.

### Checks

Checks represent verification steps in your investigation:

```python
check = cv.check_create(
    check_id="malware_detection",
    scope="endpoint",
    description="Verify file hash against threat intel",
    score=Decimal("8.0"),
    level=Level.MALICIOUS
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
    level=Level.SUSPICIOUS,
    comment="15/70 vendors flagged as malicious",
    taxonomies=[{"malware-type": "trojan"}]
)
```

### Containers

Containers organize checks hierarchically:

```python
with cv.container("network_analysis") as network:
    with network.sub_container("c2_detection") as c2:
        check = cv.check("beacon_detection", "network", "Detect C2 beacons")
        c2.add_check(check.get())
```

### Multi-Threaded Investigations

**Advanced Feature**: Use `SharedInvestigationContext` (imported directly from `cyvest.investigation`) for thread-safe parallel task execution with automatic observable sharing:

```python
from cyvest import Cyvest
from cyvest.investigation import SharedInvestigationContext, InvestigationTask, Investigation
from concurrent.futures import ThreadPoolExecutor

class EmailAnalysisTask(InvestigationTask):
    def run(self, shared_context):
        # SharedInvestigationContext.create_cyvest() creates a Cyvest instance
        # that auto-merges results when the context exits
        with shared_context.create_cyvest() as cy:
            # Access data from root observable
            data = cy.root().extra

            # Build investigation fragment
            domain = cy.observable(ObservableType.DOMAIN_NAME, data.get("domain"))

            # Auto-reconciles on exit
            return cy

# Create shared context
main_inv = Investigation(email_data, root_type="artifact")
shared = SharedInvestigationContext(main_inv)

# Run tasks in parallel - they can reference each other's observables
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(task.run, shared) for task in tasks]
    for future in as_completed(futures):
        future.result()  # Auto-reconciled

# Get merged investigation
final_investigation = shared.get_investigation()
```

See `examples/04_email.py` for a complete multi-threaded investigation example.

### Scoring & Levels

Scores and levels are automatically calculated and propagated:

- **Threat Intel → Observable**: Observable score = **max** of all threat intel scores (not sum)
- **Observable Hierarchy**: Parent observable scores include child observable scores based on relationship direction:
  - **OUTBOUND relationships**: target scores propagate to source (source is parent)
  - **INBOUND relationships**: source scores propagate to target (target is parent)
  - **BIDIRECTIONAL relationships**: no hierarchical propagation
- **Observable → Check**: Check score = **max** of all linked observables' scores and check's current score
- **Manual checks**: Set `score_policy=CheckScorePolicy.MANUAL` (or `check.disable_auto_score()`) to prevent observable-driven score/level changes
- **Check → Global**: All check scores sum to global investigation score

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
    "domain",
    "trusted.example.com",
    level=Level.SAFE
)

# Adding low-score threat intel won't downgrade to TRUSTED or INFO
cv.observable_add_threat_intel(trusted.key, "source1", score=Decimal("0"))
# Level stays SAFE, score updates to 0

# But high-score threat intel can still upgrade to MALICIOUS if warranted
cv.observable_add_threat_intel(trusted.key, "source2", score=Decimal("6.0"))
# Level upgrades to MALICIOUS, score updates to 6.0

# Threat intel with SAFE level can also mark observables as SAFE
uncertain = cv.observable_create("domain", "example.com")
cv.observable_add_threat_intel(
    uncertain.key,
    "whitelist_service",
    score=Decimal("0"),
    level=Level.SAFE
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

The root observable (the investigation's entry point with `value="input-data"`) acts as a special barrier to prevent cross-contamination:

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

## Project Structure

```
cyvest/
├── src/cyvest/
│   ├── __init__.py          # Package initialization
│   ├── cyvest.py            # High-level API facade
│   ├── investigation.py     # Core state management with merge-on-create
│   ├── proxies.py           # Read-only proxies + fluent helper methods
│   ├── levels.py            # Level enum and scoring logic
│   ├── keys.py              # Key generation utilities
│   ├── model.py             # Core data models
│   ├── score.py             # Scoring and propagation engine
│   ├── stats.py             # Statistics and aggregations
│   ├── io_serialization.py  # JSON and Markdown export
│   ├── io_rich.py           # Rich console output
│   └── cli.py               # CLI interface
├── examples/                # Example scripts
├── tests/                   # Test suite
├── docs/                    # Documentation
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

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

- **Thread-Safe**: Advanced `SharedInvestigationContext` (via `cyvest.investigation`) provides thread-safe parallel task execution
- **Deterministic Keys**: Same objects always generate same keys for merging
- **Score Propagation**: Automatic hierarchical score calculation
- **Flexible Export**: JSON for storage, Markdown for LLM analysis
- **STIX2 Relationships**: Industry-standard relationship modeling
- **Audit Trail**: Score change history for debugging

## Future Enhancements

- Database persistence layer
- Additional export formats (PDF, HTML)
