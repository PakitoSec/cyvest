# Cyvest Documentation

Welcome to the **Cyvest** documentation! Cyvest is a Python framework for building, analyzing, and structuring cybersecurity investigations programmatically.

## What is Cyvest?

Cyvest provides a comprehensive toolkit for modeling security investigations with:

- **Structured Objects**: Observables, checks, threat intelligence, enrichments, and containers
- **Automatic Scoring**: Dynamic score calculation and propagation through the investigation hierarchy
- **Level Classification**: Automatic security level assignment (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- **Relationship Tracking**: STIX2-compliant relationships between cyber observables
- **Investigation Merging**: Combine investigations from multiple threads or processes
- **Rich Reporting**: Export to JSON, Markdown, and beautiful terminal displays

## Key Features

### 🔍 Comprehensive Investigation Modeling

Model complete security investigations with observables (URLs, IPs, domains, hashes), checks (verification steps), threat intelligence (verdicts from external sources), and enrichments (structured metadata).

### 📊 Automatic Score Propagation

Scores automatically propagate through the investigation:
- Threat intelligence → Observables (using **max** of TI scores)
- Observable relationships → Parent observables (configurable MAX or SUM mode)
- Observables → Linked checks (check score = max of all linked observables)
- All checks → Global investigation score

**Flexible Scoring Modes:**
- **MAX mode** (default): Conservative scoring taking the highest severity
- **SUM mode**: Accumulative scoring for cumulative risk scenarios
- **Score history**: Complete audit trail of all score changes with timestamps and reasons

### 🎯 Flexible Architecture

Built for real-world use cases:
- Thread-safe for concurrent investigation building
- Deterministic key generation for reliable merging
- Audit trail with score change history
- STIX2-compliant relationship modeling

### 💾 Multiple Export Formats

- **JSON**: For storage, analysis, and tool integration
- **Markdown**: For LLM consumption and documentation
- **Rich Console**: Beautiful terminal displays

## Quick Example

```python
from decimal import Decimal
from cyvest import Cyvest, Level

with Cyvest() as cv:
    # Create observable with threat intelligence
    url = (
        cv.observable("url", "https://phishing.com", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=Level.MALICIOUS)
        .relate_to(cv.root(), "related-to")
    )

    # Create check
    check = (
        cv.check("phishing_check", "email", "Analyze phishing URL")
        .link_observable(url.get())
        .with_score(Decimal("8.5"))
    )

    print(f"Investigation Score: {cv.get_global_score()}")
    print(f"Investigation Level: {cv.get_global_level()}")
```

## Use Cases

Cyvest is designed for:

- **Security Operations Centers (SOCs)**: Automate investigation workflows
- **Incident Response**: Structure and document incident investigations
- **Threat Hunting**: Build repeatable hunting methodologies
- **Malware Analysis**: Track relationships between artifacts
- **Phishing Analysis**: Analyze emails and linked resources
- **Tool Integration**: Combine results from multiple security tools

## Getting Started

Ready to dive in? Check out the [Installation Guide](getting-started/installation.md) and [Quick Start](getting-started/quickstart.md) to begin using Cyvest.

## Architecture Overview

Cyvest uses a clean, layered architecture with automatic merge-on-create:

```
Cyvest (API Facade)
    ↓
Investigation (Core State Management)
    ├── Observables (URLs, IPs, domains, hashes, etc.)
    │   ├── Threat Intelligence (verdicts from sources)
    │   └── Relationships (STIX2-compliant links)
    ├── Checks (verification steps)
    │   └── Linked observables
    ├── Containers (hierarchical organization)
    │   ├── Checks
    │   └── Sub-containers
    ├── Enrichments (structured metadata)
    ├── ScoreEngine (automatic score propagation)
    └── InvestigationStats (real-time metrics)
```

**Key architectural features:**
- **Automatic merge-on-create**: Duplicate objects are automatically merged when added
- **Clean separation**: `Cyvest` provides the API, `Investigation` manages state
- **Direct DSL access**: DSL handlers work directly with `Investigation` for performance
- **CLI support**: Merge multiple investigation JSON files from command line

## Community & Support

- **GitHub**: [github.com/PakitoSec/cyvest](https://github.com/PakitoSec/cyvest)
- **Issues**: [Report bugs and request features](https://github.com/PakitoSec/cyvest/issues)
- **Discussions**: Ask questions and share use cases

## License

Cyvest is licensed under the MIT License. See the [LICENSE](https://github.com/PakitoSec/cyvest/blob/main/LICENSE) file for details.
