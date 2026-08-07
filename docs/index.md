# Cyvest

Build, score, and narrate cybersecurity investigations with a single fluent Python API.

> Cyvest turns raw observables into curated stories—complete with scoring, provenance, and export-ready reports.

---

## Start Fast

1. **Install** using [uv or pip](getting-started/installation.md).
2. **Model your first case** via the [Quick Start notebook](getting-started/quickstart.md).
3. **Master the vocabulary** with [Core Concepts](getting-started/concepts.md).

!!! info "Need help choosing the right entry point?"
    - Automating SOC workflows? Jump straight to [Quick Start](getting-started/quickstart.md#using-the-fluent-api).
    - Upgrading from Cyvest 5.x? Follow the [v5 to v6 migration guide](migration-v5-to-v6.md).
    - Running multi-threaded tasks? See [Shared Investigation Context](shared-investigation-context.md).
    - Contributing or extending the fluent helpers? Review the [Contributing guide](contributing.md#architecture-overview).

---

## Platform Highlights

| Area | Why it matters | What to look at |
| --- | --- | --- |
| **Structured objects** | Model observables, findings, TI, tags, and enrichments with typed helpers | `cyvest.model`, [Concepts](getting-started/concepts.md#observables) |
| **Deterministic scoring** | MAX/SUM propagation and automatic level classification | `cyvest.score`, [Scoring System](getting-started/concepts.md#scoring-system) |
| **Fluent helpers** | Builder-style methods with deterministic keys and safe merges | `cyvest.cyvest`, [Quick Start](getting-started/quickstart.md#using-the-fluent-api) |
| **Shared context** | Thread-safe fragments that can reconcile into a single story | `cyvest.shared.SharedInvestigationContext`, [Guide](shared-investigation-context.md) |
| **Comparison** | Compare investigations with tolerance rules for regression testing | `cyvest.compare`, [Guide](comparing-investigations.md) |
| **Observable extraction** | Extract IOCs from text, markdown, or URLs with defang/refang support | `cyvest.extract`, [Guide](observable-extraction.md) |
| **Reporting** | Export JSON, Markdown, or render rich terminal summaries | `cyvest.io_serialization`, `cyvest.io_rich`, [Quick Start](getting-started/quickstart.md#exporting-results) |

---

## Walkthrough in 60 Seconds

```python
from decimal import Decimal
from cyvest import Cyvest

cv = Cyvest(root_data={"type": "email"})
phishing_url = (
    cv.observable(cv.OBS.URL, "https://phishing.com", internal=False)
    .with_ti("virustotal", Decimal("8.5"), level=cv.LVL.MALICIOUS)
    .relate_to(cv.root(), cv.REL.RELATED_TO)
)

(
    cv.finding("email_url_finding", "Analyze embedded URL")
    .link_observable(phishing_url)
    .with_score(Decimal("8.5"))
)

print(cv.get_global_score(), cv.get_global_level())
```

!!! tip "Best practice"
    Store investigation metadata (request ID, analyst, ticket link) in the root observable's `extra` field by passing `root_data` to `Cyvest(...)`.

!!! note "Immutable proxies"
    The objects returned by `cv.observable_*`/`cv.finding_*` are read-only `*Proxy` wrappers. Use the facade or their fluent helper methods to apply changes so scoring stays consistent.

---

## Architecture Snapshot

```
Cyvest (facade + fluent proxies)
└─ Investigation (core state)
   ├─ Observables & relationships
   ├─ Findings and tags (workflow context)
   ├─ Threat intelligence (source, score, taxonomies)
   ├─ ScoreEngine (MAX/SUM propagation, history)
   ├─ InvestigationStats (live metrics)
   └─ IO / reporting utilities (JSON, Markdown, Rich)
```

**Design principles**

- Deterministic keys guarantee lossless merges from concurrent builders.
- Relationship direction controls score propagation.
- The fluent helper layer is thin—everything ultimately stores data inside a single `Investigation`.

---

## Typical Journeys

| Goal | Recommended Path |
| --- | --- |
| Evaluate Cyvest in <10 minutes | [Getting Started](getting-started/quickstart.md) |
| Upgrade an existing Cyvest 5.x integration | [Migration from v5 to v6](migration-v5-to-v6.md) |
| Understand observables vs. findings | [Core Concepts](getting-started/concepts.md#investigation-structure) |
| Share state across threads | [Shared Investigation Context](shared-investigation-context.md) |
| Compare investigations or regression test | [Comparing Investigations](comparing-investigations.md) |
| Extract IOCs from text or URLs | [Observable Extraction](observable-extraction.md) |
| Extend scoring or fluent helpers | [Contributing](contributing.md#architecture-overview) |
| Embed results in other tools | [Quick Start → Exporting Results](getting-started/quickstart.md#exporting-results) |

---

## JavaScript Packages

- `@cyvest/cyvest-js`: TypeScript types, schema validation, and graph helpers for Cyvest investigations.
- `@cyvest/cyvest-vis`: React component (Cytoscape + `d3-force`) for observable relationship graphs.
- `@cyvest/cyvest-app`: Vite demo bundling the JS packages with sample investigations.

[See JavaScript packages guide](js-packages.md) for install and workspace commands.

---

## Community

- :octicons-logo-github-16: [github.com/PakitoSec/cyvest](https://github.com/PakitoSec/cyvest)
- :octicons-issue-opened-16: [Report bugs or request features](https://github.com/PakitoSec/cyvest/issues)
- :octicons-comment-discussion-16: Join discussions and share patterns

Cyvest is MIT licensed. Contributions and issue reports are welcome!
