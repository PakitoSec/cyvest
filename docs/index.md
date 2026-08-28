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
| **Immutable facts** | An append-only log you can audit, merge and re-score | `cyvest.facts`, [Concepts](getting-started/concepts.md#the-facts) |
| **Derived scoring** | No score is ever stored; every number comes with the terms that produced it | `cyvest.evaluation`, [Scoring Model](scoring-model.md) |
| **Link basis** | Each link states what it scores on, so a finding can hold at the intel it fetched | `cyvest.enums.LinkBasis`, [Scoring Model](scoring-model.md#basis-what-a-link-scores-on) || **Fluent helpers** | Builder-style methods with deterministic keys and safe merges | `cyvest.cyvest`, [Quick Start](getting-started/quickstart.md#using-the-fluent-api) |
| **Shared context** | Thread-safe fragments that reconcile into a single story | `cyvest.shared.SharedInvestigationContext`, [Guide](shared-investigation-context.md) |
| **Timeline** | A chronology projected from the log, on two clocks | `cyvest.evaluation.timeline`, [Guide](timeline.md) |
| **Comparison** | Diff investigations with tolerance bands for regression testing | `cyvest.compare`, [Guide](comparing-investigations.md) |
| **Observable extraction** | Extract IOCs from text, markdown, or URLs with defang/refang support | `cyvest.extract`, [Guide](observable-extraction.md) |
| **Reporting** | Export JSON, Markdown, or render rich terminal summaries | `cyvest.io.serialization`, `cyvest.io.render`, [Quick Start](getting-started/quickstart.md#exporting-results) |

---

## Walkthrough in 60 Seconds

```python
from cyvest import Cyvest

cv = Cyvest(root_data={"type": "email"})
phishing_url = (
    cv.observable(cv.OBS.URL, "https://phishing.com", internal=False)
    .with_ti("virustotal", 8.5)
)
cv.observable_add_relation(cv.root().key, phishing_url.key, cv.REL.EXTRACTION)

(
    cv.finding("email_url_finding", "Analyze embedded URL")
    .link_observable(phishing_url)
    .with_weight(8.5)
)

print(cv.get_global_score(), cv.get_global_verdict())
cv.display_explanation(phishing_url.key)   # and why
```

!!! tip "Best practice"
    Store investigation metadata (request ID, analyst, ticket link) in the root observable's `extra` field by passing `root_data` to `Cyvest(...)`.

!!! note "Facts in, report out"
    `cv.observable_*` / `cv.finding_*` append immutable facts and return thin proxies. Scores are
    never stored on them: `get_report()` derives everything, so re-evaluating under another policy
    changes the numbers without touching a single fact.

---

## Architecture Snapshot

```
Cyvest (facade + fluent proxies)
└─ Investigation (thin orchestrator)
   ├─ FactStore ......... the append-only log: observables, relations, signals,
   │                      evidence, findings, decisions, tags
   ├─ Policy ............ weights, attenuation, decision bounds
   ├─ Engine ............ derives a Report from facts + policy
   └─ IO / reporting .... JSON, Markdown, Rich, timeline
```

**Design principles**

- Facts are immutable and semantically keyed, so merges are lossless and idempotent.
- No derived value is ever stored; the report is the single place numbers live.
- A relation's *kind* decides whether score propagates — there is no direction flag.
- A link's *basis* decides what it reads: the whole observable, named signals, or nothing at all.
- The evaluator never reads the clock, so an archived report stays reproducible.

---

## Typical Journeys

| Goal | Recommended Path |
| --- | --- |
| Evaluate Cyvest in <10 minutes | [Getting Started](getting-started/quickstart.md) |
| Upgrade an existing Cyvest 6.x integration | [Migration from v6 to v7](migration-v6-to-v7.md) |
| Upgrade an existing Cyvest 5.x integration | [Migration from v5 to v6](migration-v5-to-v6.md) |
| Understand observables vs. findings | [Core Concepts](getting-started/concepts.md#the-facts) |
| Understand where a number comes from | [Scoring Model](scoring-model.md) |
| Keep a finding at the intel it fetched | [Scoring Model → Basis](scoring-model.md#basis-what-a-link-scores-on) |
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
