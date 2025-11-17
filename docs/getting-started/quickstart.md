# Quick Start

Model a complete investigation, link observables, and produce a shareable report in minutes.

---

## 1. Create your first investigation

```python
from decimal import Decimal
from cyvest import Cyvest, Level, ObservableType

with Cyvest(data={"type": "email_analysis"}) as cv:
    phishing_url = cv.observable_create(
        ObservableType.URL,
        "https://fake-bank-login.com",
        internal=False,
    )

    cv.observable_add_threat_intel(
        phishing_url.key,
        source="virustotal",
        score=Decimal("8.5"),
        level=Level.MALICIOUS,
        comment="Known phishing site",
    )

    url_check = cv.check_create(
        "url_analysis",
        "email_body",
        "Analyze URLs in email",
        score=Decimal("8.5"),
    )
    cv.check_link_observable(url_check.key, phishing_url.key)

    print(cv.get_global_score(), cv.get_global_level())
```

!!! tip "Context-first mindset"
    Pass incident metadata through `Cyvest(data={...})`. Every container, check, and export inherits it so you never lose analyst intent.

!!! note "Immutable views"
    `observable_create`, `check_create`, and the DSL handlers return read-only views (`ObservableView`, `CheckView`, …). Inspect their attributes freely, but use the Cyvest facade/DSL methods for any updates so the score engine runs automatically.

---

## 2. Use the fluent DSL for expressiveness {: #using-the-fluent-dsl }

```python
from decimal import Decimal
from cyvest import Cyvest, Level, ObservableType, RelationshipType

with Cyvest() as cv:
    url = (
        cv.observable(ObservableType.URL, "https://malicious.com", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=Level.MALICIOUS)
        .relate_to(cv.root(), RelationshipType.RELATED_TO)
    )

    (
        cv.check("url_check", "analysis", "Check suspicious URL")
        .link_observable(url.get())
        .with_score(Decimal("8.5"))
    )
```

**Why the DSL?**

- Deterministic keys let you merge multiple builders without collisions.
- Relationships infer default directions from STIX2 semantics.
- Handlers expose `.get()` so you can pivot back to immutable views when needed.

---

## 3. Capture relationships with intent

```python
from cyvest import ObservableType, RelationshipDirection, RelationshipType

with Cyvest() as cv:
    url = cv.observable_create(ObservableType.URL, "http://c2-server.com")
    ip = cv.observable_create(ObservableType.IPV4_ADDR, "192.0.2.100", internal=False)
    cv.observable_add_relationship(url, ip, RelationshipType.RESOLVES_TO)  # OUTBOUND

    domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "c2-server.com", internal=False)
        .relate_to(ip, RelationshipType.RESOLVES_TO)
    )

    host1 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.10", internal=True)
    host2 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.20", internal=True)
    cv.observable_add_relationship(host1, host2, RelationshipType.COMMUNICATES_WITH)  # BIDIRECTIONAL

    malware = cv.observable_create(ObservableType.FILE, "payload.exe", internal=False)
    cv.observable_add_relationship(malware.key, url.key, RelationshipType.DOWNLOADED)  # INBOUND

    cv.observable_add_relationship(
        url.key,
        ip.key,
        RelationshipType.RESOLVES_TO,
        RelationshipDirection.INBOUND,  # explicit override
    )
```

!!! info "Default directions"
    - `RESOLVES_TO`: domain → IP (`OUTBOUND`)
    - `DOWNLOADED`: file ← source (`INBOUND`)
    - `COMMUNICATES_WITH`: symmetric (`BIDIRECTIONAL`)

---

## 4. Organize workstreams with containers

```python
with Cyvest() as cv:
    with cv.container("network_analysis", "Network telemetry") as network:
        (
            cv.check("c2_detection", "network", "Detect C2 communication")
            .in_container(network)
        )

        # Nesting is encouraged for larger stories
        with network.sub_container("east_dc", "East datacenter") as east:
            (
                cv.check("ids_east", "network", "IDS signals from east DC")
                .in_container(east)
            )
```

Containers keep checks, sub-containers, and metrics scoped. They also enable reporting sections inside Markdown exports.

---

## 5. Export and share {: #exporting-results }

```python
from cyvest.io_serialization import (
    save_investigation_json,
    save_investigation_markdown,
)
from cyvest.io_rich import display_summary
from cyvest import Level
from rich.console import Console

with Cyvest() as cv:
    # ... build investigation ...

    console = Console()
    display_summary(cv, console)

    # Filter display to show only checks at INFO level or higher (excludes NONE)
    display_summary(cv, console, min_level=Level.INFO)

    # Show only high-severity checks (SUSPICIOUS and above)
    display_summary(cv, console, min_level=Level.SUSPICIOUS)

    save_investigation_json(cv, "investigation.json")
    save_investigation_markdown(cv, "report.md")
```

!!! tip "Filtering checks by severity"
    Use the `min_level` parameter to focus on actionable findings. Setting `min_level=Level.INFO` (default: `Level.NONE`) hides checks that haven't been scored, reducing noise in large investigations.

!!! question "Where do exports live?"
    The docs assume you write to the project root, but automation pipelines typically point to `dist/` (JSON) and `reports/` (Markdown/PDF). Adjust paths to match your workflow.

---

## Next Steps

- Deep dive into the [Core Concepts](concepts.md) for scoring and levels
- Explore concurrency via [Shared Investigation Context](../shared-investigation-context.md)
- Browse the `examples/` directory for end-to-end scenarios
