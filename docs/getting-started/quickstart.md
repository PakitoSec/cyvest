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

!!! note "Immutable proxies"
    `observable_create`, `check_create`, and the fluent helpers return read-only proxies (`ObservableProxy`, `CheckProxy`, …). Inspect their attributes freely, but use the Cyvest facade or the proxy helper methods for any updates so the score engine runs automatically.

---

## 2. Use the fluent API for expressiveness {: #using-the-fluent-api }

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
        .link_observable(url)
        .with_score(Decimal("8.5"))
    )
```

**Why the fluent helpers?**

- Deterministic keys let you merge multiple builders without collisions.
- Relationships default to bidirectional; override direction when you need hierarchy.

---

## 3. Capture relationships with intent

```python
from cyvest import ObservableType, RelationshipDirection, RelationshipType

with Cyvest() as cv:
    url = cv.observable_create(ObservableType.URL, "http://c2-server.com")
    ip = cv.observable_create(ObservableType.IPV4_ADDR, "192.0.2.100", internal=False)
    cv.observable_add_relationship(url, ip, RelationshipType.RELATED_TO)  # BIDIRECTIONAL

    domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "c2-server.com", internal=False)
        .relate_to(ip, RelationshipType.RELATED_TO)
    )

    host1 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.10", internal=True)
    host2 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.20", internal=True)
    cv.observable_add_relationship(host1, host2, RelationshipType.RELATED_TO)  # BIDIRECTIONAL

    malware = cv.observable_create(ObservableType.FILE, "payload.exe", internal=False)
    cv.observable_add_relationship(malware.key, url.key, RelationshipType.RELATED_TO)  # BIDIRECTIONAL

    cv.observable_add_relationship(
        url.key,
        ip.key,
        RelationshipType.RELATED_TO,
        RelationshipDirection.INBOUND,  # explicit override
    )
```

!!! info "Default directions"
    - Default is `BIDIRECTIONAL` when no direction is provided.
    - Use `OUTBOUND`/`INBOUND` to force hierarchy for score propagation.

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

    # Hide unscored and INFO-level checks
    display_summary(cv, console, exclude_levels=[Level.NONE, Level.INFO])

    # Show only high-severity checks (SUSPICIOUS and above)
    display_summary(
        cv,
        console,
        exclude_levels=[Level.NONE, Level.TRUSTED, Level.INFO, Level.SAFE, Level.NOTABLE],
    )

    save_investigation_json(cv, "investigation.json")
    save_investigation_markdown(cv, "report.md")
```

!!! tip "Filtering checks by severity"
    Use `exclude_levels` to hide noise tiers. By default, `Level.NONE` is excluded to skip
    unscored checks; add `Level.INFO` or `Level.NOTABLE` to focus on actionable findings in
    larger investigations. Pass an empty list (`exclude_levels=[]`) to show every check,
    including unscored ones.

!!! question "Where do exports live?"
    The docs assume you write to the project root, but automation pipelines typically point to `dist/` (JSON) and `reports/` (Markdown/PDF). Adjust paths to match your workflow.

---

## Next Steps

- Deep dive into the [Core Concepts](concepts.md) for scoring and levels
- Explore concurrency via [Shared Investigation Context](../shared-investigation-context.md)
- Browse the `examples/` directory for end-to-end scenarios
