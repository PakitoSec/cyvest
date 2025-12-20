# Quick Start

Model a complete investigation, link observables, and produce a shareable report in minutes.

---

## 1. Create your first investigation

```python
from decimal import Decimal
from cyvest import Cyvest

with Cyvest(data={"type": "email_analysis"}) as cv:
    phishing_url = cv.observable_create(
        cv.OBS.URL,
        "https://fake-bank-login.com",
        internal=False,
    )

    cv.observable_add_threat_intel(
        phishing_url.key,
        source="virustotal",
        score=Decimal("8.5"),
        level=cv.LVL.MALICIOUS,
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
from cyvest import Cyvest

with Cyvest() as cv:
    url = (
        cv.observable(cv.OBS.URL, "https://malicious.com", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=cv.LVL.MALICIOUS)
        .relate_to(cv.root(), cv.REL.RELATED_TO)
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
from cyvest import Cyvest

with Cyvest() as cv:
    url = cv.observable_create(cv.OBS.URL, "http://c2-server.com")
    ip = cv.observable_create(cv.OBS.IPV4_ADDR, "192.0.2.100", internal=False)
    cv.observable_add_relationship(url, ip, cv.REL.RELATED_TO)  # BIDIRECTIONAL

    domain = (
        cv.observable(cv.OBS.DOMAIN_NAME, "c2-server.com", internal=False)
        .relate_to(ip, cv.REL.RELATED_TO)
    )

    host1 = cv.observable_create(cv.OBS.IPV4_ADDR, "10.0.1.10", internal=True)
    host2 = cv.observable_create(cv.OBS.IPV4_ADDR, "10.0.1.20", internal=True)
    cv.observable_add_relationship(host1, host2, cv.REL.RELATED_TO)  # BIDIRECTIONAL

    malware = cv.observable_create(cv.OBS.FILE, "payload.exe", internal=False)
    cv.observable_add_relationship(malware.key, url.key, cv.REL.RELATED_TO)  # BIDIRECTIONAL

    cv.observable_add_relationship(
        url.key,
        ip.key,
        cv.REL.RELATED_TO,
        cv.DIR.INBOUND,  # explicit override
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
from cyvest.io_rich import display_summary
from cyvest import Cyvest
from rich.console import Console

with Cyvest() as cv:
    # ... build investigation ...

    console = Console()
    display_summary(cv, console)

    # Hide unscored and INFO-level checks
    display_summary(cv, console, exclude_levels=[cv.LVL.NONE, cv.LVL.INFO])

    # Show only high-severity checks (SUSPICIOUS and above)
    display_summary(
        cv,
        console,
        exclude_levels=[cv.LVL.NONE, cv.LVL.TRUSTED, cv.LVL.INFO, cv.LVL.SAFE, cv.LVL.NOTABLE],
    )

    cv.io_save_json("investigation.json")
    cv.io_save_markdown("report.md")
    # Hide observables while keeping aggregate stats/whitelists
    cv.io_save_markdown("redacted_report.md", include_observables=False)
```

!!! tip "Filtering checks by severity"
    Use `exclude_levels` to hide noise tiers. By default, `Cyvest.LVL.NONE` is excluded to skip
    unscored checks; add `Cyvest.LVL.INFO` or `Cyvest.LVL.NOTABLE` to focus on actionable findings in
    larger investigations. Pass an empty list (`exclude_levels=[]`) to show every check,
    including unscored ones.

!!! question "Where do exports live?"
    The docs assume you write to the project root, but automation pipelines typically point to `dist/` (JSON) and `reports/` (Markdown/PDF). Adjust paths to match your workflow.

!!! note "Provenance fields in JSON"
    Exports include `investigation_id`, optional `investigation_name`, and the investigation-level `event_log`, plus check origins (`origin_investigation_id`) and link fields (`observable_links`, `check_links`) needed for scoring after merges.

---

## Next Steps

- Deep dive into the [Core Concepts](concepts.md) for scoring and levels
- Explore concurrency via [Shared Investigation Context](../shared-investigation-context.md)
- Browse the `examples/` directory for end-to-end scenarios
