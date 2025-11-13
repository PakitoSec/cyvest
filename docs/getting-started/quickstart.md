# Quick Start

This guide will help you create your first cybersecurity investigation with Cyvest.

## Basic Investigation

Let's analyze a suspicious email with a phishing URL:

```python
from decimal import Decimal
from cyvest import Cyvest, Level, ObservableType

# Create an investigation
with Cyvest(data={"type": "email_analysis"}) as cv:
    # Create a URL observable using STIX2 type
    phishing_url = cv.observable_create(
        ObservableType.URL,
        "https://fake-bank-login.com",
        internal=False
    )

    # Add threat intelligence
    cv.observable_add_threat_intel(
        phishing_url.key,
        source="virustotal",
        score=Decimal("8.5"),
        level=Level.MALICIOUS,
        comment="Known phishing site"
    )

    # Create a check
    url_check = cv.check_create(
        "url_analysis",
        "email_body",
        "Analyze URLs in email",
        score=Decimal("8.5")
    )

    # Link observable to check
    cv.check_link_observable(url_check.key, phishing_url.key)

    # View results
    print(f"Global Score: {cv.get_global_score()}")
    print(f"Global Level: {cv.get_global_level()}")
```

## Using the Fluent DSL

Cyvest provides a fluent API for more concise code:

```python
from decimal import Decimal
from cyvest import Cyvest, Level, ObservableType, RelationshipType

with Cyvest() as cv:
    # Create and configure observable in one chain
    url = (
        cv.observable(ObservableType.URL, "https://malicious.com", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=Level.MALICIOUS)
        .relate_to(cv.root(), RelationshipType.RELATED_TO)
    )

    # Create check and link observable
    check = (
        cv.check("url_check", "analysis", "Check suspicious URL")
        .link_observable(url.get())
        .with_score(Decimal("8.5"))
    )
```

## Working with Relationships

Track relationships between observables with automatic semantic defaults:

```python
from cyvest import ObservableType, RelationshipType

with Cyvest() as cv:
    # Create URL and IP with STIX2 types
    url = cv.observable_create(ObservableType.URL, "http://c2-server.com")
    ip = cv.observable_create(ObservableType.IPV4_ADDR, "192.0.2.100", internal=False)

    # Automatically gets OUTBOUND direction (domain → IP)
    cv.observable_add_relationship(url.key, ip.key, RelationshipType.RESOLVES_TO)

    # Using fluent API (also uses semantic defaults)
    domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "c2-server.com", internal=False)
        .relate_to(ip, RelationshipType.RESOLVES_TO)  # auto: OUTBOUND
    )

    # Automatically gets BIDIRECTIONAL for mutual communication
    host1 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.10", internal=True)
    host2 = cv.observable_create(ObservableType.IPV4_ADDR, "10.0.1.20", internal=True)
    cv.observable_add_relationship(
        host1.key,
        host2.key,
        RelationshipType.COMMUNICATES_WITH  # auto: BIDIRECTIONAL ↔
    )

    # Automatically gets INBOUND (file ← source)
    malware = cv.observable_create(ObservableType.FILE, "payload.exe", internal=False)
    cv.observable_add_relationship(
        malware.key,
        url.key,
        RelationshipType.DOWNLOADED  # auto: INBOUND ←
    )

    # Can still override defaults if needed
    from cyvest import RelationshipDirection
    cv.observable_add_relationship(
        url.key, ip.key,
        RelationshipType.RESOLVES_TO,
        RelationshipDirection.INBOUND  # explicit override
    )
```
```

## Organizing with Containers

Structure your investigation with containers:

```python
with Cyvest() as cv:
    # Create container
    with cv.container("network_analysis") as network:
        # Create checks in container
        check = (
            cv.check("c2_detection", "network", "Detect C2 communication")
            .in_container(network)
        )
```

## Exporting Results

Save your investigation:

```python
from cyvest.io_serialization import (
    save_investigation_json,
    save_investigation_markdown
)
from cyvest.io_rich import display_summary
from rich.console import Console

with Cyvest() as cv:
    # ... build investigation ...

    # Display in terminal
    console = Console()
    display_summary(cv, console)

    # Save to files
    save_investigation_json(cv, "investigation.json")
    save_investigation_markdown(cv, "report.md")
```

## Next Steps

- Learn about [Core Concepts](concepts.md)
- Explore the [User Guide](../guide/observables.md)
- Check out [Examples](../examples/email.md)
- Read the [API Reference](../api/cyvest.md)
