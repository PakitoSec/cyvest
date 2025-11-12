"""
Example demonstrating STIX2 Observable and Relationship types.

This example shows how to use the STIX2-compliant enums for observable types
and relationship types.
"""

from decimal import Decimal

from rich.console import Console

from cyvest import Cyvest, ObservableType, RelationshipType
from cyvest.io_rich import display_summary

# Create investigation
with Cyvest() as inv:
    # Create observables using STIX2 types with DSL
    domain = (
        inv.observable(ObservableType.DOMAIN_NAME, "malicious.example.com", internal=False)
        .with_ti("virustotal", score=Decimal("6.5"), comment="Suspicious domain")
        .get()
    )
    
    ip = (
        inv.observable(ObservableType.IPV4_ADDR, "192.0.2.1", internal=False)
        .with_ti("abuseipdb", score=Decimal("7.0"), comment="Known malicious IP")
        .get()
    )
    
    url = (
        inv.observable(ObservableType.URL, "https://malicious.example.com/payload", internal=False)
        .with_ti("urlscan", score=Decimal("8.0"), comment="Malicious payload detected")
        .relate_to(inv.root(), RelationshipType.RELATED_TO)
        .get()
    )
    
    file_hash = (
        inv.observable(ObservableType.FILE, "abc123...", internal=False)
        .with_ti("virustotal", score=Decimal("9.0"), comment="Known malware")
        .get()
    )
    
    email = (
        inv.observable(ObservableType.EMAIL_ADDR, "attacker@example.com", internal=False)
        .get()
    )

    # Add relationships using STIX2 relationship types
    # Use the low-level API for relationships
    inv.observable_add_relationship(domain.key, ip.key, RelationshipType.RESOLVES_TO)
    inv.observable_add_relationship(url.key, domain.key, RelationshipType.RELATED_TO)
    inv.observable_add_relationship(url.key, file_hash.key, RelationshipType.DOWNLOADED)
    inv.observable_add_relationship(email.key, url.key, RelationshipType.RELATED_TO)

    # You can also use strings (for backward compatibility or custom types)
    custom_obs = inv.observable("custom-type", "some-value", internal=False).get()
    inv.observable_add_relationship(custom_obs.key, domain.key, "custom-relationship")

    # Create a check and link observables
    check = inv.check_create(
        check_id="network_ioc",
        scope="network_analysis",
        description="Network indicators of compromise",
        score=Decimal("5.0"),
    )
    inv.check_link_observable(check.key, domain.key)
    inv.check_link_observable(check.key, ip.key)
    inv.check_link_observable(check.key, url.key)

    # Display investigation summary
    console = Console()
    display_summary(inv, console, show_graph=True)
    
