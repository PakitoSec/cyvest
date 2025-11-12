"""
Example demonstrating relationship direction feature.

This example shows how to use the new direction parameter for relationships:
- OUTBOUND: Source → Target (default)
- INBOUND: Source ← Target  
- BIDIRECTIONAL: Source ↔ Target
"""

from decimal import Decimal

from rich.console import Console

from cyvest import Cyvest, ObservableType, RelationshipDirection, RelationshipType
from cyvest.io_rich import display_summary
from cyvest.io_serialization import save_investigation_json, save_investigation_markdown

# Create investigation
with Cyvest() as inv:
    # Create network observables
    domain = (
        inv.observable(ObservableType.DOMAIN_NAME, "c2-server.example.com", internal=False)
        .with_ti("virustotal", score=Decimal("7.5"), comment="Known C2 domain")
        .get()
    )
    
    ip = (
        inv.observable(ObservableType.IPV4_ADDR, "203.0.113.42", internal=False)
        .with_ti("abuseipdb", score=Decimal("8.0"), comment="Malicious IP")
        .get()
    )
    
    # Outbound relationship: domain resolves TO ip (default)
    inv.observable_add_relationship(
        domain.key, 
        ip.key, 
        RelationshipType.RESOLVES_TO,
        RelationshipDirection.OUTBOUND
    )
    
    # Create hosts that communicate
    host1 = (
        inv.observable(ObservableType.IPV4_ADDR, "10.0.1.50", internal=True)
        .with_ti("edr", score=Decimal("0"), comment="Internal workstation")
        .get()
    )
    
    host2 = (
        inv.observable(ObservableType.IPV4_ADDR, "10.0.1.51", internal=True)
        .with_ti("edr", score=Decimal("0"), comment="Internal server")
        .get()
    )
    
    # Bidirectional relationship: hosts communicate with each other
    inv.observable_add_relationship(
        host1.key,
        host2.key,
        RelationshipType.COMMUNICATES_WITH,
        RelationshipDirection.BIDIRECTIONAL
    )
    
    # Create malware file
    malware = (
        inv.observable(ObservableType.FILE, "malware.exe", internal=False)
        .with_ti("virustotal", score=Decimal("9.5"), comment="Ransomware detected")
        .get()
    )
    
    # Inbound relationship: malware was downloaded FROM the C2 domain
    inv.observable_add_relationship(
        malware.key,
        domain.key,
        RelationshipType.DOWNLOADED,
        RelationshipDirection.INBOUND
    )
    
    # Using the fluent DSL with direction
    url = (
        inv.observable(ObservableType.URL, "http://c2-server.example.com/payload", internal=False)
        .with_ti("urlscan", score=Decimal("8.5"), comment="Malicious payload URL")
        .relate_to(domain, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
        .relate_to(malware, RelationshipType.CONTAINS, RelationshipDirection.OUTBOUND)
        .get()
    )
    
    # Create a check
    check = inv.check_create(
        check_id="network_indicators",
        scope="network_analysis",
        description="Network-based indicators of compromise",
        score=Decimal("8.0"),
    )
    inv.check_link_observable(check.key, domain.key)
    inv.check_link_observable(check.key, ip.key)
    inv.check_link_observable(check.key, malware.key)
    
    # Display investigation summary
    console = Console()
    console.print("\n[bold cyan]Relationship Direction Example[/bold cyan]\n")
    
    # Display the summary with graph
    display_summary(inv, console, show_graph=True)
    
    # Show specific relationship details
    console.print("\n[bold]Relationship Details:[/bold]")
    console.print(
        f"• Domain → IP: [green]{RelationshipDirection.OUTBOUND.value}[/green] (DNS resolution)"
    )
    console.print(
        f"• Host1 ↔ Host2: [yellow]{RelationshipDirection.BIDIRECTIONAL.value}[/yellow] "
        "(Mutual communication)"
    )
    console.print(
        f"• Malware ← Domain: [red]{RelationshipDirection.INBOUND.value}[/red] (Downloaded from)"
    )
    
    # Save investigation
    save_investigation_json(inv, "relationship_direction_demo.json")
    save_investigation_markdown(inv, "relationship_direction_demo.md")
    
    console.print("\n✓ Investigation saved to relationship_direction_demo.json and .md")
