"""
Example demonstrating relationship direction feature and score propagation.

This example shows how to use the new direction parameter for relationships:
- OUTBOUND: Source → Target (child relationship, scores propagate up)
- INBOUND: Source ← Target (parent relationship, scores propagate up)
- BIDIRECTIONAL: Source ↔ Target (no hierarchical propagation)

It also demonstrates how relationship directions affect score propagation
in the hierarchical scoring model.
"""

import tempfile
from decimal import Decimal
from pathlib import Path

from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipDirection, RelationshipType
from cyvest.io_serialization import save_investigation_json, save_investigation_markdown

logger.enable("cyvest")


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
    inv.observable_add_relationship(domain.key, ip.key, RelationshipType.RESOLVES_TO, RelationshipDirection.OUTBOUND)

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
        host1.key, host2.key, RelationshipType.COMMUNICATES_WITH, RelationshipDirection.BIDIRECTIONAL
    )

    # Create malware file
    malware = (
        inv.observable(ObservableType.FILE, "malware.exe", internal=False)
        .with_ti("virustotal", score=Decimal("9.5"), comment="Ransomware detected")
        .get()
    )

    # Inbound relationship: malware was downloaded FROM the C2 domain
    inv.observable_add_relationship(malware.key, domain.key, RelationshipType.DOWNLOADED, RelationshipDirection.INBOUND)

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
    logger.info("[bold cyan]Relationship Direction Example[/bold cyan]")

    # Display the summary with graph
    inv.display_summary()

    # Show specific relationship details
    logger.info("[bold]Relationship Details:[/bold]")
    logger.info(f"• Domain → IP: [green]{RelationshipDirection.OUTBOUND.value}[/green] (DNS resolution)")
    logger.info(f"• Host1 ↔ Host2: [yellow]{RelationshipDirection.BIDIRECTIONAL.value}[/yellow] (Mutual communication)")
    logger.info(f"• Malware ← Domain: [red]{RelationshipDirection.INBOUND.value}[/red] (Downloaded from)")

    # Show score propagation based on directions
    logger.info("[bold]Score Propagation Analysis:[/bold]")

    logger.info("[bold green]OUTBOUND Example (Domain → IP):[/bold green]")
    logger.info("  • Domain TI score: 7.5")
    logger.info("  • IP TI score: 8.0")
    logger.info("  • Domain has OUTBOUND to IP (IP is child)")
    logger.info(f"  • Domain score = max(7.5, 8.0) = [bold]{domain.score}[/bold] ✓")
    logger.info("  • Score flows UP from child (IP) to parent (Domain)")

    logger.info("[bold red]INBOUND Example (Malware ← Domain):[/bold red]")
    logger.info("  • Malware TI score: 9.5")
    logger.info("  • Domain (original) TI score: 7.5")
    logger.info("  • Malware has INBOUND to Domain (Domain is parent)")
    logger.info(f"  • Domain score includes malware = max(7.5, 9.5, 8.0) = [bold]{domain.score}[/bold] ✓")
    logger.info("  • Score flows UP from source (Malware) to target (Domain)")

    logger.info("[bold yellow]BIDIRECTIONAL Example (Host1 ↔ Host2):[/bold yellow]")
    logger.info("  • Host1 TI score: 0")
    logger.info("  • Host2 TI score: 0")
    logger.info("  • BIDIRECTIONAL relationship (no hierarchy)")
    logger.info(f"  • Host1 score = {host1.score} (no propagation) ✓")
    logger.info(f"  • Host2 score = {host2.score} (no propagation) ✓")
    logger.info("  • Scores do NOT propagate hierarchically")

    logger.info("[bold magenta]Complex Chain (URL → Domain, URL → Malware):[/bold magenta]")
    logger.info("  • URL has OUTBOUND to Domain and Malware (both are children)")
    logger.info("  • URL TI score: 8.5")
    logger.info(f"  • URL score = max(8.5, domain=9.5, malware=9.5) = [bold]{url.score}[/bold] ✓")
    logger.info("  • Multi-level propagation: IP → Domain → URL")

    logger.info("[bold]Key Takeaways:[/bold]")
    logger.info("  1. OUTBOUND (→): Target is child, scores propagate to source")
    logger.info("  2. INBOUND (←): Target is parent, scores propagate to target")
    logger.info("  3. BIDIRECTIONAL (↔): No hierarchical propagation")
    logger.info("  4. Scores cascade through multiple levels automatically")

    # Save investigation
    output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_06_"))
    json_path = output_dir / "relationship_direction_demo.json"
    md_path = output_dir / "relationship_direction_demo.md"
    save_investigation_json(inv, str(json_path))
    save_investigation_markdown(inv, str(md_path))

    logger.info(f"✓ Investigation saved to {json_path} and {md_path}")
    logger.info("Temporary output directory: {}", output_dir)
