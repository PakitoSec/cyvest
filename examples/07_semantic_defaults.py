"""
Example demonstrating semantic default directions for relationships.

This example shows how relationship types automatically get appropriate
directions based on their semantic meaning, eliminating verbose code.
"""

import tempfile
from pathlib import Path

from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipType
from cyvest.io_serialization import save_investigation_json, save_investigation_markdown

logger.enable("cyvest")

# Create investigation
with Cyvest() as inv:
    logger.info("[bold cyan]Semantic Default Directions Example[/bold cyan]")

    # Network: RESOLVES_TO → automatically OUTBOUND (domain → IP)
    domain = inv.observable(ObservableType.DOMAIN_NAME, "malware-c2.com", internal=False).get()
    ip = inv.observable(ObservableType.IPV4_ADDR, "198.51.100.10", internal=False).get()
    inv.observable_add_relationship(domain.key, ip.key, RelationshipType.RESOLVES_TO)
    # No direction specified! Automatically gets OUTBOUND
    logger.info(f"✓ RESOLVES_TO: [green]{domain.relationships[0].direction.value}[/green] (domain → IP)")

    # File: DOWNLOADED → automatically INBOUND (file ← URL)
    malware = inv.observable(ObservableType.FILE, "trojan.exe", internal=False).get()
    download_url = inv.observable(ObservableType.URL, "http://malware-c2.com/payload", internal=False).get()
    inv.observable_add_relationship(malware.key, download_url.key, RelationshipType.DOWNLOADED)
    # No direction specified! Automatically gets INBOUND
    logger.info(f"✓ DOWNLOADED: [red]{malware.relationships[0].direction.value}[/red] (file ← URL)")

    # Network: COMMUNICATES_WITH → automatically BIDIRECTIONAL (host ↔ host)
    host1 = inv.observable(ObservableType.IPV4_ADDR, "10.0.1.10", internal=True).get()
    host2 = inv.observable(ObservableType.IPV4_ADDR, "10.0.1.20", internal=True).get()
    inv.observable_add_relationship(host1.key, host2.key, RelationshipType.COMMUNICATES_WITH)
    # No direction specified! Automatically gets BIDIRECTIONAL
    logger.info(f"✓ COMMUNICATES_WITH: [yellow]{host1.relationships[0].direction.value}[/yellow] (host ↔ host)")

    # Email: FROM → automatically INBOUND (email ← sender)
    email = inv.observable(ObservableType.EMAIL_MESSAGE, "phishing@evil.com", internal=False).get()
    sender = inv.observable(ObservableType.EMAIL_ADDR, "attacker@evil.com", internal=False).get()
    inv.observable_add_relationship(email.key, sender.key, RelationshipType.FROM)
    # No direction specified! Automatically gets INBOUND
    logger.info(f"✓ FROM: [red]{email.relationships[0].direction.value}[/red] (email ← sender)")

    # Email: TO → automatically OUTBOUND (email → recipient)
    recipient = inv.observable(ObservableType.EMAIL_ADDR, "victim@company.com", internal=True).get()
    inv.observable_add_relationship(email.key, recipient.key, RelationshipType.TO)
    # No direction specified! Automatically gets OUTBOUND
    logger.info(f"✓ TO: [green]{email.relationships[1].direction.value}[/green] (email → recipient)")

    # Process: CREATED → automatically OUTBOUND (creator → created)
    process = inv.observable(ObservableType.PROCESS, "malicious.exe", internal=False).get()
    dropped_file = inv.observable(ObservableType.FILE, "ransomware.dll", internal=False).get()
    inv.observable_add_relationship(process.key, dropped_file.key, RelationshipType.CREATED)
    # No direction specified! Automatically gets OUTBOUND
    logger.info(f"✓ CREATED: [green]{process.relationships[0].direction.value}[/green] (process → file)")

    # Process: CHILD → automatically INBOUND (child ← parent)
    child_process = inv.observable(ObservableType.PROCESS, "child.exe", internal=False).get()
    parent_process = inv.observable(ObservableType.PROCESS, "parent.exe", internal=False).get()
    inv.observable_add_relationship(child_process.key, parent_process.key, RelationshipType.CHILD)
    # No direction specified! Automatically gets INBOUND
    logger.info(f"✓ CHILD: [red]{child_process.relationships[0].direction.value}[/red] (child ← parent)")

    # General: RELATED_TO → automatically BIDIRECTIONAL (symmetric)
    artifact1 = inv.observable(ObservableType.ARTIFACT, "evidence1.pcap", internal=True).get()
    artifact2 = inv.observable(ObservableType.ARTIFACT, "evidence2.log", internal=True).get()
    inv.observable_add_relationship(artifact1.key, artifact2.key, RelationshipType.RELATED_TO)
    # No direction specified! Automatically gets BIDIRECTIONAL
    logger.info(f"✓ RELATED_TO: [yellow]{artifact1.relationships[0].direction.value}[/yellow] (artifact ↔ artifact)")

    # File: DROPPED → automatically INBOUND (file ← dropper)
    dropped = inv.observable(ObservableType.FILE, "payload.bin", internal=False).get()
    dropper = inv.observable(ObservableType.FILE, "dropper.exe", internal=False).get()
    inv.observable_add_relationship(dropped.key, dropper.key, RelationshipType.DROPPED)
    # No direction specified! Automatically gets INBOUND
    logger.info(f"✓ DROPPED: [red]{dropped.relationships[0].direction.value}[/red] (file ← dropper)")

    logger.info("[bold]Summary:[/bold]")
    logger.info("• [green]OUTBOUND (→)[/green]: RESOLVES_TO, TO, CREATED, CONTAINS, BELONGS_TO")
    logger.info("• [red]INBOUND (←)[/red]: DOWNLOADED, DROPPED, FROM, SENDER, CHILD, DERIVED_FROM")
    logger.info("• [yellow]BIDIRECTIONAL (↔)[/yellow]: COMMUNICATES_WITH, RELATED_TO, DUPLICATE_OF")
    logger.info("[dim]All directions were automatically determined - no explicit direction parameters![/dim]")

    # Save investigation
    output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_07_"))
    json_path = output_dir / "semantic_defaults_demo.json"
    md_path = output_dir / "semantic_defaults_demo.md"
    save_investigation_json(inv, str(json_path))
    save_investigation_markdown(inv, str(md_path))

    logger.info(f"✓ Investigation saved to {json_path} and {md_path}")
    logger.info("Temporary output directory: {}", output_dir)
