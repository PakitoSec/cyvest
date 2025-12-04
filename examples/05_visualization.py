"""
Example: Network Visualization with Pyvis

This example demonstrates the network visualization feature that generates
an interactive HTML graph showing observables and their relationships.

The visualization uses the Rich color scheme:
- Nodes are colored by security level (red=malicious, yellow=suspicious, green=safe, etc.)
- Node sizes are based on scores (higher scores = larger nodes)
- Node shapes represent observable types (diamonds=domains, dots=IPs, boxes=URLs, etc.)
- Edges are colored by relationship direction (blue=outbound, pink=inbound, purple=bidirectional)
- Edge labels show the relationship type
"""

import tempfile
from pathlib import Path

from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipDirection, RelationshipType

logger.enable("cyvest")

# Create a comprehensive investigation with various observables
with Cyvest() as cv:
    # Malicious infrastructure
    malicious_domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "evil-phishing.com")
        .add_ti("VirusTotal", score=9.0, comment="Known phishing domain")
        .add_ti("AlienVault OTX", score=8.5, comment="Recently reported")
    )

    malicious_ip = (
        cv.observable(ObservableType.IPV4_ADDR, "185.220.101.50")
        .add_ti("AbuseIPDB", score=9.5, comment="C2 server")
        .relate_to(malicious_domain, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
    )

    # Suspicious infrastructure
    suspicious_domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "sketchy-site.net")
        .add_ti("VirusTotal", score=4.5, comment="Some detections")
        .relate_to(
            cv.observable(ObservableType.IPV4_ADDR, "192.168.100.5").add_ti("Shodan", score=3.0),
            RelationshipType.RELATED_TO,
            RelationshipDirection.OUTBOUND,
        )
    )

    # Email analysis
    attacker_email = (
        cv.observable(ObservableType.EMAIL_ADDR, "attacker@evil-phishing.com")
        .add_ti("EmailRep", score=8.0, comment="Suspicious sender")
        .relate_to(malicious_domain, RelationshipType.RELATED_TO)
    )

    victim_email = cv.observable(ObservableType.EMAIL_ADDR, "victim@company.com", internal=True).add_ti(
        "Internal Whitelist", score=-1.0, comment="Known employee"
    )

    # Email message with multiple relationships
    email_message = (
        cv.observable(ObservableType.EMAIL_MESSAGE, "Phishing Email - Invoice #12345")
        .relate_to(attacker_email, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
        .relate_to(victim_email, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
        .add_ti("Email Gateway", score=7.0, comment="Flagged as suspicious")
    )

    # Malicious URLs in email
    phishing_url1 = (
        cv.observable(ObservableType.URL, "https://evil-phishing.com/login")
        .add_ti("URLhaus", score=9.0)
        .relate_to(malicious_domain, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
    )

    phishing_url2 = (
        cv.observable(ObservableType.URL, "https://evil-phishing.com/verify")
        .add_ti("URLhaus", score=8.5)
        .relate_to(malicious_domain, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
    )

    # Email contains URLs
    email_message.relate_to(phishing_url1, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)
    email_message.relate_to(phishing_url2, RelationshipType.RELATED_TO, RelationshipDirection.OUTBOUND)

    # Malware file dropped
    malware_file = (
        cv.observable(ObservableType.FILE, "invoice.exe")
        .add_ti("VirusTotal", score=10.0, comment="Detected by 45/70 engines")
        .relate_to(phishing_url1, RelationshipType.RELATED_TO, RelationshipDirection.INBOUND)
        .relate_to(malicious_ip, RelationshipType.RELATED_TO, RelationshipDirection.BIDIRECTIONAL)
    )

    # Safe/whitelisted observables for contrast
    safe_domain = cv.observable(ObservableType.DOMAIN_NAME, "google.com", whitelisted=True).add_ti(
        "Internal Whitelist", score=-2.0, comment="Known good domain"
    )

    # Notable but not malicious
    notable_domain = cv.observable(ObservableType.DOMAIN_NAME, "new-service.cloud").add_ti(
        "Passive DNS", score=2.0, comment="Recently registered domain"
    )

    # Create checks linking observables
    email_check = (
        cv.check("email_analysis", "email", "Phishing email analysis")
        .link_observable(email_message)
        .link_observable(attacker_email)
        .link_observable(victim_email)
        .with_score(8.0)
        .in_container(cv.container("phishing_investigation/email"))
    )

    url_check = (
        cv.check("url_analysis", "network", "Malicious URLs found in email")
        .link_observable(phishing_url1)
        .link_observable(phishing_url2)
        .with_score(9.0)
        .in_container(cv.container("phishing_investigation/network"))
    )

    infrastructure_check = (
        cv.check("infrastructure", "network", "Malicious infrastructure identified")
        .link_observable(malicious_domain)
        .link_observable(malicious_ip)
        .with_score(9.5)
        .in_container(cv.container("phishing_investigation/network"))
    )

    malware_check = (
        cv.check("malware_detection", "file", "Malware file analysis")
        .link_observable(malware_file)
        .with_score(10.0)
        .in_container(cv.container("phishing_investigation/malware"))
    )

    # Finalize relationships
    cv.finalize_relationships()

    # Display text summary first
    logger.info("[bold green]Investigation Summary[/bold green]")
    cv.display_summary(show_graph=True)

    # Generate json
    logger.info("[bold cyan]Generating json...[/bold cyan]")
    tmp_path = Path(tempfile.gettempdir()) / "cyvest_investigation.json"
    json_path = cv.io_save_json(tmp_path)
    logger.info(f"[green]✓ Full json saved to: {tmp_path}[/green]")

    # Generate and open network visualization
    logger.info("[bold cyan]Generating Network Visualization...[/bold cyan]")
    html_path = cv.display_network(open_browser=False)
    logger.info(f"[green]✓ Full html visualization saved to: {html_path}[/green]")

    # Example: Export to markdown (with optional sections)
    logger.info("[bold cyan]Exporting to Markdown...[/bold cyan]")
    # Export with containers and enrichments included
    markdown_full_path = cv.io_save_markdown(
        "investigation_report_full.md", include_containers=True, include_enrichments=True
    )
    logger.info(f"[green]✓ Full markdown report saved to: {markdown_full_path}[/green]")
