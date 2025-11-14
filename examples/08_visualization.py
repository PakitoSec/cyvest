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

from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipType

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
        .relate_to(malicious_domain, RelationshipType.RESOLVES_TO)
    )

    # Suspicious infrastructure
    suspicious_domain = (
        cv.observable(ObservableType.DOMAIN_NAME, "sketchy-site.net")
        .add_ti("VirusTotal", score=4.5, comment="Some detections")
        .relate_to(
            cv.observable(ObservableType.IPV4_ADDR, "192.168.100.5").add_ti("Shodan", score=3.0),
            RelationshipType.RESOLVES_TO,
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
        .relate_to(attacker_email, RelationshipType.FROM)
        .relate_to(victim_email, RelationshipType.TO)
        .add_ti("Email Gateway", score=7.0, comment="Flagged as suspicious")
    )

    # Malicious URLs in email
    phishing_url1 = (
        cv.observable(ObservableType.URL, "https://evil-phishing.com/login")
        .add_ti("URLhaus", score=9.0)
        .relate_to(malicious_domain, RelationshipType.RESOLVES_TO)
    )

    phishing_url2 = (
        cv.observable(ObservableType.URL, "https://evil-phishing.com/verify")
        .add_ti("URLhaus", score=8.5)
        .relate_to(malicious_domain, RelationshipType.RESOLVES_TO)
    )

    # Email contains URLs
    email_message.relate_to(phishing_url1, RelationshipType.CONTAINS)
    email_message.relate_to(phishing_url2, RelationshipType.CONTAINS)

    # Malware file dropped
    malware_file = (
        cv.observable(ObservableType.FILE, "invoice.exe")
        .add_ti("VirusTotal", score=10.0, comment="Detected by 45/70 engines")
        .relate_to(phishing_url1, RelationshipType.DOWNLOADED)
        .relate_to(malicious_ip, RelationshipType.COMMUNICATES_WITH)
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

    # Generate and open network visualization
    logger.info("[bold cyan]Generating Network Visualization...[/bold cyan]")
    html_path = cv.display_network(
        open_browser=True,  # Automatically open in browser
    )

    logger.info(f"[green]✓ Network visualization saved to: {html_path}[/green]")
    logger.info("[cyan]The visualization should open in your browser automatically.[/cyan]")
    logger.info("[cyan]You can navigate the graph by dragging nodes and zooming in/out.[/cyan]")
    logger.info("")
    logger.info("[bold]Color Legend:[/bold]")
    logger.info("  🔴 Red = Malicious")
    logger.info("  🟠 Orange = Suspicious")
    logger.info("  🟡 Yellow = Notable")
    logger.info("  🟢 Green = Safe/Trusted")
    logger.info("  🔵 Cyan = Info")
    logger.info("")
    logger.info("[bold]Edge Colors:[/bold]")
    logger.info("  Blue = Outbound relationship")
    logger.info("  Pink = Inbound relationship")
    logger.info("  Purple = Bidirectional relationship")

    # Example: Generate filtered visualization (only malicious/suspicious)
    logger.info("[bold cyan]Generating Filtered View (SUSPICIOUS and above)...[/bold cyan]")
    from cyvest.levels import Level

    filtered_path = cv.display_network(
        min_level=Level.SUSPICIOUS,
        open_browser=True,  # Don't auto-open this one
    )

    logger.info(f"[green]✓ Filtered visualization saved to: {filtered_path}[/green]")
    logger.info("[dim]This filtered view only shows SUSPICIOUS and MALICIOUS observables.[/dim]")

    # Example: Generate grouped visualization (observables grouped by type)
    logger.info("[bold cyan]Generating Grouped View (by observable type)...[/bold cyan]")

    grouped_path = cv.display_network(
        group_by_type=False,  # Enable type-based grouping with hierarchical layout
        open_browser=True,  # Don't auto-open this one
    )

    logger.info(f"[green]✓ Grouped visualization saved to: {grouped_path}[/green]")
    logger.info("[dim]This view groups observables by type using a hierarchical layout.[/dim]")
