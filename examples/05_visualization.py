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

import logging
import tempfile
from pathlib import Path

import click
from logurich.opt_click import click_logger_params

from cyvest import Cyvest

logger = logging.getLogger(__name__)


@click.command()
@click_logger_params
@click.option(
    "--no-audit-log",
    "no_audit_log",
    is_flag=True,
    default=False,
    help="Exclude audit log from JSON output for deterministic output",
)
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def main(no_audit_log: bool = False, output: Path | None = None) -> None:
    # Create a comprehensive investigation with various observables
    cv = Cyvest(
        investigation_id="cyvest-visual-example",
        investigation_name="Visualization Example",
    )
    # Malicious infrastructure
    malicious_domain = (
        cv.observable(cv.OBS.DOMAIN, "evil-phishing.com")
        .with_ti("VirusTotal", score=9.0, comment="Known phishing domain")
        .with_ti("AlienVault OTX", score=8.5, comment="Recently reported")
    )

    malicious_ip = (
        cv.observable(cv.OBS.IPV4, "185.220.101.50")
        .with_ti("AbuseIPDB", score=9.5, comment="C2 server")
        .relate_to(malicious_domain, cv.REL.HOSTS)
    )

    # Suspicious infrastructure
    suspicious_domain = (
        cv.observable(cv.OBS.DOMAIN, "sketchy-site.net")
        .with_ti("VirusTotal", score=4.5, comment="Some detections")
        .relate_to(
            cv.observable(cv.OBS.IPV4, "192.168.100.5").with_ti("Shodan", score=3.0),
            cv.REL.RESOLVES_TO,
        )
    )

    # Email analysis
    attacker_email = (
        cv.observable(cv.OBS.EMAIL, "attacker@evil-phishing.com")
        .with_ti("EmailRep", score=8.0, comment="Suspicious sender")
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    victim_email = cv.observable(cv.OBS.EMAIL, "victim@company.com", internal=True).with_ti(
        "Internal Whitelist", score=-1.0, comment="Known employee"
    )

    # Email artifact with multiple relationships
    email_message = (
        cv.observable(cv.OBS.ARTIFACT, "Phishing Email - Invoice #12345")
        .relate_to(attacker_email, cv.REL.CONTAINS)
        .relate_to(victim_email, cv.REL.CONTAINS)
        .with_ti("Email Gateway", score=7.0, comment="Flagged as suspicious")
    )

    # Malicious URLs in email
    phishing_url1 = (
        cv.observable(cv.OBS.URL, "https://evil-phishing.com/login")
        .with_ti("URLhaus", score=9.0)
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    phishing_url2 = (
        cv.observable(cv.OBS.URL, "https://evil-phishing.com/verify")
        .with_ti("URLhaus", score=8.5)
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    # Email contains URLs
    email_message.relate_to(phishing_url1, cv.REL.CONTAINS)
    email_message.relate_to(phishing_url2, cv.REL.CONTAINS)

    suspicious_url = (
        cv.observable(cv.OBS.URL, "https://sketchy-site.net/invoice")
        .with_ti("URLhaus", score=4.5, comment="Low-confidence redirect")
        .relate_to(suspicious_domain, cv.REL.RELATED_TO)
    )
    trusted_url = cv.observable(
        cv.OBS.URL,
        "https://accounts.google.com/security",
        whitelisted=True,
    ).with_ti("Internal Whitelist", score=-2.0, comment="Known safe link")

    email_message.relate_to(suspicious_url, cv.REL.CONTAINS)
    email_message.relate_to(trusted_url, cv.REL.CONTAINS)

    # Malware file dropped
    malware_file = (
        cv.observable(cv.OBS.FILE, "invoice.exe")
        .with_ti("VirusTotal", score=10.0, comment="Detected by 45/70 engines")
        .relate_to(phishing_url1, cv.REL.DERIVED_FROM)
        .relate_to(malicious_ip, cv.REL.COMMUNICATES_WITH)
    )

    # Create findings linking observables
    _ = (
        cv.finding("email_analysis", "Phishing email analysis")
        .link_observable(email_message)
        .link_observable(attacker_email)
        .link_observable(victim_email)
        .with_score(8.0)
        .tagged("phishing:investigation:email")
    )

    _ = (
        cv.finding("url_analysis", "Malicious URLs found in email")
        .link_observable(phishing_url1)
        .link_observable(phishing_url2)
        .link_observable(suspicious_url)
        .with_score(9.0)
        .tagged("phishing:investigation:network")
    )

    _ = (
        cv.finding("infrastructure", "Malicious infrastructure identified")
        .link_observable(malicious_domain)
        .link_observable(malicious_ip)
        .with_score(9.5)
        .tagged("phishing:investigation:network")
    )

    _ = (
        cv.finding("malware_detection", "Malware file analysis")
        .link_observable(malware_file)
        .with_score(10.0)
        .tagged("phishing:investigation:malware")
    )

    # Finalize relationships
    cv.finalize_relationships()

    # Display text summary first
    logger.info("[bold green]Investigation Summary[/bold green]")
    cv.display_summary(show_graph=True)

    # Generate json
    logger.info("[bold cyan]Generating json...[/bold cyan]")
    output_path = output or (Path(tempfile.gettempdir()) / "cyvest_investigation.json")
    json_path = cv.io_save_json(output_path, include_audit_log=not no_audit_log)
    size_kb = Path(json_path).stat().st_size / 1024
    logger.info("[green]✓ Full json saved to: %s (%.2f KB)[/green]", json_path, size_kb)

    # Generate and open network visualization
    logger.info("[bold cyan]Generating Network Visualization...[/bold cyan]")
    html_path = cv.display_network(open_browser=False)
    logger.info(f"[green]✓ Full html visualization saved to: {html_path}[/green]")

    # Example: Export to markdown (with optional sections)
    logger.info("[bold cyan]Exporting to Markdown...[/bold cyan]")
    # Export with tags and enrichments included
    tmp_path = Path(tempfile.gettempdir()) / "investigation_report_full.md"
    markdown_full_path = cv.io_save_markdown(tmp_path, include_tags=True, include_enrichments=True)
    logger.info(f"[green]✓ Full markdown report saved to: {markdown_full_path}[/green]")


if __name__ == "__main__":
    main()
