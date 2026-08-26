"""
Example: Graph dataset for the @cyvest/cyvest-vis renderer

Builds a rich investigation covering scores, levels, and relationship flows, then
exports it as JSON. Feed the resulting file to the `@cyvest/cyvest-vis` React
component to explore the graph interactively.
"""

import tempfile
from pathlib import Path

import click
from logurich import get_logger
from logurich.opt_click import click_logger_params

from cyvest import Cyvest

logger = get_logger(__name__)


@click.command()
@click_logger_params
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def main(output: Path | None = None) -> None:
    # Create a comprehensive investigation with various observables
    cv = Cyvest(
        investigation_id="cyvest-visual-example",
        investigation_name="Visualization Example",
    )
    # Malicious infrastructure
    malicious_domain = (
        cv.observable(cv.OBS.DOMAIN, "evil-phishing.com")
        .with_ti("VirusTotal", weight=9.0, comment="Known phishing domain")
        .with_ti("AlienVault OTX", weight=8.5, comment="Recently reported")
    )

    malicious_ip = (
        cv.observable(cv.OBS.IPV4, "185.220.101.50")
        .with_ti("AbuseIPDB", weight=9.5, comment="C2 server")
        .relate_to(malicious_domain, cv.REL.PIVOT)
    )

    # Suspicious infrastructure
    suspicious_domain = (
        cv.observable(cv.OBS.DOMAIN, "sketchy-site.net")
        .with_ti("VirusTotal", weight=4.5, comment="Some detections")
        .relate_to(
            cv.observable(cv.OBS.IPV4, "192.168.100.5").with_ti("Shodan", weight=3.0),
            cv.REL.PIVOT,
        )
    )

    # Email analysis
    attacker_email = (
        cv.observable(cv.OBS.EMAIL, "attacker@evil-phishing.com")
        .with_ti("EmailRep", weight=8.0, comment="Suspicious sender")
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    victim_email = cv.observable(cv.OBS.EMAIL, "victim@company.com", internal=True).with_ti(
        "Internal Whitelist", weight=-1.0, comment="Known employee"
    )

    # Email artifact with multiple relationships
    email_message = (
        cv.observable(cv.OBS.ARTIFACT, "Phishing Email - Invoice #12345")
        .relate_to(attacker_email, cv.REL.EXTRACTION)
        .relate_to(victim_email, cv.REL.EXTRACTION)
        .with_ti("Email Gateway", weight=7.0, comment="Flagged as suspicious")
    )

    # Malicious URLs in email
    phishing_url1 = (
        cv.observable(cv.OBS.URL, "https://evil-phishing.com/login")
        .with_ti("URLhaus", weight=9.0)
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    phishing_url2 = (
        cv.observable(cv.OBS.URL, "https://evil-phishing.com/verify")
        .with_ti("URLhaus", weight=8.5)
        .relate_to(malicious_domain, cv.REL.RELATED_TO)
    )

    # Email contains URLs
    email_message.relate_to(phishing_url1, cv.REL.EXTRACTION)
    email_message.relate_to(phishing_url2, cv.REL.EXTRACTION)

    suspicious_url = (
        cv.observable(cv.OBS.URL, "https://sketchy-site.net/invoice")
        .with_ti("URLhaus", weight=4.5, comment="Low-confidence redirect")
        .relate_to(suspicious_domain, cv.REL.RELATED_TO)
    )
    # An allowlist is a declared act in v7, not a flag on the observable — and the fluent path
    # carries the attribution, so it never has to be traded for traceability.
    trusted_url = (
        cv.observable(cv.OBS.URL, "https://accounts.google.com/security")
        .with_ti("Internal Whitelist", weight=-2.0, comment="Known safe link")
        .allowlist(
            "Domaine d'authentification Google, validé par la RSSI",
            decided_by="rssi",
        )
    )

    email_message.relate_to(suspicious_url, cv.REL.EXTRACTION)
    email_message.relate_to(trusted_url, cv.REL.EXTRACTION)

    # Malware file dropped
    malware_file = (
        cv.observable(cv.OBS.FILE, "invoice.exe")
        .with_ti("VirusTotal", weight=10.0, comment="Detected by 45/70 engines")
        .relate_to(phishing_url1, cv.REL.EXTRACTION)
        .relate_to(malicious_ip, cv.REL.RELATED_TO)
    )

    # Create findings linking observables
    _ = (
        cv.finding("email_analysis", "Phishing email analysis")
        .link_observable(email_message)
        .link_observable(attacker_email)
        .link_observable(victim_email)
        .with_weight(8.0)
        .tagged("phishing:investigation:email")
    )

    _ = (
        cv.finding("url_analysis", "Malicious URLs found in email")
        .link_observable(phishing_url1)
        .link_observable(phishing_url2)
        .link_observable(suspicious_url)
        .with_weight(9.0)
        .tagged("phishing:investigation:network")
    )

    _ = (
        cv.finding("infrastructure", "Malicious infrastructure identified")
        .link_observable(malicious_domain)
        .link_observable(malicious_ip)
        .with_weight(9.5)
        .tagged("phishing:investigation:network")
    )

    _ = (
        cv.finding("malware_detection", "Malware file analysis")
        .link_observable(malware_file)
        .with_weight(10.0)
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
    json_path = cv.io_save_json(output_path)
    size_kb = Path(json_path).stat().st_size / 1024
    logger.info("[green]✓ Full json saved to: %s (%.2f KB)[/green]", json_path, size_kb)

    # The report travels inside the JSON, so a consumer reads results instead of recomputing them.
    logger.info("[bold cyan]Report carried by the document:[/bold cyan]")
    report = cv.get_report()
    logger.info(
        "[green]✓ %s · score %.2f · %s[/green]",
        report.engine_id,
        report.investigation.score or 0.0,
        report.investigation.verdict.value,
    )


if __name__ == "__main__":
    main()
