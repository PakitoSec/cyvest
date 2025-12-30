"""
Example 3: Multi-Process Investigation Merging

Demonstrates how to build investigation fragments in parallel processes
and merge them together.
"""

import multiprocessing as mp
import tempfile
from decimal import Decimal
from pathlib import Path

from logurich import logger

from cyvest import Cyvest

logger.enable("cyvest")


def analyze_network_traffic() -> Cyvest:
    """Analyze network traffic (simulating a separate process)."""
    cv = Cyvest(root_data={"type": "pcap_analysis", "source": "network_sensor_01"})

    # Create network-related observables
    malicious_ip = cv.observable_create(cv.OBS.IPV4, "203.0.113.50", internal=False)
    cv.observable_add_threat_intel(
        malicious_ip.key, "abuseipdb", score=Decimal("8.0"), level=cv.LVL.MALICIOUS, comment="Known botnet C2"
    )

    internal_host = cv.observable_create(cv.OBS.IPV4, "10.0.1.25", internal=True)
    cv.observable_add_relationship(internal_host.key, malicious_ip.key, cv.REL.RELATED_TO)

    # Create check
    network_check = cv.check_create(
        "outbound_c2", "network", "Detected outbound C2 traffic", score=Decimal("8.0"), level=cv.LVL.MALICIOUS
    )
    cv.check_link_observable(network_check.key, malicious_ip.key)
    cv.check_link_observable(network_check.key, internal_host.key)

    return cv


def analyze_endpoint_logs() -> Cyvest:
    """Analyze endpoint logs (simulating a separate process)."""
    cv = Cyvest(root_data={"type": "edr_logs", "source": "endpoint_agent"})

    # Create hash observable
    suspicious_hash = cv.observable_create(cv.OBS.HASH, "e99a18c428cb38d5f260853678922e03", internal=False)
    cv.observable_add_threat_intel(
        suspicious_hash.key,
        "virustotal",
        score=Decimal("9.5"),
        level=cv.LVL.MALICIOUS,
        comment="Ransomware detected: 45/70 vendors",
    )

    # Create executable file observable
    malicious_executable = cv.observable_create(cv.OBS.FILE, "update.exe", internal=False)
    cv.observable_add_relationship(malicious_executable.key, suspicious_hash.key, cv.REL.RELATED_TO)

    # Create check
    endpoint_check = cv.check_create(
        "malware_execution",
        "endpoint",
        "Detected malware execution",
        comment="Ransomware executed with SYSTEM privileges",
        score=Decimal("9.5"),
        level=cv.LVL.MALICIOUS,
    )
    cv.check_link_observable(endpoint_check.key, suspicious_hash.key)
    cv.check_link_observable(endpoint_check.key, malicious_executable.key)

    return cv


def analyze_email_gateway() -> Cyvest:
    """Analyze email gateway logs (simulating a separate process)."""
    cv = Cyvest(root_data={"type": "email_gateway", "source": "mail_filter"})

    # Create email observable
    phishing_email = cv.observable_create(cv.OBS.EMAIL, "attacker@evil.com", internal=False)
    cv.observable_add_threat_intel(
        phishing_email.key,
        "email_reputation",
        score=Decimal("6.0"),
        level=cv.LVL.SUSPICIOUS,
        comment="Known spam source",
    )

    # Create URL from email
    phishing_url = cv.observable_create(cv.OBS.URL, "http://malware-download.bad/payload", internal=False)
    cv.observable_add_threat_intel(
        phishing_url.key, "urlscan", score=Decimal("7.0"), level=cv.LVL.MALICIOUS, comment="Hosts malware"
    )
    cv.observable_add_relationship(phishing_email.key, phishing_url.key, cv.REL.RELATED_TO)

    # Create check
    email_check = cv.check_create(
        "phishing_detection",
        "email",
        "Detected phishing email with malware link",
        score=Decimal("6.0"),
        level=cv.LVL.SUSPICIOUS,
    )
    cv.check_link_observable(email_check.key, phishing_email.key)
    cv.check_link_observable(email_check.key, phishing_url.key)

    return cv


def main() -> None:
    """Run multi-process investigation merge example."""
    logger.info("Step 1: Analyzing different data sources in parallel...")

    # In a real scenario, these would run in separate processes
    # For simplicity, we'll call them sequentially but treat them as independent
    network_investigation = analyze_network_traffic()
    endpoint_investigation = analyze_endpoint_logs()
    email_investigation = analyze_email_gateway()

    logger.info("✓ Network analysis complete")
    logger.info("✓ Endpoint analysis complete")
    logger.info("✓ Email analysis complete")
    logger.info("")

    # Create main investigation and merge all sub-investigations
    logger.info("Step 2: Merging all investigations...")
    main_investigation = Cyvest(root_data={"type": "incident_response", "incident_id": "INC-2025-001"})

    main_investigation.merge_investigation(network_investigation)
    main_investigation.merge_investigation(endpoint_investigation)
    main_investigation.merge_investigation(email_investigation)

    # Create a container to organize all findings
    incident_container = main_investigation.container_create(
        "incident_findings", "Consolidated findings from all data sources"
    )

    # Add all checks to the container
    for check in main_investigation.get_all_checks().values():
        main_investigation.container_add_check(incident_container.key, check.key)

    # Finalize relationships
    main_investigation.finalize_relationships()

    logger.info("✓ Investigations merged successfully")
    logger.info("")

    # Display comprehensive summary
    main_investigation.display_summary(show_graph=True)

    # Export merged investigation
    output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_03_"))
    json_path = output_dir / "merged_investigation.json"
    main_investigation.io_save_json(str(json_path))
    logger.info("✓ Merged investigation saved to {}", json_path)
    logger.info("Temporary output directory: {}", output_dir)


if __name__ == "__main__":
    # Required for multiprocessing on some platforms
    mp.freeze_support()
    main()
