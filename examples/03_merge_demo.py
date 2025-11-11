"""
Example 3: Multi-Process Investigation Merging

Demonstrates how to build investigation fragments in parallel processes
and merge them together.
"""

import multiprocessing as mp
from decimal import Decimal

from cyvest import Cyvest, Level
from cyvest.io_rich import display_summary
from cyvest.io_serialization import save_investigation_json


def analyze_network_traffic() -> Cyvest:
    """Analyze network traffic (simulating a separate process)."""
    cv = Cyvest(data={"type": "pcap_analysis", "source": "network_sensor_01"})

    # Create network-related observables
    malicious_ip = cv.observable_create("ipv4", "203.0.113.50", internal=False)
    cv.observable_add_threat_intel(
        malicious_ip.key, "abuseipdb", score=Decimal("8.0"), level=Level.MALICIOUS, comment="Known botnet C2"
    )

    internal_host = cv.observable_create("ipv4", "10.0.1.25", internal=True)
    cv.observable_add_relationship(internal_host.key, malicious_ip.key, "communicates-with")

    # Create check
    network_check = cv.check_create(
        "outbound_c2", "network", "Detected outbound C2 traffic", score=Decimal("8.0"), level=Level.MALICIOUS
    )
    cv.check_link_observable(network_check.key, malicious_ip.key)
    cv.check_link_observable(network_check.key, internal_host.key)

    return cv


def analyze_endpoint_logs() -> Cyvest:
    """Analyze endpoint logs (simulating a separate process)."""
    cv = Cyvest(data={"type": "edr_logs", "source": "endpoint_agent"})

    # Create file hash observable
    suspicious_file = cv.observable_create("hash", "e99a18c428cb38d5f260853678922e03", internal=False)
    cv.observable_add_threat_intel(
        suspicious_file.key,
        "virustotal",
        score=Decimal("9.5"),
        level=Level.MALICIOUS,
        comment="Ransomware detected: 45/70 vendors",
    )

    # Create process observable
    malicious_process = cv.observable_create("process", "update.exe", internal=False)
    cv.observable_add_relationship(malicious_process.key, suspicious_file.key, "uses")

    # Create check
    endpoint_check = cv.check_create(
        "malware_execution",
        "endpoint",
        "Detected malware execution",
        comment="Ransomware executed with SYSTEM privileges",
        score=Decimal("9.5"),
        level=Level.MALICIOUS,
    )
    cv.check_link_observable(endpoint_check.key, suspicious_file.key)
    cv.check_link_observable(endpoint_check.key, malicious_process.key)

    return cv


def analyze_email_gateway() -> Cyvest:
    """Analyze email gateway logs (simulating a separate process)."""
    cv = Cyvest(data={"type": "email_gateway", "source": "mail_filter"})

    # Create email observable
    phishing_email = cv.observable_create("email", "attacker@evil.com", internal=False)
    cv.observable_add_threat_intel(
        phishing_email.key, "email_reputation", score=Decimal("6.0"), level=Level.SUSPICIOUS, comment="Known spam source"
    )

    # Create URL from email
    phishing_url = cv.observable_create("url", "http://malware-download.bad/payload", internal=False)
    cv.observable_add_threat_intel(
        phishing_url.key, "urlscan", score=Decimal("7.0"), level=Level.MALICIOUS, comment="Hosts malware"
    )
    cv.observable_add_relationship(phishing_email.key, phishing_url.key, "contains")

    # Create check
    email_check = cv.check_create(
        "phishing_detection",
        "email",
        "Detected phishing email with malware link",
        score=Decimal("6.0"),
        level=Level.SUSPICIOUS,
    )
    cv.check_link_observable(email_check.key, phishing_email.key)
    cv.check_link_observable(email_check.key, phishing_url.key)

    return cv


def main() -> None:
    """Run multi-process investigation merge example."""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: MULTI-PROCESS INVESTIGATION MERGING")
    print("=" * 80 + "\n")

    print("Step 1: Analyzing different data sources in parallel...")

    # In a real scenario, these would run in separate processes
    # For simplicity, we'll call them sequentially but treat them as independent
    network_investigation = analyze_network_traffic()
    endpoint_investigation = analyze_endpoint_logs()
    email_investigation = analyze_email_gateway()

    print("✓ Network analysis complete")
    print("✓ Endpoint analysis complete")
    print("✓ Email analysis complete\n")

    # Create main investigation and merge all sub-investigations
    print("Step 2: Merging all investigations...")
    main_investigation = Cyvest(data={"type": "incident_response", "incident_id": "INC-2025-001"})

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
    main_investigation.observable_finalize_relationships()

    print("✓ Investigations merged successfully\n")

    # Display comprehensive summary
    from rich.console import Console

    console = Console()
    display_summary(main_investigation, console, show_graph=True)

    # Display detailed statistics
    stats = main_investigation.get_statistics()
    print(f"\n{'=' * 80}")
    print("MERGED INVESTIGATION STATISTICS:")
    print(f"{'=' * 80}")
    print(f"  Total Observables: {stats['total_observables']}")
    print(f"  - Internal: {stats['internal_observables']}")
    print(f"  - External: {stats['external_observables']}")
    print(f"  Total Checks: {stats['total_checks']}")
    print(f"  - Applied: {stats['applied_checks']}")
    print(f"  Total Threat Intel Queries: {stats['total_threat_intel']}")
    print()
    print("  Observable Types:")
    for obs_type, count in stats.get("observables_by_type", {}).items():
        print(f"    - {obs_type}: {count}")
    print()
    print(f"  Global Score: {main_investigation.get_global_score()}")
    print(f"  Global Level: {main_investigation.get_global_level()}")
    print(f"{'=' * 80}\n")

    # Export merged investigation
    save_investigation_json(main_investigation, "merged_investigation.json")
    print("✓ Merged investigation saved to merged_investigation.json")


if __name__ == "__main__":
    # Required for multiprocessing on some platforms
    mp.freeze_support()
    main()
