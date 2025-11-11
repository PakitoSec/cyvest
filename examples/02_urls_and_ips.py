"""
Example 2: URLs and IP Investigation

Demonstrates investigating multiple URLs and their associated IP addresses
with relationship tracking.
"""

from decimal import Decimal

from cyvest import Cyvest, Level
from cyvest.io_rich import display_summary
from cyvest.io_serialization import save_investigation_json


def main() -> None:
    """Run a URL and IP investigation example."""
    with Cyvest(data={"type": "network_traffic"}) as cv:
        # Create container for network analysis
        with cv.container("network_analysis", "Analysis of network traffic") as network_ctr:
            # Suspicious URL 1
            url1 = (
                cv.observable("url", "http://malicious-c2.com/beacon", internal=False)
                .with_ti("virustotal", score=Decimal("9.0"), level=Level.MALICIOUS, comment="C2 server detected")
                .with_ti("alienvault", score=Decimal("8.5"), level=Level.MALICIOUS, comment="Known APT infrastructure")
            )

            # IP address for URL1
            ip1 = (
                cv.observable("ipv4", "192.0.2.100", internal=False)
                .with_ti("abuseipdb", score=Decimal("7.5"), level=Level.MALICIOUS, comment="High abuse score")
                .get()
            )

            # Link URL to IP
            url1.relate_to(ip1, "resolves-to")

            # Suspicious URL 2
            url2 = (
                cv.observable("url", "http://evil-download.net/payload.exe", internal=False)
                .with_ti("virustotal", score=Decimal("8.0"), level=Level.MALICIOUS, comment="Malware distribution")
                .get()
            )

            # IP address for URL2
            ip2 = (
                cv.observable("ipv4", "198.51.100.50", internal=False)
                .with_ti("shodan", score=Decimal("0"), comment="Open ports: 80, 443, 8080")
                .with_ti("abuseipdb", score=Decimal("6.0"), level=Level.SUSPICIOUS, comment="Moderate abuse score")
                .get()
            )

            # Link URL to IP
            cv.observable_add_relationship(url2.key, ip2.key, "resolves-to")

            # Internal host that connected
            internal_host = (
                cv.observable("hostname", "workstation-042.company.local", internal=True)
                .with_ti("edr", score=Decimal("0"), comment="Detected outbound connection to suspicious IP")
                .get()
            )

            # Link internal host to external URLs
            cv.observable_add_relationship(internal_host.key, url1.get().key, "communicates-with")
            cv.observable_add_relationship(internal_host.key, url2.key, "communicates-with")

            # Create checks
            _ = (
                cv.check("c2_detection", "network", "Detect C2 communication", score=Decimal("9.0"))
                .link_observable(url1.get())
                .link_observable(ip1)
                .in_container(network_ctr)
            )

            _ = (
                cv.check("malware_download", "network", "Detect malware download", score=Decimal("8.0"))
                .link_observable(url2)
                .link_observable(ip2)
                .in_container(network_ctr)
            )

            _ = (
                cv.check(
                    "compromised_host", "endpoint", "Identify compromised endpoint", comment="Host made connections to known malicious infrastructure", score=Decimal("7.0")
                )
                .link_observable(internal_host)
                .in_container(network_ctr)
            )

        # Finalize
        cv.observable_finalize_relationships()

        # Display summary
        print("\n" + "=" * 80)
        print("EXAMPLE 2: URLS AND IP INVESTIGATION")
        print("=" * 80 + "\n")

        from rich.console import Console

        console = Console()
        display_summary(cv, console, show_graph=True)

        # Statistics
        stats = cv.get_statistics()
        print(f"\n{'=' * 80}")
        print("STATISTICS:")
        print(f"  Total Observables: {stats['total_observables']}")
        print(f"  Internal: {stats['internal_observables']}")
        print(f"  External: {stats['external_observables']}")
        print(f"  Total Threat Intel Queries: {stats['total_threat_intel']}")
        print(f"\n  Global Score: {cv.get_global_score()}")
        print(f"  Global Level: {cv.get_global_level()}")
        print(f"{'=' * 80}\n")

        # Export
        save_investigation_json(cv, "urls_and_ips_investigation.json")
        print("✓ Investigation saved to urls_and_ips_investigation.json")


if __name__ == "__main__":
    main()
