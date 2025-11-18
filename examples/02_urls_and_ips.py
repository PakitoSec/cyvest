"""
Example 2: URLs and IP Investigation

Demonstrates investigating multiple URLs and their associated IP addresses
with relationship tracking.
"""

import tempfile
from decimal import Decimal
from pathlib import Path

from logurich import logger

from cyvest import Cyvest, Level
from cyvest.io_serialization import save_investigation_json

logger.enable("cyvest")


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
            ip1 = cv.observable("ipv4", "192.0.2.100", internal=False).with_ti(
                "abuseipdb", score=Decimal("7.5"), level=Level.MALICIOUS, comment="High abuse score"
            )

            # Link URL to IP
            cv.observable_add_relationship(url1.key, ip1.key, "resolves-to")

            # Suspicious URL 2
            url2 = cv.observable("url", "http://evil-download.net/payload.exe", internal=False).with_ti(
                "virustotal", score=Decimal("8.0"), level=Level.MALICIOUS, comment="Malware distribution"
            )

            # IP address for URL2
            ip2 = (
                cv.observable("ipv4", "198.51.100.50", internal=False)
                .with_ti("shodan", score=Decimal("0"), comment="Open ports: 80, 443, 8080")
                .with_ti("abuseipdb", score=Decimal("6.0"), level=Level.SUSPICIOUS, comment="Moderate abuse score")
            )

            # Link URL to IP
            cv.observable_add_relationship(url2.key, ip2.key, "resolves-to")

            # Internal host that connected
            internal_host = cv.observable("hostname", "workstation-042.company.local", internal=True).with_ti(
                "edr", score=Decimal("0"), comment="Detected outbound connection to suspicious IP"
            )

            # Link internal host to external URLs
            cv.observable_add_relationship(internal_host.key, url1.key, "communicates-with")
            cv.observable_add_relationship(internal_host.key, url2.key, "communicates-with")

            # Create checks
            _ = (
                cv.check("c2_detection", "network", "Detect C2 communication")
                .link_observable(url1)
                .link_observable(ip1)
                .in_container(network_ctr)
            )

            _ = (
                cv.check("malware_download", "network", "Detect malware download")
                .link_observable(url2)
                .link_observable(ip2)
                .in_container(network_ctr)
            )

            _ = (
                cv.check(
                    "compromised_host",
                    "endpoint",
                    "Identify compromised endpoint",
                    comment="Host made connections to known malicious infrastructure",
                )
                .link_observable(internal_host)
                .in_container(network_ctr)
            )

        # Finalize
        cv.observable_finalize_relationships()
        cv.display_summary(show_graph=True)

        # Export
        output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_02_"))
        json_path = output_dir / "urls_and_ips_investigation.json"
        save_investigation_json(cv, str(json_path))
        logger.info("✓ Investigation saved to {}", json_path)
        logger.info("Temporary output directory: {}", output_dir)


if __name__ == "__main__":
    main()
