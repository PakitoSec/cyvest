"""
Example 2: URLs and IP Investigation

Demonstrates investigating multiple URLs and their associated IP addresses
with relationship tracking.
"""

import logging
import tempfile
from decimal import Decimal
from pathlib import Path

from logurich import init_logger

from cyvest import Cyvest

logger = logging.getLogger(__name__)


def main() -> None:
    """Run a URL and IP investigation example."""
    cv = Cyvest(root_data={"type": "network_traffic"})

    # Create tag for network analysis
    network_tag = cv.tag("network:analysis", "Analysis of network traffic")

    # Suspicious URL 1
    url1 = (
        cv.observable(cv.OBS.URL, "http://malicious-c2.com/beacon", internal=False)
        .with_ti("virustotal", score=Decimal("9.0"), level=cv.LVL.MALICIOUS, comment="C2 server detected")
        .with_ti("alienvault", score=Decimal("8.5"), level=cv.LVL.MALICIOUS, comment="Known APT infrastructure")
    )

    # IP address for URL1
    ip1 = cv.observable(cv.OBS.IPV4, "192.0.2.100", internal=False).with_ti(
        "abuseipdb", score=Decimal("7.5"), level=cv.LVL.MALICIOUS, comment="High abuse score"
    )

    # Link URL to IP
    cv.observable_add_relationship(url1.key, ip1.key, cv.REL.RELATED_TO)

    # Suspicious URL 2
    url2 = cv.observable(cv.OBS.URL, "http://evil-download.net/payload.exe", internal=False).with_ti(
        "virustotal", score=Decimal("8.0"), level=cv.LVL.MALICIOUS, comment="Malware distribution"
    )

    # IP address for URL2
    ip2 = (
        cv.observable(cv.OBS.IPV4, "198.51.100.50", internal=False)
        .with_ti("shodan", score=Decimal("0"), comment="Open ports: 80, 443, 8080")
        .with_ti("abuseipdb", score=Decimal("6.0"), level=cv.LVL.SUSPICIOUS, comment="Moderate abuse score")
    )

    # Link URL to IP
    cv.observable_add_relationship(url2.key, ip2.key, cv.REL.RELATED_TO)

    # Internal host that connected
    internal_host = cv.observable(
        cv.OBS.DOMAIN,
        "workstation-042.company.local",
        internal=True,
    ).with_ti("edr", score=Decimal("0"), comment="Detected outbound connection to suspicious IP")

    # Link internal host to external URLs
    cv.observable_add_relationship(internal_host.key, url1.key, cv.REL.RELATED_TO)
    cv.observable_add_relationship(internal_host.key, url2.key, cv.REL.RELATED_TO)

    # Create checks
    _ = (
        cv.check("c2_detection", "Detect C2 communication")
        .link_observable(url1)
        .link_observable(ip1)
        .tagged(network_tag)
    )

    _ = (
        cv.check("malware_download", "Detect malware download")
        .link_observable(url2)
        .link_observable(ip2)
        .tagged(network_tag)
    )

    _ = (
        cv.check(
            "compromised_host",
            "Identify compromised endpoint",
            comment="Host made connections to known malicious infrastructure",
        )
        .link_observable(internal_host)
        .tagged(network_tag)
    )

    # Finalize
    cv.finalize_relationships()
    cv.display_summary(show_graph=True)

    # Export
    output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_02_"))
    json_path = output_dir / "urls_and_ips_investigation.json"
    cv.io_save_json(str(json_path))
    logger.info("✓ Investigation saved to %s", json_path)
    logger.info("Temporary output directory: %s", output_dir)


if __name__ == "__main__":
    init_logger("INFO")
    main()
