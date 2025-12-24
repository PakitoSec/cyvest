"""
Example 1: Basic Email Investigation

Demonstrates basic usage of Cyvest for analyzing a suspicious email.
"""

import tempfile
from decimal import Decimal
from pathlib import Path

from logurich import logger

from cyvest import Cyvest

logger.enable("cyvest")


def main() -> None:
    """Run a basic email investigation example."""
    # Create investigation
    cv = Cyvest(root_data={"type": "email", "subject": "Urgent: Verify Your Account"})

    # Create email-related observables using the fluent proxy interface
    sender_email = cv.observable(cv.OBS.EMAIL_ADDR, "suspicious@phishing-domain.com", internal=False).with_ti(
        "internal_db", score=Decimal("0"), comment="Unknown sender"
    )

    # Create URL observables
    phishing_url = (
        cv.observable(cv.OBS.URL, "https://fake-bank-login.com/verify", internal=False)
        .with_ti("virustotal", score=Decimal("8.5"), level=cv.LVL.MALICIOUS, comment="Known phishing URL")
        .with_ti("urlscan", score=Decimal("7.0"), level=cv.LVL.MALICIOUS, comment="Malicious content detected")
        .relate_to(cv.root(), cv.REL.RELATED_TO)
    )

    # Create domain observable
    domain = cv.observable(cv.OBS.DOMAIN_NAME, "fake-bank-login.com", internal=False).with_ti(
        "dns_lookup", score=Decimal("0"), comment="Recently registered domain (2 days old)"
    )

    # Link URL to domain
    cv.observable_add_relationship(phishing_url.key, domain.key, cv.REL.RELATED_TO)

    # Create checks
    sender_check = cv.check_create(
        "sender_verification",
        "email_headers",
        "Verify sender authenticity",
        comment="Sender domain not in known contacts. SPF check failed.",
        score=Decimal("3.5"),
    )

    url_check = cv.check_create(
        "url_analysis",
        "email_body",
        "Analyze URLs in email body",
        comment="Found phishing URL attempting to steal credentials",
        score=Decimal("8.5"),
    )

    # Link checks to observables
    cv.check_link_observable(sender_check.key, sender_email.key)
    cv.check_link_observable(url_check.key, phishing_url.key)

    # Create container for organization
    email_container = cv.container_create("email_analysis", "Analysis of suspicious email")
    cv.container_add_check(email_container.key, sender_check.key)
    cv.container_add_check(email_container.key, url_check.key)

    # Add enrichment
    cv.enrichment_create(
        "email_headers",
        {
            "from": "suspicious@phishing-domain.com",
            "to": "victim@company.com",
            "subject": "Urgent: Verify Your Account",
            "received": "2025-11-11 10:30:00",
            "spf": "fail",
            "dkim": "none",
        },
    )

    # Finalize relationships (link orphan observables to root)
    cv.finalize_relationships()
    cv.display_summary(show_graph=True)

    # Export to files in a temp directory for easy cleanup
    output_dir = Path(tempfile.mkdtemp(prefix="cyvest_example_01_"))
    json_path = output_dir / "email_investigation.json"
    md_path = output_dir / "email_investigation.md"
    cv.io_save_json(str(json_path))
    cv.io_save_markdown(str(md_path))

    logger.info("✓ Investigation saved to {} and {}", json_path, md_path)
    logger.info("Temporary output directory: {}", output_dir)


if __name__ == "__main__":
    main()
