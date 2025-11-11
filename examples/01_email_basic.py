"""
Example 1: Basic Email Investigation

Demonstrates basic usage of Cyvest for analyzing a suspicious email.
"""

from decimal import Decimal

from cyvest import Cyvest, Level
from cyvest.io_rich import display_summary
from cyvest.io_serialization import save_investigation_json, save_investigation_markdown


def main() -> None:
    """Run a basic email investigation example."""
    # Create investigation
    with Cyvest(data={"type": "email", "subject": "Urgent: Verify Your Account"}) as cv:
        # Create email-related observables using DSL
        sender_email = (
            cv.observable("email", "suspicious@phishing-domain.com", internal=False)
            .with_ti("internal_db", score=Decimal("0"), comment="Unknown sender")
            .get()
        )

        # Create URL observables
        phishing_url = (
            cv.observable("url", "https://fake-bank-login.com/verify", internal=False)
            .with_ti("virustotal", score=Decimal("8.5"), level=Level.MALICIOUS, comment="Known phishing URL")
            .with_ti("urlscan", score=Decimal("7.0"), level=Level.MALICIOUS, comment="Malicious content detected")
            .relate_to(cv.root(), "related-to")
            .get()
        )

        # Create domain observable
        domain = (
            cv.observable("domain", "fake-bank-login.com", internal=False)
            .with_ti("dns_lookup", score=Decimal("0"), comment="Recently registered domain (2 days old)")
            .get()
        )

        # Link URL to domain
        cv.observable_add_relationship(phishing_url.key, domain.key, "uses")

        # Create checks
        sender_check = cv.create_check(
            "sender_verification",
            "email_headers",
            "Verify sender authenticity",
            comment="Sender domain not in known contacts. SPF check failed.",
            score=Decimal("3.5"),
        )

        url_check = cv.create_check(
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
        cv.observable_finalize_relationships()

        # Display summary
        print("\n" + "=" * 80)
        print("EXAMPLE 1: BASIC EMAIL INVESTIGATION")
        print("=" * 80 + "\n")

        from rich.console import Console

        console = Console()
        display_summary(cv, console, show_graph=True)

        # Print global score and level
        print(f"\n{'=' * 80}")
        print(f"Global Score: {cv.get_global_score()}")
        print(f"Global Level: {cv.get_global_level()}")
        print(f"{'=' * 80}\n")

        # Export to files
        save_investigation_json(cv, "email_investigation.json")
        save_investigation_markdown(cv, "email_investigation.md")

        print("✓ Investigation saved to email_investigation.json and email_investigation.md")


if __name__ == "__main__":
    main()
