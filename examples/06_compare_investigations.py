"""
Example 6: Compare Investigations

Demonstrates how to compare two Cyvest investigations with optional tolerance rules.
Shows differences in findings, observables, and threat intelligence between investigations.
"""

from decimal import Decimal

from logurich import get_logger, init_logger

from cyvest import Cyvest, ExpectedResult, Level, compare_investigations
from cyvest.io_rich import display_diff

logger = get_logger(__name__)


def create_expected_investigation() -> Cyvest:
    """Create an expected/baseline investigation for comparison."""
    cv = Cyvest(root_data={"type": "email", "subject": "Test Email"}, investigation_name="expected")

    # Create observables
    domain = cv.observable(cv.OBS.DOMAIN, "example.com", internal=False)
    domain.with_ti("VirusTotal", score=Decimal("0.0"), level=Level.INFO)
    domain.with_ti("MISP Warning List", score=Decimal("0.0"), level=Level.SAFE)

    ip = cv.observable(cv.OBS.IPV4, "192.168.1.1", internal=False)
    ip.with_ti("VirusTotal", score=Decimal("0.0"), level=Level.INFO)
    ip.with_ti("SEKOIA", score=Decimal("0.0"), level=Level.INFO)

    # Create findings
    domain_finding = cv.finding_create(
        "domain-reputation",
        "Domain reputation finding",
        score=Decimal("0.5"),
        level=Level.NOTABLE,
    )
    domain_finding.link_observable(domain)

    ip_finding = cv.finding_create(
        "ip-reputation",
        "IP reputation finding",
        score=Decimal("0.0"),
        level=Level.INFO,
    )
    ip_finding.link_observable(ip)

    cv.finding_create(
        "roger-ai",
        "AI-based analysis",
        score=Decimal("1.11"),
        level=Level.SUSPICIOUS,
    )

    return cv


def create_actual_investigation() -> Cyvest:
    """Create an actual investigation with some differences."""
    cv = Cyvest(root_data={"type": "email", "subject": "Test Email"}, investigation_name="actual")

    # Create observables - with different scores
    domain = cv.observable(cv.OBS.DOMAIN, "example.com", internal=False)
    domain.with_ti("VirusTotal", score=Decimal("0.5"), level=Level.NOTABLE)  # Different score
    domain.with_ti("MISP Warning List", score=Decimal("0.0"), level=Level.SAFE)

    ip = cv.observable(cv.OBS.IPV4, "192.168.1.1", internal=False)
    ip.with_ti("VirusTotal", score=Decimal("0.0"), level=Level.INFO)
    ip.with_ti("SEKOIA", score=Decimal("0.0"), level=Level.INFO)

    # New observable not in expected
    malicious_domain = cv.observable(cv.OBS.DOMAIN, "malicious.com", internal=False)
    malicious_domain.with_ti("VirusTotal", score=Decimal("8.5"), level=Level.MALICIOUS)
    malicious_domain.with_ti("MISP", score=Decimal("7.0"), level=Level.MALICIOUS)

    # Create findings - with some differences
    domain_finding = cv.finding_create(
        "domain-reputation",
        "Domain reputation finding",
        score=Decimal("1.0"),  # Higher score than expected
        level=Level.NOTABLE,
    )
    domain_finding.link_observable(domain)

    ip_finding = cv.finding_create(
        "ip-reputation",
        "IP reputation finding",
        score=Decimal("0.0"),  # Same as expected
        level=Level.INFO,
    )
    ip_finding.link_observable(ip)

    cv.finding_create(
        "roger-ai",
        "AI-based analysis",
        score=Decimal("1.07"),  # Slightly different score
        level=Level.SUSPICIOUS,
    )

    # New finding not in expected
    new_finding = cv.finding_create(
        "new-detection",
        "Newly added detection rule",
        score=Decimal("2.5"),
        level=Level.NOTABLE,
    )
    new_finding.link_observable(malicious_domain)

    return cv


def main() -> None:
    """Run the comparison example."""
    logger.info("[bold magenta]Cyvest Investigation Comparison Example[/bold magenta]")
    logger.info("")

    # Create investigations
    expected = create_expected_investigation()
    actual = create_actual_investigation()

    # Compare without tolerance rules
    logger.info("[bold cyan]1. Comparing without tolerance rules:[/bold cyan]")
    logger.info("")

    diffs = compare_investigations(actual, expected)
    display_diff(diffs, lambda r: logger.rich("INFO", r, width=150), title="Diff: Without Tolerance Rules")

    logger.info("")
    logger.info(f"Total differences found: {len(diffs)}")
    logger.info("")

    # Compare with tolerance rules
    logger.info("[bold cyan]2. Comparing with tolerance rules:[/bold cyan]")
    logger.info("")

    tolerance_rules = [
        # Allow roger-ai score to be >= 1.0
        ExpectedResult(finding_name="roger-ai", level=Level.SUSPICIOUS, score=">= 1.0"),
        # Allow domain-reputation score to be < 2.0
        ExpectedResult(key="fnd:domain-reputation", score="< 2.0"),
    ]

    diffs_with_rules = compare_investigations(actual, expected, result_expected=tolerance_rules)
    display_diff(
        diffs_with_rules,
        lambda r: logger.rich("INFO", r, width=150),
        title="Diff: With Tolerance Rules",
    )

    logger.info("")
    logger.info(f"Total differences found (with tolerance): {len(diffs_with_rules)}")
    logger.info("")

    # Using the Cyvest convenience methods
    logger.info("[bold cyan]3. Using Cyvest convenience methods:[/bold cyan]")
    logger.info("")

    actual.display_diff(expected=expected, title="Diff: Using Cyvest.display_diff()")

    logger.info("")
    logger.info("[green]Example complete![/green]")


if __name__ == "__main__":
    init_logger("INFO")
    main()
