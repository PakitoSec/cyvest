"""
Multi-threaded email investigation example.

Demonstrates using ThreadPoolExecutor to run investigation tasks in parallel,
with each task building a Cyvest fragment that merges into the main investigation.
"""

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import click
from logurich import logger
from logurich.opt_click import click_logger_params

from cyvest import Cyvest, Level, ObservableType, RelationshipType
from cyvest.investigation import SharedInvestigationContext

logger.enable("cyvest")


# ============================================================================
# Task Framework
# ============================================================================


class BaseRule(ABC):
    """
    Base class for investigation tasks.

    Each task runs independently (potentially in parallel) and returns a Cyvest
    investigation fragment that will be merged into the main investigation.
    """

    _deps: list[str] = []  # Task dependencies (for ordering)
    _scope: str = "general"  # Task scope (email, network, file, etc.)
    order: int = 100  # Execution order priority

    def _run(self, shared_context: SharedInvestigationContext) -> None:
        self.shared_context = shared_context
        with shared_context.create_cyvest() as cy:
            self.run(cy)

    @abstractmethod
    def run(self, cy: Cyvest) -> None:
        """
        Execute the task and return a Cyvest investigation fragment.

        Args:
            shared_context: Shared context for cross-task observable/check sharing
                          (access data via cy.root().extra)

        Returns:
            Cyvest instance containing observables, checks, and containers
        """
        pass


class RuleExecutor:
    """
    Executes investigation tasks in parallel using ThreadPoolExecutor.

    Collects Cyvest fragments from each task and merges them into a main investigation.
    """

    def __init__(self, max_workers: int = 4):
        """
        Initialize the task executor.

        Args:
            max_workers: Maximum number of parallel workers
        """
        self.max_workers = max_workers

    def run(self, tasks: list[BaseRule], data: dict[str, Any]) -> Cyvest:
        """
        Run all tasks in parallel and merge results using shared context.

        Args:
            tasks: List of tasks to execute
            data: Shared input data stored in root observable (accessible via cy.root().extra)

        Returns:
            Final merged investigation
        """
        # Sort tasks by order
        sorted_tasks = sorted(tasks, key=lambda t: t.order)

        # Create main investigation and shared context
        from cyvest.investigation import Investigation

        main_inv = Investigation(data, root_type="artifact")
        shared = SharedInvestigationContext(main_inv)

        logger.info(f"Running {len(sorted_tasks)} tasks in parallel with {self.max_workers} workers")

        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks with shared context (tasks access data via cy.root().extra)
            future_to_task = {executor.submit(task._run, shared): task for task in sorted_tasks}

            # Wait for all tasks to complete (they auto-reconcile via context manager)
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    future.result()
                    logger.info(f"Task {task.__class__.__name__} completed and reconciled")
                except Exception as e:
                    logger.error(f"Task {task.__class__.__name__} failed: {e}")

        # Return final merged investigation as Cyvest
        final_cy = Cyvest(data, root_type="artifact")
        final_cy._investigation = shared.get_investigation()
        return final_cy


# ============================================================================
# Task Implementations
# ============================================================================


class EmailFrom(BaseRule):
    """
    Analyzes email headers (FROM, SENDER, TO, CC, BCC).

    Builds observable chain: EMAIL_ADDR -> DOMAIN_NAME -> IPV4_ADDR
    """

    _scope = "header"
    order = 100

    def run(self, cy: Cyvest) -> None:
        """Analyze email headers and build investigation fragment."""
        # Use shared context to create Cyvest with auto-reconcile
        data = cy.root().extra
        from_addr = data.get("from_addr", "noreply@domainmalicious.com")
        from_domain = data.get("from_domain", "domainmalicious.com")
        from_ip = data.get("from_ip", "8.1.2.3")

        logger.info(f"Analyzing email header FROM: {from_addr}")

        # Build observable chain with threat intel
        obs = (
            cy.observable(ObservableType.EMAIL_ADDR, from_addr)
            .relate_to(cy.root(), relationship_type=RelationshipType.FROM, direction="inbound")
            .relate_to(
                cy.observable(ObservableType.DOMAIN_NAME, from_domain)
                .add_ti("VT", 2)
                .relate_to(
                    cy.observable(ObservableType.IPV4_ADDR, from_ip).add_ti("SEKOIA", 0),
                    RelationshipType.RESOLVES_TO,
                ),
                RelationshipType.RELATED_TO,
            )
            .add_ti("VT", 10, "test")
            .get()
        )

        # Create check for header analysis
        (
            cy.check("from", "header", "test email vt 10", "> ok boys")
            .link_observable(obs)
            .in_container(cy.container("emails"))
            .get()
        )

        logger.info(f"Email header analysis complete: {obs.key}")


class EmailReciever(BaseRule):
    """
    Analyzes email body content.

    Creates checks for body HTML content.
    """

    _scope = "body"
    order = 150

    def run(self, cy: Cyvest) -> None:
        """Analyze email body and build investigation fragment."""
        logger.info("Analyzing email receiver")

        cy.enrichment_create("receiver", {"receiver": ["ok"]}, context="from splunk")
        cy.check("receiver", "header", "description", "> receiver").with_score(0.1).link_observable(
            cy.observable(ObservableType.EMAIL_ADDR, "user@company.com").relate_to(
                cy.root(), RelationshipType.TO, direction="inbound"
            )
        ).in_container(cy.container("emails"))

        logger.info("Email receiver analysis complete")

        return cy


class BodiesUrlTask(BaseRule):
    """
    Analyzes URLs found in email bodies.

    Similar to CortexBodiesURL - extracts URLs, performs threat intel checks,
    and builds observable relationships.
    """

    _scope = "body"
    order = 200

    def run(self, cy: Cyvest) -> None:
        """Analyze body URLs and build investigation fragment."""
        # Extract URLs from data (stored in root observable)
        data = cy.root().extra
        urls_with_scores = data.get("body_urls")

        logger.info(f"Checking BODIES URLs: {len(urls_with_scores)}")

        # Create container for URL checks
        container = cy.container("bodies-urls", "Bodies URLs Analysis")

        # Analyze each URL
        for url_data in urls_with_scores:
            url = url_data["url"]
            score = url_data["score"]
            link_malicious = url_data.get("link_malicious", True)

            logger.info(f"Analyzing URL: {url} (score: {score})")

            # Build URL observable with relationships
            url_obs = (
                cy.observable(ObservableType.URL, url)
                .add_ti("VT", score)
                .relate_to(
                    cy.observable(ObservableType.FILE, "BODY/HTML").relate_to(
                        cy.root(), RelationshipType.BODY_RAW, direction="inbound"
                    ),
                    RelationshipType.CONTAINS,
                    direction="inbound",
                )
            )

            # Link to malicious domain if applicable
            # The merge system will automatically deduplicate with EmailFrom's domain observable
            if link_malicious:
                logger.info(f"Linking URL {url} to malicious domain")
                url_obs = url_obs.relate_to(
                    cy.observable(ObservableType.DOMAIN_NAME, "domainmalicious.com"),
                    RelationshipType.RESOLVES_TO,
                )

            # Create check and link to container
            chk = (
                cy.check(f"body-url-{url}", "body", f"URL analysis {url}", comment=f"> score: {score}")
                .link_observable(url_obs)
                .in_container(container)
                .get()
            )

            logger.info("[bold red]Check Score: {}[/bold red]", chk.score)

        logger.info(f"Bodies URLs analysis complete: {len(urls_with_scores)} URLs processed")
        logger.info("[bold red]Container Score: {}[/bold red]", container.get().get_aggregated_score())


class AttachmentTask(BaseRule):
    """
    Analyzes email attachments.

    Scans attached files for malware, extracts hashes, and performs threat intel lookups.
    """

    _scope = "attachment"
    order = 250

    def run(self, cy: Cyvest) -> None:
        """Analyze attachments and build investigation fragment."""
        data = cy.root().extra
        attachments = data.get("attachments", [])

        logger.info(f"Checking ATTACHMENTS: {len(attachments)}")

        # Create container for attachment checks
        container = cy.container("attachments", "Email Attachments Analysis")

        # Analyze each attachment
        for attachment in attachments:
            filename = attachment["filename"]
            md5_hash = attachment["md5"]
            sha256_hash = attachment["sha256"]
            score = attachment["score"]
            size = attachment.get("size", 0)

            logger.info(f"Analyzing attachment: {filename} (score: {score})")

            # Build file observable with hash observables
            file_obs = (
                cy.observable(ObservableType.FILE, filename)
                .relate_to(cy.root(), RelationshipType.CONTAINS, direction="inbound")
                .relate_to(
                    cy.observable(ObservableType.FILE, f"MD5:{md5_hash}").add_ti("VT", score, "MD5 hash analysis"),
                    RelationshipType.RELATED_TO,
                )
            )

            # Add threat intel based on score
            if score >= 5:
                file_obs = file_obs.add_ti("MALWAREBAZAAR", score, f"Known malware: {filename}")

            # Create check and link to container
            check_desc = f"File: {filename} ({size} bytes)"
            cy.check(
                f"attachment-{filename}",
                "attachment",
                check_desc,
                comment=f"> MD5: {md5_hash}\n> SHA256: {sha256_hash}\n> Threat score: {score}",
            ).link_observable(file_obs).in_container(container)

        logger.info(f"Attachments analysis complete: {len(attachments)} files processed")


class AggregatedRiskTask(BaseRule):
    """
    Aggregated risk assessment task.

    This task demonstrates creating an aggregated check that:
    - References checks created by other tasks
    - References observables created by other tasks
    - Calculates a composite risk score based on multiple indicators
    - Uses shared context to access cross-task data

    This runs last (order=300) to ensure other tasks have completed.

    Note: Due to parallel execution, some tasks may still be running when this
    executes. The aggregated check will use whatever data is available at the
    time it runs. For guaranteed sequential execution, use order values with
    larger gaps or run tasks sequentially.
    """

    _scope = "risk_assessment"
    order = 300

    def run(self, cy: Cyvest) -> None:
        """Calculate aggregated risk score based on all previous checks."""
        from decimal import Decimal

        logger.info("Starting aggregated risk assessment")

        # Access checks from other tasks using parameter-based API
        from_check = self.shared_context.get_check("from", "header")
        receiver_check = self.shared_context.get_check("receiver", "header")

        # Access observables from other tasks using parameter-based API
        sender_email = self.shared_context.get_observable(ObservableType.EMAIL_ADDR, "noreply@domainmalicious.com")
        malicious_domain = self.shared_context.get_observable(ObservableType.DOMAIN_NAME, "domainmalicious.com")

        # Find all URL checks (created by BodiesUrlTask)
        all_checks = self.shared_context.list_checks()
        url_checks = [self.shared_context.get_check(key) for key in all_checks if key.startswith("chk:body-url-")]

        # Find all attachment checks
        attachment_checks = [
            self.shared_context.get_check(key) for key in all_checks if key.startswith("chk:attachment-")
        ]

        # Calculate composite risk score
        risk_score = Decimal("0")
        risk_indicators = []

        # Factor 1: Sender reputation (high weight)
        if sender_email and sender_email.score >= 5:
            risk_score += sender_email.score * Decimal("0.4")  # 40% weight
            risk_indicators.append(f"Malicious sender: {sender_email.value} (score: {sender_email.score})")

        # Factor 2: Domain reputation (medium weight)
        if malicious_domain and malicious_domain.score >= 3:
            risk_score += malicious_domain.score * Decimal("0.3")  # 30% weight
            risk_indicators.append(f"Suspicious domain: {malicious_domain.value} (score: {malicious_domain.score})")

        # Factor 3: URL threats (medium weight)
        if url_checks:
            max_url_score = max((check.score for check in url_checks), default=Decimal("0"))
            if max_url_score > 0:
                risk_score += max_url_score * Decimal("0.2")  # 20% weight
                risk_indicators.append(f"Suspicious URLs detected (max score: {max_url_score})")

        # Factor 4: Attachment threats (high weight)
        if attachment_checks:
            max_attachment_score = max((check.score for check in attachment_checks), default=Decimal("0"))
            if max_attachment_score >= 5:
                risk_score += max_attachment_score * Decimal("0.5")  # 50% weight
                risk_indicators.append(f"Malicious attachment detected (score: {max_attachment_score})")

        # Build aggregated check comment
        comment = "> **Aggregated Risk Assessment**\n"
        comment += f"> Total risk score: {risk_score}\n"
        comment += f"> Indicators analyzed: {len(risk_indicators)}\n"
        comment += ">\n"
        comment += "> **Risk Factors:**\n"
        for indicator in risk_indicators:
            comment += f"> - {indicator}\n"
        comment += ">\n"
        comment += "> **Component Analysis:**\n"
        comment += f"> - Header checks: {len([c for c in [from_check, receiver_check] if c])}\n"
        comment += f"> - URL checks: {len(url_checks)}\n"
        comment += f"> - Attachment checks: {len(attachment_checks)}\n"

        # Create aggregated check
        aggregated_check = cy.check(
            "email_risk_aggregated", "full", "Aggregated Email Risk Assessment", comment=comment
        ).with_score(risk_score)

        # Link all relevant observables to the aggregated check
        if sender_email:
            aggregated_check.link_observable(sender_email)
        if malicious_domain:
            aggregated_check.link_observable(malicious_domain)

        # Put in a dedicated container
        aggregated_check.in_container(cy.container("risk_assessment", "Aggregated Risk Analysis"))

        logger.info(f"Aggregated risk assessment complete: score={risk_score}")
        logger.info(f"Risk indicators: {len(risk_indicators)}")


class AI(BaseRule):
    _scope = "ai"
    order = 1000

    def run(self, cy: Cyvest) -> None:
        """Calculate aggregated risk score based on all previous checks."""
        cy.check("ai", "full", "ai", score=0, level=Level.MALICIOUS).get()


# ============================================================================
# Main Execution
# ============================================================================


@click.command()
@click_logger_params
@click.option("-w", "--workers", type=int, default=1)
@click.option("--browser", "browser", is_flag=True, default=False)
@click.option("--stats", "stats", is_flag=True, default=False)
def main(workers, browser, stats):
    """Main execution demonstrating multi-threaded investigation."""

    # Prepare input data
    email_data = {
        "structured_email": {},
        "from_addr": "noreply@domainmalicious.com",
        "from_domain": "domainmalicious.com",
        "from_ip": "8.1.2.3",
        "body_urls": [
            {"url": "https://toto.domain.malicious.com", "score": 3, "link_malicious": True},
            {"url": "https://domain.com/ok/toto", "score": -1, "link_malicious": False},
        ],
        "attachments": [
            {
                "filename": "invoice.pdf",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "score": 10,
                "size": 1024,
            },
        ],
    }

    # Create tasks
    tasks = [EmailFrom(), EmailReciever(), BodiesUrlTask(), AttachmentTask(), AggregatedRiskTask(), AI()]

    # Execute tasks in parallel
    executor = RuleExecutor(max_workers=workers)
    cy = executor.run(tasks, email_data)

    # Finalize relationships
    cy.observable_finalize_relationships()
    cy._investigation._score_engine.recalculate_all()

    c = cy._investigation.get_check("email_risk_aggregated", "full")
    logger.info(c.comment)

    # Display results
    logger.info("Investigation complete - displaying summary")

    cy.display_summary()
    if stats:
        cy.display_statistics()
    cy.display_network(open_browser=browser)


if __name__ == "__main__":
    main()
