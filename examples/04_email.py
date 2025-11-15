"""
Multi-threaded email investigation example.

Demonstrates using ThreadPoolExecutor to run investigation tasks in parallel,
with each task building a Cyvest fragment that merges into the main investigation.

Key features:
- SharedInvestigationContext for thread-safe cross-task observable sharing
- Auto-reconcile pattern using context manager (with shared_context.create_cyvest())
- Tasks access data from root observable (cy.root().extra) instead of parameters
- Parallel execution with automatic merging of results
"""

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipType
from cyvest.investigation import SharedInvestigationContext

logger.enable("cyvest")


# ============================================================================
# Task Framework
# ============================================================================


class InvestigationTask(ABC):
    """
    Base class for investigation tasks.

    Each task runs independently (potentially in parallel) and returns a Cyvest
    investigation fragment that will be merged into the main investigation.
    """

    _deps: list[str] = []  # Task dependencies (for ordering)
    _scope: str = "general"  # Task scope (email, network, file, etc.)
    order: int = 100  # Execution order priority

    @abstractmethod
    def run(self, shared_context: SharedInvestigationContext) -> Cyvest:
        """
        Execute the task and return a Cyvest investigation fragment.

        Args:
            shared_context: Shared context for cross-task observable/check sharing
                          (access data via cy.root().extra)

        Returns:
            Cyvest instance containing observables, checks, and containers
        """
        pass


class TaskExecutor:
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

    def run(self, tasks: list[InvestigationTask], data: dict[str, Any]) -> Cyvest:
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
            future_to_task = {executor.submit(task.run, shared): task for task in sorted_tasks}

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


class EmailFrom(InvestigationTask):
    """
    Analyzes email headers (FROM, SENDER, TO, CC, BCC).

    Builds observable chain: EMAIL_ADDR -> DOMAIN_NAME -> IPV4_ADDR
    """

    _scope = "header"
    order = 100

    def run(self, shared_context: SharedInvestigationContext) -> Cyvest:
        """Analyze email headers and build investigation fragment."""
        # Use shared context to create Cyvest with auto-reconcile
        with shared_context.create_cyvest() as cy:
            # Extract header data from root observable
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

            return cy  # Auto-reconciles on context exit


class EmailReciever(InvestigationTask):
    """
    Analyzes email body content.

    Creates checks for body HTML content.
    """

    _scope = "body"
    order = 150

    def run(self, shared_context: SharedInvestigationContext) -> Cyvest:
        """Analyze email body and build investigation fragment."""
        with shared_context.create_cyvest() as cy:
            logger.info("Analyzing email receiver")

            cy.enrichment_create("receiver", {"receiver": ["ok"]}, context="from splunk")
            cy.check("receiver", "header", "description", "> receiver").with_score(0.1).link_observable(
                cy.observable(ObservableType.EMAIL_ADDR, "user@company.com").relate_to(
                    cy.root(), RelationshipType.TO, direction="inbound"
                )
            ).in_container(cy.container("emails"))

            logger.info("Email receiver analysis complete")

            return cy


class BodiesUrlTask(InvestigationTask):
    """
    Analyzes URLs found in email bodies.

    Similar to CortexBodiesURL - extracts URLs, performs threat intel checks,
    and builds observable relationships.
    """

    _deps = ["EMAIL-GSOC-WL", "PHISHME", "KNOWBE4", "SOSAFE", "PSAT"]
    _scope = "body"
    order = 200

    def run(self, shared_context: SharedInvestigationContext) -> Cyvest:
        """Analyze body URLs and build investigation fragment."""
        with shared_context.create_cyvest() as cy:
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
                # Try to get the domain from shared context (created by EmailFrom task)
                if link_malicious:
                    malicious_domain = shared_context.get_observable("domain-name:domainmalicious.com")
                    if malicious_domain:
                        logger.info(f"Linking URL {url} to shared malicious domain observable")
                        url_obs = url_obs.relate_to(
                            malicious_domain,
                            RelationshipType.RESOLVES_TO,
                        )
                    else:
                        # Fallback: create new domain observable
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
            return cy


class AttachmentTask(InvestigationTask):
    """
    Analyzes email attachments.

    Scans attached files for malware, extracts hashes, and performs threat intel lookups.
    """

    _deps = ["VT", "MALWAREBAZAAR", "ANYRUN"]
    _scope = "attachment"
    order = 250

    def run(self, shared_context: SharedInvestigationContext) -> Cyvest:
        """Analyze attachments and build investigation fragment."""
        with shared_context.create_cyvest() as cy:
            # Extract attachments from data (stored in root observable)
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

            return cy


# ============================================================================
# Main Execution
# ============================================================================


def main():
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
    tasks = [EmailFrom(), EmailReciever(), BodiesUrlTask(), AttachmentTask()]

    # Execute tasks in parallel
    executor = TaskExecutor(max_workers=4)
    cy = executor.run(tasks, email_data)

    # Finalize relationships
    cy.observable_finalize_relationships()

    # Display results
    logger.info("Investigation complete - displaying summary")

    cy.display_summary()
    
    cy.display_network()


if __name__ == "__main__":
    main()
