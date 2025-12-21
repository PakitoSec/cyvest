"""
Multi-threaded email investigation example.

Demonstrates using ThreadPoolExecutor to run investigation tasks in parallel,
with each task building a Cyvest fragment that merges into the main investigation.
"""

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click
from logurich import logger
from logurich.opt_click import click_logger_params

from cyvest import Cyvest
from cyvest.shared import SharedInvestigationContext

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

        main_inv = Investigation(data, root_type="artifact", investigation_name="Email Investigation")
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
        final_cy._investigation = main_inv
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
        from_addr = data.get("from_addr")["address"]
        from_domain = from_addr.split("@")[-1]
        from_domain_score = data.get("from_addr")["score"]
        from_ip = data.get("mx_ip")["ip"]
        from_ip_score = data.get("mx_ip")["score"]

        logger.info(f"Analyzing email header FROM: {from_addr}")

        # Build observable chain with threat intel
        obs = (
            cy.observable(cy.OBS.EMAIL_ADDR, from_addr)
            .relate_to(cy.root(), relationship_type=cy.REL.RELATED_TO, direction=cy.DIR.INBOUND)
            .relate_to(
                cy.observable(cy.OBS.DOMAIN_NAME, from_domain)
                .add_ti("VT", from_domain_score)
                .relate_to(
                    cy.observable(cy.OBS.IPV4_ADDR, from_ip).add_ti("ABUSEIPDB", from_ip_score),
                    cy.REL.RELATED_TO,
                    direction=cy.DIR.OUTBOUND,
                ),
                cy.REL.RELATED_TO,
                direction=cy.DIR.OUTBOUND,
            )
            .add_ti("VT", 0, "> test")
        )

        # Create check for header analysis
        (
            cy.check("from", "header", "test email vt 10", "> ok boys")
            .link_observable(obs)
            .in_container(cy.container("emails"))
        )

        logger.info(f"Email header analysis complete: {obs.key}")


class EmailFromBIS(BaseRule):
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
        from_addr = data.get("from_addr")["address"]
        logger.info(f"Analyzing email header FROM: {from_addr}")

        # Build observable chain with threat intel
        obs = cy.observable(cy.OBS.EMAIL_ADDR, from_addr).add_ti("PROOFPOINT", 5, "> test")

        # Create check for header analysis
        (
            cy.check("from-proofpoint", "header", "test email vt 10", "> ok boys")
            .link_observable(obs)
            .in_container(cy.container("emails"))
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
            cy.observable(cy.OBS.EMAIL_ADDR, "user@company.com").relate_to(
                cy.root(), cy.REL.RELATED_TO, direction=cy.DIR.INBOUND
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
        domains_with_scores = data.get("body_domains")
        all_domains = [d["domain"] for d in domains_with_scores]

        logger.info(f"Checking BODIES URLs: {len(urls_with_scores)}")

        # Create container for URL checks
        container = cy.container("bodies-urls", "Bodies URLs Analysis")

        # Analyze each URL
        for url_data in urls_with_scores:
            url = url_data["url"]
            score = url_data["score"]

            logger.info(f"Analyzing URL: {url} (score: {score})")

            # Build URL observable with relationships
            matching_domain = None
            for domain in all_domains:
                if domain in url:
                    matching_domain = domain
                    break
            url_obs = cy.observable(cy.OBS.URL, url).add_ti("VT", score)
            if matching_domain:
                url_obs.relate_to(
                    cy.observable(cy.OBS.DOMAIN_NAME, matching_domain),
                    cy.REL.RELATED_TO,
                    direction=cy.DIR.INBOUND,
                )

            # Create check and link to container
            chk = (
                cy.check(f"body-url-{url}", "body", f"URL analysis {url}", comment=f"> score: {score}")
                .link_observable(url_obs)
                .in_container(container)
            )

            logger.info("[bold red]Check Score: {}[/bold red]", chk.score)

        logger.info(f"Bodies URLs analysis complete: {len(urls_with_scores)} URLs processed")
        logger.info("[bold red]Container Score: {}[/bold red]", container.get_aggregated_score())


class BodiesDomainTask(BaseRule):
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
        domains_with_scores = data.get("body_domains")

        logger.info(f"Checking BODIES DOMAINS: {len(domains_with_scores)}")

        # Create container for domain checks
        container = cy.container("bodies-domains", "Bodies Domains Analysis")

        # Analyze each domain
        for domain_data in domains_with_scores:
            domain = domain_data["domain"]
            score = domain_data["score"]

            logger.info(f"Analyzing domain: {domain} (score: {score})")

            # Build Domain observable with relationships
            domain_obs = (
                cy.observable(cy.OBS.DOMAIN_NAME, domain)
                .add_ti("VT", score)
                .relate_to(
                    cy.observable(cy.OBS.FILE, "BODY/HTML").relate_to(
                        cy.root(), cy.REL.RELATED_TO, direction=cy.DIR.INBOUND
                    ),
                    cy.REL.RELATED_TO,
                    direction=cy.DIR.INBOUND,
                )
            )

            # Create check and link to container
            chk = (
                cy.check(f"body-domain-{domain}", "body", f"Domain analysis {domain}", comment=f"> score: {score}")
                .link_observable(domain_obs, propagation_mode=cy.PROP.GLOBAL)
                .in_container(container)
            )

            logger.info("[bold red]Check Score: {}[/bold red]", chk.score)

        logger.info(f"Bodies DOMAINS analysis complete: {len(domains_with_scores)} DOMAINS processed")
        logger.info("[bold red]Container Score: {}[/bold red]", container.get_aggregated_score())


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
                cy.observable(cy.OBS.FILE, filename)
                .relate_to(cy.root(), cy.REL.RELATED_TO, direction=cy.DIR.INBOUND)
                .relate_to(
                    cy.observable(cy.OBS.FILE, f"MD5:{md5_hash}").add_ti("VT", score, "MD5 hash analysis"),
                    cy.REL.RELATED_TO,
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
        from_check = self.shared_context.check_get("from", "header")
        receiver_check = self.shared_context.check_get("receiver", "header")

        # Access observables from other tasks using parameter-based API
        sender_email = self.shared_context.observable_get(Cyvest.OBS.EMAIL_ADDR, "noreply@domainmalicious.com")
        malicious_domain = self.shared_context.observable_get(Cyvest.OBS.DOMAIN_NAME, "domainmalicious.com")

        url_checks = self.shared_context.observables_list_by_type(Cyvest.OBS.URL)
        attachment_checks = self.shared_context.observables_list_by_type(Cyvest.OBS.FILE)

        # Calculate composite risk score
        risk_score = Decimal("0")
        risk_indicators = []

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
        cy.check("ai", "full", "ai", score=0, level=cy.LVL.MALICIOUS)


# ============================================================================
# Main Execution
# ============================================================================


@click.command()
@click_logger_params
@click.option("-w", "--workers", type=int, default=1)
@click.option("--browser", "browser", is_flag=True, default=False)
@click.option("--stats", "stats", is_flag=True, default=False)
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def main(workers, browser, stats, output):
    """Main execution demonstrating multi-threaded investigation."""

    # Prepare input data
    email_data = {
        "structured_email": {},
        "from_addr": {"address": "noreply@dmalicious.com", "score": 1},
        "mx_ip": {"ip": "8.1.2.3", "score": 2},
        "body_urls": [
            {"url": "https://virus.com/payload.exe", "score": 5},
            {"url": "https://virus.com/about", "score": 3},
            {"url": "https://domain.com/ok/toto", "score": -1},
        ],
        "body_domains": [
            {"domain": "virus.com", "score": 3},
            {"domain": "domain.com", "score": 0},
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
    tasks = [
        EmailFrom(),
        EmailFromBIS(),
        EmailReciever(),
        BodiesUrlTask(),
        BodiesDomainTask(),
        AttachmentTask(),
        AggregatedRiskTask(),
        AI(),
    ]

    # Execute tasks in parallel
    executor = RuleExecutor(max_workers=workers)
    cy = executor.run(tasks, email_data)

    # Finalize relationships
    cy.finalize_relationships()
    cy._investigation._score_engine.recalculate_all()

    c = cy.check_get("email_risk_aggregated", "full")
    if c is not None:
        logger.info(c.comment)

    # Display results
    logger.info("Investigation complete - displaying summary - score should be 36.1")

    cy.display_summary()
    if stats:
        cy.display_statistics()
    cy.display_network(open_browser=browser)

    if output is not None:
        logger.info("[bold cyan]Generating json...[/bold cyan]")
        json_path = cy.io_save_json(output)
        size_kb = Path(json_path).stat().st_size / 1024
        logger.info("[green]✓ Full json saved to: {} ({:.2f} KB)[/green]", json_path, size_kb)


if __name__ == "__main__":
    main()
