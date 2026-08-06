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
from logurich import get_logger
from logurich.opt_click import click_logger_params

from cyvest import Cyvest
from cyvest.shared import SharedInvestigationContext

logger = get_logger(__name__)

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

    def _get_investigation_id(self) -> str:
        """Generate a deterministic investigation ID based on class name."""
        return f"fragment-{self.__class__.__name__.lower()}"

    def _get_investigation_name(self) -> str:
        """Generate a human-readable investigation name based on class name."""
        return self.__class__.__name__

    def _run(self, shared_context: SharedInvestigationContext) -> None:
        self.shared_context = shared_context
        with shared_context.create_cyvest(
            investigation_id=self._get_investigation_id(),
            investigation_name=self._get_investigation_name(),
        ) as cy:
            self.run(cy)

    @abstractmethod
    def run(self, cy: Cyvest) -> None:
        """
        Execute the task and return a Cyvest investigation fragment.

        Args:
            shared_context: Shared context for cross-task observable/finding sharing
                          (access data via cy.root().extra)

        Returns:
            Cyvest instance containing observables, findings, and tags
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
        main_cy = Cyvest(
            root_data=data,
            root_type=Cyvest.OBS.ARTIFACT,
            investigation_name="Email Investigation",
            investigation_id="cyvest-email-example",
        )
        shared = main_cy.shared_context()

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
        return main_cy


# ============================================================================
# Task Implementations
# ============================================================================


class EmailFrom(BaseRule):
    """
    Analyzes email headers (FROM, SENDER, TO, CC, BCC).

    Builds observable chain: EMAIL -> DOMAIN -> IPV4
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
            cy.observable(cy.OBS.EMAIL, from_addr)
            .with_ti("VT", 0, "> test")
            .relate_to(
                cy.observable(cy.OBS.DOMAIN, from_domain)
                .with_ti("VT", from_domain_score)
                .relate_to(
                    cy.observable(cy.OBS.IPV4, from_ip).with_ti("ABUSEIPDB", from_ip_score),
                    cy.REL.PIVOT,
                ),
                cy.REL.EXTRACTION,
            )
        )
        cy.root().relate_to(obs, cy.REL.EXTRACTION)

        # Create finding for header analysis
        cy.finding("from", "test email vt 10", "> ok boys").link_observable(obs).tagged("emails")

        logger.info(f"Email header analysis complete: {obs.key}")


class EmailFromBIS(BaseRule):
    """
    Analyzes email headers (FROM, SENDER, TO, CC, BCC).

    Builds observable chain: EMAIL -> DOMAIN -> IPV4
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
        obs = cy.observable(cy.OBS.EMAIL, from_addr).with_ti("PROOFPOINT", 5, "> test")

        # Create finding for header analysis
        (cy.finding("from-proofpoint", "test email vt 10", "> ok boys").link_observable(obs).tagged("emails"))

        logger.info(f"Email header analysis complete: {obs.key}")


class EmailReciever(BaseRule):
    """
    Analyzes email body content.

    Creates findings for body HTML content.
    """

    _scope = "body"
    order = 150

    def run(self, cy: Cyvest) -> None:
        """Analyze email body and build investigation fragment."""
        logger.info("Analyzing email receiver")

        cy.enrichment_create("receiver", {"receiver": ["ok"]}, context="from splunk")
        receiver = cy.observable(cy.OBS.EMAIL, "user@company.com")
        cy.root().relate_to(receiver, cy.REL.EXTRACTION)
        cy.finding("receiver", "description", "> receiver").with_score(0.1).link_observable(receiver).tagged(
            "emails"
        )

        logger.info("Email receiver analysis complete")

        return cy


class BodiesUrlTask(BaseRule):
    """
    Analyzes URLs found in email bodies.

    Similar to CortexBodiesURL - extracts URLs, performs threat intel findings,
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

        # Create tag for URL findings
        tag = cy.tag("bodies:urls", "Bodies URLs Analysis")
        body_obs = cy.observable(cy.OBS.FILE, "BODY/HTML")
        cy.root().relate_to(body_obs, cy.REL.EXTRACTION)

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
            url_obs = cy.observable(cy.OBS.URL, url).with_ti("VT", score)
            body_obs.relate_to(url_obs, cy.REL.EXTRACTION)
            if matching_domain:
                cy.observable(cy.OBS.DOMAIN, matching_domain).relate_to(url_obs, cy.REL.PIVOT)

            # Create finding and link to tag
            chk = (
                cy.finding(f"body-url-{url}", f"URL analysis {url}", comment=f"> score: {score}")
                .link_observable(url_obs)
                .tagged(tag)
            )

            logger.info("[bold red]Finding Score: %s[/bold red]", chk.score)

        logger.info(f"Bodies URLs analysis complete: {len(urls_with_scores)} URLs processed")
        logger.info("[bold red]Tag Score: %s[/bold red]", tag.get_aggregated_score())


class BodiesDomainTask(BaseRule):
    """
    Analyzes URLs found in email bodies.

    Similar to CortexBodiesURL - extracts URLs, performs threat intel findings,
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

        # Create tag for domain findings
        tag = cy.tag("bodies:domains", "Bodies Domains Analysis")
        body_obs = cy.observable(cy.OBS.FILE, "BODY/HTML")
        cy.root().relate_to(body_obs, cy.REL.EXTRACTION)

        # Analyze each domain
        for domain_data in domains_with_scores:
            domain = domain_data["domain"]
            score = domain_data["score"]

            logger.info(f"Analyzing domain: {domain} (score: {score})")

            # Build Domain observable with relationships
            domain_obs = cy.observable(cy.OBS.DOMAIN, domain).with_ti("VT", score)
            body_obs.relate_to(domain_obs, cy.REL.EXTRACTION)

            # Create finding and link to tag
            chk = (
                cy.finding(f"body-domain-{domain}", f"Domain analysis {domain}", comment=f"> score: {score}")
                .link_observable(domain_obs, propagation_mode=cy.PROP.GLOBAL)
                .tagged(tag)
            )

            logger.info("[bold red]Finding Score: %s[/bold red]", chk.score)

        logger.info(f"Bodies DOMAINS analysis complete: {len(domains_with_scores)} DOMAINS processed")
        logger.info("[bold red]Tag Score: %s[/bold red]", tag.get_aggregated_score())


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

        # Create tag for attachment findings
        tag = cy.tag("attachments", "Email Attachments Analysis")

        # Analyze each attachment
        for attachment in attachments:
            filename = attachment["filename"]
            md5_hash = attachment["md5"]
            sha256_hash = attachment["sha256"]
            score = attachment["score"]
            size = attachment.get("size", 0)

            logger.info(f"Analyzing attachment: {filename} (score: {score})")

            # Build file observable with hash observables
            file_obs = cy.observable(cy.OBS.FILE, filename)
            hash_obs = cy.observable(cy.OBS.HASH, f"MD5:{md5_hash}").with_ti(
                "VT", score, "MD5 hash analysis"
            )
            cy.root().relate_to(file_obs, cy.REL.EXTRACTION)
            hash_obs.relate_to(file_obs, cy.REL.EXTRACTION, direction=cy.DIR.INBOUND)

            # Add threat intel based on score
            if score >= 5:
                file_obs = file_obs.with_ti("MALWAREBAZAAR", score, f"Known malware: {filename}")

            # Create finding and link to tag
            finding_desc = f"File: {filename} ({size} bytes)"
            cy.finding(
                f"attachment-{filename}",
                finding_desc,
                comment=f"> MD5: {md5_hash}\n> SHA256: {sha256_hash}\n> Threat score: {score}",
            ).link_observable(file_obs).tagged(tag)

        logger.info(f"Attachments analysis complete: {len(attachments)} files processed")


class AggregatedRiskTask(BaseRule):
    """
    Aggregated risk assessment task.

    This task demonstrates creating an aggregated finding that:
    - References findings created by other tasks
    - References observables created by other tasks
    - Calculates a composite risk score based on multiple indicators
    - Uses shared context to access cross-task data

    This runs last (order=300) to ensure other tasks have completed.

    Note: Due to parallel execution, some tasks may still be running when this
    executes. The aggregated finding will use whatever data is available at the
    time it runs. For guaranteed sequential execution, use order values with
    larger gaps or run tasks sequentially.
    """

    _scope = "risk_assessment"
    order = 300

    def run(self, cy: Cyvest) -> None:
        """Calculate aggregated risk score based on all previous findings."""
        from decimal import Decimal

        logger.info("Starting aggregated risk assessment")

        # Access findings from other tasks using parameter-based API
        from_finding = self.shared_context.finding_get("from")
        receiver_finding = self.shared_context.finding_get("receiver")

        # Access observables from other tasks using parameter-based API
        sender_email = self.shared_context.observable_get(Cyvest.OBS.EMAIL, "noreply@domainmalicious.com")
        malicious_domain = self.shared_context.observable_get(Cyvest.OBS.DOMAIN, "domainmalicious.com")

        url_findings = self.shared_context.observables_list_by_type(Cyvest.OBS.URL)
        attachment_findings = self.shared_context.observables_list_by_type(Cyvest.OBS.FILE)

        # Calculate composite risk score
        risk_score = Decimal("0")
        risk_indicators = []

        # Factor 3: URL threats (medium weight)
        if url_findings:
            max_url_score = max((finding.score for finding in url_findings), default=Decimal("0"))
            if max_url_score > 0:
                risk_score += max_url_score * Decimal("0.2")  # 20% weight
                risk_indicators.append(f"Suspicious URLs detected (max score: {max_url_score})")

        # Factor 4: Attachment threats (high weight)
        if attachment_findings:
            max_attachment_score = max((finding.score for finding in attachment_findings), default=Decimal("0"))
            if max_attachment_score >= 5:
                risk_score += max_attachment_score * Decimal("0.5")  # 50% weight
                risk_indicators.append(f"Malicious attachment detected (score: {max_attachment_score})")

        # Build aggregated finding comment
        comment = "> **Aggregated Risk Assessment**\n"
        comment += f"> Total risk score: {risk_score}\n"
        comment += f"> Indicators analyzed: {len(risk_indicators)}\n"
        comment += ">\n"
        comment += "> **Risk Factors:**\n"
        for indicator in risk_indicators:
            comment += f"> - {indicator}\n"
        comment += ">\n"
        comment += "> **Component Analysis:**\n"
        comment += f"> - Header findings: {len([c for c in [from_finding, receiver_finding] if c])}\n"
        comment += f"> - URL findings: {len(url_findings)}\n"
        comment += f"> - Attachment findings: {len(attachment_findings)}\n"

        # Create aggregated finding
        aggregated_finding = cy.finding(
            "email_risk_aggregated", "Aggregated Email Risk Assessment", comment=comment
        ).with_score(risk_score)

        # Link all relevant observables to the aggregated finding
        if sender_email:
            aggregated_finding.link_observable(sender_email)
        if malicious_domain:
            aggregated_finding.link_observable(malicious_domain)

        # Put in a dedicated tag
        aggregated_finding.tagged(cy.tag("risk_assessment", "Aggregated Risk Analysis"))

        logger.info(f"Aggregated risk assessment complete: score={risk_score}")
        logger.info(f"Risk indicators: {len(risk_indicators)}")


class AI(BaseRule):
    _scope = "ai"
    order = 1000

    def run(self, cy: Cyvest) -> None:
        """Calculate aggregated risk score based on all previous findings."""
        cy.finding("ai", "AI Analysis", score=0, level=cy.LVL.MALICIOUS).tagged(
            cy.tag("risk_assessment:ai", "AI Analysis Tag")
        )


# ============================================================================
# Main Execution
# ============================================================================


@click.command()
@click_logger_params
@click.option("-w", "--workers", type=int, default=1)
@click.option("--browser", "browser", is_flag=True, default=False)
@click.option("--stats", "stats", is_flag=True, default=False)
@click.option("--audit", "audit", is_flag=True, default=False)
@click.option(
    "--no-audit-log",
    "no_audit_log",
    is_flag=True,
    default=False,
    help="Exclude audit log from JSON output for deterministic output",
)
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def main(workers, browser, stats, audit, no_audit_log, output):
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

    c = cy.finding_get("fnd:email_risk_aggregated")
    if c is not None:
        logger.info(c.comment)

    # Display results
    logger.info("Investigation complete - displaying summary - score should be 36.1")

    cy.display_summary(show_audit_log=audit)
    if stats:
        cy.display_statistics()
    cy.display_network(open_browser=browser)

    if output is not None:
        logger.info("[bold cyan]Generating json...[/bold cyan]")
        json_path = cy.io_save_json(output, include_audit_log=not no_audit_log)
        size_kb = Path(json_path).stat().st_size / 1024
        logger.info("[green]✓ Full json saved to: %s (%.2f KB)[/green]", json_path, size_kb)


if __name__ == "__main__":
    main()
