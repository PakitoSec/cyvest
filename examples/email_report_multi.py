"""Demonstrate combining builder-driven sections with prebuilt models from worker threads."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from queue import Queue

from cyvest import (
    Container,
    Enrichment,
    Level,
    ObsType,
    ReportBuilder,
    ResultCheck,
    Scope,
)


def _build_headers(builder: ReportBuilder) -> None:
    with builder.container("headers", scope=Scope.HEADER, description="Header inspection") as headers:
        headers.add_check(
            "spf",
            description="SPF verification failed",
            details={"expected": "example.com", "observed": "mailer.badco.com"},
        )
        headers.add_check("dkim", description="DKIM signature missing")
        headers.add_check("dmarc", description="DMARC alignment passed")
        headers.add_check(
            "received_chain",
            description="Unexpected sending host",
            details={"reported_ip": "198.51.100.52"},
        )


def _build_body(builder: ReportBuilder) -> None:
    with builder.container("body", scope=Scope.BODY, description="Body analysis") as body:
        phishing_check = body.add_check(
            "links",
            identifier="http://phish.badco.com/login",
            description="Suspicious credential harvesting link",
        )
        phishing_check.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "http://phish.badco.com/login",
                    "intel": {"name": "openphish_url", "score": 4, "level": Level.SUSPICIOUS},
                },
                {
                    "obs_type": ObsType.DOMAIN,
                    "value": "phish.badco.com",
                    "intel": {"name": "openphish_domain", "score": 4, "level": Level.SUSPICIOUS},
                },
            ]
        )

        downloader_check = body.add_check(
            "links",
            identifier="http://update.badco.com/system",
            description="Downloader prompting for credentials",
        )
        downloader_root = downloader_check.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "http://update.badco.com/system",
                    "intel": {"name": "redir_url", "score": 3, "level": Level.SUSPICIOUS},
                },
                {
                    "obs_type": ObsType.DOMAIN,
                    "value": "update.badco.com",
                    "intel": {"name": "redir_domain", "score": 3, "level": Level.SUSPICIOUS},
                },
            ]
        )

        redirects_check = body.add_check(
            "redirects",
            identifier="http://update.badco.com/system",
            description="Effective URL redirected to stage-two payload",
            details={"effective_url": "https://updates.badco-cdn.com/agent.exe"},
        )
        redirect_root = redirects_check.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "https://updates.badco-cdn.com/agent.exe",
                    "intel": {
                        "name": "redirector_url",
                        "score": 6,
                        "level": Level.MALICIOUS,
                        "extra": {"source": "redirect_follow"},
                    },
                },
                {
                    "obs_type": ObsType.DOMAIN,
                    "value": "updates.badco-cdn.com",
                    "intel": {"name": "redirector_domain", "score": 6, "level": Level.MALICIOUS},
                },
            ]
        )
        downloader_root.add_observable_children(redirect_root)

        malicious_confirmation = body.add_check(
            "links",
            identifier="http://phish.badco.com/login",
            description="Sandbox observed credential exfiltration",
        )
        malicious_confirmation.add_observable_chain(
            [
                {
                    "obs_type": ObsType.DOMAIN,
                    "value": "phish.badco.com",
                    "intel": {
                        "name": "sandbox_correlator",
                        "score": 9,
                        "level": Level.MALICIOUS,
                        "extra": {"campaign": "BazarLoader"},
                    },
                }
            ]
        )

        body.add_check(
            "links",
            identifier="https://portal.example.com",
            description="Link resolved to corporate portal",
        ).add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "https://portal.example.com",
                    "intel": {"name": "allowlist_portal", "score": 0, "level": Level.SAFE},
                }
            ]
        )

        body.add_check(
            "links",
            identifier="https://status.example.com",
            description="Corporate status page",
        ).add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "https://status.example.com",
                    "intel": {"name": "allowlist_status", "score": 0, "level": Level.SAFE},
                }
            ]
        )


def _build_attachments(builder: ReportBuilder) -> None:
    with builder.container("attachments", scope=Scope.ATTACHMENT, description="Attachment analysis") as attachments:
        with attachments.container("invoice.pdf", description="Embedded PDF") as pdf:
            pdf.add_check("static_scan", description="PDF contains embedded executable").add_observable_chain(
                [
                    {
                        "obs_type": ObsType.FILE,
                        "value": "invoice.pdf",
                        "intel": {"name": "pdf_scanner", "score": 5, "level": Level.SUSPICIOUS},
                    }
                ]
            )

            pdf.add_check("sandbox", description="Sandbox detonated PDF, spawned PowerShell").add_observable_chain(
                [
                    {
                        "obs_type": ObsType.URL,
                        "value": "http://cdn.badco.com/payload.exe",
                        "intel": {"name": "sandbox_url", "score": 10, "level": Level.MALICIOUS},
                    },
                    {
                        "obs_type": ObsType.DOMAIN,
                        "value": "cdn.badco.com",
                        "intel": {"name": "sandbox_domain", "score": 8, "level": Level.MALICIOUS},
                    },
                    {
                        "obs_type": ObsType.IP,
                        "value": "203.0.113.77",
                        "intel": {"name": "sandbox_ip", "score": 5, "level": Level.SUSPICIOUS},
                    },
                ]
            )

        with attachments.container("logs.zip", description="Password-protected archive") as zip_ctx:
            zip_ctx.add_check("archive_password", description="Archive requires password")


def _build_async_models() -> list[Container]:
    """Simulate a worker producing pre-built containers to hand off to the builder."""
    investigations = Container("async_findings", scope=Scope.BODY, description="Asynchronous intel")

    async_check = ResultCheck.create("ioc_sweep", scope=Scope.BODY, description="Async IOC sweep")
    async_check.add_observable_chain(
        [
            {
                "obs_type": ObsType.URL,
                "value": "http://async.badco.net/landing",
                "intel": {"name": "async_url", "score": 5, "level": Level.MALICIOUS},
            },
            {
                "obs_type": ObsType.DOMAIN,
                "value": "async.badco.net",
                "intel": {"name": "async_domain", "score": 4, "level": Level.SUSPICIOUS},
            },
        ]
    )
    investigations.contain(async_check)

    return [investigations]


def build_report_concurrently() -> ReportBuilder:
    builder = ReportBuilder(graph=True)
    queue: Queue[list[Container]] = Queue()

    def run_builder_task(task: Callable[[ReportBuilder], None]) -> None:
        task(builder)

    def run_model_task(task: Callable[[], list[Container]]) -> None:
        queue.put(task())

    builder_tasks: Iterable[Callable[[ReportBuilder], None]] = (
        _build_headers,
        _build_body,
        _build_attachments,
    )
    model_tasks: Iterable[Callable[[], list[Container]]] = (_build_async_models,)

    threads = [threading.Thread(target=run_builder_task, args=(task,)) for task in builder_tasks]
    model_threads = [threading.Thread(target=run_model_task, args=(task,)) for task in model_tasks]

    for thread in threads + model_threads:
        thread.start()
    for thread in threads + model_threads:
        thread.join()

    while not queue.empty():
        builder.extend_existing(queue.get())

    return builder


def build_report():
    builder = build_report_concurrently()
    report = builder.build()

    enrich_target = report.json.setdefault("data", {}).setdefault("email", {})
    Enrichment(enrich_target, "recipient", {"first_name": "Alex", "last_name": "Morgan"}).accept(report)

    return report


def main() -> None:
    report = build_report()
    report.to_stdout_from_json(report.to_json())


if __name__ == "__main__":
    main()
