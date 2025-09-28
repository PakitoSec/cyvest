"""Build email report by collecting model fragments from worker threads and integrating on the main thread."""

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

# --------------------------- worker helpers ---------------------------


def _models_headers() -> list[Container]:
    header = Container("headers", scope=Scope.HEADER, description="Header inspection")

    header.contain(
        ResultCheck.create(
            "spf",
            scope=Scope.HEADER,
            description="SPF verification failed",
            details={"expected": "example.com", "observed": "mailer.badco.com"},
        )
    )
    header.contain(ResultCheck.create("dkim", scope=Scope.HEADER, description="DKIM signature missing"))
    header.contain(ResultCheck.create("dmarc", scope=Scope.HEADER, description="DMARC alignment passed"))
    header.contain(
        ResultCheck.create(
            "received_chain",
            scope=Scope.HEADER,
            description="Unexpected sending host",
            details={"reported_ip": "198.51.100.52"},
        )
    )

    return [header]


def _models_body() -> list[Container]:
    body = Container("body", scope=Scope.BODY, description="Body analysis")

    phishing = ResultCheck.create(
        "links",
        scope=Scope.BODY,
        description="Suspicious credential harvesting link",
        identifier="http://phish.badco.com/login",
    )
    phishing.add_observable_chain(
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
    body.contain(phishing)

    downloader = ResultCheck.create(
        "links",
        scope=Scope.BODY,
        description="Downloader prompting for credentials",
        identifier="http://update.badco.com/system",
    )
    redirect_chain = downloader.add_observable_chain(
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
    body.contain(downloader)

    effective = ResultCheck.create(
        "redirects",
        scope=Scope.BODY,
        description="Effective URL redirected to stage-two payload",
        identifier="http://update.badco.com/system",
        details={"effective_url": "https://updates.badco-cdn.com/agent.exe"},
    )
    effective_root = effective.add_observable_chain(
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
    redirect_chain.add_observable_children(effective_root)
    body.contain(effective)

    confirm = ResultCheck.create(
        "links",
        scope=Scope.BODY,
        description="Sandbox observed credential exfiltration",
        identifier="http://phish.badco.com/login",
    )
    confirm.add_observable_chain(
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
    body.contain(confirm)

    portal = ResultCheck.create(
        "links",
        scope=Scope.BODY,
        description="Link resolved to corporate portal",
        identifier="https://portal.example.com",
    )
    portal.add_observable_chain(
        [
            {
                "obs_type": ObsType.URL,
                "value": "https://portal.example.com",
                "intel": {"name": "allowlist_portal", "score": 0, "level": Level.SAFE},
            }
        ]
    )
    body.contain(portal)

    status = ResultCheck.create(
        "links",
        scope=Scope.BODY,
        description="Corporate status page",
        identifier="https://status.example.com",
    )
    status.add_observable_chain(
        [
            {
                "obs_type": ObsType.URL,
                "value": "https://status.example.com",
                "intel": {"name": "allowlist_status", "score": 0, "level": Level.SAFE},
            }
        ]
    )
    body.contain(status)

    return [body]


def _models_attachments() -> list[Container]:
    attachments = Container("attachments", scope=Scope.ATTACHMENT, description="Attachment analysis")

    pdf = Container("invoice.pdf", scope=Scope.ATTACHMENT, description="Embedded PDF")
    static_scan = ResultCheck.create(
        "static_scan", scope=Scope.ATTACHMENT, description="PDF contains embedded executable"
    )
    static_scan.add_observable_chain(
        [
            {
                "obs_type": ObsType.FILE,
                "value": "invoice.pdf",
                "intel": {"name": "pdf_scanner", "score": 5, "level": Level.SUSPICIOUS},
            }
        ]
    )
    pdf.contain(static_scan)

    sandbox = ResultCheck.create(
        "sandbox", scope=Scope.ATTACHMENT, description="Sandbox detonated PDF, spawned PowerShell"
    )
    sandbox.add_observable_chain(
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
    pdf.contain(sandbox)
    attachments.contain(pdf)

    zip_container = Container("logs.zip", scope=Scope.ATTACHMENT, description="Password-protected archive")
    zip_container.contain(
        ResultCheck.create("archive_password", scope=Scope.ATTACHMENT, description="Archive requires password")
    )
    attachments.contain(zip_container)

    return [attachments]


# ------------------------------- main flow ------------------------------


def build_report_using_collected_models() -> ReportBuilder:
    builder = ReportBuilder(graph=True)
    queue: Queue[list[Container]] = Queue()

    tasks: Iterable[Callable[[], list[Container]]] = (
        _models_headers,
        _models_body,
        _models_attachments,
    )

    threads = [threading.Thread(target=lambda fn=task: queue.put(fn())) for task in tasks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    while not queue.empty():
        builder.extend_existing(queue.get())

    return builder


def build_report():
    builder = build_report_using_collected_models()
    report = builder.build()

    enrich_target = report.json.setdefault("data", {}).setdefault("email", {})
    Enrichment(enrich_target, "recipient", {"first_name": "Alex", "last_name": "Morgan"}).accept(report)

    return report


def main() -> None:
    report = build_report()
    report.to_stdout_from_json(report.to_json())


if __name__ == "__main__":
    main()
