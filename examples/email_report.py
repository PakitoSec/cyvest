"""Comprehensive example building a multi-layer investigation tree."""

from cyvest import (
    Enrichment,
    Level,
    ObsType,
    ReportBuilder,
    Scope,
)


def build_report():
    builder = ReportBuilder(graph=True)

    # Header analysis -----------------------------------------------------
    with builder.container("headers", scope=Scope.HEADER, description="Header inspection") as headers:
        headers.add_check(
            "spf",
            description="SPF verification failed",
            details={"expected": "example.com", "observed": "mailer.badco.com"},
        )
        headers.add_check("dkim", description="DKIM signature missing")
        headers.add_check("dmarc", description="DMARC alignment passed")
        headers.add_check(
            "received_chain", description="Unexpected sending host", details={"reported_ip": "198.51.100.52"}
        )

    # Body analysis -------------------------------------------------------
    link_observables = {}

    with builder.container("body", scope=Scope.BODY, description="Body analysis") as body:
        phishing_check = body.add_check(
            "links",
            identifier="http://phish.badco.com/login",
            description="Suspicious credential harvesting link",
        )
        root_phish = phishing_check.add_observable_chain(
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
        link_observables["http://phish.badco.com/login"] = root_phish

        downloader_check = body.add_check(
            "links",
            identifier="http://update.badco.com/system",
            description="Downloader prompting for credentials",
        )
        root_downloader = downloader_check.add_observable_chain(
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
        link_observables["http://update.badco.com/system"] = root_downloader

        effective_check = body.add_check(
            "redirects",
            identifier="http://update.badco.com/system",
            description="Effective URL redirected to stage-two payload",
            details={"effective_url": "https://updates.badco-cdn.com/agent.exe"},
        )
        effective_root = effective_check.add_observable_chain(
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
        parent_url = link_observables.get("http://update.badco.com/system")
        if parent_url is not None:
            parent_url.add_observable_children(effective_root)

        malicious_check = body.add_check(
            "links",
            identifier="http://phish.badco.com/login",
            description="Sandbox observed credential exfiltration",
        )
        malicious_check.add_observable_chain(
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

        safe_portal = body.add_check(
            "links",
            identifier="https://portal.example.com",
            description="Link resolved to corporate portal",
        )
        safe_portal.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "https://portal.example.com",
                    "intel": {"name": "allowlist_portal", "score": 0, "level": Level.SAFE},
                }
            ]
        )

        safe_status = body.add_check(
            "links",
            identifier="https://status.example.com",
            description="Corporate status page",
        )
        safe_status.add_observable_chain(
            [
                {
                    "obs_type": ObsType.URL,
                    "value": "https://status.example.com",
                    "intel": {"name": "allowlist_status", "score": 0, "level": Level.SAFE},
                }
            ]
        )

    # Attachment analysis -------------------------------------------------
    with builder.container("attachments", scope=Scope.ATTACHMENT, description="Attachment analysis") as attachments:
        with attachments.container("invoice.pdf", description="Embedded PDF") as pdf:
            static_check = pdf.add_check("static_scan", description="PDF contains embedded executable")
            static_check.add_observable_chain(
                [
                    {
                        "obs_type": ObsType.FILE,
                        "value": "invoice.pdf",
                        "intel": {"name": "pdf_scanner", "score": 5, "level": Level.SUSPICIOUS},
                    }
                ]
            )

            dynamic_check = pdf.add_check("sandbox", description="Sandbox detonated PDF, spawned PowerShell")
            dynamic_check.add_observable_chain(
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

    report = builder.build()

    # Add recipient enrichment to the report payload
    enrich_target = report.json.setdefault("data", {}).setdefault("email", {})
    Enrichment(enrich_target, "recipient", {"first_name": "Alex", "last_name": "Morgan"}).accept(report)

    return report


def main() -> None:
    report = build_report()
    json_data = report.to_json()

    print("\n========== Markdown Summary ==========")
    print(report.to_markdown_summary(json_data))

    print("\n========== Console View ==========")
    report.to_stdout_from_json(json_data)


if __name__ == "__main__":
    main()
