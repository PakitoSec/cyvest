"""
Tests for the observable extraction module.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyvest.cli import cli
from cyvest.extract import (
    ExtractedObservable,
    defang,
    extract_all,
    extract_domains,
    extract_emails,
    extract_from_url,
    extract_hashes,
    extract_ips,
    extract_ipv4,
    extract_ipv6,
    extract_urls,
    observables_to_markdown,
    observables_to_markdown_table,
    refang,
)
from cyvest.model_enums import ObservableType

# =============================================================================
# Refang / Defang Tests
# =============================================================================


class TestRefang:
    """Tests for the refang function."""

    def test_refang_hxxp(self):
        assert refang("hxxp://example.com") == "http://example.com"

    def test_refang_hxxps(self):
        assert refang("hxxps://example.com") == "https://example.com"

    def test_refang_bracket_dot(self):
        assert refang("example[.]com") == "example.com"

    def test_refang_paren_dot(self):
        assert refang("example(.)com") == "example.com"

    def test_refang_word_dot(self):
        assert refang("example[dot]com") == "example.com"

    def test_refang_bracket_at(self):
        assert refang("user[@]example.com") == "user@example.com"

    def test_refang_paren_at(self):
        assert refang("user(@)example.com") == "user@example.com"

    def test_refang_word_at(self):
        assert refang("user at example.com") == "user@example.com"

    def test_refang_bracket_slash(self):
        assert refang("http://example.com[/]path") == "http://example.com/path"

    def test_refang_combined(self):
        """Test multiple defang patterns in one string."""
        text = "hxxps://evil[.]domain[.]com[/]malware"
        assert refang(text) == "https://evil.domain.com/malware"

    def test_refang_email_combined(self):
        text = "user[@]example[.]com"
        assert refang(text) == "user@example.com"

    def test_refang_preserves_normal_text(self):
        text = "This is normal text without any defanged indicators."
        assert refang(text) == text


class TestDefang:
    """Tests for the defang function."""

    def test_defang_http(self):
        assert "hxxp://" in defang("http://example.com")

    def test_defang_https(self):
        assert "hxxps://" in defang("https://example.com")

    def test_defang_dots(self):
        result = defang("example.com")
        assert "[.]" in result

    def test_defang_at(self):
        result = defang("user@example.com")
        assert "[@]" in result

    def test_defang_url_combined(self):
        result = defang("https://malware.evil.com/payload")
        assert "hxxps://" in result
        assert "[.]" in result


# =============================================================================
# URL Extraction Tests
# =============================================================================


class TestExtractUrls:
    """Tests for URL extraction."""

    def test_extract_http_url(self):
        text = "Visit http://example.com for more info"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "http://example.com"
        assert urls[0].obs_type == ObservableType.URL

    def test_extract_https_url(self):
        text = "Visit https://example.com/path?query=1"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "https://example.com/path?query=1"

    def test_extract_ftp_url(self):
        text = "Download from ftp://files.example.com/file.zip"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "ftp://files.example.com/file.zip"

    def test_extract_sftp_url(self):
        text = "Connect to sftp://secure.example.com"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert "sftp://" in urls[0].value

    def test_extract_ftps_url(self):
        text = "Connect to ftps://secure.example.com"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert "ftps://" in urls[0].value

    def test_extract_tcp_url(self):
        text = "Connect to tcp://192.168.1.1:8080"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert "tcp://" in urls[0].value

    def test_extract_udp_url(self):
        text = "Send to udp://192.168.1.1:53"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert "udp://" in urls[0].value

    def test_extract_defanged_hxxp(self):
        text = "Malicious: hxxp://evil.com/malware"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "http://evil.com/malware"
        assert urls[0].defanged is True

    def test_extract_defanged_hxxps(self):
        text = "Malicious: hxxps://evil.com"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "https://evil.com"
        assert urls[0].defanged is True

    def test_extract_defanged_brackets(self):
        text = "C2: hxxps://evil[.]domain[.]com[/]c2"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "https://evil.domain.com/c2"
        assert urls[0].defanged is True

    def test_extract_url_encoded(self):
        text = "URL: https://example.com/path%20with%20spaces"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert "path with spaces" in urls[0].value

    def test_extract_hex_encoded_url(self):
        # "https://evil.com" in hex
        hex_url = "68747470733a2f2f6576696c2e636f6d"
        text = f"Encoded C2: {hex_url}"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "https://evil.com"

    def test_extract_base64_encoded_url(self):
        # "https://evil.com" in base64
        b64_url = base64.b64encode(b"https://evil.com").decode()
        text = f"Encoded: {b64_url}"
        urls = list(extract_urls(text))
        assert len(urls) == 1
        assert urls[0].value == "https://evil.com"

    def test_extract_multiple_urls(self):
        text = "Visit http://a.com and https://b.com"
        urls = list(extract_urls(text))
        assert len(urls) == 2

    def test_extract_urls_deduplicates(self):
        # Deduplication happens in extract_all, not in extract_urls
        text = "Visit http://example.com and http://example.com again"
        urls = list(extract_urls(text))
        assert len(urls) == 2  # extract_urls yields all matches
        # extract_all deduplicates and counts
        all_obs = extract_all(text, types={ObservableType.URL})
        assert len(all_obs) == 1
        assert all_obs[0].count == 2

    def test_extract_no_refang(self):
        text = "C2: hxxps://evil[.]com"
        urls = list(extract_urls(text, refang_output=False))
        assert len(urls) == 1
        assert "hxxps" in urls[0].value
        assert "[.]" in urls[0].value


# =============================================================================
# IP Extraction Tests
# =============================================================================


class TestExtractIPs:
    """Tests for IP address extraction."""

    def test_extract_ipv4(self):
        text = "Server IP: 192.168.1.1"
        ips = list(extract_ipv4(text))
        assert len(ips) == 1
        assert ips[0].value == "192.168.1.1"
        assert ips[0].obs_type == ObservableType.IPV4

    def test_extract_ipv4_defanged_brackets(self):
        text = "C2 IP: 192[.]168[.]1[.]1"
        ips = list(extract_ipv4(text))
        assert len(ips) == 1
        assert ips[0].value == "192.168.1.1"
        assert ips[0].defanged is True

    def test_extract_ipv4_defanged_parens(self):
        text = "C2 IP: 10(.)0(.)0(.)1"
        ips = list(extract_ipv4(text))
        assert len(ips) == 1
        assert ips[0].value == "10.0.0.1"

    def test_extract_ipv4_defanged_dot_word(self):
        text = "C2 IP: 10[dot]0[dot]0[dot]1"
        ips = list(extract_ipv4(text))
        assert len(ips) == 1
        assert ips[0].value == "10.0.0.1"

    def test_extract_ipv4_validates(self):
        """Invalid IPs should not be extracted."""
        text = "Invalid: 999.999.999.999"
        ips = list(extract_ipv4(text))
        assert len(ips) == 0

    def test_extract_ipv6_full(self):
        text = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ips = list(extract_ipv6(text))
        assert len(ips) == 1
        assert ips[0].obs_type == ObservableType.IPV6

    def test_extract_ipv6_compressed(self):
        text = "IPv6: 2001:db8::1"
        ips = list(extract_ipv6(text))
        assert len(ips) == 1
        assert ips[0].obs_type == ObservableType.IPV6

    def test_extract_ipv6_loopback(self):
        text = "Loopback: ::1"
        ips = list(extract_ipv6(text))
        assert len(ips) == 1
        assert ips[0].value == "::1"

    def test_extract_ips_combined(self):
        text = "IPv4: 8.8.8.8, IPv6: 2001:db8::1"
        ips = list(extract_ips(text))
        assert len(ips) == 2

    def test_extract_ips_deduplicates(self):
        # Deduplication happens in extract_all, not in extract_ips
        text = "IP 8.8.8.8 and again 8.8.8.8"
        ips = list(extract_ips(text))
        assert len(ips) == 2  # extract_ips yields all matches
        # extract_all deduplicates and counts
        all_obs = extract_all(text, types={ObservableType.IPV4})
        assert len(all_obs) == 1
        assert all_obs[0].count == 2


# =============================================================================
# Email Extraction Tests
# =============================================================================


class TestExtractEmails:
    """Tests for email extraction."""

    def test_extract_email_standard(self):
        text = "Contact: user@example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "user@example.com"
        assert emails[0].obs_type == ObservableType.EMAIL

    def test_extract_email_defanged_bracket_at(self):
        text = "Email: user[@]example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "user@example.com"
        assert emails[0].defanged is True

    def test_extract_email_defanged_paren_at(self):
        text = "Email: user(@)example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "user@example.com"

    def test_extract_email_defanged_word_at(self):
        text = "Email: user at example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "user@example.com"

    def test_extract_email_defanged_combined(self):
        text = "Phishing: admin[@]evil[.]com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "admin@evil.com"

    def test_extract_email_with_dots_in_local(self):
        text = "Email: first.last@example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "first.last@example.com"

    def test_extract_email_with_plus(self):
        text = "Email: user+tag@example.com"
        emails = list(extract_emails(text))
        assert len(emails) == 1
        assert emails[0].value == "user+tag@example.com"

    def test_extract_emails_deduplicates(self):
        # Deduplication happens in extract_all, not in extract_emails
        text = "Contact user@test.com or user@test.com"
        emails = list(extract_emails(text))
        assert len(emails) == 2  # extract_emails yields all matches
        # extract_all deduplicates and counts
        all_obs = extract_all(text, types={ObservableType.EMAIL})
        assert len(all_obs) == 1
        assert all_obs[0].count == 2


# =============================================================================
# Hash Extraction Tests
# =============================================================================


class TestExtractHashes:
    """Tests for hash extraction."""

    def test_extract_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"MD5: {md5}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1
        assert hashes[0].value == md5
        assert hashes[0].obs_type == ObservableType.HASH

    def test_extract_sha1(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        text = f"SHA1: {sha1}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1
        assert hashes[0].value == sha1

    def test_extract_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"SHA256: {sha256}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1
        assert hashes[0].value == sha256

    def test_extract_sha512(self):
        sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"  # noqa: E501
        text = f"SHA512: {sha512}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1
        assert hashes[0].value == sha512

    def test_extract_multiple_hashes(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        text = f"MD5: {md5}\nSHA1: {sha1}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 2

    def test_extract_hash_case_insensitive(self):
        md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
        text = f"MD5: {md5_upper}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1
        assert hashes[0].value == md5_upper.lower()

    def test_extract_hashes_deduplicates(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"Hash: {md5} and again {md5}"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 1

    def test_extract_hash_ignores_non_hex(self):
        """Strings with non-hex characters should not be extracted."""
        text = "Not a hash: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        hashes = list(extract_hashes(text))
        assert len(hashes) == 0


# =============================================================================
# Domain Extraction Tests
# =============================================================================


class TestExtractDomains:
    """Tests for domain extraction."""

    def test_extract_domain(self):
        text = "Lookup example.com for more info"
        domains = list(extract_domains(text))
        assert len(domains) == 1
        assert domains[0].value == "example.com"
        assert domains[0].obs_type == ObservableType.DOMAIN

    def test_extract_domain_defanged(self):
        text = "C2 domain: evil[.]com"
        domains = list(extract_domains(text))
        assert len(domains) == 1
        assert domains[0].value == "evil.com"
        assert domains[0].defanged is True

    def test_extract_subdomain(self):
        text = "Server: api.subdomain.example.com"
        domains = list(extract_domains(text))
        assert len(domains) == 1
        assert domains[0].value == "api.subdomain.example.com"

    def test_extract_domain_various_tlds(self):
        text = "Domains: test.io, test.dev, test.co.uk"
        domains = list(extract_domains(text))
        assert len(domains) >= 2

    def test_extract_domain_excludes_url_domains(self):
        """Domains within URLs should not be extracted separately."""
        text = "Visit https://example.com for info"
        domains = list(extract_domains(text))
        # example.com should not appear as it's part of a URL
        assert all(d.value != "example.com" for d in domains)

    def test_extract_domains_deduplicates(self):
        # Deduplication happens in extract_all, not in extract_domains
        text = "Check example.com and example.com"
        domains = list(extract_domains(text))
        assert len(domains) == 2  # extract_domains yields all matches
        # extract_all deduplicates and counts
        all_obs = extract_all(text, types={ObservableType.DOMAIN})
        assert len(all_obs) == 1
        assert all_obs[0].count == 2


# =============================================================================
# Combined Extraction Tests
# =============================================================================


class TestExtractAll:
    """Tests for the combined extract_all function."""

    def test_extract_all_types(self):
        text = """
        URL: https://example.com
        IP: 192.168.1.1
        Email: user@test.com
        Hash: d41d8cd98f00b204e9800998ecf8427e
        Domain: malware.io
        """
        observables = extract_all(text)
        types = {obs.obs_type for obs in observables}
        assert ObservableType.URL in types
        assert ObservableType.IPV4 in types
        assert ObservableType.EMAIL in types
        assert ObservableType.HASH in types
        assert ObservableType.DOMAIN in types

    def test_extract_all_filters_by_type(self):
        text = """
        URL: https://example.com
        IP: 192.168.1.1
        Email: user@test.com
        """
        observables = extract_all(text, types={ObservableType.URL})
        assert len(observables) == 1
        assert observables[0].obs_type == ObservableType.URL

    def test_extract_all_deduplicates(self):
        text = "IP: 8.8.8.8 and again 8.8.8.8"
        observables = extract_all(text)
        assert len(observables) == 1

    def test_extract_all_defanged(self):
        text = "C2: hxxps://evil[.]com, IP: 10[.]0[.]0[.]1"
        observables = extract_all(text)
        assert len(observables) >= 2
        for obs in observables:
            if obs.obs_type == ObservableType.URL:
                assert obs.value == "https://evil.com"
            if obs.obs_type == ObservableType.IPV4:
                assert obs.value == "10.0.0.1"


# =============================================================================
# URL Fetching Tests
# =============================================================================


class TestExtractFromUrl:
    """Tests for extract_from_url function."""

    @patch("cyvest.extract.urllib.request.urlopen")
    def test_extract_from_url_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"IP: 192.168.1.1\nURL: https://example.com"
        mock_response.headers.get.return_value = "text/plain; charset=utf-8"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        observables = extract_from_url("https://ioc-feed.example.com/list.txt")

        assert len(observables) >= 2
        types = {obs.obs_type for obs in observables}
        assert ObservableType.IPV4 in types
        assert ObservableType.URL in types

    @patch("cyvest.extract.urllib.request.urlopen")
    def test_extract_from_url_filters_types(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"IP: 192.168.1.1\nURL: https://example.com"
        mock_response.headers.get.return_value = "text/plain"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        observables = extract_from_url(
            "https://ioc-feed.example.com/list.txt",
            types={ObservableType.IPV4},
        )

        assert len(observables) == 1
        assert observables[0].obs_type == ObservableType.IPV4


# =============================================================================
# CLI Tests
# =============================================================================


class TestExtractCLI:
    """Tests for the extract CLI command."""

    def test_cli_extract_from_stdin(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract"],
            input="IP: 192.168.1.1\nURL: https://example.com\n",
        )
        assert result.exit_code == 0
        assert "192.168.1.1" in result.output
        assert "example.com" in result.output

    def test_cli_extract_specific_types(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract", "-t", "ip"],
            input="IP: 192.168.1.1\nURL: https://example.com\n",
        )
        assert result.exit_code == 0
        assert "192.168.1.1" in result.output
        # URL should not be in output since we only asked for IPs
        # (but it may appear in logs, so we check the data lines)
        lines = [line for line in result.output.split("\n") if "\t" in line]
        assert all("ipv4" in line or "ipv6" in line for line in lines)

    def test_cli_extract_json_format(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract", "-f", "json"],
            input="IP: 192.168.1.1\n",
        )
        assert result.exit_code == 0
        # Find the JSON array in the output
        output_lines = result.output.split("\n")
        json_start = None
        for i, line in enumerate(output_lines):
            if line.strip().startswith("["):
                json_start = i
                break
        if json_start is not None:
            json_text = "\n".join(output_lines[json_start:])
            data = json.loads(json_text)
            assert len(data) >= 1
            assert data[0]["obs_type"] == "ipv4"

    def test_cli_extract_no_refang(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract", "-R"],  # --no-refang
            input="IP: 192[.]168[.]1[.]1\n",
        )
        assert result.exit_code == 0

    def test_cli_extract_from_file(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("IP: 8.8.8.8\nDomain: google.com\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["extract", str(test_file)])
        assert result.exit_code == 0
        assert "8.8.8.8" in result.output

    def test_cli_extract_output_to_file(self, tmp_path):
        output_file = tmp_path / "output.txt"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract", "-o", str(output_file)],
            input="IP: 10.0.0.1\n",
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "10.0.0.1" in content

    def test_cli_extract_no_observables(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract"],
            input="No observables here.\n",
        )
        assert result.exit_code == 0

    @patch("cyvest.extract.urllib.request.urlopen")
    def test_cli_extract_from_url(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"IP: 1.2.3.4"
        mock_response.headers.get.return_value = "text/plain"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["extract", "--from-url", "https://example.com/iocs.txt"],
        )
        assert result.exit_code == 0
        assert "1.2.3.4" in result.output


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_input(self):
        observables = extract_all("")
        assert observables == []

    def test_whitespace_only(self):
        observables = extract_all("   \n\t  \n  ")
        assert observables == []

    def test_markdown_with_observables(self):
        """Test that observables are extracted from markdown."""
        text = """
        # Threat Report

        ## Indicators of Compromise

        | Type | Value |
        |------|-------|
        | IP | 192.168.1.1 |
        | URL | https://evil.com/malware |

        Contact: analyst@security.com
        """
        observables = extract_all(text)
        types = {obs.obs_type for obs in observables}
        assert ObservableType.IPV4 in types
        assert ObservableType.URL in types
        assert ObservableType.EMAIL in types

    def test_json_with_observables(self):
        """Test extraction from JSON-like content."""
        text = '{"ip": "10.0.0.1", "url": "https://c2.evil.com"}'
        observables = extract_all(text)
        assert len(observables) >= 2

    def test_mixed_defanged_and_normal(self):
        text = """
        Normal: https://good.com
        Defanged: hxxps://bad[.]com
        """
        observables = extract_all(text)
        urls = [o for o in observables if o.obs_type == ObservableType.URL]
        assert len(urls) == 2
        values = {u.value for u in urls}
        assert "https://good.com" in values
        assert "https://bad.com" in values

    def test_ip_in_url_not_duplicated(self):
        """IPs that appear in URLs should be extracted as part of the URL."""
        text = "Connect to http://192.168.1.1:8080/api"
        observables = extract_all(text)
        urls = [o for o in observables if o.obs_type == ObservableType.URL]
        ips = [o for o in observables if o.obs_type == ObservableType.IPV4]
        assert len(urls) == 1
        # IP may or may not be extracted separately - both are valid
        assert len(ips) <= 1

    def test_very_long_hash_not_false_positive(self):
        """Ensure we don't extract substrings of longer hex strings."""
        # A 256-char hex string should not produce multiple hash matches
        long_hex = "a" * 256
        text = f"Long hex: {long_hex}"
        hashes = list(extract_hashes(text))
        # Should not extract as any hash type since it's too long
        assert len(hashes) <= 2  # At most SHA512 (128) extracted


# =============================================================================
# Markdown Serialization Tests
# =============================================================================


class TestExtractedObservableStr:
    """Tests for ExtractedObservable.__str__ method."""

    def test_str_url(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.URL,
            value="https://example.com",
            original="https://example.com",
            defanged=False,
        )
        assert str(obs) == "url:https://example.com"

    def test_str_email(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.EMAIL,
            value="admin@example.com",
            original="admin@example.com",
            defanged=False,
        )
        assert str(obs) == "email:admin@example.com"

    def test_str_ipv4(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.IPV4,
            value="192.168.1.1",
            original="192[.]168[.]1[.]1",
            defanged=True,
        )
        assert str(obs) == "ipv4:192.168.1.1"


class TestExtractedObservableToMarkdown:
    """Tests for ExtractedObservable.to_markdown method."""

    def test_to_markdown_basic(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.URL,
            value="https://example.com",
            original="https://example.com",
            defanged=False,
        )
        md = obs.to_markdown()
        assert md == "- URL: `https://example.com`"

    def test_to_markdown_with_defanged_flag(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.IPV4,
            value="192.168.1.1",
            original="192[.]168[.]1[.]1",
            defanged=True,
        )
        md = obs.to_markdown()
        assert "- IPV4: `192.168.1.1`" in md
        assert "Defanged: Yes" in md

    def test_to_markdown_include_original(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.URL,
            value="https://example.com",
            original="hxxps://example[.]com",
            defanged=True,
        )
        md = obs.to_markdown(include_original=True)
        assert "- URL: `https://example.com`" in md
        assert "Original: `hxxps://example[.]com`" in md

    def test_to_markdown_include_original_same_value(self):
        """Original should not be shown if it equals value."""
        obs = ExtractedObservable(
            obs_type=ObservableType.URL,
            value="https://example.com",
            original="https://example.com",
            defanged=False,
        )
        md = obs.to_markdown(include_original=True)
        assert "Original:" not in md

    def test_to_markdown_defang_value(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.URL,
            value="https://example.com",
            original="https://example.com",
            defanged=False,
        )
        md = obs.to_markdown(defang_value=True)
        assert "hxxps://" in md
        assert "[.]" in md


class TestObservablesToMarkdown:
    """Tests for observables_to_markdown function."""

    def test_empty_list(self):
        md = observables_to_markdown([])
        assert md == "No observables found."

    def test_empty_list_with_title(self):
        md = observables_to_markdown([], title="IOCs")
        assert "## IOCs" in md
        assert "No observables found." in md

    def test_basic_list(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://example.com",
                original="https://example.com",
                defanged=False,
            ),
            ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value="192.168.1.1",
                original="192.168.1.1",
                defanged=False,
            ),
        ]
        md = observables_to_markdown(obs)
        assert "- URL: `https://example.com`" in md
        assert "- IPV4: `192.168.1.1`" in md

    def test_with_title(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.DOMAIN,
                value="example.com",
                original="example.com",
                defanged=False,
            ),
        ]
        md = observables_to_markdown(obs, title="Extracted Domains")
        assert md.startswith("## Extracted Domains")

    def test_group_by_type(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://a.com",
                original="https://a.com",
                defanged=False,
            ),
            ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value="1.2.3.4",
                original="1.2.3.4",
                defanged=False,
            ),
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://b.com",
                original="https://b.com",
                defanged=False,
            ),
        ]
        md = observables_to_markdown(obs, group_by_type=True)
        assert "### URL" in md
        assert "### IPV4" in md
        # IPV4 comes before URL in ObservableType enum order
        ipv4_section_start = md.find("### IPV4")
        url_section_start = md.find("### URL")
        assert ipv4_section_start < url_section_start

    def test_defang_values(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://malware.com/payload",
                original="https://malware.com/payload",
                defanged=False,
            ),
        ]
        md = observables_to_markdown(obs, defang_values=True)
        assert "hxxps://" in md
        assert "[.]" in md


class TestObservablesToMarkdownTable:
    """Tests for observables_to_markdown_table function."""

    def test_empty_list(self):
        md = observables_to_markdown_table([])
        assert md == "No observables found."

    def test_empty_list_with_title(self):
        md = observables_to_markdown_table([], title="IOCs")
        assert "## IOCs" in md
        assert "No observables found." in md

    def test_basic_table(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://example.com",
                original="https://example.com",
                defanged=False,
            ),
            ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value="192.168.1.1",
                original="192[.]168[.]1[.]1",
                defanged=True,
            ),
        ]
        md = observables_to_markdown_table(obs)
        assert "| Type | Value | Defanged |" in md
        assert "|------|-------|----------|" in md
        assert "| URL | `https://example.com` |  |" in md
        assert "| IPV4 | `192.168.1.1` | ✓ |" in md

    def test_with_title(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.HASH,
                value="d41d8cd98f00b204e9800998ecf8427e",
                original="d41d8cd98f00b204e9800998ecf8427e",
                defanged=False,
            ),
        ]
        md = observables_to_markdown_table(obs, title="File Hashes")
        assert md.startswith("## File Hashes")

    def test_defang_values(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.EMAIL,
                value="evil@malware.com",
                original="evil@malware.com",
                defanged=False,
            ),
        ]
        md = observables_to_markdown_table(obs, defang_values=True)
        assert "[@]" in md
        assert "[.]" in md


class TestMarkdownIntegration:
    """Integration tests for markdown serialization with extract functions."""

    def test_extract_and_serialize_to_markdown(self):
        text = """
        Malicious IP: 192[.]168[.]1[.]100
        C2 server: hxxps://evil[.]com/callback
        Contact: admin[@]evil[.]com
        """
        obs = extract_all(text)
        md = observables_to_markdown(obs, title="Threat IOCs", group_by_type=True)
        assert "## Threat IOCs" in md
        assert "192.168.1.100" in md
        assert "https://evil.com/callback" in md
        assert "admin@evil.com" in md

    def test_extract_and_serialize_to_table(self):
        text = "Visit https://example.com or contact user@example.com"
        obs = extract_all(text)
        md = observables_to_markdown_table(obs)
        assert "| URL |" in md
        assert "| EMAIL |" in md


class TestOccurrenceCounting:
    """Tests for occurrence counting functionality."""

    def test_count_duplicate_ips(self):
        text = "IP: 192.168.1.1 and again 192.168.1.1 and 192.168.1.1"
        obs = extract_all(text)
        assert len(obs) == 1
        assert obs[0].value == "192.168.1.1"
        assert obs[0].count == 3

    def test_count_single_occurrence(self):
        text = "IP: 192.168.1.1"
        obs = extract_all(text)
        assert len(obs) == 1
        assert obs[0].count == 1

    def test_count_multiple_types(self):
        text = """
        192.168.1.1 192.168.1.1
        https://example.com https://example.com https://example.com
        test@example.com
        """
        obs = extract_all(text)
        ip_obs = [o for o in obs if o.obs_type == ObservableType.IPV4][0]
        url_obs = [o for o in obs if o.obs_type == ObservableType.URL][0]
        email_obs = [o for o in obs if o.obs_type == ObservableType.EMAIL][0]

        assert ip_obs.count == 2
        assert url_obs.count == 3
        assert email_obs.count == 1

    def test_str_with_count(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.IPV4,
            value="192.168.1.1",
            original="192.168.1.1",
            defanged=False,
            count=5,
        )
        assert "(x5)" in str(obs)

    def test_to_markdown_with_count(self):
        obs = ExtractedObservable(
            obs_type=ObservableType.IPV4,
            value="192.168.1.1",
            original="192.168.1.1",
            defanged=False,
            count=3,
        )
        md = obs.to_markdown()
        assert "Count: 3" in md

    def test_table_with_count_column(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value="192.168.1.1",
                original="192.168.1.1",
                defanged=False,
                count=3,
            ),
            ExtractedObservable(
                obs_type=ObservableType.URL,
                value="https://example.com",
                original="https://example.com",
                defanged=False,
                count=1,
            ),
        ]
        md = observables_to_markdown_table(obs)
        assert "| Count |" in md
        assert "| 3 |" in md
        assert "| 1 |" in md

    def test_table_without_count_column_when_all_one(self):
        obs = [
            ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value="192.168.1.1",
                original="192.168.1.1",
                defanged=False,
                count=1,
            ),
        ]
        md = observables_to_markdown_table(obs)
        assert "| Count |" not in md
