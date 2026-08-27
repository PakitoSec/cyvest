"""
The fetching boundary of ``extract_from_url``.

Everything here is about what enters the process: which URLs are dialled at all, how much of a
response is read, and whether a body that resists decoding still yields its observables.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator

import pytest

from cyvest.extract import extract_from_url

_BODY = b"contact evil@bad.com or 8.8.8.8 hxxp://phish[.]com"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output readable
        pass

    def do_GET(self) -> None:
        if self.path == "/unknown-charset":
            content_type, body = "text/plain; charset=quokka-9", _BODY
        elif self.path == "/undecodable":
            content_type, body = "text/plain; charset=utf-8", b"\xff\xfe " + _BODY
        elif self.path == "/large":
            content_type, body = "text/plain; charset=utf-8", b"a" * 5000
        else:
            content_type, body = "text/plain; charset=utf-8", _BODY

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server_url() -> Iterator[str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class TestScheme:
    """A caller may pass a URL it did not author, so the scheme is a trust boundary."""

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/feed", "127.0.0.1/feed"])
    def test_only_http_urls_are_dialled(self, url: str) -> None:
        with pytest.raises(ValueError, match="Refusing to fetch"):
            extract_from_url(url)

    def test_an_http_url_goes_through(self, server_url: str) -> None:
        assert extract_from_url(f"{server_url}/ok")


class TestDecoding:
    """
    Retrying ``response.read()`` after a failed decode returns ``b""`` — the stream is spent.

    A body that resisted the declared charset would then extract nothing at all, silently.
    """

    def test_an_unknown_charset_falls_back_instead_of_extracting_nothing(self, server_url: str) -> None:
        assert extract_from_url(f"{server_url}/unknown-charset")

    def test_undecodable_bytes_fall_back_instead_of_extracting_nothing(self, server_url: str) -> None:
        assert extract_from_url(f"{server_url}/undecodable")


class TestSize:
    def test_an_oversized_response_is_refused(self, server_url: str) -> None:
        with pytest.raises(ValueError, match="exceeds 1000 bytes"):
            extract_from_url(f"{server_url}/large", max_bytes=1000)

    def test_a_response_sitting_on_the_limit_is_accepted(self, server_url: str) -> None:
        extract_from_url(f"{server_url}/large", max_bytes=5000)
