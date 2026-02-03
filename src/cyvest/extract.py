"""
Observable extraction module for Cyvest.

Provides functions to extract cyber observables (IPs, URLs, domains, emails, hashes)
from raw text, markdown, and web pages. Supports defanged indicators (hxxp://, [.], [@], etc.)
with automatic refanging.

Inspired by IOCExtract patterns but implemented using stdlib only.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import urllib.parse
import urllib.request
from collections.abc import Iterator

from pydantic import BaseModel, ConfigDict, Field

from cyvest.model_enums import ObservableType

# =============================================================================
# Pydantic Model
# =============================================================================


class ExtractedObservable(BaseModel):
    """Extracted observable with metadata."""

    model_config = ConfigDict(frozen=True)

    obs_type: ObservableType = Field(..., description="Type of the observable")
    value: str = Field(..., description="Normalized (refanged) value")
    original: str = Field(..., description="Original matched text")
    defanged: bool = Field(default=False, description="Whether the original was defanged")


# =============================================================================
# Defang / Refang Utilities
# =============================================================================

# Patterns for defanged indicators
_DEFANG_DOT_PATTERNS = [
    (r"\[\.\]", "."),
    (r"\(\.\)", "."),
    (r"\{\.\}", "."),
    (r"\[dot\]", "."),
    (r"\(dot\)", "."),
    (r"\{dot\}", "."),
    (r"\\.", "."),
]

_DEFANG_AT_PATTERNS = [
    (r"\[@\]", "@"),
    (r"\(@\)", "@"),
    (r"\{@\}", "@"),
    (r"\[at\]", "@"),
    (r"\(at\)", "@"),
    (r"\{at\}", "@"),
    (r"\s+at\s+", "@"),  # " at " -> "@" (removes surrounding spaces)
]

_DEFANG_SCHEME_PATTERNS = [
    (r"hxxps?", lambda m: m.group(0).replace("xx", "tt")),
    (r"fxp", "ftp"),
    (r"\[:\]//", "://"),
    (r":\[//\]", "://"),
    (r":\\\\", "://"),
    (r"\[:\/\/\]", "://"),
]

_DEFANG_SLASH_PATTERNS = [
    (r"\[/\]", "/"),
    (r"\(/\)", "/"),
]


def refang(text: str) -> str:
    """
    Convert defanged indicators to standard format.

    Handles common defang patterns like:
    - hxxp:// -> http://
    - [.] or (.) or [dot] -> .
    - [@] or (at) or " at " -> @
    - [/] -> /

    Args:
        text: Text containing potentially defanged indicators.

    Returns:
        Text with indicators refanged.
    """
    result = text

    # Refang schemes first
    for pattern, replacement in _DEFANG_SCHEME_PATTERNS:
        if callable(replacement):
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        else:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    # Refang dots
    for pattern, replacement in _DEFANG_DOT_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    # Refang at symbols
    for pattern, replacement in _DEFANG_AT_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    # Refang slashes
    for pattern, replacement in _DEFANG_SLASH_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    return result


def defang(text: str) -> str:
    """
    Convert indicators to defanged format for safe sharing.

    Applies common defanging:
    - http:// -> hxxp://
    - https:// -> hxxps://
    - . -> [.]
    - @ -> [@]

    Args:
        text: Text containing indicators to defang.

    Returns:
        Text with indicators defanged.
    """
    result = text

    # Defang schemes
    result = re.sub(r"https://", "hxxps://", result, flags=re.IGNORECASE)
    result = re.sub(r"http://", "hxxp://", result, flags=re.IGNORECASE)

    # Defang dots (but not in scheme)
    # We need to be careful not to double-defang
    if "hxxp" not in result.lower():
        result = result.replace(".", "[.]")
    else:
        # Split by scheme, defang the rest
        parts = re.split(r"(hxxps?://)", result, flags=re.IGNORECASE)
        defanged_parts = []
        for part in parts:
            if re.match(r"hxxps?://", part, re.IGNORECASE):
                defanged_parts.append(part)
            else:
                defanged_parts.append(part.replace(".", "[.]"))
        result = "".join(defanged_parts)

    # Defang @ in emails
    result = result.replace("@", "[@]")

    return result


def _is_defanged(text: str) -> bool:
    """Check if text contains defanged patterns."""
    defang_indicators = [
        r"\[\.\]",
        r"\(\.\)",
        r"\[dot\]",
        r"\(dot\)",
        r"\[@\]",
        r"\(@\)",
        r"\[at\]",
        r"\(at\)",
        r"\s+at\s+",
        r"hxxps?://",
        r"\[:\]//",
        r"\[/\]",
    ]
    for pattern in defang_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


# =============================================================================
# URL Patterns and Extraction
# =============================================================================

# Supported URL schemes
_URL_SCHEMES = r"(?:https?|ftp|ftps|sftp|tcp|udp)"
_DEFANGED_SCHEMES = r"(?:hxxps?|fxp)"

# URL pattern - matches both normal and defanged URLs
# The rest part allows defanged characters like [.], [/], etc.
_URL_PATTERN = re.compile(
    r"(?P<scheme>" + _URL_SCHEMES + r"|" + _DEFANGED_SCHEMES + r")"
    r"(?P<sep>://|\[:\]//|:\[//\]|:\\\\|\[:\/\/\])"
    r"(?P<rest>(?:[^\s\"'<>]|\[\.\]|\[/\]|\[dot\])+)",
    re.IGNORECASE,
)

# Hex-encoded URL pattern (e.g., 68747470733a2f2f... for https://)
_HEX_URL_PREFIXES = {
    "68747470733a2f2f": "https://",  # https://
    "687474703a2f2f": "http://",  # http://
    "6674703a2f2f": "ftp://",  # ftp://
}

# Base64 URL pattern
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decode_hex_url(hex_string: str) -> str | None:
    """Try to decode a hex-encoded URL."""
    try:
        decoded = bytes.fromhex(hex_string).decode("utf-8", errors="strict")
        # Check if it looks like a URL
        if re.match(r"^" + _URL_SCHEMES + r"://", decoded, re.IGNORECASE):
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def _decode_base64_url(b64_string: str) -> str | None:
    """Try to decode a base64-encoded URL."""
    try:
        # Add padding if needed
        padded = b64_string + "=" * (4 - len(b64_string) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
        # Check if it looks like a URL
        if re.match(r"^" + _URL_SCHEMES + r"://", decoded, re.IGNORECASE):
            return decoded
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        pass
    return None


def _decode_url_encoded(text: str) -> str:
    """Decode URL-encoded text."""
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


def extract_urls(text: str, refang_output: bool = True) -> Iterator[ExtractedObservable]:
    """
    Extract URLs from text.

    Supports:
    - Standard URLs (http, https, ftp, ftps, sftp, tcp, udp)
    - Defanged URLs (hxxp, hxxps, [.], etc.)
    - Hex-encoded URLs
    - URL-encoded URLs
    - Base64-encoded URLs

    Args:
        text: Text to extract URLs from.
        refang_output: Whether to refang extracted URLs.

    Yields:
        ExtractedObservable for each URL found.
    """
    seen: set[str] = set()

    # Extract standard and defanged URLs
    for match in _URL_PATTERN.finditer(text):
        original = match.group(0)
        # Clean up trailing punctuation
        original = re.sub(r"[.,;:!?)\"']+$", "", original)

        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

        # URL decode the value
        value = _decode_url_encoded(value)

        if value not in seen:
            seen.add(value)
            yield ExtractedObservable(
                obs_type=ObservableType.URL,
                value=value,
                original=original,
                defanged=defanged,
            )

    # Extract hex-encoded URLs
    hex_pattern = re.compile(r"\b([0-9a-fA-F]{14,})\b")
    for match in hex_pattern.finditer(text):
        hex_str = match.group(1)
        decoded = _decode_hex_url(hex_str)
        if decoded and decoded not in seen:
            seen.add(decoded)
            yield ExtractedObservable(
                obs_type=ObservableType.URL,
                value=decoded,
                original=hex_str,
                defanged=False,
            )

    # Extract base64-encoded URLs
    for match in _BASE64_PATTERN.finditer(text):
        b64_str = match.group(0)
        decoded = _decode_base64_url(b64_str)
        if decoded and decoded not in seen:
            seen.add(decoded)
            yield ExtractedObservable(
                obs_type=ObservableType.URL,
                value=decoded,
                original=b64_str,
                defanged=False,
            )


# =============================================================================
# IP Address Extraction
# =============================================================================

# IPv4 pattern (including defanged)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
_IPV4_SEP = r"(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\))"
_IPV4_PATTERN = re.compile(
    rf"\b{_IPV4_OCTET}{_IPV4_SEP}{_IPV4_OCTET}{_IPV4_SEP}{_IPV4_OCTET}{_IPV4_SEP}{_IPV4_OCTET}\b",
    re.IGNORECASE,
)

# IPv6 pattern (simplified - relies on ipaddress module for validation)
_IPV6_PATTERN = re.compile(
    r"(?:^|[^\w:])("
    # Full form
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    # Compressed form
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"::(?:[fF]{4}:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r")(?:[^\w:]|$)",
    re.IGNORECASE,
)


def _validate_ipv4(ip_str: str) -> bool:
    """Validate an IPv4 address using ipaddress module."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def _validate_ipv6(ip_str: str) -> bool:
    """Validate an IPv6 address using ipaddress module."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def extract_ipv4(text: str, refang_output: bool = True) -> Iterator[ExtractedObservable]:
    """
    Extract IPv4 addresses from text.

    Supports defanged formats like 192[.]168[.]1[.]1.

    Args:
        text: Text to extract IPs from.
        refang_output: Whether to refang extracted IPs.

    Yields:
        ExtractedObservable for each valid IPv4 found.
    """
    seen: set[str] = set()

    for match in _IPV4_PATTERN.finditer(text):
        original = match.group(0)
        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

        # Validate the IP
        if _validate_ipv4(value) and value not in seen:
            seen.add(value)
            yield ExtractedObservable(
                obs_type=ObservableType.IPV4,
                value=value,
                original=original,
                defanged=defanged,
            )


def extract_ipv6(text: str) -> Iterator[ExtractedObservable]:
    """
    Extract IPv6 addresses from text.

    Args:
        text: Text to extract IPs from.

    Yields:
        ExtractedObservable for each valid IPv6 found.
    """
    seen: set[str] = set()

    for match in _IPV6_PATTERN.finditer(text):
        original = match.group(1)

        # Validate the IP
        if _validate_ipv6(original) and original not in seen:
            seen.add(original)
            yield ExtractedObservable(
                obs_type=ObservableType.IPV6,
                value=original,
                original=original,
                defanged=False,
            )


def extract_ips(text: str, refang_output: bool = True) -> Iterator[ExtractedObservable]:
    """
    Extract all IP addresses (IPv4 and IPv6) from text.

    Args:
        text: Text to extract IPs from.
        refang_output: Whether to refang extracted IPs.

    Yields:
        ExtractedObservable for each valid IP found.
    """
    yield from extract_ipv4(text, refang_output)
    yield from extract_ipv6(text)


# =============================================================================
# Email Extraction
# =============================================================================

# Email pattern with defanged support
_EMAIL_LOCAL_PART = r"[a-zA-Z0-9._%+-]+"
_EMAIL_AT = r"(?:@|\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\})"
_EMAIL_AT_WORD = r"\s+at\s+"  # " at " with spaces
_EMAIL_DOMAIN_PART = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
_EMAIL_DOMAIN_SEP = r"(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\))"

# Two patterns: one for standard @ variants, one for " at " format
_EMAIL_PATTERN = re.compile(
    rf"\b({_EMAIL_LOCAL_PART}){_EMAIL_AT}({_EMAIL_DOMAIN_PART}(?:{_EMAIL_DOMAIN_SEP}{_EMAIL_DOMAIN_PART})+)\b",
    re.IGNORECASE,
)

_EMAIL_PATTERN_WORD_AT = re.compile(
    rf"\b({_EMAIL_LOCAL_PART}){_EMAIL_AT_WORD}({_EMAIL_DOMAIN_PART}(?:{_EMAIL_DOMAIN_SEP}{_EMAIL_DOMAIN_PART})+)\b",
    re.IGNORECASE,
)


def extract_emails(text: str, refang_output: bool = True) -> Iterator[ExtractedObservable]:
    """
    Extract email addresses from text.

    Supports defanged formats like:
    - user[@]example[.]com
    - user(at)example(dot)com
    - user at example dot com

    Args:
        text: Text to extract emails from.
        refang_output: Whether to refang extracted emails.

    Yields:
        ExtractedObservable for each email found.
    """
    seen: set[str] = set()

    # Match standard @ variants
    for match in _EMAIL_PATTERN.finditer(text):
        original = match.group(0)
        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

        if value not in seen:
            seen.add(value)
            yield ExtractedObservable(
                obs_type=ObservableType.EMAIL,
                value=value,
                original=original,
                defanged=defanged,
            )

    # Match " at " format (word-based)
    for match in _EMAIL_PATTERN_WORD_AT.finditer(text):
        original = match.group(0)
        defanged = True  # " at " format is always defanged
        value = refang(original) if refang_output else original

        if value not in seen:
            seen.add(value)
            yield ExtractedObservable(
                obs_type=ObservableType.EMAIL,
                value=value,
                original=original,
                defanged=defanged,
            )


# =============================================================================
# Hash Extraction
# =============================================================================

# Hash patterns by length
_MD5_PATTERN = re.compile(r"(?:^|[^a-fA-F0-9])([a-fA-F0-9]{32})(?:$|[^a-fA-F0-9])")
_SHA1_PATTERN = re.compile(r"(?:^|[^a-fA-F0-9])([a-fA-F0-9]{40})(?:$|[^a-fA-F0-9])")
_SHA256_PATTERN = re.compile(r"(?:^|[^a-fA-F0-9])([a-fA-F0-9]{64})(?:$|[^a-fA-F0-9])")
_SHA512_PATTERN = re.compile(r"(?:^|[^a-fA-F0-9])([a-fA-F0-9]{128})(?:$|[^a-fA-F0-9])")


def extract_hashes(text: str) -> Iterator[ExtractedObservable]:
    """
    Extract cryptographic hashes from text.

    Supports:
    - MD5 (32 hex characters)
    - SHA1 (40 hex characters)
    - SHA256 (64 hex characters)
    - SHA512 (128 hex characters)

    Args:
        text: Text to extract hashes from.

    Yields:
        ExtractedObservable for each hash found.
    """
    seen: set[str] = set()

    # Extract in order from longest to shortest to avoid substring matches
    for pattern in [_SHA512_PATTERN, _SHA256_PATTERN, _SHA1_PATTERN, _MD5_PATTERN]:
        for match in pattern.finditer(text):
            hash_value = match.group(1).lower()

            if hash_value not in seen:
                # Check it's not a substring of an already-found longer hash
                is_substring = False
                for existing in seen:
                    if hash_value in existing:
                        is_substring = True
                        break

                if not is_substring:
                    seen.add(hash_value)
                    yield ExtractedObservable(
                        obs_type=ObservableType.HASH,
                        value=hash_value,
                        original=match.group(1),
                        defanged=False,
                    )


# =============================================================================
# Domain Extraction
# =============================================================================

# TLD list (common TLDs - not exhaustive but covers most cases)
_COMMON_TLDS = (
    r"com|org|net|edu|gov|mil|int|"
    r"co|io|ai|app|dev|cloud|"
    r"uk|us|ca|au|de|fr|jp|cn|ru|br|in|"
    r"info|biz|name|pro|museum|"
    r"online|site|store|tech|xyz|"
    r"eu|asia|africa"
)

_DOMAIN_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
_DOMAIN_SEP = r"(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\))"

# Domain pattern - must end with a known TLD
_DOMAIN_PATTERN = re.compile(
    rf"\b({_DOMAIN_LABEL}(?:{_DOMAIN_SEP}{_DOMAIN_LABEL})*{_DOMAIN_SEP}(?:{_COMMON_TLDS}))\b",
    re.IGNORECASE,
)


def extract_domains(text: str, refang_output: bool = True) -> Iterator[ExtractedObservable]:
    """
    Extract domain names from text.

    Supports defanged formats like example[.]com.

    Note: This extracts standalone domains, not domains within URLs.
    Use extract_urls() for URLs.

    Args:
        text: Text to extract domains from.
        refang_output: Whether to refang extracted domains.

    Yields:
        ExtractedObservable for each domain found.
    """
    seen: set[str] = set()

    # First, find all URLs to exclude their domains
    url_domains: set[str] = set()
    for url_obs in extract_urls(text, refang_output=True):
        try:
            parsed = urllib.parse.urlparse(url_obs.value)
            if parsed.netloc:
                url_domains.add(parsed.netloc.lower())
        except Exception:
            pass

    for match in _DOMAIN_PATTERN.finditer(text):
        original = match.group(1)
        defanged = _is_defanged(original)
        value = refang(original).lower() if refang_output else original.lower()

        # Skip if this domain is part of a URL
        if value in url_domains:
            continue

        if value not in seen:
            seen.add(value)
            yield ExtractedObservable(
                obs_type=ObservableType.DOMAIN,
                value=value,
                original=original,
                defanged=defanged,
            )


# =============================================================================
# Combined Extraction
# =============================================================================


def extract_all(
    text: str,
    types: set[ObservableType] | None = None,
    refang_output: bool = True,
) -> list[ExtractedObservable]:
    """
    Extract all observables from text.

    Args:
        text: Text to extract observables from.
        types: Optional set of types to extract. If None, extracts all types.
        refang_output: Whether to refang extracted observables.

    Returns:
        Deduplicated list of extracted observables.
    """
    if types is None:
        types = {
            ObservableType.URL,
            ObservableType.IPV4,
            ObservableType.IPV6,
            ObservableType.EMAIL,
            ObservableType.HASH,
            ObservableType.DOMAIN,
        }

    results: list[ExtractedObservable] = []
    seen: set[tuple[ObservableType, str]] = set()

    if ObservableType.URL in types:
        for obs in extract_urls(text, refang_output):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    if ObservableType.IPV4 in types:
        for obs in extract_ipv4(text, refang_output):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    if ObservableType.IPV6 in types:
        for obs in extract_ipv6(text):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    if ObservableType.EMAIL in types:
        for obs in extract_emails(text, refang_output):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    if ObservableType.HASH in types:
        for obs in extract_hashes(text):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    if ObservableType.DOMAIN in types:
        for obs in extract_domains(text, refang_output):
            key = (obs.obs_type, obs.value)
            if key not in seen:
                seen.add(key)
                results.append(obs)

    return results


# =============================================================================
# URL Fetching
# =============================================================================


def extract_from_url(
    url: str,
    types: set[ObservableType] | None = None,
    refang_output: bool = True,
    timeout: int = 30,
) -> list[ExtractedObservable]:
    """
    Fetch content from a URL and extract observables.

    Args:
        url: URL to fetch content from.
        types: Optional set of types to extract. If None, extracts all types.
        refang_output: Whether to refang extracted observables.
        timeout: Request timeout in seconds.

    Returns:
        Deduplicated list of extracted observables.

    Raises:
        URLError: If the URL cannot be fetched.
        HTTPError: If the server returns an error response.
    """
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Cyvest/1.0; +https://github.com/PakitoSec/cyvest)"},
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        charset = "utf-8"

        # Try to extract charset from Content-Type
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip()

        try:
            text = response.read().decode(charset)
        except (UnicodeDecodeError, LookupError):
            text = response.read().decode("utf-8", errors="replace")

    return extract_all(text, types=types, refang_output=refang_output)
