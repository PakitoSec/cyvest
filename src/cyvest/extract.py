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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from cyvest.model_enums import ObservableSubtype, ObservableType

# =============================================================================
# Pydantic Model
# =============================================================================


class ExtractedObservable(BaseModel):
    """Extracted observable with metadata."""

    model_config = ConfigDict(frozen=True)

    obs_type: ObservableType = Field(..., description="Type of the observable")
    subtype: ObservableSubtype | str | None = Field(default=None, description="Optional observable subtype")
    namespace: str | None = Field(default=None, description="Optional observable namespace")
    value: str = Field(..., description="Normalized (refanged) value")
    original: str = Field(..., description="Original matched text")
    defanged: bool = Field(default=False, description="Whether the original was defanged")
    count: int = Field(default=1, description="Number of times this observable was seen")

    def __str__(self) -> str:
        """Return a simple string representation for debugging."""
        if self.count > 1:
            return f"{self.obs_type.value}:{self.value} (x{self.count})"
        return f"{self.obs_type.value}:{self.value}"

    def to_markdown(
        self,
        *,
        include_original: bool = False,
        defang_value: bool = False,
    ) -> str:
        """
        Generate markdown representation of this extracted observable.

        Useful for providing structured data to LLM models.

        Args:
            include_original: Include original (pre-refanged) text if different from value.
            defang_value: Defang the value for safe sharing.

        Returns:
            Markdown formatted string as a list item.
        """
        # Use defang function defined later in this module
        display_value = defang(self.value) if defang_value else self.value
        lines = [f"- {self.obs_type.value.upper()}: `{display_value}`"]

        if self.defanged:
            lines.append("  - Defanged: Yes")

        if self.count > 1:
            lines.append(f"  - Count: {self.count}")

        if include_original and self.original != self.value:
            lines.append(f"  - Original: `{self.original}`")

        return "\n".join(lines)


# =============================================================================
# Custom Extraction Patterns
# =============================================================================

_CUSTOM_VALUE_GROUP = "value"


def _normalize_subtype(subtype: ObservableSubtype | str | None) -> ObservableSubtype | str | None:
    """Normalize a subtype value the same way the Observable model does."""
    if subtype is None or isinstance(subtype, ObservableSubtype):
        return subtype
    normalized = str(subtype).strip().lower()
    if not normalized:
        return None
    try:
        return ObservableSubtype(normalized)
    except ValueError:
        return normalized


def _normalize_namespace(namespace: str | None) -> str | None:
    """Normalize a namespace value the same way the Observable model does."""
    if namespace is None:
        return None
    normalized = str(namespace).strip()
    return normalized or None


def _subtype_value(subtype: ObservableSubtype | str | None) -> str | None:
    """Return the string value for a subtype."""
    if isinstance(subtype, ObservableSubtype):
        return subtype.value
    return subtype


def _validate_pattern_identity(
    obs_type: ObservableType,
    subtype: ObservableSubtype | str | None,
    namespace: str | None,
) -> None:
    """Validate custom pattern identity metadata against Observable rules."""
    subtype_value = _subtype_value(subtype)
    allowed_subtypes = {
        ObservableType.USER: {
            ObservableSubtype.USER_EMAIL.value,
            ObservableSubtype.USER_SID.value,
            ObservableSubtype.USER_UPN.value,
            ObservableSubtype.USER_OKTA_ID.value,
            ObservableSubtype.USER_USERNAME.value,
            ObservableSubtype.USER_UID.value,
        },
        ObservableType.HOST: {
            ObservableSubtype.HOST_HOSTNAME.value,
            ObservableSubtype.HOST_FQDN.value,
            ObservableSubtype.HOST_NETBIOS.value,
            ObservableSubtype.HOST_DEVICE_ID.value,
        },
        ObservableType.PROCESS: {
            ObservableSubtype.PROCESS_PID.value,
            ObservableSubtype.PROCESS_GUID.value,
        },
        ObservableType.FILE: {ObservableSubtype.FILE_PATH.value},
        ObservableType.CLOUD_RESOURCE: {
            ObservableSubtype.CLOUD_AWS_ARN.value,
            ObservableSubtype.CLOUD_AZURE_RESOURCE_ID.value,
            ObservableSubtype.CLOUD_GCP_RESOURCE_NAME.value,
        },
    }
    subtype_required = {
        ObservableType.USER,
        ObservableType.HOST,
        ObservableType.PROCESS,
        ObservableType.CLOUD_RESOURCE,
    }
    if obs_type in subtype_required and not subtype_value:
        raise ValueError(f"Observable type '{obs_type.value}' requires a subtype")
    if obs_type == ObservableType.COMMAND_LINE and subtype_value is not None:
        raise ValueError("COMMAND_LINE observables do not accept a subtype")
    if isinstance(subtype, ObservableSubtype) and subtype_value not in allowed_subtypes.get(obs_type, set()):
        raise ValueError(f"Subtype '{subtype_value}' is not valid for observable type '{obs_type.value}'")

    namespace_required = {
        (ObservableType.USER, ObservableSubtype.USER_OKTA_ID.value),
        (ObservableType.USER, ObservableSubtype.USER_USERNAME.value),
        (ObservableType.USER, ObservableSubtype.USER_UID.value),
        (ObservableType.HOST, ObservableSubtype.HOST_HOSTNAME.value),
        (ObservableType.HOST, ObservableSubtype.HOST_NETBIOS.value),
        (ObservableType.HOST, ObservableSubtype.HOST_DEVICE_ID.value),
        (ObservableType.PROCESS, ObservableSubtype.PROCESS_PID.value),
        (ObservableType.FILE, ObservableSubtype.FILE_PATH.value),
    }
    if (obs_type, subtype_value) in namespace_required and not namespace:
        raise ValueError(f"Observable {obs_type.value}/{subtype_value} requires a namespace")


@dataclass(frozen=True)
class ExtractionPattern:
    """
    Regex-backed custom extraction pattern.

    The pattern must include a named ``value`` group. For example:
    ``r"user=(?P<value>[A-Za-z0-9._-]+)"``.
    """

    name: str
    obs_type: ObservableType | str
    pattern: str | re.Pattern[str]
    subtype: ObservableSubtype | str | None = None
    namespace: str | None = None
    flags: int = re.IGNORECASE
    normalize: Callable[[str], str] | None = None
    compiled_pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()
        if not normalized_name:
            raise ValueError("Extraction pattern name must not be empty")

        try:
            if isinstance(self.obs_type, ObservableType):
                obs_type = self.obs_type
            else:
                obs_type = ObservableType(str(self.obs_type).lower())
        except ValueError as exc:
            raise ValueError(f"Unknown observable type: {self.obs_type}") from exc

        subtype = _normalize_subtype(self.subtype)
        namespace = _normalize_namespace(self.namespace)
        _validate_pattern_identity(obs_type, subtype, namespace)

        if isinstance(self.pattern, re.Pattern):
            compiled_pattern = self.pattern
        else:
            compiled_pattern = re.compile(self.pattern, self.flags)
        if _CUSTOM_VALUE_GROUP not in compiled_pattern.groupindex:
            raise ValueError("Extraction pattern must define a named 'value' group")

        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "obs_type", obs_type)
        object.__setattr__(self, "subtype", subtype)
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "compiled_pattern", compiled_pattern)


_REGISTERED_EXTRACTION_PATTERNS: dict[str, ExtractionPattern] = {}


def register_extraction_pattern(pattern: ExtractionPattern, *, replace: bool = False) -> None:
    """
    Register a global custom extraction pattern.

    Registered patterns participate in ``extract_all`` and ``extract_from_url`` by default.

    Args:
        pattern: Pattern to register.
        replace: Replace an existing pattern with the same name.

    Raises:
        ValueError: If a pattern with the same name already exists and replace is False.
    """
    if pattern.name in _REGISTERED_EXTRACTION_PATTERNS and not replace:
        raise ValueError(f"Extraction pattern already registered: {pattern.name}")
    _REGISTERED_EXTRACTION_PATTERNS[pattern.name] = pattern


def unregister_extraction_pattern(name: str) -> None:
    """
    Unregister a global custom extraction pattern.

    Args:
        name: Registered pattern name.

    Raises:
        KeyError: If no pattern with the given name is registered.
    """
    del _REGISTERED_EXTRACTION_PATTERNS[name]


def clear_extraction_patterns() -> None:
    """Remove all globally registered custom extraction patterns."""
    _REGISTERED_EXTRACTION_PATTERNS.clear()


def get_extraction_patterns() -> tuple[ExtractionPattern, ...]:
    """Return globally registered custom extraction patterns."""
    return tuple(_REGISTERED_EXTRACTION_PATTERNS.values())


def extract_custom(
    text: str,
    patterns: Iterable[ExtractionPattern],
    refang_output: bool = True,
) -> Iterator[ExtractedObservable]:
    """
    Extract observables using custom registered or per-call patterns.

    Args:
        text: Text to extract observables from.
        patterns: Custom extraction patterns.
        refang_output: Whether to refang extracted values.

    Yields:
        ExtractedObservable for each custom pattern match.
    """
    for extraction_pattern in patterns:
        for match in extraction_pattern.compiled_pattern.finditer(text):
            original = match.group(_CUSTOM_VALUE_GROUP)
            value = original.strip()
            defanged = _is_defanged(original)
            if refang_output:
                value = refang(value)
            if extraction_pattern.normalize is not None:
                value = extraction_pattern.normalize(value)
            if not value:
                continue

            yield ExtractedObservable(
                obs_type=extraction_pattern.obs_type,
                subtype=extraction_pattern.subtype,
                namespace=extraction_pattern.namespace,
                value=value,
                original=original,
                defanged=defanged,
            )


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
    # Extract standard and defanged URLs
    for match in _URL_PATTERN.finditer(text):
        original = match.group(0)
        # Clean up trailing punctuation
        original = re.sub(r"[.,;:!?)\"']+$", "", original)

        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

        # URL decode the value
        value = _decode_url_encoded(value)

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
        if decoded:
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
        if decoded:
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
    for match in _IPV4_PATTERN.finditer(text):
        original = match.group(0)
        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

        # Validate the IP
        if _validate_ipv4(value):
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
    for match in _IPV6_PATTERN.finditer(text):
        original = match.group(1)

        # Validate the IP
        if _validate_ipv6(original):
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
    # Match standard @ variants
    for match in _EMAIL_PATTERN.finditer(text):
        original = match.group(0)
        defanged = _is_defanged(original)
        value = refang(original) if refang_output else original

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

            # Finding it's not a substring of an already-found longer hash
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
    extraction_patterns: Iterable[ExtractionPattern] | None = None,
    include_registered_patterns: bool = True,
) -> list[ExtractedObservable]:
    """
    Extract all observables from text.

    Args:
        text: Text to extract observables from.
        types: Optional set of types to extract. If None, extracts all types.
        refang_output: Whether to refang extracted observables.
        extraction_patterns: Optional per-call custom extraction patterns.
        include_registered_patterns: Include globally registered extraction patterns.

    Returns:
        Deduplicated list of extracted observables with occurrence counts.
    """
    custom_patterns: list[ExtractionPattern] = []
    if include_registered_patterns:
        custom_patterns.extend(get_extraction_patterns())
    if extraction_patterns is not None:
        custom_patterns.extend(extraction_patterns)

    if types is None:
        types = {
            ObservableType.URL,
            ObservableType.IPV4,
            ObservableType.IPV6,
            ObservableType.EMAIL,
            ObservableType.HASH,
            ObservableType.DOMAIN,
        }
        types.update(pattern.obs_type for pattern in custom_patterns)

    # Track counts per observable
    counts: dict[tuple[ObservableType, str | None, str | None, str], int] = {}
    # Store first occurrence of each observable (for original/defanged info)
    first_seen: dict[tuple[ObservableType, str | None, str | None, str], ExtractedObservable] = {}

    def _process_obs(obs: ExtractedObservable) -> None:
        subtype = obs.subtype.value if isinstance(obs.subtype, ObservableSubtype) else obs.subtype
        key = (obs.obs_type, subtype, obs.namespace, obs.value)
        if key in counts:
            counts[key] += 1
        else:
            counts[key] = 1
            first_seen[key] = obs

    if ObservableType.URL in types:
        for obs in extract_urls(text, refang_output):
            _process_obs(obs)

    if ObservableType.IPV4 in types:
        for obs in extract_ipv4(text, refang_output):
            _process_obs(obs)

    if ObservableType.IPV6 in types:
        for obs in extract_ipv6(text):
            _process_obs(obs)

    if ObservableType.EMAIL in types:
        for obs in extract_emails(text, refang_output):
            _process_obs(obs)

    if ObservableType.HASH in types:
        for obs in extract_hashes(text):
            _process_obs(obs)

    if ObservableType.DOMAIN in types:
        for obs in extract_domains(text, refang_output):
            _process_obs(obs)

    for obs in extract_custom(
        text,
        (pattern for pattern in custom_patterns if pattern.obs_type in types),
        refang_output,
    ):
        _process_obs(obs)

    # Build results with counts
    results: list[ExtractedObservable] = []
    for key, obs in first_seen.items():
        results.append(
            ExtractedObservable(
                obs_type=obs.obs_type,
                subtype=obs.subtype,
                namespace=obs.namespace,
                value=obs.value,
                original=obs.original,
                defanged=obs.defanged,
                count=counts[key],
            )
        )

    return results


# =============================================================================
# URL Fetching
# =============================================================================


def extract_from_url(
    url: str,
    types: set[ObservableType] | None = None,
    refang_output: bool = True,
    timeout: int = 30,
    extraction_patterns: Iterable[ExtractionPattern] | None = None,
    include_registered_patterns: bool = True,
) -> list[ExtractedObservable]:
    """
    Fetch content from a URL and extract observables.

    Args:
        url: URL to fetch content from.
        types: Optional set of types to extract. If None, extracts all types.
        refang_output: Whether to refang extracted observables.
        timeout: Request timeout in seconds.
        extraction_patterns: Optional per-call custom extraction patterns.
        include_registered_patterns: Include globally registered extraction patterns.

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

    return extract_all(
        text,
        types=types,
        refang_output=refang_output,
        extraction_patterns=extraction_patterns,
        include_registered_patterns=include_registered_patterns,
    )


# =============================================================================
# Markdown Serialization
# =============================================================================


def observables_to_markdown(
    observables: list[ExtractedObservable],
    *,
    include_original: bool = False,
    group_by_type: bool = False,
    title: str | None = None,
    defang_values: bool = False,
) -> str:
    """
    Generate markdown report for a list of extracted observables.

    Useful for providing structured data to LLM models.

    Args:
        observables: List of extracted observables.
        include_original: Include original text for each observable.
        group_by_type: Group observables by type with sub-headers.
        title: Optional title header (rendered as ## Title).
        defang_values: Defang all values for safe sharing.

    Returns:
        Markdown formatted string.

    Example:
        >>> obs = extract_all("Contact admin@example.com or visit https://example.com")
        >>> print(observables_to_markdown(obs, title="Extracted IOCs"))
        ## Extracted IOCs

        - **URL:** `https://example.com`
        - **EMAIL:** `admin@example.com`
    """
    if not observables:
        if title:
            return f"## {title}\n\nNo observables found."
        return "No observables found."

    lines: list[str] = []

    if title:
        lines.append(f"## {title}")
        lines.append("")

    if group_by_type:
        from collections import defaultdict

        by_type: dict[ObservableType, list[ExtractedObservable]] = defaultdict(list)
        for obs in observables:
            by_type[obs.obs_type].append(obs)

        for obs_type in ObservableType:
            if obs_type in by_type:
                lines.append(f"### {obs_type.value.upper()}")
                lines.append("")
                for obs in by_type[obs_type]:
                    lines.append(
                        obs.to_markdown(
                            include_original=include_original,
                            defang_value=defang_values,
                        )
                    )
                lines.append("")
    else:
        for obs in observables:
            lines.append(
                obs.to_markdown(
                    include_original=include_original,
                    defang_value=defang_values,
                )
            )

    return "\n".join(lines).rstrip()


def observables_to_markdown_table(
    observables: list[ExtractedObservable],
    *,
    title: str | None = None,
    defang_values: bool = False,
) -> str:
    """
    Generate a compact markdown table of extracted observables.

    Useful for quick summaries when providing data to LLM models.

    Args:
        observables: List of extracted observables.
        title: Optional title header (rendered as ## Title).
        defang_values: Defang all values for safe sharing.

    Returns:
        Markdown table formatted string.

    Example:
        >>> obs = extract_all("IP: 192.168.1.1, Hash: d41d8cd98f00b204e9800998ecf8427e")
        >>> print(observables_to_markdown_table(obs))
        | Type | Value | Defanged |
        |------|-------|----------|
        | IPV4 | `192.168.1.1` |  |
        | HASH | `d41d8cd98f00b204e9800998ecf8427e` |  |
    """
    if not observables:
        if title:
            return f"## {title}\n\nNo observables found."
        return "No observables found."

    lines: list[str] = []

    if title:
        lines.append(f"## {title}")
        lines.append("")

    # Check if any observable has count > 1
    show_count = any(obs.count > 1 for obs in observables)

    if show_count:
        lines.append("| Type | Value | Count | Defanged |")
        lines.append("|------|-------|-------|----------|")
    else:
        lines.append("| Type | Value | Defanged |")
        lines.append("|------|-------|----------|")

    for obs in observables:
        display_value = defang(obs.value) if defang_values else obs.value
        defanged_mark = "✓" if obs.defanged else ""
        if show_count:
            lines.append(f"| {obs.obs_type.value.upper()} | `{display_value}` | {obs.count} | {defanged_mark} |")
        else:
            lines.append(f"| {obs.obs_type.value.upper()} | `{display_value}` | {defanged_mark} |")

    return "\n".join(lines)
