# Observable Extraction

Extract cyber observables (IOCs) from raw text, markdown, or web pages with automatic defang/refang support.

---

## Overview

The `cyvest.extract` module provides utilities to identify and extract indicators of compromise (IOCs) from unstructured text. It supports:

- **Multiple observable types**: URLs, IP addresses (IPv4/IPv6), email addresses, cryptographic hashes, and domain names
- **Defanged indicators**: Automatic recognition and refanging of common defang patterns (`hxxp://`, `[.]`, `[@]`, etc.)
- **Encoded URLs**: Hex-encoded, URL-encoded, and base64-encoded URLs
- **Deduplication with counting**: Extracted observables are automatically deduplicated by value and occurrence counts are tracked
- **Web fetching**: Extract observables directly from web pages
- **Markdown output**: Generate markdown lists or tables for LLM consumption with defang support

---

## CLI Usage

The `cyvest extract` command provides a convenient way to extract observables from the command line:

```bash
# From stdin
echo "Check IP 192.168.1.1 and https://evil.com" | cyvest extract

# From file
cyvest extract threat_report.txt

# Filter by type (can specify multiple)
cyvest extract report.txt -t url -t ip -t hash

# Output as JSON
cyvest extract report.txt -f json -o extracted.json

# Fetch from URL and extract
cyvest extract --from-url https://example.com/ioc-feed.txt

# Keep defanged format (don't refang)
cyvest extract -R < defanged_iocs.txt
```

### Command Options

| Option | Description |
|--------|-------------|
| `INPUT` | Input file (defaults to stdin if not specified) |
| `-t, --types` | Types to extract: `url`, `ip`, `ipv4`, `ipv6`, `email`, `hash`, `domain`, `all` (default: `all`) |
| `-r/-R, --refang/--no-refang` | Refang extracted observables (default: enabled) |
| `-o, --output` | Output file (defaults to stdout) |
| `-f, --format` | Output format: `text`, `json`, `markdown`, or `markdown-table` (default: `text`) |
| `--from-url` | Fetch content from URL and extract observables |
| `--title` | Title for markdown output (rendered as `## Title`) |
| `--group-by-type` | Group observables by type in markdown list output |
| `--include-original` | Include original text in markdown output |
| `--defang-output` | Defang values in markdown output for safe sharing |

### Output Formats

**Text format** (default): Tab-separated type and value, one per line:

```
url     https://evil.com/malware
ipv4    192.168.1.1
email   admin@evil.com
hash    d41d8cd98f00b204e9800998ecf8427e
domain  malware.io
```

**JSON format**: Array of observable objects with metadata:

```json
[
  {
    "obs_type": "url",
    "value": "https://evil.com/malware",
    "original": "hxxps://evil[.]com/malware",
    "defanged": true,
    "count": 1
  },
  {
    "obs_type": "ipv4",
    "value": "192.168.1.1",
    "original": "192[.]168[.]1[.]1",
    "defanged": true,
    "count": 3
  }
]
```

**Markdown list format** (`--format markdown`): Human-readable list for LLM consumption:

```bash
cyvest extract report.txt --format markdown --title "Threat IOCs" --group-by-type
```

```markdown
## Threat IOCs

### URL

- URL: `https://evil.com/malware`
  - Defanged: Yes

### IPV4

- IPV4: `192.168.1.1`
  - Defanged: Yes
  - Count: 3
```

**Markdown table format** (`--format markdown-table`): Compact table view:

```bash
cyvest extract report.txt --format markdown-table --defang-output
```

```markdown
| Type | Value | Count | Defanged |
|------|-------|-------|----------|
| URL | `hxxps://evil[.]com/malware` | 1 | ✓ |
| IPV4 | `192[.]168[.]1[.]1` | 3 | ✓ |
```

> **Note:** The Count column only appears when any observable has count > 1.

---

## Programmatic Usage

### Basic Extraction

```python
from cyvest.extract import extract_all, extract_urls, extract_ips, extract_emails, extract_hashes, extract_domains
from cyvest.model_enums import ObservableType

# Extract all observable types
text = """
Threat Report:
- C2 Server: hxxps://evil[.]domain[.]com/c2
- IP Address: 192[.]168[.]1[.]1
- Contact: admin[@]evil.com
- Malware hash: d41d8cd98f00b204e9800998ecf8427e
"""

observables = extract_all(text)
for obs in observables:
    print(f"{obs.obs_type.value}: {obs.value} (defanged: {obs.defanged})")
```

Output:
```
url: https://evil.domain.com/c2 (defanged: True)
ipv4: 192.168.1.1 (defanged: True)
email: admin@evil.com (defanged: True)
hash: d41d8cd98f00b204e9800998ecf8427e (defanged: False)
domain: evil.com (defanged: True)
```

### Filter by Type

```python
from cyvest.extract import extract_all
from cyvest.model_enums import ObservableType

# Extract only URLs and IPs
observables = extract_all(
    text,
    types={ObservableType.URL, ObservableType.IPV4, ObservableType.IPV6}
)
```

### Individual Extractors

Use specific extractors for fine-grained control:

```python
from cyvest.extract import extract_urls, extract_ips, extract_emails, extract_hashes, extract_domains

# Extract URLs (returns iterator)
for url in extract_urls(text):
    print(f"URL: {url.value}")

# Extract IPs (both IPv4 and IPv6)
for ip in extract_ips(text):
    print(f"IP ({ip.obs_type.value}): {ip.value}")

# Extract emails
for email in extract_emails(text):
    print(f"Email: {email.value}")

# Extract hashes (MD5, SHA1, SHA256, SHA512)
for hash_obs in extract_hashes(text):
    print(f"Hash: {hash_obs.value}")

# Extract domains (excludes domains in URLs)
for domain in extract_domains(text):
    print(f"Domain: {domain.value}")
```

### Extract from URL

Fetch content from a web page and extract observables:

```python
from cyvest.extract import extract_from_url

# Fetch and extract
observables = extract_from_url("https://example.com/ioc-feed.txt")

# With type filtering
from cyvest.model_enums import ObservableType
observables = extract_from_url(
    "https://example.com/ioc-feed.txt",
    types={ObservableType.IPV4},
    timeout=60
)
```

---

## Defang/Refang Utilities

### Refanging

Convert defanged indicators back to their original format:

```python
from cyvest.extract import refang

# URLs
refang("hxxps://evil[.]com")  # -> "https://evil.com"
refang("hxxp://malware(.)site[/]payload")  # -> "http://malware.site/payload"

# IPs
refang("192[.]168[.]1[.]1")  # -> "192.168.1.1"
refang("10[dot]0[dot]0[dot]1")  # -> "10.0.0.1"

# Emails
refang("admin[@]evil[.]com")  # -> "admin@evil.com"
refang("user at example.com")  # -> "user@example.com"
```

### Defanging

Convert indicators to safe, non-clickable format:

```python
from cyvest.extract import defang

defang("https://malware.com/payload")  # -> "hxxps://malware[.]com[/]payload"
defang("user@evil.com")  # -> "user[@]evil[.]com"
```

---

## Supported Patterns

### URL Schemes

| Scheme | Description |
|--------|-------------|
| `http`, `https` | Standard web URLs |
| `ftp`, `ftps`, `sftp` | File transfer protocols |
| `tcp`, `udp` | Network protocols |

**Defanged variants**: `hxxp://`, `hxxps://`, `fxp://`, `[:]//`, `:\[//\]`

### IP Addresses

| Type | Pattern | Example |
|------|---------|---------|
| IPv4 | Standard dotted notation | `192.168.1.1` |
| IPv4 defanged | Bracket/paren dots | `192[.]168[.]1[.]1`, `10(dot)0(dot)0(dot)1` |
| IPv6 | Full and compressed | `2001:db8::1`, `::1` |

### Email Addresses

| Pattern | Example |
|---------|---------|
| Standard | `user@example.com` |
| Bracket @ | `user[@]example.com` |
| Paren @ | `user(@)example.com` |
| Word "at" | `user at example.com` |
| Combined | `user[@]example[.]com` |

### Hashes

| Type | Length | Example |
|------|--------|---------|
| MD5 | 32 hex chars | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 hex chars | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 hex chars | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SHA512 | 128 hex chars | `cf83e1357eefb8bdf1542850d66d8007...` |

### Encoded URLs

| Encoding | Description |
|----------|-------------|
| Hex | `68747470733a2f2f...` (hex-encoded URL) |
| URL-encoded | `https://example.com/path%20with%20spaces` |
| Base64 | `aHR0cHM6Ly9leGFtcGxlLmNvbQ==` |

---

## ExtractedObservable Model

Each extracted observable is returned as an `ExtractedObservable` Pydantic model:

```python
from cyvest.extract import ExtractedObservable

# Fields
obs.obs_type   # ObservableType enum (URL, IPV4, IPV6, EMAIL, HASH, DOMAIN)
obs.value      # Normalized (refanged) value
obs.original   # Original matched text
obs.defanged   # Boolean indicating if original was defanged
obs.count      # Number of occurrences in the source text
```

### Markdown Serialization

Each observable can be serialized to markdown for LLM consumption:

```python
# Single observable
md = obs.to_markdown()
md = obs.to_markdown(include_original=True, defang_value=True)
```

---

## Markdown Output Functions

### List Format

Generate a markdown list of observables:

```python
from cyvest.extract import extract_all, observables_to_markdown

text = "IP: 192.168.1.1, URL: https://evil.com"
observables = extract_all(text)

# Basic list
md = observables_to_markdown(observables)

# With options
md = observables_to_markdown(
    observables,
    title="Extracted IOCs",        # Add ## title header
    group_by_type=True,            # Group by observable type with ### sub-headers
    include_original=True,         # Include original text if different
    defang_values=True,            # Defang values for safe sharing
)
print(md)
```

Output:
```markdown
## Extracted IOCs

### IPV4

- IPV4: `192[.]168[.]1[.]1`
  - Defanged: Yes

### URL

- URL: `hxxps://evil[.]com`
  - Defanged: Yes
```

### Table Format

Generate a compact markdown table:

```python
from cyvest.extract import extract_all, observables_to_markdown_table

observables = extract_all(text)

# Basic table
md = observables_to_markdown_table(observables)

# With options
md = observables_to_markdown_table(
    observables,
    title="IOC Summary",           # Add ## title header
    defang_values=True,            # Defang values for safe sharing
)
print(md)
```

Output:
```markdown
## IOC Summary

| Type | Value | Defanged |
|------|-------|----------|
| IPV4 | `192[.]168[.]1[.]1` | ✓ |
| URL | `hxxps://evil[.]com` | ✓ |
```

> **Tip:** The table automatically adds a Count column when any observable appears multiple times.

---

## Integration with Cyvest

Combine extraction with investigation building:

```python
from cyvest import Cyvest
from cyvest.extract import extract_all

# Extract observables from threat report
text = open("threat_report.txt").read()
extracted = extract_all(text)

# Build investigation from extracted IOCs
cv = Cyvest(root_data={"source": "threat_report.txt"})

for obs in extracted:
    cv.observable(obs.obs_type, obs.value, internal=False)

cv.display_summary()
cv.io_save_json("investigation.json")
```

---

## Best Practices

1. **Use type filtering** when you know what you're looking for to reduce false positives
2. **Keep refanging enabled** (default) for normalized, searchable values
3. **Check the `defanged` flag** to identify indicators that were obfuscated in the source
4. **Use `extract_from_url`** with caution - set appropriate timeouts and consider rate limiting
5. **Validate extracted hashes** against known-good patterns if precision is critical
