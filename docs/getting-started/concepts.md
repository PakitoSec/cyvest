# Core Concepts

Understanding the core concepts of Cyvest will help you build effective cybersecurity investigations.

## Investigation Structure

A Cyvest investigation consists of several key components:

### Observables

**Observables** represent cyber artifacts under investigation:
- URLs, IP addresses, domains
- File hashes, processes, registry keys
- Email addresses, hostnames
- Any entity that can be analyzed

Cyvest supports **STIX2-compliant observable types** with built-in enums for type safety and IDE autocomplete.

Each observable has:
- **Type**: The kind of artifact (can use `ObservableType` enum or string)
- **Value**: The actual value
- **Score**: Numeric severity (auto-calculated)
- **Level**: Classification (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- **Relationships**: Links to other observables (can use `RelationshipType` enum)
- **Threat Intelligence**: Verdicts from external sources

**STIX2 Observable Types:**

```python
from cyvest import ObservableType

# Network observables
ObservableType.IPV4_ADDR          # "ipv4-addr"
ObservableType.IPV6_ADDR          # "ipv6-addr"
ObservableType.DOMAIN_NAME        # "domain-name"
ObservableType.URL                # "url"
ObservableType.MAC_ADDR           # "mac-addr"
ObservableType.NETWORK_TRAFFIC    # "network-traffic"

# Email observables
ObservableType.EMAIL_ADDR         # "email-addr"
ObservableType.EMAIL_MESSAGE      # "email-message"
ObservableType.EMAIL_MIME_PART    # "email-mime-part"

# File observables
ObservableType.FILE               # "file"
ObservableType.DIRECTORY          # "directory"
ObservableType.ARTIFACT           # "artifact"

# System observables
ObservableType.PROCESS            # "process"
ObservableType.SOFTWARE           # "software"
ObservableType.USER_ACCOUNT       # "user-account"
ObservableType.WINDOWS_REGISTRY_KEY  # "windows-registry-key"

# Other observables
ObservableType.AUTONOMOUS_SYSTEM  # "autonomous-system"
ObservableType.MUTEX              # "mutex"
ObservableType.X509_CERTIFICATE   # "x509-certificate"
```

You can use enums or strings interchangeably:

```python
# Using enum (recommended - provides autocomplete)
obs1 = cv.observable(ObservableType.URL, "https://example.com")

# Using string (backward compatible)
obs2 = cv.observable("url", "https://example.com")

# Custom types as strings
obs3 = cv.observable("custom-indicator", "some-value")
```

### Checks

**Checks** represent verification steps in your investigation:
- Pattern matching
- Reputation lookups
- Behavioral analysis
- Any validation logic

Each check has:
- **Check ID**: Identifier for the verification
- **Scope**: Category (email, network, endpoint, etc.)
- **Description**: What the check does
- **Score**: Contribution to overall severity
- **Level**: Result classification
- **Linked Observables**: Artifacts verified by this check

### Threat Intelligence

**Threat Intelligence** provides verdicts from external sources:
- VirusTotal, URLScan.io, AbuseIPDB
- Internal reputation databases
- Custom analysis engines

Each threat intel entry has:
- **Source**: Name of the intelligence source
- **Score**: Severity assessment
- **Level**: Classification
- **Comment**: Details about the verdict
- **Taxonomies**: Structured metadata

### Containers

**Containers** organize checks hierarchically:
- Group related checks together
- Create logical investigation sections
- Support nesting for complex structures
- Provide aggregated scores and levels

### Enrichments

**Enrichments** store structured metadata:
- Email headers
- WHOIS data
- DNS records
- Any auxiliary information

## Scoring System

### Score Calculation

Scores are **Decimal** values with automatic propagation:

1. **Threat Intel → Observable**: TI scores sum to observable score
2. **Child Observable → Parent**: Child scores aggregate to parents
3. **MALICIOUS Observable → Check**: Sets check to MALICIOUS
4. **All Checks → Global**: Check scores sum to global score

### Level Classification

Levels are automatically calculated from scores:

| Score Range | Level |
|-------------|-------|
| < 0.0 | TRUSTED |
| == 0.0 | INFO |
| 0.0 - 3.0 | NOTABLE |
| 3.0 - 5.0 | SUSPICIOUS |
| >= 5.0 | MALICIOUS |

Special cases:
- **SAFE**: Explicitly set for whitelisted items
- **NONE**: Default for new checks (no classification)

### Explicit vs. Calculated

You can set levels explicitly or let them be calculated:

```python
# Calculated from score
obs.update_score(Decimal("8.0"))  # Becomes MALICIOUS

# Explicitly set
obs.set_level(Level.SAFE)  # Overrides calculation

# Higher calculated level wins
obs.update_score(Decimal("9.0"))  # Changes to MALICIOUS
```

## Relationships

Relationships follow **STIX2 conventions** with built-in type support:

```python
from cyvest import RelationshipType

# Network relationships
RelationshipType.RESOLVES_TO           # DNS resolution
RelationshipType.BELONGS_TO            # Network ownership
RelationshipType.COMMUNICATES_WITH     # Network communication

# File relationships
RelationshipType.CONTAINS              # Containment
RelationshipType.DOWNLOADED            # Download action
RelationshipType.DROPPED               # File dropping

# Email relationships
RelationshipType.FROM                  # Email sender
RelationshipType.TO                    # Email recipient
RelationshipType.CC                    # Email CC
RelationshipType.SENDER                # Email sender field

# Process relationships
RelationshipType.CREATED               # Creation
RelationshipType.OPENED                # File opened
RelationshipType.PARENT                # Parent process
RelationshipType.CHILD                 # Child process

# General relationships
RelationshipType.RELATED_TO            # General association
RelationshipType.DERIVED_FROM          # Derivation
RelationshipType.DUPLICATE_OF          # Duplication
```

**Common Relationship Patterns:**

| Relationship Type | Meaning | Example |
|------------------|---------|---------|
| `RELATED_TO` | General association | Email related to URL |
| `RESOLVES_TO` | DNS resolution | Domain resolves to IP |
| `CONTAINS` | Containment | Email contains attachment |
| `COMMUNICATES_WITH` | Network communication | Host communicates with IP |
| `DOWNLOADED` | Download action | URL downloaded file |
| `CREATED` | Creation | Process created file |

**Creating Relationships:**

```python
# Using enum (recommended)
cv.observable_add_relationship(
    source_key=url.key,
    target_key=ip.key,
    relationship_type=RelationshipType.RESOLVES_TO
)

# Using string (backward compatible)
cv.observable_add_relationship(
    source_key=email.key,
    target_key=url.key,
    relationship_type="related-to"
)

# Custom relationship types
cv.observable_add_relationship(
    source_key=obs1.key,
    target_key=obs2.key,
    relationship_type="custom-relationship"
)
```

### Relationship Direction

Relationships support directional semantics with **automatic semantic defaults**:

```python
from cyvest import RelationshipType

# Automatically gets OUTBOUND (domain → IP)
cv.observable_add_relationship(domain.key, ip.key, RelationshipType.RESOLVES_TO)

# Automatically gets INBOUND (file ← URL)  
cv.observable_add_relationship(malware_file.key, download_url.key, RelationshipType.DOWNLOADED)

# Automatically gets BIDIRECTIONAL (host ↔ host)
cv.observable_add_relationship(host1.key, host2.key, RelationshipType.COMMUNICATES_WITH)

# Can still override semantic defaults if needed
cv.observable_add_relationship(
    domain.key, ip.key,
    RelationshipType.RESOLVES_TO,
    RelationshipDirection.INBOUND  # explicit override
)

# Using the fluent DSL (also uses semantic defaults)
url.relate_to(domain, RelationshipType.RELATED_TO)  # auto: BIDIRECTIONAL
```

**Semantic Default Directions:**

Each relationship type automatically gets the most appropriate direction:

| Relationship Type | Default Direction | Symbol | Rationale |
|-------------------|-------------------|--------|-----------|
| `RESOLVES_TO` | OUTBOUND | → | Domain resolves to IP |
| `BELONGS_TO` | OUTBOUND | → | IP belongs to network/AS |
| `COMMUNICATES_WITH` | BIDIRECTIONAL | ↔ | Mutual communication |
| `CONTAINS` | OUTBOUND | → | Container holds item |
| `DOWNLOADED` | INBOUND | ← | File from source |
| `DROPPED` | INBOUND | ← | File from dropper |
| `FROM` | INBOUND | ← | Email from sender |
| `SENDER` | INBOUND | ← | Email from sender |
| `TO`, `CC`, `BCC` | OUTBOUND | → | Email to recipient |
| `CREATED` | OUTBOUND | → | Creator to created |
| `OPENED` | OUTBOUND | → | Opener to opened |
| `PARENT` | OUTBOUND | → | Parent to child |
| `CHILD` | INBOUND | ← | Child from parent |
| `RELATED_TO` | BIDIRECTIONAL | ↔ | Symmetric association |
| `DERIVED_FROM` | INBOUND | ← | Derived from source |
| `DUPLICATE_OF` | BIDIRECTIONAL | ↔ | Symmetric duplication |

**Visualization:**

Direction symbols automatically appear in:
- Terminal output with Rich formatting
- Markdown exports for documentation
- Investigation graphs and trees

```markdown
# Example markdown output
- **Relationships:**
  - resolves-to → obs:ipv4-addr:192.0.2.1
  - downloaded ← obs:url:http://malware.com/payload
  - communicates-with ↔ obs:ipv4-addr:10.0.1.50
```

## Key Generation

Every object has a unique, deterministic key:

- **Observable**: `obs:{type}:{normalized_value}`
- **Check**: `chk:{check_id}:{scope}`
- **Threat Intel**: `ti:{source}:{observable_key}`
- **Enrichment**: `enr:{name}[:{context_hash}]`
- **Container**: `ctr:{path}`

Keys enable:
- Fast object retrieval
- Reliable merging
- Deduplication

## Root Observable

Every investigation has a **root observable** representing the analyzed artifact:

```python
cv = Cyvest()
root = cv.root()  # or cv.observable_get_root()
```

Orphan observables (without relationships) are automatically linked to root with `related-to`.

## Statistics

Real-time statistics are available throughout the investigation:

```python
stats = cv.get_statistics()

# Access metrics
stats['total_observables']
stats['observables_by_type']
stats['observables_by_level']
stats['checks_by_scope']
stats['total_threat_intel']
```

## Merging

Investigations can be merged:

```python
# Create separate investigations
inv1 = Cyvest()
inv2 = Cyvest()

# Merge inv2 into inv1
inv1.merge_investigation(inv2)
```

Merge strategy:
- **Observables/Checks**: Update score, level, extra; concatenate comments
- **Threat Intel**: Update score, level; merge taxonomies
- **Enrichments**: Replace data structure
- **Containers**: Merge trees recursively

## Next Steps

- Learn about [Observables](../guide/observables.md) in detail
- Understand [Scoring & Levels](../guide/scoring.md)
- Explore [DSL & Fluent API](../guide/dsl.md)
