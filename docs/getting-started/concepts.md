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

> **Model proxies:** All public Cyvest APIs return `ObservableProxy` (and `CheckProxy`, `ThreatIntelProxy`, …)
> instances rather than raw dataclasses. These proxies provide live scores/levels but raise an error if you
> attempt to assign attributes. Use the facade helpers (`cv.observable_add_threat_intel`, `cv.observable_set_level`, …)
> or the fluent methods on the proxies themselves (`with_ti`, `relate_to`, `link_observable`, etc.) so the score engine
> remains consistent. Safe metadata fields (`comment`, `extra`, `internal`, etc.) can be updated via the dedicated
> `update_metadata()` helpers on each proxy:
>
> ```python
> url_obs.update_metadata(comment="triaged", extra={"ticket": "INC-4242"})
> check.update_metadata(description="Updated scope")
> ```
>
> Dictionary fields are merged by default; pass `merge_extra=False` (or `merge_data=False`) to overwrite them completely.

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

1. **Threat Intel → Observable**: Observable score = **max** of all threat intel scores (not sum)
2. **Child Observable → Parent**: Child scores aggregate to parents based on scoring mode
3. **Observable → Check**: Check score = **max** of all linked observables' scores and check's current score
4. **All Checks → Global**: Check scores sum to global score

### Scoring Modes

Cyvest supports two scoring modes for observable score calculation:

**MAX Mode (Default):**
- Observable score = max(all threat intel scores, all child observable scores)
- Conservative approach - takes the highest severity indicator
- Prevents score inflation from multiple threat intel sources
- Best for most investigation scenarios

**SUM Mode:**
- Observable score = max(threat intel scores) + sum(child observable scores)
- Accumulative approach - child scores add up
- Useful when child relationships represent cumulative risk
- Can lead to higher scores with many children

```python
from cyvest import Cyvest
from cyvest.score import ScoreMode

# Use MAX mode (default)
cv = Cyvest(score_mode=ScoreMode.MAX)

# Use SUM mode for accumulative scoring
cv = Cyvest(score_mode=ScoreMode.SUM)
```

### Score History

Every score change is automatically tracked for debugging and audit purposes:

```python
# Observable score history
obs = cv.observable_create("ip", "10.0.0.1")
cv.observable_add_threat_intel(obs.key, "source1", score=Decimal("5.0"))
cv.observable_add_threat_intel(obs.key, "source2", score=Decimal("8.0"))

# Get complete history
history = obs.get_score_history()
for change in history:
    print(f"{change.timestamp}: {change.old_score} → {change.new_score}")
    print(f"  Level: {change.old_level} → {change.new_level}")
    print(f"  Reason: {change.reason}")

# Check score history works the same way
check_history = check.get_score_history()
```

**Score Change Record:**

- Timestamp
- Old/new score values
- Old/new level values
- Reason for change (which TI source, which child updated, etc.)

### Hierarchical Score Propagation

Cyvest uses **relationship directions** to determine parent-child hierarchies for score propagation. The direction of a relationship defines whether scores flow upward (to parents) or not.

**Direction-Based Hierarchy:**

- **OUTBOUND (→)**: `source → target` — Target is a **child** of source
  - Source observable's score includes child's score
  - Scores propagate **upward** from child to parent

- **INBOUND (←)**: `source ← target` — Target is a **parent** of source
  - Target observable's score includes source's score
  - Scores propagate **upward** from source to target

- **BIDIRECTIONAL (↔)**: `source ↔ target` — **No hierarchy**
  - Symmetric relationship
  - Scores do **NOT** propagate hierarchically
  - Each observable maintains independent score

**Score Formula:**

For any observable, the score is calculated as:

```
score = max(max(threat-intel-scores), max(child-observable-scores))
```

Or in SUM mode:

```
score = max(threat-intel-scores) + sum(child-observable-scores)
```

**Children** are determined by OUTBOUND relationships only. BIDIRECTIONAL relationships are excluded from hierarchy.

#### Root Observable Barrier

The **root observable** (identified by `value="input-data"`) has special propagation rules to prevent score contamination:

- **Score calculation**: Root's score is calculated using the **same algorithm** as other observables
  - MAX mode: `max(root's TI scores, child observable scores)`
  - SUM mode: `max(root's TI scores) + sum(child observable scores)`
  - Root DOES aggregate child scores normally
  
- **Upward propagation barrier**: Root does **NOT** propagate scores to parent observables
  - If root has parent relationships, those parents are not affected by root's score
  - Propagation stops after root's score is calculated
  - Prevents contamination of upstream observables
  
- **Check propagation**: Root **DOES** propagate normally to linked checks
  - Checks referencing the root observable receive root's final score
  - Maintains expected behavior for verification steps

This barrier ensures that observables linked through the root remain isolated from each other while the root itself properly aggregates threat intelligence from its investigation tree.

**Examples:**

```python
from cyvest import Cyvest, RelationshipDirection, RelationshipType
from decimal import Decimal

cv = Cyvest()

# Example 1: OUTBOUND - Domain → IP (IP is child)
domain = cv.observable_create("domain", "malware.com")
cv.observable_add_threat_intel(domain.key, "virustotal", score=Decimal("2.0"))

ip = cv.observable_create("ip", "198.51.100.42")
cv.observable_add_threat_intel(ip.key, "abuseipdb", score=Decimal("8.0"))

# Domain resolves to IP (OUTBOUND by default)
cv.observable_add_relationship(domain, ip, RelationshipType.RESOLVES_TO)

# Result: domain score = max(2.0, 8.0) = 8.0 (includes child IP score)
print(f"Domain score: {domain.score}")  # 8.0
print(f"IP score: {ip.score}")          # 8.0


# Example 2: INBOUND - File ← URL (URL is parent)
malware = cv.observable_create("file", "trojan.exe")
cv.observable_add_threat_intel(malware.key, "av", score=Decimal("9.0"))

url = cv.observable_create("url", "http://evil.com/payload")
cv.observable_add_threat_intel(url.key, "urlscan", score=Decimal("3.0"))

# File downloaded from URL (INBOUND by default for DOWNLOADED)
cv.observable_add_relationship(malware, url, RelationshipType.DOWNLOADED)

# Result: URL is parent, gets file's score
print(f"File score: {malware.score}")  # 9.0
print(f"URL score: {url.score}")        # 9.0 (includes child file score)


# Example 3: BIDIRECTIONAL - No hierarchy
host1 = cv.observable_create("ip", "10.0.1.10")
cv.observable_add_threat_intel(host1.key, "ids", score=Decimal("7.0"))

host2 = cv.observable_create("ip", "10.0.1.20")
cv.observable_add_threat_intel(host2.key, "ids", score=Decimal("2.0"))

# Hosts communicate (BIDIRECTIONAL by default)
cv.observable_add_relationship(host1, host2, RelationshipType.COMMUNICATES_WITH)

# Result: No hierarchical propagation, each keeps own score
print(f"Host1 score: {host1.score}")  # 7.0
print(f"Host2 score: {host2.score}")  # 2.0


# Example 4: Override semantic defaults
domain2 = cv.observable_create("domain", "example.com")
cv.observable_add_threat_intel(domain2.key, "source", score=Decimal("1.0"))

ip2 = cv.observable_create("ip", "192.0.2.1")
cv.observable_add_threat_intel(ip2.key, "source", score=Decimal("5.0"))

# Override RESOLVES_TO to BIDIRECTIONAL (no hierarchy)
cv.observable_add_relationship(
    domain2, ip2,  # Observable proxies
    RelationshipType.RESOLVES_TO,
    RelationshipDirection.BIDIRECTIONAL
)

# Result: No propagation due to override
print(f"Domain score: {domain2.score}")  # 1.0
print(f"IP score: {ip2.score}")          # 5.0
```

**Multi-Level Hierarchy:**

Score propagation works recursively through multiple levels:

```python
# Grandparent → Parent → Child hierarchy
grandparent = cv.observable_create("domain", "root.com")
cv.observable_add_threat_intel(grandparent.key, "source1", score=Decimal("1.0"))

parent = cv.observable_create("domain", "sub.root.com")
cv.observable_add_threat_intel(parent.key, "source2", score=Decimal("2.0"))

child = cv.observable_create("ip", "203.0.113.10")
cv.observable_add_threat_intel(child.key, "source3", score=Decimal("9.0"))

cv.observable_add_relationship(grandparent.key, parent.key, "resolves-to")
cv.observable_add_relationship(parent.key, child.key, "resolves-to")

# Scores propagate all the way up:
# child = 9.0
# parent = max(2.0, 9.0) = 9.0
# grandparent = max(1.0, 9.0) = 9.0
```

**Score Change Record:**

Each `ScoreChange` entry includes:
- `timestamp`: When the change occurred
- `old_score` / `new_score`: Score values before/after
- `old_level` / `new_level`: Level classifications before/after
- `reason`: Explanation of why the score changed

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
- **SAFE**: Explicitly set for whitelisted/trusted items with downgrade protection
- **NONE**: Default for new checks (no classification)

### Explicit vs. Calculated Levels

You can set levels explicitly or let them be calculated from scores:

```python
# Calculated from score via threat intel
cv.observable_add_threat_intel(obs.key, source="analysis", score=Decimal("8.0"))  # Becomes MALICIOUS

# Explicitly set through the facade
cv.observable_set_level(obs.key, Level.SAFE)  # Overrides calculation

# Higher calculated level wins when new intel arrives
cv.observable_add_threat_intel(obs.key, source="analysis", score=Decimal("9.0"))  # Changes to MALICIOUS
```

### SAFE Level Protection

The **SAFE level has special protection** against downgrades. When an observable is created with or set to `Level.SAFE`, it cannot be downgraded to lower levels (NONE, TRUSTED, INFO) by threat intelligence or score updates, but can still be upgraded to higher levels (NOTABLE, SUSPICIOUS, MALICIOUS).

**Key Behaviors:**

1. **Automatic Protection**: Creating an observable with `level=SAFE` automatically enables downgrade protection
2. **Score Updates**: Scores still update based on threat intelligence, but the level won't downgrade
3. **Allows Upgrades**: SAFE observables can be upgraded to NOTABLE, SUSPICIOUS, or MALICIOUS if warranted
4. **Merge Preservation**: SAFE level is preserved during investigation merges
5. **Threat Intel Propagation**: Threat intel with `level=SAFE` can upgrade observables to SAFE level

**Example:**

```python
from cyvest import Cyvest, Level
from decimal import Decimal

cv = Cyvest()

# Create a SAFE observable (e.g., known-good domain)
trusted = cv.observable_create(
    "domain",
    "trusted.example.com",
    score=0,
    level=Level.SAFE
)

# Add threat intel with low score (would normally be INFO level)
cv.observable_add_threat_intel(
    trusted.key,
    "source1",
    score=Decimal("0")
)
# Score updates to 0, but level stays SAFE (not downgraded to INFO)
print(f"Score: {trusted.score}, Level: {trusted.level}")
# Output: Score: 0, Level: SAFE

# Add threat intel with negative score (would be TRUSTED level)
cv.observable_add_threat_intel(
    trusted.key,
    "source2",
    score=Decimal("-1.0")
)
# Score updates to -1.0, but level stays SAFE (not downgraded to TRUSTED)
print(f"Score: {trusted.score}, Level: {trusted.level}")
# Output: Score: -1.0, Level: SAFE

# Add threat intel indicating malicious activity
cv.observable_add_threat_intel(
    trusted.key,
    "source3",
    score=Decimal("6.0")
)
# Both score and level upgrade (MALICIOUS > SAFE, so upgrade allowed)
print(f"Score: {trusted.score}, Level: {trusted.level}")
# Output: Score: 6.0, Level: MALICIOUS

# Threat intel with SAFE level can also mark observables as SAFE
uncertain = cv.observable_create("domain", "example.com")
cv.observable_add_threat_intel(
    uncertain.key,
    "whitelist_service",
    score=Decimal("0"),
    level=Level.SAFE,
    comment="Verified by corporate whitelist"
)
# Observable upgraded to SAFE with automatic protection enabled
print(f"Score: {uncertain.score}, Level: {uncertain.level}")
# Output: Score: 0, Level: SAFE

# Further low-score threat intel won't downgrade it
cv.observable_add_threat_intel(
    uncertain.key,
    "another_source",
    score=Decimal("-1.0")
)
print(f"Score: {uncertain.score}, Level: {uncertain.level}")
# Output: Score: -1.0, Level: SAFE (protected from downgrade)
```

**Use Cases for SAFE:**

- **Known-good Domains**: Mark trusted corporate domains that shouldn't be flagged
- **Whitelisted IPs**: Internal infrastructure that may trigger false positives
- **Legitimate Software**: Files/processes known to be safe
- **Verified URLs**: Previously validated links that should maintain trust status
- **Reputation Services**: External whitelist/reputation databases that provide SAFE verdicts
- **Security Policies**: Enforcement of organizational security policies for trusted assets

**Protection Scope:**

The SAFE protection **only applies to the SAFE level itself**. Other explicit levels (set via `set_level()`) don't have the same protection and can be overridden by higher calculated levels according to the normal rules.

**SAFE Propagation to Checks:**

Checks automatically inherit the SAFE level from their linked observables under specific conditions:

1. **At least one** linked observable has `Level.SAFE`
2. **All** other linked observables have levels ≤ SAFE (NONE, TRUSTED, INFO, or SAFE)
3. The check's current level is < SAFE

When these conditions are met, the check is automatically set to SAFE level, overriding any previous level assignment.

```python
from cyvest import Cyvest, Level

cv = Cyvest()

# Create a check
check = cv.check_create("domain_check", "network", "Analyze domain reputation")

# Link a SAFE observable
safe_domain = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
cv.check_link_observable(check.key, safe_domain.key)

# Check inherits SAFE level from the observable
print(f"Check level: {check.level}")  # Output: Check level: SAFE

# Add INFO-level observables - check remains SAFE
info_ip = cv.observable_create("ipv4-addr", "192.0.2.1")
cv.check_link_observable(check.key, info_ip.key)
print(f"Check level: {check.level}")  # Output: Check level: SAFE

# Add MALICIOUS observable - check upgrades to MALICIOUS
malicious_url = cv.observable_create("url", "http://malware.example")
cv.observable_add_threat_intel(malicious_url.key, "virustotal", score=Decimal("8.0"))
cv.check_link_observable(check.key, malicious_url.key)
print(f"Check level: {check.level}")  # Output: Check level: MALICIOUS
```

This propagation ensures that checks analyzing whitelisted/trusted assets are properly marked as SAFE, while still allowing upgrades when actual threats are discovered.

## Relationships

Relationships follow **STIX2 conventions** with built-in type support.

**Important:** Relationships should be added via the Cyvest facade or proxy helpers (e.g., `cv.observable_add_relationship()` or `ObservableProxy.relate_to()`). This ensures:
- **Validation**: Both source and target observables must exist in the investigation
- **Centralized management**: All relationships are tracked in one place
- **Data integrity**: No dangling references to non-existent observables

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
# Using observable proxies (recommended)
cv.observable_add_relationship(
    source=url,  # Observable proxy
    target=ip,   # Observable proxy
    relationship_type=RelationshipType.RESOLVES_TO
)

# Using string keys (backward compatible)
cv.observable_add_relationship(
    source=url.key,
    target=ip.key,
    relationship_type=RelationshipType.RESOLVES_TO
)

# Mix observable proxies and keys
cv.observable_add_relationship(
    source=email,      # Observable proxy
    target=url.key,    # String key
    relationship_type="related-to"
)

# Custom relationship types
cv.observable_add_relationship(
    source=obs1,
    target=obs2,
    relationship_type="custom-relationship"
)
```

### Relationship Direction

Relationships support directional semantics with **automatic semantic defaults**:

```python
from cyvest import RelationshipType

# Automatically gets OUTBOUND (domain → IP)
# Accepts observable proxies directly
cv.observable_add_relationship(domain, ip, RelationshipType.RESOLVES_TO)

# Automatically gets INBOUND (file ← URL)
cv.observable_add_relationship(malware_file, download_url, RelationshipType.DOWNLOADED)

# Automatically gets BIDIRECTIONAL (host ↔ host)
cv.observable_add_relationship(host1, host2, RelationshipType.COMMUNICATES_WITH)

# Can still override semantic defaults if needed
cv.observable_add_relationship(
    domain, ip,  # Observable proxies
    RelationshipType.RESOLVES_TO,
    RelationshipDirection.INBOUND  # explicit override
)

# Using the fluent helpers (also uses semantic defaults)
# Accepts observable proxies or string keys
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

The root observable is automatically created with:
- **Type**: `ObservableType.FILE` (default) or `ObservableType.ARTIFACT` if `root_type="artifact"`
- **Value**: `"input-data"` (fixed identifier)
- **Purpose**: Entry point for the investigation

### Root Observable Barrier

The root observable has special scoring behavior to isolate investigation branches:

**What the barrier does:**
1. Root's score is calculated **normally** using MAX or SUM mode algorithm
2. Root DOES aggregate scores from child observables (like any other observable)
3. Root does NOT propagate its score to parent observables (barrier blocks upward)
4. Root DOES propagate normally to linked checks

**Why this matters:**
- Root properly aggregates all threat intelligence from the investigation tree
- Observables linked through root remain isolated from each other
- Prevents root's aggregated score from contaminating unrelated parent observables
- Maintains proper check scoring for root verification steps

**Example:**
```python
cv = Cyvest()
root = cv.root()

# Add threat intel to root
cv.observable_add_threat_intel(root.key, "scanner", score=Decimal("9.0"))

# Create observables linked to root
child = cv.observable_create("url", "https://example.com")
cv.observable_add_threat_intel(child.key, "urlscan", score=Decimal("5.0"))
cv.relationship_add(root.key, child.key, "related-to", direction="outbound")

# Create check for root
check = cv.check_create("root-check", "validation")
cv.check_link_observable(check.check_id, root.key)

# Results (MAX mode):
# - root.score = max(9.0 TI, 5.0 child) = 9.0
# - child.score = 5.0 (NOT affected by root TI due to barrier)
# - check.score = 9.0 (receives root score)
# - If root had a parent, parent.score would NOT include root's 9.0 (barrier blocks upward)
```

### Automatic Root Linking

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

## Investigation Architecture

Cyvest uses a clean, layered architecture with automatic merge-on-create:

### Core Components

1. **`Investigation`**: Internal state management
   - Owns all object collections
   - Handles automatic merging when objects are added
   - Integrates scoring and statistics engines

2. **`Cyvest`**: High-level API facade
   - User-facing interface
   - Delegates to `Investigation`
   - Provides convenience methods

3. **Fluent helpers**: Convenience methods exposed on the proxy classes for method chaining

### Automatic Merge-on-Create

When you add any object (observable, check, threat intel, etc.), Cyvest automatically:
1. Checks if an object with the same key exists
2. If yes: merges the new data into the existing object
3. If no: registers it as a new object

This eliminates duplicate objects and ensures consistency:

```python
cv = Cyvest()

# First creation
obs1 = cv.observable_create("url", "https://example.com", score=5.0)

# Adding same observable again - automatically merges!
obs2 = cv.observable_create("url", "https://example.com", score=7.0)

# obs1 and obs2 are the same object with merged data
assert obs1 is obs2
assert obs1.score == 7.0  # Higher score wins
```

### Merging Investigations

You can also merge entire investigations:

```python
# Create separate investigations
inv1 = Cyvest()
inv1.observable_create("url", "https://example.com")

inv2 = Cyvest()
inv2.observable_create("ip", "192.168.1.1")

# Merge inv2 into inv1 - automatic deduplication
inv1.merge_investigation(inv2)

# CLI support for merging JSON files
# cyvest merge inv1.json inv2.json -o merged.json
```

**Merge strategies:**
- **Observables**: Higher score/level wins, comments concatenate, relationships and threat intel merge
- **Checks**: Higher score/level wins, observables merge by key (not identity)
- **Threat Intel**: Higher score/level wins, taxonomies merge
- **Enrichments**: Deep merge of data dictionaries
- **Containers**: Recursive merge of checks and sub-containers

## Next Steps

- Learn about [Observables](#observables) in detail
- Understand [Scoring & Levels](#scoring-system)
- Explore the [fluent helpers](quickstart.md#using-the-fluent-api) in practice
