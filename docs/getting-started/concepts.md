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

Each observable has:
- **Type**: The kind of artifact (url, ip, hash, etc.)
- **Value**: The actual value
- **Score**: Numeric severity (auto-calculated)
- **Level**: Classification (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- **Relationships**: Links to other observables
- **Threat Intelligence**: Verdicts from external sources

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

Relationships follow STIX2 conventions:

| Relationship Type | Meaning | Example |
|------------------|---------|---------|
| `related-to` | General association | Email related to URL |
| `resolves-to` | DNS resolution | URL resolves to IP |
| `contains` | Containment | Email contains attachment |
| `communicates-with` | Network communication | Host communicates with IP |
| `uses` | Usage | Process uses file |
| `extracted-from` | Extraction | File extracted from archive |

```python
# Create relationship
cv.observable_add_relationship(
    source_key=url.key,
    target_key=ip.key,
    relationship_type="resolves-to"
)
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
