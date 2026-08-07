# Core Concepts

Understanding the core concepts of Cyvest will help you build effective cybersecurity investigations.

## Investigation Structure

A Cyvest investigation consists of several key components:

### Investigation whitelisting

Mark the investigation as **safe** with one or more whitelist entries (identifier, name, and optional markdown justification):

```python
cv.investigation_add_whitelist("ticket-4242", "False positive", "Sandbox flagged a benign file")
cv.investigation_add_whitelist("allowlist-host", "Known asset")

entries = cv.investigation_get_whitelists()
assert cv.investigation_is_whitelisted() is True
assert entries[0].identifier == "ticket-4242"

cv.investigation_remove_whitelist("ticket-4242")
cv.investigation_clear_whitelists()  # remove all entries
```

Whitelist entries are included in JSON/Markdown exports so downstream systems can respect the analyst's verdict.

### Observables

**Observables** represent cyber artifacts under investigation:
- URLs, IP addresses, domains
- File hashes, processes, registry keys
- Email addresses, hostnames
- Any entity that can be analyzed

Cyvest ships enums for common observable types to keep your investigations consistent and discoverable.

Each observable has:
- **Type**: The kind of artifact (use `cv.OBS.*` to keep the vocabulary consistent)
- **Value**: The actual value
- **Score**: Numeric severity (auto-calculated)
- **Level**: Classification (TRUSTED, INFO, SAFE, NOTABLE, SUSPICIOUS, MALICIOUS)
- **Relationships**: Links to other observables (use `cv.REL.*` and `cv.DIR.*`)
- **Threat Intelligence**: Verdicts from external sources

> **Model proxies:** All public Cyvest APIs return `ObservableProxy` (and `FindingProxy`, `ThreatIntelProxy`, …)
> instances rather than raw dataclasses. These proxies provide live scores/levels but raise an error if you
> attempt to assign attributes. All mutations flow through the Investigation layer, so use the facade helpers
> (`cv.observable_add_threat_intel`, `cv.observable_set_level`, …) or the fluent methods on the proxies themselves
> (`with_ti`, `relate_to`, `link_observable`, `set_level`, etc.) so the score engine remains consistent.
> Safe metadata fields (`comment`, `extra`, `internal`, etc.) can be updated via the dedicated `update_metadata()`
> helpers on each proxy. Use `set_level()` to update the level without changing the score:
>
> ```python
> url_obs.update_metadata(comment="triaged", extra={"ticket": "INC-4242"})
> finding.update_metadata(description="Updated scope")
> finding.set_level(cv.LVL.SAFE, reason="Verified clean")
> ```
>
> Dictionary fields are merged by default; pass `merge_extra=False` (or `merge_data=False`) to overwrite them completely.

**Observable Types:**

```python
from cyvest import Cyvest

# Network observables
Cyvest.OBS.IPV4              # "ipv4"
Cyvest.OBS.IPV6              # "ipv6"
Cyvest.OBS.DOMAIN            # "domain"
Cyvest.OBS.URL               # "url"

# Hash observables
Cyvest.OBS.HASH              # "hash"

# Email observables
Cyvest.OBS.EMAIL             # "email"

# File observables
Cyvest.OBS.FILE              # "file"
Cyvest.OBS.ARTIFACT          # "artifact"
```

Use the facade namespace for autocomplete:

```python
obs = cv.observable(cv.OBS.URL, "https://example.com")
```

### Observable canonicalisation

Some raw identifiers describe the same real-world entity. For example, `USER/email alice@example.com` and
`USER/username/windows alice` might both refer to the canonical Okta user `USER/uid/okta 123`.

Register an instance-local resolver when you want `observable_create()` to resolve source identities before creating
the observable:

```python
from cyvest import (
    Cyvest,
    ObservableAlias,
    ObservableIdentity,
    ObservableResolution,
    ObservableResolver,
)

cv = Cyvest()

def resolve_user_to_okta(alias: ObservableAlias) -> ObservableIdentity | None:
    lookup = {
        ("email", None, "alice@example.com"): "123",
        ("username", "windows", "alice"): "123",
    }
    subtype = alias.subtype.value if hasattr(alias.subtype, "value") else alias.subtype
    okta_uid = lookup.get((subtype, alias.namespace, alias.value.lower()))
    if okta_uid is None:
        return None

    return ObservableIdentity(
        obs_type=cv.OBS.USER,
        subtype=cv.SUB.USER_UID,
        namespace="okta",
        value=okta_uid,
    )

cv.observable_resolver_register(
    ObservableResolver(
        name="okta-user-id",
        source_types={
            (cv.OBS.USER, cv.SUB.USER_EMAIL),
            (cv.OBS.USER, cv.SUB.USER_USERNAME),
        },
        resolve=resolve_user_to_okta,
    )
)

email = cv.observable_create(cv.OBS.USER, "alice@example.com", subtype=cv.SUB.USER_EMAIL)
username = cv.observable_create(
    cv.OBS.USER,
    "alice",
    subtype=cv.SUB.USER_USERNAME,
    namespace="windows",
)

assert email.key == username.key
assert email.subtype == cv.SUB.USER_UID
assert email.namespace == "okta"
assert email.value == "123"
assert email.occurrence_count == 2
```

Resolvers are evaluated in registration order and the first non-`None` `ObservableIdentity` wins. Returning `None`
means "not resolved", so Cyvest creates the source observable normally. Resolver exceptions are not swallowed.

The source identities are stored on the canonical observable as typed aliases:

```python
for alias in email.aliases:
    print(alias.obs_type, alias.subtype, alias.namespace, alias.value, alias.count)
```

`ObservableIdentity` is the canonical identity returned by a resolver. `ObservableAlias` is the source identity
stored on the canonical observable, with a `count` for repeated occurrences. The canonical `Observable` also tracks
`occurrence_count`, which is merged across repeated creations and investigation merges.

Resolver registration is per `Cyvest` instance:

```python
cv.observable_resolver_get_all()
cv.observable_resolver_unregister("okta-user-id")
cv.observable_resolver_clear()
```

For async lookups, register `aresolve=` and use `await cv.observable_acreate(...)`. If a matching async resolver is
registered, synchronous `observable_create()` raises a clear error instead of blocking the event loop.

When the lookup also returns useful attributes, return an `ObservableResolution`:

```python
def resolve_user_to_okta(alias: ObservableAlias) -> ObservableResolution | None:
    user = lookup_okta_user(alias)
    if user is None:
        return None

    return ObservableResolution(
        identity=ObservableIdentity(
            obs_type=cv.OBS.USER,
            subtype=cv.SUB.USER_UID,
            namespace="okta",
            value=user["id"],
        ),
        metadata=user,
    )
```

Cyvest stores this metadata on the canonical observable under
`observable.extra["resolver_data"][resolver.name]`. Dictionaries are merged recursively across repeated observable
creations and investigation merges; incoming scalar and list values replace previous values. Resolver metadata
coexists with `extra=` passed to `observable_create()`. The reserved `extra["resolver_data"]` value must be a
dictionary.

### Findings

**Findings** represent verification steps in your investigation:
- Pattern matching
- Reputation lookups
- Behavioral analysis
- Any validation logic

Each finding has:
- **Finding Name**: Identifier for the verification
- **Description**: What the finding does
- **Score**: Contribution to overall severity
- **Level**: Result classification
- **Linked Observables**: Artifacts verified by this finding

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
- **Taxonomies**: Structured metadata (unique by name)

Taxonomies are objects with a strict shape and unique names:

```python
taxonomies=[
    {"level": cv.LVL.INFO, "name": "malware-type", "value": "trojan"},
    {"level": cv.LVL.SUSPICIOUS, "name": "confidence", "value": "medium"},
]
```

If you don't know the observable yet, create a draft and attach it later:

```python
draft = cv.threat_intel_draft("virustotal", score=Decimal("4.2"))
obs.with_ti_draft(draft)
```

Drafts are plain `ThreatIntel` objects without an `observable_key`; the key is generated on attach.

To load a draft from an external API response dict (e.g. a SOAR/TIP report), use `io_load_threat_intel_draft`:

```python
report = {"source": "virustotal", "score": 4.256, "level": "SUSPICIOUS"}
ti = Cyvest.io_load_threat_intel_draft(report)
obs.with_ti_draft(ti)
```

An optional `preprocessor` callback lets you normalise source-specific data before validation.
For the common case of forcing certain reports to **SAFE**, use `safe_getter` and `safe_values` instead:

```python
ti = Cyvest.io_load_threat_intel_draft(
    report,
    safe_getter=lambda d: d.get("extra", {}).get("task_name", ""),
    safe_values=["MISP.analyzer.DBWarningList", "MISP.analyzer.SearchWarningList"],
)
```

When `safe_getter(report)` matches any entry in `safe_values` and the level is not already INFO or SAFE, the score is set to `0.0` and the level to `SAFE`.

### Tags
- Group related findings together
- Create logical investigation sections
- Auto-create ancestor tags (e.g., `header:auth:dkim` creates `header` and `header:auth`)
- Provide direct and aggregated scores/levels

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
3. **Observable → Finding (provenance-aware)**: Finding score/level only considers observables reachable through *effective* links (`observable_links`)
   - A link is effective when `propagation_mode="GLOBAL"` or when the finding's `origin_investigation_id` matches the current investigation id
4. **All Findings → Global**: Finding scores sum to global score

To override the default local-only behavior for a single link:

```python
cy.finding_link_observable(finding.key, observable.key, propagation_mode="GLOBAL")
```

### Provenance (findings)

Findings carry a **canonical origin** (`origin_investigation_id`) used by scoring/propagation to decide whether a `LOCAL_ONLY` link is effective in the current investigation.

Exports include `investigation_id` so finding origins remain meaningful after serialization.

### Reverse Links (navigation)

Observables expose `finding_links`, derived from `Finding.observable_links`, to show which findings currently link to them. These reverse links are non-authoritative and never drive propagation decisions.

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
cv = Cyvest(score_mode_obs=ScoreMode.MAX)

# Use SUM mode for accumulative scoring
cv = Cyvest(score_mode_obs=ScoreMode.SUM)
```

#### Observables Reached Through Several Branches

A score depends only on the observable's own threat intel and on its subtree, never
on the order observables were inserted. When an observable is reachable through two
independent deduction chains, it is expanded in both: this is corroboration, not
double counting.

```python
cv = Cyvest(score_mode_obs=ScoreMode.SUM)

# report -> domain_a -> shared_ip, and report -> domain_b -> shared_ip
# domain_a = its own TI + shared_ip subtree
# domain_b = its own TI + shared_ip subtree
# report   = domain_a + domain_b, the shared IP weighing in each branch
```

In MAX mode this makes no difference, since taking a maximum twice changes nothing.
A cycle stops at the observable already present on the current path, which then
contributes only its own threat intel score.

!!! warning "Changed in 6.2.0"
    Earlier versions deduplicated an observable across the branches of a single
    traversal, so the second branch was truncated to its threat intel score. A
    parent score could therefore be lower than the sum of its children. SUM mode
    scores computed before 6.2.0 may differ; recalculation is automatic on load.

#### Relationships That Do Not Carry Score

Only `OUTBOUND` and `INBOUND` relationships build the hierarchy. A `BIDIRECTIONAL`
relationship is never traversed, in either direction, so it transports no score.

Since `RELATED_TO` defaults to `BIDIRECTIONAL`, a relationship created without an
explicit direction leaves both scores untouched. This is intended: a correlation
with no established deduction mechanism has no reason to make a score propagate.
`EXTRACTION` and `PIVOT` default to `OUTBOUND` and do propagate.

Investigation names are optional, human-readable labels. They are serialized separately from `investigation_id` and are never used for scoring or propagation.

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

The **root observable** (identified by `value="root"`) acts as a special barrier to prevent cross-contamination between observables while maintaining normal score aggregation. The barrier has two components:

**1. Calculation Phase Barrier (Root as Child)**

When root appears as a child of other observables, it is **SKIPPED** in their score calculations:

- Observables that have root as a child do NOT include root's score
- This prevents cross-contamination between separate branches linked through root
- Example: If `domain -> root <- ip`, both domain and ip skip root's score

```python
# Example: Cross-contamination prevention
domain = cv.observable(cv.OBS.DOMAIN, "branch1.com")
domain.with_ti("source1", score=Decimal("9.0"))

ip = cv.observable(cv.OBS.IPV4, "192.0.2.1")
ip.with_ti("source2", score=Decimal("1.0"))

root = cv.root()

# Both have root as child
cv.observable_add_relationship(domain, root, cv.REL.RELATED_TO, direction=cv.DIR.OUTBOUND)
cv.observable_add_relationship(ip, root, cv.REL.RELATED_TO, direction=cv.DIR.OUTBOUND)

# Results:
# - domain score: 9.0 (only its TI, root skipped)
# - ip score: 1.0 (only its TI, root skipped)
# - root score: 9.0 (aggregates domain and ip normally)
# - domain and ip remain isolated despite shared root connection
```

**2. Propagation Phase Barrier (Root as Parent)**

Root's propagation behavior is asymmetric:

- **Root CAN be updated**: When children's scores change, root recalculates normally
  - Root aggregates child scores: `max(root TI, child scores)` in MAX mode
  - Root acts as aggregation point for investigation tree

- **Root does NOT propagate upward**: After root updates, propagation stops
  - If root has parent relationships, they are not affected by root's score changes
  - Prevents upstream contamination beyond root
  - Updates flow TO root but not THROUGH root

- **Root DOES propagate to findings**: Root propagates to linked findings normally
  - Findings can reflect root's aggregated investigation score

**Why the Barrier?**

The root barrier design enables:
- **Isolation**: Separate investigation branches remain independent
- **Aggregation**: Root still collects overall investigation severity
- **Flexibility**: You can link arbitrary observables to root without contamination
- **Clarity**: Parent observables only reflect their direct threat landscape
  - Findings referencing the root observable receive root's final score
  - Maintains expected behavior for verification steps

This barrier ensures that observables linked through the root remain isolated from each other while the root itself properly aggregates threat intelligence from its investigation tree.

**Examples:**

```python
from cyvest import Cyvest
from decimal import Decimal

cv = Cyvest()

# Example 1: OUTBOUND - Domain → IP (IP is child)
domain = cv.observable_create(cv.OBS.DOMAIN, "malware.com")
cv.observable_add_threat_intel(domain.key, "virustotal", score=Decimal("2.0"))

ip = cv.observable_create(cv.OBS.IPV4, "198.51.100.42")
cv.observable_add_threat_intel(ip.key, "abuseipdb", score=Decimal("8.0"))

# Domain resolves to IP (OUTBOUND by default)
cv.observable_add_relationship(domain, ip, cv.REL.RELATED_TO, cv.DIR.OUTBOUND)

# Result: domain score = max(2.0, 8.0) = 8.0 (includes child IP score)
print(f"Domain score: {domain.score}")  # 8.0
print(f"IP score: {ip.score}")          # 8.0


# Example 2: INBOUND - File ← URL (URL is parent)
malware = cv.observable_create(cv.OBS.FILE, "trojan.exe")
cv.observable_add_threat_intel(malware.key, "av", score=Decimal("9.0"))

url = cv.observable_create(cv.OBS.URL, "http://evil.com/payload")
cv.observable_add_threat_intel(url.key, "urlscan", score=Decimal("3.0"))

# File downloaded from URL (INBOUND by default for DOWNLOADED)
cv.observable_add_relationship(malware, url, cv.REL.RELATED_TO, cv.DIR.INBOUND)

# Result: URL is parent, gets file's score
print(f"File score: {malware.score}")  # 9.0
print(f"URL score: {url.score}")        # 9.0 (includes child file score)


# Example 3: BIDIRECTIONAL - No hierarchy
host1 = cv.observable_create(cv.OBS.IPV4, "10.0.1.10")
cv.observable_add_threat_intel(host1.key, "ids", score=Decimal("7.0"))

host2 = cv.observable_create(cv.OBS.IPV4, "10.0.1.20")
cv.observable_add_threat_intel(host2.key, "ids", score=Decimal("2.0"))

# Hosts communicate (BIDIRECTIONAL by default)
cv.observable_add_relationship(host1, host2, cv.REL.RELATED_TO)

# Result: No hierarchical propagation, each keeps own score
print(f"Host1 score: {host1.score}")  # 7.0
print(f"Host2 score: {host2.score}")  # 2.0


# Example 4: Override semantic defaults
domain2 = cv.observable_create(cv.OBS.DOMAIN, "example.com")
cv.observable_add_threat_intel(domain2.key, "source", score=Decimal("1.0"))

ip2 = cv.observable_create(cv.OBS.IPV4, "192.0.2.1")
cv.observable_add_threat_intel(ip2.key, "source", score=Decimal("5.0"))

# Override default to BIDIRECTIONAL (no hierarchy)
cv.observable_add_relationship(
    domain2, ip2,  # Observable proxies
    cv.REL.RELATED_TO,
    cv.DIR.BIDIRECTIONAL
)

# Result: No propagation due to override
print(f"Domain score: {domain2.score}")  # 1.0
print(f"IP score: {ip2.score}")          # 5.0
```

**Multi-Level Hierarchy:**

Score propagation works recursively through multiple levels:

```python
# Grandparent → Parent → Child hierarchy
grandparent = cv.observable_create(cv.OBS.DOMAIN, "root.com")
cv.observable_add_threat_intel(grandparent.key, "source1", score=Decimal("1.0"))

parent = cv.observable_create(cv.OBS.DOMAIN, "sub.root.com")
cv.observable_add_threat_intel(parent.key, "source2", score=Decimal("2.0"))

child = cv.observable_create(cv.OBS.IPV4, "203.0.113.10")
cv.observable_add_threat_intel(child.key, "source3", score=Decimal("9.0"))

cv.observable_add_relationship(grandparent.key, parent.key, cv.REL.RELATED_TO, cv.DIR.OUTBOUND)
cv.observable_add_relationship(parent.key, child.key, cv.REL.RELATED_TO, cv.DIR.OUTBOUND)

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
- **NONE**: Default for new findings (no classification)

### Explicit vs. Calculated Levels

You can set levels explicitly or let them be calculated from scores:

```python
# Calculated from score via threat intel
cv.observable_add_threat_intel(obs.key, source="analysis", score=Decimal("8.0"))  # Becomes MALICIOUS

# Explicitly set through the facade
cv.observable_set_level(obs.key, cv.LVL.SAFE)  # Overrides calculation

# Higher calculated level wins when new intel arrives
cv.observable_add_threat_intel(obs.key, source="analysis", score=Decimal("9.0"))  # Changes to MALICIOUS
```

### SAFE Level Protection

The **SAFE level has special protection** against downgrades. When an observable is created with or set to `Cyvest.LVL.SAFE`, it cannot be downgraded to lower levels (NONE, TRUSTED, INFO) by threat intelligence or score updates, but can still be upgraded to higher levels (NOTABLE, SUSPICIOUS, MALICIOUS).

**Key Behaviors:**

1. **Automatic Protection**: Creating an observable with `level=SAFE` automatically enables downgrade protection
2. **Score Updates**: Scores still update based on threat intelligence, but the level won't downgrade
3. **Allows Upgrades**: SAFE observables can be upgraded to NOTABLE, SUSPICIOUS, or MALICIOUS if warranted
4. **Merge Preservation**: SAFE level is preserved during investigation merges
5. **Threat Intel Propagation**: Threat intel with `level=SAFE` can upgrade observables to SAFE level

**Example:**

```python
from cyvest import Cyvest
from decimal import Decimal

cv = Cyvest()

# Create a SAFE observable (e.g., known-good domain)
trusted = cv.observable_create(
    cv.OBS.DOMAIN,
    "trusted.example.com",
    score=0,
    level=cv.LVL.SAFE
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
uncertain = cv.observable_create(cv.OBS.DOMAIN, "example.com")
cv.observable_add_threat_intel(
    uncertain.key,
    "whitelist_service",
    score=Decimal("0"),
    level=cv.LVL.SAFE,
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

The SAFE protection **only applies to the SAFE level itself**. Other explicit levels (set via `cv.observable_set_level()` or explicit threat intel `level=`) don't have the same protection and can be overridden by higher calculated levels according to the normal rules.

**SAFE Propagation to Findings:**

Findings automatically inherit the SAFE level from their linked observables under specific conditions:

1. **At least one** linked observable has `Cyvest.LVL.SAFE`
2. **All** other linked observables have levels ≤ SAFE (NONE, TRUSTED, INFO, or SAFE)
3. The finding's current level is < SAFE

When these conditions are met, the finding is automatically set to SAFE level, overriding any previous level assignment.

```python
from decimal import Decimal
from cyvest import Cyvest

cv = Cyvest()

# Create a finding
finding = cv.finding_create("domain_finding", "Analyze domain reputation")

# Link a SAFE observable
safe_domain = cv.observable_create(cv.OBS.DOMAIN, "trusted.example.com", level=cv.LVL.SAFE)
cv.finding_link_observable(finding.key, safe_domain.key)

# Finding inherits SAFE level from the observable
print(f"Finding level: {finding.level}")  # Output: Finding level: SAFE

# Add INFO-level observables - finding remains SAFE
info_ip = cv.observable_create(cv.OBS.IPV4, "192.0.2.1")
cv.finding_link_observable(finding.key, info_ip.key)
print(f"Finding level: {finding.level}")  # Output: Finding level: SAFE

# Add MALICIOUS observable - finding upgrades to MALICIOUS
malicious_url = cv.observable_create(cv.OBS.URL, "http://malware.example")
cv.observable_add_threat_intel(malicious_url.key, "virustotal", score=Decimal("8.0"))
cv.finding_link_observable(finding.key, malicious_url.key)
print(f"Finding level: {finding.level}")  # Output: Finding level: MALICIOUS
```

This propagation ensures that findings analyzing whitelisted/trusted assets are properly marked as SAFE, while still allowing upgrades when actual threats are discovered.

## Relationships

Relationships let you link observables together. Use the Cyvest facade or proxy helpers (e.g., `cv.observable_add_relationship()` or `ObservableProxy.relate_to()`) so validation and score propagation stay consistent. These helpers raise `KeyError` if either observable key is missing.

```python
# Using observable proxies (recommended)
cv.observable_add_relationship(
    source=url,  # Observable proxy
    target=ip,   # Observable proxy
    relationship_type=cv.REL.PIVOT,
)

# Override direction to control score hierarchy
cv.observable_add_relationship(
    source=parent,
    target=child,
    relationship_type=cv.REL.RELATED_TO,
    direction=cv.DIR.OUTBOUND,  # child score flows to parent
)

# Using string keys
cv.observable_add_relationship(
    source=url.key,
    target=ip.key,
    relationship_type=cv.REL.RELATED_TO,
)
```

The vocabulary describes the analyst pivot that produced the target from the
source, not an ontology of the entities themselves. Read an edge as
"source → what I deduced from it":

| Type | Meaning | Default direction |
| --- | --- | --- |
| `EXTRACTION` | The target was extracted from the source: a URL in an email body, a hash of a file, an IP in a header. | `OUTBOUND` |
| `PIVOT` | The target was obtained by enriching the source: DNS resolution, whois, threat intel, sandbox detonation. | `OUTBOUND` |
| `RELATED_TO` | The observables correlate but the deduction mechanism is not established. | `BIDIRECTIONAL` |

An explicit direction always wins and remains the source of score propagation
semantics.

## Key Generation

Every object has a unique, deterministic key:

- **Observable without subtype**: `obs:{type}:{normalized_value}`
- **Scoped observable**: `obs:{type}:{subtype}:{namespace}:{normalized_value}`
- **Finding**: `fnd:{finding_name}`
- **Evidence**: `evd:{source}:{external_id}` or a content SHA-256 key
- **Threat Intel**: `ti:{source}:{observable_key}`
- **Enrichment**: `enr:{name}[:{context_hash}]`
- **Tag**: `tag:{name}`

Keys enable:
- Fast object retrieval
- Reliable merging
- Deduplication

The facade getters accept either keys or component parameters:

```python
obs = cv.observable_get(cv.OBS.URL, "https://malicious.com")
obs_by_key = cv.observable_get("obs:url:https://malicious.com")

finding = cv.finding_get("fnd:malware_detection")
```

`COMMAND_LINE` and identities longer than 128 bytes use deterministic SHA-256 keys. `EMAIL` represents an address,
while `USER/email` represents a user account identifier. Paths identifying executables use `FILE/path` and can be
related to a `PROCESS/pid` observable.

Low-level `Investigation` getters accept keys only; use the facade for component-based lookups.

## Root Observable

Every investigation has a **root observable** representing the analyzed artifact:

```python
cv = Cyvest()
root = cv.root()  # or cv.observable_get_root()
```

The root observable is automatically created with:
- **Type**: `cv.OBS.FILE` (default) or `cv.OBS.ARTIFACT` if `root_type=Cyvest.OBS.ARTIFACT`
- **Value**: `"root"` (fixed identifier)
- **Key**: `obs:file:root` or `obs:artifact:root` (derived from type + value)
- **Extra**: `root_data` passed to `Cyvest(root_data=...)`
- **Purpose**: Entry point for the investigation

### Root Observable Barrier

The root observable has special scoring behavior to isolate investigation branches:

**What the barrier does:**
1. Root's score is calculated **normally** using MAX or SUM mode algorithm
2. Root DOES aggregate scores from child observables (like any other observable)
3. Root does NOT propagate its score to parent observables (barrier blocks upward)
4. Root DOES propagate normally to linked findings

**Why this matters:**
- Root properly aggregates all threat intelligence from the investigation tree
- Observables linked through root remain isolated from each other
- Prevents root's aggregated score from contaminating unrelated parent observables
- Maintains proper finding scoring for root verification steps

**Example:**
```python
cv = Cyvest()
root = cv.root()

# Add threat intel to root
cv.observable_add_threat_intel(root.key, "scanner", score=Decimal("9.0"))

# Create observables linked to root
child = cv.observable_create(cv.OBS.URL, "https://example.com")
cv.observable_add_threat_intel(child.key, "urlscan", score=Decimal("5.0"))
cv.relationship_add(root.key, child.key, cv.REL.RELATED_TO, direction=cv.DIR.OUTBOUND)

# Create finding for root
finding = cv.finding_create("root-finding", "Validation finding")
cv.finding_link_observable(finding.key, root.key)

# Results (MAX mode):
# - root.score = max(9.0 TI, 5.0 child) = 9.0
# - child.score = 5.0 (NOT affected by root TI due to barrier)
# - finding.score = 9.0 (receives root score)
# - If root had a parent, parent.score would NOT include root's 9.0 (barrier blocks upward)
```

### Automatic Root Linking

Orphan observables (without relationships) are automatically linked to root with `cv.REL.RELATED_TO`.

## Statistics

Real-time statistics are available throughout the investigation:

```python
stats = cv.get_statistics()

# Access metrics
stats['total_observables']
stats['observables_by_type']
stats['observables_by_level']
stats['findings_by_level']
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

When you add any object (observable, finding, threat intel, etc.), Cyvest automatically:
1. Checks if an object with the same key exists
2. If yes: merges the new data into the existing object
3. If no: registers it as a new object

This eliminates duplicate objects and ensures consistency:

```python
cv = Cyvest()

# First creation
obs1 = cv.observable_create(cv.OBS.URL, "https://example.com", score=5.0)

# Adding same observable again - automatically merges!
obs2 = cv.observable_create(cv.OBS.URL, "https://example.com", score=7.0)

# obs1 and obs2 are the same object with merged data
assert obs1 is obs2
assert obs1.score == 7.0  # Higher score wins
```

### Merging Investigations

You can also merge entire investigations:

```python
# Create separate investigations
inv1 = Cyvest()
inv1.observable_create(inv1.OBS.URL, "https://example.com")

inv2 = Cyvest()
inv2.observable_create(inv2.OBS.IPV4, "192.168.1.1")

# Merge inv2 into inv1 - automatic deduplication
inv1.merge_investigation(inv2)

# CLI support for merging JSON files
# cyvest merge inv1.json inv2.json -o merged.json
```

**Merge strategies:**
- **Observables**: Higher score/level wins, comments overwrite (if incoming non-empty), relationships and threat intel merge
- **Findings**: Higher score/level wins, description/comment overwrite (if incoming non-empty), observables merge by key (not identity)
- **Threat Intel**: Higher score/level wins, taxonomies merge by name (incoming replaces same name)
- **Enrichments**: Deep merge of data dictionaries
- **Tags**: Merge of findings, hierarchy auto-reconstructed from names

## Next Steps

- Learn about [Observables](#observables) in detail
- Understand [Scoring & Levels](#scoring-system)
- Explore the [fluent helpers](quickstart.md#using-the-fluent-api) in practice
