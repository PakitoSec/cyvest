# Migrating from Cyvest 5.x to 6.0

Cyvest 6.0 introduces a new investigation vocabulary and a strict serialized
schema. The main breaking change is the replacement of **Check** by
**Finding**. Version 6 also adds reusable **Evidence** objects and richer
observable identities.

This guide covers both serialized investigations and Python integrations.

!!! warning "No compatibility aliases"
    Cyvest 6 does not expose the old `Check`, `CheckProxy`, `cv.check_*`, or
    `chk:` interfaces. Migrate stored documents and application code together.

## Migration overview

| Cyvest 5.x | Cyvest 6.0 |
| --- | --- |
| `Check` | `Finding` |
| `CheckProxy` | `FindingProxy` |
| `check_name` | `finding_name` |
| `checks` collection | `findings` collection |
| `chk:{name}` | `fnd:{name}` |
| No evidence entity | Reusable `Evidence` linked many-to-many to Findings |
| Basic observable identity | `type` + optional `subtype` + optional `namespace` |
| No required schema version | Exact `schema_version: "6.0.0"` |

The scoring model, relationship propagation, tags, enrichments, threat
intelligence, audit log, and immutable proxy behavior remain in place.

## 1. Upgrade Cyvest

Upgrade the package in an isolated environment:

```bash
pip install --upgrade "cyvest==6.0.0"
```

With `uv`:

```bash
uv add "cyvest==6.0.0"
```

Confirm that the v6 CLI is active:

```bash
cyvest --version
```

The command must report `6.0.0`.

## 2. Migrate serialized investigations

Back up the original v5 document, then run:

```bash
cyvest migrate investigation-v5.json -o investigation-v6.json
```

The migration command:

- sets `schema_version` to `6.0.0`;
- renames the root `checks` collection to `findings`;
- renames `check_name` to `finding_name`;
- rewrites `chk:` keys to `fnd:` keys;
- updates Finding references in tags and audit events;
- recalculates observable and threat-intelligence keys;
- initializes `evidences` and every `evidence_links` collection;
- preserves existing `EMAIL` observables;
- loads and serializes the result through the v6 models to validate it.

Cyvest 6 intentionally rejects documents with a missing or older
`schema_version`. Loading v5 JSON directly produces an error instructing you to
run the migration command.

!!! tip "Migrate generated fixtures too"
    Migrate checked-in examples, golden files, comparison baselines, and
    documents consumed by `@cyvest/cyvest-js`. The Python and TypeScript models
    expect the same v6 schema.

### Validate the migrated document

Load it with the CLI:

```bash
cyvest stats investigation-v6.json
cyvest show investigation-v6.json --no-graph
```

For application-level validation:

```python
from cyvest.io_serialization import load_investigation_json

cv = load_investigation_json("investigation-v6.json")
assert cv.finding_get_all()
```

Do not update keys with a global text replacement. Observable, threat
intelligence, tag, and audit references must remain consistent; the migration
command performs those updates as one validated operation.

## 3. Rename Check APIs to Finding APIs

Update imports, type annotations, variables, facade methods, and serialized
field access.

| Cyvest 5.x | Cyvest 6.0 |
| --- | --- |
| `Check` | `Finding` |
| `CheckProxy` | `FindingProxy` |
| `cv.check(...)` | `cv.finding(...)` |
| `cv.check_create(...)` | `cv.finding_create(...)` |
| `cv.check_get(...)` | `cv.finding_get(...)` |
| `cv.check_get_all()` | `cv.finding_get_all()` |
| `cv.check_link_observable(...)` | `cv.finding_link_observable(...)` |
| `cv.check_update_score(...)` | `cv.finding_update_score(...)` |
| `cv.tag_add_check(...)` | `cv.tag_add_finding(...)` |
| `tag.checks` | `tag.findings` |
| `observable.check_links` | `observable.finding_links` |
| `check_name` | `finding_name` |

The fluent behavior is otherwise unchanged.

Cyvest 5.x:

```python
check = (
    cv.check("suspicious_url", "Analyze suspicious URL")
    .link_observable(url)
    .with_score(8.0, reason="Malicious reputation")
    .tagged("network:url")
)
```

Cyvest 6.0:

```python
finding = (
    cv.finding("suspicious_url", "Analyze suspicious URL")
    .link_observable(url)
    .with_score(8.0, reason="Malicious reputation")
    .tagged("network:url")
)
```

Finding keys now use the `fnd:` prefix:

```python
finding = cv.finding_get("fnd:suspicious_url")
```

### Rename statistics and comparison expectations

Update statistics consumers:

| Cyvest 5.x | Cyvest 6.0 |
| --- | --- |
| `total_checks` | `total_findings` |
| `applied_checks` | `applied_findings` |
| `checks_by_level` | `findings_by_level` |

Comparison rules now use `finding_name`:

```python
from cyvest.compare import ExpectedResult

expected = ExpectedResult(
    finding_name="suspicious_url",
    score=">= 5.0",
)
```

Regenerate snapshots that contain `chk:` keys or Check-oriented labels.

## 4. Model observable identities

Cyvest 6 adds:

- `HOST`
- `PROCESS`
- `USER`
- `COMMAND_LINE`
- `CLOUD_RESOURCE`

These entity types can have multiple identifier forms. Use `subtype` to
describe the identifier and `namespace` when the value is only unique in a
specific authority, tenant, host, or platform.

```python
user = cv.observable(
    cv.OBS.USER,
    "alice",
    subtype=cv.SUB.USER_USERNAME,
    namespace="corp.example",
    internal=True,
)

host = cv.observable(
    cv.OBS.HOST,
    "workstation-42",
    subtype=cv.SUB.HOST_HOSTNAME,
    namespace="corp.example",
    internal=True,
)
```

### Built-in subtype rules

| Type | Built-in subtypes | Namespace requirement |
| --- | --- | --- |
| `USER` | `email`, `sid`, `upn`, `okta_id`, `username`, `uid` | Required for `okta_id`, `username`, and `uid` |
| `HOST` | `hostname`, `fqdn`, `netbios`, `device_id` | Required for `hostname`, `netbios`, and `device_id` |
| `PROCESS` | `pid`, `process_guid` | Required for `pid` |
| `FILE` | `path` | Required for `path` |
| `CLOUD_RESOURCE` | `aws_arn`, `azure_resource_id`, `gcp_resource_name` | Not required |
| `COMMAND_LINE` | None | Does not accept a subtype |

`USER`, `HOST`, `PROCESS`, and `CLOUD_RESOURCE` require a subtype.

### EMAIL versus USER/email

Keep `EMAIL` for an address observed in content, especially an external sender
or recipient that does not assert an internal account identity:

```python
sender = cv.observable(
    cv.OBS.EMAIL,
    "sender@external.example",
    internal=False,
)
```

Use `USER/email` when the address identifies a user account in the
investigation context:

```python
account = cv.observable(
    cv.OBS.USER,
    "alice@corp.example",
    subtype=cv.SUB.USER_EMAIL,
    internal=True,
)
```

`EMAIL` and `USER/email` are distinct observables even when their values are
equal. Relate them explicitly when the investigation establishes that they
refer to the same actor or account.

### Process identity and executable paths

An executable image path does not identify a process instance. Represent the
process by a PID scoped to a host, or by a process GUID:

```python
process = cv.observable(
    cv.OBS.PROCESS,
    "4242",
    subtype=cv.SUB.PROCESS_PID,
    namespace=host.key,
)
```

Represent the executable path as a `FILE/path` observable scoped to the host,
then relate it to the process:

```python
executable = cv.observable(
    cv.OBS.FILE,
    r"C:\Windows\System32\cmd.exe",
    subtype=cv.SUB.FILE_PATH,
    namespace=host.key,
)

process.relate_to(executable, cv.REL.RELATED_TO)
```

### Positional observable arguments

`subtype` and `namespace` are inserted after `value` in the v6 Python
signature. Existing code that passed `internal`, `whitelisted`, or later
arguments positionally must be changed to keyword arguments.

```python
# Avoid carrying this v5 positional form into v6:
cv.observable(cv.OBS.DOMAIN, "example.com", False, False)

# Use explicit keywords:
cv.observable(
    cv.OBS.DOMAIN,
    "example.com",
    internal=False,
    whitelisted=False,
)
```

## 5. Add Evidence where useful

Migration does not invent Evidence from existing Check comments or extras.
Migrated Findings start with an empty `evidence_links` collection.

Evidence is reusable supporting material with no score or security level:

```python
event = cv.evidence(
    "edr_event",
    "Suspicious process creation",
    "example-edr",
    external_id="event-4242",
    content={
        "host": "workstation-42",
        "pid": 4242,
        "image": r"C:\Windows\System32\cmd.exe",
    },
)

cv.finding("suspicious_process", "Suspicious process").link_evidence(event)
cv.finding("unexpected_shell", "Unexpected shell").link_evidence(event)
```

This is a many-to-many relation:

- `Finding.evidence_links` is the authoritative stored relation;
- `Evidence.finding_links` is rebuilt for navigation and UI rendering;
- one Evidence may support several Findings;
- one Finding may reference several Evidence objects.

Evidence must contain at least one of `content` or `uri`. `content` and `extra`
must be JSON-compatible. When supplied, `captured_at` must include timezone
information.

Evidence keys are deterministic:

- `evd:{source}:{external_id}` when `external_id` is available;
- a SHA-256 content key otherwise.

## 6. Review key-dependent integrations

Key formats in v6 include:

```text
obs:{type}:{normalized_value}
obs:{type}:{subtype}:{namespace}:{normalized_value}
fnd:{finding_name}
evd:{source}:{external_id}
```

Long identities and all `COMMAND_LINE` observables use deterministic SHA-256
keys. Review systems that:

- persist Cyvest keys as foreign identifiers;
- parse `chk:` or `obs:` strings manually;
- index Findings or Observables by key;
- compare serialized snapshots;
- construct UI routes from object keys.

Prefer Cyvest key helpers and facade getters over manual string construction.

## 7. Run migration validation

Run the project tests and regenerate schema-derived TypeScript types where
applicable:

```bash
ruff check src/cyvest tests
pytest -q
corepack pnpm -C js -r run test:ci
corepack pnpm -C js -r run build
```

For a downstream integration, add tests that cover:

1. loading every migrated fixture;
2. Finding scores and levels before and after migration;
3. tag membership and observable links;
4. `EMAIL` versus `USER/email` identity;
5. process PID scoping by host;
6. Evidence shared by more than one Finding;
7. comparison baselines using `fnd:` keys.

## Troubleshooting

### Unsupported or missing schema version

The document was not migrated:

```bash
cyvest migrate old.json -o migrated.json
```

### Observable type requires a subtype

Add an identifier subtype for `USER`, `HOST`, `PROCESS`, or
`CLOUD_RESOURCE`.

### Observable requires a namespace

The selected identity is only locally unique. Supply the relevant tenant,
directory, host key, domain, or provider authority as `namespace`.

### COMMAND_LINE does not accept a subtype

Store the full command line as the value. Cyvest hashes its canonical identity
for the key automatically.

### Evidence requires content or URI

Provide structured `content`, a retrievable `uri`, or both. A title and source
alone are not sufficient.

## Completion checklist

- [ ] The runtime and CLI report version `6.0.0`.
- [ ] Every persisted v5 document has been migrated with `cyvest migrate`.
- [ ] Python imports and facade calls use Finding terminology.
- [ ] No application logic depends on `chk:` keys.
- [ ] Statistics and comparison rules use Finding field names.
- [ ] Positional observable calls have been converted to keyword arguments.
- [ ] New entity observables use appropriate subtype and namespace values.
- [ ] External addresses remain `EMAIL`; asserted accounts use `USER`.
- [ ] Process image paths use `FILE/path`, not `PROCESS`.
- [ ] Evidence payloads and links are covered by tests.
- [ ] Python tests, JavaScript tests, and generated-schema consumers pass.
