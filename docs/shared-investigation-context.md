# SharedInvestigationContext

> **Note**: This is an advanced feature that requires direct import from `cyvest.shared`. It is not part of the main `Cyvest` facade API.

## Overview

The `SharedInvestigationContext` enables safe sharing of observables and checks across concurrent tasks (threads or asyncio). This allows tasks to reuse and reference observables created by other tasks, preventing duplication and enabling aggregated checks.

**Usage**: Import directly from the shared module:
```python
from cyvest.shared import SharedInvestigationContext
```

## Features

- **Sync + Async**: Same implementation supports threads and asyncio
- **Async-safe**: Async APIs run critical sections in a worker thread (no event-loop blocking)
- **Auto-Reconcile**: Works with both `with` and `async with`
- **Cross-Task Sharing**: Tasks can access observables/checks created by other tasks
- **Deep Copying**: Prevents concurrent modification issues

## Basic Usage

```python
from cyvest.shared import SharedInvestigationContext
from cyvest import ObservableType
from concurrent.futures import ThreadPoolExecutor

# Create a shared context from the main investigation
shared_context = SharedInvestigationContext(main_investigation)

# Use in a worker with auto-reconcile
def my_worker(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        cy.observable(ObservableType.EMAIL_ADDR, data.get("email"))
```

## Cross-Task Observable Sharing

Tasks can access observables created by other tasks:

```python
from cyvest import ObservableType, RelationshipType

def email_from(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        cy.observable(ObservableType.DOMAIN_NAME, data.get("domain"))


def bodies_url(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        domain_info = shared_context.get_observable(ObservableType.DOMAIN_NAME, "malicious.com")
        if domain_info:
            cy.observable(ObservableType.URL, data.get("url")).relate_to(
                cy.observable(ObservableType.DOMAIN_NAME, domain_info.value),
                RelationshipType.RELATED_TO,
            )
```

## API Reference

### SharedInvestigationContext

#### Constructor
```python
SharedInvestigationContext(main_investigation: Investigation)
```
Creates a shared context from a main investigation. Automatically inherits `root_type`, `score_mode`, and `data`.

#### Methods

##### `create_cyvest(data=None) -> _CyvestContextManager`
Returns a context manager that creates a `Cyvest` instance and auto-reconciles on exit.

**Parameters:**
- `data`: Optional override data (defaults to main investigation's data)

**Returns:** Context manager yielding a `Cyvest` instance

**Example:**
```python
with shared_context.create_cyvest() as cy:
    # Build investigation fragment
    cy.observable(...)
    return cy  # Automatically reconciled
```

##### `reconcile(source: Cyvest | Investigation) -> None`
Manually merges observables and checks from a source into the shared context.

**Parameters:**
- `source`: Cyvest or Investigation instance to merge

**Thread-Safety:** Uses lock to ensure safe concurrent merging

##### `get_observable(key: str) -> Observable | None`
##### `get_observable(obs_type: str | ObservableType, value: str) -> Observable | None`
Retrieves a shared observable by its key or by type and value.

**Parameters:**
- **Key-based lookup**: `key` - Observable key (format: `obs:type:value`)
- **Parameter-based lookup** (recommended):
  - `obs_type` - Observable type (string like `"email-addr"` or `ObservableType` enum)
  - `value` - Observable value

**Returns:** Deep copy of the observable, or `None` if not found

**Examples:**
```python
# Parameter-based lookup (recommended) - cleaner and type-safe
domain = shared_context.get_observable(ObservableType.DOMAIN_NAME, "malicious.com")
email = shared_context.get_observable("email-addr", "user@example.com")

# Key-based lookup (advanced usage)
domain = shared_context.get_observable("obs:domain-name:malicious.com")

# Use in task to reference observables from other tasks
if domain:
    cy.observable(ObservableType.URL, "https://example.com").relate_to(
        cy.observable(ObservableType.DOMAIN_NAME, domain.value),
        RelationshipType.RELATED_TO,
    )
```

##### `get_check(key: str) -> Check | None`
##### `get_check(check_id: str, scope: str) -> Check | None`
Retrieves a shared check by its key or by check ID and scope.

**Parameters:**
- **Key-based lookup**: `key` - Check key (format: `chk:id:scope`)
- **Parameter-based lookup** (recommended):
  - `check_id` - Check identifier
  - `scope` - Check scope

**Returns:** Deep copy of the check, or `None` if not found

**Examples:**
```python
# Parameter-based lookup (recommended) - cleaner and more intuitive
from_check = shared_context.get_check("from", "header")
malware_check = shared_context.get_check("malware_scan", "attachment")

# Key-based lookup (advanced usage)
from_check = shared_context.get_check("chk:from:header")
```

##### `find_observables_by_type(obs_type: ObservableType) -> list[Observable]`
Finds all observables of a specific type.

**Parameters:**
- `obs_type`: Observable type to search for

**Returns:** List of deep copies of matching observables

##### `find_observables_by_value(value: str) -> list[Observable]`
Finds all observables with a specific value.

**Parameters:**
- `value`: Observable value to search for

**Returns:** List of deep copies of matching observables

##### `has_observable(key: str) -> bool`
##### `has_observable(obs_type: str | ObservableType, value: str) -> bool`
Checks if an observable exists in the shared context.

**Parameters:**
- **Key-based**: `key` - Observable key
- **Parameter-based** (recommended): `obs_type`, `value` - Observable type and value

**Examples:**
```python
# Parameter-based check (recommended)
if shared_context.has_observable(ObservableType.EMAIL_ADDR, "sender@domain.com"):
    # Observable exists

# Key-based check
if shared_context.has_observable("obs:email-addr:sender@domain.com"):
    # Observable exists
```

##### `has_check(key: str) -> bool`
##### `has_check(check_id: str, scope: str) -> bool`
Checks if a check exists in the shared context.

**Parameters:**
- **Key-based**: `key` - Check key
- **Parameter-based** (recommended): `check_id`, `scope` - Check ID and scope

**Examples:**
```python
# Parameter-based check (recommended)
if shared_context.has_check("malware_scan", "attachment"):
    # Check exists

# Key-based check
if shared_context.has_check("chk:malware_scan:attachment"):
    # Check exists
```

##### `list_observables() -> list[str]`
Returns a list of all observable keys in the shared context.

##### `list_checks() -> list[str]`
Returns a list of all check keys in the shared context.

##### `is_whitelisted() -> bool`
Returns whether the underlying investigation has whitelist entries.

##### `get_global_level() -> Level`
Returns the global level of the underlying investigation.

##### `io_to_markdown(include_containers: bool = False, include_enrichments: bool = False, include_observables: bool = True) -> str`
Generate a Markdown report of the shared investigation with optional sections.

Thread-safe: Uses lock to ensure consistent read of investigation state.

**Parameters:**
- `include_containers`: Include containers section in the report (default: `False`)
- `include_enrichments`: Include enrichments section in the report (default: `False`)
- `include_observables`: Include observables section in the report (default: `True`)

**Returns:** Markdown formatted report as a string

**Examples:**
```python
shared = SharedInvestigationContext(main_inv)
markdown = shared.io_to_markdown()
print(markdown)
```

##### `io_save_markdown(filepath: str | Path, include_containers: bool = False, include_enrichments: bool = False, include_observables: bool = True) -> str`
Save the shared investigation as a Markdown report.

Thread-safe: Uses lock to ensure consistent read. Relative paths are converted to absolute paths.

**Parameters:**
- `filepath`: Path to save the Markdown file (relative or absolute)
- `include_containers`: Include containers section in the report (default: `False`)
- `include_enrichments`: Include enrichments section in the report (default: `False`)
- `include_observables`: Include observables section in the report (default: `True`)

**Returns:** Absolute path to the saved file as a string

**Examples:**
```python
shared = SharedInvestigationContext(main_inv)
path = shared.io_save_markdown("report.md")
print(path)  # /absolute/path/to/report.md

path_no_obs = shared.io_save_markdown("report_redacted.md", include_observables=False)
```

##### `io_to_dict() -> dict[str, Any]`
Serialize the shared investigation to a dictionary.

Thread-safe: Uses lock to ensure consistent read of investigation state.

**Returns:** Dictionary representation suitable for JSON export

**Examples:**
```python
shared = SharedInvestigationContext(main_inv)
data = shared.io_to_dict()
print(data.keys())
```

##### `io_save_json(filepath: str | Path) -> str`
Save the shared investigation to a JSON file.

Thread-safe: Uses lock to ensure consistent read. Relative paths are converted to absolute paths.

**Parameters:**
- `filepath`: Path to save the JSON file (relative or absolute)

**Returns:** Absolute path to the saved file as a string

**Examples:**
```python
shared = SharedInvestigationContext(main_inv)
path = shared.io_save_json("investigation.json")
print(path)  # /absolute/path/to/investigation.json
```

> Access merged results by reusing the original `Investigation` instance you passed to `SharedInvestigationContext`; reconciliation mutates it in place.

## Thread Safety

The implementation uses several strategies to ensure safe concurrency:

1. **Single critical section**: Merge + registry refresh are atomic
2. **Deep Copying**: All returned observables/checks are deep copies
3. **Async-safe access**: Async APIs run critical sections in a worker thread
4. **Immutable Keys**: Observable/check keys are immutable strings

## Performance Considerations

- **Deep Copying Overhead**: Each access creates a deep copy (safe but slower)
- **Lock Contention**: Heavy concurrent access may cause some blocking
- **Memory Usage**: Shared context maintains references to all observables/checks

## Example: Multi-Threaded Email Investigation

See `examples/04_email.py` for a complete working example demonstrating:
- Parallel task execution with `ThreadPoolExecutor`
- Auto-reconcile pattern for clean code
- Cross-task observable sharing between `EmailFrom` and `BodiesUrlTask`
- Aggregated checks across multiple concurrent tasks

## Best Practices

1. **Always use context manager**: `with shared_context.create_cyvest() as cy:`
2. **Access data from root**: `data = cy.root().extra` to get the investigation data
3. **Check for None**: Always check if `get_observable()` returns None
4. **Meaningful keys**: Use descriptive observable keys for easy lookup
5. **Task ordering**: Consider task dependencies when designing workflows
6. **Error handling**: Wrap task execution in try/except for robustness

## Limitations

- Observable/check keys must be unique across the investigation
- Deep copying may impact performance for very large investigations
- Lock contention possible with high concurrency (>10-20 threads)
- No built-in task dependency management (use task ordering)
