# SharedInvestigationContext

> **Note**: This is an advanced feature. You can create it via `Cyvest.shared_context()` or import `SharedInvestigationContext` directly.

## Overview

The `SharedInvestigationContext` enables safe sharing of observables and checks across concurrent tasks (threads or asyncio). This allows tasks to reuse and reference observables created by other tasks, preventing duplication and enabling aggregated checks.

**Usage**: Create from a Cyvest instance or import directly from the shared module:
```python
from cyvest import Cyvest
from cyvest.shared import SharedInvestigationContext
```

## Features

- **Sync + Async**: Same implementation supports threads and asyncio
- **Single Lock**: Canonical state is protected by one `threading.RLock`
- **Async-safe**: Async APIs run the entire critical section in a worker thread via `asyncio.to_thread(...)` (no event-loop blocking)
- **Auto-Reconcile**: Works with both `with` and `async with`
- **Cross-Task Sharing**: Tasks can access observables/checks created by other tasks
- **Deep Copying**: Prevents concurrent modification issues

## Basic Usage

```python
from cyvest import Cyvest

# Create a shared context from the main Cyvest instance
main_cy = Cyvest(root_data=main_data, root_type=Cyvest.OBS.ARTIFACT)
shared_context = main_cy.shared_context()

# Use in a worker with auto-reconcile
def my_worker(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        cy.observable(cy.OBS.EMAIL_ADDR, data.get("email"))
```

## Cross-Task Observable Sharing

Tasks can access observables created by other tasks:

```python
def email_from(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        cy.observable(cy.OBS.DOMAIN_NAME, data.get("domain"))


def bodies_url(shared_context):
    with shared_context.create_cyvest() as cy:
        data = cy.root().extra
        domain_info = shared_context.observable_get(cy.OBS.DOMAIN_NAME, "malicious.com")
        if domain_info:
            cy.observable(cy.OBS.URL, data.get("url")).relate_to(
                cy.observable(cy.OBS.DOMAIN_NAME, domain_info.value),
                cy.REL.RELATED_TO,
            )
```

## API Reference

### SharedInvestigationContext

#### Constructor
```python
SharedInvestigationContext(
    main_cyvest: Cyvest,
    *,
    lock: threading.RLock | None = None,
    max_async_workers: int | None = None,
)
```
Creates a shared context from a main Cyvest instance. Automatically inherits `root_type`, `score_mode_obs`, and `root_data`.
`max_async_workers` (optional) limits concurrent async callers.

#### Methods

##### `create_cyvest(root_data=None) -> _CyvestContextManager`
Returns a context manager that creates a `Cyvest` instance and auto-reconciles on exit.

**Parameters:**
- `root_data`: Optional override data (defaults to the main Cyvest root data)

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

**Thread-Safety:** Merge + registry refresh are atomic under the shared `threading.RLock`.

##### `areconcile(source: Cyvest | Investigation) -> None`
Async equivalent of `reconcile()`. Runs the entire critical section in a worker thread.

##### `observable_get(obs_type: ObservableType, value: str) -> Observable | None`
Retrieves a shared observable by type and value.

**Parameters:**
- `obs_type`: Observable type (use `Cyvest.OBS.*` for the official vocabulary)
- `value`: Observable value

**Returns:** Deep copy of the observable, or `None` if not found

**Examples:**
```python
from cyvest import Cyvest

domain = shared_context.observable_get(Cyvest.OBS.DOMAIN_NAME, "malicious.com")
email = shared_context.observable_get(Cyvest.OBS.EMAIL_ADDR, "user@example.com")

# Use in task to reference observables from other tasks
if domain:
    cy.observable(cy.OBS.URL, "https://example.com").relate_to(
        cy.observable(cy.OBS.DOMAIN_NAME, domain.value),
        cy.REL.RELATED_TO,
    )
```

##### `check_get(check_name: str) -> Check | None`
Retrieves a shared check by name.

**Parameters:**
- `check_name`: Check name

**Returns:** Deep copy of the check, or `None` if not found

**Examples:**
```python
from_check = shared_context.check_get("from_verification")
malware_check = shared_context.check_get("malware_scan")
```

##### Existence checks
Use `observable_get(...)` / `check_get(...)` and check for `None`.

##### `is_whitelisted() -> bool`
Returns whether the underlying investigation has whitelist entries.

##### `get_global_level() -> Level`
Returns the global level of the underlying investigation.

##### `io_to_markdown(include_tags: bool = False, include_enrichments: bool = False, include_observables: bool = True) -> str`
Generate a Markdown report of the shared investigation with optional sections.

Thread-safe: Uses lock to ensure consistent read of investigation state.

**Parameters:**
- `include_tags`: Include tags section in the report (default: `False`)
- `include_enrichments`: Include enrichments section in the report (default: `False`)
- `include_observables`: Include observables section in the report (default: `True`)

**Returns:** Markdown formatted report as a string

**Examples:**
```python
shared = main_cy.shared_context()
markdown = shared.io_to_markdown()
print(markdown)
```

##### `io_save_markdown(filepath: str | Path, include_tags: bool = False, include_enrichments: bool = False, include_observables: bool = True) -> str`
Save the shared investigation as a Markdown report.

Thread-safe: Uses lock to ensure consistent read. Relative paths are converted to absolute paths.

**Parameters:**
- `filepath`: Path to save the Markdown file (relative or absolute)
- `include_tags`: Include tags section in the report (default: `False`)
- `include_enrichments`: Include enrichments section in the report (default: `False`)
- `include_observables`: Include observables section in the report (default: `True`)

**Returns:** Absolute path to the saved file as a string

**Examples:**
```python
shared = main_cy.shared_context()
path = shared.io_save_markdown("report.md")
print(path)  # /absolute/path/to/report.md

path_no_obs = shared.io_save_markdown("report_redacted.md", include_observables=False)
```

##### `io_to_invest() -> InvestigationSchema`
Serialize the shared investigation to an `InvestigationSchema`.

Thread-safe: Uses lock to ensure consistent read of investigation state.

**Returns:** `InvestigationSchema` instance (use `.model_dump(mode="json", by_alias=True)` for JSON-ready dict)

**Examples:**
```python
shared = main_cy.shared_context()
schema = shared.io_to_invest()
print(schema.score, schema.level)
```

##### `io_save_json(filepath: str | Path) -> str`
Save the shared investigation to a JSON file.

Thread-safe: Uses lock to ensure consistent read. Relative paths are converted to absolute paths.

**Parameters:**
- `filepath`: Path to save the JSON file (relative or absolute)

**Returns:** Absolute path to the saved file as a string

**Examples:**
```python
shared = main_cy.shared_context()
path = shared.io_save_json("investigation.json")
print(path)  # /absolute/path/to/investigation.json
```

> Access merged results by reusing the original `Cyvest` instance you passed to `SharedInvestigationContext`; reconciliation mutates it in place.

!!! note "Provenance-aware reconciliation"
    `investigation_id` is serialized and checks carry canonical provenance (`origin_investigation_id`) for LOCAL_ONLY propagation.

## Thread Safety

The implementation uses several strategies to ensure safe concurrency:

1. **Single lock**: Canonical state is protected by one `threading.RLock`
2. **Deep Copying**: All returned observables/checks are deep copies
3. **Async-safe access**: Async APIs run the entire critical section in a worker thread (never on the event loop)
4. **Immutable Keys**: Observable/check keys are immutable strings

## Async Usage

```python
import asyncio
from cyvest.shared import SharedInvestigationContext

async def worker(shared: SharedInvestigationContext):
    async with shared.create_cyvest() as cy:
        cy.observable(cy.OBS.DOMAIN_NAME, "example.com")

asyncio.run(worker(shared_context))
```

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
3. **Check for None**: Always check if `observable_get()` returns None
4. **Meaningful keys**: Use descriptive observable keys for easy lookup
5. **Task ordering**: Consider task dependencies when designing workflows
6. **Error handling**: Wrap task execution in try/except for robustness

## Limitations

- Observable/check keys must be unique across the investigation
- Deep copying may impact performance for very large investigations
- Lock contention possible with high concurrency (>10-20 threads)
- No built-in task dependency management (use task ordering)
