# Cyvest – Cyber Investigation Model

Reusable investigation domain models, visitor helpers, and reporting utilities for incident responders. Cyvest provides
a consistent data model for threat intelligence, observables, and result checks while keeping the visitor layer
extensible for bespoke workflows.

> Tip: add project badges (build, coverage, PyPI) here once CI is configured.

## Features

- Composition-friendly report builder that nests containers and checks.
- Observable graph with automatic score/level propagation across relationships.
- Visitor implementations for generating JSON/markdown reports or capturing follow-up actions.
- Tested patterns for merging external intel feeds (VirusTotal, sandbox runs, allow-lists).

## Installation

Cyvest targets Python 3.10+ and is published on PyPI:

```bash
uv pip install cyvest
```

## Quick start

Create a new report with nested containers and observables:

```python
from cyvest import Level, ObsType, ReportBuilder, Scope

builder = ReportBuilder(graph=True)

with builder.container("body", scope=Scope.BODY) as body:
    check = body.add_check("url_scan", description="Detected suspicious URL")
    check.add_observable_chain(
        [
            {
                "obs_type": ObsType.URL,
                "value": "http://example.test",
                "intel": {"name": "sandbox", "score": 4, "level": Level.SUSPICIOUS},
            }
        ]
    )

report = builder.build()
print(report.to_json())
```

Run the bundled example:

```bash
uv sync
uv run python examples/basic_report.py
```

## Development workflow

Set up dependencies with uv:

```bash
uv sync
```

Execute the unit suite:

```bash
uv run pytest tests
```

Lint and format using Ruff:

```bash
uv run ruff check
uv run ruff format --check
```

## Graph & model axioms

1. Cyclic graphs on observables or containables are not supported.
2. Every root containable model must be visited. (Observables may be skipped because parent links are tracked.)
3. Child observables do not update result checks linked only to their parents.
4. A `ResultCheck` score cannot be changed by an observable that is mutated elsewhere.
5. Adding an observable to a `ResultCheck` promotes the check to at least `Level.INFO` (a `Level.NONE` check becomes INFO).

See `examples/` and the tests under `tests/` for more scenarios, including how to subclass the provided visitors to
integrate your own tooling.
