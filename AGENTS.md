# Repository Guidelines

## Project Structure & Module Organization
- `src/cyvest/` contains core models, visitor utilities, helpers, and the `builder` DSL; `__init__.py` exposes the public API.
- `tests/` holds pytest suites covering models (`test_models.py`), action flows (`test_action.py`), and report generation (`test_report.py`).
- `examples/` provides runnable entry points such as `basic_report.py` that demonstrate report orchestration.
- `pyproject.toml` centralizes dependencies, packaging metadata, and Ruff configuration; `uv.lock` pins toolchain versions.

## Build, Test, and Development Commands
- `uv sync --project .` creates a reproducible virtual environment aligned with `uv.lock`.
- `uv run --project . python examples/email_report.py` executes the rich email pipeline end-to-end.
- `uv run --project . python -m pytest tests` runs the full test suite; add `-k <pattern>` for focused runs.
- `uv run --project . ruff check` performs linting; pair with `uv run --project . ruff format --check` to verify formatting.

## Coding Style & Naming Conventions
- Target Python 3.10+ with 4-space indentation and 120-character lines (enforced via Ruff).
- Use snake_case for functions, PascalCase for models/visitors, and UPPER_SNAKE_CASE for enum members such as `ObsType.URL`.
- Keep visitor implementations pure and side-effect-free; log via `logurich.logger` rather than `print`.
- Export new public APIs through `src/cyvest/__init__.py` to keep downstream imports stable; when possible, thread them through the builder-friendly helpers.

## Testing Guidelines
- Pytest drives validation; colocate new suites under `tests/` with filenames that start with `test_`.
- Prefer data-driven parametrized tests for observable combinations and visitor behavior.
- When adding models or scoring helpers, assert both level resolution and emitted observables to avoid regressions.

## Commit & Pull Request Guidelines
- Follow the existing history pattern: concise, imperative subject lines (`Add derived level color helper`) and optional wrapped body explaining rationale.
- Reference related issues in the body (`Refs #123`) and note breaking changes explicitly.
- PRs should summarize behavior changes, list new commands or configs, and include screenshots for CLI output when relevant.
- Confirm `pytest` and the Ruff checks pass before requesting review, and link to the executed command outputs in the PR description.

## Security & Configuration Tips
- Avoid committing sample data with real indicators; redact observables in examples.
- Store environment-specific configuration outside the repo and inject via runtime parameters when running examples.
