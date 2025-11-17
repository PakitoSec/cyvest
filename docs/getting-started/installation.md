# Installation

The fastest way to evaluate Cyvest is to install it in editable mode so the CLI, DSL, and docs stay in sync with your workspace.

---

## Requirements Checklist

| Component | Minimum |
| --- | --- |
| Python | `>= 3.10` (3.11+ recommended for perf) |
| Package manager | [uv](https://github.com/astral-sh/uv) **or** pip |
| Tooling (dev profile) | `pytest`, `pytest-cov`, `ruff`, `mypy`, `mkdocs-material` |

!!! tip "Using the repository CLI?"
    Run `uv pip install -e .` after syncing dependencies so local changes are immediately reflected in the `cyvest` command.

---

## Option 1 · uv (recommended)

```bash
# Install uv (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install uv (Windows PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# Clone and bootstrap
git clone https://github.com/PAKITOSEC/cyvest.git
cd cyvest

# Sync runtime + dev extras defined in pyproject/uv.lock
uv sync --all-extras

# Editable install to expose the CLI + module
uv pip install -e .
```

---

## Option 2 · pip

```bash
git clone https://github.com/PAKITOSEC/cyvest.git
cd cyvest

# (Recommended) create an isolated environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# Install runtime
pip install -e .

# Install development profile
pip install -e ".[dev]"
```

---

## Post-Install Validation

```bash
# Confirm the module resolves
python -c "import cyvest; print(cyvest.__version__)"

# Confirm the CLI entrypoint
cyvest --help
```

When dependencies change upstream, re-run `uv sync --all-extras` (or `pip install -e ".[dev]"`) to stay aligned with CI.

---

## Optional Integrations

- `mkdocs` + `mkdocs-material` for local docs previews (`mkdocs serve`)
- `pyvis` via `pip install "cyvest[visualization]"` for the interactive network graph CLI
- Any asyncio, queue, or orchestration library—Cyvest stays synchronous but interoperates through shared context managers

---

## Next Steps

- Build your first investigation in [Quick Start](quickstart.md)
- Deep dive into [Core Concepts](concepts.md)
- Preview the docs site with `mkdocs serve`
