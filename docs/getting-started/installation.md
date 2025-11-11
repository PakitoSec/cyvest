# Installation

## Requirements

- Python 3.10 or higher
- pip or uv package manager

## Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package installer and resolver.

### Install uv

```bash
# On macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Install Cyvest

```bash
# Clone the repository
git clone https://github.com/yourusername/cyvest.git
cd cyvest

# Install dependencies
uv sync

# Install in development mode
uv pip install -e .
```

## Using pip

```bash
# Clone the repository
git clone https://github.com/yourusername/cyvest.git
cd cyvest

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .
```

## Verify Installation

```bash
# Check version
python -c "import cyvest; print(cyvest.__version__)"

# Run CLI
cyvest --version
```

## Development Installation

To install with development dependencies (testing, linting, documentation):

```bash
# Using uv
uv sync --all-extras

# Using pip
pip install -e ".[dev]"
```

This includes:
- `pytest` for testing
- `pytest-cov` for coverage reports
- `ruff` for linting and formatting
- `mypy` for type checking
- `mkdocs` and `mkdocs-material` for documentation

## Optional Dependencies

Cyvest has minimal required dependencies by design:
- `logurich` - Logging with Rich integration
- `rich` - Beautiful terminal output

All other tools are optional development dependencies.

## Next Steps

After installation, proceed to the [Quick Start Guide](quickstart.md) to begin using Cyvest.
