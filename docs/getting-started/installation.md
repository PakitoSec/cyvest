# Installation

Cyvest is published on PyPI. Installing the package gives you both the `cyvest` module and the
`cyvest` CLI; nothing else is required to build, score, and serialize an investigation.

---

## Requirements Checklist

| Component | Minimum |
| --- | --- |
| Python | `>= 3.10` |
| Package manager | [uv](https://github.com/astral-sh/uv) **or** pip |
| Node.js | `>= 22`, only for the `@cyvest/*` JavaScript packages |

---

## Option 1 · uv (recommended)

```bash
uv add cyvest
```

To get the CLI without adding Cyvest to a project:

```bash
uv tool install cyvest
```

Or run it once without installing anything:

```bash
uvx --from cyvest cyvest --help
```

---

## Option 2 · pip

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install cyvest
```

---

## Option 3 · From source

Use this only to work **on** Cyvest — see [Contributing](../contributing.md) for the full loop.

```bash
git clone https://github.com/PakitoSec/cyvest.git
cd cyvest

# Runtime + dev + docs dependency groups, resolved from uv.lock
uv sync --all-groups
```

`uv sync` installs the project in editable mode, so `uv run cyvest` reflects your working tree
immediately. There is no separate `uv pip install -e .` step.

---

## JavaScript packages

```bash
pnpm add @cyvest/cyvest-js          # typed reader for the JSON documents
pnpm add @cyvest/cyvest-vis         # React graph components
```

Their version tracks the Python one: `@cyvest/cyvest-js@7.0.0` reads the documents written by
`cyvest==7.0.0`. See [JS packages](../js-packages.md).

---

## Post-Install Validation

```bash
# Confirm the module resolves
python -c "import cyvest; print(cyvest.__version__)"

# Confirm the CLI entrypoint
cyvest --version
```

Both must report the same version.

---

## Next Steps

- Build your first investigation in [Quick Start](quickstart.md)
- Deep dive into [Core Concepts](concepts.md)
- Upgrade an existing integration with the [v6 to v7 migration guide](../migration-v6-to-v7.md)
