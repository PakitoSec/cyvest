# Contributing to Cyvest

Thank you for helping us build a better investigation framework. This guide captures the recommended workflow, tooling, and review expectations so contributions stay consistent and easy to merge.

---

## Before You Start

| Task | Command |
| --- | --- |
| Fork and clone | `git clone https://github.com/PAKITOSEC/cyvest.git && cd cyvest` |
| Install runtime + dev deps (uv) | `uv sync --all-groups` |
| Install runtime + dev deps (pip) | `pip install -e . && pip install -e ".[dev]"` |
| Smoke test environment | `uv run pytest && uv run ruff check .` |

!!! note "Code of Conduct"
    We expect respectful, inclusive collaboration. Report unacceptable behaviour via GitHub Discussions or email.

---

## Standard Workflow

1. **Plan** — Align on scope in an issue or GitHub Discussion. Complex changes benefit from a short design note.
2. **Branch** — `git checkout -b feat/new-relationship-helper` (keep prefixes meaningful: `feat`, `fix`, `docs`, `test`, `chore`).
3. **Code** — Prefer small, focused commits. Mirror the module layout (`src/cyvest`, `tests/`, `docs/`).
4. **Validate** — Run the quality gates below before you push.
5. **Document** — Update relevant docs/snippets whenever behaviour changes.
6. **Submit** — Push your branch and open a PR describing motivation, approach, tests, and screenshots/CLI output when applicable.

---

## Quality Gates

```bash
# Fast feedback loop
ruff format .
ruff check .
pytest

# Full coverage / HTML report when touching scoring logic
pytest --cov=cyvest --cov-report=term-missing --cov-report=html
```

!!! tip "Docs changed?"
    Run `mkdocs serve` for live preview or `mkdocs build` before pushing to catch broken links or syntax errors. The docs use the Material theme with extra Markdown extensions enabled.

---

## Architecture Cliff Notes {: #architecture-overview }

| Layer | Role | Files |
| --- | --- | --- |
| **Investigation** | Authoritative state: the fact store, decisions, tags, and the evaluation entry point | `src/cyvest/investigation.py`, `src/cyvest/facts/store.py` |
| **Cyvest facade** | Public API + CLI entry, manages deterministic keys, exposes fluent helpers | `src/cyvest/cyvest.py`, `src/cyvest/cli.py` |
| **Proxy helpers** | Fluent builders for observables/findings/tags with merge-on-create semantics | `src/cyvest/proxies.py` |
| **Facts** | Immutable models for Observables, Findings, Signals, Evidences, Relations, Decisions, Tags | `src/cyvest/facts/` |
| **Evaluation** | Score engines, contribution combination, verdict projection, report and timeline derivation | `src/cyvest/evaluation/` |
| **Policy** | Weights, thresholds, attenuation and aggregation knobs handed to the engine | `src/cyvest/policy/` |

**Merge-on-create** keeps duplicates out by checking keys before inserts. When extending the fluent helpers, call back into `Investigation` for validation rather than mutating models directly.

---

## Testing Guidelines

- Prefer pytest-style fixtures and descriptive test names (`test_score_propagates_to_parent`).
- Separate behaviour tests (fluent helpers, CLI) from data-model regression tests.
- When touching concurrency/shared context, add a stress case under `tests/test_shared_context.py` or a new module.
- Keep coverage above 90% for touched modules; justify unavoidable gaps in the PR.

Example skeleton:

```python
def test_observable_merges_by_key() -> None:
    cv = Cyvest()

    first = cv.observable(cv.OBS.URL, "https://example.com")
    second = cv.observable(cv.OBS.URL, "https://example.com")

    assert first.key == second.key
    assert cv._investigation.get_observable(first.key) is not None
```

---

## Documentation Expectations

- User-facing changes require updates under `docs/` and, when applicable, a snippet in `README.md`.
- The docs site uses [MkDocs Material](https://squidfunk.github.io/mkdocs-material/). Enable the live preview with `mkdocs serve`.
- Keep prose in plain Markdown, use admonitions (`!!! note`) for callouts, and add code fences with `python`, `bash`, etc.

---

## Pull Requests

**Template**

1. Motivation / user-facing impact
2. Summary of design decisions
3. Testing evidence (commands + key output)
4. Screenshots / CLI snippets for Rich output or docs updates

Maintainers will review for correctness, coverage, docs, and adherence to coding style. Expect feedback on naming, error handling, and scoring regressions.

---

## Issue Guidelines

| Type | Include |
| --- | --- |
| **Bug** | Python + Cyvest versions, reproduction snippet, expected vs. actual behaviour, stack traces |
| **Feature** | Use case, desired API/CLI, example output, alternative approaches considered |

For quick questions or architecture discussions, open a GitHub Discussion before filing a feature request.

---

## Release & Licensing

All contributions fall under the MIT License. By submitting a PR you confirm you own the work and grant permission to license it accordingly.

Thank you for investing time and care into Cyvest! 🎉
