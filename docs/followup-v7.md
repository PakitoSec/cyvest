# Cyvest 7 — follow-up

What the v7 rewrite left open, ordered by risk. Everything here was checked against the
repository, not against the plan: percentages come from `pytest --cov`, absences from `ls`.

Status at the time of writing: 197 Python tests, 44 JS tests, lint clean, `mkdocs build --strict`
clean, `scripts/generate.sh` green end to end, the six examples run without a single error in
their output. Python coverage 78 %.

---

## 0. Done since the rewrite

**`tests/test_cli.py` — 32 tests, `cli.py` from 0 % to 79 %.** The remaining uncovered lines are
the `extract` command, untouched by the v7 port.

Writing them surfaced three defects that manual testing had missed:

- **`reevaluate()` computed a report and threw it away.** It never installed the result, so
  `--engine` had no observable effect whatsoever — the option was decorative. It now writes the
  chosen engine to the header, which survives the next fact append and is recorded on save.
- **A report named the wrong engine.** `_Evaluation` hardcoded `BasicEngine.engine_id`, so any
  engine reusing that pass would label its reports with someone else's name. That field is what
  `compare_investigations` reads to refuse incomparable diffs, so the safety check was built on a
  value that could lie.
- **`explain` on an unknown key rendered an empty table.** "Nothing contributed" and "this key
  does not exist" are different statements; a typo now raises.

One documentation inaccuracy was corrected at the same time: `--engine` does not "re-derive rather
than trust the file". Python **always** discards the stored report on load and re-derives from the
facts; the option only chooses which engine does it.

---

## 1. Test blind spots

### 1.1 `tests/test_engine_parity.py` — two lots, kept apart on purpose

The plan asks for a dedicated file with **two separate lots**:

1. **strict equality** — a migrated v6 document scores exactly what it scored in v6;
2. **allowlisted investigations** — expected to diverge, since v6 ignored the allowlist in
   `score.py` and v7 bounds the observable at `policy.allowlist_ceiling`.

The test must **fail loudly** if an allowlisted fixture drifts into the strict-equality lot:
silently tolerating the divergence would erase the one behaviour change we chose to make.

Partially covered today by `TestMigrationV6` in `test_serialization.py`, without that separation.

### 1.2 `tests/test_migration_chain.py`

A 5.x fixture **and** a 6.x fixture both landing on a document that validates against the
committed 7.0.0 schema via `jsonschema`. The chaining works and is exercised piecemeal; what is
missing is the end-to-end assertion.

### 1.3 `tests/test_schema_compat.py`

The forward-only contract, stated once and for all:

| Document | Library | Expected |
|---|---|---|
| `7.0.0` | 7.0 | read |
| `7.1.0` | 7.0 | refused, explicit message |
| `6.x` | 7.0 | refused, pointing at `cyvest migrate` |

`cyvest-js` must apply the **same** check in `validateInvestigation()`: ajv alone would happily
accept a 7.1 document read by a 7.0 SDK.

### 1.4 `io_rich.py` is at 0 % coverage

160 statements. Pure display, so the value is modest — but it was rewritten wholesale, and a
renderer that raises on an empty investigation is a real failure mode. Worth smoke tests on
`build_summary`, `build_explanation`, `build_timeline`, `build_statistics`, `build_diff`,
including the empty case.

---

## 2. `cyvest-vis` — C5 left incomplete

Three items from the plan were not delivered:

- **Node size by confidence.** Dropped during the port because an `Observable` carries no
  confidence field. Needs a decision rather than silence: derive it from the confidence of the
  signals attached to the observable, or drop the idea formally.
- **A badge on observables carrying a `Decision`.** An allowlisted node currently only fades;
  nothing says a human decided.
- **Filters by confidence band.** `confidenceBand()` already exists in the SDK and is unused by
  the graph.

Delivered: arrow heads deduced from `kind`, edge opacity modulated by relation confidence,
edges credited by the report drawn thicker, `isRootLink` based on `header.root_key`, verdict
colours from a single source.

---

## 3. CI and residual documentation

### 3.1 CI runs neither lint nor a JS typecheck

`.github/workflows/ci.yml` runs `pytest` and `pnpm -r test:ci`, nothing else. Two cheap additions:

```yaml
- run: uv run ruff check src tests examples
- run: pnpm -C js -r exec tsc --noEmit
```

Both would have caught, without human intervention, mistakes made during this port — a stale
import and a type drift between the Python models and the generated TypeScript.

Schema freshness is already covered: `test_serialization.py` fails when the committed schema and
the models disagree.

### 3.2 `docs/js-packages.md` is still v6

It advertises `investigation_id`, `investigation_name`, `score_display`, `finding_links` and
`observable_links` as top-level fields. None of them exist any more: facts moved under `facts.*`,
and every derived value lives in `report`.

---

## 4. Deliberately out of scope for 7.0

| Item | Target | Why it can wait |
|---|---|---|
| Intra-fragment freeze (`watermark`), fact versioning | 7.2 | The reference scenario is covered by `ObservableLink.scope` alone; adding it later is purely additive |
| `Outcome` (TP/FP/BTP closure) | 7.1 | Root key referenced by no fact, so additive. Cost accepted: no policy calibration, no "which feed generates our false positives" |
| `bayesian-v1` engine | 7.1 | `Report.confidence` is informative in `basic-v1`; it becomes determining for an engine that produces a verdict *without* a score |
| `Event` fact type | — | Reserved in the schema (`facts.events`), not implemented |
| Other `ObservableSignal` members (sandbox, telemetry, reputation) | — | The discriminated union is in place from day one, so adding one breaks nothing |
| Multi-axis `Label`, `Hypothesis` object | — | Only the clustering key signature is reserved |

---

## 5. Two invariants to keep in every 7.x release

1. **Any field added in a minor release is optional and carries a default** — otherwise a 7.1
   library could no longer read a 7.0 document.
2. **No `dict -> dict` migration for a minor bump.** Defaults are enough; `_MIGRATIONS` handles
   major transitions only.

And three structural constraints, already load-bearing:

- fact collections stay maps `{key: object}` — 7.2 history goes into a sibling `facts.history`,
  because turning a map into `{key: [objects]}` would break every existing document;
- nothing under `evaluation/` may read the clock, enforced by an AST test: an archived report must
  produce the same numbers next year;
- no set may reach the report. The adjacency indexes in `FactStore` are sets, so every accessor
  sorts on `(seq, key)` before returning. Enforced across processes by
  `TestDeterminism::test_a_saved_document_reports_the_same_under_any_hash_seed` — an in-process
  check cannot catch this, since set iteration is stable within a single interpreter run.
