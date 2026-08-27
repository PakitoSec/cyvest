# Roadmap

What is planned for the 7.x line, what is deliberately out of scope, and the invariants any
release must respect. Items land here only once the shape of the change is known; anything vaguer
than that belongs in an issue.

---

## 7.1

### `Outcome` — TP / FP / BTP closure

Closing an investigation with a verdict on the verdict. Additive: the root key is referenced by no
fact, so a 7.0 document stays valid. Until it ships there is no policy calibration and no way to
answer "which feed generates our false positives".

### `bayesian-v1` engine

A second engine, registered beside `basic-v1`. It produces a verdict *without* a score, which is
what turns `Report.confidence` from informative into determining. The engine registry, the
`--engine` flag and `Report.engine_id` are already in place; the diff refusal in
`compare_investigations` already reads `engine_id`, so incomparable reports are caught.

---

## 7.2

### Intra-fragment freeze (`watermark`) and fact versioning

Superseded facts kept alongside the current ones. The reference scenario is covered today by
`ObservableLink.scope` alone, which is why this waits.

Structural constraint, non-negotiable: fact collections stay maps `{key: object}`. History goes
into a **sibling** `facts.history`, because turning a map into `{key: [objects]}` would break every
document ever written.

---

## Reserved, not scheduled

| Item | State |
|---|---|
| `Event` fact type | Reserved in the schema as `facts.events`, not implemented |
| Other `ObservableSignal` members (sandbox, telemetry, reputation) | The discriminated union is in place from day one, so adding one breaks nothing |
| Multi-axis `Label`, `Hypothesis` object | Only the clustering key signature is reserved |

---

## Known gaps

Not features — work the current release is missing. Each one is worth an issue, none of them
blocks a document from being read or scored.

### `tests/test_engine_parity.py`

A dedicated file with **two separate lots**:

1. **strict equality** — a migrated v6 document scores exactly what it scored in v6;
2. **allowlisted investigations** — expected to diverge, since v6 ignored the allowlist and v7
   bounds the observable at `policy.refute_ceiling`.

The test must **fail loudly** if an allowlisted fixture drifts into the strict-equality lot:
silently tolerating the divergence would erase the one behaviour change that was chosen.

Partially covered today by `TestMigrationV6` in `test_serialization.py`, without that separation.

### `extract.py` is barely covered

393 statements, most of them untested, behind the public `cyvest extract` command and the
`observables_to_*` helpers. The rest of the library sits above 87 %.

### CI runs no lint and no JS typecheck

`.github/workflows/ci.yml` runs `pytest` and `pnpm -r test:ci`, and the publish jobs depend only on
those. Two cheap additions would close it:

```yaml
- run: uv run ruff check src tests examples
- run: pnpm -C js -r exec tsc --noEmit
```

Schema freshness is already covered: `test_serialization.py` fails when the committed schema and
the models disagree.

### `cyvest-vis` — three items left from the C5 plan

- **Node size by confidence.** Dropped during the v7 port because an `Observable` carries no
  confidence field. Needs a decision rather than silence: derive it from the confidence of the
  signals attached to the observable, or drop the idea formally.
- **A badge on observables carrying a `Decision`.** An allowlisted node currently only fades;
  nothing says a human decided.
- **Filters by confidence band.** `confidenceBand()` already exists in the SDK and is unused by the
  graph.

---

## Invariants for every 7.x release

1. **Any field added in a minor release is optional and carries a default.** The serialized shape
   only pins the major (`^7\.\d+\.\d+$`); the minor window — read older, never newer — is enforced
   by `io.serialization._check_readable` in Python and `assertReadableVersion` in
   `@cyvest/cyvest-js`. Break rule 1 and a 7.1 library silently mis-reads a 7.0 document.
2. **No `dict -> dict` migration for a minor bump.** Defaults are enough; `_MIGRATIONS` handles
   major transitions only, and `migrate_to_current` stops as soon as the major matches.
3. **Nothing under `evaluation/` may read the clock**, enforced by an AST test: an archived report
   must produce the same numbers next year.
4. **No set may reach the report.** The adjacency indexes in `FactStore` are sets, so every
   accessor sorts on `(seq, key)` before returning. Enforced across processes by
   `TestDeterminism::test_a_saved_document_reports_the_same_under_any_hash_seed` — an in-process
   check cannot catch this, since set iteration is stable within a single interpreter run.
