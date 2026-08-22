# Comparing Investigations

Comparison answers two different questions, and it is worth being clear about which one you are
asking:

- *"Did anything change between these two runs?"* — diff two investigations.
- *"Is this run still acceptable?"* — check one investigation against tolerance rules.

Both go through `compare_investigations`, and both read the **report** — nothing is re-derived.

---

## Diffing two investigations

```python
from cyvest import Cyvest, compare_investigations

expected = Cyvest(investigation_name="baseline")
url = expected.observable_create("url", "https://evil.test")
expected.finding_create("phishing-page", weight=4.0)

actual = Cyvest(investigation_name="candidate")
actual.observable_create("url", "https://evil.test")
actual.finding_create("phishing-page", weight=7.0)

diffs = compare_investigations(actual, expected)
for diff in diffs:
    print(diff.status.value, diff.rule_id, diff.expected_score, "→", diff.actual_score)
```

```
✗ phishing-page 4.0 → 7.0
```

Because a finding's identity is `(rule_id, subject)` and is stable across investigations, a changed
score shows up as **one mismatch** rather than an addition plus a removal.

| Status | Meaning |
|---|---|
| `+` (`ADDED`) | present in *actual*, absent from *expected* |
| `-` (`REMOVED`) | present in *expected*, absent from *actual* |
| `✗` (`MISMATCH`) | present in both, with a different score or verdict |

A mismatch also carries the **observables that explain it**, so you can see that a finding moved
because one of its observables did:

```python
for observable_diff in diffs[0].observable_diffs:
    print(observable_diff.value, observable_diff.expected_score, "→", observable_diff.actual_score)
```

---

## Tolerance rules

Pinning an exact score makes a test that breaks every time you tune a weight. An `ExpectedResult`
expresses a **band** instead:

```python
from cyvest import ExpectedResult, Verdict, compare_investigations

diffs = compare_investigations(
    actual,
    result_expected=[
        ExpectedResult(rule_id="phishing-page", score=">= 1.0", verdict=Verdict.SUSPICIOUS),
        ExpectedResult(key="fnd:domain-reputation:obs:file:__cyvest_root__", score="< 2.0"),
    ],
)
```

A rule targets a finding either by `rule_id` or by full `key`; one of the two is required.

### Supported operators

`>=`, `<=`, `>`, `<`, `==`, `!=` — for example `">= 0.01"`, `"< 3"`, `"== 1.0"`.

### `ExpectedResult` fields

| Field | Meaning |
|---|---|
| `rule_id` | match the finding by rule |
| `key` | match the finding by exact key |
| `verdict` | the conclusion expected |
| `score` | a band, as a rule string |
| `ignore` | statuses to tolerate, e.g. `{DiffStatus.REMOVED}` |

`ignore` is how you say "this finding may or may not fire, and that is fine":

```python
ExpectedResult(rule_id="optional-enrichment", score="> 0", ignore={DiffStatus.REMOVED})
```

---

## Comparing across engines is refused

Two engines do not produce scores on the same scale, so a diff between them would be arithmetic
without meaning:

```python
compare_investigations(actual, expected)
# EngineMismatchError: Cannot compare a basic-v1 report with a bayesian-v1 one;
# scores from different engines are not on the same scale.
```

Either re-evaluate both with the same engine, or take responsibility explicitly:

```python
actual.reevaluate(engine="basic-v1")
expected.reevaluate(engine="basic-v1")

# ... or, if you know what you are doing:
compare_investigations(actual, expected, allow_engine_mismatch=True)
```

---

## Displaying a diff

```python
actual.display_diff(expected, title="Nightly regression")
```

```python
from cyvest.io_rich import display_diff

display_diff(diffs, title="Nightly regression")
display_diff(diffs, lambda renderable: logger.rich("INFO", renderable, width=150))
```

An empty diff still renders a table, saying so — silence is ambiguous.

From the shell:

```bash
cyvest diff actual.json expected.json
cyvest diff actual.json expected.json --rules tolerances.json --engine basic-v1
```

```json
[
  {"rule_id": "domain-reputation", "score": ">= 1.0"},
  {"key": "fnd:ai-analysis:obs:url:https://evil.test", "verdict": "SUSPICIOUS", "score": "< 3.0"}
]
```

---

## Use cases

### Regression testing a rule change

```python
baseline = Cyvest.io_load_json("baseline.json")
candidate = run_pipeline_with_new_rules(sample)

diffs = compare_investigations(candidate, baseline)
assert not diffs, f"{len(diffs)} unexpected differences"
```

### Validating a sample corpus

```python
tolerances = [
    ExpectedResult(rule_id="phishing-page", score=">= 3.0"),
    ExpectedResult(rule_id="benign-domain", verdict=Verdict.SAFE),
]

for sample in corpus:
    diffs = compare_investigations(analyze(sample), result_expected=tolerances)
    assert not diffs, f"{sample.name}: {diffs}"
```

This is the form that survives policy tuning: it asserts *conclusions*, not magnitudes.
