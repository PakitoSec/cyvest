# Comparing Investigations

Cyvest provides tools to compare two investigations and identify differences in findings, observables, and threat intelligence. This is useful for regression testing, validating detection rules, and tracking changes between investigation runs.

---

## Basic Comparison

Compare two investigations using `compare_investigations()`:

```python
from decimal import Decimal
from cyvest import Cyvest, compare_investigations

# Create expected (baseline) investigation
expected = Cyvest(investigation_name="expected")
expected.finding_create("domain-finding", "Verify domain", score=Decimal("1.0"))

# Create actual investigation
actual = Cyvest(investigation_name="actual")
actual.finding_create("domain-finding", "Verify domain", score=Decimal("2.0"))
actual.finding_create("new-finding", "New detection", score=Decimal("1.5"))

# Compare
diffs = compare_investigations(actual, expected)
```

The function returns a list of `DiffItem` objects representing:

| Status | Symbol | Description |
|--------|--------|-------------|
| ADDED | `+` | Finding exists in actual but not in expected |
| REMOVED | `-` | Finding exists in expected but not in actual |
| MISMATCH | `✗` | Finding exists in both but score/level differs |

---

## Tolerance Rules

Use `ExpectedResult` rules to define acceptable score variations. When the actual score satisfies a tolerance rule, the difference is not flagged.

```python
from cyvest import ExpectedResult, Level

rules = [
    # Accept any score >= 1.0 for this finding
    ExpectedResult(finding_name="domain-finding", score=">= 1.0"),

    # Accept any score < 3.0 for roger-ai
    ExpectedResult(key="fnd:roger-ai", level=Level.SUSPICIOUS, score="< 3.0"),

    # Exact match required
    ExpectedResult(finding_name="critical-finding", score="== 5.0"),
]

diffs = compare_investigations(actual, expected, result_expected=rules)
```

### Supported Operators

| Operator | Description |
|----------|-------------|
| `>=` | Greater than or equal |
| `<=` | Less than or equal |
| `>` | Greater than |
| `<` | Less than |
| `==` | Equal |
| `!=` | Not equal |

### ExpectedResult Fields

| Field | Required | Description |
|-------|----------|-------------|
| `finding_name` | One of `finding_name` or `key` | Finding name (key will be derived) |
| `key` | One of `finding_name` or `key` | Full finding key (e.g., `fnd:my-finding`) |
| `level` | No | Expected level (informational) |
| `score` | No | Tolerance rule string |

---

## Displaying Differences

Use `display_diff()` to render differences as a rich table:

```python
from cyvest.io_rich import display_diff
from logurich import logger

display_diff(diffs, lambda r: logger.rich("INFO", r), title="Investigation Diff")
```

Output:

```
╭────────────────────────────────────────────────┬────────────────────┬─────────────────┬────────╮
│ Key                                            │      Expected      │     Actual      │ Status │
├────────────────────────────────────────────────┼────────────────────┼─────────────────┼────────┤
│ fnd:new-finding                                  │         -          │  NOTABLE 1.50   │   +    │
│ └── domain: example.com                        │         -          │   INFO 0.00     │        │
│     └── VirusTotal                             │         -          │   INFO 0.00     │        │
├────────────────────────────────────────────────┼────────────────────┼─────────────────┼────────┤
│ fnd:domain-finding                               │   NOTABLE 1.00     │  NOTABLE 2.00   │   ✗    │
╰────────────────────────────────────────────────┴────────────────────┴─────────────────┴────────╯
```

The table shows:

- **Key**: Finding key with linked observables and threat intel as a tree
- **Expected**: Level and score from expected investigation (or tolerance rule)
- **Actual**: Level and score from actual investigation
- **Status**: Diff status symbol

---

## Convenience Methods

Use methods directly on `Cyvest` objects:

```python
# Get diff items
diffs = actual.compare(expected=expected, result_expected=rules)

# Compare and display in one call
actual.display_diff(expected=expected, title="My Investigation Diff")
```

---

## DiffItem Structure

Each `DiffItem` contains:

```python
class DiffItem:
    status: DiffStatus          # ADDED, REMOVED, or MISMATCH
    key: str                    # Finding key
    finding_name: str             # Finding name
    expected_level: Level       # Expected level
    expected_score: Decimal     # Expected score
    expected_score_rule: str    # Tolerance rule (if any)
    actual_level: Level         # Actual level
    actual_score: Decimal       # Actual score
    observable_diffs: list      # Linked observable differences
```

### ObservableDiff

For each linked observable:

```python
class ObservableDiff:
    observable_key: str
    obs_type: str
    value: str
    expected_score: Decimal
    expected_level: Level
    actual_score: Decimal
    actual_level: Level
    threat_intel_diffs: list    # Threat intel differences
```

### ThreatIntelDiff

For each threat intel source:

```python
class ThreatIntelDiff:
    source: str
    expected_score: Decimal
    expected_level: Level
    actual_score: Decimal
    actual_level: Level
```

---

## Use Cases

### Regression Testing

Compare investigation outputs before and after rule changes:

```python
# Run investigation with old rules
old_cv = run_investigation(email, rules_v1)
old_cv.io_save_json("baseline.json")

# Run investigation with new rules
new_cv = run_investigation(email, rules_v2)

# Compare
baseline = Cyvest.io_load_json("baseline.json")
diffs = compare_investigations(new_cv, baseline)

if diffs:
    print(f"Found {len(diffs)} differences")
    display_diff(diffs, print, title="Rule Changes Impact")
```

### Validation with Tolerance

Define expected outcomes with acceptable variations:

```python
# Expected results for test case
expected_results = [
    ExpectedResult(finding_name="spam-score", score=">= 5.0"),
    ExpectedResult(finding_name="phishing-score", score=">= 7.0"),
    ExpectedResult(finding_name="ai-analysis", score=">= 1.0"),  # Allow variation
]

diffs = compare_investigations(actual, expected, result_expected=expected_results)

# Assert no unexpected differences
assert len(diffs) == 0, f"Unexpected differences: {[d.key for d in diffs]}"
```

---

## Example

See `examples/06_compare_investigations.py` for a complete example demonstrating:

- Creating expected and actual investigations
- Comparing without tolerance rules
- Comparing with tolerance rules
- Using convenience methods

Run it with:

```bash
python examples/06_compare_investigations.py
```
