# Sentinel validation pack

This directory contains Sentinel's deterministic, reproducible validation fixtures. It deliberately measures two different layers instead of presenting one inflated accuracy number.

## Static candidate corpus

`manifest.json` defines:

- 60 isolated Python and JavaScript cases;
- 37 positive cases, 23 negative cases, and 2 multi-signal cases;
- all 19 built-in rule IDs;
- at least one positive, negative, and edge/adversarial fixture for every rule;
- explicit language, pattern, difficulty, target-rule, and classification metadata;
- committed known limitations that remain visible in the generated report.

The evaluator computes exact-case pass rate, TP/FP/FN, targeted true negatives, precision, recall, targeted specificity, per-language metrics, per-rule confusion metrics, and coverage gaps.

## Remediation corpus

`remediation/manifest.json` defines 17 patch-escrow and non-executing regression-proof cases:

- 7 expected patch acceptances;
- 10 expected patch rejections for wrong paths, traversal, binary/rename markers, empty or context-only diffs, syntax failure, apply mismatch, and configured size limits;
- effective, ineffective, and unrelated patches producing `passed`, `failed`, and `inconclusive` proof states;
- Python and JavaScript examples;
- an explicit assertion that repository source was never executed.

## Reproduce

```bash
python -m scripts.run_evals \
  --output evals/results/latest.json \
  --markdown docs/EVALUATION.md \
  --fail-on-regression
```

The JSON includes static/remediation corpus SHA-256 values and a canonical validation-pack SHA-256. CI fails if a fixture regresses, rule coverage becomes incomplete, remediation behavior changes unexpectedly, or any proof reports source execution.

These figures validate only the committed fixtures. They are not a claim about general-world vulnerability detection accuracy, GPT-5.6 review quality, or production false-positive rates.
