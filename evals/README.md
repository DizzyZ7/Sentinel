# Sentinel evaluation corpus

This directory contains a small deterministic regression corpus for Sentinel's built-in static rules.

The corpus is intentionally narrow and transparent:

- 20 isolated Python and JavaScript cases
- 15 positive cases with one fully labelled expected rule each
- 5 negative cases with no expected findings
- SQL injection, dynamic execution, command injection, path traversal, SSRF, unsafe deserialization, unsafe YAML, sensitive routes, and hardcoded secrets
- safe parameterized SQL, argv-based subprocess execution, constant outbound URLs, and authenticated routes

Run it with:

```bash
python -m scripts.run_evals \
  --output evals/results/latest.json \
  --markdown docs/EVALUATION.md \
  --fail-on-regression
```

The runner computes exact-case pass rate, TP/FP/FN, micro precision, and micro recall. CI fails if any expected rule disappears or any unexpected rule is introduced.

These figures validate only the committed fixtures and the deterministic pre-filter. They are not a claim about general-world vulnerability detection accuracy, GPT-5.6 review quality, or production false-positive rates.
