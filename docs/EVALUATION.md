# Sentinel validation pack

Ruleset: `sentinel-rules-2026.07`
Static corpus: `sentinel-static-validation-2026.07`
Static corpus SHA-256: `fdc24b574e3b67d7afda729d3e0dfcaeab61eb05af1fa6c92d2c458f404a42d1`

Committed deterministic candidate-regression corpus with targeted positive, negative, edge, and multi-signal fixtures. Exact results validate only this corpus and are not a general-world accuracy claim.

## Static candidate evaluation

| Metric | Result |
| --- | ---: |
| Cases | 60 |
| Finding-bearing / negative cases | 37 / 23 |
| Multi-signal subset | 2 |
| Edge or adversarial cases | 33 |
| Exact case pass rate | 60/60 (100%) |
| True positives | 39 |
| Targeted true negatives | 23 |
| False positives | 0 |
| False negatives | 0 |
| Micro precision | 100% |
| Micro recall | 100% |
| Targeted specificity | 100% |

## Coverage contract

| Coverage | Result |
| --- | ---: |
| Known rules | 19 |
| Rules with positive support | 19 |
| Rules with negative support | 19 |
| Rules with edge support | 19 |
| Positive + negative coverage complete | True |
| Edge coverage complete | True |

## Per-language metrics

| Language | Cases | Pass rate | TP | TN | FP | FN | Precision | Recall | Specificity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| javascript | 26 | 100% | 17 | 10 | 0 | 0 | 100% | 100% | 100% |
| python | 34 | 100% | 22 | 13 | 0 | 0 | 100% | 100% | 100% |

## Per-rule coverage and confusion metrics

| Rule | Family | + | - | Edge | TP | TN | FP | FN | Precision | Recall | Specificity |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `JS_COMMAND_INJECTION` | command_injection | 2 | 2 | 3 | 2 | 2 | 0 | 0 | 100% | 100% | 100% |
| `JS_DYNAMIC_EXECUTION` | dynamic_execution | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `JS_PATH_TRAVERSAL` | path_traversal | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `JS_SENSITIVE_ROUTE_NO_AUTH` | missing_authorization | 3 | 2 | 3 | 3 | 2 | 0 | 0 | 100% | 100% | 100% |
| `JS_SQL_INTERPOLATION` | sql_injection | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `JS_SSRF` | ssrf | 3 | 1 | 2 | 3 | 1 | 0 | 0 | 100% | 100% | 100% |
| `JS_YAML_UNSAFE_LOAD` | unsafe_yaml | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_COMMAND_INJECTION` | command_injection | 2 | 1 | 1 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_DYNAMIC_EXECUTION` | dynamic_execution | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_PATH_TRAVERSAL` | path_traversal | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_SENSITIVE_ROUTE_NO_AUTH` | missing_authorization | 2 | 2 | 2 | 2 | 2 | 0 | 0 | 100% | 100% | 100% |
| `PY_SQL_INTERPOLATION` | sql_injection | 4 | 1 | 3 | 4 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_SSRF` | ssrf | 2 | 1 | 2 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_UNSAFE_DESERIALIZATION` | unsafe_deserialization | 2 | 1 | 1 | 2 | 1 | 0 | 0 | 100% | 100% | 100% |
| `PY_YAML_UNSAFE_LOAD` | unsafe_yaml | 2 | 2 | 2 | 2 | 2 | 0 | 0 | 100% | 100% | 100% |
| `SECRET_AWS` | hardcoded_secret | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 100% | 100% | 100% |
| `SECRET_GENERIC` | hardcoded_secret | 3 | 1 | 2 | 3 | 1 | 0 | 0 | 100% | 100% | 100% |
| `SECRET_GITHUB` | hardcoded_secret | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 100% | 100% | 100% |
| `SECRET_OPENAI` | hardcoded_secret | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 100% | 100% | 100% |

## Patch escrow and regression proof evaluation

Remediation corpus: `sentinel-remediation-validation-2026.07`
Remediation corpus SHA-256: `90820357c44b2b69e2af316db2cffb0e26fb94c561a60fb49cdb1be6be9eb22d`

| Metric | Result |
| --- | ---: |
| Cases | 17 |
| Exact case pass rate | 17/17 (100%) |
| Expected patch acceptances | 7 |
| Expected patch rejections | 10 |
| Source-executed cases | 0 |

| Case | Expected patch | Observed patch | Expected proof | Observed proof | Status |
| --- | --- | --- | --- | --- | --- |
| `py-sql-effective` | True | True | passed | passed | PASS |
| `py-sql-cosmetic` | True | True | failed | failed | PASS |
| `py-sql-unrelated-hunk` | True | True | inconclusive | inconclusive | PASS |
| `wrong-reviewed-path` | False | False | none | none | PASS |
| `unsafe-parent-path` | False | False | none | none | PASS |
| `binary-marker` | False | False | none | none | PASS |
| `rename-marker` | False | False | none | none | PASS |
| `empty-diff` | False | False | none | none | PASS |
| `context-only-diff` | False | False | none | none | PASS |
| `invalid-python` | False | False | none | none | PASS |
| `apply-context-mismatch` | False | False | none | none | PASS |
| `changed-line-limit` | False | False | none | none | PASS |
| `byte-limit` | False | False | none | none | PASS |
| `py-command-effective` | True | True | passed | passed | PASS |
| `py-ssrf-effective` | True | True | passed | passed | PASS |
| `js-sql-effective` | True | True | passed | passed | PASS |
| `js-sql-cosmetic` | True | True | failed | failed | PASS |

## Explicit limitations

- **intra_procedural_taint_only** (`known_limit`, static_analysis): Python taint tracking is intentionally local to simple assignments and does not claim interprocedural data-flow coverage.
- **javascript_regex_prefilter** (`known_limit`, static_analysis): JavaScript and TypeScript triage uses bounded regular-expression candidates rather than a full semantic parser.
- **sanitizer_semantics** (`review_required`, static_analysis): Allowlist and sanitizer effectiveness is a contextual GPT review responsibility; the deterministic layer favors recall.
- **javascript_patch_syntax** (`known_limit`, patch_validation): Patch escrow validates diff shape and git applicability for JavaScript but does not execute project tooling or claim full JavaScript syntax validation.
- **fixture_not_world_accuracy** (`disclosure`, evaluation): Exact corpus results measure only these committed fixtures and are not a production precision or recall estimate.

## Static cases

| Case | Class | Difficulty | Expected | Observed | Status |
| --- | --- | --- | --- | --- | --- |
| `py-sql-interpolation` | positive | basic | `PY_SQL_INTERPOLATION` | `PY_SQL_INTERPOLATION` | PASS |
| `js-sql-interpolation` | positive | basic | `JS_SQL_INTERPOLATION` | `JS_SQL_INTERPOLATION` | PASS |
| `py-dynamic-execution` | positive | basic | `PY_DYNAMIC_EXECUTION` | `PY_DYNAMIC_EXECUTION` | PASS |
| `js-dynamic-execution` | positive | basic | `JS_DYNAMIC_EXECUTION` | `JS_DYNAMIC_EXECUTION` | PASS |
| `py-command-injection` | positive | basic | `PY_COMMAND_INJECTION` | `PY_COMMAND_INJECTION` | PASS |
| `js-command-injection` | positive | basic | `JS_COMMAND_INJECTION` | `JS_COMMAND_INJECTION` | PASS |
| `py-path-traversal` | positive | basic | `PY_PATH_TRAVERSAL` | `PY_PATH_TRAVERSAL` | PASS |
| `js-path-traversal` | positive | basic | `JS_PATH_TRAVERSAL` | `JS_PATH_TRAVERSAL` | PASS |
| `py-ssrf` | positive | basic | `PY_SSRF` | `PY_SSRF` | PASS |
| `js-ssrf` | positive | basic | `JS_SSRF` | `JS_SSRF` | PASS |
| `py-unsafe-deserialization` | positive | basic | `PY_UNSAFE_DESERIALIZATION` | `PY_UNSAFE_DESERIALIZATION` | PASS |
| `py-unsafe-yaml` | positive | basic | `PY_YAML_UNSAFE_LOAD` | `PY_YAML_UNSAFE_LOAD` | PASS |
| `py-sensitive-route-no-auth` | positive | basic | `PY_SENSITIVE_ROUTE_NO_AUTH` | `PY_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `js-sensitive-route-no-auth` | positive | basic | `JS_SENSITIVE_ROUTE_NO_AUTH` | `JS_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `generic-hardcoded-secret` | positive | basic | `SECRET_GENERIC` | `SECRET_GENERIC` | PASS |
| `safe-parameterized-sql` | negative | basic | `none` | `none` | PASS |
| `safe-subprocess-argv` | negative | basic | `none` | `none` | PASS |
| `safe-constant-fetch` | negative | basic | `none` | `none` | PASS |
| `safe-python-authorized-route` | negative | basic | `none` | `none` | PASS |
| `safe-javascript-authorized-route` | negative | basic | `none` | `none` | PASS |
| `py-sql-percent-format` | positive | edge | `PY_SQL_INTERPOLATION` | `PY_SQL_INTERPOLATION` | PASS |
| `py-sql-concatenation` | positive | edge | `PY_SQL_INTERPOLATION` | `PY_SQL_INTERPOLATION` | PASS |
| `js-sql-concatenation` | positive | edge | `JS_SQL_INTERPOLATION` | `JS_SQL_INTERPOLATION` | PASS |
| `py-exec-request-body` | positive | edge | `PY_DYNAMIC_EXECUTION` | `PY_DYNAMIC_EXECUTION` | PASS |
| `js-function-constructor` | positive | edge | `JS_DYNAMIC_EXECUTION` | `JS_DYNAMIC_EXECUTION` | PASS |
| `py-subprocess-shell-true` | positive | edge | `PY_COMMAND_INJECTION` | `PY_COMMAND_INJECTION` | PASS |
| `js-exec-sync` | positive | edge | `JS_COMMAND_INJECTION` | `JS_COMMAND_INJECTION` | PASS |
| `py-send-file` | positive | edge | `PY_PATH_TRAVERSAL` | `PY_PATH_TRAVERSAL` | PASS |
| `js-create-read-stream` | positive | edge | `JS_PATH_TRAVERSAL` | `JS_PATH_TRAVERSAL` | PASS |
| `py-httpx-ssrf` | positive | edge | `PY_SSRF` | `PY_SSRF` | PASS |
| `js-axios-ssrf` | positive | edge | `JS_SSRF` | `JS_SSRF` | PASS |
| `py-pickle-load` | positive | edge | `PY_UNSAFE_DESERIALIZATION` | `PY_UNSAFE_DESERIALIZATION` | PASS |
| `py-yaml-full-loader` | positive | edge | `PY_YAML_UNSAFE_LOAD` | `PY_YAML_UNSAFE_LOAD` | PASS |
| `js-yaml-load` | positive | basic | `JS_YAML_UNSAFE_LOAD` | `JS_YAML_UNSAFE_LOAD` | PASS |
| `py-sensitive-billing-route` | positive | edge | `PY_SENSITIVE_ROUTE_NO_AUTH` | `PY_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `js-sensitive-token-route` | positive | edge | `JS_SENSITIVE_ROUTE_NO_AUTH` | `JS_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `secret-openai` | positive | basic | `SECRET_OPENAI` | `SECRET_OPENAI` | PASS |
| `secret-github` | positive | basic | `SECRET_GITHUB` | `SECRET_GITHUB` | PASS |
| `secret-aws` | positive | basic | `SECRET_AWS` | `SECRET_AWS` | PASS |
| `secret-generic-password` | positive | edge | `SECRET_GENERIC` | `SECRET_GENERIC` | PASS |
| `safe-python-literal-eval` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-json-parse` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-spawn-argv` | negative | edge | `none` | `none` | PASS |
| `safe-python-constant-path` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-constant-path` | negative | edge | `none` | `none` | PASS |
| `safe-python-constant-request` | negative | edge | `none` | `none` | PASS |
| `safe-python-yaml-safe-load` | negative | basic | `none` | `none` | PASS |
| `safe-javascript-yaml-safe-load` | negative | edge | `none` | `none` | PASS |
| `safe-python-json-deserialization` | negative | basic | `none` | `none` | PASS |
| `safe-python-permission-route` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-permission-route` | negative | edge | `none` | `none` | PASS |
| `safe-generic-secret-env` | negative | basic | `none` | `none` | PASS |
| `safe-openai-placeholder` | negative | edge | `none` | `none` | PASS |
| `safe-github-placeholder` | negative | edge | `none` | `none` | PASS |
| `safe-aws-placeholder` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-parameterized-sql` | negative | edge | `none` | `none` | PASS |
| `safe-javascript-constant-command` | negative | edge | `none` | `none` | PASS |
| `safe-python-yaml-safe-loader` | negative | edge | `none` | `none` | PASS |
| `py-multi-sql-secret` | multi_signal | adversarial | `PY_SQL_INTERPOLATION, SECRET_GENERIC` | `PY_SQL_INTERPOLATION, SECRET_GENERIC` | PASS |
| `js-multi-ssrf-sensitive-route` | multi_signal | adversarial | `JS_SENSITIVE_ROUTE_NO_AUTH, JS_SSRF` | `JS_SENSITIVE_ROUTE_NO_AUTH, JS_SSRF` | PASS |
