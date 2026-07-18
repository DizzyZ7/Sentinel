# Sentinel deterministic evaluation

Ruleset: `sentinel-rules-2026.07`

Curated deterministic rule-regression corpus. These metrics validate the included fixtures and must not be interpreted as general-world vulnerability detection accuracy.

| Metric | Result |
| --- | ---: |
| Cases | 20 |
| Exact case pass rate | 20/20 (100%) |
| True positives | 15 |
| False positives | 0 |
| False negatives | 0 |
| Micro precision | 100% |
| Micro recall | 100% |

## Cases

| Case | Expected | Observed | Status |
| --- | --- | --- | --- |
| `py-sql-interpolation` | `PY_SQL_INTERPOLATION` | `PY_SQL_INTERPOLATION` | PASS |
| `js-sql-interpolation` | `JS_SQL_INTERPOLATION` | `JS_SQL_INTERPOLATION` | PASS |
| `py-dynamic-execution` | `PY_DYNAMIC_EXECUTION` | `PY_DYNAMIC_EXECUTION` | PASS |
| `js-dynamic-execution` | `JS_DYNAMIC_EXECUTION` | `JS_DYNAMIC_EXECUTION` | PASS |
| `py-command-injection` | `PY_COMMAND_INJECTION` | `PY_COMMAND_INJECTION` | PASS |
| `js-command-injection` | `JS_COMMAND_INJECTION` | `JS_COMMAND_INJECTION` | PASS |
| `py-path-traversal` | `PY_PATH_TRAVERSAL` | `PY_PATH_TRAVERSAL` | PASS |
| `js-path-traversal` | `JS_PATH_TRAVERSAL` | `JS_PATH_TRAVERSAL` | PASS |
| `py-ssrf` | `PY_SSRF` | `PY_SSRF` | PASS |
| `js-ssrf` | `JS_SSRF` | `JS_SSRF` | PASS |
| `py-unsafe-deserialization` | `PY_UNSAFE_DESERIALIZATION` | `PY_UNSAFE_DESERIALIZATION` | PASS |
| `py-unsafe-yaml` | `PY_YAML_UNSAFE_LOAD` | `PY_YAML_UNSAFE_LOAD` | PASS |
| `py-sensitive-route-no-auth` | `PY_SENSITIVE_ROUTE_NO_AUTH` | `PY_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `js-sensitive-route-no-auth` | `JS_SENSITIVE_ROUTE_NO_AUTH` | `JS_SENSITIVE_ROUTE_NO_AUTH` | PASS |
| `generic-hardcoded-secret` | `SECRET_GENERIC` | `SECRET_GENERIC` | PASS |
| `safe-parameterized-sql` | `none` | `none` | PASS |
| `safe-subprocess-argv` | `none` | `none` | PASS |
| `safe-constant-fetch` | `none` | `none` | PASS |
| `safe-python-authorized-route` | `none` | `none` | PASS |
| `safe-javascript-authorized-route` | `none` | `none` | PASS |
