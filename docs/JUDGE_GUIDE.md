# Sentinel judge guide

## Fastest path: deterministic 60-second tour

Requirements:

- Docker Desktop or Docker Engine with Compose v2
- an amd64 or arm64 Linux container runtime
- no OpenAI API key

Run:

```bash
docker compose -f compose.demo.yml up -d
```

Open `http://localhost:8000`, then select **Run the 60-second security demo**.

The replay is explicitly labelled as deterministic and makes no external model call. It still exercises the real repository ingestion, static analysis, patch validation, regression verification, persistence, attack-path reporting, release gate, and Evidence Bundle code paths.

After the judge view loads, open **Executive risk** to show affected assets, residual business risk, factor breakdowns, and remediation priority.

Expected outcomes:

1. one SQL injection receives a valid parameterized patch and a passed regression proof;
2. one static candidate is rejected as a false positive;
3. one cosmetic SQL patch applies successfully but fails regression proof and remains blocked.

## Live GPT-5.6 path

Set a key before starting Compose:

```bash
export OPENAI_API_KEY="..."
docker compose -f compose.demo.yml up -d
```

On the dashboard select **Run live GPT-5.6 demo**. The same fixture is sent through Sentinel's normal secret-safe Responses API boundary. The UI and audit endpoint distinguish live GPT-5.6 calls from deterministic replay.

## Useful endpoints

```text
GET  /health
POST /scan/demo?mode=replay
POST /scan/demo?mode=live
GET  /scan/{scan_id}/progress
GET  /scan/{scan_id}/events
GET  /scan/{scan_id}/report?format=html
GET  /scan/{scan_id}/attack-paths
GET  /scan/{scan_id}/executive-report?format=html
GET  /scan/{scan_id}/risk-intelligence
GET  /scan/{scan_id}/gate
GET  /scan/{scan_id}/llm-reviews
GET  /scan/{scan_id}/findings/{finding_id}/evidence-bundle
```

## Supported platforms

The prebuilt image targets `linux/amd64` and `linux/arm64`. It runs through Docker Desktop on Windows, macOS, and Linux, or through Docker Engine on Linux.

Source development requires Python 3.12+, Git, and PostgreSQL 17 through Docker Compose. Tests use SQLite for isolated application-level verification.

## Stop and clean up

```bash
docker compose -f compose.demo.yml down -v
```

## Troubleshooting

- **Image pull denied:** the GHCR package must be public. Use the source-build fallback below if package visibility has not been enabled yet.
- **Port 8000 is occupied:** change the host side of `8000:8000` in `compose.demo.yml`.
- **Live demo returns 409:** `OPENAI_API_KEY` is not present in the API container.
- **Replay is marked as a non-GPT run:** this is intentional. Use live mode to demonstrate the actual GPT-5.6 integration.

Source-build fallback:

```bash
cp .env.example .env
docker compose up --build -d
```


### Project context profile

Open **Project context** from the judge view. The built-in demo declares production assets for the customer-data API and inventory query service. Previewing a changed profile recalculates the executive posture without altering evidence; saving creates a new immutable version for the next rescan.


### Risk acceptance path

Open **Risk exceptions** from the judge view. Create a finding-, rule-, or asset-scoped request, approve it with a different actor, and open **Governance**. The raw policy report remains blocked while the separate governance result becomes `accepted_risk`. Revoke the exception to show the blocker returning immediately.


## Security debt

Open **SLA profile** to show immutable ownership rules, then **Security debt** to demonstrate inherited deadlines, team routing, accepted-risk visibility, and overdue enforcement.

## Automated end-to-end verification

After the API is healthy, run the installed verifier:

```bash
sentinel-verify-judge \
  --base-url http://localhost:8000 \
  --timeout 120 \
  --output sentinel-judge-smoke.json
```

The command exits with code `0` only when the running product satisfies the complete deterministic judge contract:

- health reports the Sentinel service;
- the replay completes successfully;
- exactly three candidates appear and exactly two are confirmed;
- `confirmed_sql.py` has a valid patch and `passed` non-executing proof;
- `safe_constant.py` is rejected as a false positive;
- `weak_patch.py` has a valid but ineffective patch and a `failed` proof;
- both confirmed unapproved findings keep the release gate blocked;
- all three reviews are explicitly labelled `sentinel-deterministic-demo-replay`;
- every Evidence Bundle matches its finding and scan;
- every section SHA-256, canonical payload SHA-256, and response digest header is independently recalculated.

The JSON output is suitable for CI artifacts and clean-machine preflight evidence. A failed check includes the endpoint or invariant that broke instead of returning only a generic smoke-test failure.
