import argparse
import json
import urllib.error
import urllib.parse
import urllib.request


def build_url(
    base_url: str,
    current_scan_id: str,
    baseline_scan_id: str | None,
    block_on: str,
    fail_closed_on_unreviewed: bool,
) -> str:
    query = {
        "block_on": block_on,
        "fail_closed_on_unreviewed": str(fail_closed_on_unreviewed).lower(),
    }
    if baseline_scan_id:
        query["baseline_scan_id"] = baseline_scan_id
    scan_id = urllib.parse.quote(current_scan_id, safe="")
    return f"{base_url.rstrip('/')}/scan/{scan_id}/ci-gate?{urllib.parse.urlencode(query)}"


def request_gate(url: str) -> tuple[int, dict]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sentinel-ci-gate/1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"detail": body.decode("utf-8", "replace")[:500]}
        return exc.code, payload


def evaluate_exit_code(status: int, payload: dict) -> int:
    if status in {200, 409} and payload.get("schema_version") == "sentinel-ci-gate-v1":
        return int(payload.get("exit_code", 2))
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail CI when Sentinel detects a new blocking security regression.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--current-scan-id", required=True)
    parser.add_argument("--baseline-scan-id")
    parser.add_argument("--block-on", choices=["critical", "high", "medium", "low"], default="high")
    parser.add_argument("--allow-unreviewed", action="store_true")
    args = parser.parse_args(argv)
    url = build_url(
        args.base_url,
        args.current_scan_id,
        args.baseline_scan_id,
        args.block_on,
        not args.allow_unreviewed,
    )
    try:
        status, payload = request_gate(url)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        payload = {"schema_version": "sentinel-ci-gate-error-v1", "exit_code": 2, "detail": str(exc), "url": url}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return evaluate_exit_code(status, payload)


def cli() -> None:
    raise SystemExit(main())
