import argparse
import json
from pathlib import Path

from app.services.evaluation import evaluate_manifest, to_markdown

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "evals" / "manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Sentinel's deterministic static-rule evaluation corpus.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()

    result = evaluate_manifest(args.manifest)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(result), encoding="utf-8")

    metrics = result["metrics"]
    if args.fail_on_regression and (
        metrics["failed_cases"] > 0 or metrics["precision"] < 1.0 or metrics["recall"] < 1.0
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
