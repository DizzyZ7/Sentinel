import argparse
import asyncio
import json
from pathlib import Path

from app.services.evaluation import evaluate_validation_pack, to_markdown

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "evals" / "manifest.json"
DEFAULT_REMEDIATION_MANIFEST = ROOT / "evals" / "remediation" / "manifest.json"


async def _run(args: argparse.Namespace) -> int:
    result = await evaluate_validation_pack(args.manifest, args.remediation_manifest)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(result), encoding="utf-8")

    static = result["static"]
    static_metrics = static["metrics"]
    remediation_metrics = result["remediation"]["metrics"]
    coverage = static["coverage"]
    if args.fail_on_regression and (
        static_metrics["failed_cases"] > 0
        or static_metrics["precision"] < 1.0
        or static_metrics["recall"] < 1.0
        or static_metrics["specificity"] < 1.0
        or not coverage["positive_and_negative_complete"]
        or remediation_metrics["failed_cases"] > 0
        or remediation_metrics["source_executed_cases"] > 0
    ):
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Sentinel's deterministic static and remediation validation pack."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--remediation-manifest", type=Path, default=DEFAULT_REMEDIATION_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
