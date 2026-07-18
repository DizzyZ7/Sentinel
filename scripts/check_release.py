import argparse
import json
from pathlib import Path

from app.services.release_readiness import evaluate_release_readiness

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Sentinel release and submission readiness.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true", help="Also fail while manual submission steps are pending.")
    args = parser.parse_args()

    result = evaluate_release_readiness(args.root)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")

    if result["automated_failed"]:
        return 1
    if args.strict and result["manual_pending"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
