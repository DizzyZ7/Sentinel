import argparse
import json

from app.services.public_image import check_public_image


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify that a GHCR image is anonymously pullable.")
    parser.add_argument("--image", default="dizzyz7/sentinel")
    parser.add_argument("--tag", default="latest")
    args = parser.parse_args()
    result = check_public_image(args.image, args.tag)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["public"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
