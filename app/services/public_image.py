import json
import re
import urllib.error
import urllib.parse
import urllib.request

CHALLENGE_PART = re.compile(r'(\w+)="([^"]*)"')
ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


def parse_bearer_challenge(value: str) -> dict[str, str]:
    if not value.lower().startswith("bearer "):
        raise ValueError("Registry did not return a Bearer authentication challenge")
    return dict(CHALLENGE_PART.findall(value[7:]))


def _request(url: str, token: str | None = None) -> tuple[int, dict[str, str], bytes]:
    headers = {"Accept": ACCEPT, "User-Agent": "sentinel-public-image-check/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except urllib.error.URLError as exc:
        return 0, {}, str(exc.reason).encode("utf-8", "replace")


def check_public_image(image: str, tag: str = "latest") -> dict:
    owner, name = image.split("/", 1)
    manifest_url = f"https://ghcr.io/v2/{owner}/{name}/manifests/{tag}"
    status, headers, body = _request(manifest_url)
    if status == 200:
        return {
            "public": True,
            "image": image,
            "tag": tag,
            "status": status,
            "detail": "Anonymous manifest request succeeded.",
        }
    if status != 401:
        return {
            "public": False,
            "image": image,
            "tag": tag,
            "status": status,
            "detail": body.decode("utf-8", "replace")[:300],
        }

    challenge = headers.get("Www-Authenticate") or headers.get("WWW-Authenticate", "")
    params = parse_bearer_challenge(challenge)
    query = urllib.parse.urlencode({key: params[key] for key in ("service", "scope") if key in params})
    token_status, _, token_body = _request(f"{params['realm']}?{query}")
    if token_status != 200:
        return {
            "public": False,
            "image": image,
            "tag": tag,
            "status": token_status,
            "detail": "Anonymous registry token was denied.",
        }
    token_payload = json.loads(token_body)
    token = token_payload.get("token") or token_payload.get("access_token")
    final_status, _, final_body = _request(manifest_url, token)
    return {
        "public": final_status == 200,
        "image": image,
        "tag": tag,
        "status": final_status,
        "detail": (
            "Anonymous pull metadata is available."
            if final_status == 200
            else final_body.decode("utf-8", "replace")[:300]
        ),
    }
