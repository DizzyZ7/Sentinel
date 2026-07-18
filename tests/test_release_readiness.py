from pathlib import Path

from app.services.public_image import parse_bearer_challenge
from app.services.release_readiness import evaluate_release_readiness


def test_release_readiness_automated_checks_pass_for_repository() -> None:
    root = Path(__file__).resolve().parents[1]
    result = evaluate_release_readiness(root, env={})

    assert result["automated_failed"] == 0
    assert result["manual_pending"] == 4
    assert result["ready_for_submission"] is False


def test_release_readiness_can_be_fully_confirmed() -> None:
    root = Path(__file__).resolve().parents[1]
    result = evaluate_release_readiness(
        root,
        env={
            "SENTINEL_GHCR_PUBLIC": "true",
            "SENTINEL_VIDEO_URL": "https://youtu.be/example",
            "SENTINEL_CODEX_SESSION_ID": "session-example",
            "SENTINEL_DEVPOST_COMPLETE": "done",
        },
    )

    assert result["ready_for_submission"] is True
    assert result["manual_pending"] == 0


def test_parse_bearer_challenge() -> None:
    parsed = parse_bearer_challenge(
        'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:dizzyz7/sentinel:pull"'
    )
    assert parsed == {
        "realm": "https://ghcr.io/token",
        "service": "ghcr.io",
        "scope": "repository:dizzyz7/sentinel:pull",
    }


def test_public_image_check_reports_network_failure(monkeypatch) -> None:
    from app.services import public_image

    monkeypatch.setattr(public_image, "_request", lambda url, token=None: (0, {}, b"temporary DNS failure"))
    result = public_image.check_public_image("dizzyz7/sentinel")
    assert result["public"] is False
    assert result["status"] == 0
    assert "DNS" in result["detail"]
