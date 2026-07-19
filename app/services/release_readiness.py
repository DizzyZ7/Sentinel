import json
import os
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from app.core.version import APP_VERSION

Status = Literal["passed", "failed", "pending"]


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    key: str
    label: str
    category: Literal["automated", "manual"]
    status: Status
    detail: str


def _check(condition: bool, key: str, label: str, detail: str) -> ReadinessCheck:
    return ReadinessCheck(
        key=key,
        label=label,
        category="automated",
        status="passed" if condition else "failed",
        detail=detail,
    )


def _manual(key: str, label: str, env_name: str, env: dict[str, str]) -> ReadinessCheck:
    value = env.get(env_name, "").strip()
    truthy = value.lower() in {"1", "true", "yes", "done", "public"}
    present = truthy if env_name.endswith(("_PUBLIC", "_COMPLETE")) else bool(value)
    return ReadinessCheck(
        key=key,
        label=label,
        category="manual",
        status="passed" if present else "pending",
        detail=(f"Confirmed through {env_name}." if present else f"Set {env_name} after completing this manual step."),
    )


def evaluate_release_readiness(root: Path, env: dict[str, str] | None = None) -> dict:
    root = root.resolve()
    active_env = dict(os.environ if env is None else env)
    checks: list[ReadinessCheck] = []

    required = [
        "README.md",
        "compose.demo.yml",
        "docs/JUDGE_GUIDE.md",
        "docs/VIDEO_SCRIPT.md",
        "docs/RECORDING_GUIDE.md",
        "docs/DEVPOST_SUBMISSION.md",
        "docs/BUILD_LOG.md",
        "docs/EVALUATION.md",
        "docs/SUBMISSION_CHECKLIST.md",
        "docs/BASELINE_COMPARISON.md",
        "docs/LINEAGE_AND_CI.md",
        "docs/RISK_INTELLIGENCE.md",
        "docs/PROJECT_CONTEXT.md",
        "docs/SECURITY_POLICY.md",
        "docs/SECURITY_EXCEPTIONS.md",
        "docs/SECURITY_SLA.md",
        "docs/SECURITY_POSTURE.md",
        "docs/SECURITY_OBJECTIVES.md",
        "docs/PORTFOLIO_GOVERNANCE.md",
        "docs/CONTROL_PLANE.md",
        "docs/LOCAL_CLI.md",
        "scripts/verify_judge_demo.py",
        "app/cli.py",
        "app/services/local_scan.py",
        "app/services/local_sarif.py",
        "app/services/source_types.py",
        "action.yml",
        "examples/sentinel-local-scan.yml",
        "evals/manifest.json",
        "evals/results/latest.json",
        "evals/remediation/manifest.json",
        ".github/workflows/ci.yml",
        ".github/workflows/publish-image.yml",
        ".github/workflows/verify-public-image.yml",
    ]
    missing = [path for path in required if not (root / path).is_file()]
    checks.append(
        _check(
            not missing,
            "required_files",
            "Required submission files",
            f"Missing: {missing}" if missing else "All required files are present.",
        )
    )

    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = pyproject["project"]["version"]
    checks.append(
        _check(
            package_version == APP_VERSION,
            "version_alignment",
            "Application version alignment",
            f"pyproject={package_version}, app={APP_VERSION}",
        )
    )

    eval_result = json.loads((root / "evals/results/latest.json").read_text(encoding="utf-8"))
    static = eval_result.get("static", eval_result)
    remediation = eval_result.get("remediation") or {}
    metrics = static["metrics"]
    coverage = static.get("coverage") or {}
    remediation_metrics = remediation.get("metrics") or {}
    eval_ok = (
        metrics["failed_cases"] == 0
        and metrics["false_positives"] == 0
        and metrics["false_negatives"] == 0
        and metrics["case_pass_rate"] == 1.0
        and metrics.get("specificity") == 1.0
        and coverage.get("positive_and_negative_complete") is True
        and coverage.get("edge_complete") is True
        and remediation_metrics.get("failed_cases") == 0
        and remediation_metrics.get("source_executed_cases") == 0
        and len(eval_result.get("validation_pack_sha256", "")) == 64
        and len(eval_result.get("limitations") or []) >= 5
    )
    checks.append(
        _check(
            eval_ok,
            "evaluation",
            "Committed deterministic validation pack",
            (
                f"Static {metrics['passed_cases']}/{metrics['case_count']} exact cases, "
                f"FP={metrics['false_positives']}, FN={metrics['false_negatives']}; "
                f"remediation {remediation_metrics.get('passed_cases', 0)}/"
                f"{remediation_metrics.get('case_count', 0)}, "
                f"source_executed={remediation_metrics.get('source_executed_cases', 'unknown')}."
            ),
        )
    )

    compose = (root / "compose.demo.yml").read_text(encoding="utf-8")
    checks.append(
        _check(
            "ghcr.io/dizzyz7/sentinel:latest" in compose and "pull_policy: always" in compose,
            "prebuilt_image",
            "Prebuilt judge image",
            "compose.demo.yml points to the GHCR latest image and always pulls it.",
        )
    )

    publish = (root / ".github/workflows/publish-image.yml").read_text(encoding="utf-8")
    checks.append(
        _check(
            "linux/amd64,linux/arm64" in publish and "packages: write" in publish,
            "multiarch_publish",
            "Multi-architecture image publishing",
            "The publish workflow targets amd64 and arm64 with package write permission.",
        )
    )

    readme = (root / "README.md").read_text(encoding="utf-8")
    checks.append(
        _check(
            "60-second judge path" in readme and "Run the 60-second security demo" in readme,
            "judge_path",
            "Judge-oriented README",
            "README leads with the prebuilt 60-second product path.",
        )
    )

    pyproject_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    verifier = (root / "scripts/verify_judge_demo.py").read_text(encoding="utf-8")
    checks.append(
        _check(
            "sentinel-verify-judge" in pyproject_text
            and "COPY scripts ./scripts" in dockerfile
            and "EXPECTED_OUTCOMES" in verifier
            and "verify_evidence_bundle" in verifier,
            "judge_smoke_verifier",
            "Packaged judge smoke verifier",
            "The installed verifier checks exact replay outcomes and Evidence Bundle integrity.",
        )
    )

    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    checks.append(
        _check(
            "Start clean judge smoke stack" in ci
            and "sentinel-verify-judge" in ci
            and "sentinel-judge-smoke" in ci
            and "Run validation pack" in ci
            and "sentinel-validation-pack" in ci,
            "judge_smoke_ci",
            "Clean-container judge smoke CI",
            "CI starts the built image with PostgreSQL and verifies the complete replay path.",
        )
    )

    action = (root / "action.yml").read_text(encoding="utf-8")
    local_cli = (root / "app/services/local_scan.py").read_text(encoding="utf-8")
    local_docs = (root / "docs/LOCAL_CLI.md").read_text(encoding="utf-8")
    checks.append(
        _check(
            'sentinel = "app.cli:cli"' in pyproject_text
            and "Run Sentinel local scan" in action
            and 'sentinel "${args[@]}"' in action
            and "--no-deps" in action
            and "--changed-only" in local_docs
            and "LOCAL_SCAN_SCHEMA_VERSION" in local_cli
            and "Run local CLI self-scan" in ci
            and "sentinel-local-cli" in ci,
            "local_cli",
            "Local CLI and changed-files gate",
            "The installed CLI, composite action, documentation, and CI self-scan are present.",
        )
    )

    forbidden = ["_noop", ".env"]
    present_forbidden = [name for name in forbidden if (root / name).exists()]
    checks.append(
        _check(
            not present_forbidden,
            "release_hygiene",
            "Release-tree hygiene",
            (
                f"Unexpected paths: {present_forbidden}"
                if present_forbidden
                else "No known local or accidental artifacts found."
            ),
        )
    )

    checks.extend(
        [
            _manual("ghcr_public", "GHCR image is anonymously pullable", "SENTINEL_GHCR_PUBLIC", active_env),
            _manual("video_url", "Public video URL added", "SENTINEL_VIDEO_URL", active_env),
            _manual("codex_session", "Primary Codex Session ID added", "SENTINEL_CODEX_SESSION_ID", active_env),
            _manual("devpost", "Devpost fields reviewed and complete", "SENTINEL_DEVPOST_COMPLETE", active_env),
        ]
    )

    automated_failed = sum(item.category == "automated" and item.status == "failed" for item in checks)
    manual_pending = sum(item.category == "manual" and item.status != "passed" for item in checks)
    return {
        "schema_version": "sentinel-release-readiness-v1",
        "app_version": APP_VERSION,
        "ready_for_submission": automated_failed == 0 and manual_pending == 0,
        "automated_checks_passed": automated_failed == 0,
        "automated_failed": automated_failed,
        "manual_pending": manual_pending,
        "checks": [asdict(item) for item in checks],
    }
