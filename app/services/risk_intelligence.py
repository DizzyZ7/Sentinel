from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath

from app.models.finding import Finding
from app.models.risk_intelligence import RiskIntelligence
from app.schemas.risk_intelligence import (
    ExecutiveReport,
    ExecutiveRiskItem,
    ExecutiveSummary,
    RiskIntelligenceResponse,
)
from app.services.policy import evaluate_gate

RISK_ENGINE_VERSION = "sentinel-risk-intelligence-v1"

SEVERITY_SCORE = {"critical": 100.0, "high": 82.0, "medium": 58.0, "low": 30.0}


@dataclass(frozen=True, slots=True)
class RiskProfile:
    attack_surface: str
    exploitability: float
    exposure: str
    exposure_score: float
    data_exposure: str
    privilege_required: str
    blast_radius: str
    impact: str
    action: str
    remediation: tuple[str, ...]
    effort: str


DEFAULT_PROFILE = RiskProfile(
    attack_surface="application",
    exploitability=0.55,
    exposure="unknown",
    exposure_score=0.45,
    data_exposure="application state",
    privilege_required="unknown",
    blast_radius="medium",
    impact="The unsafe operation may affect application confidentiality, integrity, or availability.",
    action="Validate the trust boundary and remediate before the affected component is promoted.",
    remediation=(
        "Confirm the attacker-controlled input and sensitive operation.",
        "Apply the smallest validated code change.",
        "Keep the regression proof and human decision with the release evidence.",
    ),
    effort="30-60 minutes",
)

PROFILES: tuple[tuple[str, RiskProfile], ...] = (
    (
        "SQL_INTERPOLATION",
        RiskProfile(
            "data",
            0.9,
            "public",
            0.9,
            "application database records",
            "none_or_low",
            "high",
            "An attacker may read, alter, or delete records available to the vulnerable database identity.",
            "Replace dynamic SQL construction before release and review the database account blast radius.",
            (
                "Replace string interpolation with a parameterized query.",
                "Add a regression case containing SQL metacharacters.",
                "Verify the database identity follows least privilege.",
            ),
            "15-45 minutes",
        ),
    ),
    (
        "COMMAND_INJECTION",
        RiskProfile(
            "code_execution",
            0.95,
            "public",
            0.95,
            "host process and reachable credentials",
            "none_or_low",
            "critical",
            "An attacker may execute operating-system commands with the application process privileges.",
            (
                "Remove shell interpretation before release and rotate credentials reachable by the process "
                "if exposure occurred."
            ),
            (
                "Use an argument-array API without a shell.",
                "Allowlist permitted operations and reject metacharacters.",
                "Add a regression case proving attacker input is not interpreted as a command.",
            ),
            "30-90 minutes",
        ),
    ),
    (
        "DYNAMIC_EXECUTION",
        RiskProfile(
            "code_execution",
            0.9,
            "public",
            0.9,
            "application runtime and process secrets",
            "none_or_low",
            "critical",
            "Attacker-influenced source text may execute inside the application runtime.",
            "Eliminate dynamic evaluation and replace it with an explicit parser or allowlisted operation map.",
            (
                "Remove eval, exec, or dynamic function construction.",
                "Map accepted values to explicit operations.",
                "Add a malicious-expression regression case.",
            ),
            "30-120 minutes",
        ),
    ),
    (
        "UNSAFE_DESERIALIZATION",
        RiskProfile(
            "code_execution",
            0.82,
            "external_input",
            0.78,
            "runtime objects and process authority",
            "low",
            "critical",
            "A crafted serialized payload may instantiate unsafe objects or trigger gadget behavior.",
            "Use a data-only format and an explicit schema before accepting the payload.",
            (
                "Replace object deserialization with JSON or another data-only format.",
                "Validate the payload against an explicit schema.",
                "Reject unexpected object types and fields.",
            ),
            "45-120 minutes",
        ),
    ),
    (
        "YAML_UNSAFE_LOAD",
        RiskProfile(
            "code_execution",
            0.72,
            "file_or_request",
            0.68,
            "runtime objects and configuration",
            "low",
            "high",
            "Unsafe YAML construction may instantiate attacker-selected Python objects.",
            "Use a safe loader and constrain the accepted document schema.",
            (
                "Switch to safe_load or an explicitly safe loader.",
                "Validate expected keys and primitive types.",
                "Add a tagged-object regression fixture.",
            ),
            "15-45 minutes",
        ),
    ),
    (
        "SENSITIVE_ROUTE_NO_AUTH",
        RiskProfile(
            "authorization",
            0.88,
            "public",
            1.0,
            "administrative or user-controlled operations",
            "none",
            "high",
            "An unauthenticated caller may invoke a sensitive route or access protected records.",
            "Add identity and authorization checks before the route is deployed.",
            (
                "Require authenticated identity at the route boundary.",
                "Enforce the minimum role or ownership rule.",
                "Add anonymous and wrong-role regression cases.",
            ),
            "30-90 minutes",
        ),
    ),
    (
        "PATH_TRAVERSAL",
        RiskProfile(
            "filesystem",
            0.78,
            "public",
            0.82,
            "files readable by the application identity",
            "none_or_low",
            "high",
            "A crafted path may escape the intended directory and expose local files.",
            "Resolve paths against a fixed root and reject any path that escapes it.",
            (
                "Normalize the requested path against a fixed base directory.",
                "Reject traversal, absolute paths, and unexpected file types.",
                "Add encoded and nested traversal regression cases.",
            ),
            "30-60 minutes",
        ),
    ),
    (
        "SSRF",
        RiskProfile(
            "network",
            0.82,
            "public",
            0.9,
            "internal services and cloud metadata",
            "none_or_low",
            "high",
            "The server may be induced to reach internal services, metadata endpoints, or attacker-controlled hosts.",
            "Constrain outbound destinations and block private, loopback, and metadata address ranges.",
            (
                "Allowlist permitted schemes and destination hosts.",
                "Resolve and reject private, loopback, link-local, and metadata addresses.",
                "Revalidate redirects and add internal-address regression cases.",
            ),
            "45-120 minutes",
        ),
    ),
    (
        "SECRET",
        RiskProfile(
            "supply_chain",
            0.75,
            "repository",
            0.82,
            "credential authority and connected systems",
            "repository_access",
            "high",
            "A credential committed to source may leak through clones, logs, caches, artifacts, or container layers.",
            "Revoke the exposed credential, remove it from source, and use a managed secret provider.",
            (
                "Revoke or rotate the credential immediately.",
                "Replace the literal with a secret-provider lookup.",
                "Review repository history and downstream artifacts for exposure.",
            ),
            "30-120 minutes",
        ),
    ),
)


def _profile(rule_id: str) -> RiskProfile:
    return next((profile for marker, profile in PROFILES if marker in rule_id.upper()), DEFAULT_PROFILE)


def _asset(finding: Finding) -> tuple[str, str, str, float]:
    normalized = finding.file_path.replace("\\", "/").lower()
    path = PurePosixPath(normalized)
    component = str(path.parent) if str(path.parent) != "." else "repository root"
    tokens = set(path.parts)
    name = path.stem or "application"

    if tokens & {"admin", "auth", "identity", "iam"} or any(x in normalized for x in ("admin", "auth", "token")):
        return "identity and administrative services", "identity_service", component, 1.0
    if tokens & {"payments", "billing", "finance"} or any(x in normalized for x in ("payment", "billing")):
        return "payment and billing services", "financial_service", component, 1.0
    if any(x in normalized for x in ("user", "account", "profile", "customer")):
        return "customer data service", "data_service", component, 0.92
    if tokens & {"api", "routes", "controllers", "handlers"} or any(x in normalized for x in ("api", "route")):
        return f"{name} API component", "backend_api", component, 0.82
    if tokens & {"infra", "terraform", "k8s", "kubernetes", "docker"}:
        return "deployment infrastructure", "infrastructure", component, 0.9
    if tokens & {"frontend", "ui", "web", "client"}:
        return "user-facing web application", "frontend", component, 0.68
    return f"{name} application component", "application_component", component, 0.65


def _priority(score: float) -> str:
    if score >= 85:
        return "immediate"
    if score >= 65:
        return "before_release"
    if score >= 40:
        return "planned"
    return "monitor"


def _remediation_multiplier(finding: Finding) -> float:
    decision = getattr(finding, "decision", None)
    verification = getattr(finding, "verification", None)
    approved = bool(decision and decision.decision == "approved")
    proof_passed = bool(verification and verification.status == "passed")
    if approved and proof_passed and finding.patch_valid:
        return 0.15
    if proof_passed and finding.patch_valid:
        return 0.35
    if finding.patch_valid:
        return 0.7
    return 1.0


def build_risk_intelligence(finding: Finding) -> RiskIntelligence | None:
    if not finding.confirmed or not finding.severity:
        return None

    profile = _profile(finding.rule_id)
    asset_name, asset_type, component, asset_importance = _asset(finding)
    technical = SEVERITY_SCORE[finding.severity]
    confidence = max(0.0, min(1.0, getattr(finding, "confidence", None) or getattr(finding, "static_confidence", 0.9)))
    inherent = round(
        technical * 0.4
        + profile.exploitability * 100 * 0.2
        + profile.exposure_score * 100 * 0.15
        + asset_importance * 100 * 0.15
        + confidence * 100 * 0.1,
        1,
    )
    multiplier = _remediation_multiplier(finding)
    residual = round(inherent * multiplier, 1)
    priority = _priority(residual)
    impact_summary = f"{asset_name}: {profile.impact}"
    recommended_action = profile.action
    if multiplier < 1:
        recommended_action = (
            "Retain the validated patch, regression proof, and human decision with the release evidence."
            if multiplier <= 0.15
            else "Complete the remaining proof or human-approval stage before release."
        )

    return RiskIntelligence(
        finding_id=finding.id,
        engine_version=RISK_ENGINE_VERSION,
        asset_name=asset_name,
        asset_type=asset_type,
        component=component,
        attack_surface=profile.attack_surface,
        exposure=profile.exposure,
        data_exposure=profile.data_exposure,
        privilege_required=profile.privilege_required,
        blast_radius=profile.blast_radius,
        technical_score=technical,
        exploitability_score=round(profile.exploitability * 100, 1),
        exposure_score=round(profile.exposure_score * 100, 1),
        asset_importance_score=round(asset_importance * 100, 1),
        confidence_score=round(confidence * 100, 1),
        inherent_risk_score=inherent,
        residual_risk_score=residual,
        priority=priority,
        impact_summary=impact_summary,
        business_impact=profile.impact,
        recommended_action=recommended_action,
        remediation_plan=list(profile.remediation),
        estimated_effort=profile.effort,
        scoring_factors={
            "technical": technical,
            "exploitability": round(profile.exploitability * 100, 1),
            "exposure": round(profile.exposure_score * 100, 1),
            "asset_importance": round(asset_importance * 100, 1),
            "confidence": round(confidence * 100, 1),
            "remediation_multiplier": multiplier,
            "formula": "40% technical + 20% exploitability + 15% exposure + 15% asset + 10% confidence",
        },
    )


def ensure_risk_intelligence(finding: Finding) -> RiskIntelligence | None:
    generated = build_risk_intelligence(finding)
    if generated is None:
        finding.risk_intelligence = None
        return None
    existing = finding.risk_intelligence
    if existing is None:
        finding.risk_intelligence = generated
        return generated
    for field in (
        "engine_version",
        "asset_name",
        "asset_type",
        "component",
        "attack_surface",
        "exposure",
        "data_exposure",
        "privilege_required",
        "blast_radius",
        "technical_score",
        "exploitability_score",
        "exposure_score",
        "asset_importance_score",
        "confidence_score",
        "inherent_risk_score",
        "residual_risk_score",
        "priority",
        "impact_summary",
        "business_impact",
        "recommended_action",
        "remediation_plan",
        "estimated_effort",
        "scoring_factors",
    ):
        setattr(existing, field, getattr(generated, field))
    return existing


def _risk_response(risk: RiskIntelligence) -> RiskIntelligenceResponse:
    return RiskIntelligenceResponse.model_validate(risk)


def build_executive_report(scan_id: str, findings: list[Finding]) -> ExecutiveReport:
    confirmed = [finding for finding in findings if finding.confirmed and finding.severity]
    risks: list[ExecutiveRiskItem] = []
    for finding in confirmed:
        risk = finding.risk_intelligence or build_risk_intelligence(finding)
        if risk is None:
            continue
        risks.append(
            ExecutiveRiskItem(
                finding_id=finding.id,
                title=finding.title,
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                line=finding.line,
                severity=finding.severity,
                risk=_risk_response(risk),
            )
        )
    risks.sort(key=lambda item: (-item.risk.residual_risk_score, item.file_path, item.line))
    attack_surfaces = Counter(item.risk.attack_surface for item in risks)
    assets = Counter(item.risk.asset_name for item in risks)
    posture_score = max((item.risk.residual_risk_score for item in risks), default=0.0)
    if posture_score >= 85:
        posture_state = "critical"
    elif posture_score >= 65:
        posture_state = "high"
    elif posture_score >= 40:
        posture_state = "elevated"
    elif posture_score > 0:
        posture_state = "guarded"
    else:
        posture_state = "clear"
    gate = evaluate_gate(scan_id, findings)
    if not gate.passed:
        release_recommendation = "Block release until all gate blockers have verified and human-approved remediation."
    elif posture_score >= 40:
        release_recommendation = "Release gate passed, but schedule the remaining lower-priority exposure."
    else:
        release_recommendation = "No blocking security exposure remains in the reviewed evidence."

    summary = ExecutiveSummary(
        posture_score=posture_score,
        posture_state=posture_state,
        confirmed_findings=len(confirmed),
        unreviewed_candidates=sum(f.llm_status in {"pending", "failed", "skipped"} for f in findings),
        immediate_actions=sum(item.risk.priority == "immediate" for item in risks),
        before_release_actions=sum(item.risk.priority == "before_release" for item in risks),
        public_exposures=sum(item.risk.exposure in {"public", "external_input"} for item in risks),
        sensitive_data_paths=sum(item.risk.data_exposure != "application state" for item in risks),
        affected_assets=len(assets),
        top_attack_surface=attack_surfaces.most_common(1)[0][0] if attack_surfaces else None,
        release_recommendation=release_recommendation,
    )
    return ExecutiveReport(
        scan_id=scan_id,
        generated_at=datetime.now(UTC),
        engine_version=RISK_ENGINE_VERSION,
        gate=gate,
        summary=summary,
        top_risks=risks[:5],
        risks=risks,
        attack_surfaces=dict(attack_surfaces),
        assets=dict(assets),
    )
