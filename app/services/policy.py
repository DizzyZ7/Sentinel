from collections.abc import Iterable

from app.models.finding import Finding
from app.schemas.policy import GateBlocker, GateResponse

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate_gate(
    scan_id: str,
    findings: Iterable[Finding],
    block_on: str = "high",
    fail_closed_on_unreviewed: bool = True,
) -> GateResponse:
    threshold = SEVERITY_RANK[block_on]
    blockers: list[GateBlocker] = []
    evaluated = 0
    remediated = 0

    for finding in findings:
        if finding.confirmed and finding.severity and SEVERITY_RANK[finding.severity] >= threshold:
            evaluated += 1
            if finding.patch_valid and finding.decision and finding.decision.decision == "approved":
                remediated += 1
                continue
            if finding.decision and finding.decision.decision == "rejected":
                reason = "A human rejected the proposed remediation; the confirmed exposure remains open."
            elif not finding.patch_valid:
                reason = "The confirmed finding has no validated patch in escrow."
            else:
                reason = "The validated patch is awaiting explicit human approval."
            blockers.append(
                GateBlocker(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    file_path=finding.file_path,
                    line=finding.line,
                    severity=finding.severity,
                    reason=reason,
                )
            )
            continue

        if (
            fail_closed_on_unreviewed
            and finding.llm_status in {"failed", "skipped", "pending"}
            and finding.static_confidence >= 0.9
        ):
            evaluated += 1
            blockers.append(
                GateBlocker(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    file_path=finding.file_path,
                    line=finding.line,
                    severity=None,
                    reason=(
                        "High-confidence deterministic evidence was not completed by the deep-review stage; "
                        "the gate fails closed."
                    ),
                )
            )

    return GateResponse(
        scan_id=scan_id,
        state="passed" if not blockers else "blocked",
        passed=not blockers,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
        evaluated_findings=evaluated,
        remediated_findings=remediated,
        blockers=blockers,
    )
