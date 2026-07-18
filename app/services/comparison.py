import hashlib
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import UTC, datetime

from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.comparison import (
    ComparisonFinding,
    ComparisonItem,
    ComparisonSummary,
    DeltaGateBlocker,
    DeltaGateResponse,
    ScanComparison,
)
from app.services.policy import SEVERITY_RANK, evaluate_gate

WHITESPACE_RE = re.compile(r"\s+")
STATE_ORDER = {"introduced": 0, "changed": 1, "persistent": 2, "resolved": 3}


def _normalized_snippet(snippet: str) -> str:
    return WHITESPACE_RE.sub(" ", snippet.strip())


def finding_fingerprint(finding: Finding) -> str:
    canonical = "\0".join(
        [
            finding.rule_id,
            finding.file_path.replace("\\", "/").lower(),
            finding.language.lower(),
            _normalized_snippet(finding.snippet),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _locator(finding: Finding) -> str:
    return f"{finding.rule_id}:{finding.file_path.replace('\\', '/').lower()}"


def _snapshot(finding: Finding) -> ComparisonFinding:
    return ComparisonFinding(
        id=finding.id,
        fingerprint=finding_fingerprint(finding),
        rule_id=finding.rule_id,
        title=finding.title,
        file_path=finding.file_path,
        line=finding.line,
        end_line=finding.end_line,
        language=finding.language,
        confirmed=finding.confirmed,
        severity=finding.severity,
        static_confidence=finding.static_confidence,
        llm_status=finding.llm_status,
        patch_valid=finding.patch_valid,
        verification_status=finding.verification.status if finding.verification else None,
        decision=finding.decision.decision if finding.decision else None,
    )


def _severity_direction(baseline: Finding | None, current: Finding | None) -> str:
    if baseline is None or current is None:
        return "unknown"
    before = SEVERITY_RANK.get(baseline.severity or "")
    after = SEVERITY_RANK.get(current.severity or "")
    if before is None or after is None:
        return "unknown"
    if after > before:
        return "increased"
    if after < before:
        return "decreased"
    return "unchanged"


def compare_findings(
    baseline_findings: Iterable[Finding],
    current_findings: Iterable[Finding],
) -> list[ComparisonItem]:
    baseline = list(baseline_findings)
    current = list(current_findings)
    baseline_by_fp: dict[str, deque[Finding]] = defaultdict(deque)
    current_by_fp: dict[str, deque[Finding]] = defaultdict(deque)
    for finding in baseline:
        baseline_by_fp[finding_fingerprint(finding)].append(finding)
    for finding in current:
        current_by_fp[finding_fingerprint(finding)].append(finding)

    items: list[ComparisonItem] = []
    matched_baseline: set[str] = set()
    matched_current: set[str] = set()
    for fingerprint in sorted(set(baseline_by_fp) & set(current_by_fp)):
        left = baseline_by_fp[fingerprint]
        right = current_by_fp[fingerprint]
        while left and right:
            before = left.popleft()
            after = right.popleft()
            matched_baseline.add(before.id)
            matched_current.add(after.id)
            items.append(
                ComparisonItem(
                    state="persistent",
                    locator=_locator(after),
                    severity_direction=_severity_direction(before, after),
                    baseline=_snapshot(before),
                    current=_snapshot(after),
                )
            )

    baseline_unmatched = [item for item in baseline if item.id not in matched_baseline]
    current_unmatched = [item for item in current if item.id not in matched_current]
    baseline_by_locator: dict[str, list[Finding]] = defaultdict(list)
    current_by_locator: dict[str, list[Finding]] = defaultdict(list)
    for finding in baseline_unmatched:
        baseline_by_locator[_locator(finding)].append(finding)
    for finding in current_unmatched:
        current_by_locator[_locator(finding)].append(finding)

    paired_baseline: set[str] = set()
    paired_current: set[str] = set()
    for locator in sorted(set(baseline_by_locator) & set(current_by_locator)):
        left = sorted(baseline_by_locator[locator], key=lambda item: item.line)
        right = sorted(current_by_locator[locator], key=lambda item: item.line)
        while left and right:
            pairs = (
                (abs(before.line - after.line), before.line, after.line, before, after)
                for before in left
                for after in right
            )
            best = min(pairs, key=lambda item: item[:3])
            before, after = best[3], best[4]
            left.remove(before)
            right.remove(after)
            paired_baseline.add(before.id)
            paired_current.add(after.id)
            items.append(
                ComparisonItem(
                    state="changed",
                    locator=locator,
                    severity_direction=_severity_direction(before, after),
                    baseline=_snapshot(before),
                    current=_snapshot(after),
                )
            )

    for finding in current_unmatched:
        if finding.id in paired_current:
            continue
        items.append(
            ComparisonItem(
                state="introduced",
                locator=_locator(finding),
                severity_direction="unknown",
                baseline=None,
                current=_snapshot(finding),
            )
        )
    for finding in baseline_unmatched:
        if finding.id in paired_baseline:
            continue
        items.append(
            ComparisonItem(
                state="resolved",
                locator=_locator(finding),
                severity_direction="unknown",
                baseline=_snapshot(finding),
                current=None,
            )
        )

    return sorted(
        items,
        key=lambda item: (
            STATE_ORDER[item.state],
            -SEVERITY_RANK.get((item.current or item.baseline).severity or "", 0),
            (item.current or item.baseline).file_path,
            (item.current or item.baseline).line,
            item.locator,
        ),
    )


def _delta_gate(
    baseline_scan_id: str,
    current_scan_id: str,
    items: list[ComparisonItem],
    *,
    block_on: str,
    fail_closed_on_unreviewed: bool,
) -> DeltaGateResponse:
    threshold = SEVERITY_RANK[block_on]
    blockers: list[DeltaGateBlocker] = []
    evaluated = 0
    for item in items:
        if item.state not in {"introduced", "changed"} or item.current is None:
            continue
        current = item.current
        reason: str | None = None
        if current.confirmed and current.severity and SEVERITY_RANK[current.severity] >= threshold:
            evaluated += 1
            remediated = (
                current.patch_valid is True
                and current.verification_status == "passed"
                and current.decision == "approved"
            )
            if remediated:
                continue
            reason = (
                "A new unresolved blocking finding was introduced after the baseline."
                if item.state == "introduced"
                else "A baseline finding changed and remains unresolved at the blocking threshold."
            )
        elif (
            fail_closed_on_unreviewed
            and current.llm_status in {"failed", "skipped", "pending"}
            and current.static_confidence >= 0.9
        ):
            evaluated += 1
            reason = "New or changed high-confidence deterministic evidence was not completed by deep review."
        if reason:
            blockers.append(
                DeltaGateBlocker(
                    state=item.state,
                    current_finding_id=current.id,
                    baseline_finding_id=item.baseline.id if item.baseline else None,
                    rule_id=current.rule_id,
                    title=current.title,
                    file_path=current.file_path,
                    line=current.line,
                    severity=current.severity,
                    reason=reason,
                )
            )
    return DeltaGateResponse(
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        state="blocked" if blockers else "passed",
        passed=not blockers,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
        evaluated_regressions=evaluated,
        blockers=blockers,
    )


def build_scan_comparison(
    baseline: Scan,
    current: Scan,
    *,
    block_on: str = "high",
    fail_closed_on_unreviewed: bool = True,
    generated_at: datetime | None = None,
) -> ScanComparison:
    items = compare_findings(baseline.findings, current.findings)
    baseline_gate = evaluate_gate(
        baseline.id,
        baseline.findings,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )
    current_gate = evaluate_gate(
        current.id,
        current.findings,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )
    delta_gate = _delta_gate(
        baseline.id,
        current.id,
        items,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )
    counts = defaultdict(int)
    for item in items:
        counts[item.state] += 1
    return ScanComparison(
        generated_at=generated_at or datetime.now(UTC),
        baseline_scan_id=baseline.id,
        current_scan_id=current.id,
        baseline_gate=baseline_gate,
        current_gate=current_gate,
        delta_gate=delta_gate,
        summary=ComparisonSummary(
            introduced=counts["introduced"],
            resolved=counts["resolved"],
            persistent=counts["persistent"],
            changed=counts["changed"],
            blocking_regressions=len(delta_gate.blockers),
            baseline_risk_score=baseline.risk_score,
            current_risk_score=current.risk_score,
            risk_delta=round(current.risk_score - baseline.risk_score, 2),
        ),
        items=items,
    )
