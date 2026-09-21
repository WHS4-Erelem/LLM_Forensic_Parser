"""Action catalogue and the verdict decision rule.

Merged verbatim from: actions.py, verdicts.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ..model.entities import (
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
)
from .correlator import EvidenceGroup


# ===========================================================================
# actions
# ===========================================================================

"""Action catalogue: the fixed set of 24 detectable actions.

`action_code` (E05-05) and `rule_id` (R-E0505) stay internal — they identify
detectors, coverage rows and tests. `action_label` is the only name that reaches
the report and it always comes from this table: detectors cannot rename an
action. How strong or partial a trace is goes into 행위_상세, never the label.

Excluded by design (not a Claude web feature, or not performable in the
reproduction experiment): E02-01, E02-02, E04-02, E07-03, E08-01, E08-02,
E08-03, E09-03.
"""

# action_code -> fixed action name (기준 엑셀 명칭).
ACTION_LABELS: dict[str, str] = {
    "E01-01": "로그인",
    "E01-02": "로그아웃",
    "E01-03": "계정 전환",
    "E03-01": "새로운 대화 생성",
    "E03-02": "기존 대화 삭제",
    "E03-03": "대화 수정",
    "E03-04": "대화 재시도",
    "E04-01": "사용자 프롬프트 입력/전송",
    "E05-01": "이미지 업로드",
    "E05-02": "이미지 업로드 삭제",
    "E05-03": "문서 업로드",
    "E05-04": "문서 업로드 삭제",
    "E05-05": "문서 다운로드",
    "E06-01": "이미지 생성 요청",
    "E06-02": "생성 이미지 다운로드",
    "E06-03": "생성 이미지 다운로드 삭제",
    "E07-01": "대화 데이터 Export",
    "E07-02": "공유 링크 생성",
    "E09-01": "모델 변경",
    "E09-02": "계정 이름 변경",
    "E10-01": "임시 채팅 사용",
    "E10-02": "브라우저 시크릿 모드",
    "E10-03": "방문기록 삭제",
    "E10-04": "캐시 삭제",
}

# action_code -> rule id (internal only; never written to an output).
RULE_IDS: dict[str, str] = {
    code: "R-" + code.replace("-", "") for code in ACTION_LABELS
}

EXCLUDED_ACTION_CODES: frozenset[str] = frozenset(
    {"E02-01", "E02-02", "E04-02", "E07-03", "E08-01", "E08-02", "E08-03", "E09-03"}
)


class UnknownActionError(ValueError):
    """An action code outside the fixed 24-action catalogue."""


def check_action_code(action_code: str) -> str:
    if action_code not in ACTION_LABELS:
        raise UnknownActionError(f"action code {action_code!r} is not in the action catalogue")
    return action_code


def label_for(action_code: str) -> str:
    """The fixed action name. Unknown codes are an error, never passed through."""
    return ACTION_LABELS[check_action_code(action_code)]


def rule_for(action_code: str) -> str:
    return RULE_IDS[check_action_code(action_code)]


def compose_detail(nature: str, core: str = "") -> str:
    """행위_상세 = "<흔적 성격>_<핵심 내용>", or just the nature when core is empty."""
    nature = (nature or "").strip()
    core = " ".join(str(core or "").split())
    if nature and core:
        return f"{nature}_{core}"
    return nature or core


def first_meaningful_line(text: str, limit: int = 120) -> str:
    """First non-empty line of a prompt/draft, whitespace-collapsed."""
    for line in str(text or "").splitlines():
        line = " ".join(line.split())
        if line:
            return line[:limit]
    return ""


# ===========================================================================
# verdicts
# ===========================================================================

"""Verdict engine (spec section 16.3 / 16.5).

There is no confidence score. Each detector declares its predicate, identity
key, direct-evidence allowlist, independent-family requirement, temporal rule
and disqualifiers; this module applies the fixed decision rule to the result.

확정   : >= 2 INDEPENDENT artifact families support the same action on the same
         entity, OR a single family carries an explicit record that directly
         demonstrates the action AND that record is on the detector's
         direct-evidence allowlist.
의심   : at least one concrete POSITIVE trace, but neither condition above.
판단불가: no evidence, required artifact missing, contradictory, or
         indistinguishable from a single snapshot.

Absence alone is never sufficient -- not even for 의심.
"""

# Reason codes.
R_CROSS_FAMILY = "cross_validated_independent_families"
R_DIRECT_EVIDENCE = "direct_evidence_allowlisted"
R_SINGLE_FAMILY_ONLY = "single_family_no_direct_evidence"
R_INDIRECT_ONLY = "indirect_positive_trace_only"
R_NO_POSITIVE_EVIDENCE = "no_positive_evidence"
R_DISQUALIFIED = "disqualified_by_rule"
R_CONFLICT = "conflicting_evidence"


@dataclass
class VerdictInput:
    rule_id: str
    group: EvidenceGroup
    direct_evidence: bool = False
    direct_evidence_reason: str = ""
    disqualifiers: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    required_families: int = 2


@dataclass
class VerdictResult:
    verdict: str
    reason_code: str
    families: list[str]
    artifacts: list[str]
    explanation: str = ""


def decide(data: VerdictInput) -> VerdictResult:
    families = sorted(data.group.families)
    artifacts = data.group.display_artifacts()

    if data.conflicts:
        return VerdictResult(
            verdict=VERDICT_UNDETERMINED,
            reason_code=R_CONFLICT,
            families=families,
            artifacts=artifacts,
            explanation="; ".join(data.conflicts),
        )

    if not data.group.evidence_ids:
        return VerdictResult(
            verdict=VERDICT_UNDETERMINED,
            reason_code=R_NO_POSITIVE_EVIDENCE,
            families=families,
            artifacts=artifacts,
            explanation="no positive trace observed",
        )

    if data.disqualifiers:
        return VerdictResult(
            verdict=VERDICT_SUSPECTED,
            reason_code=R_DISQUALIFIED,
            families=families,
            artifacts=artifacts,
            explanation="; ".join(data.disqualifiers),
        )

    if data.group.independent_family_count >= data.required_families:
        return VerdictResult(
            verdict=VERDICT_CONFIRMED,
            reason_code=R_CROSS_FAMILY,
            families=families,
            artifacts=artifacts,
            explanation=(
                f"{data.group.independent_family_count} independent artifact families: "
                + ", ".join(artifacts)
            ),
        )

    if data.direct_evidence:
        return VerdictResult(
            verdict=VERDICT_CONFIRMED,
            reason_code=R_DIRECT_EVIDENCE,
            families=families,
            artifacts=artifacts,
            explanation=data.direct_evidence_reason
            or "explicit record directly demonstrates the action (allowlisted)",
        )

    return VerdictResult(
        verdict=VERDICT_SUSPECTED,
        reason_code=R_SINGLE_FAMILY_ONLY
        if data.group.independent_family_count == 1
        else R_INDIRECT_ONLY,
        families=families,
        artifacts=artifacts,
        explanation=(
            "positive trace present but neither cross-validated nor on the "
            "direct-evidence allowlist"
        ),
    )


def answers_five_questions(
    rule_id: str, identity_keys: dict[str, str], result: VerdictResult, detail_refs: list[str]
) -> bool:
    """Spec section 29: a 확정 must answer all five questions."""
    if result.verdict != VERDICT_CONFIRMED:
        return True
    if not rule_id:
        return False
    if not identity_keys:
        return False
    if result.reason_code == R_CROSS_FAMILY and len(result.families) < 2:
        return False
    if result.reason_code == R_DIRECT_EVIDENCE and not result.explanation:
        return False
    return bool(detail_refs)
