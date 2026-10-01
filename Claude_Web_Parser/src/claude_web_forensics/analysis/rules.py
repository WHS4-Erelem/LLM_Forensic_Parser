"""Action catalogue and the verdict decision rule."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..model.entities import VERDICT_CONFIRMED, VERDICT_SUSPECTED, VERDICT_UNDETERMINED
from .correlator import EvidenceGroup

ACTION_LABELS: dict[str, str] = {
    "E01-01": "로그인", "E01-02": "로그아웃", "E01-03": "계정 전환", "E03-01": "새로운 대화 생성", "E03-02": "기존 대화 삭제",
    "E03-03": "대화 수정", "E03-04": "대화 재시도", "E04-01": "사용자 프롬프트 입력/전송", "E05-01": "이미지 업로드",
    "E05-02": "이미지 업로드 삭제", "E05-03": "문서 업로드", "E05-04": "문서 업로드 삭제", "E05-05": "문서 다운로드",
    "E06-01": "이미지 생성 요청", "E06-02": "생성 이미지 다운로드", "E06-03": "생성 이미지 다운로드 삭제", "E07-01": "대화 데이터 Export",
    "E07-02": "공유 링크 생성", "E09-01": "모델 변경", "E09-02": "계정 이름 변경", "E10-01": "임시 채팅 사용",
    "E10-02": "브라우저 시크릿 모드", "E10-03": "방문기록 삭제", "E10-04": "캐시 삭제",
}

RULE_IDS: dict[str, str] = {code: "R-" + code.replace("-", "") for code in ACTION_LABELS}

EXCLUDED_ACTION_CODES: frozenset[str] = frozenset({"E02-01", "E02-02", "E04-02", "E07-03", "E08-01", "E08-02",
    "E08-03", "E09-03"})

class UnknownActionError(ValueError):
    pass

def label_for(action_code: str) -> str:
    if action_code not in ACTION_LABELS:
        raise UnknownActionError(f"action code {action_code!r} is not in the action catalogue")
    return ACTION_LABELS[action_code]

def rule_for(action_code: str) -> str:
    label_for(action_code)
    return RULE_IDS[action_code]

def compose_detail(nature: str, core: str = "") -> str:
    nature = (nature or "").strip()
    core = " ".join(str(core or "").split())
    if nature and core:
        return f"{nature}_{core}"
    return nature or core

def first_meaningful_line(text: str, limit: int = 120) -> str:
    for line in str(text or "").splitlines():
        line = " ".join(line.split())
        if line:
            return line[:limit]
    return ""

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
    explanation: str = ""

def decide(data: VerdictInput) -> VerdictResult:
    group = data.group
    if data.conflicts:
        return VerdictResult(VERDICT_UNDETERMINED, R_CONFLICT, "; ".join(data.conflicts))
    if not group.evidence_ids:
        return VerdictResult(VERDICT_UNDETERMINED, R_NO_POSITIVE_EVIDENCE, "no positive trace")
    if data.disqualifiers:
        return VerdictResult(VERDICT_SUSPECTED, R_DISQUALIFIED, "; ".join(data.disqualifiers))
    if group.independent_family_count >= data.required_families:
        return VerdictResult(
            VERDICT_CONFIRMED, R_CROSS_FAMILY,
            f"{group.independent_family_count} independent families: {sorted(group.families)}",
        )
    if data.direct_evidence:
        return VerdictResult(
            VERDICT_CONFIRMED, R_DIRECT_EVIDENCE,
            data.direct_evidence_reason or "explicit allowlisted record",
        )
    reason = R_SINGLE_FAMILY_ONLY if group.independent_family_count == 1 else R_INDIRECT_ONLY
    return VerdictResult(VERDICT_SUSPECTED, reason, "positive trace, not cross-validated")
