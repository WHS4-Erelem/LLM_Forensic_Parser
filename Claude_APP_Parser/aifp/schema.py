"""
통합 이벤트 스키마 = 데이터 정규화의 결과물.

저장소마다 생긴 게 완전히 다르다.
  캐시는 JSON 응답, IndexedDB는 UTF-16LE 문자열, config.json은 평문,
  main.log는 줄글, lockfile은 파일 존재 여부 그 자체.

이걸 전부 **한 가지 모양(Event)** 으로 바꾸는 게 정규화다.
모양이 같아야 시간순으로 줄 세우고(타임라인), 서로 대조할 수 있다(교차 검증).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from .provenance import ArtifactRef
from .timeutil import TimeConfidence, TimeSource

SCHEMA_VERSION = "1.0"


class EvidenceLevel(str, Enum):
    """이 근거 하나로 행위를 단정할 수 있는가."""
    DIRECT = "direct"              # 그 행위에서만 생기는 흔적
    SUPPORTING = "supporting"      # 다른 행위에서도 생길 수 있음
    INCONCLUSIVE = "inconclusive"  # 판단 불가


class Recovery(str, Enum):
    LIVE = "live"                             # 원본 잔존
    DELETED_RECOVERED = "deleted_recovered"   # 삭제됐지만 내용 복원
    DELETED_METADATA_ONLY = "deleted_metadata_only"  # 이름·시각만


@dataclass
class Event:
    """
    정규화된 이벤트 1건. 파서의 최종 출력 단위.

    반드시 채워야 하는 것:
      - timestamp_utc + time_source + time_confidence  (시각과 그 출처)
      - artifacts                                       (근거 — 비면 안 된다)
    """
    # 정체
    action_id: str                       # E04-01 등
    action_name: str                     # 사람이 읽는 행위 이름
    action_category: str                 # 계정 / 대화 관리 / 프롬프트 ...
    summary: str                         # 한 줄 설명

    # 시각
    timestamp_utc: str | None = None
    time_source: str = TimeSource.UNKNOWN.value
    time_confidence: str = TimeConfidence.LOW.value
    time_note: str | None = None         # 신뢰도 경고 사유

    # 판정
    evidence_level: str = EvidenceLevel.SUPPORTING.value
    confidence: int = 0                  # 0~100, 독립 채널 수 기반
    recovery: str = Recovery.LIVE.value

    # 식별자
    account_uuid: str | None = None
    org_uuid: str | None = None
    conversation_uuid: str | None = None
    device_id: str | None = None

    # 내용
    content: str | None = None           # 복원한 프롬프트·응답 원문
    content_role: str | None = None      # human / assistant
    client_version: str | None = None

    # 근거
    artifacts: list[ArtifactRef] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # 고정 필드
    event_id: str = ""          # finalize()에서 내용 기반으로 채운다
    service: str = "Claude"
    client: str = "desktop"

    def make_id(self) -> str:
        """
        이벤트 ID를 **내용에서 계산**한다.

        랜덤 UUID를 쓰면 같은 증거를 두 번 분석했을 때 ID가 달라져
        "동일 입력·동일 규칙에서 동일 출력"을 증명할 수 없다.
        행위·시각·근거 경로를 재료로 해시를 만들면 재현성이 생긴다.
        """
        def _s(v: Any) -> str:
            # 디스크에서 온 값은 문자열이 아닐 수 있다 — uuid 가 숫자로 들어오는 식이다
            if v is None or v == "":
                return "-"
            return v if isinstance(v, str) else str(v)

        seed = "|".join([
            _s(self.action_id),
            _s(self.timestamp_utc),
            _s(self.conversation_uuid),
            _s(self.content_role),
            _s(self.content)[:200],
            ";".join(sorted(f"{a.storage}:{a.path}:{a.locator or ''}:{a.offset or ''}"
                            for a in self.artifacts)),
        ])
        # 디스크에서 건진 문자열에는 짝 없는 서러게이트가 섞일 수 있다.
        # 그대로 인코딩하면 예외가 나므로 대체 문자로 바꿔서 해시한다.
        return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:32]

    # ── 조작 ────────────────────────────────────────────────────────────
    def add_artifact(self, ref: ArtifactRef) -> "Event":
        self.artifacts.append(ref)
        return self

    def add_note(self, text: str) -> "Event":
        if text and text not in self.notes:
            self.notes.append(text)
        return self

    @property
    def channels(self) -> set[str]:
        """근거가 몇 개의 서로 다른 저장소에서 나왔는가 = 독립 채널 수."""
        return {a.storage for a in self.artifacts}

    def score_confidence(self) -> int:
        """
        확신도 산출.
          직접 증거는 기본 60, 보조 증거는 35에서 출발하고
          독립 채널이 하나 늘 때마다 +15.
          시각 신뢰도가 낮으면 -10 (시각을 못 믿으면 귀속도 약해진다).
        """
        base = {EvidenceLevel.DIRECT.value: 60,
                EvidenceLevel.SUPPORTING.value: 35,
                EvidenceLevel.INCONCLUSIVE.value: 10}.get(self.evidence_level, 30)
        score = base + 15 * max(0, len(self.channels) - 1)
        if self.time_confidence == TimeConfidence.LOW.value:
            score -= 10
        self.confidence = max(0, min(100, score))
        return self.confidence

    def validate(self) -> list[str]:
        """스키마 규칙 위반 목록. 비어 있으면 통과."""
        problems: list[str] = []
        if not self.artifacts:
            problems.append("근거 아티팩트가 없다 — 결론에는 반드시 출처가 붙어야 한다")
        if self.timestamp_utc and self.time_source == TimeSource.UNKNOWN.value:
            problems.append("시각은 있는데 출처가 없다")
        if self.evidence_level not in {e.value for e in EvidenceLevel}:
            problems.append(f"증거 수준 값이 잘못됨: {self.evidence_level}")
        if self.recovery not in {r.value for r in Recovery}:
            problems.append(f"복구 상태 값이 잘못됨: {self.recovery}")
        return problems

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["artifacts"] = [a.to_dict() for a in self.artifacts]
        d["schema_version"] = SCHEMA_VERSION
        return {k: v for k, v in d.items() if v not in (None, [], "")}


@dataclass
class ParseResult:
    """파서 1회 실행의 전체 산출물."""
    events: list[Event] = field(default_factory=list)
    case_id: str = ""
    target_root: str = ""
    tool_version: str = ""
    rule_version: str = ""

    def add(self, event: Event) -> None:
        event.score_confidence()
        if not event.event_id:
            event.event_id = event.make_id()
        # 같은 사실이 두 번 실리지 않게 한다. 앱 루트가 둘 이상인 디스크에서는
        # 같은 로그 파일을 두 경로로 읽어 같은 이벤트가 중복될 수 있다.
        # event_id 는 내용에서 계산하므로, 같으면 같은 사실이다.
        if any(e.event_id == event.event_id for e in self.events):
            return
        self.events.append(event)

    def sorted_events(self) -> list[Event]:
        """시각 없는 이벤트는 뒤로 보낸다 — 순서를 왜곡하지 않기 위해."""
        return sorted(self.events, key=lambda e: (e.timestamp_utc is None, e.timestamp_utc or ""))
