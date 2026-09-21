"""
재개(resume) — 중단된 분석을 이어서 한다.

500GB 이미지를 20분 돌리다 끊기면 처음부터 다시 하는 건 실무에서 못 쓴다.
그래서 리더 하나가 끝날 때마다 **체크포인트**를 남기고,
다시 실행하면 남은 리더부터 이어 간다.

이어 갈 때 반드시 확인하는 것
  · 증거가 같은가 (경로 + 크기 + 열기 해시)
  · 규칙 파일이 같은가 (버전)
  · 도구가 같은 버전인가
하나라도 다르면 **이어가지 않고 처음부터** 한다. 섞인 결과가 제일 위험하다.
"""

from __future__ import annotations

import json
import os
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHECKPOINT_NAME = "_checkpoint.json"
RECORDS_NAME = "_records.pkl"


@dataclass
class Checkpoint:
    """중단 지점과 그때까지의 산출물."""
    case_id: str = ""
    tool_version: str = ""
    rule_version: str = ""
    evidence_source: str = ""
    evidence_size: int = 0
    evidence_digest: str = ""
    done_sources: list[str] = field(default_factory=list)
    updated_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "tool_version": self.tool_version,
            "rule_version": self.rule_version,
            "evidence_source": self.evidence_source,
            "evidence_size": self.evidence_size,
            "evidence_digest": self.evidence_digest,
            "done_sources": self.done_sources,
            "updated_utc": self.updated_utc,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Checkpoint":
        cp = cls()
        for k, v in d.items():
            if hasattr(cp, k):
                setattr(cp, k, v)
        return cp

    def matches(self, other: "Checkpoint") -> tuple[bool, str]:
        """이어가도 되는지 판단. 다르면 사유를 함께 돌려준다."""
        if self.tool_version != other.tool_version:
            return False, f"도구 버전이 다르다 ({self.tool_version} → {other.tool_version})"
        if self.rule_version != other.rule_version:
            return False, f"규칙 버전이 다르다 ({self.rule_version} → {other.rule_version})"
        if self.evidence_source != other.evidence_source:
            return False, "증거 경로가 다르다"
        if self.evidence_size != other.evidence_size:
            return False, "증거 크기가 다르다"
        if self.evidence_digest and other.evidence_digest and \
                self.evidence_digest != other.evidence_digest:
            return False, "증거 해시가 다르다 — 다른 증거이거나 변조됐다"
        return True, ""


class CheckpointStore:
    """체크포인트와 중간 레코드를 사건 폴더에 저장·복원한다."""

    def __init__(self, out_dir: Path) -> None:
        self.dir = Path(out_dir)
        self.cp_path = self.dir / CHECKPOINT_NAME
        self.rec_path = self.dir / RECORDS_NAME

    def load(self) -> tuple[Checkpoint | None, list]:
        if not self.cp_path.exists():
            return None, []
        try:
            cp = Checkpoint.from_dict(json.loads(self.cp_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError):
            return None, []
        records: list = []
        if self.rec_path.exists():
            try:
                with self.rec_path.open("rb") as f:
                    records = pickle.load(f)
            except Exception:
                # 레코드가 깨졌으면 체크포인트도 못 믿는다
                return None, []
        return cp, records

    def save(self, cp: Checkpoint, records: list) -> bool:
        """
        저장에 실패해도 분석은 계속한다. 체크포인트는 편의 기능이지
        판정 근거가 아니기 때문이다. 같은 폴더에 두 개가 동시에 돌 때
        임시 파일이 부딪히지 않도록 이름에 프로세스 번호를 붙인다.
        """
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            cp.updated_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            tmp = self.cp_path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(cp.to_dict(), ensure_ascii=False, indent=2),
                           encoding="utf-8")
            tmp.replace(self.cp_path)      # 원자적 교체 — 쓰다 끊겨도 이전 것이 남는다
        except OSError:
            return False
        try:
            with self.rec_path.open("wb") as f:
                pickle.dump(records, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass
        return True

    def clear(self) -> None:
        """분석이 정상 종료되면 체크포인트를 지운다."""
        for p in (self.cp_path, self.rec_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
