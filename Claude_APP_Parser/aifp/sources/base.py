"""
저장소 리더 공통 인터페이스.

모든 리더는 Record(원시 레코드) 목록을 돌려준다.
Record는 아직 '행위'가 아니다 — 그냥 "어디서 무엇을 읽었다"는 사실이다.
행위 판정은 actions.py가 이 Record들을 보고 한다.

리더를 추가할 때 코어를 고칠 필요가 없도록 여기만 구현하면 되게 했다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import ErrorCollector
from ..provenance import ArtifactRef, Manifest


@dataclass
class Record:
    """
    저장소에서 읽어낸 원시 레코드 1건.

    kind 예시:
      conversation  대화 전문(JSON)
      draft         입력 초안 스냅샷
      account       계정·조직 식별자
      marker        특정 문자열 마커 출현
      appevent      앱 로그 1줄
      fileinfo      파일 존재·시각
    """
    kind: str
    source: str                              # 리더 이름 (cache / indexeddb / ...)
    key: str | None = None                   # 캐시 키·LevelDB 키 등
    value: Any = None                        # 해석된 값
    ts_utc: str | None = None                # 레코드가 자체적으로 가진 시각
    time_source: str | None = None
    ref: ArtifactRef | None = None           # 이 레코드의 출처
    meta: dict[str, Any] = field(default_factory=dict)


class Source:
    """리더 베이스. name과 read()만 구현하면 파이프라인에 자동으로 들어간다."""

    name = "base"
    display = "저장소"
    # 이 리더가 무엇을 기준으로 한 번씩 돌아야 하는지.
    #   "app"    앱 루트마다 (기본)
    #   "user"   사용자 프로필마다 — 앱 루트가 둘이어도 로그는 한 벌이다
    #   "volume" 볼륨마다 — 변경 저널·휴지통은 볼륨 전체가 대상이다
    scope = "app"

    def __init__(self, root, errs: ErrorCollector, manifest: Manifest, *,
                 evidence=None, user_root=None, volume_root=None,
                 workdir: Path | None = None) -> None:
        self.root = root                  # Claude 앱 루트 (VPath)
        self.errs = errs
        self.manifest = manifest
        self.evidence = evidence          # 증거 전체 (이미지/폴더)
        self.user_root = user_root        # 사용자 프로필 루트
        self.volume_root = volume_root    # 볼륨 루트 (Windows/Prefetch 등)
        self.workdir = workdir            # 작업 사본 위치
        self.records: list[Record] = []

    def realize(self, rel: str, name: str) -> Path | None:
        """
        외부 라이브러리가 실제 파일 경로를 요구할 때, 증거에서 작업 사본을 꺼낸다.
        폴더 모드면 원래 경로를 그대로 쓴다(추가 복사 없음).
        """
        target = self.root / rel
        if not target.exists():
            return None
        if self.evidence is None or self.evidence.mode != "image":
            return Path(str(target))
        if self.workdir is None:
            return None
        dest = self.workdir / name
        if dest.exists():
            return dest
        return self.evidence.export_dir(f"{self.root.rel}/{rel}" if self.root.rel else rel,
                                        dest)

    # ── 하위 클래스가 구현 ──────────────────────────────────────────────
    def locate(self) -> list[Path]:
        """읽을 파일 목록. 없으면 빈 리스트."""
        raise NotImplementedError

    def read(self) -> list[Record]:
        """레코드 추출. 예외는 던지지 말고 self.errs에 기록할 것."""
        raise NotImplementedError

    # ── 공통 도우미 ────────────────────────────────────────────────────
    def emit(self, rec: Record) -> None:
        self.records.append(rec)

    def safe_bytes(self, path: Path) -> bytes | None:
        """읽지 못하면 None + 사실 기록. 여기서 멈추지 않는다."""
        try:
            data = path.read_bytes()
        except PermissionError as exc:
            self.errs.add("error", "ARTIFACT_LOCKED", "collect", self.name,
                          "점유 중이라 읽지 못함 — 이미지 분석에서는 발생하지 않는다", str(path))
            self.manifest.mark(path, "locked", str(exc))
            return None
        except FileNotFoundError:
            self.errs.add("info", "TARGET_NOT_FOUND", "collect", self.name,
                          "대상 파일 없음", str(path))
            return None
        except OSError as exc:
            self.errs.from_exception(exc, "collect", self.name, str(path))
            return None
        return data

    def run(self) -> list[Record]:
        """예외가 나도 파이프라인을 멈추지 않는 실행 래퍼."""
        with self.errs.guard("parse", self.name):
            self.records = self.read()
        return self.records
