"""
원본 출처(provenance).

파서가 내놓는 **모든 결론에는 근거가 붙어야 한다.**
"대화가 삭제됐다"는 문장 하나에도 어느 파일 어느 오프셋에서 나왔는지,
그 파일의 해시가 무엇인지가 따라붙어야 보고서에 인용할 수 있다.

여기서 만드는 두 가지:
  ArtifactRef  — 근거 1건 (경로·오프셋·크기·해시·저장소 종류)
  Manifest     — 수집한 파일 목록과 해시. 처리 전후 동일성 증명용
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .timeutil import to_utc_iso


class Storage(str, Enum):
    """근거가 나온 저장소 종류. 교차 검증에서 '독립 채널' 판정 기준이 된다."""
    CACHE = "cache"                # HTTP 디스크 캐시
    INDEXEDDB = "indexeddb"        # IndexedDB LevelDB
    LOCALSTORAGE = "localstorage"  # Local Storage LevelDB
    BLOB = "blob"                  # IndexedDB Blob 실물
    CONFIGFILE = "configfile"      # config.json 등 설정
    APPLOG = "applog"              # main.log 등 앱 로그
    FILESYSTEM = "filesystem"      # 파일 존재·메타데이터
    REGISTRY = "registry"          # 레지스트리 하이브


MAX_HASH_BYTES = 64 * 1024 * 1024      # 이보다 큰 파일은 해시를 건너뛴다

def sha256_file(path, chunk: int = 1 << 20) -> str | None:
    """
    파일 전체 해시. 읽지 못하면 None을 돌려주고 호출부가 사실을 기록한다.
    실제 경로(Path)와 이미지 안의 가상 경로(VPath)를 모두 받는다.
    """
    try:
        opener = getattr(path, "open", None)
        if opener is not None and isinstance(path, Path):
            h = hashlib.sha256()
            with path.open("rb") as f:          # 읽기 전용
                while True:
                    b = f.read(chunk)
                    if not b:
                        break
                    h.update(b)
            return h.hexdigest()
        data = path.read_bytes()
        if len(data) > MAX_HASH_BYTES:
            return None
        return hashlib.sha256(data).hexdigest()
    except (OSError, PermissionError, FileNotFoundError, ValueError):
        return None




@dataclass
class ArtifactRef:
    """
    결론 1건을 뒷받침하는 근거 1건.

    offset은 '그 파일 안 어디서 나왔는지'다.
    캐시 엔트리처럼 파일 안이 아니라 키로 지목되는 경우엔 locator에 키를 적는다.
    """
    path: str
    storage: str
    offset: int | None = None
    size: int | None = None
    sha256: str | None = None
    locator: str | None = None        # 캐시 키, LevelDB 키, JSON 포인터 등
    recovered: bool = False           # 삭제분에서 복원했는지
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_file(cls, path, storage: Storage | str, *,
                  offset: int | None = None, size: int | None = None,
                  locator: str | None = None, with_hash: bool = True,
                  recovered: bool = False, note: str | None = None) -> "ArtifactRef":
        st = storage.value if isinstance(storage, Storage) else str(storage)
        fsize = None
        try:
            pstat = path.stat()
            fsize = pstat.st_size
            # 삭제 엔트리에서 읽은 것이면 근거에 그대로 표시한다.
            # 클러스터가 재할당됐으면 내용이 다른 파일의 것일 수 있다.
            if getattr(pstat, "in_use", True) is False:
                recovered = True
                note = (note + " · " if note else "") + "삭제 엔트리(in_use=0)"
        except (OSError, FileNotFoundError):
            pass
        return cls(
            path=str(path),
            storage=st,
            offset=offset,
            size=size if size is not None else fsize,
            sha256=sha256_file(path) if with_hash else None,
            locator=locator,
            recovered=recovered,
            note=note,
        )


@dataclass
class ManifestEntry:
    """수집한 파일 1건."""
    path: str
    size: int
    sha256: str | None
    mtime_utc: str | None
    ctime_utc: str | None
    atime_utc: str | None
    collected_utc: str
    status: str = "ok"                # ok | locked | missing | error
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class Manifest:
    """
    수집 매니페스트.

    처리 전후로 해시를 비교해 **원본이 변하지 않았음을 증명**한다(읽기 전용 보장).
    잠겨서 못 읽은 파일도 status=locked로 남긴다 — 없었던 게 아니라 못 읽은 것이다.
    """

    def __init__(self) -> None:
        self.entries: list[ManifestEntry] = []
        self._by_path: dict[str, ManifestEntry] = {}

    def add_file(self, path, *, status: str = "ok", note: str | None = None,
                 with_hash: bool = True) -> ManifestEntry:
        """
        수집 파일 1건 기록.
        이미지에서 읽은 경우 NTFS $SI 4시각을 그대로 쓴다 — OS가 보정하지 않은 원본 시각이다.
        """
        now = to_utc_iso(datetime.now(timezone.utc))
        try:
            st = path.stat()
            def _t(attr, epoch):
                v = getattr(st, attr, None)
                if v:
                    return v
                return to_utc_iso(datetime.fromtimestamp(epoch, timezone.utc)) if epoch else None
            entry = ManifestEntry(
                path=str(path),
                size=st.st_size,
                sha256=sha256_file(path) if with_hash else None,
                mtime_utc=_t("modified_utc", st.st_mtime),
                ctime_utc=_t("created_utc", st.st_ctime),
                atime_utc=_t("accessed_utc", st.st_atime),
                collected_utc=now,
                status=status,
                note=note,
            )
            if getattr(st, "in_use", True) is False:
                entry.status = "deleted"
                entry.note = (entry.note or "") + " 삭제 엔트리(in_use=0)에서 복원"
            if entry.sha256 is None and entry.status == "ok":
                entry.status = "unhashed"
                entry.note = entry.note or "해시 미산출 — 크기 초과이거나 읽기 실패"
        except (OSError, FileNotFoundError) as exc:
            entry = ManifestEntry(str(path), 0, None, None, None, None, now,
                                  status="missing", note=str(exc))
        self.entries.append(entry)
        self._by_path[str(path)] = entry
        return entry

    def mark(self, path: Path | str, status: str, note: str | None = None) -> None:
        e = self._by_path.get(str(path))
        if e:
            e.status = status
            if note:
                e.note = note

    # ── 집계 ────────────────────────────────────────────────────────────
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.status] = out.get(e.status, 0) + 1
        return out

    @property
    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries if e.status == "ok")

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

    def digest(self) -> str:
        """매니페스트 전체를 하나의 해시로 압축 — 수집 결과의 지문."""
        h = hashlib.sha256()
        for e in sorted(self.entries, key=lambda x: x.path):
            h.update(f"{e.path}|{e.size}|{e.sha256 or '-'}".encode("utf-8", "replace"))
        return h.hexdigest()


