"""
읽기 전용 가상 파일시스템.

이미지 안의 NTFS를 마운트 없이 읽어 **pathlib처럼 다루게** 해준다.
덕분에 저장소 리더(sources/*)는 이미지에서 읽는지 폴더에서 읽는지 몰라도 된다.

여기서만 할 수 있는 일이 있다.
  · **삭제된 파일**(in_use=0)도 목록에 나온다 — 앱을 지운 뒤에도 대화를 찾는 근거
  · **$MFT 4시각**을 그대로 얻는다 — 파일시스템이 보정하지 않은 원본 시각
  · **ADS**(Zone.Identifier 등)를 스트림 이름으로 읽는다

쓰기 함수는 아예 만들지 않았다. 증거를 바꿀 방법이 없어야 한다.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..errors import InputError


@dataclass
class VStat:
    """파일 하나의 메타데이터. NTFS에서는 $SI 4시각을 그대로 쓴다."""
    size: int = 0
    st_size: int = 0
    st_mtime: float = 0.0
    st_ctime: float = 0.0
    st_atime: float = 0.0
    created_utc: str | None = None
    modified_utc: str | None = None
    mft_changed_utc: str | None = None
    accessed_utc: str | None = None
    in_use: bool = True
    is_dir: bool = False
    mft_ref: int | None = None
    streams: tuple = ()          # 명명 스트림(ADS) 이름 목록


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    return None


def _ts(dt) -> float:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return 0.0


# ══════════════════════════════════════════════════════════════════════
#  백엔드
# ══════════════════════════════════════════════════════════════════════
class Backend:
    """VPath가 호출하는 실제 읽기 구현."""
    label = "backend"
    evidence_root = ""

    def exists(self, rel: str) -> bool: raise NotImplementedError
    def is_dir(self, rel: str) -> bool: raise NotImplementedError
    def read(self, rel: str) -> bytes | None: raise NotImplementedError
    def listdir(self, rel: str) -> list[str]: raise NotImplementedError
    def stat(self, rel: str) -> VStat | None: raise NotImplementedError
    def display(self, rel: str) -> str: return rel




class NtfsBackend(Backend):
    """
    이미지 안의 NTFS 볼륨. 마운트하지 않는다.

    $MFT를 전수 파싱해 경로 색인을 만든 뒤 그 위에서 파일을 읽는다.
    삭제된 엔트리도 색인에 남겨 둔다 — 지워진 대화를 찾는 경로다.
    """
    label = "ntfs"

    def __init__(self, fs, volume_label: str = "", image_name: str = "") -> None:
        self.fs = fs
        self.volume_label = volume_label
        self.image_name = image_name
        self.evidence_root = f"{image_name}::{volume_label or 'NTFS'}"

        self.entries: dict[int, Any] = {}
        self.by_path: dict[str, int] = {}         # 소문자 경로 → ref
        self.children: dict[str, set[str]] = {}   # 소문자 디렉터리 → 자식 이름
        self.deleted: list[tuple[str, Any]] = []
        self._index()

    # ── $MFT 색인 ──────────────────────────────────────────────────────
    def _index(self) -> None:
        from . import _ntfs
        ents: dict[int, Any] = {}
        for ref, rec in self.fs.read_mft():
            try:
                e = _ntfs.NTFS.parse_entry(ref, rec)
            except Exception:
                continue
            if e.base_ref not in (0, ref) and not e.name:
                continue
            ents[ref] = e
        self.entries = ents

        paths: dict[int, str] = {}

        def path_of(ref: int, depth: int = 0) -> str:
            if ref in paths:
                return paths[ref]
            if depth > 64:
                return ""
            e = ents.get(ref)
            if e is None or not e.name:
                paths[ref] = ""
                return ""
            if e.parent == ref or e.parent == 5:
                p = e.name
            else:
                par = path_of(e.parent, depth + 1)
                p = (par + "/" + e.name) if par else e.name
            paths[ref] = p
            return p

        for ref in ents:
            path_of(ref)

        for ref, e in ents.items():
            p = paths.get(ref, "")
            if not p:
                continue
            key = p.lower()
            # 살아 있는 엔트리를 우선 색인한다
            if key not in self.by_path or e.in_use:
                self.by_path[key] = ref
            parent = posixpath.dirname(key)
            self.children.setdefault(parent, set()).add(posixpath.basename(p))
            if not e.in_use:
                self.deleted.append((p, e))

    # ── 조회 ───────────────────────────────────────────────────────────
    @staticmethod
    def _norm(rel: str) -> str:
        return rel.replace("\\", "/").strip("/").lower()

    def _entry(self, rel: str):
        ref = self.by_path.get(self._norm(rel))
        return self.entries.get(ref) if ref is not None else None

    def exists(self, rel: str) -> bool:
        return self._norm(rel) in self.by_path

    def is_dir(self, rel: str) -> bool:
        e = self._entry(rel)
        return bool(e and e.is_dir)

    def listdir(self, rel: str) -> list[str]:
        return sorted(self.children.get(self._norm(rel), set()))

    def read(self, rel: str, stream: str = "") -> bytes | None:
        ref = self.by_path.get(self._norm(rel))
        if ref is None:
            return None
        try:
            rec = self.fs.record_raw(ref)
            if rec is None:
                return None
            attrs = self.fs.full_attrs(ref, rec)
            data = self.fs.read_stream(attrs, stream)
            if data is None:
                data = self.fs.data_of(rec, stream)
            return data
        except Exception:
            return None

    def stat(self, rel: str) -> VStat | None:
        e = self._entry(rel)
        if e is None:
            return None
        cr, mo, mft, ac = e.si
        return VStat(
            size=e.size, st_size=e.size,
            st_mtime=_ts(mo), st_ctime=_ts(cr), st_atime=_ts(ac),
            created_utc=_iso(cr), modified_utc=_iso(mo),
            mft_changed_utc=_iso(mft), accessed_utc=_iso(ac),
            in_use=e.in_use, is_dir=e.is_dir, mft_ref=e.ref,
            streams=tuple(nm for nm, _sz, _res in getattr(e, "streams", ())
                          if nm),
        )

    def display(self, rel: str) -> str:
        return f"{self.evidence_root}/{rel.replace(chr(92), '/')}"

    # ── 삭제 엔트리 ────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════
#  VPath — pathlib처럼 쓰는 읽기 전용 경로
# ══════════════════════════════════════════════════════════════════════
class VPath:
    """
    백엔드 위의 경로 객체.
    저장소 리더가 쓰는 pathlib 기능만 골라 흉내 낸다. **쓰기 메서드는 없다.**
    """

    __slots__ = ("backend", "rel")

    def __init__(self, backend: Backend, rel: str = "") -> None:
        self.backend = backend
        self.rel = rel.replace("\\", "/").strip("/")

    # ── 경로 조작 ──────────────────────────────────────────────────────
    def __truediv__(self, other: str) -> "VPath":
        other = str(other).replace("\\", "/").strip("/")
        return VPath(self.backend, f"{self.rel}/{other}" if self.rel else other)

    def joinpath(self, *parts: str) -> "VPath":
        p = self
        for x in parts:
            p = p / x
        return p

    @property
    def name(self) -> str:
        return posixpath.basename(self.rel)

    @property
    def stem(self) -> str:
        return posixpath.splitext(self.name)[0]

    @property
    def suffix(self) -> str:
        return posixpath.splitext(self.name)[1]

    @property
    def parent(self) -> "VPath":
        return VPath(self.backend, posixpath.dirname(self.rel))

    def __str__(self) -> str:
        return self.backend.display(self.rel)

    def __repr__(self) -> str:
        return f"VPath({self.backend.label}:{self.rel})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VPath) and other.rel.lower() == self.rel.lower()

    def __hash__(self) -> int:
        return hash((self.backend.label, self.rel.lower()))

    def __lt__(self, other: "VPath") -> bool:
        """sorted()로 파일 목록을 정렬할 수 있게 한다."""
        return self.rel.lower() < getattr(other, "rel", "").lower()

    # ── 조회 ───────────────────────────────────────────────────────────
    def exists(self) -> bool:
        return self.backend.exists(self.rel)

    def is_dir(self) -> bool:
        return self.backend.is_dir(self.rel)

    def is_file(self) -> bool:
        return self.exists() and not self.is_dir()

    def read_bytes(self) -> bytes:
        data = self.backend.read(self.rel)
        if data is None:
            raise FileNotFoundError(str(self))
        return data

    def read_stream(self, stream: str) -> bytes | None:
        """ADS 읽기. NTFS 백엔드에서만 의미가 있다."""
        if isinstance(self.backend, NtfsBackend):
            return self.backend.read(self.rel, stream)
        return None

    def stat(self) -> VStat:
        st = self.backend.stat(self.rel)
        if st is None:
            raise FileNotFoundError(str(self))
        return st

    def iterdir(self) -> Iterator["VPath"]:
        for nm in self.backend.listdir(self.rel):
            yield self / nm

    def glob(self, pattern: str) -> Iterator["VPath"]:
        """한 단계 글롭. `**`는 rglob으로 처리한다."""
        if "**" in pattern:
            yield from self.rglob(pattern.replace("**/", "").replace("**", "*"))
            return
        if "/" in pattern:
            head, tail = pattern.split("/", 1)
            for nm in self.backend.listdir(self.rel):
                if fnmatch.fnmatch(nm.lower(), head.lower()):
                    yield from (self / nm).glob(tail)
            return
        for nm in self.backend.listdir(self.rel):
            if fnmatch.fnmatch(nm.lower(), pattern.lower()):
                yield self / nm

    def rglob(self, pattern: str, _depth: int = 0) -> Iterator["VPath"]:
        if _depth > 12:
            return
        for nm in self.backend.listdir(self.rel):
            child = self / nm
            if fnmatch.fnmatch(nm.lower(), pattern.lower()):
                yield child
            if child.is_dir():
                yield from child.rglob(pattern, _depth + 1)

    def match(self, pattern: str) -> bool:
        return fnmatch.fnmatch(self.rel.lower(), pattern.lower().replace("\\", "/"))
