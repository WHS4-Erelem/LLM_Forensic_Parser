"""
증거 컨테이너 — 디스크 이미지를 **마운트하지 않고** 바이트 단위로 읽는다.

포렌식의 기본은 원본을 건드리지 않는 것이다.
그래서 파서는 살아 있는 시스템이 아니라 **획득한 이미지**를 입력으로 받는다.

  · 마운트하지 않는다        → 관리자 권한이 필요 없고, OS가 볼륨에 쓰지 않는다
  · 쓰기 모드로 열지 않는다  → 파일 핸들 자체를 'rb'로만 연다
  · 열기 전후로 해시를 잰다  → 분석이 원본을 바꾸지 않았음을 증명한다

지원 형식
  RAW / dd        .dd .raw .img .bin (분할본 .001 .002 … 포함)
  E01 / EWF       pyewf가 설치돼 있을 때만
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import InputError

SPLIT_RE = re.compile(r"^(?P<stem>.+)\.(?P<num>\d{3})$")
RAW_SUFFIXES = {".dd", ".raw", ".img", ".bin", ".001"}


@dataclass
class SourceFile:
    """이미지를 구성하는 실제 파일 1개와 그 해시."""
    path: str
    size: int
    sha256_open: str | None = None      # 분석 시작 전
    sha256_close: str | None = None     # 분석 종료 후
    verified: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "size": self.size,
            "sha256_open": self.sha256_open,
            "sha256_close": self.sha256_close,
            "verified": self.verified,
        }


def sha256_of(path: Path, chunk: int = 4 << 20) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:           # 반드시 읽기 전용
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except OSError:
        return None


class Container:
    """모든 컨테이너의 공통 인터페이스. read(off, n)만 있으면 상위 계층이 돌아간다."""

    kind = "unknown"

    def __init__(self) -> None:
        self.sources: list[SourceFile] = []
        self.size = 0

    def read(self, off: int, n: int) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        pass

    # ── 무결성 ─────────────────────────────────────────────────────────
    def hash_open(self) -> None:
        for s in self.sources:
            s.sha256_open = sha256_of(Path(s.path))

    def hash_close(self) -> None:
        for s in self.sources:
            s.sha256_close = sha256_of(Path(s.path))
            s.verified = (s.sha256_open is not None
                          and s.sha256_open == s.sha256_close)

    @property
    def integrity_ok(self) -> bool | None:
        checked = [s for s in self.sources if s.verified is not None]
        if not checked:
            return None
        return all(s.verified for s in checked)

    def describe(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "size": self.size,
            "files": [s.to_dict() for s in self.sources],
            "integrity_ok": self.integrity_ok,
        }


class RawContainer(Container):
    """dd·raw 이미지. 분할본(.001 .002 …)이면 이어 붙여 하나로 본다."""

    kind = "raw"

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.parts: list[tuple[int, int, Path]] = []   # (시작오프셋, 길이, 경로)
        files = self._collect(path)
        off = 0
        for p in files:
            sz = p.stat().st_size
            self.parts.append((off, sz, p))
            self.sources.append(SourceFile(str(p), sz))
            off += sz
        self.size = off
        self._fh: dict[Path, Any] = {}

    @staticmethod
    def _collect(path: Path) -> list[Path]:
        m = SPLIT_RE.match(path.name)
        if not m:
            return [path]
        stem = m.group("stem")
        found = sorted(
            (p for p in path.parent.iterdir()
             if p.is_file() and SPLIT_RE.match(p.name)
             and SPLIT_RE.match(p.name).group("stem") == stem),
            key=lambda p: SPLIT_RE.match(p.name).group("num"))
        return found or [path]

    def _handle(self, p: Path):
        fh = self._fh.get(p)
        if fh is None:
            fh = p.open("rb")          # 읽기 전용
            self._fh[p] = fh
        return fh

    def read(self, off: int, n: int) -> bytes:
        out = bytearray()
        remaining = n
        pos = off
        for start, length, p in self.parts:
            if remaining <= 0:
                break
            if pos >= start + length:
                continue
            local = pos - start
            if local < 0:
                break
            take = min(remaining, length - local)
            fh = self._handle(p)
            fh.seek(local)
            chunk = fh.read(take)
            if len(chunk) < take:                 # 불량 섹터 등 — 0으로 메우고 계속
                chunk = chunk + b"\x00" * (take - len(chunk))
            out += chunk
            pos += take
            remaining -= take
        if remaining > 0:
            out += b"\x00" * remaining
        return bytes(out)

    def close(self) -> None:
        for fh in self._fh.values():
            try:
                fh.close()
            except OSError:
                pass
        self._fh.clear()


class EwfContainer(Container):
    """E01. pyewf가 있을 때만 쓴다."""

    kind = "ewf"

    def __init__(self, path: Path) -> None:
        super().__init__()
        try:
            import pyewf
        except ImportError as exc:
            raise InputError(
                "E01 이미지를 읽으려면 pyewf가 필요하다. "
                "설치가 어려우면 RAW(dd)로 변환해서 넣을 것") from exc
        try:
            names = pyewf.glob(str(path))
        except Exception as exc:                  # 분할 세그먼트 이름이 깨진 경우
            raise InputError(
                f"E01 세그먼트를 찾지 못했다: {path.name} "
                f"(분할본이면 .E01 .E02 … 를 같은 폴더에 두어야 한다) [{exc}]") from exc
        self._h = pyewf.handle()
        try:
            self._h.open(names)
            self.size = self._h.get_media_size()
        except Exception as exc:                  # 서명 불일치 · 잘린 파일 · 손상
            raise InputError(
                f"E01 이미지를 열지 못했다: {path.name} — "
                f"EnCase 형식이 아니거나 파일이 손상됐다 [{exc}]") from exc
        for nm in names:
            p = Path(nm)
            try:
                self.sources.append(SourceFile(str(p), p.stat().st_size))
            except OSError:
                self.sources.append(SourceFile(str(p), 0))

    def read(self, off: int, n: int) -> bytes:
        self._h.seek(off)
        return self._h.read(n)

    def close(self) -> None:
        try:
            self._h.close()
        except Exception:
            pass


def open_container(path: Path) -> Container:
    """확장자와 매직으로 컨테이너 종류를 판별한다."""
    path = Path(path)
    if not path.exists():
        raise InputError(f"이미지 파일이 없다: {path}")
    if path.is_dir():
        raise InputError(f"이미지 파일을 지정해야 한다(폴더가 아님): {path}")

    suf = path.suffix.lower()
    if suf in (".e01", ".ex01", ".s01"):
        return EwfContainer(path)
    if suf in RAW_SUFFIXES or SPLIT_RE.match(path.name):
        return RawContainer(path)

    # 확장자가 낯설면 매직으로 한 번 더 본다
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except OSError as exc:
        raise InputError(f"이미지를 열지 못했다: {path} ({exc})") from exc
    if head[:3] == b"EVF" or head[1:4] == b"EVF":
        return EwfContainer(path)
    return RawContainer(path)
