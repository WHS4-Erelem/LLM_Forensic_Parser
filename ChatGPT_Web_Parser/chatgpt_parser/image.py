"""Disk Image 입력 (DD·RAW / E01 → 파티션 → NTFS)."""
from __future__ import annotations
import argparse
import copy
import csv
import gc
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from . import bitlocker
from .source import Source, normalize_source_path


# =============================================================================
# 5. Disk Image Access (DD / RAW)
# =============================================================================
# DD/RAW 이미지 → 파티션 → NTFS → ImageSource(Source). 이후 Discovery·Reader·Rule 은 DirectorySource 와 같은 코드를 쓴다.
#   - Library: pytsk3==20260715 (Apache-2.0 바인딩 + Sleuth Kit, 2026-09-15 사용자 승인. AGPL 정책 미확정으로 dissect 미사용).
#     표준 라이브러리가 아닌 유일한 의존성이라 선택적으로 import 한다 (없으면 --dir 모드는 그대로 동작, --image 는 명확한 오류).
#   - 읽기 전용: pytsk3.Img_Info 는 이미지 파일을 읽기로만 연다. 이미지를 메모리·C: 로 복사하지 않고 필요한 부분만 읽는다.
#   - 파티션: Volume_Info (MBR / GPT 등 TSK 지원 형식). offset = start sector × Volume_Info 의 block_size (512 가정 없음).
#     파티션 표가 없으면 이미지 자체를 파티션으로 보고 offset 0 에서 파일시스템을 시도한다 (NTFS 파티션 이미지).
#   - NTFS 판정: 각 할당 파티션에 FS_Info 를 열어 ftype 이 NTFS 인 것만 후보. 첫 파티션을 NTFS 로 가정하지 않는다.
#     후보 중 Users 폴더가 있는 첫 NTFS 파티션을 고르고, 선택 근거를 run warning 에 남긴다. 한 파티션 실패는 warning 후 계속.
#   - 삭제된(unallocated) 디렉터리 항목은 live 파일 목록에 넣지 않는다. 링크·reparse point 는 따라가지 않는다 (TSK 는 해석하지 않음).
#   - E01/EWF (2026-09-17): pyewf (libewf-python==20240506, LGPLv3+) 로 segment 를 열고 pytsk3.Img_Info 를 상속한
#     Adapter 로 연결한다. 전체를 RAW 로 변환하지 않고 요청한 offset/size 만 읽는다. split segment 는 pyewf.glob 이 모은다.
#     pyewf 가 없는 환경에서는 E01 입력만 E01_INPUT_REQUIRES_PYEWF 오류로 거부하고 DD/RAW 는 그대로 동작한다.
#     주의: pytsk3 의 형식 자동 판별(TSK_IMG_TYPE_DETECT)은 E01 을 RAW 로 잘못 열기 때문에 쓰지 않는다 (2026-09-17 실측).

try:  # 선택 의존성
    import pytsk3  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - 설치 여부에 따라 다름
    pytsk3 = None

try:  # 선택 의존성 — E01/EWF 입력에만 필요 (libewf-python==20240506, LGPLv3+, Python 3.12 환경)
    import pyewf  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - 환경에 따라 다름
    pyewf = None

IMAGE_EWF_EXTENSIONS = (".e01", ".ex01", ".s01")          # pyewf 로 여는 disk image 형식
IMAGE_LOGICAL_EXTENSIONS = (".l01", ".lx01")              # 논리 증거 파일 — disk image 가 아니라 미지원
IMAGE_E01_EXTENSIONS = IMAGE_EWF_EXTENSIONS + IMAGE_LOGICAL_EXTENSIONS
E01_REQUIRES_PYEWF = "E01_INPUT_REQUIRES_PYEWF"
E01_SEGMENTS_UNREADABLE = "E01_SEGMENTS_UNREADABLE"
E01_OPEN_FAILED = "E01_OPEN_FAILED"
IMAGE_EWF_SEGMENTS = "IMAGE_EWF_SEGMENTS"
IMAGE_NO_PARTITION_TABLE = "IMAGE_NO_PARTITION_TABLE"
IMAGE_FILESYSTEM_OPEN_FAILED = "IMAGE_FILESYSTEM_OPEN_FAILED"
IMAGE_PARTITION_NOT_NTFS = "IMAGE_PARTITION_NOT_NTFS"
IMAGE_NTFS_CANDIDATES = "IMAGE_NTFS_CANDIDATES"
IMAGE_PARTITION_SELECTED = "IMAGE_PARTITION_SELECTED"
IMAGE_BITLOCKER_DETECTED = "IMAGE_BITLOCKER_DETECTED"
IMAGE_BITLOCKER_UNLOCKED = "IMAGE_BITLOCKER_UNLOCKED"
IMAGE_BITLOCKER_LOCKED = "IMAGE_BITLOCKER_LOCKED"
_IMAGE_READ_CHUNK = 1024 * 1024


class ImageOpenError(Exception):
    """이미지를 열 수 없거나 분석 가능한 NTFS 파일시스템이 없음."""


@dataclass(kw_only=True)
class ImagePartition:
    """Volume_Info 로 찾은 할당 파티션 (파티션 표가 없으면 index=None 인 이미지 전체)."""

    index: int | None
    description: str
    start_sector: int
    sector_count: int | None
    block_size: int | None
    byte_offset: int

    @property
    def label(self) -> str:
        return "whole-image" if self.index is None else f"partition-{self.index}"

    def describe(self) -> str:
        if self.index is None:
            return f"whole image (no partition table), byte_offset=0"
        return (f"index={self.index} byte_offset={self.byte_offset} start_sector={self.start_sector} "
                f"sector_count={self.sector_count} block_size={self.block_size} ({self.description})")


def _tsk_text(value: Any) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def list_image_partitions(image: Any) -> tuple[list[ImagePartition], list[str]]:
    """할당된 파티션 목록 (Unallocated 영역·파티션 표 자체 제외). 파티션 표가 없으면 ([], [IMAGE_NO_PARTITION_TABLE])."""
    try:
        volume = pytsk3.Volume_Info(image)
    except OSError:
        return [], [IMAGE_NO_PARTITION_TABLE]
    block_size = int(volume.info.block_size)
    partitions = []
    for part in volume:
        if not int(part.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC):
            continue
        partitions.append(ImagePartition(
            index=int(part.addr), description=_tsk_text(part.desc), start_sector=int(part.start),
            sector_count=int(part.len), block_size=block_size, byte_offset=int(part.start) * block_size,
        ))
    return partitions, []


class TskFilesystem:
    """pytsk3.FS_Info 위의 최소 파일 접근. 경로는 normalize_source_path 를 거친 'Users/...' 형태만 받는다."""

    def __init__(self, fs_info: Any) -> None:
        self._fs = fs_info

    def _open(self, path: str) -> Any:
        return self._fs.open("/" + path)

    def stat(self, path: str) -> tuple[str, int, int] | None:
        """(kind: dir / file / other, size, inode) 또는 없으면 None."""
        try:
            meta = self._open(path).info.meta
        except OSError:
            return None
        if meta is None:
            return None
        meta_type = int(meta.type)
        kind = ("dir" if meta_type == int(pytsk3.TSK_FS_META_TYPE_DIR)
                else "file" if meta_type == int(pytsk3.TSK_FS_META_TYPE_REG) else "other")
        return kind, int(meta.size), int(meta.addr)

    def listdir(self, path: str) -> list[str]:
        names: set[str] = set()
        for entry in self._fs.open_dir(path="/" + path):
            name_info = entry.info.name
            if name_info is None or entry.info.meta is None:
                continue
            if int(name_info.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
                continue  # 삭제된 항목은 live 파일로 보지 않는다
            name = _tsk_text(name_info.name)
            if name not in (".", ".."):
                names.add(name)
        return sorted(names)

    def read(self, path: str, offset: int, size: int) -> bytes:
        return self._open(path).read_random(offset, size)


class ImageSource(Source):
    """
    이미지 안에서 선택한 파일시스템을 읽기 전용 Source 로 제공한다 (DirectorySource 와 같은 계약).
    filesystem 은 stat(path) / listdir(path) / read(path, offset, size) 를 제공한다 (실제: TskFilesystem).
    root = 사용자가 준 이미지 경로 (InputInfo.path), partition / filesystem_name = InputInfo 에 기록할 값.
    """

    kind = "dd"

    def __init__(self, filesystem: Any, *, image_path: str | os.PathLike[str], partition: str | None = None,
                 filesystem_name: str | None = "NTFS", warnings: list[str] | None = None, image: Any = None,
                 kind: str = "dd") -> None:
        self.kind = kind  # "dd" (DD/RAW) 또는 "e01" (EWF)
        self.filesystem = filesystem
        self.root = str(image_path)
        self.partition = partition
        self.filesystem_name = filesystem_name
        self.warnings = list(warnings or [])
        self._image = image

    def close(self) -> None:
        """이미지 핸들 해제. pytsk3 는 Img_Info.close() 후에도 관련 객체 참조가 모두 사라져야 파일을 놓는다 (2026-09-15 확인)."""
        if self._image is not None:
            self._image.close()
        self._image = None
        self.filesystem = None
        gc.collect()

    def _stat(self, path: str) -> tuple[str, int, int] | None:
        return self.filesystem.stat(normalize_source_path(path))

    def exists(self, path: str) -> bool:
        return self._stat(path) is not None

    def is_file(self, path: str) -> bool:
        stat = self._stat(path)
        return stat is not None and stat[0] == "file"

    def is_dir(self, path: str) -> bool:
        stat = self._stat(path)
        return stat is not None and stat[0] == "dir"

    def list_dir(self, path: str = "") -> list[str]:
        stat = self._stat(path)
        if stat is None:
            raise FileNotFoundError(f"image directory not found: {path}")
        if stat[0] != "dir":
            raise NotADirectoryError(f"image path is not a directory: {path}")
        return sorted(self.filesystem.listdir(normalize_source_path(path)))

    def _file_size(self, path: str) -> int:
        stat = self._stat(path)
        if stat is None:
            raise FileNotFoundError(f"image file not found: {path}")
        if stat[0] != "file":
            raise IsADirectoryError(f"image path is not a file: {path}")
        return stat[1]

    def size(self, path: str) -> int:
        return self._file_size(path)

    def _chunks(self, path: str) -> Any:
        remaining, offset, relative = self._file_size(path), 0, normalize_source_path(path)
        while remaining > 0:
            chunk = self.filesystem.read(relative, offset, min(_IMAGE_READ_CHUNK, remaining))
            if not chunk:
                raise OSError(f"short read in image file: {path}")
            yield chunk
            offset += len(chunk)
            remaining -= len(chunk)

    def read_bytes(self, path: str) -> bytes:
        return b"".join(self._chunks(path))

    def sha256(self, path: str) -> str:
        digest = hashlib.sha256()
        for chunk in self._chunks(path):
            digest.update(chunk)
        return digest.hexdigest()

    def path_key(self, path: str) -> str:
        # 같은 MFT 레코드(대소문자·짧은 이름 별칭)는 같은 키. 없는 경로는 대소문자 무시 경로.
        stat = self._stat(path)
        return f"inode:{stat[2]}" if stat is not None else normalize_source_path(path).casefold()


_EWF_IMG_INFO_CLASS: Any = None


def _ewf_img_info_class() -> Any:
    """pyewf handle 을 pytsk3 가 읽을 수 있는 Img_Info 로 감싸는 Adapter (pytsk3 가 있을 때만 정의한다)."""
    global _EWF_IMG_INFO_CLASS
    if _EWF_IMG_INFO_CLASS is None:
        class EwfImgInfo(pytsk3.Img_Info):  # type: ignore[misc]
            """E01 을 RAW 로 변환하지 않고, pytsk3 가 요청한 offset/size 만 pyewf 로 읽어 준다."""

            def __init__(self, handle: Any, segments: list[str]) -> None:
                self._handle = handle
                self.segments = list(segments)
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def get_size(self) -> int:
                return self._handle.get_media_size()

            def read(self, offset: int, size: int) -> bytes:
                self._handle.seek(offset)
                return self._handle.read(size)

            def close(self) -> None:
                if self._handle is not None:
                    self._handle.close()
                self._handle = None

        _EWF_IMG_INFO_CLASS = EwfImgInfo
    return _EWF_IMG_INFO_CLASS


def open_ewf_image(image_path: str | os.PathLike[str]) -> tuple[Any, list[str]]:
    """E01/EWF (split segment 포함) → (pytsk3 Img_Info Adapter, warning 목록). 읽기 전용."""
    path = Path(image_path)
    if pyewf is None:
        raise ImageOpenError(f"{E01_REQUIRES_PYEWF}: pyewf (libewf-python) is not installed in this Python environment")
    try:
        segments = list(pyewf.glob(str(path)))  # .E01 → 같은 set 의 .E02, .E03 … 을 모은다
    except Exception as exc:  # pyewf 가 던지는 예외 종류가 환경마다 달라 넓게 받는다
        raise ImageOpenError(f"{E01_SEGMENTS_UNREADABLE}: {exc}") from None
    if not segments:
        raise ImageOpenError(f"{E01_SEGMENTS_UNREADABLE}: no EWF segment found for {path.name}")
    handle = pyewf.handle()
    read_flags = getattr(pyewf, "get_access_flags_read", None)
    try:
        handle.open(segments, read_flags()) if read_flags is not None else handle.open(segments)
    except Exception as exc:  # segment 누락·순서 오류·형식 불일치
        raise ImageOpenError(f"{E01_OPEN_FAILED}: {exc}") from None
    return _ewf_img_info_class()(handle, segments), [f"{IMAGE_EWF_SEGMENTS}:{len(segments)}"]


def open_image_source(image_path: str | os.PathLike[str], key_material: str | None = None) -> ImageSource:
    """DD/RAW 또는 E01/EWF 이미지를 열어 분석할 NTFS 파티션의 ImageSource 를 반환한다. 호출자가 close() 해야 한다.

    BitLocker 볼륨은 팀 공통 방식(chatgpt_parser/bitlocker.py)으로 풀어서 같은 경로로 분석한다.
    키가 없거나 맞지 않으면 그 파티션만 잠김으로 기록하고 다른 파티션을 계속 본다 (우회하지 않는다).
    """
    if pytsk3 is None:
        raise ImageOpenError("pytsk3 is not installed (approved package: pytsk3==20260715)")
    path = Path(image_path)
    suffix = path.suffix.casefold()
    if suffix in IMAGE_LOGICAL_EXTENSIONS:
        raise ImageOpenError(f"logical evidence file ({suffix}) is not a disk image — not supported")
    if not path.is_file():
        raise ImageOpenError(f"image file not found: {path}")
    kind, ewf_warnings = "dd", []
    if suffix in IMAGE_EWF_EXTENSIONS:  # E01 계열은 pytsk3 의 형식 자동 판별에 맡기지 않는다 (RAW 로 잘못 열림)
        image, ewf_warnings = open_ewf_image(path)
        kind = "e01"
    else:
        try:
            image = pytsk3.Img_Info(str(path))
        except OSError as exc:
            raise ImageOpenError(f"cannot open image: {exc}") from None

    partitions, warnings = list_image_partitions(image)
    warnings = ewf_warnings + warnings
    if not partitions:  # 파티션 표 없음 → NTFS 파티션 이미지일 수 있다
        partitions = [ImagePartition(index=None, description="whole image", start_sector=0, sector_count=None,
                                     block_size=None, byte_offset=0)]
    candidates: list[tuple[ImagePartition, TskFilesystem, bool]] = []
    fs_info = None
    unlocked_images: list[Any] = []          # 복호화 볼륨은 ImageSource 가 닫힐 때까지 살아 있어야 한다
    for partition in partitions:
        fs_image, fs_offset = image, partition.byte_offset
        if bitlocker.is_bitlocker(image, partition.byte_offset):
            warnings.append(f"{IMAGE_BITLOCKER_DETECTED}:{partition.label}")
            size = (partition.sector_count or 0) * (partition.block_size or 0)
            try:
                fs_image, method = bitlocker.open_volume(image, partition.byte_offset, size, key_material)
            except bitlocker.VolumeLockedError as exc:      # 키 없음·틀린 키·라이브러리 없음 — 값은 남기지 않는다
                warnings.append(f"{IMAGE_BITLOCKER_LOCKED}:{partition.label}:{exc}")
                continue
            unlocked_images.append(fs_image)
            fs_offset = 0                                   # 복호화 볼륨은 그 자체가 하나의 이미지다
            warnings.append(f"{IMAGE_BITLOCKER_UNLOCKED}:{partition.label}:{method}")
        try:
            fs_info = pytsk3.FS_Info(fs_image, offset=fs_offset)
        except OSError:
            warnings.append(f"{IMAGE_FILESYSTEM_OPEN_FAILED}:{partition.label}")
            continue
        if int(fs_info.info.ftype) != int(pytsk3.TSK_FS_TYPE_NTFS):
            warnings.append(f"{IMAGE_PARTITION_NOT_NTFS}:{partition.label}")
            continue
        filesystem = TskFilesystem(fs_info)
        users = filesystem.stat("Users")
        candidates.append((partition, filesystem, users is not None and users[0] == "dir"))
    if not candidates:
        image.close()
        image = fs_info = None  # 참조를 끊어야 파일 핸들이 풀린다
        gc.collect()
        raise ImageOpenError(f"no NTFS filesystem found in image ({len(partitions)} partition candidate(s) checked)")

    with_users = [candidate for candidate in candidates if candidate[2]]
    partition, filesystem, _ = (with_users or candidates)[0]
    reason = "first NTFS partition with a Users directory" if with_users else "first NTFS partition (no Users directory)"
    warnings += [f"{IMAGE_NTFS_CANDIDATES}:{len(candidates)}", f"{IMAGE_PARTITION_SELECTED}:{partition.label}:{reason}"]
    return ImageSource(filesystem, image_path=path, partition=partition.describe(), warnings=warnings, image=image,
                       kind=kind)
