"""입력 추상화 (읽기 전용 Source / DirectorySource)."""
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


# ---- Source Abstraction --------------------------------------------------------------------------
# 목적: 상위 Reader 가 폴더 입력이든 E01/DD 이미지든 같은 메서드로 파일을 읽게 한다.
#   - Source 는 읽기 기능만 제공한다. write / delete / rename / mkdir / move 는 없다.
#   - 경로는 Source root 기준 상대 경로. '/' 와 '\' 모두 허용. root 밖(.., 절대 경로, 드라이브)은 거부.
#   - 예외 의미 (Reader 가 Coverage 로 변환할 수 있게 구분)
#       SourcePathError (ValueError)            잘못된 경로 요청 — 입력/프로그래밍 오류
#       FileNotFoundError                        Evidence 파일·폴더가 없음 — Coverage NOT_PRESENT 대상
#       IsADirectoryError / NotADirectoryError  파일/폴더 종류가 기대와 다름
#   - Limitation: read_bytes() 는 파일 전체를 메모리에 올린다. 대형 Cache, 큰 SQLite, 이미지 내부 파일은
#     향후 스트리밍 / 제한적 읽기가 필요할 수 있다. (sha256() 은 DirectorySource 에서 청크 단위로 계산)
#   - Limitation: 호스트 파일시스템 설정에 따라 파일을 읽는 것만으로 분석 사본의 LastAccess 가 갱신될 수 있다.
#     파일 내용은 바뀌지 않는다.

FILE_STATUS_NOT_PRESENT = "NOT_PRESENT"
FILE_STATUS_NOT_A_FILE = "NOT_A_FILE"
FILE_STATUS_EMPTY = "EMPTY"
FILE_STATUS_PRESENT = "PRESENT"

_HASH_CHUNK_SIZE = 1024 * 1024


class SourcePathError(ValueError):
    """Source root 밖을 가리키거나 형식이 잘못된 경로."""


def normalize_source_path(path: str) -> str:
    """'Default\\History' → 'Default/History'. root 자체는 ''. root 밖을 가리키면 SourcePathError."""
    if not isinstance(path, str):
        raise TypeError(f"source path must be str, got {type(path).__name__}")
    text = path.replace("\\", "/")
    if "\x00" in text:
        raise SourcePathError("source path contains NUL character")
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
        raise SourcePathError(f"absolute path is not allowed: {path!r}")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise SourcePathError(f"path traversal is not allowed: {path!r}")
    return "/".join(parts)


class Source:
    """읽기 전용 Source 공통 인터페이스. DirectorySource 와 ImageSource 가 같은 메서드를 제공한다."""

    kind = "source"

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def is_file(self, path: str) -> bool:
        raise NotImplementedError

    def is_dir(self, path: str) -> bool:
        raise NotImplementedError

    def list_dir(self, path: str = "") -> list[str]:
        """하위 이름 목록 (항상 이름순 정렬)."""
        raise NotImplementedError

    def size(self, path: str) -> int:
        raise NotImplementedError

    def read_bytes(self, path: str) -> bytes:
        raise NotImplementedError

    def sha256(self, path: str) -> str:
        return hashlib.sha256(self.read_bytes(path)).hexdigest()

    def file_status(self, path: str) -> str:
        """NOT_PRESENT / NOT_A_FILE / EMPTY / PRESENT. 0바이트 파일(EMPTY)과 없는 파일(NOT_PRESENT)을 구분한다."""
        if not self.exists(path):
            return FILE_STATUS_NOT_PRESENT
        if not self.is_file(path):
            return FILE_STATUS_NOT_A_FILE
        return FILE_STATUS_EMPTY if self.size(path) == 0 else FILE_STATUS_PRESENT

    def path_key(self, path: str) -> str:
        """같은 실제 위치인지 비교하기 위한 키 (중복 탐색 방지용). 기본: 대소문자를 무시한 상대 경로."""
        return normalize_source_path(path).casefold()


class DirectorySource(Source):
    """폴더(수동 수집 사본, 마운트 폴더)를 읽기 전용으로 여는 Source."""

    kind = "directory"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        root_path = Path(root)
        if not root_path.exists():
            raise FileNotFoundError(f"source root not found: {root}")
        if not root_path.is_dir():
            raise NotADirectoryError(f"source root is not a directory: {root}")
        self.root = root_path.resolve()

    def _full_path(self, path: str) -> Path:
        relative = normalize_source_path(path)
        full = (self.root / relative).resolve() if relative else self.root
        # 심볼릭 링크·정션을 따라 root 밖으로 나가는 경우도 차단
        if full != self.root and self.root not in full.parents:
            raise SourcePathError(f"path escapes source root: {path!r}")
        return full

    def _existing_file(self, path: str) -> Path:
        full = self._full_path(path)
        if not full.exists():
            raise FileNotFoundError(f"source file not found: {path}")
        if not full.is_file():
            raise IsADirectoryError(f"source path is not a file: {path}")
        return full

    def exists(self, path: str) -> bool:
        return self._full_path(path).exists()

    def is_file(self, path: str) -> bool:
        return self._full_path(path).is_file()

    def is_dir(self, path: str) -> bool:
        return self._full_path(path).is_dir()

    def list_dir(self, path: str = "") -> list[str]:
        full = self._full_path(path)
        if not full.exists():
            raise FileNotFoundError(f"source directory not found: {path}")
        if not full.is_dir():
            raise NotADirectoryError(f"source path is not a directory: {path}")
        return sorted(os.listdir(full))

    def size(self, path: str) -> int:
        return self._existing_file(path).stat().st_size

    def read_bytes(self, path: str) -> bytes:
        with open(self._existing_file(path), "rb") as handle:  # 읽기 모드로만 연다
            return handle.read()

    def sha256(self, path: str) -> str:
        digest = hashlib.sha256()
        with open(self._existing_file(path), "rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def path_key(self, path: str) -> str:
        # 링크·junction 별칭과 대소문자 차이를 실제 경로로 합친다. root 밖이면 SourcePathError.
        return os.path.normcase(str(self._full_path(path)))


# ---- SQLite (메모리) --------------------------------------------------------
# Source 에서 읽은 bytes 를 메모리 DB 로 연다. 원본 파일 경로로 SQLite 를 열지 않으므로
# 원본 옆에 -wal / -shm / -journal 이 생기지 않는다.
#   - 2026-09-14 확인: Python 3.13.3 / SQLite 3.49.1 에서 sqlite3.Connection.deserialize 지원.
#   - 확인된 함정: WAL 모드 DB(헤더 18·19 바이트 = 2)는 그대로 deserialize 하면
#     "unable to open database file" 이 발생한다 → 메모리 사본의 두 바이트만 1(rollback journal)로 바꿔 연다.
#     원본 bytes 는 바꾸지 않는다.
#   - Limitation: 별도 -wal 파일에만 있는 미반영(checkpoint 전) 기록은 포함되지 않는다. 호출자가 warning 처리.
#   - 메모리 DB 는 PRAGMA query_only 로 쓰기를 막는다.

SQLITE_DESERIALIZE_SUPPORTED = hasattr(sqlite3.Connection, "deserialize")
SQLITE_HEADER = b"SQLite format 3\x00"
SQLITE_WAL_HEADER_ADJUSTED = "SQLITE_WAL_HEADER_ADJUSTED"


def open_sqlite_bytes(data: bytes) -> tuple[sqlite3.Connection, list[str]]:
    """
    SQLite DB bytes 를 읽기 전용 메모리 DB 로 연다. (connection, warnings) 반환.
    SQLite 가 아닌 bytes 는 sqlite3.DatabaseError. 호출자가 connection 을 close() 해야 한다.
    """
    if not SQLITE_DESERIALIZE_SUPPORTED:
        raise RuntimeError("sqlite3.Connection.deserialize is not available in this Python build")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    if len(data) < 100 or not data.startswith(SQLITE_HEADER):
        raise sqlite3.DatabaseError("data is not a SQLite 3 database (header mismatch)")

    warnings: list[str] = []
    buffer = bytearray(data)  # 메모리 사본만 수정한다
    if buffer[18] == 2 or buffer[19] == 2:
        buffer[18] = buffer[19] = 1
        warnings.append(SQLITE_WAL_HEADER_ADJUSTED)

    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(bytes(buffer))
        connection.execute("PRAGMA query_only = ON")
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()  # 실제로 열리는지 즉시 확인
    except Exception:
        connection.close()
        raise
    return connection, warnings
