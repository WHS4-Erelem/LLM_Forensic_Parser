"""Chrome Sessions (SNSS) Navigation Reader."""
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
from ..artifacts.history import decode_transition, is_chatgpt_url, redact_url_query
from ..artifacts.local_storage import _profile_subdir
from ..discovery import _join_source_path
from ..models import ArtifactRecord, Coverage
from ..source import FILE_STATUS_EMPTY, FILE_STATUS_NOT_A_FILE, FILE_STATUS_NOT_PRESENT, SourcePathError, normalize_source_path
from ..utils import normalize_timestamp


# ---- Chrome Sessions (SNSS) Navigation Reader ----------------------------------------------------
# 2026-09-19 실제 평문 DD (Users/llmtest/.../Chrome/User Data/Profile 1/Sessions/) 에서 byte 로 확인한 형식:
#   파일 = b"SNSS" + int32 version (관찰값 3) + [uint16 size][uint8 command_id][payload(size-1)] 반복.
#   payload = Chromium Pickle (선두 uint32 payload_size, 문자열 뒤는 4 byte 정렬).
#   UpdateTabNavigation command_id 는 파일 종류마다 다르다: Session_* = 6 (SessionService),
#   Tabs_* = 1 (TabRestoreService). 그 밖의 command 는 navigation 이 아니어서 읽지 않는다.
#   navigation payload 필드 순서 (관찰): int32 tab_id · int32 index · string url · string16 title ·
#     string page_state · uint32 transition · uint32 type_mask · string referrer_url · int32 referrer_policy ·
#     string original_request_url · int32 is_overriding_user_agent · int64 timestamp (webkit µs) ·
#     string16 search_terms · int32 http_status_code.
#   timestamp 는 그 navigation entry 자체의 시각으로 관찰됐고, 파일 이름의 시각 (파일 저장 시각) 과 다르다.
#   tail 필드는 Chrome 버전마다 다를 수 있어 해석에 실패해도 앞부분 (url · title) 은 보존한다.
# Reader 는 ChatGPT host (CHATGPT_HOSTS) navigation 만 Record 로 만들고 행위를 판정하지 않는다.

SESSIONS_DIR_PARTS = ("Sessions",)
SNSS_MAGIC = b"SNSS"
SNSS_HEADER_SIZE = 8
SNSS_OBSERVED_VERSION = 3
# 파일 이름 접두사 → UpdateTabNavigation command id
SNSS_NAVIGATION_COMMANDS = {"session_": 6, "tabs_": 1}
SNSS_FORMAT_NOT_SUPPORTED = "SNSS_FORMAT_NOT_SUPPORTED"
SNSS_VERSION_NOT_VERIFIED = "SNSS_VERSION_NOT_VERIFIED"
SNSS_FILE_KIND_UNKNOWN = "SNSS_FILE_KIND_UNKNOWN"
SNSS_READ_ERROR = "SNSS_READ_ERROR"
SNSS_PATH_OUTSIDE_SOURCE = "SNSS_PATH_OUTSIDE_SOURCE"
SNSS_RECORD_TRUNCATED = "SNSS_RECORD_TRUNCATED"
SNSS_NAVIGATION_UNPARSED = "SNSS_NAVIGATION_UNPARSED"
SNSS_NAVIGATION_TAIL_UNPARSED = "SNSS_NAVIGATION_TAIL_UNPARSED"
SNSS_NAVIGATION_TIMESTAMP_ABSENT = "SNSS_NAVIGATION_TIMESTAMP_ABSENT"


class _Pickle:
    """Chromium Pickle 읽기 (문자열 뒤 4 byte 정렬). 범위를 벗어나면 ValueError."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self._data = data
        self.offset = offset

    def _take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self._data):
            raise ValueError("pickle read out of range")
        chunk = self._data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self._take(8))[0]

    def _aligned(self, byte_length: int) -> bytes:
        chunk = self._take(byte_length)
        self._take(-byte_length % 4)
        return chunk

    def string(self) -> str:
        return self._aligned(self.i32()).decode("utf-8", "replace")

    def string16(self) -> str:
        return self._aligned(2 * self.i32()).decode("utf-16-le", "replace")


def snss_records(data: bytes) -> tuple[list[tuple[int, int, bytes]], list[str]]:
    """SNSS 파일 bytes → ([(offset, command_id, payload)], warnings). 잘린 지점에서 멈추고 앞 record 는 보존한다."""
    if data[:len(SNSS_MAGIC)] != SNSS_MAGIC or len(data) < SNSS_HEADER_SIZE:
        return [], [SNSS_FORMAT_NOT_SUPPORTED]
    version = struct.unpack_from("<i", data, len(SNSS_MAGIC))[0]
    warnings = [] if version == SNSS_OBSERVED_VERSION else [f"{SNSS_VERSION_NOT_VERIFIED}:{version}"]
    out: list[tuple[int, int, bytes]] = []
    pos = SNSS_HEADER_SIZE
    while pos + 2 <= len(data):
        size = struct.unpack_from("<H", data, pos)[0]
        if size == 0 or pos + 2 + size > len(data):
            warnings.append(f"{SNSS_RECORD_TRUNCATED}:{pos}")
            break
        out.append((pos, data[pos + 2], data[pos + 3:pos + 2 + size]))
        pos += 2 + size
    return out, warnings


def parse_snss_navigation(payload: bytes) -> tuple[dict[str, Any], list[str]]:
    """UpdateTabNavigation payload → (관찰 값, warnings). tail 해석에 실패해도 url · title 은 남긴다."""
    outer = _Pickle(payload)
    outer.u32()  # payload_size
    observed: dict[str, Any] = {"tab_id": outer.i32()}
    pickle = _Pickle(payload, outer.offset)
    observed["navigation_index"] = pickle.i32()
    observed["url"] = pickle.string()
    observed["title"] = pickle.string16()
    warnings: list[str] = []
    try:
        pickle.string()  # page_state (직렬화된 페이지 상태 — 보존하지 않는다)
        transition = pickle.u32()
        observed["transition_raw"] = transition
        observed.update(decode_transition(transition))
        pickle.u32()  # type_mask
        observed["referrer_url"] = pickle.string()
        pickle.i32()  # referrer_policy
        observed["original_request_url"] = pickle.string()
        pickle.i32()  # is_overriding_user_agent
        observed["navigation_timestamp_raw"] = pickle.i64()
        pickle.string16()  # search_terms
        observed["http_status_code"] = pickle.i32()
    except (ValueError, struct.error):
        warnings.append(SNSS_NAVIGATION_TAIL_UNPARSED)
    return observed, warnings


def _snss_navigation_record(
    observed: dict[str, Any], record_warnings: list[str], source_path: str, offset: int, command_id: int,
    os_user: str | None, browser_profile: str | None,
) -> ArtifactRecord:
    raw = observed.pop("navigation_timestamp_raw", None)
    timestamp = normalize_timestamp(raw, "webkit_us", "Sessions.UpdateTabNavigation.timestamp")
    warnings = record_warnings + timestamp.pop("warnings")
    if raw is None:
        warnings.append(SNSS_NAVIGATION_TIMESTAMP_ABSENT)
    redacted: list[str] = []
    for name in ("url", "referrer_url", "original_request_url"):
        if name in observed:
            observed[name], keys = redact_url_query(observed[name])
            redacted += [f"{name}.{key}" for key in keys]
    if redacted:
        observed["redacted_query_keys"] = redacted
    observed["snss_command_id"] = command_id
    return ArtifactRecord(
        record_id=f"sessions:{source_path}#{offset}",
        artifact_type="sessions",
        os_user=os_user,
        browser_profile=browser_profile,
        source_path=source_path,
        record_location=f"command={command_id}@{offset}",
        observed=observed,
        warnings=warnings,
        **timestamp,
    )


def snss_navigation_command(file_name: str) -> int | None:
    """파일 이름 → UpdateTabNavigation command id. Session_* / Tabs_* 가 아니면 None."""
    low = file_name.casefold()
    for prefix, command_id in SNSS_NAVIGATION_COMMANDS.items():
        if low.startswith(prefix):
            return command_id
    return None


def read_chrome_session_file(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """
    SNSS 파일 1개 → (ChatGPT navigation Record 목록, Coverage).
      NOT_PRESENT 파일 없음 / EMPTY 0 byte / NOT_SUPPORTED magic 불일치·Session_·Tabs_ 아님 /
      PARSED 정상 / PARTIAL 잘린 record·해석 실패 / PARSE_ERROR 읽기 실패
    """
    source_path = normalize_source_path(path)
    warnings: list[str] = []

    def finish(status: str, records: list[ArtifactRecord] | None = None, sha: str | None = None):
        records = records or []
        return records, Coverage(artifact_type="sessions", os_user=os_user, browser_profile=browser_profile,
                                 source_path=source_path, status=status, record_count=len(records),
                                 source_sha256=sha, warnings=warnings)

    try:
        file_status = source.file_status(source_path)
        if file_status == FILE_STATUS_NOT_PRESENT:
            return finish("NOT_PRESENT")
        if file_status == FILE_STATUS_NOT_A_FILE:
            warnings.append(SNSS_READ_ERROR)
            return finish("PARSE_ERROR")
        if file_status == FILE_STATUS_EMPTY:
            return finish("EMPTY", sha=source.sha256(source_path))
        data = source.read_bytes(source_path)
    except SourcePathError:
        warnings.append(SNSS_PATH_OUTSIDE_SOURCE)
        return finish("PARSE_ERROR")
    except OSError:
        warnings.append(SNSS_READ_ERROR)
        return finish("PARSE_ERROR")

    sha = hashlib.sha256(data).hexdigest()
    command_id = snss_navigation_command(source_path.rpartition("/")[2])
    if command_id is None:
        warnings.append(SNSS_FILE_KIND_UNKNOWN)
        return finish("NOT_SUPPORTED", sha=sha)
    items, problems = snss_records(data)
    warnings.extend(problems)
    if SNSS_FORMAT_NOT_SUPPORTED in problems:
        return finish("NOT_SUPPORTED", sha=sha)

    records: list[ArtifactRecord] = []
    unparsed = 0
    for offset, command, payload in items:
        if command != command_id:
            continue
        try:
            observed, record_warnings = parse_snss_navigation(payload)
        except (ValueError, struct.error):
            unparsed += 1  # record 1건의 실패가 전체 parsing 을 멈추지 않는다
            continue
        if is_chatgpt_url(observed.get("url")):
            records.append(_snss_navigation_record(observed, record_warnings, source_path, offset, command,
                                                   os_user, browser_profile))
    if unparsed:
        warnings.append(f"{SNSS_NAVIGATION_UNPARSED}:{unparsed}")
    damaged = bool(problems) or bool(unparsed) or any(record.warnings for record in records)
    return finish("PARTIAL" if damaged else "PARSED", records, sha)


def read_chrome_sessions(
    source: Source, sessions_path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """Sessions 폴더 → (Record 목록, Coverage 목록). Session_* / Tabs_* 파일마다 Coverage 1건."""
    directory = normalize_source_path(sessions_path)

    def coverage(status: str, notes: list[str]) -> Coverage:
        return Coverage(artifact_type="sessions", os_user=os_user, browser_profile=browser_profile,
                        source_path=directory, status=status, warnings=notes)

    try:
        names = sorted(source.list_dir(directory))
    except (FileNotFoundError, NotADirectoryError):
        return [], [coverage("NOT_PRESENT", [])]
    except SourcePathError:
        return [], [coverage("PARSE_ERROR", [SNSS_PATH_OUTSIDE_SOURCE])]
    except OSError:
        return [], [coverage("PARSE_ERROR", [SNSS_READ_ERROR])]

    targets = [name for name in names if snss_navigation_command(name) is not None]
    if not targets:
        return [], [coverage("EMPTY", [])]
    records: list[ArtifactRecord] = []
    coverages: list[Coverage] = []
    for name in targets:
        file_records, file_coverage = read_chrome_session_file(
            source, _join_source_path(directory, name), os_user=os_user, browser_profile=browser_profile)
        records.extend(file_records)
        coverages.append(file_coverage)
    return records, coverages


def sessions_dir(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'Sessions' 경로."""
    return _profile_subdir(source, profile_path, SESSIONS_DIR_PARTS, warnings)
