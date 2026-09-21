"""Chrome shared_proto_db Download Reader."""
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
from ..artifacts.history import _download_filename, redact_url_query
from ..artifacts.local_storage import _profile_subdir, _read_leveldb_folder, _read_leveldb_log_file
from ..models import ArtifactRecord
from ..utils import normalize_timestamp


# ---- 7.6 Chrome shared_proto_db Download Reader (21_download key 만) ----------
# 2026-09-19 실제 평문 DD (Users/llmtest/.../Chrome/User Data/Profile 1/shared_proto_db/000003.log) 에서 확인한 것:
#   폴더 구성 = 000003.log · CURRENT · LOCK · LOG · LOG.old · MANIFEST-000001 · metadata (.ldb 없음)
#   LevelDB .log 의 key = b"21_download,<guid>" (한 다운로드의 진행 단계마다 PUT 여러 건, DELETE 도 관찰됨)
#   value = protobuf. 아래 field 번호는 이 DD 에서 관찰한 값으로만 해석한다 (Chromium 정의를 옮긴 것이 아니다):
#     1 { 1 guid(str), 4 in_progress_info { 1 url_chain(repeated str), 2 referrer, 4 tab_url, 5 tab_referrer_url,
#          9 last_modified(HTTP 헤더 문자열), 10 total_bytes, 11 mime_type, 12 original_mime_type,
#          13 current_path(.crdownload 포함), 14 target_path — 둘 다 Chromium Pickle (아래 _shared_proto_path),
#          15 received_bytes,
#          16 start_time, 17 end_time } }
#   start_time / end_time 단위 = 1601-01-01 기준 밀리초 (webkit_ms) 로 관찰됨.
#     검증: 같은 다운로드 1건이 History downloads 에도 남아 있어 start_time (History 쪽 webkit_us 값) ·
#     total_bytes · mime_type · target_path · tab_url 이 양쪽에서 일치했다. end_time 미기록은 -1 (0xFFFF…) 이다.
#   의미를 확인하지 못한 field (21, 22, 30, 31, 32 등) 는 해석하지 않고 observed["unmapped_proto_fields"] 에
#     (field 번호 → 값) 그대로 남긴다. 특히 History 의 downloads.state 에 대응하는 field 를 확정하지 못해
#     state 를 만들지 않는다 (완료 여부를 이 Record 로 판정하지 않는다).
# Reader 는 판정하지 않는다. 같은 guid 의 PUT 이 여러 건이면 sequence 가 가장 큰 1건만 Record 로 만들고
#   (앞선 것은 같은 다운로드의 진행 중 상태), DELETE 가 있으면 observed["deleted_in_log"] 로만 남긴다
#   — Chrome 이 다운로드 record 를 지운 사실이며 파일 삭제가 아니다.

SHARED_PROTO_DB_DIR_PARTS = ("shared_proto_db",)
SHARED_PROTO_DB_DOWNLOAD_PREFIX = b"21_download,"
SHARED_PROTO_DB_VALUE_UNPARSED = "SHARED_PROTO_DB_VALUE_UNPARSED"
SHARED_PROTO_DB_DOWNLOAD_INFO_ABSENT = "SHARED_PROTO_DB_DOWNLOAD_INFO_ABSENT"
SHARED_PROTO_DB_TEXT_UNDECODABLE = "SHARED_PROTO_DB_TEXT_UNDECODABLE"
SHARED_PROTO_DB_PATH_UNPARSED = "SHARED_PROTO_DB_PATH_UNPARSED"
_SHARED_PROTO_TEXT_FIELDS = {2: "referrer", 4: "tab_url", 5: "tab_referrer_url", 9: "last_modified",
                             11: "mime_type", 12: "original_mime_type"}
_SHARED_PROTO_PATH_FIELDS = {13: "current_path", 14: "target_path"}
_SHARED_PROTO_INT_FIELDS = {10: "total_bytes", 15: "received_bytes"}
_SHARED_PROTO_URL_FIELDS = (2, 4, 5)
_SHARED_PROTO_TIME_FIELDS = {16: "start_time", 17: "end_time"}
_SHARED_PROTO_SIGNED_MIN = 1 << 63  # 이 값 이상 = 부호 있는 음수 (end_time 미기록 -1 등) → 시각으로 바꾸지 않는다


def _proto_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ValueError("bad varint")
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return result, pos
        shift += 7


def _proto_fields(data: bytes) -> dict[int, list[Any]]:
    """protobuf wire format → {field 번호: [값…]}. varint/fixed 는 int, length-delimited 는 bytes. 깨지면 ValueError."""
    fields: dict[int, list[Any]] = {}
    pos = 0
    while pos < len(data):
        key, pos = _proto_varint(data, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, pos = _proto_varint(data, pos)
        elif wire in (1, 5):
            try:
                value = struct.unpack_from("<Q" if wire == 1 else "<I", data, pos)[0]
            except struct.error as exc:
                raise ValueError("truncated fixed field") from exc
            pos += 8 if wire == 1 else 4
        elif wire == 2:
            length, pos = _proto_varint(data, pos)
            value, pos = data[pos:pos + length], pos + length
            if len(value) != length:
                raise ValueError("truncated length-delimited field")
        else:
            raise ValueError(f"unsupported wire type {wire}")
        fields.setdefault(number, []).append(value)
    return fields


def _proto_one(fields: dict[int, list[Any]], number: int) -> Any:
    """같은 field 가 여러 번 있으면 마지막 값 (protobuf 규칙). 없으면 None."""
    values = fields.get(number)
    return values[-1] if values else None


def _shared_proto_text(raw: Any, encoding: str) -> str | None:
    if not isinstance(raw, bytes):
        return None
    try:
        return raw.decode(encoding)
    except (UnicodeDecodeError, ValueError):
        return None


def _shared_proto_path(raw: Any) -> tuple[str | None, bool]:
    """Chromium Pickle 경로 field → (경로, 구조 정상 여부).

    관찰 구조: uint32 payload_size (뒤따르는 byte 수) + uint32 char_count + UTF-16LE 문자 char_count*2 byte
    + 4 byte 정렬 padding. padding 은 문자열에 포함하지 않는다.
    구조·길이가 맞지 않으면 임의로 복구하지 않고 (None, False) 로 두고 호출부가 warning 을 남긴다.
    """
    if not isinstance(raw, bytes) or len(raw) < 8:
        return None, False
    payload_size, char_count = struct.unpack_from("<II", raw, 0)
    text_end = 8 + char_count * 2
    expected = -(-(4 + char_count * 2) // 4) * 4  # 4 byte 정렬
    if payload_size != len(raw) - 4 or payload_size != expected or text_end > len(raw):
        return None, False
    try:
        return raw[8:text_end].decode("utf-16-le"), True
    except (UnicodeDecodeError, ValueError):
        return None, False


def _shared_proto_download_record(
    value: bytes, guid: str, source_path: str, os_user: str | None, browser_profile: str | None, deleted: bool,
) -> ArtifactRecord:
    """21_download,<guid> 의 마지막 PUT 1건 = Record 1건. 대표 시각은 start_time."""
    record_warnings: list[str] = []
    observed: dict[str, Any] = {"record_kind": "download", "guid": guid, "deleted_in_log": deleted}
    start_raw: Any = None
    try:
        info = _proto_fields(_proto_one(_proto_fields(value), 1) or b"")
    except ValueError:
        info = {}
        record_warnings.append(SHARED_PROTO_DB_VALUE_UNPARSED)
    progress_raw = _proto_one(info, 4)
    progress: dict[int, list[Any]] = {}
    if isinstance(progress_raw, bytes):
        try:
            progress = _proto_fields(progress_raw)
        except ValueError:
            record_warnings.append(SHARED_PROTO_DB_VALUE_UNPARSED)
    elif not record_warnings:
        record_warnings.append(SHARED_PROTO_DB_DOWNLOAD_INFO_ABSENT)

    redacted_keys: list[str] = []

    def safe(url: Any) -> Any:
        clean, keys = redact_url_query(url)
        redacted_keys.extend(keys)
        return clean

    undecodable = 0
    chain: list[dict[str, Any]] = []
    for index, raw in enumerate(progress.get(1) or []):
        url = _shared_proto_text(raw, "utf-8")
        undecodable += url is None
        chain.append({"chain_index": index, "url": safe(url)})
    observed["url_chain"] = chain
    # 실제로 내려받은 URL = chain 의 마지막 항목 (History downloads Record 와 같은 규칙)
    observed["download_url"] = chain[-1]["url"] if chain else None
    for number, name in _SHARED_PROTO_PATH_FIELDS.items():
        raw = _proto_one(progress, number)
        path, ok = _shared_proto_path(raw)
        if raw is not None and not ok:
            record_warnings.append(f"{SHARED_PROTO_DB_PATH_UNPARSED}:{name}")
        observed[name] = path
    observed["filename"] = _download_filename(observed.get("target_path"))
    for number, name in _SHARED_PROTO_TEXT_FIELDS.items():
        raw = _proto_one(progress, number)
        text = _shared_proto_text(raw, "utf-8")
        undecodable += raw is not None and text is None
        observed[name] = safe(text) if number in _SHARED_PROTO_URL_FIELDS else text
    for number, name in _SHARED_PROTO_INT_FIELDS.items():
        observed[name] = _proto_one(progress, number)

    for number, name in _SHARED_PROTO_TIME_FIELDS.items():
        raw = _proto_one(progress, number)
        if not isinstance(raw, int) or raw >= _SHARED_PROTO_SIGNED_MIN:
            # 미기록 (-1) 이거나 값이 없다 → 시각으로 바꾸지 않고 raw 만 남긴다
            if raw is not None:
                observed[f"{name}_raw_unconverted"] = str(raw)
            continue
        if number == 16:
            start_raw = raw
            continue
        end = normalize_timestamp(raw, "webkit_ms", f"shared_proto_db.21_download.{name}")
        record_warnings += end.pop("warnings")
        observed.update({f"end_{key}": item for key, item in end.items()})

    unmapped = {number: values for number, values in progress.items()
                if number != 1 and number not in _SHARED_PROTO_TEXT_FIELDS
                and number not in _SHARED_PROTO_PATH_FIELDS and number not in _SHARED_PROTO_INT_FIELDS
                and number not in _SHARED_PROTO_TIME_FIELDS}
    if unmapped:
        # 의미를 확인하지 못한 field 는 해석하지 않고 그대로 보존한다 (bytes 는 길이만)
        observed["unmapped_proto_fields"] = {
            str(number): [item if isinstance(item, int) else f"<{len(item)} bytes>" for item in values]
            for number, values in sorted(unmapped.items())
        }
    if undecodable:
        record_warnings.append(f"{SHARED_PROTO_DB_TEXT_UNDECODABLE}:{undecodable}")
    if redacted_keys:
        observed["redacted_query_keys"] = sorted(set(redacted_keys))

    timestamp = normalize_timestamp(start_raw, "webkit_ms", "shared_proto_db.21_download.start_time")
    record_warnings += timestamp.pop("warnings")
    return ArtifactRecord(
        record_id=f"shared_proto_db:{source_path}#21_download,{guid}",
        artifact_type="shared_proto_db",
        os_user=os_user,
        browser_profile=browser_profile,
        source_path=source_path,
        record_location=f"21_download,{guid}",
        observed=observed,
        warnings=record_warnings,
        **timestamp,
    )


def _shared_proto_db_records(
    operations: list[LevelDBOperation], source_path: str, os_user: str | None, browser_profile: str | None,
) -> tuple[list[ArtifactRecord], int, list[str]]:
    """21_download key 만. guid 마다 sequence 가 가장 큰 PUT 1건 + 같은 log 안의 DELETE 존재 여부."""
    latest: dict[str, LevelDBOperation] = {}
    deleted: set[str] = set()
    not_allowlisted = 0
    for operation in operations:
        if not operation.key.startswith(SHARED_PROTO_DB_DOWNLOAD_PREFIX):
            not_allowlisted += 1
            continue
        guid = operation.key[len(SHARED_PROTO_DB_DOWNLOAD_PREFIX):].decode("latin-1")
        if operation.operation == "DELETE":
            deleted.add(guid)
            continue
        previous = latest.get(guid)
        if previous is None or operation.sequence >= previous.sequence:
            latest[guid] = operation
    records = [_shared_proto_download_record(operation.value or b"", guid, source_path, os_user, browser_profile,
                                             guid in deleted)
               for guid, operation in latest.items()]
    return records, not_allowlisted, []


def read_shared_proto_db_log(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """shared_proto_db .log 1개 → (21_download Record 목록, Coverage)."""
    return _read_leveldb_log_file(
        source, path, artifact_type="shared_proto_db", prefix="SHARED_PROTO_DB", os_user=os_user,
        browser_profile=browser_profile,
        build_records=lambda operations, source_path: _shared_proto_db_records(operations, source_path, os_user,
                                                                              browser_profile),
    )


def read_shared_proto_db(
    source: Source, leveldb_dir: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """shared_proto_db 폴더 → (Record 목록, Coverage 목록). .log 만 읽고 .ldb 는 NOT_SUPPORTED (_read_leveldb_folder)."""
    return _read_leveldb_folder(source, leveldb_dir, artifact_type="shared_proto_db", prefix="SHARED_PROTO_DB",
                                read_log=read_shared_proto_db_log, os_user=os_user, browser_profile=browser_profile)


def shared_proto_db_dir(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'shared_proto_db' 경로."""
    return _profile_subdir(source, profile_path, SHARED_PROTO_DB_DIR_PARTS, warnings)
