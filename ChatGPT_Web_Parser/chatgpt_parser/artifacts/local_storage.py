"""Chrome Local Storage Reader."""
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
from ..artifacts.leveldb import LEVELDB_CRC_MISMATCH, LEVELDB_TABLE_CRC_MISMATCH, LEVELDB_TABLE_UNSUPPORTED_CODES, parse_leveldb_write_batch, read_leveldb_log, read_leveldb_table
from ..discovery import _child_paths_ci, _join_source_path
from ..models import ArtifactRecord, Coverage
from ..source import FILE_STATUS_EMPTY, FILE_STATUS_NOT_A_FILE, FILE_STATUS_NOT_PRESENT, SourcePathError, normalize_source_path
from ..utils import normalize_timestamp


# ---- 7.3 Chrome Local Storage Reader (LevelDB .log / .ldb) -------------------
# 2026-09-15 C: 분석용 사본 (E01-02 000010.log, POST_CLEANUP 000009.log) 에서 byte 로 확인한 형식:
#   key   = b"_" + origin + b"\x00" + b"\x01" + Latin-1 key 이름   (예: _https://chatgpt.com\x00\x01nextauth.message)
#           그 밖에 META:<origin>, METAACCESS:<origin> (origin 메타데이터 — 읽지 않음)
#   value = prefix 1 byte + 본문. 0x01 → Latin-1, 0x00 → UTF-16LE (conversation-history 값은 0x00 으로 관찰)
# 보안: 허용 목록 key 만 ArtifactRecord 로 만든다. 그 밖의 chatgpt.com key 는 내용 없이 개수만 Coverage warning 에 남긴다.
#   허용 key 의 값도 필요한 필드만 구조화한다. accountSwitchSessions 의 sessionToken·email·phoneNumber·name 은 출력하지 않는다
#   (필드 이름·token 길이만). 계정·scope 식별자는 SHA-256 앞 16자리만 남긴다.
# Reader 는 사용자 행위를 판정하지 않는다 (PROMPT_INPUT·LOGOUT·ACCOUNT_SWITCH·CONVERSATION_DELETE 판정 없음).
# Timestamp: .log record 자체에는 시각이 없다. 값 안의 timestamp 필드(nextauth.message: unix_s, conversation-history: unix_ms)만
#   Record 시각으로 쓰고, 없으면 None. 파일 mtime 을 쓰지 않는다.

LOCAL_STORAGE_ORIGIN = "https://chatgpt.com"
LOCAL_STORAGE_DIR_PARTS = ("Local Storage", "leveldb")
LOCAL_STORAGE_LOG_NOT_PRESENT = "LOCAL_STORAGE_LOG_NOT_PRESENT"
LOCAL_STORAGE_LDB_NOT_SUPPORTED = "LOCAL_STORAGE_LDB_NOT_SUPPORTED"
LOCAL_STORAGE_PATH_OUTSIDE_SOURCE = "LOCAL_STORAGE_PATH_OUTSIDE_SOURCE"
LOCAL_STORAGE_READ_ERROR = "LOCAL_STORAGE_READ_ERROR"
LOCAL_STORAGE_UNSUPPORTED_ENCODING = "LOCAL_STORAGE_UNSUPPORTED_ENCODING"
LOCAL_STORAGE_VALUE_NOT_JSON = "LOCAL_STORAGE_VALUE_NOT_JSON"
LOCAL_STORAGE_UNEXPECTED_STRUCTURE = "LOCAL_STORAGE_UNEXPECTED_STRUCTURE"
LOCAL_STORAGE_NON_ALLOWLISTED_OPERATIONS = "LOCAL_STORAGE_NON_ALLOWLISTED_OPERATIONS"

LOCAL_STORAGE_KEY_KINDS = {
    "nextauth.message": "nextauth_message",
    "oai/apps/accountSwitchSessions": "account_switch_sessions",
    "oai/apps/conversationDrafts": "conversation_drafts",
}
_CONVERSATION_HISTORY_KEY = re.compile(r"cache/([^/]+)/([^/]+)/conversation-history")
_CONVERSATION_HISTORY_KEY_MASKED = "cache/<user>/<scope>/conversation-history"
LOCAL_STORAGE_VALUE_ENCODINGS = {0x00: "utf-16-le", 0x01: "latin-1"}
_CONVERSATION_ITEM_FIELDS = ("id", "title", "create_time", "update_time")


def _sha256_prefix(value: Any) -> str | None:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if isinstance(value, str) else None


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def split_local_storage_key(key: bytes) -> tuple[str, str | None] | None:
    """b'_' + origin + b'\\x00' + 0x01 + Latin-1 이름 → (origin, 이름). 이름 encoding 이 0x01 이 아니면 (origin, None). 그 밖의 key 는 None."""
    if not key.startswith(b"_"):
        return None
    separator = key.find(b"\x00")
    if separator < 0:
        return None
    origin = key[1:separator].decode("latin-1")
    if key[separator + 1:separator + 2] != b"\x01":
        return origin, None
    return origin, key[separator + 2:].decode("latin-1")


def local_storage_key_kind(name: str) -> str | None:
    """허용 목록 key 의 종류. 허용 목록 밖이면 None."""
    if name in LOCAL_STORAGE_KEY_KINDS:
        return LOCAL_STORAGE_KEY_KINDS[name]
    return "conversation_history" if _CONVERSATION_HISTORY_KEY.fullmatch(name) else None


def decode_local_storage_value(value: bytes) -> tuple[str | None, str | None]:
    """(문자열, encoding). 모르는 prefix·깨진 UTF-16 은 문자열을 만들지 않고 None (encoding 은 알면 남김)."""
    encoding = LOCAL_STORAGE_VALUE_ENCODINGS.get(value[0]) if value else None
    if encoding is None:
        return None, None
    try:
        return value[1:].decode(encoding), encoding
    except UnicodeDecodeError:  # 홀수 길이·짝 없는 surrogate
        return None, encoding


def _value_timestamp(obj: dict[str, Any], name: str, timestamp_type: str, source: str) -> dict[str, Any] | None:
    """값 안의 시각 필드. 필드가 없거나 null 이면 None (없는 시각을 만들지 않음)."""
    raw = obj.get(name)
    if raw is None:
        return None
    if timestamp_type != "iso_utc" and (isinstance(raw, bool) or not isinstance(raw, int)):
        raw = str(raw)  # 정수가 아니면 normalize_timestamp 가 TIMESTAMP_INVALID_NUMBER 로 처리
    return normalize_timestamp(raw, timestamp_type, source)


def _structure_nextauth(obj: Any, observed: dict[str, Any], warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
        return None
    data = obj.get("data")
    observed["event"] = _str_or_none(obj.get("event"))
    observed["trigger"] = _str_or_none(data.get("trigger")) if isinstance(data, dict) else None
    return _value_timestamp(obj, "timestamp", "unix_s", "LocalStorage.nextauth.message.timestamp")


def _structure_account_switch_sessions(obj: Any, observed: dict[str, Any], warnings: list[str]) -> None:
    if not isinstance(obj, list):
        warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
        return None
    sessions = []
    for item in obj:
        if not isinstance(item, dict):
            warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
            continue
        token = item.get("sessionToken")
        workspaces = item.get("workspaces")
        sessions.append({
            "field_names": sorted(str(name) for name in item),
            "user_id_sha256_prefix": _sha256_prefix(item.get("userId")),
            # 계정 이름은 원문을 남기지 않고 해시 앞자리로만 비교한다 (§8.21 ACCOUNT_NAME_CHANGE)
            "account_name_sha256_prefix": _sha256_prefix(item.get("name") or item.get("accountName")),
            "session_token_present": isinstance(token, str) and bool(token),
            "session_token_length": len(token) if isinstance(token, str) else None,
            "last_logged_in_at": _value_timestamp(item, "lastLoggedInAt", "unix_ms",
                                                  "LocalStorage.oai/apps/accountSwitchSessions[].lastLoggedInAt"),
            "workspace_count": len(workspaces) if isinstance(workspaces, list) else None,
        })
    observed["session_count"] = len(obj)
    observed["sessions"] = sessions
    return None


def _structure_conversation_drafts(obj: Any, observed: dict[str, Any], warnings: list[str]) -> None:
    drafts = obj.get("drafts") if isinstance(obj, dict) else None
    if not isinstance(drafts, list):
        warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
        return None
    observed["user_id_sha256_prefix"] = _sha256_prefix(obj.get("userId"))
    observed["draft_count"] = len(drafts)
    observed["drafts"] = []
    for item in drafts:
        if not isinstance(item, dict):
            warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
            continue
        observed["drafts"].append({  # 전송 전 입력 흔적 — 대화 메시지로 쓰지 않는다 (PROMPT_INPUT 분석용)
            "draft_id": _str_or_none(item.get("id")),
            "content": _str_or_none(item.get("content")),
            "timestamp": _value_timestamp(item, "timestamp", "unix_ms", "LocalStorage.oai/apps/conversationDrafts.drafts[].timestamp"),
        })
    return None


def _structure_conversation_history(obj: Any, observed: dict[str, Any], warnings: list[str]) -> dict[str, Any] | None:
    value = obj.get("value") if isinstance(obj, dict) else None
    pages = value.get("pages") if isinstance(value, dict) else None
    if not isinstance(pages, list):
        warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
        return None
    items_out = []
    for page_index, page in enumerate(pages):
        items = page.get("items") if isinstance(page, dict) else None
        if not isinstance(items, list):
            warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
            continue
        for item_index, item in enumerate(items):
            if not isinstance(item, dict):
                warnings.append(LOCAL_STORAGE_UNEXPECTED_STRUCTURE)
                continue
            items_out.append({"page_index": page_index, "item_index": item_index,
                              **{name: _str_or_none(item.get(name)) for name in _CONVERSATION_ITEM_FIELDS}})
    observed["page_count"] = len(pages)
    observed["conversation_items"] = items_out
    return _value_timestamp(obj, "timestamp", "unix_ms", "LocalStorage.conversation-history.timestamp")


_LOCAL_STORAGE_STRUCTURERS: dict[str, Callable[[Any, dict[str, Any], list[str]], dict[str, Any] | None]] = {
    "nextauth_message": _structure_nextauth,
    "account_switch_sessions": _structure_account_switch_sessions,
    "conversation_drafts": _structure_conversation_drafts,
    "conversation_history": _structure_conversation_history,
}


def _local_storage_value_fields(
    observed: dict[str, Any], kind: str, value: bytes | None, warnings: list[str],
) -> dict[str, Any] | None:
    """value bytes → observed 구조화 + timestamp dict (.log / .ldb 공통). 값이 없거나 해석할 수 없으면 None."""
    timestamp: dict[str, Any] | None = None
    if value is not None:
        text, observed["value_encoding"] = decode_local_storage_value(value)
        if text is None:
            warnings.append(LOCAL_STORAGE_UNSUPPORTED_ENCODING)
        else:
            try:
                parsed = json.loads(text)
            except (ValueError, RecursionError):
                warnings.append(LOCAL_STORAGE_VALUE_NOT_JSON)
            else:
                timestamp = _LOCAL_STORAGE_STRUCTURERS[kind](parsed, observed, warnings)
    if timestamp is not None:
        warnings += timestamp.pop("warnings")
    return timestamp


def _local_storage_record(
    operation: LevelDBOperation, name: str, kind: str, source_path: str, os_user: str | None, browser_profile: str | None,
) -> ArtifactRecord:
    log_record = operation.record
    observed: dict[str, Any] = {
        "storage_origin": LOCAL_STORAGE_ORIGIN,
        "key": _CONVERSATION_HISTORY_KEY_MASKED if kind == "conversation_history" else name,
        "key_kind": kind,
        "operation": operation.operation,
        "sequence": operation.sequence,
        "batch_sequence": operation.batch_sequence,
        "operation_index": operation.operation_index,
        "log_record_offset": log_record.offset,
        "log_record_block": log_record.block,
        "log_record_fragments": log_record.fragments,
        "key_offset_in_record": operation.key_offset,
        "value_offset_in_record": operation.value_offset,
        "value_length": None if operation.value is None else len(operation.value),
        "value_encoding": None,
        "crc32c_verified": log_record.crc32c_verified,
    }
    if kind == "conversation_history":
        match = _CONVERSATION_HISTORY_KEY.fullmatch(name)
        observed["user_id_sha256_prefix"] = _sha256_prefix(match.group(1))
        observed["cache_scope_sha256_prefix"] = _sha256_prefix(match.group(2))
    warnings: list[str] = [] if log_record.crc32c_verified else [LEVELDB_CRC_MISMATCH]
    timestamp = _local_storage_value_fields(observed, kind, operation.value, warnings)
    return ArtifactRecord(
        record_id=f"local_storage:{source_path}#offset={log_record.offset},sequence={operation.sequence}",
        artifact_type="local_storage", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
        record_location=(f"offset={log_record.offset} block={log_record.block} "
                         f"sequence={operation.sequence} operation={operation.operation_index}"),
        observed=observed, warnings=warnings, **(timestamp or {}),
    )


def _local_storage_table_record(
    entry: LevelDBTableEntry, name: str, kind: str, source_path: str, os_user: str | None, browser_profile: str | None,
) -> ArtifactRecord:
    """SSTable 물리 Record → ArtifactRecord. 같은 key 의 옛 버전도 각각 남기므로 block·entry 위치를 record_id 에 넣는다."""
    observed: dict[str, Any] = {
        "storage_origin": LOCAL_STORAGE_ORIGIN,
        "key": _CONVERSATION_HISTORY_KEY_MASKED if kind == "conversation_history" else name,
        "key_kind": kind,
        "operation": entry.operation,
        "sequence": entry.sequence,
        "table_block_offset": entry.block_offset,
        "table_block_index": entry.block_index,
        "table_entry_index": entry.entry_index,
        "table_block_compression": entry.compression,
        "value_length": None if entry.value is None else len(entry.value),
        "value_encoding": None,
        "crc32c_verified": entry.crc32c_verified,
    }
    if kind == "conversation_history":
        match = _CONVERSATION_HISTORY_KEY.fullmatch(name)
        observed["user_id_sha256_prefix"] = _sha256_prefix(match.group(1))
        observed["cache_scope_sha256_prefix"] = _sha256_prefix(match.group(2))
    warnings: list[str] = [] if entry.crc32c_verified else [LEVELDB_TABLE_CRC_MISMATCH]
    timestamp = _local_storage_value_fields(observed, kind, entry.value, warnings)
    return ArtifactRecord(
        record_id=(f"local_storage:{source_path}#block={entry.block_offset},"
                   f"entry={entry.entry_index},sequence={entry.sequence}"),
        artifact_type="local_storage", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
        record_location=(f"block_offset={entry.block_offset} block={entry.block_index} "
                         f"entry={entry.entry_index} sequence={entry.sequence} operation={entry.operation}"),
        observed=observed, warnings=warnings, **(timestamp or {}),
    )


def _leveldb_log_operations(data: bytes) -> tuple[list[LevelDBOperation], list[str]]:
    """.log bytes → (WriteBatch operation 목록, warning 목록). 파일 순서 = sequence 순서."""
    log_records, problems = read_leveldb_log(data)
    operations: list[LevelDBOperation] = []
    for log_record in log_records:
        batch_operations, batch_problems = parse_leveldb_write_batch(log_record)
        problems += batch_problems
        operations += batch_operations
    return operations, problems


def _read_leveldb_file(
    source: Source, path: str, *, artifact_type: str, prefix: str, os_user: str | None, browser_profile: str | None,
    parse: Callable[[bytes], tuple[list[Any], list[str]]],
    build_records: Callable[[list[Any], str], tuple[list[ArtifactRecord], int, list[str]]],
    unsupported_codes: tuple[str, ...] = (),
) -> tuple[list[ArtifactRecord], Coverage]:
    """
    LevelDB 파일 1개 (.log 또는 .ldb) → parse → build_records → (Record 목록, Coverage).
    Local / Session Storage 공통. build_records 는 (records, 허용 목록 밖 항목 수, 추가 warning) 을 돌려준다.
    warning 코드는 <prefix>_READ_ERROR / _PATH_OUTSIDE_SOURCE / _NON_ALLOWLISTED_OPERATIONS. 손상은 PARTIAL,
    형식 자체가 대상이 아니면 (unsupported_codes) NOT_SUPPORTED.
    """
    source_path = normalize_source_path(path)
    warnings: list[str] = []

    def finish(status: str, records: list[ArtifactRecord] | None = None, sha: str | None = None):
        records = records or []
        return records, Coverage(
            artifact_type=artifact_type, os_user=os_user, browser_profile=browser_profile, source_path=source_path,
            status=status, record_count=len(records), source_sha256=sha, warnings=warnings,
        )

    try:
        file_status = source.file_status(source_path)
        if file_status == FILE_STATUS_NOT_PRESENT:
            return finish("NOT_PRESENT")
        if file_status == FILE_STATUS_NOT_A_FILE:
            warnings.append(f"{prefix}_READ_ERROR")
            return finish("PARSE_ERROR")
        if file_status == FILE_STATUS_EMPTY:
            return finish("EMPTY", sha=source.sha256(source_path))
        data = source.read_bytes(source_path)
    except SourcePathError:
        warnings.append(f"{prefix}_PATH_OUTSIDE_SOURCE")
        return finish("PARSE_ERROR")
    except OSError:
        warnings.append(f"{prefix}_READ_ERROR")
        return finish("PARSE_ERROR")

    items, problems = parse(data)
    records, not_allowlisted, notes = build_records(items, source_path)
    warnings.extend(problems + notes)
    if not_allowlisted:
        warnings.append(f"{prefix}_NON_ALLOWLISTED_OPERATIONS:{not_allowlisted}")
    sha = hashlib.sha256(data).hexdigest()
    if any(problem.split(":")[0] in unsupported_codes for problem in problems):
        return finish("NOT_SUPPORTED", records, sha)  # SSTable 이 아님 (= 미분석)
    damaged = bool(problems or notes) or any(record.warnings for record in records)
    return finish("PARTIAL" if damaged else "PARSED", records, sha)


def _read_leveldb_log_file(
    source: Source, path: str, *, artifact_type: str, prefix: str, os_user: str | None, browser_profile: str | None,
    build_records: Callable[[list[LevelDBOperation], str], tuple[list[ArtifactRecord], int, list[str]]],
) -> tuple[list[ArtifactRecord], Coverage]:
    """LevelDB .log 1개 → WriteBatch operation → build_records → (Record 목록, Coverage)."""
    return _read_leveldb_file(source, path, artifact_type=artifact_type, prefix=prefix, os_user=os_user,
                              browser_profile=browser_profile, parse=_leveldb_log_operations,
                              build_records=build_records)


def _read_leveldb_folder(
    source: Source, leveldb_dir: str, *, artifact_type: str, prefix: str, read_log: Callable[..., Any],
    os_user: str | None, browser_profile: str | None, read_table: Callable[..., Any] | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """
    LevelDB 폴더 → (Record 목록, Coverage 목록). Local / Session Storage 공통.
      - 폴더 없음: NOT_PRESENT 1건
      - *.log 마다 read_log (파일 이름순). *.log 가 없으면 폴더 Coverage NOT_PRESENT + <prefix>_LOG_NOT_PRESENT
      - *.ldb / *.sst: read_table 이 있으면 SSTable 로 읽고, 없으면 파일마다 NOT_SUPPORTED + <prefix>_LDB_NOT_SUPPORTED
        (= 미분석. 그 안의 데이터가 없다는 뜻이 아니다)
    """
    directory = normalize_source_path(leveldb_dir)

    def coverage(path: str, status: str, notes: list[str], sha: str | None = None) -> Coverage:
        return Coverage(artifact_type=artifact_type, os_user=os_user, browser_profile=browser_profile,
                        source_path=path, status=status, source_sha256=sha, warnings=notes)

    try:
        names = source.list_dir(directory)
    except (FileNotFoundError, NotADirectoryError):
        return [], [coverage(directory, "NOT_PRESENT", [])]
    except SourcePathError:
        return [], [coverage(directory, "PARSE_ERROR", [f"{prefix}_PATH_OUTSIDE_SOURCE"])]
    except OSError:
        return [], [coverage(directory, "PARSE_ERROR", [f"{prefix}_READ_ERROR"])]

    records: list[ArtifactRecord] = []
    coverages: list[Coverage] = []
    logs = [name for name in names if name.casefold().endswith(".log")]
    for name in logs:
        log_records, log_coverage = read_log(source, _join_source_path(directory, name),
                                             os_user=os_user, browser_profile=browser_profile)
        records.extend(log_records)
        coverages.append(log_coverage)
    if not logs:
        coverages.append(coverage(directory, "NOT_PRESENT", [f"{prefix}_LOG_NOT_PRESENT"]))
    for name in names:
        if name.casefold().endswith((".ldb", ".sst")):
            path = _join_source_path(directory, name)
            if read_table is not None:
                table_records, table_coverage = read_table(source, path, os_user=os_user, browser_profile=browser_profile)
                records.extend(table_records)
                coverages.append(table_coverage)
                continue
            try:
                sha = source.sha256(path)
            except (OSError, SourcePathError):
                sha = None
            coverages.append(coverage(path, "NOT_SUPPORTED", [f"{prefix}_LDB_NOT_SUPPORTED"], sha))
    return records, coverages


def read_local_storage_log(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """Local Storage .log 1개 → (허용 key 의 ArtifactRecord 목록, Coverage). 손상은 PARTIAL + warning."""

    def build(operations: list[LevelDBOperation], source_path: str) -> tuple[list[ArtifactRecord], int, list[str]]:
        records: list[ArtifactRecord] = []
        not_allowlisted = 0
        for operation in operations:
            parts = split_local_storage_key(operation.key)
            if parts is None or parts[0] != LOCAL_STORAGE_ORIGIN:
                continue  # 다른 origin·META key 는 ChatGPT Artifact 가 아니다
            kind = local_storage_key_kind(parts[1]) if parts[1] is not None else None
            if kind is None:
                not_allowlisted += 1  # 내용은 출력하지 않는다
                continue
            records.append(_local_storage_record(operation, parts[1], kind, source_path, os_user, browser_profile))
        return records, not_allowlisted, []

    return _read_leveldb_log_file(source, path, artifact_type="local_storage", prefix="LOCAL_STORAGE", os_user=os_user,
                                  browser_profile=browser_profile, build_records=build)


def read_local_storage_table(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """Local Storage .ldb (SSTable) 1개 → (허용 key 의 ArtifactRecord 목록, Coverage). 옛 버전·tombstone 도 남긴다."""

    def build(entries: list[LevelDBTableEntry], source_path: str) -> tuple[list[ArtifactRecord], int, list[str]]:
        records: list[ArtifactRecord] = []
        not_allowlisted = 0
        for entry in entries:
            parts = split_local_storage_key(entry.key)
            if parts is None or parts[0] != LOCAL_STORAGE_ORIGIN:
                continue  # 다른 origin·META key 는 ChatGPT Artifact 가 아니다
            kind = local_storage_key_kind(parts[1]) if parts[1] is not None else None
            if kind is None:
                not_allowlisted += 1  # 내용은 출력하지 않는다
                continue
            records.append(_local_storage_table_record(entry, parts[1], kind, source_path, os_user, browser_profile))
        return records, not_allowlisted, []

    return _read_leveldb_file(source, path, artifact_type="local_storage", prefix="LOCAL_STORAGE", os_user=os_user,
                              browser_profile=browser_profile, parse=read_leveldb_table, build_records=build,
                              unsupported_codes=LEVELDB_TABLE_UNSUPPORTED_CODES)


def read_local_storage(
    source: Source, leveldb_dir: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """Local Storage leveldb 폴더 → (ArtifactRecord 목록, Coverage 목록). 규칙은 _read_leveldb_folder."""
    return _read_leveldb_folder(source, leveldb_dir, artifact_type="local_storage", prefix="LOCAL_STORAGE",
                                read_log=read_local_storage_log, os_user=os_user, browser_profile=browser_profile,
                                read_table=read_local_storage_table)


def _profile_subdir(source: Source, profile_path: str, parts: tuple[str, ...], warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 하위 경로 (대소문자 무시로 실제 이름 사용, 없으면 기본 이름)."""
    notes: list[str] = [] if warnings is None else warnings
    current = normalize_source_path(profile_path)
    for part in parts:
        found = _child_paths_ci(source, current, part, notes)
        current = found[0] if found else _join_source_path(current, part)
    return current


def local_storage_dir(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'Local Storage/leveldb' 경로."""
    return _profile_subdir(source, profile_path, LOCAL_STORAGE_DIR_PARTS, warnings)
