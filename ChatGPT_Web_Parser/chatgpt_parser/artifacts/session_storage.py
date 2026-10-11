"""Chrome Session Storage Reader."""
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
from ..artifacts.leveldb import LEVELDB_CRC_MISMATCH
from ..artifacts.local_storage import _profile_subdir, _read_leveldb_folder, _read_leveldb_log_file
from ..models import ArtifactRecord
from ..utils import normalize_timestamp


# ---- Chrome Session Storage Reader (LevelDB .log) — Data Export 확인 대기 키만 -------------------------
# 2026-09-15 D: E07-01 원자료 (PRE / POST Chrome\Session Storage\000003.log) 에서 byte 로 확인한 형식:
#   namespace-<namespace id>-<origin> → value = map 번호 (ASCII 숫자)            예: namespace-…-https://chatgpt.com/ = "2"
#   map-<map 번호>-<key 이름>          → value = UTF-16LE 문자열 (Local Storage 와 달리 prefix byte 없음), key 이름은 1 byte 문자
#   DELETE 는 value 없음. 같은 map 번호가 나중에 다른 origin 에 다시 쓰인다 (원자료에서 map-2: www.google.com → chatgpt.com)
#   → .log 를 sequence 순서로 따라가며 namespace PUT / DELETE 로 "map 번호 → origin" 을 갱신하고, map key 의 origin 을 그때 값으로 정한다.
# 2026-09-18 D: 실제 마커 DD (llmtest/Default/Session Storage/000003.log) 에서 확인한 두 번째 허용 키:
#   imagegen_progress:<uuid> → 값 = JSON {"startedAtMs":13자리 Unix ms,"estimatedDurationMs":int,"lastDisplayedPercent":int}
#   같은 key 에 진행률만 바뀐 PUT 이 여러 번 (40 → 50 → 61 → 74) 이어지고 startedAtMs 는 그대로였다. 마지막에 같은 key DELETE.
#   <uuid> 는 History 의 conversation id 와 일치하지 않았다 (대화 상관은 Reader 도 Rule 도 하지 않는다).
# 허용 목록: origin https://chatgpt.com/ 의 chatgpt_export_data_pending_confirm (값 = 13자리 Unix ms, E07-01 확인) 과
#   imagegen_progress:<uuid> 만 Record.
#   그 밖의 chatgpt.com key 는 개수만 (값 비출력). 다른 origin (accounts.google.com sessionPrivateKey, auth.openai.com
#   authapi:client_auth_session_id 등 인증 값) 은 세지도 않는다. namespace id 는 SHA-256 앞 16자리만.
# Reader 는 판정하지 않는다 (DATA_EXPORT_REQUEST 는 Rule 의 역할).

SESSION_STORAGE_DIR_PARTS = ("Session Storage",)
SESSION_STORAGE_ORIGIN = "https://chatgpt.com/"
SESSION_STORAGE_EXPORT_KEY = "chatgpt_export_data_pending_confirm"
SESSION_STORAGE_IMAGEGEN_PREFIX = "imagegen_progress:"
SESSION_STORAGE_LOG_NOT_PRESENT = "SESSION_STORAGE_LOG_NOT_PRESENT"
SESSION_STORAGE_LDB_NOT_SUPPORTED = "SESSION_STORAGE_LDB_NOT_SUPPORTED"
SESSION_STORAGE_PATH_OUTSIDE_SOURCE = "SESSION_STORAGE_PATH_OUTSIDE_SOURCE"
SESSION_STORAGE_READ_ERROR = "SESSION_STORAGE_READ_ERROR"
SESSION_STORAGE_NON_ALLOWLISTED_OPERATIONS = "SESSION_STORAGE_NON_ALLOWLISTED_OPERATIONS"
SESSION_STORAGE_ORIGIN_UNRESOLVED = "SESSION_STORAGE_ORIGIN_UNRESOLVED"
SESSION_STORAGE_UNSUPPORTED_ENCODING = "SESSION_STORAGE_UNSUPPORTED_ENCODING"
SESSION_STORAGE_VALUE_NOT_JSON = "SESSION_STORAGE_VALUE_NOT_JSON"
_SESSION_EXPORT_TIME_SOURCE = "SessionStorage.chatgpt_export_data_pending_confirm.value"
_SESSION_IMAGEGEN_TIME_SOURCE = "SessionStorage.imagegen_progress.startedAtMs"
# imagegen_progress 값에서 남기는 필드 (실제 관찰된 것만. observed 이름 → JSON 이름)
_SESSION_IMAGEGEN_FIELDS = (("started_at_ms", "startedAtMs"), ("estimated_duration_ms", "estimatedDurationMs"),
                            ("last_displayed_percent", "lastDisplayedPercent"))
_SESSION_NAMESPACE_KEY = re.compile(rb"namespace-([^-]+)-(.+)", re.S)
_SESSION_MAP_KEY = re.compile(rb"map-([0-9]+)-(.*)", re.S)


def _session_key_kind(key: bytes) -> str | None:
    """허용 목록 key → key_kind. 그 밖의 key 는 None (Record 를 만들지 않는다)."""
    if key == SESSION_STORAGE_EXPORT_KEY.encode("ascii"):
        return "data_export_pending_confirm"
    if key.startswith(SESSION_STORAGE_IMAGEGEN_PREFIX.encode("ascii")):
        return "imagegen_progress"
    return None


def _session_storage_record(
    operation: LevelDBOperation, origin: str, namespace_id: bytes, map_id: bytes, key: bytes, key_kind: str,
    source_path: str, os_user: str | None, browser_profile: str | None,
) -> ArtifactRecord:
    log_record = operation.record
    observed: dict[str, Any] = {
        "storage_origin": origin, "key": key.decode("utf-8", "replace"), "key_kind": key_kind,
        "operation": operation.operation, "sequence": operation.sequence, "batch_sequence": operation.batch_sequence,
        "operation_index": operation.operation_index, "map_id": map_id.decode("ascii"),
        "namespace_id_sha256_prefix": hashlib.sha256(namespace_id).hexdigest()[:16],
        "log_record_offset": log_record.offset, "log_record_block": log_record.block,
        "value_length": None if operation.value is None else len(operation.value), "value_encoding": None, "value": None,
        "crc32c_verified": log_record.crc32c_verified,
    }
    warnings: list[str] = [] if log_record.crc32c_verified else [LEVELDB_CRC_MISMATCH]
    if key_kind == "imagegen_progress":
        observed["key_suffix"] = key[len(SESSION_STORAGE_IMAGEGEN_PREFIX):].decode("utf-8", "replace")
        observed.update({name: None for name, _ in _SESSION_IMAGEGEN_FIELDS})
    timestamp: dict[str, Any] = {}
    if operation.value is not None:
        try:
            text = operation.value.decode("utf-16-le")
        except UnicodeDecodeError:
            warnings.append(SESSION_STORAGE_UNSUPPORTED_ENCODING)
        else:
            observed["value_encoding"], observed["value"] = "utf-16-le", text
            if key_kind != "imagegen_progress":
                timestamp = normalize_timestamp(text, "unix_ms", _SESSION_EXPORT_TIME_SOURCE)
                warnings += timestamp.pop("warnings")
            else:
                try:
                    parsed = json.loads(text)
                except ValueError:
                    parsed = None
                    warnings.append(SESSION_STORAGE_VALUE_NOT_JSON)
                if isinstance(parsed, dict):
                    for name, field in _SESSION_IMAGEGEN_FIELDS:
                        if field in parsed:
                            observed[name] = parsed[field]
                    if observed["started_at_ms"] is not None:
                        timestamp = normalize_timestamp(observed["started_at_ms"], "unix_ms", _SESSION_IMAGEGEN_TIME_SOURCE)
                        warnings += timestamp.pop("warnings")
    return ArtifactRecord(
        record_id=f"session_storage:{source_path}#offset={log_record.offset},sequence={operation.sequence}",
        artifact_type="session_storage", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
        record_location=(f"offset={log_record.offset} block={log_record.block} "
                         f"sequence={operation.sequence} operation={operation.operation_index}"),
        observed=observed, warnings=warnings, **timestamp,
    )


def _session_storage_records(
    operations: list[LevelDBOperation], source_path: str, os_user: str | None, browser_profile: str | None,
) -> tuple[list[ArtifactRecord], int, list[str]]:
    map_origin: dict[bytes, tuple[str, bytes]] = {}  # map 번호 → (origin, namespace id)
    records: list[ArtifactRecord] = []
    not_allowlisted = unresolved = 0
    for operation in operations:  # 파일 순서 = sequence 순서
        namespace = _SESSION_NAMESPACE_KEY.fullmatch(operation.key)
        if namespace is not None:
            origin = namespace.group(2).decode("latin-1")
            if operation.operation == "PUT" and operation.value and operation.value.isdigit():
                map_origin[operation.value] = (origin, namespace.group(1))
            elif operation.operation == "DELETE":
                for number in [n for n, owner in map_origin.items() if owner == (origin, namespace.group(1))]:
                    del map_origin[number]
            continue
        entry = _SESSION_MAP_KEY.fullmatch(operation.key)
        if entry is None:
            continue
        key_kind = _session_key_kind(entry.group(2))
        owner = map_origin.get(entry.group(1))
        if owner is None:
            unresolved += int(key_kind is not None)  # origin 을 정할 수 없는 허용 목록 키는 Record 로 만들지 않고 개수만
            continue
        if owner[0] != SESSION_STORAGE_ORIGIN:
            continue
        if key_kind is None:
            not_allowlisted += 1
            continue
        records.append(_session_storage_record(operation, owner[0], owner[1], entry.group(1), entry.group(2), key_kind,
                                               source_path, os_user, browser_profile))
    return records, not_allowlisted, [f"{SESSION_STORAGE_ORIGIN_UNRESOLVED}:{unresolved}"] if unresolved else []


def read_session_storage_log(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """Session Storage .log 1개 → (Data Export 확인 대기 키 Record 목록, Coverage)."""
    return _read_leveldb_log_file(
        source, path, artifact_type="session_storage", prefix="SESSION_STORAGE", os_user=os_user,
        browser_profile=browser_profile,
        build_records=lambda operations, source_path: _session_storage_records(operations, source_path, os_user, browser_profile),
    )


def read_session_storage(
    source: Source, leveldb_dir: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """Session Storage 폴더 → (Record 목록, Coverage 목록). .log 만 읽고 .ldb 는 NOT_SUPPORTED (_read_leveldb_folder)."""
    return _read_leveldb_folder(source, leveldb_dir, artifact_type="session_storage", prefix="SESSION_STORAGE",
                                read_log=read_session_storage_log, os_user=os_user, browser_profile=browser_profile)


def session_storage_dir(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'Session Storage' 경로."""
    return _profile_subdir(source, profile_path, SESSION_STORAGE_DIR_PARTS, warnings)
