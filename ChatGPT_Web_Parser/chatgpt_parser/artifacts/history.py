"""Chrome History Reader (urls / visits / downloads)."""
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
from ..discovery import HISTORY_PATH_OUTSIDE_SOURCE
from ..models import ArtifactRecord, Coverage
from ..source import FILE_STATUS_EMPTY, FILE_STATUS_NOT_A_FILE, FILE_STATUS_NOT_PRESENT, SourcePathError, normalize_source_path, open_sqlite_bytes
from ..utils import normalize_timestamp


# ---- Artifact Readers ----------------------------------------------------------------------------
# Reader 는 Source 에서 bytes 를 읽어 ArtifactRecord(관찰 사실)와 Coverage 를 만든다.
# 사용자 행위 판정(Event)은 하지 않는다 — detectors/ 의 Rule 이 할 일이다.

# ---- Chrome History ------------------------------------------------------------------------------
#   - 원본 경로로 sqlite3.connect 하지 않는다: Source.read_bytes → open_sqlite_bytes (메모리, query_only).
#   - Visit 1건 = ArtifactRecord 1건. 시각은 urls.last_visit_time 이 아니라 visits.visit_time (webkit_us).
#   - Chrome 버전별 Schema 차이: 필수 테이블·컬럼이 없으면 PARSE_ERROR, 선택 컬럼은 있을 때만 읽는다.
#   - Reader(read_history) 와 ChatGPT URL Filter(is_chatgpt_url) 를 분리한다.
#   - Limitation: History-wal 에만 있는(checkpoint 전) 기록은 반영하지 않는다 → HISTORY_WAL_PRESENT_UNMERGED.
#     History-journal(hot journal) 롤백도 적용하지 않는다.
#   - 보안: URL 의 인증 관련 query 값(code, state 등)은 출력하지 않고 키 이름만 남긴다.

# 수동 분석에서 실제 관찰된 ChatGPT Web 관련 host (정확히 일치하는 host 만 인정)
CHATGPT_HOSTS = frozenset({"chatgpt.com", "auth.openai.com"})

HISTORY_REQUIRED_COLUMNS = {
    "urls": ("id", "url", "title"),
    "visits": ("id", "url", "visit_time", "from_visit", "transition"),
}
HISTORY_OPTIONAL_VISIT_COLUMNS = ("originator_cache_guid", "is_known_to_sync")

# Coverage / Record warning 코드 (':' 뒤에 대상 이름이 붙을 수 있다)
HISTORY_WAL_PRESENT_UNMERGED = "HISTORY_WAL_PRESENT_UNMERGED"
HISTORY_NOT_A_FILE = "HISTORY_NOT_A_FILE"
HISTORY_EMPTY_FILE = "HISTORY_EMPTY_FILE"
HISTORY_READ_ERROR = "HISTORY_READ_ERROR"
HISTORY_NOT_SQLITE = "HISTORY_NOT_SQLITE"
HISTORY_SQLITE_UNSUPPORTED = "HISTORY_SQLITE_UNSUPPORTED"
HISTORY_MISSING_TABLE = "HISTORY_MISSING_TABLE"
HISTORY_MISSING_COLUMN = "HISTORY_MISSING_COLUMN"
HISTORY_OPTIONAL_COLUMN_ABSENT = "HISTORY_OPTIONAL_COLUMN_ABSENT"
HISTORY_QUERY_ERROR = "HISTORY_QUERY_ERROR"
HISTORY_ROW_SKIPPED = "HISTORY_ROW_SKIPPED"
HISTORY_URL_ROW_MISSING = "HISTORY_URL_ROW_MISSING"

# login_hint (계정 이메일)·auth_session_logging_id (인증 세션 id) 는 2026-09-15 D: E07-01 History 의 인증 흐름 URL 에서 확인되어 추가
# sig 는 2026-09-18 Marker E01 의 chatgpt.com/backend-api/estuary/content 다운로드 URL 에서 확인된 서명 값 (token/signature/auth 도 같이 가린다)
REDACTED_QUERY_KEYS = frozenset({"code", "state", "access_token", "id_token", "refresh_token",
                                 "login_hint", "auth_session_logging_id",
                                 "sig", "signature", "token", "auth", "authorization"})

# Chromium ui::PageTransition
TRANSITION_CORE_TYPES = {
    0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME", 4: "MANUAL_SUBFRAME", 5: "GENERATED",
    6: "AUTO_TOPLEVEL", 7: "FORM_SUBMIT", 8: "RELOAD", 9: "KEYWORD", 10: "KEYWORD_GENERATED",
}
TRANSITION_QUALIFIERS = (
    (0x00800000, "BLOCKED"), (0x01000000, "FORWARD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"),
    (0x04000000, "HOME_PAGE"), (0x08000000, "FROM_API"), (0x10000000, "CHAIN_START"),
    (0x20000000, "CHAIN_END"), (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT"),
)

# ---- Chrome History downloads --------------------------------------------------------------------
# 2026-09-18 실제 Marker E01 (Chrome Stable, llmtest/Default) History 에서 확인한 Schema:
#   downloads(id, guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type,
#             interrupt_reason, hash, end_time, opened, last_access_time, transient, referrer, site_url,
#             embedder_download_data, tab_url, tab_referrer_url, http_method, by_ext_id, by_ext_name,
#             by_web_app_id, etag, last_modified, mime_type, original_mime_type)
#   downloads_url_chains(id, chain_index, url)  — 한 download 에 여러 행, chain_index 순서를 보존한다
#   start_time / end_time / last_access_time 은 visits.visit_time 과 같은 webkit_us (end_time 0 = 기록 없음)
# Chrome 버전마다 컬럼이 다를 수 있어 필수 3개만 요구하고 나머지는 있을 때만 읽는다.
# Reader 는 download 를 사용자 행위로 판정하지 않는다 (ChatGPT 판정은 CHATGPT_FILE_DOWNLOAD_001 Rule 의 역할).

HISTORY_DOWNLOAD_REQUIRED_COLUMNS = ("id", "target_path", "start_time")
HISTORY_DOWNLOAD_OPTIONAL_COLUMNS = (
    "guid", "current_path", "end_time", "received_bytes", "total_bytes", "state", "danger_type",
    "interrupt_reason", "opened", "last_access_time", "transient", "referrer", "site_url",
    "tab_url", "tab_referrer_url", "http_method", "mime_type", "original_mime_type",
    "by_ext_id", "by_ext_name", "etag", "last_modified",
)
HISTORY_DOWNLOAD_URL_COLUMNS = ("tab_url", "tab_referrer_url", "referrer", "site_url")
HISTORY_DOWNLOADS_TABLE_ABSENT = "HISTORY_DOWNLOADS_TABLE_ABSENT"
HISTORY_DOWNLOADS_COLUMN_ABSENT = "HISTORY_DOWNLOADS_COLUMN_ABSENT"
HISTORY_DOWNLOADS_SCHEMA_UNSUPPORTED = "HISTORY_DOWNLOADS_SCHEMA_UNSUPPORTED"
HISTORY_DOWNLOAD_URL_CHAINS_ABSENT = "HISTORY_DOWNLOAD_URL_CHAINS_ABSENT"
HISTORY_DOWNLOAD_ROW_SKIPPED = "HISTORY_DOWNLOAD_ROW_SKIPPED"


def is_chatgpt_url(url: Any) -> bool:
    """http(s) URL 의 host 가 CHATGPT_HOSTS 와 정확히 일치하면 True. (notchatgpt.com, chatgpt.com.evil.x 는 False)"""
    if not isinstance(url, str) or not url:
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname  # 소문자로 정규화됨
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host:
        return False
    return host.rstrip(".") in CHATGPT_HOSTS


def redact_url_query(url: Any) -> tuple[Any, list[str]]:
    """인증 관련 query 값을 'REDACTED' 로 바꾼다. (url, 가린 키 목록) 반환. 가릴 것이 없으면 원문 그대로."""
    if not isinstance(url, str) or "?" not in url:
        return url, []
    try:
        parts = urlsplit(url)
    except ValueError:
        return url, []
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted = sorted({key for key, _ in pairs if key.lower() in REDACTED_QUERY_KEYS})
    if not redacted:
        return url, []
    query = urlencode([(key, "REDACTED" if key.lower() in REDACTED_QUERY_KEYS else value) for key, value in pairs])
    return urlunsplit(parts._replace(query=query)), redacted


def decode_transition(value: Any) -> dict[str, Any]:
    """visits.transition 해석. 원본 정수는 호출자가 transition_raw 로 따로 보존한다."""
    if isinstance(value, bool) or not isinstance(value, int):
        return {"transition_hex": None, "transition_core": None, "transition_qualifiers": []}
    bits = value & 0xFFFFFFFF  # Chrome 이 signed 32bit 로 저장해 음수가 나올 수 있다
    core = bits & 0xFF
    return {
        "transition_hex": f"0x{bits:08X}",
        "transition_core": TRANSITION_CORE_TYPES.get(core, f"UNKNOWN_{core}"),
        "transition_qualifiers": [name for mask, name in TRANSITION_QUALIFIERS if bits & mask],
    }


def _sqlite_table_columns(connection: sqlite3.Connection, table: str) -> set[str] | None:
    """테이블이 없으면 None, 있으면 컬럼 이름 집합."""
    found = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if found is None:
        return None
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def read_history(
    source: Source,
    path: str = "History",
    *,
    os_user: str | None = None,
    browser_profile: str | None = None,
    url_filter: Callable[[Any], bool] | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """
    Chrome History DB 를 읽어 (visit 단위 ArtifactRecord 목록, Coverage) 를 반환한다.
    url_filter 가 있으면 True 인 URL 의 visit 만 Record 로 만든다 (record_count 도 필터 후 개수).
    Evidence 쪽 문제(없음·손상·Schema 차이)는 예외 대신 Coverage 상태와 warning 으로 돌려준다.
    """
    source_path = normalize_source_path(path)
    warnings: list[str] = []

    def finish(status: str, records: list[ArtifactRecord] | None = None, sha: str | None = None):
        records = records or []
        coverage = Coverage(
            artifact_type="history", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
            status=status, record_count=len(records), source_sha256=sha, warnings=warnings,
        )
        return records, coverage

    try:
        file_status = source.file_status(source_path)
        wal_present = file_status != FILE_STATUS_NOT_PRESENT and source.exists(source_path + "-wal")
    except SourcePathError:  # 링크·junction 이 Source 밖을 가리킴 — 따라가지 않는다
        warnings.append(HISTORY_PATH_OUTSIDE_SOURCE)
        return finish("PARSE_ERROR")
    if file_status == FILE_STATUS_NOT_PRESENT:
        return finish("NOT_PRESENT")
    if file_status == FILE_STATUS_NOT_A_FILE:
        warnings.append(HISTORY_NOT_A_FILE)
        return finish("PARSE_ERROR")
    if wal_present:
        warnings.append(HISTORY_WAL_PRESENT_UNMERGED)
    if file_status == FILE_STATUS_EMPTY:
        warnings.append(HISTORY_EMPTY_FILE)
        return finish("EMPTY", sha=source.sha256(source_path))

    try:
        data = source.read_bytes(source_path)
    except OSError:
        warnings.append(HISTORY_READ_ERROR)
        return finish("PARSE_ERROR")
    sha = hashlib.sha256(data).hexdigest()

    try:
        connection, sqlite_warnings = open_sqlite_bytes(data)
    except sqlite3.DatabaseError:
        warnings.append(HISTORY_NOT_SQLITE)
        return finish("PARSE_ERROR", sha=sha)
    except RuntimeError:
        warnings.append(HISTORY_SQLITE_UNSUPPORTED)
        return finish("PARSE_ERROR", sha=sha)
    warnings.extend(sqlite_warnings)

    try:
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")  # 깨진 UTF-8 한 건 때문에 전체 실패 방지

        # Schema 확인
        schema_problems: list[str] = []
        visit_columns: set[str] = set()
        for table, required in HISTORY_REQUIRED_COLUMNS.items():
            columns = _sqlite_table_columns(connection, table)
            if columns is None:
                schema_problems.append(f"{HISTORY_MISSING_TABLE}:{table}")
                continue
            schema_problems += [f"{HISTORY_MISSING_COLUMN}:{table}.{name}" for name in required if name not in columns]
            if table == "visits":
                visit_columns = columns
        if schema_problems:
            warnings.extend(schema_problems)
            return finish("PARSE_ERROR", sha=sha)

        optional_present = [name for name in HISTORY_OPTIONAL_VISIT_COLUMNS if name in visit_columns]
        warnings += [f"{HISTORY_OPTIONAL_COLUMN_ABSENT}:visits.{name}"
                     for name in HISTORY_OPTIONAL_VISIT_COLUMNS if name not in visit_columns]

        select = ["v.id", "v.url", "u.id", "u.url", "u.title", "v.visit_time", "v.from_visit", "v.transition"]
        select += [f"v.{name}" for name in optional_present]
        query = (f"SELECT {', '.join(select)} FROM visits AS v "
                 "LEFT JOIN urls AS u ON u.id = v.url ORDER BY v.visit_time, v.id")

        records: list[ArtifactRecord] = []
        skipped = 0
        for row in connection.execute(query):
            visit_id, visit_url_id, url_row_id, url, title, visit_time, from_visit, transition = row[:8]
            if url_filter is not None and not url_filter(url):
                continue
            optional_values = dict(zip(optional_present, row[8:]))
            try:
                records.append(_history_visit_record(
                    source_path, os_user, browser_profile, visit_id, visit_url_id, url_row_id,
                    url, title, visit_time, from_visit, transition, optional_values,
                ))
            except (TypeError, ValueError):
                skipped += 1
                warnings.append(f"{HISTORY_ROW_SKIPPED}:visits.id={visit_id}")

        download_records, skipped_downloads = _read_history_downloads(
            connection, source_path, os_user, browser_profile, url_filter, warnings)
        records += download_records
        skipped += skipped_downloads
    except sqlite3.DatabaseError:
        warnings.append(HISTORY_QUERY_ERROR)
        return finish("PARSE_ERROR", sha=sha)
    finally:
        connection.close()

    return finish("PARTIAL" if skipped else "PARSED", records, sha)


def read_chatgpt_history(source: Source, path: str = "History", **kwargs: Any) -> tuple[list[ArtifactRecord], Coverage]:
    """read_history + ChatGPT 관련 host 필터."""
    return read_history(source, path, url_filter=is_chatgpt_url, **kwargs)


def _history_visit_record(
    source_path: str, os_user: str | None, browser_profile: str | None,
    visit_id: Any, visit_url_id: Any, url_row_id: Any, url: Any, title: Any,
    visit_time: Any, from_visit: Any, transition: Any, optional_values: dict[str, Any],
) -> ArtifactRecord:
    timestamp = normalize_timestamp(visit_time, "webkit_us", "History.visits.visit_time")
    record_warnings = timestamp.pop("warnings")
    safe_url, redacted_keys = redact_url_query(url)

    observed: dict[str, Any] = {
        "visit_id": visit_id,
        "url_id": visit_url_id,
        "url": safe_url,
        "title": title,
        "from_visit": from_visit,
        "transition_raw": transition,
        **decode_transition(transition),
    }
    # 선택 컬럼: 컬럼이 없으면 None (컬럼이 있고 값이 빈 문자열인 경우와 구분됨)
    for name in HISTORY_OPTIONAL_VISIT_COLUMNS:
        observed[name] = optional_values.get(name)
    if redacted_keys:
        observed["redacted_query_keys"] = redacted_keys
    if url_row_id is None:
        record_warnings.append(HISTORY_URL_ROW_MISSING)

    return ArtifactRecord(
        record_id=f"history:{source_path}#visits.id={visit_id}",
        artifact_type="history",
        os_user=os_user,
        browser_profile=browser_profile,
        source_path=source_path,
        record_location=f"visits.id={visit_id}",
        observed=observed,
        warnings=record_warnings,
        **timestamp,
    )


def _read_history_downloads(
    connection: sqlite3.Connection, source_path: str, os_user: str | None, browser_profile: str | None,
    url_filter: Callable[[Any], bool] | None, warnings: list[str],
) -> tuple[list[ArtifactRecord], int]:
    """downloads / downloads_url_chains → download 단위 ArtifactRecord. 테이블·컬럼이 없으면 warning 만 남기고 빈 목록."""
    columns = _sqlite_table_columns(connection, "downloads")
    if columns is None:
        warnings.append(HISTORY_DOWNLOADS_TABLE_ABSENT)
        return [], 0
    missing = [name for name in HISTORY_DOWNLOAD_REQUIRED_COLUMNS if name not in columns]
    if missing:
        warnings += [f"{HISTORY_DOWNLOADS_COLUMN_ABSENT}:downloads.{name}" for name in missing]
        warnings.append(HISTORY_DOWNLOADS_SCHEMA_UNSUPPORTED)
        return [], 0
    present = [name for name in HISTORY_DOWNLOAD_OPTIONAL_COLUMNS if name in columns]
    warnings += [f"{HISTORY_DOWNLOADS_COLUMN_ABSENT}:downloads.{name}"
                 for name in HISTORY_DOWNLOAD_OPTIONAL_COLUMNS if name not in columns]

    # URL chain (chain_index 순서 보존). 테이블이 없으면 chain 없이 download 만 남긴다.
    chains: dict[Any, list[tuple[Any, Any]]] = {}
    chain_columns = _sqlite_table_columns(connection, "downloads_url_chains")
    if chain_columns is None or not {"id", "chain_index", "url"} <= chain_columns:
        warnings.append(HISTORY_DOWNLOAD_URL_CHAINS_ABSENT)
    else:
        for download_id, chain_index, url in connection.execute(
                "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains.setdefault(download_id, []).append((chain_index, url))

    select = list(HISTORY_DOWNLOAD_REQUIRED_COLUMNS) + present
    records: list[ArtifactRecord] = []
    skipped = 0
    for row in connection.execute(f"SELECT {', '.join(select)} FROM downloads ORDER BY start_time, id"):
        values = dict(zip(select, row))
        download_id = values["id"]
        chain = chains.get(download_id, [])
        if url_filter is not None and not any(
                url_filter(url) for url in [u for _, u in chain] + [values.get(name) for name in HISTORY_DOWNLOAD_URL_COLUMNS]):
            continue
        try:
            records.append(_history_download_record(source_path, os_user, browser_profile, values, chain))
        except (TypeError, ValueError):
            skipped += 1
            warnings.append(f"{HISTORY_DOWNLOAD_ROW_SKIPPED}:downloads.id={download_id}")
    return records, skipped


def _history_download_record(
    source_path: str, os_user: str | None, browser_profile: str | None,
    values: dict[str, Any], chain: list[tuple[Any, Any]],
) -> ArtifactRecord:
    """download 1건 = Record 1건. 대표 시각은 start_time (다운로드 시작), end_time 은 observed 로 보존한다."""
    download_id = values["id"]
    timestamp = normalize_timestamp(values.get("start_time"), "webkit_us", "History.downloads.start_time")
    record_warnings = timestamp.pop("warnings")

    redacted_keys: list[str] = []

    def safe(url: Any) -> Any:
        clean, keys = redact_url_query(url)
        redacted_keys.extend(keys)
        return clean

    target_path = values.get("target_path")
    url_chain = [{"chain_index": index, "url": safe(url)} for index, url in chain]
    observed: dict[str, Any] = {
        "record_kind": "download",
        "download_id": download_id,
        "target_path": target_path,
        "filename": _download_filename(target_path),
        "url_chain": url_chain,
        # 실제로 내려받은 URL = chain 의 마지막 항목 (redirect 이 있으면 최종 URL)
        "download_url": url_chain[-1]["url"] if url_chain else None,
    }
    for name in HISTORY_DOWNLOAD_OPTIONAL_COLUMNS:
        value = values.get(name)
        observed[name] = safe(value) if name in HISTORY_DOWNLOAD_URL_COLUMNS else value

    # end_time 0 = Chrome 이 종료 시각을 기록하지 않은 상태. 변환하지 않고 raw 만 남긴다.
    end_time = values.get("end_time")
    if isinstance(end_time, int) and end_time > 0:
        end = normalize_timestamp(end_time, "webkit_us", "History.downloads.end_time")
        record_warnings += end.pop("warnings")
        observed.update({f"end_{key}": value for key, value in end.items()})

    if redacted_keys:
        observed["redacted_query_keys"] = sorted(set(redacted_keys))

    return ArtifactRecord(
        record_id=f"history:{source_path}#downloads.id={download_id}",
        artifact_type="history",
        os_user=os_user,
        browser_profile=browser_profile,
        source_path=source_path,
        record_location=f"downloads.id={download_id}",
        observed=observed,
        warnings=record_warnings,
        **timestamp,
    )


def _download_filename(target_path: Any) -> str | None:
    """target_path 의 마지막 구성요소. Windows·POSIX 구분자 모두 처리하고 값을 해석하지 않는다."""
    if not isinstance(target_path, str) or not target_path:
        return None
    return re.split(r"[\\/]", target_path)[-1] or None
