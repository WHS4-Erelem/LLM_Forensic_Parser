"""Chrome Blockfile Cache Reader (CacheAddr · index · carving · 응답 본문 복원)."""
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
from ..artifacts.history import redact_url_query
from ..artifacts.local_storage import _profile_subdir
from ..discovery import _join_source_path
from ..models import ArtifactRecord, Coverage
from ..source import SourcePathError, normalize_source_path
from ..utils import normalize_timestamp


# ---- Chrome Blockfile Cache Reader (ChatGPT 대화 API 응답만) ------------------------------------------
# 2026-09-15 C: POST_CLEANUP / PRE_CLEANUP 사본에서 확인한 형식 (이번 실험 환경 기준. 모든 Chrome 이 이 형식이라는 뜻이 아니다):
#   Cache/Cache_Data/index (magic 0xC103CAC3) + data_0~3 (block file, magic 0xC104CAC3, header 8192 B) + f_XXXXXX (external)
#   index: header 368 B 뒤 table_len 개의 CacheAddr hash table → EntryStore 의 next 로 이어진 체인을 따라 entry 를 열거한다.
#   CacheAddr: bit31 사용 중, bit28-30 file type (0 external, 1 36 B, 2 256 B, 3 1 KB, 4 4 KB, 6 104 B, 7 48 B),
#              bit24-25 block 수-1, bit16-23 data_N 번호, bit0-15 시작 block (external 은 bit0-27 = f_ 번호)
#   EntryStore: +4 next, +20 state, +24 creation_time (base::Time µs = webkit_us), +32 key_len, +36 long_key,
#               +40 data_size[4], +56 data_addr[4], +96 key
#   stream 0 = HTTP 응답 정보 ("HTTP/1.1 200\0name: value\0…\0\0" 포함), stream 1 = 응답 본문 (정확히 data_size[1] byte)
# 범위: key 의 URL 이 대화 1건의 응답 endpoint 인 entry 만 Record 로 만든다 (_CONVERSATION_API_URL).
#   stream_status / textdocs / interpreter/download / 목록 API 는 메시지 본문이 없어 대상이 아니다.
#   응답 헤더는 status code, content-type, content-encoding 만 남긴다 (set-cookie 등 나머지 헤더 값은 출력하지 않는다).
#   본문 인코딩: 없음·identity → 그대로, br → brotli (brotli==1.2.0, MIT, 2026-09-15 사용자 승인, 선택 import), 그 밖 → warning.
#   Reader 는 대화 JSON 중 대화·메시지 복원에 필요한 필드만 observed["conversation"] 에 남긴다 (행위 판정·메시지 생성 없음).
#   Record 시각 = cache entry 생성 시각 (사용자 행위 시각이 아니다).
# index 에 반영되지 않은 entry 는 data_* block 전체 탐색(carving)으로 보완한다 (2026-09-20). index 열거가 primary,
#   carving 은 fallback 이며 구조 검증(key 길이·decode·stream 주소 범위·헤더 파싱)을 통과한 후보만 받는다.
#   Chrome 실행 중 snapshot 처럼 index 가 최신이 아닌 사본에서 실제로 필요했다. 중복은 (key, stream 주소)로 제거한다.
# 한계: index 가 없는 cache (Simple Cache 등) 는 NOT_SUPPORTED.

try:  # 선택 의존성
    import brotli  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - 설치 여부에 따라 다름
    brotli = None

CACHE_DIR_PARTS = ("Cache", "Cache_Data")
CACHE_INDEX_MAGIC = 0xC103CAC3
CACHE_BLOCK_MAGIC = 0xC104CAC3
CACHE_INDEX_HEADER_SIZE = 368
CACHE_BLOCK_HEADER_SIZE = 8192
_CACHE_BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096, 6: 104, 7: 48}
_CACHE_HEADER_ALLOWLIST = ("content-type", "content-encoding")
# 대화 1건의 응답 endpoint. 2026-09-30 Scenario 이미지 Cache 에서 확인한 두 가지 형태를 모두 받는다:
#   .../backend-api/conversation/<id>                          단수형 (2026-09-15 확인)
#   .../backend-api/conversations/<id>?<query>                  복수형 + query (현재 웹 client)
# 목록 endpoint (.../conversations?<query> — <id> 없음) 와 하위 경로 (/textdocs · /stream_status) 는 대화 본문이 없어
# 대상이 아니다. <id> 문자 집합에 '/' 와 '?' 가 없으므로 fullmatch 만으로 이 둘이 함께 배제된다.
_CONVERSATION_API_URL = re.compile(r"https://chatgpt\.com/backend-api/conversations?/([0-9A-Za-z-]+)(?:\?.*)?")
CACHE_FORMAT_NOT_SUPPORTED = "CACHE_FORMAT_NOT_SUPPORTED"
CACHE_READ_ERROR = "CACHE_READ_ERROR"
CACHE_PATH_OUTSIDE_SOURCE = "CACHE_PATH_OUTSIDE_SOURCE"
CACHE_ENTRY_UNREADABLE = "CACHE_ENTRY_UNREADABLE"
CACHE_BODY_UNREADABLE = "CACHE_BODY_UNREADABLE"
CACHE_BROTLI_NOT_AVAILABLE = "CACHE_BROTLI_NOT_AVAILABLE"
CACHE_BROTLI_DECOMPRESSION_FAILED = "CACHE_BROTLI_DECOMPRESSION_FAILED"
CACHE_CONTENT_ENCODING_NOT_SUPPORTED = "CACHE_CONTENT_ENCODING_NOT_SUPPORTED"
CACHE_BODY_NOT_JSON = "CACHE_BODY_NOT_JSON"
CACHE_UNEXPECTED_STRUCTURE = "CACHE_UNEXPECTED_STRUCTURE"
CACHE_BLOCKFILE_CARVED_ENTRY = "CACHE_BLOCKFILE_CARVED_ENTRY"
_CACHE_DATA_FILES = ("data_0", "data_1", "data_2", "data_3")  # data_N 의 block 크기 = _CACHE_BLOCK_SIZES[N + 1]
_CACHE_MAX_KEY_LENGTH = 0x10000


def _cache_address_file(address: int) -> str | None:
    """CacheAddr 가 가리키는 실제 파일 이름 (data_N / f_xxxxxx). 해석할 수 없으면 None — 이름을 만들어 내지 않는다."""
    if not address & 0x80000000:
        return None
    file_type = (address >> 28) & 7
    if file_type == 0:
        return f"f_{address & 0x0FFFFFFF:06x}"
    return f"data_{(address >> 16) & 0xFF}" if file_type in _CACHE_BLOCK_SIZES else None


class _BlockfileCache:
    def __init__(self, source: Source, directory: str) -> None:
        self.source, self.directory, self._files = source, directory, {}

    def _file(self, name: str) -> bytes:
        if name not in self._files:
            # ponytail: data_N 파일 전체를 메모리에 올린다 (실험 사본 기준 수 MB). 큰 cache 는 Source 에 부분 읽기 API 필요
            self._files[name] = self.source.read_bytes(_join_source_path(self.directory, name))
        return self._files[name]

    def read(self, address: int, size: int | None = None) -> bytes:
        """CacheAddr 가 가리키는 bytes (size 가 있으면 정확히 그만큼). 읽을 수 없으면 ValueError / OSError."""
        if not address & 0x80000000:
            raise ValueError("cache address not initialized")
        file_type = (address >> 28) & 7
        if file_type == 0:
            data = self._file(f"f_{address & 0x0FFFFFFF:06x}")
        else:
            block_size = _CACHE_BLOCK_SIZES.get(file_type)
            if block_size is None:
                raise ValueError("unknown cache block file type")
            blob = self._file(f"data_{(address >> 16) & 0xFF}")
            if blob[:4] != struct.pack("<I", CACHE_BLOCK_MAGIC):
                raise ValueError("block file magic mismatch")
            start = CACHE_BLOCK_HEADER_SIZE + (address & 0xFFFF) * block_size
            data = blob[start:start + (((address >> 24) & 3) + 1) * block_size]
        if size is not None:
            if size > len(data):
                raise ValueError("cache stream shorter than recorded size")
            data = data[:size]
        return data


def _cache_entries(cache: _BlockfileCache, index: bytes) -> tuple[list[tuple[int, int, int, str, tuple, tuple]], int]:
    """index hash table 의 모든 EntryStore → ([(address, state, creation_time, key, data_size, data_addr)], 읽지 못한 체인 수)."""
    table_len = struct.unpack_from("<i", index, 28)[0]
    if table_len <= 0 or CACHE_INDEX_HEADER_SIZE + 4 * table_len > len(index):
        raise ValueError("cache index table out of range")
    entries, unreadable, seen = [], 0, set()
    for address in struct.unpack_from(f"<{table_len}I", index, CACHE_INDEX_HEADER_SIZE):
        while address and address not in seen:  # seen: 순환 체인 방지
            seen.add(address)
            try:
                raw = cache.read(address)
                next_address, = struct.unpack_from("<I", raw, 4)
                state, created, key_len, long_key = struct.unpack_from("<iQiI", raw, 20)
                sizes, addresses = struct.unpack_from("<4i", raw, 40), struct.unpack_from("<4I", raw, 56)
                if key_len < 0:
                    raise ValueError("negative key length")
                key = cache.read(long_key, key_len) if long_key else raw[96:96 + key_len]
                if len(key) != key_len:
                    raise ValueError("truncated key")
            except (ValueError, OSError, struct.error):
                unreadable += 1
                break
            entries.append((address, state, created, key.decode("latin-1"), sizes, addresses))
            address = next_address
    return entries, unreadable


def _cache_entry_at(
    cache: _BlockfileCache, blob: bytes, start: int, file_number: int, block_size: int,
) -> tuple[int, int, int, str, tuple, tuple] | None:
    """data_N 의 block 경계 하나를 EntryStore 후보로 해석한다. 구조 검증을 통과하지 못하면 None (byte 일치만으로 받아들이지 않는다)."""
    try:
        state, created, key_len, long_key = struct.unpack_from("<iQiI", blob, start + 20)
        sizes = struct.unpack_from("<4i", blob, start + 40)
        addresses = struct.unpack_from("<4I", blob, start + 56)
    except struct.error:
        return None
    if not 0 <= state <= 3 or created <= 0 or not 0 < key_len <= _CACHE_MAX_KEY_LENGTH:
        return None
    try:
        key_bytes = cache.read(long_key, key_len) if long_key else blob[start + 96:start + 96 + key_len]
    except (ValueError, OSError):
        return None
    if len(key_bytes) != key_len:
        return None
    try:
        key = key_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None
    if "://" not in key or not key.isprintable():  # HTTP(S) cache key 구조만 받는다
        return None
    for size, address in zip(sizes, addresses):
        if size < 0 or (size and not address):
            return None
        try:
            if address and len(cache.read(address, size)) != size:
                return None
        except (ValueError, OSError):
            return None
    blocks = min(4, max(1, -(-(96 + (0 if long_key else key_len)) // block_size)))
    address = (0x80000000 | ((file_number + 1) << 28) | ((blocks - 1) << 24)
               | (file_number << 16) | (start - CACHE_BLOCK_HEADER_SIZE) // block_size)
    return address, state, created, key, sizes, addresses


def _cache_carved_entries(cache: _BlockfileCache) -> list[tuple[tuple, str]]:
    """index 에서 도달하지 못한 EntryStore 를 data_* 전체 탐색으로 찾는다 (fallback). [(entry, 'data_N@offset=…')]."""
    carved = []
    for file_number, name in enumerate(_CACHE_DATA_FILES):
        block_size = _CACHE_BLOCK_SIZES[file_number + 1]
        if block_size < 96:  # EntryStore 가 들어갈 수 없는 block 크기 (data_0 36 B)
            continue
        try:
            blob = cache._file(name)
        except (SourcePathError, OSError):
            continue
        if blob[:4] != struct.pack("<I", CACHE_BLOCK_MAGIC):
            continue
        for start in range(CACHE_BLOCK_HEADER_SIZE, len(blob) - 96 + 1, block_size):
            entry = _cache_entry_at(cache, blob, start, file_number, block_size)
            if entry is not None:
                carved.append((entry, f"{name}@offset={start}"))
    return carved


def _cache_response_headers(info: bytes) -> tuple[int | None, dict[str, str]]:
    """stream 0 에서 status code 와 허용 헤더만."""
    start = info.find(b"HTTP/")
    if start < 0:
        return None, {}
    end = info.find(b"\x00\x00", start)
    lines = info[start:end if end >= 0 else len(info)].split(b"\x00")
    status_fields = lines[0].split()
    status = int(status_fields[1]) if len(status_fields) > 1 and status_fields[1].isdigit() else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        name_text = name.strip().lower().decode("latin-1")
        if separator and name_text in _CACHE_HEADER_ALLOWLIST:
            headers[name_text] = value.strip().decode("latin-1")
    return status, headers


def _reduce_message(message: Any) -> dict[str, Any] | None:
    """message 객체 → 대화·메시지 복원에 필요한 필드만. message 가 없는 노드 (트리의 root 등) 는 None."""
    if not isinstance(message, dict):
        return None
    author = message.get("author") if isinstance(message.get("author"), dict) else {}
    metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
    reduced = {"id": message.get("id"), "role": author.get("role"), "author_name": author.get("name"),
               "create_time": message.get("create_time"), "update_time": message.get("update_time"),
               "status": message.get("status"), "recipient": message.get("recipient"),
               "message_type": metadata.get("message_type"), "content": message.get("content"),
               "attachments": metadata.get("attachments"),  # 업로드 파일 메타데이터 (FILE_UPLOAD Rule)
               "model_slug": metadata.get("model_slug")}  # 응답을 만든 모델 (MODEL_CHANGE Rule)
    # has_versions: 응답 URL 의 include_has_versions=true 로 서버가 붙이는 "이 메시지에 다른 버전이 있는가" 표시.
    # 키가 실제로 있을 때만 남긴다 (없는 응답의 observed 를 바꾸지 않는다). 이 값으로 행위를 판정하지 않는다 —
    # 지금은 증거 보존만 하고, 분기(mapping 트리)가 실제로 캐시된 이미지를 확보한 뒤 판정을 검토한다.
    if "has_versions" in metadata:
        reduced["has_versions"] = metadata.get("has_versions")
    return reduced


def _reduce_conversation_json(obj: Any) -> dict[str, Any] | None:
    """
    대화 응답 JSON → 대화·메시지 복원에 필요한 필드만 (owner·moderation·request_id 등 제외).
    확인된 두 가지 응답 형식을 같은 노드 목록으로 정규화한다. 둘 다 아니면 None (CACHE_UNEXPECTED_STRUCTURE).
      - "mapping": {node_id: {parent, children, message}}  트리 (2026-09-15 확인)
      - "messages": [message, ...]                        평면 목록 (2026-09-30 Scenario 이미지에서 확인)
        평면 목록은 부모가 message.metadata.parent_id 에만 있고 children 이 응답에 없다 → parent 링크를 뒤집어 채운다.
        parent_id 가 가리키는 부모가 응답에 없으면 (num_turns 로 잘린 경우) 그 노드는 root 로 남는다.
    """
    if not isinstance(obj, dict):
        return None
    nodes: list[dict[str, Any]] = []
    if isinstance(obj.get("mapping"), dict):
        for node_id, node in obj["mapping"].items():
            if not isinstance(node, dict):
                return None
            nodes.append({"node_id": node_id, "parent": node.get("parent"),
                          "children": node.get("children"), "message": _reduce_message(node.get("message"))})
    elif isinstance(obj.get("messages"), list):
        used: set[str] = set()
        for index, message in enumerate(obj["messages"]):
            if not isinstance(message, dict):
                return None
            message_id = message.get("id")
            # node_id 는 트리 형식의 key 와 같은 자리다. id 가 없거나 겹치면 순번으로 대체한다 (값을 만들어 내지 않는다).
            node_id = message_id if isinstance(message_id, str) and message_id and message_id not in used \
                else f"messages[{index}]"
            used.add(node_id)
            metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
            parent = metadata.get("parent_id")
            nodes.append({"node_id": node_id, "parent": parent if isinstance(parent, str) else None,
                          "children": [], "message": _reduce_message(message)})
        by_id = {node["node_id"]: node for node in nodes}
        for node in nodes:
            parent_node = by_id.get(node["parent"])
            if parent_node is not None and parent_node is not node:
                parent_node["children"].append(node["node_id"])
    else:
        return None
    return {"conversation_id": obj.get("conversation_id"), "title": obj.get("title"), "create_time": obj.get("create_time"),
            "update_time": obj.get("update_time"), "current_node": obj.get("current_node"), "mapping": nodes}


def _cache_conversation_record(
    cache: _BlockfileCache, entry: tuple, url: str, url_id: str, directory: str, os_user: str | None,
    browser_profile: str | None, *, carved_at: str | None = None,
) -> ArtifactRecord:
    address, state, created, _, sizes, addresses = entry
    # url 은 cache key 에서 읽은 실제 요청 URL 이다 (단수형·복수형·query 가 그대로 남는다). 만들어 내지 않는다.
    redacted_url, redacted_keys = redact_url_query(url)
    observed: dict[str, Any] = {
        "url": redacted_url, "cache_key_kind": "conversation_response",
        "url_conversation_id": url_id, "entry_address": f"0x{address:08x}", "entry_state": state,
        "entry_origin": "carved" if carved_at else "index",
        "http_status": None, "content_type": None, "content_encoding": None,
        "body_length": sizes[1], "body_sha256": None, "decoded_length": None, "decoded_sha256": None,
    }
    if redacted_keys:
        observed["url_redacted_keys"] = redacted_keys
    warnings: list[str] = []
    timestamp = normalize_timestamp(created, "webkit_us", "Cache.EntryStore.creation_time") if created else {}
    warnings += timestamp.pop("warnings", [])
    record_location = f"entry=0x{address:08x} stream0=0x{addresses[0]:08x} stream1=0x{addresses[1]:08x}"
    # 응답 본문(stream1)이 실제로 들어 있는 파일. source_path 는 Cache_Data 폴더라 파일 이름이 여기 없으면
    # "어느 파일에서 복구했는가" 를 알 수 없다. 해석되지 않으면 붙이지 않는다 (이름을 만들어 내지 않는다).
    body_file = _cache_address_file(addresses[1])
    if body_file:
        record_location = f"file={body_file} " + record_location
    if carved_at:
        record_location += f" carved={carved_at}"

    def finish() -> ArtifactRecord:
        return ArtifactRecord(
            record_id=f"cache:{directory}#entry=0x{address:08x}", artifact_type="cache", os_user=os_user,
            browser_profile=browser_profile, source_path=directory, record_location=record_location,
            observed=observed, warnings=warnings, **timestamp,
        )

    try:
        observed["http_status"], headers = _cache_response_headers(cache.read(addresses[0], sizes[0]) if sizes[0] > 0 else b"")
        body = cache.read(addresses[1], sizes[1]) if sizes[1] > 0 else b""
    except (ValueError, OSError):
        warnings.append(CACHE_BODY_UNREADABLE)
        return finish()
    observed["content_type"] = headers.get("content-type")
    observed["content_encoding"] = headers.get("content-encoding")
    observed["body_sha256"] = hashlib.sha256(body).hexdigest()

    encoding = (headers.get("content-encoding") or "identity").strip().lower()
    decoded: bytes | None = None
    if encoding == "identity":
        decoded = body
    elif encoding == "br":
        if brotli is None:
            warnings.append(CACHE_BROTLI_NOT_AVAILABLE)
        else:
            try:
                decoded = brotli.decompress(body)
            except brotli.error:
                warnings.append(CACHE_BROTLI_DECOMPRESSION_FAILED)
    else:
        warnings.append(f"{CACHE_CONTENT_ENCODING_NOT_SUPPORTED}:{encoding}")
    if decoded is None:
        return finish()
    observed["decoded_length"] = len(decoded)
    observed["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
    try:
        parsed = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        warnings.append(CACHE_BODY_NOT_JSON)
        return finish()
    conversation = _reduce_conversation_json(parsed)
    if conversation is None:
        warnings.append(CACHE_UNEXPECTED_STRUCTURE)
    else:
        observed["conversation"] = conversation
    return finish()


def read_chrome_cache(
    source: Source, cache_dir: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """
    Blockfile Cache 폴더 → (대화 API 응답 Record 목록, Coverage). Coverage source_sha256 = index 파일 SHA-256.
      NOT_PRESENT 폴더 없음 / NOT_SUPPORTED index 없음·magic 불일치 / PARSED 대화 응답 0건 이상 정상 /
      PARTIAL 읽지 못한 entry·본문·해제·JSON 실패 / PARSE_ERROR 읽기 실패·index table 손상
    """
    directory = normalize_source_path(cache_dir)
    warnings: list[str] = []

    def finish(status: str, records: list[ArtifactRecord] | None = None, sha: str | None = None):
        records = records or []
        return records, Coverage(artifact_type="cache", os_user=os_user, browser_profile=browser_profile,
                                 source_path=directory, status=status, record_count=len(records),
                                 source_sha256=sha, warnings=warnings)

    index_path = _join_source_path(directory, "index")
    try:
        if not source.is_dir(directory):
            return finish("NOT_PRESENT")
        if not source.is_file(index_path):
            warnings.append(CACHE_FORMAT_NOT_SUPPORTED)
            return finish("NOT_SUPPORTED")
        index = source.read_bytes(index_path)
    except SourcePathError:
        warnings.append(CACHE_PATH_OUTSIDE_SOURCE)
        return finish("PARSE_ERROR")
    except OSError:
        warnings.append(CACHE_READ_ERROR)
        return finish("PARSE_ERROR")
    sha = hashlib.sha256(index).hexdigest()
    if len(index) < CACHE_INDEX_HEADER_SIZE or struct.unpack_from("<I", index)[0] != CACHE_INDEX_MAGIC:
        warnings.append(CACHE_FORMAT_NOT_SUPPORTED)
        return finish("NOT_SUPPORTED", sha=sha)

    cache = _BlockfileCache(source, directory)
    try:
        entries, unreadable = _cache_entries(cache, index)
    except ValueError:
        warnings.append(CACHE_FORMAT_NOT_SUPPORTED)
        return finish("PARSE_ERROR", sha=sha)
    if unreadable:
        warnings.append(f"{CACHE_ENTRY_UNREADABLE}:{unreadable}")
    # index 에 연결된 entry 가 primary, data_* carving 은 fallback 이다. 같은 entry 는 (key, stream 주소) 로 한 번만 처리한다.
    seen = {(entry[3], entry[5][0], entry[5][1]) for entry in entries}
    enumerated: list[tuple[tuple, str | None]] = [(entry, None) for entry in entries]
    carved_count = 0
    for entry, location in _cache_carved_entries(cache):
        identity = (entry[3], entry[5][0], entry[5][1])
        if identity in seen:
            continue
        seen.add(identity)
        enumerated.append((entry, location))
        carved_count += 1
    if carved_count:  # 정보성 기록 (carving 자체는 오류도 사용자 행위도 아니다)
        warnings.append(f"{CACHE_BLOCKFILE_CARVED_ENTRY}:{carved_count}")
    records = []
    for entry, location in enumerated:
        match = _CONVERSATION_API_URL.fullmatch(entry[3].rsplit(" ", 1)[-1])
        if match is not None:
            records.append(_cache_conversation_record(cache, entry, match.group(0), match.group(1), directory,
                                                      os_user, browser_profile, carved_at=location))
    damaged = bool(unreadable) or any(record.warnings for record in records)
    return finish("PARTIAL" if damaged else "PARSED", records, sha)


def cache_data_dir(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'Cache/Cache_Data' 경로."""
    return _profile_subdir(source, profile_path, CACHE_DIR_PARTS, warnings)


# ---- Event Rules ---------------------------------------------------------------------------------
# Rule 은 ArtifactRecord (와 선택적으로 Coverage 요약)만 입력으로 받는다. 파일·SQLite·이미지를 읽지 않는다.
# 입력 ArtifactRecord 는 수정하지 않고 Event 를 새로 만든다 (Observation ≠ User Action).

REASON_RULE_VERIFIED = "RULE_VERIFIED"
REASON_DIRECT_URL = "DIRECT_URL"
REASON_TIMESTAMP_EXPLAINED = "TIMESTAMP_EXPLAINED"
REASON_TIMESTAMP_MISSING = "TIMESTAMP_MISSING"
REASON_URL_VARIANT_NOT_VERIFIED = "URL_VARIANT_NOT_VERIFIED"
# NO_KNOWN_CONTRADICTION 은 모순 검사를 실제로 구현한 뒤에만 사용한다 (현재 미사용).


def history_device_attribution(observed: dict[str, Any]) -> tuple[str, str]:
    """
    History visit 의 (device_attribution, 이유).
      - originator_cache_guid 가 비어 있지 않음 → REMOTE_SYNCED
      - 빈 문자열 → UNKNOWN (LOCAL 후보. '빈 값 = 이 PC 방문' 이 실험으로 검증되지 않아 LOCAL 로 확정하지 않음)
      - None (컬럼 없음 또는 NULL) → UNKNOWN
    is_known_to_sync 는 사용하지 않는다 (단독 판정 금지).
    """
    guid = observed.get("originator_cache_guid")
    if isinstance(guid, str) and guid:
        return "REMOTE_SYNCED", "originator_cache_guid non-empty"
    if guid == "":
        return "UNKNOWN", "originator_cache_guid empty (LOCAL candidate, not verified)"
    return "UNKNOWN", "originator_cache_guid column absent or NULL"
