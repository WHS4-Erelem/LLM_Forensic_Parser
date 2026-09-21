"""LevelDB 저수준 Reader (.log WriteBatch · .ldb SSTable)."""
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


# ---- 7.2 LevelDB .log Reader ------------------------------------------------
# Chrome Local Storage leveldb 폴더의 *.log (write-ahead log) 만 읽는다. *.ldb (SSTable, Snappy 압축) 는 미지원.
# 형식 (LevelDB log_format):
#   32 KiB block. physical record = checksum 4 (masked CRC32C of type+data, LE) + length 2 (LE) + type 1 + data
#   type 1 FULL / 2 FIRST / 3 MIDDLE / 4 LAST → FIRST (MIDDLE…) LAST 를 하나의 logical record 로 재조립
#   block 끝에 7 byte 미만이 남으면 trailer(padding). type 0·length 0 header 는 0 으로 채워진 사전 할당 영역 → block 나머지 건너뜀
#   logical record = WriteBatch: sequence 8 (LE) + count 4 (LE) + [tag 1 (1=PUT, 0=DELETE) + varint32 key 길이 + key (+ varint32 value 길이 + value)]
# CRC: CRC32C (Castagnoli) 를 표준 라이브러리만으로 계산해 검증한다. zlib.crc32 (CRC32) 와 다른 알고리즘이다.
#   2026-09-15 C: 분석용 사본 000010.log (E01-02) · 000009.log (POST_CLEANUP) 의 모든 physical record 에서 일치 확인.
#   불일치 record 도 버리지 않고 crc32c_verified=False + warning 으로 남긴다 (잔존 데이터 보존).
# 손상(길이·fragment 순서·varint 등)은 예외 대신 warning. 이 Reader 는 key·value 의미를 해석하지 않는다.
# .log 의 PUT 은 "현재 Local Storage 값"이 아니다. 과거에 기록된 잔존 레코드이며 뒤에 같은 key 의 PUT·DELETE 가 있을 수 있다.

LEVELDB_BLOCK_SIZE = 32768
LEVELDB_HEADER_SIZE = 7
LEVELDB_WRITEBATCH_HEADER_SIZE = 12
LEVELDB_RECORD_TYPES = {1: "FULL", 2: "FIRST", 3: "MIDDLE", 4: "LAST"}
LEVELDB_TRUNCATED_HEADER = "LEVELDB_TRUNCATED_HEADER"
LEVELDB_INVALID_LENGTH = "LEVELDB_INVALID_LENGTH"
LEVELDB_TRUNCATED_RECORD = "LEVELDB_TRUNCATED_RECORD"
LEVELDB_UNKNOWN_RECORD_TYPE = "LEVELDB_UNKNOWN_RECORD_TYPE"
LEVELDB_INVALID_FRAGMENT_SEQUENCE = "LEVELDB_INVALID_FRAGMENT_SEQUENCE"
LEVELDB_CRC_MISMATCH = "LEVELDB_CRC_MISMATCH"
LEVELDB_WRITEBATCH_INVALID = "LEVELDB_WRITEBATCH_INVALID"


def _crc32c_table() -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC32C_TABLE = _crc32c_table()


def crc32c(data: bytes) -> int:
    """CRC32C (Castagnoli, reflected polynomial 0x82F63B78). 표준 검사값: crc32c(b"123456789") == 0xE3069283."""
    # ponytail: byte 단위 Python 루프 (MB 당 수 초). 대용량 .log 가 느리면 slicing-by-8 표로 교체
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def leveldb_mask_crc(crc: int) -> int:
    """LevelDB 가 checksum 을 저장하기 전에 적용하는 mask (.log header 와 .ldb block trailer 공통)."""
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def leveldb_masked_crc(record_type: int, payload: bytes) -> int:
    """LevelDB 가 physical record header 에 저장하는 값: CRC32C(type + data) 를 mask 한 값."""
    return leveldb_mask_crc(crc32c(bytes([record_type]) + payload))


@dataclass(kw_only=True)
class LevelDBLogRecord:
    """재조립한 logical record. offset / block 은 첫 physical record 의 파일 위치."""

    offset: int
    block: int
    fragments: int
    crc32c_verified: bool
    data: bytes


@dataclass(kw_only=True)
class LevelDBOperation:
    """WriteBatch 안의 PUT / DELETE 1건. key_offset / value_offset 은 logical record data 안의 byte 위치."""

    record: LevelDBLogRecord
    sequence: int
    batch_sequence: int
    operation_index: int
    operation: str
    key: bytes
    key_offset: int
    value: bytes | None = None
    value_offset: int | None = None


def read_leveldb_log(data: bytes) -> tuple[list[LevelDBLogRecord], list[str]]:
    """LevelDB .log bytes → (logical record 목록, warning 목록). 예외를 던지지 않는다."""
    records: list[LevelDBLogRecord] = []
    warnings: list[str] = []
    pending: dict[str, Any] | None = None  # 재조립 중인 FIRST…
    size, pos = len(data), 0

    def drop_pending() -> None:
        nonlocal pending
        if pending is not None:
            warnings.append(f"{LEVELDB_INVALID_FRAGMENT_SEQUENCE}:offset={pending['offset']}")
            pending = None

    while pos < size:
        block_left = LEVELDB_BLOCK_SIZE - pos % LEVELDB_BLOCK_SIZE
        if block_left < LEVELDB_HEADER_SIZE:  # block trailer
            pos += block_left
            continue
        if size - pos < LEVELDB_HEADER_SIZE:
            if any(data[pos:]):
                warnings.append(f"{LEVELDB_TRUNCATED_HEADER}:offset={pos}")
            break
        checksum, length, record_type = struct.unpack_from("<IHB", data, pos)
        if record_type == 0 and length == 0:
            pos += block_left
            continue
        if LEVELDB_HEADER_SIZE + length > block_left:
            warnings.append(f"{LEVELDB_INVALID_LENGTH}:offset={pos}")
            drop_pending()
            pos += block_left  # 다음 block 에서 다시 맞춘다
            continue
        end = pos + LEVELDB_HEADER_SIZE + length
        if end > size:
            warnings.append(f"{LEVELDB_TRUNCATED_RECORD}:offset={pos}")
            break
        payload = data[pos + LEVELDB_HEADER_SIZE:end]
        verified = leveldb_masked_crc(record_type, payload) == checksum
        if not verified:
            warnings.append(f"{LEVELDB_CRC_MISMATCH}:offset={pos}")
        kind = LEVELDB_RECORD_TYPES.get(record_type)
        if kind is None:
            warnings.append(f"{LEVELDB_UNKNOWN_RECORD_TYPE}:offset={pos}")
            drop_pending()
        elif kind == "FULL":
            drop_pending()
            records.append(LevelDBLogRecord(offset=pos, block=pos // LEVELDB_BLOCK_SIZE, fragments=1,
                                            crc32c_verified=verified, data=payload))
        elif kind == "FIRST":
            drop_pending()
            pending = {"offset": pos, "parts": [payload], "verified": verified}
        elif pending is None:  # FIRST 없는 MIDDLE / LAST
            warnings.append(f"{LEVELDB_INVALID_FRAGMENT_SEQUENCE}:offset={pos}")
        else:
            pending["parts"].append(payload)
            pending["verified"] = pending["verified"] and verified
            if kind == "LAST":
                records.append(LevelDBLogRecord(
                    offset=pending["offset"], block=pending["offset"] // LEVELDB_BLOCK_SIZE,
                    fragments=len(pending["parts"]), crc32c_verified=pending["verified"], data=b"".join(pending["parts"]),
                ))
                pending = None
        pos = end
    drop_pending()  # 파일 끝까지 LAST 가 없음
    return records, warnings


def _read_varint32(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
    raise ValueError("varint longer than 5 bytes")


def parse_leveldb_write_batch(record: LevelDBLogRecord) -> tuple[list[LevelDBOperation], list[str]]:
    """logical record → (PUT / DELETE 목록, warning 목록). 손상 지점 이전의 operation 은 유지한다."""
    data = record.data
    if len(data) < LEVELDB_WRITEBATCH_HEADER_SIZE:
        return [], [f"{LEVELDB_WRITEBATCH_INVALID}:offset={record.offset}:header"]
    batch_sequence, count = struct.unpack_from("<QI", data, 0)
    operations: list[LevelDBOperation] = []
    pos = LEVELDB_WRITEBATCH_HEADER_SIZE
    try:
        for index in range(count):
            if pos >= len(data):
                raise ValueError("fewer operations than count")
            tag = data[pos]
            pos += 1
            if tag not in (0, 1):
                raise ValueError("unknown operation tag")
            key_length, pos = _read_varint32(data, pos)
            key_offset, pos = pos, pos + key_length
            if pos > len(data):
                raise ValueError("truncated key")
            value = value_offset = None
            if tag == 1:
                value_length, pos = _read_varint32(data, pos)
                value_offset, pos = pos, pos + value_length
                if pos > len(data):
                    raise ValueError("truncated value")
                value = data[value_offset:pos]
            operations.append(LevelDBOperation(
                record=record, sequence=batch_sequence + index, batch_sequence=batch_sequence, operation_index=index,
                operation="PUT" if tag == 1 else "DELETE", key=data[key_offset:key_offset + key_length],
                key_offset=key_offset, value=value, value_offset=value_offset,
            ))
    except ValueError:
        return operations, [f"{LEVELDB_WRITEBATCH_INVALID}:offset={record.offset}:operation={len(operations)}"]
    if pos != len(data):
        return operations, [f"{LEVELDB_WRITEBATCH_INVALID}:offset={record.offset}:trailing_bytes"]
    return operations, []


# ---- 7.2b LevelDB .ldb (SSTable) Reader --------------------------------------
# 2026-09-16 실제 .ldb (C: uid07 000005·000007, POST_CLEANUP 000010, D: E03-02 000005·000008) 에서 byte 로 확인한 형식:
#   파일 끝 48 byte footer = metaindex handle + index handle (각각 varint64 offset·size) + padding + magic 0xdb4775248b80fb57 (LE)
#   block = data + 1 byte compression type (0 none / 1 Snappy raw) + 4 byte masked CRC32C(data + compression type byte)
#   block 안 = entry* + restart offset 배열 (uint32) + restart 개수 (uint32)
#   entry = varint shared + varint non_shared + varint value 길이 + key 조각 + value  (shared = 앞 key 와의 공통 접두 길이)
#   key = internal key = user key + 8 byte trailer (LE) = sequence << 8 | value type (1 PUT / 0 DELETE)
#   metaindex 는 확인한 사본에서 entry 0개 (filter block 없음). filter block 은 이번 범위 밖이고, 있어도 실패로 보지 않는다.
# Snappy 해제는 cramjam 의 raw(비 framed) API. 없으면 압축 block 만 건너뛰고 warning 을 남긴다.
# 이 Reader 는 판정하지 않는다. .ldb 의 PUT 은 "현재 값"이 아니라 compaction 으로 옮겨진 잔존 물리 Record 이며,
#   같은 user key 의 옛 버전과 tombstone(DELETE) 도 합치지 않고 그대로 남긴다.

try:  # 선택 의존성 (cramjam==2.12.1, MIT, 2026-09-16 사용자 승인)
    import cramjam  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - 설치 여부에 따라 다름
    cramjam = None

LEVELDB_TABLE_MAGIC = 0xDB4775248B80FB57
LEVELDB_TABLE_FOOTER_SIZE = 48
LEVELDB_TABLE_TRAILER_SIZE = 5
LEVELDB_TABLE_COMPRESSIONS = {0: "none", 1: "snappy"}
LEVELDB_TABLE_TOO_SMALL = "LEVELDB_TABLE_TOO_SMALL"
LEVELDB_TABLE_BAD_MAGIC = "LEVELDB_TABLE_BAD_MAGIC"
LEVELDB_TABLE_INVALID_HANDLE = "LEVELDB_TABLE_INVALID_HANDLE"
LEVELDB_TABLE_BLOCK_INVALID = "LEVELDB_TABLE_BLOCK_INVALID"
LEVELDB_TABLE_CRC_MISMATCH = "LEVELDB_TABLE_CRC_MISMATCH"
LEVELDB_TABLE_UNSUPPORTED_COMPRESSION = "LEVELDB_TABLE_UNSUPPORTED_COMPRESSION"
LEVELDB_TABLE_SNAPPY_NOT_AVAILABLE = "LEVELDB_TABLE_SNAPPY_NOT_AVAILABLE"
LEVELDB_TABLE_SNAPPY_DECOMPRESSION_FAILED = "LEVELDB_TABLE_SNAPPY_DECOMPRESSION_FAILED"
LEVELDB_TABLE_INVALID_INTERNAL_KEY = "LEVELDB_TABLE_INVALID_INTERNAL_KEY"
LEVELDB_TABLE_UNSUPPORTED_CODES = (LEVELDB_TABLE_TOO_SMALL, LEVELDB_TABLE_BAD_MAGIC)


@dataclass(kw_only=True)
class LevelDBTableEntry:
    """SSTable 안의 물리 Record 1건. block 위치·entry 순서·sequence 를 provenance 로 남긴다."""

    block_offset: int
    block_index: int
    entry_index: int
    sequence: int
    operation: str
    key: bytes
    value: bytes | None
    compression: str
    crc32c_verified: bool


def _read_varint64(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
    raise ValueError("varint longer than 10 bytes")


def _leveldb_block_payload(
    data: bytes, offset: int, size: int, warnings: list[str], label: str,
) -> tuple[bytes | None, str, bool]:
    """block handle → (해제된 payload, compression 이름, CRC 일치 여부). 읽을 수 없으면 payload 는 None."""
    if offset < 0 or size < 0 or offset + size + LEVELDB_TABLE_TRAILER_SIZE > len(data):
        warnings.append(f"{LEVELDB_TABLE_INVALID_HANDLE}:{label}")
        return None, "unknown", False
    raw = data[offset:offset + size]
    compression_id = data[offset + size]
    stored, = struct.unpack_from("<I", data, offset + size + 1)
    verified = leveldb_mask_crc(crc32c(raw + bytes([compression_id]))) == stored
    if not verified:
        warnings.append(f"{LEVELDB_TABLE_CRC_MISMATCH}:{label}")  # 버리지 않고 표시만 (.log 정책과 같음)
    name = LEVELDB_TABLE_COMPRESSIONS.get(compression_id)
    if name is None:
        warnings.append(f"{LEVELDB_TABLE_UNSUPPORTED_COMPRESSION}:{label}:{compression_id}")
        return None, f"unsupported:{compression_id}", verified
    if name == "none":
        return raw, name, verified
    if cramjam is None:
        warnings.append(f"{LEVELDB_TABLE_SNAPPY_NOT_AVAILABLE}:{label}")
        return None, name, verified
    try:
        return bytes(cramjam.snappy.decompress_raw(raw)), name, verified
    except Exception:  # cramjam 자체 예외 — block 1개 실패가 파일 전체 실패가 되지 않게 한다
        warnings.append(f"{LEVELDB_TABLE_SNAPPY_DECOMPRESSION_FAILED}:{label}")
        return None, name, verified


def _leveldb_block_entries(payload: bytes, warnings: list[str], label: str) -> list[tuple[bytes, bytes]]:
    """block payload → [(key, value)]. 앞 key 와의 공통 접두로 key 를 복원하고, 손상되면 그 지점까지만 돌려준다."""
    if len(payload) < 4:
        warnings.append(f"{LEVELDB_TABLE_BLOCK_INVALID}:{label}:size")
        return []
    restart_count, = struct.unpack_from("<I", payload, len(payload) - 4)
    limit = len(payload) - 4 - restart_count * 4
    if limit < 0:
        warnings.append(f"{LEVELDB_TABLE_BLOCK_INVALID}:{label}:restarts")
        return []
    entries: list[tuple[bytes, bytes]] = []
    pos, previous = 0, b""
    while pos < limit:
        try:
            shared, pos = _read_varint64(payload, pos)
            non_shared, pos = _read_varint64(payload, pos)
            value_length, pos = _read_varint64(payload, pos)
            if shared > len(previous) or pos + non_shared + value_length > limit:
                raise ValueError("entry out of range")
        except ValueError:
            warnings.append(f"{LEVELDB_TABLE_BLOCK_INVALID}:{label}:entry={len(entries)}")
            break
        key = previous[:shared] + payload[pos:pos + non_shared]
        pos += non_shared
        entries.append((key, payload[pos:pos + value_length]))
        pos += value_length
        previous = key
    return entries


def read_leveldb_table(data: bytes) -> tuple[list[LevelDBTableEntry], list[str]]:
    """LevelDB .ldb (SSTable) bytes → (물리 Record 목록, warning 목록). 예외를 던지지 않는다."""
    warnings: list[str] = []
    if len(data) < LEVELDB_TABLE_FOOTER_SIZE:
        return [], [LEVELDB_TABLE_TOO_SMALL]
    footer = data[-LEVELDB_TABLE_FOOTER_SIZE:]
    if struct.unpack_from("<Q", footer, LEVELDB_TABLE_FOOTER_SIZE - 8)[0] != LEVELDB_TABLE_MAGIC:
        return [], [LEVELDB_TABLE_BAD_MAGIC]
    try:
        meta_offset, pos = _read_varint64(footer, 0)
        meta_size, pos = _read_varint64(footer, pos)
        index_offset, pos = _read_varint64(footer, pos)
        index_size, _ = _read_varint64(footer, pos)
    except ValueError:
        return [], [f"{LEVELDB_TABLE_INVALID_HANDLE}:footer"]

    _leveldb_block_payload(data, meta_offset, meta_size, warnings, "metaindex")  # 구조만 확인 (filter block 미지원)
    index_payload, _, _ = _leveldb_block_payload(data, index_offset, index_size, warnings, "index")
    if index_payload is None:
        return [], warnings

    entries: list[LevelDBTableEntry] = []
    for block_index, (_, handle) in enumerate(_leveldb_block_entries(index_payload, warnings, "index")):
        label = f"data_block={block_index}"
        try:
            offset, pos = _read_varint64(handle, 0)
            size, _ = _read_varint64(handle, pos)
        except ValueError:
            warnings.append(f"{LEVELDB_TABLE_INVALID_HANDLE}:{label}")
            continue
        payload, compression, verified = _leveldb_block_payload(data, offset, size, warnings, label)
        if payload is None:
            continue  # block 1개 실패로 다른 block 을 포기하지 않는다
        for entry_index, (key, value) in enumerate(_leveldb_block_entries(payload, warnings, label)):
            if len(key) < 8:
                warnings.append(f"{LEVELDB_TABLE_INVALID_INTERNAL_KEY}:{label}:entry={entry_index}")
                continue
            trailer, = struct.unpack_from("<Q", key, len(key) - 8)
            value_type = trailer & 0xFF
            if value_type not in (0, 1):
                warnings.append(f"{LEVELDB_TABLE_INVALID_INTERNAL_KEY}:{label}:entry={entry_index}:type={value_type}")
                continue
            entries.append(LevelDBTableEntry(
                block_offset=offset, block_index=block_index, entry_index=entry_index, sequence=trailer >> 8,
                operation="PUT" if value_type == 1 else "DELETE", key=key[:-8],
                value=value if value_type == 1 else None, compression=compression, crc32c_verified=verified,
            ))
    return entries, warnings
