"""여러 모듈이 함께 쓰는 helper (timestamp 정규화 · KST 변환 · 값 마스킹)."""
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


# =============================================================================
# 3. Timestamp Normalization
# =============================================================================
# 처리 순서: raw → UTC 계산 → UTC 를 KST(+09:00) 로 변환.
#   - raw 를 KST 로 가정하지 않는다. 분석 PC 의 로컬 시간대·현재 시각을 쓰지 않는다.
#   - 정수 timestamp 는 float 를 거치지 않고 정수 timedelta 로 계산한다 (정밀도 보존).
#   - normalize_timestamp() 는 예외를 밖으로 던지지 않는다. 실패는 warning 코드로 돌려준다.
#   - filesystem(NTFS FILETIME) 은 NTFS 단계에서 구현한다.

UTC = timezone.utc
KST = timezone(timedelta(hours=9), "KST")
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

SUPPORTED_TIMESTAMP_TYPES = ("webkit_us", "webkit_ms", "unix_s", "unix_s_decimal", "unix_ms", "iso_utc")
_UNIX_S_DECIMAL = re.compile(r"([0-9]+)(?:\.([0-9]{1,9}))?")

TS_MISSING = "TIMESTAMP_MISSING"
TS_INVALID_NUMBER = "TIMESTAMP_INVALID_NUMBER"
TS_OUT_OF_RANGE = "TIMESTAMP_OUT_OF_RANGE"
TS_UNSUPPORTED_TYPE = "TIMESTAMP_UNSUPPORTED_TYPE"
TS_NAIVE_ISO = "TIMESTAMP_NAIVE_ISO"
TS_INVALID_ISO = "TIMESTAMP_INVALID_ISO"

# 정수형 timestamp: (기준 시각, timedelta 단위)
_INTEGER_TIMESTAMP_UNITS = {
    "webkit_us": (WEBKIT_EPOCH, "microseconds"),
    "webkit_ms": (WEBKIT_EPOCH, "milliseconds"),  # Chrome shared_proto_db 의 download start/end time 에서 관찰됨
    "unix_s": (UNIX_EPOCH, "seconds"),
    "unix_ms": (UNIX_EPOCH, "milliseconds"),
}


def _iso(dt: datetime) -> str:
    # 마이크로초가 0이면 초까지만, 있으면 6자리 모두 표시
    return dt.isoformat(timespec="microseconds" if dt.microsecond else "seconds")


def format_utc(dt: datetime) -> str:
    """timezone-aware datetime → 'YYYY-MM-DDTHH:MM:SS[.ffffff]Z'."""
    text = _iso(dt.astimezone(UTC))
    return text[:-6] + "Z"  # '+00:00' → 'Z'


def format_kst(dt: datetime) -> str:
    """timezone-aware datetime → 'YYYY-MM-DDTHH:MM:SS[.ffffff]+09:00'."""
    return _iso(dt.astimezone(KST))


def _parse_integer_timestamp(raw: Any, timestamp_type: str) -> tuple[datetime | None, str | None]:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return None, TS_INVALID_NUMBER  # float 등은 정밀도 문제로 받지 않는다
    text = str(raw).strip()
    digits = text[1:] if text.startswith("-") else text
    if not (digits.isascii() and digits.isdigit()):
        return None, TS_INVALID_NUMBER
    value = int(text)
    if value < 0:
        return None, TS_OUT_OF_RANGE
    if value == 0 and timestamp_type == "webkit_us":
        return None, TS_MISSING  # Chrome 은 WebKit 시각 0 을 '값 없음'으로 쓴다 (1601-01-01 을 만들지 않음)
    epoch, unit = _INTEGER_TIMESTAMP_UNITS[timestamp_type]
    try:
        return epoch + timedelta(**{unit: value}), None
    except (OverflowError, ValueError):
        return None, TS_OUT_OF_RANGE


def _parse_unix_s_decimal(raw: Any) -> tuple[datetime | None, str | None]:
    """
    소수 초 문자열 ('1787221032.403678'). ChatGPT API 의 create_time 이 JSON 소수로 기록돼 있어 추가 (2026-09-15 실제 응답 확인).
    float 계산 없이 정수부·소수부를 따로 계산한다. 소수 9자리까지 받고 마이크로초 미만은 버린다 (raw 는 그대로 보존).
    float 객체는 여전히 받지 않는다 — 호출자가 JSON 숫자를 repr() 문자열로 넘긴다.
    """
    if not isinstance(raw, str):
        return None, TS_INVALID_NUMBER
    text = raw.strip()
    if text.startswith("-") and _UNIX_S_DECIMAL.fullmatch(text[1:]):
        return None, TS_OUT_OF_RANGE
    match = _UNIX_S_DECIMAL.fullmatch(text)
    if match is None:
        return None, TS_INVALID_NUMBER
    microseconds = int(((match.group(2) or "") + "000000")[:6])
    try:
        return UNIX_EPOCH + timedelta(seconds=int(match.group(1)), microseconds=microseconds), None
    except (OverflowError, ValueError):
        return None, TS_OUT_OF_RANGE


def _parse_iso_utc(raw: Any) -> tuple[datetime | None, str | None]:
    if not isinstance(raw, str):
        return None, TS_INVALID_ISO
    try:
        dt = datetime.fromisoformat(raw.strip())
    except ValueError:
        return None, TS_INVALID_ISO
    if dt.tzinfo is None or dt.utcoffset() is None:
        return None, TS_NAIVE_ISO  # 시간대 없는 값을 UTC 로 가정하지 않는다
    return dt, None


def normalize_timestamp(raw: Any, timestamp_type: str, source: str | None = None) -> dict[str, Any]:
    """
    raw timestamp 를 UTC / KST 문자열로 정규화한다. 예외를 던지지 않는다.

    반환 키: timestamp_raw, timestamp_utc, timestamp_kst, timestamp_type, timestamp_source, warnings

    실패 정책
      - timestamp_raw 는 가능한 한 원문 문자열로 보존한다 (None 이면 None).
      - 지원하지 않는 timestamp_type → timestamp_type="unknown" + TIMESTAMP_UNSUPPORTED_TYPE
      - 지원 type 인데 값이 손상됨 → timestamp_type 은 그대로 두고 utc/kst=None + warning 코드
    """
    result: dict[str, Any] = {
        "timestamp_raw": None if raw is None else str(raw),
        "timestamp_utc": None,
        "timestamp_kst": None,
        "timestamp_type": timestamp_type,
        "timestamp_source": None if source is None else str(source),
        "warnings": [],
    }

    if timestamp_type not in SUPPORTED_TIMESTAMP_TYPES:
        result["timestamp_type"] = "unknown"
        result["warnings"].append(TS_UNSUPPORTED_TYPE)
    if result["timestamp_raw"] is None or not result["timestamp_raw"].strip():
        result["warnings"].append(TS_MISSING)
    if result["warnings"]:
        return result

    if timestamp_type == "iso_utc":
        dt, warning = _parse_iso_utc(raw)
    elif timestamp_type == "unix_s_decimal":
        dt, warning = _parse_unix_s_decimal(raw)
    else:
        dt, warning = _parse_integer_timestamp(raw, timestamp_type)

    if dt is not None:
        try:
            result["timestamp_utc"] = format_utc(dt)
            result["timestamp_kst"] = format_kst(dt)
        except (OverflowError, ValueError):  # 예: 9999-12-31T20:00Z 는 KST 로 옮기면 연도 범위를 넘는다
            result["timestamp_utc"] = result["timestamp_kst"] = None
            warning = TS_OUT_OF_RANGE

    if warning:
        result["warnings"].append(warning)
    return result
