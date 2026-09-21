"""
시각 정규화.

모든 시각은 **UTC로 저장**하고 표시할 때만 타임존을 입힌다.
그리고 시각마다 **어디서 나온 값인지(출처)** 와 **믿을 수 있는지(신뢰도)** 를 함께 들고 다닌다.

실제로 부딪히는 함정:
  Chromium은 종료할 때 밀린 쓰기를 한꺼번에 flush한다.
  그래서 캐시·IDB 파일의 MFT 시각은 '대화한 시각'이 아니라 '앱을 끈 시각'으로 수렴한다.
  이 시각을 그대로 타임라인에 쓰면 결론이 통째로 틀어진다 → time_confidence=low + 경고.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

# ── 에폭 기준점 ─────────────────────────────────────────────────────────
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)   # 100ns 단위
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)     # 마이크로초 단위
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class TimeSource(str, Enum):
    """시각의 출처. 신뢰도 순서가 곧 이 순서다."""
    USNJRNL = "usnjrnl"          # 변경 저널 — 행위 귀속의 가장 정확한 근거
    APPLOG = "applog"            # 앱 로그 — 앱이 직접 찍은 시각
    APIRESPONSE = "apiresponse"  # API 응답 본문의 created_at/updated_at
    CONFIG = "config"            # 설정 파일에 기록된 시각
    FILENAME = "filename"        # 파일명에 박힌 날짜
    MFT = "mft"                  # 파일시스템 시각 — flush 수렴 위험
    UNKNOWN = "unknown"


class TimeConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# 출처별 기본 신뢰도
_DEFAULT_CONFIDENCE = {
    TimeSource.USNJRNL: TimeConfidence.HIGH,
    TimeSource.APPLOG: TimeConfidence.HIGH,
    TimeSource.APIRESPONSE: TimeConfidence.HIGH,
    TimeSource.CONFIG: TimeConfidence.MEDIUM,
    TimeSource.FILENAME: TimeConfidence.MEDIUM,
    TimeSource.MFT: TimeConfidence.LOW,
    TimeSource.UNKNOWN: TimeConfidence.LOW,
}

# MFT 시각이 이 간격 안에 몰려 있으면 종료 flush로 수렴한 것으로 본다
FLUSH_CONVERGENCE_WINDOW = timedelta(seconds=3)


def confidence_for(source: TimeSource) -> TimeConfidence:
    return _DEFAULT_CONFIDENCE.get(source, TimeConfidence.LOW)


# ── 변환기 ──────────────────────────────────────────────────────────────
def from_filetime(value: int) -> datetime | None:
    """Windows FILETIME(1601 기준 100ns). 레지스트리 PCT/PTT, $MFT가 이 형식."""
    if not value or value <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None




def from_unix(value: float, unit: str = "auto") -> datetime | None:
    """
    Unix epoch. 초/밀리초/마이크로초를 자릿수로 자동 판별한다.
    JS의 Date.now()는 밀리초라서 그냥 초로 읽으면 5만년 뒤가 된다.
    """
    if not value or value <= 0:
        return None
    v = float(value)
    if unit == "auto":
        if v > 1e17:
            v /= 1e6      # 마이크로초
        elif v > 1e11:
            v /= 1e3      # 밀리초
    elif unit == "ms":
        v /= 1e3
    elif unit == "us":
        v /= 1e6
    try:
        return _UNIX_EPOCH + timedelta(seconds=v)
    except (OverflowError, ValueError):
        return None


def from_iso(text: str) -> datetime | None:
    """ISO 8601 문자열. API 응답의 created_at이 이 형식(끝의 Z 포함)."""
    if not text:
        return None
    s = str(text).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                    "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_utc_iso(dt: datetime | None) -> str | None:
    """저장용 표준 표기. 초 단위까지만 쓴다."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def display(dt_iso: str | None, tz: str = "UTC") -> str:
    """표시용. 저장값은 건드리지 않고 보여줄 때만 변환한다."""
    if not dt_iso:
        return "-"
    dt = from_iso(dt_iso)
    if dt is None:
        return dt_iso
    if tz.upper() == "KST":
        dt = dt + timedelta(hours=9)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f" {tz}"


def detect_flush_convergence(mft_times: list[datetime]) -> bool:
    """
    MFT 시각들이 한 점으로 수렴했는지 판정.
    3개 이상이 3초 안에 몰려 있으면 종료 flush로 본다.
    """
    valid = sorted(t for t in mft_times if t is not None)
    if len(valid) < 3:
        return False
    return (valid[-1] - valid[0]) <= FLUSH_CONVERGENCE_WINDOW
