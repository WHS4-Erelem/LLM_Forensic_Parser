"""Shared utilities: deterministic serialisation, stream helpers and time conversion."""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import enum
import json
from pathlib import Path
from typing import Any, BinaryIO

def safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception as exc:
        return f"<{type(value).__name__} str-error: {exc}>"

def to_jsonable(value: Any, _depth: int = 0, _seen: set[int] | None = None) -> Any:
    if _seen is None:
        _seen = set()
    if _depth > 24:
        return f"<{type(value).__name__}: max-depth>"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {
            "__type__": "bytes", "length": len(value),
            "base64": base64.b64encode(value).decode("ascii") if len(value) <= 4096 else None,
        }
    if isinstance(value, bytearray):
        return to_jsonable(bytes(value), _depth + 1, _seen)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, enum.Enum):
        return {"name": value.name, "value": to_jsonable(value.value, _depth + 1, _seen)}

    oid = id(value)
    if oid in _seen:
        return f"<{type(value).__name__}: cyclic-reference>"

    _seen.add(oid)
    try:
        if isinstance(value, dict):
            return {safe_str(k): to_jsonable(v, _depth + 1, _seen) for k, v in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [to_jsonable(v, _depth + 1, _seen) for v in value]
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return {
                f.name: to_jsonable(getattr(value, f.name), _depth + 1, _seen)
                for f in dataclasses.fields(value)
            }
        if hasattr(value, "__dict__"):
            try:
                return {k: to_jsonable(v, _depth + 1, _seen) for k, v in vars(value).items()
                        if not k.startswith("_")}
            except Exception:
                return {"repr": safe_str(value)}
        return safe_str(value)
    finally:
        _seen.discard(oid)

def stable_json(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def stable_key(obj: Any) -> str:
    return stable_json(obj)

def get_attr_any(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(obj, name):
            try:
                return getattr(obj, name)
            except Exception:
                continue
    return default

CHUNK = 1024 * 1024

def logical_size(record) -> int | None:
    try:
        return int(record.size())
    except Exception:
        return None

def streams_equal(left: BinaryIO, right: BinaryIO) -> bool:
    while True:
        a = left.read(CHUNK)
        b = right.read(CHUNK)
        if a != b:
            return False
        if not a:
            return True

def stream_equals_file(stream: BinaryIO | None, path: Path) -> bool:
    if stream is None:
        return False
    try:
        with Path(path).open("rb") as fh:
            return streams_equal(stream, fh)
    except OSError:
        return False

KST = dt.timezone(dt.timedelta(hours=9), "KST")
UTC = dt.timezone.utc
WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)
UNIX_EPOCH = dt.datetime(1970, 1, 1, tzinfo=UTC)

def from_webkit(value: Any) -> dt.datetime | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return WEBKIT_EPOCH + dt.timedelta(microseconds=n)
    except (OverflowError, OSError, ValueError):
        return None

def from_unix_millis(value: Any) -> dt.datetime | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return UNIX_EPOCH + dt.timedelta(milliseconds=n)
    except (OverflowError, OSError, ValueError):
        return None

def from_filetime(value: Any) -> dt.datetime | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return WEBKIT_EPOCH + dt.timedelta(microseconds=n / 10)
    except (OverflowError, OSError, ValueError):
        return None

def from_iso8601(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed

def ensure_aware(value: dt.datetime | None, assume: dt.tzinfo = UTC) -> dt.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=assume)
    return value

def to_kst_display(value: dt.datetime | None) -> str:
    if value is None:
        return ""
    aware = ensure_aware(value)
    if aware is None:
        return ""
    return aware.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S.%f") + " KST"

def sort_key(value: dt.datetime | None) -> tuple[int, float]:
    aware = ensure_aware(value)
    if aware is None:
        return (1, 0.0)
    return (0, aware.timestamp())
