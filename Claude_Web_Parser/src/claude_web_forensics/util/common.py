"""Shared utilities: deterministic serialisation, stream helpers and time conversion.

Merged verbatim from: serialize.py, streaming.py, timeutil.py.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import enum
import json
from pathlib import Path
from typing import Any
from typing import BinaryIO


# ===========================================================================
# serialize
# ===========================================================================

"""Deterministic, cycle-safe serialisation helpers.

Reused from chrome_artifact_diff_v2.py:151-237 (see docs/design_review.md 3.1).
"""

def safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception as exc:  # pragma: no cover - defensive
        return f"<{type(value).__name__} str-error: {exc}>"


def to_jsonable(value: Any, _depth: int = 0, _seen: set[int] | None = None) -> Any:
    """Best-effort, cycle-safe conversion of CCL/Python objects to JSON-safe values."""
    if _seen is None:
        _seen = set()
    if _depth > 24:
        return f"<{type(value).__name__}: max-depth>"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {
            "__type__": "bytes",
            "length": len(value),
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

    if isinstance(value, dict):
        _seen.add(oid)
        try:
            return {safe_str(k): to_jsonable(v, _depth + 1, _seen) for k, v in value.items()}
        finally:
            _seen.discard(oid)
    if isinstance(value, (list, tuple, set, frozenset)):
        _seen.add(oid)
        try:
            return [to_jsonable(v, _depth + 1, _seen) for v in value]
        finally:
            _seen.discard(oid)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        _seen.add(oid)
        try:
            return {
                f.name: to_jsonable(getattr(value, f.name), _depth + 1, _seen)
                for f in dataclasses.fields(value)
            }
        finally:
            _seen.discard(oid)
    if hasattr(value, "__dict__"):
        _seen.add(oid)
        try:
            return {
                k: to_jsonable(v, _depth + 1, _seen)
                for k, v in vars(value).items()
                if not k.startswith("_")
            }
        except Exception:
            return {"repr": safe_str(value)}
        finally:
            _seen.discard(oid)

    return safe_str(value)


def stable_json(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_key(obj: Any) -> str:
    """Deterministic identity key: the canonical JSON itself (no hashing)."""
    return stable_json(obj)


def get_attr_any(obj: Any, *names: str, default: Any = None) -> Any:
    """Read the first attribute that exists. Absorbs CCL version differences."""
    for name in names:
        if hasattr(obj, name):
            try:
                return getattr(obj, name)
            except Exception:
                continue
    return default


# ===========================================================================
# streaming
# ===========================================================================

"""Small stream helpers for NTFS records.

No file bytes are exported. Content is compared chunk by chunk only when a
file's size already equals a known Claude download body (see claude_scope), so
identity is established by direct byte comparison instead of hashing.
"""

CHUNK = 1024 * 1024


def logical_size(record) -> int | None:
    """Best-effort logical size of an NTFS record's default data stream."""
    try:
        return int(record.size())
    except Exception:
        return None


def streams_equal(left: BinaryIO, right: BinaryIO) -> bool:
    """True when both streams yield exactly the same bytes."""
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


# ===========================================================================
# timeutil
# ===========================================================================

"""Time policy (spec section 18).

Internally we keep timezone-aware instants; final CSV output is KST only.
Epochs are mapped explicitly per source field -- never guessed from magnitude
(that was the defect in chrome_artifact_diff_test_readable_v3.py:187-230).
"""

KST = dt.timezone(dt.timedelta(hours=9), "KST")
UTC = dt.timezone.utc
WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)
UNIX_EPOCH = dt.datetime(1970, 1, 1, tzinfo=UTC)


def from_webkit(value: Any) -> dt.datetime | None:
    """Chrome/WebKit: microseconds since 1601-01-01 UTC."""
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


def from_unix_seconds(value: Any) -> dt.datetime | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return UNIX_EPOCH + dt.timedelta(seconds=n)
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


def from_unix_micros(value: Any) -> dt.datetime | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return UNIX_EPOCH + dt.timedelta(microseconds=n)
    except (OverflowError, OSError, ValueError):
        return None


def from_filetime(value: Any) -> dt.datetime | None:
    """Windows FILETIME: 100ns intervals since 1601-01-01 UTC."""
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
    """Claude API timestamps, e.g. 2026-08-22T12:08:37.058420Z."""
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
        # Naive values in Claude API payloads are UTC. SNSS values are local-naive
        # and are handled by the caller, which passes an explicit tzinfo instead.
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def ensure_aware(value: dt.datetime | None, assume: dt.tzinfo = UTC) -> dt.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=assume)
    return value


def to_kst_string(value: dt.datetime | None) -> str:
    """Final CSV representation. Empty string when there is no defensible time."""
    if value is None:
        return ""
    aware = ensure_aware(value)
    if aware is None:
        return ""
    return aware.astimezone(KST).isoformat()


def to_kst_display(value: dt.datetime | None) -> str:
    """Report format: '2026-08-21 07:43:58.056458 KST'. Empty when unknown."""
    if value is None:
        return ""
    aware = ensure_aware(value)
    if aware is None:
        return ""
    return aware.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S.%f") + " KST"


def sort_key(value: dt.datetime | None) -> tuple[int, float]:
    """Deterministic ordering that pushes unknown timestamps to the end."""
    aware = ensure_aware(value)
    if aware is None:
        return (1, 0.0)
    return (0, aware.timestamp())
