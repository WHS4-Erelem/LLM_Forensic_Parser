"""시각 해석, 발췌, 민감정보 마스킹 유틸."""

import re
from datetime import datetime, timezone

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?"
    r"(Z|[+-]\d{2}:?\d{2})?$")


def parse_any_time(value):
    """다양한 표기의 시각을 UTC ISO8601 로. 반환 (iso|None, format_desc, note)."""
    if value is None:
        return None, None, "값 없음"
    if isinstance(value, bool):
        return None, None, "불리언 값은 시각이 아님"
    if isinstance(value, (int, float)):
        v = float(value)
        # epoch 초 / 밀리초 / 마이크로초 자동 판별 (1990~2100 범위로 검증)
        for div, desc in ((1.0, "epoch_seconds"), (1e3, "epoch_milliseconds"),
                          (1e6, "epoch_microseconds"), (1e9, "epoch_nanoseconds")):
            try:
                dt = datetime.fromtimestamp(v / div, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
            if 1990 <= dt.year <= 2100:
                return _iso(dt), desc, None
        return None, None, "수치 시각을 해석 가능한 범위로 변환 실패"
    if not isinstance(value, str):
        return None, None, "지원하지 않는 시각 타입: %s" % type(value).__name__

    s = value.strip()
    m = _ISO_RE.match(s)
    if m:
        tz = m.group(8)
        base = s
        if tz is None:
            # 타임존 표기 없음 — UTC 로 단정하지 않고 naive 로 보존
            return None, "ISO8601_naive", (
                "타임존 표기가 없어 UTC 로 단정하지 않음 (원본값 보존)")
        norm = base.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", norm):
            norm = norm[:-2] + ":" + norm[-2:]
        try:
            dt = datetime.fromisoformat(norm)
        except ValueError:
            return None, None, "ISO8601 파싱 실패"
        return _iso(dt.astimezone(timezone.utc)), "ISO8601", None
    return None, None, "알려진 시각 형식이 아님"


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def excerpt(text, limit=500):
    if text is None:
        return None
    if not isinstance(text, str):
        text = repr(text)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[:limit] + "…[%d자 중 %d자]" % (len(text), limit)


# --- 민감정보 마스킹 -------------------------------------------------------
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}")
_SK_RE = re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,})")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                     re.S)
_SENSITIVE_KEYS = {
    "access_token", "id_token", "refresh_token", "token", "api_key", "apikey",
    "openai_api_key", "secret", "client_secret", "password", "cookie", "cookies",
    "authorization", "private_key", "session_token",
}


def mask_text(text):
    """로그·출력용 문자열에서 토큰/키를 마스킹."""
    if not isinstance(text, str):
        return text
    text = _PEM_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _SK_RE.sub("[REDACTED_API_KEY]", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    return text


def redact(obj, _depth=0):
    """JSON 구조에서 인증 토큰·쿠키·개인키 값을 제거하고 메타만 남긴다."""
    if _depth > 24:
        return "[REDACTED_DEPTH_LIMIT]"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                out[k] = _describe_secret(v)
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj


def _describe_secret(v):
    if isinstance(v, str):
        return {"_redacted": True, "length": len(v),
                "prefix": v[:3] + "…" if len(v) > 6 else "…"}
    if v is None:
        return None
    return {"_redacted": True, "type": type(v).__name__}
