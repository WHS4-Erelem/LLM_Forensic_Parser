#!/usr/bin/env python3
"""Gemini Web forensic-image/artifact parser; Python 3.10+.

Image mode requires pytsk3; EWF additionally requires pyewf (libewf-python).
BitLocker partitions additionally require dissect.fve and dissect.ntfs. Only an
image-internal Clear Key is supported; external credentials are not accepted.
Decrypted reads are partition-relative and read-only;
no full decrypted image is created. States are in JSON partition_status detail.
Profile mode still uses only the standard library. Dependency installation is
external to this script; there is no automatic install, mount, or image write.

Only list[dict] is the primary result. Status/inventory records use the same
schema as findings and have detail.record_type to distinguish them. Binary artifacts keep the conservative raw-scan fallback, but when ccl_chromium_reader
is available the parser first performs native Chromium Cache / IndexedDB / Local Storage /
Sessions decoding from the private staged profile.  Decoded Gemini HTTP bodies are decompressed
and passed into the existing f.req / wrb.fr / hNvQHb / StreamGenerate decoders before the raw
scanner runs. The analyst
CSV summarizes forensic findings into two analyst-facing CSVs.  The CSV headers and row semantics follow the team's
reference outputs (Son Seonim sample): timeline.csv uses the seven English field
names Model/Timestamp/User_behavior/Behavior_details /Verdict/Artifact_path/Artifact_details ,
and recovered_conversations.csv uses the ten-field conversation schema. Final CSV semantics
are intentionally strict for team integration: timeline.csv contains user-action events/candidates,
while recovered_conversations.csv contains only structurally recovered persistent message content.
Gemini History titles are retained as conversation metadata and may be used only to correlate a
structured cid-less request payload to a unique conversation; titles are never promoted to message bodies. Detection/coverage
rules are declared for every agreed Gemini Web
project action; actions without sufficient local evidence remain NOT_OBSERVED/INCONCLUSIVE rather than
being fabricated. Raw Session/Cache/LevelDB hits, coverage, offsets and parser-status records remain in
gemini_results.json (and optional coverage.csv with --debug-output). Unrelated
Chrome downloads/Recycle Bin rows remain in JSON. No unstructured raw string hit or History title is promoted to a recovered chat or a confirmed
prompt; recovered conversation rows require structured message semantics or a narrowly correlated
structured Gemini request payload. History/Sessions metadata and body recovery are reported separately.

Evidence files are opened only for reading. SQLite opens private temporary
copies, including WAL/rollback journals, never the evidence database itself.
Live copies cannot guarantee an atomic acquisition; use a collected snapshot
for evidentiary work. Ordinary reads can affect OS-managed access timestamps;
use read-only mounted/collected evidence when preservation of those matters.

SQLite WAL rationale: https://www.sqlite.org/wal.html
EWF adapter: https://github.com/libyal/libewf/wiki/Python-development
"""

from __future__ import annotations

import argparse
import bisect
import configparser
import csv
import gzip
import io
import hashlib
import html
import importlib
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import zlib
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath, PurePosixPath
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit


FIELDS = ("service", "environment", "timestamp", "action_candidate", "artifact",
          "observation", "detail", "source_path", "source_locator",
          "evidence_level", "status", "error")
# 2026-09-19 팀 회의에서 합의한 Timeline 최소 공통 필드.
# 서비스별 추가 내부 정보는 lossless JSON에 보존하고, CSV는 통합하기 쉬운 최소 형식으로 출력한다.
TIMELINE_FIELDS = ("Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict", "Artifact_path", "Artifact_details ")

# 2026-09-20 team/reference Conversation schema.  Keep these names exactly so every
# service parser can be merged without per-parser header translation.
CONVERSATION_FIELDS = ("Model", "timestamp", "conversation_uuid", "conversation_title",
                       "message_uuid", "parent_message_uuid", "message order", "role",
                       "content", "Artifact_path")
PARSER_VERSION = "1.4.8.6-bitlocker-clear-key"
OUTPUT_CONTRACT_VERSION = "2026-09-team-v1"
COVERAGE_FIELDS = ("Model", "Scope", "Item", "Status", "Reason", "Artifact_path", "Artifact_details")
TEAM_VERDICTS = {"확정", "의심"}
TEAM_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST$")
# Final timeline behaviors.  Raw strings/settings/cookies are evidence, not user behaviors.
# 팀 합의 Gemini Web 행위 + 상세 실험의 첨부/생성 이미지 삭제 행위 + 분석 편의 보조 행위
PROJECT_ACTIONS = (
    "로그인", "로그아웃", "계정 전환", "새로운 대화 생성", "기존 대화 삭제",
    "대화 수정", "대화 재시도", "사용자 프롬프트 입력/전송", "사용자 프롬프트 삭제",
    "이미지 업로드", "이미지 업로드 삭제", "문서 업로드", "문서 업로드 삭제", "문서 다운로드",
    "이미지 생성 요청", "생성 이미지 다운로드", "생성 이미지 다운로드 삭제",
    "대화 데이터 Export", "공유 링크 생성",
    "모델 변경", "계정 이름 변경", "임시 채팅 사용", "브라우저 시크릿 모드",
    "방문기록 삭제", "캐시 삭제",
)
# Timeline User_behavior values are restricted to the team's integration/user_behaviors.txt names.
# Service-specific/raw helper labels stay in JSON/Behavior_details and never leak into timeline.csv.
TEAM_BEHAVIORS = set(PROJECT_ACTIONS) | {
    "파일 다운로드",
}
# Artifact families inspected for each action. Used only for optional coverage/debug output.
ACTION_COVERAGE_ARTIFACTS = {
    "로그인": {"Chrome History", "Chrome Cookies", "Chrome Preferences"},
    "로그아웃": {"Chrome History", "Chrome Local Storage", "Chrome Session Storage"},
    "계정 전환": {"Chrome History", "Chrome Preferences", "Chrome Local Storage"},
    "새로운 대화 생성": {"Chrome Cache", "Chrome Sessions", "Chrome Local Storage", "Chrome IndexedDB", "Chrome Service Worker"},
    "기존 대화 삭제": {"Chrome Cache", "Chrome Local Storage", "Chrome IndexedDB", "Chrome Service Worker"},
    "대화 수정": {"Chrome Cache", "Chrome Sessions", "Chrome Local Storage", "Chrome Service Worker"},
    "대화 재시도": {"Chrome Cache", "Chrome Sessions", "Chrome Service Worker"},
    "사용자 프롬프트 입력/전송": {"Chrome Cache", "Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage", "Chrome Service Worker"},
    "사용자 프롬프트 삭제": {"Chrome History", "Chrome Cookies", "Chrome Local Storage", "Chrome Service Worker"},
    "이미지 업로드": {"Chrome Cache", "Chrome History", "Chrome Local Storage", "Chrome Service Worker"},
    "문서 업로드": {"Chrome Cache", "Chrome History", "Chrome Local Storage", "Chrome Service Worker"},
    "이미지 업로드 삭제": {"Chrome Cache", "Chrome Local Storage", "Chrome Service Worker"},
    "문서 업로드 삭제": {"Chrome Cache", "Chrome Local Storage", "Chrome Service Worker"},
    "문서 다운로드": {"Chrome History", "Zone.Identifier"},
    "이미지 생성 요청": {"Chrome Cache", "Chrome Session Storage", "Chrome Sessions", "Chrome Service Worker"},
    "생성 이미지 다운로드": {"Chrome History", "Zone.Identifier"},
    "생성 이미지 다운로드 삭제": {"Windows Recycle Bin", "Chrome History"},
    "대화 데이터 Export": {"Chrome History", "Chrome Session Storage", "Chrome Cache", "Chrome Service Worker"},
    "공유 링크 생성": {"Chrome History", "Chrome Cache", "Chrome Service Worker"},
    "모델 변경": {"Chrome Cache", "Chrome Sessions", "Chrome Local Storage", "Chrome Service Worker"},
    "계정 이름 변경": {"Chrome History", "Chrome Preferences"},
    "임시 채팅 사용": {"Chrome Sessions", "Chrome Cache", "Chrome History", "Chrome Service Worker"},
    "브라우저 시크릿 모드": {"Chrome Sessions", "Chrome History", "Chrome Preferences"},
    "방문기록 삭제": {"Chrome History", "Forensic Image"},
    "캐시 삭제": {"Chrome Cache", "Chrome Preferences", "Forensic Image"},
}
STATUSES = {"success", "artifact_not_found", "no_relevant_trace", "partial",
            "unsupported", "locked_database", "parse_error", "skipped"}
UTC = timezone.utc
KST = timezone(timedelta(hours=9))
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
CHUNK = 1024 * 1024
CONTEXT_BYTES = 2048
OVERLAP = 262144
MAX_PROTOCOL_TEXT = 8 * 1024 * 1024
AGGRESSIVE_PROMPT_CONTEXT = 64 * 1024
AGGRESSIVE_PROMPT_MAX_PER_FILE = 256
URL_RE = re.compile(r"https?://[^\s\x00-\x20<>\"'`\\]+", re.I)
DOMAIN_RE = re.compile(r"(?<![a-z0-9_.-])gemini\.google\.com(?![a-z0-9_.-])", re.I)
APP_RE = re.compile(r"/app/([A-Za-z0-9_-]{1,256})(?=[/?#\s\x00\"'<>]|$)")
PREF_RE = re.compile(r"gemini|google|account|cache|clear_data|content_settings|site_engagement", re.I)
SECRET_RE = re.compile(r"password|secret|token|credential|encrypted|cookie_value", re.I)
IMAGE_SUFFIXES = {".dd", ".img", ".raw", ".e01", ".001"}
SPLIT_RAW_RE = re.compile(r"^(?P<stem>.+)\.(?P<num>\d{3})$")

# Conservative semantic signatures. They are evaluated only on Gemini-scoped bounded
# context, explicit History URLs, or structured preference fields. A keyword match is
# candidate/support evidence, not automatic proof of the user action.
UPLOAD_FILE_RE = re.compile(r"(?i)([A-Za-z0-9가-힣 _().\-]{1,180}\.(?:png|jpe?g|gif|webp|bmp|heic|avif|pdf|docx?|hwp[x]?|txt|rtf|pptx?|xlsx?|csv|zip|py|c|cpp|java|json))(?=$|[\s\"\'<>),;\]\}])")
IMAGE_FILE_RE = re.compile(r"(?i)\.(?:png|jpe?g|gif|webp|bmp|heic|avif)$")
DOCUMENT_FILE_RE = re.compile(r"(?i)\.(?:pdf|docx?|hwp[x]?|txt|rtf|pptx?|xlsx?|csv|zip|py|c|cpp|java|json)$")
MODEL_VALUE_RE = re.compile(r"(?i)\b(gemini[-_ ]?(?:\d+(?:\.\d+)?|pro|flash|ultra|advanced|thinking)[A-Za-z0-9_.+ -]{0,40})\b")
EXPLICIT_SEMANTIC_RULES = (
    ("conversation_delete", re.compile(r"(?i)(?:delete|remove|trash)[_ .:-]{0,16}(?:conversation|chat)|(?:conversation|chat)[_ .:-]{0,16}(?:delete|remove|trash)")),
    ("conversation_edit", re.compile(r"(?i)(?:edit|modify)[_ .:-]{0,16}(?:message|conversation|prompt)|(?:message|conversation|prompt)[_ .:-]{0,16}(?:edit|modify)")),
    ("conversation_retry", re.compile(r"(?i)(?:retry|regenerate|redo)[_ .:-]{0,16}(?:response|answer|message|conversation)?|(?:response|answer)[_ .:-]{0,16}(?:retry|regenerate|redo)")),
    ("attachment_remove", re.compile(r"(?i)(?:remove|delete|detach)[_ .:-]{0,16}(?:attachment|upload|file)|(?:attachment|upload|file)[_ .:-]{0,16}(?:remove|delete|detach)")),
    ("image_generation", re.compile(r"(?i)(?:image[_ -]?generation|generate[_ -]?image|generated[_ -]?image|imagegen(?:eration)?|imagen[_ -]?(?:request|result))")),
    ("temporary_chat", re.compile(r"(?i)(?:is[_ -]?temporary\s*[:=]\s*true|temporary[_ -]?chat|temp[_ -]?chat|ephemeral[_ -]?chat)")),
)

# Findings produced from raw/static/browser-state heuristics remain useful analyst clues, but
# they are not final user-behavior events.  Keep them in gemini_results.json / coverage and
# require event-specific or protocol-structured evidence before Timeline promotion.
SUPPORTING_ONLY_ACTIONS = {
    "prompt_send_candidate",
    "conversation_delete_candidate", "conversation_edit_candidate",
    "conversation_retry_candidate", "temporary_chat_candidate",
    "attachment_remove_candidate", "image_generation_candidate",
    "image_upload_candidate", "document_upload_candidate",
    "model_change_candidate", "document_download_candidate",
    "generated_image_download_candidate", "share_link_candidate",
    "prompt_delete_candidate", "data_export_candidate",
    "account_name_change_candidate", "incognito_mode_candidate",
    "history_clear_candidate", "cache_clear_candidate",
}
# Browser-level privacy/cleanup actions are intentionally NOT derived from generic raw keywords.
# A Session/Tabs file can contain multiple tabs (e.g. Gemini + chrome://settings/clearBrowserData)
# in one bounded byte window, which proves neither that history/cache deletion executed nor that
# incognito mode was used.  History/cache clear are emitted only by conservative before/after
# comparison (or future direct deletion evidence); incognito stays coverage-only until an explicit
# event-specific persisted record is available.


def safe_value(value):
    """Make schema variants (including SQLite BLOBs) JSON representable."""
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value), "hex_prefix": value[:64].hex()}
    if isinstance(value, dict):
        return {str(k): safe_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_value(v) for v in value]
    if isinstance(value, float) and not (-float("inf") < value < float("inf")):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def normalize_timestamp(raw, kind="chrome"):
    """Preserve raw values; avoid floating point for WebKit and FILETIME."""
    result = {"raw": safe_value(raw), "utc": None, "kst": None}
    if raw is None or raw == 0 or raw == "0" or raw == "":
        return result
    try:
        if isinstance(raw, bool) or not isinstance(raw, (str, int)):
            raise ValueError("timestamp must be an integer or integer string")
        value = int(raw)
        if value < 0:
            raise ValueError("negative timestamp")
        if kind == "chrome":
            dt = CHROME_EPOCH + timedelta(microseconds=value)
        elif kind == "filetime":
            dt = CHROME_EPOCH + timedelta(microseconds=value // 10)
        elif kind == "unix_ns":
            dt = UNIX_EPOCH + timedelta(microseconds=value // 1000)
        else:
            raise ValueError("unknown timestamp format: " + kind)
        result["utc"] = dt.isoformat().replace("+00:00", "Z")
        result["kst"] = dt.astimezone(KST).isoformat()
    except (ValueError, TypeError, OverflowError) as exc:
        result["error"] = str(exc)
    return result


def normalize_team_kst_timestamp(value):
    """Convert an already validated team-format KST timestamp into the internal timestamp dict.

    Gemini READ_CHAT can expose per-turn Unix timestamps even when the surrounding Cache/Session
    record has no trustworthy browser-record time.  Only the exact team KST format is accepted;
    ambiguous values remain unavailable rather than being guessed.
    """
    text = str(value or "").strip()
    if not TEAM_TIMESTAMP_RE.fullmatch(text):
        return normalize_timestamp(None)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f KST").replace(tzinfo=KST)
    except (TypeError, ValueError):
        return normalize_timestamp(None)
    return {
        "raw": text,
        "utc": parsed.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "kst": parsed.isoformat(),
    }


def chrome_integer(raw):
    return int(raw) if normalize_timestamp(raw).get("utc") else None


def url_host(url):
    try:
        parsed = urlsplit(str(url))
        if parsed.scheme.lower() not in ("http", "https"):
            return ""
        return (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


def is_gemini_url(url):
    return url_host(url) == "gemini.google.com"


def conversation_id(url):
    if not is_gemini_url(url):
        return None
    match = re.match(r"^/app/([^/]+)", urlsplit(url).path)
    return unquote(match.group(1)) if match else None


# Optional native Chromium decoding.  The dependency is deliberately lazy so the parser keeps
# its v1.2 raw-scan behavior when the integration environment has not installed CCL yet.
# The pinned version/commit matches the Claude Web parser reviewed for this project.
CCL_EXPECTED_VERSION = "0.3.18"
CCL_EXPECTED_COMMIT = "ef840de30221c4d65bc96d2f4d9057e9ef2f526d"
_CCL_MODULES = None
_CCL_IMPORT_ATTEMPTED = False
_CCL_IMPORT_ERROR = None
DEEP_MAX_DECODED_BYTES = 256 * 1024 * 1024
DEEP_MAX_DECODE_RATIO = 400


def _load_ccl_modules():
    """Load the Chromium container readers lazily; return a module dict or None."""
    global _CCL_MODULES, _CCL_IMPORT_ATTEMPTED, _CCL_IMPORT_ERROR
    if _CCL_IMPORT_ATTEMPTED:
        return _CCL_MODULES
    _CCL_IMPORT_ATTEMPTED = True
    try:
        package = importlib.import_module("ccl_chromium_reader")
        _CCL_MODULES = {
            "package": package,
            "cache": importlib.import_module("ccl_chromium_reader.ccl_chromium_cache"),
            "indexeddb": importlib.import_module("ccl_chromium_reader.ccl_chromium_indexeddb"),
            "local_storage": importlib.import_module("ccl_chromium_reader.ccl_chromium_localstorage"),
            "session_storage": importlib.import_module("ccl_chromium_reader.ccl_chromium_sessionstorage"),
            "leveldb": importlib.import_module("ccl_chromium_reader.storage_formats.ccl_leveldb"),
            "snss": importlib.import_module("ccl_chromium_reader.ccl_chromium_snss2"),
        }
        _CCL_IMPORT_ERROR = None
    except Exception as exc:
        _CCL_MODULES = None
        _CCL_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    return _CCL_MODULES


def _ccl_get_attr(obj, *names, default=None):
    if obj is None:
        return default
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj.get(name)
        if hasattr(obj, name):
            try:
                return getattr(obj, name)
            except Exception:
                continue
    return default


def _ccl_safe_str(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    try:
        return str(value)
    except Exception:
        return ""


def _ccl_location_str(location):
    if location is None:
        return ""
    source = _ccl_get_attr(location, "source_file", "file_name", default="")
    offset = _ccl_get_attr(location, "offset", default=None)
    if source or offset is not None:
        return f"{_ccl_safe_str(source)}@{offset}"
    return _ccl_safe_str(location)


def _ccl_location_path(location, root):
    """Resolve a CCL source-file locator to the staged file when it is safely inside root."""
    source = _ccl_safe_str(_ccl_get_attr(location, "source_file", "file_name", default="")).strip()
    root = Path(root)
    if not source:
        return root
    candidate = Path(source)
    if not candidate.is_absolute():
        candidate = root / candidate.name
    try:
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    except OSError:
        pass
    return root


def _ccl_header_pairs(meta):
    attrs = _ccl_get_attr(meta, "http_header_attributes", default=[]) or []
    output = []
    for item in attrs:
        try:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                name, value = item[0], item[1]
            elif isinstance(item, dict):
                name, value = item.get("name") or item.get("key"), item.get("value")
            else:
                name = _ccl_get_attr(item, "name", "key", default=None)
                value = _ccl_get_attr(item, "value", default=None)
            if name is not None and value is not None:
                output.append((_ccl_safe_str(name).strip().lower(), _ccl_safe_str(value).strip()))
        except Exception:
            continue
    return output


def _ccl_header_value(meta, name):
    target = str(name).casefold()
    values = [value for key, value in _ccl_header_pairs(meta) if key == target]
    return ", ".join(values) if values else None


def _deep_decode_http_body(data, content_encoding=None):
    """Decode HTTP Content-Encoding with hard size/ratio guards; never guess plaintext."""
    if not isinstance(data, (bytes, bytearray)):
        return None, [], "body is not bytes"
    raw = bytes(data)
    encodings = [x.strip().lower() for x in str(content_encoding or "").split(",") if x.strip()]
    if not encodings:
        if raw.startswith(b"\x1f\x8b"):
            encodings = ["gzip"]
        elif raw.startswith(b"\x28\xb5\x2f\xfd"):
            encodings = ["zstd"]
    decoded = raw
    applied = []
    try:
        for enc in reversed(encodings):
            if enc in ("", "identity"):
                continue
            if enc in ("gzip", "x-gzip"):
                decoded = gzip.decompress(decoded)
            elif enc in ("deflate", "x-deflate"):
                try:
                    decoded = zlib.decompress(decoded)
                except zlib.error:
                    decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
            elif enc == "br":
                try:
                    brotli = importlib.import_module("brotli")
                except Exception as exc:
                    return None, applied, f"brotli unavailable: {exc}"
                decoded = brotli.decompress(decoded)
            elif enc in ("zstd", "zstandard"):
                try:
                    zstandard = importlib.import_module("zstandard")
                except Exception as exc:
                    return None, applied, f"zstd unavailable: {exc}"
                dctx = zstandard.ZstdDecompressor()
                try:
                    decoded = dctx.decompress(decoded)
                except Exception:
                    with dctx.stream_reader(io.BytesIO(decoded)) as reader:
                        decoded = reader.read(DEEP_MAX_DECODED_BYTES + 1)
            else:
                return None, applied, f"unsupported content-encoding: {enc}"
            applied.append(enc)
            if len(decoded) > DEEP_MAX_DECODED_BYTES:
                return None, applied, f"decoded body exceeds {DEEP_MAX_DECODED_BYTES} bytes"
            if len(raw) and len(decoded) // max(1, len(raw)) > DEEP_MAX_DECODE_RATIO:
                return None, applied, "decoded/raw size ratio exceeds guard"
    except Exception as exc:
        return None, applied, f"{type(exc).__name__}: {exc}"
    return decoded, applied, None


def _deep_decode_text(data, content_type=None):
    """Decode only plausible text; binary bodies are not forced through latin-1."""
    if not isinstance(data, (bytes, bytearray)):
        return None, "not-bytes"
    blob = bytes(data)
    if not blob:
        return "", "empty"
    content_type = str(content_type or "")
    charset = None
    match = re.search(r"charset\s*=\s*[\"']?([^;\"']+)", content_type, re.I)
    if match:
        charset = match.group(1).strip()
    candidates = [charset] if charset else []
    candidates += ["utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"]
    for encoding in dict.fromkeys(x for x in candidates if x):
        try:
            text = blob.decode(encoding)
        except Exception:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if not text or printable / max(1, len(text)) >= 0.85:
            return text, encoding
    return None, "binary/unreadable"


def _cache_key_gemini_url(key):
    """Return the actual Gemini URL embedded in a Chromium cache key, never a linked URL in a body."""
    text = _ccl_safe_str(key)
    for match in re.finditer(r"https?://[^\s\x00<>\"']+", text, re.I):
        candidate = match.group(0).rstrip(")],;}")
        if is_gemini_url(candidate):
            return candidate
    return None


def _gemini_cache_endpoint_kind(url):
    """Classify a Gemini-owned cache key without claiming that it contains a conversation body."""
    try:
        parsed = urlsplit(str(url or ""))
    except Exception:
        return "unknown"
    path = (parsed.path or "").casefold()
    query = (parsed.query or "").casefold()
    if "batchexecute" in path or "batchexecute" in query:
        return "batchexecute"
    if "streamgenerate" in path or "streamgenerate" in query:
        return "streamgenerate"
    if "/_/bardchatui/" in path or "bardchatui" in path:
        return "bardchatui"
    if re.match(r"^/app/[^/]+", parsed.path or "", re.I):
        return "conversation_page"
    if path in ("", "/"):
        return "gemini_root"
    if any(token in path for token in ("/static/", "/images/", "/favicon", "/robots.txt")):
        return "static_asset"
    return "other_gemini"


def _ccl_cache_stream_state(cache, raw_key):
    """Best-effort forensic description of a cache entry's four blockfile streams.

    CCL exposes the response body through stream 1.  When that stream is absent we keep
    the fact explicit rather than silently treating it as an empty decoded body.  This
    helper intentionally does not read extra streams as message evidence.
    """
    out = {"entry_available": False, "stream_sizes": [], "stream_initialized": []}
    try:
        entry = cache[raw_key]
    except Exception as exc:
        out["entry_error"] = error_text(exc)
        return out
    out["entry_available"] = True
    sizes = _ccl_get_attr(entry, "data_sizes", default=()) or ()
    addrs = _ccl_get_attr(entry, "data_addrs", default=()) or ()
    try:
        out["stream_sizes"] = [int(x) for x in list(sizes)[:4]]
    except Exception:
        out["stream_sizes"] = [_ccl_safe_str(x) for x in list(sizes)[:4]]
    initialized = []
    for addr in list(addrs)[:4]:
        try:
            initialized.append(bool(_ccl_get_attr(addr, "is_initialized", default=False)))
        except Exception:
            initialized.append(False)
    out["stream_initialized"] = initialized
    state = _ccl_get_attr(entry, "state", default=None)
    if state is not None:
        out["entry_state"] = _ccl_safe_str(state)
    created = _ccl_get_attr(entry, "creation_time", default=None)
    if created is not None:
        out["creation_time"] = _ccl_safe_str(created)
    return out


def history_relevance(url):
    """Classify URLs relevant to the Gemini action rules without retaining unrelated Google browsing."""
    if is_gemini_url(url):
        return "gemini_url"
    try:
        parsed = urlsplit(str(url))
        host = (parsed.hostname or "").lower().rstrip(".")
        path = (parsed.path or "").lower()
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        lowered = str(url).lower()
    except (ValueError, TypeError):
        return None
    if host == "takeout.google.com":
        return "google_takeout"
    if host == "myactivity.google.com":
        return "google_myactivity"
    if host == "myaccount.google.com" and ("/profile/name" in path or "/personal-info" in path):
        return "google_account_name"
    if host == "accounts.google.com":
        # Google sign-in URLs are shared by many services (Drive, Claude, LM Studio, etc.).
        # Attribute the flow to Gemini only when the URL itself carries an explicit Gemini
        # destination/origin.  Generic /signin/, authuser=, or ServiceLogin markers alone
        # are insufficient and previously caused cross-service false positives.
        values = " ".join(str(v) for v in query.values()).lower()
        explicit_gemini_target = (
            "gemini.google.com" in values
            or "bard.google.com" in values
            or "gemini.google.com" in lowered
            or "bard.google.com" in lowered
        )
        if explicit_gemini_target:
            return "google_account_url_with_gemini_reference"
    if host == "support.google.com" and "gemini" in lowered:
        return "google_gemini_support"
    return None


def within(path, root):
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def is_link(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def exception_status(exc):
    if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in (32, 33):
        return "locked_database"
    if isinstance(exc, sqlite3.OperationalError) and any(
            term in str(exc).lower() for term in ("locked", "busy")):
        return "locked_database"
    return "parse_error"


def error_text(exc):
    return f"{type(exc).__name__}: {exc}"


class GeminiParser:
    ARTIFACTS = {
        "history": "Chrome History", "sessions": "Chrome Sessions",
        "cookies": "Chrome Cookies", "preferences": "Chrome Preferences",
        "secure_preferences": "Chrome Secure Preferences", "cache": "Chrome Cache",
        "local_storage": "Chrome Local Storage", "session_storage": "Chrome Session Storage",
        "indexeddb": "Chrome IndexedDB", "service_worker": "Chrome Service Worker",
        "conversation_scope": "Gemini Conversation Recovery Scope", "recycle_bin": "Windows Recycle Bin",
    }

    def __init__(self, profile_path, user_root=None, *, evidence_root=None,
                 correlation_seconds=300, max_binary_bytes=0, max_matches_per_file=200,
                 max_files=0, max_json_bytes=64 * 1024 * 1024, verbose=False,
                 image_mode=None, temp_root=None, keep_temp=False, max_extracted_bytes=0,
                 deep_recovery=True):
        self.profile_path = Path(profile_path).expanduser().absolute()
        self.user_root = Path(user_root).expanduser().absolute() if user_root else None
        self.evidence_root = Path(evidence_root).expanduser().absolute() if evidence_root else None
        if correlation_seconds < 0 or max_binary_bytes < 0 or max_files < 0:
            raise ValueError("limits and correlation_seconds must be nonnegative")
        if max_matches_per_file < 1 or max_json_bytes < 1:
            raise ValueError("max_matches_per_file and max_json_bytes must be positive")
        self.correlation_seconds = correlation_seconds
        self.max_binary_bytes = max_binary_bytes
        self.max_matches_per_file = max_matches_per_file
        self.max_files = max_files
        self.max_json_bytes = max_json_bytes
        self.verbose = verbose
        self.results = []
        self.artifacts = {}
        self.artifact_status = {}
        self._discovery_errors = {}
        self._expected = {}
        self._visits = []
        self._visit_times = []
        self._downloads = []
        self._source_files = set()
        self.image_mode = image_mode
        self.temp_root = temp_root
        self.keep_temp = keep_temp
        self.max_extracted_bytes = max_extracted_bytes
        self.deep_recovery = bool(deep_recovery)
        # True only for a Chrome profile staged from a read-only forensic image.
        # Used to avoid reporting live-copy race limitations for static image evidence.
        self._staged_from_forensic_image = False
        self._image_parser = None

    def _artifact_options(self):
        return {"correlation_seconds": self.correlation_seconds, "max_binary_bytes": self.max_binary_bytes,
                "max_matches_per_file": self.max_matches_per_file, "max_files": self.max_files,
                "max_json_bytes": self.max_json_bytes, "verbose": self.verbose,
                "deep_recovery": self.deep_recovery}

    def _say(self, text):
        if self.verbose:
            print(text, flush=True)

    def _emit(self, key, observation, *, detail=None, path=None, locator=None,
              timestamp=None, action=None, level="support", status="success", error=None):
        if status not in STATUSES or level not in {"direct", "support", "unconfirmed"}:
            raise ValueError("invalid schema status or evidence level")
        row = dict(zip(FIELDS, [
            "Gemini", "Web", timestamp or normalize_timestamp(None), action,
            self.ARTIFACTS.get(key, key), observation, safe_value(detail or {}),
            str(path) if path is not None else None, safe_value(locator or {}),
            level, status, error,
        ]))
        self.results.append(row)
        if path is not None:
            self._source_files.add(str(Path(path).absolute()).casefold())
        return row

    def _issue(self, key, path, error, *, status="parse_error", locator=None):
        return self._emit(key, "Artifact could not be fully analyzed",
                          detail={"record_type": "analysis_issue"}, path=path,
                          locator=locator, level="unconfirmed", status=status, error=error)

    def discover_artifacts(self):
        """Return existing paths; retain missing/inaccessible states separately."""
        p = self.profile_path
        expected = {
            "history": p / "History", "cookies": p / "Network" / "Cookies",
            "preferences": p / "Preferences", "secure_preferences": p / "Secure Preferences",
            "cache": p / "Cache" / "Cache_Data", "local_storage": p / "Local Storage" / "leveldb",
            "session_storage": p / "Session Storage", "indexeddb": p / "IndexedDB",
            "service_worker": p / "Service Worker", "sessions": p / "Sessions",
        }
        self.artifacts, self.artifact_status, self._discovery_errors = {}, {}, {}
        self._expected = expected
        directory_keys = {"cache", "local_storage", "session_storage", "indexeddb", "service_worker", "sessions"}
        for key, path in expected.items():
            try:
                info = path.stat()
                if not within(path, p) or is_link(path):
                    raise ValueError("linked artifact outside acquisition or reparse point skipped")
                valid = stat.S_ISDIR(info.st_mode) if key in directory_keys else stat.S_ISREG(info.st_mode)
                if not valid:
                    raise ValueError("artifact has an unexpected file type")
                if key == "sessions":
                    files = sorted(x for x in path.iterdir()
                                   if x.name.startswith(("Session_", "Tabs_")) and not is_link(x))
                    self.artifacts[key] = [str(x) for x in files if x.is_file()]
                    self.artifact_status[key] = "success" if self.artifacts[key] else "artifact_not_found"
                else:
                    self.artifacts[key] = str(path)
                    self.artifact_status[key] = "success"
            except FileNotFoundError:
                self.artifacts[key] = [] if key == "sessions" else None
                self.artifact_status[key] = "artifact_not_found"
            except (OSError, ValueError, RuntimeError) as exc:
                self.artifacts[key] = [] if key == "sessions" else None
                self.artifact_status[key] = "parse_error"
                self._discovery_errors[key] = error_text(exc)
        recycle_roots = []
        for root in (self.evidence_root, self.user_root):
            if root is None:
                continue
            candidate = root if root.name == "$Recycle.Bin" else root / "$Recycle.Bin"
            try:
                if stat.S_ISDIR(candidate.stat().st_mode) and not is_link(candidate) and within(candidate, root):
                    if str(candidate) not in recycle_roots:
                        recycle_roots.append(str(candidate))
            except FileNotFoundError:
                continue
            except OSError as exc:
                self._discovery_errors["recycle_bin"] = error_text(exc)
        self.artifacts["recycle_bin"] = recycle_roots
        self._expected["recycle_bin"] = (
            (self.evidence_root or self.user_root) / "$Recycle.Bin"
            if self.evidence_root or self.user_root else None)
        self.artifact_status["recycle_bin"] = (
            "parse_error" if "recycle_bin" in self._discovery_errors else
            "success" if recycle_roots else "artifact_not_found")
        return self.artifacts.copy()

    def parse(self) -> list[dict]:
        if self.image_mode is True or (self.image_mode is None and not self.profile_path.is_dir()
                                      and (self.profile_path.suffix.lower() in IMAGE_SUFFIXES or self.profile_path.is_file())):
            self._image_parser = GeminiImageParser(self.profile_path, temp_root=self.temp_root,
                                                  keep_temp=self.keep_temp, max_extracted_bytes=self.max_extracted_bytes,
                                                  **self._artifact_options())
            self.results = self._image_parser.parse()
            self._downloads = self._image_parser._downloads
            self._source_files = self._image_parser._source_files
            self.artifact_status = self._image_parser.artifact_status
            return self.results
        self.results, self._visits, self._visit_times, self._downloads = [], [], [], []
        self._source_files = set()
        self._say("[Artifact Discovery]")
        self.discover_artifacts()
        for key, state in self.artifact_status.items():
            self._say(f"[{'+' if state == 'success' else '-'}] {self.ARTIFACTS[key]}: {state}")
        self._say("[Parsing]")
        routines = [
            ("history", self._parse_history), ("sessions", self._parse_browser_artifact),
            ("cookies", self._parse_cookies), ("preferences", self._parse_preferences),
            ("secure_preferences", self._parse_preferences), ("cache", self._parse_browser_artifact),
            ("local_storage", self._parse_browser_artifact),
            ("session_storage", self._parse_browser_artifact), ("indexeddb", self._parse_browser_artifact),
            ("service_worker", self._parse_browser_artifact),
            ("recycle_bin", self._parse_recycle_bin),
        ]
        for key, routine in routines:
            start = len(self.results)
            state = self.artifact_status[key]
            if state == "success":
                try:
                    routine(key)
                except Exception as exc:
                    # The artifact boundary deliberately isolates unforeseen errors.
                    self._issue(key, self._expected[key], error_text(exc),
                                status=exception_status(exc) if key in {"history", "cookies"} else "parse_error")
                rows = self.results[start:]
                issues = {r["status"] for r in rows if r["status"] != "success"}
                findings = sum(r["detail"].get("record_type") == "finding" for r in rows)
                blocking_issues = issues - {"artifact_not_found", "no_relevant_trace"}
                if "partial" in blocking_issues or (findings and blocking_issues):
                    state = "partial"
                elif blocking_issues:
                    state = next((s for s in ("locked_database", "parse_error", "unsupported") if s in blocking_issues), "partial")
                else:
                    state = "success" if findings else "no_relevant_trace"
            else:
                findings = 0
            self.artifact_status[key] = state
            limitations = []
            if key in {"sessions", "cache", "local_storage", "session_storage", "indexeddb", "service_worker"}:
                limitations = ["Raw byte/string scan remains a fallback. Native Chromium decoding is attempted separately with ccl_chromium_reader when available.",
                               "No recoverable local record does not establish absence of service use."]
            self._emit(key, "Artifact analysis status", path=self._expected[key],
                       detail={"record_type": "analysis_status", "finding_count": findings,
                               "limitations": limitations}, status=state, level="unconfirmed",
                       error=self._discovery_errors.get(key))
            self._say(f"[{'+' if findings else '-'}] {self.ARTIFACTS[key]}: {findings} findings ({state})")
        # Semantic/correlation derivation must finish before recovery summaries are frozen.
        # This prevents JSON summary counts from describing an earlier view than the final CSV.
        self._derive_semantic_actions()
        self._emit_conversation_scope_summaries()
        return self.results

    def get_results(self) -> list[dict]:
        return self.results

    @contextmanager
    def _database_copy(self, path, key):
        """Never connect SQLite to the original, even in mode=ro (SHM risk).

        WAL and rollback journals are copied with the database. SHM is a
        transient index and is rebuilt only in the private working directory.
        Stat checks detect common live-copy races, but do not prove atomicity.
        """
        path = Path(path)
        def signature():
            data = {}
            for suffix in ("", "-wal", "-journal"):
                source = Path(str(path) + suffix)
                try:
                    s = source.stat()
                    if is_link(source) or not within(source, self.profile_path):
                        raise ValueError("unsafe database or sidecar path")
                    data[suffix] = (s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                except FileNotFoundError:
                    if not suffix:
                        raise
            return data
        with tempfile.TemporaryDirectory(prefix="gemini_sqlite_") as scratch:
            # tempfile only owns its new directory; no evidence is removed.
            for attempt in range(3):
                destination = Path(scratch) / str(attempt)
                destination.mkdir()
                before = signature()
                try:
                    for suffix in before:
                        shutil.copyfile(Path(str(path) + suffix), destination / (path.name + suffix))
                    after = signature()
                except FileNotFoundError:
                    if attempt == 2:
                        raise
                    continue
                if before == after:
                    break
            else:
                raise OSError("database or journal changed during all three copy attempts; acquire a stable snapshot")
            if "-wal" in before or "-journal" in before or attempt:
                staged_image = bool(getattr(self, "_staged_from_forensic_image", False))
                note_status = "success" if staged_image and attempt == 0 else "partial"
                limitation = (
                    "Database and available sidecars were staged from the same read-only forensic image "
                    "before isolated SQLite access; no live-source copy race applies."
                    if staged_image else
                    "Stable size/mtime checks do not guarantee an atomic live snapshot."
                )
                self._emit(key, "Database and available journals copied for isolated SQLite reading",
                           path=path, level="unconfirmed", status=note_status,
                           detail={"record_type": "acquisition_note", "copied_sidecars": [s for s in before if s],
                                   "copy_attempts": attempt + 1,
                                   "source_snapshot": "forensic_image_stage" if staged_image else "profile_copy",
                                   "limitation": limitation})
            connection = sqlite3.connect(str(destination / path.name), timeout=2)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA query_only=ON")
                checked = connection.execute("PRAGMA quick_check(1)").fetchone()
                if not checked or checked[0] != "ok":
                    raise sqlite3.DatabaseError("SQLite quick_check: " + str(checked[0] if checked else "no result"))
                yield connection
            finally:
                connection.close()

    @staticmethod
    def _columns(connection, table):
        quoted = '"' + table.replace('"', '""') + '"'
        # Views from an untrusted database are not treated as artifact tables.
        found = connection.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
        if not found or found[0] != "table":
            return set()
        return {r[1] for r in connection.execute("PRAGMA table_info(" + quoted + ")")}

    def _rows(self, connection, table, wanted, *, where="", params=()):
        columns = self._columns(connection, table)
        actual = [c for c in wanted if c in columns]
        if not actual:
            return
        select = ",".join('"' + c.replace('"', '""') + '"' for c in actual)
        sql = 'SELECT ' + select + ' FROM "' + table.replace('"', '""') + '"'
        if where:
            sql += " WHERE " + where
        for ordinal, row in enumerate(connection.execute(sql, params)):
            result = {c: None for c in wanted}
            result.update(dict(row))
            result["_query_row_index"] = ordinal
            yield result

    def _parse_history(self, key):
        path = Path(self.artifacts[key])
        with self._database_copy(path, key) as db:
            for routine in (self._history_visits, self._history_downloads):
                try:
                    routine(db, path)
                except Exception as exc:
                    self._issue(key, path, error_text(exc), status=exception_status(exc),
                                locator={"component": routine.__name__})

    def _history_visits(self, db, path):
        fields = ["id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"]
        columns = self._columns(db, "urls")
        if not {"id", "url"} <= columns:
            self._issue("history", path, "urls table or required id/url columns are missing",
                        status="unsupported", locator={"table": "urls"})
            return
        patterns = ("%gemini.google.com%", "%accounts.google.com%", "%myaccount.google.com%",
                    "%myactivity.google.com%", "%takeout.google.com%")
        where = " OR ".join("lower(url) LIKE ?" for _ in patterns)
        urls = {}
        for row in self._rows(db, "urls", fields, where=where, params=patterns):
            if history_relevance(row["url"]):
                urls[row["id"]] = row
        try:
            total_urls = int(db.execute("SELECT COUNT(*) FROM urls").fetchone()[0])
            table_names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            total_visits = int(db.execute("SELECT COUNT(*) FROM visits").fetchone()[0]) if "visits" in table_names else None
            self._emit("history", "Chrome History table inventory", path=path, level="unconfirmed",
                       detail={"record_type": "inventory", "urls_total": total_urls, "visits_total": total_visits,
                               "relevant_url_rows": len(urls),
                               "limitation": "Counts describe the current database only; a clear/delete operation requires a baseline or direct deletion evidence."})
        except sqlite3.Error as exc:
            self._issue("history", path, "History table inventory failed: " + error_text(exc), status="partial")
        visited = set()
        vcolumns = self._columns(db, "visits")
        visit_fields = ["id", "url", "visit_time", "from_visit", "transition", "visit_duration", "opener_visit"]
        if {"url", "visit_time"} <= vcolumns:
            ids = list(urls)
            for start in range(0, len(ids), 400):
                subset = ids[start:start + 400]
                for visit in self._rows(db, "visits", visit_fields,
                                        where='"url" IN (' + ",".join("?" for _ in subset) + ")", params=subset):
                    row = urls[visit["url"]]
                    visited.add(row["id"])
                    self._history_url_record(path, row, visit, columns, vcolumns)
        else:
            self._issue("history", path, "visits table or url/visit_time columns missing; using urls summaries",
                        status="unsupported", locator={"table": "visits"})
        for identifier, row in urls.items():
            if identifier not in visited:
                self._history_url_record(path, row, None, columns, vcolumns)
        self._visits.sort(key=lambda x: x["time"])
        self._visit_times = [x["time"] for x in self._visits]

    def _history_url_record(self, path, row, visit, columns, vcolumns):
        url = row["url"]
        cid = conversation_id(url)
        time = normalize_timestamp(visit["visit_time"] if visit else row["last_visit_time"])
        detail = {"record_type": "finding", "url": url, "title": row["title"],
                  "url_id": row["id"], "visit_count": row["visit_count"], "typed_count": row["typed_count"],
                  "conversation_id": cid, "last_visit_time": normalize_timestamp(row["last_visit_time"]),
                  "visit_time": normalize_timestamp(visit["visit_time"] if visit else None),
                  "relevance_basis": history_relevance(url), "timestamp_format": "chrome_microseconds_since_1601",
                  "missing_url_columns": sorted(set(row) - columns - {"_query_row_index"}),
                  "limitation": "Recorded navigation or URL summary does not prove conversation creation, a prompt, or intent."}
        locator = {"table": "visits" if visit else "urls", "id": visit["id"] if visit else row["id"],
                   "url_id": row["id"], "url": url}
        if visit:
            detail["visit"] = {k: v for k, v in visit.items() if not k.startswith("_")}
            detail["missing_visit_columns"] = sorted(set(visit) - vcolumns - {"_query_row_index"})
            locator["visit_time"] = visit["visit_time"]
        action = "conversation_access" if cid else "gemini_access_candidate"
        if history_relevance(url) != "gemini_url":
            action = "account_activity_candidate"
        self._emit("history", "Gemini-related visit record found" if visit else "Gemini-related URL summary found",
                   path=path, locator=locator, timestamp=time, detail=detail, action=action,
                   level="direct" if visit and is_gemini_url(url) else "support",
                   status="partial" if time.get("error") else "success", error=time.get("error"))
        integer = chrome_integer(visit["visit_time"]) if visit else None
        if integer is not None and is_gemini_url(url):
            self._visits.append({"time": integer, "url": url, "visit_id": visit["id"],
                                 "url_id": row["id"], "conversation_id": cid})

    def _nearby_visits(self, raw):
        value = chrome_integer(raw)
        if value is None or not self._visit_times:
            return [], 0
        window = int(self.correlation_seconds * 1000000)
        lo = bisect.bisect_left(self._visit_times, value - window)
        hi = bisect.bisect_right(self._visit_times, value + window)
        # Keep the closest twenty; retain the full count and declared window.
        nearby = sorted(self._visits[lo:hi], key=lambda r: abs(r["time"] - value))[:20]
        return [{"visit_id": r["visit_id"], "url_id": r["url_id"], "url": r["url"],
                 "conversation_id": r["conversation_id"], "timestamp": normalize_timestamp(r["time"]),
                 "delta_seconds": (value - r["time"]) / 1000000} for r in nearby], hi - lo

    def _history_downloads(self, db, path):
        fields = ["id", "target_path", "current_path", "start_time", "end_time", "received_bytes",
                  "total_bytes", "state", "danger_type", "interrupt_reason", "tab_url", "tab_referrer_url",
                  "referrer", "site_url", "mime_type", "original_mime_type"]
        columns = self._columns(db, "downloads")
        if "id" not in columns:
            self._issue("history", path, "downloads table or id column missing", status="unsupported",
                        locator={"table": "downloads"})
            return
        chains = {}
        ccolumns = self._columns(db, "downloads_url_chains")
        chain_status = "success"
        if {"id", "url"} <= ccolumns:
            if "chain_index" not in ccolumns:
                chain_status = "partial"
                self._issue("history", path, "downloads_url_chains.chain_index missing; chain order is unknown",
                            status="partial", locator={"table": "downloads_url_chains"})
            try:
                for row in self._rows(db, "downloads_url_chains", ["id", "chain_index", "url"]):
                    chains.setdefault(row["id"], []).append({
                        "download_id": row["id"], "chain_index": row["chain_index"], "url": row["url"],
                        "source_locator": {"table": "downloads_url_chains", "id": row["id"],
                                           "chain_index": row["chain_index"], "url": row["url"]}})
            except sqlite3.Error as exc:
                chain_status = "partial"
                self._issue("history", path, error_text(exc), status=exception_status(exc),
                            locator={"table": "downloads_url_chains"})
        else:
            chain_status = "unsupported"
            self._issue("history", path, "downloads_url_chains table or required columns missing",
                        status="unsupported", locator={"table": "downloads_url_chains"})
        examined = 0
        for download in self._rows(db, "downloads", fields):
            examined += 1
            try:
                chain = chains.get(download["id"], [])
                chain.sort(key=lambda r: (not isinstance(r["chain_index"], int),
                                          r["chain_index"] if isinstance(r["chain_index"], int) else 0))
                self._download_record(path, download, chain, columns, chain_status)
            except Exception as exc:
                self._issue("history", path, error_text(exc), locator={"table": "downloads", "id": download["id"]})
        # Only explicit URL/Zone linkage counts as Gemini-associated.  Pure temporal
        # proximity remains a supporting clue in JSON and is not counted as service attribution.
        associated_count = sum(
            1 for r in self._downloads
            if (r.get("detail") or {}).get("gemini_attribution") == "url_associated_candidate"
        )
        self._emit("history", "Chrome download records examined and preserved", path=path, level="unconfirmed",
                   detail={"record_type": "inventory", "downloads_examined": examined,
                           "downloads_retained": len(self._downloads),
                           "downloads_gemini_associated": associated_count,
                           "limitation": "All Chrome download records are preserved. Service attribution is separate and may remain unconfirmed."})

    def _download_record(self, path, download, chain, columns, chain_status):
        """Preserve every Chrome download record; classify Gemini attribution separately."""
        links = [(key, download[key]) for key in ("tab_url", "tab_referrer_url", "referrer", "site_url")]
        links.extend(("downloads_url_chains", r["url"]) for r in chain)
        basis = [{"type": field, "url": url} for field, url in links if is_gemini_url(url)]
        nearby, nearby_count = self._nearby_visits(download["start_time"])
        resolution = self.resolve_download_path(download["target_path"], download["current_path"])
        actual = Path(resolution["resolved_path"]) if resolution.get("resolved_path") else None
        zone = self._read_zone(actual) if actual else None
        if zone:
            for field in ("ReferrerUrl", "HostUrl"):
                if is_gemini_url(zone.get("values", {}).get(field)):
                    basis.append({"type": "Zone.Identifier." + field, "url": zone["values"][field]})

        if nearby and not basis:
            basis.append({"type": "temporal_proximity_only"})

        if any(item.get("type") != "temporal_proximity_only" for item in basis):
            attribution = "url_associated_candidate"
        elif basis:
            attribution = "temporal_candidate"
        else:
            attribution = "unlinked_chrome_download"

        raw_path = download["target_path"] or download["current_path"] or ""
        detail = {k: v for k, v in download.items() if not k.startswith("_")}
        detail.update({"record_type": "finding", "filename": PureWindowsPath(str(raw_path)).name,
                       "start_time": normalize_timestamp(download["start_time"]),
                       "end_time": normalize_timestamp(download["end_time"]),
                       "url_chain": chain, "url_chain_status": chain_status,
                       "missing_columns": sorted(set(download) - columns - {"_query_row_index"}),
                       "timestamp_format": "chrome_microseconds_since_1601", "relevance_basis": basis,
                       "nearby_gemini_visits": nearby, "nearby_visit_count": nearby_count,
                       "correlation_window_seconds": self.correlation_seconds,
                       "gemini_attribution": attribution,
                       "service_attribution": "candidate" if attribution == "url_associated_candidate" else "unconfirmed",
                       "limitation": (
                           "Temporal proximity to a Gemini visit is only a supporting clue and is not sufficient for Gemini service attribution."
                           if attribution == "temporal_candidate" else
                           "Association does not prove Gemini generated the file. A missing file does not prove deletion."
                           if attribution == "url_associated_candidate" else
                           "Chrome download record is preserved, but no Gemini-specific linkage was established from the examined local artifacts."
                       ),
                       **resolution})
        if actual:
            try:
                metadata = self._file_metadata(actual)
                sha256, stable = self._hash_file(actual)
                detail.update(file_size=metadata["file_size"], sha256=sha256,
                              file_metadata=metadata, file_unchanged_during_hash=stable)
                if not stable:
                    detail["file_error"] = "file metadata changed during hashing; hash is not a stable snapshot"
                total = download["total_bytes"]
                detail["size_matches_history_total"] = (
                    metadata["file_size"] == total if isinstance(total, int) and total >= 0 else None)
            except OSError as exc:
                detail["file_error"] = error_text(exc)
                detail["file_exists"] = None if isinstance(exc, PermissionError) else actual.is_file()
        else:
            detail.update(file_size=None, sha256=None)
        detail["zone_identifier"] = zone
        if not raw_path:
            detail["resolution_error"] = "download record has neither target_path nor current_path; file presence is unknown"
            detail["file_exists"] = None
        errors = [detail[k] for k in ("resolution_error", "file_error") if detail.get(k)]
        for value in (detail["start_time"], detail["end_time"]):
            if value.get("error"):
                errors.append(value["error"])

        associated = attribution == "url_associated_candidate"
        direct = (associated and detail.get("file_exists") is True and detail.get("sha256")
                  and detail.get("file_unchanged_during_hash") and resolution.get("path_field") == "target_path"
                  and detail.get("size_matches_history_total") is not False)
        if direct:
            level = "direct"
            action = "file_download"
        elif attribution == "url_associated_candidate":
            # Explicit Gemini URL/Zone linkage exists, but the local file proof is incomplete.
            level = "support"
            action = "file_download"
        elif attribution == "temporal_candidate":
            # Time proximity alone must never become a Gemini user-action Timeline event.
            # Preserve the Chrome record in JSON as a supporting candidate only.
            level = "support"
            action = "file_download_candidate"
        else:
            level = "unconfirmed"
            action = "file_download_candidate"

        observation = "Chrome History download record found; " + (
            "target file found" if actual and resolution.get("path_field") == "target_path" else
            "current-path file found (may be incomplete)" if actual else
            "downloaded_file_not_found" if resolution.get("file_exists") is False else "file presence could not be established")
        detail["download_record_exists"] = True
        record = self._emit("history", observation, path=path, locator={"table": "downloads", "id": download["id"]},
                            timestamp=detail["start_time"], detail=detail, action=action, level=level,
                            status="partial" if errors or chain_status != "success" else "success",
                            error="; ".join(errors) or None)
        self._downloads.append(record)
        if actual:
            self._source_files.add(str(actual.absolute()).casefold())
            self._emit("Zone.Identifier", "Download file Zone.Identifier examination", path=str(actual) + ":Zone.Identifier",
                       detail={"record_type": "finding" if zone and zone["status"] == "success" else "analysis_status",
                               "download_id": download["id"], "values": zone.get("values", {}) if zone else {},
                               "related_history_path": str(path),
                               "service_attribution": detail["service_attribution"],
                               "limitation": "ZoneId alone does not identify Gemini or establish download completion."},
                       locator={"stream": "Zone.Identifier", "section": "ZoneTransfer"},
                       level="support" if zone and zone["status"] == "success" and attribution != "unlinked_chrome_download" else "unconfirmed",
                       status=zone["status"] if zone else "artifact_not_found", error=zone.get("error") if zone else None)

    def resolve_download_path(self, target_path, current_path=None):
        """Map by complete user-relative/drive-relative paths, never basename.

        An explicit acquisition root disables fallback to the analyst's live
        original path. Ambiguous mappings are reported, never guessed. UNC,
        device paths, ADS paths, traversal and escaping links are rejected.
        """
        candidates, rejected, problems = [], [], []
        roots = [(self.user_root, "user_root"), (self.evidence_root, "evidence_root")]
        for field, value in (("target_path", target_path), ("current_path", current_path)):
            if not value:
                continue
            if not isinstance(value, str):
                rejected.append(field + ": non-string path")
                continue
            win = PureWindowsPath(value)
            if ("\x00" in value or ".." in win.parts or value.startswith(("\\\\", "//"))
                    or any(":" in part for part in win.parts[1:])):
                rejected.append(field + ": unsafe path")
                continue
            path_candidates = []
            if self.user_root or self.evidence_root:
                parts = list(win.parts[1:]) if win.drive else list(win.parts)
                if not win.is_absolute():
                    rejected.append(field + ": original Windows absolute path required for mapping")
                    continue
                users_at = next((i for i, part in enumerate(parts[:-1]) if part.lower() == "users"), None)
                for root, label in roots:
                    if root is None:
                        continue
                    if label == "user_root" and users_at is not None and len(parts) > users_at + 2:
                        tail = parts[users_at + 2:]
                        # --user-root denotes the acquired user directory; its
                        # name can intentionally differ from the original user.
                        path_candidates.append((root.joinpath(*tail), root, label + ":user_relative"))
                        if root.name.casefold() == "users":
                            path_candidates.append((root.joinpath(*parts[users_at + 1:]), root, label + ":users_tree"))
                    path_candidates.append((root.joinpath(*parts), root, label + ":drive_relative"))
                    path_candidates.append((root / win.drive.rstrip(":") / Path(*parts), root, label + ":drive_directory"))
            else:
                native = Path(value)
                if not native.is_absolute():
                    rejected.append(field + ": path cannot be resolved on this host without an acquisition root")
                    continue
                path_candidates.append((native, native.parent, "original_absolute_path"))
            existing, attempted = {}, []
            for candidate, root, method in path_candidates:
                attempted.append(str(candidate))
                try:
                    if not within(candidate, root):
                        rejected.append(str(candidate) + ": mapping escapes acquisition root")
                        continue
                    # Reject every reparse point along the relative path.
                    relative = candidate.absolute().relative_to(root.absolute())
                    walk = root
                    linked = is_link(root)
                    for part in relative.parts:
                        walk /= part
                        linked = linked or is_link(walk)
                    if linked:
                        rejected.append(str(candidate) + ": linked path skipped")
                        continue
                    info = candidate.stat()
                    if stat.S_ISREG(info.st_mode):
                        existing[str(candidate.resolve()).casefold()] = (candidate, method)
                except FileNotFoundError:
                    continue
                except (OSError, ValueError, RuntimeError) as exc:
                    problems.append(str(candidate) + ": " + error_text(exc))
            candidates.extend(attempted)
            if len(existing) > 1:
                return {"file_exists": None, "resolved_path": None, "path_field": field,
                        "resolution_candidates": list(existing), "resolution_error": "ambiguous path mapping; multiple files found"}
            if existing:
                chosen, method = next(iter(existing.values()))
                return {"file_exists": True, "resolved_path": str(chosen), "path_field": field,
                        "resolution_method": method, "resolution_candidates": candidates,
                        "resolution_error": "; ".join(problems + rejected) or None}
        return {"file_exists": None if rejected or problems else False, "resolved_path": None,
                "path_field": None, "resolution_candidates": candidates,
                "resolution_error": "; ".join(problems + rejected) or None}

    @staticmethod
    def _file_metadata(path):
        s = path.stat()
        birth = getattr(s, "st_birthtime_ns", None)
        if birth is None and os.name == "nt":
            birth = s.st_ctime_ns
        return {"filename": path.name, "file_size": s.st_size,
                "created_time": normalize_timestamp(birth, "unix_ns"),
                "modified_time": normalize_timestamp(s.st_mtime_ns, "unix_ns"),
                "timestamp_format": "unix_nanoseconds", "timestamp_role": "filesystem_metadata_not_user_action"}

    @staticmethod
    def _hash_file(path):
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(CHUNK):
                digest.update(block)
        after = path.stat()
        stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        return digest.hexdigest(), stable

    @staticmethod
    def _read_zone(path, *, data=None):
        result = {"status": "artifact_not_found", "values": {}, "error": None}
        if data is None and os.name != "nt":
            result.update(status="unsupported", error="NTFS ADS access requires Windows in profile mode")
            return result
        try:
            if data is None:
                with Path(str(path) + ":Zone.Identifier").open("rb") as stream:
                    data = stream.read(65537)
            if len(data) > 65536:
                raise ValueError("Zone.Identifier exceeds 64 KiB read limit")
            if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                text = data.decode("utf-16")
            else:
                try:
                    text = data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    text = data.decode("cp1252")
            ini = configparser.ConfigParser(interpolation=None, strict=False)
            ini.read_string(text)
            if not ini.has_section("ZoneTransfer"):
                raise ValueError("ZoneTransfer section missing")
            for name in ("ZoneId", "ReferrerUrl", "HostUrl"):
                result["values"][name] = ini.get("ZoneTransfer", name, fallback=None)
            zone_id = result["values"]["ZoneId"]
            if zone_id is not None:
                try:
                    result["values"]["ZoneId"] = int(zone_id)
                except ValueError:
                    result.update(status="partial", error="ZoneId is not an integer")
                    return result
            result["status"] = "success"
        except FileNotFoundError:
            return result
        except (OSError, UnicodeError, ValueError, configparser.Error) as exc:
            result.update(status="parse_error", error=error_text(exc))
        return result

    def _parse_cookies(self, key):
        path = Path(self.artifacts[key])
        fields = ["host_key", "name", "path", "creation_utc", "last_access_utc", "expires_utc",
                  "is_secure", "is_httponly", "top_frame_site_key", "has_cross_site_ancestor"]
        with self._database_copy(path, key) as db:
            columns = self._columns(db, "cookies")
            if "host_key" not in columns:
                self._issue(key, path, "cookies table or host_key missing", status="unsupported", locator={"table": "cookies"})
                return
            for row in self._rows(db, "cookies", fields, where="lower(host_key) LIKE ?", params=("%google%",)):
                host = str(row["host_key"] or "").strip(".").lower()
                if not any(host == domain or host.endswith("." + domain)
                           for domain in ("google.com", "googleusercontent.com", "googleapis.com", "gstatic.com")):
                    continue
                detail = {k: v for k, v in row.items() if not k.startswith("_")}
                errors = []
                for field in ("creation_utc", "last_access_utc", "expires_utc"):
                    detail[field] = normalize_timestamp(row[field])
                    if detail[field].get("error"):
                        errors.append(field + ": " + detail[field]["error"])
                detail.update(record_type="finding", timestamp_format="chrome_microseconds_since_1601",
                              missing_columns=sorted(set(fields) - columns),
                              relevance_scope="gemini_host" if host == "gemini.google.com" else "google_shared_host",
                              limitation="Cookie metadata is shared account/site context; it does not prove Gemini use or successful login. Cookie values are not extracted.")
                self._emit(key, "Google/Gemini cookie metadata found", path=path, timestamp=detail["creation_utc"],
                           detail=detail, locator={"table": "cookies", "host_key": row["host_key"], "name": row["name"],
                                                  "path": row["path"], "creation_utc": row["creation_utc"],
                                                  "top_frame_site_key": row["top_frame_site_key"],
                                                  "has_cross_site_ancestor": row["has_cross_site_ancestor"]},
                           status="partial" if errors else "success", error="; ".join(errors) or None)

    def _parse_preferences(self, key):
        path = Path(self.artifacts[key])
        if path.stat().st_size > self.max_json_bytes:
            self._issue(key, path, f"JSON exceeds configured {self.max_json_bytes} byte limit", status="partial")
            return
        with path.open("rb") as stream:
            data = stream.read(self.max_json_bytes + 1)
        if len(data) > self.max_json_bytes:
            self._issue(key, path, "JSON grew beyond configured read limit", status="partial")
            return
        document = json.loads(data.decode("utf-8-sig"))
        stack = [((), document)]
        count, visited = 0, 0
        while stack:
            if count >= 10000:
                self._issue(key, path, "Relevant preference result limit (10000) reached", status="partial")
                break
            parts, value = stack.pop()
            visited += 1
            if visited > 500000:
                self._issue(key, path, "JSON node limit (500000) reached", status="partial")
                break
            if len(parts) > 100:
                self._issue(key, path, "JSON nesting limit (100) reached", status="partial")
                continue
            key_path = ".".join(map(str, parts))
            if SECRET_RE.search(key_path):
                # Do not dump credentials while searching broad account settings.
                if PREF_RE.search(key_path):
                    self._emit(key, "Relevant sensitive preference key present; value omitted", path=path,
                               detail={"record_type": "finding", "key_path": key_path, "value": "[REDACTED]"},
                               locator={"json_pointer": self._json_pointer(parts)})
                    count += 1
                continue
            if isinstance(value, dict) and value:
                stack.extend((parts + (k,), v) for k, v in reversed(list(value.items())))
                continue
            if isinstance(value, list) and value:
                stack.extend((parts + (i,), v) for i, v in reversed(list(enumerate(value))))
                continue
            relevant = PREF_RE.search(key_path) or (isinstance(value, str) and PREF_RE.search(value))
            if not relevant:
                continue
            truncated = isinstance(value, str) and len(value) > 4096
            self._emit(key, "Relevant preference key/value found", path=path,
                       detail={"record_type": "finding", "key_path": key_path,
                               "value": value[:4096] if truncated else value, "value_truncated": truncated,
                               "relevance_scope": "gemini" if DOMAIN_RE.search(key_path + " " + str(value)) else "shared_profile_context",
                               "limitation": "A stored setting is not proof of login, clearing data, or another user action."},
                       locator={"json_pointer": self._json_pointer(parts)}, status="partial" if truncated else "success")
            count += 1

    @staticmethod
    def _json_pointer(parts):
        return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)

    def _walk_files(self, root, key):
        """Do not follow junctions/symlinks or leave an acquired artifact root."""
        pending, count = [Path(root)], 0
        while pending:
            directory = pending.pop()
            try:
                entries = sorted(directory.iterdir(), key=lambda p: p.name.casefold())
            except OSError as exc:
                self._issue(key, directory, error_text(exc))
                continue
            for entry in entries:
                try:
                    if is_link(entry) or not within(entry, root):
                        self._issue(key, entry, "Linked/reparse-point entry skipped", status="partial")
                        continue
                    info = entry.stat()
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(entry)
                    elif stat.S_ISREG(info.st_mode):
                        if self.max_files and count >= self.max_files:
                            self._issue(key, root, f"Configured file limit ({self.max_files}) reached", status="partial")
                            return
                        count += 1
                        yield entry
                except OSError as exc:
                    self._issue(key, entry, error_text(exc))

    @staticmethod
    def _normalize_recovered_text(value):
        """Normalize a text candidate without claiming that it is a decoded Gemini message."""
        if not isinstance(value, str):
            return None
        value = value.replace("\x00", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
        value = re.sub(r"\s+", " ", value).strip()
        if len(value) < 2 or len(value) > 4000:
            return None
        if re.fullmatch(r"https?://\S+", value, re.I):
            return None
        if "gemini.google.com" in value.lower() and len(value.split()) <= 3:
            return None
        if re.fullmatch(r"[A-Za-z0-9_.:/@+\-=]{4,}", value) and " " not in value:
            return None
        lowered = value.lower()
        if lowered in {
            "message", "message_text", "text", "content", "prompt", "query", "response",
            "answer", "input", "output", "application/json", "text/plain", "true", "false", "null"
        }:
            return None
        alpha = sum(ch.isalpha() for ch in value)
        hangul = len(re.findall(r"[가-힣]", value))
        if alpha + hangul < 2:
            return None
        return value

    @classmethod
    def _extract_labeled_message_candidates(cls, raw_context):
        """Extract only label-associated text candidates from bounded raw context.

        This is a heuristic fallback, not a native Gemini/Chrome cache decoder.  Matches are
        exported only as partial/raw candidates and never promoted to confirmed messages solely
        because this pattern matched.
        """
        if not isinstance(raw_context, str) or not raw_context:
            return []
        pattern = re.compile(
            r"""(?i)[\"']?(message_text|message|prompt|query|response|answer|input|output|content|text)[\"']?\s*[:=]\s*\"((?:\\.|[^\"\\]){2,4000})\""""
        )
        variants = [raw_context]
        if '\\"' in raw_context:
            variants.append(raw_context.replace('\\"', '"'))

        found = []
        seen = set()
        for variant in variants:
            for match in pattern.finditer(variant):
                key = match.group(1).lower()
                encoded = match.group(2)
                try:
                    decoded = json.loads('"' + encoded + '"')
                except (json.JSONDecodeError, TypeError):
                    decoded = encoded.replace('\\n', ' ').replace('\\r', ' ').replace('\\t', ' ')
                    decoded = decoded.replace('\\"', '"').replace('\\\\', '\\')
                normalized = cls._normalize_recovered_text(decoded)
                if not normalized:
                    continue
                identity = (key, normalized)
                if identity in seen:
                    continue
                seen.add(identity)
                role = ("user" if key in {"prompt", "query", "input"} else
                        "assistant" if key in {"response", "answer", "output"} else "")
                found.append({
                    "field": key,
                    "text": normalized,
                    "role_hint": role,
                    "recovery_basis": "labeled_string_in_bounded_raw_context",
                })
                if len(found) >= 8:
                    return found
        return found

    @staticmethod
    def _is_google_search_context(text):
        """Return True for Google Search result/query contexts.

        Gemini links frequently appear inside ordinary Google Search result HTML. Those pages
        must never be treated as Gemini chat evidence merely because gemini.google.com and a
        query string coexist in the same cache entry.
        """
        if not isinstance(text, str) or not text:
            return False
        low = text.casefold()
        markers = (
            "www.google.com/search", "google.com/search?", "google.com/search&",
            "data-async-context=\"query:", "data-async-context='query:",
            "id=\"rso\"", "id='rso'", "<div id=\"search\"", "<div id='search'",
            "google search", "search?q=", "&q=", "?q=",
        )
        if any(marker in low for marker in markers):
            return True
        if re.search(r"(?i)data-async-context\s*=\s*[\"']query%?[:=]", text):
            return True
        return False

    @staticmethod
    def _is_cross_service_prompt_context(text):
        """Detect a bounded context that belongs to another service rather than Gemini chat."""
        if not isinstance(text, str) or not text:
            return False
        low = text.casefold()
        return any(host in low for host in (
            "drive.google.com", "drive.usercontent.google.com", "docs.google.com",
            "mail.google.com", "gmail.com", "calendar.google.com", "photos.google.com",
            "youtube.com", "youtu.be", "myaccount.google.com",
            "chatgpt.com", "openai.com", "claude.ai", "lmstudio.ai",
        ))

    @classmethod
    def _decode_aggressive_prompt_text(cls, value, field=""):
        """Decode one fallback prompt candidate without turning transport text into chat."""
        if not isinstance(value, str):
            return None
        text = value.strip().strip("\x00")
        if not text:
            return None

        try:
            if "\\" in text:
                decoded = json.loads('"' + text.replace('"', '\\"') + '"')
                if isinstance(decoded, str):
                    text = decoded
        except (json.JSONDecodeError, TypeError, ValueError):
            text = text.replace("\\n", " ").replace("\\r", " ").replace("\\t", " ")
            text = text.replace('\\"', '"').replace("\\/", "/")

        for _ in range(2):
            previous = text
            text = html.unescape(text)
            if re.search(r"%[0-9A-Fa-f]{2}", text):
                try:
                    text = unquote_plus(text)
                except Exception:
                    pass
            if text == previous:
                break

        text = text.strip().strip("\"'")
        label = str(field or "").casefold()
        if re.match(r"(?i)^query\s*[:=]", text):
            if label != "query":
                return None
            text = re.sub(r"(?i)^query\s*[:=]\s*", "", text, count=1)
        normalized = cls._normalize_message_content(text)
        if not normalized:
            return None
        low = normalized.casefold()
        if any(token in low for token in (
            "data-async-context", "id=\"rso\"", "id='rso'", "google search",
            "<html", "<div", "<script", "<style", "stylesheet", "javascript:",
        )):
            return None
        return normalized

    @classmethod
    def _extract_aggressive_prompt_candidates_from_text(cls, text, absolute_base=0,
                                                        encoding="utf-8", origin_scoped=False):
        """Recover high-confidence user prompt candidates from raw Gemini-scoped text.

        This fallback is used when native RPC decoding did not recover the message. It requires
        a Gemini-specific anchor close to the labelled text and rejects Google Search HTML/query
        contexts as well as unrelated service contexts. Generic sentences are never emitted.
        """
        if not isinstance(text, str) or not text:
            return []



        variants = [(text, False)]
        unescaped = html.unescape(text.replace('\\"', '"').replace("\\/", "/"))
        if unescaped != text:
            variants.append((unescaped, True))
        if re.search(r"%[0-9A-Fa-f]{2}", text):
            try:
                decoded = unquote_plus(text)
            except Exception:
                decoded = text
            if decoded != text and decoded != unescaped:
                variants.append((decoded, True))

        # Disjoint escape/plain branches avoid backtracking over alternate parses
        # of backslashes. Plain text excludes both quotes, so greediness cannot
        # consume an unescaped closing quote; retain the existing 8192-atom bound.
        quoted = re.compile(
            r'''(?is)["']?(?P<label>prompt_text|prompt|user_input|input|query|message_text|message|content|text)["']?\s*[:=]\s*(?P<quote>["'])(?P<value>(?:\\.|[^\\"']){2,8192})(?P=quote)'''
        )
        form = re.compile(
            r'''(?is)(?:^|[?&;\s])(?P<label>prompt_text|prompt|user_input|input|query)\s*=\s*(?P<value>[^&\r\n]{2,8192})'''
        )
        colon = re.compile(
            r'''(?is)(?:^|[,{;\s])(?P<label>prompt_text|prompt|user_input|input|query)\s*:\s*(?P<value>[^\r\n,}\]]{2,4096})'''
        )

        output, seen = [], set()
        for variant, approximate in variants:
            # Exact ranges are meaningful only within this particular variant.
            google_search_cache, cid_cache, strong_rpc_cache = {}, {}, {}
            cross_service_cache, role_cache = {}, {}
            for rx in (quoted, form, colon):
                for match in rx.finditer(variant):
                    label = str(match.group("label") or "").casefold()
                    start = match.start()
                    c0 = max(0, start - AGGRESSIVE_PROMPT_CONTEXT)
                    c1 = min(len(variant), match.end() + AGGRESSIVE_PROMPT_CONTEXT)
                    context_key = (c0, c1)
                    context = variant[c0:c1]

                    if context_key not in google_search_cache:
                        google_search_cache[context_key] = cls._is_google_search_context(context)
                    if google_search_cache[context_key]:
                        continue

                    if context_key not in cid_cache:
                        cid_cache[context_key] = cls._explicit_conversation_id_from_text(context)
                    cid = cid_cache[context_key]
                    if context_key not in strong_rpc_cache:
                        strong_rpc_cache[context_key] = bool(re.search(
                            r"(?i)(?:\bhnvQHb\b|StreamGenerate|BardChatUi|gemini\.google\.com/_/|"
                            r"origin\s*=\s*(?:https?%3A%2F%2F|https?://)?gemini\.google\.com|"
                            r"source-path\s*[:=]\s*[\"']?/app)", context
                        ))
                    strong_rpc = strong_rpc_cache[context_key]
                    gemini_anchor = bool(cid or origin_scoped or strong_rpc)
                    if not gemini_anchor:
                        continue
                    if context_key not in cross_service_cache:
                        cross_service_cache[context_key] = cls._is_cross_service_prompt_context(context)
                    if cross_service_cache[context_key] and not (cid or strong_rpc):
                        continue

                    role = "user" if label in {"prompt_text", "prompt", "user_input", "input", "query"} else ""
                    if not role:
                        if context_key not in role_cache:
                            user_side = bool(re.search(
                                r'''(?i)(?:["']role["']\s*[:=]\s*["'](?:user|human)["']|["']author["']\s*[:=]\s*["']user["']|user[_ -]?message|user[_ -]?input)''',
                                context,
                            ))
                            assistant_side = bool(re.search(
                                r'''(?i)(?:["']role["']\s*[:=]\s*["'](?:assistant|model)["']|["']author["']\s*[:=]\s*["'](?:assistant|model)["'])''',
                                context,
                            ))
                            role_cache[context_key] = (user_side, assistant_side)
                        else:
                            user_side, assistant_side = role_cache[context_key]
                        if not user_side or assistant_side:
                            continue
                        role = "user"

                    prompt = cls._decode_aggressive_prompt_text(match.group("value"), label)
                    if not prompt:
                        continue
                    if prompt.casefold().startswith(("http://", "https://")):
                        continue
                    identity = (cid or "", prompt.casefold())
                    if identity in seen:
                        continue
                    seen.add(identity)

                    if approximate:
                        offset = absolute_base
                    else:
                        try:
                            if encoding == "utf-16le":
                                offset = absolute_base + match.start() * 2
                            else:
                                offset = absolute_base + len(variant[:match.start()].encode("utf-8", errors="ignore"))
                        except Exception:
                            offset = absolute_base
                    output.append({
                        "conversation_id": cid or "",
                        "message_id": "",
                        "parent_message_id": "",
                        "message_order": None,
                        "role": role,
                        "message_content": prompt,
                        "response_id": None,
                        "choice_id": None,
                        "recovery_basis": "aggressive_raw_prompt",
                        "protocol": "raw-labelled-fallback",
                        "protocol_offset": offset,
                        "protocol_encoding": encoding,
                        "offset_is_approximate": bool(approximate),
                        "prompt_field": label,
                    })
                    if len(output) >= AGGRESSIVE_PROMPT_MAX_PER_FILE:
                        return output
        return output

    @classmethod
    def _normalize_message_content(cls, value):
        """Normalize recovered chat text while preserving useful line structure.

        This is stricter than ordinary string extraction: identifiers, URLs, protocol labels,
        HTML fragments and high-entropy tokens are rejected so they cannot become chat rows.
        """
        if not isinstance(value, str):
            return None
        value = value.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r"\n{4,}", "\n\n\n", value).strip()
        if len(value) < 2 or len(value) > 262144:
            return None
        lowered = value.casefold()
        # A JSON-encoded container can contain the actual prompt plus IDs and metadata.
        # Decode it structurally elsewhere; never emit the whole serialized container as content.
        if value[:1] in "[{":
            try:
                decoded_container = json.loads(value)
            except (json.JSONDecodeError, TypeError, ValueError):
                decoded_container = None
            if isinstance(decoded_container, (list, dict)):
                return None
        if re.fullmatch(r"https?://\S+", value, re.I):
            return None
        if lowered in {
            "message", "message_text", "text", "content", "prompt", "query", "response",
            "answer", "input", "output", "generic", "null", "true", "false", "undefined",
            "application/json", "application/x-www-form-urlencoded", "text/plain",
        }:
            return None
        if re.fullmatch(r"[A-Za-z0-9_./:@+%?&=\-]{8,}", value) and not re.search(r"\s", value):
            return None
        if value.startswith("<") and value.endswith(">") and re.search(r"</?[A-Za-z][^>]*>", value):
            return None
        # Reject common protocol/UI-only fragments.
        if any(token in lowered for token in (
            "dynamicframe", "rotatecookiespage", "__features__", "rpctoken=",
            "source-path=", "rpcids=", "blink serialized form state version",
        )) and len(value.split()) < 18:
            return None
        letters = sum(ch.isalpha() for ch in value)
        hangul = len(re.findall(r"[가-힣]", value))
        if letters + hangul < 2:
            return None
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in value)
        if printable / max(1, len(value)) < 0.92:
            return None
        return value

    @staticmethod
    def _protocol_id(value):
        if not isinstance(value, str):
            return None
        value = value.strip()
        if value.startswith("c_") and 4 <= len(value) <= 260:
            return value[2:]
        if re.fullmatch(r"(?:r|rc)_[A-Za-z0-9_-]{1,253}", value):
            return value
        if re.fullmatch(r"[A-Za-z0-9_-]{8,256}", value):
            # Pure decimal values are usually counters/timestamps rather than IDs.
            if value.isdigit():
                return None
            return value
        return None

    @staticmethod
    def _conversation_protocol_id(value):
        """Accept only Gemini conversation-id shapes observed in chat URLs/protocol payloads.

        Model hashes, request UUIDs, RPC ids and other opaque tokens can also be 8-32
        characters long, so the generic _protocol_id() is deliberately not sufficient here.
        Current Gemini Web conversation ids observed in /app/<id> and c_<id> forms are
        16 hexadecimal characters; preserve the original hex case but strip the c_ wrapper.
        """
        if not isinstance(value, str):
            return None
        value = value.strip()
        if value.startswith("c_"):
            value = value[2:]
        return value if re.fullmatch(r"[0-9a-fA-F]{16}", value) else None

    @classmethod
    def _walk_json_strings(cls, value, max_nodes=20000):
        """Yield strings from a decoded JSON-like tree with a hard traversal bound."""
        stack = [value]
        seen_nodes = 0
        while stack and seen_nodes < max_nodes:
            current = stack.pop()
            seen_nodes += 1
            if isinstance(current, str):
                yield current
            elif isinstance(current, dict):
                stack.extend(reversed(list(current.values())))
            elif isinstance(current, (list, tuple)):
                stack.extend(reversed(current))

    @classmethod
    def _natural_strings(cls, value, limit=32):
        found = []
        seen = set()
        for raw in cls._walk_json_strings(value):
            text = cls._normalize_message_content(raw)
            if not text:
                continue
            ident = text.casefold()
            if ident in seen:
                continue
            seen.add(ident)
            found.append(text)
            if len(found) >= limit:
                break
        return found

    @classmethod
    def _stream_payload_messages(cls, payload, absolute_offset=0, protocol="gemini_stream_payload"):
        """Decode Gemini StreamGenerate/chat-response arrays conservatively.

        A valid chat response must expose a 16-hex conversation id at index 1, a response id,
        and a choice list at index 4.  Those anchors are substantially stronger than merely
        finding a wrb.fr envelope, which is shared by many unrelated Google RPCs.
        """
        out = []
        seen = set()
        visited = 0
        stack = [payload]
        while stack and visited < 5000:
            node = stack.pop()
            visited += 1
            if isinstance(node, dict):
                stack.extend(reversed(list(node.values())))
                continue
            if not isinstance(node, list):
                continue
            stack.extend(reversed(node))
            if len(node) < 5 or not isinstance(node[1], list) or len(node[1]) < 2:
                continue
            cid = cls._conversation_protocol_id(node[1][0])
            response_id = cls._protocol_id(node[1][1])
            choices = node[4]
            if not cid or not response_id or not isinstance(choices, list):
                continue

            query_text = None
            if isinstance(node[2], list) and node[2]:
                candidates = cls._natural_strings(node[2], limit=8)
                if candidates:
                    query_text = max(candidates, key=len)
            if query_text:
                item = {
                    "conversation_id": cid,
                    "message_id": "",
                    "parent_message_id": "",
                    "message_order": None,
                    "role": "user",
                    "message_content": query_text,
                    "response_id": response_id,
                    "choice_id": None,
                    "recovery_basis": "structured_stream_query",
                    "protocol": protocol,
                    "protocol_offset": absolute_offset,
                }
                key = (cid, response_id, "user", query_text)
                if key not in seen:
                    seen.add(key)
                    out.append(item)

            assistant_count = 0
            for choice in choices[:16]:
                if not isinstance(choice, list) or len(choice) < 2:
                    continue
                choice_id = cls._protocol_id(choice[0]) if choice else None
                texts = cls._natural_strings(choice[1], limit=16)
                if not texts:
                    continue
                # Stream chunks normally carry an accumulated candidate.  Keep the longest
                # natural-language value in this choice; cross-chunk consolidation happens later.
                content = max(texts, key=len)
                if query_text and content.strip() == query_text.strip():
                    continue
                assistant_count += 1
                item = {
                    "conversation_id": cid,
                    "message_id": response_id or choice_id or "",
                    "parent_message_id": "",
                    "message_order": None,
                    "role": "assistant",
                    "message_content": content,
                    "response_id": response_id,
                    "choice_id": choice_id,
                    "recovery_basis": "structured_stream_choice",
                    "protocol": protocol,
                    "protocol_offset": absolute_offset,
                }
                key = (cid, response_id, choice_id, "assistant", content)
                if key not in seen:
                    seen.add(key)
                    out.append(item)
                # Alternative drafts are choices, not separate conversation turns.
                break
            # Do not stop after the first response-shaped node. A single Google frame can
            # contain multiple wrb.fr/chat payloads, and all must remain recoverable.
        return out

    @classmethod
    def _decode_nested_json_strings(cls, value, depth=0, max_depth=4):
        """Yield JSON values nested inside JSON-encoded strings at any container depth.

        Batchexecute payloads commonly wrap an RPC request/response several list levels deep
        before the useful value appears as a JSON string.  Traverse ordinary containers without
        increasing the decode depth; only decoding a string consumes one depth level.
        """
        yield value
        queue = [(value, depth)]
        visited = 0
        while queue and visited < 20000:
            current, current_depth = queue.pop()
            visited += 1
            if isinstance(current, dict):
                queue.extend((child, current_depth) for child in current.values())
                continue
            if isinstance(current, (list, tuple)):
                queue.extend((child, current_depth) for child in current)
                continue
            if not isinstance(current, str) or current_depth >= max_depth:
                continue
            stripped = current.strip()
            if not (2 <= len(stripped) <= MAX_PROTOCOL_TEXT and stripped[:1] in "[{"):
                continue
            try:
                decoded = json.loads(stripped)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            yield decoded
            queue.append((decoded, current_depth + 1))

    @staticmethod
    def _explicit_conversation_id_from_text(text):
        """Return a conversation id only when the text carries an explicit chat anchor.

        A bare 16-hex token is *not* enough: current Gemini request payloads also contain
        16-hex model hashes, which must never become conversation_uuid values.  Accept only
        /app/<id> paths or c_<16hex> protocol ids here.  Response payloads use their own
        positional conversation-id decoder.
        """
        if not isinstance(text, str):
            return None
        match = re.search(r"(?:https?://gemini\.google\.com)?/app/([A-Za-z0-9_-]{8,256})", text, re.I)
        if match:
            return match.group(1)
        match = re.search(r"\bc_([0-9a-fA-F]{16})\b", text)
        if match:
            return match.group(1)
        return None

    @classmethod
    def _stream_request_prompts(cls, value, limit=8):
        """Read only the StreamGenerate request slot, never arbitrary nested settings."""
        if limit < 1 or not isinstance(value, list):
            return []
        # StreamGenerate f.req envelope: [null, JSON-encoded inner request].
        if len(value) == 2 and value[0] is None and isinstance(value[1], str):
            try:
                value = json.loads(value[1])
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
        # Inner request: [[prompt, ...], null/[language], [continuation ids...], ...].
        if not (isinstance(value, list) and len(value) >= 3
                and isinstance(value[0], list) and value[0]
                and isinstance(value[0][0], str)
                and isinstance(value[2], list) and len(value[2]) >= 3
                and all(isinstance(item, str) for item in value[2][:3])):
            return []
        language = value[1]
        if language is not None and not (
            isinstance(language, list) and len(language) == 1
            and isinstance(language[0], str)
            and re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z]{2,4})?", language[0])
        ):
            return []
        prompt = cls._normalize_message_content(value[0][0])
        return [prompt] if prompt else []

    @classmethod
    def _iter_wrb_entries(cls, value):
        """Yield supported batchexecute response envelopes in source order."""
        if isinstance(value, list):
            if len(value) >= 3 and value[0] == "wrb.fr" and isinstance(value[2], str):
                yield value
                return
            # Some captured/decoded Google frames expose [rpcid, null, inner_json, ...]
            # without the outer wrb.fr tag.  Only normalize the known READ_CHAT rpc id.
            if len(value) >= 3 and value[0] == "hNvQHb" and value[1] is None and isinstance(value[2], str):
                yield ["wrb.fr", "hNvQHb", value[2]]
                return
            for child in value:
                yield from cls._iter_wrb_entries(child)
        elif isinstance(value, dict):
            for child in value.values():
                yield from cls._iter_wrb_entries(child)

    @staticmethod
    def _history_timestamp_value(value):
        """Convert a Gemini READ_CHAT [epoch_seconds, nanoseconds] value to strict KST."""
        if isinstance(value, (list, tuple)) and value:
            seconds = value[0]
            nanos = value[1] if len(value) > 1 else 0
        else:
            seconds, nanos = value, 0
        try:
            seconds = float(seconds)
            nanos = int(nanos or 0)
        except (TypeError, ValueError, OverflowError):
            return ""
        # Contemporary READ_CHAT records use Unix seconds.  Keep a conservative range so
        # unrelated counters/file-times cannot silently become message timestamps.
        if not (946684800 <= seconds <= 4102444800):  # 2000-01-01 .. 2100-01-01 UTC
            return ""
        try:
            whole = int(seconds)
            micros = int(round((seconds - whole) * 1_000_000)) + max(0, min(nanos, 999_999_999)) // 1000
            if micros >= 1_000_000:
                whole += micros // 1_000_000
                micros %= 1_000_000
            parsed = datetime.fromtimestamp(whole, tz=timezone.utc).replace(microsecond=micros).astimezone(KST)
        except (OSError, OverflowError, ValueError):
            return ""
        return parsed.strftime("%Y-%m-%d %H:%M:%S") + f".{parsed.microsecond:06d} KST"

    @classmethod
    def _history_attachment_metadata(cls, node):
        """Recover conservative attachment metadata from a READ_CHAT prompt attachment field.

        Only the dedicated attachment subtree is inspected.  Natural-language strings elsewhere
        in the turn are deliberately ignored so filenames cannot be invented from prompt text or
        assistant content.  The output is internal JSON evidence; it is never appended to message
        content.
        """
        if node in (None, "", [], {}):
            return []
        found = {}
        stack = [node]
        visited = 0
        mime_re = re.compile(r"^[a-z0-9.+-]+/[a-z0-9.+-]+$", re.I)
        while stack and visited < 2000:
            current = stack.pop()
            visited += 1
            if isinstance(current, dict):
                stack.extend(reversed(list(current.values())))
                continue
            if isinstance(current, (list, tuple)):
                stack.extend(reversed(list(current)))
                continue
            if not isinstance(current, str):
                continue
            text = current.strip().replace("\x00", "")
            if not text or len(text) > 1024:
                continue
            match = UPLOAD_FILE_RE.search(text)
            if match:
                filename = match.group(1).strip()
                key = filename.casefold()
                item = found.setdefault(key, {"filename": filename})
                item["media_kind"] = "image" if IMAGE_FILE_RE.search(filename) else "document"
            elif mime_re.fullmatch(text):
                # MIME strings are retained only as a page-level hint.  Do not attach them to a
                # filename unless the private RPC structure gives an explicit relationship.
                found.setdefault("__mime__:" + text.casefold(), {"mime_type": text})
        filenames = [value for key, value in found.items() if not key.startswith("__mime__:")]
        mime_hints = [value["mime_type"] for key, value in found.items()
                      if key.startswith("__mime__:") and value.get("mime_type")]
        if len(filenames) == 1 and len(mime_hints) == 1:
            filenames[0]["mime_type"] = mime_hints[0]
        return filenames[:32]

    @classmethod
    def _history_rpc_messages(cls, payload, absolute_offset=0, protocol="wrb.fr/hNvQHb"):
        """Decode hNvQHb READ_CHAT pages into user/assistant message records.

        The decoder requires the positional anchors observed in Gemini's READ_CHAT turn
        records.  It also follows the candidate id referenced by later turns so a regenerated
        response branch that was actually continued is preferred over abandoned alternatives.
        Thinking/tool metadata outside the selected candidate-text field is not promoted.
        """
        output = []
        seen = set()

        # READ_CHAT body is normally [turns, cursor/...], but nested JSON-string wrappers can
        # expose that body at different depths. Search bounded containers for a turn list.
        candidates = []
        stack = [payload]
        visited = 0
        while stack and visited < 4000:
            node = stack.pop()
            visited += 1
            if isinstance(node, dict):
                stack.extend(reversed(list(node.values())))
                continue
            if not isinstance(node, list):
                continue
            if node and isinstance(node[0], list):
                possible_turns = node[0]
                if possible_turns and all(isinstance(turn, list) for turn in possible_turns[:3]):
                    candidates.append(possible_turns)
            stack.extend(reversed([child for child in node if isinstance(child, (list, dict))]))

        for turns in candidates[:8]:
            # hNvQHb pages are newest-first.  A regenerated response can leave several
            # candidates; a candidate id referenced by a turn's parent/choice metadata is
            # evidence that branch was actually continued.
            continued_choice_ids = set()
            for turn in turns[:2000]:
                if isinstance(turn, list) and len(turn) > 1 and isinstance(turn[1], list) and len(turn[1]) > 2:
                    choice = cls._protocol_id(turn[1][2])
                    if choice:
                        continued_choice_ids.add(choice)

            total_turns = min(len(turns), 2000)
            for turn_index, turn in enumerate(turns[:2000]):
                if not isinstance(turn, list) or len(turn) < 4:
                    continue
                meta = turn[0] if isinstance(turn[0], list) else None
                extended = turn[1] if len(turn) > 1 and isinstance(turn[1], list) else None
                if not meta or len(meta) < 2:
                    continue
                cid = cls._conversation_protocol_id(meta[0])
                response_id = cls._protocol_id(meta[1])
                if not cid or not response_id:
                    continue

                parent_response_id = None
                referenced_choice_id = None
                if extended:
                    ext_cid = cls._conversation_protocol_id(extended[0]) if len(extended) > 0 else None
                    if ext_cid and ext_cid != cid:
                        continue
                    # The second value is the parent response id for follow-up turns; it is
                    # not required to equal the current response id.
                    parent_response_id = cls._protocol_id(extended[1]) if len(extended) > 1 else None
                    referenced_choice_id = cls._protocol_id(extended[2]) if len(extended) > 2 else None

                timestamp = cls._history_timestamp_value(turn[4] if len(turn) > 4 else None)
                # Restore chronological protocol order even when timestamps are unavailable.
                chronological_index = total_turns - 1 - turn_index

                prompt_section = turn[2] if len(turn) > 2 else None
                try:
                    raw_prompt = prompt_section[0][0]
                except (TypeError, IndexError):
                    raw_prompt = None
                try:
                    attachment_section = prompt_section[0][4]
                except (TypeError, IndexError):
                    attachment_section = None
                attachments = cls._history_attachment_metadata(attachment_section)
                prompt = cls._normalize_message_content(raw_prompt)
                if prompt:
                    item = {
                        "conversation_id": cid,
                        "message_id": "",
                        "parent_message_id": parent_response_id or "",
                        "message_order": None,
                        "role": "user",
                        "message_content": prompt,
                        "message_timestamp": timestamp,
                        "response_id": response_id,
                        "choice_id": referenced_choice_id,
                        "recovery_basis": "history_rpc_user_prompt",
                        "protocol": protocol,
                        "protocol_offset": absolute_offset,
                        "protocol_sequence": chronological_index * 2,
                        "attachments": attachments,
                    }
                    key = (cid, response_id, "user", prompt)
                    if key not in seen:
                        seen.add(key)
                        output.append(item)

                # Current READ_CHAT response section is a candidate list at turn[3][0].
                # Preserve every response candidate here.  The final conversation builder resolves
                # the active branch globally using choice ids referenced by later turns, which also
                # works when pagination placed the parent pointer in a different cache response.
                response_section = turn[3] if len(turn) > 3 else None
                try:
                    response_candidates = response_section[0]
                except (TypeError, IndexError):
                    response_candidates = None
                if isinstance(response_candidates, list):
                    for candidate_rank, candidate in enumerate(response_candidates[:16]):
                        if not isinstance(candidate, list) or len(candidate) < 2:
                            continue
                        selected_choice_id = cls._protocol_id(candidate[0])
                        if not selected_choice_id:
                            continue
                        text_container = candidate[1]
                        if isinstance(text_container, list) and text_container and isinstance(text_container[0], str):
                            answer = cls._normalize_message_content(text_container[0])
                        elif isinstance(text_container, str):
                            answer = cls._normalize_message_content(text_container)
                        else:
                            answer = None
                        if not answer or (prompt and answer.strip() == prompt.strip()):
                            continue
                        item = {
                            "conversation_id": cid,
                            "message_id": response_id,
                            "parent_message_id": "",
                            "message_order": None,
                            "role": "assistant",
                            "message_content": answer,
                            "message_timestamp": timestamp,
                            "response_id": response_id,
                            "choice_id": selected_choice_id,
                            "candidate_rank": candidate_rank,
                            "recovery_basis": "history_rpc_assistant_candidate",
                            "protocol": protocol,
                            "protocol_offset": absolute_offset,
                            "protocol_sequence": chronological_index * 2 + 1,
                        }
                        key = (cid, response_id, selected_choice_id, "assistant", answer)
                        if key not in seen:
                            seen.add(key)
                            output.append(item)
                if len(output) >= 4000:
                    return output
        return output

    @classmethod
    def _wrb_messages_from_text(cls, text, absolute_base=0):
        """Recover Gemini chat responses from Google wrb.fr transport frames.

        Google uses wrb.fr for many products/RPCs.  We therefore decode the envelope first and
        only promote payloads that satisfy the stricter Gemini chat-response structure checked by
        _stream_payload_messages().  Source order is preserved across multiple entries/chunks.
        """
        if not isinstance(text, str) or ('wrb.fr' not in text and 'hNvQHb' not in text):
            return []
        output = []
        seen = set()
        cursor = 0
        for line in text.splitlines():
            line_offset = text.find(line, cursor)
            if line_offset < 0:
                line_offset = cursor
            cursor = line_offset + len(line) + 1
            if ('wrb.fr' not in line and 'hNvQHb' not in line) or len(line) > MAX_PROTOCOL_TEXT:
                continue
            candidate = line.strip()
            start = candidate.find('[')
            if start > 0:
                candidate = candidate[start:]
            try:
                # Cache/session bytes can append unrelated binary/text after a valid JSON frame
                # on the same physical line.  Decode the first complete JSON value rather than
                # requiring the remainder of the line to be empty.  Structural RPC validation
                # below still decides whether the value is a Gemini message frame.
                outer, _ = json.JSONDecoder().raw_decode(candidate)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            entry_index = 0
            for entry in cls._iter_wrb_entries(outer):
                entry_index += 1
                rpc_id = entry[1] if len(entry) > 1 else None
                inner_text = entry[2]
                if not isinstance(inner_text, str) or not inner_text.strip():
                    continue
                try:
                    decoded_root = json.loads(inner_text)
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
                protocol = "wrb.fr/StreamGenerate" if rpc_id in (None, "") else f"wrb.fr/{rpc_id}"
                for decoded in cls._decode_nested_json_strings(decoded_root):
                    if rpc_id == "hNvQHb":
                        decoded_messages = cls._history_rpc_messages(
                            decoded, absolute_base + line_offset, protocol=protocol
                        )
                    else:
                        decoded_messages = cls._stream_payload_messages(
                            decoded, absolute_base + line_offset, protocol=protocol
                        )
                    for msg in decoded_messages:
                        msg = dict(msg)
                        # READ_CHAT carries its own per-turn sequence; stream frames use entry order.
                        if msg.get("protocol_sequence") is None:
                            msg["protocol_sequence"] = entry_index
                        key = (
                            msg.get("conversation_id"), msg.get("response_id"), msg.get("choice_id"),
                            msg.get("role"), msg.get("message_content"), msg.get("protocol_offset")
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        output.append(msg)
                        if len(output) >= 4096:
                            return output
        return output

    @classmethod
    def _f_req_messages_from_text(cls, text, absolute_base=0):
        """Recover submitted user text from Gemini f.req payloads.

        Only the known StreamGenerate request envelope and positional prompt slot qualify.
        Unknown layouts remain unrecovered rather than promoting settings/UI strings.
        """
        if not isinstance(text, str) or "f.req" not in text:
            return []
        low = text.casefold()
        if not any(marker in low for marker in (
            "gemini.google.com", "bardchatui", "streamgenerate", "source-path=/app",
            "source-path=%2fapp",
        )):
            # batchexecute/f.req is a shared Google transport (Drive and many other products
            # use it too).  Without a Gemini/Bard/chat-specific anchor, promoting request text
            # would create cross-service prompt/timeline false positives.
            return []
        output = []
        seen = set()
        for match in re.finditer(r"f\.req\s*=\s*([^&\r\n\x00]{2,})", text, re.I):
            raw = match.group(1).strip().strip("\"'")
            if len(raw) > MAX_PROTOCOL_TEXT * 2:
                continue
            try:
                decoded_text = unquote_plus(raw)
            except Exception:
                decoded_text = raw
            decoded_text = decoded_text.strip()
            try:
                payload = json.loads(decoded_text)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            decoded_values = list(cls._decode_nested_json_strings(payload))
            serialized_payloads = [decoded_text]
            for decoded in decoded_values:
                try:
                    serialized_payloads.append(json.dumps(decoded, ensure_ascii=False, separators=(",", ":")))
                except (TypeError, ValueError):
                    pass

            # Never infer a conversation id from an unanchored 16-hex token: model hashes use
            # the same shape.  Only explicit /app/<id> or c_<id> anchors qualify here.
            cid = None
            context_start = max(0, match.start() - 4096)
            context_end = min(len(text), match.end() + 4096)
            cid = cls._explicit_conversation_id_from_text(text[context_start:context_end])
            if not cid:
                for serialized in serialized_payloads:
                    cid = cls._explicit_conversation_id_from_text(serialized)
                    if cid:
                        break

            structured_prompts = cls._stream_request_prompts(payload)
            basis = "gemini_f_req_structured"

            prompts = structured_prompts

            for prompt in prompts[:1]:
                key = (cid, prompt, absolute_base + match.start())
                if key in seen:
                    continue
                seen.add(key)
                output.append({
                    "conversation_id": cid,
                    "message_id": "",
                    "parent_message_id": "",
                    "message_order": None,
                    "role": "user",
                    "message_content": prompt,
                    "response_id": None,
                    "choice_id": None,
                    "recovery_basis": basis,
                    "protocol": "f.req/batchexecute",
                    "protocol_offset": absolute_base + match.start(),
                })
            if len(output) >= 32:
                break
        return output

    @classmethod
    def _protocol_messages_from_text(cls, text, absolute_base=0):
        output = []
        seen = set()
        for extractor in (cls._wrb_messages_from_text, cls._f_req_messages_from_text):
            for msg in extractor(text, absolute_base):
                content = cls._normalize_message_content(msg.get("message_content"))
                if not content:
                    continue
                msg = dict(msg)
                msg["message_content"] = content
                key = (
                    msg.get("conversation_id"), msg.get("response_id"), msg.get("choice_id"),
                    msg.get("role"), content, msg.get("protocol_offset")
                )
                if key in seen:
                    continue
                seen.add(key)
                output.append(msg)
        return output

    @classmethod
    def _protocol_messages_from_bytes(cls, data, absolute_base=0):
        """Decode protocol messages from raw bytes, including bounded gzip members when present."""
        views = []
        try:
            text = data.decode("utf-8", errors="ignore")
            if any(marker in text for marker in ("wrb.fr", "f.req", "StreamGenerate", "batchexecute", "hNvQHb")):
                views.append((text, absolute_base, "utf-8"))
        except Exception:
            pass
        # Some Chrome/session records are UTF-16LE.
        try:
            text16 = data.decode("utf-16le", errors="ignore")
            if any(marker in text16 for marker in ("wrb.fr", "f.req", "StreamGenerate", "batchexecute", "hNvQHb")):
                views.append((text16, absolute_base, "utf-16le"))
        except Exception:
            pass

        # Cache bodies can contain gzip-compressed HTTP payloads. Decode only a few bounded
        # members per chunk and cap output to avoid decompression bombs.
        pos = 0
        members = 0
        while members < 4:
            pos = data.find(b"\x1f\x8b\x08", pos)
            if pos < 0:
                break
            members += 1
            try:
                obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = obj.decompress(data[pos:], MAX_PROTOCOL_TEXT)
                if raw:
                    decoded = raw.decode("utf-8", errors="ignore")
                    if any(marker in decoded for marker in ("wrb.fr", "f.req", "StreamGenerate", "batchexecute", "hNvQHb")):
                        views.append((decoded, absolute_base + pos, "gzip/utf-8"))
            except (zlib.error, ValueError, OverflowError):
                pass
            pos += 3

        output = []
        seen = set()
        for text, base, encoding in views:
            for msg in cls._protocol_messages_from_text(text, base):
                msg = dict(msg)
                msg["protocol_encoding"] = encoding
                key = (
                    msg.get("conversation_id"), msg.get("response_id"), msg.get("choice_id"),
                    msg.get("role"), msg.get("message_content"), msg.get("protocol_offset")
                )
                if key in seen:
                    continue
                seen.add(key)
                output.append(msg)
                if len(output) >= 4096:
                    return output
        return output


    @staticmethod
    def _context_hit(data, at, base, encoding):
        unit = 2 if encoding == "utf-16le" else 1
        needle_length = len("gemini.google.com") * unit
        start = max(0, at - CONTEXT_BYTES)
        if unit == 2:
            start += (at - start) % 2
        end = min(len(data), at + needle_length + CONTEXT_BYTES)
        if unit == 2:
            end -= (end - start) % 2
        before = data[max(0, at - unit):at].decode(encoding, errors="replace")
        after = data[at + needle_length:at + needle_length + unit].decode(encoding, errors="replace")
        if (before and re.match(r"[A-Za-z0-9_.-]", before)) or (after and re.match(r"[A-Za-z0-9_.-]", after)):
            return None
        raw_context = data[start:end].decode(encoding, errors="replace")
        text = raw_context.replace("\\/", "/")
        urls = []
        for match in URL_RE.finditer(text):
            url = match.group().rstrip(".,);]}")
            if is_gemini_url(url) and url not in urls:
                urls.append(url)
        cids = list(dict.fromkeys(cid for url in urls if (cid := conversation_id(url))))
        domain_path = re.search(r"gemini\.google\.com(/app/([A-Za-z0-9_-]{1,256}))", text, re.I)
        if domain_path and domain_path.group(2) not in cids:
            cids.append(domain_path.group(2))
        clean = "".join(c if c.isprintable() else " " for c in raw_context)
        message_candidates = GeminiParser._extract_labeled_message_candidates(raw_context)
        return {"offset": base + at, "context_offset": base + start, "encoding": encoding,
                "matched_string": "gemini.google.com", "found_string": clean,
                "url": urls[0] if urls else None, "urls": urls[:8], "conversation_ids": cids[:8],
                "conversation_id": cids[0] if cids else None,
                "message_candidates": message_candidates,
                "context_is_bounded": True, "urls_are_raw_candidates": True}

    def _scan_binary_file(self, path, key, origin_scoped=False):
        """Streaming literal search with overlap for UTF-8/UTF-16LE boundaries.

        Encoded/compressed records are deliberately not interpreted as live
        values. Offsets always point to original bytes, including UTF-16 hits.
        """
        service_worker = key == "service_worker"
        initial = path.stat()
        size = initial.st_size
        hits, images, protocol_messages, prompt_candidates = [], [], [], []
        seen_hits, seen_images, seen_protocol, seen_prompts = set(), set(), set(), set()
        truncated_hits = truncated_images = truncated_protocol = truncated_prompts = False
        consumed, tail = 0, b""
        protocol_carry, protocol_carry_base = b"", 0
        gzip_carry, gzip_carry_base = b"", 0


        # Superset of the existing literal/protocol/aggressive-prompt anchors, in both
        # encodings. This is a scheduling filter, never a new forensic detection rule.
        sw_needles = tuple(marker.encode(enc) for enc in ("utf-8", "utf-16le")
                           for marker in ("gemini.google.com", "wrb.fr", "hnvqhb", "f.req",
                                          "streamgenerate", "batchexecute", "bardchatui"))
        budget = min(size, self.max_binary_bytes) if self.max_binary_bytes else size
        header = b""
        with path.open("rb") as stream:
            while consumed < budget:
                block = stream.read(min(CHUNK, budget - consumed))
                if not block:
                    break
                if not header:
                    header = block[:8]
                base = consumed - len(tail)
                consumed += len(block)
                data = tail + block
                final = consumed >= budget or len(block) < min(CHUNK, budget - consumed + len(block))
                # Defer anchors at the edge until their right-hand context is available.
                safe_end = len(data) if final else max(0, len(data) - OVERLAP // 2)
                lowered = data.lower()
                for encoding in ("utf-8", "utf-16le"):
                    needle = "gemini.google.com".encode(encoding)
                    at = lowered.find(needle)
                    while 0 <= at < safe_end:
                        identity = (base + at, encoding)
                        if identity not in seen_hits:
                            found = self._context_hit(data, at, base, encoding)
                            if found:
                                if len(hits) >= self.max_matches_per_file:
                                    truncated_hits = True
                                    break
                                seen_hits.add(identity)
                                hits.append(found)
                        at = lowered.find(needle, at + len(needle))
                    if origin_scoped:
                        # IndexedDB namespaces can supply the origin even when
                        # a value stores only a relative conversation path.
                        app_needle = "/app/".encode(encoding)
                        at = data.find(app_needle)
                        while 0 <= at < safe_end:
                            identity = (base + at, encoding)
                            if identity not in seen_hits:
                                unit = 2 if encoding == "utf-16le" else 1
                                snippet = data[at:at + 600 * unit].decode(encoding, errors="replace")
                                match = APP_RE.match(snippet)
                                if match:
                                    if len(hits) >= self.max_matches_per_file:
                                        truncated_hits = True
                                        break
                                    seen_hits.add(identity)
                                    hits.append({"offset": base + at, "context_offset": base + at,
                                                 "encoding": encoding, "matched_string": match.group(),
                                                 "found_string": "".join(c if c.isprintable() else " " for c in snippet),
                                                 "url": None, "urls": [], "conversation_id": match.group(1),
                                                 "conversation_ids": [match.group(1)], "context_is_bounded": True,
                                                 "relevance_basis": "Gemini origin in IndexedDB namespace; relative path in raw bytes"})
                            at = data.find(app_needle, at + len(app_needle))
                if key == "cache":
                    signatures = [(b"\xff\xd8\xff", "JPEG"), (b"\x89PNG\r\n\x1a\n", "PNG"),
                                  (b"GIF87a", "GIF"), (b"GIF89a", "GIF"), (b"RIFF", "WEBP")]
                    for signature, kind in signatures:
                        at = data.find(signature)
                        while 0 <= at < safe_end:
                            identity = (base + at, kind)
                            valid = kind != "WEBP" or data[at + 8:at + 12] == b"WEBP"
                            if valid and identity not in seen_images:
                                if len(images) >= self.max_matches_per_file:
                                    truncated_images = True
                                    break
                                seen_images.add(identity)
                                estimate = None
                                if kind == "WEBP":
                                    declared = struct.unpack_from("<I", data, at + 4)[0] + 8
                                    if declared >= 12 and base + at + declared <= size:
                                        estimate = declared
                                images.append({"offset": base + at, "detected_type": kind,
                                               "estimated_size": estimate,
                                               "size_method": "RIFF declared length; not full validation" if estimate else None,
                                               "detection_method": "magic_signature_only"})
                            at = data.find(signature, at + len(signature))

                # Keep enumeration, inventory and literal search for every Service Worker
                # file. Irrelevant chunks need no full text decode or protocol recovery;
                # overlap and pending records preserve candidates crossing chunk boundaries.
                if (service_worker and not protocol_carry and not gzip_carry
                        and b"\x1f\x8b\x08" not in data
                        and not any(needle in lowered for needle in sw_needles)):
                    tail = data[-OVERLAP:]
                    continue

                # Decode structured Gemini request/response payloads independently of the
                # domain-string hit path. A batchexecute JSON frame can be larger than the normal
                # raw-search overlap, so preserve an incomplete marker-bearing line across chunks
                # (bounded by MAX_PROTOCOL_TEXT) instead of silently losing long conversations.
                if protocol_carry:
                    protocol_data = protocol_carry + block
                    protocol_base = protocol_carry_base
                else:
                    protocol_data = data
                    protocol_base = base
                protocol_carry, protocol_carry_base = b"", 0
                pending_start = None
                if not final and len(protocol_data) < MAX_PROTOCOL_TEXT:
                    marker_positions = [
                        pos for marker in (b"wrb.fr", b"hNvQHb", b"f.req", b"StreamGenerate", b"batchexecute")
                        if (pos := protocol_data.find(marker)) >= 0
                    ]
                    if marker_positions:
                        first_marker = min(marker_positions)
                        line_start = max(protocol_data.rfind(b"\n", 0, first_marker),
                                         protocol_data.rfind(b"\r", 0, first_marker)) + 1
                        line_end_n = protocol_data.find(b"\n", first_marker)
                        line_end_r = protocol_data.find(b"\r", first_marker)
                        ends = [x for x in (line_end_n, line_end_r) if x >= 0]
                        if not ends:
                            candidate_carry = protocol_data[line_start:]
                            if len(candidate_carry) < MAX_PROTOCOL_TEXT:
                                protocol_carry = candidate_carry
                                protocol_carry_base = protocol_base + line_start
                                pending_start = line_start

                # Defer only a single unfinished line. With a completed prefix, retain the
                # full old context (f.req can use a Gemini anchor on a neighboring line).
                # Keep gzip handling unchanged: a binary member is not a text line.
                protocol_input = protocol_data
                if service_worker and pending_start == 0 and b"\x1f\x8b\x08" not in protocol_data:
                    protocol_input = b""
                protocol_inputs = [(protocol_input, protocol_base)] if protocol_input else []
                if (service_worker and len(protocol_data) >= MAX_PROTOCOL_TEXT
                        and b"\x1f\x8b\x08" not in protocol_data):
                    # A valid frame may precede a very long unterminated suffix. Preserve
                    # recovery at the bound before the full line exceeds the decoder cap.
                    protocol_inputs.insert(0, (protocol_data[:MAX_PROTOCOL_TEXT], protocol_base))
                if gzip_carry:
                    gzip_probe = gzip_carry + block
                    protocol_inputs.append((gzip_probe, gzip_carry_base))
                else:
                    gzip_probe = data
                    gzip_carry_base = base

                for protocol_input, input_base in protocol_inputs:
                    for message in self._protocol_messages_from_bytes(
                            protocol_input, input_base):
                        identity = (
                            message.get("conversation_id"), message.get("response_id"), message.get("choice_id"),
                            message.get("role"), message.get("message_content"), message.get("protocol_offset"),
                        )
                        if identity in seen_protocol:
                            continue
                        if len(protocol_messages) >= self.max_matches_per_file:
                            truncated_protocol = True
                            break
                        seen_protocol.add(identity)
                        protocol_messages.append(message)

                # Aggressive prompt fallback: search the full chunk (not only the ±2 KiB
                # gemini.google.com hit context) for explicitly labelled user text.  The helper
                # requires a nearby Gemini-specific anchor and rejects Google Search pages.
                # This recovers prompt strings that survive locally even when the private RPC
                # container is truncated or no longer decodable.
                aggressive_views = []
                for enc in ("utf-8", "utf-16le"):
                    try:
                        decoded_view = data.decode(enc, errors="ignore")
                    except Exception:
                        continue
                    low_view = decoded_view.casefold()
                    if origin_scoped or any(marker in low_view for marker in (
                        "gemini.google.com", "hnvQHb".casefold(), "streamgenerate", "bardchatui"
                    )):
                        aggressive_views.append((decoded_view, enc))
                for decoded_view, enc in aggressive_views:
                    for prompt in self._extract_aggressive_prompt_candidates_from_text(
                            decoded_view, base, enc, origin_scoped):
                        identity = (
                            prompt.get("conversation_id"), prompt.get("role"),
                            prompt.get("message_content"), prompt.get("protocol_offset"),
                        )
                        if identity in seen_prompts:
                            continue
                        if len(prompt_candidates) >= AGGRESSIVE_PROMPT_MAX_PER_FILE:
                            truncated_prompts = True
                            break
                        seen_prompts.add(identity)
                        prompt_candidates.append(prompt)

                # A large gzip-compressed cache response can span raw scan chunks.  Preserve an
                # incomplete gzip member from its header until zlib reports EOF, subject to the
                # same bounded protocol size. This lets long compressed hNvQHb/stream responses
                # be decoded without retaining entire cache files in memory.
                gzip_carry, next_gzip_base = b"", 0
                if not final and len(gzip_probe) < MAX_PROTOCOL_TEXT:
                    search_at = 0
                    while True:
                        gz_at = gzip_probe.find(b"\x1f\x8b\x08", search_at)
                        if gz_at < 0:
                            break
                        try:
                            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
                            raw_probe = obj.decompress(gzip_probe[gz_at:], MAX_PROTOCOL_TEXT)
                            incomplete = not obj.eof and len(raw_probe) < MAX_PROTOCOL_TEXT
                        except (zlib.error, ValueError, OverflowError):
                            incomplete = False
                        if incomplete:
                            candidate_gzip = gzip_probe[gz_at:]
                            if len(candidate_gzip) < MAX_PROTOCOL_TEXT:
                                gzip_carry = candidate_gzip
                                next_gzip_base = gzip_carry_base + gz_at
                                break
                        search_at = gz_at + 3
                gzip_carry_base = next_gzip_base

                tail = data[-OVERLAP:]
        current = path.stat()
        changed = (size, initial.st_mtime_ns, initial.st_ctime_ns) != (
            current.st_size, current.st_mtime_ns, current.st_ctime_ns)
        return {"hits": hits, "images": images, "protocol_messages": protocol_messages,
                "prompt_candidates": prompt_candidates, "bytes_read": consumed,
                "file_size_at_scan_start": size, "scan_limit_reached": consumed < size,
                "string_result_limit_reached": truncated_hits, "image_result_limit_reached": truncated_images,
                "protocol_result_limit_reached": truncated_protocol,
                "prompt_result_limit_reached": truncated_prompts,
                "file_changed_during_scan": changed, "header_hex": header.hex(),
                "session_signature": "SNSS" if header[:4] == b"SNSS" else None,
                "session_version_candidate": struct.unpack_from("<I", header, 4)[0]
                if len(header) == 8 and header[:4] == b"SNSS" else None}

    def _parse_browser_artifact(self, key):
        """Run native Chromium decoding first, then preserve the v1.2 raw scanner as fallback/support."""
        if self.deep_recovery:
            self._parse_ccl_artifact(key)
        self._parse_binary_artifact(key)

    def _deep_recovery_status(self, key, observation, *, detail=None, status="partial", error=None):
        payload = {
            "record_type": "deep_recovery_status",
            "decoder": "ccl_chromium_reader",
            "expected_version": CCL_EXPECTED_VERSION,
            "expected_commit": CCL_EXPECTED_COMMIT,
            "native_structure_decoded": status in {"success", "partial"} and not error,
            **(detail or {}),
        }
        return self._emit(key, observation, path=self._expected.get(key), detail=payload,
                          level="unconfirmed", status=status, error=error)

    @classmethod
    def _structured_messages_from_json_value(cls, value, *, conversation_hint=None,
                                             basis="ccl_structured_object", protocol="structured-json",
                                             max_messages=2000):
        """Recover only explicit message objects from decoded Gemini-owned JSON-like storage.

        This is deliberately stricter than a string walk: role + text + an explicit/ancestor
        conversation id are required.  It exists mainly for IndexedDB/Local Storage records whose
        object model is already deserialized by CCL.
        """
        output, seen = [], set()
        stack = [(value, conversation_hint, "", 0)]
        visited = 0

        def cid_from_dict(node, current):
            for name in ("conversation_id", "conversationId", "conversation_uuid", "conversationUuid",
                         "chat_id", "chatId"):
                candidate = node.get(name)
                cid = cls._conversation_protocol_id(candidate) if isinstance(candidate, str) else None
                if cid:
                    return cid
            for name in ("url", "href", "conversation_url", "conversationUrl"):
                candidate = node.get(name)
                cid = cls._explicit_conversation_id_from_text(candidate) if isinstance(candidate, str) else None
                if cid:
                    return cid
            return current

        def text_from_content(content):
            if isinstance(content, str):
                return cls._normalize_message_content(content)
            if isinstance(content, list):
                parts = []
                for item in content[:200]:
                    if isinstance(item, str):
                        cleaned = cls._normalize_message_content(item)
                        if cleaned:
                            parts.append(cleaned)
                    elif isinstance(item, dict):
                        for field in ("text", "content"):
                            if isinstance(item.get(field), str):
                                cleaned = cls._normalize_message_content(item[field])
                                if cleaned:
                                    parts.append(cleaned)
                                    break
                return "\n".join(parts) if parts else None
            if isinstance(content, dict):
                for field in ("text", "message", "value"):
                    if isinstance(content.get(field), str):
                        cleaned = cls._normalize_message_content(content[field])
                        if cleaned:
                            return cleaned
                if isinstance(content.get("parts"), list):
                    return text_from_content(content["parts"])
            return None

        while stack and visited < 25000 and len(output) < max_messages:
            node, current_cid, current_title, depth = stack.pop()
            visited += 1
            if depth > 18:
                continue
            if isinstance(node, str):
                stripped = node.strip()
                if stripped[:1] in "[{" and len(stripped) <= MAX_PROTOCOL_TEXT:
                    try:
                        stack.append((json.loads(stripped), current_cid, current_title, depth + 1))
                    except Exception:
                        pass
                continue
            if isinstance(node, list):
                for child in reversed(node[:1000]):
                    stack.append((child, current_cid, current_title, depth + 1))
                continue
            if not isinstance(node, dict):
                continue

            cid = cid_from_dict(node, current_cid)
            title = current_title
            for title_key in ("conversation_title", "conversationTitle", "title", "name"):
                if isinstance(node.get(title_key), str) and node.get(title_key).strip():
                    title = cls._clean_title(node.get(title_key))
                    break

            role = node.get("role") or node.get("sender")
            author = node.get("author")
            if isinstance(author, dict):
                role = role or author.get("role") or author.get("name")
            elif isinstance(author, str):
                role = role or author
            role = str(role or "").strip().lower()
            if role == "human":
                role = "user"
            elif role in {"model", "gemini"}:
                role = "assistant"

            content = None
            for field in ("message_content", "message_text", "text", "content", "parts"):
                if field in node:
                    content = text_from_content(node.get(field))
                    if content:
                        break
            if role in {"user", "assistant"} and content and cid:
                message_id = node.get("message_id") or node.get("messageId") or node.get("message_uuid") or node.get("messageUuid") or node.get("id")
                parent = node.get("parent_message_id") or node.get("parentMessageId") or node.get("parent_message_uuid") or node.get("parentMessageUuid") or node.get("parent_id")
                message_time = node.get("created_at") or node.get("create_time") or node.get("timestamp") or node.get("time")
                item = {
                    "conversation_id": cid,
                    "conversation_title": title,
                    "message_id": str(message_id) if message_id not in (None, "") else "",
                    "parent_message_id": str(parent) if parent not in (None, "") else "",
                    "message_order": node.get("message_order") or node.get("index") or node.get("sequence"),
                    "role": role,
                    "message_content": content,
                    "message_timestamp": message_time,
                    "recovery_basis": basis,
                    "protocol": protocol,
                }
                ident = (cid, item["message_id"], role, content)
                if ident not in seen:
                    seen.add(ident)
                    output.append(item)

            for child in reversed(list(node.values())):
                if isinstance(child, (dict, list, str)):
                    stack.append((child, cid, title, depth + 1))
        return output

    def _emit_deep_message(self, key, path, message, *, locator=None, extra=None):
        basis = str(message.get("recovery_basis") or "ccl_native")
        qualified = self._qualified_message_recovery_basis(basis)
        detail = {
            "record_type": "finding",
            "conversation_id": message.get("conversation_id"),
            "conversation_title": message.get("conversation_title") or "",
            "message_id": message.get("message_id") or "",
            "parent_message_id": message.get("parent_message_id") or "",
            "message_order": message.get("message_order"),
            "role": message.get("role") or "",
            "message_content": message.get("message_content") or "",
            "response_id": message.get("response_id"),
            "choice_id": message.get("choice_id"),
            "candidate_rank": message.get("candidate_rank"),
            "message_timestamp": message.get("message_timestamp") or "",
            "recovery_basis": basis,
            "protocol": message.get("protocol") or "ccl-native",
            "protocol_offset": message.get("protocol_offset"),
            "protocol_sequence": message.get("protocol_sequence"),
            "native_chromium_structure_decoded": True,
            "message_semantics_verified": qualified,
            "container_decoder": "ccl_chromium_reader",
            "limitation": (
                "Container/native structure was decoded, but this candidate did not pass the "
                "allowlist for message semantics and is retained only as supporting evidence."
                if not qualified else None
            ),
            **(extra or {}),
        }
        timestamp = normalize_team_kst_timestamp(message.get("message_timestamp"))
        return self._emit(
            key,
            "Native Chromium Gemini message recovered" if qualified else
            "Gemini message candidate preserved; message semantics not verified",
            path=path, detail=detail, locator=locator or {}, timestamp=timestamp,
            level="direct" if qualified else "support",
            status="success" if qualified else "partial",
        )

    def _parse_ccl_artifact(self, key):
        modules = _load_ccl_modules()
        if modules is None:
            self._deep_recovery_status(
                key, "Native Chromium deep recovery unavailable; raw fallback will continue",
                detail={"ccl_available": False, "fallback": "raw_scan"},
                status="partial", error=_CCL_IMPORT_ERROR,
            )
            return 0
        try:
            if key == "cache":
                return self._parse_ccl_cache(key, modules)
            if key == "indexeddb":
                return self._parse_ccl_indexeddb(key, modules)
            if key == "local_storage":
                return self._parse_ccl_local_storage(key, modules)
            if key == "session_storage":
                return self._parse_ccl_session_storage(key, modules)
            if key == "service_worker":
                return self._parse_ccl_service_worker(key, modules)
            if key == "sessions":
                return self._parse_ccl_sessions(key, modules)
        except Exception as exc:
            self._deep_recovery_status(
                key, "Native Chromium deep recovery failed; raw fallback will continue",
                detail={"ccl_available": True, "fallback": "raw_scan"},
                status="partial", error=error_text(exc),
            )
        return 0

    def _parse_ccl_cache(self, key, modules):
        """Decode Chromium Cache entries and preserve per-key diagnostics.

        v1.3.1 deliberately distinguishes: metadata present, body stream absent, body read
        exception, empty body, decompression failure, non-text body, and decoded text with no
        Gemini message.  This prevents `bodies_decoded=0` from hiding the actual failure mode.
        """
        directory = Path(self.artifacts[key])
        cache_module = modules["cache"]
        cache_type = cache_module.guess_cache_class(directory)
        if cache_type is None:
            self._deep_recovery_status(
                key, "Chromium cache layout was not recognized by CCL",
                detail={"ccl_available": True, "cache_layout": "unrecognized"}, status="partial")
            return 0

        cache = cache_type(directory)
        entered = False
        if hasattr(cache, "__enter__"):
            cache.__enter__(); entered = True

        keys_examined = gemini_keys = variants = bodies_decoded = messages_found = 0
        metadata_read_errors = body_read_errors = location_read_errors = 0
        body_stream_absent = empty_bodies = decode_errors = nontext_bodies = decoded_text_bodies = 0
        api_like_keys = 0
        diagnostic_rows = 0
        try:
            try:
                keys = list(cache.keys())
            except Exception as exc:
                keys = []
                self._deep_recovery_status(
                    key, "Chromium Cache key enumeration failed; raw fallback will continue",
                    detail={"ccl_available": True, "cache_layout": getattr(cache_type, "__name__", str(cache_type)),
                            "key_enumeration_error": error_text(exc)},
                    status="partial", error=error_text(exc))
            keys_examined = len(keys)

            for raw_key in keys:
                key_text = _ccl_safe_str(raw_key)
                gemini_url = _cache_key_gemini_url(key_text)
                if not gemini_url:
                    continue
                gemini_keys += 1
                endpoint_kind = _gemini_cache_endpoint_kind(gemini_url)
                if endpoint_kind in {"batchexecute", "streamgenerate", "bardchatui", "conversation_page"}:
                    api_like_keys += 1

                stream_state = _ccl_cache_stream_state(cache, raw_key)
                meta_error = body_error = meta_loc_error = body_loc_error = None
                try:
                    metas = list(cache.get_metadata(raw_key))
                except Exception as exc:
                    metas = []
                    metadata_read_errors += 1
                    meta_error = error_text(exc)
                try:
                    bodies = list(cache.get_cachefile(raw_key))
                except Exception as exc:
                    bodies = []
                    body_read_errors += 1
                    body_error = error_text(exc)
                try:
                    meta_locs = list(cache.get_location_for_metadata(raw_key))
                except Exception as exc:
                    meta_locs = []
                    location_read_errors += 1
                    meta_loc_error = error_text(exc)
                try:
                    body_locs = list(cache.get_location_for_cachefile(raw_key))
                except Exception as exc:
                    body_locs = []
                    location_read_errors += 1
                    body_loc_error = error_text(exc)

                count = max(len(metas), len(bodies), len(meta_locs), len(body_locs), 1)
                for variant in range(count):
                    variants += 1
                    meta = metas[variant] if variant < len(metas) else None
                    body = bodies[variant] if variant < len(bodies) else None
                    meta_loc = meta_locs[variant] if variant < len(meta_locs) else None
                    body_loc = body_locs[variant] if variant < len(body_locs) else None
                    content_type = _ccl_header_value(meta, "content-type") or ""
                    content_encoding = _ccl_header_value(meta, "content-encoding") or ""
                    content_length = _ccl_header_value(meta, "content-length") or ""
                    response_time = _ccl_get_attr(meta, "response_time", default=None)
                    request_time = _ccl_get_attr(meta, "request_time", default=None)

                    diagnostic = {
                        "record_type": "deep_recovery_diagnostic",
                        "diagnostic_kind": "cache_entry",
                        "decoder": "ccl_chromium_reader",
                        "cache_layout": getattr(cache_type, "__name__", str(cache_type)),
                        "cache_key_raw": key_text,
                        "gemini_url": gemini_url,
                        "endpoint_kind": endpoint_kind,
                        "variant": variant,
                        "metadata_present": meta is not None,
                        "metadata_count": len(metas),
                        "body_result_count": len(bodies),
                        "body_present": body is not None,
                        "body_length": len(body) if isinstance(body, (bytes, bytearray)) else None,
                        "content_type": content_type,
                        "content_encoding": content_encoding,
                        "content_length_header": content_length,
                        "metadata_location": _ccl_location_str(meta_loc),
                        "body_location": _ccl_location_str(body_loc),
                        "request_time": _ccl_safe_str(request_time),
                        "response_time": _ccl_safe_str(response_time),
                        "metadata_read_error": meta_error,
                        "body_read_error": body_error,
                        "metadata_location_error": meta_loc_error,
                        "body_location_error": body_loc_error,
                        **stream_state,
                    }

                    # CCL Blockfile stream 1 is the cached resource body.  Do not silently
                    # turn an uninitialised stream into a successful zero-length decode.
                    if body is None:
                        body_stream_absent += 1
                        diagnostic["body_state"] = "absent_or_uninitialized" if not body_error else "read_error"
                        self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=directory,
                                   detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                                   level="unconfirmed", status="partial" if body_error else "success",
                                   error=body_error)
                        diagnostic_rows += 1
                        continue
                    if not isinstance(body, (bytes, bytearray)):
                        body_read_errors += 1
                        diagnostic["body_state"] = "unexpected_non_bytes"
                        diagnostic["body_python_type"] = type(body).__name__
                        self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=directory,
                                   detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                                   level="unconfirmed", status="partial",
                                   error=f"unexpected cache body type: {type(body).__name__}")
                        diagnostic_rows += 1
                        continue
                    if len(body) == 0:
                        empty_bodies += 1
                        diagnostic["body_state"] = "empty"
                        self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=directory,
                                   detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                                   level="unconfirmed", status="success")
                        diagnostic_rows += 1
                        continue

                    decoded, applied, decode_error = _deep_decode_http_body(body, content_encoding)
                    diagnostic["body_sha256"] = hashlib.sha256(bytes(body)).hexdigest()
                    diagnostic["applied_decoders"] = applied
                    if decoded is None:
                        decode_errors += 1
                        diagnostic["body_state"] = "decode_error"
                        diagnostic["decode_error"] = decode_error
                        self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=_ccl_location_path(body_loc, directory),
                                   detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                                   level="unconfirmed", status="partial", error=decode_error)
                        diagnostic_rows += 1
                        continue

                    bodies_decoded += 1
                    diagnostic["decoded_body_length"] = len(decoded)
                    diagnostic["decoded_body_sha256"] = hashlib.sha256(decoded).hexdigest()
                    text, text_encoding = _deep_decode_text(decoded, content_type)
                    diagnostic["text_encoding"] = text_encoding
                    if text is None:
                        nontext_bodies += 1
                        diagnostic["body_state"] = "decoded_nontext"
                        self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=_ccl_location_path(body_loc, directory),
                                   detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                                   level="unconfirmed", status="success")
                        diagnostic_rows += 1
                        continue

                    decoded_text_bodies += 1
                    diagnostic["body_state"] = "decoded_text"
                    diagnostic["text_length"] = len(text)
                    low_text = text.casefold()
                    diagnostic["protocol_markers"] = [m for m in ("wrb.fr", "hnvQHb", "streamgenerate", "f.req", "batchexecute")
                                                        if m.casefold() in low_text]

                    messages = []
                    for msg in self._wrb_messages_from_text(text, 0):
                        item = dict(msg)
                        item["recovery_basis"] = "ccl_cache_" + str(item.get("recovery_basis") or "wrb")
                        messages.append(item)
                    for msg in self._f_req_messages_from_text(text, 0):
                        item = dict(msg)
                        item["recovery_basis"] = "ccl_cache_" + str(item.get("recovery_basis") or "f_req")
                        messages.append(item)

                    # Already-materialised JSON is common on some cache surfaces.
                    if text.lstrip()[:1] in "[{":
                        try:
                            parsed = json.loads(text.lstrip())
                        except Exception:
                            parsed = None
                        if parsed is not None:
                            messages.extend(self._structured_messages_from_json_value(
                                parsed, conversation_hint=conversation_id(gemini_url),
                                basis="ccl_cache_structured_object", protocol="cache-json"))

                    # Strongly Gemini-owned Cache bodies may still contain an explicitly labelled
                    # prompt even when a private RPC wrapper is truncated.  Reuse the existing
                    # conservative fallback only on API/conversation entries, never on static assets.
                    if not messages and endpoint_kind in {"batchexecute", "streamgenerate", "bardchatui", "conversation_page"}:
                        for candidate in self._extract_aggressive_prompt_candidates_from_text(
                                text, 0, text_encoding or "utf-8", True):
                            if candidate.get("role") == "user" and candidate.get("message_content"):
                                item = dict(candidate)
                                item["recovery_basis"] = "ccl_cache_aggressive_prompt"
                                item.setdefault("protocol", "cache-text")
                                messages.append(item)

                    dedup = {}
                    for msg in messages:
                        ident = (msg.get("conversation_id"), msg.get("message_id"), msg.get("response_id"),
                                 msg.get("choice_id"), msg.get("role"), msg.get("message_content"))
                        dedup.setdefault(ident, msg)
                    diagnostic["message_candidates"] = len(dedup)
                    if diagnostic["protocol_markers"]:
                        diagnostic["body_state"] = "decoded_protocol_text"

                    self._emit(key, "Gemini Cache entry deep-recovery diagnostic", path=_ccl_location_path(body_loc, directory),
                               detail=diagnostic, locator={"cache_key": gemini_url, "variant": variant},
                               level="unconfirmed", status="success")
                    diagnostic_rows += 1

                    for msg in dedup.values():
                        locator = {
                            "cache_key": gemini_url,
                            "variant": variant,
                            "metadata_location": _ccl_location_str(meta_loc),
                            "body_location": _ccl_location_str(body_loc),
                        }
                        body_source_path = _ccl_location_path(body_loc, directory)
                        self._emit_deep_message(key, body_source_path, msg, locator=locator, extra={
                            "cache_key": gemini_url,
                            "cache_variant": variant,
                            "endpoint_kind": endpoint_kind,
                            "content_type": content_type,
                            "content_encoding": content_encoding,
                            "applied_decoders": applied,
                            "text_encoding": text_encoding,
                            "decoded_body_sha256": hashlib.sha256(decoded).hexdigest(),
                            "body_sha256": hashlib.sha256(bytes(body)).hexdigest(),
                        })
                        messages_found += 1
        finally:
            if entered:
                try:
                    cache.__exit__(None, None, None)
                except Exception:
                    pass
            elif hasattr(cache, "close"):
                try:
                    cache.close()
                except Exception:
                    pass

        total_errors = metadata_read_errors + body_read_errors + location_read_errors + decode_errors
        self._deep_recovery_status(
            key, "Native Chromium Cache deep recovery completed",
            detail={
                "ccl_available": True,
                "cache_layout": getattr(cache_type, "__name__", str(cache_type)),
                "keys_examined": keys_examined,
                "gemini_keys": gemini_keys,
                "api_like_gemini_keys": api_like_keys,
                "variants_examined": variants,
                "body_stream_absent": body_stream_absent,
                "empty_body_variants": empty_bodies,
                "bodies_decoded": bodies_decoded,
                "decoded_text_bodies": decoded_text_bodies,
                "nontext_bodies": nontext_bodies,
                "metadata_read_errors": metadata_read_errors,
                "body_read_errors": body_read_errors,
                "location_read_errors": location_read_errors,
                "decode_errors": decode_errors,
                "diagnostic_rows": diagnostic_rows,
                "message_findings": messages_found,
                "interpretation": (
                    "Gemini cache keys were present but their response-body stream was absent/uninitialised."
                    if gemini_keys and body_stream_absent == variants and not total_errors else
                    "See deep_recovery_diagnostic cache_entry rows for per-key body state."
                ),
            },
            status="success" if not total_errors else "partial")
        return messages_found

    @staticmethod
    def _ccl_idb_key_text(key):
        value = _ccl_get_attr(key, "value", default=None)
        return _ccl_safe_str(value if value is not None else key)

    def _parse_ccl_indexeddb(self, key, modules):
        root = Path(self.artifacts[key])
        idb_module = modules["indexeddb"]
        all_directories = sorted(p for p in root.iterdir() if p.is_dir() and p.name.endswith(".leveldb"))
        # Chromium IndexedDB directory names include the origin.  Do not attempt to open unrelated
        # ChatGPT/Claude databases and then report their unsupported record types as a Gemini error.
        directories = [p for p in all_directories if any(token in p.name.casefold() for token in
                       ("gemini.google.com", "bard.google.com", "gemini", "bard"))]
        ignored = [p.name for p in all_directories if p not in directories]
        records_examined = gemini_records = messages_found = errors = 0
        directory_errors = []

        if not directories:
            self._deep_recovery_status(
                key, "No Gemini-owned Chromium IndexedDB directory was present",
                detail={"ccl_available": True, "leveldb_directories": len(all_directories),
                        "gemini_leveldb_directories": 0, "ignored_non_gemini_directories": ignored[:50],
                        "records_examined": 0, "gemini_scoped_records": 0,
                        "message_findings": 0, "decode_errors": 0},
                status="success")
            return 0

        for leveldb_dir in directories:
            blob_dir = leveldb_dir.with_name(leveldb_dir.name[:-8] + ".blob")
            try:
                try:
                    wrapper = idb_module.WrappedIndexDB(leveldb_dir, blob_dir if blob_dir.exists() else None)
                except TypeError:
                    wrapper = idb_module.WrappedIndexDB(leveldb_dir)
            except Exception as exc:
                errors += 1
                directory_errors.append({"directory": leveldb_dir.name, "stage": "open", "error": error_text(exc)})
                continue
            try:
                try:
                    database_ids = list(getattr(wrapper, "database_ids", []) or [])
                except Exception as exc:
                    errors += 1
                    directory_errors.append({"directory": leveldb_dir.name, "stage": "database_ids", "error": error_text(exc)})
                    continue
                for database_id in database_ids:
                    db_no = _ccl_get_attr(database_id, "dbid_no", "db_id", default=None)
                    try:
                        database = wrapper[db_no] if db_no is not None else wrapper[database_id]
                    except Exception as exc:
                        errors += 1
                        directory_errors.append({"directory": leveldb_dir.name, "stage": "database_open",
                                                 "database_id": _ccl_safe_str(database_id), "error": error_text(exc)})
                        continue
                    db_name = _ccl_safe_str(_ccl_get_attr(database, "name", "database_name", default=""))
                    origin = _ccl_safe_str(_ccl_get_attr(database, "origin", "database_origin", default=""))
                    origin_is_gemini = is_gemini_url(origin) or "gemini.google.com" in origin.casefold() or "bard.google.com" in origin.casefold()
                    try:
                        store_names = list(_ccl_get_attr(database, "object_store_names", default=[]) or [])
                    except Exception as exc:
                        errors += 1
                        directory_errors.append({"directory": leveldb_dir.name, "stage": "object_store_names",
                                                 "database": db_name, "error": error_text(exc)})
                        continue
                    for store_name in store_names:
                        try:
                            store = database.get_object_store_by_name(store_name) if hasattr(database, "get_object_store_by_name") else database[store_name]
                            iterator = store.iterate_records(errors_to_stdout=False)
                        except Exception as exc:
                            errors += 1
                            directory_errors.append({"directory": leveldb_dir.name, "stage": "store_open",
                                                     "database": db_name, "store": _ccl_safe_str(store_name),
                                                     "error": error_text(exc)})
                            continue
                        try:
                            for record in iterator:
                                records_examined += 1
                                record_key = self._ccl_idb_key_text(_ccl_get_attr(record, "key", "user_key", default=None))
                                value = _ccl_get_attr(record, "value", default=None)
                                value_text = ""
                                if isinstance(value, str):
                                    value_text = value
                                elif isinstance(value, bytes):
                                    value_text, _ = _deep_decode_text(value, None)
                                    value_text = value_text or ""
                                elif isinstance(value, (dict, list)):
                                    try:
                                        value_text = json.dumps(value, ensure_ascii=False, default=str)
                                    except Exception:
                                        value_text = ""
                                scoped = (origin_is_gemini or "gemini" in db_name.casefold() or
                                          "bard" in db_name.casefold() or
                                          "gemini.google.com" in value_text[:8192].casefold())
                                if not scoped:
                                    continue
                                gemini_records += 1
                                cid_hint = self._explicit_conversation_id_from_text(record_key + " " + value_text[:8192])
                                messages = self._structured_messages_from_json_value(
                                    value, conversation_hint=cid_hint,
                                    basis="ccl_indexeddb_structured_object", protocol="indexeddb-object")
                                if value_text:
                                    for msg in self._wrb_messages_from_text(value_text, 0):
                                        item = dict(msg); item["recovery_basis"] = "ccl_indexeddb_" + str(item.get("recovery_basis") or "wrb"); messages.append(item)
                                    for msg in self._f_req_messages_from_text(value_text, 0):
                                        item = dict(msg); item["recovery_basis"] = "ccl_indexeddb_" + str(item.get("recovery_basis") or "f_req"); messages.append(item)
                                seen = set()
                                for msg in messages:
                                    ident = (msg.get("conversation_id"), msg.get("message_id"), msg.get("role"), msg.get("message_content"))
                                    if ident in seen:
                                        continue
                                    seen.add(ident)
                                    self._emit_deep_message(key, leveldb_dir, msg, locator={
                                        "database": db_name, "object_store": _ccl_safe_str(store_name),
                                        "key": record_key, "ldb_seq_no": _ccl_get_attr(record, "ldb_seq_no", default=None),
                                        "record_location": _ccl_safe_str(_ccl_get_attr(record, "record_location", default="")),
                                    }, extra={"indexeddb_origin": origin, "indexeddb_key": record_key,
                                              "record_state": "live" if _ccl_get_attr(record, "is_live", default=None) is True else
                                                              "historical_or_deleted" if _ccl_get_attr(record, "is_live", default=None) is False else "unknown"})
                                    messages_found += 1
                        except Exception as exc:
                            errors += 1
                            directory_errors.append({"directory": leveldb_dir.name, "stage": "record_iteration",
                                                     "database": db_name, "store": _ccl_safe_str(store_name),
                                                     "error": error_text(exc)})
            finally:
                if hasattr(wrapper, "close"):
                    try:
                        wrapper.close()
                    except Exception:
                        pass

        self._deep_recovery_status(
            key, "Native Chromium IndexedDB deep recovery completed",
            detail={"ccl_available": True, "leveldb_directories": len(all_directories),
                    "gemini_leveldb_directories": len(directories),
                    "ignored_non_gemini_directories": ignored[:50],
                    "records_examined": records_examined, "gemini_scoped_records": gemini_records,
                    "message_findings": messages_found, "decode_errors": errors,
                    "directory_errors": directory_errors[:20]},
            status="success" if not errors else "partial")
        return messages_found

    def _parse_ccl_local_storage(self, key, modules):
        directory = Path(self.artifacts[key])
        module = modules["local_storage"]
        store = module.LocalStoreDb(directory)
        records_examined = gemini_records = logical_messages = errors = 0
        try:
            for storage_key in store.iter_storage_keys():
                storage_text = _ccl_safe_str(storage_key)
                if "gemini.google.com" not in storage_text.lower() and "bard.google.com" not in storage_text.lower():
                    continue
                try:
                    records = store.iter_records_for_storage_key(storage_key)
                    for record in records:
                        records_examined += 1
                        gemini_records += 1
                        value = _ccl_get_attr(record, "value", default=None)
                        if isinstance(value, bytes):
                            text, _ = _deep_decode_text(value, None)
                            text = text or ""
                        else:
                            text = _ccl_safe_str(value)
                        script_key = _ccl_safe_str(_ccl_get_attr(record, "script_key", "key", default=""))
                        cid_hint = self._explicit_conversation_id_from_text(script_key + " " + text[:8192])
                        parsed = None
                        if text.strip()[:1] in "[{":
                            try:
                                parsed = json.loads(text.strip())
                            except Exception:
                                parsed = None
                        messages = self._structured_messages_from_json_value(
                            parsed if parsed is not None else value, conversation_hint=cid_hint,
                            basis="ccl_local_storage_structured_object", protocol="local-storage")
                        for extractor, suffix in ((self._wrb_messages_from_text, "wrb"),
                                                  (self._f_req_messages_from_text, "f_req")):
                            for msg in extractor(text, 0):
                                item = dict(msg)
                                item["recovery_basis"] = "ccl_local_storage_" + str(item.get("recovery_basis") or suffix)
                                messages.append(item)
                        seen = set()
                        for msg in messages:
                            ident = (msg.get("conversation_id"), msg.get("message_id"), msg.get("role"), msg.get("message_content"))
                            if ident in seen:
                                continue
                            seen.add(ident)
                            origin_file = _ccl_safe_str(_ccl_get_attr(record, "file", "origin_file", default=""))
                            source = directory / Path(origin_file).name if origin_file else directory
                            self._emit_deep_message(key, source, msg, locator={
                                "storage_key": storage_text, "script_key": script_key,
                                "leveldb_seq_number": _ccl_get_attr(record, "leveldb_seq_number", "leveldb_sequence_number", "sequence_number", default=None),
                            }, extra={"storage_key": storage_text, "script_key": script_key,
                                      "persistent_source_class": "local_storage_logical"})
                            logical_messages += 1
                except Exception:
                    errors += 1
        finally:
            try:
                store.close()
            except Exception:
                pass

        stale = self._scan_ccl_raw_leveldb(
            key, directory, modules, source_tag="local_storage_stale",
            protocol_name="local-storage-leveldb")
        messages_found = logical_messages + stale["message_findings"]
        errors += stale["decode_errors"]
        self._deep_recovery_status(
            key, "Native Chromium Local Storage deep recovery completed",
            detail={"ccl_available": True, "records_examined": records_examined,
                    "gemini_scoped_records": gemini_records,
                    "logical_message_findings": logical_messages,
                    "stale_leveldb": stale, "message_findings": messages_found,
                    "decode_errors": errors},
            status="success" if not errors else "partial")
        return messages_found

    def _scan_ccl_raw_leveldb(self, key, directory, modules, *, source_tag, protocol_name):
        """Inspect LevelDB physical records, including stale/deleted table entries.

        Only records whose key/value explicitly contains a Gemini/Bard origin are treated as
        Gemini-scoped.  This keeps stale-record recovery conservative and prevents generic f.req
        strings from another web app being promoted as Gemini evidence.
        """
        directory = Path(directory)
        stats = {
            "directory": str(directory), "present": directory.is_dir(),
            "records_examined": 0, "deleted_records": 0, "explicit_deleted_records": 0,
            "compressed_records": 0, "gemini_scoped_records": 0,
            "protocol_marker_records": 0, "message_findings": 0,
            "deleted_message_findings": 0, "decode_errors": 0,
            "stale_record_note": (
                "RawLevelDb exposes physical .log/.ldb/.sst records, including obsolete versions. "
                "deleted_records counts only explicit LevelDB tombstones; an older stale value may still have state=Live."
            ),
        }
        if not directory.is_dir():
            return stats
        raw_module = modules.get("leveldb")
        if raw_module is None:
            stats["decode_errors"] = 1
            stats["error"] = "CCL raw LevelDB module unavailable"
            return stats
        try:
            with raw_module.RawLevelDb(directory) as raw_db:
                for record in raw_db.iterate_records_raw():
                    stats["records_examined"] += 1
                    state = _ccl_safe_str(_ccl_get_attr(record, "state", default="unknown"))
                    state_name = _ccl_safe_str(_ccl_get_attr(_ccl_get_attr(record, "state", default=None), "name", default=state))
                    if state_name.casefold() == "deleted":
                        stats["deleted_records"] += 1
                        stats["explicit_deleted_records"] += 1
                    if bool(_ccl_get_attr(record, "was_compressed", default=False)):
                        stats["compressed_records"] += 1

                    user_key = _ccl_get_attr(record, "user_key", "key", default=b"")
                    value = _ccl_get_attr(record, "value", default=b"")
                    key_bytes = bytes(user_key) if isinstance(user_key, (bytes, bytearray)) else _ccl_safe_str(user_key).encode("utf-8", "ignore")
                    value_bytes = bytes(value) if isinstance(value, (bytes, bytearray)) else _ccl_safe_str(value).encode("utf-8", "ignore")
                    raw = key_bytes + b"\n" + value_bytes
                    low = raw.lower()
                    domain_ascii = b"gemini.google.com" in low or b"bard.google.com" in low
                    domain_utf16 = ("gemini.google.com".encode("utf-16le") in low
                                    or "bard.google.com".encode("utf-16le") in low)

                    key_text, _ = _deep_decode_text(key_bytes, None)
                    if key_text is None:
                        key_text = _ccl_safe_str(user_key)
                    value_text, _ = _deep_decode_text(value_bytes, None)
                    value_text = value_text or ""
                    low_text = (key_text + "\n" + value_text).casefold()
                    protocol_marker = any(
                        marker in low_text
                        for marker in ("wrb.fr", "hnvqhb", "streamgenerate", "f.req", "batchexecute")
                    )
                    if protocol_marker:
                        stats["protocol_marker_records"] += 1
                    if domain_ascii or domain_utf16:
                        stats["gemini_scoped_records"] += 1
                    # Generic structured-object recovery requires an explicit Gemini/Bard origin.
                    # Protocol decoders may additionally inspect a record without an origin string,
                    # because Session Storage physical records can separate origin metadata from values;
                    # the protocol decoders themselves remain Gemini-specific and reject unrelated traffic.
                    if not (domain_ascii or domain_utf16 or protocol_marker):
                        continue

                    cid_hint = self._explicit_conversation_id_from_text(key_text + " " + value_text[:8192])
                    parsed = None
                    if value_text.strip()[:1] in "[{":
                        try:
                            parsed = json.loads(value_text.strip())
                        except Exception:
                            parsed = None
                    messages = []
                    if domain_ascii or domain_utf16:
                        messages.extend(self._structured_messages_from_json_value(
                            parsed if parsed is not None else value,
                            conversation_hint=cid_hint,
                            basis=f"ccl_{source_tag}_structured_object",
                            protocol=protocol_name))
                    if protocol_marker:
                        for extractor, suffix in ((self._wrb_messages_from_text, "wrb"),
                                                  (self._f_req_messages_from_text, "f_req")):
                            for msg in extractor(value_text, 0):
                                item = dict(msg)
                                item["recovery_basis"] = f"ccl_{source_tag}_" + str(item.get("recovery_basis") or suffix)
                                messages.append(item)
                    seen = set()
                    for msg in messages:
                        ident = (msg.get("conversation_id"), msg.get("message_id"), msg.get("role"), msg.get("message_content"))
                        if ident in seen:
                            continue
                        seen.add(ident)
                        origin_file = _ccl_safe_str(_ccl_get_attr(record, "origin_file", default=""))
                        source = directory / Path(origin_file).name if origin_file else directory
                        self._emit_deep_message(
                            key, source, msg,
                            locator={"raw_leveldb": True,
                                     "sequence": _ccl_get_attr(record, "seq", default=None),
                                     "state": state_name,
                                     "origin_file": origin_file,
                                     "offset": _ccl_get_attr(record, "offset", default=None)},
                            extra={"record_state": state_name,
                                   "was_compressed": bool(_ccl_get_attr(record, "was_compressed", default=False)),
                                   "persistent_source_class": source_tag})
                        stats["message_findings"] += 1
                        if state_name.casefold() == "deleted":
                            stats["deleted_message_findings"] += 1
        except Exception as exc:
            stats["decode_errors"] += 1
            stats["error"] = error_text(exc)
        return stats

    def _parse_ccl_session_storage(self, key, modules):
        directory = Path(self.artifacts[key])
        module = modules["session_storage"]
        records_examined = gemini_records = logical_messages = errors = 0
        store = module.SessionStoreDb(directory)
        try:
            for host in store.iter_hosts():
                host_text = _ccl_safe_str(host)
                if "gemini.google.com" not in host_text.lower() and "bard.google.com" not in host_text.lower():
                    continue
                try:
                    for record in store.iter_records_for_host(host):
                        records_examined += 1
                        gemini_records += 1
                        record_key = _ccl_safe_str(_ccl_get_attr(record, "key", default=""))
                        value = _ccl_get_attr(record, "value", default=None)
                        if isinstance(value, bytes):
                            text, _ = _deep_decode_text(value, None)
                            text = text or ""
                        else:
                            text = _ccl_safe_str(value)
                        cid_hint = self._explicit_conversation_id_from_text(host_text + " " + record_key + " " + text[:8192])
                        parsed = None
                        if text.strip()[:1] in "[{":
                            try:
                                parsed = json.loads(text.strip())
                            except Exception:
                                parsed = None
                        messages = self._structured_messages_from_json_value(
                            parsed if parsed is not None else value, conversation_hint=cid_hint,
                            basis="ccl_session_storage_structured_object", protocol="session-storage")
                        for extractor, suffix in ((self._wrb_messages_from_text, "wrb"),
                                                  (self._f_req_messages_from_text, "f_req")):
                            for msg in extractor(text, 0):
                                item = dict(msg)
                                item["recovery_basis"] = "ccl_session_storage_" + str(item.get("recovery_basis") or suffix)
                                messages.append(item)
                        seen = set()
                        for msg in messages:
                            ident = (msg.get("conversation_id"), msg.get("message_id"), msg.get("role"), msg.get("message_content"))
                            if ident in seen:
                                continue
                            seen.add(ident)
                            self._emit_deep_message(
                                key, directory, msg,
                                locator={"host": host_text, "key": record_key,
                                         "leveldb_sequence_number": _ccl_get_attr(record, "leveldb_sequence_number", default=None)},
                                extra={"session_storage_host": host_text, "session_storage_key": record_key,
                                       "persistent_source_class": "session_storage_logical"})
                            logical_messages += 1
                except Exception:
                    errors += 1
        finally:
            try:
                store.close()
            except Exception:
                pass

        stale = self._scan_ccl_raw_leveldb(
            key, directory, modules, source_tag="session_storage_stale",
            protocol_name="session-storage-leveldb")
        messages_found = logical_messages + stale["message_findings"]
        errors += stale["decode_errors"]
        self._deep_recovery_status(
            key, "Native Chromium Session Storage deep recovery completed",
            detail={"ccl_available": True, "records_examined": records_examined,
                    "gemini_scoped_records": gemini_records,
                    "logical_message_findings": logical_messages,
                    "stale_leveldb": stale, "message_findings": messages_found,
                    "decode_errors": errors},
            status="success" if not errors else "partial")
        return messages_found

    def _parse_ccl_service_worker(self, key, modules):
        root = Path(self.artifacts[key])
        database = root / "Database"
        cache_storage = root / "CacheStorage"
        script_cache = root / "ScriptCache"
        stale = self._scan_ccl_raw_leveldb(
            key, database, modules, source_tag="service_worker_stale",
            protocol_name="service-worker-database") if database.is_dir() else {
                "directory": str(database), "present": False, "records_examined": 0,
                "deleted_records": 0, "explicit_deleted_records": 0,
                "compressed_records": 0, "gemini_scoped_records": 0,
                "protocol_marker_records": 0, "message_findings": 0,
                "deleted_message_findings": 0, "decode_errors": 0,
                "stale_record_note": "Service Worker Database directory was not present.",
            }
        errors = int(stale.get("decode_errors") or 0)
        self._deep_recovery_status(
            key, "Chromium Service Worker persistent-storage inspection completed",
            detail={"ccl_available": True,
                    "database_present": database.is_dir(),
                    "cache_storage_present": cache_storage.is_dir(),
                    "script_cache_present": script_cache.is_dir(),
                    "cache_storage_analysis": "raw_scan_fallback" if cache_storage.is_dir() else "not_present",
                    "script_cache_analysis": "raw_scan_fallback" if script_cache.is_dir() else "not_present",
                    "database_leveldb": stale,
                    "message_findings": int(stale.get("message_findings") or 0),
                    "decode_errors": errors,
                    "limitation": "Service Worker script/cache presence is supporting storage evidence; it is not a conversation body unless an explicit structured Gemini message is decoded."},
            status="success" if not errors else "partial")
        return int(stale.get("message_findings") or 0)

    def _parse_ccl_sessions(self, key, modules):
        snss_module = modules["snss"]
        paths = [Path(p) for p in self.artifacts[key]]
        navigation_records = gemini_navigation = errors = 0
        for path in paths:
            file_type = snss_module.SnssFileType.Session if path.name.startswith("Session_") else snss_module.SnssFileType.Tab
            try:
                with path.open("rb") as stream:
                    snss = snss_module.SnssFile(file_type, stream)
                    ordinal = 0
                    for command in snss.iter_session_commands():
                        ordinal += 1
                        if not isinstance(command, snss_module.NavigationEntry):
                            continue
                        navigation_records += 1
                        url = _ccl_safe_str(_ccl_get_attr(command, "url", default=""))
                        original = _ccl_safe_str(_ccl_get_attr(command, "original_request_url", default=""))
                        if not is_gemini_url(url) and not is_gemini_url(original):
                            continue
                        gemini_navigation += 1
                        chosen = url if is_gemini_url(url) else original
                        self._emit(key, "Native SNSS Gemini navigation entry decoded", path=path,
                                   detail={"record_type": "finding", "url": chosen,
                                           "conversation_id": conversation_id(chosen),
                                           "title": _ccl_safe_str(_ccl_get_attr(command, "title", default="")),
                                           "navigation_index": _ccl_get_attr(command, "index", default=None),
                                           "recovery_basis": "ccl_snss_navigation",
                                           "native_chromium_structure_decoded": True,
                                           "container_decoder": "ccl_chromium_reader",
                                           "limitation": "SNSS NavigationEntry is navigation evidence, not message-body evidence."},
                                   locator={"file": path.name, "ordinal": ordinal}, level="support", status="success")
            except Exception:
                errors += 1
        self._deep_recovery_status(key, "Native Chromium Sessions deep recovery completed",
                                   detail={"ccl_available": True, "files_examined": len(paths),
                                           "navigation_records": navigation_records,
                                           "gemini_navigation_records": gemini_navigation,
                                           "message_findings": 0, "decode_errors": errors},
                                   status="success" if not errors else "partial")
        return 0

    def _parse_binary_artifact(self, key):
        start = len(self.results)
        artifact = self.artifacts[key]
        if key == "sessions":
            paths = (Path(p) for p in artifact)
            root = self.profile_path / "Sessions"
        else:
            root = Path(artifact)
            paths = self._walk_files(root, key)
        file_count, files_read, findings = 0, 0, 0
        bytes_read_total = string_match_total = protocol_message_total = prompt_candidate_total = image_signature_total = 0
        files_with_gemini_context = files_with_protocol = files_with_prompt_candidates = 0
        scan_limited_files = result_limited_files = changed_files = 0
        scan_started = time.perf_counter()
        for path in paths:
            if key == "sessions" and self.max_files and file_count >= self.max_files:
                self._issue(key, root, f"Configured file limit ({self.max_files}) reached", status="partial")
                break
            file_count += 1
            try:
                relative = str(path.relative_to(root)).replace("\\", "/")
                origin = key == "indexeddb" and bool(re.search(
                    r"(?:^|/)https?_gemini\.google\.com(?:_|/)", relative, re.I))
                metadata = self._file_metadata(path)
                scan = self._scan_binary_file(path, key, origin)
                files_read += 1
                hits, images = scan.pop("hits"), scan.pop("images")
                protocol_messages = scan.pop("protocol_messages", [])
                prompt_candidates = scan.pop("prompt_candidates", [])
                gemini_associated = bool(hits) or origin or bool(protocol_messages) or bool(prompt_candidates)
                bytes_read_total += int(scan.get("bytes_read") or 0)
                string_match_total += len(hits)
                protocol_message_total += len(protocol_messages)
                prompt_candidate_total += len(prompt_candidates)
                image_signature_total += len(images)
                files_with_gemini_context += int(gemini_associated)
                files_with_protocol += int(bool(protocol_messages))
                files_with_prompt_candidates += int(bool(prompt_candidates))
                scan_limited_files += int(bool(scan.get("scan_limit_reached")))
                result_limited_files += int(any(bool(scan.get(name)) for name in (
                    "string_result_limit_reached", "image_result_limit_reached",
                    "protocol_result_limit_reached", "prompt_result_limit_reached")))
                changed_files += int(bool(scan.get("file_changed_during_scan")))
                inventory = {"record_type": "inventory", **metadata, **scan,
                             "origin_namespace_matches_gemini": origin, "string_match_count": len(hits),
                             "structured_protocol_message_count": len(protocol_messages),
                             "aggressive_prompt_candidate_count": len(prompt_candidates),
                             "scan_status": "success" if gemini_associated else "no_relevant_trace",
                             "image_signature_count": len(images), "gemini_related_strings_found": bool(hits),
                             "image_signatures": images if not gemini_associated else [],
                             "image_signatures_gemini_association": "same_file_raw_context_only" if gemini_associated else "not_established",
                             "limitations": ["This record is from the raw fallback scanner; native CCL decoding is reported separately when available.",
                                             "File modification time is not a conversation or download timestamp."]}
                self._emit(key, "Artifact file examined by raw byte search", path=path, detail=inventory,
                           level="unconfirmed", status="partial",
                           error="file changed while scanning" if scan["file_changed_during_scan"] else None)
                for hit in hits:
                    detail = {"record_type": "finding", **hit, "filename": path.name,
                              "origin_namespace_matches_gemini": origin,
                              "limitation": "Readable context is not a decoded title or prompt and does not establish a specific user action."}
                    self._emit(key, "Gemini-related raw string found", path=path, detail=detail,
                               locator={"offset": hit["offset"], "encoding": hit["encoding"], "context_offset": hit["context_offset"]},
                               action="conversation_candidate" if hit["conversation_ids"] else None, status="partial")
                    findings += 1

                for prompt in prompt_candidates:
                    detail = {
                        "record_type": "finding",
                        "conversation_id": prompt.get("conversation_id") or None,
                        "message_id": "",
                        "parent_message_id": "",
                        "message_order": None,
                        "role": "user",
                        "prompt_text": prompt.get("message_content") or "",
                        "recovery_basis": "aggressive_raw_prompt",
                        "protocol": prompt.get("protocol") or "raw-labelled-fallback",
                        "protocol_encoding": prompt.get("protocol_encoding"),
                        "protocol_offset": prompt.get("protocol_offset"),
                        "prompt_field": prompt.get("prompt_field"),
                        "offset_is_approximate": bool(prompt.get("offset_is_approximate")),
                        "filename": path.name,
                        "origin_namespace_matches_gemini": origin,
                        "limitation": (
                            "Prompt text was recovered from an explicitly labelled user-text field in a bounded "
                            "Gemini-scoped raw browser context. Native Gemini RPC decoding was unavailable; Google "
                            "Search and unrelated service contexts are explicitly excluded, but this fallback remains "
                            "weaker than a decoded hNvQHb/wrb.fr/StreamGenerate record."
                        ),
                    }
                    locator = {
                        "offset": prompt.get("protocol_offset"),
                        "encoding": prompt.get("protocol_encoding"),
                        "recovery": "aggressive_raw_prompt",
                        "conversation_id": prompt.get("conversation_id"),
                    }
                    locator = {k: v for k, v in locator.items() if v not in (None, "")}
                    self._emit(
                        key, "Gemini-scoped raw user prompt recovered", path=path, detail=detail,
                        locator=locator, action=None, level="support", status="partial"
                    )
                    findings += 1

                for message in protocol_messages:
                    detail = {
                        "record_type": "finding",
                        "conversation_id": message.get("conversation_id"),
                        "message_id": message.get("message_id") or "",
                        "parent_message_id": message.get("parent_message_id") or "",
                        "message_order": message.get("message_order"),
                        "role": message.get("role") or "",
                        "message_content": message.get("message_content") or "",
                        "response_id": message.get("response_id"),
                        "choice_id": message.get("choice_id"),
                        "recovery_basis": message.get("recovery_basis"),
                        "protocol": message.get("protocol"),
                        "protocol_encoding": message.get("protocol_encoding"),
                        "protocol_offset": message.get("protocol_offset"),
                        "protocol_sequence": message.get("protocol_sequence"),
                        "candidate_rank": message.get("candidate_rank"),
                        "attachments": safe_value(message.get("attachments") or []),
                        "attachment_count": len(message.get("attachments") or []),
                        "message_timestamp": message.get("message_timestamp") or "",
                        "filename": path.name,
                        "origin_namespace_matches_gemini": origin,
                        "limitation": (
                            "Message text was decoded from a Gemini web request/response payload found in raw browser artifact bytes. "
                            "The surrounding Chrome cache/session container itself is not natively decoded, so record timestamp/deletion state may remain unavailable."
                        ),
                    }
                    role = str(detail.get("role") or "").lower()
                    # The protocol record itself is evidence.  Semantic user-action promotion is
                    # done once in _derive_semantic_actions(), avoiding duplicate Timeline rows.
                    action = None
                    message_timestamp = normalize_team_kst_timestamp(message.get("message_timestamp"))
                    locator = {
                        "offset": message.get("protocol_offset"),
                        "encoding": message.get("protocol_encoding"),
                        "protocol": message.get("protocol"),
                        "conversation_id": message.get("conversation_id"),
                        "response_id": message.get("response_id"),
                        "choice_id": message.get("choice_id"),
                        "protocol_sequence": message.get("protocol_sequence"),
                    }
                    locator = {k: v for k, v in locator.items() if v not in (None, "")}
                    self._emit(
                        key, "Structured Gemini message payload recovered", path=path, detail=detail,
                        locator=locator, timestamp=message_timestamp, action=action, level="support", status="partial"
                    )
                    findings += 1

                    # READ_CHAT attachment metadata is stronger than a raw filename/keyword hit,
                    # but the surrounding Chrome container is still not natively decoded.  Emit
                    # a conservative upload candidate so the analyst can see the structured link
                    # between a Gemini turn and the attached file without claiming upload success.
                    if role in {"user", "human"}:
                        for attachment in message.get("attachments") or []:
                            filename = str((attachment or {}).get("filename") or "").strip()
                            if not filename:
                                continue
                            if IMAGE_FILE_RE.search(filename):
                                upload_action = "image_upload_candidate"
                            elif DOCUMENT_FILE_RE.search(filename):
                                upload_action = "document_upload_candidate"
                            else:
                                continue
                            upload_detail = {
                                "record_type": "finding",
                                "filename": filename,
                                "media_kind": (attachment or {}).get("media_kind"),
                                "mime_type": (attachment or {}).get("mime_type"),
                                "conversation_id": message.get("conversation_id"),
                                "response_id": message.get("response_id"),
                                "associated_prompt": message.get("message_content") or "",
                                "recovery_basis": "history_rpc_attachment_metadata",
                                "protocol": message.get("protocol"),
                                "protocol_offset": message.get("protocol_offset"),
                                "structured_attachment_metadata": True,
                                "limitation": (
                                    "Attachment metadata was recovered from a structured Gemini conversation-history payload. "
                                    "The local Chrome container is not natively decoded, so this is exported as an upload candidate rather than proof of a completed network upload."
                                ),
                            }
                            self._emit(
                                key, "Structured Gemini conversation attachment metadata recovered",
                                path=path, detail=upload_detail, locator=locator,
                                timestamp=message_timestamp,
                                action=upload_action, level="support", status="partial"
                            )
                            findings += 1

                if key == "cache" and gemini_associated:
                    for candidate in images:
                        self._emit(key, "Image signature found in a file containing Gemini-related raw context",
                                   path=path, locator={"offset": candidate["offset"]}, action="cached_image_candidate",
                                   status="partial", detail={"record_type": "finding", **candidate,
                                   "gemini_related_strings_found": bool(hits),
                                   "related_string_offsets": [hit["offset"] for hit in hits[:20]],
                                   "association_scope": "same_file_only; may belong to a different cache entry",
                                   "limitation": "Signature only; image validity and Gemini generation are not established. No carving performed."})
                        findings += 1
            except (OSError, ValueError, struct.error) as exc:
                self._issue(key, path, error_text(exc))
            if file_count % 100 == 0:
                self._say(f"[.] {self.ARTIFACTS[key]}: processed {file_count} files")
        read_errors = sum(r["status"] == "parse_error" for r in self.results[start:])
        scan_status = ("parse_error" if read_errors and not files_read else
                       "partial" if read_errors else "success" if findings else "no_relevant_trace")
        elapsed = round(time.perf_counter() - scan_started, 3)
        self._emit(key, "Raw artifact scan completed", path=root,
                   status="parse_error" if read_errors and not files_read else "partial", level="unconfirmed",
                   detail={"record_type": "scan_summary", "files_examined": file_count,
                           "files_read": files_read, "read_error_count": read_errors,
                           "finding_count": findings, "scan_status": scan_status,
                           "bytes_read": bytes_read_total,
                           "string_match_count": string_match_total,
                           "structured_protocol_message_count": protocol_message_total,
                           "aggressive_prompt_candidate_count": prompt_candidate_total,
                           "image_signature_count": image_signature_total,
                           "files_with_gemini_context": files_with_gemini_context,
                           "files_with_structured_protocol": files_with_protocol,
                           "files_with_aggressive_prompt_candidates": files_with_prompt_candidates,
                           "scan_limit_reached_files": scan_limited_files,
                           "result_limit_reached_files": result_limited_files,
                           "files_changed_during_scan": changed_files,
                           "elapsed_sec": elapsed,
                           "native_structure_decoded": False,
                           "max_binary_bytes_per_file": self.max_binary_bytes or None,
                           "max_matches_per_file": self.max_matches_per_file})

    @staticmethod
    def _canonical_windows_path(value):
        if not isinstance(value, str) or not value or "\x00" in value:
            return None
        path = PureWindowsPath(value)
        if ".." in path.parts or not path.is_absolute():
            return None
        return str(path).casefold()

    def _parse_recycle_bin(self, key):
        """Parse $I metadata independently, then correlate exact original paths when possible."""
        paths = {}
        for record in self._downloads:
            for field in ("target_path", "current_path"):
                canonical = self._canonical_windows_path((record.get("detail") or {}).get(field))
                if canonical:
                    paths.setdefault(canonical, []).append(record)
        examined, parsed = 0, 0
        for root in map(Path, self.artifacts[key]):
            for path in self._walk_files(root, key):
                if not path.name.startswith("$I"):
                    continue
                examined += 1
                try:
                    with path.open("rb") as stream:
                        raw = stream.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024 or len(raw) < 24:
                        raise ValueError("unsupported $I size or truncated header")
                    version, original_size, deleted_time = struct.unpack_from("<QQQ", raw)
                    if version == 1:
                        if len(raw) < 544:
                            raise ValueError("truncated version 1 $I path")
                        original = raw[24:544].decode("utf-16le").split("\x00", 1)[0]
                    elif version == 2:
                        if len(raw) < 28:
                            raise ValueError("truncated version 2 $I path length")
                        length = struct.unpack_from("<I", raw, 24)[0]
                        if length < 1 or 28 + length * 2 > len(raw):
                            raise ValueError("invalid version 2 $I path length")
                        original = raw[28:28 + length * 2].decode("utf-16le").rstrip("\x00")
                    else:
                        self._issue(key, path, f"$I layout version {version} is unsupported", status="unsupported")
                        continue

                    canonical = self._canonical_windows_path(original)
                    matches = paths.get(canonical, []) if canonical else []
                    matches = list({((r.get("detail") or {}).get("id"), r.get("source_path")): r for r in matches}.values())
                    gemini_matches = [r for r in matches if self._is_gemini_specific_finding(r)]
                    payload = path.with_name("$R" + path.name[2:])
                    payload_exists = payload.is_file() and not is_link(payload)
                    timestamp = normalize_timestamp(deleted_time, "filetime")
                    under_downloads = bool(re.search(r"\\users\\[^\\]+\\downloads\\", str(original), re.I))
                    detail = {
                        "record_type": "finding", "version": version,
                        "original_path": original, "original_filename": PureWindowsPath(original).name,
                        "original_size": original_size, "deletion_time": timestamp,
                        "timestamp_format": "windows_filetime_100ns_since_1601",
                        "payload_path": str(payload), "payload_exists": payload_exists,
                        "download_ids": list(dict.fromkeys((r.get("detail") or {}).get("id") for r in matches
                                                            if (r.get("detail") or {}).get("id") is not None)),
                        "history_source_paths": list(dict.fromkeys(r.get("source_path") for r in matches if r.get("source_path"))),
                        "related_download_match_count": len(matches),
                        "gemini_related_download_match_count": len(gemini_matches),
                        "original_path_under_downloads": under_downloads,
                        "match_basis": "exact_normalized_original_path" if matches else "none",
                        "gemini_attribution": "linked_download_candidate" if gemini_matches else "unconfirmed",
                        "service_attribution": "candidate" if gemini_matches else "unconfirmed",
                        "limitation": "Recycle Bin $I metadata proves a recycle event for this path, but does not by itself identify Gemini as the source of the file."
                    }
                    observation = (
                        "Recycle Bin metadata parsed; original path matches a Gemini-associated Chrome download"
                        if gemini_matches else
                        "Recycle Bin metadata parsed; original path matches a Chrome download"
                        if matches else
                        "Recycle Bin metadata parsed; no examined Chrome download link established"
                    )
                    self._emit(key, observation, path=path, locator={"offset": 0, "version": version},
                               timestamp=timestamp, action="file_delete_candidate",
                               level="support" if gemini_matches else "unconfirmed",
                               status="partial" if timestamp.get("error") else "success",
                               error=timestamp.get("error"), detail=detail)
                    parsed += 1
                except (OSError, ValueError, UnicodeError, struct.error) as exc:
                    self._issue(key, path, error_text(exc))
        self._emit(key, "Recycle Bin metadata scan completed", path=self._expected[key], status="partial",
                   level="unconfirmed", detail={"record_type": "scan_summary", "metadata_files_examined": examined,
                   "metadata_files_parsed": parsed,
                   "limitation": "Allocated $I metadata only; no deleted-record carving or full NTFS journal interpretation."})

    def correlate_filesystem_evidence(self, filesystem_records):
        """After parse(), append exact-path/SHA-256 links to external records.

        Accepts common-schema dictionaries. This hook does not read raw $MFT or
        $UsnJrnl and does not promote an external interpretation to a fact.
        Returns newly appended records, also available through get_results().
        """
        if not isinstance(filesystem_records, list):
            raise TypeError("filesystem_records must be a list of dictionaries")
        added = []
        for index, external in enumerate(list(filesystem_records)):
            if not isinstance(external, dict):
                added.append(self._issue("External File-System Evidence", None,
                                         f"record {index} is not a dictionary", locator={"external_record_index": index}))
                continue
            detail = external.get("detail", external)
            if not isinstance(detail, dict):
                added.append(self._issue("External File-System Evidence", external.get("source_path"),
                                         f"record {index} detail is not a dictionary", locator={"external_record_index": index}))
                continue
            external_paths = {self._canonical_windows_path(detail.get(k)) for k in
                              ("path", "original_path", "target_path", "current_path", "resolved_path", "file_path")}
            external_paths.discard(None)
            digest = detail.get("sha256")
            valid_hash = isinstance(digest, str) and bool(re.fullmatch(r"[A-Fa-f0-9]{64}", digest))
            for download in self._downloads:
                d = download["detail"]
                download_paths = {self._canonical_windows_path(d.get(k)) for k in ("target_path", "current_path", "resolved_path")}
                download_paths.discard(None)
                matched_path = sorted(external_paths & download_paths)
                matched_hash = bool(valid_hash and d.get("sha256") and digest.casefold() == d["sha256"].casefold())
                if not matched_path and not matched_hash:
                    continue
                imported_time = external.get("timestamp")
                timestamp = ({k: imported_time.get(k) for k in ("raw", "utc", "kst")}
                             if isinstance(imported_time, dict) else None)
                added.append(self._emit("External File-System Evidence", "External filesystem record linked to a download",
                             path=external.get("source_path"), timestamp=timestamp,
                             locator={"external_record_index": index, "external_locator": external.get("source_locator")},
                             detail={"record_type": "finding", "download_id": d["id"],
                                     "history_source_path": download["source_path"], "matched_paths": matched_path,
                                     "sha256_match": matched_hash, "external_record": external,
                                     "limitation": "External facts/interpretations are retained as supplied; exact path can be reused. Raw filesystem artifacts were not parsed."}))
        return added

    def _validate_export(self, path):
        path = Path(path).expanduser().absolute()
        if within(path, self.profile_path):
            raise ValueError("Export destination must be outside the source Chrome Profile")
        if str(path).casefold() in self._source_files or str(path.resolve()).casefold() in self._source_files:
            raise ValueError("Export destination is an evidence source path")
        if path.exists() or path.is_symlink():
            raise FileExistsError("Refusing to overwrite an existing file: " + str(path))
        for root in self.artifacts.get("recycle_bin", []):
            if within(path, Path(root)):
                raise ValueError("Export destination must be outside Recycle Bin evidence")
        # No ADS destinations: exports must be ordinary files, not a stream.
        if ":" in path.name:
            raise ValueError("ADS export destinations are not supported")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _display_timestamp(row):
        """Return the analyst-facing KST timestamp while preserving raw/UTC in JSON."""
        timestamp = row.get("timestamp") or {}
        if not isinstance(timestamp, dict):
            return str(timestamp) if timestamp else "-"
        value = timestamp.get("kst") or timestamp.get("utc")
        if not value:
            detail = row.get("detail") or {}
            reason = detail.get("timestamp_unavailable_reason") if isinstance(detail, dict) else None
            return "N/A - " + str(reason) if reason else "-"
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(KST)
                base = parsed.strftime("%Y-%m-%d %H:%M:%S")
                fraction = f".{parsed.microsecond:06d}"
                return base + fraction + " KST"
        except (ValueError, TypeError):
            pass
        return str(value)

    @staticmethod
    def _compact_display_value(value, limit=240):
        if value is None or value == "":
            return None
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        else:
            rendered = str(value)
        rendered = " ".join(rendered.split())
        return rendered if len(rendered) <= limit else rendered[:limit - 1] + "…"

    @classmethod
    def _display_artifact_content(cls, row):
        """Build a concise human-readable description without discarding the full JSON detail."""
        detail = row.get("detail") or {}
        parts = []
        observation = cls._compact_display_value(row.get("observation"), 320)
        if observation:
            parts.append(observation)

        # Prefer fields that help an analyst understand the actual artifact rather
        # than dumping the whole nested detail dictionary into one CSV cell.
        preferred = (
            ("url", "URL"), ("title", "Title"), ("conversation_id", "Conversation ID"),
            ("filename", "Filename"), ("target_path", "Target"), ("current_path", "Current"),
            ("resolved_path", "Resolved"), ("host_key", "Host"), ("name", "Name"),
            ("key_path", "Key"), ("value", "Value"), ("matched_string", "Matched"),
            ("found_string", "Context"), ("detected_type", "Detected type"),
            ("estimated_size", "Estimated size"), ("download_id", "Download ID"),
            ("finding_count", "Finding count"), ("profile_outcome", "Profile outcome"),
            ("reason", "Reason"), ("filesystem_type", "Filesystem"),
            ("windows_directory_present", "Windows directory"),
            ("raw_hit_count", "Raw hit count"), ("unique_urls", "Representative URLs"),
            ("conversation_ids", "Conversation IDs"), ("encodings", "Encodings"),
            ("original_path", "Original path"), ("original_filename", "Original filename"),
            ("original_size", "Original size"), ("payload_exists", "$R payload exists"),
            ("service_attribution", "Service attribution"), ("gemini_attribution", "Gemini attribution"),
            ("preference_key_count", "Preference key count"), ("preference_items", "Preference items"),
        )
        for key, label in preferred:
            if key not in detail:
                continue
            value = cls._compact_display_value(detail.get(key), 360 if key == "found_string" else 240)
            if value is not None:
                parts.append(f"{label}: {value}")

        # Zone.Identifier keeps its useful values nested under detail.values.
        limitation = cls._compact_display_value(detail.get("limitation"), 420)
        if limitation:
            parts.append("Limitation: " + limitation)
        limitations = detail.get("limitations")
        if isinstance(limitations, list) and limitations:
            rendered_limits = "; ".join(str(x) for x in limitations if x)
            rendered_limits = cls._compact_display_value(rendered_limits, 420)
            if rendered_limits:
                parts.append("Limitations: " + rendered_limits)

        values = detail.get("values")
        if isinstance(values, dict):
            zone_bits = []
            for key in ("ZoneId", "ReferrerUrl", "HostUrl"):
                value = cls._compact_display_value(values.get(key), 220)
                if value is not None:
                    zone_bits.append(f"{key}={value}")
            if zone_bits:
                parts.append("Zone.Identifier: " + "; ".join(zone_bits))

        if not parts:
            record_type = detail.get("record_type")
            if record_type:
                parts.append("Record type: " + str(record_type))
        return " | ".join(parts) if parts else "-"

    @classmethod
    def _display_source(cls, row):
        """Combine container image, internal filesystem path and record locator."""
        locator = row.get("source_locator") or {}
        detail = row.get("detail") or {}
        parts = []
        source = cls._compact_display_value(row.get("source_path"), 500)
        if source:
            parts.append(source)

        fs_path = locator.get("filesystem_path") if isinstance(locator, dict) else None
        if fs_path and str(fs_path) != str(row.get("source_path")):
            parts.append(str(fs_path))

        if isinstance(detail, dict):
            user = detail.get("windows_user")
            profile = detail.get("chrome_profile")
            if user:
                parts.append("user=" + str(user))
            if profile:
                parts.append("profile=" + str(profile))

        if isinstance(locator, dict):
            for key, label in (
                ("partition_offset", "partition_offset"), ("table", "table"), ("id", "id"),
                ("url_id", "url_id"), ("json_pointer", "json_pointer"), ("offset", "offset"),
                ("context_offset", "context_offset"), ("stream", "stream"), ("section", "section"),
                ("inode", "inode"), ("sequence", "sequence"),
            ):
                value = locator.get(key)
                if value is not None and value != "":
                    parts.append(f"{label}={cls._compact_display_value(value, 180)}")
        return " | ".join(parts) if parts else "-"

    @classmethod
    def _display_action_detail(cls, row):
        """Render action_candidate as an analyst-friendly Korean action description."""
        action = row.get("action_candidate")
        detail = row.get("detail") or {}
        labels = {
            "gemini_access_candidate": "Gemini 접속 후보",
            "conversation_access": "대화 접근",
            "account_activity_candidate": "계정 활동 접근 후보",
            "conversation_candidate": "대화 관련 흔적 후보",
            "cached_image_candidate": "캐시 이미지 후보",
            "file_download": "파일 다운로드",
            "file_download_candidate": "파일 다운로드 후보",
            "file_delete_candidate": "파일 삭제 후보",
        }

        parts = []
        if action:
            parts.append(labels.get(action, str(action)))

        # Keep this column focused on the inferred/candidate user action.  The
        # artifact-specific technical details stay in '아티팩트 상세내용'.
        action_fields = []
        if action in {"conversation_access", "conversation_candidate"}:
            action_fields = [
                ("title", "제목"),
                ("conversation_id", "대화 ID"),
                ("url", "URL"),
            ]
        elif action in {"gemini_access_candidate", "account_activity_candidate"}:
            action_fields = [("title", "제목"), ("url", "URL")]
        elif action in {"file_download", "file_download_candidate"}:
            action_fields = [
                ("filename", "파일명"),
                ("target_path", "대상 경로"),
                ("current_path", "현재 경로"),
                ("url", "URL"),
            ]
        elif action == "file_delete_candidate":
            action_fields = [
                ("original_filename", "파일명"),
                ("original_path", "원본 경로"),
            ]
        elif action == "cached_image_candidate":
            action_fields = [
                ("detected_type", "이미지 형식"),
                ("estimated_size", "추정 크기"),
            ]

        for key, label in action_fields:
            value = cls._compact_display_value(detail.get(key), 260)
            if value is not None:
                parts.append(f"{label}: {value}")

        # Status/context records may not have an action_candidate.  In that
        # case, retain the observation instead of leaving the action cell blank.
        if not parts:
            observation = cls._compact_display_value(row.get("observation"), 420)
            if observation:
                parts.append(observation)

        return " | ".join(parts) if parts else "-"

    @classmethod
    def _display_verdict(cls, row):
        """Keep evidence semantics while presenting one compact Korean verdict column."""
        evidence = row.get("evidence_level")
        status = row.get("status")
        evidence_labels = {
            "direct": "직접 근거",
            "support": "보조 근거",
            "unconfirmed": "미확인",
        }
        status_labels = {
            "success": "분석 성공",
            "partial": "부분 분석",
            "artifact_not_found": "아티팩트 없음",
            "no_relevant_trace": "관련 흔적 없음",
            "unsupported": "지원 안 됨",
            "locked_database": "DB 잠김",
            "parse_error": "파싱 오류",
            "skipped": "건너뜀",
        }

        parts = []
        if evidence in evidence_labels:
            parts.append(evidence_labels[evidence])

        # success is implicit for findings.  Surface non-success states because
        # Status is no longer a standalone CSV column.
        if status and (not parts or status != "success"):
            parts.append(status_labels.get(status, str(status)))

        return " / ".join(parts) if parts else "-"

    @classmethod
    def _display_artifact_detail_for_csv(cls, row):
        """Prefix the artifact name and preserve important status/error context."""
        artifact = cls._compact_display_value(row.get("artifact"), 180) or "Unknown artifact"
        content = cls._display_artifact_content(row)
        parts = [f"[{artifact}] {content}"]

        error = cls._compact_display_value(row.get("error"), 500)
        if error:
            parts.append("오류: " + error)

        return " | ".join(parts)

    @classmethod
    def _csv_row(cls, row):
        return {
            "타임스탬프": cls._display_timestamp(row),
            "행위 상세": cls._display_action_detail(row),
            "판정": cls._display_verdict(row),
            "경로": cls._display_source(row),
            "아티팩트 상세내용": cls._display_artifact_detail_for_csv(row),
        }

    @staticmethod
    def _analyst_timestamp_sort_key(row):
        timestamp = row.get("timestamp") or {}
        value = timestamp.get("utc") if isinstance(timestamp, dict) else None
        if not value:
            return (1, "")
        return (0, str(value))

    @staticmethod
    def _is_gemini_specific_finding(row):
        detail = row.get("detail") or {}
        if detail.get("record_type") not in {"finding", "finding_summary"}:
            return False
        basis = detail.get("relevance_basis")
        if is_gemini_url(detail.get("url")):
            return True
        if isinstance(basis, str) and basis in {"gemini_url", "google_account_url_with_gemini_reference"}:
            return True
        if isinstance(basis, list) and any(isinstance(x, dict) and is_gemini_url(x.get("url"))
                                           for x in basis):
            return True
        if detail.get("relevance_scope") in {"gemini", "gemini_host"}:
            return True
        if detail.get("matched_string") or detail.get("origin_namespace_matches_gemini"):
            return True
        if detail.get("gemini_attribution") in {"url_associated_candidate", "linked_download_candidate"}:
            return True
        action = row.get("action_candidate")
        if action == "file_delete_candidate":
            return bool(detail.get("gemini_related_download_match_count"))
        if action in {"conversation_access", "gemini_access_candidate", "account_activity_candidate",
                      "file_download", "conversation_candidate", "cached_image_candidate"}:
            return True
        return False

    @staticmethod
    def _is_meaningful_context(row):
        detail = row.get("detail") or {}
        key_path = str(detail.get("key_path") or "").lower()
        if row.get("artifact") in {"Chrome Preferences", "Chrome Secure Preferences"}:
            return "clear_data.cache" in key_path or ("clear_data" in key_path and key_path.endswith(".cache"))
        return False

    @classmethod
    def _is_analyst_relevant_finding(cls, row):
        if cls._is_gemini_specific_finding(row) or cls._is_meaningful_context(row):
            return True
        detail = row.get("detail") or {}
        action = row.get("action_candidate")
        if action == "file_download_candidate":
            return True
        if action == "file_delete_candidate":
            return bool(detail.get("original_path_under_downloads") or detail.get("related_download_match_count"))
        return False

    @classmethod
    def _aggregate_raw_findings(cls, rows):
        """Collapse repeated raw-string hits per artifact file for analyst CSV only."""
        aggregate_artifacts = {"Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage",
                               "Chrome IndexedDB", "Chrome Cache"}
        grouped, passthrough = {}, []
        for row in rows:
            detail = row.get("detail") or {}
            if (row.get("artifact") in aggregate_artifacts and
                    detail.get("record_type") == "finding" and
                    row.get("observation") == "Gemini-related raw string found"):
                locator = row.get("source_locator") or {}
                fs_path = locator.get("filesystem_path") or row.get("source_path") or "unknown"
                profile = detail.get("chrome_profile")
                key = (row.get("artifact"), fs_path, profile)
                bucket = grouped.setdefault(key, {"rows": [], "urls": [], "conversation_ids": [], "encodings": set()})
                bucket["rows"].append(row)
                for url in detail.get("urls") or ([detail.get("url")] if detail.get("url") else []):
                    if url and url not in bucket["urls"]:
                        bucket["urls"].append(url)
                for cid in detail.get("conversation_ids") or ([detail.get("conversation_id")] if detail.get("conversation_id") else []):
                    if cid and cid not in bucket["conversation_ids"]:
                        bucket["conversation_ids"].append(cid)
                if detail.get("encoding"):
                    bucket["encodings"].add(detail["encoding"])
            else:
                passthrough.append(row)

        summaries = []
        for (artifact, fs_path, profile), bucket in grouped.items():
            first = bucket["rows"][0]
            first_detail = first.get("detail") or {}
            first_locator = dict(first.get("source_locator") or {})
            for k in ("offset", "context_offset"):
                first_locator.pop(k, None)
            summary_detail = {
                "record_type": "finding_summary",
                "raw_hit_count": len(bucket["rows"]),
                "unique_urls": bucket["urls"][:12],
                "conversation_ids": bucket["conversation_ids"][:12],
                "encodings": sorted(bucket["encodings"]),
                "windows_user": first_detail.get("windows_user"),
                "chrome_profile": profile,
                "filesystem_path": fs_path,
                "timestamp_unavailable_reason": "raw scan has no record timestamp",
                "limitation": "Repeated raw byte/string hits are summarized per artifact file for CSV readability; individual offsets and contexts remain in JSON."
            }
            action = "conversation_candidate" if any(r.get("action_candidate") == "conversation_candidate" for r in bucket["rows"]) else None
            summaries.append(dict(zip(FIELDS, [
                first.get("service", "Gemini"), first.get("environment", "Web"), normalize_timestamp(None), action,
                artifact, f"Gemini-related raw string hits summarized ({len(bucket['rows'])} hits in one file)",
                summary_detail, first.get("source_path"), first_locator, "support", "partial", None
            ])))

        preference_groups, remaining = {}, []
        for row in passthrough:
            detail = row.get("detail") or {}
            key_path = str(detail.get("key_path") or "")
            if (row.get("artifact") in {"Chrome Preferences", "Chrome Secure Preferences"}
                    and detail.get("record_type") == "finding"
                    and detail.get("relevance_scope") == "gemini"
                    and "gemini.google.com" in key_path.lower()
                    and row.get("action_candidate") is None):
                category = ("media_engagement" if "media_engagement" in key_path.lower() else
                            "site_engagement" if "site_engagement" in key_path.lower() else "gemini_preference")
                locator = row.get("source_locator") or {}
                fs_path = locator.get("filesystem_path") or row.get("source_path") or "unknown"
                profile = detail.get("chrome_profile")
                preference_groups.setdefault((row.get("artifact"), fs_path, profile, category), []).append(row)
            else:
                remaining.append(row)

        pref_summaries = []
        for (artifact, fs_path, profile, category), group in preference_groups.items():
            first = group[0]
            first_detail = first.get("detail") or {}
            first_locator = dict(first.get("source_locator") or {})
            first_locator.pop("json_pointer", None)
            items = []
            for r in group[:12]:
                d = r.get("detail") or {}
                items.append({"key": d.get("key_path"), "value": d.get("value")})
            detail = {
                "record_type": "finding_summary", "preference_category": category,
                "preference_key_count": len(group), "preference_items": items,
                "windows_user": first_detail.get("windows_user"), "chrome_profile": profile,
                "filesystem_path": fs_path,
                "timestamp_unavailable_reason": "stored preference has no reliable user-action timestamp",
                "relevance_scope": "gemini",
                "limitation": "Gemini-specific stored preferences are summarized for CSV readability; individual keys remain in JSON and do not by themselves prove a user action."
            }
            pref_summaries.append(dict(zip(FIELDS, [
                first.get("service", "Gemini"), first.get("environment", "Web"), normalize_timestamp(None), None,
                artifact, f"Gemini {category.replace('_', ' ')} preferences summarized ({len(group)} keys)",
                detail, first.get("source_path"), first_locator, "support", "success", None
            ])))
        return remaining + summaries + pref_summaries

    def analyst_rows(self):
        """Action-focused CSV; lossless raw records remain in JSON."""
        candidates = []
        gemini_profiles = {
            ((r.get("detail") or {}).get("windows_user"), (r.get("detail") or {}).get("chrome_profile"))
            for r in self.results if self._is_gemini_specific_finding(r)
        }
        for row in self.results:
            detail = row.get("detail") or {}
            record_type = detail.get("record_type")
            if self._is_meaningful_context(row):
                profile_key = (detail.get("windows_user"), detail.get("chrome_profile"))
                if profile_key in gemini_profiles:
                    candidates.append(row)
                continue
            if self._is_analyst_relevant_finding(row):
                candidates.append(row)
                continue
            if record_type == "profile_status":
                candidates.append(row)
                continue
            if record_type == "image_status" and row.get("observation") in {"Image opened read-only", "Image examination completed", "Image input could not be analyzed"}:
                candidates.append(row)
                continue
            if record_type == "analysis_status" and row.get("status") in {"parse_error", "locked_database", "unsupported"}:
                candidates.append(row)
                continue
            if row.get("error") and record_type not in {"partition_status", "discovery_status"}:
                candidates.append(row)

        rows = self._aggregate_raw_findings(candidates)
        rows.sort(key=lambda row: (self._analyst_timestamp_sort_key(row),
                                   0 if self._is_gemini_specific_finding(row) else 1,
                                   str(row.get("artifact") or ""),
                                   str(row.get("observation") or "")))
        return rows

    def key_findings(self, limit=20):
        """Presentation-friendly findings prioritized by user-action value, then evidence and time."""
        findings = [row for row in self.analyst_rows() if (row.get("detail") or {}).get("record_type") in {"finding", "finding_summary"}]
        evidence_rank = {"direct": 0, "support": 1, "unconfirmed": 2}
        action_rank = {
            "file_download": 0,
            "file_delete_candidate": 1,
            "conversation_access": 2,
            "file_download_candidate": 3,
            "gemini_access_candidate": 4,
            "account_activity_candidate": 5,
            "conversation_candidate": 6,
            "cached_image_candidate": 7,
            None: 9,
        }
        findings.sort(key=lambda row: (
            action_rank.get(row.get("action_candidate"), 8),
            evidence_rank.get(row.get("evidence_level"), 9),
            self._analyst_timestamp_sort_key(row),
            str(row.get("artifact") or ""),
        ))
        return findings[:max(0, limit)]

    @staticmethod
    def _semantic_text(row):
        """Return fields that can carry user-action semantics, excluding parser bookkeeping."""
        detail = row.get("detail") or {}
        parts = []
        for key in ("url", "title", "found_string", "matched_string", "key_path", "value",
                    "filename", "original_filename", "target_path", "current_path", "original_path",
                    "prompt_text", "message_text", "message_content", "response_text", "draft_text"):
            value = detail.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
        for key in ("urls", "conversation_ids", "login_steps"):
            values = detail.get(key)
            if isinstance(values, (list, tuple)):
                parts.extend(str(v) for v in values if isinstance(v, (str, int)) and str(v))
        return "\n".join(parts)

    @staticmethod
    def _extract_filename(text):
        if not isinstance(text, str):
            return None
        match = UPLOAD_FILE_RE.search(text)
        return match.group(1).strip() if match else None

    @staticmethod
    def _explicit_send_marker(text):
        return bool(re.search(r"(?i)(?:send|submit|sent|dispatch|message[_ -]?(?:send|submit)|prompt[_ -]?(?:send|submit))", text or ""))

    @staticmethod
    def _copy_as_derived(source, action, rule_id, observation, *, detail_extra=None,
                         level="support", status="partial"):
        row = dict(source)
        detail = dict(source.get("detail") or {})
        detail.update({
            "record_type": "finding",
            "derived_rule_id": rule_id,
            "derived_from_action_candidate": source.get("action_candidate"),
            "derived_from_artifact": source.get("artifact"),
        })
        if detail_extra:
            detail.update(detail_extra)
        row["action_candidate"] = action
        row["observation"] = observation
        row["detail"] = safe_value(detail)
        row["evidence_level"] = level
        row["status"] = status
        locator = dict(source.get("source_locator") or {})
        locator["derived_rule_id"] = rule_id
        row["source_locator"] = locator
        row["error"] = None
        return row

    def _derive_semantic_actions(self):
        """Derive candidates/events for every project action from parsed artifacts.

        Rules are evidence-preserving: explicit semantic markers or structured records can add a
        support/direct row, but absence, generic UUIDs, file mtimes and unrelated Chrome records
        never become actions. Raw source records remain in JSON for analyst verification.
        """
        original = list(self.results)
        derived = []
        signatures = set()

        def add(row):
            detail = row.get("detail") or {}
            key = (row.get("action_candidate"), row.get("source_path"),
                   json.dumps(row.get("source_locator") or {}, ensure_ascii=False, sort_keys=True, default=str),
                   detail.get("derived_rule_id"), detail.get("filename"), detail.get("conversation_id"),
                   detail.get("url"), detail.get("prompt_text"), detail.get("new_model"))
            if key in signatures:
                return
            signatures.add(key)
            derived.append(row)

        for source in original:
            detail = source.get("detail") or {}
            # Derived semantic rows are terminal rule outputs. Re-feeding them into the
            # semantic engine can create rule-on-rule duplicates on repeated calls.
            if detail.get("derived_rule_id"):
                continue
            if detail.get("record_type") not in {"finding", "finding_summary"}:
                continue
            text = self._semantic_text(source)
            low = text.lower()
            url = str(detail.get("url") or "")
            relevance = detail.get("relevance_basis") or history_relevance(url)
            cids = self._conversation_ids_for_row(source)
            cid = cids[0] if cids else None

            # Authentication / account actions.
            if source.get("artifact") == "Chrome History" and re.search(r"(?i)(?:/logout|/signout|[?&](?:logout|signout)=|logout|signout)", url):
                add(self._copy_as_derived(source, "logout", "GEM-AUTH-LOGOUT-001",
                    "Logout/signout URL visit observed", detail_extra={"conversation_id": cid,
                    "limitation": "Navigation is observed; server-side logout completion is not independently verified."},
                    level="support",
                    status="success" if self._has_reliable_timeline_timestamp(source) else "partial"))

            # Prompt/activity deletion flow.
            if source.get("artifact") == "Chrome History" and relevance == "google_myactivity":
                add(self._copy_as_derived(source, "prompt_delete_candidate", "GEM-PROMPT-DELETE-001",
                    "Google/My Activity flow related to Gemini activity observed",
                    detail_extra={"limitation": "Activity-management navigation supports a deletion-flow candidate; deleted prompt text/count is not locally proven."},
                    level="support", status="success" if self._has_reliable_timeline_timestamp(source) else "partial"))

            # Export flow.
            if source.get("artifact") == "Chrome History" and (relevance == "google_takeout" or "takeout.google.com" in low):
                add(self._copy_as_derived(source, "data_export_candidate", "GEM-EXPORT-001",
                    "Google Takeout/export navigation observed",
                    detail_extra={"limitation": "Takeout navigation does not prove archive generation or download completion."},
                    level="support", status="success" if self._has_reliable_timeline_timestamp(source) else "partial"))

            # Account display name edit flow.
            if source.get("artifact") == "Chrome History" and relevance == "google_account_name":
                add(self._copy_as_derived(source, "account_name_change_candidate", "GEM-ACCOUNT-NAME-001",
                    "Google account name/profile edit flow observed",
                    detail_extra={"limitation": "Profile/name edit navigation is observed; changed display-name text is not necessarily stored locally."},
                    level="support", status="success" if self._has_reliable_timeline_timestamp(source) else "partial"))

            # Share link/snapshot trace.
            if is_gemini_url(url):
                try:
                    pth = urlsplit(url).path.lower()
                except ValueError:
                    pth = ""
                if "/share/" in pth or pth.startswith("/share") or re.search(r"(?i)(?:share[_ -]?(?:id|snapshot|link)|shared[_ -]?conversation)", low):
                    add(self._copy_as_derived(source, "share_link_candidate", "GEM-SHARE-001",
                        "Gemini share-link/share-snapshot trace observed",
                        detail_extra={"limitation": "When only a URL visit exists, creation of the share link itself remains a candidate."},
                        level="support", status="success" if self._has_reliable_timeline_timestamp(source) else "partial"))

            scoped = ("gemini.google.com" in low or bool(cid) or detail.get("origin_namespace_matches_gemini") is True
                      or detail.get("relevance_scope") == "gemini")
            # Generic semantic markers are evaluated only in state/content artifacts.
            # A History download row whose filename happens to contain "Generated_Image", for
            # example, must never become an image-generation *request* event. History has its
            # own URL/download rules above/below.
            semantic_artifact = source.get("artifact") in {
                "Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage",
                "Chrome IndexedDB", "Chrome Cache", "Chrome Preferences",
                "Chrome Secure Preferences"
            }
            if scoped and semantic_artifact:
                # Conversation edit/delete/retry, image generation, temporary chat, incognito/clear markers.
                for action, pattern in EXPLICIT_SEMANTIC_RULES:
                    if not pattern.search(text):
                        continue
                    filename_for_rule = self._extract_filename(text)
                    # Raw/static UI labels are common in browser state and scripts.  Even when
                    # a conversation/file anchor is nearby they do not prove that the action ran.
                    # Preserve them as supporting candidates only; a future native event decoder
                    # may emit the non-candidate action when event-specific structure is present.
                    if action in {"conversation_delete", "conversation_edit", "conversation_retry", "temporary_chat"} and not cid:
                        continue
                    if action == "attachment_remove" and not (cid or filename_for_rule):
                        continue
                    if action == "image_generation" and not cid:
                        continue
                    candidate_map = {
                        "conversation_delete": "conversation_delete_candidate",
                        "conversation_edit": "conversation_edit_candidate",
                        "conversation_retry": "conversation_retry_candidate",
                        "temporary_chat": "temporary_chat_candidate",
                        "attachment_remove": "attachment_remove_candidate",
                        "image_generation": "image_generation_candidate",
                    }
                    derived_action = candidate_map.get(action, action + "_candidate")
                    add(self._copy_as_derived(source, derived_action,
                        "GEM-SEM-" + derived_action.upper().replace("_", "-") + "-001",
                        "Gemini-scoped semantic/UI marker preserved as supporting finding",
                        detail_extra={"conversation_id": cid, "filename": filename_for_rule,
                        "semantic_marker": pattern.pattern, "supporting_finding": True,
                        "limitation": "A nearby Gemini conversation/file anchor plus a semantic/UI label does not prove that the user executed the action."},
                        level="support", status="partial"))

                # Upload preparation / attachment trace with recoverable filename.
                filename = self._extract_filename(text)
                if (filename and re.search(r"(?i)(?:upload|attachment|attach|file[_ -]?upload|blob[_ -]?storage|local[_ -]?file)", text)
                        and not re.search(r"(?i)(?:remove|delete|detach)[_ .:-]{0,24}(?:attachment|upload|file)|(?:attachment|upload|file)[_ .:-]{0,24}(?:remove|delete|detach)", text)):
                    action = "image_upload_candidate" if IMAGE_FILE_RE.search(filename) else "document_upload_candidate"
                    add(self._copy_as_derived(source, action, "GEM-UPLOAD-001",
                        "Gemini-scoped upload/attachment trace with filename observed",
                        detail_extra={"filename": filename, "conversation_id": cid,
                        "limitation": "Upload preparation/file reference is visible; successful message transmission is not independently verified."},
                        level="support", status="partial"))

                # Prompt send requires text plus an explicit send/submit marker in the same bounded context.
                candidates = detail.get("message_candidates") or []
                if self._explicit_send_marker(text) and isinstance(candidates, list):
                    for candidate in candidates:
                        if not isinstance(candidate, dict):
                            continue
                        if str(candidate.get("role_hint") or "").lower() != "user" and str(candidate.get("field") or "").lower() not in {"prompt", "query", "input"}:
                            continue
                        prompt = self._normalize_recovered_text(candidate.get("text"))
                        if prompt:
                            add(self._copy_as_derived(source, "prompt_send_candidate", "GEM-PROMPT-SEND-001",
                                "Prompt text and send-like label co-occur in bounded Gemini raw context",
                                detail_extra={"prompt_text": prompt, "conversation_id": cid,
                                "supporting_finding": True,
                                "limitation": "Raw co-occurrence does not establish a submitted Gemini message; native/structured message semantics are required for Timeline or Conversation promotion."},
                                level="support", status="partial"))

                # Model selection/change trace.
                if re.search(r"(?i)(?:selected[_ -]?model|model[_ -]?(?:id|name|selection)|switch[_ -]?model|change[_ -]?model)", text):
                    models = []
                    for match in MODEL_VALUE_RE.finditer(text):
                        model = re.sub(r"\s+", " ", match.group(1)).strip()
                        if model and model.casefold() not in {m.casefold() for m in models}:
                            models.append(model)
                    if models:
                        add(self._copy_as_derived(source, "model_change_candidate", "GEM-MODEL-001",
                            "Gemini model selection/change marker preserved as supporting finding",
                            detail_extra={"previous_model": models[-2] if len(models) >= 2 else None,
                                          "new_model": models[-1], "conversation_id": cid,
                                          "supporting_finding": True,
                                          "limitation": "Raw/state model labels do not prove an executed model change; event-specific structure is required for Timeline promotion."},
                            level="support", status="partial"))

            # Structured message -> prompt send / recovered conversation.
            structured = self._structured_message_from_row(source)
            if structured and str(structured.get("role") or "").lower() in {"user", "human"}:
                recovery_basis = str(structured.get("recovery_basis") or "")
                aggressive = recovery_basis.startswith("aggressive_raw_prompt")
                add(self._copy_as_derived(source, "prompt_send",
                    "GEM-PROMPT-SEND-RAW-001" if aggressive else "GEM-PROMPT-SEND-STRUCT-001",
                    "Gemini-scoped raw user prompt recovered" if aggressive else "Structured user message recovered",
                    detail_extra={"prompt_text": structured.get("content"),
                                  "conversation_id": structured.get("conversation_id"),
                                  "message_id": structured.get("message_id"),
                                  "recovery_basis": recovery_basis,
                                  "limitation": (
                                      "Prompt text is strongly Gemini-scoped but comes from a labelled raw fallback; transmission is likely but native RPC decoding was unavailable."
                                      if aggressive else
                                      "Structured recovered user message is treated as a sent-message record."
                                  )},
                    level="support" if aggressive else "direct",
                    status="partial" if aggressive else "success"))

            # Semantic download classification.
            if source.get("action_candidate") == "file_download":
                kind = self._download_media_kind(detail)
                filename = str(detail.get("filename") or "")
                completed = self._download_completed(detail)
                gemini_linked = detail.get("gemini_attribution") in {"url_associated_candidate", "linked_download_candidate"}
                if kind == "document" and gemini_linked:
                    add(self._copy_as_derived(source,
                        "document_download" if completed else "document_download_candidate",
                        "GEM-DOWNLOAD-DOC-001", "Gemini-associated document download record",
                        detail_extra={"filename": filename},
                        level="direct" if completed and source.get("evidence_level") == "direct" else "support",
                        status="success" if completed else "partial"))
                if kind == "image" and self._looks_like_gemini_generated_image(detail):
                    add(self._copy_as_derived(source,
                        "generated_image_download" if completed and gemini_linked else "generated_image_download_candidate",
                        "GEM-DOWNLOAD-GENIMG-001", "Generated-image-style Gemini download record",
                        detail_extra={"filename": filename,
                                      "limitation": "Filename pattern is a clue; Gemini attribution is strongest with History/Zone URL linkage."},
                        level="direct" if completed and gemini_linked and source.get("evidence_level") == "direct" else "support",
                        status="success" if completed else "partial"))

            # Generated image deletion in Recycle Bin.
            if source.get("action_candidate") == "file_delete_candidate" and self._looks_like_gemini_generated_image(detail):
                add(self._copy_as_derived(source, "generated_image_delete", "GEM-DELETE-GENIMG-001",
                    "Gemini-generated-style image path found in Recycle Bin metadata",
                    detail_extra={"limitation": "Recycle Bin metadata proves path deletion; Gemini source needs download correlation."},
                    level="direct" if int(detail.get("gemini_related_download_match_count") or 0) > 0 and detail.get("payload_exists") is True else "support",
                    status="success"))

        # First locally observed /app/<id> -> conversation-create candidate only.
        by_cid = {}
        for source in original:
            if source.get("artifact") != "Chrome History" or source.get("action_candidate") != "conversation_access":
                continue
            cids = self._conversation_ids_for_row(source)
            if not cids:
                continue
            cid = cids[0]
            dt = self._row_timestamp_dt(source)
            d = source.get("detail") or {}
            key = (str(d.get("windows_user") or ""), str(d.get("chrome_profile") or ""), cid)
            previous = by_cid.get(key)
            if previous is None or (dt is not None and (previous[0] is None or dt < previous[0])):
                by_cid[key] = (dt, source)
        for (_, _, cid), (_, source) in by_cid.items():
            d = source.get("detail") or {}
            add(self._copy_as_derived(source, "conversation_create", "GEM-CONV-CREATE-001",
                "First locally observed History visit for this Gemini conversation ID",
                detail_extra={"conversation_id": cid, "conversation_title": d.get("title"),
                              "creation_basis": "first_observed_local_history_visit",
                              "limitation": "Creation candidate only; without baseline/event-specific creation data an older conversation first opened locally cannot be excluded."},
                level="support", status="partial"))

        # Multiple explicit account contexts in one profile -> switch candidate.  Keep
        # GAIA/account IDs separate from authuser//u/ slot indices: one real account plus
        # authuser=0 must never be misread as two accounts.
        account_contexts = {}
        source_by_profile = {}
        for source in original:
            detail = source.get("detail") or {}
            profile = (str(detail.get("windows_user") or ""), str(detail.get("chrome_profile") or ""))
            ctx = account_contexts.setdefault(profile, {"account_ids": set(), "slots": set()})
            key_path = str(detail.get("key_path") or "")
            value = detail.get("value")
            if re.search(r"(?i)account_info\.\d+\.account_id$", key_path) and value not in (None, ""):
                ctx["account_ids"].add(str(value)); source_by_profile.setdefault(profile, source)
            url = str(detail.get("url") or "")
            try:
                parsed = urlsplit(url)
                q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                if q.get("authuser") not in (None, ""):
                    ctx["slots"].add(str(q.get("authuser"))); source_by_profile.setdefault(profile, source)
                m = re.search(r"/u/(\d+)(?:/|$)", parsed.path)
                if m:
                    ctx["slots"].add(m.group(1)); source_by_profile.setdefault(profile, source)
            except ValueError:
                pass
        for profile, ctx in account_contexts.items():
            ids = sorted(ctx["account_ids"])
            slots = sorted(ctx["slots"], key=lambda x: (0, int(x)) if x.isdigit() else (1, x))
            if len(ids) >= 2:
                contexts = ["account_id:" + value for value in ids]
                basis = "multiple_account_ids"
            elif len(slots) >= 2:
                contexts = ["account_slot:" + value for value in slots]
                basis = "multiple_account_slots"
            else:
                continue
            source = source_by_profile.get(profile)
            if not source:
                continue
            add(self._copy_as_derived(source, "account_switch", "GEM-ACCOUNT-SWITCH-001",
                "Multiple Google account contexts observed in one Chrome profile",
                detail_extra={"account_contexts": contexts, "account_context_basis": basis,
                              "account_switch_order_known": False,
                              "limitation": "Multiple account contexts are present; switch order/execution is not independently proven."},
                level="support", status="partial"))

        # Deduplicate repeated calls (profile parse + image-wide post-correlation pass).
        existing = set()
        for row in self.results:
            detail = row.get("detail") or {}
            rule = detail.get("derived_rule_id")
            if rule:
                existing.add((rule, row.get("source_path"),
                              json.dumps(row.get("source_locator") or {}, ensure_ascii=False, sort_keys=True, default=str),
                              row.get("action_candidate")))
        appended = 0
        for row in derived:
            detail = row.get("detail") or {}
            key = (detail.get("derived_rule_id"), row.get("source_path"),
                   json.dumps(row.get("source_locator") or {}, ensure_ascii=False, sort_keys=True, default=str),
                   row.get("action_candidate"))
            if key in existing:
                continue
            self.results.append(row); existing.add(key); appended += 1
        if appended:
            self._say(f"[+] Semantic action rules: {appended} derived candidates/events")
        return appended

    @classmethod
    def _profile_key(cls, row):
        detail = row.get("detail") or {}
        return (str(detail.get("windows_user") or ""), str(detail.get("chrome_profile") or ""))

    @classmethod
    def _history_conversation_state(cls, rows):
        state = {}
        for row in rows:
            if row.get("artifact") != "Chrome History":
                continue
            detail = row.get("detail") or {}
            if detail.get("record_type") != "finding":
                continue
            cids = cls._conversation_ids_for_row(row)
            if not cids:
                continue
            profile = cls._profile_key(row)
            for cid in cids:
                key = (profile, cid)
                existing = state.get(key)
                dt = cls._row_timestamp_dt(row)
                title = cls._clean_title(detail.get("title") or detail.get("conversation_title"))
                if existing is None or (dt is not None and (existing[0] is None or dt < existing[0])):
                    state[key] = (dt, title, row)
        return state

    @classmethod
    def _inventory_by_profile(cls, rows, artifact, record_type="inventory"):
        output = {}
        for row in rows:
            if row.get("artifact") != artifact:
                continue
            detail = row.get("detail") or {}
            if detail.get("record_type") != record_type:
                continue
            output.setdefault(cls._profile_key(row), []).append(row)
        return output

    @staticmethod
    def _comparison_template(after_rows, artifact, profile):
        for row in after_rows:
            if row.get("artifact") == artifact and GeminiParser._profile_key(row) == profile:
                return row
        for row in after_rows:
            if row.get("artifact") == artifact:
                return row
        return {
            "service": "Gemini", "environment": "Web", "timestamp": normalize_timestamp(None),
            "action_candidate": None, "artifact": artifact, "observation": "Baseline comparison",
            "detail": {"record_type": "finding", "windows_user": profile[0], "chrome_profile": profile[1]},
            "source_path": None, "source_locator": {}, "evidence_level": "support", "status": "partial", "error": None,
        }

    @classmethod
    def _history_comparison_usable(cls, rows, profile):
        """Require a readable History inventory and no blocking History parse issue for a profile."""
        inventory = False
        for row in rows:
            if row.get("artifact") != "Chrome History" or cls._profile_key(row) != profile:
                continue
            detail = row.get("detail") or {}
            if detail.get("record_type") == "inventory" and isinstance(detail.get("urls_total"), int):
                inventory = True
            if detail.get("record_type") == "analysis_issue" and row.get("status") in {"parse_error", "locked_database", "unsupported"}:
                return False
        return inventory

    def compare_with_baseline(self, baseline_results):
        """Append conservative before/after comparison findings.

        This is optional and is the preferred route for actions whose evidence is inherently
        state-differential (conversation deletion/edit, History clear, Cache clear).  It never
        treats a missing artifact caused by parse failure as deletion.
        """
        before = baseline_results.results if hasattr(baseline_results, "results") else baseline_results
        if not isinstance(before, list):
            raise TypeError("baseline_results must be a parser instance or list of common-schema rows")
        after = list(self.results)
        additions = []

        # Conversation deletion / title-change comparison by profile + conversation ID.
        bstate = self._history_conversation_state(before)
        astate = self._history_conversation_state(after)
        profiles = {profile for profile, _ in bstate} | {profile for profile, _ in astate}
        for profile in profiles:
            if not (self._history_comparison_usable(before, profile) and self._history_comparison_usable(after, profile)):
                continue
            before_ids = {cid for (p, cid) in bstate if p == profile}
            after_ids = {cid for (p, cid) in astate if p == profile}
            # If every conversation disappears, History clear/profile reset is more plausible than
            # individual conversation deletion, so do not emit per-conversation delete events.
            removed = before_ids - after_ids if after_ids else set()
            for cid in sorted(removed):
                source = bstate[(profile, cid)][2]
                baseline_observed = self._display_timestamp(source)
                derived = self._copy_as_derived(source, "conversation_delete_candidate", "GEM-CONV-DELETE-CMP-001",
                    "Conversation ID present in baseline History but absent after comparison",
                    detail_extra={"conversation_id": cid, "comparison_mode": "before_after",
                                  "baseline_present": True, "after_present": False,
                                  "baseline_observed_time": baseline_observed,
                                  "event_timestamp_known": False, "supporting_finding": True,
                                  "limitation": "A History-state difference does not distinguish browser-history removal from server-side Gemini conversation deletion; no deletion time is inferred."},
                    level="support", status="partial")
                derived["timestamp"] = normalize_timestamp(None)
                additions.append(derived)
            common = before_ids & after_ids
            for cid in sorted(common):
                btitle = bstate[(profile, cid)][1]
                atitle = astate[(profile, cid)][1]
                if btitle and atitle and btitle != atitle:
                    source = astate[(profile, cid)][2]
                    after_observed = self._display_timestamp(source)
                    derived = self._copy_as_derived(source, "conversation_edit_candidate", "GEM-CONV-EDIT-CMP-001",
                        "Conversation title differs across baseline History comparison",
                        detail_extra={"conversation_id": cid, "previous_title": btitle, "conversation_title": atitle,
                                      "comparison_mode": "before_after", "after_observed_time": after_observed,
                                      "event_timestamp_known": False, "supporting_finding": True,
                                      "limitation": "A History title difference does not identify a user message edit or its execution time."},
                        level="support", status="partial")
                    derived["timestamp"] = normalize_timestamp(None)
                    additions.append(derived)

        # History clear candidate from table-cardinality decrease. Requires the new inventory rows.
        b_hist = self._inventory_by_profile(before, "Chrome History")
        a_hist = self._inventory_by_profile(after, "Chrome History")
        for profile in set(b_hist) & set(a_hist):
            if not (self._history_comparison_usable(before, profile) and self._history_comparison_usable(after, profile)):
                continue
            def best(rows):
                candidates = [r for r in rows if (r.get("detail") or {}).get("urls_total") is not None]
                return candidates[-1] if candidates else None
            br, ar = best(b_hist[profile]), best(a_hist[profile])
            if not br or not ar:
                continue
            bd, ad = br.get("detail") or {}, ar.get("detail") or {}
            bu, au = bd.get("urls_total"), ad.get("urls_total")
            bv, av = bd.get("visits_total"), ad.get("visits_total")
            if isinstance(bu, int) and isinstance(au, int) and isinstance(bv, int) and isinstance(av, int):
                url_drop, visit_drop = bu - au, bv - av
                material = (url_drop >= 5 and visit_drop >= 5) or (bu > 0 and bv > 0 and au <= bu // 3 and av <= bv // 3)
                if url_drop > 0 and visit_drop > 0 and material:
                    source = self._comparison_template(after, "Chrome History", profile)
                    additions.append(self._copy_as_derived(source, "history_clear_candidate", "GEM-HISTORY-CLEAR-CMP-001",
                        "Chrome History URL/visit counts materially decreased across baseline comparison",
                        detail_extra={"comparison_mode": "before_after", "urls_before": bu, "urls_after": au,
                                      "visits_before": bv, "visits_after": av, "deleted_count": max(url_drop, visit_drop),
                                      "limitation": "A material count decrease is consistent with history deletion; exact user intent/scope still requires scenario or direct deletion evidence."},
                        level="support", status="partial"))

        # Cache clear candidate from file-count collapse. This uses scan_summary, not generic mtimes.
        def cache_counts(rows):
            out = {}
            for row in rows:
                if row.get("artifact") != "Chrome Cache":
                    continue
                d = row.get("detail") or {}
                if d.get("record_type") != "scan_summary":
                    continue
                out[GeminiParser._profile_key(row)] = (d.get("files_read"), d.get("files_examined"), row)
            return out
        bc, ac = cache_counts(before), cache_counts(after)
        for profile in set(bc) & set(ac):
            br, be, _ = bc[profile]
            ar, ae, source = ac[profile]
            before_count = br if isinstance(br, int) else be
            after_count = ar if isinstance(ar, int) else ae
            if isinstance(before_count, int) and isinstance(after_count, int) and before_count > 0 and after_count < before_count:
                # Avoid labelling ordinary churn as clear unless the decrease is material.
                drop = before_count - after_count
                if drop >= 5 or after_count <= max(1, before_count // 3):
                    additions.append(self._copy_as_derived(source, "cache_clear_candidate", "GEM-CACHE-CLEAR-CMP-001",
                        "Chrome Cache file count materially decreased across baseline comparison",
                        detail_extra={"comparison_mode": "before_after", "cache_files_before": before_count,
                                      "cache_files_after": after_count, "deleted_count": drop,
                                      "limitation": "Material cache shrink is consistent with cache clearing; USN/file-delete evidence is stronger when available."},
                        level="support", status="partial"))

        # Append with the same dedupe identity used by semantic derivation.
        existing = {(str((r.get("detail") or {}).get("derived_rule_id")), r.get("source_path"),
                     json.dumps(r.get("source_locator") or {}, ensure_ascii=False, sort_keys=True, default=str),
                     r.get("action_candidate")) for r in self.results if (r.get("detail") or {}).get("derived_rule_id")}
        appended = 0
        for row in additions:
            d = row.get("detail") or {}
            key = (str(d.get("derived_rule_id")), row.get("source_path"),
                   json.dumps(row.get("source_locator") or {}, ensure_ascii=False, sort_keys=True, default=str),
                   row.get("action_candidate"))
            if key in existing:
                continue
            self.results.append(row); existing.add(key); appended += 1
        if appended:
            self._say(f"[+] Baseline comparison rules: {appended} findings")
        return appended

    def export_json(self, path):
        path = self._validate_export(path)
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(self.results, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        return str(path)

    @staticmethod
    def _spreadsheet_safe(flat):
        """Render blank CSV cells explicitly and neutralize formula-like spreadsheet cells."""
        safe = dict(flat)
        for key, value in safe.items():
            if value is None or (isinstance(value, str) and not value.strip()):
                safe[key] = "-"
                continue
            if isinstance(value, str):
                stripped = value.lstrip()
                if len(stripped) > 1 and stripped.startswith(("=", "+", "-", "@", "\t", "\r")):
                    safe[key] = "'" + value
        return safe

    @classmethod
    def _conversation_ids_for_row(cls, row):
        detail = row.get("detail") or {}
        found = []
        values = detail.get("conversation_ids")
        if isinstance(values, (list, tuple)):
            found.extend(str(v) for v in values if v)
        if detail.get("conversation_id"):
            found.append(str(detail["conversation_id"]))
        for key in ("url",):
            value = detail.get(key)
            cid = conversation_id(value) if value else None
            if cid:
                found.append(cid)
        for value in detail.get("urls") or []:
            cid = conversation_id(value)
            if cid:
                found.append(cid)
        return list(dict.fromkeys(found))

    @staticmethod
    def _clean_title(value):
        if value in (None, ""):
            return ""
        text = str(value).replace("\u200e", "").replace("\u200f", "").replace("\ufeff", "").strip()
        return re.sub(r"\s*-\s*Google Gemini\s*$", "", text, flags=re.I).strip()

    @staticmethod
    def _download_media_kind(detail):
        raw_path = detail.get("target_path") or detail.get("current_path") or detail.get("filename") or ""
        suffix = PureWindowsPath(str(raw_path)).suffix.lower()
        mime = str(detail.get("mime_type") or detail.get("original_mime_type") or "").lower()
        if mime.startswith("image/") or suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".avif"}:
            return "image"
        if suffix in {".pdf", ".doc", ".docx", ".hwp", ".hwpx", ".txt", ".rtf", ".ppt", ".pptx", ".xls", ".xlsx", ".csv", ".zip"}:
            return "document"
        return "file"

    @staticmethod
    def _download_completed(detail):
        # Chromium History downloads.state: 1 commonly represents COMPLETE.  File presence and
        # byte equality are additional local corroboration; none of these establish Gemini attribution.
        state = detail.get("state")
        if state == 1:
            return True
        if state in {0, 2, 3, 4}:
            return False
        received, total = detail.get("received_bytes"), detail.get("total_bytes")
        if isinstance(received, int) and isinstance(total, int) and total >= 0 and received == total:
            return True
        return detail.get("file_exists") is True and detail.get("size_matches_history_total") is not False

    @staticmethod
    def _row_timestamp_dt(row):
        """Return an aware UTC datetime for sorting/grouping, or None."""
        timestamp = row.get("timestamp") or {}
        if not isinstance(timestamp, dict):
            return None
        value = timestamp.get("utc") or timestamp.get("kst")
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _row_url(row):
        detail = row.get("detail") or {}
        return str(detail.get("url") or "").strip()

    @classmethod
    def _is_login_trace_row(cls, row):
        """Identify URL-level traces that belong to a Gemini-directed Google login flow."""
        action = row.get("action_candidate")
        detail = row.get("detail") or {}
        url = cls._row_url(row).lower()
        if action == "account_activity_candidate":
            # Re-evaluate attribution from the URL instead of trusting an older stored
            # relevance_basis.  This also cleans up legacy result JSON where generic Google
            # OAuth for Claude/LM Studio/Drive was incorrectly tagged as Gemini-related.
            return history_relevance(url) == "google_account_url_with_gemini_reference" and any(
                token in url for token in ("signin", "login", "servicelogin", "challenge", "identifier",
                                           "accountchooser", "checkcookie")
            )
        if action == "gemini_access_candidate":
            try:
                parsed = urlsplit(url)
                return parsed.hostname == "gemini.google.com" and parsed.path.rstrip("/").endswith("/signin")
            except ValueError:
                return False
        return False

    @staticmethod
    def _login_step_label(row):
        raw = str((row.get("detail") or {}).get("url") or "")
        try:
            parsed = urlsplit(raw)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
        except ValueError:
            host, path = "", raw.lower()
        if host == "gemini.google.com" and path.rstrip("/").endswith("/signin"):
            return "Gemini signin redirect"
        if path.endswith("/servicelogin"):
            return "ServiceLogin"
        if path.endswith("/signin/identifier"):
            return "identifier"
        if path.endswith("/signin/accountchooser"):
            return "account chooser"
        if path.endswith("/signin/challenge/pwd"):
            return "password challenge"
        if "/signin/challenge/" in path:
            return "additional verification challenge"
        if path.endswith("/checkcookie"):
            return "CheckCookie"
        return "login-related URL"

    @staticmethod
    def _forensic_scope(row):
        """Keep correlation inside one evidence partition and Windows/Chrome profile."""
        detail = row.get("detail") or {}
        locator = row.get("source_locator") or {}
        evidence = detail.get("image_path") or locator.get("image_path")
        if not evidence:
            # Profile-mode rows carry artifact paths instead of image provenance. Strip only
            # known artifact suffixes so History and Cache share their original profile root.
            source = str(row.get("source_path") or "").replace("\\", "/")
            profile_path = re.match(
                r"^(.*)/(?:History(?:-wal|-shm|-journal)?|Cache|Code Cache|Sessions|Local Storage|"
                r"Session Storage|IndexedDB|Service Worker)(?:/.*)?$", source, re.I,
            )
            evidence = profile_path.group(1) if profile_path else source
        if not evidence:
            # Missing provenance is not proof that two independent rows share evidence.
            evidence = f"unscoped:{id(row)}"
        partition = detail.get("profile_partition_offset")
        if partition is None:
            partition = detail.get("partition_offset")
        if partition is None:
            partition = locator.get("partition_offset")
        return (str(evidence or "").replace("\\", "/").casefold(),
                str(partition) if partition is not None else "",
                str(detail.get("windows_user") or ""), str(detail.get("chrome_profile") or ""))

    @classmethod
    def _aggregate_login_flows(cls, rows, gap_seconds=180):
        """Collapse a burst of login-navigation URLs into one analyst timeline event.

        This does not claim successful authentication.  It only states that a linked login URL
        sequence was observed.  Raw visit rows remain untouched in gemini_results.json.
        """
        traces = [r for r in rows if cls._is_login_trace_row(r) and cls._row_timestamp_dt(r) is not None]
        traces.sort(key=lambda r: cls._row_timestamp_dt(r))
        if not traces:
            return []

        scoped_traces = {}
        for row in traces:
            scoped_traces.setdefault(cls._forensic_scope(row), []).append(row)
        groups = []
        for scoped_rows in scoped_traces.values():
            current = [scoped_rows[0]]
            for row in scoped_rows[1:]:
                prev_dt = cls._row_timestamp_dt(current[-1])
                cur_dt = cls._row_timestamp_dt(row)
                if prev_dt is not None and cur_dt is not None and (cur_dt - prev_dt).total_seconds() <= gap_seconds:
                    current.append(row)
                else:
                    groups.append(current)
                    current = [row]
            groups.append(current)
        groups.sort(key=lambda group: cls._row_timestamp_dt(group[0]))

        summaries = []
        for group in groups:
            first = group[0]
            first_detail = first.get("detail") or {}
            urls = []
            steps = []
            ids = []
            for row in group:
                url = cls._row_url(row)
                if url and url not in urls:
                    urls.append(url)
                step = cls._login_step_label(row)
                if step not in steps:
                    steps.append(step)
                locator = row.get("source_locator") or {}
                if isinstance(locator, dict) and locator.get("id") is not None:
                    ids.append(locator.get("id"))
            start_dt = cls._row_timestamp_dt(group[0])
            end_dt = cls._row_timestamp_dt(group[-1])
            duration = int((end_dt - start_dt).total_seconds()) if start_dt and end_dt else None
            detail = {
                "record_type": "finding_summary",
                "login_trace_count": len(group),
                "login_steps": steps,
                "urls": urls[:20],
                "visit_ids": ids[:50],
                "flow_duration_seconds": duration,
                "relevance_basis": "google_login_flow_with_gemini_redirect",
                "windows_user": first_detail.get("windows_user"),
                "chrome_profile": first_detail.get("chrome_profile"),
                "filesystem_type": first_detail.get("filesystem_type"),
                "image_path": first_detail.get("image_path"),
                "partition_offset": first_detail.get("partition_offset"),
                "limitation": (
                    "Google/Gemini login-related navigation was observed as one URL flow. "
                    "URL navigation alone does not prove that authentication completed successfully."
                ),
            }
            summaries.append(dict(zip(FIELDS, [
                first.get("service", "Gemini"), first.get("environment", "Web"), first.get("timestamp"),
                "login_flow_candidate", "Chrome History",
                f"Gemini-directed Google login URL flow summarized ({len(group)} visit records)",
                detail, first.get("source_path"),
                {"table": "visits", "id": ids[0] if ids else None,
                 "flow_visit_ids": ids[:50],
                 "partition_offset": (first.get("source_locator") or {}).get("partition_offset"),
                 "filesystem_path": (first.get("source_locator") or {}).get("filesystem_path")},
                "support", "success", None
            ])))
        return summaries

    @staticmethod
    def _looks_like_gemini_generated_image(detail):
        """Strict filename-only clue used only to retain an *unconfirmed* delete candidate."""
        raw = (detail.get("original_filename") or detail.get("filename") or detail.get("original_path")
               or detail.get("target_path") or detail.get("current_path") or "")
        name = PureWindowsPath(str(raw)).name.lower().replace(" ", "_")
        if not name:
            return False
        return bool(re.match(r"^gemini[_-]generated[_-]image(?:[_-]|\.)", name))

    @staticmethod
    def _portable_payload_location(value):
        """Render an image-internal Recycle Bin path without DD/E01 container prefixes."""
        text = str(value or "").strip()
        if not text:
            return "?"
        match = re.search(r"::NTFS@\d+(/.*)$", text, re.I)
        return match.group(1) if match else text

    @classmethod
    def _is_timeline_relevant_finding(cls, row):
        """Keep only Gemini-specific or strongly Gemini-linked action candidates in timeline.csv.

        Generic Chrome downloads and unrelated Recycle Bin rows are preserved in JSON but omitted
        from the service-specific analyst timeline.
        """
        detail = row.get("detail") or {}
        action = row.get("action_candidate")
        if not action or detail.get("record_type") not in {"finding", "finding_summary"}:
            return False
        if row.get("status") not in {"success", "partial"}:
            return False

        # The final team Timeline is for user actions, not every supporting clue.
        # Keep weak/ambiguous candidates in gemini_results.json, but do not promote them
        # to timeline.csv without event-specific evidence.
        if action == "conversation_create" and detail.get("creation_basis") == "first_observed_local_history_visit":
            return False
        if action == "account_switch" and detail.get("account_switch_order_known") is False:
            return False
        if action in SUPPORTING_ONLY_ACTIONS:
            return False

        if action in {
            "conversation_access", "file_download",
            "login", "logout", "account_switch", "conversation_create", "conversation_delete",
            "conversation_edit", "conversation_retry", "prompt_send", "prompt_draft", "image_upload",
            "document_upload", "attachment_remove",
            "document_download", "image_generation",
            "generated_image_download", "generated_image_delete",
            "data_export", "share_link_create", "model_change",
            "account_name_change", "temporary_chat", "temporary_chat_url",
        }:
            return True

        if action == "gemini_access_candidate":
            # /signin belongs to the aggregated login flow, not to ordinary Gemini access.
            return is_gemini_url(detail.get("url")) and not cls._is_login_trace_row(row)

        if action == "account_activity_candidate":
            # Login traces are aggregated separately. Non-login account URLs may remain if Gemini-linked.
            if cls._is_login_trace_row(row):
                return False
            return detail.get("relevance_basis") == "google_account_url_with_gemini_reference"

        if action == "file_download_candidate":
            # By definition this row lacks sufficient Gemini attribution; keep it only in JSON.
            return False

        if action == "file_delete_candidate":
            if detail.get("gemini_related_download_match_count"):
                return True
            if detail.get("gemini_attribution") in {"linked_download_candidate", "url_associated_candidate"}:
                return True
            # A Gemini-generated default filename is only a clue: retain as '의심', never '확정'.
            return cls._looks_like_gemini_generated_image(detail)

        return False

    @classmethod
    def _is_visible_support_evidence(cls, row):
        """Return True for Gemini-specific evidence worth showing in the two CSV analyst view.

        These rows are deliberately labelled as 흔적/의심 and never as a confirmed semantic
        action.  Generic Chrome downloads and unrelated Recycle Bin items remain excluded.
        """
        detail = row.get("detail") or {}
        if detail.get("record_type") not in {"finding", "finding_summary"}:
            return False
        if row.get("status") not in {"success", "partial"}:
            return False

        action = row.get("action_candidate")
        if action in {"conversation_candidate", "cached_image_candidate"}:
            return True

        if action == "file_download_candidate":
            return False
        if action == "file_delete_candidate":
            return cls._looks_like_gemini_generated_image(detail) or bool(detail.get("gemini_related_download_match_count"))

        artifact = str(row.get("artifact") or "")
        if artifact in {"Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage", "Chrome IndexedDB", "Chrome Cache"}:
            return bool(detail.get("matched_string") or detail.get("raw_hit_count") or detail.get("origin_namespace_matches_gemini"))
        if artifact in {"Chrome Preferences", "Chrome Secure Preferences"}:
            # Only surface settings explicitly scoped/categorized as Gemini evidence.
            # Browser-global values such as clear_data.cache are preserved in JSON but are
            # not a Gemini user-action trace by themselves.
            return detail.get("relevance_scope") == "gemini" or bool(detail.get("preference_category"))
        if artifact == "Chrome Cookies":
            return detail.get("relevance_scope") == "gemini_host" or str(detail.get("host_key") or "").lower().endswith("gemini.google.com")
        return False

    @classmethod
    def _timeline_action(cls, row):
        """Map internal candidates to the team's analyst-facing behavior names.

        Candidate/uncertainty belongs in Behavior_details and Verdict rather than in a
        different behavior name.  This mirrors the team reference CSV, e.g. a draft
        prompt is still shown under '사용자 프롬프트 입력/전송' with Verdict='의심'.
        """
        action = row.get("action_candidate")
        detail = row.get("detail") or {}
        labels = {
            "login": "로그인",
            "login_flow_candidate": "로그인",
            "logout": "로그아웃",
            "account_switch": "계정 전환",
            "conversation_create": "새로운 대화 생성",
            "conversation_delete": "기존 대화 삭제",
            "conversation_edit": "대화 수정",
            "conversation_retry": "대화 재시도",
            "prompt_send": "사용자 프롬프트 입력/전송",
            "prompt_draft": "사용자 프롬프트 입력/전송",
            "prompt_delete_candidate": "사용자 프롬프트 삭제",
            "image_upload": "이미지 업로드",
            "image_upload_candidate": "이미지 업로드",
            "document_upload": "문서 업로드",
            "document_upload_candidate": "문서 업로드",
            "document_download": "문서 다운로드",
            "document_download_candidate": "문서 다운로드",
            "image_generation": "이미지 생성 요청",
            "image_generation_candidate": "이미지 생성 요청",
            "generated_image_download": "생성 이미지 다운로드",
            "generated_image_download_candidate": "생성 이미지 다운로드",
            "generated_image_delete": "생성 이미지 다운로드 삭제",
            "data_export": "대화 데이터 Export",
            "data_export_candidate": "대화 데이터 Export",
            "share_link_create": "공유 링크 생성",
            "share_link_candidate": "공유 링크 생성",
            "model_change": "모델 변경",
            "account_name_change": "계정 이름 변경",
            "account_name_change_candidate": "계정 이름 변경",
            "temporary_chat": "임시 채팅 사용",
            "temporary_chat_url": "임시 채팅 사용",
            "incognito_mode_candidate": "브라우저 시크릿 모드",
            "history_clear_candidate": "방문기록 삭제",
            "cache_clear_candidate": "캐시 삭제",
            "gemini_access_candidate": "서비스 접속",
            "conversation_access": "서비스 접속",
            "conversation_candidate": "대화 관련 흔적",
            "cached_image_candidate": "이미지 생성 관련 흔적",
        }

        if action == "account_activity_candidate":
            url = str(detail.get("url") or "").lower()
            if any(token in url for token in ("logout", "signout")):
                return "로그아웃"
            if any(token in url for token in ("signin", "login", "servicelogin", "challenge", "identifier", "accountchooser", "checkcookie")):
                return "로그인"
            return "계정 활동 접근"

        if action == "attachment_remove":
            filename = detail.get("filename") or detail.get("original_filename") or ""
            if IMAGE_FILE_RE.search(str(filename)):
                return "이미지 업로드 삭제"
            if DOCUMENT_FILE_RE.search(str(filename)):
                return "문서 업로드 삭제"
            # The team taxonomy has no generic upload-delete label. Keep an
            # unclassified removal only in JSON/coverage instead of inventing one.
            return "업로드 삭제 관련 흔적"

        if action == "file_delete_candidate" and cls._looks_like_gemini_generated_image(detail):
            return "생성 이미지 다운로드 삭제"

        if action in {"file_download", "file_download_candidate"}:
            kind = cls._download_media_kind(detail)
            if kind == "document":
                return "문서 다운로드"
            # The shared taxonomy distinguishes generated-image downloads, but has
            # no generic '이미지 다운로드' action. Non-generated images use the
            # agreed upper-level '파일 다운로드' label.
            return "파일 다운로드"

        if not action:
            artifact = str(row.get("artifact") or "")
            record_type = detail.get("record_type")
            if record_type in {"finding", "finding_summary"}:
                if artifact in {"Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage", "Chrome IndexedDB", "Chrome Cache"}:
                    return "Gemini 관련 흔적"
                if artifact in {"Chrome Preferences", "Chrome Secure Preferences"}:
                    return "Gemini 설정 흔적"
                if artifact == "Chrome Cookies":
                    return "Gemini 계정/세션 흔적"
            return "분석 관련 흔적"
        return labels.get(action, str(action))
    @classmethod
    def _timeline_action_detail(cls, row):
        """Render 행위_상세 using the team's shared wording without promoting weak evidence.

        The wording describes the artifact actually observed.  Raw Session/Cache/LevelDB hits are
        deliberately phrased as traces/candidates rather than confirmed semantic user actions.
        """
        action = row.get("action_candidate")
        detail = row.get("detail") or {}
        cids = cls._conversation_ids_for_row(row)
        cid = cids[0] if cids else ""
        title = cls._clean_title(detail.get("conversation_title") or detail.get("title"))
        url = str(detail.get("url") or "").strip()
        filename = str(detail.get("filename") or detail.get("original_filename") or "").strip()
        subject = title or cid or filename or url

        def tagged(prefix, value=None):
            value = str(value if value is not None else subject).strip()
            return f"{prefix}_{value}" if value else prefix

        # Shared-team taxonomy / future decoded-event actions.
        if action == "login_flow_candidate":
            steps = detail.get("login_steps") or []
            suffix = " → ".join(str(x) for x in steps[:8] if x)
            count = detail.get("login_trace_count")
            base = "로그인 URL 방문 흔적(인증 완료 미확인)"
            if suffix:
                base += "_" + suffix
            if count:
                base += f" ({count}개 방문 레코드)"
            return base
        if action == "login":
            method = str(detail.get("auth_method") or "").lower()
            return tagged("magic-link 인증 URL 방문" if "magic" in method else "로그인 URL 방문 흔적(인증 완료 미확인)", url)
        if action == "logout":
            return tagged("로그아웃 시각 기록" if detail.get("logout_time") else "로그아웃 URL 방문", url or cls._display_timestamp(row))
        if action == "account_switch":
            before = detail.get("previous_account_uuid") or detail.get("previous_uuid")
            after = detail.get("new_account_uuid") or detail.get("current_uuid")
            if before and after and detail.get("account_switch_order_known") is not False:
                return f"재인증 이벤트와 복수 계정 컨텍스트_{before} → {after}"
            contexts = detail.get("account_contexts") or []
            rendered = " | ".join(str(x) for x in contexts[:8] if x)
            return "복수 계정 컨텍스트(전환 순서/실행 미확인)" + ("_" + rendered if rendered else "")
        if action == "conversation_create":
            if detail.get("creation_basis") == "first_observed_local_history_visit":
                return tagged("신규 대화 후보(History 최초 관찰, 생성 직접 증거 미확인)", title or cid)
            return tagged("대화 생성 기록", title or cid)
        if action == "conversation_delete":
            return tagged("대화 삭제 이벤트/요청 근거", title or cid)
        if action == "conversation_edit":
            return tagged("대화 수정 이벤트/메시지 관계 근거", title or cid)
        if action == "conversation_retry":
            return tagged("응답 재시도/재생성 이벤트 근거", title or cid)
        if action in {"conversation_delete_candidate", "conversation_edit_candidate", "conversation_retry_candidate"}:
            return tagged("대화 관련 semantic/UI marker(행위 실행 미확인)", title or cid)
        if action == "prompt_send":
            prompt = detail.get("prompt_text") or detail.get("message_content") or detail.get("message_text") or ""
            first = str(prompt).strip().splitlines()[0] if str(prompt).strip() else title or cid
            return tagged("사용자 메시지 전송", first)
        if action == "prompt_draft":
            prompt = detail.get("prompt_text") or detail.get("draft_text") or ""
            first = str(prompt).strip().splitlines()[0] if str(prompt).strip() else title or cid
            return tagged("프롬프트 작성 흔적(전송 미확인)", first)
        if action == "prompt_send_candidate":
            prompt = detail.get("prompt_text") or detail.get("message_content") or ""
            first = str(prompt).strip().splitlines()[0] if str(prompt).strip() else title or cid
            return tagged("프롬프트/전송 라벨 공존 흔적(실제 전송 미확인)", first)
        if action == "prompt_delete_candidate":
            return tagged("Gemini 활동/프롬프트 삭제 관련 페이지 접근(삭제 내용 미확인)", url or title)
        if action in {"image_upload", "document_upload"}:
            return tagged("전송 메시지 첨부", filename)
        if action == "image_upload_candidate":
            return tagged("이미지 업로드 준비 흔적(전송 불확인)", filename)
        if action == "document_upload_candidate":
            return tagged("문서 업로드 준비 흔적(전송 불확인)", filename)
        if action == "attachment_remove":
            summary = detail.get("summary") or row.get("observation") or filename
            return tagged("첨부 제거 이벤트", summary)
        if action == "attachment_remove_candidate":
            return tagged("첨부 제거 관련 marker(실행 미확인)", filename or title or cid)
        if action in {"document_download", "generated_image_download"}:
            return tagged("다운로드 완료 기록", filename)
        if action in {"document_download_candidate", "generated_image_download_candidate"}:
            return tagged("다운로드 시도 흔적(완료 미확인)", filename)
        if action == "image_generation":
            return tagged("생성 이미지 결과 객체", title or cid)
        if action == "image_generation_candidate":
            return tagged("이미지 생성 요청 관련 흔적(결과 객체 미확인)", title or cid)
        if action == "generated_image_delete":
            original = detail.get("original_path") or "?"
            final = cls._portable_payload_location(detail.get("payload_path") or detail.get("final_path"))
            return f"휴지통 이동 기록_{original} → {final}"
        if action == "data_export":
            return tagged("Export 요청/아카이브 확인", detail.get("cache_key") or url)
        if action == "data_export_candidate":
            return tagged("Export 설정 화면 접근(완료 미확인)", url)
        if action == "share_link_create":
            return tagged("공유 스냅샷 객체", title or cid)
        if action == "share_link_candidate":
            return tagged("공유 URL/스냅샷 관련 흔적(신규 생성 미확인)", url or title or cid)
        if action == "model_change":
            before = detail.get("previous_model") or "?"
            after = detail.get("new_model") or detail.get("model") or "?"
            prefix = "대화 내 모델 변경" if cid else "모델 선택 이벤트"
            return f"{prefix}_{before} → {after}"
        if action == "model_change_candidate":
            before = detail.get("previous_model") or "?"
            after = detail.get("new_model") or detail.get("model") or "?"
            return f"모델 관련 상태/라벨 흔적(변경 실행 미확인)_{before} → {after}"
        if action == "account_name_change":
            before = detail.get("previous_name") or "?"
            after = detail.get("new_name") or "?"
            return f"계정 표시 이름 변경 기록_{before} → {after}"
        if action == "account_name_change_candidate":
            return tagged("계정 이름 변경 화면 접근(변경 완료 미확인)", url or title)
        if action == "temporary_chat":
            return tagged("임시 채팅 상태/이벤트 근거", title or cid)
        if action == "temporary_chat_candidate":
            return tagged("임시 채팅 관련 semantic/UI marker(사용 실행 미확인)", title or cid)
        if action == "temporary_chat_url":
            return tagged("임시 채팅 URL 접근 흔적(대화 미확인)", url)
        if action == "incognito_mode_candidate":
            return "시크릿/Off-the-record 관련 로컬 흔적(사용 사실 단독 확정 불가)"
        if action == "history_clear_candidate":
            return "방문기록 삭제 관련 흔적(삭제 실행/범위 추가 검증 필요)"
        if action == "cache_clear_candidate":
            count = detail.get("deleted_count") or detail.get("file_count") or detail.get("count")
            rule_id = str(detail.get("derived_rule_id") or "")
            artifact = str(row.get("artifact") or "")
            # Never claim USN deletion unless the record actually came from an NTFS/USN
            # deletion comparison.  A Preferences flag or raw clearBrowserData marker only
            # supports a cache-clear candidate.
            if count not in (None, "") and ("USN" in artifact.upper() or "CACHE-CLEAR-CMP" in rule_id):
                return f"Cache 파일 일괄 삭제/감소 흔적(사용자 의도 미확인)_Cache 파일 {count}건"
            return "캐시 삭제 관련 흔적(실제 삭제 실행/범위 추가 검증 필요)"

        # Actions currently produced by the Gemini parser.
        if action == "gemini_access_candidate":
            return tagged("Gemini URL 방문 흔적", url or title)
        if action == "conversation_access":
            # History /app/<id> proves navigation/access, not conversation creation or prompt submission.
            return tagged("대화 URL 접근 흔적", title or cid or url)
        if action == "account_activity_candidate":
            low = url.lower()
            if any(token in low for token in ("logout", "signout")):
                return tagged("로그아웃 URL 방문", url)
            if any(token in low for token in ("signin", "login", "servicelogin", "challenge", "identifier")):
                return tagged("로그인 URL 방문 흔적(인증 완료 미확인)", url)
            return tagged("Google 계정 활동 URL 접근 흔적(Gemini 관련)", url or title)
        if action == "conversation_candidate":
            return tagged("대화 관련 raw 문자열 흔적(행위 미확인)", cid or title)
        if action == "cached_image_candidate":
            image_type = detail.get("type") or detail.get("detected_type") or detail.get("format") or "image signature"
            return tagged("생성 이미지 후보 흔적(Cache raw, 결과 객체 미확인)", image_type)
        if action in {"file_download", "file_download_candidate"}:
            completed = cls._download_completed(detail)
            attribution = detail.get("gemini_attribution")
            if completed:
                prefix = "다운로드 완료 기록"
                if action == "file_download_candidate" or attribution == "unlinked_chrome_download":
                    prefix += "(Gemini 연관 미확인)"
            else:
                prefix = "다운로드 시도 흔적(완료 미확인)"
            return tagged(prefix, filename or detail.get("target_path") or detail.get("current_path"))
        if action == "file_delete_candidate":
            original = detail.get("original_path") or filename or "?"
            final = cls._portable_payload_location(detail.get("payload_path"))
            if detail.get("payload_exists"):
                return f"휴지통 이동 기록_{original} → {final}"
            return tagged("Recycle Bin 삭제 메타데이터 기록(payload 존재 미확인)", original)

        # Supporting evidence that is Gemini-specific but does not establish one of the
        # team's semantic user actions is still shown, explicitly as a trace rather than
        # being promoted to a confirmed action.
        if not action:
            artifact = str(row.get("artifact") or "")
            if detail.get("raw_hit_count") is not None:
                return f"Gemini raw 문자열 흔적_{artifact} {detail.get('raw_hit_count')}건"
            if detail.get("matched_string"):
                locator = row.get("source_locator") or {}
                offset = detail.get("offset", locator.get("offset"))
                suffix = f" offset={offset}" if offset is not None else ""
                return f"Gemini raw 문자열 흔적_{artifact}{suffix}"
            if artifact in {"Chrome Preferences", "Chrome Secure Preferences"}:
                category = detail.get("preference_category")
                count = detail.get("preference_key_count")
                if category:
                    return f"Gemini 관련 설정 흔적_{category}" + (f" {count}개" if count is not None else "")
                if detail.get("key_path"):
                    return tagged("Gemini 관련 설정 값", detail.get("key_path"))
            if artifact == "Chrome Cookies":
                host = detail.get("host_key") or ""
                name = detail.get("name") or ""
                return tagged("Gemini 쿠키 메타데이터", f"{host}/{name}".strip("/"))

        observation = cls._compact_display_value(row.get("observation"), 420)
        return observation or "-"

    @classmethod
    def _timeline_verdict(cls, row):
        """Return only the two team-agreed analyst verdicts: 확정 / 의심.

        확정 기준은 회의 피드백대로 (1) 해당 행위를 직접 특정하는 명시적 근거 1개,
        또는 (2) 서로 독립적인 아티팩트가 같은 행위를 일관되게 교차 검증하는 경우다.
        단순 raw 문자열 반복이나 같은 History 안의 여러 URL은 독립 교차 검증으로 세지 않는다.
        """
        detail = row.get("detail") or {}
        evidence = row.get("evidence_level")
        status = row.get("status")
        action = row.get("action_candidate")

        if evidence == "direct" and status == "success":
            return "확정"

        if status == "success" and detail.get("cross_validated") is True:
            return "확정"
        try:
            if status == "success" and int(detail.get("independent_artifact_count") or 0) >= 2:
                return "확정"
        except (TypeError, ValueError):
            pass

        # A Recycle Bin $I record directly proves deletion of the path, while an exact
        # Gemini-associated download match independently establishes the service source.
        # Only promote the generated-image category when the filename clue is also present.
        if (action == "file_delete_candidate" and status == "success"
                and cls._looks_like_gemini_generated_image(detail)
                and detail.get("payload_exists") is True
                and int(detail.get("gemini_related_download_match_count") or 0) > 0):
            return "확정"

        return "의심"

    @staticmethod
    def _model_name(row):
        """Return the normalized team model label used by the reference CSVs."""
        service = str(row.get("service") or "Gemini").strip().lower().replace(" ", "-")
        environment = str(row.get("environment") or "Web").strip().lower().replace(" ", "-")
        if service == "gemini" and environment == "web":
            return "gemini-web"
        if environment and environment not in {"unknown", "n/a"} and environment not in service:
            return f"{service}-{environment}"
        return service
    @staticmethod
    def _artifact_tag(artifact):
        return {
            "Chrome History": "History",
            "Chrome Cookies": "Cookies",
            "Chrome Preferences": "Preferences",
            "Chrome Secure Preferences": "Secure Preferences",
            "Chrome Sessions": "Sessions/Tabs",
            "Chrome Local Storage": "Local Storage",
            "Chrome Session Storage": "Session Storage",
            "Chrome IndexedDB": "IndexedDB",
            "Chrome Cache": "Cache",
            "Windows Recycle Bin": "$Recycle.Bin",
            "Zone.Identifier": "Zone.Identifier",
        }.get(str(artifact or ""), str(artifact or "Artifact"))

    @staticmethod
    def _image_internal_to_windows(value):
        """Convert image-internal /Users/... paths to the reference C:\\... notation."""
        raw = str(value or "").strip()
        if not raw:
            return ""
        match = re.search(r"::NTFS@\d+(/.*)$", raw, re.I)
        if match:
            raw = match.group(1)
        if re.match(r"^[A-Za-z]:[\\/]", raw):
            return raw.replace("/", "\\")
        if raw.startswith("/"):
            return "C:" + raw.replace("/", "\\")
        return raw

    @classmethod
    def _team_artifact_path(cls, row):
        """Return evidence paths only, without image-container/profile bookkeeping.

        The reference output points analysts to the actual History/Cache/LevelDB/$I/$R
        artifacts.  DD/E01 container names, partition offsets and user/profile labels stay in JSON.
        """
        detail = row.get("detail") or {}
        locator = row.get("source_locator") or {}
        paths = []

        def add(value):
            rendered = cls._image_internal_to_windows(value)
            if not rendered:
                return
            low = rendered.lower()
            # Never use the E01/DD container itself as Artifact_path when an internal
            # filesystem artifact is known.
            if low.endswith((".e01", ".dd", ".img", ".raw", ".001")):
                return
            if rendered not in paths:
                paths.append(rendered)

        if isinstance(locator, dict):
            add(locator.get("filesystem_path"))

        # Correlated file evidence, when actually present/identified.
        if row.get("action_candidate") in {"file_download", "document_download", "generated_image_download"}:
            if detail.get("file_exists") is True:
                add(detail.get("resolved_path") or detail.get("current_path") or detail.get("target_path"))
        if row.get("action_candidate") in {"file_delete_candidate", "generated_image_delete"}:
            add(detail.get("payload_path"))

        # Profile-mode parser source paths are already the evidence paths.
        source = str(row.get("source_path") or "")
        if source and not re.search(r"\.(?:e01|dd|img|raw)$", source, re.I):
            add(source)

        return "|".join(paths)

    @classmethod
    def _timeline_artifact_detail(cls, row):
        """Render concise evidence text in the same style as the team reference output."""
        detail = row.get("detail") or {}
        action = row.get("action_candidate")
        artifact = row.get("artifact")
        tag = cls._artifact_tag(artifact)

        if action == "login_flow_candidate":
            urls = [str(x) for x in (detail.get("urls") or []) if x]
            steps = [str(x) for x in (detail.get("login_steps") or []) if x]
            bits = [f"[{tag}] 로그인 관련 URL={len(urls)}건"]
            if steps:
                bits.append("단계=" + " → ".join(steps[:8]))
            if urls:
                bits.append("대표 URL=" + cls._compact_display_value(urls[0], 420))
            return bits[0] + ((", " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact == "Chrome History":
            if action in {"file_download", "file_download_candidate", "document_download", "document_download_candidate", "generated_image_download", "generated_image_download_candidate"}:
                state = detail.get("state")
                state_text = "COMPLETE" if state == 1 else str(state) if state is not None else "UNKNOWN"
                chain = detail.get("url_chain") or []
                dl_url = ""
                if chain and isinstance(chain[0], dict):
                    dl_url = str(chain[0].get("url") or "")
                bits = [f"[{tag}] 다운로드 상태={state_text}"]
                filename = detail.get("filename")
                if filename:
                    bits.append(f"파일명={filename}")
                target = detail.get("target_path") or detail.get("current_path")
                if target:
                    bits.append(f"저장 경로={target}")
                if detail.get("mime_type"):
                    bits.append(f"MIME={detail.get('mime_type')}")
                size = detail.get("total_bytes") if detail.get("total_bytes") is not None else detail.get("received_bytes")
                if size is not None:
                    bits.append(f"크기={size}")
                if dl_url:
                    bits.append("다운로드 URL=" + cls._compact_display_value(dl_url, 420))
                return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

            bits = [f"[{tag}]"]
            if detail.get("url"):
                bits.append("URL=" + cls._compact_display_value(detail.get("url"), 500))
            if detail.get("title"):
                bits.append("제목=" + cls._compact_display_value(cls._clean_title(detail.get("title")), 220))
            if detail.get("visit_count") is not None:
                bits.append(f"방문 횟수={detail.get('visit_count')}")
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact == "Windows Recycle Bin":
            bits = [f"[{tag}]"]
            if detail.get("original_path"):
                bits.append(f"원본 경로={detail.get('original_path')}")
            if detail.get("original_size") is not None:
                bits.append(f"원본 크기={detail.get('original_size')}")
            deletion_time = detail.get("deletion_time")
            if deletion_time:
                fake = {"timestamp": deletion_time, "detail": {}}
                bits.append("삭제 시각=" + cls._display_timestamp(fake))
            if detail.get("payload_exists") is not None:
                bits.append("$R 존재=" + ("예" if detail.get("payload_exists") else "아니오"))
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact == "Chrome Cache":
            bits = [f"[{tag}]"]
            if action == "cached_image_candidate":
                bits.append("유형=image_signature_candidate")
                if detail.get("detected_type"):
                    bits.append(f"형식={detail.get('detected_type')}")
                bits.append("Gemini 문자열 동일 파일=" + ("예" if detail.get("gemini_related_strings_found") else "아니오"))
            else:
                cache_type = detail.get("cache_type") or detail.get("response_type") or detail.get("type")
                if cache_type:
                    bits.append("유형=" + str(cache_type))
                if detail.get("conversation_title") or detail.get("title"):
                    bits.append("대화 제목=" + str(detail.get("conversation_title") or detail.get("title")))
                cids = cls._conversation_ids_for_row(row)
                if cids:
                    bits.append("대화 UUID=" + cids[0])
                if detail.get("is_temporary") is not None:
                    bits.append("is_temporary=" + str(bool(detail.get("is_temporary"))))
                model = detail.get("model") or detail.get("model_name")
                if model:
                    bits.append("모델=" + str(model))
                content_type = detail.get("content_type") or detail.get("Content-Type")
                if content_type:
                    bits.append("Content-Type=" + str(content_type))
                content_encoding = detail.get("content_encoding") or detail.get("Content-Encoding")
                if content_encoding:
                    bits.append("Content-Encoding=" + str(content_encoding))
                text_value = detail.get("message_content") or detail.get("message_text") or detail.get("prompt_text") or detail.get("response_text")
                if text_value:
                    bits.append("내용=" + cls._compact_display_value(text_value, 420))
                if detail.get("matched_string"):
                    bits.append("문자열=" + str(detail.get("matched_string")))
                if detail.get("raw_hit_count") is not None:
                    bits.append(f"raw hit={detail.get('raw_hit_count')}건")
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact in {"Chrome Sessions", "Chrome Local Storage", "Chrome Session Storage", "Chrome IndexedDB"}:
            bits = [f"[{tag}]"]
            store = detail.get("store") or detail.get("store_name") or detail.get("object_store")
            if store:
                bits.append("저장소=" + str(store))
            if detail.get("key"):
                bits.append(f"key={detail.get('key')}")
            if detail.get("key_path"):
                bits.append(f"key={detail.get('key_path')}")
            live_state = detail.get("live_state") or detail.get("entry_state")
            if live_state:
                bits.append("상태=" + str(live_state))
            if detail.get("raw_hit_count") is not None:
                bits.append(f"Gemini raw hit={detail.get('raw_hit_count')}건")
            cids = cls._conversation_ids_for_row(row)
            if cids:
                bits.append("대화 UUID=" + cids[0])
            if detail.get("matched_string"):
                bits.append("문자열=" + str(detail.get("matched_string")))
            text_value = detail.get("prompt_text") or detail.get("draft_text") or detail.get("value")
            if text_value not in (None, ""):
                bits.append("내용=" + cls._compact_display_value(text_value, 420))
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact == "Chrome Cookies":
            bits = [f"[{tag}]"]
            for key, label in (("host_key", "host"), ("name", "name"), ("is_secure", "secure"), ("is_httponly", "httponly")):
                if detail.get(key) is not None:
                    bits.append(f"{label}={detail.get(key)}")
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        if artifact in {"Chrome Preferences", "Chrome Secure Preferences"}:
            bits = [f"[{tag}]"]
            if detail.get("key_path"):
                bits.append(f"key={detail.get('key_path')}")
            if detail.get("value") not in (None, ""):
                bits.append("값=" + cls._compact_display_value(detail.get("value"), 420))
            return bits[0] + ((" " + ", ".join(bits[1:])) if len(bits) > 1 else "")

        # Generic fallback: concise observation + the most useful structured fields.
        parts = [f"[{tag}]"]
        observation = cls._compact_display_value(row.get("observation"), 320)
        if observation:
            parts.append(observation)
        for key, label in (("filename", "파일명"), ("url", "URL"), ("original_path", "원본 경로"),
                           ("conversation_id", "대화 UUID"), ("model", "모델")):
            value = cls._compact_display_value(detail.get(key), 360)
            if value:
                parts.append(f"{label}={value}")
        return ", ".join(parts)
    @classmethod
    def _timeline_rule(cls, row):
        artifact = row.get("artifact")
        action = row.get("action_candidate")
        detail = row.get("detail") or {}
        derived_rule = detail.get("derived_rule_id")
        if derived_rule:
            return str(derived_rule)
        if artifact == "Chrome History" and action == "conversation_access":
            return "GEM-HIS-002: /app/<conversation-id> 방문 기록"
        if artifact == "Chrome History" and action == "gemini_access_candidate":
            return "GEM-HIS-001: Gemini URL 방문 기록"
        if action == "file_download":
            return "GEM-DL-001: Chrome download + Gemini 연관성"
        if action == "file_download_candidate":
            return "GEM-DL-002: Chrome download 존재, Gemini 연관성 미확정"
        if action == "file_delete_candidate":
            if detail.get("related_download_match_count") or detail.get("gemini_related_download_match_count"):
                return "GEM-RB-001: Recycle Bin $I + 다운로드 경로 상관분석"
            return "GEM-RB-002: Recycle Bin $I 삭제 흔적"
        if artifact == "Chrome Sessions":
            return "GEM-SES-001: Session/Tabs raw Gemini 문자열"
        if artifact in {"Chrome Local Storage", "Chrome Session Storage", "Chrome IndexedDB"}:
            return "GEM-STO-001: Storage raw Gemini 문자열"
        if artifact == "Chrome Cache" and action == "cached_image_candidate":
            return "GEM-CACHE-002: Gemini raw context + 이미지 시그니처"
        if artifact == "Chrome Cache":
            return "GEM-CACHE-001: Cache raw Gemini 문자열"
        if artifact in {"Chrome Preferences", "Chrome Secure Preferences"}:
            return "GEM-PREF-001: Gemini 관련 Preference 값"
        return "GEM-GEN-001: 아티팩트 기반 사용자 행위 후보"

    @classmethod
    def _timeline_basis(cls, row):
        detail = row.get("detail") or {}
        parts = []
        observation = cls._compact_display_value(row.get("observation"), 360)
        if observation:
            parts.append(observation)
        evidence = row.get("evidence_level")
        if evidence == "direct":
            parts.append("해당 행위/접근을 직접 보여주는 구조화 아티팩트에 기반")
        elif evidence == "support":
            parts.append("직접 행위 증명은 아니며 다른 증거를 보조하는 흔적")
        elif evidence == "unconfirmed":
            parts.append("아티팩트는 존재하지만 Gemini 사용자 행위와의 직접 연결이 불명확")
        limitation = detail.get("limitation")
        if limitation:
            parts.append("제한: " + str(limitation))
        if row.get("error"):
            parts.append("오류: " + str(row["error"]))
        return " | ".join(parts) if parts else "-"

    @classmethod
    def _timeline_row(cls, row):
        timestamp = cls._display_timestamp(row) if cls._has_reliable_timeline_timestamp(row) else ""
        return {
            "Model": cls._model_name(row),
            "Timestamp": timestamp,
            "User_behavior": cls._timeline_action(row),
            "Behavior_details ": cls._timeline_action_detail(row),
            "Verdict": cls._timeline_verdict(row),
            "Artifact_path": cls._team_artifact_path(row),
            "Artifact_details ": cls._timeline_artifact_detail(row) + cls._volume_suffix(row),
        }

    @staticmethod
    def _volume_suffix(row):
        """팀 통합 volume_ref 용: 행의 파티션 오프셋을 Artifact_details 끝에 volume=ntfs@<offset> 로 남긴다."""
        locator = row.get("source_locator") or {}
        offset = locator.get("partition_offset") if isinstance(locator, dict) else None
        return f", volume=ntfs@{offset}" if offset not in (None, "") else ""

    @staticmethod
    def _has_reliable_timeline_timestamp(row):
        timestamp = row.get("timestamp") or {}
        if not isinstance(timestamp, dict):
            return False
        return bool(timestamp.get("utc") or timestamp.get("kst"))

    def _raw_prompt_draft_rows(self):
        """Promote only explicitly label-associated raw prompt text to an *uncertain* behavior.

        This mirrors the reference parser's draft rows: the text is useful to an analyst, but raw
        LevelDB/Session/Cache context does not prove transmission, so the synthetic event is always
        support/partial and therefore Verdict='의심'.
        """
        output = []
        seen = set()
        for row in self.results:
            detail = row.get("detail") or {}
            semantic_text = self._semantic_text(row)
            if self._is_google_search_context(semantic_text):
                continue
            cids = self._conversation_ids_for_row(row)
            strong_gemini = bool(cids or detail.get("origin_namespace_matches_gemini") is True
                                 or re.search(r"(?i)(?:hNvQHb|StreamGenerate|BardChatUi|gemini\.google\.com/_/)", semantic_text))
            if self._is_cross_service_prompt_context(semantic_text) and not strong_gemini:
                continue
            if self._explicit_send_marker(semantic_text):
                # The semantic rule engine will emit prompt_send; do not duplicate it as an unsent draft.
                continue
            candidates = detail.get("message_candidates")
            if not isinstance(candidates, list):
                continue
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                field = str(candidate.get("field") or "").lower()
                role = str(candidate.get("role_hint") or "").lower()
                if field not in {"prompt", "query", "input"} and role != "user":
                    continue
                text = self._decode_aggressive_prompt_text(candidate.get("text"), field)
                if not text:
                    continue
                source = self._team_artifact_path(row)
                key = (source, text)
                if key in seen:
                    continue
                seen.add(key)
                cloned = dict(row)
                cloned_detail = dict(detail)
                cloned_detail["record_type"] = "finding"
                cloned_detail["prompt_text"] = text
                cloned_detail["draft_text"] = text
                cloned_detail["limitation"] = (
                    "Label-associated text was recovered from bounded raw context; transmission was not confirmed."
                )
                cloned["detail"] = cloned_detail
                cloned["action_candidate"] = "prompt_draft"
                cloned["observation"] = "Prompt draft text recovered from bounded raw context"
                cloned["evidence_level"] = "support"
                cloned["status"] = "partial"
                output.append(cloned)
        return output

    def timeline_rows(self):
        """Return final team Timeline rows: user-action events/candidates only.

        Raw Session/Storage/Cache strings, cookies and preference values remain evidence in JSON.
        They are not themselves user behavior and therefore are not emitted as Timeline rows.
        Login URL steps are collapsed into one candidate flow. Explicitly labelled raw prompt text
        may appear only as a prompt *draft* candidate with Verdict='의심'; transmission is not claimed.
        """
        rows = []
        for row in self.results:
            detail = row.get("detail") or {}
            if detail.get("record_type") not in {"finding", "finding_summary"}:
                continue
            if self._is_login_trace_row(row):
                continue
            if not self._is_timeline_relevant_finding(row):
                continue

            action = row.get("action_candidate")
            # Account URLs that are not a login/logout/switch event are context, not a user action.
            if action == "account_activity_candidate":
                mapped = self._timeline_action(row)
                if mapped == "계정 활동 접근":
                    continue
                # login is aggregated and logout is represented by the semantic derived row.
                if mapped in {"로그인", "로그아웃"}:
                    continue
            # Unlinked generic Chrome downloads never enter the Gemini timeline.
            if action == "file_download_candidate":
                continue
            if action == "file_download" and self._download_media_kind(detail) == "image" and self._looks_like_gemini_generated_image(detail):
                # Prefer generated_image_download(_candidate), which carries the correct team behavior name.
                continue
            # Recycle Bin rows require a Gemini-related download link or a strict Gemini-generated
            # filename clue; filename-only evidence remains an uncertain candidate.
            if action == "file_delete_candidate" and not (
                self._looks_like_gemini_generated_image(detail)
                or detail.get("gemini_related_download_match_count")
                or detail.get("gemini_attribution") in {"linked_download_candidate", "url_associated_candidate"}
            ):
                continue
            rows.append(row)

        rows.extend(self._aggregate_login_flows(self.results))
        rows.extend(self._raw_prompt_draft_rows())

        unique = []
        seen = set()
        for row in rows:
            rendered = self._timeline_row(row)
            behavior = rendered.get("User_behavior")
            if behavior not in TEAM_BEHAVIORS:
                # Integration contract: unknown/raw labels must not leak into final timeline.csv.
                continue
            key = tuple(str(rendered.get(field, "")) for field in TIMELINE_FIELDS)
            if key in seen:
                continue
            seen.add(key)
            unique.append(row)

        unique.sort(key=lambda r: (
            0 if self._has_reliable_timeline_timestamp(r) else 1,
            self._analyst_timestamp_sort_key(r),
            self._timeline_action(r),
            self._team_artifact_path(r),
            str((r.get("source_locator") or {}).get("offset") or ""),
        ))
        return unique

    @classmethod
    def _timestamp_value_for_display(cls, value):
        """Return a timestamp only when it can satisfy the team CSV contract.

        The integration runner accepts only ``YYYY-MM-DD HH:MM:SS.ffffff KST`` or ``-``.
        Structured message timestamps may be independent of the enclosing artifact row, so
        timezone-less, numeric-without-format, or otherwise ambiguous values are not guessed.
        They are returned as an empty value and become ``-`` only at CSV rendering time.
        """
        if value in (None, ""):
            return ""
        if isinstance(value, dict):
            candidate = value.get("kst") or value.get("utc")
            if not candidate:
                return ""
        else:
            candidate = value

        # A bare number has no trustworthy unit/epoch here.  Do not manufacture a time.
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
            return ""
        text = str(candidate).strip()
        if not text:
            return ""
        if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST", text):
            return text
        # Digit-only strings are equally ambiguous (seconds/ms/WebKit/FILETIME, etc.).
        if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", text):
            return ""
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return ""
            parsed = parsed.astimezone(KST)
            return parsed.strftime("%Y-%m-%d %H:%M:%S") + f".{parsed.microsecond:06d} KST"
        except (TypeError, ValueError, OverflowError):
            return ""

    @staticmethod
    def _qualified_message_recovery_basis(basis):
        """Allow only protocol/native structures that explicitly encode message semantics.

        Raw/heuristic text may remain valuable supporting evidence in JSON, but must never be
        re-used as recovered conversation content or a confirmed prompt-send event.
        """
        value = str(basis or "").strip().casefold()
        if not value:
            return False
        rejected = (
            "aggressive_raw_prompt", "gemini_f_req_heuristic",
            "labeled_string_in_bounded_raw_context", "structured_artifact_fields",
        )
        if any(token in value for token in rejected):
            return False
        exact = {
            "structured_stream_query", "structured_stream_choice",
            "history_rpc_user_prompt", "history_rpc_assistant_candidate",
            "gemini_f_req_structured",
        }
        if value in exact:
            return True
        # CCL/native storage wrappers prepend an artifact namespace to the same qualified
        # protocol basis. Explicit deserialized message objects are also allowed because
        # _structured_messages_from_json_value() requires role + content + conversation id.
        if any(value.endswith("_" + suffix) for suffix in exact):
            return True
        if "structured_object" in value and value.startswith("ccl_"):
            return True
        return False

    @classmethod
    def _structured_message_from_row(cls, row):
        """Extract a message only when the record already contains explicit structured message fields.

        Raw Session/Cache/LevelDB context is deliberately NOT promoted to message content.
        """
        detail = row.get("detail") or {}
        recovery_basis = str(detail.get("recovery_basis") or "")
        if detail.get("message_semantics_verified") is False or not cls._qualified_message_recovery_basis(recovery_basis):
            return None
        cids = cls._conversation_ids_for_row(row)
        cid = cids[0] if cids else None
        content = None
        content_key = None
        for key in ("message_content", "message_text", "content", "prompt_text", "response_text"):
            value = detail.get(key)
            if isinstance(value, str) and value.strip():
                content, content_key = value, key
                break
        role = detail.get("role") or detail.get("message_role")
        message_id = detail.get("message_id") or detail.get("message_uuid")
        parent_id = detail.get("parent_message_id") or detail.get("parent_message_uuid")
        # Require explicit message semantics.  A generic raw context/string is not enough.
        # conversation_id may be absent in a request payload; recovered_conversation_rows()
        # may correlate a user prompt to a unique History conversation title afterward.
        content = cls._normalize_message_content(content) if content else None
        if not content or not (role or message_id or content_key in {"prompt_text", "response_text"}):
            return None
        msg_time = detail.get("message_timestamp") or detail.get("message_time")
        if isinstance(msg_time, dict):
            time_display = cls._timestamp_value_for_display(msg_time)
        elif msg_time:
            time_display = cls._timestamp_value_for_display(msg_time)
        else:
            # Use row timestamp only when the record itself explicitly represents a structured message.
            time_display = cls._display_timestamp(row)
        return {
            "model_name": cls._model_name(row),
            "conversation_id": cid,
            "title": detail.get("conversation_title") or detail.get("title") or "",
            "message_id": message_id or "",
            "parent_message_id": parent_id or "",
            "message_order": detail.get("message_order") or detail.get("message_index"),
            "role": role or ("user" if content_key == "prompt_text" else "assistant" if content_key == "response_text" else ""),
            "content": content,
            "message_time": time_display if time_display != "N/A - raw scan has no record timestamp" else "",
            "recovery_status": "본문 복구",
            "artifact": row.get("artifact") or "",
            "artifact_path": cls._team_artifact_path(row),
            "artifact_detail": cls._timeline_artifact_detail(row),
            "recovery_basis": recovery_basis,
            "protocol": detail.get("protocol"),
            "protocol_offset": detail.get("protocol_offset"),
            "protocol_sequence": detail.get("protocol_sequence"),
            "response_id": detail.get("response_id"),
            "choice_id": detail.get("choice_id"),
            "candidate_rank": detail.get("candidate_rank"),
        }

    @classmethod
    def _raw_message_candidates_from_row(cls, row):
        """Return explicitly unconfirmed message candidates from bounded raw context."""
        detail = row.get("detail") or {}
        candidates = detail.get("message_candidates")
        if not isinstance(candidates, list) or not candidates:
            return []
        cids = cls._conversation_ids_for_row(row)
        cid = cids[0] if cids else ""
        title = cls._clean_title(detail.get("conversation_title") or detail.get("title"))
        locator = row.get("source_locator") or {}
        base_offset = locator.get("offset", detail.get("offset"))
        output = []
        for index, candidate in enumerate(candidates, 1):
            if not isinstance(candidate, dict):
                continue
            content = cls._normalize_recovered_text(candidate.get("text"))
            if not content:
                continue
            field = str(candidate.get("field") or "text")
            message_id = f"raw@{base_offset if base_offset is not None else 'unknown'}#{index}"
            explanation = (
                cls._timeline_artifact_detail(row)
                + f" | raw field={field}; bounded context에서 추출된 본문 후보이며 "
                  "native Gemini message decode 결과가 아니므로 실제 대화/역할은 미확정"
            )
            output.append({
                "model_name": cls._model_name(row),
                "conversation_id": cid,
                "title": title,
                "message_id": message_id,
                "parent_message_id": "",
                "message_order": "",
                "role": candidate.get("role_hint") or "",
                "content": content,
                "message_time": "",
                "recovery_status": "부분 복구 후보 (raw context, 본문/역할 미확정)",
                "artifact": row.get("artifact") or "",
                "artifact_path": cls._team_artifact_path(row),
                "artifact_detail": explanation,
            })
        return output

    def recovered_conversation_rows(self):
        """Return recovered Gemini messages in the team Conversation schema.

        Only structurally decoded persistent Gemini request/response messages qualify.
        History titles and aggressive raw-prompt candidates are metadata/supporting evidence only.
        Streamed wrb.fr chunks are consolidated by response id so partial cumulative answers are
        not emitted as separate assistant messages. A cid-less structured request prompt is linked
        only when its text uniquely matches a locally observed Gemini History title.
        """
        history_titles = {}
        title_index = {}
        for source_index, row in enumerate(self.results):
            if row.get("artifact") != "Chrome History":
                continue
            detail = row.get("detail") or {}
            cid = detail.get("conversation_id")
            title = self._clean_title(detail.get("conversation_title") or detail.get("title"))
            if not cid or not title:
                continue
            cid = str(cid)
            scope = self._forensic_scope(row)
            history_titles.setdefault((scope, cid), title)
            canonical = re.sub(r"\s+", " ", title).strip().casefold()
            title_index.setdefault(scope, {}).setdefault(canonical, set()).add(cid)



        candidates = []
        for source_index, row in enumerate(self.results):
            detail = row.get("detail") or {}
            if detail.get("record_type") not in {"finding", "finding_summary"}:
                continue
            recovery_basis = str(detail.get("recovery_basis") or "")
            if not self._qualified_message_recovery_basis(recovery_basis):
                # Raw/heuristic/derived text remains JSON supporting evidence only.
                continue
            msg = self._structured_message_from_row(row)
            if not msg:
                continue

            cid = str(msg.get("conversation_id") or "").strip()
            content = self._normalize_message_content(msg.get("content"))
            if not content:
                continue
            scope = self._forensic_scope(row)
            role = str(msg.get("role") or "UNKNOWN").strip().lower()
            if role == "human":
                role = "user"
            elif role == "model":
                role = "assistant"

            # Request payloads can carry the prompt without a conversation id. Correlate only
            # against a unique, non-generic Gemini History title. This prevents arbitrary f.req
            # strings from becoming recovered conversations.
            if not cid and role == "user":
                canonical = re.sub(r"\s+", " ", content).strip().casefold()
                generic_titles = {"새로운 대화 시작", "new chat", "gemini", "google gemini"}
                # Generic Gemini landing/new-chat titles are not message semantics.  Reject
                # them before both exact and prefix correlation so an exact title match cannot
                # accidentally assign a cid-less request to an arbitrary conversation.
                scoped_titles = title_index.get(scope, {})
                matches = set() if canonical in generic_titles else set(scoped_titles.get(canonical, set()))
                if not matches and canonical not in generic_titles:
                    for candidate_title, candidate_cids in scoped_titles.items():
                        if candidate_title in generic_titles:
                            continue
                        shorter = min(len(canonical), len(candidate_title))
                        if shorter < 16:
                            continue
                        if canonical.startswith(candidate_title) or candidate_title.startswith(canonical):
                            matches.update(candidate_cids)
                if len(matches) == 1:
                    cid = next(iter(matches))

            if not cid:
                continue

            title = self._clean_title(msg.get("title") or "") or history_titles.get((scope, cid), "")
            candidates.append({
                "Model": msg.get("model_name") or "gemini-web",
                "timestamp": msg.get("message_time") or "",
                "conversation_uuid": cid,
                "conversation_title": title,
                "message_uuid": msg.get("message_id") or "",
                "parent_message_uuid": msg.get("parent_message_id") or "",
                "message order": msg.get("message_order") if msg.get("message_order") is not None else "",
                "role": role or "UNKNOWN",
                "content": content,
                "Artifact_path": msg.get("artifact_path") or "",
                "_source_index": source_index,
                "_scope": scope,
                "_protocol_offset": msg.get("protocol_offset"),
                "_protocol_sequence": msg.get("protocol_sequence"),
                "_basis": msg.get("recovery_basis") or "",
                "_response_id": str(msg.get("response_id") or ""),
                "_choice_id": str(msg.get("choice_id") or ""),
                "_candidate_rank": msg.get("candidate_rank"),
            })

        # History titles remain metadata only. They are never synthesized into user-message rows.

        def basis_score(row):
            basis = str(row.get("_basis") or "")
            if basis.startswith("ccl_cache_"):
                return 9
            if basis.startswith("ccl_indexeddb_"):
                return 8
            if basis.startswith("ccl_local_storage_"):
                return 7
            if basis.startswith("ccl_session_storage_"):
                return 7
            if basis.startswith("ccl_service_worker_"):
                return 6
            if basis.startswith("history_rpc_"):
                return 6
            if basis.startswith("structured_stream"):
                return 4
            if basis == "gemini_f_req_structured":
                return 3
            if "f_req" in basis:
                return 2
            return 1

        def row_quality(row):
            return (
                basis_score(row),
                len(str(row.get("content") or "")),
                1 if row.get("message_uuid") else 0,
                1 if row.get("timestamp") else 0,
                int(row.get("_protocol_offset") or 0),
                int(row.get("_source_index") or 0),
            )

        # READ_CHAT parent metadata points to the response-candidate branch that was actually
        # continued. Collect those choice ids across all artifacts/pages before collapsing groups.
        referenced_history_choices = {
            (str(row.get("conversation_uuid") or ""), str(row.get("_choice_id") or ""))
            for row in candidates
            if row.get("role") == "user" and "history_rpc_" in str(row.get("_basis") or "")
            and row.get("_choice_id")
        }

        # First consolidate records that have a real message/response turn identifier. This is
        # critical for streamed Gemini answers: later wrb.fr chunks usually repeat the same
        # response_id with progressively longer text, and only the best/final text should remain.
        strong_groups = {}
        fallback = []
        for row in candidates:
            response_id = row.get("_response_id")
            message_id = row.get("message_uuid")
            if response_id:
                key = ("response", row["conversation_uuid"], row["role"], response_id)
            elif message_id:
                key = ("message", row["conversation_uuid"], row["role"], message_id)
            else:
                fallback.append(row)
                continue
            strong_groups.setdefault(key, []).append(row)

        output = []
        for group in strong_groups.values():
            history_assistants = [
                row for row in group
                if row.get("role") == "assistant" and "history_rpc_" in str(row.get("_basis") or "")
            ]
            if history_assistants:
                continued = [
                    row for row in history_assistants
                    if (str(row.get("conversation_uuid") or ""), str(row.get("_choice_id") or ""))
                    in referenced_history_choices
                ]
                if continued:
                    best = max(continued, key=row_quality).copy()
                else:
                    # Latest/uncontinued regenerated turn: use the first candidate returned by
                    # Gemini, matching the web client's own fallback when no child pointer exists.
                    best = min(
                        history_assistants,
                        key=lambda row: (
                            int(row.get("_candidate_rank")) if str(row.get("_candidate_rank")).isdigit() else 10**9,
                            -row_quality(row)[0],
                        ),
                    ).copy()
            else:
                best = max(group, key=row_quality).copy()
            offsets = [int(r.get("_protocol_offset")) for r in group if r.get("_protocol_offset") is not None]
            sources = [int(r.get("_source_index") or 0) for r in group]
            best["_turn_offset"] = min(offsets) if offsets else int(best.get("_protocol_offset") or 0)
            best["_turn_source_index"] = min(sources) if sources else int(best.get("_source_index") or 0)
            output.append(best)

        # A request-side f.req prompt can duplicate the user query already recovered from the
        # matching response. Suppress that weaker copy, but do not collapse two strong response
        # turns merely because the user happened to submit identical text twice.
        strong_semantics = {
            (
                str(row.get("conversation_uuid") or ""),
                str(row.get("role") or "").lower(),
                re.sub(r"\s+", " ", str(row.get("content") or "")).strip(),
            )
            for row in output
        }
        fallback_unique = {}
        for row in fallback:
            semantic = (
                str(row.get("conversation_uuid") or ""),
                str(row.get("role") or "").lower(),
                re.sub(r"\s+", " ", str(row.get("content") or "")).strip(),
            )
            if semantic in strong_semantics:
                continue
            if str(row.get("_basis") or "").startswith("aggressive_raw_prompt"):
                continue
            fallback_key = semantic
            previous = fallback_unique.get(fallback_key)
            if previous is None or row_quality(row) > row_quality(previous):
                fallback_unique[fallback_key] = row
        for row in fallback_unique.values():
            row = row.copy()
            row["_turn_offset"] = int(row.get("_protocol_offset") or 0)
            row["_turn_source_index"] = int(row.get("_source_index") or 0)
            output.append(row)

        by_cid = {}
        for row in output:
            by_cid.setdefault(str(row["conversation_uuid"]), []).append(row)
        for cid, group in by_cid.items():
            # Preserve explicit order and timestamps. Untimed READ_CHAT turns use their
            # chronological protocol sequence before byte/source position.
            group.sort(key=lambda r: (
                0 if str(r.get("message order") or "").isdigit() else 1,
                int(r["message order"]) if str(r.get("message order") or "").isdigit() else 10**9,
                0 if r.get("timestamp") not in (None, "", "-") else 1,
                str(r.get("timestamp") or ""),
                (int(r["_protocol_sequence"])
                 if r.get("timestamp") in (None, "", "-")
                 and "history_rpc_" in str(r.get("_basis") or "")
                 and r.get("_protocol_sequence") is not None else 0),
                int(r.get("_turn_source_index") or 0),
                int(r.get("_turn_offset") or 0),
                int(r.get("_protocol_sequence") or 0),
                0 if r.get("role") == "user" else 1 if r.get("role") == "assistant" else 2,
            ))
            used = {int(r["message order"]) for r in group if str(r.get("message order") or "").isdigit()}
            nxt = 1
            for row in group:
                if row.get("message order") in (None, ""):
                    while nxt in used:
                        nxt += 1
                    row["message order"] = nxt
                    used.add(nxt)
                    nxt += 1
                if not row.get("conversation_title"):
                    row["conversation_title"] = history_titles.get((row["_scope"], cid), "")

        output.sort(key=lambda r: (
            str(r.get("conversation_uuid") or ""),
            int(r["message order"]) if str(r.get("message order") or "").isdigit() else 10**9,
            str(r.get("timestamp") or ""),
            int(r.get("_turn_source_index") or 0),
        ))
        return [{field: row.get(field, "") for field in CONVERSATION_FIELDS} for row in output]

    def _emit_conversation_scope_summaries(self):
        """Emit JSON-only primary metadata and persistent-body recovery summaries.

        These rows deliberately do not feed either team CSV. History/SNSS navigation identifies
        conversations and access traces; body recovery is reported separately so a title is never
        mistaken for the user's prompt.
        """
        # Build the final qualified conversation view first.  This reuses the same filtering,
        # correlation and de-duplication rules as recovered_conversations.csv, so an aggressive
        # raw prompt can never make the JSON summary claim that a body was recovered.
        conversation_rows = self.recovered_conversation_rows()
        recovered_cids = {
            str(row.get("conversation_uuid") or "")
            for row in conversation_rows if row.get("conversation_uuid")
        }

        conversations = {}
        structured_by_artifact = Counter()
        for row in self.results:
            detail = row.get("detail") or {}
            artifact = str(row.get("artifact") or "")

            # Count only rows that meet the persistent structured-message policy.  Raw prompt
            # candidates remain useful support evidence but are not conversation-body findings.
            basis = str(detail.get("recovery_basis") or "")
            if (detail.get("record_type") in {"finding", "finding_summary"}
                    and self._qualified_message_recovery_basis(basis)
                    and self._structured_message_from_row(row) is not None):
                structured_by_artifact[artifact] += 1

            if artifact not in {"Chrome History", "Chrome Sessions"} or detail.get("record_type") != "finding":
                continue
            # Metadata summaries describe primary History/SNSS observations only. Semantic
            # action rows are derived copies of those observations and must not be counted again
            # as additional History/Session records after semantic derivation has completed.
            if detail.get("derived_rule_id"):
                continue
            for cid in self._conversation_ids_for_row(row):
                if not cid:
                    continue
                cid = str(cid)
                item = conversations.setdefault(cid, {
                    "conversation_id": cid, "titles": [], "history_records": 0,
                    "session_navigation_records": 0, "evidence_sources": [], "timestamps": [],
                })
                title = self._clean_title(detail.get("conversation_title") or detail.get("title"))
                if title and title not in item["titles"]:
                    item["titles"].append(title)
                if artifact not in item["evidence_sources"]:
                    item["evidence_sources"].append(artifact)
                if artifact == "Chrome History":
                    item["history_records"] += 1
                elif artifact == "Chrome Sessions" and detail.get("recovery_basis") == "ccl_snss_navigation":
                    item["session_navigation_records"] += 1
                shown = self._display_timestamp(row)
                if shown and shown not in {"-", "N/A - raw scan has no record timestamp"}:
                    item["timestamps"].append(shown)

        for cid, item in sorted(conversations.items()):
            times = sorted(set(item.pop("timestamps")))
            title = item["titles"][0] if item["titles"] else ""
            payload = {
                "record_type": "conversation_metadata_summary",
                **item,
                "conversation_title": title,
                "first_observed": times[0] if times else "",
                "last_observed": times[-1] if times else "",
                "body_recovered_from_persistent_artifact": cid in recovered_cids,
                "scope": "persistent_disk_artifacts",
                "limitation": "History/Sessions prove navigation/access metadata, not the literal conversation body.",
            }
            self._emit("conversation_scope", "Gemini conversation metadata summary",
                       detail=payload, level="support", status="success")

        deep_rows = []
        deep_limitations = {}
        for row in self.results:
            detail = row.get("detail") or {}
            if detail.get("record_type") != "deep_recovery_status":
                continue
            artifact = str(row.get("artifact") or "-")
            summary = {
                "artifact": artifact,
                "status": row.get("status") or "-",
                "message_findings": int(detail.get("message_findings") or 0),
                "decode_errors": int(detail.get("decode_errors") or 0),
                "ccl_available": bool(detail.get("ccl_available")),
                "native_structure_decoded": bool(detail.get("native_structure_decoded")),
            }
            deep_rows.append(summary)
            reasons = []
            if not summary["ccl_available"]:
                reasons.append("ccl_unavailable")
            if summary["decode_errors"]:
                reasons.append(f"decode_errors={summary['decode_errors']}")
            if row.get("status") in {"parse_error", "locked_database", "unsupported"}:
                reasons.append(str(row.get("status")))
            if reasons:
                deep_limitations.setdefault(artifact, []).extend(reasons)

        body_artifacts = ["Chrome Cache", "Chrome Sessions", "Chrome IndexedDB",
                          "Chrome Local Storage", "Chrome Session Storage", "Chrome Service Worker"]
        unavailable = {
            artifact: self.artifact_status.get(key)
            for key, artifact in self.ARTIFACTS.items()
            if artifact in body_artifacts and key in self.artifact_status
            and self.artifact_status.get(key) in {"parse_error", "locked_database", "unsupported"}
        }
        for artifact, reasons in deep_limitations.items():
            unavailable.setdefault(artifact, ",".join(sorted(set(reasons))))

        if conversation_rows:
            recovery_status = "persistent_body_recovered"
        elif not self.deep_recovery:
            recovery_status = "persistent_body_not_assessed"
        elif unavailable:
            recovery_status = "persistent_body_not_found_with_limitations"
        else:
            recovery_status = "persistent_body_not_found"
        self._emit(
            "conversation_scope", "Persistent Gemini conversation-body recovery summary",
            detail={
                "record_type": "conversation_recovery_summary",
                "scope": "persistent_disk_artifacts",
                "recovery_status": recovery_status,
                "metadata_conversation_count": len(conversations),
                "recovered_conversation_rows": len(conversation_rows),
                "structured_message_findings_by_artifact": dict(structured_by_artifact),
                "body_source_artifacts": body_artifacts,
                "artifact_limitations": unavailable,
                "deep_recovery_statuses": deep_rows,
                "memory_analysis_included": False,
                "network_capture_included": False,
                "limitation": (
                    "No persistent body finding means no stable body was recovered from the examined supported local artifacts; "
                    "it does not prove that the conversation never existed. Live-memory/HAR findings are intentionally outside this parser input scope."
                ),
            },
            level="unconfirmed", status="partial" if unavailable else "success")

    def _artifact_analysis_states(self):
        """Collect per-artifact parser coverage from analysis_status records."""
        states = {}
        for row in self.results:
            detail = row.get("detail") or {}
            if detail.get("record_type") != "analysis_status":
                continue
            artifact = str(row.get("artifact") or "")
            if not artifact:
                continue
            states.setdefault(artifact, []).append(str(row.get("status") or ""))
        return states

    def _weak_action_support(self, behavior):
        """Return a conservative reason when supporting evidence exists but cannot prove the behavior."""
        action_map = {
            "계정 전환": {"account_switch"},
            "새로운 대화 생성": {"conversation_create"},
            "기존 대화 삭제": {"conversation_delete_candidate"},
            "대화 수정": {"conversation_edit_candidate"},
            "대화 재시도": {"conversation_retry_candidate"},
            "사용자 프롬프트 입력/전송": {"prompt_send_candidate"},
            "사용자 프롬프트 삭제": {"prompt_delete_candidate"},
            "이미지 업로드": {"image_upload_candidate"},
            "문서 업로드": {"document_upload_candidate"},
            "이미지 생성 요청": {"image_generation_candidate", "cached_image_candidate"},
            "대화 데이터 Export": {"data_export_candidate"},
            "공유 링크 생성": {"share_link_candidate"},
            "모델 변경": {"model_change_candidate"},
            "계정 이름 변경": {"account_name_change_candidate"},
            "임시 채팅 사용": {"temporary_chat_candidate", "temporary_chat_url"},
            "브라우저 시크릿 모드": {"incognito_mode_candidate"},
            "방문기록 삭제": {"history_clear_candidate"},
            "캐시 삭제": {"cache_clear_candidate"},
        }
        actions = action_map.get(behavior, set())
        supporting = [
            row for row in self.results
            if row.get("action_candidate") in actions
            and (row.get("detail") or {}).get("record_type") in {"finding", "finding_summary"}
        ]
        if supporting:
            return f"Supporting Finding {len(supporting)}건 확인; 최종 사용자 행위로 승격할 직접/구조적 근거는 부족함"

        if behavior == "사용자 프롬프트 입력/전송":
            drafts = self._raw_prompt_draft_rows()
            if drafts:
                return f"bounded raw context에서 프롬프트/입력 라벨 후보 {len(drafts)}건 확인; 전송 여부 미확인"
        if behavior in {"새로운 대화 생성", "대화 수정", "대화 재시도", "임시 채팅 사용", "모델 변경"}:
            count = sum(
                1 for row in self.results
                if row.get("action_candidate") == "conversation_candidate"
                and (row.get("detail") or {}).get("record_type") == "finding"
            )
            if count:
                return f"대화 관련 raw 구조/ID 후보 {count}건 확인; 해당 행위를 직접 특정할 수 없음"
        if behavior == "이미지 생성 요청":
            count = sum(1 for row in self.results if row.get("action_candidate") == "cached_image_candidate")
            if count:
                return f"Gemini 관련 Cache 파일에서 이미지 시그니처 후보 {count}건 확인; 생성 결과 객체/요청 행위 미확인"
        if behavior == "방문기록 삭제":
            inv = [r for r in self.results if r.get("artifact") == "Chrome History" and (r.get("detail") or {}).get("record_type") == "inventory" and (r.get("detail") or {}).get("urls_total") is not None]
            if inv:
                return "현재 History 수량은 확인했지만 단일 사후 이미지의 수량만으로 삭제 실행을 확정할 수 없음; baseline/직접 삭제 증거 필요"
        if behavior == "캐시 삭제":
            pref = [r for r in self.results if r.get("artifact") in {"Chrome Preferences", "Chrome Secure Preferences"} and "clear_data.cache" in str((r.get("detail") or {}).get("key_path") or "").lower()]
            if pref:
                return "clear_data.cache 설정 흔적은 확인했지만 설정값만으로 실제 캐시 삭제 실행을 확정할 수 없음; 직접 삭제 증거 필요"
        if behavior == "브라우저 시크릿 모드":
            return "일반 Profile의 비잔존만으로 시크릿 모드 사용을 증명할 수 없음; 명시적 OTR/incognito 흔적이 없으면 판단 보류"
        return None

    def coverage_rows(self):
        """Optional debug coverage: what was detected, inconclusive, or simply not observed.

        This never feeds timeline.csv. It exists so '판단 불가/미관찰' 상태 is retained without
        pretending it is a user action, matching the mentoring feedback.
        """
        timeline = [self._timeline_row(row) for row in self.timeline_rows()]
        detected = Counter(str(row.get("User_behavior") or "") for row in timeline)
        states = self._artifact_analysis_states()
        rows = []
        for behavior, artifacts in ACTION_COVERAGE_ARTIFACTS.items():
            if detected.get(behavior):
                status = "DETECTED"
                reason = f"timeline event {detected[behavior]}건"
            else:
                weak = self._weak_action_support(behavior)
                relevant_states = [state for artifact in artifacts for state in states.get(artifact, [])]
                usable = any(state in {"success", "partial", "no_relevant_trace"} for state in relevant_states)
                failures = sorted({state for state in relevant_states if state in {"parse_error", "locked_database", "unsupported", "artifact_not_found"}})
                if weak:
                    status = "INCONCLUSIVE"
                    reason = weak
                elif relevant_states and not usable:
                    status = "ARTIFACT_UNAVAILABLE"
                    reason = "필요 아티팩트 상태=" + ",".join(failures or sorted(set(relevant_states)))
                else:
                    status = "NOT_OBSERVED"
                    reason = "분석 범위에서 행위 특정 근거를 관찰하지 못함; 행위가 없었다는 의미는 아님"
            paths = []
            details = []
            for row in self.results:
                if row.get("artifact") not in artifacts:
                    continue
                detail = row.get("detail") or {}
                if detail.get("record_type") != "analysis_status":
                    continue
                path = self._team_artifact_path(row)
                if path and path not in paths:
                    paths.append(path)
                details.append(f"{row.get('artifact')}={row.get('status')}")
            rows.append({
                "Model": "gemini-web",
                "Scope": "project_action" if behavior in PROJECT_ACTIONS else "helper_behavior",
                "Item": behavior,
                "Status": status,
                "Reason": reason,
                "Artifact_path": " | ".join(paths[:8]),
                "Artifact_details": "; ".join(dict.fromkeys(details)),
            })
        return rows

    def qa_summary(self):
        """Return non-destructive QA metrics derived from already parsed records.

        This is intentionally separate from the two team CSV schemas.  It helps reviewers tell
        whether an empty conversation result came from no protocol payloads, decoder failure,
        scan limits, or simply no recoverable messages.
        """
        scan_summaries = []
        for row in self.results:
            detail = row.get("detail") or {}
            if detail.get("record_type") == "scan_summary":
                scan_summaries.append({
                    "artifact": row.get("artifact") or "-",
                    "status": detail.get("scan_status") or row.get("status") or "-",
                    "files_examined": int(detail.get("files_examined") or 0),
                    "files_read": int(detail.get("files_read") or 0),
                    "bytes_read": int(detail.get("bytes_read") or 0),
                    "string_match_count": int(detail.get("string_match_count") or 0),
                    "structured_protocol_message_count": int(detail.get("structured_protocol_message_count") or 0),
                    "aggressive_prompt_candidate_count": int(detail.get("aggressive_prompt_candidate_count") or 0),
                    "files_with_aggressive_prompt_candidates": int(detail.get("files_with_aggressive_prompt_candidates") or 0),
                    "scan_limit_reached_files": int(detail.get("scan_limit_reached_files") or 0),
                    "result_limit_reached_files": int(detail.get("result_limit_reached_files") or 0),
                    "read_error_count": int(detail.get("read_error_count") or 0),
                    "elapsed_sec": detail.get("elapsed_sec"),
                })
        deep_summaries = []
        for row in self.results:
            detail = row.get("detail") or {}
            if detail.get("record_type") == "deep_recovery_status":
                deep_summaries.append({
                    "artifact": row.get("artifact") or "-",
                    "status": row.get("status") or "-",
                    "native_structure_decoded": bool(detail.get("native_structure_decoded")),
                    "message_findings": int(detail.get("message_findings") or 0),
                    "ccl_available": bool(detail.get("ccl_available")),
                    "decode_errors": int(detail.get("decode_errors") or 0),
                })
        structured_rows = [
            row for row in self.results
            if (row.get("detail") or {}).get("record_type") == "finding"
            and not (row.get("detail") or {}).get("derived_rule_id")
            and self._qualified_message_recovery_basis((row.get("detail") or {}).get("recovery_basis"))
            and (row.get("detail") or {}).get("message_content")
            and str((row.get("detail") or {}).get("role") or "").lower() in {"user", "human", "assistant", "model"}
        ]
        scope_summaries = [
            (row.get("detail") or {}) for row in self.results
            if (row.get("detail") or {}).get("record_type") == "conversation_recovery_summary"
        ]
        metadata_summaries = [
            (row.get("detail") or {}) for row in self.results
            if (row.get("detail") or {}).get("record_type") == "conversation_metadata_summary"
        ]
        return {
            "parser_version": PARSER_VERSION,
            "total_records": len(self.results),
            "timeline_rows": len(self.timeline_rows()),
            "conversation_rows": len(self.recovered_conversation_rows()),
            "structured_message_findings": len(structured_rows),
            "conversation_metadata_summaries": len(metadata_summaries),
            "conversation_recovery": scope_summaries[-1] if scope_summaries else {},
            "deep_recovery": deep_summaries,
            "artifact_scans": scan_summaries,
        }

    def validate_team_contract(self):
        """Validate the final two CSV views before handoff/integration."""
        timeline = [self._timeline_row(row) for row in self.timeline_rows()]
        conversations = self.recovered_conversation_rows()
        errors = []

        def rendered(row):
            return self._spreadsheet_safe(row)

        def validate_timestamp(value, label):
            text = str(value or "").strip()
            if text != "-" and not TEAM_TIMESTAMP_RE.fullmatch(text):
                errors.append(f"{label} invalid timestamp={text!r}")

        if TIMELINE_FIELDS != ("Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict", "Artifact_path", "Artifact_details "):
            errors.append("timeline header contract changed")
        if CONVERSATION_FIELDS != ("Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid", "parent_message_uuid", "message order", "role", "content", "Artifact_path"):
            errors.append("conversation header contract changed")
        for index, row in enumerate(timeline):
            if tuple(row.keys()) != TIMELINE_FIELDS:
                errors.append(f"timeline row {index} field order mismatch")
            safe_row = rendered(row)
            if any(str(safe_row.get(field) or "").strip() == "" for field in TIMELINE_FIELDS):
                errors.append(f"timeline row {index} contains empty rendered cell")
            if safe_row.get("Model") != "gemini-web":
                errors.append(f"timeline row {index} invalid model={safe_row.get('Model')!r}")
            validate_timestamp(safe_row.get("Timestamp"), f"timeline row {index}")
            if row.get("Verdict") not in TEAM_VERDICTS:
                errors.append(f"timeline row {index} invalid verdict={row.get('Verdict')!r}")
            if row.get("User_behavior") not in TEAM_BEHAVIORS:
                errors.append(f"timeline row {index} non-contract behavior={row.get('User_behavior')!r}")
            if row.get("User_behavior") in {"Gemini 관련 흔적", "Gemini 설정 흔적", "Gemini 계정/세션 흔적", "분석 관련 흔적"}:
                errors.append(f"timeline row {index} raw evidence leaked as behavior")
        timeline_keys = [tuple(str(row.get(k, "")) for k in TIMELINE_FIELDS) for row in timeline]
        if len(timeline_keys) != len(set(timeline_keys)):
            errors.append("duplicate final timeline rows")
        for index, row in enumerate(conversations):
            if tuple(row.keys()) != CONVERSATION_FIELDS:
                errors.append(f"conversation row {index} field order mismatch")
            safe_row = rendered(row)
            if any(str(safe_row.get(field) or "").strip() == "" for field in CONVERSATION_FIELDS):
                errors.append(f"conversation row {index} contains empty rendered cell")
            if safe_row.get("Model") != "gemini-web":
                errors.append(f"conversation row {index} invalid model={safe_row.get('Model')!r}")
            validate_timestamp(safe_row.get("timestamp"), f"conversation row {index}")
            if not str(row.get("conversation_uuid") or "").strip():
                errors.append(f"conversation row {index} missing conversation_uuid")
            if not str(row.get("content") or "").strip():
                errors.append(f"conversation row {index} missing recovered content")
            role = str(row.get("role") or "").strip().lower()
            if role not in {"user", "assistant"}:
                errors.append(f"conversation row {index} invalid role={role!r}")
            order = str(row.get("message order") or "").strip()
            if not order.isdigit() or int(order) < 1:
                errors.append(f"conversation row {index} invalid message order={order!r}")
            if "본문 미복구" in str(row.get("content") or ""):
                errors.append(f"conversation row {index} non-recovered placeholder leaked")
        conversation_keys = [tuple(str(row.get(k, "")) for k in CONVERSATION_FIELDS) for row in conversations]
        if len(conversation_keys) != len(set(conversation_keys)):
            errors.append("duplicate final conversation rows")

        # Coverage must preserve every agreed project action even when the evidence is
        # absent/deleted.  This is the integration contract that prevents an unsupported
        # action from silently disappearing from the parser's declared scope.
        coverage = self.coverage_rows()
        project_coverage = [row for row in coverage if row.get("Scope") == "project_action"]
        coverage_items = [str(row.get("Item") or "") for row in project_coverage]
        missing_actions = [action for action in PROJECT_ACTIONS if action not in coverage_items]
        duplicate_actions = sorted({action for action in coverage_items if coverage_items.count(action) > 1})
        unknown_actions = sorted({action for action in coverage_items if action not in PROJECT_ACTIONS})
        if missing_actions:
            errors.append("coverage missing project actions=" + ",".join(missing_actions))
        if duplicate_actions:
            errors.append("coverage duplicate project actions=" + ",".join(duplicate_actions))
        if unknown_actions:
            errors.append("coverage unknown project actions=" + ",".join(unknown_actions))
        if len(project_coverage) != len(PROJECT_ACTIONS):
            errors.append(f"coverage project-action count={len(project_coverage)} expected={len(PROJECT_ACTIONS)}")
        if errors:
            raise ValueError("team output contract validation failed: " + "; ".join(errors[:20]))
        return {
            "parser_version": PARSER_VERSION,
            "output_contract_version": OUTPUT_CONTRACT_VERSION,
            "timeline_rows": len(timeline),
            "conversation_rows": len(conversations),
            "coverage_rows": len(self.coverage_rows()),
        }

    def export_coverage_csv(self, path):
        path = self._validate_export(path)
        with path.open("x", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=COVERAGE_FIELDS)
            writer.writeheader()
            for row in self.coverage_rows():
                writer.writerow(self._spreadsheet_safe(row))
        return str(path)

    def export_timeline_csv(self, path):
        self.validate_team_contract()
        path = self._validate_export(path)
        with path.open("x", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=TIMELINE_FIELDS)
            writer.writeheader()
            for row in self.timeline_rows():
                writer.writerow(self._spreadsheet_safe(self._timeline_row(row)))
        return str(path)

    def export_recovered_conversations_csv(self, path):
        self.validate_team_contract()
        path = self._validate_export(path)
        with path.open("x", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CONVERSATION_FIELDS)
            writer.writeheader()
            for row in self.recovered_conversation_rows():
                writer.writerow(self._spreadsheet_safe(row))
        return str(path)

    def export_csv(self, path):
        """Backward-compatible alias: exports timeline-style CSV to the requested path."""
        return self.export_timeline_csv(path)


class ImageDependencyError(RuntimeError):
    """The optional native image-reading bindings are unavailable."""


class ImageReadError(OSError):
    """An image object is unreadable, incomplete, or outside its bounds."""


class BitLockerError(ImageReadError):
    """Only fixed, key-free messages cross the BitLocker input boundary."""

    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class PartitionView(io.RawIOBase):
    """Bounded read-only file object; closing it never closes the evidence."""

    def __init__(self, image, offset, length):
        super().__init__()
        if offset < 0 or length <= 0 or offset + length > image.get_size():
            raise ImageReadError("Invalid partition view bounds")
        self.image, self.offset, self.length = image, offset, length
        self.position = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def get_size(self):
        self._checkClosed()
        return self.length

    def tell(self):
        self._checkClosed()
        return self.position

    def seek(self, offset, whence=0):
        self._checkClosed()
        if whence not in (0, 1, 2):
            raise ValueError("Invalid partition seek origin")
        position = offset + (self.position if whence == 1 else self.length if whence == 2 else 0)
        if position < 0:
            raise ValueError("Negative partition seek")
        self.position = position
        return position

    def read(self, size=-1):
        self._checkClosed()
        available = max(0, self.length - self.position)
        size = available if size is None or size < 0 else min(size, available)
        if not size:
            return b""
        try:
            data = self.image.read(self.offset + self.position, size)
        except Exception:
            raise ImageReadError("Unable to read BitLocker partition bytes") from None
        if len(data) != size:
            raise ImageReadError("Short read within BitLocker partition")
        self.position += len(data)
        return data

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)




class DissectBitLockerVolume:
    """Own the read-only clear-key stream and NTFS backend until reader.close()."""

    @staticmethod
    def has_signature(boot):
        # Windows Vista/7/used-space-only/BitLocker To Go signatures.
        identifier = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")
        used_space = bytes.fromhex("3b4da89280dd0e4d9e4eb1e3284eaed8")
        return (boot[3:11] == b"-FVE-FS-" or boot[160:176] in (identifier, used_space)
                or boot[424:440] == identifier)

    def __init__(self, reader, metadata):
        self.view = self.bde = self.stream = self.ntfs = self.filesystem = None
        self.size = 0
        metadata.update(bitlocker_backend="dissect.fve -> dissect.ntfs",
                        bitlocker_has_clear_key=None)
        try:
            try:
                from dissect.fve.bde import BDE
                from dissect.ntfs import NTFS
            except Exception:
                metadata["bitlocker_reason"] = "dependency_unavailable"
                raise BitLockerError("BITLOCKER_UNSUPPORTED",
                                     "BitLocker requires compatible dissect.fve and dissect.ntfs dependencies") from None

            metadata["bitlocker_reason"] = "metadata_parse_failed"
            self.view = PartitionView(reader.image, metadata["partition_offset"], metadata["partition_length"])
            self.bde = BDE(self.view)
            metadata["bitlocker_has_clear_key"] = bool(self.bde.has_clear_key())
            if not metadata["bitlocker_has_clear_key"]:
                metadata["bitlocker_reason"] = "clear_key_missing"
                raise BitLockerError("BITLOCKER_LOCKED", "BitLocker volume has no image-internal clear key")

            metadata["bitlocker_reason"] = "clear_key_unlock_failed"
            self.bde.unlock_with_clear_key()
            metadata["bitlocker_reason"] = "decrypted_stream_open_failed"
            self.stream = self.bde.open()
            self.stream.seek(0, io.SEEK_END)
            self.size = int(self.stream.tell())
            if self.size <= 0 or self.size > metadata["partition_length"]:
                raise ImageReadError("Invalid decrypted BitLocker volume size")
            self.stream.seek(0)
            metadata["bitlocker_reason"] = "ntfs_open_failed"
            self.ntfs = NTFS(self.stream)
            self.filesystem = DissectForensicFilesystem(reader, self.ntfs, metadata, self)
            metadata.update(bitlocker_reason="clear_key_unlocked", bitlocker_unlock_method="clear_key")
        except BitLockerError:
            self.close()
            raise
        except Exception:
            self.close()
            raise BitLockerError("BITLOCKER_OPEN_ERROR",
                                 "BitLocker clear-key volume could not be opened; see bitlocker_reason") from None
        except BaseException:
            self.close()
            raise

    def close(self):
        stream, self.stream = self.stream, None
        self.filesystem = self.ntfs = self.bde = None
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
        if self.view is not None:
            self.view.close()
            self.view = None


class ForensicImageReader:
    """Read-only RAW/split-RAW -> pytsk3 / EWF -> pyewf -> pytsk3 adapter.

    Split RAW images are accepted as ``name.001, name.002, ...``.  Only the
    first ``.001`` segment is supplied by the caller; following segments are
    discovered in the same directory and exposed to pytsk3 as one continuous
    read-only image.  No temporary merged DD is created.

    No OS mount, filesystem repair, raw MFT decoder, or write API is used.
    Imports are lazy so --help and the original --profile mode stay usable.
    """

    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()
        self.image_type = None
        self.segments = []
        self.tsk = self.image = self.ewf = None
        self.raw_handles = []
        self.size = 0
        self.initial_stats = {}
        self._bitlocker_volumes = []

    @staticmethod
    def _split_raw_match(path):
        return SPLIT_RAW_RE.fullmatch(Path(path).name)

    def _discover_split_raw_segments(self):
        """Return a validated contiguous ``.001/.002/...`` RAW segment set."""
        match = self._split_raw_match(self.path)
        if not match:
            raise ImageReadError("Split RAW input does not use a numeric .001 segment name")
        if int(match.group("num")) != 1:
            raise ImageReadError("Split RAW input must start with the first .001 segment")

        parent = self.path.parent
        stem = match.group("stem")
        found = {}
        try:
            entries = list(parent.iterdir())
        except OSError as exc:
            raise ImageReadError("Unable to enumerate split RAW segment directory: " + error_text(exc)) from exc

        for entry in entries:
            candidate = SPLIT_RAW_RE.fullmatch(entry.name)
            if not candidate or candidate.group("stem").casefold() != stem.casefold():
                continue
            number = int(candidate.group("num"))
            if number < 1:
                continue
            if number in found:
                raise ImageReadError(f"Duplicate split RAW segment number .{number:03d}")
            found[number] = entry.absolute()

        if 1 not in found:
            raise ImageReadError("Split RAW first segment .001 was not found")
        highest = max(found)
        missing = [number for number in range(1, highest + 1) if number not in found]
        if missing:
            rendered = ", ".join(f".{number:03d}" for number in missing[:20])
            if len(missing) > 20:
                rendered += f", ... (+{len(missing) - 20} more)"
            raise ImageReadError("Split RAW segment sequence has a gap; missing: " + rendered)

        segments = [found[number] for number in range(1, highest + 1)]
        for segment in segments:
            try:
                info = segment.stat()
            except OSError as exc:
                raise ImageReadError("Unable to stat split RAW segment: " + str(segment) + ": " + error_text(exc)) from exc
            if not within(segment, parent) or is_link(segment) or not stat.S_ISREG(info.st_mode):
                raise ImageReadError("Invalid or linked split RAW segment: " + str(segment))
            if info.st_size <= 0:
                raise ImageReadError("Split RAW segment is empty: " + str(segment))
        return segments

    def identify(self):
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Image input must be a regular file")
        if not info.st_size:
            raise ValueError("Image file is empty")

        # Inspect the physical header before relying on the filename.  This keeps
        # genuine EWF data from being silently treated as RAW solely by extension.
        with self.path.open("rb") as stream:
            signature = stream.read(16)
        suffix = self.path.suffix.lower()
        split_match = self._split_raw_match(self.path)
        is_ewf = signature.startswith((b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00"))

        if is_ewf:
            if suffix != ".e01":
                raise ValueError("EWF signature detected; supply the first .E01 segment")
            self.image_type = "EWF"
        elif suffix == ".e01":
            raise ValueError(".E01 input has no supported physical EWF signature")
        elif split_match:
            if int(split_match.group("num")) != 1:
                raise ValueError("Split RAW input must start with the first .001 segment")
            self.image_type = "SPLIT_RAW"
        elif suffix in {".dd", ".img", ".raw"}:
            self.image_type = "RAW"
        else:
            raise ValueError("Unsupported image extension; use .dd, .img, .raw, first .001 split-RAW segment, or first .E01 segment")
        return self.image_type

    def __enter__(self):
        self.identify()
        try:
            self.tsk = importlib.import_module("pytsk3")
        except (ImportError, OSError) as exc:
            raise ImageDependencyError("pytsk3 is required for image input: " + error_text(exc)) from exc
        try:
            if self.image_type == "EWF":
                try:
                    pyewf = importlib.import_module("pyewf")
                except (ImportError, OSError) as exc:
                    raise ImageDependencyError("E01 input requires pyewf (libewf-python) for this Python version: " + error_text(exc)) from exc
                self.segments = [Path(p).absolute() for p in pyewf.glob(str(self.path))]
                if not self.segments:
                    raise ImageReadError("pyewf.glob found no EWF segments")
                for segment in self.segments:
                    if not within(segment, self.path.parent) or not stat.S_ISREG(segment.stat().st_mode):
                        raise ImageReadError("Invalid or out-of-directory EWF segment: " + str(segment))
                self.ewf = pyewf.handle()
                self.ewf.open([str(p) for p in self.segments], "r")
                handle, tsk = self.ewf, self.tsk

                class EwfImage(tsk.Img_Info):
                    def __init__(self):
                        super().__init__(url="", type=tsk.TSK_IMG_TYPE_EXTERNAL)

                    def read(self, offset, size):
                        handle.seek(offset)
                        return handle.read(size)

                    def get_size(self):
                        return handle.get_media_size()

                    def close(self):
                        # The outer owner closes the handle exactly once, after FS objects.
                        return None

                self.image = EwfImage()
            elif self.image_type == "SPLIT_RAW":
                self.segments = self._discover_split_raw_segments()
                sizes = [int(segment.stat().st_size) for segment in self.segments]
                starts = []
                total = 0
                for size in sizes:
                    starts.append(total)
                    total += size

                self.raw_handles = []
                try:
                    for segment in self.segments:
                        self.raw_handles.append(segment.open("rb"))
                except Exception:
                    for handle in self.raw_handles:
                        try:
                            handle.close()
                        except Exception:
                            pass
                    self.raw_handles = []
                    raise

                handles, tsk = self.raw_handles, self.tsk

                class SplitRawImage(tsk.Img_Info):
                    def __init__(self):
                        super().__init__(url="", type=tsk.TSK_IMG_TYPE_EXTERNAL)

                    def read(self, offset, size):
                        offset, size = int(offset), int(size)
                        if offset < 0 or size < 0:
                            raise ImageReadError("Negative split RAW read offset/size")
                        if size == 0 or offset >= total:
                            return b""
                        end = min(total, offset + size)
                        index = bisect.bisect_right(starts, offset) - 1
                        if index < 0:
                            index = 0
                        position = offset
                        output = bytearray()
                        while position < end and index < len(handles):
                            local_offset = position - starts[index]
                            available = sizes[index] - local_offset
                            if available <= 0:
                                index += 1
                                continue
                            wanted = min(end - position, available)
                            handles[index].seek(local_offset)
                            block = handles[index].read(wanted)
                            if len(block) != wanted:
                                raise ImageReadError(
                                    f"Short read in split RAW segment {self_path(index)}: "
                                    f"wanted {wanted}, got {len(block)}"
                                )
                            output.extend(block)
                            position += len(block)
                            index += 1
                        return bytes(output)

                    def get_size(self):
                        return total

                    def close(self):
                        # The outer ForensicImageReader owns the segment handles.
                        return None

                segment_paths = self.segments
                def self_path(index):
                    return str(segment_paths[index]) if 0 <= index < len(segment_paths) else "?"

                self.image = SplitRawImage()
            else:
                self.segments = [self.path]
                self.image = self.tsk.Img_Info(str(self.path), type=self.tsk.TSK_IMG_TYPE_RAW)
            self.size = int(self.image.get_size())
            self.initial_stats = self.segment_stats()
            return self
        except Exception:
            self.close()
            raise

    def segment_stats(self):
        return {str(p): (p.stat().st_size, p.stat().st_mtime_ns) for p in self.segments}

    def close(self):
        volumes, self._bitlocker_volumes = self._bitlocker_volumes, []
        for volume in reversed(volumes):
            volume.close()
        try:
            if self.image is not None:
                self.image.close()
        finally:
            self.image = None
            if self.ewf is not None:
                handle, self.ewf = self.ewf, None
                handle.close()
            handles, self.raw_handles = self.raw_handles, []
            for handle in handles:
                try:
                    handle.close()
                except OSError:
                    pass

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def filesystems(self):
        """Yield (metadata, filesystem or None, error); offsets are BYTES."""
        candidates = []
        volume_error = None
        try:
            volume = self.tsk.Volume_Info(self.image)
            block_size = int(volume.info.block_size)
            for partition in volume:
                if not partition.flags & self.tsk.TSK_VS_PART_FLAG_ALLOC:
                    continue
                if partition.flags & self.tsk.TSK_VS_PART_FLAG_META:
                    continue
                offset, length = int(partition.start) * block_size, int(partition.len) * block_size
                description = partition.desc.decode("utf-8", "replace") if isinstance(partition.desc, bytes) else str(partition.desc)
                candidates.append({"partition_offset": offset, "partition_length": length,
                                   "partition_index": int(partition.addr), "partition_description": description,
                                   "sector_size": block_size, "partition_table_present": True})
        except (OSError, RuntimeError) as exc:
            volume_error = error_text(exc)
        if not candidates:
            # A partition image/superfloppy may have an NTFS boot sector at byte zero.
            candidates = [{"partition_offset": 0, "partition_length": self.size,
                           "partition_index": None, "partition_table_present": False,
                           "partition_table_error": volume_error}]
        seen = set()
        for metadata in candidates:
            offset, length = metadata["partition_offset"], metadata["partition_length"]
            if offset in seen:
                continue
            seen.add(offset)
            if offset < 0 or length <= 0 or offset + length > self.size:
                yield metadata, None, "Partition extends beyond available image bytes"
                continue
            try:
                boot = self.image.read(offset, min(512, length))
                metadata["bitlocker_status"] = "NOT_ENCRYPTED"
                fs_image, fs_offset = self.image, offset
                if DissectBitLockerVolume.has_signature(boot):
                    metadata["filesystem_type"] = "BitLocker_locked"
                    # legacy compatibility field; external BitLocker credentials are no longer supported
                    metadata["bitlocker_key_supplied"] = False
                    decrypted = DissectBitLockerVolume(self, metadata)
                    self._bitlocker_volumes.append(decrypted)
                    metadata.update(bitlocker_status="BITLOCKER_UNLOCKED", bitlocker_read_only=True,
                                    decrypted_volume_size=decrypted.size)
                    metadata.update(filesystem_type="NTFS")
                    yield metadata, decrypted.filesystem, None
                    continue
                fs = self.tsk.FS_Info(fs_image, offset=fs_offset)
                ftype = int(fs.info.ftype)
                is_ntfs = bool(ftype & self.tsk.TSK_FS_TYPE_NTFS_DETECT)
                metadata.update(filesystem_type="NTFS" if is_ntfs else "non_NTFS:" + str(ftype),
                                filesystem_type_code=ftype)
                yield metadata, ForensicFilesystem(self, fs, metadata) if is_ntfs else None, None
            except BitLockerError as exc:
                metadata["bitlocker_status"] = exc.status
                yield metadata, None, str(exc)
            except (OSError, RuntimeError) as exc:
                metadata["filesystem_type"] = "unrecognized"
                yield metadata, None, error_text(exc)


class ForensicFilesystem:
    """Allocated NTFS namespace and stream access delegated entirely to TSK."""

    def __init__(self, reader, fs, metadata):
        self.reader, self.fs, self.metadata = reader, fs, metadata
        self.offset = metadata["partition_offset"]
        self._directories = {}

    @staticmethod
    def _name(value):
        return value.decode("utf-8", "strict") if isinstance(value, bytes) else str(value)

    def listdir(self, path):
        path = str(PurePosixPath(path))
        if path in self._directories:
            return self._directories[path]
        nodes = []
        for entry in self.fs.open_dir(path=path):
            named, meta = entry.info.name, entry.info.meta
            if named is None or meta is None:
                continue
            if not named.flags & self.reader.tsk.TSK_FS_NAME_FLAG_ALLOC:
                continue
            if not meta.flags & self.reader.tsk.TSK_FS_META_FLAG_ALLOC:
                continue
            name = self._name(named.name)
            if name in (".", ".."):
                continue
            if not name or any(c in name for c in ("/", "\\", "\x00")):
                raise ImageReadError("Invalid image directory entry name")
            node_path = str(PurePosixPath(path) / name)
            nodes.append({"path": node_path, "name": name, "inode": int(meta.addr),
                          "sequence": int(getattr(meta, "seq", 0)), "size": int(meta.size),
                          "is_dir": meta.type == self.reader.tsk.TSK_FS_META_TYPE_DIR,
                          "is_file": meta.type == self.reader.tsk.TSK_FS_META_TYPE_REG,
                          "created_ns": int(getattr(meta, "crtime", 0)) * 1000000000 + int(getattr(meta, "crtime_nano", 0)),
                          "modified_ns": int(getattr(meta, "mtime", 0)) * 1000000000 + int(getattr(meta, "mtime_nano", 0)),
                          "metadata_changed_ns": int(getattr(meta, "ctime", 0)) * 1000000000 + int(getattr(meta, "ctime_nano", 0))})
        self._directories[path] = sorted(nodes, key=lambda n: n["name"].casefold())
        return self._directories[path]

    def lookup(self, path):
        parts = PurePosixPath(path).parts
        if not parts or parts[0] != "/" or ".." in parts:
            raise ValueError("Image filesystem path must be absolute without traversal")
        current = "/"
        node = {"path": "/", "name": "/", "is_dir": True, "is_file": False}
        for part in parts[1:]:
            if not node["is_dir"]:
                return None
            matches = [n for n in self.listdir(current) if n["name"].casefold() == part.casefold()]
            if not matches:
                return None
            if len(matches) > 1:
                raise ImageReadError("Ambiguous case-insensitive filesystem path: " + str(path))
            node = matches[0]
            if self.is_reparse(node):
                raise ImageReadError("Reparse point is not followed: " + node["path"])
            current = node["path"]
        return node

    def is_reparse(self, node):
        if "inode" not in node:
            return False
        f = self.fs.open_meta(inode=node["inode"])
        return any(int(a.info.type) == getattr(self.reader.tsk, "TSK_FS_ATTR_TYPE_NTFS_REPARSE", 0xC0) for a in f)

    def streams(self, node):
        file = self.fs.open_meta(inode=node["inode"])
        return [{"name": self._name(a.info.name) if a.info.name else "",
                 "type": int(a.info.type), "id": int(a.info.id), "size": int(a.info.size)}
                for a in file if int(a.info.type) == self.reader.tsk.TSK_FS_ATTR_TYPE_NTFS_DATA]

    def chunks(self, node, stream=None):
        file = self.fs.open_meta(inode=node["inode"])
        size = stream["size"] if stream else node["size"]
        offset = 0
        while offset < size:
            amount = min(CHUNK, size - offset)
            data = file.read_random(offset, amount, type=stream["type"], id=stream["id"]) if stream else file.read_random(offset, amount)
            if not data or len(data) > amount:
                raise ImageReadError("Short/invalid read at file offset " + str(offset) + ": " + node["path"])
            yield data
            offset += len(data)

    def metadata_for(self, node):
        return {"filename": node["name"], "file_size": node["size"],
                "created_time": normalize_timestamp(node.get("created_ns"), "unix_ns"),
                "modified_time": normalize_timestamp(node.get("modified_ns"), "unix_ns"),
                "metadata_changed_time": normalize_timestamp(node.get("metadata_changed_ns"), "unix_ns"),
                "timestamp_format": "unix_nanoseconds", "timestamp_role": "NTFS_metadata_not_user_action",
                "filesystem_type": "NTFS", "inode": node["inode"], "sequence": node["sequence"]}


class DissectForensicFilesystem(ForensicFilesystem):
    """Expose allocated Dissect NTFS records through the existing collector interface."""

    def __init__(self, reader, fs, metadata, owner):
        super().__init__(reader, fs, metadata)
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, FILE_NUMBER_ROOT, FILE_RECORD_SEGMENT_IN_USE
        self._data_type = ATTRIBUTE_TYPE_CODE.DATA
        self._standard_type = ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION
        self._in_use = FILE_RECORD_SEGMENT_IN_USE
        self._root_segment = FILE_NUMBER_ROOT
        self._owner = owner

    def _directory_record(self, path):
        # Integer MFT lookup cannot follow a symlink/junction. Non-root paths are
        # resolved by the inherited component-wise, case-insensitive lookup.
        if path == "/":
            record = self.fs.mft.get(self._root_segment)
        else:
            node = self.lookup(path)
            if node is None or not node["is_dir"]:
                raise ImageReadError("Image directory not found")
            record = node["_record"]
        if record.is_reparse_point():
            raise ImageReadError("Reparse point is not followed")
        return record

    def listdir(self, path):
        path = str(PurePosixPath(path))
        parts = PurePosixPath(path).parts
        if not parts or parts[0] != "/" or ".." in parts:
            raise ValueError("Image filesystem path must be absolute without traversal")
        if path in self._directories:
            return self._directories[path]
        try:
            record = self._directory_record(path)
            nodes = []
            # Keep directory-index names: dereference=True expands record-wide
            # hard-link names, which can belong to a different parent directory.
            for name, entry in record.listdir(dereference=False, ignore_dos=True).items():
                if name in (".", ".."):
                    continue
                name = self._name(name)
                if not name or any(c in name for c in ("/", "\\", "\x00")):
                    raise ImageReadError("Invalid image directory entry name")
                child = entry.dereference()
                if not child.header.Flags & self._in_use:
                    continue
                if entry.header.FileReference.SequenceNumber != child.header.SequenceNumber:
                    continue
                standard = child.attributes[self._standard_type]
                if len(standard) != 1:
                    raise ImageReadError("Missing or ambiguous NTFS standard information")
                is_dir = child.is_dir()
                nodes.append({"path": str(PurePosixPath(path) / name), "name": name,
                              "inode": int(child.segment), "sequence": int(child.header.SequenceNumber),
                              "size": 0 if is_dir or not child.has_stream() else child.size(),
                              "is_dir": is_dir, "is_file": child.is_file(),
                              "created_ns": standard.creation_time_ns,
                              "modified_ns": standard.last_modification_time_ns,
                              "metadata_changed_ns": standard.last_change_time_ns,
                              "_record": child})
            self._directories[path] = sorted(nodes, key=lambda n: n["name"].casefold())
            return self._directories[path]
        except (ImageReadError, ValueError):
            raise
        except Exception:
            raise ImageReadError("Unable to enumerate Dissect NTFS directory") from None

    def is_reparse(self, node):
        if "inode" not in node:
            return False
        try:
            return node["_record"].is_reparse_point()
        except Exception:
            raise ImageReadError("Unable to inspect NTFS reparse attribute") from None

    def streams(self, node):
        try:
            record = node["_record"]
            streams, seen = [], set()
            for attr in record.attributes[self._data_type]:
                name = attr.name
                if name in seen:
                    continue  # One logical stream can span multiple DATA attributes.
                seen.add(name)
                streams.append({"name": name, "type": int(self._data_type.value),
                                "id": int(attr.header.header.Instance), "size": record.size(name=name)})
            return streams
        except Exception:
            raise ImageReadError("Unable to enumerate NTFS DATA streams") from None

    def chunks(self, node, stream=None):
        size = stream["size"] if stream else node["size"]
        try:
            record = node["_record"]
            with record.open(name=stream["name"]) if stream else record.open() as source:
                offset = 0
                while offset < size:
                    amount = min(CHUNK, size - offset)
                    data = source.read(amount)
                    if len(data) != amount:
                        raise ImageReadError("Short/invalid NTFS stream read at file offset " + str(offset))
                    yield data
                    offset += len(data)
        except ImageReadError:
            raise
        except Exception:
            raise ImageReadError("Unable to read NTFS DATA stream") from None


class ImageArtifactCollector:
    """Extract only parser artifacts and lazily requested downloads to owned scratch."""

    FILES = {"History": "history", "History-wal": "history", "History-shm": "history", "History-journal": "history",
             "Network/Cookies": "cookies", "Network/Cookies-wal": "cookies", "Network/Cookies-shm": "cookies",
             "Network/Cookies-journal": "cookies", "Preferences": "preferences", "Secure Preferences": "secure_preferences"}
    TREES = {"Sessions": "sessions", "Cache/Cache_Data": "cache", "Local Storage/leveldb": "local_storage",
             "Session Storage": "session_storage", "IndexedDB": "indexeddb", "Service Worker": "service_worker"}

    def __init__(self, owner, fs, filesystems, context, profile_node, scratch):
        self.owner, self.fs, self.filesystems, self.context = owner, fs, filesystems, context
        self.profile_node, self.scratch = profile_node, scratch
        self.profile = scratch / "profile"
        self.volume = scratch / "volume"
        self.profile.mkdir()
        self.volume.mkdir()
        self.manifest, self.aliases, self.errors, self.zone_cache = {}, {}, {}, {}
        self.extracted_bytes = 0
        self.aliases[str(self.profile)] = (fs, profile_node["path"])
        self.aliases[str(self.volume)] = (fs, "/")

    @staticmethod
    def component(name):
        # Only scratch names are escaped; original names remain in provenance.
        reserved = re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", name, re.I)
        if name in (".", "..") or reserved or re.search(r'[<>:"/\\|?*\x00-\x1f]', name) or name.endswith((".", " ")):
            return "__image_name_" + hashlib.sha256(name.encode("utf-8")).hexdigest()
        return name

    def issue(self, key, image_path, exc, status="parse_error"):
        message = error_text(exc) if isinstance(exc, Exception) else str(exc)
        self.errors.setdefault(key, []).append(message)
        self.owner._image_record("Artifact extraction incomplete", self.context, status=status, error=message,
                                 detail={"record_type": "extraction_issue", "artifact_key": key,
                                         "filesystem_path": image_path})

    def extract(self, fs, node, destination, key):
        destination = Path(destination)
        if not within(destination, self.scratch):
            raise ValueError("Extraction destination escapes owned scratch directory")
        if str(destination) in self.manifest:
            return destination
        if not node["is_file"] or fs.is_reparse(node):
            raise ImageReadError("Only ordinary allocated files can be extracted: " + node["path"])
        limit = self.owner.max_extracted_bytes
        if limit and self.extracted_bytes + node["size"] > limit:
            raise ImageReadError("Configured extraction byte limit exceeded; file was not partially passed to a parser")
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest, written = hashlib.sha256(), 0
        created = False
        try:
            with destination.open("xb") as output:
                created = True
                for data in fs.chunks(node):
                    output.write(data)
                    digest.update(data)
                    written += len(data)
            if written != node["size"]:
                raise ImageReadError("Extracted size does not match filesystem metadata")
        except Exception:
            if created:
                destination.unlink()  # Only this new, private partial copy is discarded.
            raise
        self.extracted_bytes += written
        self.manifest[str(destination)] = {"fs": fs, "node": node, "sha256": digest.hexdigest(), "artifact_key": key}
        self.aliases[str(destination)] = (fs, node["path"])
        return destination

    def tree(self, fs, node, local, key, predicate=None):
        pending, seen, count = [(node, local)], set(), 0
        while pending:
            parent, folder = pending.pop()
            if parent.get("inode") in seen:
                self.issue(key, parent["path"], "Repeated directory inode skipped", "partial")
                continue
            seen.add(parent.get("inode"))
            try:
                if fs.is_reparse(parent):
                    raise ImageReadError("Reparse directory skipped")
                folder.mkdir(parents=True, exist_ok=True)
                self.aliases[str(folder)] = (fs, parent["path"])
                for child in fs.listdir(parent["path"]):
                    dest = folder / self.component(child["name"])
                    if child["is_dir"]:
                        pending.append((child, dest))
                    elif child["is_file"] and (predicate is None or predicate(child["name"])):
                        if self.owner.max_files and count >= self.owner.max_files:
                            self.issue(key, parent["path"], "Configured extraction file count limit reached", "partial")
                            return
                        count += 1
                        try:
                            self.extract(fs, child, dest, key)
                        except (OSError, RuntimeError, ValueError) as exc:
                            self.issue(key, child["path"], exc)
            except (OSError, RuntimeError, ValueError) as exc:
                self.issue(key, parent["path"], exc)

    def collect(self):
        for relative, key in self.FILES.items():
            source = str(PurePosixPath(self.profile_node["path"]) / relative)
            try:
                node = self.fs.lookup(source)
                if node:
                    self.extract(self.fs, node, self.profile.joinpath(*PurePosixPath(relative).parts), key)
            except (OSError, RuntimeError, ValueError) as exc:
                self.issue(key, source, exc)
        for relative, key in self.TREES.items():
            source = str(PurePosixPath(self.profile_node["path"]) / relative)
            try:
                node = self.fs.lookup(source)
                if node:
                    if not node["is_dir"]:
                        raise ImageReadError("Artifact tree is not a directory")
                    predicate = (lambda name: name.startswith(("Session_", "Tabs_"))) if key == "sessions" else None
                    self.tree(self.fs, node, self.profile.joinpath(*PurePosixPath(relative).parts), key, predicate)
            except (OSError, RuntimeError, ValueError) as exc:
                self.issue(key, source, exc)
        if self.fs.offset not in self.owner._recycle_scanned_partitions:
            self.owner._recycle_scanned_partitions.add(self.fs.offset)
            try:
                recycle = self.fs.lookup("/$Recycle.Bin")
                if recycle:
                    self.tree(self.fs, recycle, self.volume / "$Recycle.Bin", "recycle_bin", lambda n: n.startswith("$I"))
            except (OSError, RuntimeError, ValueError) as exc:
                self.issue("recycle_bin", "/$Recycle.Bin", exc)

    def origin(self, local):
        text = str(local)
        for prefix in sorted(self.aliases, key=len, reverse=True):
            if text == prefix or text.startswith(prefix + os.sep) or text.startswith(prefix + ":"):
                fs, source = self.aliases[prefix]
                tail = text[len(prefix):].replace("\\", "/")
                return fs, source.rstrip("/") + tail or "/"
        return None, None

    def display_path(self, local):
        fs, source = self.origin(local)
        return f"{self.owner.image_path}::NTFS@{fs.offset}{source}" if fs else str(local)

    def rewrite(self, value):
        if isinstance(value, dict):
            return {k: self.rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.rewrite(v) for v in value]
        if isinstance(value, str):
            if value.startswith(str(self.scratch)):
                return self.display_path(value)
            # Error strings can include temporary filenames as a substring.
            for prefix in sorted(self.aliases, key=len, reverse=True):
                if prefix in value:
                    value = value.replace(prefix, self.display_path(prefix))
            return value
        return value

    def resolve_download(self, target_path, current_path):
        attempted, errors = [], []
        for field, raw in (("target_path", target_path), ("current_path", current_path)):
            if not raw:
                continue
            win = PureWindowsPath(str(raw))
            if (not win.is_absolute() or str(raw).startswith(("\\\\", "//")) or ".." in win.parts
                    or "\x00" in str(raw) or any(":" in p for p in win.parts[1:])):
                errors.append("Unsafe or non-local original download path: " + str(raw))
                continue
            source = "/" + "/".join(win.parts[1:])
            matches = []
            for fs in self.filesystems:
                attempted.append({"partition_offset": fs.offset, "filesystem_path": source})
                try:
                    node = fs.lookup(source)
                    if node and node["is_file"]:
                        matches.append((fs, node))
                except (OSError, RuntimeError, ValueError) as exc:
                    errors.append(error_text(exc))
            if len(matches) > 1:
                return {"file_exists": None, "resolved_path": None, "path_field": field,
                        "resolution_error": "Ambiguous download path across NTFS partitions; no file chosen",
                        "resolution_candidates": attempted}
            if matches:
                fs, node = matches[0]
                local = self.scratch / "downloads" / str(fs.offset)
                local = local.joinpath(*(self.component(p) for p in PurePosixPath(node["path"]).parts[1:]))
                try:
                    self.extract(fs, node, local, "downloaded_file")
                    return {"file_exists": True, "resolved_path": str(local), "path_field": field,
                            "resolution_method": "unique_image_relative_path", "resolution_candidates": attempted,
                            "download_partition_offset": fs.offset, "download_filesystem_path": node["path"],
                            "drive_letter_mapping": "unverified; original drive letters are not inferred from partition order",
                            "resolution_error": "; ".join(errors) or None}
                except (OSError, RuntimeError, ValueError) as exc:
                    errors.append(error_text(exc))
                    self.issue("downloaded_file", node["path"], exc)
        return {"file_exists": None if errors else False, "resolved_path": None, "path_field": None,
                "resolution_candidates": attempted, "resolution_error": "; ".join(errors) or None}

    def zone(self, local):
        if str(local) in self.zone_cache:
            return self.zone_cache[str(local)]
        record = self.manifest[str(local)]
        fs, node = record["fs"], record["node"]
        try:
            streams = [s for s in fs.streams(node) if s["name"].casefold() == "zone.identifier"]
            if not streams:
                result = {"status": "artifact_not_found", "values": {}, "error": None}
            elif len(streams) != 1 or streams[0]["size"] > 65536:
                raise ImageReadError("Ambiguous or oversized Zone.Identifier stream")
            else:
                data = b"".join(fs.chunks(node, streams[0]))
                result = GeminiParser._read_zone(local, data=data)
                result["stream_locator"] = {"inode": node["inode"], "attribute_type": streams[0]["type"],
                                            "attribute_id": streams[0]["id"], "filesystem_path": node["path"]}
        except (OSError, RuntimeError, ValueError) as exc:
            result = {"status": "parse_error", "values": {}, "error": error_text(exc)}
        self.zone_cache[str(local)] = result
        return result


class ImageProfileParser(GeminiParser):
    """Reuse every artifact parser with image-backed file/ADS resolution."""

    def __init__(self, collector, **options):
        super().__init__(collector.profile, evidence_root=collector.volume, image_mode=False, **options)
        self.collector = collector
        self._staged_from_forensic_image = True

    def resolve_download_path(self, target_path, current_path=None):
        return self.collector.resolve_download(target_path, current_path)

    def _read_zone(self, path):
        return self.collector.zone(path)

    def _file_metadata(self, path):
        manifest = self.collector.manifest.get(str(path))
        if manifest:
            return manifest["fs"].metadata_for(manifest["node"])
        return super()._file_metadata(path)


class GeminiImageParser(GeminiParser):
    """Image-level orchestrator; common schema and JSON/CSV/API are inherited."""

    def __init__(self, image_path, *, temp_root=None, keep_temp=False, max_extracted_bytes=0, **options):
        super().__init__(image_path, image_mode=False, **options)
        self.image_path = Path(image_path).expanduser().absolute()
        self.temp_root = Path(temp_root).expanduser().absolute() if temp_root else None
        self.keep_temp = keep_temp
        if max_extracted_bytes < 0:
            raise ValueError("max_extracted_bytes must be nonnegative")
        self.max_extracted_bytes = max_extracted_bytes
        self.image_type = None
        self.retained_temp_dirs = []
        self._owned_temp_dirs = set()
        self._recycle_scanned_partitions = set()
        self.profile_summaries = []

    def _context(self, **values):
        return {"image_path": str(self.image_path), "image_type": self.image_type,
                "partition_offset": values.get("partition_offset"), "filesystem_type": values.get("filesystem_type"),
                "windows_user": values.get("windows_user"), "chrome_profile": values.get("chrome_profile")}

    def _image_record(self, observation, context=None, *, detail=None, status="success", error=None):
        context = context or self._context()
        return self._emit("Forensic Image", observation, path=self.image_path, level="unconfirmed", status=status,
                          error=error, detail={**(detail or {}), **context},
                          locator={"partition_offset": context.get("partition_offset"),
                                   "filesystem_path": (detail or {}).get("filesystem_path")})

    def _cleanup(self, path):
        resolved = str(Path(path).resolve())
        if resolved not in self._owned_temp_dirs or not Path(resolved).name.startswith("gemini_image_"):
            raise ValueError("Refusing cleanup of an unowned temporary path")
        shutil.rmtree(resolved)
        self._owned_temp_dirs.remove(resolved)

    def cleanup_temp(self):
        """Explicitly remove this instance's retained --keep-temp directories."""
        for path in list(self._owned_temp_dirs):
            self._cleanup(path)
        self.retained_temp_dirs = []

    def _filesystem_metadata(self, fs, context):
        for source in ("/$MFT", "/$Extend/$UsnJrnl"):
            try:
                node = fs.lookup(source)
                streams = fs.streams(node) if node else []
                self._image_record("Shared filesystem artifact presence checked; contents not parsed", context,
                                   status="success" if node else "artifact_not_found",
                                   detail={"record_type": "filesystem_artifact_metadata", "filesystem_path": source,
                                           "exists": bool(node), "inode": node.get("inode") if node else None,
                                           "streams": streams, "content_parsed": False})
            except (OSError, RuntimeError, ValueError) as exc:
                self._image_record("Filesystem artifact presence could not be established", context, status="parse_error",
                                   error=error_text(exc), detail={"record_type": "filesystem_artifact_metadata", "filesystem_path": source})

    def _profiles(self, fs):
        users = fs.lookup("/Users")
        if not users or not users["is_dir"]:
            return
        for user in fs.listdir(users["path"]):
            if not user["is_dir"]:
                continue
            context = self._context(partition_offset=fs.offset, filesystem_type="NTFS", windows_user=user["name"])
            try:
                if fs.is_reparse(user):
                    self._image_record("Windows user reparse directory skipped", context, status="skipped",
                                       detail={"record_type": "discovery_status", "reason": "reparse_point",
                                               "filesystem_path": user["path"]})
                    continue
                data = fs.lookup(str(PurePosixPath(user["path"]) / "AppData/Local/Google/Chrome/User Data"))
                if not data or not data["is_dir"]:
                    continue
                for profile in fs.listdir(data["path"]):
                    if not profile["is_dir"]:
                        continue
                    conventional = profile["name"].casefold() == "default" or profile["name"].casefold().startswith("profile ")
                    try:
                        if fs.is_reparse(profile):
                            summary = self._image_record("Chrome profile reparse directory skipped",
                                       {**context, "chrome_profile": profile["name"]}, status="skipped",
                                       detail={"record_type": "profile_status", "profile_outcome": "skipped",
                                               "reason": "reparse_point", "filesystem_path": profile["path"]})
                            self.profile_summaries.append(summary)
                            continue
                        children = {n["name"].casefold() for n in fs.listdir(profile["path"])}
                        looks_like_profile = "preferences" in children or "history" in children
                        if conventional or looks_like_profile:
                            yield user["name"], profile
                    except (OSError, RuntimeError, ValueError) as exc:
                        summary = self._image_record("Chrome profile could not be enumerated", {**context, "chrome_profile": profile["name"]},
                                           status="parse_error", error=error_text(exc),
                                           detail={"record_type": "profile_status", "profile_outcome": "analysis_failed",
                                                   "filesystem_path": profile["path"]})
                        self.profile_summaries.append(summary)
            except (OSError, RuntimeError, ValueError) as exc:
                self._image_record("Windows user Chrome directory search failed", context, status="parse_error", error=error_text(exc),
                                   detail={"record_type": "discovery_issue", "filesystem_path": user["path"]})

    @staticmethod
    def _gemini_finding(record):
        return GeminiParser._is_gemini_specific_finding(record)

    def _run_profile(self, fs, filesystems, user, node):
        context = self._context(partition_offset=fs.offset, filesystem_type="NTFS", windows_user=user, chrome_profile=node["name"])
        self._say(f"[Profile] NTFS@{fs.offset} / {user} / {node['name']}")
        try:
            scratch = Path(tempfile.mkdtemp(prefix="gemini_image_", dir=self.temp_root))
        except OSError as exc:
            summary = self._image_record("Could not create profile extraction workspace", context,
                                        status="parse_error", error=error_text(exc),
                                        detail={"record_type": "profile_status", "profile_outcome": "analysis_failed",
                                                "filesystem_path": node["path"]})
            self.profile_summaries.append(summary)
            return
        self._owned_temp_dirs.add(str(scratch.resolve()))
        try:
            collector = ImageArtifactCollector(self, fs, filesystems, context, node, scratch)
            collector.collect()
            parser = ImageProfileParser(collector, **self._artifact_options())
            parsed = parser.parse()
            hits = sum(self._gemini_finding(r) for r in parsed)
            issues = sum(r["status"] in {"parse_error", "locked_database"} or
                         (r["status"] == "unsupported" and r["artifact"] == "Chrome History") for r in parsed)
            errors = bool(collector.errors) or bool(issues)
            partial = any(r["status"] in {"partial", "unsupported"} for r in parsed)
            for row in parsed:
                local_source = row["source_path"]
                source_fs, source_path = collector.origin(local_source) if local_source else (None, None)
                manifest = collector.manifest.get(local_source)
                if row["artifact"] == "Windows Recycle Bin" and row["detail"].get("payload_path"):
                    payload_fs, payload_path = collector.origin(row["detail"]["payload_path"])
                    try:
                        payload = payload_fs.lookup(payload_path) if payload_fs else None
                        row["detail"]["payload_exists"] = bool(payload and payload["is_file"])
                        row["detail"]["payload_extracted"] = False
                    except (OSError, RuntimeError, ValueError) as exc:
                        row["detail"]["payload_exists"] = None
                        row["error"] = error_text(exc)
                        row["status"] = "partial"
                key = next((k for k, label in self.ARTIFACTS.items() if label == row["artifact"]), None)
                if key in collector.errors:
                    row["detail"]["extraction_errors"] = collector.errors[key]
                    row["status"] = "parse_error" if row["status"] == "artifact_not_found" else "partial"
                    if row["evidence_level"] == "direct":
                        row["evidence_level"] = "support"
                # An unknown original drive letter is a path/provenance limitation, not
                # evidence that the user action itself is weaker.  Preserve direct evidence
                # when History + target file + hash/size checks establish the download.
                row.update(collector.rewrite(row))
                row["source_path"] = str(self.image_path)
                row["detail"].update(context)
                if source_fs and source_fs.offset != fs.offset:
                    row["detail"].update(partition_offset=source_fs.offset, profile_partition_offset=fs.offset)
                row["source_locator"].update(image_path=str(self.image_path),
                                             partition_offset=source_fs.offset if source_fs else fs.offset,
                                             filesystem_path=source_path)
                if manifest:
                    row["source_locator"].update(inode=manifest["node"]["inode"], sequence=manifest["node"]["sequence"])
                    row["detail"]["extracted_artifact_sha256"] = manifest["sha256"]
                if row["artifact"] == "Zone.Identifier" and local_source:
                    zone = collector.zone_cache.get(local_source.removesuffix(":Zone.Identifier"), {})
                    row["source_locator"].update(zone.get("stream_locator", {}))
                self.results.append(row)
            self._downloads.extend(parser._downloads)
            outcome = "gemini_trace_found" if hits else "analysis_failed" if errors else "no_relevant_trace"
            state = "partial" if hits and (errors or partial) else "success" if hits else "parse_error" if errors else "no_relevant_trace"
            summary = self._image_record("Chrome profile independently examined", context, status=state,
                               detail={"record_type": "profile_status", "profile_outcome": outcome,
                                       "gemini_finding_count": hits, "analysis_errors_present": errors,
                                       "analysis_coverage": "partial" if partial or errors else "available_supported_artifacts",
                                       "filesystem_path": node["path"], "extracted_file_count": len(collector.manifest),
                                       "extracted_bytes": collector.extracted_bytes,
                                       "artifact_status": parser.artifact_status,
                                       "limitation": "No relevant trace means none in the examined local artifacts; it does not prove no Gemini use."})
            self.profile_summaries.append(summary)
        except Exception as exc:
            summary = self._image_record("Chrome profile analysis failed; other profiles continue", context,
                               status="parse_error", error=error_text(exc),
                               detail={"record_type": "profile_status", "profile_outcome": "analysis_failed", "filesystem_path": node["path"]})
            self.profile_summaries.append(summary)
        finally:
            if self.keep_temp:
                self.retained_temp_dirs.append(str(scratch))
                self._image_record("Extracted temporary files retained by request", context,
                                   detail={"record_type": "temporary_workspace", "temporary_path": str(scratch)})
            else:
                try:
                    self._cleanup(scratch)
                except OSError as exc:
                    self.retained_temp_dirs.append(str(scratch))
                    self._image_record("Temporary cleanup failed", context, status="partial", error=error_text(exc),
                                       detail={"record_type": "temporary_workspace", "temporary_path": str(scratch)})

    def _correlate_recycle_findings(self):
        """Link independently parsed $I rows to all Chrome downloads after every profile is parsed."""
        by_path = {}
        for record in self._downloads:
            detail = record.get("detail") or {}
            for field in ("target_path", "current_path"):
                canonical = self._canonical_windows_path(detail.get(field))
                if canonical:
                    by_path.setdefault(canonical, []).append(record)
        for row in self.results:
            if row.get("artifact") != "Windows Recycle Bin":
                continue
            detail = row.get("detail") or {}
            if detail.get("record_type") != "finding" or not detail.get("original_path"):
                continue
            matches = by_path.get(self._canonical_windows_path(detail.get("original_path")), [])
            matches = list({((r.get("detail") or {}).get("id"), r.get("source_path")): r for r in matches}.values())
            gemini_matches = [r for r in matches if self._is_gemini_specific_finding(r)]
            detail["download_ids"] = list(dict.fromkeys((r.get("detail") or {}).get("id") for r in matches
                                                         if (r.get("detail") or {}).get("id") is not None))
            detail["history_source_paths"] = list(dict.fromkeys(r.get("source_path") for r in matches if r.get("source_path")))
            detail["related_download_match_count"] = len(matches)
            detail["gemini_related_download_match_count"] = len(gemini_matches)
            detail["match_basis"] = "exact_normalized_original_path" if matches else "none"
            if gemini_matches:
                detail["gemini_attribution"] = "linked_download_candidate"
                detail["service_attribution"] = "candidate"
                row["evidence_level"] = "support"
                row["observation"] = "Recycle Bin metadata parsed; original path matches a Gemini-associated Chrome download"
            elif matches:
                row["observation"] = "Recycle Bin metadata parsed; original path matches a Chrome download; Gemini attribution unconfirmed"
        return None

    def parse(self) -> list[dict]:
        self.results, self._downloads, self.profile_summaries = [], [], []
        self._recycle_scanned_partitions = set()
        self.artifact_status = {}
        self._source_files = {str(self.image_path).casefold()}
        reader = ForensicImageReader(self.image_path)
        try:
            self.image_type = reader.identify()
            if self.temp_root:
                self.temp_root.mkdir(parents=True, exist_ok=True)
            with reader:
                self._source_files.update(str(p).casefold() for p in reader.segments)
                self._image_record("Image opened read-only", detail={"record_type": "image_status", "image_size": reader.size,
                                   "image_segments": [str(p) for p in reader.segments],
                                   "reader_pipeline": ("pyewf -> pytsk3" if self.image_type == "EWF" else
                                                       "split-raw -> pytsk3" if self.image_type == "SPLIT_RAW" else "pytsk3")})
                filesystems = []
                for metadata, fs, error in reader.filesystems():
                    bitlocker_status = metadata.get("bitlocker_status", "NOT_ENCRYPTED")
                    if bitlocker_status != "NOT_ENCRYPTED":
                        self._say(f"[BitLocker] partition offset {metadata['partition_offset']}: {bitlocker_status}")
                        if error:
                            self._say("[BitLocker] " + error)
                    self._image_record("Partition/filesystem probe", self._context(**metadata),
                                       status="success" if fs else "unsupported",
                                       error=error, detail={"record_type": "partition_status", **metadata})
                    if fs:
                        filesystems.append(fs)
                if not filesystems:
                    self._image_record("No readable NTFS filesystem found", status="unsupported",
                                       detail={"record_type": "image_status", "reason": "no_readable_ntfs_filesystem"})
                for fs in filesystems:
                    context = self._context(partition_offset=fs.offset, filesystem_type="NTFS")
                    self._filesystem_metadata(fs, context)
                    count = 0
                    discovery_start = len(self.results)
                    try:
                        windows = fs.lookup("/Windows")
                        self._image_record("Windows directory presence checked", context,
                                           detail={"record_type": "filesystem_inventory", "windows_directory_present": bool(windows)})
                        for user, profile in self._profiles(fs):
                            count += 1
                            self._run_profile(fs, filesystems, user, profile)
                        if not count:
                            failed = any(r["status"] == "parse_error" for r in self.results[discovery_start:])
                            self._image_record("Chrome profile discovery incomplete" if failed else
                                               "No Chrome profiles discovered in the examined Users tree", context,
                                               status="partial" if failed else "no_relevant_trace",
                                               detail={"record_type": "discovery_status",
                                               "reason": "discovery_incomplete" if failed else "no_chrome_profiles_discovered",
                                               "filesystem_path": "/Users"})
                    except (OSError, RuntimeError, ValueError) as exc:
                        self._image_record("NTFS user/profile discovery failed", context, status="parse_error", error=error_text(exc),
                                           detail={"record_type": "discovery_status", "reason": "discovery_failed"})
                self._correlate_recycle_findings()
                # Re-run after global download/Recycle correlation; internal dedupe prevents duplicates.
                self._derive_semantic_actions()
                changed = reader.segment_stats() != reader.initial_stats
                self._image_record("Image examination completed", status="partial" if changed else "success",
                                   error="Image segment size/mtime changed during analysis" if changed else None,
                                   detail={"record_type": "image_status", "profiles_examined": len(self.profile_summaries),
                                           "image_size_mtime_unchanged": not changed,
                                           "image_integrity_hash_verified": False})
                # Drop references to TSK FS objects before closing the image handle.
                filesystems.clear()
        except Exception as exc:
            status = "unsupported" if isinstance(exc, (ImageDependencyError, ValueError)) else "parse_error"
            self._image_record("Image input could not be analyzed", status=status, error=error_text(exc),
                               detail={"record_type": "image_status", "reason": "image_open_failed"})
        return self.results


class LiveArtifactCollector:
    """Read-only, non-atomic filesystem acquisition; no Gemini interpretation.

    Use as a context manager. Only verified stable copies are published to the
    profile parser. SQLite main/WAL/SHM/journal are acquired as one group.
    """

    PROFILE_MARKERS = ("History", "Preferences", "Network/Cookies", "Sessions",
                       "Local Storage", "IndexedDB", "Session Storage", "Service Worker")
    TREES = {"Sessions": "sessions", "Cache/Cache_Data": "cache",
             "Local Storage/leveldb": "local_storage", "Session Storage": "session_storage",
             "IndexedDB": "indexeddb", "Service Worker": "service_worker"}
    CHROME_PARTS = ("AppData", "Local", "Google", "Chrome", "User Data")

    class Changed(OSError):
        pass

    class Unsafe(OSError):
        pass

    def __init__(self, source_path, *, evidence_root=None, temp_root=None, copy_attempts=2):
        self.source = Path(os.path.abspath(Path(source_path).expanduser()))
        self.evidence_root = Path(os.path.abspath(Path(evidence_root).expanduser())) if evidence_root else None
        self.temp_root = Path(temp_root).expanduser().absolute() if temp_root else None
        if not isinstance(copy_attempts, int) or not 1 <= copy_attempts <= 3:
            raise ValueError("copy_attempts must be between 1 and 3")
        self.copy_attempts = copy_attempts
        self.profiles, self.events, self.manifest, self.aliases = [], [], {}, {}
        self.zone_cache = {}
        self.scratch = self.volume = self._temporary = None

    @staticmethod
    def _signature(info):
        return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)

    @staticmethod
    def _identity_signature(info):
        # Windows path stat and fd fstat can expose different ctime semantics.
        # Keep ctime in _signature for all same-API snapshot comparisons.
        return (info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)

    @classmethod
    def _safe_stat(cls, path):
        # lstat every ancestor: Python 3.10 also rejects Windows junctions and
        # other reparse points, without relying on Path.is_junction (3.12+).
        path = Path(path).absolute()
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            if (stat.S_ISLNK(info.st_mode) or
                    getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                raise cls.Unsafe("Linked or reparse path skipped")
            if item != path and not stat.S_ISDIR(info.st_mode):
                raise cls.Unsafe("Non-directory path component skipped")
        return info

    @staticmethod
    def _failure_state(exc):
        if isinstance(exc, LiveArtifactCollector.Changed):
            return "changed_during_copy"
        if isinstance(exc, LiveArtifactCollector.Unsafe):
            return "unsafe_path"
        if getattr(exc, "winerror", None) in (32, 33):
            return "locked"
        if isinstance(exc, PermissionError):
            return "permission_denied"
        if isinstance(exc, FileNotFoundError):
            return "not_found"
        return "copy_error"

    def _event(self, path, key, state, *, profile=None, **detail):
        self.events.append({"record_type": "acquisition_status", "artifact_key": key,
                            "acquisition_state": state, "source_path": str(path),
                            "profile_source": str(profile) if profile else None, **detail})

    def _directory(self, path, key="discovery", profile=None):
        try:
            info = self._safe_stat(path)
            if not stat.S_ISDIR(info.st_mode):
                raise self.Unsafe("Expected an ordinary directory")
            return True
        except OSError as exc:
            self._event(path, key, self._failure_state(exc), profile=profile)
            return False

    def _entries(self, path, key="discovery", profile=None):
        if not self._directory(path, key, profile):
            return []
        try:
            return sorted(Path(path).iterdir(), key=lambda p: (p.name.casefold(), p.name))
        except OSError as exc:
            self._event(path, key, self._failure_state(exc), profile=profile)
            return []

    def _profile_candidate(self, path):
        if not (path.name.casefold() == "default" or re.fullmatch(r"Profile [0-9]+", path.name, re.I)):
            return False
        if not self._directory(path):
            return False
        for relative in self.PROFILE_MARKERS:
            try:
                info = self._safe_stat(path / relative)
                is_file = relative in {"History", "Preferences", "Network/Cookies"}
                if stat.S_ISREG(info.st_mode) if is_file else stat.S_ISDIR(info.st_mode):
                    return True
            except FileNotFoundError:
                continue
            except OSError as exc:
                self._event(path / relative, "discovery", self._failure_state(exc), profile=path)
        return False

    def _user_for_data(self, data):
        if len(data.parts) >= 6 and tuple(p.casefold() for p in data.parts[-5:]) == tuple(p.casefold() for p in self.CHROME_PARTS):
            return data.parents[4]
        return None

    def _add_profiles(self, data, user):
        for candidate in self._entries(data):
            if self._profile_candidate(candidate):
                self.profiles.append({"source": candidate, "user": user})
        if not any(p["source"].parent == data for p in self.profiles):
            self._event(data, "discovery", "not_found", reason="no_chrome_profiles")

    def discover(self):
        """Recognize a volume/Users/user/User Data/conventional profile only."""
        self.profiles = []
        if not self._directory(self.source):
            return []
        if self.evidence_root and not self._directory(self.evidence_root):
            self.evidence_root = None
        if self._profile_candidate(self.source):
            data = self.source.parent
            user = self._user_for_data(data)
            self.profiles.append({"source": self.source, "user": user})
        elif self.source.name.casefold() == "user data":
            user = self._user_for_data(self.source)
            self._add_profiles(self.source, user)
        else:
            user = None
            users = self.source if self.source.name.casefold() == "users" else self.source / "Users"
            try:
                info = self._safe_stat(users)
                if not stat.S_ISDIR(info.st_mode):
                    raise self.Unsafe("Users is not a directory")
            except FileNotFoundError:
                # A user with no Chrome profile is a valid empty acquisition.
                user = self.source
                self._add_profiles(user.joinpath(*self.CHROME_PARTS), user)
            except OSError as exc:
                self._event(users, "discovery", self._failure_state(exc))
            else:
                self.evidence_root = self.evidence_root or users.parent
                for candidate in self._entries(users):
                    try:
                        if not stat.S_ISDIR(self._safe_stat(candidate).st_mode):
                            continue
                        self._add_profiles(candidate.joinpath(*self.CHROME_PARTS), candidate)
                    except OSError as exc:
                        self._event(candidate, "discovery", self._failure_state(exc))
        if not self.evidence_root:
            known_user = user if user else (self.profiles[0]["user"] if self.profiles else None)
            if known_user and known_user.parent.name.casefold() == "users":
                self.evidence_root = known_user.parent.parent
        for spec in self.profiles:
            spec["context"] = {"windows_user": spec["user"].name if spec["user"] else None,
                               "chrome_profile": spec["source"].name,
                               "source_profile": str(spec["source"]), "acquisition_mode": "filesystem",
                               "source_snapshot": "non_atomic_filesystem_copy", "staged_copy": True}
        return self.profiles

    def __enter__(self):
        self.discover()
        base = self.temp_root or Path(tempfile.gettempdir())
        self._safe_stat(base)
        protected = [p["source"].parent for p in self.profiles]
        protected += [p["user"] / "Downloads" for p in self.profiles if p["user"]]
        if self.evidence_root:
            protected.append(self.evidence_root / "$Recycle.Bin")
        if any(within(base, path) for path in protected):
            raise ValueError("Temporary workspace must be outside Chrome, Downloads and Recycle Bin sources")
        self._temporary = tempfile.TemporaryDirectory(prefix="gemini_filesystem_", dir=base)
        self.scratch = Path(self._temporary.name)
        self.volume = self.scratch / "volume"
        try:
            self.volume.mkdir(mode=0o700)
            if self.evidence_root:
                self.aliases[str(self.volume)] = str(self.evidence_root)
            for index, spec in enumerate(self.profiles):
                spec["staged"] = self.scratch / ("profile_" + str(index))
                spec["staged"].mkdir(mode=0o700)
                self.aliases[str(spec["staged"])] = str(spec["source"])
        except BaseException:
            self._temporary.cleanup()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._temporary is not None:
            try:
                self._temporary.cleanup()
            except OSError:
                self._event(self.source, "cleanup", "copy_error", reason="private_workspace_cleanup_failed")
            finally:
                self._temporary = None

    def _copy_one(self, source, destination, before):
        """Bounded read from a verified descriptor; never open source for write."""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or self._identity_signature(opened) != self._identity_signature(before):
                raise self.Changed("Source replaced before copy")
            if self._signature(self._safe_stat(source)) != self._signature(before):
                raise self.Changed("Source changed before copy")
            with destination.open("xb") as output:
                remaining = before.st_size
                while remaining:
                    block = stream.read(min(CHUNK, remaining))
                    if not block:
                        raise self.Changed("Source shortened during copy")
                    output.write(block)
                    digest.update(block)
                    remaining -= len(block)
                if stream.read(1) or self._signature(os.fstat(stream.fileno())) != self._signature(opened):
                    raise self.Changed("Source changed during copy")
        return digest.hexdigest()

    def _group(self, pairs, key, profile=None, *, sqlite_group=False):
        """Publish a whole stable group; discard incomplete/unstable attempts."""
        last_state, failure_path, snapshots = "copy_error", pairs[0][0], {}
        for attempt in range(self.copy_attempts):
            copied = []
            try:
                before = {}
                for source, destination in pairs:
                    failure_path = source
                    try:
                        info = self._safe_stat(source)
                        if not stat.S_ISREG(info.st_mode):
                            raise self.Unsafe("Expected an ordinary file")
                        before[source] = info
                    except FileNotFoundError:
                        before[source] = None
                snapshots = {str(p): ({"size": s.st_size, "mtime_ns": s.st_mtime_ns} if s else None)
                             for p, s in before.items()}
                if before[pairs[0][0]] is None:
                    state = "changed_during_copy" if last_state == "changed_during_copy" else "not_found"
                    self._event(pairs[0][0], key, state, profile=profile,
                                sqlite_group=sqlite_group, members=snapshots,
                                attempts=attempt + 1, passed_to_parser=False)
                    return False
                with tempfile.TemporaryDirectory(prefix="attempt_", dir=self.scratch) as work:
                    for index, (source, destination) in enumerate(pairs):
                        failure_path = source
                        info = before[source]
                        if info is None:
                            continue
                        metadata = GeminiParser._file_metadata(source)
                        temporary = Path(work) / str(index)
                        digest = self._copy_one(source, temporary, info)
                        copied.append((source, destination, temporary, info, digest, metadata))
                    for source, _ in pairs:
                        failure_path = source
                        try:
                            after = self._safe_stat(source)
                        except FileNotFoundError:
                            after = None
                        prior = before[source]
                        if (prior is None) != (after is None) or (prior and self._signature(prior) != self._signature(after)):
                            raise self.Changed("Acquisition group changed during copy")
                    for source, destination, temporary, info, digest, metadata in copied:
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.utime(temporary, ns=(info.st_atime_ns, info.st_mtime_ns))
                        os.replace(temporary, destination)
                        self.aliases[str(destination)] = str(source)
                        self.manifest[str(destination)] = {"source": str(source), "sha256": digest,
                            "metadata": metadata, "signature": self._signature(info), "artifact_key": key}
                self._event(pairs[0][0], key, "copied", profile=profile, attempts=attempt + 1,
                            sqlite_group=sqlite_group, members=snapshots, stable=True,
                            absent_sidecars=[str(p) for p, s in before.items() if s is None])
                return True
            except OSError as exc:
                last_state = self._failure_state(exc)
                if isinstance(exc, FileNotFoundError) and before.get(failure_path) is not None:
                    last_state = "changed_during_copy"
                # No incomplete attempt is passed to the artifact engine.
                for _, destination, *_ in copied:
                    if str(destination) in self.manifest:
                        destination.unlink(missing_ok=True)
                        self.manifest.pop(str(destination), None)
                        self.aliases.pop(str(destination), None)
                if last_state not in {"changed_during_copy", "not_found"}:
                    break
        self._event(pairs[0][0], key, last_state, profile=profile, attempts=attempt + 1,
                    sqlite_group=sqlite_group, members=snapshots, failed_source=str(failure_path),
                    stable=False, passed_to_parser=False)
        return False

    def _tree(self, source, destination, key, profile=None, predicate=None):
        if not self._directory(source, key, profile):
            return
        pending = [(source, destination)]
        while pending:
            folder, target = pending.pop()
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.aliases[str(target)] = str(folder)
            for entry in self._entries(folder, key, profile):
                try:
                    info = self._safe_stat(entry)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((entry, target / entry.name))
                    elif stat.S_ISREG(info.st_mode) and (predicate is None or predicate(entry.name)):
                        self._group([(entry, target / entry.name)], key, profile)
                    elif not stat.S_ISREG(info.st_mode):
                        self._event(entry, key, "unsafe_path", profile=profile, reason="non_regular_file")
                except OSError as exc:
                    self._event(entry, key, self._failure_state(exc), profile=profile)

    def collect_profile(self, spec):
        source, target = spec["source"], spec["staged"]
        for relative, key in (("History", "history"), ("Network/Cookies", "cookies")):
            pairs = [(source / (relative + suffix), target / (relative + suffix))
                     for suffix in ("", "-wal", "-shm", "-journal")]
            self._group(pairs, key, source, sqlite_group=True)
        for relative, key in (("Preferences", "preferences"), ("Secure Preferences", "secure_preferences")):
            self._group([(source / relative, target / relative)], key, source)
        for relative, key in self.TREES.items():
            predicate = (lambda n: n.startswith(("Session_", "Tabs_"))) if key == "sessions" else None
            self._tree(source / relative, target / relative, key, source, predicate)

    def collect_recycle(self):
        if self.evidence_root:
            self._tree(self.evidence_root / "$Recycle.Bin", self.volume / "$Recycle.Bin",
                       "recycle_bin", predicate=lambda n: n.startswith("$I"))
        else:
            self._event(self.source, "recycle_bin", "not_found", reason="volume_root_unknown")

    def original_path(self, value):
        text = str(value)
        for prefix in sorted(self.aliases, key=len, reverse=True):
            if text == prefix or text.startswith(prefix + os.sep) or text.startswith(prefix + ":"):
                return self.aliases[prefix] + text[len(prefix):]
        return text

    def rewrite(self, value):
        if isinstance(value, dict):
            return {k: self.rewrite(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.rewrite(v) for v in value]
        if isinstance(value, Path):
            value = str(value)
        if isinstance(value, str):
            for prefix in sorted(self.aliases, key=len, reverse=True):
                value = value.replace(prefix, self.aliases[prefix])
            if self.scratch:
                value = value.replace(str(self.scratch), "[private acquisition workspace]")
        return value

    def payload_exists(self, local):
        source = Path(self.original_path(local))
        try:
            return stat.S_ISREG(self._safe_stat(source).st_mode)
        except FileNotFoundError:
            return False
        except OSError as exc:
            self._event(source, "recycle_bin", self._failure_state(exc), reason="payload_presence_only")
            return None

    def resolve_download(self, spec, target_path, current_path):
        # Reuse the existing strict path mapping and attribution engine. Supplying
        # a root disables fallback to arbitrary files on the analyst's machine.
        resolver = GeminiParser(spec["source"], image_mode=False,
                                user_root=spec["user"] if not self.evidence_root else None,
                                evidence_root=self.evidence_root or (spec["source"] if not spec["user"] else None))
        result = resolver.resolve_download_path(target_path, current_path)
        if not result.get("resolved_path"):
            return result
        original = Path(result["resolved_path"])
        token = hashlib.sha256(str(original).encode("utf-8")).hexdigest()
        local = self.scratch / "downloads" / token / original.name
        # Reuse a stable acquisition made earlier in this run; do not read the
        # source again merely because another profile references the same file.
        if str(local) not in self.manifest and not self._group([(original, local)], "downloaded_file", spec["source"]):
            return {**result, "file_exists": None, "resolved_path": None,
                    "resolution_error": "Referenced download could not be safely staged"}
        return {**result, "resolved_path": str(local)}

    def zone(self, local):
        if str(local) not in self.zone_cache:
            manifest = self.manifest[str(local)]
            source = Path(manifest["source"])
            try:
                if self._signature(self._safe_stat(source)) != manifest["signature"]:
                    raise self.Changed("Download changed before ADS inspection")
                result = GeminiParser._read_zone(source)
                if self._signature(self._safe_stat(source)) != manifest["signature"]:
                    raise self.Changed("Download changed during ADS inspection")
            except OSError as exc:
                self._event(source, "downloaded_file", self._failure_state(exc), reason="zone_inspection")
                result = {"status": "partial", "values": {}, "error": "Source changed or was inaccessible during Zone.Identifier inspection"}
            self.zone_cache[str(local)] = result
        return self.zone_cache[str(local)]


class FilesystemProfileParser(GeminiParser):
    """Only acquisition hooks differ; all artifact/semantic routines are inherited."""

    def __init__(self, collector, spec, **options):
        super().__init__(spec["staged"], image_mode=False, **options)
        self.collector, self.spec = collector, spec

    def _emit(self, key, observation, **kwargs):
        # Establish original, stable scope before title correlation, message IDs
        # or summaries are derived. No parser routine reopens row.source_path.
        kwargs = self.collector.rewrite(kwargs)
        kwargs["detail"] = {**(kwargs.get("detail") or {}), **self.spec["context"]}
        if key == "recycle_bin" and kwargs["detail"].get("payload_path"):
            kwargs["detail"]["payload_exists"] = self.collector.payload_exists(kwargs["detail"]["payload_path"])
            kwargs["detail"]["payload_extracted"] = False
        return super()._emit(key, self.collector.rewrite(observation), **kwargs)

    def discover_artifacts(self):
        super().discover_artifacts()
        for event in self.collector.events:
            key = event["artifact_key"]
            if event.get("profile_source") != str(self.spec["source"]) or key not in self.artifact_status:
                continue
            if event["acquisition_state"] not in {"copied", "not_found"} and self.artifact_status[key] == "artifact_not_found":
                self.artifact_status[key] = "locked_database" if event["acquisition_state"] == "locked" else "parse_error"
                self._discovery_errors[key] = "Filesystem acquisition incomplete: " + event["acquisition_state"]
        return self.artifacts.copy()

    def resolve_download_path(self, target_path, current_path=None):
        return self.collector.resolve_download(self.spec, target_path, current_path)

    def _read_zone(self, path):
        return self.collector.zone(path)

    def _file_metadata(self, path):
        return self.collector.manifest[str(path)]["metadata"]


class GeminiFilesystemParser(GeminiParser):
    """Internal directory API. The existing CLI remains unchanged.

    parse() owns acquisition and cleanup. Inherited export methods operate on
    original-path results after the private staging directory has been removed.
    """

    def __init__(self, source_path, *, evidence_root=None, temp_root=None, copy_attempts=2, **options):
        super().__init__(source_path, image_mode=False, evidence_root=evidence_root, **options)
        self.filesystem_temp_root = temp_root
        self.copy_attempts = copy_attempts
        self.profile_summaries = []
        self.acquisition_manifest = {}

    def parse(self):
        self.results, self._downloads, self.profile_summaries = [], [], []
        self._source_files = set()
        self.artifacts = {}
        self.acquisition_manifest = {}
        collector = LiveArtifactCollector(self.profile_path, evidence_root=self.evidence_root,
                                          temp_root=self.filesystem_temp_root, copy_attempts=self.copy_attempts)
        try:
            with collector:
                self.artifacts["recycle_bin"] = ([str(collector.evidence_root / "$Recycle.Bin")]
                                                  if collector.evidence_root else [])
                for spec in collector.profiles:
                    start = len(collector.events)
                    try:
                        collector.collect_profile(spec)
                        parser = FilesystemProfileParser(collector, spec, **self._artifact_options())
                        self.results.extend(parser.parse())
                        self._downloads.extend(parser._downloads)
                        self._source_files.update(str(Path(r["source_path"]).absolute()).casefold()
                                                  for r in parser.results if r.get("source_path"))
                        failures = any(e["acquisition_state"] not in {"copied", "not_found"} for e in collector.events[start:])
                        row = self._emit("Filesystem Acquisition", "Chrome profile examined from private staging",
                            path=spec["source"], status="partial" if failures else "success", level="unconfirmed",
                            detail={"record_type": "profile_status", **spec["context"],
                                    "artifact_status": parser.artifact_status, "acquisition_incomplete": failures})
                    except Exception:
                        row = self._emit("Filesystem Acquisition", "Profile acquisition or analysis failed; other profiles continue",
                            path=spec["source"], status="partial", level="unconfirmed",
                            error="Filesystem profile could not be fully analyzed",
                            detail={"record_type": "profile_status", **spec["context"], "acquisition_incomplete": True})
                    self.profile_summaries.append(row)
                # Parse $I metadata once, after all History downloads are known.
                # Reuse the original recycle parser and semantic rules unchanged.
                collector.collect_recycle()
                recycle_spec = {"source": collector.evidence_root or collector.source,
                                "staged": collector.volume, "user": None,
                                "context": {"acquisition_mode": "filesystem", "source_snapshot": "non_atomic_filesystem_copy",
                                            "staged_copy": True, "windows_user": None, "chrome_profile": None}}
                recycle = FilesystemProfileParser(collector, recycle_spec, **self._artifact_options())
                root = collector.volume / "$Recycle.Bin"
                recycle.artifacts = {"recycle_bin": [str(root)] if root.is_dir() else []}
                recycle._expected = {"recycle_bin": root}
                recycle._downloads = self._downloads
                if collector.evidence_root:
                    recycle._parse_recycle_bin("recycle_bin")
                    recycle._derive_semantic_actions()
                    self.results.extend(recycle.results)
                self.acquisition_manifest = {m["source"]: {k: v for k, v in m.items() if k != "source"}
                                             for m in collector.manifest.values()}
                self._source_files.update(str(Path(p).absolute()).casefold() for p in self.acquisition_manifest)
        except (OSError, ValueError):
            self._emit("Filesystem Acquisition", "Filesystem acquisition could not be completed",
                       path=self.profile_path, status="partial", level="unconfirmed",
                       detail={"record_type": "acquisition_status", "acquisition_state": "copy_error"})
        finally:
            for event in collector.events:
                state = event["acquisition_state"]
                status = {"copied": "success", "not_found": "artifact_not_found", "locked": "locked_database"}.get(state, "partial")
                self._emit(self.ARTIFACTS.get(event["artifact_key"], "Filesystem Acquisition"),
                           "Filesystem acquisition status", path=event["source_path"], status=status, level="unconfirmed",
                           detail={**event, "acquisition_mode": "filesystem", "atomic_snapshot": False})
            self._emit("Filesystem Acquisition", "Filesystem acquisition is not an atomic snapshot",
                       path=self.profile_path, level="unconfirmed", status="partial",
                       detail={"record_type": "acquisition_summary", "acquisition_mode": "filesystem",
                               "atomic_snapshot": False, "profiles_discovered": len(collector.profiles),
                               "profiles_examined": len(self.profile_summaries),
                               "staged_file_count": len(self.acquisition_manifest),
                               "limitation": "Stable size/mtime checks do not prove an atomic live snapshot; locked or unstable files may be absent from this analysis."})
        return self.results


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def positive_int(value):
    number = nonnegative_int(value)
    if number == 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


EXAMPLE_WORKDIR = r"C:\Users\me\Desktop\gemini_parser"


def _clean_console_path(value):
    """Accept normal pasted paths as well as Explorer's quoted 'Copy as path' form."""
    value = str(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1].strip()
    return value


def _prompt_image_path():
    """Interactive image-path prompt used only when no CLI image/profile was supplied."""
    print("\n[입력]")
    print("분석할 이미지 파일 경로를 입력하세요 (.dd / .img / .raw / .001 / .E01)")
    print(r"예: C:\Users\me\Desktop\gemini_parser\victim.E01")
    while True:
        raw = _clean_console_path(input("> "))
        if not raw:
            print("경로를 입력해 주세요.")
            continue
        path = Path(raw).expanduser()
        try:
            path = path.absolute()
        except OSError:
            pass
        if not path.exists():
            print("파일을 찾을 수 없습니다. 다시 입력해 주세요.")
            continue
        if not path.is_file():
            print("파일 경로가 아닙니다. 다시 입력해 주세요.")
            continue
        if path.suffix.lower() not in IMAGE_SUFFIXES:
            print("지원하지 않는 형식입니다. .dd, .img, .raw, 첫 .001, .E01 중 하나를 입력해 주세요.")
            continue
        return str(path)


def _prompt_output_path(image_path):
    """Ask for an output directory; blank input chooses a folder beside the image."""
    image = Path(image_path)
    suggested = image.parent / (image.stem + "_gemini_result")
    print("\n결과를 저장할 출력 폴더를 입력하세요")
    print("Enter만 누르면 다음 폴더를 사용합니다:")
    print(str(suggested))
    print(r"예: C:\Users\me\Desktop\gemini_parser\result")
    raw = _clean_console_path(input("> "))
    if not raw:
        return str(suggested)
    path = Path(raw).expanduser()
    try:
        path = path.absolute()
    except OSError:
        pass
    return str(path)


def _apply_interactive_image_input(args):
    """Populate image/output for the beginner-friendly no-argument execution path."""
    print("========================================")
    print("Gemini Web Forensic Parser")
    print("========================================")
    print("명령행 인자가 없어 대화형 입력 모드로 실행합니다.")
    print(r"작업 폴더 예시: C:\Users\me\Desktop\gemini_parser")
    args.image = _prompt_image_path()
    if not args.output:
        args.output = _prompt_output_path(args.image)
    raw_csv = input("timeline.csv와 recovered_conversations.csv도 저장할까요? [Y/n]: ").strip().lower()
    args.csv = raw_csv not in {"n", "no", "아니오"}
    print("\n[분석 설정]")
    print("이미지 경로:", args.image)
    print("출력 폴더:", args.output)
    print("CSV 저장:", "예" if args.csv else "아니오")
    print("분석을 시작합니다.\n")
    return args


def analyze_filesystem(source_path, **options):
    """Parse a directory through private filesystem acquisition and validate output."""
    parser = GeminiFilesystemParser(source_path, **options)
    parser.parse()
    parser.validate_team_contract()
    return parser


def analyze_image(image_path, **options):
    """Integration-friendly API: parse one DD/RAW/split-RAW/E01 image and validate final output contract.

    Returns the configured GeminiImageParser instance so a controller can consume:
      parser.results
      parser.timeline_rows()
      parser.recovered_conversation_rows()
      parser.coverage_rows()
    """
    parser = GeminiImageParser(image_path, **options)
    parser.parse()
    parser.validate_team_contract()
    return parser


def analyze_image_with_baseline(image_path, baseline_image_path, **options):
    """Parse BEFORE and AFTER images, then add conservative state-difference findings to AFTER."""
    baseline = GeminiImageParser(baseline_image_path, **options)
    baseline.parse()
    parser = GeminiImageParser(image_path, **options)
    parser.parse()
    parser.compare_with_baseline(baseline.results)
    parser.validate_team_contract()
    return parser


def main(argv=None):
    cli = argparse.ArgumentParser(description="Gemini Web forensic parser: image input or --folder filesystem acquisition; RAW/DD/split-RAW via pytsk3; E01 via pyewf + pytsk3; BitLocker clear key via dissect.fve + dissect.ntfs")
    cli.add_argument("image", nargs="?", help="Primary input: .dd / .img / .raw / first .001 split-RAW segment / first .E01 segment")
    cli.add_argument("--folder", help="Filesystem acquisition input: Chrome User Data (recommended), profile, Windows user, Users or volume root")
    cli.add_argument("--profile", help="Development/debug input: extracted Chrome Profile directory")
    cli.add_argument("--baseline-image", help="Optional BEFORE image for state-difference rules (conversation/history/cache deletion/edit)")
    cli.add_argument("--user-root", help="Acquired user directory; --profile development/debug mode only")
    cli.add_argument("--evidence-root", help="Optional acquired volume root for drive-path mapping and $Recycle.Bin; --profile or --folder mode")
    cli.add_argument("--output", help=r"Result directory. Interactive example: C:\Users\me\Desktop\gemini_parser\result")
    cli.add_argument("--csv", action="store_true", help="Also export team-format timeline.csv and recovered_conversations.csv")
    cli.add_argument("--debug-output", action="store_true",
                     help="Also export optional coverage.csv (does not change the two final team CSVs)")
    cli.add_argument("--correlation-seconds", type=nonnegative_int, default=300, help="Download/visit proximity window (default: 300 seconds)")
    cli.add_argument("--max-binary-mib", type=nonnegative_int, default=0, help="Raw scan limit per file; 0 scans all bytes (default)")
    cli.add_argument("--max-matches-per-file", type=positive_int, default=200, help="String/image finding cap per file (default: 200 each)")
    cli.add_argument("--max-files", type=nonnegative_int, default=0, help="File cap per binary artifact tree; 0 is unlimited")
    cli.add_argument("--max-json-mib", type=positive_int, default=64, help="Preferences input size cap (default: 64 MiB)")
    cli.add_argument("--temp-root", help="Parent directory for private image or filesystem staging; for --folder it must already exist")
    cli.add_argument("--keep-temp", action="store_true", help="Image only: retain extracted files for debugging (default: clean up)")
    cli.add_argument("--max-extracted-mib", type=nonnegative_int, default=None,
                     help="Image only: extraction byte limit per profile; default/0 is unlimited. Incomplete extraction is reported.")
    args = cli.parse_args(argv)
    if sum(value is not None for value in (args.image, args.folder, args.profile)) > 1:
        cli.error("provide one image path OR --folder OR --profile")
    if args.folder is not None:
        if not args.folder.strip():
            cli.error("--folder requires a non-empty directory path")
        if (args.baseline_image is not None
                or args.keep_temp or args.max_extracted_mib is not None):
            cli.error("--baseline-image, --keep-temp and --max-extracted-mib are image-only options; not supported with --folder")
    if args.user_root is not None and args.profile is None:
        cli.error("--user-root applies only to --profile mode")
    if args.image is None and args.folder is None and args.profile is None:
        try:
            args = _apply_interactive_image_input(args)
        except (EOFError, KeyboardInterrupt):
            print("\n입력이 취소되었습니다.", file=sys.stderr)
            return 130
    if args.debug_output:
        args.csv = True
    if args.baseline_image and not args.image:
        cli.error("--baseline-image is supported only with an image input")
    if args.image and (args.user_root or args.evidence_root):
        cli.error("--user-root applies only to --profile; --evidence-root applies to --profile or --folder")
    options = dict(correlation_seconds=args.correlation_seconds,
                   max_binary_bytes=args.max_binary_mib * 1024 * 1024,
                   max_matches_per_file=args.max_matches_per_file, max_files=args.max_files,
                   max_json_bytes=args.max_json_mib * 1024 * 1024, verbose=True)
    if args.image:
        parser = GeminiImageParser(args.image, temp_root=args.temp_root, keep_temp=args.keep_temp,
                                   max_extracted_bytes=(args.max_extracted_mib or 0) * 1024 * 1024, **options)
    elif args.folder is not None:
        parser = GeminiFilesystemParser(args.folder, evidence_root=args.evidence_root,
                                        temp_root=args.temp_root, **options)
    else:
        parser = GeminiParser(args.profile, args.user_root, evidence_root=args.evidence_root,
                              image_mode=False, **options)
    try:
        if args.image:
            ForensicImageReader(args.image).identify()
        elif not parser.profile_path.is_dir():
            label = "Filesystem source" if args.folder is not None else "Chrome Profile"
            print("Error: " + label + " directory does not exist or is not a directory: " + str(parser.profile_path), file=sys.stderr)
            return 2
        for label, root in (("user-root", parser.user_root), ("evidence-root", parser.evidence_root)):
            if root is not None and not root.is_dir():
                print(f"Error: --{label} is not an accessible directory: {root}", file=sys.stderr)
                return 2
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S_%fZ")
        output = Path(args.output).expanduser().absolute() if args.output else Path.cwd() / ("gemini_output_" + stamp)
        # Fail early for unsafe or existing export destinations.
        if (args.profile or args.folder is not None) and within(output, parser.profile_path):
            raise ValueError("Output must be outside the evidence filesystem source" if args.folder is not None
                             else "Output must be outside the evidence Chrome Profile")
        planned = ["gemini_results.json"]
        if args.csv:
            planned += ["timeline.csv", "recovered_conversations.csv"]
        if args.debug_output:
            planned += ["coverage.csv"]
        for filename in planned:
            if (output / filename).exists():
                raise FileExistsError("Output already exists; choose a new --output directory: " + str(output / filename))
        print("========================================\nGemini Web Forensic Parser\n========================================")
        print(f"Parser version: {PARSER_VERSION} | Output contract: {OUTPUT_CONTRACT_VERSION}")
        print(("Image:\n" if args.image else "Folder:\n" if args.folder is not None else "Profile:\n") + str(parser.profile_path) + "\n", flush=True)
        if args.baseline_image:
            print("Baseline image:\n" + str(Path(args.baseline_image).expanduser().absolute()) + "\n", flush=True)
        results = parser.parse()
        if args.baseline_image:
            baseline = GeminiImageParser(args.baseline_image, temp_root=args.temp_root, keep_temp=args.keep_temp,
                                         max_extracted_bytes=(args.max_extracted_mib or 0) * 1024 * 1024, **options)
            baseline.parse()
            parser.compare_with_baseline(baseline.results)
            results = parser.results
        contract = parser.validate_team_contract()
        json_path = parser.export_json(output / "gemini_results.json")
        timeline_path = parser.export_timeline_csv(output / "timeline.csv") if args.csv else None
        conversations_path = parser.export_recovered_conversations_csv(output / "recovered_conversations.csv") if args.csv else None
        coverage_path = parser.export_coverage_csv(output / "coverage.csv") if args.debug_output else None
        findings = [row for row in results if row["detail"].get("record_type") == "finding"]
        gemini_findings = [row for row in results if parser._is_gemini_specific_finding(row)]
        analyst_findings = [row for row in parser.analyst_rows()
                            if (row.get("detail") or {}).get("record_type") in {"finding", "finding_summary"}]
        levels = Counter(row["evidence_level"] for row in analyst_findings)
        print("\n[File Correlation]")
        print("[+] Downloaded files found:", sum(r["detail"].get("file_exists") is True for r in parser._downloads))
        print("[-] Downloaded files missing:", sum(r["detail"].get("file_exists") is False for r in parser._downloads))
        print("\n[Result]")
        print(f"Total records: {len(results)}")
        print(f"All parsed findings: {len(findings)}")
        print(f"Gemini-related raw findings: {len(gemini_findings)}")
        print(f"Analyst-facing findings: {len(analyst_findings)}")
        print(f"Direct: {levels['direct']}\nSupport: {levels['support']}\nUnconfirmed: {levels['unconfirmed']}")
        print("Team output contract: PASS", contract)
        qa = parser.qa_summary()
        if qa.get("artifact_scans"):
            print("Structured protocol message findings:", qa.get("structured_message_findings", 0))
            print("Recovered conversation rows:", qa.get("conversation_rows", 0))
            for item in qa["artifact_scans"]:
                print("[QA] {artifact}: files={files_read}/{files_examined}, bytes={bytes_read}, protocol_messages={structured_protocol_message_count}, limits={scan_limit_reached_files}/{result_limit_reached_files}, errors={read_error_count}, elapsed={elapsed_sec}s".format(**item))

        key_findings = parser.timeline_rows()[:20]
        print("\n[Timeline Preview]")
        if not key_findings:
            print("Timeline에 표시할 timestamp 기반 direct/support finding이 없습니다. 상세 상태와 raw 결과는 JSON에서 확인하세요.")
        else:
            for index, row in enumerate(key_findings, 1):
                display = parser._timeline_row(row)
                print(f"\n[{index}]")
                print("Model           :", display["Model"])
                print("Timestamp       :", display["Timestamp"])
                print("User_behavior   :", display["User_behavior"])
                print("Behavior_details:", display["Behavior_details "])
                print("Verdict         :", display["Verdict"])
                print("Artifact_path   :", display["Artifact_path"])
                print("Artifact_details:", display["Artifact_details "])

        print("\nJSON (full common-schema result):\n" + json_path)
        if timeline_path:
            print("Timeline CSV (사용자가 언제 무엇을 했는가):\n" + timeline_path)
            print("Recovered conversations CSV (실제로 복구된 메시지):\n" + conversations_path)
        if coverage_path:
            print("Coverage CSV (개발/검증용, 최종 팀 CSV 아님):\n" + coverage_path)
        if args.image:
            outcomes = Counter(r["detail"]["profile_outcome"] for r in parser.profile_summaries)
            print("Profiles:", dict(outcomes))
            if any(r["detail"].get("reason") == "image_open_failed" for r in results):
                return 2
            examined = results + (baseline.results if args.baseline_image else [])
            if any(r["detail"].get("bitlocker_status") in {
                    "BITLOCKER_LOCKED", "BITLOCKER_UNSUPPORTED",
                    "BITLOCKER_OPEN_ERROR"} for r in examined):
                print("BitLocker: one or more partitions could not be unlocked; see partition_status in JSON.", file=sys.stderr)
                return 2
        # Partial/unsupported raw formats are expected non-fatal analysis outcomes.
        return 0
    except (OSError, ValueError) as exc:
        print("Error: " + error_text(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Analysis interrupted; no completed export is guaranteed.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
