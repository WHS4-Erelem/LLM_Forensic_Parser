"""One-line descriptions of the records a detector used (Artifact_details)."""
from __future__ import annotations

import datetime as dt
import re
from typing import Any

from ..model.entities import FAMILY_DISPLAY, EvidenceRecord
from ..util.common import KST, ensure_aware, from_webkit

MAX_VALUE = 120
_SECRET_QUERY = re.compile(
    r"(?:^|&)(?:code|state|token|nonce|hop_nonce|client_id|scope|tl|part|as|rart|gis_params|"
    r"session\w*|authuser|continue|ifkv|flowname)=", re.I,
)

def clip(value: Any, limit: int = MAX_VALUE) -> str:
    text = " ".join(str(value if value is not None else "").replace("\x00", "").split())
    return text if len(text) <= limit else text[:limit] + "…"

def short_url(url: Any, limit: int = MAX_VALUE) -> str:
    text = str(url or "").replace("\x00", "").strip().split(" ")[-1]
    prefix = ""
    if text.startswith("blob:"):
        prefix, text = "blob:", text[5:]
    text = re.sub(r"^[a-z]+://", "", text)
    base, _, fragment = text.partition("#")
    path, _, query = base.partition("?")
    if query and (len(query) > 40 or _SECRET_QUERY.search(query)):
        query = "…"
    out = prefix + path + (f"?{query}" if query else "")
    if fragment and "=" not in fragment:
        out += f"#{fragment}"
    return clip(out, limit)

def kst(value: dt.datetime | None) -> str:
    aware = ensure_aware(value)
    return aware.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S") if aware else "-"

def _title(value: Any) -> str:
    return f" ({clip(value, 40)})" if value else ""

def _pairs(*items: tuple[str, Any]) -> str:
    return ", ".join(f"{k}={clip(v)}" for k, v in items if v not in (None, "", [], {}))

def summarize_record(record: EvidenceRecord) -> str:
    family = record.artifact_family
    attrs = record.attributes
    head = f"[{FAMILY_DISPLAY.get(family, family)}]"
    subtype = attrs.get("subtype")

    if family == "history" and subtype == "download":
        end = from_webkit(attrs.get("end_time")) or record.timestamp
        return f"{head} 다운로드 {attrs.get('state_label')} {kst(end)}, " + _pairs(
            ("파일", attrs.get("file_name")), ("MIME", attrs.get("mime_type")),
            ("크기", attrs.get("received_bytes")), ("URL", short_url((attrs.get("chain_urls") or [""])[0])),
        )
    if family == "history" and subtype == "visit":
        return f"{head} {kst(record.timestamp)} 방문 {short_url(attrs.get('url'))}{_title(attrs.get('title'))}"
    if family == "history":
        return (f"{head} {short_url(attrs.get('url'))}{_title(attrs.get('title'))}, "
                f"방문 {attrs.get('visit_count')}회, 마지막 {kst(record.timestamp)}")
    if family == "sessions":
        return f"{head} {kst(record.timestamp)} 탭 탐색 {short_url(attrs.get('url'))}{_title(attrs.get('title'))}"
    if family == "cookies":
        return f"{head} {attrs.get('host_key')} {attrs.get('name')} 생성 {kst(record.timestamp)}"
    if family == "cache":
        line = f"{head} {attrs.get('key_kind')} {short_url(attrs.get('cache_key'))}"
        if attrs.get("response_at"):
            line += f" 응답 {kst(attrs['response_at'])}"
        return line + (f", {clip(attrs.get('content_type'), 40)}" if attrs.get("content_type") else "")
    if family == "indexeddb":
        line = (f"{head} {attrs.get('database')}/{attrs.get('object_store')} "
                f"key={clip(attrs.get('key_text'), 60)}, 상태={attrs.get('record_state')}")
        return line + (f", updatedAt {kst(record.timestamp)}" if record.timestamp else "")
    if family == "local_storage":
        line = f"{head} key={clip(attrs.get('script_key'), 60)}"
        return line + (f", 기록 시각 {kst(record.timestamp)}" if record.timestamp else "") + \
            f", 값 {attrs.get('value_length')}자"
    if family == "mft":
        streams = ";".join(attrs.get("data_streams") or [])
        return f"{head} " + _pairs(
            ("경로", attrs.get("full_path")), ("할당", attrs.get("allocated")),
            ("크기", attrs.get("logical_size")), ("대체 스트림", streams),
        )
    if family == "zone_identifier":
        return f"{head} " + _pairs(
            ("ZoneId", attrs.get("zone_id")), ("HostUrl", short_url(attrs.get("host_url"))),
            ("ReferrerUrl", short_url(attrs.get("referrer_url"))),
        )
    if family == "filesystem_file":
        return f"{head} " + _pairs(("파일", attrs.get("file_name")), ("경로", attrs.get("windows_path")), ("크기",
            attrs.get("size")),)
    if family == "usn":
        return f"{head} " + _pairs(
            ("파일", attrs.get("file_name")), ("변경", ";".join(attrs.get("reasons") or [])),
            ("시각", kst(record.timestamp)),
        )
    if family == "recycle_bin":
        return f"{head} " + _pairs(
            ("원본 경로", attrs.get("original_path")), ("원본 크기", attrs.get("original_size")),
            ("삭제 시각", kst(record.timestamp)), ("$R 존재", "예" if attrs.get("has_r_file") else "아니오"),
        )
    return f"{head} {clip(record.summary)}"
