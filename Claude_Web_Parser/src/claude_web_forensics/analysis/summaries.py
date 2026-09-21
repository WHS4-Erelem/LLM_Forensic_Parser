"""Human-readable summaries of the artifact records a detector actually used.

What goes in: the values that *demonstrate* the action — filenames, URLs, paths
that are themselves the evidence, UUIDs, timestamps, states.

What stays out: evidence ids, detail refs, table row ids, LevelDB sequence
numbers, record locators, MFT record positions, source paths inside the image,
staging paths, raw references and whole JSON blobs. Those remain internal.
"""
from __future__ import annotations

from typing import Any, Iterable

from ..model.entities import FAMILY_DISPLAY, EvidenceRecord
from ..util.common import to_kst_display

# Keys that must never be rendered into the report.
_FORBIDDEN_KEYS = frozenset(
    {
        "record_locator", "evidence_id", "detail_ref", "raw_ref", "source_path",
        "ldb_seq_no", "leveldb_seq_number", "sequence_number", "mft_segment",
        "mft_sequence", "byte_offset", "record_location", "metadata_location",
        "body_location", "staged_path", "value", "_json", "command_ordinal",
        "download_id", "usn", "variant_index", "external_value_path",
        "decoded_body_path", "artifact_path",
    }
)

MAX_VALUE = 180


def _clip(value: Any, limit: int = MAX_VALUE) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _pairs(items: Iterable[tuple[str, Any]]) -> str:
    out = []
    for key, value in items:
        if key in _FORBIDDEN_KEYS:
            continue
        if value in (None, "", [], {}):
            continue
        out.append(f"{key}={_clip(value)}")
    return ", ".join(out)


def summarize_record(record: EvidenceRecord) -> str:
    """One line describing what this record shows. Empty when nothing useful."""
    family = record.artifact_family
    attrs = record.attributes
    display = FAMILY_DISPLAY.get(family, family)
    subtype = attrs.get("subtype")

    if family == "history":
        if subtype == "download":
            body = _pairs(
                [
                    ("상태", attrs.get("state_label")),
                    ("파일명", attrs.get("file_name")),
                    ("저장 경로", attrs.get("target_path") or attrs.get("current_path")),
                    ("MIME", attrs.get("mime_type")),
                    ("크기", attrs.get("received_bytes")),
                    ("다운로드 URL", (attrs.get("chain_urls") or [""])[0]),
                ]
            )
            return f"[{display}] 다운로드 {body}" if body else ""
        if subtype in ("url", "visit"):
            body = _pairs(
                [
                    ("URL", attrs.get("url")),
                    ("제목", attrs.get("title")),
                    ("방문 횟수", attrs.get("visit_count")),
                ]
            )
            return f"[{display}] {body}" if body else ""

    if family == "cookies":
        body = _pairs(
            [
                ("host", attrs.get("host_key")),
                ("name", attrs.get("name")),
                ("secure", attrs.get("is_secure")),
                ("httponly", attrs.get("is_httponly")),
            ]
        )
        # Cookie values are never reproduced.
        return f"[{display}] {body}" if body else ""

    if family == "cache":
        body = _pairs(
            [
                ("유형", attrs.get("key_kind")),
                ("대화 제목", attrs.get("conversation_title")),
                ("대화 UUID", record.conversation_uuid),
                ("snapshot UUID", attrs.get("snapshot_uuid")),
                ("is_temporary", attrs.get("is_temporary")),
                ("모델", attrs.get("conversation_model")),
                ("Content-Type", attrs.get("content_type")),
                ("Content-Encoding", attrs.get("content_encoding")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "indexeddb":
        body = _pairs(
            [
                ("저장소", f"{attrs.get('database')}/{attrs.get('object_store')}"
                 if attrs.get("database") else None),
                ("key", attrs.get("key_text")),
                ("상태", attrs.get("record_state")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "local_storage":
        body = _pairs(
            [
                ("key", attrs.get("script_key")),
                ("내용", attrs.get("value_preview")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "sessions":
        body = _pairs(
            [
                ("URL", attrs.get("url")),
                ("제목", attrs.get("title")),
                ("referrer", attrs.get("referrer_url")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "mft":
        body = _pairs(
            [
                ("경로", attrs.get("full_path")),
                ("할당", attrs.get("allocated")),
                ("크기", attrs.get("logical_size")),
                ("대체 스트림", ";".join(attrs.get("data_streams") or []) or None),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "zone_identifier":
        body = _pairs(
            [
                ("ZoneId", attrs.get("zone_id")),
                ("HostUrl", attrs.get("host_url")),
                ("ReferrerUrl", attrs.get("referrer_url")),
                ("대화 UUID", record.conversation_uuid),
                ("원격 경로", attrs.get("remote_path")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "usn":
        reasons = ";".join(attrs.get("reasons") or [])
        body = _pairs(
            [
                ("파일명", attrs.get("file_name")),
                ("변경", reasons or None),
                ("시각", to_kst_display(record.timestamp) or None),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "recycle_bin":
        body = _pairs(
            [
                ("원본 경로", attrs.get("original_path")),
                ("원본 크기", attrs.get("original_size")),
                ("삭제 시각", to_kst_display(record.timestamp) or None),
                ("$R 존재", "예" if attrs.get("has_r_file") else "아니오"),
            ]
        )
        return f"[{display}] {body}" if body else ""

    if family == "filesystem_file":
        body = _pairs(
            [
                ("파일명", attrs.get("file_name")),
                ("경로", attrs.get("windows_path")),
                ("크기", attrs.get("size")),
            ]
        )
        return f"[{display}] {body}" if body else ""

    return f"[{display}] {_clip(record.summary)}" if record.summary else ""


def summarize_group(
    records: Iterable[EvidenceRecord], max_lines_per_family: int = 3
) -> list[str]:
    """Deduplicated per-artifact lines for the records a detector relied on.

    Duplicate records of the same artifact collapse into one line; records the
    detector did not use are never passed in, so they never appear.
    """
    seen: set[str] = set()
    per_family: dict[str, int] = {}
    lines: list[str] = []
    for record in records:
        if record is None:
            continue
        line = summarize_record(record)
        if not line or line in seen:
            continue
        family = record.artifact_family
        if per_family.get(family, 0) >= max_lines_per_family:
            continue
        per_family[family] = per_family.get(family, 0) + 1
        seen.add(line)
        lines.append(line)
    # Stable order: group by artifact display name.
    lines.sort()
    return lines
