"""Chrome storage parsers built on ccl_chromium_reader: IndexedDB, Local Storage, Sessions/Tabs."""
from __future__ import annotations

import collections
import datetime as dt
import json
from pathlib import Path
from typing import Any

from ..model.entities import (
    FAMILY_INDEXEDDB, FAMILY_LOCAL_STORAGE, FAMILY_SESSIONS, STATE_HISTORICAL_OR_DELETED, STATE_LIVE,
    EvidenceRecord, make_evidence_id,
)
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import UTC, ensure_aware, from_iso8601, from_unix_millis, to_jsonable
from . import ccl_adapter as ccl
from .common import conversation_from_url, is_claude_url, organization_from_url, truncate

_CLAUDE_ORIGINS = ("claude.ai", "claude.com")

def _millis(value: Any) -> dt.datetime | None:
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    return from_unix_millis(value) if isinstance(value, (int, float)) else None

KEY_REACT_QUERY = "react-query-cache"
KEY_CHAT_DRAFT_PREFIX = "store:chat-draft:"

def classify_idb_key(key_text: str) -> str:
    k = (key_text or "").lower()
    if KEY_REACT_QUERY in k:
        return "react_query_cache"
    if k.startswith(KEY_CHAT_DRAFT_PREFIX):
        return "chat_draft"
    if "store:attachment-blob" in k:
        return "attachment_blob"
    if "pin-state" in k:
        return "ui_state"
    return "other"

def _idb_time(value: Any) -> dt.datetime | None:
    if isinstance(value, dict):
        return _millis(value.get("updatedAt")) or _millis(value.get("timestamp"))
    return None

def parse_indexeddb(
    indexeddb_dir: Path, source_path: str, volume_id: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    if not indexeddb_dir.exists():
        return records, ParseStatus(
            artifact="IndexedDB", family=FAMILY_INDEXEDDB, status=ST_NOT_FOUND,
            source_path=source_path, message="IndexedDB directory not staged",
        )
    all_dirs = sorted(p for p in indexeddb_dir.iterdir() if p.is_dir() and p.name.endswith(".leveldb"))
    leveldb_dirs = [p for p in all_dirs if any(o in p.name.lower() for o in _CLAUDE_ORIGINS)]
    if not leveldb_dirs:
        return records, ParseStatus(
            artifact="IndexedDB", family=FAMILY_INDEXEDDB, status=ST_NOT_FOUND, source_path=source_path,
            message=f"no Claude-origin *.leveldb directory ({len(all_dirs)} other origin(s) skipped)",
        )

    errors: list[str] = []
    counts: collections.Counter = collections.Counter()
    query_keys: collections.Counter = collections.Counter()
    for leveldb_dir in leveldb_dirs:
        blob_dir = leveldb_dir.with_name(leveldb_dir.name[: -len(".leveldb")] + ".blob")
        leveldb_path = f"{source_path}/{leveldb_dir.name}"

        def on_bad(key: Any, buffer: bytes, _dir: Path = leveldb_dir) -> None:
            counts["bad_deserialization"] += 1
            locator = f"leveldb={_dir.name};bad_deserialization={counts['bad_deserialization']}"
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(
                        FAMILY_INDEXEDDB, source_path, locator,
                        {"key": to_jsonable(key), "size": len(buffer or b"")},
                    ),
                    artifact="IndexedDB", artifact_family=FAMILY_INDEXEDDB,
                    source_path=source_path, artifact_path=f"{source_path}/{_dir.name}",
                    record_locator=locator, summary="IndexedDB 역직렬화 실패 레코드",
                    attributes={"subtype": "bad_deserialization", "leveldb": _dir.name,
                                "buffer_size": len(buffer or b""), "volume_id": volume_id},
                )
            )

        def on_store_error(where: str, exc: Exception, _dir: Path = leveldb_dir) -> None:
            errors.append(f"{_dir.name}/{where}: {type(exc).__name__}: {exc}")

        wrapper = None
        try:
            wrapper = ccl.open_indexeddb(leveldb_dir, blob_dir if blob_dir.exists() else None)
            for rec in ccl.iter_indexeddb_records(wrapper, on_bad, on_store_error):
                counts[rec.state] += 1
                if rec.external_value_path:
                    counts["external_blob"] += 1
                kind = classify_idb_key(rec.key_text)
                counts[f"kind:{kind}"] += 1
                value = to_jsonable(rec.value)
                if kind == "react_query_cache" and isinstance(value, dict):
                    for query in (value.get("clientState") or {}).get("queries") or []:
                        qk = query.get("queryKey") if isinstance(query, dict) else None
                        query_keys[str(qk[0]) if isinstance(qk, list) and qk else "?"] += 1
                locator = f"leveldb={leveldb_dir.name};{rec.locator}"
                records.append(
                    EvidenceRecord(
                        evidence_id=make_evidence_id(
                            FAMILY_INDEXEDDB, source_path, locator,
                            {"key": rec.key_text, "seq": rec.ldb_seq_no, "state": rec.state,
                             "file": rec.origin_file},
                        ),
                        artifact="IndexedDB", artifact_family=FAMILY_INDEXEDDB, source_path=source_path,

                        artifact_path=f"{leveldb_path}/{rec.origin_file}" if rec.origin_file
                        else leveldb_path, volume_id=volume_id, record_locator=locator,
                        timestamp=_idb_time(value),
                        summary=f"IndexedDB {rec.database_name}/{rec.object_store} "
                                f"key={truncate(rec.key_text, 60)} [{rec.state}]", attributes={
                            "subtype": "indexeddb_record", "leveldb": leveldb_dir.name,
                            "database": rec.database_name, "object_store": rec.object_store,
                            "key_text": rec.key_text, "key_kind": kind, "ldb_seq_no": rec.ldb_seq_no,

                            "record_state": rec.state, "external_value_path": rec.external_value_path,
                            "value": value, "volume_id": volume_id,
                        },
                    )
                )
        except Exception as exc:
            errors.append(f"{leveldb_dir.name}: {type(exc).__name__}: {exc}")
        finally:
            ccl.close_indexeddb(wrapper)

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    if counts["bad_deserialization"] and not errors:
        status = ST_PARTIAL
    note = (
        f"live={counts[STATE_LIVE]} historical_or_deleted={counts[STATE_HISTORICAL_OR_DELETED]} "
        f"external_blob={counts['external_blob']} bad_deserialization={counts['bad_deserialization']} "
        f"non_claude_origins_skipped={len(all_dirs) - len(leveldb_dirs)}"
    )
    kinds = ", ".join(f"{k[5:]}={v}" for k, v in sorted(counts.items()) if k.startswith("kind:"))
    details = [f"indexeddb key kinds: {kinds}"]
    if query_keys:
        details.append(
            "indexeddb react-query queryKey[0]: "
            + ", ".join(f"{k}×{v}" for k, v in sorted(query_keys.items()))
        )
    return records, ParseStatus(
        artifact="IndexedDB", family=FAMILY_INDEXEDDB, status=status, source_path=source_path,
        record_count=len(records),
        message="; ".join(errors[:5]) or note, details=details,
    )

PRIORITY_EXACT = {
    "__qk_hint_account_uuid", "rq-cache-confirmed-account", "rq-cache-confirmed-account-session",
    "static-composer-draft-data", "static-composer-greeting-data-v2",
}
PRIORITY_SUBSTRINGS = (
    "accountuuid", "organizationuuid", "chat-draft", "composer-draft", "model_selected",
    "model-selected", "incognito", "temporary", "logout-at", "logout_at",
    "analytics_queue", "antalytics_queue", "membership", "onboarding", "current_account",
)

ANALYTICS_PROPERTIES = (
    "conversation_uuid", "message_uuid", "message_index", "message_length", "prompt_length",
    "model", "previous_model", "selected_model", "is_incognito", "incognito_mode",
    "is_temporary", "is_new_conversation", "has_attachments", "has_files", "has_images",
    "source", "client_platform", "row_kind", "via", "origin", "succeeded", "flow_type",
    "send_origin", "path", "edit_kind", "is_identical_content", "is_last_human_message",
    "branch_parent_message_uuid", "file_id", "file_extension", "is_output_file",
    "snapshot_uuid", "is_shared", "file_count", "file_name", "fileName", "mime_type", "file_kind",
)

def classify_local_storage_key(script_key: str) -> str:
    k = (script_key or "").lower()
    if script_key in PRIORITY_EXACT:
        return script_key
    if "logout" in k:
        return "logout_marker"
    if "analytics_queue" in k or "antalytics_queue" in k:
        return "analytics_queue"
    if "draft" in k:
        return "draft"
    if "incognito" in k or "temporary" in k:
        return "temporary_marker"
    if "model" in k and ("select" in k or "current" in k):
        return "model_selection"
    if "account" in k or "organization" in k or "membership" in k:
        return "account_state"
    return "other"

def is_priority(script_key: str) -> bool:
    k = (script_key or "").lower()
    return script_key in PRIORITY_EXACT or any(token in k for token in PRIORITY_SUBSTRINGS)

def _value_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")

def _analytics_events(parsed: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, dict) and isinstance(node.get("eventName"), str):
            props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
            events.append({
                "eventName": node["eventName"], "eventTimestamp": node.get("eventTimestamp"),
                "eventId": node.get("eventId"),
                "account_uuid": str(node.get("accountUuid") or props.get("account_uuid") or "").lower(),
                "organization_uuid": str(node.get("organizationUuid") or props.get("organization_uuid") or "").lower(),
                "properties": {k: props[k] for k in ANALYTICS_PROPERTIES if k in props},
            })
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:1000]:
                walk(item, depth + 1)

    walk(parsed)
    return events

def _extract(script_key: str, text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.count("-") == 4 and len(stripped) == 36:
        return {"account_uuid": stripped.lower()}
    if "logout-at" in script_key.lower() or "logout_at" in script_key.lower():
        at = _millis(stripped)
        return {"marker_at": at} if at else {}
    if not stripped or stripped[0] not in "[{":
        return {}
    try:
        parsed = json.loads(stripped)
    except Exception:
        return {}

    out: dict[str, Any] = {}
    if isinstance(parsed, dict):
        account = parsed.get("accountUuid") or parsed.get("account_uuid") or parsed.get("account")
        if isinstance(account, str) and len(account) == 36:
            out["account_uuid"] = account.lower()
        if script_key == "rq-cache-confirmed-account-session":
            out["marker_at"] = _millis(parsed.get("marker"))
        for name in ("updatedAt", "updated_at"):
            if isinstance(parsed.get(name), (int, float)):
                out["updated_at"] = from_unix_millis(parsed[name])
        for name in ("attachmentCount", "fileCount", "text"):
            if name in parsed:
                out[name] = parsed[name]
    events = _analytics_events(parsed)
    if events:
        out["analytics_events"] = events

        out["model_selection_events"] = [
            {**e["properties"], "eventTimestamp": e["eventTimestamp"], "account_uuid": e["account_uuid"]}
            for e in events
            if "model_selected" in e["eventName"] and e["properties"].get("previous_model")
        ]
        accounts = {e["account_uuid"] for e in events if e["account_uuid"]}
        if len(accounts) == 1:
            out.setdefault("account_uuid", accounts.pop())
    return out

def parse_local_storage(
    leveldb_dir: Path, source_path: str, volume_id: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []
    if not leveldb_dir.exists():
        return records, ParseStatus(
            artifact="Local Storage", family=FAMILY_LOCAL_STORAGE, status=ST_NOT_FOUND,
            source_path=source_path, message="Local Storage leveldb not staged",
        )

    def on_error(where: str, exc: Exception) -> None:
        errors.append(f"{where}: {type(exc).__name__}: {exc}")

    event_names: collections.Counter = collections.Counter()
    try:
        for rec in ccl.iter_local_storage(leveldb_dir, on_error):
            if "claude" not in rec.storage_key.lower():
                continue
            text = _value_text(rec.value)
            priority = is_priority(rec.script_key)
            extracted = _extract(rec.script_key, text) if priority else {}
            for event in extracted.get("analytics_events", []):
                event_names[event["eventName"]] += 1
            locator = f"leveldb;{rec.locator}"
            attributes: dict[str, Any] = {
                "subtype": "local_storage_record", "storage_key": rec.storage_key,
                "script_key": rec.script_key, "key_kind": classify_local_storage_key(rec.script_key),
                "is_priority_key": priority, "leveldb_seq_number": rec.seq, "value_length": len(text),
                "value_preview": truncate(text, 600), "volume_id": volume_id,
            }
            attributes.update(extracted)
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(
                        FAMILY_LOCAL_STORAGE, source_path, locator,
                        {"storage_key": rec.storage_key, "script_key": rec.script_key,
                         "seq": rec.seq, "file": rec.origin_file, "value_length": len(text)},
                    ),
                    artifact="Local Storage", artifact_family=FAMILY_LOCAL_STORAGE, source_path=source_path,

                    artifact_path=f"{source_path}/{rec.origin_file}" if rec.origin_file
                    else source_path, volume_id=volume_id, record_locator=locator,
                    timestamp=extracted.get("updated_at") or extracted.get("marker_at"),
                    account_uuid=extracted.get("account_uuid"),
                    summary=f"Local Storage {rec.storage_key} / {truncate(rec.script_key, 70)}",
                    attributes=attributes,
                )
            )
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    details = []
    if event_names:
        details.append(
            "local storage analytics events (all queue versions): "
            + ", ".join(f"{k}×{v}" for k, v in sorted(event_names.items()))
        )
    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="Local Storage", family=FAMILY_LOCAL_STORAGE, status=status,
        source_path=source_path, record_count=len(records),
        message="; ".join(errors[:5]), details=details,
    )

def event_time(event: dict[str, Any]) -> dt.datetime | None:
    value = event.get("eventTimestamp")
    return from_iso8601(value) if isinstance(value, str) else _millis(value)

def parse_sessions(
    sessions_dir: Path, source_path: str, volume_id: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []
    unprocessed = 0
    files = sorted(
        p for p in (sessions_dir.iterdir() if sessions_dir.exists() else [])
        if p.is_file() and p.name.startswith(("Session_", "Tabs_"))
    )
    if not files:
        return records, ParseStatus(
            artifact="Sessions/Tabs", family=FAMILY_SESSIONS, status=ST_NOT_FOUND,
            source_path=source_path, message="no Session_*/Tabs_* files staged",
        )

    def on_error(name: str, exc: Exception) -> None:
        errors.append(f"{name}: {type(exc).__name__}: {exc}")

    for snss_file in files:
        for command in ccl.iter_snss_commands(snss_file, on_error):
            if not command.is_navigation:
                unprocessed += 1
                continue
            if not (is_claude_url(command.url) or is_claude_url(command.original_request_url)):
                continue
            ts = command.timestamp
            ts = ensure_aware(ts, UTC) if isinstance(ts, dt.datetime) else None
            payload = {
                "file": command.file_name, "index": command.index, "url": command.url,
                "original_request_url": command.original_request_url,
                "referrer_url": command.referrer_url, "timestamp": str(command.timestamp),
            }
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(FAMILY_SESSIONS, source_path, command.locator, payload),
                    artifact="Sessions/Tabs", artifact_family=FAMILY_SESSIONS,
                    source_path=f"{source_path}/{command.file_name}", record_locator=command.locator,
                    timestamp=ts, organization_uuid=organization_from_url(command.url),
                    conversation_uuid=conversation_from_url(command.url)
                    or conversation_from_url(command.original_request_url),
                    summary=f"탭 탐색: {truncate(command.url, 150)}", attributes={
                        "subtype": "navigation_entry", "session_file": command.file_name,
                        "index": command.index, "url": command.url,
                        "original_request_url": command.original_request_url,
                        "referrer_url": command.referrer_url, "title": command.title, "volume_id": volume_id,
                    },
                )
            )

    return records, ParseStatus(
        artifact="Sessions/Tabs", family=FAMILY_SESSIONS,
        status=ST_PARTIAL if records or not errors else ST_FAILED,
        source_path=source_path, record_count=len(records),
        message="; ".join(errors[:5])
        or f"CCL SNSS support is partial; NavigationEntry parsed, "
           f"{unprocessed} non-navigation command(s) retained as locators only",
    )
