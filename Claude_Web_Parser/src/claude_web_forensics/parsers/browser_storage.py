"""Chrome storage parsers built on ccl_chromium_reader: IndexedDB, Local Storage, Sessions/Tabs.

Merged verbatim from: indexeddb.py, local_storage.py, sessions.py.
"""
from __future__ import annotations

from pathlib import Path
from ..model.entities import (
    FAMILY_INDEXEDDB,
    STATE_HISTORICAL_OR_DELETED,
    STATE_LIVE,
    EvidenceRecord,
    make_evidence_id,
)
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import to_jsonable
from .common import truncate
from . import ccl_adapter as ccl
import json
from typing import Any
from ..model.entities import FAMILY_LOCAL_STORAGE, EvidenceRecord, make_evidence_id
from ..util.common import from_iso8601, from_unix_millis
import datetime as dt
from ..model.entities import FAMILY_SESSIONS, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARTIAL, ParseStatus
from ..util.common import KST, ensure_aware
from .common import conversation_from_url, is_claude_url, organization_from_url, truncate


# ===========================================================================
# indexeddb
# ===========================================================================

"""IndexedDB parser (spec section 10.4).

The `.leveldb` directory and its sibling `.blob` directory are provided
together. CCL returns live and old/deleted versions; that distinction is
preserved verbatim and never collapsed into a "current" view. A single bad
deserialization does not abort the store.
"""

# Keys that carry Claude account / draft / conversation state.
KEY_REACT_QUERY = "react-query-cache"
KEY_CHAT_DRAFT_PREFIX = "store:chat-draft:"
KEY_ATTACHMENT_BLOB = "store:attachment-blob"


def classify_idb_key(key_text: str) -> str:
    k = (key_text or "").lower()
    if KEY_REACT_QUERY in k:
        return "react_query_cache"
    if k.startswith(KEY_CHAT_DRAFT_PREFIX):
        return "chat_draft"
    if KEY_ATTACHMENT_BLOB in k:
        return "attachment_blob"
    if "pin-state" in k:
        return "ui_state"
    return "other"


def parse_indexeddb(
    indexeddb_dir: Path,
    source_path: str,
    volume_id: str,
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []
    bad_records = 0

    if not indexeddb_dir.exists():
        return records, ParseStatus(
            artifact="IndexedDB",
            family=FAMILY_INDEXEDDB,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="IndexedDB directory not staged",
            impact="conversation tree / draft / attachment metadata unavailable",
        )

    leveldb_dirs = sorted(
        p for p in indexeddb_dir.iterdir() if p.is_dir() and p.name.endswith(".leveldb")
    )
    if not leveldb_dirs:
        return records, ParseStatus(
            artifact="IndexedDB",
            family=FAMILY_INDEXEDDB,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="no *.leveldb directories present",
        )

    live_count = 0
    hist_count = 0
    ext_blob_count = 0

    for leveldb_dir in leveldb_dirs:
        blob_dir = leveldb_dir.with_name(
            leveldb_dir.name[: -len(".leveldb")] + ".blob"
        )
        blob_present = blob_dir.exists()

        def on_bad(key: Any, buffer: bytes, _dir: Path = leveldb_dir) -> None:
            nonlocal bad_records
            bad_records += 1
            # Preserve the failure rather than dropping the record silently.
            locator = f"leveldb={_dir.name};bad_deserialization={bad_records}"
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(
                        FAMILY_INDEXEDDB, source_path, locator,
                        {"key": to_jsonable(key), "size": len(buffer or b"")},
                    ),
                    artifact="IndexedDB",
                    artifact_family=FAMILY_INDEXEDDB,
                    source_path=source_path,
                    artifact_path=f"{source_path}/{_dir.name}",
                    record_locator=locator,
                    summary="IndexedDB 역직렬화 실패 레코드",
                    attributes={
                        "subtype": "bad_deserialization",
                        "leveldb": _dir.name,
                        "key": to_jsonable(key),
                        "buffer_size": len(buffer or b""),
                        "volume_id": volume_id,
                    },
                )
            )

        def on_store_error(where: str, exc: Exception, _dir: Path = leveldb_dir) -> None:
            errors.append(f"{_dir.name}/{where}: {type(exc).__name__}: {exc}")

        wrapper = None
        try:
            wrapper = ccl.open_indexeddb(leveldb_dir, blob_dir if blob_present else None)
            for rec in ccl.iter_indexeddb_records(wrapper, on_bad, on_store_error):
                if rec.state == STATE_LIVE:
                    live_count += 1
                elif rec.state == STATE_HISTORICAL_OR_DELETED:
                    hist_count += 1
                if rec.external_value_path:
                    ext_blob_count += 1

                kind = classify_idb_key(rec.key_text)
                value_json = to_jsonable(rec.value)
                locator = f"leveldb={leveldb_dir.name};{rec.locator}"
                payload = {
                    "key": rec.key_text,
                    "seq": rec.ldb_seq_no,
                    "state": rec.state,
                    "file": rec.origin_file,
                }
                # The LevelDB file inside <profile>/IndexedDB/<db>.leveldb/.
                leveldb_path = f"{source_path}/{leveldb_dir.name}"
                artifact_path = (
                    f"{leveldb_path}/{rec.origin_file}" if rec.origin_file else leveldb_path
                )

                records.append(
                    EvidenceRecord(
                        evidence_id=make_evidence_id(
                            FAMILY_INDEXEDDB, source_path, locator, payload
                        ),
                        artifact="IndexedDB",
                        artifact_family=FAMILY_INDEXEDDB,
                        source_path=source_path,
                        artifact_path=artifact_path,
                        volume_id=volume_id,
                        record_locator=locator,
                        summary=(
                            f"IndexedDB {rec.database_name}/{rec.object_store} "
                            f"key={truncate(rec.key_text, 60)} [{rec.state}]"
                        ),
                        attributes={
                            "subtype": "indexeddb_record",
                            "leveldb": leveldb_dir.name,
                            "blob_dir": blob_dir.name if blob_present else "",
                            "database": rec.database_name,
                            "object_store": rec.object_store,
                            "origin": rec.origin,
                            "key_text": rec.key_text,
                            "key_kind": kind,
                            "ldb_seq_no": rec.ldb_seq_no,
                            # LIVE / HISTORICAL_OR_DELETED / UNKNOWN. We do not
                            # claim a deletion when CCL cannot distinguish old
                            # values from deletions (spec section 10.4).
                            "record_state": rec.state,
                            "external_value_path": rec.external_value_path,
                            "record_location": rec.record_location,
                            "value": value_json,
                            "volume_id": volume_id,
                        },
                    )
                )
        except Exception as exc:
            errors.append(f"{leveldb_dir.name}: {type(exc).__name__}: {exc}")
        finally:
            ccl.close_indexeddb(wrapper)

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    note = (
        f"live={live_count} historical_or_deleted={hist_count} "
        f"external_blob={ext_blob_count} bad_deserialization={bad_records}"
    )
    return records, ParseStatus(
        artifact="IndexedDB",
        family=FAMILY_INDEXEDDB,
        status=ST_PARTIAL if (bad_records and not errors) else status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors) + bad_records,
        message="; ".join(errors[:5]) or note,
        impact="some object stores unreadable" if errors else "",
    )


# ===========================================================================
# local_storage
# ===========================================================================

"""Local Storage parser (spec section 10.5).

Priority keys: __qk_hint_account_uuid, accountUuid/organizationUuid,
static-composer-draft-data, chat draft, selected model, temporary/incognito
values, logout timestamps, account/membership values.

LevelDB batch timestamps are approximate and are never promoted to a user
action time.
"""

PRIORITY_EXACT = {
    "__qk_hint_account_uuid",
    "rq-cache-confirmed-account",
    "static-composer-draft-data",
    "static-composer-greeting-data-v2",
}

PRIORITY_SUBSTRINGS = (
    "accountuuid",
    "organizationuuid",
    "chat-draft",
    "composer-draft",
    "model_selected",
    "model-selected",
    "incognito",
    "temporary",
    "logout-at",
    "logout_at",
    "analytics_queue",
    "antalytics_queue",
    "membership",
    "onboarding",
    "current_account",
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
    if script_key in PRIORITY_EXACT:
        return True
    k = (script_key or "").lower()
    return any(token in k for token in PRIORITY_SUBSTRINGS)


def _value_text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(value or "")


def _extract_identifiers(text: str) -> dict[str, Any]:
    """Pull account/org identifiers and notable flags from a JSON-ish value."""
    out: dict[str, Any] = {}
    stripped = text.strip()
    if stripped.count("-") == 4 and len(stripped) == 36:
        out["account_uuid"] = stripped.lower()
        return out
    if not stripped or stripped[0] not in "[{":
        return out
    try:
        parsed = json.loads(stripped)
    except Exception:
        return out

    accounts: set[str] = set()
    orgs: set[str] = set()
    flags: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    model_selections: list[dict[str, Any]] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                lk = str(key).lower()
                if lk in ("accountuuid", "account_uuid") and isinstance(value, str):
                    accounts.add(value.lower())
                elif lk in ("organizationuuid", "organization_uuid") and isinstance(value, str):
                    orgs.add(value.lower())
                elif lk == "incognito_mode":
                    flags["incognito_mode"] = value
                elif lk == "is_temporary":
                    flags["is_temporary"] = value
                elif lk in ("model", "previous_model", "selected_model") and isinstance(value, str):
                    flags.setdefault("models", [])
                    if value not in flags["models"]:
                        flags["models"].append(value)
                elif lk == "eventname" and isinstance(value, str):
                    props = (
                        node.get("properties") if isinstance(node.get("properties"), dict) else {}
                    )
                    events.append(
                        {
                            "eventName": value,
                            "eventTimestamp": node.get("eventTimestamp"),
                            "properties": {
                                k: v
                                for k, v in props.items()
                                if k
                                in (
                                    "incognito_mode",
                                    "model",
                                    "previous_model",
                                    "selected_model",
                                    "surface",
                                    "is_temporary",
                                )
                            },
                        }
                    )
                    # An explicit model_selected analytics event carries the
                    # previous -> selected transition, which is the direct
                    # evidence the model-change detector needs.
                    if "model_selected" in value and props.get("previous_model"):
                        model_selections.append(
                            {
                                "eventName": value,
                                "eventTimestamp": node.get("eventTimestamp"),
                                "previous_model": props.get("previous_model"),
                                "model": props.get("model") or props.get("selected_model"),
                                "account_uuid": node.get("accountUuid"),
                                "organization_uuid": node.get("organizationUuid"),
                            }
                        )
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:200]:
                walk(item, depth + 1)

    walk(parsed)
    if len(accounts) == 1:
        out["account_uuid"] = next(iter(accounts))
    elif accounts:
        out["account_uuid_candidates"] = sorted(accounts)
    if len(orgs) == 1:
        out["organization_uuid"] = next(iter(orgs))
    elif orgs:
        out["organization_uuid_candidates"] = sorted(orgs)
    if flags:
        out.update(flags)
    if events:
        out["analytics_events"] = events[:80]
    if model_selections:
        out["model_selection_events"] = model_selections[:40]

    # Draft payloads carry their own updatedAt (ms) and attachment counters.
    if isinstance(parsed, dict):
        for field_name in ("updatedAt", "updated_at"):
            if isinstance(parsed.get(field_name), (int, float)):
                out["updated_at_ms"] = parsed[field_name]
        for field_name in ("attachmentCount", "fileCount", "text"):
            if field_name in parsed:
                out[field_name] = parsed[field_name]
    return out


def parse_local_storage(
    leveldb_dir: Path,
    source_path: str,
    volume_id: str,
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []

    if not leveldb_dir.exists():
        return records, ParseStatus(
            artifact="Local Storage",
            family=FAMILY_LOCAL_STORAGE,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="Local Storage leveldb not staged",
            impact="account hint / draft / analytics evidence unavailable",
        )

    def on_error(where: str, exc: Exception) -> None:
        errors.append(f"{where}: {type(exc).__name__}: {exc}")

    try:
        from . import ccl_adapter as ccl

        for rec in ccl.iter_local_storage(leveldb_dir, on_error):
            if "claude" not in rec.storage_key.lower():
                continue
            text = _value_text(rec.value)
            kind = classify_local_storage_key(rec.script_key)
            priority = is_priority(rec.script_key)
            identifiers = _extract_identifiers(text) if priority else {}

            locator = f"leveldb;{rec.locator}"
            payload = {
                "storage_key": rec.storage_key,
                "script_key": rec.script_key,
                "seq": rec.seq,
                "file": rec.origin_file,
                "value_length": len(text),
            }

            # Draft timestamps come from the payload itself, not from LevelDB
            # batch metadata, which is only approximate (spec section 10.5).
            timestamp = None
            if "updated_at_ms" in identifiers:
                timestamp = from_unix_millis(identifiers["updated_at_ms"])
            elif identifiers.get("analytics_events"):
                first = identifiers["analytics_events"][0]
                timestamp = from_iso8601(first.get("eventTimestamp"))

            attributes: dict[str, Any] = {
                "subtype": "local_storage_record",
                "storage_key": rec.storage_key,
                "script_key": rec.script_key,
                "key_kind": kind,
                "is_priority_key": priority,
                "leveldb_seq_number": rec.seq,
                "value_length": len(text),
                "value_preview": truncate(text, 600),
                "volume_id": volume_id,
                # Approximate only; never used as a user action time.
                "batch_timestamp_is_approximate": True,
            }
            attributes.update(identifiers)

            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(
                        FAMILY_LOCAL_STORAGE, source_path, locator, payload
                    ),
                    artifact="Local Storage",
                    artifact_family=FAMILY_LOCAL_STORAGE,
                    source_path=source_path,
                    # The LevelDB file (.ldb / .log) inside Local Storage/leveldb.
                    artifact_path=(
                        f"{source_path}/{rec.origin_file}" if rec.origin_file else source_path
                    ),
                    volume_id=volume_id,
                    record_locator=locator,
                    timestamp=timestamp,
                    account_uuid=identifiers.get("account_uuid"),
                    organization_uuid=identifiers.get("organization_uuid"),
                    summary=f"Local Storage {rec.storage_key} / {truncate(rec.script_key, 70)}",
                    attributes=attributes,
                )
            )
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="Local Storage",
        family=FAMILY_LOCAL_STORAGE,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5]),
    )


# ===========================================================================
# sessions
# ===========================================================================

"""Sessions/Tabs SNSS parser (spec section 10.6).

NavigationEntry is the supported surface. Commands CCL cannot decode keep only
a raw locator and are never interpreted as user actions. Duplicate commands
inside one SNSS file count as one corroboration (spec section 16.1).
"""

def parse_sessions(
    sessions_dir: Path,
    source_path: str,
    volume_id: str,
    local_tz: dt.tzinfo = KST,
) -> tuple[list[EvidenceRecord], ParseStatus]:
    """Parse Session_*/Tabs_* files.

    SNSS NavigationEntry timestamps are naive local time as written by the
    browser host, so they are interpreted in the examiner-configured local zone
    (KST by default) rather than assumed to be UTC.
    """
    records: list[EvidenceRecord] = []
    errors: list[str] = []
    unprocessed = 0

    if not sessions_dir.exists():
        return records, ParseStatus(
            artifact="Sessions/Tabs",
            family=FAMILY_SESSIONS,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="Sessions directory not staged",
            impact="navigation evidence unavailable",
        )

    files = sorted(
        p
        for p in sessions_dir.iterdir()
        if p.is_file() and (p.name.startswith("Session_") or p.name.startswith("Tabs_"))
    )
    if not files:
        return records, ParseStatus(
            artifact="Sessions/Tabs",
            family=FAMILY_SESSIONS,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="no Session_*/Tabs_* files present",
        )

    def on_error(name: str, exc: Exception) -> None:
        errors.append(f"{name}: {type(exc).__name__}: {exc}")

    for snss_file in files:
        for command in ccl.iter_snss_commands(snss_file, on_error):
            if not command.is_navigation:
                unprocessed += 1
                continue
            if not is_claude_url(command.url) and not is_claude_url(
                command.original_request_url
            ):
                continue

            ts = None
            if isinstance(command.timestamp, dt.datetime):
                ts = ensure_aware(command.timestamp, local_tz)

            locator = command.locator
            payload = {
                "file": command.file_name,
                "index": command.index,
                "url": command.url,
                "original_request_url": command.original_request_url,
                "referrer_url": command.referrer_url,
                "timestamp": str(command.timestamp),
            }
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(FAMILY_SESSIONS, source_path, locator, payload),
                    artifact="Sessions/Tabs",
                    artifact_family=FAMILY_SESSIONS,
                    source_path=f"{source_path}/{command.file_name}",
                    record_locator=locator,
                    timestamp=ts,
                    organization_uuid=organization_from_url(command.url),
                    conversation_uuid=conversation_from_url(command.url)
                    or conversation_from_url(command.original_request_url),
                    summary=f"탭 탐색: {truncate(command.url, 150)}",
                    attributes={
                        "subtype": "navigation_entry",
                        "session_file": command.file_name,
                        "command_ordinal": command.ordinal,
                        "index": command.index,
                        "url": command.url,
                        "original_request_url": command.original_request_url,
                        "referrer_url": command.referrer_url,
                        "title": command.title,
                        "timestamp_source": "snss_navigation_entry",
                        "volume_id": volume_id,
                    },
                )
            )

    # CCL documents SNSS support as partial; we mirror that rather than
    # overstating it (spec section 8).
    status = ST_PARTIAL if records or not errors else ST_FAILED
    return records, ParseStatus(
        artifact="Sessions/Tabs",
        family=FAMILY_SESSIONS,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5])
        or (
            f"CCL SNSS support is partial; NavigationEntry parsed, "
            f"{unprocessed} non-navigation command(s) retained as locators only"
        ),
    )
