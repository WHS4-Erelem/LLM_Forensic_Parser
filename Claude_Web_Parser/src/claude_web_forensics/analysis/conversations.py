"""IndexedDB conversation reconstruction and cache conversation metadata."""
from __future__ import annotations

import collections
import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..model.entities import (
    CONV_CURRENT, CONV_HISTORICAL_OR_DELETED, CONV_UNKNOWN, FAMILY_CACHE, FAMILY_INDEXEDDB,
    FAMILY_LOCAL_STORAGE, STATE_HISTORICAL_OR_DELETED, STATE_LIVE, ConversationMessage, EvidenceRecord,
    EvidenceStore, normalize_role,
)
from ..util.common import from_iso8601

_CONVERSATION_KINDS = ("conversation_api", "conversation_list", "latest_or_snapshot")
_STATE = {STATE_LIVE: CONV_CURRENT, STATE_HISTORICAL_OR_DELETED: CONV_HISTORICAL_OR_DELETED}

_ORGANIZATION_MARKERS = ("capabilities", "billing_type", "organization_type", "rate_limit_tier")

@dataclass
class ConversationInfo:
    conversation_uuid: str
    title: str = ""
    model: str = ""
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
    is_temporary: Any = None
    organization_uuid: str | None = None
    record_state: str = CONV_UNKNOWN
    snapshot_uuid: str = ""
    snapshot_created_at: dt.datetime | None = None

    object_ids: list[str] = field(default_factory=list)
    snapshot_ids: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)
    messages: dict[str, ConversationMessage] = field(default_factory=dict)

@dataclass
class DraftTrace:
    draft_id: str
    text: str
    timestamp: dt.datetime | None
    account_uuid: str | None
    family: str
    evidence_ids: list[str] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    sequence: int | None = None

def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for item in content if isinstance(content, list) else []:
        if isinstance(item, str) and item.strip():
            parts.append(item)
        elif isinstance(item, dict):
            if isinstance(item.get("text"), str) and item["text"].strip():
                parts.append(item["text"])
            if isinstance(item.get("content"), list):
                inner = _content_text(item["content"])
                if inner:
                    parts.append(inner)
    return "\n".join(parts)

def _is_conversation(node: dict[str, Any]) -> bool:
    return (
        isinstance(node.get("uuid") or node.get("conversationUuid"), str)
        and ("chat_messages" in node or "current_leaf_message_uuid" in node
             or ("is_temporary" in node and "created_at" in node))
        and "sender" not in node
        and not any(marker in node for marker in _ORGANIZATION_MARKERS)
    )

def _is_message(node: dict[str, Any]) -> bool:
    return (
        any(isinstance(node.get(k), str) for k in ("uuid", "message_uuid"))
        and node.get("sender", node.get("role")) is not None
    )

def _walk(
    node: Any, owner: str, conversations: list[dict[str, Any]],
    messages: list[tuple[dict[str, Any], str]] | None, depth: int = 0,
) -> None:
    if depth > 14:
        return
    if isinstance(node, dict):
        if _is_conversation(node):
            conversations.append(node)
            owner = (node.get("uuid") or node["conversationUuid"]).lower()
        elif messages is not None and _is_message(node):
            explicit = node.get("conversation_uuid") or node.get("chat_conversation_uuid")
            messages.append((node, str(explicit).lower() if explicit else owner))
        for key, value in node.items():
            if messages is not None or key not in ("chat_messages", "messageByUuid"):
                _walk(value, owner, conversations, messages, depth + 1)
    elif isinstance(node, list):
        for item in node[:1000]:
            _walk(item, owner, conversations, messages, depth + 1)

def _message(obj: dict[str, Any], conversation_uuid: str, model: str) -> ConversationMessage:
    text = _content_text(obj.get("content")) or (obj["text"] if isinstance(obj.get("text"), str) else "")
    return ConversationMessage(
        conversation_uuid=conversation_uuid,
        message_uuid=str(obj.get("uuid") or obj.get("message_uuid")).lower(),
        parent_message_uuid=str(obj.get("parent_message_uuid") or "").lower(),
        timestamp=from_iso8601(obj.get("created_at")),
        role=normalize_role(obj.get("sender", obj.get("role"))), model=str(obj.get("model") or model or ""),
        input_mode=str(obj.get("input_mode") or ""), content=text, attributes={
            "attachments": obj.get("attachments") or [],
            "files": obj.get("files") or obj.get("files_v2") or [],
            "previous_model": obj.get("previous_model"),
            "server_record": "updated_at" in obj,
        },
    )

def _merge(existing: ConversationMessage, incoming: ConversationMessage) -> None:
    # The page first stores its own copy of a message (no updated_at) stamped with the client submit time; the
    # server record that replaces it carries the real created_at. Only that step overrides an earlier value.
    if incoming.timestamp and incoming.attributes["server_record"] and not existing.attributes["server_record"]:
        existing.timestamp = incoming.timestamp
    for name in ("content", "timestamp", "parent_message_uuid", "model", "input_mode"):
        if not getattr(existing, name) and getattr(incoming, name):
            setattr(existing, name, getattr(incoming, name))
    for name in ("evidence_ids", "families"):
        target = getattr(existing, name)
        target.extend(value for value in getattr(incoming, name) if value not in target)
    order = {CONV_CURRENT: 2, CONV_HISTORICAL_OR_DELETED: 1, CONV_UNKNOWN: 0}
    if order[incoming.record_state] > order[existing.record_state]:
        existing.record_state = incoming.record_state
    for key, value in incoming.attributes.items():
        if value and not existing.attributes.get(key):
            existing.attributes[key] = value

class ConversationBuilder:
    def __init__(self) -> None:
        self.conversations: dict[str, ConversationInfo] = {}
        self.drafts: list[DraftTrace] = []

        self.stats: collections.Counter = collections.Counter()

    def ingest(self, store: EvidenceStore) -> None:
        for record in store.by_family(FAMILY_CACHE):
            self._ingest_cache(record)
        for record in store.by_family(FAMILY_INDEXEDDB):
            self._ingest_indexeddb(record)
        for record in store.by_family(FAMILY_LOCAL_STORAGE):
            self._ingest_local_storage_draft(record)

    def _conv(self, uuid: str) -> ConversationInfo:
        return self.conversations.setdefault(uuid, ConversationInfo(conversation_uuid=uuid))

    def _ingest_cache(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        kind = attrs.get("key_kind")
        if kind not in _CONVERSATION_KINDS:
            return
        payload = attrs.get("_json")
        if payload is None:
            self.stats[f"cache:{kind}: no parsed JSON body"] += 1
            return
        key_owner = (record.conversation_uuid or "").lower()
        if kind == "latest_or_snapshot":
            if attrs.get("snapshot_uuid") and key_owner:
                info = self._conv(key_owner)
                info.snapshot_uuid = attrs["snapshot_uuid"]
                info.snapshot_created_at = from_iso8601(attrs.get("snapshot_created_at"))
                info.snapshot_ids.append(record.evidence_id)
                info.families.add(FAMILY_CACHE)
                self.stats[f"cache:{kind}: share snapshot object"] += 1
            return
        self._ingest_payload(record, payload, key_owner, CONV_UNKNOWN, f"cache:{kind}")

    def _ingest_indexeddb(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        kind = attrs.get("key_kind")
        if kind == "chat_draft":
            self._ingest_idb_draft(record)
            return
        value = attrs.get("value")
        state = _STATE.get(attrs.get("record_state"), CONV_UNKNOWN)
        if kind != "react_query_cache":
            if attrs.get("database") == "claude-conversation-store" and attrs.get("object_store") == "trees":
                self._ingest_payload(record, value, "", state, "idb:conversation_store")
            return
        if not isinstance(value, dict):
            self.stats["idb:react_query: tombstone/empty value"] += 1
            return
        for query in (value.get("clientState") or {}).get("queries") or []:
            data = (query.get("state") or {}).get("data") if isinstance(query, dict) else None
            self._ingest_payload(record, data, "", state, "idb:react_query")

    def _ingest_payload(
        self, record: EvidenceRecord, payload: Any, key_owner: str, state: str, source: str
    ) -> None:
        conversations: list[dict[str, Any]] = []
        messages = [] if record.artifact_family == FAMILY_INDEXEDDB else None
        _walk(payload, key_owner, conversations, messages)
        family = record.artifact_family
        self.stats[f"{source}: conversation objects"] += len(conversations)
        self.stats[f"{source}: message objects"] += len(messages or ())
        for meta in conversations:
            info = self._conv((meta.get("uuid") or meta["conversationUuid"]).lower())
            info.families.add(family)
            if record.evidence_id not in info.object_ids:
                info.object_ids.append(record.evidence_id)
            info.title = info.title or str(meta.get("name") or "")
            info.model = info.model or str(meta.get("model") or "")
            info.created_at = info.created_at or from_iso8601(meta.get("created_at"))
            info.updated_at = info.updated_at or from_iso8601(meta.get("updated_at"))
            if info.is_temporary is None and meta.get("is_temporary") is not None:
                info.is_temporary = meta.get("is_temporary")
            info.organization_uuid = info.organization_uuid or record.organization_uuid
            if state == CONV_CURRENT or info.record_state == CONV_UNKNOWN:
                info.record_state = state
        for obj, owner in messages or ():
            if not owner:
                self.stats[f"{source}: message dropped (owner conversation unknown)"] += 1
                continue
            info = self._conv(owner)
            info.families.add(family)
            message = _message(obj, owner, info.model)
            message.record_state = state
            message.evidence_ids.append(record.evidence_id)
            message.families.append(family)
            existing = info.messages.get(message.message_uuid)
            if existing is None:
                info.messages[message.message_uuid] = message
            else:
                _merge(existing, message)
            self.stats[f"{source}: message kept"] += 1

    def _ingest_idb_draft(self, record: EvidenceRecord) -> None:
        value = record.attributes.get("value")
        state = value.get("state") if isinstance(value, dict) else None
        text = _draft_text((state or {}).get("tipTapEditorState")) if isinstance(state, dict) else ""
        attachments = []
        if isinstance(state, dict):
            attachments = [a for a in (state.get("attachments") or []) + (state.get("files") or [])
                           if isinstance(a, dict)]
        self.drafts.append(
            DraftTrace(
                draft_id=str(record.attributes.get("key_text") or record.evidence_id),
                text=text, timestamp=record.timestamp, account_uuid=record.account_uuid,
                family=FAMILY_INDEXEDDB, evidence_ids=[record.evidence_id],
                attachments=attachments, sequence=record.attributes.get("ldb_seq_no"),
            )
        )

    def _ingest_local_storage_draft(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        if attrs.get("script_key") != "static-composer-draft-data":
            return
        text = attrs.get("text")
        self.drafts.append(
            DraftTrace(
                draft_id="static-composer-draft-data", text=text if isinstance(text, str) else "",
                timestamp=record.timestamp, account_uuid=record.account_uuid,
                family=FAMILY_LOCAL_STORAGE, evidence_ids=[record.evidence_id],
                sequence=attrs.get("leveldb_seq_number"),
            )
        )

    def draft_compositions(self) -> list[list[DraftTrace]]:
        by_key: dict[tuple[str, str], list[DraftTrace]] = collections.defaultdict(list)
        for draft in self.drafts:
            by_key[(draft.family, draft.draft_id)].append(draft)
        groups: list[list[DraftTrace]] = []
        for versions in by_key.values():
            versions.sort(key=lambda d: (d.sequence is None, d.sequence or 0))
            current: list[DraftTrace] = []
            for draft in versions:
                text = draft.text.strip()
                if current and (not text or not _continues(current[-1].text.strip(), text)):
                    groups.append(current)
                    current = []
                if text:
                    current.append(draft)
            if current:
                groups.append(current)
        return groups

    def all_messages(self) -> list[ConversationMessage]:
        out: list[ConversationMessage] = []
        for info in self.conversations.values():
            for message in info.messages.values():
                message.conversation_title = message.conversation_title or info.title
                out.append(message)
        return out

    def summary_lines(self) -> list[str]:
        with_messages = sum(1 for i in self.conversations.values() if i.messages)
        lines = [
            f"conversations: objects={sum(1 for i in self.conversations.values() if i.object_ids)} "
            f"with_messages={with_messages} messages={len(self.all_messages())} "
            f"snapshots={sum(1 for i in self.conversations.values() if i.snapshot_uuid)} "
            f"draft_versions={len(self.drafts)} draft_compositions={len(self.draft_compositions())}"
        ]
        lines += [f"conversation source {k}: {v}" for k, v in sorted(self.stats.items())]
        return lines

def _continues(previous: str, text: str) -> bool:
    shared = 0
    for a, b in zip(previous, text):
        if a != b:
            break
        shared += 1
    return shared >= max(1, min(len(previous), len(text)) // 2)

def _draft_text(node: Any, depth: int = 0) -> str:
    if depth > 10:
        return ""
    if isinstance(node, dict):
        if node.get("type") == "text" and isinstance(node.get("text"), str):
            return node["text"]
        return _draft_text(node.get("content"), depth + 1)
    if isinstance(node, list):
        parts = [_draft_text(item, depth + 1) for item in node[:200]]
        return ("\n" if depth <= 1 else "").join(p for p in parts if p)
    return ""

def draft_attachment_names(drafts: Iterable[DraftTrace]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for draft in drafts:
        for item in draft.attachments:
            name = item.get("file_name") or item.get("fileName") or item.get("name")
            if isinstance(name, str) and name:
                out.append((name, item))
    return out
