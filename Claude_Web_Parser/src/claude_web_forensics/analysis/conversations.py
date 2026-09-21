"""Conversation reconstruction (spec section 14).

Source priority: Cache conversation API -> IndexedDB conversation tree ->
IndexedDB message cache. Local Storage drafts are kept SEPARATE from sent
messages. Messages merge on message_uuid first; different message UUIDs are
never de-duplicated even when their text is identical, so human-edit and
assistant-retry branches survive.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..model.entities import (
    FAMILY_CACHE,
    FAMILY_INDEXEDDB,
    STATE_HISTORICAL_OR_DELETED,
    STATE_LIVE,
    EvidenceRecord,
    EvidenceStore,
)
from ..model.entities import (
    CONV_CURRENT,
    CONV_HISTORICAL_OR_DELETED,
    CONV_UNKNOWN,
    ConversationMessage,
    normalize_role,
)
from ..util.common import stable_key
from ..util.common import from_iso8601

ROOT_PARENT = "00000000-0000-4000-8000-000000000000"


@dataclass
class ConversationInfo:
    conversation_uuid: str
    title: str = ""
    model: str = ""
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
    is_temporary: Any = None
    organization_uuid: str | None = None
    account_uuid: str | None = None
    record_state: str = CONV_UNKNOWN
    snapshot_uuid: str = ""
    snapshot_created_at: dt.datetime | None = None
    snapshot_name: str = ""
    families: set[str] = field(default_factory=set)
    evidence_ids: list[str] = field(default_factory=list)
    messages: dict[str, ConversationMessage] = field(default_factory=dict)

    @property
    def root_messages(self) -> list[ConversationMessage]:
        return [
            m
            for m in self.messages.values()
            if not m.parent_message_uuid or m.parent_message_uuid == ROOT_PARENT
        ]

    def children_of(self, message_uuid: str) -> list[ConversationMessage]:
        return [m for m in self.messages.values() if m.parent_message_uuid == message_uuid]


@dataclass
class DraftTrace:
    """Composer draft evidence. NEVER treated as a sent message."""

    draft_id: str
    text: str
    timestamp: dt.datetime | None
    account_uuid: str | None
    conversation_uuid: str | None
    attachment_count: Any
    file_count: Any
    family: str
    evidence_ids: list[str] = field(default_factory=list)


def _content_text(content: Any) -> str:
    """Flatten a Claude message content array to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str) and item.strip():
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text)
                nested = item.get("content")
                if isinstance(nested, list):
                    inner = _content_text(nested)
                    if inner:
                        parts.append(inner)
        return "\n".join(parts)
    return ""


def _message_from_object(
    obj: dict[str, Any], conversation_uuid: str, default_model: str = ""
) -> ConversationMessage | None:
    uuid = obj.get("uuid") or obj.get("id") or obj.get("message_uuid")
    sender = obj.get("sender") or obj.get("role") or obj.get("author")
    if not uuid or sender is None:
        return None
    text = _content_text(obj.get("content"))
    if not text and isinstance(obj.get("text"), str):
        text = obj["text"]
    return ConversationMessage(
        conversation_uuid=conversation_uuid,
        message_uuid=str(uuid).lower(),
        parent_message_uuid=str(obj.get("parent_message_uuid") or "").lower(),
        timestamp=from_iso8601(obj.get("created_at") or obj.get("timestamp")),
        role=normalize_role(sender),
        model=str(obj.get("model") or default_model or ""),
        input_mode=str(obj.get("input_mode") or ""),
        content=text,
        attributes={
            "index": obj.get("index"),
            "stop_reason": obj.get("stop_reason"),
            "attachments": obj.get("attachments") or [],
            "files": obj.get("files") or [],
            "updated_at": obj.get("updated_at"),
            "previous_model": obj.get("previous_model"),
        },
    )


def _walk_messages(
    node: Any,
    out: list[tuple[dict[str, Any], str]],
    depth: int = 0,
    conversation: str = "",
) -> None:
    """Find message dicts, remembering which conversation object encloses each.

    A react-query cache entry can hold messages for SEVERAL conversations. Each
    message must stay attached to its own conversation, otherwise unrelated
    root messages collapse into one conversation and fabricate edit branches.
    """
    if depth > 14:
        return
    if isinstance(node, dict):
        # Entering a conversation object switches the active context.
        context = conversation
        if isinstance(node.get("uuid"), str) and (
            "chat_messages" in node or "current_leaf_message_uuid" in node
        ):
            context = str(node["uuid"]).lower()

        has_id = any(k in node for k in ("uuid", "message_uuid"))
        has_sender = any(k in node for k in ("sender", "role", "author"))
        if has_id and has_sender:
            explicit = node.get("conversation_uuid") or node.get("chat_conversation_uuid")
            out.append((node, str(explicit).lower() if explicit else context))
        for value in node.values():
            _walk_messages(value, out, depth + 1, context)
    elif isinstance(node, list):
        for item in node[:500]:
            _walk_messages(item, out, depth + 1, conversation)


def _merge(existing: ConversationMessage, incoming: ConversationMessage) -> ConversationMessage:
    """Merge two observations of the SAME message_uuid."""
    if not existing.content and incoming.content:
        existing.content = incoming.content
    if existing.timestamp is None:
        existing.timestamp = incoming.timestamp
    if not existing.parent_message_uuid:
        existing.parent_message_uuid = incoming.parent_message_uuid
    if not existing.model:
        existing.model = incoming.model
    if not existing.input_mode:
        existing.input_mode = incoming.input_mode
    if not existing.account_uuid:
        existing.account_uuid = incoming.account_uuid
    if not existing.organization_uuid:
        existing.organization_uuid = incoming.organization_uuid
    if not existing.conversation_title:
        existing.conversation_title = incoming.conversation_title
    for eid in incoming.evidence_ids:
        if eid not in existing.evidence_ids:
            existing.evidence_ids.append(eid)
    for fam in incoming.families:
        if fam not in existing.families:
            existing.families.append(fam)
    # CURRENT beats UNKNOWN; a historical observation never downgrades a live one.
    order = {CONV_CURRENT: 2, CONV_HISTORICAL_OR_DELETED: 1, CONV_UNKNOWN: 0}
    if order.get(incoming.record_state, 0) > order.get(existing.record_state, 0):
        existing.record_state = incoming.record_state
    for key, value in incoming.attributes.items():
        existing.attributes.setdefault(key, value)
    return existing


def _fallback_key(message: ConversationMessage) -> str:
    """Join key when no message UUID exists (spec section 14, priority 3)."""
    return "MSG-" + stable_key(
        {
            "conversation": message.conversation_uuid,
            "role": message.role,
            "timestamp": message.timestamp.isoformat() if message.timestamp else "",
            "content": message.content.strip(),
        }
    )


class ConversationBuilder:
    def __init__(self) -> None:
        self.conversations: dict[str, ConversationInfo] = {}
        self.drafts: list[DraftTrace] = []

    # -- ingestion -------------------------------------------------------
    def ingest(self, store: EvidenceStore) -> None:
        for record in store.by_family(FAMILY_CACHE):
            self._ingest_cache(record)
        for record in store.by_family(FAMILY_INDEXEDDB):
            self._ingest_indexeddb(record)

    def _conv(self, uuid: str) -> ConversationInfo:
        return self.conversations.setdefault(uuid, ConversationInfo(conversation_uuid=uuid))

    def _ingest_cache(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        payload = attrs.get("_json")
        conv_uuid = (attrs.get("conversation_uuid") or record.conversation_uuid or "").lower()
        kind = attrs.get("key_kind")

        # Share snapshot object (E07-02 direct evidence).
        if attrs.get("snapshot_uuid"):
            target = (attrs.get("snapshot_conversation_uuid") or conv_uuid or "").lower()
            if target:
                info = self._conv(target)
                info.snapshot_uuid = str(attrs["snapshot_uuid"])
                info.snapshot_name = str(attrs.get("snapshot_name") or "")
                info.snapshot_created_at = from_iso8601(attrs.get("snapshot_created_at"))
                info.families.add(FAMILY_CACHE)
                if record.evidence_id not in info.evidence_ids:
                    info.evidence_ids.append(record.evidence_id)

        if not conv_uuid or payload is None:
            return
        if kind not in ("conversation_api", "latest_or_snapshot", "conversation_list"):
            return

        info = self._conv(conv_uuid)
        info.families.add(FAMILY_CACHE)
        if record.evidence_id not in info.evidence_ids:
            info.evidence_ids.append(record.evidence_id)
        info.title = info.title or str(attrs.get("conversation_title") or "")
        info.model = info.model or str(attrs.get("conversation_model") or "")
        info.created_at = info.created_at or from_iso8601(attrs.get("conversation_created_at"))
        info.updated_at = info.updated_at or from_iso8601(attrs.get("conversation_updated_at"))
        if attrs.get("is_temporary") is not None and info.is_temporary is None:
            info.is_temporary = attrs.get("is_temporary")
        info.organization_uuid = info.organization_uuid or record.organization_uuid
        info.account_uuid = info.account_uuid or attrs.get("account_uuid")
        # Cache alone cannot prove the conversation still exists server-side.
        if info.record_state == CONV_UNKNOWN:
            info.record_state = CONV_UNKNOWN

        found: list[tuple[dict[str, Any], str]] = []
        _walk_messages(payload, found, conversation=conv_uuid)
        for obj, owner in found:
            # A conversation-list body carries many conversations; attribute
            # each message to its own, never to the cache key's conversation.
            target = owner or conv_uuid
            if target != conv_uuid:
                continue
            message = _message_from_object(obj, conv_uuid, info.model)
            if message is None:
                continue
            message.conversation_title = info.title
            message.organization_uuid = info.organization_uuid
            message.account_uuid = info.account_uuid
            message.is_temporary = "" if info.is_temporary is None else str(info.is_temporary)
            message.record_state = CONV_UNKNOWN
            message.evidence_ids.append(record.evidence_id)
            message.families.append(FAMILY_CACHE)
            self._add_message(info, message)

    def _ingest_indexeddb(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        if attrs.get("key_kind") == "chat_draft":
            self._ingest_draft(record)
            return
        if attrs.get("key_kind") != "react_query_cache":
            return
        value = attrs.get("value")
        if value is None:
            return

        state = attrs.get("record_state")
        conv_state = (
            CONV_CURRENT
            if state == STATE_LIVE
            else CONV_HISTORICAL_OR_DELETED
            if state == STATE_HISTORICAL_OR_DELETED
            else CONV_UNKNOWN
        )

        # Conversation metadata objects.
        for meta in _find_conversation_objects(value):
            uuid = str(meta.get("uuid") or "").lower()
            if not uuid:
                continue
            info = self._conv(uuid)
            info.families.add(FAMILY_INDEXEDDB)
            if record.evidence_id not in info.evidence_ids:
                info.evidence_ids.append(record.evidence_id)
            info.title = info.title or str(meta.get("name") or "")
            info.model = info.model or str(meta.get("model") or "")
            info.created_at = info.created_at or from_iso8601(meta.get("created_at"))
            info.updated_at = info.updated_at or from_iso8601(meta.get("updated_at"))
            if meta.get("is_temporary") is not None and info.is_temporary is None:
                info.is_temporary = meta.get("is_temporary")
            if conv_state == CONV_CURRENT:
                info.record_state = CONV_CURRENT
            elif info.record_state == CONV_UNKNOWN:
                info.record_state = conv_state

        # Messages inside the react-query cache.
        found: list[tuple[dict[str, Any], str]] = []
        _walk_messages(value, found)
        if not found:
            return
        for obj, owner in found:
            uuid = str(obj.get("uuid") or obj.get("message_uuid") or "").lower()
            if not uuid:
                continue
            # Only the enclosing conversation object may claim a message. With
            # no enclosing context we fall back to a conversation that already
            # holds this exact message UUID, and otherwise skip it rather than
            # guessing an owner.
            target = owner or _owning_conversation(self.conversations, uuid)
            if not target:
                continue
            info = self._conv(target)
            info.families.add(FAMILY_INDEXEDDB)
            message = _message_from_object(obj, target, info.model)
            if message is None:
                continue
            message.conversation_title = info.title
            message.organization_uuid = info.organization_uuid
            message.account_uuid = info.account_uuid
            message.is_temporary = "" if info.is_temporary is None else str(info.is_temporary)
            message.record_state = conv_state
            message.evidence_ids.append(record.evidence_id)
            message.families.append(FAMILY_INDEXEDDB)
            self._add_message(info, message)

    def _ingest_draft(self, record: EvidenceRecord) -> None:
        attrs = record.attributes
        value = attrs.get("value") or {}
        text = _draft_text(value)
        if not text:
            return
        key_text = str(attrs.get("key_text") or "")
        conv = key_text.split(":")[-1] if key_text.count(":") >= 2 else ""
        self.drafts.append(
            DraftTrace(
                draft_id=key_text or record.evidence_id,
                text=text,
                timestamp=record.timestamp,
                account_uuid=record.account_uuid,
                conversation_uuid=conv if len(conv) == 36 else None,
                attachment_count=_deep_get(value, "attachments"),
                file_count=_deep_get(value, "files"),
                family=FAMILY_INDEXEDDB,
                evidence_ids=[record.evidence_id],
            )
        )

    def _add_message(self, info: ConversationInfo, message: ConversationMessage) -> None:
        key = message.message_uuid or _fallback_key(message)
        existing = info.messages.get(key)
        if existing is None:
            info.messages[key] = message
        else:
            _merge(existing, message)

    # -- drafts from Local Storage --------------------------------------
    def ingest_local_storage_drafts(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            attrs = record.attributes
            if attrs.get("script_key") != "static-composer-draft-data":
                continue
            text = attrs.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            self.drafts.append(
                DraftTrace(
                    draft_id=f"local_storage:{attrs.get('leveldb_seq_number')}",
                    text=text,
                    timestamp=record.timestamp,
                    account_uuid=record.account_uuid,
                    conversation_uuid=None,
                    attachment_count=attrs.get("attachmentCount"),
                    file_count=attrs.get("fileCount"),
                    family=record.artifact_family,
                    evidence_ids=[record.evidence_id],
                )
            )

    def all_messages(self) -> list[ConversationMessage]:
        out: list[ConversationMessage] = []
        for info in self.conversations.values():
            for message in info.messages.values():
                message.conversation_title = message.conversation_title or info.title
                out.append(message)
        return out


def _find_conversation_objects(node: Any, depth: int = 0) -> list[dict[str, Any]]:
    """Dicts that look like conversation metadata (uuid + name + created_at)."""
    out: list[dict[str, Any]] = []
    if depth > 12:
        return out
    if isinstance(node, dict):
        if (
            isinstance(node.get("uuid"), str)
            and "name" in node
            and ("created_at" in node or "updated_at" in node)
            and "sender" not in node
            and not _looks_like_organization(node)
        ):
            out.append(node)
        for value in node.values():
            out.extend(_find_conversation_objects(value, depth + 1))
    elif isinstance(node, list):
        for item in node[:500]:
            out.extend(_find_conversation_objects(item, depth + 1))
    return out


# Organization objects share the uuid/name/created_at shape but are not
# conversations; these keys only ever appear on an organization.
_ORGANIZATION_MARKERS = (
    "capabilities",
    "billing_type",
    "organization_type",
    "rate_limit_tier",
    "raven_settings",
    "api_disabled_reason",
)


def _looks_like_organization(node: dict[str, Any]) -> bool:
    return any(marker in node for marker in _ORGANIZATION_MARKERS)


def _conversation_hint(node: Any, depth: int = 0) -> str:
    """A react-query entry usually carries the conversation uuid at its root."""
    if depth > 8:
        return ""
    if isinstance(node, dict):
        if isinstance(node.get("uuid"), str) and "chat_messages" in node:
            return str(node["uuid"]).lower()
        for value in node.values():
            found = _conversation_hint(value, depth + 1)
            if found:
                return found
    elif isinstance(node, list):
        for item in node[:200]:
            found = _conversation_hint(item, depth + 1)
            if found:
                return found
    return ""


def _owning_conversation(
    conversations: dict[str, ConversationInfo], message_uuid: str
) -> str:
    for uuid, info in conversations.items():
        if message_uuid in info.messages:
            return uuid
    return ""


def _draft_text(value: Any, depth: int = 0) -> str:
    if depth > 10:
        return ""
    if isinstance(value, dict):
        if value.get("type") == "text" and isinstance(value.get("text"), str):
            return value["text"]
        for child in value.values():
            found = _draft_text(child, depth + 1)
            if found:
                return found
    elif isinstance(value, list):
        parts = [_draft_text(item, depth + 1) for item in value[:100]]
        joined = "\n".join(p for p in parts if p)
        if joined:
            return joined
    return ""


def _deep_get(value: Any, key: str, depth: int = 0) -> Any:
    if depth > 8:
        return None
    if isinstance(value, dict):
        if key in value:
            found = value[key]
            return len(found) if isinstance(found, list) else found
        for child in value.values():
            result = _deep_get(child, key, depth + 1)
            if result is not None:
                return result
    elif isinstance(value, list):
        for item in value[:100]:
            result = _deep_get(item, key, depth + 1)
            if result is not None:
                return result
    return None
