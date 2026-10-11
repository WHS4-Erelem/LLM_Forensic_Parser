"""복구된 Cache 대화 응답 → RecoveredConversation / RecoveredMessage."""
from __future__ import annotations
import argparse
import copy
import csv
import gc
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from ..detectors.common import CHATGPT_HOST, _CONVERSATION_PATH, _is_history_download, _record_key, _record_url, match_history_url
from ..models import RecoveredConversation, RecoveredMessage
from ..utils import normalize_timestamp


# 한계: 서로 다른 Artifact 의 근거를 시각으로 묶는 Evidence Correlation 은 하지 않는다.
# nextauth.message·accountSwitchSessions Record 도 LOGOUT·ACCOUNT_SWITCH 결과에 자동 연결하지 않는다
# (시간이 가깝다는 것만으로는 같은 행위라고 볼 근거가 되지 않기 때문이다).


# ---- Conversation Residue Extraction -------------------------------------------------------------
# ArtifactRecord → RecoveredConversation(recovery_status="RESIDUAL_ONLY"). 파일을 읽지 않고, 사용자 행위를 판정하지 않는다.
#   - 입력: Local Storage conversation-history PUT Record 의 conversation_items (id·title·create_time·update_time 만)
#   - 같은 (os_user, browser_profile, 대화 ID) 의 여러 버전은 대화 1건으로 묶고 source_artifacts 에 버전별 위치·값을 모두 남긴다.
#     버전마다 값이 다르면 하나를 고르지 않고 대화 필드를 None + RESIDUAL_VALUE_CONFLICT:<필드> warning
#     (sequence 가 크면 나중에 기록된 값이지만, 그 값을 "진짜"로 볼 근거는 확인되지 않음).
#   - DELETE operation 은 대화를 만들거나 없애지 않는다 (Record 로만 남음). CONVERSATION_DELETE 판정 없음.
#   - 이 경로는 messages 를 항상 [] 로 둔다. 메시지 본문 복구는 아래 Cache 대화 응답 경로가 한다.
#   - History /c/<id> 방문과는 같은 os_user·browser_profile 에서 ID 가 정확히 같을 때만 correlated_record_ids 로 연결한다.
#     시간이 가깝다는 이유로 연결하지 않는다.

RESIDUAL_MULTIPLE_VERSIONS = "MULTIPLE_RESIDUAL_VERSIONS"
RESIDUAL_VALUE_CONFLICT = "RESIDUAL_VALUE_CONFLICT"
_RESIDUE_CREATE_TIME_SOURCE = "LocalStorage.conversation-history.value.pages[].items[].create_time"


def _history_conversation_links(records: list[ArtifactRecord]) -> dict[tuple[str | None, str | None, str], list[str]]:
    """(os_user, browser_profile, History /c/<id> 의 id) → History record_id 목록. ID 정확히 일치로만 연결한다.

    visits 의 방문 URL 과 downloads 의 tab_url (다운로드를 실행한 탭) 을 같은 기준으로 연결한다.
    """
    links: dict[tuple[str | None, str | None, str], list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for record in records:
        if record.artifact_type != "history" or _record_key(record) in seen:
            continue
        seen.add(_record_key(record))
        url = record.observed.get("tab_url") if _is_history_download(record) else _record_url(record)
        match, path = match_history_url(url, CHATGPT_HOST, _CONVERSATION_PATH)
        if match is not None:
            links.setdefault((record.os_user, record.browser_profile, path.group(1)), []).append(record.record_id)
    return links


def extract_conversation_residue(
    records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = (),
) -> list[RecoveredConversation]:
    sha_by_source = {coverage.source_path: coverage.source_sha256 for coverage in coverages}
    history_links = _history_conversation_links(records)

    residue_records: dict[str, ArtifactRecord] = {}
    for record in records:
        observed = record.observed
        if (record.artifact_type == "local_storage" and observed.get("key_kind") == "conversation_history"
                and observed.get("operation") == "PUT"):
            residue_records.setdefault(record.record_id, record)
    ordered = sorted(residue_records.values(), key=lambda r: (
        r.os_user or "", r.browser_profile or "", r.observed.get("sequence", -1), r.source_path, r.record_id))

    versions: dict[tuple[str | None, str | None, str], list[tuple[ArtifactRecord, dict[str, Any]]]] = {}
    for record in ordered:
        for item in record.observed.get("conversation_items") or []:
            conversation_id = item.get("id")
            if isinstance(conversation_id, str) and conversation_id:
                versions.setdefault((record.os_user, record.browser_profile, conversation_id), []).append((record, item))

    conversations: list[RecoveredConversation] = []
    for (os_user, browser_profile, conversation_id), found in versions.items():
        warnings = [RESIDUAL_MULTIPLE_VERSIONS] if len(found) > 1 else []
        values: dict[str, str | None] = {}
        for name in ("title", "create_time"):
            distinct = {item.get(name) for _, item in found}
            if len(distinct) > 1:
                warnings.append(f"{RESIDUAL_VALUE_CONFLICT}:{name}")
                values[name] = None
            else:
                values[name] = distinct.pop()
        create_time: dict[str, Any] = {}
        if values["create_time"] is not None:
            normalized = normalize_timestamp(values["create_time"], "iso_utc", _RESIDUE_CREATE_TIME_SOURCE)
            warnings += normalized.pop("warnings")
            create_time = {key.replace("timestamp_", "create_time_"): value for key, value in normalized.items()}
        conversations.append(RecoveredConversation(
            conversation_id=conversation_id, title=values["title"], recovery_status="RESIDUAL_ONLY", messages=[],
            source_artifacts=[{
                "artifact_type": record.artifact_type, "source_path": record.source_path,
                "record_location": f"{record.record_location} page={item['page_index']} item={item['item_index']}",
                "source_sha256": sha_by_source.get(record.source_path), "record_id": record.record_id,
                "sequence": record.observed.get("sequence"), "operation": record.observed.get("operation"),
                "title": item.get("title"), "create_time": item.get("create_time"), "update_time": item.get("update_time"),
            } for record, item in found],
            correlated_record_ids=history_links.get((os_user, browser_profile, conversation_id), []),
            warnings=warnings, **create_time,
        ))
    return conversations


# ---- Conversation Message Extraction (Cache 대화 API 응답) -------------------------------------------
# Cache Record 의 observed["conversation"] → RecoveredConversation + RecoveredMessage[]. 파일을 읽지 않고, 행위를 판정하지 않는다.
# 2026-09-15 실제 응답 (6a86d3ee-…) 에서 확인한 구조를 기준으로 한다:
#   mapping{node_id: {id, parent, children[], message|null}}, 루트 노드 message=null, children 순서 보존, 분기 있음
#   (같은 부모의 user 2개 / assistant 2개 (metadata.message_type next·variant) / tool 2개).
#   message: author.role (user / assistant / tool), create_time = JSON 소수 초, content.content_type 별 본문 필드가 다르다.
# 순서: 루트부터 children 순서대로 전위 탐색한 순번을 sequence_index 로 쓴다. 분기는 이어서 나열되고 하나를 고르지 않는다
#   → 분기 구분은 parent_message_id 로 한다 (같은 parent 를 가진 메시지 = 분기). create_time 정렬로 순서를 만들지 않는다.
# 본문: 아래 표의 필드만 content 로 쓴다. parts 의 문자열이 여러 개면 "\n" 으로 이어 붙이고 MESSAGE_PARTS_JOINED.
#   문자열이 아닌 part (이미지 asset 등) 나 본문 외 문자열 필드 (summary 등) 가 있으면 PARTIAL + warning (원본은 Record 에 남음).
#   표에 없는 content_type → content None, PARTIAL.
# 상태: 모든 메시지 RECOVERED 면 대화 RECOVERED, 하나라도 PARTIAL 이면 PARTIAL. "대화 전체가 완전하다"는 뜻이 아니다.
# 같은 (os_user, browser_profile, conversation_id) 에 본문이 같은 응답이 여러 Source 에 있으면 대화 1건 + source_artifacts 여러 개.
#   본문이 다르면 따로 만들고 CACHE_MULTIPLE_RESPONSE_VERSIONS. URL id 와 JSON conversation_id 가 다르면 JSON 값 + warning.
# Local Storage 잔존 대화와 ID 가 같아도 합치지 않는다 (별도 항목). History 연결은 ID 정확히 일치만.

CACHE_CONVERSATION_ID_MISMATCH = "CACHE_CONVERSATION_ID_MISMATCH"
CACHE_MULTIPLE_RESPONSE_VERSIONS = "CACHE_MULTIPLE_RESPONSE_VERSIONS"
CONVERSATION_BRANCHES = "CONVERSATION_BRANCHES"
CONVERSATION_TREE_INCOMPLETE = "CONVERSATION_TREE_INCOMPLETE"
MESSAGE_PARTS_JOINED = "MESSAGE_PARTS_JOINED"
MESSAGE_NON_TEXT_PARTS = "MESSAGE_NON_TEXT_PARTS"
MESSAGE_FIELDS_NOT_IN_CONTENT = "MESSAGE_FIELDS_NOT_IN_CONTENT"
MESSAGE_CONTENT_NOT_TEXT = "MESSAGE_CONTENT_NOT_TEXT"
MESSAGE_CONTENT_TYPE_NOT_SUPPORTED = "MESSAGE_CONTENT_TYPE_NOT_SUPPORTED"
_CACHE_MESSAGE_TIME_SOURCE = "Cache.conversation.mapping[].message.create_time"
_CACHE_CONVERSATION_TIME_SOURCE = "Cache.conversation.create_time"
# content_type → 본문 필드 (2026-09-15 실제 응답에서 관찰한 형태)
_MESSAGE_TEXT_FIELDS = {"text": "parts", "multimodal_text": "parts", "code": "text", "execution_output": "text",
                        "reasoning_recap": "content", "tether_browsing_display": "result"}


def _json_time(value: Any, source: str) -> dict[str, Any] | None:
    """JSON 숫자 초 → S2 normalize_timestamp. 소수는 repr() 문자열 (JSON 에 기록된 숫자와 같은 값) 로 넘긴다."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float):
        return normalize_timestamp(repr(value), "unix_s_decimal", source)
    if isinstance(value, int):
        return normalize_timestamp(value, "unix_s", source)
    return normalize_timestamp(value, "iso_utc" if isinstance(value, str) else "unknown", source)


def _message_content(content: Any) -> tuple[str | None, str | None, str, list[str]]:
    """(content, content_type, recovery_status, warnings)."""
    if not isinstance(content, dict):
        return None, None, "PARTIAL", [MESSAGE_CONTENT_NOT_TEXT]
    content_type = content.get("content_type") if isinstance(content.get("content_type"), str) else None
    field_name = _MESSAGE_TEXT_FIELDS.get(content_type)
    if field_name is None:
        return None, content_type, "PARTIAL", [f"{MESSAGE_CONTENT_TYPE_NOT_SUPPORTED}:{content_type}"]
    value, warnings, text = content.get(field_name), [], None
    if field_name == "parts" and isinstance(value, list):
        texts = [part for part in value if isinstance(part, str)]
        if len(texts) != len(value):
            warnings.append(f"{MESSAGE_NON_TEXT_PARTS}:{len(value) - len(texts)}")
        if len(texts) > 1:
            warnings.append(MESSAGE_PARTS_JOINED)
        text = "\n".join(texts) if texts else None
    elif isinstance(value, str):
        text = value
    if text is None and not warnings:
        warnings.append(MESSAGE_CONTENT_NOT_TEXT)
    others = sorted(name for name, other in content.items()
                    if name not in ("content_type", "language", field_name) and isinstance(other, str) and other)
    if others:
        warnings.append(f"{MESSAGE_FIELDS_NOT_IN_CONTENT}:{','.join(others)}")
    recovered = text is not None and all(warning == MESSAGE_PARTS_JOINED for warning in warnings)
    return text, content_type, "RECOVERED" if recovered else "PARTIAL", warnings


def _ordered_nodes(nodes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """루트부터 children 순서대로 전위 탐색. (순서대로 나열한 노드, 도달하지 못한 노드가 있었는지)."""
    by_id = {node["node_id"]: node for node in nodes}
    order: list[dict[str, Any]] = []
    visited: set[str] = set()
    stack = [node for node in reversed(nodes) if node.get("parent") not in by_id]
    while stack:
        node = stack.pop()
        if node["node_id"] in visited:
            continue
        visited.add(node["node_id"])
        order.append(node)
        children = node.get("children") if isinstance(node.get("children"), list) else []
        stack.extend(by_id[child] for child in reversed(children) if child in by_id and child not in visited)
    missing = [node for node in nodes if node["node_id"] not in visited]
    return order + missing, bool(missing)


def extract_cache_conversations(
    records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = (),
) -> list[RecoveredConversation]:
    history_links = _history_conversation_links(records)
    groups: dict[tuple[str | None, str | None, str, str], list[ArtifactRecord]] = {}
    for record in sorted({r.record_id: r for r in records}.values(), key=lambda r: (r.source_path, r.record_id)):
        conversation = record.observed.get("conversation") if record.artifact_type == "cache" else None
        if not isinstance(conversation, dict):
            continue
        json_id = conversation.get("conversation_id")
        conversation_id = json_id if isinstance(json_id, str) and json_id else record.observed.get("url_conversation_id")
        key = (record.os_user, record.browser_profile, conversation_id, record.observed.get("decoded_sha256") or "")
        groups.setdefault(key, []).append(record)
    versions: dict[tuple[str | None, str | None, str], int] = {}
    for os_user, browser_profile, conversation_id, _ in groups:
        versions[(os_user, browser_profile, conversation_id)] = versions.get((os_user, browser_profile, conversation_id), 0) + 1

    conversations: list[RecoveredConversation] = []
    for (os_user, browser_profile, conversation_id, _), found in groups.items():
        record = found[0]
        data = record.observed["conversation"]
        warnings: list[str] = []
        if versions[(os_user, browser_profile, conversation_id)] > 1:
            warnings.append(CACHE_MULTIPLE_RESPONSE_VERSIONS)
        if any(r.observed.get("url_conversation_id") != conversation_id for r in found):
            warnings.append(CACHE_CONVERSATION_ID_MISMATCH)
        nodes = [node for node in data.get("mapping") or [] if isinstance(node, dict) and isinstance(node.get("node_id"), str)]
        ordered, incomplete = _ordered_nodes(nodes)
        if incomplete:
            warnings.append(CONVERSATION_TREE_INCOMPLETE)
        branch_points = sum(1 for node in nodes if isinstance(node.get("children"), list) and len(node["children"]) > 1)
        if branch_points:
            warnings.append(f"{CONVERSATION_BRANCHES}:{branch_points}")

        by_id = {node["node_id"]: node for node in nodes}
        sha = record.observed.get("body_sha256")
        messages: list[RecoveredMessage] = []
        for node in ordered:
            message = node.get("message")
            if not isinstance(message, dict):
                continue
            parent = by_id.get(node.get("parent"))
            parent_message = parent.get("message") if parent else None
            parent_id = parent_message.get("id") if isinstance(parent_message, dict) else None
            text, content_type, status, message_warnings = _message_content(message.get("content"))
            timestamp = _json_time(message.get("create_time"), _CACHE_MESSAGE_TIME_SOURCE) or {}
            message_warnings += timestamp.pop("warnings", [])
            messages.append(RecoveredMessage(
                message_id=message.get("id") if isinstance(message.get("id"), str) else None,
                conversation_id=conversation_id,
                parent_message_id=parent_id if isinstance(parent_id, str) else None,
                sequence_index=len(messages),
                role=message.get("role") if isinstance(message.get("role"), str) and message.get("role") else "UNKNOWN",
                content=text, content_type=content_type, source_artifact="cache", source_path=record.source_path,
                record_location=f"{record.record_location} mapping={node['node_id']}", source_sha256=sha,
                recovery_status=status, warnings=message_warnings, **timestamp,
            ))
        if not messages:
            status = "RESIDUAL_ONLY"
        else:
            status = "RECOVERED" if all(m.recovery_status == "RECOVERED" for m in messages) else "PARTIAL"
        create_time: dict[str, Any] = {}
        normalized = _json_time(data.get("create_time"), _CACHE_CONVERSATION_TIME_SOURCE)
        if normalized is not None:
            warnings += normalized.pop("warnings")
            create_time = {key.replace("timestamp_", "create_time_"): value for key, value in normalized.items()}
        conversations.append(RecoveredConversation(
            conversation_id=conversation_id, title=data.get("title") if isinstance(data.get("title"), str) else None,
            recovery_status=status, messages=messages,
            source_artifacts=[{
                "artifact_type": r.artifact_type, "source_path": r.source_path, "record_location": r.record_location,
                "source_sha256": r.observed.get("body_sha256"), "record_id": r.record_id,
                "http_status": r.observed.get("http_status"), "content_encoding": r.observed.get("content_encoding"),
                "url_conversation_id": r.observed.get("url_conversation_id"),
                "decoded_sha256": r.observed.get("decoded_sha256"),
                "current_node": r.observed["conversation"].get("current_node"),
            } for r in found],
            correlated_record_ids=history_links.get((os_user, browser_profile, conversation_id), []),
            warnings=warnings, **create_time,
        ))
    return conversations
