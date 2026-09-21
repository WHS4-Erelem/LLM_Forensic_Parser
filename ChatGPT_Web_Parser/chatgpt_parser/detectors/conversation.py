"""대화 Rule (CREATE / ACCESS / RETRY / REMOVED_FROM_LIST / DELETE)."""
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
from ..artifacts.cache import REASON_DIRECT_URL, REASON_RULE_VERIFIED, REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING, REASON_URL_VARIANT_NOT_VERIFIED
from ..artifacts.history import is_chatgpt_url
from ..detectors.common import CHATGPT_HOST, REASON_CONVERSATION_ID_NOT_LINKED, REASON_EMBEDDED_TIMESTAMP, REASON_NOT_UNIQUE_TO_ACTION, REASON_RULE_PARTIALLY_VERIFIED, REASON_SERVER_CONVERSATION_ID_MISSING, REASON_SUPPORTING_CORRELATED, REASON_TIME_ORDER_INCONSISTENT, URL_MATCH_VARIANT, _CONVERSATION_PATH, _TIMESTAMP_LIMITATION, _VARIANT_LIMITATION, _WEB_CONVERSATION_PATH, _candidate_event, _gap_text, _history_groups, _history_sha_by_source, _merged_warnings, _new_event, _record_evidence, _record_key, _record_url, _seconds_between, _session_evidence, _timestamp_explained, _unique_history_records, _visit_event, _visit_note, match_history_url
from ..models import Event, EvidenceItem
from ..recovery.conversations import _CACHE_MESSAGE_TIME_SOURCE, _json_time


# ---- 8.5 CHATGPT_CONVERSATION_CREATE_001 / 8.6 CHATGPT_CONVERSATION_ACCESS_001 ----------
# 관찰 (REPORT bundle3, C: PRE/POST_CLEANUP History 사본): 새 대화 시작 시 /c/WEB:<클라이언트 임시 ID> 가 먼저 기록되고
# 바로 다음 ChatGPT 방문이 /c/<서버 대화 ID> 이다 (+3.154초, +1.980초). 두 ID 는 서로 다른 값이고 from_visit=0.
# 따라서 같은 ID 로는 연결할 수 없다 → 같은 History 안에서 WEB: 방문 바로 다음 ChatGPT host 방문이 /c/<id> 이면 연결.
#   - 연결됨: DETECTED / MEDIUM (식별자로 직접 연결되지 않으므로 HIGH 조건 미충족)
#   - WEB: 뒤에 /c/<id> 가 바로 오지 않음: CANDIDATE / LOW (생성 완료·서버 ID 미확인)
#   - rule_verification PARTIALLY_VERIFIED: 인접 방문 연결이 대화 생성에만 나타나는 패턴인지 충분히 검증되지 않음 (2026-09-15 정정)
# CREATE 에 연결된 /c/<id> 방문은 CONVERSATION_ACCESS 로 중복 출력하지 않는다. 그 밖의 /c/<id> 방문은 ACCESS.

CONVERSATION_CREATE_RULE_ID = "CHATGPT_CONVERSATION_CREATE_001"
CONVERSATION_ACCESS_RULE_ID = "CHATGPT_CONVERSATION_ACCESS_001"


def _conversation_create_links(records: list[ArtifactRecord]) -> list[tuple[ArtifactRecord, ArtifactRecord | None]]:
    """[(WEB: 방문, 바로 다음 ChatGPT 방문이 /c/<id> 이면 그 방문 아니면 None)]."""
    links: list[tuple[ArtifactRecord, ArtifactRecord | None]] = []
    for group in _history_groups(records):
        chatgpt_visits = [record for record in group if is_chatgpt_url(_record_url(record))]
        for index, record in enumerate(chatgpt_visits):
            if match_history_url(_record_url(record), CHATGPT_HOST, _WEB_CONVERSATION_PATH)[0] is None:
                continue
            following = chatgpt_visits[index + 1] if index + 1 < len(chatgpt_visits) else None
            if following is not None and match_history_url(_record_url(following), CHATGPT_HOST, _CONVERSATION_PATH)[0] is None:
                following = None
            links.append((record, following))
    return links


def detect_conversation_create(records: list[ArtifactRecord],
                               coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = _history_sha_by_source(coverages)
    events: list[Event] = []
    for web, created in _conversation_create_links(records):
        sha = sha_by_source.get(web.source_path)
        web_match, web_path = match_history_url(_record_url(web), CHATGPT_HOST, _WEB_CONVERSATION_PATH)
        client_id = web_path.group(1)
        web_evidence = _record_evidence(web, CONVERSATION_CREATE_RULE_ID, "DIRECT", sha, _visit_note(web, "WEB: temporary URL; "),
                                        {"client_conversation_id": client_id})
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_URL]
        limitations = ["WEB:<id> 는 새 대화 시작 시 클라이언트가 만든 임시 ID 로 관찰됨 (REPORT bundle3, 2회) — 공식 문서 미확인"]
        variant = web_match == URL_MATCH_VARIANT
        involved = [web]

        if created is None:
            reasons.append(REASON_SERVER_CONVERSATION_ID_MISSING)
            limitations.append("같은 History 에서 WEB: 방문 바로 다음 ChatGPT 방문이 /c/<id> 가 아니어서 대화 생성 완료와 서버 대화 ID 를 확인하지 못함")
            representative, supporting, confidence = web_evidence, [], "LOW"
        else:
            created_match, created_path = match_history_url(_record_url(created), CHATGPT_HOST, _CONVERSATION_PATH)
            server_id = created_path.group(1)
            created_evidence = _record_evidence(created, CONVERSATION_CREATE_RULE_ID, "SUPPORTING", sha,
                                                _visit_note(created, "first /c/<id> visit after WEB:; "),
                                                {"conversation_id": server_id})
            reasons.append(REASON_SUPPORTING_CORRELATED)
            if server_id.casefold() != client_id.casefold():
                reasons.append(REASON_CONVERSATION_ID_NOT_LINKED)
                limitations.append("client temporary conversation id 와 server conversation id 를 직접 연결하지 못했으며, "
                                   "인접 방문 기반 correlation 을 사용함 (같은 History 안에서 바로 이어진 ChatGPT 방문)")
            else:
                limitations.append("임시 ID 와 서버 대화 ID 가 같다 — 실험에서 관찰되지 않은 형태")
            gap = _seconds_between(web, created)
            limitations.append(f"{_gap_text('WEB: → /c/', gap)}. 시간 창 기준은 사용하지 않음 (NEEDS_VERIFICATION)")
            variant = variant or created_match == URL_MATCH_VARIANT
            involved.append(created)
            representative, supporting, confidence = created_evidence, [created_evidence], "MEDIUM"
            if gap is not None and gap < 0:
                reasons.append(REASON_TIME_ORDER_INCONSISTENT)
                limitations.append("visits.id 순서와 visit_time 순서가 다름")
                confidence = "LOW"

        if variant:
            reasons.append(REASON_URL_VARIANT_NOT_VERIFIED)
            limitations.append(_VARIANT_LIMITATION)
        if all(_timestamp_explained(record) for record in involved):
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append(_TIMESTAMP_LIMITATION)
            confidence = "LOW"
        events.append(_new_event(
            rule_id=CONVERSATION_CREATE_RULE_ID, event_record=web, representative=representative, records=involved,
            action="CONVERSATION_CREATE", action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            confidence=confidence, confidence_reason=reasons, rule_verification="PARTIALLY_VERIFIED",
            primary_evidence=[web_evidence], supporting_evidence=supporting, limitations=limitations,
        ))
    return events


def detect_conversation_access(records: list[ArtifactRecord],
                               coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = _history_sha_by_source(coverages)
    created_keys = {_record_key(created) for _, created in _conversation_create_links(records) if created is not None}
    events: list[Event] = []
    for record in _unique_history_records(records):
        match, path = match_history_url(_record_url(record), CHATGPT_HOST, _CONVERSATION_PATH)
        if match is None or _record_key(record) in created_keys:
            continue
        events.append(_visit_event(
            record, rule_id=CONVERSATION_ACCESS_RULE_ID, action="CONVERSATION_ACCESS", rule_verification="VERIFIED",
            confidence="HIGH", reasons=[REASON_RULE_VERIFIED, REASON_DIRECT_URL], match=match,
            source_sha256=sha_by_source.get(record.source_path), extra_observed={"conversation_id": path.group(1)},
        ))
    return events


# ---- 8.10 Conversation Removed From List Rule -------------------------------
# 2026-09-17 D:\WHS_RETEST\E03-02_CONV_DELETE_RETEST (RUN_20260913_034139 + 루트 09-02 RUN) 에서 확인한 전이:
#   conversation-history 의 연속된 물리 version 에서 sequence 가 더 큰 쪽에 기존 대화 ID 하나만 빠지고
#   나머지 ID 집합은 그대로였다. 주 RUN 은 POST 수집본 하나 안에서 seq 137 (15건, 대상 포함, 03:42:25)
#   → seq 146 (14건, 대상 없음, 03:42:39) 로 관찰됐고, 두 시각 모두 실험 Action Window 안이었다.
#   서로 다른 대상 ID 를 쓴 두 실험에서 같은 형태가 반복됐다.
# 의미는 "그 대화가 목록에서 빠진 상태가 저장됨" 까지다. 다음을 뜻하지 않는다:
#   삭제 API 호출 / 사용자가 삭제 버튼을 누름 / 서버에서 영구 삭제됨.
#   대화 보관(Archive)·프로젝트 이동·서버 측 목록 변화도 같은 흔적을 만들 수 있어 구분하지 못한다.
#   그래서 Action 이름을 CONVERSATION_DELETE 로 쓰지 않고, DIRECT Evidence 로 표시하지 않는다.
# 참고: Cache 의 대화 목록 API 응답(/backend-api/conversations?…) 도 같은 방향으로 바뀌는 것을 수동 Audit 에서
#   확인했지만 (15→14 / 14→13), 그 endpoint 는 현재 Cache Reader 범위 밖이라 Rule 이 자동으로 연결하지 않는다.
#   Rule 은 제거된 대화의 Cache 대화 응답 Record 가 남아 있으면 그것만 보조 Evidence 로 붙인다.

CONVERSATION_REMOVED_RULE_ID = "CHATGPT_CONVERSATION_REMOVED_FROM_LIST_001"
REASON_LIST_TRANSITION = "CONVERSATION_LIST_TRANSITION"
REASON_SINGLE_CONVERSATION_REMOVED = "SINGLE_CONVERSATION_REMOVED"
REASON_OTHER_CONVERSATIONS_UNCHANGED = "OTHER_CONVERSATIONS_UNCHANGED"
_CONVERSATION_REMOVED_INFERENCE = (
    "conversation-history 의 더 나중 저장 상태에서 이 대화 ID 하나만 목록에서 빠졌고 나머지 대화 ID 는 그대로였음. "
    "대화가 목록에서 제거된 상태가 저장된 것으로 관찰됨"
)
_CONVERSATION_REMOVED_LIMITATIONS = (
    "대화가 목록에서 제거된 상태를 관찰한 것이며, 사용자의 삭제 행위를 직접 나타내지 않는다",
    "대화 보관(Archive)·프로젝트 이동·서버 측 목록 변화도 같은 흔적을 만들 수 있어 구분하지 못한다",
    "목록 내용은 서버 응답의 로컬 사본이므로 다른 기기에서의 조작이 반영된 것일 수 있다",
    "삭제·보관을 수행하지 않은 Negative Control 이 없어 이 전이가 특정 행위에 특이적인지 검증되지 않았다 (NEEDS_VERIFICATION)",
    "LevelDB sequence 는 저장 순서이지 사용자 행위 시각이 아니다. Event 시각은 값 안의 timestamp 다",
    "제거된 대화의 잔존 데이터(RecoveredConversation)는 이 Event 와 무관하게 그대로 유지된다",
)


def _removed_evidence(record: ArtifactRecord, level: str, source_sha256: str | None, note: str,
                      summary: dict[str, Any] | None = None) -> EvidenceItem:
    """conversation-history Record → Evidence. 대화 제목 목록(conversation_items)은 넣지 않는다."""
    observed = {key: copy.deepcopy(value) for key, value in record.observed.items() if key != "conversation_items"}
    observed["conversation_count"] = len(record.observed.get("conversation_items") or [])
    if summary:
        observed.update(summary)
    return EvidenceItem(
        evidence_id=f"evidence:{CONVERSATION_REMOVED_RULE_ID}:{record.record_id}", record_id=record.record_id,
        evidence_level=level, artifact_type=record.artifact_type, source_path=record.source_path,
        record_location=record.record_location, source_sha256=source_sha256,
        timestamp_raw=record.timestamp_raw, timestamp_utc=record.timestamp_utc, timestamp_kst=record.timestamp_kst,
        timestamp_type=record.timestamp_type, timestamp_source=record.timestamp_source, observed=observed, note=note,
    )


def _conversation_history_versions(records: list[ArtifactRecord]) -> dict[tuple, list[tuple[ArtifactRecord, frozenset]]]:
    """(os_user, profile, user/scope 해시) → sequence 순 conversation-history PUT version 목록."""
    grouped: dict[tuple, dict[str, tuple[ArtifactRecord, frozenset]]] = {}
    for record in records:
        observed = record.observed
        if (record.artifact_type != "local_storage" or observed.get("key_kind") != "conversation_history"
                or observed.get("operation") != "PUT"):
            continue
        items = observed.get("conversation_items")
        if not isinstance(items, list) or not items:
            continue  # 빈 목록·구조를 읽지 못한 값은 비교 대상이 아니다
        ids = frozenset(item.get("id") for item in items if isinstance(item.get("id"), str) and item.get("id"))
        if not ids:
            continue
        owner = (record.os_user, record.browser_profile,
                 observed.get("user_id_sha256_prefix"), observed.get("cache_scope_sha256_prefix"))
        grouped.setdefault(owner, {})[record.record_id] = (record, ids)
    ordered: dict[tuple, list[tuple[ArtifactRecord, frozenset]]] = {}
    for owner, found in grouped.items():
        versions = sorted(found.values(), key=lambda pair: (pair[0].observed.get("sequence", -1), pair[0].record_id))
        unique: list[tuple[ArtifactRecord, frozenset]] = []
        for record, ids in versions:  # 같은 sequence 의 물리 중복은 한 번만 본다
            if unique and unique[-1][0].observed.get("sequence") == record.observed.get("sequence"):
                continue
            unique.append((record, ids))
        ordered[owner] = unique
    return ordered


def detect_conversation_removed_from_list(
    records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = (),
) -> list[Event]:
    """conversation-history 의 연속된 물리 version 에서 대화 ID 하나만 빠진 전이 → CANDIDATE Event."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    cache_by_conversation: dict[tuple, list[ArtifactRecord]] = {}
    for record in records:
        if record.artifact_type == "cache" and record.observed.get("url_conversation_id"):
            key = (record.os_user, record.browser_profile, record.observed["url_conversation_id"])
            cache_by_conversation.setdefault(key, []).append(record)

    events: list[Event] = []
    for owner, versions in _conversation_history_versions(records).items():
        for (older, older_ids), (newer, newer_ids) in zip(versions, versions[1:]):
            older_sequence = older.observed.get("sequence")
            newer_sequence = newer.observed.get("sequence")
            if not isinstance(older_sequence, int) or not isinstance(newer_sequence, int) or newer_sequence <= older_sequence:
                continue
            removed, added = older_ids - newer_ids, newer_ids - older_ids
            if len(removed) != 1 or added:
                continue  # 2건 이상 제거 / 추가·제거 동시 / 변화 없음 → Event 없음
            conversation_id = next(iter(removed))
            if not newer.timestamp_utc:
                continue  # 값 안의 시각을 변환하지 못하면 Event 를 만들지 않는다 (sequence 를 행위 시각으로 쓰지 않음)
            summary = {
                "removed_conversation_id": conversation_id,
                "conversation_count_before": len(older_ids),
                "conversation_count_after": len(newer_ids),
                "other_conversations_unchanged": True,
                "previous_sequence": older_sequence,
            }
            primary = _removed_evidence(
                newer, "SUPPORTING", sha_by_source.get(newer.source_path),
                "이 대화 ID 가 빠진 뒤의 conversation-history 저장 상태 (목록에서 제거된 상태)", summary)
            supporting = [_removed_evidence(
                older, "SUPPORTING", sha_by_source.get(older.source_path),
                "같은 Profile 의 직전 conversation-history 저장 상태 (이 대화 ID 포함)",
                {"removed_conversation_id": conversation_id, "contains_removed_conversation": True})]
            cache_records = cache_by_conversation.get((owner[0], owner[1], conversation_id), [])
            for cache_record in cache_records:
                supporting.append(EvidenceItem(
                    evidence_id=f"evidence:{CONVERSATION_REMOVED_RULE_ID}:{cache_record.record_id}",
                    record_id=cache_record.record_id, evidence_level="SUPPORTING", artifact_type="cache",
                    source_path=cache_record.source_path, record_location=cache_record.record_location,
                    source_sha256=None, timestamp_raw=cache_record.timestamp_raw,
                    timestamp_utc=cache_record.timestamp_utc, timestamp_kst=cache_record.timestamp_kst,
                    timestamp_type=cache_record.timestamp_type, timestamp_source=cache_record.timestamp_source,
                    observed={"url_conversation_id": cache_record.observed.get("url_conversation_id"),
                              "entry_state": cache_record.observed.get("entry_state")},
                    note="목록에서 빠진 대화의 Cache 응답이 남아 있음 (잔존 — 삭제 여부를 뜻하지 않음)"))
            reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_LIST_TRANSITION, REASON_SINGLE_CONVERSATION_REMOVED,
                       REASON_OTHER_CONVERSATIONS_UNCHANGED, REASON_EMBEDDED_TIMESTAMP, REASON_SUPPORTING_CORRELATED,
                       REASON_TIMESTAMP_EXPLAINED, REASON_NOT_UNIQUE_TO_ACTION]
            limitations = list(_CONVERSATION_REMOVED_LIMITATIONS)
            if cache_records:
                limitations.append(f"제거된 대화의 Cache 응답 Record {len(cache_records)}건이 남아 있음 (대화 내용은 별도 복구 결과로 유지)")
            events.append(Event(
                event_id=f"event:{CONVERSATION_REMOVED_RULE_ID}:{newer.record_id}:removed={conversation_id}",
                finding_type="USER_ACTION", action="CONVERSATION_REMOVED_FROM_LIST", action_status="CANDIDATE",
                timestamp_raw=newer.timestamp_raw, timestamp_utc=newer.timestamp_utc, timestamp_kst=newer.timestamp_kst,
                timestamp_type=newer.timestamp_type, timestamp_source=newer.timestamp_source,
                representative_evidence_id=primary.evidence_id, confidence="MEDIUM", confidence_reason=reasons,
                rule_id=CONVERSATION_REMOVED_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=owner[0],
                browser=newer.browser, browser_profile=owner[1], device_attribution="UNKNOWN",
                primary_evidence=[primary], supporting_evidence=supporting,
                inference=_CONVERSATION_REMOVED_INFERENCE, limitations=limitations,
                warnings=list(newer.warnings),
            ))
    return events


# ---- 8.15 CHATGPT_CONVERSATION_RETRY_001 -------------------------------------
# 근거: Cache 대화 응답 JSON (§7.4 Reader) 의 mapping 에서 같은 부모 아래 assistant 응답이 2개 이상이고
#   그 중 하나의 metadata.message_type 이 "variant" 인 구조. 새 Reader 를 만들지 않고 기존 Record 의
#   observed["conversation"]["mapping"] 만 읽는다.
# 2026-09-20 실제 사본 (C:\WHS_Analysis\PRE_CLEANUP · POST_CLEANUP 의 Cache, read-only) 에서 확인한 것:
#   대화 6a86d3ee-… (node 42) 에서 user 부모 0df995f0 아래 assistant 자식 2개 —
#   38603572 message_type="next" (create_time 1787221207.19656) 과 5f867f9a message_type="variant"
#   (create_time 1787221310.645676). 같은 대화의 나머지 분기는 variant 가 아니었다:
#   루트 아래 user 자식 2개 (프롬프트 편집 분기), user 부모 5fe38ada 아래 tool 자식 2개 (둘 다 "next").
#   전체 42 node 중 message_type 은 next 31 / variant 1 / null 10 이라 "variant" 는 이 구조에만 나타났다.
# 판정: CONVERSATION_RETRY DETECTED / MEDIUM, PARTIALLY_VERIFIED
#   - Artifact 가 직접 나타내는 사실 = "같은 프롬프트에 대한 두 번째 assistant 응답이 variant 로 저장됨".
#     재시도 버튼·응답 비교 등 어떤 UI 조작이었는지는 판정하지 않는다.
#   - 근거가 서버가 만든 대화 JSON 한 곳뿐이고 대체 원인 (응답 비교 기능 등) 을 실험으로 배제하지 못해
#     Evidence Level 은 SUPPORTING 이고 HIGH / VERIFIED 를 쓰지 않는다.
#   - 대표 시각 = variant 응답의 create_time (서버 생성 시각) 이며 사용자의 클릭 시각이 아니다.

CONVERSATION_RETRY_RULE_ID = "CHATGPT_CONVERSATION_RETRY_001"
CONVERSATION_RETRY_MESSAGE_TYPE = "variant"
REASON_SIBLING_VARIANT_RESPONSE = "SIBLING_VARIANT_RESPONSE"
_CONVERSATION_RETRY_INFERENCE = (
    "Cache 에 남은 대화 응답에서 같은 부모 아래 assistant 응답이 2개 이상이고 그 중 하나가 message_type=variant 임 "
    "→ 같은 프롬프트에 대한 응답을 다시 받은 것으로 추론한다 (어떤 UI 조작이었는지 · 재시도 횟수 · 사용자가 어느 응답을 선택했는지는 추론하지 않음)"
)
_CONVERSATION_RETRY_LIMITATIONS = (
    "근거가 서버가 만든 대화 JSON 한 곳뿐이라 Evidence Level 은 SUPPORTING 이다 (대체 원인을 배제하는 실험이 없음)",
    "응답 비교(두 응답 중 선택) 기능 등 재시도가 아닌 조작도 variant 를 만들 수 있는지 검증되지 않았다 (NEEDS_VERIFICATION)",
    "대표 시각은 variant 응답의 create_time (서버가 응답을 만든 시각) 이며 사용자가 재시도를 누른 시각이 아니다",
    "Cache 응답은 서버가 보낸 대화 상태라 device_attribution 은 SERVER_SIDE_CACHE 이고 이 PC 에서의 조작으로 확정하지 않는다",
    "variant 가 지워진 뒤 저장된 응답에는 이 구조가 남지 않는다 — 구조 부재가 재시도 부재를 뜻하지 않는다",
    "프롬프트 편집으로 생긴 user 분기 · tool 분기는 이 Rule 의 조건이 아니다 (assistant + variant 만 본다)",
)


def _conversation_retry_findings(record: ArtifactRecord) -> list[dict[str, Any]]:
    """Cache Record 1건 → variant assistant 응답별 관찰 요약 (원문 본문은 넣지 않는다)."""
    conversation = record.observed.get("conversation")
    if not isinstance(conversation, dict) or not isinstance(conversation.get("mapping"), list):
        return []
    nodes: dict[str, dict[str, Any]] = {}
    children: dict[str, list[dict[str, Any]]] = {}
    for node in conversation["mapping"]:
        if not isinstance(node, dict) or not isinstance(node.get("node_id"), str):
            continue
        nodes[node["node_id"]] = node
        parent = node.get("parent")
        if isinstance(parent, str):
            children.setdefault(parent, []).append(node)

    findings: list[dict[str, Any]] = []
    for node_id, node in nodes.items():
        message = node.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        if message.get("message_type") != CONVERSATION_RETRY_MESSAGE_TYPE:
            continue
        parent_id = node.get("parent")
        if not isinstance(parent_id, str):
            continue
        siblings = [other for other in children.get(parent_id, [])
                    if other.get("node_id") != node_id and isinstance(other.get("message"), dict)
                    and other["message"].get("role") == "assistant"]
        if not siblings:
            continue  # 형제 응답이 없으면 '다시 받은 응답' 구조가 아니다
        parent_message = nodes.get(parent_id, {}).get("message")
        findings.append({
            "conversation_id": conversation.get("conversation_id") or record.observed.get("url_conversation_id"),
            "variant_message_id": message.get("id") or node_id,
            "variant_node_id": node_id,
            "variant_create_time": message.get("create_time"),
            "parent_node_id": parent_id,
            "parent_role": parent_message.get("role") if isinstance(parent_message, dict) else None,
            "sibling_assistant_message_ids": [(other["message"].get("id") or other["node_id"]) for other in siblings],
            "sibling_assistant_message_types": [other["message"].get("message_type") for other in siblings],
            "assistant_children_count": len(siblings) + 1,
        })
    return sorted(findings, key=lambda item: str(item["variant_message_id"]))


def detect_conversation_retry(records: list[ArtifactRecord],
                              coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """Cache 대화 응답의 같은 부모 아래 variant assistant 응답 → CONVERSATION_RETRY (DETECTED / MEDIUM)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "cache"}
    grouped: dict[tuple, list[tuple[ArtifactRecord, dict[str, Any]]]] = {}
    for record in records:
        if record.artifact_type != "cache":
            continue
        for finding in _conversation_retry_findings(record):
            key = (record.os_user or "", record.browser_profile or "",
                   str(finding["conversation_id"]), str(finding["variant_message_id"]))
            group = grouped.setdefault(key, [])
            if record.record_id not in [existing.record_id for existing, _ in group]:
                group.append((record, finding))

    events: list[Event] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: item[0].source_path)
        record, finding = group[0]
        timestamp = _json_time(finding["variant_create_time"], _CACHE_MESSAGE_TIME_SOURCE) or {}
        warnings = _merged_warnings([item[0] for item in group]) + list(timestamp.pop("warnings", []))
        note = (f"Cache 대화 응답에서 부모 {finding['parent_node_id']} 아래 assistant 응답 "
                f"{finding['assistant_children_count']}개 중 message_type=variant 인 응답 {finding['variant_message_id']}")
        primary = _session_evidence(record, "SUPPORTING", sha_by_source.get(record.source_path), note,
                                    CONVERSATION_RETRY_RULE_ID)
        primary.observed = dict(finding)  # 대화 본문 전체가 아니라 판정에 쓴 구조만 남긴다
        supporting = []
        for other, other_finding in group[1:]:
            item = _session_evidence(other, "SUPPORTING", sha_by_source.get(other.source_path),
                                     f"같은 variant 응답이 남은 다른 Cache 사본 — {note}", CONVERSATION_RETRY_RULE_ID)
            item.observed = dict(other_finding)
            supporting.append(item)
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_SIBLING_VARIANT_RESPONSE, REASON_NOT_UNIQUE_TO_ACTION]
        limitations = list(_CONVERSATION_RETRY_LIMITATIONS)
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if timestamp.get("timestamp_utc"):
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("variant 응답의 create_time 을 UTC/KST 로 변환하지 못해 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(Event(
            event_id=f"event:{CONVERSATION_RETRY_RULE_ID}:{record.record_id}:variant={finding['variant_message_id']}",
            finding_type="USER_ACTION", action="CONVERSATION_RETRY",
            action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=timestamp.get("timestamp_raw"), timestamp_utc=timestamp.get("timestamp_utc"),
            timestamp_kst=timestamp.get("timestamp_kst"),
            timestamp_type=timestamp.get("timestamp_type", "unknown"),
            timestamp_source=timestamp.get("timestamp_source", _CACHE_MESSAGE_TIME_SOURCE),
            representative_evidence_id=primary.evidence_id, confidence=confidence, confidence_reason=reasons,
            rule_id=CONVERSATION_RETRY_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=record.os_user,
            browser=record.browser, browser_profile=record.browser_profile,
            device_attribution="SERVER_SIDE_CACHE", primary_evidence=[primary], supporting_evidence=supporting,
            inference=_CONVERSATION_RETRY_INFERENCE, limitations=limitations, warnings=warnings,
        ))
    return events


# ---- 8.24 CHATGPT_CONVERSATION_DELETE_001 -----------------------------------
# CONVERSATION_REMOVED_FROM_LIST 와 같은 전이를 근거로 쓰지만 뜻이 다르다:
#   CONVERSATION_REMOVED_FROM_LIST = 관찰된 사실 (목록에서 빠진 상태가 저장됨)
#   CONVERSATION_DELETE            = 그 사실에 대한 사용자 행위 해석 (사용자가 대화를 지웠다)
# 해석을 남기려면 관찰 사실보다 조건이 더 엄격해야 한다. 그래서 다음을 모두 만족할 때만 Event 를 만든다:
#   (a) 대화 ID 하나만 빠진 전이이고 나머지 목록은 그대로   (REMOVED_FROM_LIST 와 같은 조건)
#   (b) 그 뒤의 어떤 저장 상태에도 그 대화가 다시 나타나지 않음 (일시적 목록 변화·페이지 경계가 아님)
#   (c) 그 대화의 Cache 대화 응답 Record 도 남아 있지 않음   (목록과 캐시 양쪽에서 사라짐)
# conversation-history key 전체 DELETE 는 개별 대화 삭제로 보지 않는다 (조건 (a) 를 만족하지 않는다).

CONVERSATION_DELETE_RULE_ID = "CHATGPT_CONVERSATION_DELETE_001"
REASON_CONVERSATION_NOT_RESTORED = "CONVERSATION_NOT_RESTORED"
REASON_CACHE_RESPONSE_ABSENT = "CACHE_RESPONSE_ABSENT"
_CONVERSATION_DELETE_INFERENCE = (
    "대화 하나만 목록에서 빠진 뒤 다시 나타나지 않고 그 대화의 Cache 응답도 남아 있지 않음 → "
    "사용자가 그 대화를 삭제했을 가능성이 있는 것으로 해석한다 (보관·이동과 완전히 구분하지는 못함)"
)
_CONVERSATION_DELETE_LIMITATIONS = (
    "보관(Archive)·프로젝트 이동·서버 측 목록 변화도 같은 흔적을 만든다 — 삭제로 확정하지 않는다",
    "같은 전이를 근거로 CONVERSATION_REMOVED_FROM_LIST(관찰 사실) Event 도 함께 생성된다. 두 Event 는 같은 근거의 관찰과 해석이다",
    "Cache 응답이 없다는 것은 캐시가 지워졌거나 원래 캐시되지 않았을 수도 있다 ('미존재'는 '삭제'가 아니다)",
    "삭제 API 호출·삭제 버튼 조작을 관찰한 것이 아니다",
    "시각은 대화 목록이 저장된 시각이며 삭제를 실행한 시각이 아니다",
)


def detect_conversation_delete(records: list[ArtifactRecord],
                               coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """목록에서 빠진 뒤 복귀하지 않고 Cache 응답도 없는 대화 → CONVERSATION_DELETE (CANDIDATE / MEDIUM)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    cached_conversations = {(r.os_user, r.browser_profile, r.observed.get("url_conversation_id"))
                            for r in records if r.artifact_type == "cache"}
    events: list[Event] = []
    for owner, versions in _conversation_history_versions(records).items():
        for index, ((older, older_ids), (newer, newer_ids)) in enumerate(zip(versions, versions[1:])):
            removed, added = older_ids - newer_ids, newer_ids - older_ids
            if len(removed) != 1 or added or not newer.timestamp_utc:
                continue
            conversation_id = next(iter(removed))
            if any(conversation_id in later_ids for _, later_ids in versions[index + 2:]):
                continue  # 나중 상태에서 다시 나타나면 삭제 해석을 하지 않는다
            if (owner[0], owner[1], conversation_id) in cached_conversations:
                continue  # Cache 응답이 남아 있으면 관찰 사실(REMOVED_FROM_LIST)까지만 남긴다
            summary = {"removed_conversation_id": conversation_id, "conversation_count_before": len(older_ids),
                       "conversation_count_after": len(newer_ids), "restored_in_later_state": False,
                       "cache_response_present": False, "previous_sequence": older.observed.get("sequence")}
            primary = _removed_evidence(newer, "SUPPORTING", sha_by_source.get(newer.source_path),
                                        "이 대화가 빠진 뒤의 대화 목록 상태 — 이후 상태에도 다시 나타나지 않음", summary)
            primary.evidence_id = f"evidence:{CONVERSATION_DELETE_RULE_ID}:{newer.record_id}"
            earlier = _removed_evidence(older, "SUPPORTING", sha_by_source.get(older.source_path),
                                        "이 대화가 아직 목록에 있던 직전 상태",
                                        {"removed_conversation_id": conversation_id})
            earlier.evidence_id = f"evidence:{CONVERSATION_DELETE_RULE_ID}:{older.record_id}"
            timestamp = {"timestamp_raw": newer.timestamp_raw, "timestamp_utc": newer.timestamp_utc,
                         "timestamp_kst": newer.timestamp_kst, "timestamp_type": newer.timestamp_type,
                         "timestamp_source": newer.timestamp_source}
            reasons = [REASON_LIST_TRANSITION, REASON_SINGLE_CONVERSATION_REMOVED, REASON_CONVERSATION_NOT_RESTORED,
                       REASON_CACHE_RESPONSE_ABSENT, REASON_SUPPORTING_CORRELATED, REASON_NOT_UNIQUE_TO_ACTION,
                       REASON_TIMESTAMP_EXPLAINED]
            events.append(_candidate_event(
                rule_id=CONVERSATION_DELETE_RULE_ID, action="CONVERSATION_DELETE",
                event_id=f"event:{CONVERSATION_DELETE_RULE_ID}:{newer.record_id}:removed={conversation_id}",
                record=newer, primary=primary, supporting=[earlier], timestamp=timestamp, reasons=reasons,
                inference=_CONVERSATION_DELETE_INFERENCE, limitations=list(_CONVERSATION_DELETE_LIMITATIONS),
                confidence="MEDIUM", warnings=list(newer.warnings)))
    return events
