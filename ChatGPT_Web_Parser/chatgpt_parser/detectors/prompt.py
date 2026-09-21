"""프롬프트 Rule (PROMPT_DRAFT / PROMPT_SEND)."""
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
from ..artifacts.cache import REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING
from ..detectors.common import REASON_DIRECT_VALUE, REASON_EMBEDDED_TIMESTAMP, REASON_NOT_UNIQUE_TO_ACTION, REASON_RULE_PARTIALLY_VERIFIED, REASON_SUPPORTING_CORRELATED, REASON_TIMESTAMP_APPROXIMATED, _cache_conversation_nodes, _candidate_event, _conversation_id_of, _merged_warnings, _session_evidence
from ..models import Event, EvidenceItem
from ..recovery.conversations import _CACHE_MESSAGE_TIME_SOURCE, _history_conversation_links, _json_time


# ---- 8.9 CHATGPT_PROMPT_DRAFT_001 --------------------------------------------
# 근거: Local Storage (https://chatgpt.com) oai/apps/conversationDrafts PUT 의 초안 항목 (§7.3 Reader 가 이미 만드는 Record).
# 2026-09-15 C: SNAPSHOT_EXTRACT Local Storage .log (uid06 · uid12 · uid15 · uid16 · uid26 · uid31) 에서 확인한 형식:
#   값 = {"drafts":[{"id", "content", "doc"(ProseMirror, content 와 같은 글자), "timestamp"(13자리 Unix ms)}], "userId"}
#   PUT 마다 초안 목록 전체를 다시 쓴다. 초안을 비울 때는 DELETE 가 아니라 {"drafts":[],"userId":null} PUT.
#   id 는 "null_thread" (대화가 아직 없는 새 대화 화면) 또는 서버 대화 UUID. WEB: 임시 ID 는 관찰되지 않음.
#   같은 id 의 내용이 바뀔 때마다 timestamp 가 갱신됨 → 최초 입력 시각이 아니라 그 내용의 저장 시각.
# 실험 대응 (REPORT EVIDENCE_LEVEL_REAUDIT F-2 · remaining_action_analysis): E04-01 · E03-01 · E05-03 마커 프롬프트가 초안으로 복원됨.
# 판정: PROMPT_DRAFT DETECTED / MEDIUM, PARTIALLY_VERIFIED
#   - Artifact 가 직접 나타내는 사실 = "입력창 초안이 이 내용으로 저장됨". 전송·서버 전달·대화 생성은 판정하지 않는다
#     (PROMPT_SENT / MESSAGE_SENT / CONVERSATION_CREATE 를 만들지 않음, CONVERSATION_CREATE Event 와 합치지 않음).
#   - 입력 후 전송하지 않은 경우·붙여넣기 등 Negative Control 이 없어 VERIFIED 로 두지 않는다 → HIGH 조건 미충족.
#   - 같은 (저장소·계정 Profile, draft id, content) 는 처음 저장된 PUT 1건만 Event, 뒤의 같은 내용 재저장은 SUPPORTING.
#     내용이 바뀌면 새 Event. 빈 초안·빈 목록 PUT 은 Event 로 만들지 않는다 (전송·취소를 구분할 수 없음).
#   - Event·Evidence 에는 초안 원문을 복사하지 않는다 (길이·SHA-256 앞자리만). 원문은 records[] 의 Local Storage Record 에만.
#   - draft id 가 History /c/<id> 와 정확히 같으면 그 방문 record_id 를 Evidence observed 에 남긴다 (null_thread 는 연결하지 않음).
#   - timestamp 가 없거나 변환 실패 → LOW / CANDIDATE.

PROMPT_DRAFT_RULE_ID = "CHATGPT_PROMPT_DRAFT_001"
_PROMPT_DRAFT_INFERENCE = ("ChatGPT 입력창 초안 자동 저장 값 (oai/apps/conversationDrafts) 에 이 내용의 초안이 기록됨 → "
                           "사용자가 입력창에 이 내용을 입력한 것으로 추론한다 (전송·서버 전달·대화 생성은 추론하지 않음)")
_PROMPT_DRAFT_LIMITATIONS = (
    "초안은 전송 전 입력창 상태다. 프롬프트 전송·메시지 서버 전달·대화 생성을 뜻하지 않는다",
    "draft timestamp 는 내용이 바뀔 때마다 갱신돼 최초 입력 시각이 아니라 이 내용이 저장된 시각으로 관찰됨",
    "키보드 입력과 붙여넣기 등 입력 방식은 구분하지 못한다",
    "초안이 비워진 PUT ({\"drafts\":[]}) 은 전송·지우기·다른 원인을 구분할 수 없어 이 Event 와 연결하지 않는다",
    "입력 후 전송하지 않은 경우 등을 비교한 Negative Control 이 없다 (NEEDS_VERIFICATION)",
    "draft id 'null_thread' 는 대화가 아직 없는 새 대화 화면의 입력이며 서버 대화 ID 로 바꾸지 않는다",
    "같은 초안 상태가 .log 와 .ldb 여러 곳에 물리적으로 남아 있어도 Event 는 1건이다 (나머지는 보조 Evidence·Record 로 보존)",
    "LevelDB sequence·block 위치는 저장 순서일 뿐 사용자 입력 시각이 아니다",
)
_UUID_TEXT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _draft_evidence(record: ArtifactRecord, index: int, draft: dict[str, Any], level: str, source_sha256: str | None,
                    note: str, history_ids: list[str] | None = None) -> EvidenceItem:
    """초안 원문 대신 길이·해시만 담은 Evidence (원문은 Record 에만 둔다)."""
    content = draft.get("content") or ""
    observed = {key: copy.deepcopy(value) for key, value in record.observed.items() if key != "drafts"}
    observed["draft"] = {"draft_index": index, "draft_id": draft.get("draft_id"), "content_length": len(content),
                         "content_sha256_prefix": hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]}
    if history_ids is not None:
        observed["history_conversation_record_ids"] = history_ids
    timestamp = draft.get("timestamp") if isinstance(draft.get("timestamp"), dict) else {}
    return EvidenceItem(
        evidence_id=f"evidence:{PROMPT_DRAFT_RULE_ID}:{record.record_id}:draft={index}", record_id=record.record_id,
        evidence_level=level, artifact_type=record.artifact_type, source_path=record.source_path,
        record_location=f"{record.record_location} draft={index}", source_sha256=source_sha256,
        timestamp_raw=timestamp.get("timestamp_raw"), timestamp_utc=timestamp.get("timestamp_utc"),
        timestamp_kst=timestamp.get("timestamp_kst"), timestamp_type=timestamp.get("timestamp_type", "unknown"),
        timestamp_source=timestamp.get("timestamp_source"), observed=observed, note=note,
    )


def detect_prompt_draft(records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "local_storage"}
    history_links = _history_conversation_links(records)
    puts = {r.record_id: r for r in records if r.artifact_type == "local_storage"
            and r.observed.get("key_kind") == "conversation_drafts" and r.observed.get("operation") == "PUT"}
    # 물리 Record (.log / .ldb / 같은 값의 옛 버전) 와 논리 Draft 상태를 구분한다.
    # 같은 (os_user, profile, draft id, 내용, 저장 시각) 이면 Event 1건이고, 나머지 물리 Record 는 보조 Evidence 로 붙는다.
    # 대표 Record 는 sequence 가 가장 이른 것 (그 상태가 처음 기록된 위치).
    ordered = sorted(puts.values(), key=lambda r: (r.os_user or "", r.browser_profile or "",
                                                   r.observed.get("sequence", -1), r.source_path, r.record_id))
    found: dict[tuple, dict[str, Any]] = {}
    for record in ordered:
        for index, draft in enumerate(record.observed.get("drafts") or []):
            content = draft.get("content") if isinstance(draft, dict) else None
            if not isinstance(content, str) or not content:
                continue  # 빈 초안은 입력 내용이 없다
            timestamp = draft.get("timestamp") if isinstance(draft.get("timestamp"), dict) else {}
            key = (record.os_user, record.browser_profile, draft.get("draft_id"),
                   hashlib.sha256(content.encode("utf-8")).hexdigest(), timestamp.get("timestamp_raw"))
            if key in found:
                found[key]["later"].append((record, index, draft))  # 같은 초안 상태의 다른 물리 Record
            else:
                found[key] = {"record": record, "index": index, "draft": draft, "later": []}

    events: list[Event] = []
    for (os_user, browser_profile, draft_id, _, _), item in found.items():
        record, index, draft = item["record"], item["index"], item["draft"]
        sha = sha_by_source.get(record.source_path)
        history_ids = (history_links.get((os_user, browser_profile, draft_id), [])
                       if isinstance(draft_id, str) and _UUID_TEXT.fullmatch(draft_id) else [])
        primary = _draft_evidence(record, index, draft, "DIRECT", sha, "입력창 초안 저장 값 — 원문은 records[] 의 Local Storage Record",
                                  history_ids)
        supporting = [_draft_evidence(later, later_index, later_draft, "SUPPORTING", sha_by_source.get(later.source_path),
                                      "같은 초안 상태가 남아 있는 다른 물리 Record (.log / .ldb 또는 옛 버전)")
                      for later, later_index, later_draft in item["later"]]
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_VALUE]
        limitations = list(_PROMPT_DRAFT_LIMITATIONS)
        timestamp = draft.get("timestamp") if isinstance(draft.get("timestamp"), dict) else {}
        if timestamp.get("timestamp_raw") is not None:
            reasons.append(REASON_EMBEDDED_TIMESTAMP)
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if timestamp.get("timestamp_utc"):
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("초안에 변환 가능한 timestamp 가 없어 입력(저장) 시각을 확인할 수 없음")
            confidence = "LOW"
        if history_ids:
            limitations.append(f"draft id 와 정확히 같은 History /c/<id> 방문 {len(history_ids)}건 — 같은 대화의 입력창이었다는 뜻이며 전송을 뜻하지 않음")
        if supporting:
            sources = sorted({evidence.source_path for evidence in [primary] + supporting})
            limitations.append(f"같은 초안 상태가 물리 Record {len(supporting) + 1}건에서 발견됨 (파일 {len(sources)}개)")
        events.append(Event(
            event_id=f"event:{PROMPT_DRAFT_RULE_ID}:{record.record_id}:draft={index}", finding_type="USER_ACTION",
            action="PROMPT_DRAFT", action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=primary.timestamp_raw, timestamp_utc=primary.timestamp_utc, timestamp_kst=primary.timestamp_kst,
            timestamp_type=primary.timestamp_type, timestamp_source=primary.timestamp_source,
            representative_evidence_id=primary.evidence_id, confidence=confidence, confidence_reason=reasons,
            rule_id=PROMPT_DRAFT_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=os_user,
            browser=record.browser, browser_profile=browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_PROMPT_DRAFT_INFERENCE,
            limitations=limitations, warnings=list(record.warnings) + list(timestamp.get("warnings") or []),
        ))
    return events


# ---- 8.18 CHATGPT_PROMPT_SEND_001 -------------------------------------------
# PROMPT_DRAFT (초안 저장) 와 PROMPT_SEND (전송) 는 서로 다른 행위다.
#   PROMPT_DRAFT = Local Storage 의 conversationDrafts 에 입력창 내용이 저장된 상태.
#   PROMPT_SEND  = 그 내용이 실제로 전송되어 대화에 user 메시지로 남은 행위.
# 근거 우선순위 (사용자 지정):
#   1·2. 복구된 대화 / Cache 대화 응답 mapping 의 user 메시지   → 전송된 메시지가 남아 있음
#   3.   conversationDrafts 가 non-empty → empty 로 바뀐 전이   → 초안이 비워진 사실만 (전송·취소 구분 못 함)
#   4·5. 대화 상태 갱신 · loggedInUserMessageCount 는 단독 근거로 쓰지 않는다
#        (loggedInUserMessageCount 는 현재 Local Storage 허용 key 목록 밖이라 Reader 가 읽지 않는다)
# user 메시지는 "전송 이후 서버가 돌려준 대화 상태" 라 전송 시각·전송 단말을 직접 증명하지 못한다 → CANDIDATE.

PROMPT_SEND_RULE_ID = "CHATGPT_PROMPT_SEND_001"
REASON_USER_MESSAGE_PRESENT = "USER_MESSAGE_PRESENT"
REASON_DRAFT_CLEARED = "DRAFT_CLEARED_AFTER_NON_EMPTY"
_PROMPT_SEND_INFERENCE = (
    "대화에 user 메시지가 남아 있음 → 그 메시지를 전송한 것으로 추론한다 "
    "(전송 시각·전송 단말·전송 횟수·메시지를 입력한 방법은 추론하지 않음)"
)
_PROMPT_SEND_LIMITATIONS = (
    "user 메시지는 전송 이후 서버가 돌려준 대화 상태이므로 전송 시각 자체의 근거가 아니다 (create_time 은 서버가 메시지를 만든 시각)",
    "같은 계정을 다른 기기에서 사용했다면 이 PC 에서 전송한 것이 아닐 수 있다 (device_attribution=SERVER_SIDE_CACHE)",
    "PROMPT_DRAFT 와 같은 행위가 아니다. 초안만 저장하고 보내지 않은 내용은 이 Rule 의 대상이 아니다",
    "초안이 비워진 전이(conversationDrafts non-empty → empty)는 전송·취소·다른 대화로 이동을 구분하지 못한다",
    "loggedInUserMessageCount 같은 누적 카운터는 단독 근거로 쓰지 않는다 (현재 Reader 범위 밖)",
)


def _prompt_send_findings(record: ArtifactRecord) -> list[dict[str, Any]]:
    """Cache Record 1건 → user 메시지별 관찰 요약 (본문은 넣지 않는다)."""
    conversation, nodes = _cache_conversation_nodes(record)
    findings = []
    for node in nodes:
        message = node.get("message")
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        findings.append({
            "conversation_id": _conversation_id_of(record, conversation),
            "message_id": message.get("id") or node.get("node_id"),
            "message_create_time": message.get("create_time"),
            "parent_node_id": node.get("parent"),
            "message_status": message.get("status"),
            "has_content": bool(message.get("content")),
            "attachment_count": len(message["attachments"]) if isinstance(message.get("attachments"), list) else 0,
        })
    return sorted(findings, key=lambda item: str(item["message_id"]))


def _drafts_of(record: ArtifactRecord) -> list[dict[str, Any]] | None:
    drafts = record.observed.get("drafts")
    return drafts if isinstance(drafts, list) else None


def _draft_cleared_transitions(records: list[ArtifactRecord]) -> list[tuple[ArtifactRecord, ArtifactRecord]]:
    """conversationDrafts 의 non-empty → empty 전이 (sequence 순, 같은 Profile 안에서만)."""
    grouped: dict[tuple, list[ArtifactRecord]] = {}
    for record in records:
        if (record.artifact_type == "local_storage" and record.observed.get("key_kind") == "conversation_drafts"
                and record.observed.get("operation") == "PUT" and _drafts_of(record) is not None):
            grouped.setdefault((record.os_user, record.browser_profile), []).append(record)
    transitions = []
    for group in grouped.values():
        ordered = sorted(group, key=lambda r: (r.observed.get("sequence", -1), r.record_id))
        for older, newer in zip(ordered, ordered[1:]):
            if _drafts_of(older) and not _drafts_of(newer):
                transitions.append((older, newer))
    return transitions


def detect_prompt_send(records: list[ArtifactRecord],
                       coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """대화에 남은 user 메시지 (없으면 초안이 비워진 전이) → PROMPT_SEND (CANDIDATE)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    grouped: dict[tuple, list[tuple[ArtifactRecord, dict[str, Any]]]] = {}
    for record in records:
        if record.artifact_type != "cache":
            continue
        for finding in _prompt_send_findings(record):
            key = (record.os_user or "", record.browser_profile or "",
                   str(finding["conversation_id"]), str(finding["message_id"]))
            group = grouped.setdefault(key, [])
            if record.record_id not in [existing.record_id for existing, _ in group]:
                group.append((record, finding))

    events: list[Event] = []
    profiles_with_message: set[tuple] = set()
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: item[0].source_path)
        record, finding = group[0]
        profiles_with_message.add((record.os_user, record.browser_profile))
        timestamp = _json_time(finding["message_create_time"], _CACHE_MESSAGE_TIME_SOURCE) or {}
        warnings = _merged_warnings([item[0] for item in group]) + list(timestamp.pop("warnings", []))
        note = (f"Cache 대화 응답에 남은 user 메시지 {finding['message_id']} "
                f"(대화 {finding['conversation_id']}) — 전송된 메시지의 서버 사본")
        primary = _session_evidence(record, "SUPPORTING", sha_by_source.get(record.source_path), note,
                                    PROMPT_SEND_RULE_ID)
        primary.observed = dict(finding)  # 본문은 넣지 않는다 (복구된 원문은 conversations[] 에만 있다)
        supporting = []
        for other, other_finding in group[1:]:
            item = _session_evidence(other, "SUPPORTING", sha_by_source.get(other.source_path),
                                     f"같은 user 메시지가 남은 다른 Cache 사본 — {note}", PROMPT_SEND_RULE_ID)
            item.observed = dict(other_finding)
            supporting.append(item)
        reasons = [REASON_USER_MESSAGE_PRESENT, REASON_NOT_UNIQUE_TO_ACTION]
        limitations = list(_PROMPT_SEND_LIMITATIONS)
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if timestamp.get("timestamp_utc"):
            reasons.append(REASON_TIMESTAMP_APPROXIMATED)  # 메시지 생성 시각이며 전송 시각이 아니다
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("user 메시지의 create_time 을 UTC/KST 로 변환하지 못해 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(_candidate_event(
            rule_id=PROMPT_SEND_RULE_ID, action="PROMPT_SEND",
            event_id=f"event:{PROMPT_SEND_RULE_ID}:{record.record_id}:message={finding['message_id']}",
            record=record, primary=primary, supporting=supporting, timestamp=timestamp, reasons=reasons,
            inference=_PROMPT_SEND_INFERENCE, limitations=limitations, confidence=confidence,
            device_attribution="SERVER_SIDE_CACHE", warnings=warnings))

    for older, newer in _draft_cleared_transitions(records):
        if (newer.os_user, newer.browser_profile) in profiles_with_message:
            continue  # 전송된 메시지 자체가 남아 있으면 더 약한 근거로 Event 를 늘리지 않는다
        note = "conversationDrafts 가 내용이 있는 상태에서 빈 상태로 저장됨 (초안이 비워진 사실만)"
        primary = _session_evidence(newer, "SUPPORTING", sha_by_source.get(newer.source_path), note,
                                    PROMPT_SEND_RULE_ID)
        supporting = [_session_evidence(older, "SUPPORTING", sha_by_source.get(older.source_path),
                                        "직전의 내용이 있는 conversationDrafts 저장 상태", PROMPT_SEND_RULE_ID)]
        timestamp = {"timestamp_raw": newer.timestamp_raw, "timestamp_utc": newer.timestamp_utc,
                     "timestamp_kst": newer.timestamp_kst, "timestamp_type": newer.timestamp_type,
                     "timestamp_source": newer.timestamp_source}
        reasons = [REASON_DRAFT_CLEARED, REASON_NOT_UNIQUE_TO_ACTION, REASON_SUPPORTING_CORRELATED,
                   REASON_TIMESTAMP_EXPLAINED if newer.timestamp_utc else REASON_TIMESTAMP_MISSING]
        events.append(_candidate_event(
            rule_id=PROMPT_SEND_RULE_ID, action="PROMPT_SEND",
            event_id=f"event:{PROMPT_SEND_RULE_ID}:{newer.record_id}:draft_cleared",
            record=newer, primary=primary, supporting=supporting, timestamp=timestamp, reasons=reasons,
            inference="conversationDrafts 가 비워진 상태가 저장됨 → 초안이 전송되었을 가능성이 있는 것으로만 관찰한다",
            limitations=list(_PROMPT_SEND_LIMITATIONS), confidence="LOW", warnings=list(newer.warnings)))
    return events
