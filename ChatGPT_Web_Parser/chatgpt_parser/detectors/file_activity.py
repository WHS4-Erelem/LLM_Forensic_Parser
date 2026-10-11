"""파일 Rule (FILE_DOWNLOAD / FILE_UPLOAD / FILE_UPLOAD_DELETE)."""
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
from ..artifacts.cache import REASON_RULE_VERIFIED, REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING, REASON_URL_VARIANT_NOT_VERIFIED
from ..detectors.common import CHATGPT_HOST, DOWNLOAD_ARTIFACT_TYPES, REASON_NOT_UNIQUE_TO_ACTION, REASON_RULE_PARTIALLY_VERIFIED, REASON_SUPPORTING_CORRELATED, REASON_TIMESTAMP_APPROXIMATED, URL_MATCH_VARIANT, _CONVERSATION_PATH, _VARIANT_LIMITATION, _cache_conversation_nodes, _candidate_event, _conversation_id_of, _is_download_record, _merged_warnings, _new_event, _record_evidence, _record_key, _session_evidence, match_history_url
from ..models import Event
from ..recovery.conversations import _CACHE_MESSAGE_TIME_SOURCE, _json_time


# ---- CHATGPT_FILE_DOWNLOAD_001 (History downloads) -----------------------------------------------
# 근거: Chrome History downloads / downloads_url_chains (History downloads Reader 가 만드는 record_kind="download" Record).
# 2026-09-18 Marker E01 (Chrome Stable) 에서 확인한 구조:
#   - ChatGPT 가 만든 파일의 다운로드 URL = https://chatgpt.com/backend-api/estuary/content?... (서명 query 포함)
#   - 같은 행의 tab_url = https://chatgpt.com/c/<conversation id> (다운로드를 실행한 탭)
#   - Claude (claude.ai/api/.../download-file) · Gemini (contribution.usercontent.google.com/download) 는 host 가 달라 걸리지 않는다
# 판정 조건은 구조(호스트 + 경로)뿐이다. 파일 이름·마커 문자열·대화 제목은 조건으로 쓰지 않는다.
# 판정 (2026-09-18 정책 교정): rule_verification 이 PARTIALLY_VERIFIED 인 동안에는 HIGH 를 쓰지 않는다.
#   - chain URL 이 chatgpt.com/backend-api/estuary/content → DIRECT evidence, DETECTED / MEDIUM
#     (ChatGPT 서버가 파일을 내려준 경로 자체지만 Rule 이 아직 PARTIALLY_VERIFIED → HIGH 아님.
#      독립 실험·다른 Chrome 버전에서 일반화가 검증돼 Rule 을 VERIFIED 로 올릴 때 HIGH 를 검토한다)
#   - chain URL 은 다른 host 인데 tab_url 만 chatgpt.com/c/<id> → SUPPORTING evidence, CANDIDATE / LOW
#     (ChatGPT 탭에서 외부 링크를 눌러 일반 파일을 받은 경우와 구분하지 못한다 = alternative explanation.
#      "ChatGPT 가 생성한 파일 다운로드" 로 확정하지 않는다)
#   - 둘 다 아니면 Event 를 만들지 않는다 (일반 웹 다운로드 · 다른 LLM 다운로드)
#   - 대표 시각 = downloads.start_time (다운로드 시작). end_time 은 Record·Evidence 에 보존만 한다
#   - 시각 변환 실패 → LOW / CANDIDATE. download_id 1개 = Event 1건 (url_chain 여러 행은 하나의 Evidence 안에 보존)

FILE_DOWNLOAD_RULE_ID = "CHATGPT_FILE_DOWNLOAD_001"
REASON_DIRECT_DOWNLOAD_URL = "DIRECT_DOWNLOAD_URL"
REASON_TAB_CONTEXT_ONLY = "TAB_CONTEXT_ONLY"
_ESTUARY_CONTENT_PATH = re.compile(r"/backend-api/estuary/content")
_FILE_DOWNLOAD_INFERENCE = ("ChatGPT 가 제공한 파일 경로에서 이 브라우저 Profile 이 파일을 로컬에 내려받은 것으로 추론한다 "
                            "(파일을 누가 만들었는지 · 내려받은 파일을 이후 열었는지는 추론하지 않음)")
_FILE_DOWNLOAD_TAB_ONLY_INFERENCE = ("ChatGPT 대화 화면이 열린 탭에서 파일 다운로드가 시작된 것이 관찰됨 — 파일 출처가 ChatGPT 인지는 "
                                     "이 근거만으로 추론하지 않는다 (탭에서 연 외부 링크일 가능성이 남는다)")
_FILE_DOWNLOAD_LIMITATIONS = (
    "downloads Record 는 다운로드가 시작된 사실을 나타낸다. 파일 생성 주체(업로드본·생성물)와 다운로드 후 사용 여부는 판정하지 않는다",
    "target_path 의 파일이 현재도 존재하는지는 History 만으로 확인하지 않는다 (이후 이동·삭제 가능)",
    "downloads.start_time 은 Chrome 이 기록한 다운로드 시작 시각이며 사용자가 버튼을 누른 시각과 정확히 같다고 확정하지 않는다",
)
_FILE_DOWNLOAD_TAB_ONLY_LIMITATIONS = (
    "다운로드 URL 이 chatgpt.com 이 아니고 tab_url 만 ChatGPT 대화 화면이다 — 파일 출처가 ChatGPT 라고 확정하지 않는다",
    "Alternative explanation: ChatGPT 대화 화면에서 외부 링크를 눌러 ChatGPT 와 무관한 파일을 내려받은 경우에도 같은 기록이 남는다",
    "이 조합만으로 'ChatGPT 가 생성한 파일 다운로드' 를 판정하지 않는다 (action_status CANDIDATE)",
)
_FILE_DOWNLOAD_DIRECT_LIMITATION = ("Rule 이 아직 PARTIALLY_VERIFIED 다 — 다른 Chrome 버전·독립 실험에서 estuary content URL 형태의 "
                                    "일반화가 검증되지 않아 DIRECT evidence 여도 confidence 는 MEDIUM 을 넘지 않는다")


_FILE_DOWNLOAD_SHARED_PROTO_LIMITATIONS = (
    "shared_proto_db Record 의 field 의미는 이 Parser 가 실제 DD 관찰로 해석한 것이다 (Chromium 정의로 검증되지 않았고, "
    "해석하지 못한 field 는 observed 에 원본 형태로만 남는다)",
    "shared_proto_db Record 에는 History 의 downloads.state 에 대응하는 값을 확정하지 못해 파일이 끝까지 저장됐는지 판정하지 않는다",
)


def _download_origin_note(record: ArtifactRecord) -> str:
    return "History downloads" if record.artifact_type == "history" else "Chrome shared_proto_db 21_download"


def _download_chatgpt_link(record: ArtifactRecord) -> tuple[str | None, str | None, str | None]:
    """(estuary URL match 종류 | None, tab_url match 종류 | None, tab conversation id | None)."""
    observed = record.observed
    chain = [item.get("url") for item in observed.get("url_chain") or []]
    direct = next((match for match in
                   (match_history_url(url, CHATGPT_HOST, _ESTUARY_CONTENT_PATH, query_expected=True)[0] for url in chain)
                   if match is not None), None)
    tab_match, tab_path = match_history_url(observed.get("tab_url"), CHATGPT_HOST, _CONVERSATION_PATH)
    return direct, tab_match, tab_path.group(1) if tab_path is not None else None


def detect_file_download(records: list[ArtifactRecord],
                         coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {coverage.source_path: coverage.source_sha256 for coverage in coverages
                     if coverage.artifact_type in DOWNLOAD_ARTIFACT_TYPES}
    downloads = [record for record in records if _is_download_record(record)]
    history_guids = {record.observed.get("guid") for record in downloads
                     if record.artifact_type == "history"} - {None}
    # 같은 guid 가 History 에도 있으면 History Record 가 그대로 대표다 (덮어쓰지 않는다). shared_proto_db Record 는
    # 같은 다운로드의 다른 출처로 보조 Evidence 에 남긴다 — 어느 Artifact 에서 나왔는지 구분할 수 있어야 한다.
    extras: dict[Any, list[ArtifactRecord]] = {}
    for record in downloads:
        if record.artifact_type != "history" and record.observed.get("guid") in history_guids:
            extras.setdefault(record.observed.get("guid"), []).append(record)

    events: list[Event] = []
    seen: set[tuple[str, str]] = set()
    for record in downloads:
        guid = record.observed.get("guid")
        if _record_key(record) in seen or (record.artifact_type != "history" and guid in history_guids):
            continue
        direct, tab_match, conversation_id = _download_chatgpt_link(record)
        if direct is None and tab_match is None:
            continue  # ChatGPT 와 구조적으로 연결되지 않는 다운로드
        seen.add(_record_key(record))

        reasons = [REASON_RULE_PARTIALLY_VERIFIED]
        limitations = list(_FILE_DOWNLOAD_LIMITATIONS)
        if record.artifact_type == "shared_proto_db":
            limitations += list(_FILE_DOWNLOAD_SHARED_PROTO_LIMITATIONS)
        if direct is not None:
            # DIRECT evidence 지만 Rule 이 PARTIALLY_VERIFIED 라 MEDIUM 이 상한이다.
            confidence, status, level = "MEDIUM", "DETECTED", "DIRECT"
            reasons.append(REASON_DIRECT_DOWNLOAD_URL)
            limitations.append(_FILE_DOWNLOAD_DIRECT_LIMITATION)
            note = f"{_download_origin_note(record)} — ChatGPT 파일 제공 경로(backend-api/estuary/content)에서 시작된 다운로드"
            if direct == URL_MATCH_VARIANT:
                reasons.append(REASON_URL_VARIANT_NOT_VERIFIED)
                limitations.append(_VARIANT_LIMITATION)
        else:
            # 탭 문맥만 일치한다 = 행위에 고유하지 않은 근거 → CANDIDATE / LOW, evidence 도 DIRECT 로 올리지 않는다.
            confidence, status, level = "LOW", "CANDIDATE", "SUPPORTING"
            reasons += [REASON_TAB_CONTEXT_ONLY, REASON_NOT_UNIQUE_TO_ACTION]
            limitations += list(_FILE_DOWNLOAD_TAB_ONLY_LIMITATIONS)
            note = f"{_download_origin_note(record)} — 다운로드를 실행한 탭이 ChatGPT 대화 화면 (파일 출처는 chatgpt.com 이 아님)"
        extra: dict[str, Any] = {}
        if conversation_id is not None:
            extra["tab_conversation_id"] = conversation_id
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if record.timestamp_utc:
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("start_time 을 UTC/KST 로 변환하지 못해 다운로드 시각을 확인할 수 없음")
            confidence = "LOW"
        state = record.observed.get("state")
        if state is not None and state != 1:
            limitations.append(f"downloads.state={state} (Chrome 이 완료로 기록한 값 1 이 아님) — 파일이 끝까지 저장됐는지 확인하지 못함")

        evidence = _record_evidence(record, FILE_DOWNLOAD_RULE_ID, level,
                                    sha_by_source.get(record.source_path), note, extra)
        same_download = extras.get(guid, [])
        supporting = [_record_evidence(other, FILE_DOWNLOAD_RULE_ID, "SUPPORTING",
                                       sha_by_source.get(other.source_path),
                                       f"{_download_origin_note(other)} — 같은 guid 의 다운로드 Record (같은 다운로드의 다른 출처)")
                      for other in same_download]
        if supporting and REASON_SUPPORTING_CORRELATED not in reasons:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        events.append(_new_event(
            rule_id=FILE_DOWNLOAD_RULE_ID, event_record=record, representative=evidence,
            records=[record, *same_download],
            action="FILE_DOWNLOAD", action_status="CANDIDATE" if confidence == "LOW" else status,
            confidence=confidence, confidence_reason=reasons, rule_verification="PARTIALLY_VERIFIED",
            primary_evidence=[evidence], supporting_evidence=supporting, limitations=limitations,
            inference=_FILE_DOWNLOAD_INFERENCE if direct is not None else _FILE_DOWNLOAD_TAB_ONLY_INFERENCE,
        ))
    return events


# ---- CHATGPT_FILE_UPLOAD_001 ---------------------------------------------------------------------
# 근거: Cache 대화 응답 JSON (Cache Reader) 의 user 메시지 metadata.attachments[] 에 source="local" 인 파일 항목.
#   새 Reader 를 만들지 않고 Cache Reader 가 이미 보존하는 observed["conversation"]["mapping"] 만 읽는다.
# 2026-09-20 실제 사본 (C:\WHS_Analysis\PRE_CLEANUP · POST_CLEANUP 의 Cache, read-only) 에서 확인한 것:
#   같은 대화의 user 메시지 3건에 attachments 1건씩 — image/jpeg 38024 B (create_time 1787223224.127),
#   application/pdf 26779 B (1787224739.997), text/x-python 100 B (1787226914.536). 모두 source="local" 이고
#   library_file_id 를 가진다. assistant 가 만든 이미지 (DALL-E) 는 attachments 가 아니라 content 의
#   image_asset_pointer 로만 나타나 업로드와 구분된다.
# 판정: FILE_UPLOAD DETECTED / MEDIUM
#   - Evidence Level 은 DIRECT — 대화 JSON 이 "이 메시지에 로컬 파일을 첨부해 보냈다"를 직접 기술한다.
#   - backend-api/files/library/nodes 의 file_upload_time 을 읽지 않으므로 업로드 시각 근거가 없고,
#     규칙대로 MEDIUM + TIMESTAMP_APPROXIMATED 로 둔다. 대표 시각은 첨부한 메시지의 create_time 이다.
#   - source="local" 은 "업로드한 기기의 로컬"이지 "이 PC"가 아니다 → device_attribution=SERVER_SIDE_CACHE.

FILE_UPLOAD_RULE_ID = "CHATGPT_FILE_UPLOAD_001"
FILE_UPLOAD_LOCAL_SOURCE = "local"
REASON_LOCAL_ATTACHMENT = "LOCAL_ATTACHMENT"
_FILE_UPLOAD_INFERENCE = (
    "Cache 에 남은 대화 응답의 user 메시지 metadata.attachments 에 source=local 인 파일이 있음 "
    "→ 그 메시지를 보낼 때 로컬 파일을 첨부한 것으로 추론한다 "
    "(어떤 UI 조작이었는지 · 파일이 이 PC 에 지금도 있는지 · 파일 내용은 추론하지 않음)"
)
_FILE_UPLOAD_LIMITATIONS = (
    "대표 시각은 첨부한 메시지의 create_time (서버가 메시지를 만든 시각) 이며 파일을 고른 시각이 아니다 "
    "— backend-api/files/library/nodes 의 file_upload_time 을 읽지 않아 업로드 시각 자체의 근거가 없다",
    "source=local 은 업로드한 기기의 로컬을 뜻하며 이 PC 라는 뜻이 아니다 (device_attribution=SERVER_SIDE_CACHE)",
    "Cache 응답은 서버가 보낸 대화 상태라 파일 원본이 이 디스크에 남아 있다는 뜻이 아니다",
    "attachments 가 지워진 뒤 저장된 응답에는 이 구조가 남지 않는다 — 구조 부재가 업로드 부재를 뜻하지 않는다",
    "assistant 가 만든 파일·이미지 (DALL-E 등) 는 attachments 가 아니므로 이 Rule 의 대상이 아니다",
    "source 값이 local 이 아닌 첨부 (연결된 드라이브 등) 는 Negative Control 이 없어 판정하지 않는다",
)


def _file_upload_findings(record: ArtifactRecord) -> list[dict[str, Any]]:
    """Cache Record 1건 → user 메시지의 로컬 첨부 파일별 관찰 요약 (메시지 본문은 넣지 않는다)."""
    conversation = record.observed.get("conversation")
    if not isinstance(conversation, dict) or not isinstance(conversation.get("mapping"), list):
        return []
    findings: list[dict[str, Any]] = []
    for node in conversation["mapping"]:
        if not isinstance(node, dict):
            continue
        message = node.get("message")
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        attachments = message.get("attachments")
        if not isinstance(attachments, list):
            continue
        for attachment in attachments:
            if not isinstance(attachment, dict) or attachment.get("source") != FILE_UPLOAD_LOCAL_SOURCE:
                continue
            findings.append({
                "conversation_id": conversation.get("conversation_id") or record.observed.get("url_conversation_id"),
                "message_id": message.get("id") or node.get("node_id"),
                "message_create_time": message.get("create_time"),
                "file_id": attachment.get("id"),
                "file_name": attachment.get("name"),
                "mime_type": attachment.get("mime_type"),
                "size_bytes": attachment.get("size"),
                "library_file_id": attachment.get("library_file_id"),
                "attachment_source": attachment.get("source"),
            })
    return sorted(findings, key=lambda item: (str(item["message_id"]), str(item["file_id"])))


def detect_file_upload(records: list[ArtifactRecord],
                       coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """Cache 대화 응답의 user 메시지 로컬 첨부 → FILE_UPLOAD (DETECTED / MEDIUM)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "cache"}
    grouped: dict[tuple, list[tuple[ArtifactRecord, dict[str, Any]]]] = {}
    for record in records:
        if record.artifact_type != "cache":
            continue
        for finding in _file_upload_findings(record):
            key = (record.os_user or "", record.browser_profile or "",
                   str(finding["conversation_id"]), str(finding["message_id"]), str(finding["file_id"]))
            group = grouped.setdefault(key, [])
            if record.record_id not in [existing.record_id for existing, _ in group]:
                group.append((record, finding))

    events: list[Event] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: item[0].source_path)
        record, finding = group[0]
        timestamp = _json_time(finding["message_create_time"], _CACHE_MESSAGE_TIME_SOURCE) or {}
        warnings = _merged_warnings([item[0] for item in group]) + list(timestamp.pop("warnings", []))
        note = (f"Cache 대화 응답의 user 메시지 {finding['message_id']} 에 source=local 첨부 "
                f"{finding['file_id']} ({finding['mime_type']}, {finding['size_bytes']} bytes)")
        primary = _session_evidence(record, "DIRECT", sha_by_source.get(record.source_path), note, FILE_UPLOAD_RULE_ID)
        primary.observed = dict(finding)  # 첨부 메타데이터만 — 메시지 본문·파일 내용은 넣지 않는다
        supporting = []
        for other, other_finding in group[1:]:
            item = _session_evidence(other, "DIRECT", sha_by_source.get(other.source_path),
                                     f"같은 첨부가 남은 다른 Cache 사본 — {note}", FILE_UPLOAD_RULE_ID)
            item.observed = dict(other_finding)
            supporting.append(item)
        reasons = [REASON_RULE_VERIFIED, REASON_LOCAL_ATTACHMENT]
        limitations = list(_FILE_UPLOAD_LIMITATIONS)
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if timestamp.get("timestamp_utc"):
            reasons.append(REASON_TIMESTAMP_APPROXIMATED)  # 메시지 시각이며 업로드 시각이 아니다
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("첨부한 메시지의 create_time 을 UTC/KST 로 변환하지 못해 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(Event(
            event_id=f"event:{FILE_UPLOAD_RULE_ID}:{record.record_id}:file={finding['file_id']}",
            finding_type="USER_ACTION", action="FILE_UPLOAD",
            action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=timestamp.get("timestamp_raw"), timestamp_utc=timestamp.get("timestamp_utc"),
            timestamp_kst=timestamp.get("timestamp_kst"),
            timestamp_type=timestamp.get("timestamp_type", "unknown"),
            timestamp_source=timestamp.get("timestamp_source", _CACHE_MESSAGE_TIME_SOURCE),
            representative_evidence_id=primary.evidence_id, confidence=confidence, confidence_reason=reasons,
            rule_id=FILE_UPLOAD_RULE_ID, rule_verification="VERIFIED", os_user=record.os_user,
            browser=record.browser, browser_profile=record.browser_profile,
            device_attribution="SERVER_SIDE_CACHE", primary_evidence=[primary], supporting_evidence=supporting,
            inference=_FILE_UPLOAD_INFERENCE, limitations=limitations, warnings=warnings,
        ))
    return events


# ---- CHATGPT_FILE_UPLOAD_DELETE_001 --------------------------------------------------------------
# FILE_UPLOAD 이 쓰는 같은 구조 (user 메시지 metadata.attachments[] 의 source="local") 를 재사용한다.
# 판정 조건: 같은 Profile · 같은 대화의 Cache 사본 2개 이상에서, 앞선 사본에 있던 로컬 첨부가
#   뒤의 사본에서 사라지고 다른 첨부는 그대로인 전이.
# 전송 완료로 초안 첨부가 비워지는 경우와 사용자가 첨부를 직접 지운 경우를 구분하지 못한다 → CANDIDATE / LOW.
# E05-02(이미지) · E05-04(문서) 를 별도 action 으로 쪼개지 않고 FILE_UPLOAD_DELETE 하나로 두며 mime_type 을 요약에 남긴다.

FILE_UPLOAD_DELETE_RULE_ID = "CHATGPT_FILE_UPLOAD_DELETE_001"
REASON_ATTACHMENT_DISAPPEARED = "ATTACHMENT_DISAPPEARED"
_FILE_UPLOAD_DELETE_INFERENCE = (
    "같은 대화의 더 나중 Cache 사본에서 이전에 있던 로컬 첨부가 사라짐 → 그 첨부가 대화에서 제거된 것으로 관찰한다 "
    "(사용자가 지웠는지 · 전송 완료로 비워졌는지 · 서버에서 제거됐는지는 추론하지 않음)"
)
_FILE_UPLOAD_DELETE_LIMITATIONS = (
    "첨부가 사라진 사실을 관찰한 것이며 사용자의 삭제 행위를 직접 나타내지 않는다 (전송 완료·서버 측 변화와 구분 못 함)",
    "비교 시각은 Cache entry 생성 시각이며 사용자가 첨부를 지운 시각이 아니다",
    "Cache 사본이 하나뿐이면 이 전이를 볼 수 없다 — 흔적의 부재는 행위의 부재가 아니다",
    "파일 원본이 디스크에서 지워졌는지는 이 Rule 이 판정하지 않는다 ('미존재'와 '삭제'는 다르다)",
)


def _cache_records_by_conversation(records: list[ArtifactRecord]) -> dict[tuple, list[ArtifactRecord]]:
    grouped: dict[tuple, list[ArtifactRecord]] = {}
    for record in records:
        if record.artifact_type != "cache":
            continue
        conversation, _ = _cache_conversation_nodes(record)
        conversation_id = _conversation_id_of(record, conversation)
        if conversation_id:
            grouped.setdefault((record.os_user, record.browser_profile, conversation_id), []).append(record)
    return {key: sorted(group, key=lambda r: (r.timestamp_utc or "", r.record_id)) for key, group in grouped.items()}


def detect_file_upload_delete(records: list[ArtifactRecord],
                              coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """같은 대화의 나중 Cache 사본에서 로컬 첨부가 사라진 전이 → FILE_UPLOAD_DELETE (CANDIDATE / LOW)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "cache"}
    events: list[Event] = []
    for (os_user, profile, conversation_id), group in sorted(_cache_records_by_conversation(records).items(),
                                                             key=lambda item: str(item[0])):
        if len(group) < 2:
            continue
        for older, newer in zip(group, group[1:]):
            before = {str(f["file_id"]): f for f in _file_upload_findings(older)}
            after = {str(f["file_id"]) for f in _file_upload_findings(newer)}
            removed = sorted(set(before) - after)
            if not removed or set(after) - set(before):
                continue  # 사라진 것이 없거나 추가·제거가 동시에 일어났으면 전이로 보지 않는다
            for file_id in removed:
                finding = before[file_id]
                summary = {"conversation_id": conversation_id, "removed_file_id": file_id,
                           "file_name": finding.get("file_name"), "mime_type": finding.get("mime_type"),
                           "size_bytes": finding.get("size_bytes"), "message_id": finding.get("message_id"),
                           "attachment_count_before": len(before), "attachment_count_after": len(after)}
                note = (f"대화 {conversation_id} 의 나중 Cache 사본에서 로컬 첨부 {file_id} "
                        f"({finding.get('mime_type')}) 가 사라짐")
                primary = _session_evidence(newer, "SUPPORTING", sha_by_source.get(newer.source_path), note,
                                            FILE_UPLOAD_DELETE_RULE_ID)
                primary.observed = dict(summary)
                earlier = _session_evidence(older, "SUPPORTING", sha_by_source.get(older.source_path),
                                            "같은 첨부가 아직 있던 직전 Cache 사본", FILE_UPLOAD_DELETE_RULE_ID)
                earlier.observed = dict(finding)
                timestamp = {"timestamp_raw": newer.timestamp_raw, "timestamp_utc": newer.timestamp_utc,
                             "timestamp_kst": newer.timestamp_kst, "timestamp_type": newer.timestamp_type,
                             "timestamp_source": newer.timestamp_source}
                reasons = [REASON_ATTACHMENT_DISAPPEARED, REASON_SUPPORTING_CORRELATED, REASON_NOT_UNIQUE_TO_ACTION,
                           REASON_TIMESTAMP_APPROXIMATED if newer.timestamp_utc else REASON_TIMESTAMP_MISSING]
                events.append(_candidate_event(
                    rule_id=FILE_UPLOAD_DELETE_RULE_ID, action="FILE_UPLOAD_DELETE",
                    event_id=f"event:{FILE_UPLOAD_DELETE_RULE_ID}:{newer.record_id}:file={file_id}",
                    record=newer, primary=primary, supporting=[earlier], timestamp=timestamp, reasons=reasons,
                    inference=_FILE_UPLOAD_DELETE_INFERENCE, limitations=list(_FILE_UPLOAD_DELETE_LIMITATIONS),
                    confidence="LOW", device_attribution="SERVER_SIDE_CACHE",
                    warnings=_merged_warnings([older, newer])))
    return events
