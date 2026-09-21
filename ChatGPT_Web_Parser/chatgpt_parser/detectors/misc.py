"""그 밖의 Rule (DATA_EXPORT / IMAGE_GENERATION / TEMPORARY_CHAT / SHARE_LINK / MODEL_CHANGE / HISTORY_DELETE / CACHE_DELETE / INCOGNITO)."""
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
from ..artifacts.cache import REASON_DIRECT_URL, REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING
from ..artifacts.history import redact_url_query
from ..artifacts.session_storage import SESSION_STORAGE_ORIGIN
from ..detectors.common import CHATGPT_HOST, DATA_EXPORT_REQUEST_RULE_ID, REASON_EMBEDDED_TIMESTAMP, REASON_HEURISTIC_RULE, REASON_MULTIPLE_SUPPORTING_SIGNALS, REASON_NOT_UNIQUE_TO_ACTION, REASON_RULE_PARTIALLY_VERIFIED, REASON_SUPPORTING_CORRELATED, REASON_TIMESTAMP_APPROXIMATED, _HEURISTIC_COMMON_LIMITATIONS, _cache_conversation_nodes, _candidate_event, _conversation_id_of, _merged_warnings, _message_sort_key, _session_evidence
from ..models import Event, EvidenceItem
from ..recovery.conversations import _CACHE_MESSAGE_TIME_SOURCE, _json_time


REASON_DIRECT_KEY = "DIRECT_KEY"
_DATA_EXPORT_INFERENCE = ("ChatGPT 데이터 내보내기 흐름에서 '최종 확인 대기' 상태가 이 브라우저의 chatgpt.com Session Storage 에 "
                          "기록됨 → Export 요청 단계까지 진행한 것으로 추론한다 (확인 완료·서버 접수·Export 완료는 추론하지 않음)")
_DATA_EXPORT_LIMITATIONS = (
    "chatgpt_export_data_pending_confirm 는 Export 최종 확인 대기 상태 키로 관찰됨 (E07-01). "
    "요청 전송·서버 접수·Export 완료 (메일·ZIP 다운로드) 는 이 근거로 확인하지 않는다",
    "확인 창에서 취소한 경우에도 같은 키가 기록·삭제되는지 실험되지 않음 (Negative Control 없음, NEEDS_VERIFICATION)",
    "내보내기 화면은 SPA 모달이라 History·SNSS 에 Export 관련 URL 이 남지 않음 (E07-01) — History 보조 근거 없음",
    "Session Storage 는 탭·브라우저 종료 시 정리될 수 있어 키 부재가 요청 없음을 뜻하지 않는다",
    "Session Storage 는 동기화되지 않는 브라우저 로컬 저장소라 LOCAL 후보이나 실험으로 확정하지 않아 device_attribution UNKNOWN",
)


def detect_data_export_request(records: list[ArtifactRecord],
                               coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "session_storage"}
    keyed: dict[str, ArtifactRecord] = {}
    for record in records:
        observed = record.observed
        if (record.artifact_type == "session_storage" and observed.get("key_kind") == "data_export_pending_confirm"
                and observed.get("storage_origin") == SESSION_STORAGE_ORIGIN):
            keyed.setdefault(record.record_id, record)  # 같은 Record 중복 입력 → 1건
    ordered = sorted(keyed.values(), key=lambda r: (r.os_user or "", r.browser_profile or "", r.source_path,
                                                    r.observed.get("sequence", -1)))
    events: list[Event] = []
    for index, put in enumerate(ordered):
        if put.observed.get("operation") != "PUT":
            continue
        owner = (put.source_path, put.os_user, put.browser_profile)
        delete = None
        for later in ordered[index + 1:]:
            if (later.source_path, later.os_user, later.browser_profile) != owner:
                continue
            delete = later if later.observed.get("operation") == "DELETE" else None
            break  # 바로 다음 같은 키 operation 만 본다 (다음 PUT 이면 DELETE 없음)
        sha = sha_by_source.get(put.source_path)
        primary = _session_evidence(put, "DIRECT", sha, "Session Storage 확인 대기 키 PUT — 값은 Unix ms 시각")
        supporting = [] if delete is None else [_session_evidence(
            delete, "SUPPORTING", sha, "같은 키 DELETE (값·시각 없음) — 대기 상태 해제로 보이나 확인 완료·Export 완료를 뜻하지 않음")]
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_KEY, REASON_EMBEDDED_TIMESTAMP]
        limitations = list(_DATA_EXPORT_LIMITATIONS)
        if delete is not None:
            reasons.append(REASON_SUPPORTING_CORRELATED)
            limitations.append(f"같은 키의 DELETE (sequence {delete.observed.get('sequence')}) 가 뒤에 있음 — 시각이 없고 확인 완료를 뜻하지 않음")
        else:
            limitations.append("같은 .log 에서 이 PUT 뒤에 같은 키의 DELETE 가 없음 — 대기 상태가 해제됐는지 확인하지 못함")
        if put.timestamp_utc:
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("값을 Unix ms 시각으로 변환하지 못해 요청 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(Event(
            event_id=f"event:{DATA_EXPORT_REQUEST_RULE_ID}:{put.record_id}", finding_type="USER_ACTION",
            action="DATA_EXPORT_REQUEST", action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=put.timestamp_raw, timestamp_utc=put.timestamp_utc, timestamp_kst=put.timestamp_kst,
            timestamp_type=put.timestamp_type, timestamp_source=put.timestamp_source,
            representative_evidence_id=primary.evidence_id, confidence=confidence, confidence_reason=reasons,
            rule_id=DATA_EXPORT_REQUEST_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=put.os_user,
            browser=put.browser, browser_profile=put.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_DATA_EXPORT_INFERENCE,
            limitations=limitations, warnings=list(put.warnings),
        ))
    return events


# ---- 8.13 CHATGPT_IMAGE_GENERATION_REQUEST_001 (Session Storage imagegen_progress) ----
# 근거: origin https://chatgpt.com/ 의 imagegen_progress:<uuid> PUT (§7.5 Reader Record).
# 2026-09-18 실제 마커 DD (llmtest/Default/Session Storage/000003.log) 에서 확인한 것:
#   - 같은 key 에 PUT 4건 (lastDisplayedPercent 40 → 50 → 61 → 74). startedAtMs·estimatedDurationMs 는 4건 모두 같은 값
#   - 그 뒤 같은 key 의 DELETE 1건 (값 없음) — 진행 표시가 끝났다는 뜻일 뿐 생성 완료 판정에 쓰지 않는다
#   - startedAtMs = 2026-09-15T01:28:18.265+09:00. Ground Truth E06-01 '이미지 생성 요청' 2026-09-15 01:28:25.596 과
#     7.331초 차이 (artifact 가 더 이름). 같은 이미지의 다른 Event 도 GT 보다 이른 쪽이다 (E05-05 −12.649초, E06-02 −6.140초)
#   - key 의 <uuid> 는 History 의 conversation id 중 어느 것과도 같지 않았다 → 대화 상관은 하지 않는다 (conversation_id 없음)
# 판정: IMAGE_GENERATION_REQUEST DETECTED / MEDIUM, rule_verification PARTIALLY_VERIFIED
#   - 이 브라우저 탭에서 이미지 생성 진행 표시가 시작된 것까지만 본다. 생성 완료·이미지 저장·다운로드는 판정하지 않는다
#   - 취소·새로고침 때도 같은 키가 남는지, 한 대화에서 여러 번 요청하면 키가 몇 개 생기는지 실험되지 않음 → HIGH 조건 미충족
#   - 같은 (key, startedAtMs) PUT 여러 건 = 진행률 갱신 → Event 1건 (첫 PUT 이 대표 DIRECT, 나머지는 SUPPORTING)
#   - startedAtMs 를 시각으로 바꾸지 못하면 LOW / CANDIDATE

IMAGE_GENERATION_REQUEST_RULE_ID = "CHATGPT_IMAGE_GENERATION_REQUEST_001"
_IMAGEGEN_INFERENCE = ("chatgpt.com Session Storage 에 이미지 생성 진행 상태 키 (imagegen_progress) 가 기록됨 → 이 브라우저 탭에서 "
                       "이미지 생성 요청 단계까지 진행한 것으로 추론한다 (생성 완료·이미지 저장·다운로드는 추론하지 않음)")
_IMAGEGEN_LIMITATIONS = (
    "imagegen_progress 는 이미지 생성 진행률 표시용 키로 관찰됨 (실제 마커 DD) — 생성 성공·이미지 수신 여부는 이 근거로 판정하지 않는다",
    "생성 도중 취소하거나 페이지를 새로고침한 경우에도 같은 키가 기록되는지 실험되지 않음 (Negative Control 없음, NEEDS_VERIFICATION)",
    "한 대화에서 이미지 생성을 여러 번 요청할 때 키가 몇 개 생기는지 실험되지 않음 (관찰 사례 1건, NEEDS_VERIFICATION)",
    "startedAtMs 가 사용자의 요청 입력 시각인지 클라이언트 진행 표시 시작 시각인지 구분하는 실험이 없다",
    "key 의 <uuid> 는 History 의 conversation id 와 일치하지 않아 어떤 대화의 요청인지 이 근거만으로 연결하지 않는다",
    "Session Storage 는 탭·브라우저 종료 시 정리될 수 있어 키 부재가 이미지 생성 요청 없음을 뜻하지 않는다",
    "Session Storage 는 동기화되지 않는 브라우저 로컬 저장소라 LOCAL 후보이나 실험으로 확정하지 않아 device_attribution UNKNOWN",
)


def detect_image_generation_request(records: list[ArtifactRecord],
                                    coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "session_storage"}
    keyed: dict[str, ArtifactRecord] = {}
    for record in records:
        observed = record.observed
        if (record.artifact_type == "session_storage" and observed.get("key_kind") == "imagegen_progress"
                and observed.get("storage_origin") == SESSION_STORAGE_ORIGIN
                and observed.get("operation") == "PUT" and observed.get("started_at_ms") is not None):
            keyed.setdefault(record.record_id, record)  # 같은 Record 중복 입력 → 1건
    groups: dict[tuple[str, ...], list[ArtifactRecord]] = {}
    for record in sorted(keyed.values(), key=lambda r: (r.os_user or "", r.browser_profile or "", r.source_path,
                                                        r.observed.get("sequence", -1))):
        observed = record.observed
        groups.setdefault((record.os_user or "", record.browser_profile or "", record.source_path,
                           str(observed.get("key_suffix")), str(observed.get("started_at_ms"))), []).append(record)
    events: list[Event] = []
    for group in groups.values():
        first, updates = group[0], group[1:]
        sha = sha_by_source.get(first.source_path)
        primary = _session_evidence(first, "DIRECT", sha, "이미지 생성 진행 상태 키 PUT — 값의 startedAtMs 가 진행 시작 시각",
                                    IMAGE_GENERATION_REQUEST_RULE_ID)
        supporting = [_session_evidence(update, "SUPPORTING", sha,
                                        "같은 key·startedAtMs 의 진행률 갱신 PUT — 새로운 요청이 아니다",
                                        IMAGE_GENERATION_REQUEST_RULE_ID) for update in updates]
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_KEY, REASON_EMBEDDED_TIMESTAMP]
        limitations = list(_IMAGEGEN_LIMITATIONS)
        if updates:
            reasons.append(REASON_SUPPORTING_CORRELATED)
            limitations.append(f"같은 key 의 진행률 갱신 PUT {len(updates)}건을 같은 요청으로 묶었다 "
                               f"(sequence {[u.observed.get('sequence') for u in updates]})")
        if first.timestamp_utc:
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("startedAtMs 를 Unix ms 시각으로 변환하지 못해 요청 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(Event(
            event_id=f"event:{IMAGE_GENERATION_REQUEST_RULE_ID}:{first.record_id}", finding_type="USER_ACTION",
            action="IMAGE_GENERATION_REQUEST", action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=first.timestamp_raw, timestamp_utc=first.timestamp_utc, timestamp_kst=first.timestamp_kst,
            timestamp_type=first.timestamp_type, timestamp_source=first.timestamp_source,
            representative_evidence_id=primary.evidence_id, confidence=confidence, confidence_reason=reasons,
            rule_id=IMAGE_GENERATION_REQUEST_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=first.os_user,
            browser=first.browser, browser_profile=first.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_IMAGEGEN_INFERENCE,
            limitations=limitations, warnings=list(first.warnings),
        ))
    return events


# ---- 8.14 CHATGPT_TEMPORARY_CHAT_001 -----------------------------------------
# 근거: Sessions (SNSS) navigation entry 의 chatgpt.com URL query 에 temporary-chat=true 가 있는 경우 (§7.7 Reader).
# 2026-09-19 실제 평문 DD (Profile 1/Sessions) 에서 확인한 것:
#   같은 navigation 1건이 Session_13433848693271468(cmd 6) · Tabs_13433848648354897(cmd 1) ·
#   Tabs_13433918899064245(cmd 1) 세 파일에 tab_id 만 다르게 중복 저장됐고, index · title("ChatGPT") ·
#   referrer(같은 계정의 /c/<id> 대화) · original_request_url(https://chatgpt.com/) · timestamp 는 모두 같았다.
#   같은 Profile 의 다른 chatgpt.com navigation (/auth/logout, ?account_switch_action=logout, /ko-KR/download/) 과
#   다른 Profile 의 다른 서비스 navigation 에는 temporary-chat query 가 없었다.
# 판정: TEMPORARY_CHAT DETECTED / MEDIUM, PARTIALLY_VERIFIED
#   - Artifact 가 직접 나타내는 사실 = "이 탭이 임시 채팅 URL 상태로 저장됨". 메시지 전송·임시 대화 내용·종료 시각은 판정하지 않는다.
#   - temporary-chat=true 를 만들지 않는 Negative Control 실험 (URL 직접 입력 · 북마크 · 복원) 이 없어 HIGH / VERIFIED 를 쓰지 않는다.
#   - 문자열 contains 가 아니라 scheme · host · query key/value 구조로 판정한다.

TEMPORARY_CHAT_RULE_ID = "CHATGPT_TEMPORARY_CHAT_001"
TEMPORARY_CHAT_QUERY_KEY = "temporary-chat"
TEMPORARY_CHAT_QUERY_VALUE = "true"
_TEMPORARY_CHAT_INFERENCE = (
    "이 브라우저 Profile 의 탭 세션 상태에 chatgpt.com 임시 채팅 query (temporary-chat=true) navigation 이 저장됨 "
    "→ 임시 채팅 화면에 들어간 것으로 추론한다 (메시지 전송 · 임시 대화 내용 · 종료 시각은 추론하지 않음)"
)
_TEMPORARY_CHAT_LIMITATIONS = (
    "navigation entry 저장은 임시 채팅 화면 상태까지만 나타내고, 그 화면에서 실제로 프롬프트를 보냈는지는 판정하지 않는다",
    "URL 직접 입력 · 북마크 · 링크 열기 · 탭 복원으로도 같은 navigation 이 저장될 수 있다 (Negative Control 실험 없음, NEEDS_VERIFICATION)",
    "SNSS navigation timestamp 는 그 navigation entry 의 시각으로 관찰됨 — 파일 이름 시각 (세션 파일 저장 시각) · 브라우저 종료 시각과 다르다",
    "같은 navigation 이 Session_ · Tabs_ 여러 파일에 중복 저장되어 (os_user, profile, URL, navigation timestamp, index) 로 Event 1건으로 합쳤다",
    "SNSS 는 브라우저 로컬 탭 상태라 LOCAL 후보이나 실험으로 확정하지 않아 device_attribution UNKNOWN",
    "SNSS command id · navigation 필드 순서는 이 DD 의 Chrome 버전에서 관찰한 것이며 다른 버전에서 검증되지 않았다",
)


def match_temporary_chat_url(url: Any) -> bool:
    """http(s) + host 가 chatgpt.com + query 에 temporary-chat=true 가 있으면 True (문자열 contains 아님)."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or (parts.hostname or "").rstrip(".") != CHATGPT_HOST:
        return False
    return any(key.casefold() == TEMPORARY_CHAT_QUERY_KEY and value.casefold() == TEMPORARY_CHAT_QUERY_VALUE
               for key, value in parse_qsl(parts.query, keep_blank_values=True))


def _temporary_chat_note(record: ArtifactRecord) -> str:
    observed = record.observed
    return (f"Sessions navigation (command {observed.get('snss_command_id')}, tab_id {observed.get('tab_id')}, "
            f"index {observed.get('navigation_index')}) 의 임시 채팅 query URL")


def detect_temporary_chat(records: list[ArtifactRecord],
                          coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "sessions"}
    grouped: dict[tuple, list[ArtifactRecord]] = {}
    for record in records:
        if record.artifact_type != "sessions" or not match_temporary_chat_url(record.observed.get("url")):
            continue
        key = (record.os_user or "", record.browser_profile or "", record.observed.get("url"),
               record.timestamp_raw, record.observed.get("navigation_index"))
        group = grouped.setdefault(key, [])
        if record.record_id not in [existing.record_id for existing in group]:
            group.append(record)

    events: list[Event] = []
    for key in sorted(grouped, key=lambda item: (str(item[3]), item[0], item[1])):
        group = sorted(grouped[key], key=lambda record: record.source_path)
        record = group[0]
        primary = _session_evidence(record, "DIRECT", sha_by_source.get(record.source_path),
                                    _temporary_chat_note(record), TEMPORARY_CHAT_RULE_ID)
        supporting = [_session_evidence(other, "SUPPORTING", sha_by_source.get(other.source_path),
                                        f"같은 navigation 의 중복 저장본 — {_temporary_chat_note(other)}",
                                        TEMPORARY_CHAT_RULE_ID)
                      for other in group[1:]]
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_URL]
        limitations = list(_TEMPORARY_CHAT_LIMITATIONS)
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        if record.timestamp_utc:
            reasons.append(REASON_TIMESTAMP_EXPLAINED)
            confidence = "MEDIUM"
        else:
            reasons.append(REASON_TIMESTAMP_MISSING)
            limitations.append("navigation timestamp 를 UTC/KST 로 변환하지 못해 시각을 확인할 수 없음")
            confidence = "LOW"
        events.append(Event(
            event_id=f"event:{TEMPORARY_CHAT_RULE_ID}:{record.record_id}", finding_type="USER_ACTION",
            action="TEMPORARY_CHAT", action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
            timestamp_raw=record.timestamp_raw, timestamp_utc=record.timestamp_utc,
            timestamp_kst=record.timestamp_kst, timestamp_type=record.timestamp_type,
            timestamp_source=record.timestamp_source, representative_evidence_id=primary.evidence_id,
            confidence=confidence, confidence_reason=reasons, rule_id=TEMPORARY_CHAT_RULE_ID,
            rule_verification="PARTIALLY_VERIFIED", os_user=record.os_user, browser=record.browser,
            browser_profile=record.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_TEMPORARY_CHAT_INFERENCE,
            limitations=limitations, warnings=_merged_warnings(group),
        ))
    return events


# ---- 8.20 CHATGPT_SHARE_LINK_001 --------------------------------------------
# 근거: 어떤 Reader 가 만든 Record 든 그 안의 URL 이 ChatGPT 공유 링크 형태인 경우.
#   /share/<id>            → 공유 링크 화면 (DIRECT 에 가까운 근거)
#   /backend-api/share...  → 공유 API 경로 (요청 단계만, 생성·해제 구분 못 함)
# 공유 링크 생성 실험 자료가 없어 Rule 은 검증되지 않았다. 기존 실험의 share URL 은 재사용하지 않는다.

SHARE_LINK_RULE_ID = "CHATGPT_SHARE_LINK_001"
_SHARE_VIEW_PATTERN = re.compile(r"https?://[^/]*chatgpt\.com/share/([0-9a-zA-Z\-]+)")
_SHARE_API_PATTERN = re.compile(r"https?://[^/]*chatgpt\.com/backend-api/[^\s\"']*share", re.IGNORECASE)
_SHARE_URL_FIELDS = ("url", "original_request_url", "download_url", "tab_url", "tab_referrer_url", "referrer",
                     "referrer_url")
REASON_SHARE_URL = "SHARE_URL"
REASON_SHARE_API_URL = "SHARE_API_URL"
_SHARE_LINK_INFERENCE = (
    "ChatGPT 공유 링크 형태의 URL 이 관찰됨 → 대화 공유 링크를 만들었거나 열어 본 것으로 관찰한다 "
    "(생성·열람·해제 중 무엇이었는지 · 누가 만든 링크인지는 추론하지 않음)"
)
_SHARE_LINK_LIMITATIONS = (
    "공유 링크를 '연' 것과 '만든' 것을 구분하지 못한다 (다른 사람이 만든 링크를 열어도 같은 URL 이 남는다)",
    "공유 해제(link 삭제) 는 이 Rule 이 판정하지 않는다",
    "공유 링크 생성 전후를 비교한 자료가 없어 Rule 이 검증되지 않았다 (NEEDS_VERIFICATION)",
    "URL 의 공유 ID 는 대화 ID 와 다르므로 대화 내용과 자동으로 연결하지 않는다",
)


def _share_link_hits(record: ArtifactRecord) -> list[tuple[str, str, str]]:
    """Record 안의 공유 URL → (필드 이름, 종류, 정리된 URL) 목록."""
    hits = []
    for field_name in _SHARE_URL_FIELDS:
        value = record.observed.get(field_name)
        if not isinstance(value, str) or not value:
            continue
        redacted = redact_url_query(value)[0]
        if _SHARE_VIEW_PATTERN.search(value):
            hits.append((field_name, "share_view", redacted))
        elif _SHARE_API_PATTERN.search(value):
            hits.append((field_name, "share_api", redacted))
    return hits


def detect_share_link(records: list[ArtifactRecord],
                      coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """공유 링크 URL 이 남은 Record → SHARE_LINK (CANDIDATE)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    grouped: dict[tuple, list[tuple[ArtifactRecord, str, str, str]]] = {}
    for record in records:
        for field_name, kind, url in _share_link_hits(record):
            key = (record.os_user or "", record.browser_profile or "", kind, url, record.timestamp_utc or "")
            grouped.setdefault(key, []).append((record, field_name, kind, url))

    events: list[Event] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: (item[0].artifact_type, item[0].record_id))
        record, field_name, kind, url = group[0]
        note = f"{record.artifact_type} Record 의 {field_name} 이 ChatGPT 공유 링크 형태 ({kind})"
        primary = _session_evidence(record, "SUPPORTING" if kind == "share_api" else "DIRECT",
                                    sha_by_source.get(record.source_path), note, SHARE_LINK_RULE_ID)
        primary.observed = {"share_url": url, "share_url_kind": kind, "url_field": field_name,
                            "artifact_type": record.artifact_type}
        supporting = []
        for other, other_field, _, other_url in group[1:]:
            item = _session_evidence(other, "SUPPORTING", sha_by_source.get(other.source_path),
                                     f"같은 공유 링크가 남은 다른 Record ({other.artifact_type}.{other_field})",
                                     SHARE_LINK_RULE_ID)
            item.observed = {"share_url": other_url, "url_field": other_field}
            supporting.append(item)
        timestamp = {"timestamp_raw": record.timestamp_raw, "timestamp_utc": record.timestamp_utc,
                     "timestamp_kst": record.timestamp_kst, "timestamp_type": record.timestamp_type,
                     "timestamp_source": record.timestamp_source}
        reasons = [REASON_SHARE_URL if kind == "share_view" else REASON_SHARE_API_URL, REASON_NOT_UNIQUE_TO_ACTION,
                   REASON_TIMESTAMP_EXPLAINED if record.timestamp_utc else REASON_TIMESTAMP_MISSING]
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        confidence = "MEDIUM" if kind == "share_view" and record.timestamp_utc else "LOW"
        events.append(_candidate_event(
            rule_id=SHARE_LINK_RULE_ID, action="SHARE_LINK",
            event_id=f"event:{SHARE_LINK_RULE_ID}:{record.record_id}:{field_name}",
            record=record, primary=primary, supporting=supporting, timestamp=timestamp, reasons=reasons,
            inference=_SHARE_LINK_INFERENCE, limitations=list(_SHARE_LINK_LIMITATIONS), confidence=confidence,
            warnings=_merged_warnings([item[0] for item in group])))
    return events


# ---- 8.21 CHATGPT_MODEL_CHANGE_001 ------------------------------------------
# 근거: Cache 대화 응답 mapping 의 assistant 메시지 metadata.model_slug (§7.4 reducer 가 보존).
# 판정 조건: 같은 대화 안에서 시각 순으로 이어지는 assistant 응답의 model_slug 가 A → B 로 바뀐 전이.
# models / tpp-models 목록(카탈로그)이 존재한다는 것만으로는 Event 를 만들지 않는다 — 전이가 있어야 한다.
# 2026-09-20 조사: PRE/POST Cache 전수에서 model_slug 는 같은 값(auto)뿐이라 전이가 관찰되지 않았다 → Event 0건.

MODEL_CHANGE_RULE_ID = "CHATGPT_MODEL_CHANGE_001"
REASON_MODEL_SLUG_TRANSITION = "MODEL_SLUG_TRANSITION"
_MODEL_CHANGE_INFERENCE = (
    "같은 대화의 이어지는 assistant 응답에서 model_slug 가 서로 다름 → 대화 중 모델이 바뀐 것으로 관찰한다 "
    "(사용자가 모델을 직접 골랐는지 · 자동 라우팅인지는 추론하지 않음)"
)
_MODEL_CHANGE_LIMITATIONS = (
    "model_slug 는 응답을 만든 모델이며 사용자가 UI 에서 고른 값이라는 근거가 아니다 (자동 라우팅으로도 바뀔 수 있다)",
    "모델 목록(카탈로그) 이 Cache 에 있다는 것은 선택·변경의 근거가 아니다",
    "시각은 바뀐 뒤 응답의 create_time (서버 생성 시각) 이며 사용자가 모델을 바꾼 시각이 아니다",
    "모델 변경 전후를 비교한 실험 자료가 없어 Rule 이 검증되지 않았다 (NEEDS_VERIFICATION)",
)


def _model_transitions(record: ArtifactRecord) -> list[dict[str, Any]]:
    conversation, nodes = _cache_conversation_nodes(record)
    ordered = []
    for node in nodes:
        message = node.get("message")
        if (isinstance(message, dict) and message.get("role") == "assistant"
                and isinstance(message.get("model_slug"), str) and message["model_slug"]):
            ordered.append(message)
    ordered.sort(key=_message_sort_key)
    transitions = []
    for older, newer in zip(ordered, ordered[1:]):
        if older["model_slug"] == newer["model_slug"]:
            continue
        transitions.append({
            "conversation_id": _conversation_id_of(record, conversation),
            "model_slug_before": older["model_slug"], "model_slug_after": newer["model_slug"],
            "message_id_before": older.get("id"), "message_id_after": newer.get("id"),
            "message_create_time": newer.get("create_time"),
        })
    return transitions


def detect_model_change(records: list[ArtifactRecord],
                        coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """같은 대화 안의 model_slug A → B 전이 → MODEL_CHANGE (CANDIDATE)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "cache"}
    seen: dict[tuple, tuple[ArtifactRecord, dict[str, Any]]] = {}
    for record in records:
        if record.artifact_type != "cache":
            continue
        for transition in _model_transitions(record):
            key = (record.os_user or "", record.browser_profile or "", str(transition["conversation_id"]),
                   str(transition["message_id_after"]), transition["model_slug_before"], transition["model_slug_after"])
            seen.setdefault(key, (record, transition))

    events: list[Event] = []
    for key in sorted(seen):
        record, transition = seen[key]
        timestamp = _json_time(transition["message_create_time"], _CACHE_MESSAGE_TIME_SOURCE) or {}
        warnings = list(record.warnings) + list(timestamp.pop("warnings", []))
        note = (f"대화 {transition['conversation_id']} 의 assistant 응답 model_slug 가 "
                f"{transition['model_slug_before']} → {transition['model_slug_after']} 로 바뀜")
        primary = _session_evidence(record, "SUPPORTING", sha_by_source.get(record.source_path), note,
                                    MODEL_CHANGE_RULE_ID)
        primary.observed = dict(transition)
        reasons = [REASON_MODEL_SLUG_TRANSITION, REASON_NOT_UNIQUE_TO_ACTION,
                   REASON_TIMESTAMP_APPROXIMATED if timestamp.get("timestamp_utc") else REASON_TIMESTAMP_MISSING]
        events.append(_candidate_event(
            rule_id=MODEL_CHANGE_RULE_ID, action="MODEL_CHANGE",
            event_id=f"event:{MODEL_CHANGE_RULE_ID}:{record.record_id}:message={transition['message_id_after']}",
            record=record, primary=primary, supporting=[], timestamp=timestamp, reasons=reasons,
            inference=_MODEL_CHANGE_INFERENCE, limitations=list(_MODEL_CHANGE_LIMITATIONS),
            confidence="MEDIUM" if timestamp.get("timestamp_utc") else "LOW",
            device_attribution="SERVER_SIDE_CACHE", warnings=warnings))
    return events


# ---- 8.23 CHATGPT_HISTORY_DELETE_001 ----------------------------------------
# 방문기록 삭제 고유의 흔적은 기존 조사(REPORT REAUDIT F-7)에서 확인되지 않았다. 그래서 단일 신호로는 판정하지 않고,
# 서로 독립적인 보조 신호가 2개 이상 모일 때만 CANDIDATE / LOW 로 남긴다 (3개 이상이면 MEDIUM 검토).
#   S1 ChatGPT 대화 목록(conversation-history)에 대화 ID 가 있는데 History 에 그 대화 방문이 하나도 없음
#   S2 History 에 남은 가장 이른 ChatGPT 방문보다 이른 ChatGPT 활동이 다른 Artifact 에 있음 (그 구간을 History 가 덮지 못함)
#   S3 History Coverage 는 PARSED 인데 ChatGPT 방문 Record 가 0건이고 같은 Profile 에 다른 ChatGPT Artifact 가 있음
# "History 가 비어 있다" 하나만으로는 Event 를 만들지 않는다. Chrome 전체 방문기록 삭제일 수 있고 ChatGPT 전용 행위가 아니다.
# confidence 는 LOW 로 고정한다. S2(방문이 있어야 성립)와 S3(방문이 0건일 때만 성립)는 동시에 성립할 수 없어
# 신호가 3개 모이는 구성이 없고, 신호 개수로 confidence 를 올리지도 않는다.

HISTORY_DELETE_RULE_ID = "CHATGPT_HISTORY_DELETE_001"
REASON_CONVERSATION_VISIT_MISSING = "CONVERSATION_VISIT_MISSING"
REASON_ACTIVITY_BEFORE_FIRST_VISIT = "ACTIVITY_BEFORE_FIRST_VISIT"
REASON_NO_VISIT_WITH_OTHER_ARTIFACTS = "NO_VISIT_WITH_OTHER_ARTIFACTS"
_HISTORY_DELETE_INFERENCE = (
    "ChatGPT 사용 흔적이 다른 Artifact 에는 남아 있는데 대응하는 History 방문 기록이 없음 → "
    "방문기록이 지워졌을 가능성이 있는 것으로만 관찰한다 (누가·언제·어떤 범위를 지웠는지는 추론하지 않음)"
)
_HISTORY_DELETE_LIMITATIONS = (
    "방문기록 삭제에 고유한 흔적은 확인되지 않았다. 이 Event 는 '삭제됨'이 아니라 '방문 기록이 없다'는 관찰이다",
    "Chrome 전체 방문기록 삭제일 수 있으며 ChatGPT 전용 행위가 아니다",
    "History 가 보관 주기·프로필 재생성·다른 기기 사용 때문에 비어 있을 수도 있다 ('미존재'는 '삭제'가 아니다)",
    "삭제 시각의 근거가 없어 Event 시각을 만들지 않는다 (시각 없음)",
    "삭제 전후를 비교한 자료가 없어 Rule 이 검증되지 않았다 (NEEDS_VERIFICATION)",
    "신호가 2개 이상 모여도 confidence 는 LOW 로 둔다 (근거 개수로 신뢰도를 올리지 않는다)",
)


def _chatgpt_visits(records: list[ArtifactRecord]) -> list[ArtifactRecord]:
    return [r for r in records if r.artifact_type == "history" and r.observed.get("record_kind") != "download"
            and isinstance(r.observed.get("url"), str)]


def detect_history_delete(records: list[ArtifactRecord],
                          coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """History 방문 기록의 결손 신호가 2개 이상 겹칠 때만 HISTORY_DELETE (CANDIDATE)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    profiles: dict[tuple, list[ArtifactRecord]] = {}
    for record in records:
        profiles.setdefault((record.os_user, record.browser_profile), []).append(record)

    events: list[Event] = []
    for profile_key in sorted(profiles, key=str):
        group = profiles[profile_key]
        visits = _chatgpt_visits(group)
        visit_urls = " ".join(str(r.observed.get("url")) for r in visits)
        conversation_ids = sorted({item.get("id") for r in group if r.artifact_type == "local_storage"
                                   and r.observed.get("key_kind") == "conversation_history"
                                   for item in (r.observed.get("conversation_items") or [])
                                   if isinstance(item, dict) and isinstance(item.get("id"), str)})
        other_records = [r for r in group if r.artifact_type != "history" and r.timestamp_utc]
        first_visit = min((r.timestamp_utc for r in visits if r.timestamp_utc), default=None)
        history_parsed = any(c.artifact_type == "history" and c.status == "PARSED"
                             and (c.os_user, c.browser_profile) == profile_key for c in coverages)

        signals: list[tuple[str, str, ArtifactRecord]] = []
        unvisited = [cid for cid in conversation_ids if cid not in visit_urls]
        if conversation_ids and len(unvisited) == len(conversation_ids):
            anchor = next(r for r in group if r.artifact_type == "local_storage"
                          and r.observed.get("key_kind") == "conversation_history")
            signals.append((REASON_CONVERSATION_VISIT_MISSING,
                            f"대화 목록에 대화 {len(conversation_ids)}건이 있으나 History 에 그 대화 방문이 0건", anchor))
        earlier = [r for r in other_records if first_visit and r.timestamp_utc < first_visit]
        if earlier:
            anchor = min(earlier, key=lambda r: r.timestamp_utc)
            signals.append((REASON_ACTIVITY_BEFORE_FIRST_VISIT,
                            f"History 의 가장 이른 ChatGPT 방문({first_visit})보다 이른 ChatGPT 활동이 "
                            f"{anchor.artifact_type} 에 있음({anchor.timestamp_utc})", anchor))
        if history_parsed and not visits and other_records:
            signals.append((REASON_NO_VISIT_WITH_OTHER_ARTIFACTS,
                            "History 는 읽혔지만 ChatGPT 방문 Record 가 0건이고 다른 ChatGPT Artifact 는 존재",
                            other_records[0]))
        if len(signals) < 2:
            continue  # 단일 신호로는 판정하지 않는다

        anchor_record = signals[0][2]
        primary = _session_evidence(anchor_record, "INFERRED", sha_by_source.get(anchor_record.source_path),
                                    signals[0][1], HISTORY_DELETE_RULE_ID)
        primary.observed = {"signal": signals[0][0], "signal_count": len(signals),
                            "conversation_count": len(conversation_ids), "chatgpt_visit_count": len(visits)}
        supporting = []
        for reason, text, record in signals[1:]:
            item = _session_evidence(record, "INFERRED", sha_by_source.get(record.source_path), text,
                                     HISTORY_DELETE_RULE_ID)
            item.observed = {"signal": reason, "artifact_type": record.artifact_type}
            supporting.append(item)
        reasons = [reason for reason, _, _ in signals] + [REASON_MULTIPLE_SUPPORTING_SIGNALS,
                                                          REASON_NOT_UNIQUE_TO_ACTION, REASON_TIMESTAMP_MISSING]
        events.append(_candidate_event(
            rule_id=HISTORY_DELETE_RULE_ID, action="HISTORY_DELETE",
            event_id=f"event:{HISTORY_DELETE_RULE_ID}:{anchor_record.record_id}",
            record=anchor_record, primary=primary, supporting=supporting, timestamp={}, reasons=reasons,
            inference=_HISTORY_DELETE_INFERENCE, limitations=list(_HISTORY_DELETE_LIMITATIONS), confidence="LOW",
            warnings=_merged_warnings([record for _, _, record in signals])))
    return events


# ---- 8.25 CHATGPT_CACHE_DELETE_001 ------------------------------------------
# 브라우저 캐시 삭제 고유의 흔적은 없다. 단일 수집본에서 볼 수 있는 것은 "있어야 할 캐시가 없다" 뿐이라
# 독립 신호 2개 이상이 겹칠 때만 CANDIDATE / LOW 로 남긴다. 정상 eviction 과 구분하지 못한다.
#   S1 (필수) Cache Coverage 는 PARSED 인데 ChatGPT 대화 응답 Record 가 0건 — 캐시는 읽혔지만 대상 entry 가 없음
#   S2 같은 Profile 의 대화 목록에 대화 ID 가 남아 있음 (캐시될 대상이 있었음)
#   S3 같은 Profile 의 History·Sessions 에 ChatGPT 대화 화면 방문이 남아 있음
# Cache 자체가 없으면(NOT_PRESENT) Event 를 만들지 않는다 — '미존재'는 '삭제'가 아니다.

CACHE_DELETE_RULE_ID = "CHATGPT_CACHE_DELETE_001"
REASON_CACHE_PARSED_WITHOUT_ENTRIES = "CACHE_PARSED_WITHOUT_ENTRIES"
REASON_CONVERSATION_LIST_PRESENT = "CONVERSATION_LIST_PRESENT"
REASON_CONVERSATION_VISIT_PRESENT = "CONVERSATION_VISIT_PRESENT"
_CACHE_DELETE_INFERENCE = (
    "캐시는 읽혔는데 ChatGPT 대화 응답 entry 가 하나도 없고, 대화 목록·방문 기록은 남아 있음 → "
    "캐시가 지워졌을 가능성이 있는 것으로만 관찰한다 (삭제 시각·범위·수행자는 추론하지 않음)"
)
_CACHE_DELETE_LIMITATIONS = (
    "캐시 삭제에 고유한 흔적은 없다. 정상 eviction(용량 회수)·캐시 미보존과 구분하지 못한다",
    "브라우저 전체 캐시 삭제일 수 있으며 ChatGPT 전용 행위가 아니다",
    "삭제 시각의 근거가 없어 Event 시각을 만들지 않는다 (시각 없음)",
    "Cache 파일 자체가 없는 경우(NOT_PRESENT)는 이 Rule 의 대상이 아니다 ('미존재'는 '삭제'가 아니다)",
    "NTFS $UsnJrnl 등 파일 시스템 레벨 삭제 근거는 현재 Reader 범위 밖이라 결합하지 않는다",
)


def detect_cache_delete(records: list[ArtifactRecord],
                        coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """캐시는 읽혔지만 ChatGPT 대화 응답 entry 가 없고 다른 흔적은 남은 경우 → CACHE_DELETE (CANDIDATE / LOW)."""
    events: list[Event] = []
    for coverage in sorted([c for c in coverages if c.artifact_type == "cache" and c.status == "PARSED"],
                           key=lambda c: c.source_path):
        profile_key = (coverage.os_user, coverage.browser_profile)
        group = [r for r in records if (r.os_user, r.browser_profile) == profile_key]
        if any(r.artifact_type == "cache" and r.observed.get("cache_key_kind") == "conversation_response"
               for r in group):
            continue  # S1 불성립 — 대화 응답 entry 가 남아 있다
        conversation_records = [r for r in group if r.artifact_type == "local_storage"
                                and r.observed.get("key_kind") == "conversation_history"
                                and (r.observed.get("conversation_items") or [])]
        visit_records = [r for r in group if r.artifact_type in ("history", "sessions")
                         and isinstance(r.observed.get("url"), str) and "/c/" in r.observed["url"]]
        signals = [(REASON_CACHE_PARSED_WITHOUT_ENTRIES, "Cache 는 읽혔지만 ChatGPT 대화 응답 entry 가 0건", None)]
        if conversation_records:
            signals.append((REASON_CONVERSATION_LIST_PRESENT,
                            f"같은 Profile 의 대화 목록 Record {len(conversation_records)}건이 남아 있음",
                            conversation_records[0]))
        if visit_records:
            signals.append((REASON_CONVERSATION_VISIT_PRESENT,
                            f"같은 Profile 에 ChatGPT 대화 화면 방문 Record {len(visit_records)}건이 남아 있음",
                            visit_records[0]))
        if len(signals) < 2:
            continue

        anchor = signals[1][2]
        primary = EvidenceItem(
            evidence_id=f"evidence:{CACHE_DELETE_RULE_ID}:{coverage.source_path}",
            record_id=None, evidence_level="INFERRED", artifact_type="cache", source_path=coverage.source_path,
            record_location=None, source_sha256=coverage.source_sha256,
            observed={"signal": signals[0][0], "signal_count": len(signals),
                      "cache_coverage_status": coverage.status, "conversation_response_record_count": 0},
            note=signals[0][1])
        supporting = []
        for reason, text, record in signals[1:]:
            item = _session_evidence(record, "INFERRED", None, text, CACHE_DELETE_RULE_ID)
            item.observed = {"signal": reason, "artifact_type": record.artifact_type}
            supporting.append(item)
        reasons = [reason for reason, _, _ in signals] + [REASON_MULTIPLE_SUPPORTING_SIGNALS,
                                                          REASON_NOT_UNIQUE_TO_ACTION, REASON_TIMESTAMP_MISSING]
        events.append(Event(
            event_id=f"event:{CACHE_DELETE_RULE_ID}:{coverage.source_path}",
            finding_type="USER_ACTION", action="CACHE_DELETE", action_status="CANDIDATE",
            timestamp_type="unknown", representative_evidence_id=primary.evidence_id, confidence="LOW",
            confidence_reason=[REASON_HEURISTIC_RULE] + reasons, rule_id=CACHE_DELETE_RULE_ID,
            rule_verification="PARTIALLY_VERIFIED", os_user=coverage.os_user, browser=coverage.browser,
            browser_profile=coverage.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_CACHE_DELETE_INFERENCE,
            limitations=list(_CACHE_DELETE_LIMITATIONS) + list(_HEURISTIC_COMMON_LIMITATIONS),
            warnings=list(coverage.warnings)))
    return events


# ---- 8.26 CHATGPT_INCOGNITO_001 ---------------------------------------------
# 시크릿(off-the-record) 창은 디스크에 Profile Artifact 를 남기지 않는 것이 정상이다.
# 따라서 "일반 Profile 에 기록이 없다"는 이유로 Event 를 만들지 않는다 (흔적의 부재는 행위의 부재도, 존재도 아니다).
# Rule 은 Record 안에 시크릿 사용을 직접 가리키는 표식이 있을 때만 동작한다 (실행 인자 --incognito,
# off-the-record profile 표시 등). 실험 자료가 없어 검증되지 않았다.

INCOGNITO_RULE_ID = "CHATGPT_INCOGNITO_001"
_INCOGNITO_STRONG_MARKERS = ("--incognito", "off-the-record", "offtherecord", "otr profile")
_INCOGNITO_WEAK_MARKERS = ("incognito",)
REASON_INCOGNITO_MARKER = "INCOGNITO_MARKER"
_INCOGNITO_INFERENCE = (
    "Artifact 값에 시크릿(off-the-record) 창을 가리키는 표식이 남아 있음 → 시크릿 창이 사용된 것으로 관찰한다 "
    "(ChatGPT 를 시크릿 창에서 썼는지 · 언제 썼는지는 추론하지 않음)"
)
_INCOGNITO_LIMITATIONS = (
    "시크릿 창은 디스크 Artifact 를 남기지 않는 것이 정상이라 흔적의 부재로는 판정할 수 없다",
    "표식이 남아 있어도 그 창에서 ChatGPT 를 사용했다는 근거는 아니다 (브라우저 전역 기능)",
    "표식 문자열의 출처(실행 인자·프로필 표시·페이지 내용)를 구분하지 못할 수 있다",
    "시크릿 사용 전후를 비교한 실험 자료가 없어 Rule 이 검증되지 않았다 (NEEDS_VERIFICATION)",
)


def _incognito_markers(record: ArtifactRecord) -> tuple[str, str, str] | None:
    """(필드 이름, 표식, 강·약) — 값 원문은 반환하지 않는다."""
    for name, value in sorted(record.observed.items()):
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        for marker in _INCOGNITO_STRONG_MARKERS:
            if marker in lowered:
                return name, marker, "strong"
        for marker in _INCOGNITO_WEAK_MARKERS:
            if marker in lowered:
                return name, marker, "weak"
    return None


def detect_incognito(records: list[ArtifactRecord],
                     coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """Record 에 남은 시크릿 창 표식 → INCOGNITO (CANDIDATE). 표식이 없으면 Event 0건."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages}
    events: list[Event] = []
    for record in sorted(records, key=lambda r: r.record_id):
        found = _incognito_markers(record)
        if found is None:
            continue
        field_name, marker, strength = found
        note = f"{record.artifact_type} Record 의 {field_name} 에 시크릿 창 표식 '{marker}' 이 있음"
        primary = _session_evidence(record, "SUPPORTING", sha_by_source.get(record.source_path), note,
                                    INCOGNITO_RULE_ID)
        primary.observed = {"marker": marker, "marker_field": field_name, "marker_strength": strength,
                            "artifact_type": record.artifact_type}
        timestamp = {"timestamp_raw": record.timestamp_raw, "timestamp_utc": record.timestamp_utc,
                     "timestamp_kst": record.timestamp_kst, "timestamp_type": record.timestamp_type,
                     "timestamp_source": record.timestamp_source}
        reasons = [REASON_INCOGNITO_MARKER, REASON_NOT_UNIQUE_TO_ACTION,
                   REASON_TIMESTAMP_EXPLAINED if record.timestamp_utc else REASON_TIMESTAMP_MISSING]
        events.append(_candidate_event(
            rule_id=INCOGNITO_RULE_ID, action="INCOGNITO",
            event_id=f"event:{INCOGNITO_RULE_ID}:{record.record_id}:{field_name}",
            record=record, primary=primary, supporting=[], timestamp=timestamp, reasons=reasons,
            inference=_INCOGNITO_INFERENCE, limitations=list(_INCOGNITO_LIMITATIONS),
            confidence="MEDIUM" if strength == "strong" and record.timestamp_utc else "LOW",
            warnings=list(record.warnings)))
    return events
