"""Event Rule 공통 도구 (Evidence 생성 · Event 조립 · heuristic 기본값)."""
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
from ..artifacts.cache import REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING, REASON_URL_VARIANT_NOT_VERIFIED, history_device_attribution
from ..models import Event, EvidenceItem


LOGOUT_PATH = "/auth/logout"
_UNVERIFIED_TRANSITION_QUALIFIERS = ("CLIENT_REDIRECT", "SERVER_REDIRECT", "FORWARD_BACK")


# ---- 8.2 S8 공통 도구 ---------------------------------------------------------
# S8 Rule (LOGIN / ACCOUNT_SWITCH / CONVERSATION_CREATE / CONVERSATION_ACCESS / PROFILE_ACCESS) 이 함께 쓴다.
#   - URL 은 분해해서 판정한다: https, host 정확히 일치, path 가 패턴과 완전히 일치 (문자열 포함 여부 사용 안 함).
#   - 같은 source_path + record_location 이 입력에 중복되면 한 번만 본다. 입력 Record 는 수정하지 않는다.
#   - 여러 방문을 잇는 Rule 은 같은 History (source_path, os_user, browser_profile) 안에서만,
#     visits.id 순서로 연결한다 (C: History 사본에서 visits.id 순서와 visit_time 순서가 일치함을 관찰).
#     from_visit 은 쓰지 않는다: 대화 URL 은 from_visit=0 (SPA), 로그인 체인은 중간 Google 방문이 필터로 빠져 끊긴다.
#   - 근거 없는 시간 창 숫자를 쓰지 않는다. 방문 간격은 limitation 에 기록만 한다.
# ponytail: LOGOUT(S5) 은 manual artifact 로 검증된 구현을 그대로 두고 이 도구로 옮기지 않았다. Rule 이 더 늘면 합친다.

CHATGPT_HOST = "chatgpt.com"
AUTH_OPENAI_HOST = "auth.openai.com"
URL_MATCH_EXACT = "exact"
URL_MATCH_VARIANT = "variant"

REASON_RULE_PARTIALLY_VERIFIED = "RULE_PARTIALLY_VERIFIED"
REASON_SUPPORTING_CORRELATED = "SUPPORTING_CORRELATED"
REASON_NOT_UNIQUE_TO_ACTION = "NOT_UNIQUE_TO_ACTION"
REASON_RULE_EVIDENCE_NOT_RECONFIRMED = "RULE_EVIDENCE_NOT_RECONFIRMED"
REASON_CONVERSATION_ID_NOT_LINKED = "CONVERSATION_ID_NOT_LINKED"
REASON_SERVER_CONVERSATION_ID_MISSING = "SERVER_CONVERSATION_ID_MISSING"
REASON_TIME_ORDER_INCONSISTENT = "TIME_ORDER_INCONSISTENT"

_LOGOUT_PATH_PATTERN = re.compile(re.escape(LOGOUT_PATH))
_LOGIN_WITH_PATH = re.compile(r"/auth/login_with")
_AUTHORIZE_PATH = re.compile(r"/api/accounts/authorize")
_LOGIN_CALLBACK_PATH = re.compile(r"/api/auth/callback/openai")
_PROFILE_PATH = re.compile(r"/profile")
# 관찰된 대화 ID 는 UUID 형태 (예: 6a86cf88-a4d8-83ee-9ef5-d2e6b3c3952f). 영문·숫자·하이픈 한 구간만 허용한다.
_CONVERSATION_PATH = re.compile(r"/c/([0-9A-Za-z-]+)")
_WEB_CONVERSATION_PATH = re.compile(r"/c/WEB:([0-9A-Za-z-]+)")

_VARIANT_LIMITATION = "URL 표기(query·fragment·포트 등)가 실험에서 관찰된 형태와 다름"
_TIMESTAMP_LIMITATION = "History visit_time 을 UTC/KST 로 변환하지 못해 행위 시각을 확인할 수 없음"


def match_history_url(
    url: Any, host: str, path_pattern: re.Pattern[str], *, query_expected: bool = False,
) -> tuple[str | None, re.Match[str] | None]:
    """
    https + host 정확히 일치 + path 가 path_pattern 과 완전히 일치하면 ('exact' 또는 'variant', path match), 아니면 (None, None).
    'variant' = fragment·포트·userinfo·끝의 '.' 처럼 관찰된 형태와 다른 표기. query_expected=False 이면 query 도 variant.
    """
    if not isinstance(url, str):
        return None, None
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        _ = parts.port  # 잘못된 포트 표기면 ValueError
    except ValueError:
        return None, None
    if parts.scheme != "https" or hostname is None or hostname.rstrip(".") != host:
        return None, None
    match = path_pattern.fullmatch(parts.path)
    if match is None:
        return None, None
    exact = parts.netloc.lower() == host and not parts.fragment and (query_expected or not parts.query)
    return (URL_MATCH_EXACT if exact else URL_MATCH_VARIANT), match


def _record_url(record: ArtifactRecord) -> Any:
    return record.observed.get("url")


def _history_sha_by_source(coverages: list[Coverage] | tuple[Coverage, ...]) -> dict[str, str | None]:
    return {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "history"}


def _record_key(record: ArtifactRecord) -> tuple[str, str]:
    return record.source_path, record.record_location or record.record_id


def _is_history_download(record: ArtifactRecord) -> bool:
    return record.artifact_type == "history" and record.observed.get("record_kind") == "download"


# 다운로드 1건을 기록하는 Artifact. 두 Reader 가 같은 observed 이름 (url_chain·target_path·tab_url 등) 을 쓴다.
DOWNLOAD_ARTIFACT_TYPES = ("history", "shared_proto_db")


def _is_download_record(record: ArtifactRecord) -> bool:
    return record.artifact_type in DOWNLOAD_ARTIFACT_TYPES and record.observed.get("record_kind") == "download"


def _unique_history_records(records: list[ArtifactRecord]) -> list[ArtifactRecord]:
    """visits 기반 History Record 만, 같은 source_path + record_location 은 첫 번째만 (입력 순서 유지).

    downloads Record 는 visit URL 이 없으므로 visit 기반 Rule 에서 제외한다 (§8.12 Rule 이 따로 읽는다).
    """
    seen: set[tuple[str, str]] = set()
    unique: list[ArtifactRecord] = []
    for record in records:
        if _is_history_download(record):
            continue
        if record.artifact_type != "history" or _record_key(record) in seen:
            continue
        seen.add(_record_key(record))
        unique.append(record)
    return unique


def _visit_order_key(record: ArtifactRecord) -> tuple[int, int, str]:
    visit_id = record.observed.get("visit_id")
    if isinstance(visit_id, int) and not isinstance(visit_id, bool):
        return 0, visit_id, record.record_id
    return 1, 0, record.record_id


def _history_groups(records: list[ArtifactRecord]) -> list[list[ArtifactRecord]]:
    """같은 History (source_path, os_user, browser_profile) 끼리 묶어 visits.id 순서로 정렬."""
    groups: dict[tuple[str, str | None, str | None], list[ArtifactRecord]] = {}
    for record in _unique_history_records(records):
        groups.setdefault((record.source_path, record.os_user, record.browser_profile), []).append(record)
    return [sorted(group, key=_visit_order_key) for group in groups.values()]


def _timestamp_explained(record: ArtifactRecord) -> bool:
    return bool(record.timestamp_utc and record.timestamp_kst and record.timestamp_source)


def _record_utc(record: ArtifactRecord) -> datetime | None:
    try:
        return datetime.fromisoformat(record.timestamp_utc) if record.timestamp_utc else None
    except ValueError:
        return None


def _seconds_between(first: ArtifactRecord, second: ArtifactRecord) -> float | None:
    start, end = _record_utc(first), _record_utc(second)
    return None if start is None or end is None else (end - start).total_seconds()


def _gap_text(label: str, seconds: float | None) -> str:
    return f"{label} 간격 {seconds:g}초" if seconds is not None else f"{label} 간격 확인 불가 (시각 없음)"


def _transition_limitations(observed: dict[str, Any]) -> list[str]:
    core = observed.get("transition_core")
    qualifiers = list(observed.get("transition_qualifiers") or [])
    flagged = (["RELOAD"] if core == "RELOAD" else []) + [q for q in qualifiers if q in _UNVERIFIED_TRANSITION_QUALIFIERS]
    if not flagged:
        return []
    return [f"transition 메타데이터 {', '.join(flagged)} 존재 — 오탐과의 관계가 검증되지 않아 Confidence 에 반영하지 않음"]


def _visit_note(record: ArtifactRecord, prefix: str = "") -> str:
    observed = record.observed
    _, device_note = history_device_attribution(observed)
    transition = f"transition {observed.get('transition_hex')} {observed.get('transition_core')} {list(observed.get('transition_qualifiers') or [])}"
    return f"{prefix}{transition}; {device_note}"


def _record_evidence(
    record: ArtifactRecord, rule_id: str, level: str, source_sha256: str | None, note: str,
    extra_observed: dict[str, Any] | None = None,
) -> EvidenceItem:
    observed = copy.deepcopy(record.observed)  # 입력 Record 는 건드리지 않는다
    if extra_observed:
        observed.update(extra_observed)
    return EvidenceItem(
        evidence_id=f"evidence:{rule_id}:{record.record_id}", record_id=record.record_id, evidence_level=level,
        artifact_type=record.artifact_type, source_path=record.source_path, record_location=record.record_location,
        source_sha256=source_sha256, timestamp_raw=record.timestamp_raw, timestamp_utc=record.timestamp_utc,
        timestamp_kst=record.timestamp_kst, timestamp_type=record.timestamp_type,
        timestamp_source=record.timestamp_source, observed=observed, note=note,
    )


def _chain_device_attribution(records: list[ArtifactRecord]) -> str:
    """관련 방문의 device_attribution 이 모두 같으면 그 값, 섞이면 UNKNOWN."""
    values = {history_device_attribution(record.observed)[0] for record in records}
    return values.pop() if len(values) == 1 else "UNKNOWN"


def _merged_warnings(records: list[ArtifactRecord]) -> list[str]:
    merged: list[str] = []
    for record in records:
        merged += [warning for warning in record.warnings if warning not in merged]
    return merged


def _new_event(
    *, rule_id: str, event_record: ArtifactRecord, representative: EvidenceItem, records: list[ArtifactRecord],
    **fields: Any,
) -> Event:
    return Event(
        event_id=f"event:{rule_id}:{event_record.record_id}", finding_type="USER_ACTION", rule_id=rule_id,
        timestamp_raw=representative.timestamp_raw, timestamp_utc=representative.timestamp_utc,
        timestamp_kst=representative.timestamp_kst, timestamp_type=representative.timestamp_type,
        timestamp_source=representative.timestamp_source, representative_evidence_id=representative.evidence_id,
        os_user=event_record.os_user, browser=event_record.browser, browser_profile=event_record.browser_profile,
        device_attribution=_chain_device_attribution(records), warnings=_merged_warnings(records), **fields,
    )


def _visit_event(
    record: ArtifactRecord, *, rule_id: str, action: str, rule_verification: str, confidence: str,
    reasons: list[str], match: str, source_sha256: str | None, limitations: list[str] | tuple[str, ...] = (),
    extra_observed: dict[str, Any] | None = None,
) -> Event:
    """방문 1건이 곧 근거인 Rule 의 Event. variant URL → HIGH 는 MEDIUM, 시각 변환 실패 → LOW / CANDIDATE."""
    reasons = list(reasons)
    notes = list(limitations)
    if match == URL_MATCH_VARIANT:
        reasons.append(REASON_URL_VARIANT_NOT_VERIFIED)
        notes.append(_VARIANT_LIMITATION)
        confidence = "MEDIUM" if confidence == "HIGH" else confidence
    if _timestamp_explained(record):
        reasons.append(REASON_TIMESTAMP_EXPLAINED)
    else:
        reasons.append(REASON_TIMESTAMP_MISSING)
        notes.append(_TIMESTAMP_LIMITATION)
        confidence = "LOW"
    evidence = _record_evidence(record, rule_id, "DIRECT", source_sha256, _visit_note(record), extra_observed)
    return _new_event(
        rule_id=rule_id, event_record=record, representative=evidence, records=[record],
        action=action, action_status="CANDIDATE" if confidence == "LOW" else "DETECTED", confidence=confidence,
        confidence_reason=reasons, rule_verification=rule_verification, primary_evidence=[evidence],
        limitations=notes + _transition_limitations(record.observed),
    )


def _detect_visit_rule(
    records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...], *, host: str,
    path: re.Pattern[str], query_expected: bool, **event_fields: Any,
) -> list[Event]:
    sha_by_source = _history_sha_by_source(coverages)
    events: list[Event] = []
    for record in _unique_history_records(records):
        match, _ = match_history_url(_record_url(record), host, path, query_expected=query_expected)
        if match is not None:
            events.append(_visit_event(record, match=match, source_sha256=sha_by_source.get(record.source_path), **event_fields))
    return events


# ---- 8.8 CHATGPT_DATA_EXPORT_REQUEST_001 -------------------------------------
# 근거: Session Storage (origin https://chatgpt.com/) 의 chatgpt_export_data_pending_confirm PUT.
# 2026-09-15 D: E07-01 원자료 재확인: PRE 0건 → POST PUT (값 UTF-16LE "1788249242085" = Unix ms, 2026-09-01T16:54:02.085+09:00)
#   → 같은 키 DELETE (값·시각 없음). 실험 기록 (REPORT E07-01): 설정 → 데이터 제어 → 데이터 내보내기 → 본인 인증 → 최종 확인 → 요청.
# 판정: DATA_EXPORT_REQUEST DETECTED / MEDIUM, rule_verification PARTIALLY_VERIFIED
#   - 키는 Export '최종 확인 대기' 상태로 관찰됐다. 요청 전송·서버 접수·완료는 판정하지 않는다 (CONFIRMATION / COMPLETION Event 없음).
#   - 확인 창에서 취소해도 같은 키가 생기는지 Negative Control 이 없어 VERIFIED 로 두지 않는다 → HIGH 조건 미충족.
#   - 같은 키의 바로 뒤 DELETE (다음 PUT 이전) 는 SUPPORTING — 시각이 없고 대기 해제 흔적일 뿐 확인 완료가 아니다.
#   - Export 화면은 SPA 라 History·SNSS 에 Export URL 이 없다 (E07-01 PRE/POST History 재조회) → History 보조 근거를 연결하지 않는다.
#   - 값을 시각으로 변환하지 못하면 LOW / CANDIDATE. device_attribution 은 UNKNOWN (Session Storage 는 로컬 저장소지만 실험으로 확정 안 함).

DATA_EXPORT_REQUEST_RULE_ID = "CHATGPT_DATA_EXPORT_REQUEST_001"
REASON_EMBEDDED_TIMESTAMP = "EMBEDDED_TIMESTAMP"


def _session_evidence(record: ArtifactRecord, level: str, source_sha256: str | None, note: str,
                      rule_id: str = DATA_EXPORT_REQUEST_RULE_ID) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=f"evidence:{rule_id}:{record.record_id}", record_id=record.record_id,
        evidence_level=level, artifact_type=record.artifact_type, source_path=record.source_path,
        record_location=record.record_location, source_sha256=source_sha256, timestamp_raw=record.timestamp_raw,
        timestamp_utc=record.timestamp_utc, timestamp_kst=record.timestamp_kst, timestamp_type=record.timestamp_type,
        timestamp_source=record.timestamp_source, observed=copy.deepcopy(record.observed), note=note,
    )
REASON_DIRECT_VALUE = "DIRECT_VALUE"
REASON_TIMESTAMP_APPROXIMATED = "TIMESTAMP_APPROXIMATED"


# ---- 8.17 나머지 행위 Rule 공통 (heuristic Rule 기본값) -----------------------
# 2026-09-20. 아래 §8.18~§8.26 은 "행위 특이적 직접 증거가 확인되지 않은" 행위들의 Rule 이다.
# 원칙:
#   - Rule 이 존재하는 것과 실제로 Event 가 나오는 것은 다르다. 근거 Record 가 없으면 Event 를 만들지 않는다.
#   - 기본값은 CANDIDATE / LOW / PARTIALLY_VERIFIED / SUPPORTING 이고, 값을 올리는 것은 개별 Rule 이 근거를 적어 설명한다.
#   - HIGH 는 쓰지 않는다 (어느 Rule 도 controlled experiment 로 검증되지 않았다).
#   - 시각을 만들어 내지 않는다. 변환 가능한 시각이 없으면 Event 의 시각은 비워 두고 TIMESTAMP_MISSING 을 남긴다.
REASON_HEURISTIC_RULE = "HEURISTIC_RULE"
REASON_SERVER_RESPONSE_COPY = "SERVER_RESPONSE_COPY"
REASON_MULTIPLE_SUPPORTING_SIGNALS = "MULTIPLE_SUPPORTING_SIGNALS"
_HEURISTIC_COMMON_LIMITATIONS = (
    "이 Rule 은 controlled experiment 로 검증되지 않았다 — 같은 흔적을 만드는 다른 원인을 배제하지 못한다 (NEEDS_VERIFICATION)",
    "Rule 이 구현돼 있다는 것과 이 이미지에서 근거가 관찰됐다는 것은 다르다. 근거가 없으면 Event 를 만들지 않는다",
)


def is_server_response_copy(record: ArtifactRecord) -> bool:
    """이 Record 가 '서버가 반환한 응답의 사본' 인가 — 본문까지 복구된 Cache 의 대화 API 응답만 True.

    팀 최종 판정 기준(2026-10-09)의 확정 근거 유형이다. Cache 라는 것만으로는 True 가 아니다:
    URL 만 남은 entry · header 만 있는 entry · 본문 읽기/brotli/JSON 실패 · 목록 API · 정적 리소스는
    conversation 본문이 없으므로 모두 False 가 된다 (Reader 가 그런 Record 에는 conversation 을 넣지 않는다).
    """
    observed = record.observed
    return (record.artifact_type == "cache"
            and observed.get("cache_key_kind") == "conversation_response"
            and observed.get("http_status") == 200
            and bool(observed.get("decoded_sha256"))          # 본문을 실제로 해제했다
            and isinstance(observed.get("conversation"), dict))


def _candidate_event(*, rule_id: str, action: str, event_id: str, record: ArtifactRecord,
                     primary: EvidenceItem, supporting: list[EvidenceItem], timestamp: dict[str, Any],
                     reasons: list[str], inference: str, limitations: list[str],
                     confidence: str = "LOW", device_attribution: str = "UNKNOWN",
                     warnings: list[str] | None = None, server_response_copy: bool = False) -> Event:
    """heuristic Rule 공통 Event 생성. 기본 action_status 는 CANDIDATE 이고 HIGH 는 쓰지 않는다.

    server_response_copy=True 는 "행위의 결과물이 서버 응답 본문에 그대로 들어 있다" 고 Rule 이 선언한 경우에만
    쓴다. 그때도 Record 가 실제로 복구된 대화 API 응답일 때만(is_server_response_copy) 확정으로 올린다 —
    Cache 라는 이유만으로 올리는 일괄 승격은 하지 않는다. 시각을 확인하지 못한 Event(LOW)는 올리지 않는다.
    """
    if confidence not in ("LOW", "MEDIUM"):
        raise ValueError(f"heuristic rule confidence must be LOW/MEDIUM, got {confidence!r}")
    confirmed = server_response_copy and confidence != "LOW" and is_server_response_copy(record)
    if confirmed:
        reasons = [REASON_SERVER_RESPONSE_COPY] + list(reasons)
    return Event(
        event_id=event_id, finding_type="USER_ACTION", action=action,
        action_status="DETECTED" if confirmed else "CANDIDATE",
        timestamp_raw=timestamp.get("timestamp_raw"), timestamp_utc=timestamp.get("timestamp_utc"),
        timestamp_kst=timestamp.get("timestamp_kst"), timestamp_type=timestamp.get("timestamp_type", "unknown"),
        timestamp_source=timestamp.get("timestamp_source"),
        representative_evidence_id=primary.evidence_id, confidence=confidence,
        confidence_reason=[REASON_HEURISTIC_RULE] + reasons,
        rule_id=rule_id, rule_verification="PARTIALLY_VERIFIED", os_user=record.os_user, browser=record.browser,
        browser_profile=record.browser_profile, device_attribution=device_attribution,
        primary_evidence=[primary], supporting_evidence=supporting, inference=inference,
        limitations=list(limitations) + list(_HEURISTIC_COMMON_LIMITATIONS),
        warnings=list(warnings or []),
    )


def _cache_conversation_nodes(record: ArtifactRecord) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Cache Record → (대화 dict, mapping node 목록). 구조가 아니면 (None, [])."""
    conversation = record.observed.get("conversation")
    if not isinstance(conversation, dict) or not isinstance(conversation.get("mapping"), list):
        return None, []
    return conversation, [node for node in conversation["mapping"] if isinstance(node, dict)]


def _conversation_id_of(record: ArtifactRecord, conversation: dict[str, Any] | None) -> str | None:
    value = (conversation or {}).get("conversation_id") or record.observed.get("url_conversation_id")
    return value if isinstance(value, str) and value else None


def _message_sort_key(message: dict[str, Any]) -> tuple:
    create_time = message.get("create_time")
    return (0, float(create_time)) if isinstance(create_time, (int, float)) and not isinstance(create_time, bool) \
        else (1, 0.0)
