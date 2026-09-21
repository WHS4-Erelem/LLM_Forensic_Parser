"""인증·계정 Rule (LOGOUT / LOGIN / ACCOUNT_SWITCH / PROFILE_ACCESS / ACCOUNT_SESSION / ACCOUNT_NAME_CHANGE)."""
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
from ..artifacts.cache import REASON_DIRECT_URL, REASON_RULE_VERIFIED, REASON_TIMESTAMP_EXPLAINED, REASON_TIMESTAMP_MISSING, REASON_URL_VARIANT_NOT_VERIFIED, history_device_attribution
from ..detectors.common import AUTH_OPENAI_HOST, CHATGPT_HOST, LOGOUT_PATH, REASON_DIRECT_VALUE, REASON_EMBEDDED_TIMESTAMP, REASON_NOT_UNIQUE_TO_ACTION, REASON_RULE_EVIDENCE_NOT_RECONFIRMED, REASON_RULE_PARTIALLY_VERIFIED, REASON_SUPPORTING_CORRELATED, REASON_TIMESTAMP_APPROXIMATED, REASON_TIME_ORDER_INCONSISTENT, _AUTHORIZE_PATH, _LOGIN_CALLBACK_PATH, _LOGIN_WITH_PATH, _LOGOUT_PATH_PATTERN, _PROFILE_PATH, _UNVERIFIED_TRANSITION_QUALIFIERS, _candidate_event, _detect_visit_rule, _gap_text, _history_groups, _history_sha_by_source, _merged_warnings, _new_event, _record_evidence, _record_url, _record_utc, _seconds_between, _session_evidence, _timestamp_explained, _visit_note, match_history_url
from ..models import Event, EvidenceItem


# ---- 8.1 CHATGPT_LOGOUT_001 --------------------------------------------------
# DIRECT 근거: History 의 https://chatgpt.com/auth/logout 방문 (수동 실험 E01-02 에서 검증된 형태).
# URL 판정 (문자열 contains 사용 안 함)
#   - scheme https, host chatgpt.com, path 정확히 /auth/logout 이어야 한다.
#     /auth/logout2, /foo/auth/logout, /auth/logout/, http://, notchatgpt.com, chatgpt.com.example.com 은 제외.
#   - 검증된 형태는 'https://chatgpt.com/auth/logout' (query·fragment·포트·userinfo 없음).
#     host·path 는 맞지만 표기가 다르면 'variant': Event 는 만들되 URL_VARIANT_NOT_VERIFIED, Confidence MEDIUM.
# Confidence
#   - HIGH   : 검증된 형태 + 시각 설명 가능
#   - MEDIUM : variant URL + 시각 설명 가능
#   - LOW    : 시각 변환 실패 (EVENT_RULES §2 "Timestamp 불완전" → LOW) → action_status CANDIDATE
# transition(REDIRECT·RELOAD·FORWARD_BACK)·Sync 메타데이터는 보존만 하고 Confidence 를 바꾸지 않는다.
# 같은 source_path + record_location(visits.id) 은 Event 1건. 서로 다른 visit 은 각각 Event.

LOGOUT_RULE_ID = "CHATGPT_LOGOUT_001"
LOGOUT_HOST = "chatgpt.com"
LOGOUT_MATCH_EXACT = "exact"
LOGOUT_MATCH_VARIANT = "variant"


def match_logout_url(url: Any) -> str | None:
    """로그아웃 URL 이면 'exact' 또는 'variant', 아니면 None."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # 잘못된 포트 표기면 ValueError
    except ValueError:
        return None
    if parts.scheme != "https" or host is None or host.rstrip(".") != LOGOUT_HOST or parts.path != LOGOUT_PATH:
        return None
    if parts.netloc.lower() == LOGOUT_HOST and not parts.query and not parts.fragment:
        return LOGOUT_MATCH_EXACT
    return LOGOUT_MATCH_VARIANT


def detect_logout(records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """
    History ArtifactRecord 에서 CHATGPT_LOGOUT_001 Event 를 만든다.
    coverages 는 EvidenceItem.source_sha256 을 채우기 위해서만 사용한다 (선택).
    """
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "history"}
    events: list[Event] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        if record.artifact_type != "history":
            continue
        match = match_logout_url(record.observed.get("url"))
        if match is None:
            continue
        key = (record.source_path, record.record_location or record.record_id)
        if key in seen:  # 같은 visit 이 입력에 중복으로 들어온 경우만 건너뛴다
            continue
        seen.add(key)
        events.append(_build_logout_event(record, match, sha_by_source.get(record.source_path)))
    return events


def _build_logout_event(record: ArtifactRecord, match: str, source_sha256: str | None) -> Event:
    observed = copy.deepcopy(record.observed)  # 입력 Record 는 건드리지 않는다
    device_attribution, device_note = history_device_attribution(observed)
    core = observed.get("transition_core")
    qualifiers = list(observed.get("transition_qualifiers") or [])

    reasons = [REASON_RULE_VERIFIED, REASON_DIRECT_URL]
    limitations: list[str] = []
    if match == LOGOUT_MATCH_VARIANT:
        reasons.append(REASON_URL_VARIANT_NOT_VERIFIED)
        limitations.append("URL 표기(query·fragment·포트 등)가 실험에서 검증된 https://chatgpt.com/auth/logout 과 다름")

    timestamp_explained = bool(record.timestamp_utc and record.timestamp_kst and record.timestamp_source)
    if timestamp_explained:
        reasons.append(REASON_TIMESTAMP_EXPLAINED)
    else:
        reasons.append(REASON_TIMESTAMP_MISSING)
        limitations.append("History visit_time 을 UTC/KST 로 변환하지 못해 로그아웃 시각을 확인할 수 없음")

    flagged = (["RELOAD"] if core == "RELOAD" else []) + [q for q in qualifiers if q in _UNVERIFIED_TRANSITION_QUALIFIERS]
    if flagged:
        limitations.append(
            f"transition 메타데이터 {', '.join(flagged)} 존재 — 오탐과의 관계가 검증되지 않아 Confidence 에 반영하지 않음"
        )

    if not timestamp_explained:
        confidence = "LOW"
    elif match == LOGOUT_MATCH_VARIANT:
        confidence = "MEDIUM"
    else:
        confidence = "HIGH"

    evidence = EvidenceItem(
        evidence_id=f"evidence:{record.record_id}",
        record_id=record.record_id,
        evidence_level="DIRECT",
        artifact_type=record.artifact_type,
        source_path=record.source_path,
        record_location=record.record_location,
        source_sha256=source_sha256,
        timestamp_raw=record.timestamp_raw,
        timestamp_utc=record.timestamp_utc,
        timestamp_kst=record.timestamp_kst,
        timestamp_type=record.timestamp_type,
        timestamp_source=record.timestamp_source,
        observed=observed,
        note=f"transition {observed.get('transition_hex')} {core} {qualifiers}; {device_note}",
    )
    return Event(
        event_id=f"event:{LOGOUT_RULE_ID}:{record.record_id}",
        finding_type="USER_ACTION",
        action="LOGOUT",
        action_status="CANDIDATE" if confidence == "LOW" else "DETECTED",
        timestamp_raw=evidence.timestamp_raw,
        timestamp_utc=evidence.timestamp_utc,
        timestamp_kst=evidence.timestamp_kst,
        timestamp_type=evidence.timestamp_type,
        timestamp_source=evidence.timestamp_source,
        representative_evidence_id=evidence.evidence_id,
        confidence=confidence,
        confidence_reason=reasons,
        rule_id=LOGOUT_RULE_ID,
        rule_verification="VERIFIED",
        os_user=record.os_user,
        browser=record.browser,
        browser_profile=record.browser_profile,
        device_attribution=device_attribution,
        primary_evidence=[evidence],
        limitations=limitations,
        warnings=list(record.warnings),
    )


# ---- 8.3 CHATGPT_LOGIN_001 ---------------------------------------------------
# 근거: https://chatgpt.com/api/auth/callback/openai 방문 (OAuth 로그인 완료 경로, E01-01 체인에서 관찰).
# 관찰된 callback 은 code·scope·state query 를 가진다 (Reader 가 code·state 값을 가림) → query 는 variant 아님.
# PARTIALLY_VERIFIED / MEDIUM: 정상 로그인·세션 재개·로그인 실패·재인증을 구분하는 Negative Control 실험이 없다.

LOGIN_RULE_ID = "CHATGPT_LOGIN_001"
_LOGIN_LIMITATIONS = (
    "callback 방문은 OAuth 로그인 완료와 강하게 관련되지만, 정상 로그인·세션 재개·로그인 실패·재인증을 구분하는 "
    "Negative Control 실험이 없어 로그인 성공을 유일하게 확정하지 않음 (Export 확인 등 재인증에서도 callback 이 관찰됨)",
)


def detect_login(records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    return _detect_visit_rule(
        records, coverages, host=CHATGPT_HOST, path=_LOGIN_CALLBACK_PATH, query_expected=True,
        rule_id=LOGIN_RULE_ID, action="LOGIN", rule_verification="PARTIALLY_VERIFIED", confidence="MEDIUM",
        reasons=[REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_URL], limitations=_LOGIN_LIMITATIONS,
    )


# ---- 8.4 CHATGPT_ACCOUNT_SWITCH_001 ------------------------------------------
# 같은 History 안에서 visits.id 순서로 logout → login_with → authorize(auth.openai.com) → callback 이 이어지면
# CANDIDATE / MEDIUM. 각 단계는 logout 뒤 첫 번째 해당 방문이며, 다음 logout 이 나오면 그 체인은 끊긴다.
# 이 체인은 인증 전환 절차와 일치할 뿐 "다른 계정으로 실제 변경"을 증명하지 않는다 (같은 계정 재로그인 Negative Control 없음).
# 계정 식별자가 바뀌었다는 Evidence 를 확인할 수 있을 때만 DETECTED 승격을 검토한다.
# 시간 창은 실험으로 검증된 값이 없어 기본 None (적용 안 함, NEEDS_VERIFICATION). 간격은 limitation 에 기록한다.

ACCOUNT_SWITCH_RULE_ID = "CHATGPT_ACCOUNT_SWITCH_001"
ACCOUNT_SWITCH_WINDOW_SECONDS: float | None = None  # NEEDS_VERIFICATION
_AUTH_STEPS = (
    ("logout", CHATGPT_HOST, _LOGOUT_PATH_PATTERN),
    ("login_with", CHATGPT_HOST, _LOGIN_WITH_PATH),
    ("authorize", AUTH_OPENAI_HOST, _AUTHORIZE_PATH),
    ("callback", CHATGPT_HOST, _LOGIN_CALLBACK_PATH),
)


def _auth_step(record: ArtifactRecord) -> str | None:
    for name, host, path in _AUTH_STEPS:
        if match_history_url(_record_url(record), host, path, query_expected=True)[0] is not None:
            return name
    return None


def _account_identity_observations(records: list[ArtifactRecord]) -> dict[tuple, list[tuple[str, str, ArtifactRecord]]]:
    """(os_user, profile) 별로 "이 시각에 이 계정 식별자가 관찰됨" 목록을 만든다 (Local Storage).

    계정 식별자는 Reader 가 이미 만들어 둔 SHA-256 앞자리만 쓰고, 특정 key 이름·값을 조건으로 쓰지 않는다.
    시각을 변환하지 못한 관찰은 History 체인과 시간으로 대응시킬 수 없으므로 버린다.
    같은 (시각, 식별자) 가 .log·.ldb 여러 물리 Record 에 남아 있어도 관찰 1건으로 합친다.
    """
    found: dict[tuple, dict[tuple[str, str], tuple[str, str, ArtifactRecord]]] = {}
    for record in records:
        if record.artifact_type != "local_storage":
            continue
        pairs = [(record.observed.get("user_id_sha256_prefix"), record.timestamp_utc)]
        for session in record.observed.get("sessions") or ():
            if isinstance(session, dict):
                stamp = session.get("last_logged_in_at")
                pairs.append((session.get("user_id_sha256_prefix"),
                              stamp.get("timestamp_utc") if isinstance(stamp, dict) else None))
        for user, when in pairs:
            if user and when:
                found.setdefault((record.os_user, record.browser_profile), {}).setdefault(
                    (when, user), (when, user, record))
    return {owner: [items[key] for key in sorted(items)] for owner, items in found.items()}


def _account_identity_transition(
    observations: list[tuple[str, str, ArtifactRecord]], chain: list[ArtifactRecord],
) -> tuple[tuple[str, str, ArtifactRecord], tuple[str, str, ArtifactRecord]] | None:
    """인증 체인 직전에 관찰된 계정과 직후에 관찰된 계정이 서로 다르면 (before, after) 를 돌려준다.

    같은 계정으로 재로그인한 경우 (before == after) 는 전환 근거가 아니므로 None 이다.
    """
    start, end = chain[0].timestamp_utc, chain[-1].timestamp_utc
    if not start or not end:
        return None  # 체인 시각을 모르면 앞뒤를 나눌 수 없다
    before = [item for item in observations if item[0] <= start]
    after = [item for item in observations if item[0] >= end]
    if not before or not after or before[-1][1] == after[0][1]:
        return None
    return before[-1], after[0]


def detect_account_switch(
    records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = (), *,
    window_seconds: float | None = ACCOUNT_SWITCH_WINDOW_SECONDS,
) -> list[Event]:
    sha_by_source = _history_sha_by_source(coverages)
    observations = _account_identity_observations(records)
    events: list[Event] = []
    for group in _history_groups(records):
        steps = [(record, step) for record in group if (step := _auth_step(record)) is not None]
        for index, (logout, step) in enumerate(steps):
            if step != "logout":
                continue
            chain = [logout]
            wanted = ["login_with", "authorize", "callback"]
            for record, name in steps[index + 1:]:
                if name == "logout":
                    break
                if name == wanted[0]:
                    chain.append(record)
                    wanted.pop(0)
                    if not wanted:
                        break
            if wanted:
                continue
            gap = _seconds_between(chain[0], chain[-1])
            if window_seconds is not None and (gap is None or gap > window_seconds):
                continue
            identity = _account_identity_transition(
                observations.get((logout.os_user, logout.browser_profile), []), chain)
            events.append(_account_switch_event(chain, sha_by_source.get(logout.source_path), gap, window_seconds,
                                                identity))
    return events


def _account_identity_evidence(item: tuple[str, str, ArtifactRecord], position: str) -> EvidenceItem:
    when, user, record = item
    return EvidenceItem(
        evidence_id=f"evidence:{ACCOUNT_SWITCH_RULE_ID}:{record.record_id}:identity={position}",
        record_id=record.record_id, evidence_level="SUPPORTING", artifact_type=record.artifact_type,
        source_path=record.source_path, record_location=record.record_location, source_sha256=None,
        timestamp_raw=record.timestamp_raw, timestamp_utc=when, timestamp_kst=record.timestamp_kst,
        timestamp_type=record.timestamp_type, timestamp_source=record.timestamp_source,
        observed={"user_id_sha256_prefix": user, "key_kind": record.observed.get("key_kind"),
                  "operation": record.observed.get("operation"), "sequence": record.observed.get("sequence")},
        note=f"인증 체인 {position}에 Local Storage 에서 관찰된 계정 식별자 (SHA-256 앞자리) {user}",
    )


def _account_switch_event(chain: list[ArtifactRecord], source_sha256: str | None, gap: float | None,
                          window_seconds: float | None,
                          identity: tuple[tuple[str, str, ArtifactRecord], tuple[str, str, ArtifactRecord]] | None
                          = None) -> Event:
    names = ("logout", "login_with", "authorize", "callback")
    evidence = [
        _record_evidence(record, ACCOUNT_SWITCH_RULE_ID, "SUPPORTING", source_sha256,
                         _visit_note(record, f"account switch chain step {position}/4 {name}; "))
        for position, (record, name) in enumerate(zip(chain, names), start=1)
    ]
    reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_SUPPORTING_CORRELATED, REASON_NOT_UNIQUE_TO_ACTION]
    limitations = [
        "NOT_UNIQUE_TO_ACTION: logout → login_with → authorize → callback 순서의 인증 전환 절차와 일치하는 History 체인이다. "
        "같은 계정 재로그인과 구별되지 않으며, 계정 식별자가 바뀌었다는 Evidence 는 없다"
        if identity is None else
        "NOT_UNIQUE_TO_ACTION: 인증 체인 자체는 같은 계정 재로그인과 구별되지 않는다. "
        "체인 앞뒤의 계정 식별자가 서로 다르다는 별도 Evidence 를 함께 보았을 때만 전환으로 판정했다",
        "visits.id 순서로 연결했다. from_visit 은 사용하지 않았다 (중간 Google·OpenAI 인증 방문이 ChatGPT Record 에 없어 연결이 끊김)",
        f"{_gap_text('logout → callback', gap)}. 시간 창 기준은 실험으로 검증되지 않음 "
        f"(ACCOUNT_SWITCH_WINDOW_SECONDS={window_seconds}, NEEDS_VERIFICATION)",
    ]
    confidence = "MEDIUM"
    if all(_timestamp_explained(record) for record in chain):
        reasons.append(REASON_TIMESTAMP_EXPLAINED)
        if any(_record_utc(a) > _record_utc(b) for a, b in zip(chain, chain[1:])):
            reasons.append(REASON_TIME_ORDER_INCONSISTENT)
            limitations.append("visits.id 순서와 visit_time 순서가 다름")
            confidence = "LOW"
    else:
        reasons.append(REASON_TIMESTAMP_MISSING)
        limitations.append("체인 방문 중 시각을 변환하지 못한 방문이 있어 시간 순서를 확인할 수 없음")
        confidence = "LOW"
    representative, status = evidence[-1], "CANDIDATE"
    if identity is not None:
        # 인증 체인(History) 과 계정 식별자 전이(Local Storage) 는 서로 독립적인 아티팩트다. 둘이 같은 구간에서
        # 대응할 때만 DETECTED 로 올린다. rule_verification 이 PARTIALLY_VERIFIED 이므로 confidence 는 HIGH 로 올리지 않는다.
        before, after = identity
        representative = _account_identity_evidence(after, "직후")
        representative.observed["user_id_sha256_prefix_before"] = before[1]
        representative.note = (f"인증 체인(logout → callback) 앞뒤로 Local Storage 계정 식별자가 "
                               f"{before[1]} → {after[1]} 로 바뀜 (SHA-256 앞자리)")
        evidence = evidence + [_account_identity_evidence(before, "직전"), representative]
        status = "DETECTED"
        reasons.append(REASON_DIRECT_VALUE)
        limitations.append(
            "계정 식별자는 SHA-256 앞자리로만 비교했다. 두 값이 다르다는 것은 확인되지만 실제 계정·이메일은 기록하지 않는다")
        limitations.append(
            "식별자 관찰 시각은 Local Storage 에 저장된 값 기준이다. 전환 조작 시점 자체를 관찰한 것은 아니다")
    return _new_event(
        rule_id=ACCOUNT_SWITCH_RULE_ID, event_record=chain[0], representative=representative, records=chain,
        action="ACCOUNT_SWITCH", action_status=status, confidence=confidence, confidence_reason=reasons,
        rule_verification="PARTIALLY_VERIFIED", primary_evidence=[], supporting_evidence=evidence,
        limitations=limitations,
    )


# ---- 8.7 CHATGPT_PROFILE_ACCESS_001 ------------------------------------------
# 근거: https://chatgpt.com/profile 방문 = 프로필 설정 화면 접근. 계정 이름 변경(ACCOUNT_NAME_CHANGE)이 아니다.
# 근거 원자료(RETEST_FINAL_ANALYSIS)를 C: 에서 재확인하지 못했고 분석용 History 사본에 /profile 방문이 0건이라
# PARTIALLY_VERIFIED / MEDIUM (2026-09-15 정정). synthetic 테스트 통과는 실제 Artifact 에서 Rule 의미가 검증됐다는 뜻이 아니다.

PROFILE_ACCESS_RULE_ID = "CHATGPT_PROFILE_ACCESS_001"
_PROFILE_ACCESS_LIMITATIONS = (
    "프로필 설정 화면 접근만 나타낸다. 계정 이름 변경(ACCOUNT_NAME_CHANGE)을 뜻하지 않는다",
    "Rule 근거는 문서 기록(HANDOFF, SHEET_GAP_AUDIT T57)뿐이다. 원자료(RETEST_FINAL_ANALYSIS)는 C: 에서 확인하지 못했고 "
    "분석용 History 사본에 /profile 방문이 없어 실제 Artifact 에서 Rule 의미를 검증하지 못함",
)


def detect_profile_access(records: list[ArtifactRecord],
                          coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    return _detect_visit_rule(
        records, coverages, host=CHATGPT_HOST, path=_PROFILE_PATH, query_expected=False,
        rule_id=PROFILE_ACCESS_RULE_ID, action="PROFILE_ACCESS", rule_verification="PARTIALLY_VERIFIED", confidence="MEDIUM",
        reasons=[REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_URL, REASON_RULE_EVIDENCE_NOT_RECONFIRMED],
        limitations=_PROFILE_ACCESS_LIMITATIONS,
    )


# ---- 8.11 CHATGPT_ACCOUNT_SESSION_001 (Local Storage accountSwitchSessions) ---
# 근거: Local Storage oai/apps/accountSwitchSessions PUT. Reader 가 이미 session 별로
#   userId SHA-256 앞자리 / sessionToken 존재·길이 / lastLoggedInAt(unix ms) / workspace 수를 뽑아 두지만
#   지금까지 이 Record 를 읽는 Rule 이 없었다 (History 가 지워진 이미지에서는 로그인·계정 전환 근거가 전부 사라졌다).
# 판정:
#   - session 마다 lastLoggedInAt 이 있으면 LOGIN (DETECTED / MEDIUM). 시각은 값 안에 들어 있는 서버 보고 값이다.
#   - 한 값 안에 서로 다른 userId 가 2개 이상이면 ACCOUNT_SWITCH (DETECTED / MEDIUM).
#     시각은 그 값 안에서 가장 나중의 lastLoggedInAt (= 마지막으로 로그인한 계정) 을 쓴다.
# 물리 Record 와 논리 상태를 구분한다: 같은 (os_user, profile, userId 앞자리, lastLoggedInAt) 이면 Event 1건이고
#   .log·.ldb 의 다른 물리 Record 는 보조 Evidence 로 붙는다 (PROMPT_DRAFT 와 같은 방식).

ACCOUNT_SESSION_RULE_ID = "CHATGPT_ACCOUNT_SESSION_001"
_ACCOUNT_SESSION_LOGIN_INFERENCE = (
    "ChatGPT 계정 전환용 세션 목록 (oai/apps/accountSwitchSessions) 에 이 계정의 lastLoggedInAt 이 기록됨 → "
    "그 시각에 이 계정으로 로그인한 것으로 추론한다 (로그인 방식·성공 여부·이 PC 여부는 추론하지 않음)")
_ACCOUNT_SESSION_SWITCH_INFERENCE = (
    "한 accountSwitchSessions 값 안에 서로 다른 계정 식별자가 2개 이상 기록됨 → "
    "이 Profile 에서 여러 계정을 등록해 계정 전환을 사용한 것으로 추론한다 (전환 횟수·방향은 추론하지 않음)")
_ACCOUNT_SESSION_LIMITATIONS = (
    "lastLoggedInAt 은 값 안에 들어 있는 서버 보고 시각이다. 로컬에서 관찰한 행위 시각이 아니며 저장 시각과 다를 수 있다",
    "세션 목록은 로그인·전환 때마다 통째로 다시 저장되므로 같은 lastLoggedInAt 이 여러 물리 Record 에 남는다 (Event 는 1건)",
    "계정 식별자는 SHA-256 앞자리로만 비교한다. 실제 계정·이메일은 Event 에 기록하지 않는다",
    "세션 목록에 계정이 남아 있다는 것이 현재 로그인 상태를 뜻하지 않는다 (로그아웃 후에도 남을 수 있음)",
    "전환 시점 자체는 관찰하지 못한다. 시각은 '가장 나중에 로그인한 계정의 lastLoggedInAt' 이다",
    "같은 계정으로 재로그인한 경우를 비교한 Negative Control 이 없다 (NEEDS_VERIFICATION)",
)


def _account_session_evidence(record: ArtifactRecord, index: int, session: dict[str, Any], level: str,
                              source_sha256: str | None, note: str) -> EvidenceItem:
    timestamp = session.get("last_logged_in_at") if isinstance(session.get("last_logged_in_at"), dict) else {}
    return EvidenceItem(
        evidence_id=f"evidence:{ACCOUNT_SESSION_RULE_ID}:{record.record_id}:session={index}",
        record_id=record.record_id, evidence_level=level, artifact_type=record.artifact_type,
        source_path=record.source_path, record_location=record.record_location, source_sha256=source_sha256,
        timestamp_raw=timestamp.get("timestamp_raw"), timestamp_utc=timestamp.get("timestamp_utc"),
        timestamp_kst=timestamp.get("timestamp_kst"), timestamp_type=timestamp.get("timestamp_type"),
        timestamp_source=timestamp.get("timestamp_source"),
        observed={"session_index": index, "session_count": record.observed.get("session_count"),
                  "user_id_sha256_prefix": session.get("user_id_sha256_prefix"),
                  "session_token_present": session.get("session_token_present"),
                  "session_token_length": session.get("session_token_length"),
                  "workspace_count": session.get("workspace_count"),
                  "sequence": record.observed.get("sequence")},
        note=note,
    )


def _account_session_puts(records: list[ArtifactRecord]) -> list[ArtifactRecord]:
    puts = {r.record_id: r for r in records if r.artifact_type == "local_storage"
            and r.observed.get("key_kind") == "account_switch_sessions" and r.observed.get("operation") == "PUT"
            and isinstance(r.observed.get("sessions"), list) and r.observed.get("sessions")}
    return sorted(puts.values(), key=lambda r: (r.os_user or "", r.browser_profile or "",
                                                r.observed.get("sequence", -1), r.source_path, r.record_id))


def detect_account_session_login(records: list[ArtifactRecord],
                                 coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "local_storage"}
    found: dict[tuple, dict[str, Any]] = {}
    for record in _account_session_puts(records):
        for index, session in enumerate(record.observed["sessions"]):
            if not isinstance(session, dict):
                continue
            timestamp = session.get("last_logged_in_at") if isinstance(session.get("last_logged_in_at"), dict) else {}
            if not timestamp.get("timestamp_utc"):
                continue  # 변환 가능한 로그인 시각이 없으면 Event 를 만들지 않는다 (sequence 를 시각으로 쓰지 않음)
            key = (record.os_user, record.browser_profile, session.get("user_id_sha256_prefix"),
                   timestamp.get("timestamp_raw"))
            if key in found:
                found[key]["later"].append((record, index, session))
            else:
                found[key] = {"record": record, "index": index, "session": session, "later": []}

    events: list[Event] = []
    for item in found.values():
        record, index, session = item["record"], item["index"], item["session"]
        timestamp = session["last_logged_in_at"]
        primary = _account_session_evidence(record, index, session, "SUPPORTING", sha_by_source.get(record.source_path),
                                            "계정 전환용 세션 목록에 기록된 이 계정의 lastLoggedInAt (서버 보고 값)")
        supporting = [_account_session_evidence(later, later_index, later_session, "SUPPORTING",
                                                sha_by_source.get(later.source_path),
                                                "같은 로그인 상태가 남아 있는 다른 물리 Record (.log / .ldb 또는 옛 버전)")
                      for later, later_index, later_session in item["later"]]
        reasons = [REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_VALUE, REASON_EMBEDDED_TIMESTAMP,
                   REASON_TIMESTAMP_EXPLAINED, REASON_NOT_UNIQUE_TO_ACTION]
        if supporting:
            reasons.append(REASON_SUPPORTING_CORRELATED)
        events.append(Event(
            event_id=f"event:{ACCOUNT_SESSION_RULE_ID}:{record.record_id}:login={index}", finding_type="USER_ACTION",
            action="LOGIN", action_status="DETECTED", timestamp_raw=timestamp.get("timestamp_raw"),
            timestamp_utc=timestamp.get("timestamp_utc"), timestamp_kst=timestamp.get("timestamp_kst"),
            timestamp_type=timestamp.get("timestamp_type"), timestamp_source=timestamp.get("timestamp_source"),
            representative_evidence_id=primary.evidence_id, confidence="MEDIUM", confidence_reason=reasons,
            rule_id=ACCOUNT_SESSION_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=record.os_user,
            browser=record.browser, browser_profile=record.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting, inference=_ACCOUNT_SESSION_LOGIN_INFERENCE,
            limitations=list(_ACCOUNT_SESSION_LIMITATIONS),
            warnings=list(record.warnings) + list(timestamp.get("warnings") or []),
        ))
    return events


def detect_account_session_switch(records: list[ArtifactRecord],
                                  coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "local_storage"}
    found: dict[tuple, dict[str, Any]] = {}
    for record in _account_session_puts(records):
        sessions = [s for s in record.observed["sessions"] if isinstance(s, dict)]
        users = {s.get("user_id_sha256_prefix") for s in sessions if s.get("user_id_sha256_prefix")}
        if len(users) < 2:
            continue  # 계정이 하나면 전환 근거가 아니다
        latest = max(
            ((s, s["last_logged_in_at"]) for s in sessions
             if isinstance(s.get("last_logged_in_at"), dict) and s["last_logged_in_at"].get("timestamp_utc")),
            key=lambda pair: pair[1]["timestamp_utc"], default=None)
        if latest is None:
            continue  # 변환 가능한 로그인 시각이 하나도 없으면 Event 시각을 정할 수 없다
        key = (record.os_user, record.browser_profile, frozenset(users), latest[1].get("timestamp_raw"))
        if key in found:
            found[key]["later"].append(record)
        else:
            found[key] = {"record": record, "sessions": sessions, "users": users, "latest": latest, "later": []}

    events: list[Event] = []
    for item in found.values():
        record, sessions, users = item["record"], item["sessions"], item["users"]
        latest_session, timestamp = item["latest"]
        sha = sha_by_source.get(record.source_path)
        primary = _account_session_evidence(
            record, sessions.index(latest_session), latest_session, "SUPPORTING", sha,
            f"서로 다른 계정 {len(users)}개가 함께 기록된 세션 목록 — 가장 나중의 lastLoggedInAt 계정")
        supporting = [_account_session_evidence(record, index, session, "SUPPORTING", sha,
                                                "같은 세션 목록에 함께 기록된 다른 계정")
                      for index, session in enumerate(sessions) if session is not latest_session]
        supporting += [_account_session_evidence(later, 0, later.observed["sessions"][0], "SUPPORTING",
                                                 sha_by_source.get(later.source_path),
                                                 "같은 계정 조합이 남아 있는 다른 물리 Record (.log / .ldb 또는 옛 버전)")
                       for later in item["later"]]
        events.append(Event(
            event_id=f"event:{ACCOUNT_SESSION_RULE_ID}:{record.record_id}:switch", finding_type="USER_ACTION",
            action="ACCOUNT_SWITCH", action_status="DETECTED", timestamp_raw=timestamp.get("timestamp_raw"),
            timestamp_utc=timestamp.get("timestamp_utc"), timestamp_kst=timestamp.get("timestamp_kst"),
            timestamp_type=timestamp.get("timestamp_type"), timestamp_source=timestamp.get("timestamp_source"),
            representative_evidence_id=primary.evidence_id, confidence="MEDIUM",
            confidence_reason=[REASON_RULE_PARTIALLY_VERIFIED, REASON_DIRECT_VALUE, REASON_EMBEDDED_TIMESTAMP,
                               REASON_TIMESTAMP_EXPLAINED, REASON_SUPPORTING_CORRELATED, REASON_NOT_UNIQUE_TO_ACTION],
            rule_id=ACCOUNT_SESSION_RULE_ID, rule_verification="PARTIALLY_VERIFIED", os_user=record.os_user,
            browser=record.browser, browser_profile=record.browser_profile, device_attribution="UNKNOWN",
            primary_evidence=[primary], supporting_evidence=supporting,
            inference=_ACCOUNT_SESSION_SWITCH_INFERENCE,
            limitations=list(_ACCOUNT_SESSION_LIMITATIONS) + [
                f"이 값에 기록된 계정 식별자 {len(users)}개 (SHA-256 앞자리): " + ", ".join(sorted(users))],
            warnings=list(record.warnings) + list(timestamp.get("warnings") or []),
        ))
    return events


# ---- 8.22 CHATGPT_ACCOUNT_NAME_CHANGE_001 -----------------------------------
# 근거: Local Storage oai/apps/accountSwitchSessions 의 같은 계정(userId 해시) 항목에서 이름 해시가 바뀐 전이.
#   이름 원문은 저장하지 않고 SHA-256 앞자리만 비교한다 (계정 정보 비노출 정책).
# 변경 후 이름만 있고 변경 전 값이 없으면 Event 를 만들지 않는다 (값 하나로 '변경'을 판정하지 않는다).

ACCOUNT_NAME_CHANGE_RULE_ID = "CHATGPT_ACCOUNT_NAME_CHANGE_001"
REASON_ACCOUNT_NAME_TRANSITION = "ACCOUNT_NAME_TRANSITION"
_ACCOUNT_NAME_CHANGE_INFERENCE = (
    "같은 계정 식별자의 세션 항목에서 이름 해시가 서로 다른 값으로 바뀜 → 계정 표시 이름이 바뀐 것으로 관찰한다 "
    "(사용자가 직접 바꿨는지 · 어떤 이름이었는지는 추론하지 않음)"
)
_ACCOUNT_NAME_CHANGE_LIMITATIONS = (
    "이름은 해시 앞자리로만 비교한다. 실제 이름·이메일은 Event 에 기록하지 않는다",
    "세션 목록은 서버 응답의 로컬 사본이므로 다른 기기에서의 변경이 반영된 것일 수 있다",
    "변경 전 값이 남아 있지 않으면 이 전이를 볼 수 없다 — 값이 하나뿐이면 Event 를 만들지 않는다",
    "이름 변경 전후를 비교한 실험 자료가 없어 Rule 이 검증되지 않았다 (NEEDS_VERIFICATION)",
    "시각은 세션 항목의 lastLoggedInAt 이며 이름을 바꾼 시각이 아니다",
)


def detect_account_name_change(records: list[ArtifactRecord],
                               coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """accountSwitchSessions 의 같은 계정에서 이름 해시가 바뀐 전이 → ACCOUNT_NAME_CHANGE (CANDIDATE)."""
    sha_by_source = {c.source_path: c.source_sha256 for c in coverages if c.artifact_type == "local_storage"}
    names: dict[tuple, list[tuple[ArtifactRecord, dict[str, Any]]]] = {}
    for record in _account_session_puts(records):
        for session in record.observed["sessions"]:
            if not isinstance(session, dict) or not session.get("account_name_sha256_prefix"):
                continue
            key = (record.os_user, record.browser_profile, session.get("user_id_sha256_prefix"))
            names.setdefault(key, []).append((record, session))

    events: list[Event] = []
    for key in sorted(names, key=str):
        history = names[key]
        for (older, older_session), (newer, newer_session) in zip(history, history[1:]):
            before = older_session["account_name_sha256_prefix"]
            after = newer_session["account_name_sha256_prefix"]
            if before == after:
                continue
            summary = {"user_id_sha256_prefix": key[2], "account_name_sha256_prefix_before": before,
                       "account_name_sha256_prefix_after": after,
                       "sequence_before": older.observed.get("sequence"),
                       "sequence_after": newer.observed.get("sequence")}
            note = "accountSwitchSessions 의 같은 계정 항목에서 이름 해시가 바뀜 (이름 원문은 기록하지 않음)"
            primary = _session_evidence(newer, "SUPPORTING", sha_by_source.get(newer.source_path), note,
                                        ACCOUNT_NAME_CHANGE_RULE_ID)
            primary.observed = dict(summary)
            earlier = _session_evidence(older, "SUPPORTING", sha_by_source.get(older.source_path),
                                        "직전의 이름 해시가 기록된 세션 목록", ACCOUNT_NAME_CHANGE_RULE_ID)
            earlier.observed = {"user_id_sha256_prefix": key[2], "account_name_sha256_prefix": before,
                                "sequence": older.observed.get("sequence")}
            timestamp = newer_session.get("last_logged_in_at") if isinstance(newer_session.get("last_logged_in_at"), dict) else {}
            timestamp = {name: value for name, value in timestamp.items() if name != "warnings"}
            reasons = [REASON_ACCOUNT_NAME_TRANSITION, REASON_SUPPORTING_CORRELATED, REASON_NOT_UNIQUE_TO_ACTION,
                       REASON_TIMESTAMP_APPROXIMATED if timestamp.get("timestamp_utc") else REASON_TIMESTAMP_MISSING]
            events.append(_candidate_event(
                rule_id=ACCOUNT_NAME_CHANGE_RULE_ID, action="ACCOUNT_NAME_CHANGE",
                event_id=f"event:{ACCOUNT_NAME_CHANGE_RULE_ID}:{newer.record_id}:account={key[2]}",
                record=newer, primary=primary, supporting=[earlier], timestamp=timestamp, reasons=reasons,
                inference=_ACCOUNT_NAME_CHANGE_INFERENCE, limitations=list(_ACCOUNT_NAME_CHANGE_LIMITATIONS),
                confidence="MEDIUM" if timestamp.get("timestamp_utc") else "LOW",
                warnings=_merged_warnings([older, newer])))
    return events
