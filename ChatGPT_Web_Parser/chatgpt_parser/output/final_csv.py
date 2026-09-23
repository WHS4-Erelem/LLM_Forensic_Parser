"""최종 사용자용 CSV 2종 (팀 공통 schema)."""
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
from ..artifacts.history import redact_url_query
from ..discovery import _join_source_path


# --- 12-2. 최종 사용자용 CSV 2종 ---------------------------------------------
# 개발·검증용 CSV 5종 (위) 은 그대로 두고, 사람이 바로 읽는 최종 출력 2개를 같은 ParseResult 에서 파생한다.
#   timeline.csv                → "사용자가 언제 무엇을 했는가"  (Event 1건 = 1 row, 시각순)
#   recovered_conversations.csv → "사용자가 LLM 과 어떤 대화를 했는가" (복구된 메시지 1건 = 1 row)
# 새 판정을 만들지 않는다. Event 수·메시지 수와 행 수가 정확히 일치하고, 복구되지 않은 내용을 채우지 않는다.
# 시각은 KST(+09:00) 표기이며 원본 raw·UTC 는 events.csv / JSON 에 그대로 남아 있다.

# 컬럼 이름·순서는 팀 공통 CSV 형식에 맞춘다. "Behavior_details " / "Artifact_details " / "message order" 의
# 뒤 공백·중간 공백은 팀 샘플에 실제로 있는 문자라서 그대로 둔다 (정규화하면 샘플과 어긋난다).
CSV_TIMELINE_COLUMNS = (
    "Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict", "Artifact_path", "Artifact_details ",
)
# role 은 "누가 말했는가" 없이는 대화를 읽을 수 없어 포함한다 (Artifact 값 그대로).
CSV_RECOVERED_CONVERSATION_COLUMNS = (
    "Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
    "parent_message_uuid", "message order", "role", "content", "Artifact_path",
)
CSV_FINAL_MODEL = "chatgpt-web"  # 최종 CSV 표기. 내부 SERVICE("chatgpt_web") 는 그대로 둔다.

# action(내부 Rule 코드) → 최종 CSV 의 사람이 읽는 행위 이름. 최종 CSV 표기에만 쓰고 Rule·판정은 바꾸지 않는다.
# 의미를 코드에서 확인한 action 만 넣는다. 없는 action 은 내부 코드 문자열을 그대로 출력한다 (잘못 번역하지 않는다).
CSV_USER_BEHAVIOR_LABELS = {
    "LOGIN": "로그인",
    "LOGOUT": "로그아웃",
    "ACCOUNT_SWITCH": "계정 전환",
    "ACCOUNT_NAME_CHANGE": "계정 이름 변경",
    "PROFILE_ACCESS": "프로필 화면 접근",
    "CONVERSATION_CREATE": "새로운 대화 생성",
    "CONVERSATION_ACCESS": "대화 열람",
    "CONVERSATION_RETRY": "대화 재시도",
    "CONVERSATION_REMOVED_FROM_LIST": "대화 목록에서 사라짐",
    "CONVERSATION_DELETE": "대화 삭제",
    "PROMPT_DRAFT": "사용자 프롬프트 입력/전송",  # 팀 행위 분류 체계: 초안은 별도 행위가 아니라 전송 미확인(의심) 으로 표기 (2026-09-23)
    "PROMPT_SEND": "사용자 프롬프트 입력/전송",
    "FILE_UPLOAD": "파일 업로드",
    "FILE_UPLOAD_DELETE": "업로드한 파일 삭제",
    "FILE_DOWNLOAD": "파일 다운로드",
    "IMAGE_GENERATION_REQUEST": "이미지 생성 요청",
    "SHARE_LINK": "공유 링크 생성",
    "MODEL_CHANGE": "모델 변경",
    "TEMPORARY_CHAT": "임시 채팅 사용",
    "INCOGNITO": "브라우저 시크릿 모드",
    "DATA_EXPORT_REQUEST": "대화 데이터 Export",
    "HISTORY_DELETE": "방문기록 삭제",
    "CACHE_DELETE": "캐시 삭제",
}
# action_status → 팀 형식. Parser 가 만드는 값은 이 둘뿐이라 매핑에 없으면 원문을 그대로 둔다.
CSV_VERDICT_LABELS = {"DETECTED": "확정", "CANDIDATE": "의심"}


def csv_final_timestamp(kst: str | None) -> str | None:
    """
    ISO KST(`2026-09-01T18:41:00.065000+09:00`) → 팀 공통 표기(`2026-09-01 18:41:00.065000 KST`).
    소수 자리를 늘리거나 줄이지 않는다 — 원본 precision 이 낮으면 낮은 그대로 둔다 (가짜 정밀도 금지).
    +09:00 이 아닌 값은 손대지 않는다 (표기를 바꾸면서 시각을 바꾸지 않는다).
    """
    if not kst or not kst.endswith("+09:00"):
        return kst
    text = kst[:-len("+09:00")].replace("T", " ")
    if "." not in text:  # 팀 공통: 소수 6자리 고정 (원본 정밀도는 JSON timestamp_raw 에 보존)
        text += ".000000"
    return text + " KST"


def csv_final_artifact_path(source_path: str | None, record_location: str | None) -> str | None:
    """
    최종 CSV 의 Artifact_path = **원본 파일 경로만**. entry/stream/offset 같은 record 상세는 넣지 않는다.
    Cache 처럼 source_path 가 폴더이고 record_location 에 `file=<이름>` 이 있으면 그 파일까지 붙인다.
    파일을 특정할 수 없으면 source_path 를 그대로 둔다 (경로를 만들어 내지 않는다).
    """
    if not source_path:
        return None
    match = re.search(r"(?:^|\s)file=(\S+)", record_location or "")
    return _join_source_path(source_path, match.group(1)) if match else source_path


def _timeline_evidence(event: Event) -> EvidenceItem | None:
    """Event 의 대표 Evidence (없으면 primary 첫 건)."""
    candidates = list(event.primary_evidence) + list(event.supporting_evidence)
    for item in candidates:
        if item.evidence_id == event.representative_evidence_id:
            return item
    return candidates[0] if candidates else None


def _timeline_conversation_id(event: Event) -> str | None:
    """Evidence 가 실제로 관찰한 대화 ID. 없으면 None — 추정해서 채우지 않는다."""
    for item in list(event.primary_evidence) + list(event.supporting_evidence):
        for key in ("conversation_id", "url_conversation_id"):
            value = item.observed.get(key) if isinstance(item.observed, dict) else None
            if isinstance(value, str) and value:
                return value
    return None


def _timeline_summary(event: Event, evidence: EvidenceItem | None) -> str:
    """사람이 읽는 한 줄 요약. action 으로 시작하고 Evidence Level 과 관찰 note 를 잇는다."""
    parts = [event.action]
    if evidence is not None:
        parts.append(evidence.evidence_level)
        if evidence.note:
            parts.append(evidence.note)
    if event.warnings:
        parts.append("warnings=" + ",".join(event.warnings))
    return " | ".join(redact_url_query(part)[0] for part in parts)  # note 에 URL 이 섞여도 인증 값을 남기지 않는다


CSV_EMPTY_CELL = "-"  # 팀 공통: 시각·ID 등 값이 없는 셀은 빈칸 대신 "-"


def _fill_empty(row: dict[str, Any]) -> dict[str, Any]:
    """최종 CSV 2종 전용: None / 빈 문자열 셀을 팀 공통 placeholder 로 바꾼다 (debug CSV 는 그대로)."""
    return {k: (CSV_EMPTY_CELL if v is None or (isinstance(v, str) and not v.strip()) else v)
            for k, v in row.items()}


def _timeline_row(event: Event) -> dict[str, Any]:
    evidence = _timeline_evidence(event)
    location = record_detail = None
    if evidence is not None:
        location = redact_url_query(csv_final_artifact_path(evidence.source_path, evidence.record_location))[0]
        if evidence.record_location:
            record_detail = redact_url_query(evidence.record_location)[0]
    conversation_id = _timeline_conversation_id(event)
    behavior = [_timeline_summary(event, evidence)]  # 무엇을 했는가
    if event.action == "PROMPT_DRAFT":  # 초안 저장만 확인됨 — 전송은 미확인이라 Verdict 도 의심으로 고정
        behavior.append("전송 미확인(입력창 초안 저장만)")
    if conversation_id:
        behavior.append(f"conversation_id={conversation_id}")
    # 무엇을 근거로 판정했는가 — confidence·rule_id·artifact_type 은 최종 CSV 에서 이 칸에만 남는다.
    details = [f"artifact_type={evidence.artifact_type}"] if evidence is not None else []
    details += [f"confidence={event.confidence}", f"rule_id={event.rule_id}",
                f"rule_verification={event.rule_verification}"]
    if record_detail:  # entry / stream / block / offset / carving 등 record 상세는 경로가 아니라 이 칸에 둔다
        details.append(f"record={record_detail}")
    return _fill_empty({
        "Model": CSV_FINAL_MODEL,
        "Timestamp": csv_final_timestamp(event.timestamp_kst),  # 없으면 빈 cell — 시각을 만들어 내지 않는다
        "User_behavior": CSV_USER_BEHAVIOR_LABELS.get(event.action, event.action),
        "Behavior_details ": " | ".join(behavior),
        "Verdict": "의심" if event.action == "PROMPT_DRAFT" else CSV_VERDICT_LABELS.get(event.action_status, event.action_status),
        "Artifact_path": location,
        "Artifact_details ": " | ".join(details),
    })


def _recovered_conversation_row(conversation: RecoveredConversation, message: RecoveredMessage) -> dict[str, Any]:
    # 실제로 복구해 온 원본 파일 경로만 넣는다. entry·offset 같은 record 상세는 messages.csv 에 남는다
    # (이 CSV 에는 Artifact_details 칸이 없다). 파일을 특정할 수 없으면 만들어 내지 않는다.
    location = csv_final_artifact_path(message.source_path, message.record_location)
    return _fill_empty({
        "Model": CSV_FINAL_MODEL,
        "timestamp": csv_final_timestamp(message.timestamp_kst),
        "conversation_uuid": message.conversation_id or conversation.conversation_id,
        "conversation_title": conversation.title,
        "message_uuid": message.message_id,
        "parent_message_uuid": message.parent_message_id,
        "message order": message.sequence_index,
        "role": message.role,
        "content": message.content,  # 복구된 원문 전체 (요약·절단 없음)
        "Artifact_path": redact_url_query(location)[0] if location else None,
    })
