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
from ..artifacts.preferences import PREFERENCES_CLEAR_DATA_KEY
from ..discovery import _join_source_path


# --- 12-2. 최종 사용자용 CSV 2종 ---------------------------------------------
# 개발·검증용 CSV 5종 (위) 은 그대로 두고, 사람이 바로 읽는 최종 출력 2개를 같은 ParseResult 에서 파생한다.
#   timeline.csv                → "사용자가 언제 무엇을 했는가"  (팀 행위 분류 체계에 있는 Event 1건 = 1 row, 시각순)
#   recovered_conversations.csv → "사용자가 LLM 과 어떤 대화를 했는가" (복구된 메시지 1건 = 1 row)
# 새 판정을 만들지 않고, 복구되지 않은 내용을 채우지 않는다. 메시지 수와 행 수는 정확히 일치한다.
# timeline.csv 행 수는 Event 수와 다를 수 있다 — 팀 행위 목록 밖 action 은 최종 행을 만들지 않는다 (아래 참조).
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
# 의미를 코드에서 확인한 action 만 넣는다 (잘못 번역하지 않는다). 여기 없는 action 은 최종 timeline 행을
# 만들지 않는다 — csv_final_user_behavior() 참조. 탐지·Event·근거는 그대로 남는다.
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
    "CONVERSATION_DELETE": "기존 대화 삭제",  # 팀 분류 체계의 이름 (Rule 이 보는 것은 개별 대화 1건의 삭제다)
    "PROMPT_DRAFT": "사용자 프롬프트 입력/전송",  # 팀 행위 분류 체계: 초안은 별도 행위가 아니라 전송 미확인(의심) 으로 표기 (2026-09-23)
    "PROMPT_SEND": "사용자 프롬프트 입력/전송",
    # FILE_UPLOAD 는 csv_final_upload_behavior() 가 첨부 MIME 으로 문서/이미지를 가릴 때만 최종 행위가 된다.
    # 아래 값은 종류를 가리지 못한 업로드의 내부 표기이며 최종 CSV 에는 쓰지 않는다 (FILE_DOWNLOAD 와 같다).
    "FILE_UPLOAD": "파일 업로드",
    "FILE_UPLOAD_DELETE": "업로드한 파일 삭제",
    # FILE_DOWNLOAD 는 csv_final_download_behavior() 가 evidence 로 문서/생성 이미지를 가릴 때만
    # 최종 행위가 된다. 아래 값은 종류를 가리지 못한 다운로드의 내부 표기이며 최종 CSV 에는 쓰지 않는다.
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
# 팀 공통 행위 분류 체계 (integration/user_behaviors.txt, 2026-10-08 기준) 의 사본.
# 파서 6개는 통합기와 서로에게 독립이라 그 파일을 읽지 않는다 (경로가 없는 배포에서도 같게 동작해야 한다).
# 목록이 바뀌면 여기만 고친다. 사본이 원본과 같은지는 test 가 원본 파일과 대조해서 지킨다.
CSV_TEAM_USER_BEHAVIORS = frozenset({
    "로그인", "로그아웃", "계정 전환", "계정 이름 변경",
    "애플리케이션 설치", "애플리케이션 실행", "애플리케이션 삭제", "정상 종료", "강제 종료",
    "새로운 대화 생성", "기존 대화 삭제", "대화 수정", "대화 재시도", "대화 공유", "공유 링크 생성",
    "대화 데이터 Export", "사용자 프롬프트 입력/전송", "사용자 프롬프트 삭제", "임시 채팅 사용",
    "이미지 업로드", "이미지 업로드 삭제", "문서 업로드", "문서 업로드 삭제", "문서 다운로드",
    "이미지 생성 요청", "생성 이미지 다운로드", "생성 이미지 다운로드 삭제",
    "모델 변경", "모델 다운로드 내역",
    "브라우저 시크릿 모드", "방문기록 삭제", "캐시 삭제",
})
# 팀 회의(2026-09-23) 확정: 공유 분석표(「시나리오 이미지 행위 시각」의 사용자 행위 열, = integration/user_behaviors.txt)
# 에 있는 행위만 최종 timeline.csv 의 User_behavior 로 낸다. 목록 밖 행위는 **탐지를 멈추지 않는다** —
# Rule·Evidence·Coverage·debug CSV(events.csv)·result.json 에는 그대로 남고, 최종 timeline.csv 행만 만들지 않는다.
# ("탐지하지 않는다" 와 "최종 User_behavior 로 내지 않는다" 는 다르다. 판정 근거는 지우지 않는다.)
#
# 제외 대상을 이름마다 손으로 적지 않고 팀 목록과 대조해서 만든다 — 목록 밖 이름이 새로 생겨도
# 통합기의 UNKNOWN_USER_BEHAVIOR 로 새지 않는다. (2026-09-30: FILE_UPLOAD "파일 업로드" 가 그 경우였다.)
#   CONVERSATION_ACCESS            대화 열람 — 회의에서 개별 삭제 확정 ("무려 29개나, 얘도 그냥 지우는 걸로")
#   PROFILE_ACCESS                 프로필 화면 접근 — 분석표에 없는 파서 고유 행위
#   CONVERSATION_REMOVED_FROM_LIST 대화 목록에서 사라짐 — 기존 대화 삭제 판정의 보조 근거로만 남긴다
#   FILE_UPLOAD                    파일 업로드 — 첨부 MIME 으로 문서/이미지 업로드를 가려 낸다
#                                  (csv_final_upload_behavior). 상위 이름 자체는 분석표에 없어 여기 남는다.
#   FILE_UPLOAD_DELETE             업로드한 파일 삭제 — 분석표는 종류별로 나눠 쓰는데 파서는 상위 이름만 낸다 → 팀 결정 대기
#   FILE_DOWNLOAD                  파일 다운로드 — 2026-10-08 팀 목록에서 삭제되어 여기로 들어왔다. 전부터
#                                  csv_final_download_behavior() 가 문서/생성 이미지만 올렸으므로 출력은 그대로다.
# label 이 아예 없는 action 은 이 집합에 들어오지 않지만 최종 timeline 에서 빠지는 결과는 같다
# (csv_final_user_behavior() 가 팀 목록 대조 하나로 판단한다). 내부 action 코드를 User_behavior 로
# 내보내는 fallback 은 두지 않는다 — 팀 목록 밖 값은 통합기의 UNKNOWN_USER_BEHAVIOR 가 된다 (2026-10-01 확정).
# 이름을 정하지 않은 새 Rule 이 조용히 묻히는 것은 test 로 막는다
# (test_every_shipped_detector_action_has_a_team_label: 배포된 action 전부에 팀 목록 라벨이 있어야 한다).
CSV_NON_TEAM_ACTIONS = frozenset(action for action, label in CSV_USER_BEHAVIOR_LABELS.items()
                                 if label not in CSV_TEAM_USER_BEHAVIORS)

# action_status → 팀 형식. Parser 가 만드는 값은 이 둘뿐이라 매핑에 없으면 원문을 그대로 둔다.
CSV_VERDICT_LABELS = {"DETECTED": "확정", "CANDIDATE": "의심"}


# --- 다운로드: 종류가 evidence 로 확인될 때만 최종 행위로 올린다 (2026-10-05 팀 결정) ---
# generic "파일 다운로드" 는 최종 timeline 에 내지 않는다. 확장자만으로 승격하지 않는다 —
# ChatGPT 가 파일을 내려 주는 경로(backend-api/estuary/content 등) 에서 시작했는지와 MIME 을 함께 본다.
# 판별되지 않는 다운로드는 FILE_DOWNLOAD Event·Evidence 로 그대로 남고 최종 행만 만들지 않는다.
CSV_DOCUMENT_MIME_PREFIXES = (
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.",   # docx / xlsx / pptx
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.oasis.opendocument.",
    "application/rtf",
)
# ChatGPT 가 생성·보관한 파일을 내려 주는 경로. blob: URL 은 브라우저 내부 객체라 출처를 말해 주지 않는다.
CSV_CHATGPT_FILE_URL_MARKERS = ("backend-api/estuary/content", "backend-api/files/")
CSV_DOWNLOAD_DOCUMENT = "문서 다운로드"
CSV_DOWNLOAD_GENERATED_IMAGE = "생성 이미지 다운로드"


def _download_observed(event: Event) -> dict[str, Any]:
    """다운로드 Event 의 관찰값 (Reader 가 History downloads 에서 읽은 그대로)."""
    for item in list(event.primary_evidence) + list(event.supporting_evidence):
        observed = item.observed if isinstance(item.observed, dict) else {}
        if observed.get("filename") or observed.get("download_url") or observed.get("mime_type"):
            return observed
    return {}


def _from_chatgpt_file_endpoint(observed: dict[str, Any]) -> bool:
    url = str(observed.get("download_url") or "")
    return any(marker in url for marker in CSV_CHATGPT_FILE_URL_MARKERS)


def csv_final_download_behavior(event: Event) -> str | None:
    """FILE_DOWNLOAD 의 최종 User_behavior. 종류를 확인하지 못하면 None (최종 행 없음).

    - 문서: MIME 이 문서 형식이고 ChatGPT 파일 제공 경로에서 시작한 다운로드
    - 생성 이미지: 이미지 MIME + ChatGPT 파일 제공 경로 + 같은 대화에서 이미지 생성 요청이 확인된 경우
      (확장자·파일명만으로는 올리지 않는다. blob: URL 은 출처 근거가 되지 않는다.)
    """
    observed = _download_observed(event)
    mime = str(observed.get("mime_type") or "").lower()
    if not _from_chatgpt_file_endpoint(observed):
        return None
    if any(mime.startswith(prefix) for prefix in CSV_DOCUMENT_MIME_PREFIXES):
        return CSV_DOWNLOAD_DOCUMENT
    if mime.startswith("image/") and observed.get("generated_image_conversation_id"):
        return CSV_DOWNLOAD_GENERATED_IMAGE
    return None


# --- 업로드: 종류가 evidence 로 확인될 때만 최종 행위로 올린다 (다운로드와 같은 설계) ---
# 분석표는 업로드를 종류별(이미지 업로드 / 문서 업로드)로 쓰는데 Rule 은 상위 이름 FILE_UPLOAD 하나만 낸다.
# 첨부 MIME 은 Cache 대화 응답의 user 메시지에 이미 들어 있어 (Reader 가 읽어 둔 observed["mime_type"]),
# 그 값만으로 종류를 가린다. 탐지 Rule·Evidence 는 건드리지 않는다 — 최종 표기만 정한다.
# MIME 으로 가려지지 않으면 None (최종 행 없음). 확장자·파일명으로 추측해 올리지 않는다.
CSV_UPLOAD_DOCUMENT = "문서 업로드"
CSV_UPLOAD_IMAGE = "이미지 업로드"


def _upload_observed(event: Event) -> dict[str, Any]:
    """업로드 Event 의 관찰값 (Reader 가 Cache user 메시지 첨부에서 읽은 그대로)."""
    for item in list(event.primary_evidence) + list(event.supporting_evidence):
        observed = item.observed if isinstance(item.observed, dict) else {}
        if observed.get("mime_type"):
            return observed
    return {}


def csv_final_upload_behavior(event: Event) -> str | None:
    """FILE_UPLOAD 의 최종 User_behavior. 종류를 확인하지 못하면 None (최종 행 없음).

    - 문서: 첨부 MIME 이 문서 형식 (다운로드 쪽과 같은 CSV_DOCUMENT_MIME_PREFIXES 목록)
    - 이미지: 첨부 MIME 이 image/*
    그 밖의 MIME(예: text/x-python)·MIME 없음 은 올리지 않는다 — FILE_UPLOAD Event·Evidence 로 그대로 남는다.
    """
    mime = str(_upload_observed(event).get("mime_type") or "").lower()
    if any(mime.startswith(prefix) for prefix in CSV_DOCUMENT_MIME_PREFIXES):
        return CSV_UPLOAD_DOCUMENT
    if mime.startswith("image/"):
        return CSV_UPLOAD_IMAGE
    return None


def csv_final_user_behavior(action: str, event: Event | None = None) -> str | None:
    """최종 timeline.csv 의 User_behavior. 팀 목록에 없는 action(라벨이 없는 경우까지) 은 None.

    None 은 "이 Event 로 최종 timeline 행을 만들지 않는다" 는 뜻이다. 탐지를 멈추거나 근거를 지우는 것이
    아니라서 Event·Evidence·Coverage 는 events.csv / result.json 에 그대로 남는다.
    FILE_DOWNLOAD 는 종류가 evidence 로 확인될 때만 문서/생성 이미지 다운로드로 나간다.
    FILE_UPLOAD 도 같게 — 첨부 MIME 으로 문서/이미지 업로드를 가릴 때만 나간다.
    """
    if action == "FILE_DOWNLOAD":
        label = csv_final_download_behavior(event) if event is not None else None
        return label if label in CSV_TEAM_USER_BEHAVIORS else None
    if action == "FILE_UPLOAD":
        label = csv_final_upload_behavior(event) if event is not None else None
        return label if label in CSV_TEAM_USER_BEHAVIORS else None
    label = CSV_USER_BEHAVIOR_LABELS.get(action)
    return label if label in CSV_TEAM_USER_BEHAVIORS else None


def csv_final_timestamp(kst: str | None) -> str | None:
    """
    ISO KST(`2026-09-01T18:41:00.065000+09:00`) → 팀 공통 표기(`2026-09-01 18:41:00.065000 KST`).
    소수부는 팀 공통 계약대로 6자리 표기로 정규화한다 (소수부가 없으면 `.000000` 을 채운다) — 원본 정밀도는
    JSON 의 timestamp_raw / timestamp_utc 에 그대로 보존한다. 시각이 아예 없으면 None 을 돌려주고,
    최종 CSV 에는 csv_final_cells 가 `-` 로 적는다 (빈 칸은 통합 contract 위반이다).
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


# --- 최종 timeline.csv 의 사람이 읽는 두 칸 -------------------------------------
# 팀 요구(2026-10-01): 최종 CSV 에는 Parser 내부 표현을 내지 않는다.
#   Behavior_details  = "<발견 근거>_<핵심 내용>"  — 이 칸 하나만 보고 왜 그 행위로 판단했는지 알 수 있어야 한다
#   Artifact_details  = "[아티팩트명] 핵심 내용"   — Event 하나가 여러 artifact 를 썼으면 " | " 로 잇는다
# action · evidence_level(DIRECT/SUPPORTING) · rule_id · confidence · rule_verification · artifact_type ·
# signal 코드는 최종 CSV 에서 빼되 **지우지 않는다** — events.csv / records.csv / result.json 에 그대로 남는다
# (표현만 바꾸는 것이고 판정 근거를 없애는 것이 아니다).
# 핵심 내용은 Evidence·Record 가 실제로 가진 값만 쓴다. 관찰되지 않은 파일명·UUID·제목·URL·계정은 만들어 내지
# 않고, 값이 없으면 발견 근거만 적는다.
CSV_BEHAVIOR_REASONS = {
    "LOGIN": "로그인 URL 방문 흔적",
    "LOGOUT": "로그아웃 URL 방문",
    "ACCOUNT_SWITCH": "재인증/계정 전환 흔적",
    "ACCOUNT_NAME_CHANGE": "계정 이름 변경 흔적",
    "CONVERSATION_CREATE": "대화 생성 기록",
    "CONVERSATION_DELETE": "대화 삭제 요청/이벤트",
    "CONVERSATION_RETRY": "동일 사용자 메시지 아래 응답 분기",
    "PROMPT_SEND": "사용자 메시지 전송",
    "PROMPT_DRAFT": "프롬프트 작성 흔적(전송 미확인)",
    "FILE_DOWNLOAD": "다운로드 완료 기록",
    "IMAGE_GENERATION_REQUEST": "이미지 생성 요청 기록",
    "SHARE_LINK": "공유 링크 생성 기록",
    "MODEL_CHANGE": "모델 선택 값 변경",
    "TEMPORARY_CHAT": "임시 대화 객체",
    "INCOGNITO": "시크릿 창 표식",
    "DATA_EXPORT_REQUEST": "대화 데이터 Export 요청 기록",
    "HISTORY_DELETE": "방문 기록 결손 흔적",
    "CACHE_DELETE": "캐시 삭제 설정 흔적",
    # 아래 5개는 최종 timeline.csv 에 나가지 않는다 (CSV_NON_TEAM_ACTIONS). _timeline_row 를 직접 부르는
    # 쪽에서도 내부 표현이 보이지 않게 같은 형식으로 적어 둔다.
    "CONVERSATION_ACCESS": "대화 화면 방문 기록",
    "CONVERSATION_REMOVED_FROM_LIST": "대화 목록에서 사라진 대화",
    "PROFILE_ACCESS": "프로필 화면 방문 기록",
    "FILE_UPLOAD": "업로드 첨부 기록",
    "FILE_UPLOAD_DELETE": "업로드 첨부 삭제 기록",
}
# 같은 행위를 서로 다른 아티팩트에서 찾는 Rule 이 있으면 Rule 마다 근거 문장이 달라야 한다 — 관찰하지 않은 근거를
# 적지 않기 위한 것이다. (LOGIN 은 인증 URL 방문(CHATGPT_LOGIN_001) 과 계정 세션 목록의 lastLoggedInAt
# (CHATGPT_ACCOUNT_SESSION_001) 두 경로로 나온다. Rule 이름 자체는 최종 CSV 에 적지 않는다.)
# 세션 목록(Local Storage) 근거의 LOGIN — URL 이 없어 핵심 내용을 세션 개수로 적는다
CSV_ACCOUNT_SESSION_RULE_ID = "CHATGPT_ACCOUNT_SESSION_001"

CSV_BEHAVIOR_REASONS_BY_RULE = {
    CSV_ACCOUNT_SESSION_RULE_ID: "세션 목록의 최근 로그인 기록",
}
# 핵심 내용으로 쓸 observed key (앞에 있는 것 우선). 어느 것도 없으면 관찰된 대화 ID 를 본다.
CSV_BEHAVIOR_CORE_KEYS = {
    "LOGIN": ("url",),
    "LOGOUT": ("url",),
    "ACCOUNT_SWITCH": ("url",),
    "ACCOUNT_NAME_CHANGE": ("url",),
    "CONVERSATION_CREATE": ("title", "client_conversation_id"),
    "CONVERSATION_DELETE": ("title", "removed_conversation_id"),
    "CONVERSATION_RETRY": ("title",),
    "PROMPT_SEND": ("message_id",),
    "FILE_DOWNLOAD": ("filename", "target_path"),
    "FILE_UPLOAD": ("file_name",),
    "FILE_UPLOAD_DELETE": ("file_name",),
    "TEMPORARY_CHAT": ("url", "title"),
    "INCOGNITO": ("url",),
    "SHARE_LINK": ("url",),
    "MODEL_CHANGE": ("model_after", "model"),
    "CONVERSATION_ACCESS": ("title",),
    "PROFILE_ACCESS": ("url",),
}
CSV_BEHAVIOR_ID_KEYS = ("conversation_id", "url_conversation_id")
# "이전 → 이후" 로 보여 줄 행위: (이전 값 key, 이후 값 key). 두 값은 **같은 Evidence 안**에 있는 것만 짝으로 쓴다
# (다른 Evidence 의 값을 섞으면 관찰하지 않은 전이를 만들어 내게 된다).
CSV_BEHAVIOR_TRANSITIONS = {
    "ACCOUNT_SWITCH": ("user_id_sha256_prefix_before", "user_id_sha256_prefix"),
    "ACCOUNT_NAME_CHANGE": ("account_name_sha256_prefix_before", "account_name_sha256_prefix_after"),
}
CSV_ARTIFACT_LABELS = {
    "history": "History", "local_storage": "Local Storage", "session_storage": "Session Storage",
    "sessions": "Sessions", "cache": "Cache", "preferences": "Preferences", "cookies": "Cookies",
    "favicons": "Favicons", "indexeddb": "IndexedDB", "local_state": "Local State",
    "shared_proto_db": "Shared Proto DB", "ntfs": "NTFS",
}
# artifact 별로 최종 CSV 에 낼 observed key: (observed key, 사람이 읽는 이름, 단위)
CSV_ARTIFACT_DETAIL_FIELDS = {
    "history": (("url", "URL", ""), ("title", "제목", ""), ("state", "다운로드 상태", ""),
                ("filename", "파일명", ""), ("current_path", "저장 경로", ""), ("mime_type", "파일 형식", "")),
    "local_storage": (("key", "저장 key", ""), ("conversation_count", "대화 항목", "건"),
                      ("draft_count", "초안", "건"), ("session_count", "계정 세션", "개"),
                      ("removed_conversation_id", "사라진 대화", "")),
    "session_storage": (("key", "저장 key", ""),),
    "sessions": (("url", "URL", ""), ("title", "제목", "")),
    "cache": (("conversation_id", "대화 ID", ""), ("message_id", "메시지 ID", ""),
              ("file_name", "파일명", ""), ("mime_type", "파일 형식", "")),
    "shared_proto_db": (("file_name", "파일명", ""), ("filename", "파일명", "")),
}
# 관찰 값 뒤에 붙이는 한 마디. Preferences 는 값 자체가 설명이라 붙이지 않는다.
CSV_ARTIFACT_SUMMARIES = {
    "history": "방문 기록 확인", "cache": "응답 데이터 확인", "local_storage": "저장 값 확인",
    "session_storage": "저장 값 확인", "sessions": "세션 복원 기록 확인",
    "shared_proto_db": "다운로드 메타데이터 확인",
}
# Chrome downloads.state 값 이름 (표기만 바꾼다 — 판정에 쓰지 않는다).
CSV_DOWNLOAD_STATES = {0: "IN_PROGRESS", 1: "COMPLETE", 2: "CANCELLED", 3: "INTERRUPTED"}
CSV_PROMPT_LINE_LIMIT = 120  # 프롬프트 첫 줄이 이보다 길면 잘랐다는 것을 "…" 로 알린다


def _evidence_items(event: Event) -> list[EvidenceItem]:
    """Event 가 실제로 쓴 Evidence (primary 먼저, 그다음 supporting)."""
    return list(event.primary_evidence) + list(event.supporting_evidence)


def _observed_value(event: Event, key: str) -> Any:
    """Evidence 가 실제로 관찰한 값. 없으면 None — 추정해서 채우지 않는다."""
    for item in _evidence_items(event):
        observed = item.observed if isinstance(item.observed, dict) else {}
        value = observed.get(key)
        if value not in (None, "", [], {}) and not isinstance(value, bool):
            return value
    return None


def _first_line(text: str) -> str:
    """여러 줄 값의 첫 줄만. 자를 때는 자른 것을 "…" 로 알린다 (내용을 바꾸지 않는다)."""
    line = next((part.strip() for part in text.splitlines() if part.strip()), "")
    return line if len(line) <= CSV_PROMPT_LINE_LIMIT else line[:CSV_PROMPT_LINE_LIMIT] + "…"


def timeline_prompt_texts(result: ParseResult) -> dict[str, str]:
    """
    프롬프트 원문 첫 줄 찾아보기 표: message_id / record_id → 첫 줄.
    **이미 복구된** 사용자 메시지(conversations[]) 와 입력창 초안(records[] 의 drafts[]) 에 있는 값만 모은다.
    없는 대화 내용을 만들어 내지 않으며, 못 찾으면 Behavior_details 는 발견 근거만 적는다.
    """
    texts: dict[str, str] = {}
    for conversation in result.conversations:
        for message in conversation.messages:
            if (message.role == "user" and message.message_id
                    and isinstance(message.content, str) and message.content.strip()):
                texts.setdefault(message.message_id, _first_line(message.content))
    for record in result.records:
        drafts = record.observed.get("drafts") if isinstance(record.observed, dict) else None
        for draft in drafts or ():
            content = draft.get("content") if isinstance(draft, dict) else None
            if isinstance(content, str) and content.strip():
                texts.setdefault(record.record_id, _first_line(content))
                break
    return texts


def _behavior_core(event: Event, prompt_texts: dict[str, str]) -> str | None:
    """Behavior_details 의 "_<핵심 내용>". 관찰된 값이 없으면 None (발견 근거만 남는다)."""
    if event.action == "CACHE_DELETE":  # 삭제 대화상자의 선택 상태가 유일한 값이다 (시각은 없다)
        selected = _observed_value(event, "clear_data")
        return (f"{PREFERENCES_CLEAR_DATA_KEY}.cache=true"
                if isinstance(selected, dict) and selected.get("cache") is True else None)
    if event.rule_id == CSV_ACCOUNT_SESSION_RULE_ID:
        # 세션 목록 근거의 LOGIN 에는 URL 이 없다. 관찰값 중 사람이 바로 읽을 수 있는 것은 세션 개수뿐이고,
        # 계정 식별자 해시·토큰 길이는 최종 CSV 에 내지 않는다 (계정 정보 노출 금지).
        count = _observed_value(event, "session_count")
        return f"세션 {count}개" if isinstance(count, int) else None
    transition = CSV_BEHAVIOR_TRANSITIONS.get(event.action)
    if transition is not None:
        for item in _evidence_items(event):
            observed = item.observed if isinstance(item.observed, dict) else {}
            before, after = observed.get(transition[0]), observed.get(transition[1])
            if before and after:
                return f"{before} → {after}"
    if event.action in ("PROMPT_SEND", "PROMPT_DRAFT"):  # 복구된 원문이 있으면 프롬프트 첫 줄
        for item in _evidence_items(event):
            observed = item.observed if isinstance(item.observed, dict) else {}
            text = (prompt_texts.get(str(observed.get("message_id") or ""))
                    or prompt_texts.get(item.record_id or ""))
            if text:
                return text
    for key in tuple(CSV_BEHAVIOR_CORE_KEYS.get(event.action, ())) + CSV_BEHAVIOR_ID_KEYS:
        value = _observed_value(event, key)
        if value is not None:
            return redact_url_query(str(value))[0]
    return None


def _behavior_details(event: Event, prompt_texts: dict[str, str]) -> str | None:
    """"<발견 근거>_<핵심 내용>". 행위명을 정하지 않은 새 action 은 근거 문장을 만들어 내지 않는다."""
    reason = CSV_BEHAVIOR_REASONS_BY_RULE.get(event.rule_id) or CSV_BEHAVIOR_REASONS.get(event.action)
    if reason is None:
        return None
    core = _behavior_core(event, prompt_texts)
    return f"{reason}_{core}" if core else reason


def _artifact_fields(item: EvidenceItem) -> list[str]:
    """한 Evidence 에서 최종 CSV 에 낼 관찰 값 (whitelist 밖 값과 내부 분석 정보는 내지 않는다)."""
    observed = item.observed if isinstance(item.observed, dict) else {}
    if item.artifact_type == "preferences":  # 삭제 대화상자 체크박스 상태를 그대로 펼친다
        selected = observed.get("clear_data")
        if isinstance(selected, dict) and selected:
            names = (["cache"] if "cache" in selected else []) + sorted(n for n in selected if n != "cache")
            return ([f"{PREFERENCES_CLEAR_DATA_KEY}.{names[0]}={str(bool(selected[names[0]])).lower()}"]
                    + [f"{name}={str(bool(selected[name])).lower()}" for name in names[1:]])
    fields = []
    for key, label, unit in CSV_ARTIFACT_DETAIL_FIELDS.get(item.artifact_type, ()):
        value = observed.get(key)
        if value in (None, "") or isinstance(value, bool):
            continue
        if key == "state":  # downloads.state 는 숫자다 — 이름을 붙여 읽을 수 있게 한다
            value = CSV_DOWNLOAD_STATES.get(value, value)
        if key in ("url", "current_path", "target_path"):
            value = redact_url_query(str(value))[0]
        fields.append(f"{label}={value}{unit}")
    return fields


def _artifact_segment(item: EvidenceItem) -> str:
    """"[아티팩트명] 핵심 내용" 한 조각."""
    fields = _artifact_fields(item)
    if fields:
        summary = ("다운로드 기록 확인" if item.artifact_type == "history" and "filename" in (item.observed or {})
                   else CSV_ARTIFACT_SUMMARIES.get(item.artifact_type))
        if summary:
            fields.append(summary)
    elif item.note:  # whitelist 에 없는 관찰이면 Evidence 가 남긴 설명을 그대로 쓴다 (내부 코드가 아니다)
        fields = [redact_url_query(item.note)[0]]
    else:
        fields = [CSV_ARTIFACT_SUMMARIES.get(item.artifact_type, "기록 확인")]
    return f"[{CSV_ARTIFACT_LABELS.get(item.artifact_type, item.artifact_type)}] " + ", ".join(fields)


def _artifact_details(event: Event) -> str | None:
    """Event 가 쓴 artifact 를 순서대로 "[이름] 내용 | [이름] 내용" 으로. 같은 문장은 한 번만."""
    segments: list[str] = []
    for item in _evidence_items(event):
        segment = _artifact_segment(item)
        if segment not in segments:
            segments.append(segment)
    return " | ".join(segments) if segments else None


CSV_EMPTY_CELL = "-"  # 팀 공통: 시각·ID 등 값이 없는 셀은 빈칸 대신 "-"


def _fill_empty(row: dict[str, Any]) -> dict[str, Any]:
    """최종 CSV 2종 전용: None / 빈 문자열 셀을 팀 공통 placeholder 로 바꾼다 (debug CSV 는 그대로)."""
    return {k: (CSV_EMPTY_CELL if v is None or (isinstance(v, str) and not v.strip()) else v)
            for k, v in row.items()}


def _timeline_row(event: Event, prompt_texts: dict[str, str] | None = None) -> dict[str, Any]:
    evidence = _timeline_evidence(event)
    location = None
    if evidence is not None:
        location = redact_url_query(csv_final_artifact_path(evidence.source_path, evidence.record_location))[0]
    return _fill_empty({
        "Model": CSV_FINAL_MODEL,
        "Timestamp": csv_final_timestamp(event.timestamp_kst),  # 없으면 "-" — 시각을 만들어 내지 않는다
        "User_behavior": csv_final_user_behavior(event.action, event),  # 팀 목록 밖이면 None — 내부 코드를 내지 않는다
        "Behavior_details ": _behavior_details(event, prompt_texts or {}),
        "Verdict": "의심" if event.action == "PROMPT_DRAFT" else CSV_VERDICT_LABELS.get(event.action_status, event.action_status),
        "Artifact_path": location,
        "Artifact_details ": _artifact_details(event),
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
