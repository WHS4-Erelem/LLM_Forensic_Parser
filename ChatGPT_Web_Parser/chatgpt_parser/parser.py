"""분석 orchestration (extract / detect / run)."""
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
from .artifacts.cache import cache_data_dir, read_chrome_cache
from .image import open_image_source
from .output.csv_writer import write_result_csv
from .artifacts.history import read_chatgpt_history
from .artifacts.local_storage import local_storage_dir, read_local_storage
from .artifacts.preferences import preferences_path, read_preferences
from .artifacts.session_storage import read_session_storage, session_storage_dir
from .artifacts.sessions import read_chrome_sessions, sessions_dir
from .artifacts.shared_proto_db import read_shared_proto_db, shared_proto_db_dir
from .detectors.auth import correlate_login_evidence, detect_account_name_change, detect_account_session_login, detect_account_session_switch, detect_account_switch, detect_login, detect_logout, detect_profile_access
from .detectors.conversation import detect_conversation_access, detect_conversation_create, detect_conversation_delete, detect_conversation_removed_from_list, detect_conversation_retry
from .detectors.file_activity import detect_file_download, detect_file_upload, detect_file_upload_delete
from .detectors.misc import detect_cache_delete, detect_data_export_request, detect_history_delete, detect_image_generation_request, detect_incognito, detect_model_change, detect_share_link, detect_temporary_chat
from .detectors.prompt import detect_prompt_draft, detect_prompt_send
from .discovery import CHROME_PROFILE_NOT_FOUND, discover_chrome_profiles
from .models import InputInfo, ParseResult
from .recovery.conversations import extract_cache_conversations, extract_conversation_residue
from .source import DirectorySource, normalize_source_path
from .utils import UTC, format_utc


# ---- extract() / detect() / run() ----------------------------------------------------------------
# 팀 Controller 가 함수로 호출할 수 있는 진입점.
#   extract(): Source → ArtifactRecord[] + Coverage[]
#              history_path 지정 = Explicit Mode (History 1개 + 같은 폴더의 Local Storage/leveldb, 자동 탐색 안 함)
#              history_path None = Auto Discovery Mode (Chrome Profile 탐색 → Profile 별 History + Local Storage/leveldb)
#   detect():  ArtifactRecord[] → Event[]            (History Rule — EVENT_RULES)
#   run():     extract + detect + extract_conversation_residue + extract_cache_conversations → ParseResult

RUN_WARNING_ANALYSIS_SCOPE = "ANALYSIS_SCOPE_HISTORY_LOCAL_STORAGE_LOG_SESSION_STORAGE_LOG_CACHE"
RUN_WARNING_MESSAGE_RECOVERY_SCOPE = "CONVERSATION_MESSAGE_RECOVERY_CACHE_CONVERSATION_RESPONSES_ONLY"
_SORT_TIME_MISSING = datetime.min.replace(tzinfo=UTC)


def sort_by_timestamp(items: list[Any]) -> list[Any]:
    """
    timestamp_utc 오름차순. 문자열이 아니라 실제 시각으로 비교한다
    ('...:02.5Z' 는 문자열로는 '...:02Z' 보다 앞에 오기 때문). 시각이 없는 항목은 뒤로, 같은 시각은 입력 순서 유지.
    """
    def key(item: Any) -> tuple[int, datetime]:
        value = getattr(item, "timestamp_utc", None)
        if value:
            try:
                return 0, datetime.fromisoformat(value)
            except ValueError:
                pass
        return 1, _SORT_TIME_MISSING

    return sorted(items, key=key)


def extract(
    source: Source, history_path: str | None = None, *, os_user: str | None = None,
    browser_profile: str | None = None, warnings: list[str] | None = None,
) -> tuple[list[ArtifactRecord], list[Coverage]]:
    """
    Source 에서 ChatGPT 관련 Artifact 를 읽어 (ArtifactRecord 목록, Coverage 목록) 을 반환한다. 판정하지 않는다.
      - history_path 지정: 그 History 1개만 읽는다 (os_user / browser_profile 은 호출자가 준 값).
      - history_path None: Chrome Profile 을 자동 탐색해 Profile 마다 History 를 읽는다 (Profile 값은 탐색 결과).
    warnings 목록을 넘기면 탐색 warning (CHROME_PROFILE_NOT_FOUND 등) 이 추가된다.
    """
    notes: list[str] = [] if warnings is None else warnings
    if history_path is not None:
        targets = [(history_path, normalize_source_path(history_path).rpartition("/")[0], os_user, browser_profile)]
    else:
        profiles = discover_chrome_profiles(source, notes)
        if not profiles:
            notes.append(CHROME_PROFILE_NOT_FOUND)
        # discover_chrome_profiles 가 같은 실제 Profile 을 한 번만 반환한다
        targets = [(pr.history_path, pr.profile_path, pr.os_user, pr.browser_profile) for pr in profiles]

    records: list[ArtifactRecord] = []
    coverages: list[Coverage] = []
    for history, profile_path, user, profile in targets:  # Profile 마다 따로 읽어 서로 섞지 않는다
        history_records, history_coverage = read_chatgpt_history(source, history, os_user=user, browser_profile=profile)
        storage_records, storage_coverages = read_local_storage(
            source, local_storage_dir(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        session_records, session_coverages = read_session_storage(
            source, session_storage_dir(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        cache_records, cache_coverage = read_chrome_cache(
            source, cache_data_dir(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        preference_records, preferences_coverage = read_preferences(
            source, preferences_path(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        download_records, download_coverages = read_shared_proto_db(
            source, shared_proto_db_dir(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        navigation_records, snss_coverages = read_chrome_sessions(
            source, sessions_dir(source, profile_path, notes), os_user=user, browser_profile=profile,
        )
        records += (history_records + storage_records + session_records + cache_records + preference_records
                    + download_records + navigation_records)
        coverages += ([history_coverage] + storage_coverages + session_coverages + [cache_coverage]
                      + [preferences_coverage] + download_coverages + snss_coverages)
    return records, coverages


EVENT_RULES = (
    detect_logout,               # CHATGPT_LOGOUT_001
    detect_login,                # CHATGPT_LOGIN_001
    detect_account_switch,       # CHATGPT_ACCOUNT_SWITCH_001 (CANDIDATE)
    detect_account_session_login,   # CHATGPT_ACCOUNT_SESSION_001 LOGIN (Local Storage lastLoggedInAt)
    detect_account_session_switch,  # CHATGPT_ACCOUNT_SESSION_001 ACCOUNT_SWITCH (계정 식별자 2개 이상)
    detect_conversation_create,  # CHATGPT_CONVERSATION_CREATE_001
    detect_conversation_access,  # CHATGPT_CONVERSATION_ACCESS_001 (CREATE 에 연결된 방문 제외)
    detect_profile_access,       # CHATGPT_PROFILE_ACCESS_001
    detect_data_export_request,  # CHATGPT_DATA_EXPORT_REQUEST_001 (Session Storage, 요청 단계만)
    detect_prompt_draft,         # CHATGPT_PROMPT_DRAFT_001 (Local Storage 초안 저장, 전송 판정 없음)
    detect_conversation_removed_from_list,  # CHATGPT_CONVERSATION_REMOVED_FROM_LIST_001 (CANDIDATE, 삭제 판정 아님)
    detect_file_download,        # CHATGPT_FILE_DOWNLOAD_001 (History downloads, download_id 1개 = Event 1건)
    detect_temporary_chat,  # CHATGPT_TEMPORARY_CHAT_001 (Sessions SNSS, 임시 채팅 화면 상태만)
    detect_image_generation_request,  # CHATGPT_IMAGE_GENERATION_REQUEST_001 (Session Storage, 요청 단계만)
    detect_conversation_retry,  # CHATGPT_CONVERSATION_RETRY_001 (Cache 대화 응답 variant, UI 조작 판정 아님)
    detect_file_upload,  # CHATGPT_FILE_UPLOAD_001 (Cache 대화 응답 user 메시지의 source=local 첨부)
    # 아래 9개는 행위 특이적 직접 증거가 없는 heuristic Rule 이다. 근거가 없으면 Event 를 만들지 않는다.
    detect_prompt_send,           # CHATGPT_PROMPT_SEND_001 (대화에 남은 user 메시지 / 초안이 비워진 전이)
    detect_file_upload_delete,    # CHATGPT_FILE_UPLOAD_DELETE_001 (Cache 사본 간 로컬 첨부 소멸)
    detect_share_link,            # CHATGPT_SHARE_LINK_001 (chatgpt.com/share/ · backend-api share URL)
    detect_model_change,          # CHATGPT_MODEL_CHANGE_001 (같은 대화의 model_slug 전이)
    detect_account_name_change,   # CHATGPT_ACCOUNT_NAME_CHANGE_001 (계정 이름 해시 전이)
    detect_history_delete,        # CHATGPT_HISTORY_DELETE_001 (방문 기록 결손 신호 2개 이상)
    detect_conversation_delete,   # CHATGPT_CONVERSATION_DELETE_001 (목록 이탈 + 복귀 없음 + Cache 응답 없음)
    # CHATGPT_CACHE_DELETE_001: Preferences browser.clear_data.cache is True + ChatGPT 맥락(S2 목록 또는 S3 방문).
    # 대화 응답 entry 0건은 양성 신호가 아니다 - 판정·evidence·confidence 에 쓰지 않는다.
    detect_cache_delete,
    detect_incognito,             # CHATGPT_INCOGNITO_001 (시크릿 창 표식이 있을 때만)
)


def detect(records: list[ArtifactRecord], coverages: list[Coverage] | tuple[Coverage, ...] = ()) -> list[Event]:
    """
    ArtifactRecord 에 ChatGPT Event Rule 을 적용한다. 파일을 읽지 않고 입력 Record 를 수정하지 않는다.
    Rule 사이에 상태를 공유하지 않는다 (ACCESS 는 CREATE 연결을 스스로 다시 계산해 제외한다).
    Rule 을 모두 적용한 뒤 Evidence 결합 단계가 한 번 돈다 — 같은 행위 1회를 두 Rule 이 각각 Event 로
    만든 경우를 합치기만 하고, 새 판정·새 시각·새 Evidence 는 만들지 않는다 (correlate_login_evidence).
    """
    events: list[Event] = []
    for rule in EVENT_RULES:
        events.extend(rule(records, coverages))
    return correlate_login_evidence(events, records)


def run(
    source: Source, history_path: str | None = None, *, os_user: str | None = None, browser_profile: str | None = None,
) -> ParseResult:
    """extract → detect → ParseResult. run_started_utc 는 Parser 실행 시각이며 사용자 행위 시각이 아니다."""
    run_started_utc = format_utc(datetime.now(UTC))
    discovery_warnings: list[str] = []
    records, coverages = extract(source, history_path, os_user=os_user, browser_profile=browser_profile,
                                 warnings=discovery_warnings)
    events = detect(records, coverages)
    return ParseResult(
        run_id=str(uuid.uuid4()),
        run_started_utc=run_started_utc,
        input=InputInfo(kind=source.kind, path=str(getattr(source, "root", "")),
                        partition=getattr(source, "partition", None), filesystem=getattr(source, "filesystem_name", None)),
        coverage=coverages,
        records=sort_by_timestamp(records),
        events=sort_by_timestamp(sorted(events, key=lambda event: event.event_id)),  # 같은 시각은 event_id 순 (반복 실행 시 순서 고정)
        conversations=(extract_conversation_residue(records, coverages)      # Local Storage 잔존 (RESIDUAL_ONLY)
                       + extract_cache_conversations(records, coverages)),   # Cache 대화 응답 메시지 (RECOVERED / PARTIAL)
        warnings=[RUN_WARNING_ANALYSIS_SCOPE, RUN_WARNING_MESSAGE_RECOVERY_SCOPE]
                 + list(getattr(source, "warnings", [])) + discovery_warnings,  # ImageSource: 파티션 선택 근거
    )


# ---- 팀 통합용 진입점 (analyze_chatgpt_web / write_final_outputs) ---------------------------------------
# 팀 통합 담당자는 Cache carving 이나 Rule 구현을 몰라도 이 두 함수만으로 분석과 출력을 할 수 있다.
# 새로운 판정을 만들지 않는다. 기존 run() / write_result_csv() 를 그대로 호출한다.

INPUT_TYPES = ("dir", "image")


def analyze_chatgpt_web(
    input_path: str | os.PathLike[str], *, input_type: str = "dir", history_path: str | None = None,
    os_user: str | None = None, browser_profile: str | None = None, key_material: str | None = None,
) -> ParseResult:
    """
    입력 1개를 분석해 ParseResult 를 돌려준다. **파일을 쓰지 않는다** (출력은 write_final_outputs 가 한다).
      input_type="dir"    input_path = 분석용 폴더 (원본은 읽기만 한다)
      input_type="image"  input_path = DD/RAW 또는 E01 이미지 (pytsk3 / pyewf 필요)
    history_path 를 주면 자동 탐색 대신 그 History 1개만 읽는다 (Source 기준 상대 경로).
    key_material 은 BitLocker 이미지용 키다 (recovery:/passphrase:/bek:/fvek:, 폴더 입력에는 쓰지 않는다).
    """
    if input_type not in INPUT_TYPES:
        raise ValueError(f"input_type must be one of {INPUT_TYPES}, got {input_type!r}")
    if input_type == "dir":
        return run(DirectorySource(input_path), history_path, os_user=os_user, browser_profile=browser_profile)
    image_source = open_image_source(input_path, key_material)
    try:
        return run(image_source, history_path, os_user=os_user, browser_profile=browser_profile)
    finally:
        image_source.close()


def write_final_outputs(
    result: ParseResult, output_dir: str | os.PathLike[str], *, overwrite: bool = False, debug: bool = False,
) -> list[Path]:
    """
    최종 사용자용 CSV 2종(timeline.csv / recovered_conversations.csv)을 output_dir 에 쓴다.
    debug=True 이면 개발·검증용 CSV 5종도 함께 쓴다. 결과 내용은 ParseResult 그대로이며 새로 만들지 않는다.
    """
    return write_result_csv(result, output_dir, overwrite=overwrite, debug=debug)
