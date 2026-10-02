"""Chrome Preferences Reader (browser.clear_data 선택 상태만)."""
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
from ..artifacts.local_storage import _profile_subdir
from ..models import ArtifactRecord, Coverage
from ..source import FILE_STATUS_NOT_PRESENT, Source, SourcePathError, normalize_source_path


# ---- 7.7 Chrome Preferences Reader (browser.clear_data) ----------------------
# 2026-09-30 E10-04 원자료 (PRE / POST 의 Chrome\User Data\Default\Preferences) 에서 확인한 것:
#   PRE  (캐시 삭제 전)  browser = {theme, window_placement} — clear_data 키 자체가 없다
#   POST (캐시 삭제 후)  browser.clear_data = {"browsing_history": false, "cache": true,
#                                             "cookies": false, "download_history": false}
#   두 파일 모두 last_clear_browsing_data_time 같은 시각 필드는 없었다 → Reader 는 시각을 만들지 않는다.
#   (파일 수정 시각은 Preferences 가 다른 이유로도 계속 쓰이므로 행위 시각으로 쓰지 않는다.)
# browser.clear_data 는 Chrome '인터넷 사용 기록 삭제' 대화상자의 체크박스가 마지막으로 어떤 상태였는지를
#   저장한 값이다. 삭제 실행 여부·시각·범위는 이 값만으로는 알 수 없다 (판정은 §8.25 Rule 이 CANDIDATE 로만 한다).
# 보안: 이 한 섹션의 bool 값만 Record 로 만든다. Preferences 의 나머지 최상위 키 (계정·동기화·자동완성 등
#   개인정보) 는 읽지 않는다.
# Coverage: 파일 없음 NOT_PRESENT / 읽고 JSON 파싱됨 PARSED / 읽기·파싱 실패 PARSE_ERROR.
#   clear_data 키가 없는 것은 오류가 아니라 '선택 상태가 저장된 적 없음' 이므로 PARSED + warning (Record 0건).

PREFERENCES_FILE_PARTS = ("Preferences",)
PREFERENCES_CLEAR_DATA_KEY = "browser.clear_data"
PREFERENCES_CLEAR_DATA_KIND = "clear_browsing_data_selection"
PREFERENCES_PATH_OUTSIDE_SOURCE = "PREFERENCES_PATH_OUTSIDE_SOURCE"
PREFERENCES_READ_ERROR = "PREFERENCES_READ_ERROR"
PREFERENCES_NOT_JSON = "PREFERENCES_NOT_JSON"
PREFERENCES_CLEAR_DATA_NOT_PRESENT = "PREFERENCES_CLEAR_DATA_NOT_PRESENT"


def read_preferences(
    source: Source, path: str, *, os_user: str | None = None, browser_profile: str | None = None,
) -> tuple[list[ArtifactRecord], Coverage]:
    """Preferences 1개 → (browser.clear_data Record 0~1건, Coverage). 시각을 만들지 않고 판정하지 않는다."""
    source_path = normalize_source_path(path)
    warnings: list[str] = []

    def finish(status: str, records: list[ArtifactRecord] | None = None, sha: str | None = None):
        records = records or []
        return records, Coverage(
            artifact_type="preferences", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
            status=status, record_count=len(records), source_sha256=sha, warnings=warnings,
        )

    try:
        if source.file_status(source_path) == FILE_STATUS_NOT_PRESENT:
            return finish("NOT_PRESENT")
        data = source.read_bytes(source_path)          # 폴더인 경우 IsADirectoryError (OSError) 로 걸린다
    except SourcePathError:
        warnings.append(PREFERENCES_PATH_OUTSIDE_SOURCE)
        return finish("PARSE_ERROR")
    except OSError:
        warnings.append(PREFERENCES_READ_ERROR)
        return finish("PARSE_ERROR")

    sha = hashlib.sha256(data).hexdigest()
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        warnings.append(PREFERENCES_NOT_JSON)
        return finish("PARSE_ERROR", sha=sha)

    browser = parsed.get("browser") if isinstance(parsed, dict) else None
    section = browser.get("clear_data") if isinstance(browser, dict) else None
    if not isinstance(section, dict):
        warnings.append(PREFERENCES_CLEAR_DATA_NOT_PRESENT)
        return finish("PARSED", sha=sha)  # 파일은 읽혔다. 키 부재는 '삭제를 안 했다' 는 뜻이 아니다
    record = ArtifactRecord(
        record_id=f"preferences:{source_path}#{PREFERENCES_CLEAR_DATA_KEY}",
        artifact_type="preferences", os_user=os_user, browser_profile=browser_profile, source_path=source_path,
        record_location=PREFERENCES_CLEAR_DATA_KEY,
        observed={"key": PREFERENCES_CLEAR_DATA_KEY, "key_kind": PREFERENCES_CLEAR_DATA_KIND,
                  # 체크박스 상태만 (bool 아닌 값은 남기지 않는다). 시각 필드는 이 섹션에 없다
                  "clear_data": {name: value for name, value in sorted(section.items())
                                 if isinstance(value, bool)}},
    )
    return finish("PARSED", [record], sha)


def preferences_path(source: Source, profile_path: str, warnings: list[str] | None = None) -> str:
    """Profile 폴더 아래 'Preferences' 경로."""
    return _profile_subdir(source, profile_path, PREFERENCES_FILE_PARTS, warnings)
