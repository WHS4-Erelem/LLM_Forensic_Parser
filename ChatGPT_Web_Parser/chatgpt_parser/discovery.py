"""Windows 사용자 · Chrome Profile 탐색."""
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
from .constants import DEFAULT_BROWSER
from .models import _Model, _require_str
from .source import SourcePathError


# ---- Windows / Chrome Discovery ------------------------------------------------------------------
# Source 구조만 탐색한다. 파일 내용(History 포함)을 읽지 않고, Event 를 만들지 않는다.
#   - 대상: Google Chrome Stable 만 — Users/<user>/AppData/Local/Google/Chrome/User Data/<profile>
#     (Chrome Beta·Dev·Canary, Chromium, Edge, Brave, Firefox 는 탐색하지 않는다)
#   - 사용자 이름을 하드코딩하지 않는다. 사용자 폴더 이름(Public, Default 등)으로 제외하지 않고,
#     User Data 경로가 실제로 있는지만 기준으로 삼는다.
#   - Profile = User Data 바로 아래의 'Default' 또는 'Profile <숫자>' 폴더. System Profile / Guest Profile 등은 제외.
#     History 파일이 없어도 Profile 로 인정한다 (History Coverage NOT_PRESENT 로 표현).
#   - Windows/NTFS 에 맞춰 이름은 대소문자 구분 없이 비교하되, 결과 경로에는 실제 폴더 이름을 쓴다.
#   - 링크·junction 이 Source 밖을 가리키면 따라가지 않고 warning 을 남긴다 (S3 경로 안전성 유지).
#   - 같은 실제 폴더(대소문자 중복, root 안 junction 별칭)는 한 번만 반환한다 (Source.path_key).
#   - Local State 는 사용하지 않는다 (없거나 손상돼도 영향 없음).

CHROME_USER_DATA_PARTS = ("AppData", "Local", "Google", "Chrome", "User Data")
CHROME_PROFILE_NOT_FOUND = "CHROME_PROFILE_NOT_FOUND"
DISCOVERY_PATH_OUTSIDE_SOURCE = "DISCOVERY_PATH_OUTSIDE_SOURCE"
DISCOVERY_READ_ERROR = "DISCOVERY_READ_ERROR"
HISTORY_PATH_OUTSIDE_SOURCE = "HISTORY_PATH_OUTSIDE_SOURCE"
_PROFILE_NUMBER_NAME = re.compile(r"profile ([0-9]+)")


@dataclass(kw_only=True)
class ChromeProfile(_Model):
    """발견된 Chrome Profile. 탐색 결과일 뿐 결과 JSON 에 직접 들어가지 않는다 (Coverage·Record 의 os_user / browser_profile 로 반영)."""

    os_user: str
    browser: str = DEFAULT_BROWSER
    browser_profile: str
    profile_path: str
    history_path: str

    def __post_init__(self) -> None:
        for name in ("os_user", "browser", "browser_profile", "profile_path", "history_path"):
            _require_str(name, getattr(self, name))


def is_chrome_profile_name(name: str) -> bool:
    """'Default' 또는 'Profile <숫자>' (대소문자 무시). System Profile / Guest Profile / 'Profile' 은 False."""
    folded = name.casefold()
    return folded == "default" or _PROFILE_NUMBER_NAME.fullmatch(folded) is not None


def _profile_sort_key(name: str) -> tuple[int, int, str]:
    """Default → Profile 1 → Profile 2 → Profile 10 (숫자 크기 순)."""
    folded = name.casefold()
    if folded == "default":
        return 0, 0, name
    match = _PROFILE_NUMBER_NAME.fullmatch(folded)
    if match:
        return 1, int(match.group(1)), name
    return 2, 0, name


def _join_source_path(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _list_dir_safe(source: Source, path: str, warnings: list[str]) -> list[str]:
    try:
        return source.list_dir(path)
    except (FileNotFoundError, NotADirectoryError):
        return []
    except SourcePathError:
        warnings.append(f"{DISCOVERY_PATH_OUTSIDE_SOURCE}:{path}")
    except OSError:
        warnings.append(f"{DISCOVERY_READ_ERROR}:{path}")
    return []


def _is_dir_safe(source: Source, path: str, warnings: list[str]) -> bool:
    try:
        return source.is_dir(path)
    except SourcePathError:
        warnings.append(f"{DISCOVERY_PATH_OUTSIDE_SOURCE}:{path}")
    except OSError:
        warnings.append(f"{DISCOVERY_READ_ERROR}:{path}")
    return False


def _child_paths_ci(source: Source, parent: str, name: str, warnings: list[str]) -> list[str]:
    """parent 아래에서 이름이 name 과 대소문자 무시로 같은 항목들의 경로."""
    target = name.casefold()
    return [_join_source_path(parent, child) for child in _list_dir_safe(source, parent, warnings)
            if child.casefold() == target]


def discover_chrome_profiles(source: Source, warnings: list[str] | None = None) -> list[ChromeProfile]:
    """
    Source 안의 Windows 사용자별 Chrome Stable Profile 목록 (os_user → Profile 자연 순서 정렬).
    warnings 목록을 넘기면 탐색 중 건너뛴 경로의 warning 이 추가된다. 예외를 밖으로 던지지 않는다.
    """
    notes: list[str] = [] if warnings is None else warnings
    profiles: list[ChromeProfile] = []
    seen: set[str] = set()
    for users_dir in _child_paths_ci(source, "", "Users", notes):
        if not _is_dir_safe(source, users_dir, notes):
            continue
        for user in sorted(_list_dir_safe(source, users_dir, notes), key=lambda name: (name.casefold(), name)):
            user_dir = _join_source_path(users_dir, user)
            if not _is_dir_safe(source, user_dir, notes):
                continue
            candidates = [user_dir]
            for part in CHROME_USER_DATA_PARTS:
                candidates = [child for parent in candidates for child in _child_paths_ci(source, parent, part, notes)
                              if _is_dir_safe(source, child, notes)]
            for user_data in candidates:
                for name in sorted(_list_dir_safe(source, user_data, notes), key=_profile_sort_key):
                    profile_path = _join_source_path(user_data, name)
                    if not is_chrome_profile_name(name) or not _is_dir_safe(source, profile_path, notes):
                        continue
                    key = source.path_key(profile_path)
                    if key in seen:
                        continue
                    seen.add(key)
                    history = _child_paths_ci(source, profile_path, "History", notes)
                    profiles.append(ChromeProfile(
                        os_user=user, browser_profile=name, profile_path=profile_path,
                        history_path=history[0] if history else _join_source_path(profile_path, "History"),
                    ))
    return sorted(profiles, key=lambda pr: (pr.os_user.casefold(), pr.os_user, _profile_sort_key(pr.browser_profile)))
