"""공통 상수 (service 이름 · warning 코드 · CSV schema 등)."""
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


PARSER_NAME = "chatgpt_web_parser"
PARSER_VERSION = "0.1.0"
SERVICE = "chatgpt_web"
DEFAULT_BROWSER = "chrome"
DISPLAY_TIMEZONE = "+09:00 (KST)"

# 허용 값 목록 (docs/OUTPUT_SCHEMA.md 기준)
INPUT_KINDS = ("e01", "dd", "directory")

COVERAGE_STATUSES = ("NOT_PRESENT", "EMPTY", "PARSED", "PARTIAL", "PARSE_ERROR", "NOT_SUPPORTED")

ARTIFACT_TYPES = (
    "history", "favicons", "cookies", "local_storage", "session_storage", "indexeddb",
    "cache", "sessions", "preferences", "local_state", "shared_proto_db", "ntfs",
)

TIMESTAMP_TYPES = ("webkit_us", "webkit_ms", "unix_s", "unix_s_decimal", "unix_ms", "iso_utc", "filesystem", "unknown")

EVIDENCE_LEVELS = ("DIRECT", "SUPPORTING", "INFERRED")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
RULE_VERIFICATIONS = ("VERIFIED", "PARTIALLY_VERIFIED", "NOT_VERIFIED")
DEVICE_ATTRIBUTIONS = ("LOCAL", "REMOTE_SYNCED", "SERVER_SIDE_CACHE", "UNKNOWN")
FINDING_TYPES = ("USER_ACTION", "RECOVERED_DATA")

# Observed-only 정보는 Event가 아니라 ArtifactRecord에 저장하므로 Event 상태는 두 값뿐이다.
ACTION_STATUSES = ("DETECTED", "CANDIDATE")

# 복구된 대화(conversations[]) 상태. 대화 전체가 완전한지 검증하기 어려우므로 COMPLETE 는 쓰지 않는다.
#   RECOVERED     구조화된 대화·메시지 내용이 실제로 복구됨
#   PARTIAL       일부 메시지 또는 일부 내용만 복구됨
#   RESIDUAL_ONLY ID·제목 등 잔존 흔적만 있고 메시지 본문은 복구되지 않음 (메시지 없음)
# 복구하지 못한 경우는 conversations[] 항목을 만들지 않고 Coverage / warning 으로 남긴다.
RECOVERY_STATUSES = ("RECOVERED", "PARTIAL", "RESIDUAL_ONLY")
MESSAGE_RECOVERY_STATUSES = ("RECOVERED", "PARTIAL")
