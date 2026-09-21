"""개발·검증용 출력 (result.json · CSV 5종)."""
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


def write_result_json(result: ParseResult, path: str | os.PathLike[str], *, overwrite: bool = False) -> Path:
    """UTF-8 JSON 저장 (ensure_ascii=False). overwrite=False 이면 기존 파일을 덮어쓰지 않는다 (FileExistsError)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w" if overwrite else "x", encoding="utf-8", newline="\n") as handle:
        handle.write(result.to_json())
        handle.write("\n")
    return out

CSV_COVERAGE_COLUMNS = (
    "artifact_type", "os_user", "browser", "browser_profile", "source_path",
    "status", "record_count", "source_sha256", "warnings",
)
CSV_RECORD_COLUMNS = (
    "record_id", "service", "artifact_type", "os_user", "browser", "browser_profile",
    "source_path", "record_location",
    "timestamp_raw", "timestamp_utc", "timestamp_kst", "timestamp_type", "timestamp_source",
    "observed", "warnings",
)
CSV_EVENT_COLUMNS = (
    "service", "event_id", "finding_type", "action", "action_status",
    "timestamp_raw", "timestamp_utc", "timestamp_kst", "timestamp_type", "timestamp_source",
    "confidence", "rule_id", "rule_verification",
    "os_user", "browser", "browser_profile", "device_attribution",
    "representative_evidence_id", "primary_evidence_count", "supporting_evidence_count",
    "confidence_reason", "inference", "limitations", "warnings",
)
CSV_CONVERSATION_COLUMNS = (
    "conversation_id", "title", "recovery_status",
    "create_time_raw", "create_time_utc", "create_time_kst", "create_time_type", "create_time_source",
    "message_count", "source_artifact_count", "correlated_record_count",
    "source_artifacts", "correlated_record_ids", "warnings",
)
CSV_MESSAGE_COLUMNS = (
    "conversation_id", "conversation_title", "message_id", "parent_message_id", "sequence_index",
    "role", "content_type", "content",
    "timestamp_raw", "timestamp_utc", "timestamp_kst", "timestamp_type", "timestamp_source",
    "recovery_status", "source_artifact", "source_path", "record_location", "source_sha256", "warnings",
)
