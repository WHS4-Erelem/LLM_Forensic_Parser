#!/usr/bin/env python3
"""Read-only LM Studio forensic artifact parser for Windows evidence.

The parser deliberately separates observations from rule decisions.  It never
uses a directory name as a ground-truth label and never treats absence alone as
proof of a user action.
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import getpass
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from contextlib import contextmanager
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Mapping, Sequence, TextIO
from unittest.mock import Mock, patch
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# 1. Constants
# ---------------------------------------------------------------------------

SERVICE_NAME = "lmstudio"
REFERENCE_LM_STUDIO_VERSION = "0.4.21 Build 2"
TIMELINE_HEADER = [
    "Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
    "Artifact_path", "Artifact_details ",  # 팀 공유본 헤더: 끝 공백 1개씩 포함
]
CONVERSATION_HEADER = [
    "Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
    "parent_message_uuid", "message order", "role", "content", "Artifact_path",
]
DECISION_KO = {"confirmed": "확정", "suspected": "의심", "indeterminate": "미확정"}  # 팀 판정값: 확정/의심
KST = timezone(timedelta(hours=9), name="KST")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_EXPORT_BYTES = 16 * 1024 * 1024
MAX_RESIDENT_BYTES = 16 * 1024 * 1024
SPREADSHEET_PREFIXES = ("=", "+", "-", "@")
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(credential|access[_-]?token|refresh[_-]?token|auth(?:entication)?[_-]?token|"
    r"private[_-]?key|passkey|secret|password|api[_-]?key|bearer)"
)
PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE|PUBLIC) KEY-----")
BASE64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/]{256,}={0,2}$")
LM_EXPORT_SIGNATURES = (
    re.compile(r"(?im)^#{1,3}\s+.*LM Studio"),
    re.compile(r"(?im)^\*\*(?:User|Assistant|Model|Created|LM Studio)\*\*"),
    re.compile(r"(?im)^##\s+(?:User|Assistant)\b"),
    re.compile(r"(?im)^LM Studio(?:\s+version)?\s*[:\-]"),
)
RELEVANT_NAME_RE = re.compile(
    r"(?i)(\.conversation\.json$|conversation-config\.json$|local-identity\.json$|"
    r"user-profile\.json$|lmstudio-hub\.json$|lm-link-account-status-cache\.json$|"
    r"lm-link-config\.json$|model-data\.json$|download-jobs-info\.json$|"
    r"single-downloads-info\.json$|\.metadata\.json$|server-logs-state\.json$|"
    r"http-server\.json$|llmster-pid\.lock$|global\.json$|window-\d+\.json$|"
    r"lm studio(?:\.exe|\.lnk)?$|unins\d*\.exe$|\.gguf(?:\.part)?$|\.md$)"
)


# ---------------------------------------------------------------------------
# 2. Dataclasses and rule contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Provenance:
    source_image: str = ""
    original_artifact_path: str = ""
    materialized_path: str = ""
    evidence_location: str = ""
    # Populate when a collector knows that a materialization is a copy of a source.
    lineage_key: str = ""


@dataclass(frozen=True)
class TimestampValue:
    raw: str = ""
    normalized: str = ""
    semantics: str = ""
    verified_unit: bool = False


@dataclass
class ArtifactRecord:
    artifact_id: str
    path: str
    provenance: Provenance
    kind: str
    size: int | None = None
    created: TimestampValue | None = None
    modified: TimestampValue | None = None
    content: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ObservedFact:
    fact_type: str
    family: str
    provenance: Provenance
    value: str = ""
    key: str = ""
    timestamp: TimestampValue | None = None
    direct_tag: str = ""
    target_path: str = ""
    conversation_ref: str = ""
    message_ref: str = ""


@dataclass
class CandidateEvent:
    event_type: str
    action: str
    rule_id: str
    korean_action: str
    matched_conditions: list[str]
    facts: list[ObservedFact]
    evidence_families: set[str]
    direct_evidence: bool
    decision_status: str
    decision_reason: str
    limitation: str = ""
    timestamp: TimestampValue | None = None
    conversation_ref: str = ""
    conflict: bool = False


@dataclass(frozen=True)
class AnalysisIssue:
    code: str
    artifact_path: str
    limitation: str
    fatal: bool = False


@dataclass(frozen=True)
class RecoveredMessage:
    conversation_id: str
    title: str
    message_id: str
    parent_message_id: str
    order: int
    role: str
    content: str
    timestamp: TimestampValue | None
    recovery_status: str
    artifact_path: str
    location: str
    title_source: str = ""
    message_id_source: str = ""
    parent_id_source: str = ""
    timestamp_source: str = ""


@dataclass(frozen=True)
class RuleDefinition:
    evidence_id: str
    event_type: str
    action: str
    korean: str
    rule_id: str
    positive_conditions: tuple[str, ...]
    direct_evidence: tuple[str, ...]
    corroborating_evidence: tuple[str, ...]
    false_positive_guards: tuple[str, ...]
    default_decision: str
    decision_reason_format: str


def _rule(
    evidence_id: str,
    event_type: str,
    action: str,
    korean: str,
    rule_id: str,
    positive: Sequence[str],
    direct: Sequence[str],
    corroborating: Sequence[str],
    guards: Sequence[str],
    default: str,
    detail: str,
) -> RuleDefinition:
    return RuleDefinition(
        evidence_id,
        event_type,
        action,
        korean,
        rule_id,
        tuple(positive),
        tuple(direct),
        tuple(corroborating),
        tuple(guards),
        default,
        detail,
    )


RULES: dict[str, RuleDefinition] = {
    "login": _rule("E01-01", "possible_login", "login", "로그인", "lmstudio.account.login_candidate",
        ["복수 account state가 일관된 logged-in 상태"], ["explicit_login_log"],
        ["account_state", "lmstudio_log", "filesystem"], ["단일 account 파일 금지", "credential 원문 금지"],
        "suspected", "로그인 상태 전환_{subject}"),
    "logout": _rule("E01-02", "possible_logout", "logout", "로그아웃", "lmstudio.account.logout_candidate",
        ["복수 account artifact의 coordinated reset"], ["explicit_logout_log"],
        ["account_state", "lmstudio_log", "filesystem"], ["단일 null 금지", "초기 비로그인과 구분"],
        "indeterminate", "계정 인증 상태 초기화_{subject}"),
    "account_switch": _rule("E01-03", "possible_account_switch", "account_switch", "계정 전환", "lmstudio.account.account_switch_candidate",
        ["before/after 안전 account identifier 변화", "재인증과 profile context 변화"], ["explicit_account_switch_log"],
        ["account_state", "lmstudio_log", "filesystem"], ["현재 profile 하나 금지"],
        "suspected", "계정 전환_{subject}"),
    "application_install": _rule("E02-01", "possible_application_install", "application_install", "애플리케이션 설치", "lmstudio.application.install_candidate",
        ["LM Studio program install structure", "shortcut/installer/filesystem 생성"], ["explicit_installer_record"],
        ["windows_os", "filesystem"], [".lmstudio 존재만으로 생성 금지"],
        "suspected", "LM Studio 설치_{subject}"),
    "application_uninstall": _rule("E02-02", "possible_application_uninstall", "application_uninstall", "애플리케이션 삭제", "lmstudio.application.uninstall_candidate",
        ["program component 실제 삭제", "uninstaller/shortcut/NTFS 삭제"], ["explicit_uninstaller_execution"],
        ["windows_os", "filesystem"], ["program directory 현재 부재만으로 생성 금지"],
        "suspected", "LM Studio 제거_{subject}"),
    "conversation_create": _rule("E03-01", "possible_conversation_create", "conversation_create", "새로운 대화 생성", "lmstudio.conversation.create_candidate",
        ["initial conversation 구조", "conversation-config selection", "filesystem create"], [],
        ["conversation_state", "filesystem"], ["empty conversation 하나 금지", "model-load 생성과 구분"],
        "suspected", "대화 생성_{subject}"),
    "conversation_delete": _rule("E03-02", "possible_conversation_delete", "conversation_delete", "기존 대화 삭제", "lmstudio.conversation.delete_candidate",
        ["conversation actual delete/rename/recycle history"], [],
        ["conversation_state", "filesystem"], ["현재 파일 부재 금지"],
        "suspected", "대화 삭제_{subject}"),
    "message_edit": _rule("E03-03", "possible_message_edit", "message_edit", "대화 수정", "lmstudio.conversation.message_edit_candidate",
        ["explicit edited marker", "동일 user message before/after 본문 변화", "검증된 user-version compatibility"], ["explicit_edited_marker"],
        ["conversation_state", "filesystem", "lmstudio_log"], ["현재 user text 하나 금지"],
        "suspected", "사용자 메시지 수정_{subject}"),
    "assistant_retry": _rule("E03-04", "possible_assistant_retry", "assistant_retry", "대화 재시도", "lmstudio.conversation.assistant_retry_candidate",
        ["assistant versions >= 2", "old/new response와 selected version"], [],
        ["conversation_state", "lmstudio_log", "filesystem"], ["version count 하나로 확정 금지"],
        "suspected", "Assistant 응답 재시도_{subject}"),
    "prompt_interaction": _rule("E04-01", "possible_prompt_interaction", "prompt_interaction", "사용자 프롬프트 입력/전송", "lmstudio.conversation.prompt_interaction_candidate",
        ["user message text", "assistant response/generation"], ["server_inference_log"],
        ["conversation_state", "lmstudio_log"], ["draft clientInput만으로 확정 금지"],
        "suspected", "사용자 메시지 전송_{subject}"),
    "prompt_delete": _rule("E04-02", "possible_prompt_delete", "prompt_delete", "사용자 프롬프트 삭제", "lmstudio.conversation.prompt_delete_candidate",
        ["before/after user message 제거", "conversation rewrite/history"], [],
        ["conversation_state", "filesystem"], ["assistant-only 현재 상태 하나 금지"],
        "suspected", "사용자 메시지 삭제_{subject}"),
    "image_upload": _rule("E05-01", "possible_image_upload", "image_upload", "이미지 업로드", "lmstudio.attachment.image_upload_candidate",
        ["LM Studio image metadata", "conversation attachment link"], [],
        ["attachment", "conversation_state", "filesystem"], ["filename 하나 금지", "preview base64 출력 금지"],
        "suspected", "이미지 첨부_{subject}"),
    "image_upload_delete": _rule("E05-02", "possible_image_upload_delete", "image_upload_delete", "이미지 업로드 삭제", "lmstudio.attachment.image_delete_candidate",
        ["image metadata actual deletion", "linked attachment removal"], [],
        ["attachment", "conversation_state", "filesystem"], ["metadata 현재 부재 금지"],
        "suspected", "이미지 첨부 제거_{subject}"),
    "document_upload": _rule("E05-03", "possible_document_upload", "document_upload", "문서 업로드", "lmstudio.attachment.document_upload_candidate",
        ["document metadata", "conversation fileIdentifier link"], [],
        ["attachment", "conversation_state", "filesystem"], ["preprocessed text 하나 금지"],
        "suspected", "문서 첨부_{subject}"),
    "document_upload_delete": _rule("E05-04", "possible_document_upload_delete", "document_upload_delete", "문서 업로드 삭제", "lmstudio.attachment.document_delete_candidate",
        ["document actual deletion", "conversation attachment/message removal"], [],
        ["attachment", "conversation_state", "filesystem"], ["현재 PDF 부재 금지"],
        "suspected", "문서 첨부 제거_{subject}"),
    "conversation_export": _rule("E07-01", "possible_conversation_export", "conversation_export", "대화 데이터 Export", "lmstudio.conversation.export_candidate",
        ["LM Studio markdown signature", "filesystem creation"], [],
        ["final_file", "filesystem"], ["일반 Markdown 금지"],
        "suspected", "대화 Export 완료_{subject}"),
    "application_launch": _rule("E08-01", "possible_application_launch", "application_launch", "애플리케이션 실행", "lmstudio.runtime.application_launch_candidate",
        ["runtime/server/UI 양성 흔적", "Prefetch/execution artifact"], ["lmstudio_prefetch_execution"],
        ["lmstudio_log", "windows_os", "filesystem"], ["lock 하나 금지"],
        "suspected", "LM Studio 실행 흔적_{subject}"),
    "application_normal_exit": _rule("E08-02", "possible_application_normal_exit", "application_normal_exit", "정상 종료", "lmstudio.runtime.normal_exit_candidate",
        ["positive UI/state flush", "independent runtime cleanup"], ["explicit_normal_exit_log"],
        ["lmstudio_log", "filesystem", "windows_os"], ["lock 부재 하나 금지"],
        "suspected", "LM Studio 정상 종료 흔적_{subject}"),
    "application_forced_exit": _rule("E08-03", "possible_application_forced_exit", "application_forced_exit", "강제 종료", "lmstudio.runtime.forced_exit_candidate",
        ["positive abnormal runtime/state residue", "forced termination OS evidence"], ["explicit_forced_termination"],
        ["filesystem", "windows_os", "lmstudio_log"], ["정상 종료 evidence 부재만으로 생성 금지"],
        "indeterminate", "LM Studio 강제 종료 의심_{subject}"),
    "model_change": _rule("E09-01", "possible_model_change", "model_change", "모델 변경", "lmstudio.model.change_candidate",
        ["model identifier와 verified load timestamp", "conversation/log model context"], ["explicit_model_load_log"],
        ["model_state", "conversation_state", "lmstudio_log"], ["identifier-only 금지", "timestamp-only 금지"],
        "suspected", "모델 변경_{subject}"),
    "model_download": _rule("E09-03", "possible_model_download", "model_download", "모델 다운로드 내역", "lmstudio.model.download_candidate",
        ["GGUF/model context와 download semantic fields", "completed/incomplete state"], [],
        ["model_state", "final_file", "filesystem"], ["URL 하나 금지", "part 하나로 완료 금지", "무관 JSON 금지"],
        "suspected", "모델 다운로드 {subject}"),
}


@dataclass
class AnalysisContext:
    input_path: Path
    source_image: str = ""
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    facts: list[ObservedFact] = field(default_factory=list)
    candidates: list[CandidateEvent] = field(default_factory=list)
    messages: list[RecoveredMessage] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)
    parsed_json: dict[str, Any] = field(default_factory=dict)
    usn_stats: list[dict[str, Any]] = field(default_factory=list)
    live: bool = False
    evidence_roots: list[Path] = field(default_factory=list)
    lmstudio_homes: list[str] = field(default_factory=list)

    def issue(self, code: str, path: str, limitation: str, fatal: bool = False) -> None:
        self.issues.append(AnalysisIssue(code, path, limitation, fatal))

    def add_artifact(self, artifact: ArtifactRecord) -> None:
        self.artifacts.append(artifact)

    def add_fact(self, fact: ObservedFact) -> None:
        self.facts.append(fact)


# ---------------------------------------------------------------------------
# 3. Safe scalar, JSON, timestamp, and provenance helpers
# ---------------------------------------------------------------------------

def stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()[:20]


def safe_fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def as_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def safe_nonconversation_text(value: str, *, max_length: int = 500) -> str:
    if not value:
        return ""
    value = value.replace("\x00", "")
    if PEM_RE.search(value):
        return "[민감정보 비노출]"
    if BASE64_BLOB_RE.fullmatch(value.strip()):
        return "[바이너리 데이터 비노출]"
    value = re.sub(r"(?i)\b(?:credential|access[_-]?token|refresh[_-]?token|private[_-]?key|passkey|secret|password|api[_-]?key)\s*[=:]\s*[^\s;]+", "[REDACTED]", value)
    value = re.sub(r"[A-Za-z0-9+/]{256,}={0,2}", "[바이너리 데이터 비노출]", value)
    value = re.sub(r"(?i)([?&](?:token|key|secret|signature|sig|auth)=[^&\s]+)", "", value)
    value = re.sub(
        r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        value,
    )
    if len(value) > max_length:
        value = value[:max_length]
    return value


def safe_url_summary(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    path = parsed.path[:200]
    return f"{parsed.scheme}://{parsed.hostname}{path}"


def spreadsheet_safe(value: Any) -> str:
    text = csv_value(value)
    if text != "-" and text.startswith(SPREADSHEET_PREFIXES):
        return "'" + text
    return text


def csv_value(value: Any) -> str:
    return "-" if value is None or value == "" else str(value)


def iso_from_epoch_ms(value: Any, semantics: str) -> TimestampValue | None:
    """Convert only fields whose millisecond unit is established by evidence."""
    if semantics not in {"model_last_loaded", "model_load_attempt", "user_message_event",
                         "assistant_message_event", "download_started", "download_completed"}:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        dt = datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return TimestampValue(str(value), dt.isoformat().replace("+00:00", "Z"), semantics, True)


def iso_from_datetime(value: Any, semantics: str) -> TimestampValue | None:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return TimestampValue(value.isoformat(), "", semantics, False)
        dt = value
        return TimestampValue(value.isoformat(), dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), semantics, True)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    variants = [text, text.replace("Z", "+00:00")]
    for candidate in variants:
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if dt.tzinfo is None:
            return TimestampValue(text, "", semantics, False)
        return TimestampValue(text, dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), semantics, True)
    return TimestampValue(text, "", semantics, False)


def format_timestamp_kst(value: TimestampValue | None) -> str:
    """Serialize an established absolute instant as team format `YYYY-MM-DD HH:MM:SS.ffffff KST`."""
    if value is None or not value.normalized or not value.verified_unit:
        return ""
    try:
        dt = datetime.fromisoformat(value.normalized.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if dt.tzinfo is None or dt.utcoffset() is None:
        return ""
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S.%f") + " KST"


def timestamp_from_stat(value: float | None, semantics: str) -> TimestampValue | None:
    if value is None:
        return None
    try:
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return TimestampValue(str(value), dt.isoformat().replace("+00:00", "Z"), semantics, True)


def json_pointer_escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def safe_json_load(ctx: AnalysisContext, artifact: ArtifactRecord) -> Any | None:
    if artifact.content is None:
        return None
    if len(artifact.content) > MAX_JSON_BYTES:
        ctx.issue("json_too_large", artifact.path, "JSON 크기 제한으로 해당 artifact만 건너뜀")
        return None
    try:
        text = artifact.content.decode("utf-8-sig")
        return json.loads(text)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        ctx.issue("json_parse_failed", artifact.path, "JSON parsing 실패; 다른 artifact 분석은 계속됨")
        return None


def recursive_items(value: Any, pointer: str = "") -> Iterator[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{pointer}/{json_pointer_escape(str(key))}"
            yield child, str(key), value[key]
            yield from recursive_items(value[key], child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child = f"{pointer}/{index}"
            yield child, str(index), item
            yield from recursive_items(item, child)


def first_scalar(mapping: Mapping[str, Any], aliases: Sequence[str]) -> tuple[str, str]:
    for key in aliases:
        value = mapping.get(key)
        text = scalar(value)
        if text:
            return key, text
    return "", ""


def basename(path: str) -> str:
    return PureWindowsPath(path.replace("/", "\\")).name


def lower_path(path: str) -> str:
    return path.replace("/", "\\").lower()


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def artifact_provenance(artifact: ArtifactRecord, location: str = "") -> Provenance:
    return Provenance(
        source_image=artifact.provenance.source_image,
        original_artifact_path=artifact.provenance.original_artifact_path,
        materialized_path="",
        evidence_location=location or artifact.provenance.evidence_location,
        lineage_key=artifact.provenance.lineage_key,
    )


# ---------------------------------------------------------------------------
# 4. Generic evidence store and directory collector
# ---------------------------------------------------------------------------

def should_read_content(path: str, size: int | None) -> bool:
    name = basename(path).lower()
    lp = lower_path(path)
    if size is not None and size < 0:
        return False
    if name.endswith(".json") and (size is None or size <= MAX_JSON_BYTES):
        return True
    if name.endswith(".conversation.json") and (size is None or size <= MAX_JSON_BYTES):
        return True
    if name.endswith(".log") and ".lmstudio\\server-logs" in lp and (size is None or size <= MAX_LOG_BYTES):
        return True
    if name.endswith(".md") and (size is None or size <= MAX_EXPORT_BYTES):
        return True
    if name.endswith(".txt") and (size is None or size <= MAX_LOG_BYTES):
        return True
    if name.endswith(".csv") or name.endswith(".db"):
        return False
    if name in {"zone.identifier", "$i", "$r"} and (size is None or size <= MAX_RESIDENT_BYTES):
        return True
    return False


def should_record_path(path: str) -> bool:
    lp = lower_path(path)
    name = basename(path)
    if name.lower().endswith(".pf") and re.search(r"(?i)lm[ -]?studio", name):
        return True
    if name.lower() in {"$mft.copy0", "$mft", "$j.copy0", "$logfile.copy0"}:
        return True
    if RELEVANT_NAME_RE.search(name):
        return True
    return any(
        marker in lp
        for marker in (
            "\\.lmstudio\\",
            "\\programs\\lm studio\\",
            "\\lm-studio-updater\\",
            "\\server-logs\\",
            "\\user-files\\",
            "\\windows\\prefetch\\lm studio",
            "\\start menu\\programs\\lm studio",
        )
    )


def local_access_issue(ctx: AnalysisContext, path: str, exc: OSError, fallback: str) -> None:
    if not ctx.live:
        ctx.issue(fallback, path, "artifact 접근 실패; 다른 artifact 분석은 계속됨")
        return
    if getattr(exc, "winerror", None) in {32, 33}:
        code = "live_artifact_locked"
    elif isinstance(exc, PermissionError):
        code = "live_permission_denied"
    elif isinstance(exc, FileNotFoundError):
        code = "live_artifact_not_found"
    else:
        code = "live_artifact_read_failed"
    ctx.issue(code, path, "로컬 artifact 접근 실패; 다른 artifact 분석은 계속됨")


def lmstudio_log_path(ctx: AnalysisContext, path: str) -> bool:
    low = lower_path(path)
    return "\\.lmstudio\\server-logs\\" in low or any(
        low.startswith(lower_path(home).rstrip("\\") + "\\server-logs\\")
        for home in ctx.lmstudio_homes
    )


def add_local_file(ctx: AnalysisContext, path: Path, logical_path: str | None = None) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        local_access_issue(ctx, str(path), exc, "artifact_stat_failed")
        return
    original = logical_path or str(path.resolve())
    size = int(st.st_size)
    content = None
    if should_read_content(original, size) or (lmstudio_log_path(ctx, original) and size <= MAX_LOG_BYTES):
        try:
            # Bound reads even when a live file grows after stat().
            with path.open("rb") as fh:
                content = fh.read(max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES) + 1)
            if len(content) > max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES):
                content = None
                ctx.issue("artifact_too_large", original, "artifact 읽기 크기 제한 초과")
        except OSError as exc:
            local_access_issue(ctx, original, exc, "artifact_read_failed")
    if ctx.live:
        try:
            after = path.stat()
            if (st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                content = None
                ctx.issue("live_artifact_changed", original, "읽기 전후 metadata 변경; 불안정한 본문은 분석에서 제외됨")
        except OSError as exc:
            content = None
            local_access_issue(ctx, original, exc, "artifact_stat_failed")
    birth = getattr(st, "st_birthtime", None)
    if birth is None and os.name == "nt":
        birth = st.st_ctime
    artifact = ArtifactRecord(
        artifact_id=stable_id(ctx.source_image, original, str(size)),
        path=original,
        provenance=Provenance(ctx.source_image, original, "", "file",
                              "content:" + hashlib.sha256(content).hexdigest() if content else ""),
        kind="file",
        size=size,
        content=content,
        metadata={"collection_birthtime": birth, "collection_mtime_ns": st.st_mtime_ns,
                  "collection_ctime_ns": st.st_ctime_ns},
    )
    ctx.add_artifact(artifact)
    if os.name == "nt" and path.is_file():
        ads_name = str(path) + ":Zone.Identifier"
        try:
            with open(ads_name, "rb") as fh:
                ads = fh.read(MAX_RESIDENT_BYTES + 1)
            if len(ads) <= MAX_RESIDENT_BYTES:
                ads_path = original + ":Zone.Identifier"
                ctx.add_artifact(ArtifactRecord(
                    stable_id(ctx.source_image, ads_path), ads_path,
                    Provenance(ctx.source_image, ads_path, "", "ADS Zone.Identifier"),
                    "ads", len(ads), content=ads,
                ))
        except OSError:
            pass


def local_reparse_point(path: Path) -> bool:
    st = path.lstat()
    return path.is_symlink() or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def walk_selected_local(ctx: AnalysisContext, root: Path, *, broad: bool = False) -> None:
    skip_names = {"$extend", "system volume information"}
    def onerror(exc: OSError) -> None:
        local_access_issue(ctx, str(exc.filename or root), exc, "directory_read_failed")

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        dirs[:] = sorted(d for d in dirs if d.lower() not in skip_names)
        if ctx.live:
            for name in list(dirs):
                try:
                    if local_reparse_point(Path(current) / name):
                        dirs.remove(name)
                except OSError as exc:
                    dirs.remove(name)
                    local_access_issue(ctx, str(Path(current) / name), exc, "directory_read_failed")
        for name in sorted(files):
            path = Path(current) / name
            if ctx.live:
                try:
                    if local_reparse_point(path):
                        continue
                except OSError as exc:
                    local_access_issue(ctx, str(path), exc, "artifact_stat_failed")
                    continue
            lp = lower_path(str(path))
            if name.lower().endswith((".csv", ".db")):
                add_local_file(ctx, path)
                continue
            if should_record_path(str(path)):
                add_local_file(ctx, path)
                continue
            if broad and name.lower().endswith((".json", ".log", ".txt")):
                add_local_file(ctx, path)


PROFILE_TARGETS = (
    "AppData/Local/Programs/LM Studio", "AppData/Local/lm-studio-updater",
    "AppData/Roaming/Microsoft/Windows/Start Menu",
    "AppData/Roaming/Microsoft/Windows/Recent", "Desktop", "Downloads", "Documents",
)
EXCLUDED_PROFILES = {"default", "default user", "public", "all users"}


def decode_home_pointer(content: bytes) -> str:
    # LM Studio writes a plain UTF-8 path, not a Dissect key or CLI syntax.
    text = content.decode("utf-8-sig").strip()
    if not text or "\x00" in text or "\n" in text or "\r" in text:
        raise ValueError("invalid home pointer")
    return text


def profile_roots(profile: Path, ctx: AnalysisContext | None = None,
                  evidence_root: Path | None = None) -> list[tuple[Path, bool]]:
    homes = [profile / ".lmstudio"]
    pointer = profile / ".lmstudio-home-pointer"
    try:
        with pointer.open("rb") as fh:
            data = fh.read(4097)
        if len(data) > 4096:
            raise ValueError("oversized home pointer")
        text = decode_home_pointer(data)
        home = Path(text)
        if PureWindowsPath(text).drive.startswith("\\\\"):
            raise ValueError("network home pointer")
        if not home.is_absolute():
            home = profile / home
        # Offline directories must never follow an evidence pointer into the host.
        if evidence_root is None or is_inside(home, evidence_root):
            homes.append(home)
        elif ctx is not None:
            ctx.issue("home_pointer_outside_evidence", str(pointer), "추출 directory 밖의 Home pointer는 따르지 않음")
    except FileNotFoundError:
        pass
    except OSError as exc:
        if ctx is not None:
            local_access_issue(ctx, str(pointer), exc, "home_pointer_read_failed")
    except (UnicodeError, ValueError):
        if ctx is not None:
            ctx.issue("home_pointer_invalid", str(pointer), "Home pointer 형식이 유효하지 않음")
    roots = [(home, True) for home in homes]
    roots.extend((profile / relative, False) for relative in PROFILE_TARGETS)
    result = []
    for path, broad in roots:
        if ctx is not None and ctx.live:
            ctx.evidence_roots.append(path.resolve())
        try:
            path.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            if ctx is not None:
                local_access_issue(ctx, str(path), exc, "directory_read_failed")
            continue
        result.append((path, broad))
        if ctx is not None and broad:
            ctx.lmstudio_homes.append(str(path.resolve()))
    return result


def directory_roots(input_path: Path, ctx: AnalysisContext | None = None) -> list[tuple[Path, bool]]:
    roots: list[tuple[Path, bool]] = []
    if input_path.name.lower() == ".lmstudio":
        return [(input_path, True)]
    users = input_path / "Users"
    if users.is_dir():
        for user in sorted((p for p in users.iterdir() if p.is_dir()), key=lambda p: p.name.lower()):
            roots.extend(profile_roots(user, ctx, input_path))
        prefetch = input_path / "Windows" / "Prefetch"
        if prefetch.exists():
            roots.append((prefetch, False))
        recycle = input_path / "$Recycle.Bin"
        if recycle.exists():
            roots.append((recycle, False))
        return roots
    if any((input_path / name).exists() for name in (".lmstudio", "AppData", ".lmstudio-home-pointer")):
        return profile_roots(input_path, ctx, input_path)
    # Research extracts and other focused artifact directories are safe to scan broadly.
    return [(input_path, True)]


def collect_directory(ctx: AnalysisContext) -> None:
    seen: set[str] = set()
    for root, broad in directory_roots(ctx.input_path, ctx):
        key = str(root.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        if root.is_file():
            add_local_file(ctx, root)
        else:
            walk_selected_local(ctx, root, broad=broad)


def live_roots(ctx: AnalysisContext, root: Path | None = None) -> list[tuple[Path, bool]]:
    profiles: list[Path] = []
    windows_root = root or Path(os.environ.get("SystemDrive", "C:") + "\\")
    users = windows_root / "Users"
    try:
        profiles.extend(sorted(users.iterdir(), key=lambda p: str(p).lower()))
    except OSError as exc:
        local_access_issue(ctx, str(users), exc, "directory_read_failed")
    current = os.environ.get("USERPROFILE")
    if root is None and current:
        profiles.append(Path(current))
    roots: list[tuple[Path, bool]] = []
    seen: set[str] = set()
    for profile in profiles:
        if profile.name.lower() in EXCLUDED_PROFILES:
            continue
        try:
            profile.stat()
            if not profile.is_dir() or local_reparse_point(profile):
                continue
            key = str(profile.resolve()).lower()
            if key in seen:
                continue
            seen.add(key)
            roots.extend(profile_roots(profile, ctx))
        except OSError as exc:
            local_access_issue(ctx, str(profile), exc, "directory_read_failed")
    roots.append((windows_root / "Windows" / "Prefetch", False))
    ctx.evidence_roots = list(dict.fromkeys([*ctx.evidence_roots, *(path.resolve() for path, _ in roots)]))
    return roots


def collect_live(ctx: AnalysisContext, root: Path | None = None) -> None:
    if sys.platform != "win32":
        ctx.issue("live_platform_unsupported", "Windows Live", "--live는 Windows에서만 지원됨", True)
        return
    seen: set[str] = set()
    for path, broad in live_roots(ctx, root):
        key = str(path.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            path.stat()
            if path.is_dir() and not local_reparse_point(path):
                walk_selected_local(ctx, path, broad=broad)
        except FileNotFoundError:
            continue
        except OSError as exc:
            local_access_issue(ctx, str(path), exc, "directory_read_failed")
    if not ctx.lmstudio_homes:
        ctx.issue("live_home_not_found", "Windows Live", "접근 가능한 LM Studio Home을 찾지 못함")
    ctx.issue("live_metadata_limited", "Windows Live", "현재 접근 가능한 파일만 수집; raw $MFT/$UsnJrnl 및 삭제 파일 복구는 수행하지 않음")


# ---------------------------------------------------------------------------
# 5. Pre-parsed Windows history collectors (CSV and read-only SQLite)
# ---------------------------------------------------------------------------

def relevant_history_target(path: str) -> bool:
    lp = lower_path(path)
    return bool(RELEVANT_NAME_RE.search(basename(path))) or any(
        marker in lp for marker in ("\\.lmstudio\\", "\\programs\\lm studio\\", "\\lm-studio-updater\\")
    )


def history_kind(event: str, source_name: str, in_use: str = "") -> str:
    text = f"{event} {source_name}".lower()
    if "delete" in text or in_use.lower() in {"false", "0"}:
        return "history_delete"
    if "renam" in text or "move" in text:
        return "history_rename"
    if "file_create" in text or "file creation" in text or re.search(r"(?:^|[_-])created(?:[_.-]|$)", source_name.lower()):
        return "history_create"
    if "modif" in text or "overwrite" in text or "extend" in text or "truncat" in text or "data_added" in text:
        return "history_modify"
    return "history_observed"


def parse_csv_timestamp(row: Mapping[str, str], kind: str) -> TimestampValue | None:
    aliases = (
        ("TimeStamp", "history_event"),
        ("EventTime", "history_event"),
        ("Created0x10", "ntfs_created"),
        ("CreationTimeUtc", "filesystem_created"),
        ("LastModified0x10", "ntfs_modified"),
        ("LastWriteTimeUtc", "filesystem_modified"),
    )
    for key, semantics in aliases:
        value = row.get(key, "")
        if value:
            ts = iso_from_datetime(value, semantics)
            if ts:
                return ts
    return None


def collect_preparsed_csv(ctx: AnalysisContext, artifact: ArtifactRecord) -> None:
    source_path = Path(artifact.path)
    try:
        with source_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for number, row in enumerate(reader, start=2):
                full = (row.get("FullName") or "").strip()
                if not full:
                    parent = (row.get("ParentPath") or "").strip()
                    name = (row.get("FileName") or row.get("Name") or "").strip()
                    full = str(PureWindowsPath(parent) / name) if name else parent
                if not full or not relevant_history_target(full):
                    continue
                event = (row.get("Event") or "").strip()
                kind = history_kind(event, source_path.name, (row.get("InUse") or "").strip())
                location = f"record {number}"
                lineage = f"record:{lower_path(artifact.path)}#{number}"
                prov = Provenance(ctx.source_image, artifact.path, "", location, lineage)
                direct_tag = ""
                low_full = lower_path(full)
                if kind == "history_delete" and basename(full).lower().endswith(".conversation.json"):
                    direct_tag = "ntfs_conversation_delete"
                elif kind == "history_delete" and ("user-files" in low_full or ".metadata.json" in low_full):
                    direct_tag = "ntfs_document_delete" if any(ext in low_full for ext in (".pdf", ".doc", ".txt")) else "ntfs_image_delete"
                ctx.add_fact(ObservedFact(
                    kind, "filesystem", prov,
                    value=safe_nonconversation_text(event, max_length=120),
                    key=(row.get("FileReferenceNumber") or row.get("EntryNumber") or "").strip(),
                    timestamp=parse_csv_timestamp(row, kind),
                    direct_tag=direct_tag,
                    target_path=full,
                ))
                zone = (row.get("ZoneIdContents") or "").strip()
                if zone:
                    ctx.add_fact(ObservedFact("zone_identifier", "final_file", prov, "present", timestamp=parse_csv_timestamp(row, kind), target_path=full))
                resident = (row.get("ResidentDataBase64") or "").strip()
                if resident and basename(full).lower().endswith((".json", ".md")):
                    try:
                        data = base64.b64decode(resident, validate=True)
                    except (ValueError, base64.binascii.Error):
                        data = b""
                    if 0 < len(data) <= MAX_RESIDENT_BYTES:
                        ctx.add_artifact(ArtifactRecord(
                            stable_id(artifact.path, str(number), full), full,
                            Provenance(ctx.source_image, full, "", f"{artifact.path}; record {number}; resident data", lineage),
                            "recovered_resident", len(data), content=data, metadata={"history_kind": kind},
                        ))
    except (OSError, csv.Error, UnicodeError):
        ctx.issue("csv_parse_failed", artifact.path, "pre-parsed CSV 읽기 실패")


def collect_history_database(ctx: AnalysisContext, artifact: ArtifactRecord) -> None:
    try:
        uri = Path(artifact.path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    except (sqlite3.Error, OSError, ValueError):
        ctx.issue("history_db_open_failed", artifact.path, "history database 읽기 실패")
        return
    try:
        table_names = {
            str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table, time_column in (("UsnJrnl", "TimeStamp"), ("LogFile", "EventTime")):
            if table not in table_names:
                continue
            query = f'SELECT rowid, "{time_column}", Event, FileName, FullPath FROM "{table}" ORDER BY rowid'
            try:
                cursor = conn.execute(query)
            except sqlite3.Error:
                continue
            for rowid, time_text, event, filename, full_path in cursor:
                target = str(full_path or "")
                if not target and filename:
                    target = str(filename)
                if not relevant_history_target(target):
                    continue
                kind = history_kind(str(event or ""), table)
                tag = ""
                low_event = str(event or "").lower()
                low_target = lower_path(target)
                if kind == "history_delete" and basename(target).lower().endswith(".conversation.json"):
                    tag = "ntfs_conversation_delete"
                elif kind == "history_delete" and ("user-files" in low_target or ".metadata.json" in low_target):
                    tag = "ntfs_document_delete" if ".pdf" in low_target or "document" in low_target else "ntfs_image_delete"
                elif "uninstall" in low_target and re.search(r"\b(?:execute|executed|execution)\b", low_event):
                    tag = "explicit_uninstaller_execution"
                ts = iso_from_datetime(str(time_text or ""), "history_event")
                ctx.add_fact(ObservedFact(
                    kind, "filesystem",
                    Provenance(ctx.source_image, artifact.path, "", f"{table} rowid {rowid}"),
                    safe_nonconversation_text(str(event or ""), max_length=120),
                    timestamp=ts, direct_tag=tag, target_path=target,
                ))
    except sqlite3.Error:
        ctx.issue("history_db_parse_failed", artifact.path, "history database 부분 parsing 실패")
    finally:
        conn.close()


def collect_preparsed_history(ctx: AnalysisContext) -> None:
    for artifact in sorted(list(ctx.artifacts), key=lambda a: a.path.lower()):
        suffix = Path(artifact.path).suffix.lower()
        if suffix == ".csv" and Path(artifact.path).is_file():
            collect_preparsed_csv(ctx, artifact)
        elif suffix == ".db" and Path(artifact.path).is_file():
            collect_history_database(ctx, artifact)


def collect_standalone_mft(ctx: AnalysisContext) -> None:
    """Recover relevant resident files from research/extracted $MFT copies."""
    mft_artifacts = [a for a in ctx.artifacts if basename(a.path).lower() in {"$mft.copy0", "$mft"}]
    if not mft_artifacts:
        return
    try:
        from dissect.ntfs import NTFS
    except ImportError:
        return
    for source in sorted(mft_artifacts, key=lambda a: a.path.lower()):
        entry_numbers: set[int] = set()
        for csv_artifact in ctx.artifacts:
            if not csv_artifact.path.lower().endswith(".csv") or "mftecmd" not in lower_path(csv_artifact.path):
                continue
            try:
                with Path(csv_artifact.path).open("r", encoding="utf-8-sig", errors="replace", newline="") as index_fh:
                    for row in csv.DictReader(index_fh):
                        name = (row.get("FileName") or "").strip()
                        path = str(PureWindowsPath(row.get("ParentPath") or "") / name)
                        if not should_record_path(name):
                            continue
                        if (row.get("InUse") or "").strip().lower() not in {"true", "1"} and not deleted_json_target(path):
                            continue
                        try:
                            entry_numbers.add(int(row.get("EntryNumber") or ""))
                        except ValueError:
                            continue
            except (OSError, csv.Error):
                continue
        try:
            fh = Path(source.path).open("rb")
        except OSError:
            ctx.issue("mft_open_failed", source.path, "$MFT copy 읽기 실패")
            continue
        try:
            ntfs = NTFS(mft=fh)
            records: Iterable[Any]
            if entry_numbers:
                records = (ntfs.mft.get(number) for number in sorted(entry_numbers))
            else:
                records = ntfs.mft.segments()
            for record in records:
                try:
                    if record.is_dir():
                        continue
                    if not (int(record.header.Flags) & 0x1):
                        try:
                            deleted_path = str(record.full_path(ignore_dos=True))
                            recover_deleted_resident(ctx, record, deleted_path, source.path)
                        except Exception:
                            pass
                        continue
                    name = str(record.filename or "")
                    if not should_record_path(name):
                        continue
                    if not record.resident:
                        continue
                    size = int(record.size())
                    if not should_read_content(name, size):
                        continue
                    data = record.open().read(max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES) + 1)
                    if len(data) > max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES):
                        continue
                    try:
                        full = str(record.full_path(ignore_dos=True) or name)
                    except Exception:
                        full = name
                    created, modified = ntfs_record_times(record)
                    location = f"{source.path}; {ntfs_locator(record)}; resident $DATA"
                    ctx.add_artifact(ArtifactRecord(
                        stable_id(source.path, full, ntfs_locator(record)), full,
                        Provenance(ctx.source_image, full, "", location),
                        "mft_resident", size, created, modified, data,
                    ))
                except Exception:
                    continue
        except Exception:
            ctx.issue("mft_parse_failed", source.path, "$MFT copy 부분 parsing 실패")
        finally:
            fh.close()


# ---------------------------------------------------------------------------
# 6. DD/E01 read-only selective collector
# ---------------------------------------------------------------------------

def ntfs_record_times(record: Any) -> tuple[TimestampValue | None, TimestampValue | None]:
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

        si = record.attributes[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION]
        created = iso_from_datetime(si.creation_time, "ntfs_created")
        modified = iso_from_datetime(si.last_modification_time, "ntfs_modified")
        return created, modified
    except Exception:
        return None, None


def ntfs_locator(record: Any) -> str:
    try:
        sequence = int(record.header.SequenceNumber)
        return f"MFT {int(record.segment)}#{sequence}"
    except Exception:
        return "MFT record"


def add_ntfs_file(ctx: AnalysisContext, record: Any, logical_path: str, volume_index: int) -> None:
    if record.is_dir():
        return
    size: int | None = None
    try:
        size = int(record.size())
    except Exception:
        pass
    content = None
    if should_read_content(logical_path, size):
        try:
            if size is None or size <= max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES):
                fh = record.open()
                content = fh.read(max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES) + 1)
                if len(content) > max(MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_EXPORT_BYTES):
                    content = None
        except Exception:
            ctx.issue("ntfs_artifact_read_failed", logical_path, "NTFS artifact 내용 읽기 실패")
    created, modified = ntfs_record_times(record)
    location = ntfs_locator(record)
    artifact = ArtifactRecord(
        stable_id(ctx.source_image, str(volume_index), logical_path, location),
        logical_path,
        Provenance(ctx.source_image, logical_path, "", location),
        "ntfs_file",
        size,
        created,
        modified,
        content,
        {"volume_index": volume_index},
    )
    ctx.add_artifact(artifact)
    try:
        if record.has_stream("Zone.Identifier"):
            ads_data = record.open("Zone.Identifier").read(MAX_RESIDENT_BYTES + 1)
            if len(ads_data) <= MAX_RESIDENT_BYTES:
                ads_path = logical_path + ":Zone.Identifier"
                ctx.add_artifact(ArtifactRecord(
                    stable_id(ctx.source_image, str(volume_index), ads_path, location),
                    ads_path,
                    Provenance(ctx.source_image, ads_path, "", location + "; ADS Zone.Identifier"),
                    "ntfs_ads", len(ads_data), created, modified, ads_data,
                    {"volume_index": volume_index},
                ))
    except Exception:
        ctx.issue("ntfs_ads_read_failed", logical_path, "Zone.Identifier stream 읽기 실패")


def walk_ntfs_record(
    ctx: AnalysisContext,
    record: Any,
    logical_path: str,
    volume_index: int,
    mode: str,
    seen: set[tuple[int, int]],
    depth: int = 0,
) -> None:
    if depth > 64:
        return
    try:
        identity = (int(record.segment), int(record.header.SequenceNumber))
    except Exception:
        identity = (id(record), 0)
    if identity in seen:
        return
    seen.add(identity)
    if record.is_file():
        if mode == "lmstudio" or should_record_path(logical_path):
            add_ntfs_file(ctx, record, logical_path, volume_index)
        return
    try:
        children = list(record.iterdir(dereference=True, ignore_dos=True))
    except Exception:
        ctx.issue("ntfs_directory_read_failed", logical_path, "NTFS directory 일부 읽기 실패")
        return
    children.sort(key=lambda item: (str(item.filename or "").lower(), int(item.segment or 0)))
    for child in children:
        name = str(child.filename or "")
        if not name or name in {".", ".."}:
            continue
        child_path = logical_path.rstrip("\\") + "\\" + name
        child_mode = mode
        if mode == "documents" and child.is_dir() and depth >= 5:
            continue
        if mode == "program" and child.is_dir() and depth >= 4:
            continue
        if mode == "focused" and not should_record_path(child_path) and child.is_file():
            continue
        walk_ntfs_record(ctx, child, child_path, volume_index, child_mode, seen, depth + 1)


def ntfs_get(record_or_ntfs: Any, path: str) -> Any | None:
    try:
        if hasattr(record_or_ntfs, "mft"):
            return record_or_ntfs.mft.get(path)
        return record_or_ntfs.get(path)
    except Exception:
        return None


def collect_ntfs_current(ctx: AnalysisContext, ntfs: Any, volume_index: int) -> None:
    users = ntfs_get(ntfs, "Users")
    if users is None or not users.is_dir():
        return
    try:
        user_records = list(users.iterdir(dereference=True, ignore_dos=True))
    except Exception:
        ctx.issue("ntfs_users_read_failed", f"volume{volume_index}:\\Users", "Users directory 읽기 실패")
        return
    user_records.sort(key=lambda r: str(r.filename or "").lower())
    for user in user_records:
        if not user.is_dir():
            continue
        user_name = str(user.filename or "")
        if not user_name or user_name.lower() in {"default", "default user", "public", "all users"}:
            continue
        base = f"volume{volume_index}:\\Users\\{user_name}"
        targets = (
            (".lmstudio", "lmstudio"),
            (r"AppData\Local\Programs\LM Studio", "program"),
            (r"AppData\Local\lm-studio-updater", "program"),
            (r"AppData\Roaming\Microsoft\Windows\Start Menu", "focused"),
            ("Desktop", "documents"),
            ("Downloads", "documents"),
            ("Documents", "documents"),
        )
        for relative, mode in targets:
            target = ntfs_get(user, relative)
            if target is None:
                continue
            logical = base + "\\" + relative
            walk_ntfs_record(ctx, target, logical, volume_index, mode, set())
    for relative, mode in ((r"Windows\Prefetch", "focused"), (r"$Recycle.Bin", "focused")):
        target = ntfs_get(ntfs, relative)
        if target is not None:
            walk_ntfs_record(ctx, target, f"volume{volume_index}:\\{relative}", volume_index, mode, set())


def usn_filename_relevant(filename: str) -> bool:
    low = filename.lower()
    return bool(RELEVANT_NAME_RE.search(filename)) or any(
        marker in low
        for marker in ("lm studio", "uninstall", "user-files", ".lmstudio", "conversation")
    )


def collect_ntfs_usn(ctx: AnalysisContext, ntfs: Any, volume_index: int) -> None:
    journal = getattr(ntfs, "usnjrnl", None)
    if journal is None:
        return
    source = f"volume{volume_index}:\\$Extend\\$UsnJrnl:$J"
    stats = {"source": source, "records_read": 0, "relevant_records": 0,
             "records_skipped": 0, "records_failed": 0, "path_failures": 0,
             "timestamp_failures": 0, "reference_failures": 0,
             "first_failing_offset": None, "last_successful_offset": None}
    ctx.usn_stats.append(stats)
    try:
        records = iter(journal.records())
    except Exception as exc:
        ctx.issue("usn_iterator_failed", source, f"USN iterator 생성 실패 ({type(exc).__name__})")
        return
    recovered: set[str] = set()
    while True:
        try:
            record = next(records)
        except StopIteration:
            break
        except Exception as exc:
            ctx.issue("usn_iterator_failed", source, f"USN iterator 중단; 이전 기록 보존 ({type(exc).__name__})")
            break
        stats["records_read"] += 1
        offset = None
        try:
            offset = int(record.offset)
            filename = str(getattr(record, "filename", "") or "")
            if not usn_filename_relevant(filename):
                stats["records_skipped"] += 1
                continue
            stats["relevant_records"] += 1
            try:
                target = str(record.full_path)
            except Exception:
                target = filename
                stats["path_failures"] += 1
            reason = str(getattr(record, "Reason", "") or "")
            kind = history_kind(reason, "$UsnJrnl")
            tag = ""
            low_target = lower_path(target)
            if kind == "history_delete" and basename(target).lower().endswith(".conversation.json"):
                tag = "ntfs_conversation_delete"
            elif kind == "history_delete" and ("user-files" in low_target or ".metadata.json" in low_target):
                tag = "ntfs_document_delete" if ".pdf" in low_target else "ntfs_image_delete"
            ts = None
            try:
                ts = iso_from_datetime(record.timestamp, "usn_event")
            except Exception:
                stats["timestamp_failures"] += 1
            try:
                reference = record.FileReferenceNumber
                if hasattr(reference, "SequenceNumber"):
                    from dissect.ntfs.util import segment_reference
                    frn = f"{segment_reference(reference)}#{reference.SequenceNumber}"
                else:
                    frn = str(int(reference))
            except Exception:
                frn = ""
                stats["reference_failures"] += 1
            ctx.add_fact(ObservedFact(
                kind, "filesystem",
                Provenance(ctx.source_image, source, "", f"offset 0x{offset:x}"),
                safe_nonconversation_text(reason, max_length=160), frn, ts, tag, target,
            ))
            stats["last_successful_offset"] = offset
            if kind == "history_delete" and frn and frn not in recovered and deleted_json_target(target):
                recovered.add(frn)
                try:
                    mft_record = record.file
                    sequence = record.FileReferenceNumber.SequenceNumber
                    if mft_record is not None and mft_record.header.SequenceNumber == sequence:
                        recover_deleted_resident(ctx, mft_record, target, source)
                except Exception as exc:
                    ctx.issue("deleted_mft_unavailable", source, f"선택된 삭제 record 복구 불가 ({type(exc).__name__})")
        except Exception as exc:
            stats["records_failed"] += 1
            if stats["first_failing_offset"] is None:
                stats["first_failing_offset"] = offset if offset is not None else "unavailable"
            ctx.issue("usn_record_failed", source, f"개별 USN record 건너뜀; 후속 수집 계속 ({type(exc).__name__})")


def deleted_json_target(path: str) -> bool:
    low = lower_path(path)
    return "\\.lmstudio\\" in low and (
        "\\conversations\\" in low and low.endswith(".conversation.json")
        or "\\user-files\\" in low and low.endswith(".metadata.json")
    )


def recover_deleted_resident(ctx: AnalysisContext, record: Any, path: str, source: str) -> None:
    """Only a matched, not-in-use LM Studio resident JSON; never credentials/carving."""
    if not deleted_json_target(path) or int(record.header.Flags) & 1 or not record.resident:
        return
    size = int(record.size())
    if not 0 < size <= MAX_JSON_BYTES:
        return
    content = record.open().read(size)
    locator = ntfs_locator(record)
    identity = stable_id(source, locator, path)
    if any(a.artifact_id == identity for a in ctx.artifacts):
        return
    ctx.add_artifact(ArtifactRecord(identity, path,
        Provenance(ctx.source_image, path, "", f"{source}; {locator}; deleted resident $DATA"),
        "deleted_mft_resident", size, content=content, metadata={"history_kind": "history_delete"}))


class SplitRawImageError(ValueError):
    """A split RAW/DD segment set is incomplete or was entered incorrectly."""


def split_raw_segment_number(path: Path) -> int | None:
    match = re.fullmatch(r".+\.(\d{3})", path.name)
    return int(match.group(1)) if match is not None else None


def discover_split_raw_segments(path: Path) -> list[Path]:
    if split_raw_segment_number(path) != 1 or path.suffix != ".001":
        raise SplitRawImageError("분할 RAW/DD 이미지는 첫 segment인 .001을 지정하십시오.")
    prefix = path.name[:-4]
    pattern = re.compile(re.escape(prefix) + r"\.(\d{3})\Z")
    segments: dict[int, Path] = {}
    try:
        siblings = path.parent.iterdir()
        for sibling in siblings:
            match = pattern.fullmatch(sibling.name)
            if match is not None and sibling.is_file():
                segments[int(match.group(1))] = sibling
    except OSError as exc:
        raise SplitRawImageError("분할 RAW/DD segment 목록을 읽을 수 없습니다.") from exc
    if 1 not in segments:
        raise SplitRawImageError("분할 RAW/DD 이미지의 .001 segment를 찾을 수 없습니다.")
    for expected in range(1, max(segments) + 1):
        if expected not in segments:
            raise SplitRawImageError(
                f"분할 RAW/DD segment가 연속적이지 않습니다. 예상 segment: .{expected:03d}"
            )
    return [segments[index] for index in range(1, max(segments) + 1)]


class SegmentedRawStream(io.RawIOBase):
    """Read-only logical stream over ordered RAW/DD segments without joining them."""

    def __init__(self, segments: Sequence[Path]) -> None:
        super().__init__()
        if not segments:
            raise ValueError("segment가 필요합니다.")
        self._handles: list[BinaryIO] = []
        self._ends: list[int] = []
        self._position = 0
        total = 0
        try:
            for segment in segments:
                handle = segment.open("rb")
                self._handles.append(handle)
                total += int(os.fstat(handle.fileno()).st_size)
                self._ends.append(total)
        except Exception:
            for handle in reversed(self._handles):
                handle.close()
            raise
        self._size = total

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("invalid whence")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if size == 0 or self._position >= self._size:
            return b""
        remaining = self._size - self._position if size is None or size < 0 else min(size, self._size - self._position)
        chunks: list[bytes] = []
        while remaining > 0:
            segment_index = next(index for index, end in enumerate(self._ends) if self._position < end)
            segment_start = self._ends[segment_index - 1] if segment_index else 0
            available = self._ends[segment_index] - self._position
            handle = self._handles[segment_index]
            handle.seek(self._position - segment_start)
            chunk = handle.read(min(remaining, available))
            if not chunk:
                raise OSError("분할 RAW/DD segment가 분석 중 변경되었습니다.")
            chunks.append(chunk)
            self._position += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def readinto(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self) -> None:
        if not self.closed:
            for handle in reversed(self._handles):
                try:
                    handle.close()
                except OSError:
                    pass
        super().close()


def open_image_stream(path: Path) -> tuple[BinaryIO, list[Any]]:
    keepalive: list[Any] = []
    if path.suffix.lower() in {".e01", ".ex01", ".s01", ".l01"}:
        from dissect.evidence.ewf import EWF, find_files

        ewf = EWF(find_files(path))
        keepalive.append(ewf)
        return ewf.open(), keepalive
    if path.suffix == ".001":
        segments = discover_split_raw_segments(path)
        try:
            stream = SegmentedRawStream(segments)
        except OSError as exc:
            raise SplitRawImageError("분할 RAW/DD segment를 읽기 전용으로 열지 못했습니다.") from exc
        keepalive.append(stream)
        return stream, keepalive
    fh = path.open("rb")
    keepalive.append(fh)
    return fh, keepalive


@dataclass(repr=False)
class BitLockerCredential:
    """Ephemeral access material; never attach this object to AnalysisContext."""

    kind: str
    value: str | bytes | Path = field(repr=False)
    reader: Callable[[], BitLockerCredential | None] | None = field(default=None, repr=False)

    def resolve(self) -> BitLockerCredential:
        """Read an explicit credential once, only if Clear Key did not unlock."""
        if self.reader is not None:
            reader, self.reader = self.reader, None
            resolved = reader()
            if resolved is None:
                raise ValueError("authorized credential unavailable")
            self.kind, self.value = resolved.kind, resolved.value
        if self.kind == "deferred":
            # A failed/cancelled prompt must not be repeated for every partition.
            raise ValueError("authorized credential unavailable")
        return self


@contextmanager
def quiet_fve_logs() -> Iterator[None]:
    # The backend can log exception objects when DISSECT_LOG_BDE is enabled.
    loggers = [logging.getLogger(name) for name in list(logging.Logger.manager.loggerDict)
               if name == "dissect.fve" or name.startswith("dissect.fve.")]
    states = [(logger, logger.disabled) for logger in loggers]
    try:
        for logger, _ in states:
            logger.disabled = True
        yield
    finally:
        for logger, disabled in states:
            logger.disabled = disabled


def open_volume_stream(ctx: AnalysisContext, volume: BinaryIO, location: str,
                       credential: BitLockerCredential | None = None) -> tuple[BinaryIO | None, bool]:
    """Return a normal or on-the-fly decrypted stream, never an evidence copy."""
    try:
        from dissect.fve.bde import BDE, is_bde_volume
    except ImportError:
        # OEM bytes are only a backend-unavailable hint, never a positive verdict.
        volume.seek(0)
        hint = volume.read(512)
        volume.seek(0)
        if hint[3:11] == b"-FVE-FS-":
            ctx.issue("bitlocker_backend_unavailable", location, "BitLocker 보조 indicator 발견; dissect.fve 설치가 필요하며 공식 판별/unlock은 수행하지 못함")
            return None, False
        return volume, False
    with quiet_fve_logs():
        try:
            detected = is_bde_volume(volume)
            volume.seek(0)
        except Exception:
            ctx.issue("volume_detection_failed", location, "공식 volume 판별 읽기 실패; 해당 volume 건너뜀")
            return None, False
        if not detected:
            return volume, False
        try:
            bde = BDE(volume)
            has_clear_key = bde.has_clear_key()
        except Exception:
            ctx.issue("bitlocker_metadata_failed", location, "BitLocker detected; encryption metadata를 열지 못함; 해당 partition 건너뜀")
            return None, True
        if credential is None and not has_clear_key:
            ctx.issue("bitlocker_credential_missing", location, "BitLocker detected; Clear Key protector unavailable; no authorized credential provided; 해당 partition 건너뜀")
            return None, True
        unlocked = False
        unlock_kind = ""
        if has_clear_key:
            try:
                bde.unlock_with_clear_key()
                unlocked = True
                unlock_kind = "clear_key"
            except Exception:
                # A real but unusable clear protector may coexist with a user protector.
                ctx.issue("bitlocker_clear_key_unlock_failed", location, "Clear Key protector detected; Clear Key unlock failed; explicit authorized credential이 있을 때만 fallback 시도")
        if not unlocked and credential is not None:
            try:
                credential = credential.resolve()
            except (Exception, KeyboardInterrupt):
                ctx.issue("bitlocker_credential_read_failed", location, "명시적으로 요청한 BitLocker credential을 안전하게 읽지 못함; 값은 기록하지 않으며 해당 partition 건너뜀")
                return None, True
            try:
                if credential.kind == "recovery":
                    bde.unlock_with_recovery_password(credential.value)
                elif credential.kind == "passphrase":
                    bde.unlock_with_passphrase(credential.value)
                elif credential.kind == "bek":
                    with Path(credential.value).open("rb") as bek:
                        bde.unlock_with_bek(bek)
                elif credential.kind == "fvek":
                    bde.unlock_with_fvek(credential.value)
                else:
                    raise ValueError("unsupported credential type")
                unlocked = True
                unlock_kind = credential.kind
            except Exception:
                pass
        if not unlocked:
            ctx.issue("bitlocker_unlock_failed", location, "BitLocker unlock failed; recovery material이 잘못되었거나 protector를 해제하지 못함; 해당 partition 건너뜀")
            return None, True
        decrypted = None
        try:
            decrypted = bde.open()
            decrypted.seek(0)
            header = decrypted.read(512)
            decrypted.seek(0)
            if unlock_kind == "fvek" and header[3:11] != b"NTFS    ":
                # Raw FVEK has no authentication: successful API return is insufficient.
                ctx.issue("bitlocker_unlock_failed", location, "Raw FVEK stream의 NTFS header 검증 실패; 잘못된 key/손상/비지원 filesystem 가능; 해당 partition 건너뜀")
                decrypted.close()
                return None, True
        except Exception:
            if decrypted is not None:
                decrypted.close()
            ctx.issue("bitlocker_stream_error", location, "BitLocker 해제 후 decrypted stream 읽기 실패; 해당 partition 건너뜀")
            return None, True
        ctx.issue("bitlocker_unlocked", location,
                  "Clear Key protector detected; Clear Key unlock succeeded; 기존 NTFS 분석 경로 사용"
                  if unlock_kind == "clear_key" else "BitLocker volume read-only unlock 성공; 기존 NTFS 분석 경로 사용")
        return decrypted, True


def collect_image(ctx: AnalysisContext, credential: BitLockerCredential | None = None) -> None:
    try:
        from dissect.ntfs import NTFS
        from dissect.volume.disk import Disk
    except ImportError:
        ctx.issue("image_dependency_missing", str(ctx.input_path), "DD/E01 분석용 Dissect dependency가 설치되지 않음", True)
        return
    try:
        stream, keepalive = open_image_stream(ctx.input_path)
    except SplitRawImageError as exc:
        ctx.issue("split_raw_invalid", str(ctx.input_path), str(exc), True)
        return
    except Exception:
        ctx.issue("image_open_failed", str(ctx.input_path), "image를 읽기 전용으로 열지 못함", True)
        return
    if not any(handle is stream for handle in keepalive):
        keepalive.append(stream)
    ntfs_volumes: list[Any] = []
    encrypted_seen = False
    try:
        try:
            disk = Disk(stream)
            partitions = list(disk.partitions)
        except Exception:
            partitions = []
        volumes: list[tuple[str, BinaryIO]] = []
        for index, partition in enumerate(partitions):
            try:
                volume = partition.open()
                keepalive.append(volume)
                volumes.append((f"partition{index}@{partition.offset}", volume))
            except Exception:
                ctx.issue("partition_open_failed", f"partition{index}", "partition stream 접근 실패; 다른 partition 분석은 계속됨")
        if not partitions:
            stream.seek(0)
            volumes.append(("volume@0", stream))
        for location, volume in volumes:
            try:
                accessible, encrypted = open_volume_stream(ctx, volume, location, credential)
                encrypted_seen = encrypted_seen or encrypted
                if accessible is None:
                    continue
                if accessible is not volume:
                    keepalive.append(accessible)
                accessible.seek(0)
                ntfs_volumes.append(NTFS(accessible))
            except Exception:
                ctx.issue("volume_filesystem_unavailable", location, "지원 NTFS filesystem을 열지 못함; unsupported/손상/읽기 실패 가능; 다른 partition 분석은 계속됨")
        if not ntfs_volumes:
            ctx.issue("ntfs_not_found", str(ctx.input_path), "지원되는 NTFS volume을 찾지 못함; BitLocker partition 접근 진단도 확인하십시오." if encrypted_seen else "지원되는 NTFS volume을 찾지 못함", True)
            return
        for index, ntfs in enumerate(ntfs_volumes):
            try:
                collect_ntfs_current(ctx, ntfs, index)
                collect_ntfs_usn(ctx, ntfs, index)
            except Exception:
                ctx.issue("ntfs_collection_failed", f"volume{index}", "NTFS 수집 중 읽기 실패; 다른 volume 분석은 계속됨")
    finally:
        # EWF owns lazily opened segments. Explicitly close only handles that expose close().
        for handle in reversed(keepalive):
            try:
                close = getattr(handle, "close", None)
                if callable(close):
                    close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 7. Artifact parsers: JSON, logs, accounts, conversations, and attachments
# ---------------------------------------------------------------------------

def parse_json_artifacts(ctx: AnalysisContext) -> None:
    for artifact in sorted(ctx.artifacts, key=lambda a: (a.path.lower(), a.artifact_id)):
        name = basename(artifact.path).lower()
        if not name.endswith(".json"):
            continue
        parsed = safe_json_load(ctx, artifact)
        if parsed is not None:
            ctx.parsed_json[artifact.artifact_id] = parsed


def artifact_for_id(ctx: AnalysisContext, artifact_id: str) -> ArtifactRecord | None:
    for artifact in ctx.artifacts:
        if artifact.artifact_id == artifact_id:
            return artifact
    return None


def facts_for_target(ctx: AnalysisContext, path: str, kinds: set[str] | None = None) -> list[ObservedFact]:
    target_name = basename(path).lower()
    result = []
    for fact in ctx.facts:
        if kinds is not None and fact.fact_type not in kinds:
            continue
        if basename(fact.target_path).lower() == target_name and target_name:
            result.append(fact)
    return result


def safe_account_identifier(profile: Mapping[str, Any]) -> str:
    for key in ("userId", "id", "identifier", "username", "email", "name"):
        value = profile.get(key)
        if isinstance(value, str) and value:
            return safe_fingerprint(value)
    return ""


def parse_accounts(ctx: AnalysisContext) -> dict[str, list[ObservedFact]]:
    states: dict[str, list[ObservedFact]] = {"logged_in": [], "reset": [], "profile": []}
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or not isinstance(data, dict):
            continue
        name = basename(artifact.path).lower()
        prov = artifact_provenance(artifact)
        if name == "local-identity.json":
            identity_type = as_string(data.get("type"))
            if identity_type == "loggedInUser":
                fact = ObservedFact("account_logged_in_state", "account_state", prov, "local identity logged-in", key="/type")
                states["logged_in"].append(fact)
                ctx.add_fact(fact)
            elif identity_type.lower() == "none":
                fact = ObservedFact("account_reset_state", "account_state", prov, "local identity none", key="/type")
                states["reset"].append(fact)
                ctx.add_fact(fact)
        elif name == "user-profile.json":
            profile = data.get("profile")
            if isinstance(profile, dict):
                identifier = safe_account_identifier(profile)
                fact = ObservedFact("account_profile_state", "account_state", prov, identifier or "profile present", key="/profile")
                states["logged_in"].append(fact)
                states["profile"].append(fact)
                ctx.add_fact(fact)
            elif profile is None:
                fact = ObservedFact("account_reset_state", "account_state", prov, "profile null", key="/profile")
                states["reset"].append(fact)
                ctx.add_fact(fact)
        elif name == "lmstudio-hub.json":
            # Never retain credential values. Only a structural null/presence state is recorded.
            # Research 10/11: the authentication object is exactly root /key.
            if isinstance(data.get("key"), dict) and data["key"]:
                fact = ObservedFact("credential_present_state", "account_state", prov, "credential state present", key="/")
                states["logged_in"].append(fact)
                ctx.add_fact(fact)
            elif "key" in data and data["key"] is None:
                fact = ObservedFact("account_reset_state", "account_state", prov, "credential fields null", key="/")
                states["reset"].append(fact)
                ctx.add_fact(fact)
        elif name == "lm-link-account-status-cache.json":
            status = data.get("json")
            if isinstance(status, dict):
                fact = ObservedFact("account_status_state", "account_state", prov, "account status present", key="/json")
                states["logged_in"].append(fact)
                ctx.add_fact(fact)
            elif status is None:
                fact = ObservedFact("account_reset_state", "account_state", prov, "account status null", key="/json")
                states["reset"].append(fact)
                ctx.add_fact(fact)
    return states


def log_timestamp(line: str) -> TimestampValue | None:
    match = re.match(r"^\s*(\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?)", line)
    return iso_from_datetime(match.group(1), "log_event") if match else None


def explicit_log_tag(line: str, fact_type: str) -> str:
    """Allowlisted whole event records, not quoted text, requests or substrings.

    Prefix support is intentionally limited to an optional ISO timestamp and
    INFO marker. Account switch/inference require stronger semantic context.
    """
    body = re.sub(r"^\s*\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\s+", "", line).strip()
    body = re.sub(r"^(?:\[INFO\]|INFO[: ])\s*", "", body, flags=re.I)
    allowed = {
        "account_login_log": (r"(?:login succeeded|logged in|signed in)", "explicit_login_log"),
        "account_logout_log": (r"(?:logout succeeded|logged out|signed out)", "explicit_logout_log"),
        "normal_exit_log": (r"(?:normal exit|graceful shutdown|shutdown complete|clean shutdown)", "explicit_normal_exit_log"),
        "forced_exit_log": (r"(?:forced termination|terminated forcibly)", "explicit_forced_termination"),
        "model_load_log": (r"model (?:loaded|load succeeded)(?::\s*[A-Za-z0-9_./-]+)?", "explicit_model_load_log"),
    }
    pattern, tag = allowed.get(fact_type, (r"(?!)", ""))
    return tag if re.fullmatch(pattern + r"[.!]?", body, re.I) else ""


def parse_logs(ctx: AnalysisContext) -> list[ObservedFact]:
    found: list[ObservedFact] = []
    patterns = (
        (re.compile(r"(?i)\b(?:logged in|login succeeded|authentication succeeded|signed in)\b"), "account_login_log", "lmstudio_log", "explicit_login_log"),
        (re.compile(r"(?i)\b(?:logged out|logout succeeded|signed out)\b"), "account_logout_log", "lmstudio_log", "explicit_logout_log"),
        (re.compile(r"(?i)\b(?:account switched|switch(?:ed)? account)\b"), "account_switch_log", "lmstudio_log", ""),
        (re.compile(r"(?i)\bre-authentication\b"), "account_reauthentication", "lmstudio_log", ""),
        (re.compile(r"(?i)\b(?:prediction|inference|generation)\b.*\b(?:start|request|complete|finish)"), "server_inference", "lmstudio_log", "server_inference_log"),
        (re.compile(r"(?i)\b(?:model)\b.*\b(?:loaded|load succeeded|successfully loaded)\b"), "model_load_log", "lmstudio_log", "explicit_model_load_log"),
        (re.compile(r"(?i)\b(?:graceful shutdown|normal exit|shutdown complete|clean shutdown)\b"), "normal_exit_log", "lmstudio_log", "explicit_normal_exit_log"),
        (re.compile(r"(?i)\b(?:terminated forcibly|forced termination|taskkill|killed process)\b"), "forced_exit_log", "windows_os", "explicit_forced_termination"),
    )
    for artifact in sorted(ctx.artifacts, key=lambda a: a.path.lower()):
        if artifact.content is None or not basename(artifact.path).lower().endswith((".log", ".txt")):
            continue
        if not lmstudio_log_path(ctx, artifact.path):
            continue
        try:
            text = artifact.content.decode("utf-8-sig", errors="replace")
        except UnicodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for regex, fact_type, family, direct in patterns:
                if not regex.search(line):
                    continue
                conv_match = re.search(r'\bconversationId[=:]\s*"?([A-Za-z0-9_.-]+)', line)
                message_match = re.search(r'\bmessageId[=:]\s*"?([A-Za-z0-9_.-]+)', line)
                tag = explicit_log_tag(line, fact_type) if artifact.path.lower().endswith(".log") else ""
                model = re.search(r"(?i)\bmodel (?:loaded|load succeeded):\s*([A-Za-z0-9_./-]+)", line) if tag == "explicit_model_load_log" else None
                fact = ObservedFact(
                    fact_type, family,
                    artifact_provenance(artifact, f"line {number}"),
                    # Never retain a raw log line (it may contain credentials).
                    safe_nonconversation_text(model.group(1)) if model else fact_type, key=message_match.group(1) if message_match else "",
                    timestamp=log_timestamp(line), direct_tag=tag,
                    conversation_ref=conv_match.group(1) if conv_match else "",
                )
                ctx.add_fact(fact)
                found.append(fact)
    return found


def parse_text_listings(ctx: AnalysisContext) -> list[ObservedFact]:
    """Read focused PowerShell/tree listings as observations, never as labels."""
    result: list[ObservedFact] = []
    path_re = re.compile(r"(?i)([A-Z]:\\[^\r\n]*?(?:\.lmstudio|LM Studio)[^\r\n]*?)(?:\s{2,}|$)")
    for artifact in sorted(ctx.artifacts, key=lambda a: a.path.lower()):
        if artifact.content is None or not basename(artifact.path).lower().endswith(".txt"):
            continue
        try:
            text = artifact.content.decode("utf-8-sig", errors="replace")
        except UnicodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            match = path_re.search(line)
            target = match.group(1).strip() if match else ""
            low = line.lower()
            if not target and not any(name in low for name in ("http-server.json", "llmster-pid.lock", "lm studio.exe")):
                continue
            if not target:
                target = basename(line.strip().split()[0]) if line.strip() else ""
            name = basename(target).lower()
            if name not in {"http-server.json", "llmster-pid.lock", "lm studio.exe"} and not relevant_history_target(target):
                continue
            fact_type = "listing_observed"
            if name == "http-server.json":
                fact_type = "http_server_runtime"
            elif name == "llmster-pid.lock":
                fact_type = "pid_lock_runtime"
            fact = ObservedFact(fact_type, "filesystem", artifact_provenance(artifact, f"line {number}"), name or "artifact listed", target_path=target)
            ctx.add_fact(fact)
            result.append(fact)
    return result


def explicit_identifier(mapping: Mapping[str, Any], aliases: Sequence[str]) -> str:
    for key in aliases:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def message_timestamp(message: Mapping[str, Any], version: Mapping[str, Any]) -> TimestampValue | None:
    for container, prefix in ((version, "version"), (message, "message")):
        for key in ("timestamp", "createdAt", "sentAt"):
            value = container.get(key)
            if isinstance(value, str):
                parsed = iso_from_datetime(value, f"{prefix}_{key}")
                if parsed and parsed.normalized:
                    return parsed
    return None


def conversation_scope(path: str) -> str:
    """Keep joins within one profile/snapshot, not across research stage folders."""
    low = lower_path(path)
    for marker in ("\\conversations\\", "\\.internal\\"):
        if marker in low:
            return low.split(marker, 1)[0]
    return str(PureWindowsPath(low).parent)


def config_conversation_refs(ctx: AnalysisContext, path: str) -> list[tuple[str, str]]:
    result = []
    name = basename(path).lower()
    for artifact in ctx.artifacts:
        if conversation_scope(artifact.path) != conversation_scope(path):
            continue
        data = ctx.parsed_json.get(artifact.artifact_id)
        if not isinstance(data, dict):
            continue
        if basename(artifact.path).lower() == "conversation-config.json":
            pairs = [(key, data.get(key)) for key in ("selectedConversation", "newChatConversationIdentifier")]
            history = data.get("selectedConversationHistory")
            if isinstance(history, list):
                pairs.extend((f"selectedConversationHistory/{i}", value) for i, value in enumerate(history))
        elif re.fullmatch(r"window-\d+\.json", basename(artifact.path).lower()):
            chat = data.get("chat")
            pairs = [("chat/activeConversationIdentifier", chat.get("activeConversationIdentifier"))] if isinstance(chat, dict) else []
        else:
            continue
        for key, value in pairs:
            if isinstance(value, str) and value and basename(value).lower() == name:
                result.append((value, f"{artifact.path}:/{key}"))
    return sorted(set(result))


def resolve_conversation_id(ctx: AnalysisContext, artifact: ArtifactRecord, data: Mapping[str, Any]) -> str:
    explicit = explicit_identifier(data, ("conversationId", "conversationIdentifier"))
    if explicit:
        return explicit
    refs = {value for value, _ in config_conversation_refs(ctx, artifact.path)}
    return next(iter(refs)) if len(refs) == 1 else ""


def row_timestamp(message: Mapping[str, Any], version: Mapping[str, Any],
                  version_pointer: str, location: str) -> TimestampValue | None:
    """Only traverse ancestors of this text, never a sibling content/step."""
    relative = location.removeprefix(version_pointer).strip("/").split("/")
    node: Any = version
    ancestors: list[Mapping[str, Any]] = []
    for component in relative[:-1]:
        try:
            node = node[int(component)] if isinstance(node, list) else node[component]
        except (KeyError, IndexError, ValueError, TypeError):
            break
        if isinstance(node, dict):
            ancestors.append(node)
    for container in reversed(ancestors):
        # No numeric units or additional timestamp aliases are inferred.
        parsed = iso_from_datetime(container.get("timestamp"), "content_or_step_timestamp")
        if parsed and parsed.normalized:
            return parsed
    return message_timestamp(message, version)


def enrich_recovered_metadata(ctx: AnalysisContext, logs: Sequence[ObservedFact]) -> None:
    """Use only unambiguous, explicit IDs for separately recovered metadata.

    No unobserved config-title/version-ID schema is invented. A recovered
    conversation with the same actual ID can supply its real root name.
    Log time requires BOTH the conversation and message identifiers.
    """
    titles: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for artifact in ctx.artifacts:
        data = ctx.parsed_json.get(artifact.artifact_id)
        if not isinstance(data, dict) or not basename(artifact.path).lower().endswith(".conversation.json"):
            continue
        identifier = resolve_conversation_id(ctx, artifact, data)
        title = as_string(data.get("name"))
        if identifier and title:
            titles[(conversation_scope(artifact.path), identifier)][title] = f"{artifact.path}:/name"
    enriched = []
    for message in ctx.messages:
        updates: dict[str, Any] = {}
        choices = titles.get((conversation_scope(message.artifact_path), message.conversation_id), {})
        if not message.title and len(choices) == 1:
            title, source = next(iter(choices.items()))
            updates.update(title=title, title_source=source)
        if (message.timestamp is None or not message.timestamp.normalized) and message.conversation_id and message.message_id:
            matches = [f for f in logs if f.fact_type == "server_inference"
                       and f.conversation_ref == message.conversation_id and f.key == message.message_id
                       and f.timestamp and f.timestamp.normalized]
            # Retry versions share message IDs. Do not apply a log time to all versions.
            rows_for_id = [m for m in ctx.messages if m.artifact_path == message.artifact_path and m.message_id == message.message_id]
            if len(rows_for_id) == 1 and len({f.timestamp.normalized for f in matches}) == 1:
                updates.update(timestamp=matches[0].timestamp,
                               timestamp_source=f"{matches[0].provenance.original_artifact_path}:{matches[0].provenance.evidence_location}")
        enriched.append(replace(message, **updates) if updates else message)
    ctx.messages = enriched


def content_texts(content: Any, pointer: str) -> tuple[list[tuple[str, str]], bool]:
    texts: list[tuple[str, str]] = []
    partial = False
    if not isinstance(content, list):
        return texts, content is not None
    for index, item in enumerate(content):
        if not isinstance(item, dict):
            partial = True
            continue
        if item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                texts.append((text, f"{pointer}/{index}/text"))
            else:
                partial = True
    return texts, partial


def version_texts(version: Mapping[str, Any], pointer: str) -> tuple[list[tuple[str, str]], bool]:
    texts, partial = content_texts(version.get("content"), f"{pointer}/content")
    steps = version.get("steps")
    if isinstance(steps, list):
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                partial = True
                continue
            found, was_partial = content_texts(step.get("content"), f"{pointer}/steps/{index}/content")
            texts.extend(found)
            partial = partial or was_partial
    elif steps is not None:
        partial = True
    return texts, partial


@dataclass
class ConversationSummary:
    artifact: ArtifactRecord
    conversation_id: str
    title: str
    empty_initial: bool
    user_facts: list[ObservedFact] = field(default_factory=list)
    assistant_facts: list[ObservedFact] = field(default_factory=list)
    generation_facts: list[ObservedFact] = field(default_factory=list)
    retry_facts: list[ObservedFact] = field(default_factory=list)
    edited_facts: list[ObservedFact] = field(default_factory=list)
    attachment_links: list[ObservedFact] = field(default_factory=list)
    model_identifiers: set[str] = field(default_factory=set)


def parse_conversations(ctx: AnalysisContext) -> list[ConversationSummary]:
    summaries: list[ConversationSummary] = []
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or not basename(artifact.path).lower().endswith(".conversation.json"):
            continue
        if not isinstance(data, dict):
            ctx.issue("conversation_wrong_type", artifact.path, "conversation root가 object가 아님")
            continue
        conv_id = resolve_conversation_id(ctx, artifact, data)
        title = as_string(data.get("name"))
        messages = data.get("messages")
        if not isinstance(messages, list):
            ctx.issue("conversation_messages_wrong_type", artifact.path, "messages가 array가 아님")
            continue
        empty_initial = (
            len(messages) == 0
            and data.get("tokenCount") == 0
            and data.get("clientInput") in ("", None)
            and data.get("name") in (None, "")
        )
        summary = ConversationSummary(artifact, conv_id, title, empty_initial)
        role_indexes: dict[str, list[int]] = defaultdict(list)
        for index, raw_message in enumerate(messages):
            if not isinstance(raw_message, dict) or not isinstance(raw_message.get("versions"), list):
                continue
            if any(isinstance(version, dict) and version.get("role") in {"user", "assistant", "tool"} for version in raw_message["versions"]):
                for role_name in {version.get("role") for version in raw_message["versions"] if isinstance(version, dict)}:
                    if role_name in {"user", "assistant", "tool"}:
                        role_indexes[str(role_name)].append(index)
        last_user_index = max(role_indexes.get("user", [-1]))
        last_assistant_index = max(role_indexes.get("assistant", [-1]))
        historical = artifact.metadata.get("history_kind") == "history_delete"
        last_model = None if historical else data.get("lastUsedModel")
        if isinstance(last_model, dict):
            for key in ("identifier", "indexedModelIdentifier"):
                value = last_model.get(key)
                if isinstance(value, str) and value:
                    summary.model_identifiers.add(value)
                    fact = ObservedFact("conversation_model", "conversation_state", artifact_provenance(artifact, f"/lastUsedModel/{key}"), value, key=f"/lastUsedModel/{key}", conversation_ref=conv_id)
                    ctx.add_fact(fact)
        for mi, message in enumerate(messages):
            if not isinstance(message, dict):
                ctx.issue("conversation_message_wrong_type", artifact.path, f"message {mi}가 object가 아님")
                continue
            versions = message.get("versions")
            if not isinstance(versions, list):
                ctx.issue("conversation_versions_wrong_type", artifact.path, f"message {mi} versions가 array가 아님")
                continue
            selected = message.get("currentlySelected")
            version_has_text: list[bool] = []
            version_roles: list[str] = []
            for vi, version in enumerate(versions):
                if not isinstance(version, dict):
                    ctx.issue("conversation_version_wrong_type", artifact.path, f"message {mi} version {vi}가 object가 아님")
                    continue
                role = as_string(version.get("role"))
                version_roles.append(role)
                # Preserve other observed roles too; only known roles create
                # user/assistant-specific Facts and role-last time fallbacks.
                pointer = f"/messages/{mi}/versions/{vi}"
                texts, partial = version_texts(version, pointer)
                version_has_text.append(bool(texts))
                message_id = explicit_identifier(message, ("messageId",))
                parent_id = explicit_identifier(message, ("parentMessageId",))
                ts = message_timestamp(message, version)
                # Retry root timestamps do not identify an individual version.
                # Research establishes role-last timestamps, not per-retry time.
                if ts is None and len(versions) == 1:
                    if role == "user" and mi == last_user_index:
                        ts = iso_from_epoch_ms(data.get("userLastMessagedAt"), "user_message_event")
                    elif role == "assistant" and mi == last_assistant_index:
                        ts = iso_from_epoch_ms(data.get("assistantLastMessagedAt"), "assistant_message_event")
                for text_value, location in texts:
                    row_ts = row_timestamp(message, version, pointer, location) or ts
                    ctx.messages.append(RecoveredMessage(
                        conv_id, title, message_id, parent_id, mi + 1, role, text_value, row_ts,
                        "부분 복구" if partial else "복구됨", artifact.path, location,
                        title_source=f"{artifact.path}:/name" if title else "",
                        message_id_source=f"/messages/{mi}/messageId" if message_id else "",
                        parent_id_source=f"/messages/{mi}/parentMessageId" if parent_id else "",
                        timestamp_source=row_ts.semantics if row_ts else "",
                    ))
                if not texts:
                    has_structured_content = isinstance(version.get("content"), list) or isinstance(version.get("steps"), list)
                    if has_structured_content:
                        ctx.messages.append(RecoveredMessage(
                            conv_id, title, message_id, parent_id, mi + 1, role, "", ts,
                            "부분 복구" if partial else "메타데이터만", artifact.path, pointer,
                        ))
                prov = artifact_provenance(artifact, pointer)
                if role == "user" and texts:
                    msg_ts = ts
                    fact = ObservedFact("user_message", "conversation_state", prov, texts[0][0], key=pointer, timestamp=msg_ts, conversation_ref=conv_id, message_ref=message_id)
                    summary.user_facts.append(fact)
                    ctx.add_fact(fact)
                if role == "assistant" and texts:
                    msg_ts = ts
                    fact = ObservedFact("assistant_response", "conversation_state", prov, "assistant text present", key=pointer, timestamp=msg_ts, conversation_ref=conv_id)
                    summary.assistant_facts.append(fact)
                    ctx.add_fact(fact)
                generation_keys = {"modelInfo", "stats", "generationInfo", "stopReason", "loadModelConfig"}
                steps = version.get("steps")
                if role == "assistant" and (
                    isinstance(steps, list) and len(steps) > 0
                    or any(key in version for key in generation_keys)
                ):
                    fact = ObservedFact("generation_metadata", "conversation_state", prov, "generation metadata present", key=pointer, conversation_ref=conv_id)
                    summary.generation_facts.append(fact)
                    ctx.add_fact(fact)
                edited = version.get("edited") is True or message.get("edited") is True
                if role == "user" and edited:
                    fact = ObservedFact("explicit_message_edit", "conversation_state", prov, "edited marker true", key=pointer, direct_tag="explicit_edited_marker", conversation_ref=conv_id)
                    summary.edited_facts.append(fact)
                    ctx.add_fact(fact)
                content = version.get("content")
                if isinstance(content, list):
                    for ci, item in enumerate(content):
                        if not isinstance(item, dict) or item.get("type") not in {"file", "image"}:
                            continue
                        identifier = as_string(item.get("fileIdentifier"))
                        file_type = as_string(item.get("fileType"))
                        if not identifier:
                            continue
                        link_value = safe_fingerprint(identifier)
                        link_prov = artifact_provenance(artifact, f"{pointer}/content/{ci}/fileIdentifier")
                        fact = ObservedFact("conversation_attachment", "conversation_state", link_prov, link_value, key=file_type, conversation_ref=conv_id)
                        summary.attachment_links.append(fact)
                        ctx.add_fact(fact)
            assistant_versions = [index for index, role in enumerate(version_roles) if role == "assistant"]
            assistant_text_count = sum(1 for index in assistant_versions if index < len(version_has_text) and version_has_text[index])
            if len(assistant_versions) >= 2 and assistant_text_count >= 2 and isinstance(selected, int) and selected > 0:
                prov = artifact_provenance(artifact, f"/messages/{mi}")
                fact = ObservedFact("assistant_retry_structure", "conversation_state", prov, str(len(assistant_versions)), key=f"/messages/{mi}/versions", conversation_ref=conv_id)
                summary.retry_facts.append(fact)
                ctx.add_fact(fact)
        if not historical:
            summaries.append(summary)
    return summaries


def parse_conversation_configs(ctx: AnalysisContext) -> dict[str, list[ObservedFact]]:
    selections: dict[str, list[ObservedFact]] = defaultdict(list)
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or basename(artifact.path).lower() != "conversation-config.json" or not isinstance(data, dict):
            continue
        for key in ("selectedConversation", "newChatConversationIdentifier"):
            value = data.get(key)
            if isinstance(value, str) and value:
                name = basename(value).lower()
                fact = ObservedFact("conversation_selected", "conversation_state", artifact_provenance(artifact, f"/{key}"), "selected", key=f"/{key}", target_path=value, conversation_ref=value)
                selections[name].append(fact)
                ctx.add_fact(fact)
    return selections


@dataclass
class AttachmentSummary:
    artifact: ArtifactRecord
    media: str
    original_name: str
    identifier_fingerprint: str
    fact: ObservedFact


def classify_attachment(mime_or_type: str, original_name: str) -> str:
    low_type = mime_or_type.lower()
    suffix = Path(original_name).suffix.lower()
    if low_type.startswith("image/") or suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}:
        return "image"
    if low_type in {"application/pdf", "text/plain", "application/msword"} or suffix in {".pdf", ".txt", ".doc", ".docx", ".rtf", ".odt"}:
        return "document"
    return ""


def parse_attachments(ctx: AnalysisContext) -> list[AttachmentSummary]:
    result: list[AttachmentSummary] = []
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or not basename(artifact.path).lower().endswith(".metadata.json") or not isinstance(data, dict):
            continue
        original = as_string(data.get("originalName"))
        identifier = as_string(data.get("fileIdentifier"))
        mime = as_string(data.get("type")) or as_string(data.get("mime")) or as_string(data.get("mimeType"))
        size = data.get("sizeBytes")
        sha = data.get("sha256Hex") or data.get("sha256")
        media = classify_attachment(mime, original)
        semantic_count = sum((bool(original), bool(identifier), isinstance(size, int), isinstance(sha, str) and bool(sha), bool(media)))
        if not media or semantic_count < 3:
            continue
        fp = safe_fingerprint(identifier) if identifier else ""
        fact = ObservedFact(
            f"{media}_metadata", "attachment", artifact_provenance(artifact, "/"),
            safe_nonconversation_text(original, max_length=200), key=fp, target_path=artifact.path,
        )
        ctx.add_fact(fact)
        result.append(AttachmentSummary(artifact, media, original, fp, fact))
    return result


# ---------------------------------------------------------------------------
# 8. Model, download, export, application, and runtime observations
# ---------------------------------------------------------------------------

@dataclass
class ModelLoadSummary:
    identifier: str
    fact: ObservedFact
    timestamp: TimestampValue | None


def parse_model_data(ctx: AnalysisContext) -> list[ModelLoadSummary]:
    result: list[ModelLoadSummary] = []
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or basename(artifact.path).lower() != "model-data.json" or not isinstance(data, dict):
            continue
        pairs = data.get("json")
        if not isinstance(pairs, list):
            ctx.issue("model_data_wrong_type", artifact.path, "model-data json field가 array가 아님")
            continue
        for index, pair in enumerate(pairs):
            if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) or not isinstance(pair[1], dict):
                continue
            identifier = pair[0]
            state = pair[1]
            loaded = iso_from_epoch_ms(state.get("lastLoadedTimestamp"), "model_last_loaded")
            attempted = iso_from_epoch_ms(state.get("lastAttemptedToLoadTimestamp"), "model_load_attempt")
            timestamp = loaded or attempted
            if not identifier or timestamp is None:
                continue
            location = f"/json/{index}/1/" + ("lastLoadedTimestamp" if loaded else "lastAttemptedToLoadTimestamp")
            fact = ObservedFact("model_loaded_state", "model_state", artifact_provenance(artifact, location), identifier, key=location, timestamp=timestamp)
            ctx.add_fact(fact)
            result.append(ModelLoadSummary(identifier, fact, timestamp))
    return result


def nested_download_values(node: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(node)
    for key in ("request", "download", "downloadRequest", "jobState", "status"):
        value = node.get(key)
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                merged.setdefault(nested_key, nested_value)
                merged.setdefault(f"{key}.{nested_key}", nested_value)
    return merged


def download_statuses(mapping: Mapping[str, Any]) -> set[str]:
    statuses: set[str] = set()
    for key in ("status", "state", "type", "endReason", "jobState.type", "status.type", "status.endReason", "download.status"):
        value = mapping.get(key)
        if isinstance(value, str) and value:
            statuses.add(value.lower())
    return statuses


@dataclass
class DownloadSummary:
    target: str
    completed: bool
    fact: ObservedFact
    timestamp: TimestampValue | None
    completion_timestamp: TimestampValue | None = None
    start_timestamp: TimestampValue | None = None


def download_node_summary(node: Mapping[str, Any]) -> tuple[str, bool, int, TimestampValue | None]:
    merged = nested_download_values(node)
    _, target = first_scalar(merged, ("filename", "targetPath", "savePath", "filePath", "path", "subpath", "modelName", "model", "name"))
    if not target:
        for value in merged.values():
            if isinstance(value, str) and ".gguf" in value.lower():
                target = value
                break
    _, explicit_model = first_scalar(merged, ("modelName", "model"))
    model_context = ".gguf" in target.lower() or bool(explicit_model)
    if not model_context:
        return "", False, 0, None
    statuses = download_statuses(merged)
    complete_words = {"completed"}
    failure_words = {"failed", "error", "cancelled", "canceled", "aborted"}
    completed = bool(statuses & complete_words) and not bool(statuses & failure_words)
    semantic = 1
    if statuses:
        semantic += 1
    if any(isinstance(merged.get(key), (int, float)) for key in ("fileSizeBytes", "totalSizeBytes", "downloadedSizeBytes", "sizeBytes", "size")):
        semantic += 1
    if any(isinstance(merged.get(key), str) and merged.get(key) for key in ("sha256", "sha256Hex", "hash")):
        semantic += 1
    if any(isinstance(merged.get(key), str) and merged.get(key) for key in ("targetPath", "savePath", "subpath")):
        semantic += 1
    # Research jobs/maps contain startedTimestamp, but no verified completion field.
    timestamp = None if completed else iso_from_epoch_ms(merged.get("startedTimestamp"), "download_started")
    return basename(target) or target, completed, semantic, timestamp


def parse_downloads(ctx: AnalysisContext) -> list[DownloadSummary]:
    result: list[DownloadSummary] = []
    seen: set[tuple[str, str, bool]] = set()
    for artifact_id, data in sorted(ctx.parsed_json.items()):
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or basename(artifact.path).lower() not in {"download-jobs-info.json", "single-downloads-info.json"}:
            continue
        nodes: list[tuple[Mapping[str, Any], str, TimestampValue | None]] = []
        if isinstance(data, dict):
            jobs = data.get("jobs")
            if isinstance(jobs, list):
                for ji, job in enumerate(jobs):
                    if not isinstance(job, dict):
                        continue
                    job_ts = iso_from_epoch_ms(job.get("startedTimestamp"), "download_started")
                    tasks = job.get("tasks")
                    if isinstance(tasks, list):
                        for ti, task in enumerate(tasks):
                            if isinstance(task, dict):
                                merged = dict(task)
                                merged["startedTimestamp"] = job.get("startedTimestamp")
                                merged["jobState"] = job.get("jobState")
                                if "completedTimestamp" in job and "completedTimestamp" not in merged:
                                    merged["completedTimestamp"] = job["completedTimestamp"]
                                nodes.append((merged, f"/jobs/{ji}/tasks/{ti}", job_ts))
            for map_key in ("endedDownloadsMap", "downloadsMap"):
                entries = data.get(map_key)
                if isinstance(entries, list):
                    for index, pair in enumerate(entries):
                        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[1], dict):
                            nodes.append((pair[1], f"/{map_key}/{index}/1", None))
            # Version-tolerant fallback: explicit aliases, still gated by GGUF context and semantic fields.
            if not nodes:
                for pointer, _, value in recursive_items(data):
                    if isinstance(value, dict):
                        nodes.append((value, pointer, None))
        for node, pointer, inherited_ts in nodes:
            target, completed, semantic, timestamp = download_node_summary(node)
            if not target or semantic < 2:
                continue
            key = (artifact.path, target.lower(), completed)
            if key in seen:
                continue
            seen.add(key)
            fact_type = "download_completed_record" if completed else "download_attempt_record"
            event_ts = timestamp if completed else timestamp or inherited_ts
            fact = ObservedFact(fact_type, "model_state", artifact_provenance(artifact, pointer), target, key=pointer, timestamp=event_ts, target_path=target)
            ctx.add_fact(fact)
            # Event-only time sources: do not replace the completed-record Fact's
            # time with a start time or alter any evidence/decision condition.
            values = nested_download_values(node)
            completion_value = values.get("completedTimestamp")
            completion = (iso_from_epoch_ms(completion_value, "download_completed")
                          if isinstance(completion_value, (int, float))
                          else iso_from_datetime(completion_value, "download_completed"))
            start = iso_from_epoch_ms(values.get("startedTimestamp"), "download_started") or inherited_ts
            result.append(DownloadSummary(target, completed, fact, event_ts, completion, start))
    return result


def parse_zone_identifiers(ctx: AnalysisContext) -> list[ObservedFact]:
    result: list[ObservedFact] = []
    for artifact in sorted(ctx.artifacts, key=lambda a: a.path.lower()):
        if artifact.content is None or not artifact.path.lower().endswith(":zone.identifier"):
            continue
        try:
            text = artifact.content.decode("utf-8-sig", errors="replace")
        except UnicodeError:
            continue
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"ZoneId", "HostUrl", "ReferrerUrl"}:
                fields[key] = value.strip()
        if not fields:
            continue
        hosts = []
        for key in ("HostUrl", "ReferrerUrl"):
            summary = safe_url_summary(fields.get(key, ""))
            if summary:
                try:
                    hosts.append(urlsplit(summary).hostname or "")
                except ValueError:
                    pass
        value = "ZoneId present"
        if hosts:
            value += "; origin=" + ",".join(sorted(set(hosts)))
        fact = ObservedFact("zone_identifier", "final_file", artifact_provenance(artifact), value, target_path=artifact.path.removesuffix(":Zone.Identifier"))
        ctx.add_fact(fact)
        result.append(fact)
    return result


def export_signature(text: str) -> bool:
    matched = sum(1 for pattern in LM_EXPORT_SIGNATURES if pattern.search(text))
    roles = bool(re.search(r"(?im)^#{1,4}\s*(?:User|Assistant)\b|\*\*(?:User|Assistant)\*\*", text))
    lm_marker = "lm studio" in text.lower()
    return matched >= 2 or (roles and lm_marker)


def parse_exports(ctx: AnalysisContext) -> list[ObservedFact]:
    result = []
    for artifact in sorted(ctx.artifacts, key=lambda a: a.path.lower()):
        if artifact.content is None or not basename(artifact.path).lower().endswith(".md"):
            continue
        try:
            text = artifact.content.decode("utf-8-sig", errors="replace")
        except UnicodeError:
            continue
        if not export_signature(text):
            continue
        fact = ObservedFact("lmstudio_export", "final_file", artifact_provenance(artifact), basename(artifact.path), timestamp=artifact.created, target_path=artifact.path)
        ctx.add_fact(fact)
        result.append(fact)
    return result


@dataclass
class RuntimeObservations:
    install_files: list[ObservedFact] = field(default_factory=list)
    install_os: list[ObservedFact] = field(default_factory=list)
    runtime: list[ObservedFact] = field(default_factory=list)
    prefetch: list[ObservedFact] = field(default_factory=list)
    ui_flush: list[ObservedFact] = field(default_factory=list)
    residue: list[ObservedFact] = field(default_factory=list)


def parse_runtime_and_application(ctx: AnalysisContext) -> RuntimeObservations:
    result = RuntimeObservations()
    for artifact in sorted(ctx.artifacts, key=lambda a: a.path.lower()):
        lp = lower_path(artifact.path)
        name = basename(artifact.path).lower()
        prov = artifact_provenance(artifact)
        if name == "lm studio.exe" and "\\programs\\lm studio\\" in lp:
            fact = ObservedFact("application_binary", "filesystem", prov, "LM Studio.exe", timestamp=artifact.created, target_path=artifact.path)
            ctx.add_fact(fact); result.install_files.append(fact)
        elif name.endswith(".lnk") and "lm studio" in name:
            fact = ObservedFact("application_shortcut", "windows_os", prov, name, timestamp=artifact.created, target_path=artifact.path)
            ctx.add_fact(fact); result.install_os.append(fact)
        elif name in {"installer.exe", "unins000.exe", "uninstall lm studio.exe"} or "lm-studio-updater" in lp:
            fact = ObservedFact("application_installer", "windows_os", prov, name, timestamp=artifact.created, target_path=artifact.path)
            ctx.add_fact(fact); result.install_os.append(fact)
        if name.endswith(".pf") and "lm studio" in name:
            fact = ObservedFact("application_prefetch", "windows_os", prov, name, timestamp=artifact.modified, direct_tag="lmstudio_prefetch_execution", target_path=artifact.path)
            ctx.add_fact(fact); result.prefetch.append(fact)
        if name.endswith(".log") and "server-logs" in lp:
            fact = ObservedFact("server_log_artifact", "lmstudio_log", prov, name, timestamp=artifact.modified, target_path=artifact.path)
            ctx.add_fact(fact); result.runtime.append(fact)
        if name == "http-server.json":
            fact = ObservedFact("http_server_runtime", "filesystem", prov, "http-server state present", timestamp=artifact.modified, target_path=artifact.path)
            ctx.add_fact(fact); result.runtime.append(fact); result.residue.append(fact)
        if name == "llmster-pid.lock":
            fact = ObservedFact("pid_lock_runtime", "filesystem", prov, "pid lock present", timestamp=artifact.modified, target_path=artifact.path)
            ctx.add_fact(fact); result.residue.append(fact)
    global_states: list[tuple[ArtifactRecord, dict[str, Any]]] = []
    window_states: list[tuple[ArtifactRecord, dict[str, Any]]] = []
    for artifact_id, data in ctx.parsed_json.items():
        artifact = artifact_for_id(ctx, artifact_id)
        if artifact is None or not isinstance(data, dict):
            continue
        name = basename(artifact.path).lower()
        if name == "global.json":
            global_states.append((artifact, data))
        elif re.fullmatch(r"window-\d+\.json", name):
            window_states.append((artifact, data))
    for artifact, data in global_states:
        if data.get("openedTabs") == [] and data.get("selectedTabIndex") is None and data.get("openedWindowKeys") == []:
            fact = ObservedFact("ui_final_state_flush", "runtime_state", artifact_provenance(artifact, "/openedTabs"), "closed UI state persisted", timestamp=artifact.modified)
            ctx.add_fact(fact); result.ui_flush.append(fact)
    for artifact, data in window_states:
        chat = data.get("chat")
        if isinstance(chat, dict) and chat.get("activeConversationIdentifier") is None:
            fact = ObservedFact("ui_conversation_cleared", "runtime_state", artifact_provenance(artifact, "/chat/activeConversationIdentifier"), "active conversation cleared", timestamp=artifact.modified)
            ctx.add_fact(fact); result.ui_flush.append(fact)
    for fact in ctx.facts:
        if fact.fact_type == "http_server_runtime":
            result.runtime.append(fact)
            result.residue.append(fact)
        elif fact.fact_type == "pid_lock_runtime":
            result.residue.append(fact)
    return result


# ---------------------------------------------------------------------------
# 9. Evidence-family decision engine and 21 detectors
# ---------------------------------------------------------------------------

def choose_timestamp(facts: Sequence[ObservedFact], preferred: TimestampValue | None = None) -> TimestampValue | None:
    if preferred is not None:
        return preferred
    timestamps = [fact.timestamp for fact in facts if fact.timestamp is not None and fact.timestamp.normalized]
    if not timestamps:
        return None
    return sorted(timestamps, key=lambda item: (item.normalized, item.semantics, item.raw))[0]


def source_identity(fact: ObservedFact) -> tuple[str, str, str]:
    prov = fact.provenance
    path = lower_path(prov.original_artifact_path)
    source = prov.lineage_key or path
    if prov.lineage_key.startswith("record:"):
        return lower_path(prov.source_image), prov.lineage_key, ""
    location = prov.evidence_location
    # JSON pointers are fields of one source, not independent records. Logs,
    # journals, CSV and databases expose actual record boundaries instead.
    record = ""
    if not path.endswith((".json", ".md")):
        match = re.search(r"(?:line \d+|(?:\w+ )?rowid \d+|record \d+|offset 0x[0-9a-f]+|USN[^;]*|MFT[^;]*)", location, re.I)
        if match:
            record = match.group(0).lower()
    return lower_path(prov.source_image), source, record


def evaluate_decision(
    rule: RuleDefinition,
    facts: Sequence[ObservedFact],
    *,
    conflict: bool = False,
    forced: str | None = None,
) -> tuple[str, bool, set[str]]:
    families = {fact.family for fact in facts if fact.family}
    direct = any(fact.direct_tag and fact.direct_tag in rule.direct_evidence for fact in facts)
    if conflict:
        return "indeterminate", direct, families
    if forced is not None:
        return forced, direct, families
    independent = any(
        left.family != right.family and source_identity(left) != source_identity(right)
        for i, left in enumerate(facts) for right in facts[i + 1:]
        if left.family and right.family
    )
    if direct or independent:
        return "confirmed", direct, families
    if facts:
        return rule.default_decision, direct, families
    return "indeterminate", direct, families


def add_candidate(
    ctx: AnalysisContext,
    action: str,
    facts: Sequence[ObservedFact],
    conditions: Sequence[str],
    detail: str,
    *,
    timestamp: TimestampValue | None = None,
    conversation_ref: str = "",
    limitation: str = "",
    conflict: bool = False,
    forced: str | None = None,
    infer_timestamp: bool = True,
) -> None:
    if not facts:
        return
    rule = RULES[action]
    status, direct, families = evaluate_decision(rule, facts, conflict=conflict, forced=forced)
    safe_detail = safe_nonconversation_text(detail, max_length=500)
    candidate = CandidateEvent(
        rule.event_type, action, rule.rule_id, rule.korean,
        sorted(set(conditions)), list(facts), families, direct, status,
        safe_detail, limitation, choose_timestamp(facts, timestamp) if infer_timestamp else timestamp, conversation_ref, conflict,
    )
    ctx.candidates.append(candidate)


def detail_subject(title: str, conversation_id: str = "") -> str:
    return safe_nonconversation_text(title or conversation_id, max_length=160)


def first_prompt_line(text: str) -> str:
    line = text.splitlines()[0] if text.splitlines() else ""
    return safe_nonconversation_text(line[:100], max_length=100)


def history_for_name(ctx: AnalysisContext, name: str, kinds: set[str]) -> list[ObservedFact]:
    low = name.lower()
    return [fact for fact in ctx.facts if fact.fact_type in kinds and basename(fact.target_path).lower() == low]


def exact_history(ctx: AnalysisContext, path: str, kinds: set[str]) -> list[ObservedFact]:
    target = lower_path(path)
    result = []
    for fact in ctx.facts:
        if fact.fact_type not in kinds:
            continue
        observed = lower_path(fact.target_path)
        source = lower_path(fact.provenance.original_artifact_path)
        volume = re.match(r"^(volume\d+:)\\", source)
        if volume and not re.match(r"^(?:[a-z]:|volume\d+:)", observed):
            observed = volume.group(1) + "\\" + observed.lstrip("\\")
        if observed == target:
            result.append(fact)
    return result


def unambiguous_history_time(facts: Sequence[ObservedFact]) -> TimestampValue | None:
    times = {f.timestamp.normalized: f.timestamp for f in facts if f.timestamp and f.timestamp.normalized}
    return next(iter(times.values())) if len(times) == 1 else None


def detect_snapshot_transitions(ctx: AnalysisContext, before: AnalysisContext) -> None:
    """Explicit caller-supplied Before -> After, never ordered by folder labels."""
    state_types = {"account_logged_in_state", "account_profile_state", "credential_present_state",
                   "account_status_state", "account_reset_state"}
    old = [f for f in before.facts if f.fact_type in state_types]
    new = [f for f in ctx.facts if f.fact_type in state_types]
    old_ids = {f.value for f in old if f.fact_type == "account_profile_state" and f.value.startswith("sha256:")}
    new_ids = {f.value for f in new if f.fact_type == "account_profile_state" and f.value.startswith("sha256:")}
    old_logged = any(f.fact_type == "account_logged_in_state" for f in old)
    new_logged = any(f.fact_type == "account_logged_in_state" for f in new)
    old_reset = any(f.fact_type == "account_reset_state" for f in old)
    new_reset = any(f.fact_type == "account_reset_state" for f in new)
    # An input containing several profile snapshots has no implicit ordering.
    profiles = [[f for f in facts if f.fact_type == "account_profile_state"] for facts in (old, new)]
    action = ""
    if all(len(group) <= 1 for group in profiles):
        if old_logged and new_logged and len(old_ids) == len(new_ids) == 1 and old_ids != new_ids:
            action = "account_switch"
        elif old_logged and not new_logged and new_reset:
            action = "logout"
        elif old_reset and not old_logged and new_logged:
            action = "login"
    if action and len({f.provenance.original_artifact_path for f in old}) >= 2 and len({f.provenance.original_artifact_path for f in new}) >= 2:
        history = [h for f in new for h in exact_history(ctx, f.provenance.original_artifact_path, {"history_create", "history_modify", "history_delete"})]
        ctx.candidates = [c for c in ctx.candidates if c.action != action]
        add_candidate(ctx, action, old + new + history, ["explicit Before/After account state", "actual identifier change" if action == "account_switch" else "coordinated state transition"],
                      f"{RULES[action].korean}_Before→After 실제 계정 상태 변화", timestamp=unambiguous_history_time(history), infer_timestamp=False,
                      forced=None if history else "suspected")
    before_by_id: dict[str, list[RecoveredMessage]] = defaultdict(list)
    after_by_id: dict[str, list[RecoveredMessage]] = defaultdict(list)
    for messages, grouped in ((before.messages, before_by_id), (ctx.messages, after_by_id)):
        for message in messages:
            if message.conversation_id:
                grouped[message.conversation_id].append(message)
    for identifier in sorted(before_by_id.keys() & after_by_id.keys()):
        old_messages, new_messages = before_by_id[identifier], after_by_id[identifier]
        if len({m.artifact_path for m in old_messages}) != 1 or len({m.artifact_path for m in new_messages}) != 1:
            continue
        old_users = [m for m in old_messages if m.role == "user" and m.content]
        new_users = [m for m in new_messages if m.role == "user" and m.content]
        if not old_users or len(new_users) >= len(old_users):
            continue
        path = new_messages[0].artifact_path
        history = exact_history(ctx, path, {"history_modify"})
        if not history:
            continue
        evidence = [ObservedFact("before_user_message", "conversation_state", Provenance(before.source_image, old_users[0].artifact_path, "", old_users[0].location), "actual Before user content", conversation_ref=identifier),
                    ObservedFact("after_user_removed", "conversation_state", Provenance(ctx.source_image, path, "", "/messages"), "fewer user rows in explicit After", conversation_ref=identifier)]
        ctx.candidates = [c for c in ctx.candidates if not (c.action == "prompt_delete" and c.conversation_ref == identifier)]
        add_candidate(ctx, "prompt_delete", evidence + history, ["Before user content", "After user removal", "exact conversation rewrite"],
                      "사용자 메시지 삭제_Before→After 실제 user message 감소 및 rewrite", conversation_ref=identifier,
                      timestamp=unambiguous_history_time(history), infer_timestamp=False)


def currently_observed_names(ctx: AnalysisContext) -> set[str]:
    names = {basename(artifact.path).lower() for artifact in ctx.artifacts if artifact.kind not in {"csv", "db"} and artifact.metadata.get("history_kind") != "history_delete"}
    for fact in ctx.facts:
        source = lower_path(fact.provenance.original_artifact_path)
        if fact.fact_type == "history_observed" and ("\\mftecmd\\" in source or "\\filesystem\\" in source):
            name = basename(fact.target_path).lower()
            if name:
                names.add(name)
    return names


def detect_accounts(ctx: AnalysisContext, states: dict[str, list[ObservedFact]], logs: list[ObservedFact]) -> None:
    login_logs = [fact for fact in logs if fact.fact_type == "account_login_log"]
    logout_logs = [fact for fact in logs if fact.fact_type == "account_logout_log"]
    switch_logs = [fact for fact in logs if fact.fact_type == "account_switch_log"]
    logged_sources = {fact.provenance.original_artifact_path.lower() for fact in states["logged_in"]}
    reset_sources = {fact.provenance.original_artifact_path.lower() for fact in states["reset"]}
    if len(logged_sources) >= 2:
        facts = states["logged_in"] + login_logs
        identifiers = sorted({fact.value for fact in states["profile"] if fact.value.startswith("sha256:")})
        subject = identifiers[0] if identifiers else "계정 상태 확인"
        add_candidate(ctx, "login", facts, ["복수 account state 일치"], f"로그인 상태 전환_{subject}")
    elif any(f.direct_tag == "explicit_login_log" for f in login_logs):
        add_candidate(ctx, "login", [f for f in login_logs if f.direct_tag], ["explicit login event record"], "명시적 로그인 성공 로그")
    if len(reset_sources) >= 2:
        facts = states["reset"] + logout_logs
        forced = None if logout_logs else "indeterminate"
        add_candidate(ctx, "logout", facts, ["복수 account artifact coordinated reset"], "계정 인증 상태 초기화_null/reset 상태 확인", limitation="현재 reset 상태만으로 초기 비로그인과 로그아웃을 완전히 구분할 수 없음" if not logout_logs else "", forced=forced)
    elif any(f.direct_tag == "explicit_logout_log" for f in logout_logs):
        add_candidate(ctx, "logout", [f for f in logout_logs if f.direct_tag], ["explicit logout event record"], "명시적 로그아웃 성공 로그")
    if switch_logs:
        add_candidate(ctx, "account_switch", switch_logs + states["profile"], ["account switch wording in scoped log"], "계정 전환 의심_로그 문구; Before→After 식별자 변화 미확인", forced="suspected")


def detect_application(ctx: AnalysisContext, runtime: RuntimeObservations, logs: list[ObservedFact]) -> None:
    create_history = [f for f in ctx.facts if f.fact_type == "history_create" and "\\programs\\lm studio" in lower_path(f.target_path)]
    created_exe = [f for f in create_history if basename(f.target_path).lower() == "lm studio.exe"]
    created_os = [f for f in ctx.facts if f.fact_type == "history_create" and (basename(f.target_path).lower().endswith(".lnk") or "lm-studio-updater" in lower_path(f.target_path) or "unins" in basename(f.target_path).lower())]
    if runtime.install_files:
        facts = runtime.install_files + runtime.install_os + create_history
        if runtime.install_os or create_history:
            install_path = str(PureWindowsPath(runtime.install_files[0].target_path).parent)
            add_candidate(ctx, "application_install", facts, ["LM Studio executable 존재", "설치/OS 보강 artifact"], f"LM Studio 설치_{install_path}", forced=None if created_exe else "suspected", timestamp=choose_timestamp(created_exe), infer_timestamp=False)
    elif created_exe:
        target_parent = str(PureWindowsPath(created_exe[0].target_path).parent)
        os_facts = created_os + runtime.install_os
        add_candidate(ctx, "application_install", created_exe + os_facts, ["LM Studio program files 생성", "shortcut/updater 생성" if os_facts else "filesystem install structure"], f"LM Studio 설치_{target_parent}")
    delete_history = [f for f in ctx.facts if f.fact_type == "history_delete" and "\\programs\\lm studio" in lower_path(f.target_path)]
    core_delete = [f for f in delete_history if basename(f.target_path).lower() in {"lm studio.exe", "unins000.exe", "uninstall lm studio.exe"}]
    shortcut_delete = [f for f in ctx.facts if f.fact_type == "history_delete" and basename(f.target_path).lower().endswith(".lnk") and "lm studio" in basename(f.target_path).lower()]
    uninstaller_evidence = [f for f in ctx.facts if f.direct_tag == "explicit_uninstaller_execution"]
    if core_delete and (shortcut_delete or uninstaller_evidence or len(delete_history) >= 10):
        residual = any("\\.lmstudio\\" in lower_path(a.path) for a in ctx.artifacts)
        detail = "LM Studio 제거_Program 설치 구성요소 삭제; 사용자 데이터 잔존 여부=" + ("잔존" if residual else "확인되지 않음")
        facts = core_delete + shortcut_delete + uninstaller_evidence
        forced = None if (shortcut_delete or uninstaller_evidence) else "suspected"
        add_candidate(ctx, "application_uninstall", facts, ["core program component 실제 삭제", "shortcut/uninstaller 보강" if shortcut_delete or uninstaller_evidence else "mass component deletion"], detail, forced=forced)
    launch_logs = [f for f in logs if f.fact_type in {"server_inference", "model_load_log"}]
    history_runtime = [f for f in ctx.facts if f.fact_type in {"history_create", "history_observed", "history_modify"} and basename(f.target_path).lower() in {"http-server.json", "server-logs-state.json"}]
    launch_start = len(ctx.candidates)
    if runtime.prefetch:
        add_candidate(ctx, "application_launch", runtime.prefetch + runtime.runtime + launch_logs, ["Windows execution artifact", "LM Studio runtime context"], "LM Studio 실행 흔적_Prefetch 및 runtime/server 근거")
    elif len(runtime.runtime) >= 2 or (runtime.runtime and launch_logs):
        add_candidate(ctx, "application_launch", runtime.runtime + launch_logs, ["복수 runtime/server 양성 흔적"], "LM Studio 실행 흔적_runtime/server 상태", forced="suspected")
    elif len({basename(f.target_path).lower() for f in history_runtime}) >= 2:
        add_candidate(ctx, "application_launch", history_runtime, ["복수 runtime/server filesystem 흔적"], "LM Studio 실행 흔적_runtime/server filesystem 상태", forced="suspected")
    # Only already-created E08-01 events receive this timestamp selection.
    # Facts, direct tags, families, and decision status remain untouched.
    for candidate in ctx.candidates[launch_start:]:
        direct_time = choose_timestamp([f for f in launch_logs if f.timestamp and f.timestamp.verified_unit])
        if direct_time:
            candidate.timestamp = direct_time
        elif not format_timestamp_kst(candidate.timestamp):
            sources = {lower_path(f.provenance.original_artifact_path) for f in candidate.facts
                       if f.fact_type in {"application_prefetch", "server_log_artifact", "http_server_runtime"}}
            fallback = []
            for artifact in ctx.artifacts:
                if lower_path(artifact.path) not in sources:
                    continue
                mtime_ns = artifact.metadata.get("collection_mtime_ns")
                if isinstance(mtime_ns, int):
                    ts = timestamp_from_stat(mtime_ns / 1_000_000_000, "launch_filesystem_fallback")
                    if ts and ts.normalized:
                        fallback.append(ts)
            if fallback:
                candidate.timestamp = min(fallback, key=lambda ts: ts.normalized)
                candidate.decision_reason += "; 직접 실행 시각 미확인; runtime filesystem mtime을 발생 시각 fallback으로 사용"


def is_runtime_ui_state_file(path: str) -> bool:
    name = basename(path).lower()
    return name in {"global.json", "server-logs-state.json"} or re.fullmatch(r"window-\d+\.json", name) is not None


def detect_runtime_exit(ctx: AnalysisContext, runtime: RuntimeObservations, logs: list[ObservedFact]) -> None:
    cleanup = [
        f for f in ctx.facts
        if f.fact_type == "history_delete" and basename(f.target_path).lower() in {"http-server.json", "server-logs-state.json"}
    ]
    normal_logs = [f for f in logs if f.fact_type == "normal_exit_log"]
    if normal_logs or (runtime.ui_flush and cleanup):
        facts = runtime.ui_flush + cleanup + normal_logs
        add_candidate(ctx, "application_normal_exit", facts, ["positive state flush", "runtime cleanup/log"], "LM Studio 정상 종료 흔적_state flush 및 runtime 정리 근거")
    elif cleanup:
        modified_ui = [f for f in ctx.facts if f.fact_type == "history_modify" and is_runtime_ui_state_file(f.target_path)]
        if modified_ui:
            add_candidate(ctx, "application_normal_exit", cleanup + modified_ui, ["runtime cleanup", "state artifact update"], "LM Studio 정상 종료 흔적_state update 및 runtime 정리 근거", forced="suspected")
    forced_logs = [f for f in logs if f.fact_type == "forced_exit_log"]
    if forced_logs:
        add_candidate(ctx, "application_forced_exit", forced_logs + runtime.residue, ["명시적 forced termination", "runtime residue"], "LM Studio 강제 종료 의심_forced termination 및 runtime/state 양성 근거")
    # Research running/forced listings are identical: residue is not a
    # positive termination observation, even when two filenames are present.


def detect_conversations(
    ctx: AnalysisContext,
    summaries: list[ConversationSummary],
    selections: dict[str, list[ObservedFact]],
    logs: list[ObservedFact],
) -> None:
    inference_logs = [f for f in logs if f.fact_type == "server_inference"]
    for summary in summaries:
        name = basename(summary.artifact.path).lower()
        subject = detail_subject(summary.title, summary.conversation_id)
        scoped_selections = [f for f in selections.get(name, []) if conversation_scope(f.provenance.original_artifact_path) == conversation_scope(summary.artifact.path)]
        history = exact_history(ctx, summary.artifact.path, {"history_create"})
        if not history and summary.artifact.kind in {"ntfs_file", "mft_resident"} and summary.artifact.created:
            history = [ObservedFact("conversation_ntfs_creation", "filesystem", artifact_provenance(summary.artifact, summary.artifact.provenance.evidence_location + "; $STANDARD_INFORMATION creation"), "original NTFS creation", timestamp=summary.artifact.created, target_path=summary.artifact.path)]
        if scoped_selections and (summary.empty_initial or history):
            facts = scoped_selections + history
            if history:
                add_candidate(ctx, "conversation_create", facts, ["conversation config selection", "filesystem create"], "대화 생성" + (f"_{subject}" if subject else ""), conversation_ref=summary.conversation_id)
            else:
                add_candidate(ctx, "conversation_create", facts, ["empty initial structure", "conversation config selection"], "대화 생성" + (f"_{subject}" if subject else ""), limitation="model load가 만든 empty conversation과 사용자 New Chat을 완전히 구분할 filesystem creation history가 없음", forced="indeterminate", conversation_ref=summary.conversation_id)
        for edit_fact in summary.edited_facts:
            history = exact_history(ctx, summary.artifact.path, {"history_modify"})
            add_candidate(ctx, "message_edit", [edit_fact] + history, ["explicit edited marker"], "사용자 메시지 수정" + (f"_{subject}" if subject else ""), conversation_ref=summary.conversation_id, timestamp=edit_fact.timestamp or unambiguous_history_time(history), infer_timestamp=False)
        for retry in summary.retry_facts:
            version_count = retry.value
            facts = [retry] + summary.generation_facts + [f for f in inference_logs if summary.conversation_id and f.conversation_ref == summary.conversation_id]
            retry_time = retry.timestamp or unambiguous_history_time(exact_history(ctx, summary.artifact.path, {"history_modify"}))
            add_candidate(ctx, "assistant_retry", facts, ["assistant 복수 version", "selected 후속 version"], f"Assistant 응답 재시도" + (f"_{subject}" if subject else "") + f"; versions={version_count}", conversation_ref=summary.conversation_id, timestamp=retry_time, infer_timestamp=False)
        for user_fact in summary.user_facts:
            user_index = int(user_fact.key.split("/")[2])
            next_user = min((int(f.key.split("/")[2]) for f in summary.user_facts if int(f.key.split("/")[2]) > user_index), default=float("inf"))
            related_assistant = [f for f in summary.assistant_facts + summary.generation_facts if user_index < int(f.key.split("/")[2]) < next_user]
            correlated = [f for f in inference_logs if summary.conversation_id and f.conversation_ref == summary.conversation_id
                          and ((user_fact.message_ref and f.key == user_fact.message_ref)
                               or (not user_fact.message_ref and len(summary.user_facts) == 1))]
            facts = [user_fact] + related_assistant + correlated
            detail = ("사용자 메시지 전송_" if related_assistant or correlated else "사용자 메시지 입력_") + first_prompt_line(user_fact.value)
            if not related_assistant and not correlated:
                detail += "; 전송 여부 미확인"
            add_candidate(ctx, "prompt_interaction", facts, ["user message text"], detail, timestamp=user_fact.timestamp, conversation_ref=summary.conversation_id, infer_timestamp=False)
        # Assistant-only is not proof: require positive prior user activity plus write context.
        if not summary.user_facts and summary.assistant_facts:
            data = ctx.parsed_json.get(summary.artifact.artifact_id, {})
            prior_user = iso_from_epoch_ms(data.get("userLastMessagedAt"), "user_message_event")
            rewrite = exact_history(ctx, summary.artifact.path, {"history_modify"}) if prior_user else []
            deletion_time = unambiguous_history_time(rewrite)
            if prior_user and not rewrite and summary.artifact.kind == "ntfs_file" and summary.artifact.modified:
                rewrite = [ObservedFact("conversation_ntfs_write_context", "filesystem", artifact_provenance(summary.artifact), "original NTFS write context; not a deletion timestamp", target_path=summary.artifact.path)]
            if rewrite:
                activity = ObservedFact("historical_user_activity", "conversation_state", artifact_provenance(summary.artifact, "/userLastMessagedAt"), "verified user-last activity; not a deletion time", conversation_ref=summary.conversation_id)
                add_candidate(ctx, "prompt_delete", summary.assistant_facts + [activity] + rewrite, ["assistant residual context", "positive prior user activity", "conversation rewrite context"], "사용자 메시지 삭제" + (f"_{subject}" if subject else ""), limitation="Before user message를 직접 복구하지 못해 제거 행위를 확정할 수 없음", conversation_ref=summary.conversation_id, forced="indeterminate", timestamp=deletion_time, infer_timestamp=False)
    current_names = currently_observed_names(ctx)
    deleted = [f for f in ctx.facts if f.fact_type in {"history_delete", "history_rename"} and basename(f.target_path).lower().endswith(".conversation.json") and basename(f.target_path).lower() not in current_names]
    grouped_deleted: dict[str, list[ObservedFact]] = defaultdict(list)
    for fact in deleted:
        grouped_deleted[basename(fact.target_path).lower()].append(fact)
    for _, facts in sorted(grouped_deleted.items()):
        fact = sorted(facts, key=lambda f: (normalized_time_value(f), f.provenance.evidence_location))[-1]
        subject = basename(fact.target_path)
        detail = f"대화 삭제; conversation artifact={safe_nonconversation_text(subject, max_length=160)}"
        if fact.fact_type == "history_rename" or "$recycle.bin" in lower_path(fact.target_path):
            detail += "; 휴지통 이동/rename 흔적"
        refs = {s.conversation_id for s in summaries if lower_path(s.artifact.path) == lower_path(fact.target_path) and s.conversation_id}
        if not refs:
            refs = {ref for ref, _ in config_conversation_refs(ctx, fact.target_path)}
        ref = next(iter(refs)) if len(refs) == 1 else ""
        add_candidate(ctx, "conversation_delete", facts, ["conversation actual deletion/rename", "현재 동일 파일 미관찰"], detail, timestamp=fact.timestamp, forced="suspected", conversation_ref=ref)


def detect_attachments(
    ctx: AnalysisContext,
    attachments: list[AttachmentSummary],
    summaries: list[ConversationSummary],
) -> None:
    links = [link for summary in summaries for link in summary.attachment_links]
    for attachment in attachments:
        if attachment.artifact.metadata.get("history_kind") == "history_delete":
            continue
        matched = [link for link in links if attachment.identifier_fingerprint and link.value == attachment.identifier_fingerprint]
        history = history_for_name(ctx, basename(attachment.artifact.path), {"history_create"})
        facts = [attachment.fact] + matched + history
        if not matched:
            forced = "suspected"
            limitation = "conversation attachment link를 확인하지 못함"
        else:
            forced = None
            limitation = ""
        subject = attachment.original_name or attachment.identifier_fingerprint
        action = "image_upload" if attachment.media == "image" else "document_upload"
        prefix = "이미지 첨부_" if attachment.media == "image" else "문서 첨부_"
        refs = sorted({link.conversation_ref for link in matched if link.conversation_ref}) or [""]
        for ref in refs:
            linked_facts = [attachment.fact] + [link for link in matched if link.conversation_ref == ref] + history
            upload_time = attachment.artifact.created if attachment.artifact.kind in {"ntfs_file", "mft_resident"} else None
            upload_time = upload_time or unambiguous_history_time(exact_history(ctx, attachment.artifact.path, {"history_create"}))
            add_candidate(ctx, action, linked_facts, ["LM Studio metadata", "conversation attachment link" if matched else "metadata only"], prefix + safe_nonconversation_text(subject, max_length=200), limitation=limitation, forced=forced, conversation_ref=ref, timestamp=upload_time, infer_timestamp=False)
    current_names = currently_observed_names(ctx)
    delete_facts = [f for f in ctx.facts if f.fact_type == "history_delete" and ("user-files" in lower_path(f.target_path) or ".metadata.json" in lower_path(f.target_path)) and basename(f.target_path).lower() not in current_names]
    for fact in delete_facts:
        low = lower_path(fact.target_path)
        is_document = any(ext in low for ext in (".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt"))
        is_image = any(ext in low for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"))
        if not is_document and not is_image:
            continue
        action = "document_upload_delete" if is_document else "image_upload_delete"
        prefix = "문서 첨부 제거_" if is_document else "이미지 첨부 제거_"
        subject = basename(fact.target_path).removesuffix(".metadata.json")
        metadata = [a for a in attachments if lower_path(a.artifact.path) == lower_path(fact.target_path)]
        matched = [link for a in metadata for link in links if a.identifier_fingerprint and link.value == a.identifier_fingerprint]
        refs = sorted({link.conversation_ref for link in matched if link.conversation_ref}) or [""]
        for ref in refs:
            add_candidate(ctx, action, [fact] + [a.fact for a in metadata] + [link for link in matched if link.conversation_ref == ref], ["actual user-files deletion"], prefix + safe_nonconversation_text(subject, max_length=200), timestamp=fact.timestamp, conversation_ref=ref)


def detect_exports(ctx: AnalysisContext, exports: list[ObservedFact]) -> None:
    for fact in exports:
        history = history_for_name(ctx, basename(fact.target_path), {"history_create"})
        facts = [fact] + history
        add_candidate(ctx, "conversation_export", facts, ["LM Studio Export signature", "filesystem creation" if history else "signature only"], f"대화 Export 완료_{basename(fact.target_path)}", timestamp=choose_timestamp(history), infer_timestamp=False)


def normalize_model_identifier(value: str) -> str:
    return value.replace("\\", "/").lower()


def normalized_time_value(fact: ObservedFact) -> str:
    return fact.timestamp.normalized if fact.timestamp and fact.timestamp.normalized else ""


def history_download_patterns(ctx: AnalysisContext) -> list[tuple[str, list[ObservedFact], TimestampValue | None]]:
    """Correlate LM Studio job mutation, .part activity, and final GGUF rename/create."""
    relevant = [f for f in ctx.facts if f.fact_type in {"history_create", "history_modify", "history_rename"}]
    job_facts = [f for f in relevant if basename(f.target_path).lower() in {"download-jobs-info.json", "single-downloads-info.json"}]
    part_facts = [f for f in relevant if basename(f.target_path).lower().endswith(".gguf.part")]
    final_facts = [
        f for f in relevant
        if basename(f.target_path).lower().endswith(".gguf")
        and ".internal\\bundled-models" not in lower_path(f.target_path)
        and f.fact_type in {"history_create", "history_rename"}
    ]
    grouped: dict[str, list[ObservedFact]] = defaultdict(list)
    for fact in final_facts:
        grouped[basename(fact.target_path).lower()].append(fact)
    result: list[tuple[str, list[ObservedFact], TimestampValue | None]] = []
    for name, finals in sorted(grouped.items()):
        matching_parts = []
        for fact in part_facts:
            part_name = basename(fact.target_path).lower()
            normalized = part_name.removeprefix("downloading_").removesuffix(".part")
            if normalized == name:
                matching_parts.append(fact)
        if not matching_parts or not job_facts:
            continue
        final = sorted(finals, key=lambda f: (normalized_time_value(f), f.provenance.evidence_location))[-1]
        part = sorted(matching_parts, key=lambda f: (normalized_time_value(f), f.provenance.evidence_location))[-1]
        job = sorted(job_facts, key=lambda f: (normalized_time_value(f), f.provenance.evidence_location))[-1]
        result.append((basename(final.target_path), [job, part, final], final.timestamp))
    return result


def detect_models(
    ctx: AnalysisContext,
    loads: list[ModelLoadSummary],
    downloads: list[DownloadSummary],
    summaries: list[ConversationSummary],
    logs: list[ObservedFact],
    zones: list[ObservedFact],
) -> None:
    conversation_models = [(identifier, fact) for summary in summaries for identifier in summary.model_identifiers for fact in ctx.facts if fact.fact_type == "conversation_model" and fact.value == identifier]
    model_logs = [f for f in logs if f.fact_type == "model_load_log"]
    for load in loads:
        matched = [fact for identifier, fact in conversation_models if normalize_model_identifier(identifier) in normalize_model_identifier(load.identifier) or normalize_model_identifier(load.identifier) in normalize_model_identifier(identifier)]
        facts = [load.fact] + matched
        detail = f"모델 변경_{safe_nonconversation_text(load.identifier, max_length=240)}; 이전 모델 미확인"
        add_candidate(ctx, "model_change", facts, ["model identifier", "verified load timestamp", "conversation/log context" if matched or model_logs else "model state only"], detail, timestamp=load.timestamp)
    ggufs = [a for a in ctx.artifacts if basename(a.path).lower().endswith(".gguf")]
    parts = [a for a in ctx.artifacts if basename(a.path).lower().endswith(".gguf.part")]
    processed_downloads: set[tuple[str, bool]] = set()
    for download in downloads:
        target_name = basename(download.target).lower()
        group_key = (target_name, download.completed)
        if group_key in processed_downloads:
            continue
        processed_downloads.add(group_key)
        grouped_records = [item for item in downloads if basename(item.target).lower() == target_name and item.completed == download.completed]
        matching_files = [a for a in ggufs if basename(a.path).lower() == target_name]
        matching_zone = [z for z in zones if basename(z.target_path).lower() == target_name]
        history = history_for_name(ctx, target_name, {"history_create"})
        file_facts = [ObservedFact("final_gguf", "final_file", artifact_provenance(a), basename(a.path), timestamp=a.created, target_path=a.path) for a in matching_files]
        for fact in file_facts:
            ctx.add_fact(fact)
        facts = [item.fact for item in grouped_records] + matching_zone + history + file_facts
        group_timestamp = download.timestamp or next((item.timestamp for item in grouped_records if item.timestamp), None)
        if download.completed:
            completion_times = [item.completion_timestamp for item in grouped_records
                                if format_timestamp_kst(item.completion_timestamp)]
            start_times = [item.start_timestamp for item in grouped_records
                           if format_timestamp_kst(item.start_timestamp)]
            start_fallback = False
            if completion_times:
                group_timestamp = min(completion_times, key=lambda ts: ts.normalized)
            elif not format_timestamp_kst(group_timestamp) and start_times:
                group_timestamp = min(start_times, key=lambda ts: ts.normalized)
                start_fallback = True
            detail = f"모델 다운로드 완료_{safe_nonconversation_text(download.target, max_length=240)}"
            if matching_zone:
                detail += "; LM Studio 다운로드 기록 및 GGUF 출처 교차검증"
            elif not (history or file_facts):
                detail += "; 독립 파일 출처 증거 미확인"
            if start_fallback:
                detail += "; 다운로드 완료 시각 미확인; download start timestamp를 발생 시각 fallback으로 사용"
            add_candidate(ctx, "model_download", facts, ["completed download record", "GGUF/final file evidence" if matching_files or matching_zone or history else "internal record only"], detail, timestamp=group_timestamp, infer_timestamp=False)
        else:
            detail = f"모델 다운로드 시도_{safe_nonconversation_text(download.target, max_length=240)}; 완료 미확인"
            add_candidate(ctx, "model_download", facts, ["incomplete download record", "model/GGUF target"], detail, timestamp=group_timestamp, forced="suspected")
    known_targets = {basename(item.target).lower() for item in downloads}
    for artifact in parts:
        target = basename(artifact.path).removeprefix("downloading_").removesuffix(".part")
        if target.lower() in known_targets:
            continue
        fact = ObservedFact("partial_download_file", "filesystem", artifact_provenance(artifact), target, timestamp=artifact.created, target_path=artifact.path)
        ctx.add_fact(fact)
        add_candidate(ctx, "model_download", [fact], ["GGUF part file", "download job 미확인"], f"모델 다운로드 시도_{safe_nonconversation_text(target, max_length=240)}; 완료 미확인", timestamp=artifact.created, limitation="part file만으로 완료 여부 및 LM Studio job 연결을 확인할 수 없음", forced="indeterminate")
    for target, facts, timestamp in history_download_patterns(ctx):
        if target.lower() in known_targets:
            continue
        add_candidate(
            ctx, "model_download", facts,
            ["LM Studio download job state change", "GGUF part activity", "final GGUF create/rename"],
            f"모델 다운로드 완료_{safe_nonconversation_text(target, max_length=240)}; LM Studio job 및 최종 GGUF filesystem 흔적 교차검증",
            timestamp=timestamp,
        )


# ---------------------------------------------------------------------------
# 10. Timeline/conversation transformers and deterministic CSV writer
# ---------------------------------------------------------------------------

def unique_candidates(candidates: Sequence[CandidateEvent]) -> list[CandidateEvent]:
    result: list[CandidateEvent] = []
    seen: set[tuple[Any, ...]] = set()
    for candidate in candidates:
        paths = tuple(sorted({fact.provenance.original_artifact_path for fact in candidate.facts}))
        key = (
            candidate.rule_id,
            candidate.conversation_ref,
            candidate.timestamp.normalized if candidate.timestamp else "",
            candidate.decision_reason,
            paths,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def candidate_artifact_paths(candidate: CandidateEvent) -> list[str]:
    paths: set[str] = set()
    for _, facts in artifact_display_groups(candidate):
        representative = artifact_display_representative(facts)
        path = representative.provenance.original_artifact_path
        if path:
            paths.add(safe_nonconversation_text(path, max_length=2000))
    return sorted(paths)


def pointer_order(location: str) -> tuple[int, ...]:
    return tuple(int(part) for part in location.split("/") if part.isdigit())


def candidate_message_subject(ctx: AnalysisContext, candidate: CandidateEvent) -> str:
    paths = {f.provenance.original_artifact_path for f in candidate.facts}
    titles = sorted({m.title for m in ctx.messages if m.artifact_path in paths and m.title})
    if titles:
        return " | ".join(titles)
    if candidate.conversation_ref:
        return safe_nonconversation_text(candidate.conversation_ref, max_length=500)
    filenames = sorted({basename(f.target_path) for f in candidate.facts
                        if basename(f.target_path).lower().endswith(".conversation.json")})
    return " | ".join(filenames)


def candidate_user_message_first_lines(ctx: AnalysisContext, candidate: CandidateEvent, fact_type: str) -> str:
    anchors = [f for f in candidate.facts if f.fact_type == fact_type]
    messages = [m for m in ctx.messages if m.role == "user" and m.content and any(
        m.artifact_path == f.provenance.original_artifact_path and
        m.location.startswith(f.key.rstrip("/") + "/") for f in anchors)]
    values = [first_prompt_line(m.content) for m in sorted(messages, key=lambda m: (m.artifact_path, pointer_order(m.location)))]
    if not values and fact_type == "user_message":
        values = [first_prompt_line(f.value) for f in anchors if f.value]
    return " | ".join(dict.fromkeys(value for value in values if value))


def candidate_behavior_details(ctx: AnalysisContext, candidate: CandidateEvent) -> str:
    """Return a concise, user-facing ``<basis>_<subject>`` description."""
    action = candidate.action
    types = {f.fact_type for f in candidate.facts}

    def values(*fact_types: str) -> str:
        return " | ".join(sorted({safe_nonconversation_text(f.value, max_length=1000)
                                  for f in candidate.facts if f.fact_type in fact_types and f.value}))

    if action == "prompt_interaction":
        subject = candidate_user_message_first_lines(ctx, candidate, "user_message")
        sent = bool(types & {"assistant_response", "generation_metadata", "server_inference"})
        prefix = "사용자 메시지 전송" if sent else "프롬프트 작성 흔적(전송 미확인)"
        return prefix + ("_" + subject if subject else "")
    if action == "message_edit":
        subject = candidate_user_message_first_lines(ctx, candidate, "explicit_message_edit")
        return "사용자 메시지 수정 기록" + ("_" + subject if subject else "")
    if action in {"image_upload", "document_upload"}:
        subject = values("image_metadata", "document_metadata")
        linked = "conversation_attachment" in types
        prefix = "전송 메시지 첨부" if linked else (
            "이미지 업로드 준비 흔적(전송 불확인)" if action == "image_upload"
            else "문서 업로드 준비 흔적(전송 불확인)"
        )
        return prefix + ("_" + subject if subject else "")
    if action in {"image_upload_delete", "document_upload_delete"}:
        subject = " | ".join(sorted({
            safe_nonconversation_text(basename(f.target_path).removesuffix(".metadata.json"), max_length=500)
            for f in candidate.facts if f.target_path
        }))
        return "첨부 제거 이벤트" + ("_" + subject if subject else "")
    if action == "model_change":
        subject = values("model_loaded_state", "conversation_model") or " | ".join(sorted({
            safe_nonconversation_text(f.value, max_length=500) for f in candidate.facts
            if f.fact_type == "model_load_log" and f.value != "model_load_log"
        })) or ("LM Studio" if candidate.direct_evidence else "")
        return "모델 변경 기록" + ("_" + subject if subject else "")
    if action == "model_download":
        final_targets = sorted({safe_nonconversation_text(basename(f.target_path), max_length=500)
                                for f in candidate.facts
                                if basename(f.target_path).lower().endswith(".gguf")})
        partial_targets = sorted({safe_nonconversation_text(
            basename(f.target_path).removeprefix("downloading_").removesuffix(".part"), max_length=500)
            for f in candidate.facts if basename(f.target_path).lower().endswith(".gguf.part")})
        subject = values("download_completed_record", "download_attempt_record", "final_gguf")
        subject = subject or " | ".join(final_targets) or " | ".join(partial_targets)
        history_completed = bool(final_targets and partial_targets and any(
            basename(f.target_path).lower() in {"download-jobs-info.json", "single-downloads-info.json"}
            for f in candidate.facts
        ))
        completed = "download_completed_record" in types or "final_gguf" in types or history_completed
        prefix = "다운로드 완료 기록" if completed else "다운로드 시도 흔적(완료 미확인)"
        return prefix + ("_" + subject if subject else "")
    if action == "conversation_delete":
        subject = " | ".join(sorted({safe_nonconversation_text(basename(f.target_path), max_length=500)
                                     for f in candidate.facts if f.target_path}))
        return "대화 파일 삭제 흔적" + ("_" + subject if subject else "")
    if action == "conversation_export":
        subject = " | ".join(sorted({safe_nonconversation_text(basename(f.target_path), max_length=500)
                                     for f in candidate.facts if f.target_path}))
        prefix = "Export 완료 기록" if "history_create" in types else "Export 파일 흔적(완료 미확인)"
        return prefix + ("_" + subject if subject else "")
    if action in {"conversation_create", "assistant_retry", "prompt_delete"}:
        subject = candidate_message_subject(ctx, candidate)
        prefix = {
            "conversation_create": "대화 생성 기록",
            "assistant_retry": "응답 재시도 기록",
            "prompt_delete": "사용자 메시지 삭제 흔적",
        }[action]
        if action == "assistant_retry":
            count = values("assistant_retry_structure")
            subject += ("; " if subject else "") + "versions=" + (count or "-")
        return prefix + ("_" + safe_nonconversation_text(subject, max_length=1000) if subject else "")
    if action in {"login", "logout", "account_switch"}:
        if candidate.direct_evidence:
            return {"login": "로그인 성공 기록_명시적 로그인 성공",
                    "logout": "로그아웃 성공 기록_명시적 로그아웃 성공",
                    "account_switch": "계정 전환 기록_명시적 계정 전환"}[action]
        if action == "login":
            identifiers = values("account_profile_state")
            return "로그인 상태 확인_" + (identifiers or "인증된 계정 상태")
        if action == "logout":
            return "계정 인증 상태 초기화_null/reset 상태 확인"
        identifiers = list(dict.fromkeys(
            f.value for f in candidate.facts
            if f.fact_type == "account_profile_state" and f.value.startswith("sha256:")
        ))
        before_after = any("Before/After" in condition for condition in candidate.matched_conditions)
        if before_after and len(identifiers) == 2:
            return "계정 전환 기록_" + " → ".join(identifiers)
        subject = " | ".join(identifiers) or "계정 전환 로그 문구"
        return "계정 전환 흔적_" + subject
    if action == "application_install":
        subject = next((safe_nonconversation_text(f.target_path, max_length=1000) for f in candidate.facts
                        if f.fact_type == "application_binary" and f.target_path), "")
        subject = subject or " | ".join(sorted({basename(f.target_path) for f in candidate.facts if f.target_path}))
        return "설치 기록" + ("_" + subject if subject else "")
    if action == "application_uninstall":
        subject = " | ".join(sorted({safe_nonconversation_text(basename(f.target_path), max_length=500)
                                     for f in candidate.facts if f.target_path}))
        return "프로그램 삭제 기록" + ("_" + subject if subject else "")
    if action == "application_launch":
        prefetch = next((basename(f.target_path) for f in candidate.facts if f.fact_type == "application_prefetch"), "")
        if prefetch:
            return "Prefetch 실행 기록_" + safe_nonconversation_text(prefetch, max_length=500)
        runtime = next((basename(f.provenance.original_artifact_path) for f in candidate.facts
                        if f.fact_type in {"server_log_artifact", "http_server_runtime", "history_create", "history_modify"}), "")
        return "애플리케이션 실행 흔적_" + safe_nonconversation_text(runtime or "runtime/server 상태", max_length=500)
    if action == "application_normal_exit":
        return "정상 종료 기록_LM Studio" if candidate.direct_evidence else "정상 종료 흔적_state flush 및 runtime 정리"
    if action == "application_forced_exit":
        return "강제 종료 기록_LM Studio" if candidate.direct_evidence else "강제 종료 흔적_runtime/state 양성 근거"
    return candidate.korean_action + "_관찰된 LM Studio 아티팩트"


def artifact_display_name(fact: ObservedFact) -> str:
    source = lower_path(fact.provenance.original_artifact_path)
    target = lower_path(fact.target_path)
    location = fact.provenance.evidence_location.lower()
    name = basename(fact.provenance.original_artifact_path).lower()
    target_name = basename(fact.target_path).lower()
    combined = source + " " + target
    if "offset 0x" in location or "$usnjrnl" in combined:
        return "$UsnJrnl"
    if "mft" in location or name in {"$mft", "$mft.copy0"} or fact.provenance.original_artifact_path == "C:\\$MFT":
        return "$MFT"
    if fact.fact_type.startswith("history_"):
        return "History"
    if name == "conversation-config.json":
        return "Conversation Config"
    if name.endswith(".conversation.json") or target_name.endswith(".conversation.json"):
        return "Conversation"
    if name in {"local-identity.json", "user-profile.json", "lmstudio-hub.json", "lm-link-account-status-cache.json"}:
        return "Account"
    if name.endswith(".metadata.json") or target_name.endswith(".metadata.json"):
        return "Attachment Metadata"
    if name == "model-data.json":
        return "Model Data"
    if name in {"download-jobs-info.json", "single-downloads-info.json"}:
        return "Download Record"
    if name.endswith(".log") and "server-logs" in source:
        return "Server Log"
    if name.endswith(".pf") or fact.fact_type == "application_prefetch":
        return "Prefetch"
    if name in {"http-server.json", "llmster-pid.lock", "global.json"} or re.fullmatch(r"window-\d+\.json", name):
        return "Runtime"
    if name.endswith(":zone.identifier") or fact.fact_type == "zone_identifier":
        return "Zone.Identifier"
    if target_name.endswith(".gguf") or target_name.endswith(".gguf.part") or name.endswith(".gguf") or name.endswith(".gguf.part"):
        return "GGUF"
    if fact.fact_type == "lmstudio_export" or name.endswith(".md"):
        return "Export"
    if name == "lm studio.exe" or target_name == "lm studio.exe":
        return "Program File"
    if name.endswith(".lnk") or target_name.endswith(".lnk"):
        return "Shortcut"
    if fact.fact_type == "application_installer" or "uninstall" in combined or "updater" in combined:
        return "Installer"
    return "Artifact"


def artifact_location_detail(location: str) -> str:
    safe = safe_nonconversation_text(location, max_length=1000)
    if not safe or safe.lower() == "file":
        return ""
    low = safe.lower()
    if safe.startswith("/"):
        return "JSON 위치=" + safe
    if "offset 0x" in low:
        return "위치=" + safe[safe.lower().index("offset 0x"):]
    if "mft" in low:
        return "위치=" + safe
    if re.search(r"\bline \d+\b", safe, re.I):
        return "위치=" + re.search(r"\bline \d+\b", safe, re.I).group(0)
    return "위치=" + safe


def fact_event_name(fact_type: str) -> str:
    return {
        "history_create": "생성", "history_modify": "수정", "history_delete": "삭제",
        "history_rename": "이름 변경", "history_observed": "관찰",
        "account_login_log": "로그인 성공", "account_logout_log": "로그아웃 성공",
        "account_switch_log": "계정 전환", "account_reauthentication": "재인증",
        "server_inference": "추론 실행", "model_load_log": "모델 로드 성공",
        "normal_exit_log": "정상 종료", "forced_exit_log": "강제 종료",
    }.get(fact_type, "")


def fact_artifact_detail(fact: ObservedFact) -> str:
    label = artifact_display_name(fact)
    name = basename(fact.provenance.original_artifact_path)
    target_name = basename(fact.target_path)
    fields: list[str] = []

    event = fact_event_name(fact.fact_type)
    if fact.fact_type.startswith("history_"):
        if target_name:
            fields.append("대상=" + safe_nonconversation_text(target_name, max_length=500))
        if label == "$MFT" and fact.target_path:
            fields.append("경로=" + safe_nonconversation_text(fact.target_path, max_length=1000))
        if event:
            fields.append("이벤트=" + event)
    elif fact.fact_type in {"user_message", "assistant_response", "generation_metadata", "explicit_message_edit",
                            "conversation_attachment", "assistant_retry_structure", "conversation_selected",
                            "before_user_message", "after_user_removed", "historical_user_activity",
                            "conversation_ntfs_creation", "conversation_ntfs_write_context", "conversation_model"}:
        if name:
            fields.append("파일=" + safe_nonconversation_text(name, max_length=500))
        if fact.fact_type == "conversation_attachment":
            fields.append("이벤트=메시지 첨부 연결")
        elif fact.fact_type == "explicit_message_edit":
            fields.append("이벤트=사용자 메시지 수정")
        elif fact.fact_type == "assistant_retry_structure":
            fields.append("응답 버전 수=" + safe_nonconversation_text(fact.value, max_length=40))
        elif fact.fact_type == "conversation_selected":
            fields.append("이벤트=대화 선택")
        elif fact.fact_type == "conversation_model" and fact.value:
            fields.append("모델=" + safe_nonconversation_text(fact.value, max_length=500))
    elif fact.fact_type in {"image_metadata", "document_metadata"}:
        fields.append("파일명=" + safe_nonconversation_text(fact.value or target_name, max_length=500))
    elif fact.fact_type in {"model_loaded_state", "model_load_log"}:
        if fact.value and fact.value != fact.fact_type:
            fields.append("모델=" + safe_nonconversation_text(fact.value, max_length=500))
        else:
            fields.append("이벤트=모델 로드 성공")
    elif fact.fact_type in {"download_completed_record", "download_attempt_record"}:
        fields.append("상태=" + ("완료" if fact.fact_type == "download_completed_record" else "완료 미확인"))
        fields.append("파일명=" + safe_nonconversation_text(fact.value or target_name, max_length=500))
    elif fact.fact_type in {"final_gguf", "partial_download_file"}:
        fields.append("파일명=" + safe_nonconversation_text(fact.value or target_name or name, max_length=500))
        if fact.fact_type == "partial_download_file":
            fields.append("상태=부분 다운로드")
    elif fact.fact_type == "zone_identifier":
        fields.append("대상=" + safe_nonconversation_text(target_name or name.removesuffix(":Zone.Identifier"), max_length=500))
        fields.append("상태=인터넷 출처 표시")
    elif event:
        fields.append("이벤트=" + event)
    elif fact.fact_type == "application_prefetch":
        fields.extend(["실행 파일=LM Studio.exe", "파일=" + safe_nonconversation_text(target_name or name, max_length=500)])
    elif fact.fact_type in {"application_binary", "application_shortcut", "application_installer"}:
        fields.append("파일=" + safe_nonconversation_text(target_name or name, max_length=500))
    elif fact.fact_type in {"server_log_artifact", "http_server_runtime", "pid_lock_runtime",
                            "ui_final_state_flush", "ui_conversation_cleared", "listing_observed"}:
        fields.append("상태=" + {
            "server_log_artifact": "서버 로그 확인", "http_server_runtime": "HTTP 서버 상태 확인",
            "pid_lock_runtime": "PID lock 확인", "ui_final_state_flush": "UI 상태 저장",
            "ui_conversation_cleared": "활성 대화 상태 초기화", "listing_observed": "파일 목록 관찰",
        }[fact.fact_type])
        if name:
            fields.append("파일=" + safe_nonconversation_text(name, max_length=500))
    elif fact.fact_type.startswith("account_") or fact.fact_type == "credential_present_state":
        state = {
            "account_logged_in_state": "로그인 상태", "account_profile_state": "계정 프로필 확인",
            "account_reset_state": "null/reset 상태", "account_status_state": "계정 상태 확인",
            "credential_present_state": "인증 상태 존재",
        }.get(fact.fact_type, "계정 상태 확인")
        fields.append("상태=" + state)
        if fact.fact_type == "account_profile_state" and fact.value.startswith("sha256:"):
            fields.append("계정 식별값=" + fact.value)
    elif fact.fact_type == "lmstudio_export":
        fields.append("파일=" + safe_nonconversation_text(target_name or name, max_length=500))
    else:
        fields.append("파일=" + safe_nonconversation_text(target_name or name or "LM Studio artifact", max_length=500))

    location = artifact_location_detail(fact.provenance.evidence_location)
    if location:
        fields.append(location)
    if not fields:
        fields.append("파일=" + safe_nonconversation_text(name or target_name or "LM Studio artifact", max_length=500))
    return f"[{label}] " + ", ".join(dict.fromkeys(fields))


def usn_artifact_detail_key(fact: ObservedFact) -> tuple[str, ...] | None:
    label = artifact_display_name(fact)
    if (label != "$UsnJrnl" or not fact.fact_type.startswith("history_")
            or not fact_event_name(fact.fact_type) or not fact.target_path):
        return None
    # Keep full target/source paths in the key: equal basenames in different
    # profiles or journals must not become one displayed evidence group.
    return (label, fact.fact_type, fact.target_path,
            fact.provenance.source_image, fact.provenance.original_artifact_path)


def prefetch_display_executable(fact: ObservedFact) -> str:
    """Identify the executable from observed PF names or an explicit .exe value."""
    names = [basename(fact.provenance.original_artifact_path)]
    if fact.target_path:
        names.append(basename(fact.target_path))
    executables: set[str] = set()
    for name in names:
        match = re.fullmatch(r"(.+\.exe)-[A-Za-z0-9]+\.pf", name, re.I)
        if match:
            executables.add(match.group(1).lower())
        elif not name.lower().endswith(".pf"):
            return ""
    if fact.value.lower().endswith(".exe"):
        executables.add(basename(fact.value).lower())
    return next(iter(executables)) if len(executables) == 1 else ""


def artifact_display_group_key(candidate: CandidateEvent, fact: ObservedFact) -> tuple[str, ...] | None:
    """Conservative display equivalence; never an evidence-independence decision."""
    source = fact.provenance.original_artifact_path
    if not source:
        return None
    common = (candidate.action, candidate.event_type, candidate.rule_id,
              fact.fact_type, fact.family, fact.direct_tag,
              fact.conversation_ref, fact.message_ref, fact.provenance.source_image)
    if fact.fact_type == "application_prefetch":
        executable = prefetch_display_executable(fact)
        if not executable:
            return None
        # Hash-specific PF names identify repeated supporting files. Keep their
        # directory/volume, executable and any additional semantic value apart.
        value = fact.value
        if value.lower() in {basename(source).lower(), basename(fact.target_path).lower(), executable}:
            value = ""
        return ("Prefetch", *common, executable,
                lower_path(str(PureWindowsPath(source).parent)),
                lower_path(str(PureWindowsPath(fact.target_path).parent)) if fact.target_path else "",
                value, fact.key)
    if basename(source).lower().endswith(".log") and "\\server-logs\\" in lower_path(source):
        if fact.fact_type in {
            "server_log_artifact", "server_inference", "model_load_log",
            "account_login_log", "account_logout_log", "account_switch_log",
            "account_reauthentication", "normal_exit_log", "forced_exit_log",
        }:
            location = fact.provenance.evidence_location
            # Only line-number differences are ignored. MFT/other locators can
            # describe different source records and must retain their scope.
            scope = "line" if re.fullmatch(r"line \d+", location) else location
            return ("Server Log", *common, lower_path(source),
                    fact.provenance.lineage_key, lower_path(fact.target_path),
                    fact.value, fact.key, scope)
    if (artifact_display_name(fact) == "Runtime" and not fact.direct_tag
            and fact.fact_type in {"http_server_runtime", "pid_lock_runtime",
                                   "ui_final_state_flush", "ui_conversation_cleared"}):
        # Other supporting state is compressed only for the same source locator.
        return ("Runtime", *common, lower_path(source), fact.provenance.lineage_key,
                fact.provenance.evidence_location, lower_path(fact.target_path),
                fact.value, fact.key)
    return None


def artifact_display_groups(candidate: CandidateEvent) -> list[tuple[tuple[str, ...] | None, list[ObservedFact]]]:
    groups: dict[tuple[str, ...], list[ObservedFact]] = defaultdict(list)
    individual: list[tuple[tuple[str, ...] | None, list[ObservedFact]]] = []
    for fact in candidate.facts:
        key = artifact_display_group_key(candidate, fact)
        if key is None:
            individual.append((None, [fact]))
        else:
            groups[key].append(fact)
    return individual + list(groups.items())


def artifact_display_representative(facts: Sequence[ObservedFact]) -> ObservedFact:
    return min(facts, key=lambda fact: (
        fact.provenance.original_artifact_path, fact.provenance.evidence_location,
        fact.target_path, fact.value, fact.key, fact.conversation_ref, fact.message_ref,
    ))


def grouped_artifact_detail(key: tuple[str, ...], facts: Sequence[ObservedFact]) -> str:
    representative = artifact_display_representative(facts)
    if key[0] == "Prefetch":
        executable = prefetch_display_executable(representative)
        display = "LM Studio.exe" if executable == "lm studio.exe" else executable
        detail = "[Prefetch] 실행 파일=" + safe_nonconversation_text(display, max_length=500)
        detail += ", 대표 파일=" + safe_nonconversation_text(basename(representative.provenance.original_artifact_path), max_length=500)
        location = artifact_location_detail(representative.provenance.evidence_location)
        if location:
            detail += ", " + location.replace("위치=", "대표 위치=", 1)
    else:
        detail = fact_artifact_detail(representative).replace(", 위치=", ", 대표 위치=", 1)
    return detail + f", 동일 근거={len(facts)}건"


def candidate_artifact_details(candidate: CandidateEvent) -> str:
    segments: set[str] = set()
    usn_groups: dict[tuple[str, ...], list[ObservedFact]] = defaultdict(list)
    for display_key, facts in artifact_display_groups(candidate):
        if display_key is not None and len(facts) > 1:
            segments.add(grouped_artifact_detail(display_key, facts))
            continue
        fact = facts[0]
        key = usn_artifact_detail_key(fact)
        if key is None:
            segments.add(fact_artifact_detail(fact))
        else:
            usn_groups[key].append(fact)
    # Aggregate only the CSV display; all raw Facts/locators remain available
    # to detection, verdicts and debugging in the unchanged Candidate.
    details = list(segments)
    for facts in usn_groups.values():
        # Lexically first rendered locator, matching the existing output sort.
        detail = min(fact_artifact_detail(fact) for fact in facts)
        if len(facts) > 1:
            detail += f", 동일 근거={len(facts)}건"
        details.append(detail)
    details.sort()
    if candidate.timestamp and candidate.timestamp.semantics == "download_started" and details:
        for index, detail in enumerate(details):
            if detail.startswith("[Download Record] "):
                details[index] = detail + ", 시각 출처=다운로드 시작"
                break
    return " | ".join(details)


def timeline_rows(ctx: AnalysisContext) -> list[list[str]]:
    rows: list[tuple[tuple[Any, ...], list[str]]] = []
    for candidate in unique_candidates(ctx.candidates):
        if candidate.decision_status not in {"confirmed", "suspected"}:
            continue
        timestamp = format_timestamp_kst(candidate.timestamp)
        artifact_paths = candidate_artifact_paths(candidate)
        row = [
            SERVICE_NAME,
            timestamp,
            candidate.korean_action,
            candidate_behavior_details(ctx, candidate),
            DECISION_KO[candidate.decision_status],
            " | ".join(artifact_paths),
            candidate_artifact_details(candidate),
        ]
        sort_key = (
            0 if timestamp else 1,
            timestamp,
            candidate.rule_id,
            candidate.conversation_ref,
            candidate.decision_reason,
            tuple(artifact_paths),
        )
        rows.append((sort_key, row))
    return [[csv_value(cell) for cell in row] for _, row in sorted(rows, key=lambda item: item[0])]


def conversation_rows(ctx: AnalysisContext) -> list[list[str]]:
    rows: list[tuple[tuple[Any, ...], str, list[str]]] = []
    seen: set[tuple[Any, ...]] = set()
    for message in ctx.messages:
        key = (
            message.artifact_path,
            message.location,
            message.role,
            message.content,
            message.message_id,
            message.parent_message_id,
        )
        if key in seen:
            continue
        seen.add(key)
        timestamp = format_timestamp_kst(message.timestamp)
        conversation_uuid = message.conversation_id or (
            basename(message.artifact_path) if message.artifact_path.lower().endswith(".conversation.json") else ""
        )
        conversation_order_key = conversation_uuid
        if conversation_uuid.endswith(".conversation.json"):
            conversation_uuid = conversation_uuid.removesuffix(".conversation.json")
        row = [
            SERVICE_NAME,
            timestamp,
            conversation_uuid,
            message.title,
            message.message_id,
            message.parent_message_id,
            str(message.order),
            message.role,
            message.content,
            message.artifact_path,
        ]
        sort_key = (
            message.conversation_id,
            message.title,
            message.artifact_path.lower(),
            message.order,
            pointer_order(message.location),
            message.role,
            message.message_id,
        )
        rows.append((sort_key, conversation_order_key, row))
    result = []
    orders: dict[tuple[str, str], int] = defaultdict(int)
    for _, conversation_order_key, row in sorted(rows, key=lambda item: item[0]):
        group = (row[9], conversation_order_key)
        orders[group] += 1
        row[6] = str(orders[group])
        result.append([csv_value(cell) for cell in row])
    return result


def write_csv(path: Path, header: Sequence[str], rows: Sequence[Sequence[str]], *,
              overwrite: bool = False) -> None:
    with path.open("w" if overwrite else "x", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow([spreadsheet_safe(value) for value in header])
        for row in rows:
            writer.writerow([spreadsheet_safe(value) for value in row])


def preflight_outputs(output: Path, *, overwrite: bool = False, validate: bool = False) -> None:
    """Check every planned result before any result file is written."""
    names = ("timeline.csv", "recovered_conversations.csv") + (("validation.json",) if validate else ())
    targets = [output / name for name in names]
    existing = [target for target in targets if target.exists() or target.is_symlink()]
    if existing and not overwrite:
        raise FileExistsError("기존 결과 파일이 존재합니다: " + ", ".join(str(target) for target in existing)
                              + ". 다른 --output 경로를 지정하거나 --overwrite로 명시적으로 교체하십시오.")
    for target in targets:
        if target.is_symlink() or target.resolve().parent != output.resolve() or (target.exists() and target.stat().st_nlink > 1):
            raise ValueError(f"출력 대상이 link 또는 외부 경로입니다: {target}")
    for target in existing:
        if not target.is_file():
            raise ValueError(f"출력 대상이 일반 파일이 아닙니다: {target}")


def write_outputs(ctx: AnalysisContext, output: Path, *, overwrite: bool = False,
                  validate: bool = False) -> None:
    error = validate_live_output(ctx, output) if ctx.live else validate_paths(ctx.input_path, output)
    if error:
        raise ValueError(error)
    preflight_outputs(output, overwrite=overwrite, validate=validate)
    output.mkdir(parents=True, exist_ok=True)
    write_csv(output / "timeline.csv", TIMELINE_HEADER, timeline_rows(ctx), overwrite=overwrite)
    write_csv(output / "recovered_conversations.csv", CONVERSATION_HEADER, conversation_rows(ctx), overwrite=overwrite)


# ---------------------------------------------------------------------------
# 11. Orchestration, safety validation, and CLI
# ---------------------------------------------------------------------------

def is_image_path(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in {".dd", ".raw", ".img", ".e01", ".ex01", ".s01", ".l01", ".001"}


def research_evidence_root(path: Path) -> Path | None:
    resolved = path.resolve()
    parts = list(resolved.parts)
    for index, part in enumerate(parts):
        if part.lower() == "lmstudio_research_evidence":
            return Path(*parts[: index + 1])
    return None


def validate_paths(input_path: Path, output_path: Path) -> str:
    if not input_path.exists():
        return "입력 경로가 존재하지 않습니다."
    segment_number = split_raw_segment_number(input_path) if input_path.is_file() else None
    if segment_number is not None and segment_number != 1:
        return "분할 RAW/DD 이미지는 첫 segment인 .001을 지정하십시오."
    if input_path.is_file() and input_path.suffix == ".001":
        try:
            discover_split_raw_segments(input_path)
        except SplitRawImageError as exc:
            return str(exc)
    if input_path.is_dir() and is_inside(output_path, input_path):
        return "출력 경로는 Evidence directory 내부일 수 없습니다."
    research_root = research_evidence_root(input_path)
    if research_root is not None and is_inside(output_path, research_root):
        return "출력 경로는 Research Evidence 내부일 수 없습니다."
    try:
        if input_path.is_file() and output_path.resolve() == input_path.resolve():
            return "출력 경로는 Evidence file과 같을 수 없습니다."
    except OSError:
        pass
    return ""


def validate_live_output(ctx: AnalysisContext, output: Path) -> str:
    for protected in ctx.evidence_roots:
        if is_inside(output, protected) or is_inside(protected, output):
            return "Live 출력 경로가 수집 대상 directory와 겹칩니다. 별도 output directory를 지정하십시오."
    return ""


def select_output_directory(ctx: AnalysisContext, output: Path, *, overwrite: bool = False,
                            validate: bool = False, before_path: Path | None = None) -> Path:
    """Reuse an unoccupied output, or reserve the first unused numbered sibling."""
    def check_path(candidate: Path) -> None:
        error = validate_live_output(ctx, candidate) if ctx.live else validate_paths(ctx.input_path, candidate)
        if before_path is not None:
            error = error or validate_paths(before_path, candidate)
        if error:
            raise ValueError(error)

    check_path(output)
    try:
        preflight_outputs(output, overwrite=overwrite, validate=validate)
    except FileExistsError:
        if overwrite:
            raise
    else:
        return output

    index = 1
    while True:
        candidate = output.with_name(f"{output.name}_{index:03d}")
        index += 1
        if candidate.exists() or candidate.is_symlink():
            continue
        check_path(candidate)
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        preflight_outputs(candidate, validate=validate)
        return candidate


def terminal_text(value: str) -> str:
    text = safe_nonconversation_text(value, max_length=4000)
    text = re.sub(r"(?i)\b(?:access[_-]?token|refresh[_-]?token|credential|secret|passkey|password|private[_-]?key)\s*[=:]\s*[^\s;]+", "[REDACTED]", text)
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)


def emit_progress(stage: int, message: str, stream: TextIO | None = None) -> None:
    print(f"[{stage}/7] {terminal_text(message)}", file=stream or sys.stdout, flush=True)


def report_analysis(ctx: AnalysisContext, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    print(f"Artifact={len(ctx.artifacts)}; ObservedFact={len(ctx.facts)}; Candidate={len(ctx.candidates)}", file=stream)
    for stats in ctx.usn_stats:
        print("USN " + terminal_text(json.dumps(stats, ensure_ascii=False, sort_keys=True)), file=stream)
    for issue in ctx.issues:
        print(terminal_text(f"[{'fatal' if issue.fatal else 'non-fatal'}] {issue.code}; {issue.artifact_path}; {issue.limitation}"), file=stream)
    for candidate in unique_candidates(ctx.candidates):
        label = "미확정/CSV 제외" if candidate.decision_status == "indeterminate" else DECISION_KO[candidate.decision_status]
        print(terminal_text(f"[{label}] {candidate.korean_action}; internal={candidate.decision_status}; Rule={candidate.rule_id}; Evidence Family={','.join(sorted(candidate.evidence_families))}; Direct Evidence={candidate.direct_evidence}"), file=stream)
        # Do not echo user messages or raw log/credential values to the terminal.
        for location in sorted({f.provenance.original_artifact_path + ":" + f.provenance.evidence_location for f in candidate.facts})[:3]:
            print("  Evidence: " + terminal_text(location), file=stream)
        print("  limitation: " + terminal_text(candidate.limitation or "-"), file=stream)
    stream.flush()


def analyze(input_path: Path, before_path: Path | None = None,
            progress: Callable[[int, str], None] | None = None, *,
            live: bool = False, live_root: Path | None = None,
            credential: BitLockerCredential | None = None) -> AnalysisContext:
    ctx = AnalysisContext(input_path=input_path, source_image=str(input_path.resolve()) if is_image_path(input_path) else "", live=live)
    if progress:
        progress(2, "파일시스템 및 아티팩트 수집")
    if live:
        collect_live(ctx, live_root)
    elif is_image_path(input_path):
        collect_image(ctx, credential)
    elif input_path.is_dir():
        collect_directory(ctx)
        collect_standalone_mft(ctx)
        collect_preparsed_history(ctx)
    elif input_path.is_file():
        add_local_file(ctx, input_path)
        collect_preparsed_history(ctx)
    else:
        ctx.issue("unsupported_input", str(input_path), "지원되는 file/directory input이 아님", True)
        return ctx
    if any(issue.fatal for issue in ctx.issues):
        return ctx
    if progress:
        volumes = {a.metadata["volume_index"] for a in ctx.artifacts if "volume_index" in a.metadata}
        progress(2, f"NTFS volume={len(volumes)}; Artifact={len(ctx.artifacts)}; USN records read={sum(s['records_read'] for s in ctx.usn_stats)}")
        progress(3, "LM Studio 아티팩트 분석")
    parse_json_artifacts(ctx)
    logs = parse_logs(ctx)
    parse_text_listings(ctx)
    account_states = parse_accounts(ctx)
    summaries = parse_conversations(ctx)
    enrich_recovered_metadata(ctx, logs)
    selections = parse_conversation_configs(ctx)
    attachments = parse_attachments(ctx)
    loads = parse_model_data(ctx)
    downloads = parse_downloads(ctx)
    zones = parse_zone_identifiers(ctx)
    exports = parse_exports(ctx)
    runtime = parse_runtime_and_application(ctx)
    if progress:
        progress(3, f"JSON parsed={len(ctx.parsed_json)}; Conversation={len(summaries)}; Attachment={len(attachments)}; Account={sum(len(v) for v in account_states.values())}; Model={len(loads)}; Download={len(downloads)}")
        progress(4, f"분석 사실 생성: ObservedFact={len(ctx.facts)}")
        progress(5, "사용자 행위 판정")
    detect_accounts(ctx, account_states, logs)
    detect_application(ctx, runtime, logs)
    detect_runtime_exit(ctx, runtime, logs)
    detect_conversations(ctx, summaries, selections, logs)
    detect_attachments(ctx, attachments, summaries)
    detect_exports(ctx, exports)
    detect_models(ctx, loads, downloads, summaries, logs, zones)
    for fact in logs:
        if fact.direct_tag == "explicit_model_load_log":
            add_candidate(ctx, "model_change", [fact], ["explicit model load event record"], "명시적 모델 로드 로그", timestamp=fact.timestamp)
    if before_path is not None:
        before_ctx = analyze(before_path, credential=credential)
        if any(issue.fatal for issue in before_ctx.issues):
            ctx.issue("before_input_failed", str(before_path), "Before snapshot 분석 실패", True)
        else:
            detect_snapshot_transitions(ctx, before_ctx)
    if progress:
        progress(6, f"대화 복구: Recovered messages={len(conversation_rows(ctx))}")
    return ctx


ImageStatSnapshot = tuple[tuple[str, int, int], ...]


def image_stat(path: Path) -> ImageStatSnapshot | None:
    if not is_image_path(path):
        return None
    try:
        paths = discover_split_raw_segments(path) if path.suffix == ".001" else [path]
        return tuple(
            (str(segment.resolve()), int(stat.st_size), int(stat.st_mtime_ns))
            for segment in paths
            for stat in (segment.stat(),)
        )
    except (OSError, SplitRawImageError):
        return None


def _validation_sensitive_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str) and len(value) >= 8:
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _validation_sensitive_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _validation_sensitive_strings(child)


def _read_and_validate_csv(path: Path, header: Sequence[str], expected: Sequence[Sequence[str]]) -> tuple[list[list[str]], str]:
    raw = path.read_bytes()
    if not raw.startswith(b"\xef\xbb\xbf"):
        raise AssertionError(f"UTF-8 BOM 누락: {path.name}")
    if not raw.endswith(b"\r\n"):
        raise AssertionError(f"CRLF 종료 누락: {path.name}")
    text = raw.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    if not rows or rows[0] != list(header):
        raise AssertionError(f"CSV schema 불일치: {path.name}")
    if any(len(row) != len(header) for row in rows):
        raise AssertionError(f"CSV column 수 불일치: {path.name}")
    if any(cell == "" for row in rows[1:] for cell in row):
        raise AssertionError(f"빈 CSV cell 발견: {path.name}")
    if any(cell != "-" and cell.startswith(SPREADSHEET_PREFIXES) for row in rows[1:] for cell in row):
        raise AssertionError(f"Formula injection 방어 실패: {path.name}")
    serialized = io.StringIO(newline="")
    csv.writer(serialized, lineterminator="\r\n").writerows(rows)
    if serialized.getvalue() != text:
        raise AssertionError(f"CSV 직렬화/CRLF 불일치: {path.name}")
    safe_expected = [[spreadsheet_safe(cell) for cell in row] for row in expected]
    if rows[1:] != safe_expected:
        raise AssertionError(f"내부 결과와 CSV 불일치: {path.name}")
    return rows, hashlib.sha256(raw).hexdigest()


def validate_analysis(ctx: AnalysisContext, input_path: Path, output_path: Path,
                      before_image_stat: ImageStatSnapshot | None = None, *,
                      credential: BitLockerCredential | None = None,
                      before_path: Path | None = None) -> dict[str, Any]:
    """Self-contained production validation; never relies on project fixtures."""
    timeline, timeline_hash = _read_and_validate_csv(
        output_path / "timeline.csv", TIMELINE_HEADER, timeline_rows(ctx))
    recovered, recovered_hash = _read_and_validate_csv(
        output_path / "recovered_conversations.csv", CONVERSATION_HEADER, conversation_rows(ctx))
    if any(row[4] not in {"확정", "의심"} for row in timeline[1:]):
        raise AssertionError("timeline Verdict는 확정/의심만 허용")
    if any(row[1] != "-" and not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST", row[1])
           for row in timeline[1:] + recovered[1:]):
        raise AssertionError("Timestamp 형식 불일치")
    unique = unique_candidates(ctx.candidates)
    included = [candidate for candidate in unique if candidate.decision_status in {"confirmed", "suspected"}]
    excluded = [candidate for candidate in unique if candidate.decision_status == "indeterminate"]
    if len(included) != len(timeline) - 1:
        raise AssertionError("Candidate/Timeline 수 불일치")
    diagnostic = io.StringIO()
    report_analysis(ctx, diagnostic)
    if diagnostic.getvalue().count("[미확정/CSV 제외]") != len(excluded):
        raise AssertionError("미확정 Candidate 터미널 표시 불일치")
    sensitive: set[str] = set()
    for artifact in ctx.artifacts:
        data = ctx.parsed_json.get(artifact.artifact_id)
        if not isinstance(data, dict):
            continue
        if basename(artifact.path).lower() == "lmstudio-hub.json":
            sensitive.update(_validation_sensitive_strings(data.get("key")))
        preview = data.get("preview")
        if isinstance(preview, dict):
            sensitive.update(_validation_sensitive_strings(preview.get("data")))
    non_content = repr([row[:3] + row[4:] for row in timeline[1:]])
    non_content += repr([row[:8] + row[9:] for row in recovered[1:]])
    non_content += diagnostic.getvalue()
    if any(secret in non_content for secret in sensitive):
        raise AssertionError("민감정보가 비대화 출력 또는 터미널에 노출됨")
    if before_image_stat is not None and image_stat(input_path) != before_image_stat:
        raise AssertionError("Evidence image size/mtime 변경")
    with tempfile.TemporaryDirectory(prefix="LMSTUDIO_VALIDATION_") as temporary:
        repeat_ctx = analyze(input_path, before_path, credential=credential)
        if any(issue.fatal for issue in repeat_ctx.issues):
            raise AssertionError("반복 분석 fatal issue")
        repeat_output = Path(temporary) / "repeat"
        write_outputs(repeat_ctx, repeat_output)
        repeat_hashes = {
            name: hashlib.sha256((repeat_output / name).read_bytes()).hexdigest()
            for name in ("timeline.csv", "recovered_conversations.csv")
        }
    hashes = {"timeline.csv": timeline_hash, "recovered_conversations.csv": recovered_hash}
    if repeat_hashes != hashes:
        raise AssertionError("반복 분석 CSV가 byte-identical하지 않음")
    protected = {RULES[action].rule_id for action in ("application_launch", "model_change", "model_download")}
    protected_rows = [
        {"rule": candidate.rule_id, "timestamp": format_timestamp_kst(candidate.timestamp) or "-",
         "status": candidate.decision_status}
        for candidate in unique if candidate.rule_id in protected
    ]
    return {
        "status": "PASS", "parser": str(Path(__file__).resolve()),
        "input": str(input_path), "output": str(output_path),
        "timeline_rows": len(timeline) - 1, "recovered_rows": len(recovered) - 1,
        "verdict_counts": dict(Counter(row[4] for row in timeline[1:])),
        "candidate_count": len(unique), "excluded_indeterminate": len(excluded),
        "empty_cells": 0, "sensitive_values_checked": len(sensitive), "sensitive_leaks": 0,
        "usn_stats": ctx.usn_stats,
        "issues": [{"code": issue.code, "fatal": issue.fatal} for issue in ctx.issues],
        "sha256": hashes, "repeat_byte_identical": True,
        "protected_rules": protected_rows,
        "image_stat_unchanged": before_image_stat is None or image_stat(input_path) == before_image_stat,
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Windows LM Studio forensic artifact parser (read-only evidence access)",
    )
    parser.add_argument("input", nargs="?", type=Path, help=".lmstudio, User Profile, Windows root, DD/RAW/IMG (including split .001), or E01")
    parser.add_argument("--output", type=Path, help="Result directory; existing results use a new _001, _002, ... sibling")
    parser.add_argument("--overwrite", action="store_true", help="Replace results in the requested directory instead of selecting a new sibling")
    parser.add_argument("--before", type=Path, help="Explicit earlier snapshot of the same subject; no folder-name inference")
    parser.add_argument("--validate", action="store_true", help="Analyze twice and validate CSV, security, integrity, and determinism")
    parser.add_argument("--self-test", action="store_true", help="Run the embedded regression suite")
    parser.add_argument("--live", action="store_true", help="Read current Windows profiles and LM Studio files")
    parser.add_argument("--live-root", type=Path, help="Windows root containing Users; requires --live (default: SystemDrive)")
    credential = parser.add_mutually_exclusive_group()
    credential.add_argument("--bitlocker-recovery-prompt", action="store_true", help="Prompt for authorized recovery password without echo")
    credential.add_argument("--bitlocker-passphrase-prompt", action="store_true", help="Prompt for authorized user passphrase without echo")
    credential.add_argument("--bitlocker-bek", type=Path, help="Authorized BEK file, opened read-only")
    credential.add_argument("--bitlocker-fvek", type=Path, help="Authorized raw binary FVEK file (no hex/header/container)")
    return parser


def read_bitlocker_credential(args: argparse.Namespace, *, defer: bool = False) -> BitLockerCredential | None:
    if defer and (args.bitlocker_recovery_prompt or args.bitlocker_passphrase_prompt
                  or args.bitlocker_bek is not None or args.bitlocker_fvek is not None):
        return BitLockerCredential("deferred", "", reader=lambda: read_bitlocker_credential(args))
    if args.bitlocker_recovery_prompt or args.bitlocker_passphrase_prompt:
        kind = "recovery" if args.bitlocker_recovery_prompt else "passphrase"
        # getpass can fall back to echoed stdin. Reject that fallback explicitly.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("BitLocker recovery password: " if kind == "recovery" else "BitLocker passphrase: ")
        if not value:
            raise ValueError("empty credential")
        return BitLockerCredential(kind, value)
    if args.bitlocker_bek is not None:
        return BitLockerCredential("bek", args.bitlocker_bek)
    if args.bitlocker_fvek is not None:
        with args.bitlocker_fvek.open("rb") as fh:
            value = fh.read(65)
        if len(value) not in {16, 32, 64}:
            raise ValueError("invalid raw FVEK size")
        return BitLockerCredential("fvek", value)
    return None


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    has_credential = bool(args.bitlocker_recovery_prompt or args.bitlocker_passphrase_prompt
                          or args.bitlocker_bek is not None or args.bitlocker_fvek is not None)
    if args.self_test:
        if args.input is not None or args.output is not None or args.overwrite or args.before is not None or args.validate or args.live or args.live_root is not None or has_credential:
            print("오류: --self-test는 다른 분석 인자와 함께 사용할 수 없습니다.", file=sys.stderr)
            return 2
        return run_self_tests()
    if args.live_root is not None and not args.live:
        print("오류: --live-root에는 --live가 필요합니다.", file=sys.stderr)
        return 2
    if args.live and (args.input is not None or args.before is not None or args.validate or has_credential):
        print("오류: --live에는 input/--before/--validate/BitLocker credential을 함께 지정할 수 없습니다.", file=sys.stderr)
        return 2
    if args.live and sys.platform != "win32":
        print("오류: live_platform_unsupported; --live는 Windows에서만 지원됩니다.", file=sys.stderr)
        return 2
    if (args.input is None and not args.live) or args.output is None:
        print("오류: 분석에는 input과 --output이 필요합니다.", file=sys.stderr)
        return 2
    input_path = (args.input or args.live_root or Path(os.environ.get("SystemDrive", "C:") + "\\")).resolve()
    if args.live and (not input_path.is_dir() or str(input_path).startswith("\\\\")):
        print("오류: --live-root는 로컬 Windows root directory여야 합니다.", file=sys.stderr)
        return 2
    if has_credential and not is_image_path(input_path):
        print("오류: BitLocker credential은 forensic image 입력에만 사용됩니다.", file=sys.stderr)
        return 2
    requested_output = args.output.resolve()
    output_path = requested_output
    input_kind = "Windows Live" if args.live else (input_path.suffix.upper().lstrip('.') + " image" if is_image_path(input_path) else "directory/file")
    emit_progress(1, f"입력 검증: {input_path}; 입력 유형={input_kind}")
    if args.live:
        preflight = AnalysisContext(input_path, live=True)
        live_roots(preflight, args.live_root)
        path_error = validate_live_output(preflight, output_path)
    else:
        path_error = validate_paths(input_path, output_path)
    if args.before is not None:
        path_error = path_error or validate_paths(args.before.resolve(), output_path)
    if path_error:
        print(f"오류: {path_error}", file=sys.stderr)
        return 2
    try:
        preflight_outputs(output_path, overwrite=args.overwrite, validate=args.validate)
    except FileExistsError:
        # Select a fresh directory after analysis, before any result is written.
        pass
    except (OSError, ValueError) as exc:
        print("오류: " + terminal_text(str(exc)), file=sys.stderr)
        return 3
    before = image_stat(input_path)
    before_snapshot_stat = image_stat(args.before.resolve()) if args.before is not None else None
    try:
        credential = read_bitlocker_credential(args, defer=True)
    except (OSError, ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print("오류: BitLocker credential을 안전하게 읽지 못했습니다. 값은 기록하지 않습니다.", file=sys.stderr)
        return 2
    ctx = analyze(input_path, args.before.resolve() if args.before is not None else None, progress=emit_progress,
                  live=args.live, live_root=args.live_root, credential=credential)
    report_analysis(ctx)
    if any(issue.fatal for issue in ctx.issues):
        print("오류: 입력 Evidence를 분석할 수 없습니다. dependency, filesystem, image 형식을 확인하십시오.", file=sys.stderr)
        return 2
    try:
        emit_progress(7, "CSV 출력")
        output_path = select_output_directory(ctx, requested_output, overwrite=args.overwrite, validate=args.validate,
                                               before_path=args.before.resolve() if args.before is not None else None)
        if output_path != requested_output:
            print("기존 분석 결과 보존: " + terminal_text(str(requested_output)), flush=True)
        print("결과 저장 경로: " + terminal_text(str(output_path)), flush=True)
        write_outputs(ctx, output_path, overwrite=args.overwrite, validate=args.validate)
    except (OSError, ValueError) as exc:
        print("오류: 출력 CSV를 작성할 수 없습니다. " + terminal_text(str(exc)), file=sys.stderr)
        return 3
    after = image_stat(input_path)
    if args.before is not None and before_snapshot_stat != image_stat(args.before.resolve()):
        print("오류: Before image size 또는 mtime이 분석 중 변경되었습니다.", file=sys.stderr)
        return 4
    if before is not None and before != after:
        print("오류: image size 또는 mtime이 분석 중 변경되었습니다.", file=sys.stderr)
        return 4
    print(
        f"완료: timeline {len(timeline_rows(ctx))}건, recovered conversation {len(conversation_rows(ctx))}건, 부분 분석 issue {len(ctx.issues)}건.",
        file=sys.stderr,
    )
    for name in ("timeline.csv", "recovered_conversations.csv"):
        print(terminal_text(str(output_path / name)), flush=True)
    if args.validate:
        try:
            validation = validate_analysis(ctx, input_path, output_path, before, credential=credential,
                                           before_path=args.before.resolve() if args.before is not None else None)
            validation_path = output_path / "validation.json"
            with validation_path.open("w" if args.overwrite else "x", encoding="utf-8") as fh:
                fh.write(json.dumps(validation, ensure_ascii=False, indent=2))
            print("검증 PASS: " + terminal_text(str(validation_path)), flush=True)
        except (AssertionError, OSError, ValueError) as exc:
            print("검증 FAIL: " + terminal_text(str(exc)), file=sys.stderr)
            return 5
    return 0


# ---------------------------------------------------------------------------
# 12. Embedded regression suite (--self-test)
# ---------------------------------------------------------------------------

parser = sys.modules[__name__]


class SplitRawImageTests(unittest.TestCase):
    def _segments(self, contents: Sequence[bytes] = (b"ABCDE", b"FGHIJ", b"KLMNO")) -> tuple[tempfile.TemporaryDirectory[str], list[Path]]:
        temporary = tempfile.TemporaryDirectory(prefix="SYNTHETIC_SPLIT_RAW_")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        paths = []
        for index, content in enumerate(contents, 1):
            path = root / f"evidence.{index:03d}"
            path.write_bytes(content)
            paths.append(path)
        return temporary, paths

    def test_discovery_orders_numeric_segments_and_excludes_sidecar(self) -> None:
        _, paths = self._segments()
        sidecar = paths[0].with_name(paths[0].name + ".txt")
        sidecar.write_text("not a segment", encoding="utf-8")
        self.assertEqual(paths, parser.discover_split_raw_segments(paths[0]))
        self.assertNotIn(sidecar, parser.discover_split_raw_segments(paths[0]))
        self.assertTrue(parser.is_image_path(paths[0]))

    def test_discovery_rejects_gap_with_expected_segment(self) -> None:
        _, paths = self._segments((b"A", b"B", b"C"))
        paths[1].unlink()
        with self.assertRaisesRegex(parser.SplitRawImageError, r"\.002"):
            parser.discover_split_raw_segments(paths[0])

    def test_direct_nonfirst_segment_input_is_rejected(self) -> None:
        temporary, paths = self._segments()
        error = parser.validate_paths(paths[1], Path(temporary.name) / "output")
        self.assertIn(".001", error)
        self.assertFalse(parser.is_image_path(paths[1]))

    def test_segmented_stream_reads_and_seeks_across_boundaries(self) -> None:
        _, paths = self._segments()
        with parser.SegmentedRawStream(paths) as stream:
            self.assertTrue(stream.readable())
            self.assertTrue(stream.seekable())
            self.assertFalse(stream.writable())
            self.assertEqual(b"ABC", stream.read(3))
            self.assertEqual(b"DEFG", stream.read(4))
            self.assertEqual(7, stream.tell())
            self.assertEqual(4, stream.seek(-3, os.SEEK_CUR))
            self.assertEqual(b"EFGH", stream.read(4))
            self.assertEqual(12, stream.seek(-3, os.SEEK_END))
            self.assertEqual(b"MNO", stream.read())
            self.assertEqual(3, stream.seek(3, os.SEEK_SET))
            buffer = bytearray(5)
            self.assertEqual(5, stream.readinto(buffer))
            self.assertEqual(b"DEFGH", bytes(buffer))

    def test_read_only_stream_preserves_all_segment_content_size_and_mtime(self) -> None:
        _, paths = self._segments()
        before_content = [path.read_bytes() for path in paths]
        before_stat = parser.image_stat(paths[0])
        stream, keepalive = parser.open_image_stream(paths[0])
        self.assertEqual(b"EFG", (stream.seek(4), stream.read(3))[1])
        for handle in reversed(keepalive):
            handle.close()
        self.assertTrue(stream.closed)
        self.assertEqual(before_content, [path.read_bytes() for path in paths])
        self.assertEqual(before_stat, parser.image_stat(paths[0]))
        self.assertEqual(3, len(before_stat or ()))

    def test_image_stat_detects_change_in_nonfirst_segment(self) -> None:
        _, paths = self._segments()
        before = parser.image_stat(paths[0])
        stat = paths[1].stat()
        os.utime(paths[1], ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        self.assertNotEqual(before, parser.image_stat(paths[0]))

    def test_segment_open_failure_has_split_raw_error(self) -> None:
        _, paths = self._segments()
        with patch.object(parser, "SegmentedRawStream", side_effect=OSError("synthetic")):
            with self.assertRaisesRegex(parser.SplitRawImageError, "segment.*열지 못했습니다"):
                parser.open_image_stream(paths[0])

    def test_single_raw_image_open_path_is_unchanged(self) -> None:
        temporary, _ = self._segments(())
        raw = Path(temporary.name) / "single.dd"
        raw.write_bytes(b"SINGLE")
        stream, keepalive = parser.open_image_stream(raw)
        try:
            self.assertEqual(b"SINGLE", stream.read())
            self.assertEqual([stream], keepalive)
        finally:
            stream.close()

    def test_ewf_still_uses_find_files_and_ewf(self) -> None:
        entry = Path("synthetic.E01")
        opened = io.BytesIO(b"EWF")
        ewf = SimpleNamespace(open=lambda: opened)
        with patch("dissect.evidence.ewf.find_files", return_value=["synthetic.E01", "synthetic.E02"]) as find_files_mock, \
             patch("dissect.evidence.ewf.EWF", return_value=ewf) as ewf_mock:
            stream, keepalive = parser.open_image_stream(entry)
        find_files_mock.assert_called_once_with(entry)
        ewf_mock.assert_called_once_with(["synthetic.E01", "synthetic.E02"])
        self.assertIs(opened, stream)
        self.assertEqual([ewf], keepalive)


class RuleContractTests(unittest.TestCase):
    def test_exactly_21_complete_rule_contracts(self) -> None:
        self.assertEqual(21, len(parser.RULES))
        for action, rule in parser.RULES.items():
            with self.subTest(action=action):
                self.assertTrue(rule.evidence_id)
                self.assertTrue(rule.event_type)
                self.assertEqual(action, rule.action)
                self.assertTrue(rule.korean)
                self.assertTrue(rule.rule_id)
                self.assertTrue(rule.positive_conditions)
                self.assertIsInstance(rule.direct_evidence, tuple)
                self.assertTrue(rule.corroborating_evidence)
                self.assertTrue(rule.false_positive_guards)
                self.assertIn(rule.default_decision, {"confirmed", "suspected", "indeterminate"})
                self.assertTrue(rule.decision_reason_format)

    def test_engine_same_source_is_not_independent_and_empty_has_no_candidate(self) -> None:
        provenance = parser.Provenance("", r"C:\SYNTHETIC_TEST\artifact", "", "/test")
        for action, rule in parser.RULES.items():
            with self.subTest(action=action):
                context = parser.AnalysisContext(Path("SYNTHETIC_TEST"))
                one = parser.ObservedFact("positive", "family_a", provenance, "TEST_positive")
                two = parser.ObservedFact("corroborating", "family_b", provenance, "TEST_corroborating")
                parser.add_candidate(context, action, [one, two], ["TEST condition"], "TEST detail")
                self.assertEqual(1, len(context.candidates))
                self.assertNotEqual("confirmed", context.candidates[0].decision_status)
                negative = parser.AnalysisContext(Path("SYNTHETIC_TEST"))
                parser.add_candidate(negative, action, [], [], "TEST missing")
                self.assertEqual([], negative.candidates)

    def test_direct_evidence_contracts(self) -> None:
        provenance = parser.Provenance("", r"C:\SYNTHETIC_TEST\artifact", "", "record 1")
        for action, rule in parser.RULES.items():
            if not rule.direct_evidence:
                continue
            fact = parser.ObservedFact("direct", "one_family", provenance, direct_tag=rule.direct_evidence[0])
            status, direct, families = parser.evaluate_decision(rule, [fact])
            self.assertEqual("confirmed", status, action)
            self.assertTrue(direct, action)
            self.assertEqual({"one_family"}, families)


class FalsePositiveGuardTests(unittest.TestCase):
    def _analyze_fixture(self, files: dict[str, str | bytes]) -> parser.AnalysisContext:
        temp = tempfile.TemporaryDirectory(prefix="SYNTHETIC_LMSTUDIO_")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for relative, value in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
        return parser.analyze(root)

    def test_single_account_file_is_not_login(self) -> None:
        ctx = self._analyze_fixture({".internal/local-identity.json": '{"type":"loggedInUser"}'})
        self.assertNotIn("login", {c.action for c in ctx.candidates})

    def test_empty_conversation_alone_is_not_creation(self) -> None:
        conversation = {"name": None, "tokenCount": 0, "clientInput": "", "messages": []}
        ctx = self._analyze_fixture({"conversations/TEST.conversation.json": json.dumps(conversation)})
        self.assertNotIn("conversation_create", {c.action for c in ctx.candidates})

    def test_assistant_only_alone_is_not_prompt_delete(self) -> None:
        conversation = {
            "messages": [{"versions": [{"role": "assistant", "steps": [{"content": [{"type": "text", "text": "TEST answer"}]}]}], "currentlySelected": 0}]
        }
        ctx = self._analyze_fixture({"conversations/TEST.conversation.json": json.dumps(conversation)})
        self.assertNotIn("prompt_delete", {c.action for c in ctx.candidates})

    def test_generic_markdown_is_not_export(self) -> None:
        ctx = self._analyze_fixture({"Documents/notes.md": "# TEST notes\nordinary markdown"})
        self.assertNotIn("conversation_export", {c.action for c in ctx.candidates})

    def test_single_lock_is_not_launch_or_forced_exit(self) -> None:
        ctx = self._analyze_fixture({".internal/llmster-pid.lock": b"1234"})
        actions = {c.action for c in ctx.candidates}
        self.assertNotIn("application_launch", actions)
        self.assertNotIn("application_forced_exit", actions)

    def test_model_identifier_only_and_timestamp_only_are_negative(self) -> None:
        identifier_only = {"json": [["TEST/model", {"source": {"type": "hub"}}]], "meta": {"values": ["map"]}}
        timestamp_only = {"json": [["", {"lastLoadedTimestamp": 1789708040375}]], "meta": {"values": ["map"]}}
        ctx = self._analyze_fixture({
            ".internal/model-data.json": json.dumps(identifier_only),
            "other/model-data.json": json.dumps(timestamp_only),
        })
        self.assertNotIn("model_change", {c.action for c in ctx.candidates})

    def test_part_only_is_not_completed_download(self) -> None:
        ctx = self._analyze_fixture({"models/downloading_TEST.gguf.part": b"TEST"})
        downloads = [c for c in ctx.candidates if c.action == "model_download"]
        self.assertEqual(1, len(downloads))
        self.assertEqual("indeterminate", downloads[0].decision_status)
        self.assertIn("완료 미확인", downloads[0].decision_reason)

    def test_malformed_json_isolated(self) -> None:
        ctx = self._analyze_fixture({
            "conversations/bad.conversation.json": "{not-json",
            ".internal/model-data.json": json.dumps({"json": [["TEST/model", {"lastLoadedTimestamp": 1789708040375}]]}),
        })
        self.assertTrue(any(issue.code == "json_parse_failed" for issue in ctx.issues))
        self.assertIn("model_change", {c.action for c in ctx.candidates})


class OutputContractTests(unittest.TestCase):
    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temp = tempfile.TemporaryDirectory(prefix="SYNTHETIC_OUTPUT_")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "evidence"
        output = Path(temp.name) / "output"
        (root / "conversations").mkdir(parents=True)
        conversation = {
            "name": "TEST title",
            "userLastMessagedAt": 1789708040375,
            "messages": [
                {"versions": [{"role": "user", "content": [{"type": "text", "text": "=TEST prompt\nsecond line"}]}], "currentlySelected": 0},
                {"versions": [{"role": "assistant", "steps": [{"content": [{"type": "text", "text": "TEST answer"}]}]}], "currentlySelected": 0},
            ],
        }
        (root / "conversations" / "TEST.conversation.json").write_text(json.dumps(conversation), encoding="utf-8")
        return temp, root, output

    def test_csv_contract_bom_crlf_headers_and_formula_guard(self) -> None:
        _, root, output = self._fixture()
        ctx = parser.analyze(root)
        parser.write_outputs(ctx, output)
        timeline = (output / "timeline.csv").read_bytes()
        recovered = (output / "recovered_conversations.csv").read_bytes()
        self.assertTrue(timeline.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(recovered.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\r\n", timeline)
        with (output / "timeline.csv").open("r", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(parser.TIMELINE_HEADER, rows[0])
        self.assertEqual(7, len(rows[0]))
        self.assertTrue(all(len(row) == 7 for row in rows))
        self.assertNotIn("신뢰도", rows[0])
        with (output / "recovered_conversations.csv").open("r", encoding="utf-8-sig", newline="") as fh:
            recovered_rows = list(csv.reader(fh))
        self.assertEqual(parser.CONVERSATION_HEADER, recovered_rows[0])
        self.assertTrue(all(len(row) == 10 for row in recovered_rows))
        user_rows = [row for row in recovered_rows[1:] if row[7] == "user"]
        self.assertEqual("'=TEST prompt\nsecond line", user_rows[0][8])

    def test_deterministic_output(self) -> None:
        _, root, output = self._fixture()
        ctx1 = parser.analyze(root)
        parser.write_outputs(ctx1, output)
        first = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ("timeline.csv", "recovered_conversations.csv")}
        ctx2 = parser.analyze(root)
        repeat_output = output.with_name("repeat_output")
        parser.write_outputs(ctx2, repeat_output)
        second = {name: hashlib.sha256((repeat_output / name).read_bytes()).hexdigest() for name in ("timeline.csv", "recovered_conversations.csv")}
        self.assertEqual(first, second)

    def test_sensitive_account_values_not_retained(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="SYNTHETIC_SECRET_")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "evidence"
        out = Path(temp.name) / "out"
        (root / "credentials").mkdir(parents=True)
        (root / ".internal").mkdir(parents=True)
        secret = "SYNTHETIC_SECRET_DO_NOT_EMIT"
        (root / "credentials" / "lmstudio-hub.json").write_text(json.dumps({"accessToken": secret}), encoding="utf-8")
        (root / ".internal" / "local-identity.json").write_text(json.dumps({"type": "loggedInUser"}), encoding="utf-8")
        parser.write_outputs(parser.analyze(root), out)
        emitted = (out / "timeline.csv").read_text(encoding="utf-8-sig")
        self.assertNotIn(secret, emitted)

    def test_output_inside_evidence_rejected(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="SYNTHETIC_PATH_")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "evidence"
        root.mkdir()
        error = parser.validate_paths(root, root / "output")
        self.assertTrue(error)


class OutputCollisionTests(unittest.TestCase):
    _fixture = OutputContractTests._fixture

    def _run_cli(self, root: Path, output: Path, *options: str) -> tuple[int, str, str]:
        from contextlib import redirect_stdout, redirect_stderr
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = parser.main([str(root), "--output", str(output), *options])
        return code, stdout.getvalue(), stderr.getvalue()

    def _snapshot(self, output: Path) -> dict[str, tuple[bytes, str]]:
        snapshot = {}
        for path in output.iterdir():
            if path.is_file():
                content = path.read_bytes()
                snapshot[path.name] = (content, hashlib.sha256(content).hexdigest())
        return snapshot

    def test_cli_creates_missing_output(self) -> None:
        _, root, output = self._fixture()
        self.assertFalse(output.exists())
        code, _, stderr = self._run_cli(root, output)
        self.assertEqual(0, code, stderr)
        self.assertEqual({"timeline.csv", "recovered_conversations.csv"}, set(self._snapshot(output)))

    def test_existing_directory_and_unplanned_files_are_preserved(self) -> None:
        _, root, output = self._fixture()
        output.mkdir()
        for name in ("unrelated.txt", "validation.json"):
            (output / name).write_bytes(b"SYNTHETIC_UNPLANNED_RESULT")
        before = self._snapshot(output)
        code, _, stderr = self._run_cli(root, output)
        self.assertEqual(0, code, stderr)
        after = self._snapshot(output)
        self.assertEqual(before, {name: after[name] for name in before})
        self.assertEqual(set(before) | {"timeline.csv", "recovered_conversations.csv"}, set(after))

    def test_cli_accepts_empty_existing_output_directory(self) -> None:
        for validate in (False, True):
            with self.subTest(validate=validate):
                _, root, output = self._fixture()
                output.mkdir()
                code, _, stderr = self._run_cli(root, output, *(["--validate"] if validate else []))
                self.assertEqual(0, code, stderr)
                expected = {"timeline.csv", "recovered_conversations.csv"} | ({"validation.json"} if validate else set())
                self.assertEqual(expected, set(self._snapshot(output)))

    def test_all_collision_subsets_preserve_content_hashes_and_prevent_partial_output(self) -> None:
        for validate in (False, True):
            names = ("timeline.csv", "recovered_conversations.csv") + (("validation.json",) if validate else ())
            for mask in range(1, 1 << len(names)):
                with self.subTest(validate=validate, mask=mask):
                    _, root, output = self._fixture()
                    output.mkdir()
                    existing = [name for index, name in enumerate(names) if mask & (1 << index)]
                    for name in existing + ["unrelated.txt"]:
                        (output / name).write_bytes(("기존 분석 결과: " + name + "\n보존").encode("utf-8"))
                    before = self._snapshot(output)
                    directory_mtime = output.stat().st_mtime_ns
                    selected = output.with_name(output.name + "_001")
                    with patch.object(parser, "write_outputs", wraps=parser.write_outputs) as writer:
                        code, stdout, stderr = self._run_cli(root, output, *(["--validate"] if validate else []))
                    self.assertEqual(0, code, stderr)
                    self.assertIn("기존 분석 결과 보존: " + str(output), stdout)
                    self.assertIn("결과 저장 경로: " + str(selected), stdout)
                    self.assertEqual(before, self._snapshot(output))
                    self.assertEqual(directory_mtime, output.stat().st_mtime_ns)
                    self.assertEqual(set(names), set(self._snapshot(selected)))
                    self.assertTrue(all(call.args[1] != output for call in writer.call_args_list))
                    self.assertEqual(selected, writer.call_args_list[0].args[1])
                    if validate:
                        result = json.loads((selected / "validation.json").read_text(encoding="utf-8"))
                        self.assertEqual("PASS", result["status"])
                        self.assertEqual(str(selected), result["output"])
                        self.assertTrue(result["repeat_byte_identical"])

    def test_repeated_runs_group_all_results_in_numbered_directories(self) -> None:
        _, root, output = self._fixture()
        snapshots = {}
        csv_hashes = None
        for index in range(3):
            selected = output if index == 0 else output.with_name(f"{output.name}_{index:03d}")
            code, stdout, stderr = self._run_cli(root, output, "--validate")
            self.assertEqual(0, code, stderr)
            self.assertIn("결과 저장 경로: " + str(selected), stdout)
            for previous, snapshot in snapshots.items():
                self.assertEqual(snapshot, self._snapshot(previous))
            snapshot = self._snapshot(selected)
            self.assertEqual({"timeline.csv", "recovered_conversations.csv", "validation.json"}, set(snapshot))
            result = json.loads((selected / "validation.json").read_text(encoding="utf-8"))
            self.assertEqual("PASS", result["status"])
            self.assertEqual(str(selected), result["output"])
            self.assertTrue(result["repeat_byte_identical"])
            if csv_hashes is not None:
                self.assertEqual(csv_hashes, result["sha256"])
            csv_hashes = result["sha256"]
            snapshots[selected] = snapshot

    def test_numbered_directory_skips_existing_directories_and_files(self) -> None:
        for occupied_kind in ("results", "empty", "unrelated", "file"):
            with self.subTest(occupied_kind=occupied_kind):
                _, root, output = self._fixture()
                output.mkdir()
                (output / "timeline.csv").write_bytes(b"SYNTHETIC_PRIOR_RESULT")
                before = self._snapshot(output)
                occupied = output.with_name(output.name + "_001")
                if occupied_kind == "file":
                    occupied.write_bytes(b"SYNTHETIC_OCCUPIED_PATH")
                    occupied_before = occupied.read_bytes()
                else:
                    occupied.mkdir()
                    if occupied_kind != "empty":
                        name = "recovered_conversations.csv" if occupied_kind == "results" else "unrelated.txt"
                        (occupied / name).write_bytes(b"SYNTHETIC_OCCUPIED_DIRECTORY")
                    occupied_before = self._snapshot(occupied)
                occupied_mtime = occupied.stat().st_mtime_ns
                selected = output.with_name(output.name + "_002")
                code, stdout, stderr = self._run_cli(root, output)
                self.assertEqual(0, code, stderr)
                self.assertIn("결과 저장 경로: " + str(selected), stdout)
                self.assertEqual(before, self._snapshot(output))
                self.assertEqual(occupied_before, occupied.read_bytes() if occupied_kind == "file" else self._snapshot(occupied))
                self.assertEqual(occupied_mtime, occupied.stat().st_mtime_ns)
                self.assertEqual({"timeline.csv", "recovered_conversations.csv"}, set(self._snapshot(selected)))

    def test_numbered_directory_uses_first_available_suffix(self) -> None:
        _, root, output = self._fixture()
        output.mkdir()
        (output / "timeline.csv").write_bytes(b"SYNTHETIC_PRIOR_RESULT")
        occupied = output.with_name(output.name + "_002")
        occupied.mkdir()
        (occupied / "unrelated.txt").write_bytes(b"SYNTHETIC_KEEP")
        before = self._snapshot(occupied)
        code, stdout, stderr = self._run_cli(root, output)
        self.assertEqual(0, code, stderr)
        self.assertIn("결과 저장 경로: " + str(output.with_name(output.name + "_001")), stdout)
        self.assertEqual(before, self._snapshot(occupied))

    def test_numbered_directory_reservation_retries_a_creation_collision(self) -> None:
        _, root, output = self._fixture()
        output.mkdir()
        (output / "timeline.csv").write_bytes(b"SYNTHETIC_PRIOR_RESULT")
        before = self._snapshot(output)
        competing = output.with_name(output.name + "_001")
        original_mkdir = Path.mkdir
        content = b"SYNTHETIC_COMPETING_DIRECTORY"
        def competing_mkdir(path, *args, **kwargs):
            if path == competing:
                original_mkdir(path, *args, **kwargs)
                (path / "unrelated.txt").write_bytes(content)
                raise FileExistsError("SYNTHETIC_DIRECTORY_CREATED_CONCURRENTLY")
            return original_mkdir(path, *args, **kwargs)
        with patch.object(Path, "mkdir", competing_mkdir):
            code, stdout, stderr = self._run_cli(root, output)
        self.assertEqual(0, code, stderr)
        selected = output.with_name(output.name + "_002")
        self.assertIn("결과 저장 경로: " + str(selected), stdout)
        self.assertEqual(before, self._snapshot(output))
        self.assertEqual({"unrelated.txt": (content, hashlib.sha256(content).hexdigest())}, self._snapshot(competing))
        self.assertEqual({"timeline.csv", "recovered_conversations.csv"}, set(self._snapshot(selected)))

    def test_numbered_directory_creation_failure_preserves_existing_results(self) -> None:
        _, root, output = self._fixture()
        output.mkdir()
        (output / "timeline.csv").write_bytes(b"SYNTHETIC_PRIOR_RESULT")
        before = self._snapshot(output)
        selected = output.with_name(output.name + "_001")
        original_mkdir = Path.mkdir
        def denied_mkdir(path, *args, **kwargs):
            if path == selected:
                raise PermissionError("SYNTHETIC_OUTPUT_CREATION_DENIED")
            return original_mkdir(path, *args, **kwargs)
        with patch.object(Path, "mkdir", denied_mkdir), patch.object(parser, "write_csv") as writer:
            code, _, stderr = self._run_cli(root, output)
        self.assertEqual(3, code)
        self.assertIn("SYNTHETIC_OUTPUT_CREATION_DENIED", stderr)
        self.assertEqual(before, self._snapshot(output))
        self.assertFalse(selected.exists())
        writer.assert_not_called()

    def test_write_outputs_preflights_all_planned_results(self) -> None:
        for name, validate in (("timeline.csv", False), ("recovered_conversations.csv", False),
                               ("validation.json", True)):
            with self.subTest(name=name):
                _, root, output = self._fixture()
                ctx = parser.analyze(root)
                output.mkdir()
                (output / name).write_bytes(b"SYNTHETIC_PRIOR_RESULT")
                before = self._snapshot(output)
                with patch.object(parser, "write_csv") as writer:
                    with self.assertRaisesRegex(FileExistsError, re.escape(name)):
                        parser.write_outputs(ctx, output, validate=validate)
                writer.assert_not_called()
                self.assertEqual(before, self._snapshot(output))

    def test_cli_rechecks_collisions_after_analysis_before_writing(self) -> None:
        _, root, output = self._fixture()
        ctx = parser.analyze(root)
        content = b"SYNTHETIC_RESULT_CREATED_DURING_ANALYSIS"
        def analyze_and_create_result(*args, **kwargs):
            output.mkdir()
            (output / "recovered_conversations.csv").write_bytes(content)
            return ctx
        with patch.object(parser, "analyze", side_effect=analyze_and_create_result), \
             patch.object(parser, "write_csv", wraps=parser.write_csv) as writer:
            code, stdout, stderr = self._run_cli(root, output)
        self.assertEqual(0, code, stderr)
        selected = output.with_name(output.name + "_001")
        self.assertIn("결과 저장 경로: " + str(selected), stdout)
        self.assertEqual([selected / "timeline.csv", selected / "recovered_conversations.csv"],
                         [call.args[0] for call in writer.call_args_list])
        self.assertEqual({"recovered_conversations.csv": (content, hashlib.sha256(content).hexdigest())},
                         self._snapshot(output))

    def test_cli_explicit_overwrite_replaces_only_planned_results(self) -> None:
        for validate in (False, True):
            with self.subTest(validate=validate):
                _, root, output = self._fixture()
                ctx = parser.analyze(root)
                output.mkdir()
                for name in ("timeline.csv", "recovered_conversations.csv", "validation.json", "unrelated.txt"):
                    (output / name).write_bytes(b"SYNTHETIC_PRIOR_RESULT")
                before = self._snapshot(output)
                options = ["--overwrite"] + (["--validate"] if validate else [])
                code, _, stderr = self._run_cli(root, output, *options)
                self.assertEqual(0, code, stderr)
                parser._read_and_validate_csv(output / "timeline.csv", parser.TIMELINE_HEADER, parser.timeline_rows(ctx))
                parser._read_and_validate_csv(output / "recovered_conversations.csv", parser.CONVERSATION_HEADER,
                                              parser.conversation_rows(ctx))
                after = self._snapshot(output)
                self.assertFalse(output.with_name(output.name + "_001").exists())
                self.assertEqual(set(before), set(after))
                self.assertEqual(before["unrelated.txt"], after["unrelated.txt"])
                for name in ("timeline.csv", "recovered_conversations.csv"):
                    self.assertNotEqual(before[name], after[name])
                if validate:
                    result = json.loads((output / "validation.json").read_text(encoding="utf-8"))
                    self.assertEqual("PASS", result["status"])
                    self.assertTrue(result["repeat_byte_identical"])
                    self.assertEqual({name: after[name][1] for name in ("timeline.csv", "recovered_conversations.csv")},
                                     result["sha256"])
                else:
                    self.assertEqual(before["validation.json"], after["validation.json"])

    def test_csv_writer_requires_explicit_overwrite(self) -> None:
        _, _, output = self._fixture()
        output.mkdir()
        target = output / "timeline.csv"
        content = b"SYNTHETIC_PRIOR_RESULT"
        target.write_bytes(content)
        with self.assertRaises(FileExistsError):
            parser.write_csv(target, ["header"], [["새 결과"]])
        self.assertEqual(content, target.read_bytes())
        self.assertEqual(hashlib.sha256(content).hexdigest(), hashlib.sha256(target.read_bytes()).hexdigest())
        parser.write_csv(target, ["header"], [["새 결과"]], overwrite=True)
        parser._read_and_validate_csv(target, ["header"], [["새 결과"]])

    def test_korean_multiline_formula_csv_and_determinism_with_validation(self) -> None:
        _, root, output = self._fixture()
        fixture = root / "conversations" / "TEST.conversation.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        text = '=한국어 질문\n둘째 줄, "따옴표"'
        data["name"] = "한국어 대화"
        data["messages"][0]["versions"][0]["content"][0]["text"] = text
        fixture.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        code, _, stderr = self._run_cli(root, output, "--validate")
        self.assertEqual(0, code, stderr)
        ctx = parser.analyze(root)
        rows, _ = parser._read_and_validate_csv(output / "recovered_conversations.csv", parser.CONVERSATION_HEADER,
                                               parser.conversation_rows(ctx))
        self.assertEqual("한국어 대화", rows[1][3])
        self.assertEqual("'" + text, rows[1][8])
        parser._read_and_validate_csv(output / "timeline.csv", parser.TIMELINE_HEADER, parser.timeline_rows(ctx))
        result = json.loads((output / "validation.json").read_text(encoding="utf-8"))
        self.assertTrue(result["repeat_byte_identical"])

    def test_overwrite_cannot_bypass_link_or_directory_safety(self) -> None:
        for name in ("timeline.csv", "recovered_conversations.csv", "validation.json"):
            for linked in (False, True):
                with self.subTest(name=name, linked=linked):
                    _, root, output = self._fixture()
                    output.mkdir()
                    target = output / name
                    if linked:
                        source = output / "unrelated.txt"
                        source.write_bytes(b"SYNTHETIC_LINK_SOURCE")
                        os.link(source, target)
                    else:
                        target.mkdir()
                    before = self._snapshot(output)
                    with patch.object(parser, "write_csv") as writer:
                        code, _, stderr = self._run_cli(root, output, "--overwrite", "--validate")
                    self.assertEqual(3, code)
                    self.assertIn(name, stderr)
                    writer.assert_not_called()
                    self.assertEqual(before, self._snapshot(output))
                    self.assertEqual({name, "unrelated.txt"} if linked else {name},
                                     {path.name for path in output.iterdir()})
                    code, stdout, stderr = self._run_cli(root, output, "--validate")
                    self.assertEqual(0, code, stderr)
                    selected = output.with_name(output.name + "_001")
                    self.assertIn("결과 저장 경로: " + str(selected), stdout)
                    self.assertEqual(before, self._snapshot(output))
                    self.assertEqual({"timeline.csv", "recovered_conversations.csv", "validation.json"},
                                     set(self._snapshot(selected)))

    def test_self_test_rejects_overwrite_analysis_option(self) -> None:
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()), patch.object(parser, "run_self_tests") as tests:
            self.assertEqual(2, parser.main(["--self-test", "--overwrite"]))
        tests.assert_not_called()


def message(role="user", text="TEST text", **fields):
    return {"versions": [{"role": role, "content": [{"type": "text", "text": text}]}],
            "currentlySelected": 0, **fields}


def conversation(*messages, **fields):
    return {"messages": list(messages), **fields}


def history(*records):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["FullName", "Event", "TimeStamp"])
    for path, event in records:
        writer.writerow([path, event, "2026-09-15T18:51:56.973000Z"])
    return stream.getvalue()


CONV = "conversations/TEST.conversation.json"
CONFIG = "conversation-config.json"
LOG = "logs/.lmstudio/server-logs/test.log"
EXE = "AppData/Local/Programs/LM Studio/LM Studio.exe"
SHORTCUT = "Desktop/LM Studio.lnk"
EXPORT = "# LM Studio\n## User\nTEST prompt\n## Assistant\nTEST reply"
JOB = {"jobs": [{"startedTimestamp": 1789708040375, "jobState": {"type": "completed"},
                  "tasks": [{"download": {"filename": "TEST.gguf", "targetPath": "TEST.gguf", "status": "completed"}}]}]}


class FixtureCase(unittest.TestCase):
    def analyze_files(self, files):
        temp = tempfile.TemporaryDirectory(prefix="FIX01_SYNTHETIC_")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        # Use a focused research extract root even when AppData is part of fixture.
        evidence = root / ".lmstudio"
        evidence.mkdir()
        for relative, value in files.items():
            path = evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            if isinstance(value, str):
                value = value.replace("$ROOT", str(evidence)).encode("utf-8")
            path.write_bytes(value)
        before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in evidence.rglob("*") if p.is_file()}
        ctx = parser.analyze(evidence)
        self.assertEqual(before, {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in before})
        return ctx

    def candidates(self, ctx, action):
        return [candidate for candidate in ctx.candidates if candidate.action == action]


# Each entry creates real artifacts and enters analyze(), not add_candidate().
# Positive means a supported candidate, not an artificially forced confirmation.
RULE_FIXTURES = {
    "login": ({"local-identity.json": {"type": "loggedInUser"}, "lmstudio-hub.json": {"key": {"secret": "TEST"}}},
              {"local-identity.json": {"type": "loggedInUser"}}, "suspected"),
    "logout": ({"local-identity.json": {"type": "none"}, "lmstudio-hub.json": {"key": None}},
               {"lmstudio-hub.json": {"key": None}}, "indeterminate"),
    "account_switch": ({LOG: "2026-09-20T00:00:00Z account switched"},
                       {LOG: "2026-09-20T00:00:00Z re-authentication", "user-profile.json": {"profile": {"id": "TEST"}}}, "suspected"),
    "application_install": ({EXE: b"TEST", SHORTCUT: b"TEST"}, {EXE: b"TEST"}, "suspected"),
    "application_uninstall": ({"history.csv": history((r"C:\Users\TEST\AppData\Local\Programs\LM Studio\LM Studio.exe", "File_Deleted"), (r"C:\Users\TEST\Desktop\LM Studio.lnk", "File_Deleted"))},
                              {"local-identity.json": {"type": "none"}}, "suspected"),
    "conversation_create": ({CONV: conversation(tokenCount=0, clientInput="", name=None, conversationId="TEST-CONV"), CONFIG: {"selectedConversation": "TEST.conversation.json"}, "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "File_Created"))},
                            {CONV: conversation(tokenCount=0, clientInput="", name=None)}, "confirmed"),
    "conversation_delete": ({"history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "File_Deleted")), CONFIG: {"selectedConversationHistory": ["TEST.conversation.json"]}},
                            {CONFIG: {"selectedConversationHistory": ["TEST.conversation.json"]}}, "suspected"),
    "message_edit": ({CONV: conversation(message(edited=True))}, {CONV: conversation(message())}, "confirmed"),
    "assistant_retry": ({CONV: conversation({"versions": [message("assistant", "old")["versions"][0], message("assistant", "new")["versions"][0]], "currentlySelected": 1})},
                        {CONV: conversation(message("assistant"))}, "suspected"),
    "prompt_interaction": ({CONV: conversation(message())}, {CONV: conversation(clientInput="TEST draft")}, "suspected"),
    "prompt_delete": ({CONV: conversation(message("assistant"), userLastMessagedAt=1789708040375), "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "Data_Overwrite"))},
                      {CONV: conversation(message("assistant"))}, "indeterminate"),
    "conversation_export": ({"Documents/export.md": EXPORT}, {"Documents/export.md": "# Ordinary\nTEST"}, "suspected"),
    "application_launch": ({"Windows/Prefetch/LM STUDIO.EXE-TEST.pf": b"TEST"}, {"llmster-pid.lock": b"TEST"}, "confirmed"),
    "application_normal_exit": ({LOG: "2026-09-20T00:00:00Z graceful shutdown"}, {"global.json": {"openedTabs": [], "selectedTabIndex": None, "openedWindowKeys": []}}, "confirmed"),
    "application_forced_exit": ({LOG: "2026-09-20T00:00:00Z forced termination", "http-server.json": {}, "llmster-pid.lock": b"TEST"}, {"llmster-pid.lock": b"TEST"}, "confirmed"),
    "model_change": ({"model-data.json": {"json": [["TEST/model", {"lastLoadedTimestamp": 1789708040375}]]}},
                     {"model-data.json": {"json": [["TEST/model", {}]]}}, "suspected"),
    "model_download": ({"download-jobs-info.json": JOB}, {"download-jobs-info.json": {"url": "https://example.org/TEST"}}, "suspected"),
}
for media, suffix, mime in (("image", "png", "image/png"), ("document", "pdf", "application/pdf")):
    meta = {"originalName": f"TEST.{suffix}", "fileIdentifier": "TEST-FILE", "type": mime, "sizeBytes": 4}
    link = message()
    link["versions"][0]["content"].append({"type": "file", "fileIdentifier": "TEST-FILE", "fileType": mime})
    RULE_FIXTURES[f"{media}_upload"] = (
        {f"user-files/TEST.{suffix}.metadata.json": meta, CONV: conversation(link, conversationId="TEST-CONV")},
        {f"user-files/TEST.{suffix}": b"TEST"}, "confirmed")
    RULE_FIXTURES[f"{media}_upload_delete"] = (
        {"history.csv": history((f"$ROOT\\user-files\\TEST.{suffix}.metadata.json", "File_Deleted"))},
        {"history.csv": history((f"$ROOT\\user-files\\TEST.{suffix}.metadata.json", "File_Created"))}, "suspected")


class DetectorPathTests(FixtureCase):
    def test_fixture_inventory_covers_all_21_rules(self):
        self.assertEqual(set(parser.RULES), set(RULE_FIXTURES))


def detector_test(action, positive):
    def test(self):
        yes, no, status = RULE_FIXTURES[action]
        ctx = self.analyze_files(yes if positive else no)
        candidates = self.candidates(ctx, action)
        if positive:
            self.assertTrue(candidates, action)
            self.assertEqual(status, candidates[0].decision_status)
            self.assertTrue(all(candidate.facts for candidate in candidates))
        else:
            self.assertEqual([], candidates, action)
    return test


for _action in RULE_FIXTURES:
    for _positive in (True, False):
        setattr(DetectorPathTests, f"test_{_action}_{'positive' if _positive else 'negative'}", detector_test(_action, _positive))


class Fix01MetadataTests(FixtureCase):
    def test_same_actual_id_title_recovered_from_separate_artifact(self):
        ctx = self.analyze_files({CONV: conversation(message(), conversationId="TEST-ID"), "conversations/history.conversation.json": conversation(name="RECOVERED TITLE", conversationId="TEST-ID")})
        self.assertEqual("RECOVERED TITLE", ctx.messages[0].title)
        self.assertIn("history.conversation.json", ctx.messages[0].title_source)

    def test_conflicting_linked_titles_not_guessed(self):
        ctx = self.analyze_files({CONV: conversation(message(), conversationId="TEST-ID"), "conversations/historyA.conversation.json": conversation(name="A", conversationId="TEST-ID"), "conversations/historyB.conversation.json": conversation(name="B", conversationId="TEST-ID")})
        self.assertEqual("", ctx.messages[0].title)

    def test_log_timestamp_requires_both_ids_and_unique_row(self):
        files = {CONV: conversation(message(messageId="TEST-MSG"), conversationId="TEST-CONV"), LOG: "2026-09-20T00:00:00Z inference completed conversationId=TEST-CONV messageId=TEST-MSG"}
        ctx = self.analyze_files(files)
        self.assertEqual("2026-09-20 09:00:00.000000 KST", parser.conversation_rows(ctx)[0][1])
        files[LOG] = "2026-09-20T00:00:00Z inference completed conversationId=OTHER messageId=TEST-MSG"
        ctx = self.analyze_files(files)
        self.assertEqual("-", parser.conversation_rows(ctx)[0][1])

    def test_deleted_attachment_uses_recovered_metadata_identifier_link(self):
        meta = {"originalName": "TEST.pdf", "type": "application/pdf", "fileIdentifier": "TEST-FILE", "sizeBytes": 4}
        body = base64.b64encode(json.dumps(meta).encode()).decode()
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["FullName", "Event", "ResidentDataBase64"])
        writer.writerow(["$ROOT\\user-files\\TEST.pdf.metadata.json", "File_Deleted", body])
        msg = message()
        msg["versions"][0]["content"].append({"type": "file", "fileIdentifier": "TEST-FILE", "fileType": "application/pdf"})
        ctx = self.analyze_files({CONV: conversation(msg, conversationId="TEST-CONV"), "history.csv": stream.getvalue()})
        self.assertEqual("TEST-CONV", self.candidates(ctx, "document_upload_delete")[0].conversation_ref)

    def test_explicit_title_conversation_message_parent_metadata(self):
        ctx = self.analyze_files({CONV: conversation(message(messageId="TEST-MSG-001", parentMessageId="TEST-MSG-000"), conversationId="TEST-CONV-001", name="TEST TITLE")})
        row = parser.conversation_rows(ctx)[0]
        self.assertEqual(["TEST-CONV-001", "TEST TITLE", "TEST-MSG-001", "TEST-MSG-000"], row[2:6])
        self.assertEqual("TEST-CONV-001", self.candidates(ctx, "prompt_interaction")[0].conversation_ref)
        self.assertTrue(ctx.messages[0].message_id_source)

    def test_absent_title_ids_parents_not_fabricated(self):
        ctx = self.analyze_files({"conversations/1789707934740.conversation.json": conversation(message(id="wrong", identifier="wrong"), message("assistant"), name=None, id="wrong-conv")})
        for row in parser.conversation_rows(ctx):
            self.assertEqual(["1789707934740", "-", "-", "-"], row[2:6])
        self.assertEqual("", self.candidates(ctx, "prompt_interaction")[0].conversation_ref)

    def test_config_actual_identifier_preserved_and_scoped(self):
        ctx = self.analyze_files({CONV: conversation(message()), CONFIG: {"selectedConversation": "TEST.conversation.json"}})
        self.assertEqual("TEST.conversation.json", ctx.messages[0].conversation_id)
        ctx = self.analyze_files({"snapshotA/" + CONV: conversation(message()), "snapshotB/" + CONFIG: {"selectedConversation": "TEST.conversation.json"}})
        self.assertEqual("", ctx.messages[0].conversation_id)

    def test_version_timestamp_kst_and_created_at_not_message_time(self):
        msg = message()
        msg["versions"][0]["timestamp"] = "2026-09-15T18:51:56.973000Z"
        ctx = self.analyze_files({CONV: conversation(msg, message("assistant"), createdAt=1789708040375)})
        rows = parser.conversation_rows(ctx)
        self.assertEqual("2026-09-16 03:51:56.973000 KST", rows[0][1])
        self.assertEqual("-", rows[1][1])

    def test_only_last_user_gets_role_last_timestamp(self):
        ctx = self.analyze_files({CONV: conversation(message(text="A"), message("assistant"), message(text="B"), userLastMessagedAt=1789708040375)})
        rows = [row for row in parser.conversation_rows(ctx) if row[7] == "user"]
        self.assertEqual("-", rows[0][1])
        self.assertRegex(rows[1][1], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST$")

    def test_retry_old_timestamp_blank_latest_own_timestamp(self):
        old = message("assistant", "old")["versions"][0]
        new = message("assistant", "new")["versions"][0]
        new["timestamp"] = "2026-09-20T00:00:00.999999Z"
        ctx = self.analyze_files({CONV: conversation({"versions": [old, new], "currentlySelected": 1}, assistantLastMessagedAt=1789708040375)})
        rows = parser.conversation_rows(ctx)
        self.assertEqual("-", rows[0][1])
        self.assertEqual("2026-09-20 09:00:00.999999 KST", rows[1][1])

    def test_retry_root_timestamp_not_assigned_to_any_ambiguous_version(self):
        version = message("assistant")["versions"][0]
        ctx = self.analyze_files({CONV: conversation({"versions": [version, version], "currentlySelected": 1}, assistantLastMessagedAt=1789708040375)})
        self.assertTrue(all(row[1] == "-" for row in parser.conversation_rows(ctx)))

    def test_content_step_version_timestamp_precedence(self):
        version = {"role": "assistant", "timestamp": "2026-09-20T00:00:03Z", "steps": [
            {"timestamp": "2026-09-20T00:00:02Z", "content": [
                {"type": "text", "text": "A", "timestamp": "2026-09-20T00:00:01Z"}, {"type": "text", "text": "B"}]},
            {"content": [{"type": "text", "text": "C"}]}]}
        ctx = self.analyze_files({CONV: conversation({"versions": [version]})})
        self.assertEqual(["2026-09-20 09:00:01.000000 KST", "2026-09-20 09:00:02.000000 KST", "2026-09-20 09:00:03.000000 KST"], [r[1] for r in parser.conversation_rows(ctx)])

    def test_conversation_create_and_attachment_refs_and_install_blank(self):
        for action in ("conversation_create", "image_upload", "document_upload", "application_install"):
            ctx = self.analyze_files(RULE_FIXTURES[action][0])
            expected = "" if action == "application_install" else "TEST-CONV"
            self.assertEqual(expected, self.candidates(ctx, action)[0].conversation_ref)

    def test_deleted_conversation_config_history_ref(self):
        ctx = self.analyze_files(RULE_FIXTURES["conversation_delete"][0])
        self.assertEqual("TEST.conversation.json", self.candidates(ctx, "conversation_delete")[0].conversation_ref)


class Fix01DecisionTests(FixtureCase):
    def test_resident_json_and_same_csv_row_share_lineage(self):
        lineage = "record:history.csv#2"
        first = parser.ObservedFact("history_create", "filesystem", parser.Provenance("", "history.csv", "", "record 2", lineage))
        second = parser.ObservedFact("parsed", "model_state", parser.Provenance("", "job.json", "", "/jobs/0", lineage))
        self.assertNotEqual("confirmed", parser.evaluate_decision(parser.RULES["model_download"], [first, second])[0])

    def test_previous_assistant_does_not_mark_last_unsent_user_as_sent(self):
        ctx = self.analyze_files({CONV: conversation(message(text="A"), message("assistant"), message(text="B"))})
        last = [c for c in self.candidates(ctx, "prompt_interaction") if "입력_B" in c.decision_reason]
        self.assertEqual(1, len(last))
        self.assertIn("전송 여부 미확인", last[0].decision_reason)

    def test_install_creation_history_plus_shortcut_can_confirm(self):
        ctx = self.analyze_files({EXE: b"TEST", SHORTCUT: b"TEST", "history.csv": history(("$ROOT\\AppData\\Local\\Programs\\LM Studio\\LM Studio.exe", "File_Created"))})
        self.assertEqual("confirmed", self.candidates(ctx, "application_install")[0].decision_status)

    def test_sensitive_values_absent_in_facts_candidates_and_outputs(self):
        secret = "FIX01_TEST_PRIVATE_SECRET_9h48"
        ctx = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "lmstudio-hub.json": {"key": {"privateKey": secret}}, "user-files/TEST.png.metadata.json": {"originalName": "TEST.png", "fileIdentifier": "TEST-FILE", "type": "image/png", "sizeBytes": 4, "preview": {"data": secret}}})
        self.assertNotIn(secret, repr(ctx.facts) + repr(ctx.candidates) + repr(parser.timeline_rows(ctx)) + repr(parser.conversation_rows(ctx)))

    def test_same_log_line_and_json_fields_cannot_double_count(self):
        for path, location in (("test.log", "line 7"), ("test.json", "/a")):
            prov = parser.Provenance("", path, "", location)
            facts = [parser.ObservedFact("one", "family1", prov), parser.ObservedFact("two", "family2", prov)]
            self.assertNotEqual("confirmed", parser.evaluate_decision(parser.RULES["model_download"], facts)[0])

    def test_known_copies_share_lineage(self):
        p1 = parser.Provenance("", "copyA.json", "", "/a", "same-source")
        p2 = parser.Provenance("", "copyB.json", "", "/b", "same-source")
        facts = [parser.ObservedFact("one", "family1", p1), parser.ObservedFact("two", "family2", p2)]
        self.assertNotEqual("confirmed", parser.evaluate_decision(parser.RULES["model_download"], facts)[0])

    def test_export_requires_separate_history_not_stat(self):
        for with_history in (False, True):
            files = {"Documents/export.md": EXPORT}
            if with_history:
                files["history.csv"] = history(("$ROOT\\Documents\\export.md", "File_Created"))
            ctx = self.analyze_files(files)
            candidate = self.candidates(ctx, "conversation_export")[0]
            self.assertEqual("confirmed" if with_history else "suspected", candidate.decision_status)
            self.assertEqual(bool(with_history), bool(candidate.timestamp))

    def test_job_plus_gguf_ads_independent_completion_fact_blank_start_fallback(self):
        ctx = self.analyze_files({"download-jobs-info.json": JOB, "models/TEST.gguf": b"GGUF", "models/TEST.gguf:Zone.Identifier": "[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.org/TEST.gguf"})
        candidate = self.candidates(ctx, "model_download")[0]
        self.assertEqual("confirmed", candidate.decision_status)
        self.assertEqual("download_started", candidate.timestamp.semantics)
        self.assertEqual(str(JOB["jobs"][0]["startedTimestamp"]), candidate.timestamp.raw)
        self.assertIn("다운로드 완료 시각 미확인", candidate.decision_reason)
        self.assertTrue(all(f.timestamp is None for f in candidate.facts if f.fact_type == "download_completed_record"))
        self.assertTrue(any(f.fact_type == "zone_identifier" for f in candidate.facts))

    def test_job_filesystem_mutation_stays_filesystem(self):
        ctx = self.analyze_files({"history.csv": history(("$ROOT\\download-jobs-info.json", "Data_Overwrite"), ("$ROOT\\models\\downloading_TEST.gguf.part", "File_Created"), ("$ROOT\\models\\TEST.gguf", "File_Created"))})
        candidate = self.candidates(ctx, "model_download")[0]
        self.assertNotEqual("confirmed", candidate.decision_status)
        self.assertEqual({"filesystem"}, candidate.evidence_families)
        self.assertEqual("다운로드 완료 기록_TEST.gguf", parser.candidate_behavior_details(ctx, candidate))

    def test_unrelated_hub_metadata_is_not_authentication(self):
        ctx = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "lmstudio-hub.json": {"version": 1, "metadata": "TEST"}})
        self.assertEqual([], self.candidates(ctx, "login"))

    def test_ordinary_text_never_becomes_direct_log(self):
        ctx = self.analyze_files({"ordinary.txt": "login succeeded\nforced termination\naccount switched\nmodel loaded"})
        self.assertFalse(any(f.direct_tag for f in ctx.facts))
        self.assertEqual([], ctx.candidates)

    def test_reauthentication_and_profile_never_confirm_switch(self):
        ctx = self.analyze_files(RULE_FIXTURES["account_switch"][1])
        self.assertEqual([], self.candidates(ctx, "account_switch"))

    def test_unsent_prompt_candidate_and_draft_distinction(self):
        ctx = self.analyze_files({CONV: conversation(message(text="first\nsecond"))})
        candidate = self.candidates(ctx, "prompt_interaction")[0]
        self.assertEqual("suspected", candidate.decision_status)
        self.assertEqual("사용자 메시지 입력_first; 전송 여부 미확인", candidate.decision_reason)
        ctx = self.analyze_files({CONV: conversation(clientInput="")})
        self.assertEqual([], self.candidates(ctx, "prompt_interaction"))

    def test_unrelated_inference_log_does_not_confirm_prompt(self):
        ctx = self.analyze_files({CONV: conversation(message(), message("assistant"), conversationId="TEST-CONV"), LOG: "2026-09-20T00:00:00Z inference completed conversationId=OTHER"})
        self.assertEqual("suspected", self.candidates(ctx, "prompt_interaction")[0].decision_status)

    def test_correlated_inference_log_can_confirm_prompt(self):
        ctx = self.analyze_files({CONV: conversation(message(), message("assistant"), conversationId="TEST-CONV"), LOG: "2026-09-20T00:00:00Z inference completed conversationId=TEST-CONV"})
        self.assertEqual("confirmed", self.candidates(ctx, "prompt_interaction")[0].decision_status)

    def test_current_install_no_time_and_no_confirmation(self):
        ctx = self.analyze_files(RULE_FIXTURES["application_install"][0])
        candidate = self.candidates(ctx, "application_install")[0]
        self.assertEqual("suspected", candidate.decision_status)
        self.assertIsNone(candidate.timestamp)
        self.assertTrue(all(a.created is None and a.modified is None for a in ctx.artifacts))

    def test_kst_truncation_and_unknown_timezone_blank(self):
        for raw, expected in (("2026-09-15T18:51:56.973000Z", "2026-09-16 03:51:56.973000 KST"), ("2026-09-20T00:00:00Z", "2026-09-20 09:00:00.000000 KST"), ("2026-09-20T00:00:00.999999Z", "2026-09-20 09:00:00.999999 KST"), ("2026-09-20 01:30:00", ""), (datetime(2026, 9, 20, 1, 30), "")):
            self.assertEqual(expected, parser.format_timestamp_kst(parser.iso_from_datetime(raw, "test")))
        self.assertIsNone(parser.iso_from_epoch_ms(1789708040375, "unknown_unit"))


class EventTimestampRestoreTests(FixtureCase):
    def download(self, start=None, completion=None):
        job = copy.deepcopy(JOB)
        job["jobs"][0]["startedTimestamp"] = start
        job["jobs"][0]["completedTimestamp"] = completion
        ctx = self.analyze_files({"download-jobs-info.json": job})
        return ctx, self.candidates(ctx, "model_download")[0]

    def test_a_completion_timestamp_precedes_start(self):
        ctx, candidate = self.download(1789708040375, 1789708050999)
        self.assertEqual("1789708050999", candidate.timestamp.raw)
        self.assertEqual("download_completed", candidate.timestamp.semantics)
        self.assertEqual("suspected", candidate.decision_status)
        self.assertNotIn("fallback", candidate.decision_reason)

    def test_b_start_fallback_does_not_change_decision_or_facts(self):
        ctx, candidate = self.download(1789708040375)
        converter = parser.iso_from_epoch_ms
        with patch.object(parser, "iso_from_epoch_ms", side_effect=lambda value, semantics: None if semantics == "download_started" else converter(value, semantics)):
            without = parser.analyze(ctx.input_path)
        baseline = self.candidates(without, "model_download")[0]
        self.assertEqual(candidate.facts, baseline.facts)
        self.assertEqual(candidate.decision_status, baseline.decision_status)
        self.assertEqual(candidate.direct_evidence, baseline.direct_evidence)
        self.assertEqual(candidate.evidence_families, baseline.evidence_families)
        self.assertEqual("1789708040375", candidate.timestamp.raw)
        self.assertIn("download start timestamp", candidate.decision_reason)

    def test_c_no_download_timestamp_stays_blank(self):
        ctx, candidate = self.download()
        self.assertIsNone(candidate.timestamp)
        self.assertEqual("-", parser.timeline_rows(ctx)[0][1])

    def test_d_runtime_log_time_precedes_filesystem(self):
        ctx = self.analyze_files({"http-server.json": {}, "server-logs/runtime.log": "2099-09-20T00:00:00.999999Z inference completed"})
        candidate = self.candidates(ctx, "application_launch")[0]
        self.assertEqual("log_event", candidate.timestamp.semantics)
        self.assertEqual("2099-09-20 09:00:00.999999 KST", parser.format_timestamp_kst(candidate.timestamp))
        self.assertEqual("suspected", candidate.decision_status)

    def test_e_launch_filesystem_fallback_no_promotion(self):
        ctx = self.analyze_files({"http-server.json": {}, "server-logs/runtime.log": "TEST no event time"})
        candidate = self.candidates(ctx, "application_launch")[0]
        with patch.object(parser, "timestamp_from_stat", return_value=None):
            baseline = parser.analyze(ctx.input_path)
        original = self.candidates(baseline, "application_launch")[0]
        self.assertEqual(original.facts, candidate.facts)
        self.assertEqual("suspected", candidate.decision_status)
        self.assertEqual(original.decision_status, candidate.decision_status)
        self.assertEqual(original.direct_evidence, candidate.direct_evidence)
        self.assertEqual(original.evidence_families, candidate.evidence_families)
        self.assertEqual("launch_filesystem_fallback", candidate.timestamp.semantics)
        expected = min(a.metadata["collection_mtime_ns"] for a in ctx.artifacts if parser.basename(a.path) in {"http-server.json", "runtime.log"})
        self.assertEqual(parser.timestamp_from_stat(expected / 1_000_000_000, "test").normalized, candidate.timestamp.normalized)
        self.assertTrue(all(f.timestamp is None for f in candidate.facts))

    def test_f_fallback_does_not_spread_to_other_events(self):
        files = {EXE: b"TEST", SHORTCUT: b"TEST", "http-server.json": {}, "llmster-pid.lock": b"TEST",
                 "server-logs/runtime.log": "TEST no event time", "global.json": {"openedTabs": [], "selectedTabIndex": None, "openedWindowKeys": []},
                 "history.csv": history(("$ROOT\\server-logs-state.json", "File_Deleted")),
                 CONV: conversation(message(), userLastMessagedAt=1789708040375), "Documents/export.md": EXPORT}
        ctx = self.analyze_files(files)
        with patch.object(parser, "timestamp_from_stat", return_value=None):
            baseline = parser.analyze(ctx.input_path)
        self.assertEqual([c for c in baseline.candidates if c.action != "application_launch"], [c for c in ctx.candidates if c.action != "application_launch"])
        self.assertIsNone(self.candidates(ctx, "application_install")[0].timestamp)
        self.assertEqual([], self.candidates(ctx, "application_forced_exit"))
        self.assertTrue(self.candidates(ctx, "application_normal_exit"))

    def test_g_fallback_csv_is_kst_truncated(self):
        ctx, candidate = self.download(1789498316973)
        self.assertEqual("2026-09-16 03:51:56.973000 KST", parser.format_timestamp_kst(candidate.timestamp))
        row = self.candidates(ctx, "model_download")[0]
        self.assertEqual("2026-09-16 03:51:56.973000 KST", next(r[1] for r in parser.timeline_rows(ctx) if r[2] == row.korean_action))
        ctx = self.analyze_files({"http-server.json": {}, "server-logs/runtime.log": "TEST"})
        self.assertRegex(parser.format_timestamp_kst(self.candidates(ctx, "application_launch")[0].timestamp), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST$")

    def test_timestamp_alone_never_creates_download_or_launch(self):
        ctx = self.analyze_files({"download-jobs-info.json": {"startedTimestamp": 1789708040375}, "llmster-pid.lock": b"TEST"})
        self.assertEqual([], self.candidates(ctx, "model_download"))
        self.assertEqual([], self.candidates(ctx, "application_launch"))

    def test_completion_in_second_download_source_beats_first_start(self):
        job = copy.deepcopy(JOB)
        ctx = self.analyze_files({"download-jobs-info.json": job, "single-downloads-info.json": {"endedDownloadsMap": [["TEST", {"filename": "TEST.gguf", "status": {"type": "ended", "endReason": "completed"}, "completedTimestamp": "2026-09-20T00:00:00.999999Z"}]]}})
        candidate = self.candidates(ctx, "model_download")[0]
        self.assertEqual("2026-09-20 09:00:00.999999 KST", parser.format_timestamp_kst(candidate.timestamp))
        self.assertNotIn("fallback", candidate.decision_reason)

    def test_naive_completion_time_is_not_assumed_utc(self):
        _, candidate = self.download(1789708040375, "2026-09-20 01:30:00")
        self.assertEqual("download_started", candidate.timestamp.semantics)

    def test_launch_existing_explicit_time_not_replaced_by_host_stat(self):
        ctx = self.analyze_files({"http-server.json": {}, "server-logs/runtime.log": "TEST"})
        runtime = parser.parse_runtime_and_application(ctx)
        explicit = parser.iso_from_datetime("2026-09-15T18:51:56.973000Z", "ntfs_modified")
        runtime.runtime = [parser.replace(f, timestamp=explicit) for f in runtime.runtime]
        ctx.candidates.clear()
        parser.detect_application(ctx, runtime, [])
        self.assertEqual(explicit, self.candidates(ctx, "application_launch")[0].timestamp)

    def test_launch_no_time_and_no_stat_stays_blank(self):
        with patch.object(parser, "timestamp_from_stat", return_value=None):
            ctx = self.analyze_files({"http-server.json": {}, "server-logs/runtime.log": "TEST"})
        self.assertIsNone(self.candidates(ctx, "application_launch")[0].timestamp)


class Fix02Tests(FixtureCase):
    def test_deleted_resident_recovery_is_targeted_and_excludes_credentials(self):
        raw = json.dumps({"type": "image", "originalName": "TEST.png", "fileIdentifier": "F", "sizeBytes": 4}).encode()
        record = SimpleNamespace(header=SimpleNamespace(Flags=0, SequenceNumber=2), resident=True,
                                 segment=12, size=lambda: len(raw), open=lambda: io.BytesIO(raw))
        ctx = parser.AnalysisContext(Path("synthetic"))
        parser.recover_deleted_resident(ctx, record, r"Users\TEST\.lmstudio\user-files\TEST.png.metadata.json", "$MFT")
        self.assertEqual(1, len(ctx.artifacts))
        self.assertEqual("history_delete", ctx.artifacts[0].metadata["history_kind"])
        parser.recover_deleted_resident(ctx, record, r"Users\TEST\.lmstudio\credentials\lmstudio-hub.json", "$MFT")
        parser.recover_deleted_resident(ctx, record, r"Users\TEST\Documents\random.json", "$MFT")
        self.assertEqual(1, len(ctx.artifacts))

    def test_reused_live_mft_record_not_recovered_as_deleted(self):
        record = SimpleNamespace(header=SimpleNamespace(Flags=1), resident=True)
        ctx = parser.AnalysisContext(Path("synthetic"))
        parser.recover_deleted_resident(ctx, record, r"Users\TEST\.lmstudio\conversations\TEST.conversation.json", "$MFT")
        self.assertEqual([], ctx.artifacts)

    def test_deleted_nonresident_mft_content_not_carved(self):
        record = SimpleNamespace(header=SimpleNamespace(Flags=0), resident=False)
        ctx = parser.AnalysisContext(Path("synthetic"))
        parser.recover_deleted_resident(ctx, record, r"Users\TEST\.lmstudio\conversations\TEST.conversation.json", "$MFT")
        self.assertEqual([], ctx.artifacts)

    def test_image_type_schema_is_separate_from_document(self):
        files = copy.deepcopy(RULE_FIXTURES["image_upload"][0])
        files['user-files/TEST.png.metadata.json']['type'] = 'image'
        ctx = self.analyze_files(files)
        self.assertTrue(self.candidates(ctx, 'image_upload'))
        self.assertEqual([], self.candidates(ctx, 'document_upload'))

    def test_ntfs_prompt_delete_context_has_no_fabricated_delete_time(self):
        ctx = self.analyze_files({CONV: conversation(message("assistant"), userLastMessagedAt=1789708040375)})
        a = next(a for a in ctx.artifacts if a.path.endswith('.conversation.json'))
        a.kind = 'ntfs_file'
        a.modified = parser.iso_from_datetime('2026-09-20T00:00:00Z', 'ntfs_modified')
        ctx.candidates.clear()
        parser.detect_conversations(ctx, parser.parse_conversations(ctx), {}, [])
        c = self.candidates(ctx, 'prompt_delete')[0]
        self.assertEqual('indeterminate', c.decision_status)
        self.assertIsNone(c.timestamp)

    def test_protected_rule_function_bodies_unchanged_from_fix02(self):
        import ast
        expected = {
            'format_timestamp_kst': 'f4b38cba11fc537c47f1b5f08324639f0a0a414fff62433963b61702052b76d0',  # team format .ffffff KST
            'parse_model_data': 'cd578a857f57163f4f62453d1560cd6e0a8668934366acc5098f3b4ba5ae74c0',
            'download_node_summary': '2eb48b132b52133c26633dacc0b2fa4a4ae7e6450eefb123a544643b7aa7c659',
            'parse_downloads': '02836cb1c2254cf9ee9093c6cf9a0165540d35dfee6076af73d63def306e8b9c',
            'source_identity': 'e30a16ae7bef5851f4bd4539d5c44bb0c17465c9e8fa3301a42ef33b1e4afd12',
            'evaluate_decision': '9025f7470d6642f7f54fc0a35448e8d467b9f4070de066e76b2f719d2f43005b',
            'detect_application': 'b5ddefe72f429d3a06f64ea0d24492b9c79f5ede63563a2e7be103b205aecdd7',
            'history_download_patterns': 'f72d9f994788a0e92ae86ad1074fce7a361acb98fd514a2ac31ee58620fe08d5',
            'detect_models': 'fbe6b8b7d7a63f115145b29dfc6a2fa9abf34d59807343bb991a5fc88fb8073c',
        }
        functions = {n.name: hashlib.sha256((
            ast.dump(n, include_attributes=False, show_empty=True)
            if sys.version_info >= (3, 13) else ast.dump(n, include_attributes=False)
        ).encode()).hexdigest()
                     for n in ast.parse(Path(parser.__file__).read_text(encoding='utf-8')).body if isinstance(n, ast.FunctionDef)}
        for name, digest in expected.items():
            self.assertEqual(digest, functions[name], name)

    def usn_record(self, offset=8, reason="USN_REASON.FILE_DELETE|CLOSE", name="TEST.conversation.json"):
        return SimpleNamespace(filename=name, offset=offset, Reason=reason,
                               full_path="Users\\TEST\\.lmstudio\\conversations\\" + name,
                               timestamp=datetime.fromisoformat("2026-09-20T00:00:00+00:00"),
                               FileReferenceNumber=12)

    def test_usn_bad_record_does_not_discard_following_delete(self):
        ctx = parser.AnalysisContext(Path("synthetic"))
        records = [self.usn_record(), self.usn_record(offset="bad"), self.usn_record(offset=24)]
        parser.collect_ntfs_usn(ctx, SimpleNamespace(usnjrnl=SimpleNamespace(records=lambda: iter(records))), 0)
        self.assertEqual(2, len([f for f in ctx.facts if f.fact_type == "history_delete"]))
        self.assertEqual(1, ctx.usn_stats[0]["records_failed"])
        self.assertEqual(24, ctx.usn_stats[0]["last_successful_offset"])

    def test_usn_iterator_failure_reported_not_hidden(self):
        def records():
            yield self.usn_record()
            raise ValueError("SYNTHETIC_PRIVATE_ERROR")
        ctx = parser.AnalysisContext(Path("synthetic"))
        parser.collect_ntfs_usn(ctx, SimpleNamespace(usnjrnl=SimpleNamespace(records=records)), 0)
        self.assertEqual(1, len(ctx.facts))
        self.assertTrue(any(i.code == "usn_iterator_failed" for i in ctx.issues))
        self.assertNotIn("SYNTHETIC_PRIVATE_ERROR", repr(ctx.issues))

    def test_raw_usn_create_and_modify_tokens(self):
        self.assertEqual("history_create", parser.history_kind("USN_REASON.FILE_CREATE|CLOSE", "$UsnJrnl"))
        self.assertEqual("history_modify", parser.history_kind("USN_REASON.DATA_TRUNCATION|CLOSE", "$UsnJrnl"))

    def test_nonempty_conversation_create_with_exact_config_and_history(self):
        ctx = self.analyze_files({CONV: conversation(message(), conversationId="TEST-ID"), CONFIG: {"selectedConversation": "TEST.conversation.json"}, "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "File_Created"))})
        self.assertTrue(self.candidates(ctx, "conversation_create"))
        self.assertEqual("TEST-ID", self.candidates(ctx, "conversation_create")[0].conversation_ref)

    def test_nonempty_conversation_existence_alone_not_create(self):
        ctx = self.analyze_files({CONV: conversation(message())})
        self.assertEqual([], self.candidates(ctx, "conversation_create"))

    def test_running_residue_is_not_forced_exit(self):
        ctx = self.analyze_files({"http-server.json": {"pid": 123}, "llmster-pid.lock": b"123"})
        self.assertEqual([], self.candidates(ctx, "application_forced_exit"))

    def test_history_residue_is_not_forced_exit(self):
        ctx = self.analyze_files({"history.csv": history(("$ROOT\\http-server.json", "File_Created"), ("$ROOT\\llmster-pid.lock", "File_Created"))})
        self.assertEqual([], self.candidates(ctx, "application_forced_exit"))

    def test_explicit_forced_log_still_positive(self):
        ctx = self.analyze_files({LOG: "2026-09-20T00:00:00Z forced termination"})
        self.assertTrue(self.candidates(ctx, "application_forced_exit"))

    def test_attachment_ntfs_created_time_without_strength_change(self):
        ctx = self.analyze_files(RULE_FIXTURES["document_upload"][0])
        baseline = self.candidates(ctx, "document_upload")[0]
        a = next(a for a in ctx.artifacts if a.path.endswith('.metadata.json'))
        a.kind = "ntfs_file"
        a.created = parser.iso_from_datetime("2026-09-20T00:00:00.999999Z", "ntfs_created")
        ctx.candidates.clear()
        parser.detect_attachments(ctx, parser.parse_attachments(ctx), parser.parse_conversations(ctx))
        updated = self.candidates(ctx, "document_upload")[0]
        self.assertEqual(baseline.decision_status, updated.decision_status)
        self.assertEqual("2026-09-20 09:00:00.999999 KST", parser.format_timestamp_kst(updated.timestamp))

    def test_directory_attachment_time_remains_blank(self):
        ctx = self.analyze_files(RULE_FIXTURES["image_upload"][0])
        self.assertIsNone(self.candidates(ctx, "image_upload")[0].timestamp)

    def test_attachment_same_basename_other_profile_not_timestamp_source(self):
        files = copy.deepcopy(RULE_FIXTURES["image_upload"][0])
        files['history.csv'] = history((r'C:\Other\.lmstudio\user-files\TEST.png.metadata.json', 'File_Created'))
        ctx = self.analyze_files(files)
        self.assertIsNone(self.candidates(ctx, 'image_upload')[0].timestamp)

    def test_nonempty_create_does_not_claim_empty_structure(self):
        ctx = self.analyze_files({CONV: conversation(message()), CONFIG: {'selectedConversation': 'TEST.conversation.json'}, 'history.csv': history(('$ROOT\\conversations\\TEST.conversation.json', 'File_Created'))})
        candidate = self.candidates(ctx, 'conversation_create')[0]
        self.assertNotIn('empty initial structure', candidate.matched_conditions)

    def test_assistant_and_unrelated_rewrite_not_prompt_delete(self):
        ctx = self.analyze_files({CONV: conversation(message("assistant")), "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "Data_Overwrite"))})
        self.assertEqual([], self.candidates(ctx, "prompt_delete"))

    def test_historical_user_activity_without_body_is_indeterminate(self):
        ctx = self.analyze_files({CONV: conversation(message("assistant"), userLastMessagedAt=1789708040375), "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "Data_Overwrite"))})
        self.assertEqual("indeterminate", self.candidates(ctx, "prompt_delete")[0].decision_status)

    def test_prompt_before_after_requires_same_actual_conversation_and_rewrite(self):
        before = self.analyze_files({CONV: conversation(message(text="removed"), message("assistant"), conversationId="TEST-ID")})
        after = self.analyze_files({CONV: conversation(message("assistant"), conversationId="TEST-ID"), "history.csv": history(("$ROOT\\conversations\\TEST.conversation.json", "Data_Overwrite"))})
        parser.detect_snapshot_transitions(after, before)
        self.assertEqual("confirmed", self.candidates(after, "prompt_delete")[0].decision_status)

    def test_before_after_without_rewrite_not_delete(self):
        before = self.analyze_files({CONV: conversation(message(), conversationId="TEST-ID")})
        after = self.analyze_files({CONV: conversation(message("assistant"), conversationId="TEST-ID")})
        parser.detect_snapshot_transitions(after, before)
        self.assertEqual([], self.candidates(after, "prompt_delete"))

    def test_account_login_transition(self):
        before = self.analyze_files({"local-identity.json": {"type": "none"}, "user-profile.json": {"profile": None}})
        after = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "user-profile.json": {"profile": {"id": "ACCOUNT-A"}}})
        parser.detect_snapshot_transitions(after, before)
        self.assertTrue(any("Before" in c.decision_reason for c in self.candidates(after, "login")))

    def test_account_logout_transition(self):
        before = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "user-profile.json": {"profile": {"id": "ACCOUNT-A"}}})
        after = self.analyze_files({"local-identity.json": {"type": "none"}, "user-profile.json": {"profile": None}})
        parser.detect_snapshot_transitions(after, before)
        self.assertEqual("suspected", self.candidates(after, "logout")[0].decision_status)

    def test_account_switch_needs_changed_actual_identifier_and_history(self):
        before = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "user-profile.json": {"profile": {"id": "ACCOUNT-A"}}})
        after = self.analyze_files({"local-identity.json": {"type": "loggedInUser"}, "user-profile.json": {"profile": {"id": "ACCOUNT-B"}}, "history.csv": history(("$ROOT\\user-profile.json", "Data_Overwrite"))})
        parser.detect_snapshot_transitions(after, before)
        candidate = self.candidates(after, "account_switch")[0]
        self.assertEqual("confirmed", candidate.decision_status)
        self.assertNotIn("ACCOUNT-A", repr(candidate))
        self.assertNotIn("ACCOUNT-B", repr(candidate))

    def test_account_current_profile_only_not_switch(self):
        ctx = self.analyze_files({"user-profile.json": {"profile": {"id": "ACCOUNT-B"}}})
        self.assertEqual([], self.candidates(ctx, "account_switch"))

    def test_export_generic_document_remains_negative(self):
        ctx = self.analyze_files({"Documents/new.md": "# ordinary document", "history.csv": history(("$ROOT\\Documents\\new.md", "File_Created"))})
        self.assertEqual([], self.candidates(ctx, "conversation_export"))


class ReadableTimelineDetailsTests(FixtureCase):
    def details(self, files, action):
        ctx = self.analyze_files(files)
        candidate = self.candidates(ctx, action)[0]
        return ctx, candidate, parser.candidate_behavior_details(ctx, candidate), parser.candidate_artifact_details(candidate)

    def test_model_change_and_conversation_delete_have_explanatory_prefixes(self):
        _, _, behavior, _ = self.details(
            {"model-data.json": {"json": [["google/gemma-3-1b", {"lastLoadedTimestamp": 1789708040375}]]}},
            "model_change",
        )
        self.assertEqual("모델 변경 기록_google/gemma-3-1b", behavior)
        _, _, behavior, _ = self.details(RULE_FIXTURES["conversation_delete"][0], "conversation_delete")
        self.assertEqual("대화 파일 삭제 흔적_TEST.conversation.json", behavior)

    def test_prompt_sent_and_unsent_wording_uses_first_line(self):
        sent = self.analyze_files({CONV: conversation(message(text="sent first\nfull body"), message("assistant"))})
        unsent = self.analyze_files({CONV: conversation(message(text="draft first\nfull body"))})
        self.assertEqual("사용자 메시지 전송_sent first", parser.candidate_behavior_details(sent, self.candidates(sent, "prompt_interaction")[0]))
        self.assertEqual("프롬프트 작성 흔적(전송 미확인)_draft first", parser.candidate_behavior_details(unsent, self.candidates(unsent, "prompt_interaction")[0]))

    def test_linked_and_metadata_only_attachments_are_distinguished(self):
        for media, suffix, mime, action in (("image", "png", "image/png", "image_upload"),
                                            ("document", "pdf", "application/pdf", "document_upload")):
            with self.subTest(media=media):
                metadata = {"originalName": f"TEST.{suffix}", "fileIdentifier": "TEST-FILE", "type": mime, "sizeBytes": 4}
                linked_message = message()
                linked_message["versions"][0]["content"].append({"type": "file", "fileIdentifier": "TEST-FILE", "fileType": mime})
                linked = self.analyze_files({f"user-files/TEST.{suffix}.metadata.json": metadata,
                                             CONV: conversation(linked_message, conversationId="TEST-CONV")})
                self.assertEqual(f"전송 메시지 첨부_TEST.{suffix}",
                                 parser.candidate_behavior_details(linked, self.candidates(linked, action)[0]))
                metadata_only = self.analyze_files({f"user-files/TEST.{suffix}.metadata.json": metadata})
                expected = f"{'이미지' if media == 'image' else '문서'} 업로드 준비 흔적(전송 불확인)_TEST.{suffix}"
                self.assertEqual(expected, parser.candidate_behavior_details(metadata_only, self.candidates(metadata_only, action)[0]))

    def test_completed_and_incomplete_download_wording(self):
        completed = self.analyze_files({"download-jobs-info.json": JOB})
        self.assertEqual("다운로드 완료 기록_TEST.gguf",
                         parser.candidate_behavior_details(completed, self.candidates(completed, "model_download")[0]))
        incomplete_job = {"jobs": [{"startedTimestamp": 1789708040375, "jobState": {"type": "downloading"},
                                    "tasks": [{"download": {"filename": "TEST.gguf", "targetPath": "TEST.gguf", "status": "downloading"}}]}]}
        incomplete = self.analyze_files({"download-jobs-info.json": incomplete_job})
        self.assertEqual("다운로드 시도 흔적(완료 미확인)_TEST.gguf",
                         parser.candidate_behavior_details(incomplete, self.candidates(incomplete, "model_download")[0]))

    def test_export_completion_wording_requires_creation_history(self):
        incomplete = self.analyze_files({"Documents/export.md": EXPORT})
        complete = self.analyze_files({"Documents/export.md": EXPORT,
                                       "history.csv": history(("$ROOT\\Documents\\export.md", "File_Created"))})
        self.assertEqual("Export 파일 흔적(완료 미확인)_export.md",
                         parser.candidate_behavior_details(incomplete, self.candidates(incomplete, "conversation_export")[0]))
        self.assertEqual("Export 완료 기록_export.md",
                         parser.candidate_behavior_details(complete, self.candidates(complete, "conversation_export")[0]))

    def test_account_switch_arrow_uses_only_observed_safe_identifiers(self):
        before = self.analyze_files({"local-identity.json": {"type": "loggedInUser"},
                                     "user-profile.json": {"profile": {"id": "ACCOUNT-A"}}})
        after = self.analyze_files({"local-identity.json": {"type": "loggedInUser"},
                                    "user-profile.json": {"profile": {"id": "ACCOUNT-B"}},
                                    "history.csv": history(("$ROOT\\user-profile.json", "Data_Overwrite"))})
        parser.detect_snapshot_transitions(after, before)
        behavior = parser.candidate_behavior_details(after, self.candidates(after, "account_switch")[0])
        self.assertRegex(behavior, r"^계정 전환 기록_sha256:[0-9a-f]{12} → sha256:[0-9a-f]{12}$")
        self.assertNotIn("ACCOUNT-A", behavior)
        self.assertNotIn("ACCOUNT-B", behavior)

    def test_artifact_details_are_named_user_facing_segments_without_internal_diagnostics(self):
        ctx = self.analyze_files({"download-jobs-info.json": JOB, "models/TEST.gguf": b"GGUF",
                                  "models/TEST.gguf:Zone.Identifier": "[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.org/TEST.gguf"})
        details = parser.candidate_artifact_details(self.candidates(ctx, "model_download")[0])
        segments = details.split(" | ")
        self.assertTrue(all(re.fullmatch(r"\[[^\]]+\] .+", segment) for segment in segments))
        self.assertIn("[Download Record]", details)
        self.assertIn("[GGUF]", details)
        self.assertIn("[Zone.Identifier]", details)
        self.assertIn("시각 출처=다운로드 시작", details)
        for forbidden in ("Rule=", "Evidence Family=", "Direct Evidence=", "Facts=", "confidence=",
                          "DIRECT", "SUPPORTING", "timestamp_source=", "download_started", "history_delete"):
            self.assertNotIn(forbidden, details)

        create = self.analyze_files(RULE_FIXTURES["conversation_create"][0])
        self.assertIn("[Conversation Config]", parser.candidate_artifact_details(self.candidates(create, "conversation_create")[0]))

    def test_multiple_artifacts_are_deterministic_and_duplicate_descriptions_are_removed(self):
        ctx = self.analyze_files({CONV: conversation(message(), message("assistant"), conversationId="TEST-CONV"),
                                  LOG: "2026-09-20T00:00:00Z inference completed conversationId=TEST-CONV"})
        candidate = self.candidates(ctx, "prompt_interaction")[0]
        candidate.facts.append(candidate.facts[0])
        first = parser.candidate_artifact_details(candidate)
        second = parser.candidate_artifact_details(candidate)
        segments = first.split(" | ")
        self.assertEqual(first, second)
        self.assertGreater(len(segments), 1)
        self.assertEqual(len(segments), len(set(segments)))

    def test_formatting_does_not_mutate_candidate_decision_contract(self):
        ctx = self.analyze_files({CONV: conversation(message(), message("assistant"), conversationId="TEST-CONV"),
                                  LOG: "2026-09-20T00:00:00Z inference completed conversationId=TEST-CONV"})
        candidate = self.candidates(ctx, "prompt_interaction")[0]
        before = (candidate.action, candidate.decision_status, candidate.timestamp, tuple(candidate.facts),
                  frozenset(candidate.evidence_families), candidate.direct_evidence, candidate.conversation_ref)
        parser.candidate_behavior_details(ctx, candidate)
        parser.candidate_artifact_details(candidate)
        after = (candidate.action, candidate.decision_status, candidate.timestamp, tuple(candidate.facts),
                 frozenset(candidate.evidence_families), candidate.direct_evidence, candidate.conversation_ref)
        self.assertEqual(before, after)

    def test_sensitive_values_do_not_reappear_in_readable_details(self):
        secret = "READABLE_DETAILS_PRIVATE_SECRET"
        ctx = self.analyze_files({"local-identity.json": {"type": "loggedInUser"},
                                  "user-profile.json": {"profile": {"email": secret + "@example.test"}},
                                  "lmstudio-hub.json": {"key": {"accessToken": secret}}})
        candidate = self.candidates(ctx, "login")[0]
        emitted = parser.candidate_behavior_details(ctx, candidate) + parser.candidate_artifact_details(candidate)
        self.assertNotIn(secret, emitted)
        self.assertIn("sha256:", emitted)


class UsnArtifactDetailsTests(FixtureCase):
    target = r"volume0:\Users\llmtest\.lmstudio\conversations\1790915225165.conversation.json"
    journal = r"volume0:\$Extend\$UsnJrnl:$J"

    def usn_fact(self, offset, fact_type="history_modify", target=None, source=None):
        return parser.ObservedFact(
            fact_type, "filesystem",
            parser.Provenance("SYNTHETIC_USN.dd", source or self.journal, "", f"offset 0x{offset:x}"),
            "DATA_OVERWRITE|CLOSE", key="42#1",
            timestamp=parser.iso_from_datetime("2026-10-02T00:00:00Z", "usn_event"),
            target_path=self.target if target is None else target,
        )

    def edit_context(self, count=663):
        ctx = parser.AnalysisContext(Path("SYNTHETIC_USN.dd"), source_image="SYNTHETIC_USN.dd")
        content = json.dumps(conversation(message(text="first line\nfull edited body", edited=True))).encode("utf-8")
        ctx.add_artifact(parser.ArtifactRecord(
            "SYNTHETIC_CONVERSATION", self.target,
            parser.Provenance(ctx.source_image, self.target), "ntfs_file", content=content,
        ))
        parser.parse_json_artifacts(ctx)
        summaries = parser.parse_conversations(ctx)
        for index in range(count):
            ctx.add_fact(self.usn_fact(0x100 + index * 0x80))
        parser.detect_conversations(ctx, summaries, {}, [])
        return ctx, self.candidates(ctx, "message_edit")[0]

    @staticmethod
    def legacy_details(candidate):
        # Freeze the pre-aggregation serializer to compare the other columns.
        details = sorted({parser.fact_artifact_detail(fact) for fact in candidate.facts})
        if candidate.timestamp and candidate.timestamp.semantics == "download_started" and details:
            for index, detail in enumerate(details):
                if detail.startswith("[Download Record] "):
                    details[index] = detail + ", 시각 출처=다운로드 시작"
                    break
        return " | ".join(details)

    def test_663_usn_modifications_keep_all_facts_and_one_counted_group(self):
        ctx, candidate = self.edit_context()
        before = copy.deepcopy(ctx)
        facts_list = candidate.facts
        self.assertEqual(664, len(self.legacy_details(candidate).split(" | ")))
        details = parser.candidate_artifact_details(candidate)
        segments = details.split(" | ")
        self.assertEqual(2, len(segments))
        self.assertIn("[$UsnJrnl] 대상=1790915225165.conversation.json, 이벤트=수정, 위치=offset 0x100, 동일 근거=663건", segments)
        self.assertIn("[Conversation]", details)
        self.assertIn("JSON 위치=/messages/0/versions/0", details)
        self.assertNotIn("\r", details)
        self.assertNotIn("\n", details)
        self.assertIs(facts_list, candidate.facts)
        self.assertEqual(664, len(candidate.facts))
        self.assertEqual(663, sum(f.fact_type == "history_modify" for f in candidate.facts))
        self.assertEqual(before, ctx)

    def test_other_targets_events_and_fact_types_stay_separate(self):
        _, candidate = self.edit_context(2)
        candidate.facts.extend([
            self.usn_fact(0x200, target=self.target.replace("1790915225165", "OTHER")),
            self.usn_fact(0x280, "history_create"),
            self.usn_fact(0x300, "history_observed"),
            self.usn_fact(0x380, "listing_observed"),
        ])
        details = parser.candidate_artifact_details(candidate)
        self.assertEqual(6, len(details.split(" | ")))
        self.assertEqual(1, details.count("동일 근거="))
        for segment in ("대상=OTHER.conversation.json, 이벤트=수정", "이벤트=생성", "이벤트=관찰", "상태=파일 목록 관찰"):
            self.assertIn(segment, details)

    def test_same_basename_in_other_profile_or_journal_stays_separate(self):
        _, candidate = self.edit_context(2)
        for offset in (0x100, 0x180):
            fact = self.usn_fact(offset)
            candidate.facts.extend([
                replace(fact, target_path=self.target.replace("llmtest", "other-user")),
                replace(fact, provenance=replace(fact.provenance, original_artifact_path=self.journal.replace("volume0", "volume1"))),
                replace(fact, provenance=replace(fact.provenance, source_image="OTHER.dd")),
            ])
        details = parser.candidate_artifact_details(candidate)
        self.assertEqual(5, len(details.split(" | ")))
        self.assertEqual(4, details.count("동일 근거=2건"))

    def test_mft_conversation_and_download_locators_are_not_aggregated(self):
        _, candidate = self.edit_context(2)
        edit_fact = candidate.facts[0]
        candidate.facts.append(replace(edit_fact, provenance=replace(edit_fact.provenance, evidence_location="/messages/1/versions/0")))
        for index in (10, 11):
            candidate.facts.append(parser.ObservedFact(
                "history_modify", "filesystem", parser.Provenance("SYNTHETIC_USN.dd", r"volume0:\$MFT", "", f"MFT record {index}"),
                target_path=self.target,
            ))
            candidate.facts.append(parser.ObservedFact(
                "download_completed_record", "model_state", parser.Provenance("SYNTHETIC_USN.dd", "download-jobs-info.json", "", f"/jobs/{index}"),
                "TEST.gguf",
            ))
        details = parser.candidate_artifact_details(candidate)
        for label in ("[Conversation]", "[$MFT]", "[Download Record]"):
            self.assertEqual(2, details.count(label))
        self.assertEqual(7, len(details.split(" | ")))
        self.assertEqual(1, details.count("동일 근거="))

    def test_representative_is_deterministic_even_when_fact_order_changes(self):
        _, candidate = self.edit_context()
        candidate.facts.append(self.usn_fact(0x80))
        expected = parser.candidate_artifact_details(candidate)
        self.assertEqual(expected, parser.candidate_artifact_details(candidate))
        self.assertEqual(expected, parser.candidate_artifact_details(replace(candidate, facts=list(reversed(candidate.facts)))))
        self.assertEqual(expected, parser.candidate_artifact_details(replace(candidate, facts=candidate.facts[200:] + candidate.facts[:200])))
        self.assertIn("위치=offset 0x100, 동일 근거=664건", expected)

    def test_single_usn_and_missing_target_keep_legacy_display(self):
        _, candidate = self.edit_context(1)
        self.assertEqual(self.legacy_details(candidate), parser.candidate_artifact_details(candidate))
        candidate.facts.extend([self.usn_fact(0x180, target=""), self.usn_fact(0x200, target="")])
        self.assertEqual(self.legacy_details(candidate), parser.candidate_artifact_details(candidate))

    def test_edit_csv_only_changes_artifact_details_and_recovery_bytes_match(self):
        ctx, _ = self.edit_context()
        before = copy.deepcopy(ctx)
        with tempfile.TemporaryDirectory(prefix="SYNTHETIC_USN_CSV_") as temporary:
            root = Path(temporary)
            with patch.object(parser, "candidate_artifact_details", side_effect=self.legacy_details):
                old_rows = parser.timeline_rows(ctx)
                parser.write_csv(root / "old_timeline.csv", parser.TIMELINE_HEADER, old_rows)
                parser.write_csv(root / "old_recovered.csv", parser.CONVERSATION_HEADER, parser.conversation_rows(ctx))
            new_rows = parser.timeline_rows(ctx)
            parser.write_csv(root / "new_timeline.csv", parser.TIMELINE_HEADER, new_rows)
            parser.write_csv(root / "new_recovered.csv", parser.CONVERSATION_HEADER, parser.conversation_rows(ctx))
            parser.write_csv(root / "repeat_timeline.csv", parser.TIMELINE_HEADER, parser.timeline_rows(ctx))
            self.assertEqual([row[:6] for row in old_rows], [row[:6] for row in new_rows])
            self.assertEqual(1, sum(a[6] != b[6] for a, b in zip(old_rows, new_rows)))
            self.assertEqual((root / "old_recovered.csv").read_bytes(), (root / "new_recovered.csv").read_bytes())
            raw = (root / "new_timeline.csv").read_bytes()
            self.assertEqual(raw, (root / "repeat_timeline.csv").read_bytes())
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            self.assertEqual(len(new_rows) + 1, raw.count(b"\r\n"))
            self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
            emitted = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
            self.assertEqual(parser.TIMELINE_HEADER, emitted[0])
            self.assertEqual(new_rows, emitted[1:])
            self.assertTrue(all(len(row) == 7 and all(row) for row in emitted))
        self.assertEqual(before, ctx)

    def test_all_21_rule_fixtures_keep_other_timeline_columns_and_recovery(self):
        for action, (positive, negative, _) in RULE_FIXTURES.items():
            for files in (positive, negative):
                with self.subTest(action=action, files=files):
                    ctx = self.analyze_files(files)
                    before = copy.deepcopy(ctx)
                    with patch.object(parser, "candidate_artifact_details", side_effect=self.legacy_details):
                        old_rows = parser.timeline_rows(ctx)
                        old_recovered = parser.conversation_rows(ctx)
                    self.assertEqual([row[:6] for row in old_rows], [row[:6] for row in parser.timeline_rows(ctx)])
                    self.assertEqual(old_recovered, parser.conversation_rows(ctx))
                    self.assertEqual(before, ctx)


class FinalContractTests(FixtureCase):
    def test_exact_headers_and_no_empty_cells(self):
        self.assertEqual(['Model', 'Timestamp', 'User_behavior', 'Behavior_details ', 'Verdict', 'Artifact_path', 'Artifact_details '], parser.TIMELINE_HEADER)
        self.assertEqual(['Model', 'timestamp', 'conversation_uuid', 'conversation_title', 'message_uuid', 'parent_message_uuid', 'message order', 'role', 'content', 'Artifact_path'], parser.CONVERSATION_HEADER)
        ctx = self.analyze_files({CONV: conversation(message(), message('assistant'))})
        for row in parser.timeline_rows(ctx) + parser.conversation_rows(ctx):
            self.assertTrue(all(cell != '' for cell in row))
            self.assertEqual('lmstudio', row[0])

    def test_hyphen_and_formula_guard(self):
        for value in ('', None, '-'):
            self.assertEqual('-', parser.spreadsheet_safe(value))
        for value in ('-danger', '+formula', '=SUM(A1:A2)', '@SUM(1)', '=text\nsecond'):
            self.assertEqual("'" + value, parser.spreadsheet_safe(value))

    def test_indeterminate_only_terminal_not_context_deletion(self):
        ctx = self.analyze_files({CONV: conversation(message('assistant'), userLastMessagedAt=1789708040375), 'history.csv': history(('$ROOT\\conversations\\TEST.conversation.json', 'Data_Overwrite'))})
        uncertain = self.candidates(ctx, 'prompt_delete')[0]
        stream = io.StringIO()
        parser.report_analysis(ctx, stream)
        self.assertIn('미확정/CSV 제외', stream.getvalue())
        self.assertIn(uncertain.rule_id, stream.getvalue())
        self.assertIn('internal=indeterminate', stream.getvalue())
        self.assertTrue(uncertain in ctx.candidates)
        self.assertFalse(any('Rule=' + uncertain.rule_id in row[6] for row in parser.timeline_rows(ctx)))

    def test_confirmed_and_suspected_csv_labels(self):
        ctx = self.analyze_files({CONV: conversation(message(edited=True))})
        self.assertEqual({'확정', '의심'}, {row[4] for row in parser.timeline_rows(ctx)})

    def test_single_explicit_logout_success_is_direct(self):
        ctx = self.analyze_files({LOG: '2026-09-20T00:00:00Z logout succeeded'})
        candidate = self.candidates(ctx, 'logout')[0]
        self.assertEqual(1, len(candidate.facts))
        self.assertEqual('confirmed', candidate.decision_status)
        self.assertEqual('explicit_logout_log', candidate.facts[0].direct_tag)

    def test_allowlisted_direct_log_actions(self):
        for text, action in [('login succeeded', 'login'), ('logged in', 'login'), ('logged out', 'logout'), ('signed out', 'logout'), ('normal exit', 'application_normal_exit'), ('graceful shutdown', 'application_normal_exit'), ('forced termination', 'application_forced_exit'), ('model loaded', 'model_change')]:
            with self.subTest(text=text):
                ctx = self.analyze_files({LOG: '2026-09-20T00:00:00Z [INFO] ' + text})
                self.assertTrue(any(c.direct_evidence and c.decision_status == 'confirmed' for c in self.candidates(ctx, action)))

    def test_log_quote_negative_failure_and_substring_not_direct(self):
        for text in ['not logged out', 'logout succeeded? false', 'prompt="logout succeeded"', 'logout succeeded but validation failed', 'attempting graceful shutdown', 'forced termination requested', 'model loaded failed', '[ERROR] logout succeeded']:
            with self.subTest(text=text):
                ctx = self.analyze_files({LOG: '2026-09-20T00:00:00Z ' + text})
                self.assertFalse(any(f.direct_tag for f in ctx.facts))

    def test_text_listing_even_inside_server_logs_not_direct(self):
        ctx = self.analyze_files({'logs/.lmstudio/server-logs/listing.txt': 'logout succeeded'})
        self.assertFalse(any(f.direct_tag for f in ctx.facts))
        self.assertFalse(any(c.decision_status == 'confirmed' for c in ctx.candidates))

    def test_wrong_log_directory_not_direct(self):
        ctx = self.analyze_files({'logs/server-logs/test.log': 'logout succeeded'})
        self.assertFalse(any(f.direct_tag for f in ctx.facts))

    def test_explicit_model_log_preserves_actual_identifier(self):
        ctx = self.analyze_files({LOG: '2026-09-20T00:00:00Z model loaded: TEST/model'})
        self.assertEqual('모델 변경 기록_TEST/model', parser.candidate_behavior_details(ctx, self.candidates(ctx, 'model_change')[0]))

    def test_nonconversation_secret_and_embedded_preview_redacted(self):
        for text, secret in [('secret=PRIVATE_VALUE', 'PRIVATE_VALUE'), ('preview=' + 'A' * 300, 'A' * 300), ('access_token=PRIVATE_TOKEN', 'PRIVATE_TOKEN')]:
            self.assertNotIn(secret, parser.safe_nonconversation_text(text))

    def test_uninstaller_creation_is_not_execution(self):
        import sqlite3
        ctx = self.analyze_files({})
        db = ctx.input_path / 'history.db'
        connection = sqlite3.connect(db)
        connection.execute('CREATE TABLE LogFile (EventTime TEXT, Event TEXT, FileName TEXT, FullPath TEXT)')
        connection.execute('INSERT INTO LogFile VALUES (?, ?, ?, ?)', ('2026-09-20T00:00:00Z', 'File_Created', 'uninstall LM Studio.exe', r'C:\Users\TEST\AppData\Local\Programs\LM Studio\uninstall LM Studio.exe'))
        connection.commit()
        connection.close()
        updated = parser.analyze(ctx.input_path)
        self.assertFalse(any(f.direct_tag == 'explicit_uninstaller_execution' for f in updated.facts))

    def test_null_profile_lock_identifier_not_confirmed(self):
        for files in [{'user-profile.json': {'profile': None}}, {'llmster-pid.lock': b'1'}, {'model-data.json': {'json': [['TEST/model', {}]]}}]:
            self.assertFalse(any(c.decision_status == 'confirmed' for c in self.analyze_files(files).candidates))

    def test_timeline_uses_first_line_and_conversation_keeps_full_multiline_content(self):
        content = '=full prompt\n' + 'long ' * 150
        ctx = self.analyze_files({CONV: conversation(message(text=content, edited=True))})
        self.assertEqual("프롬프트 작성 흔적(전송 미확인)_=full prompt",
                         parser.candidate_behavior_details(ctx, self.candidates(ctx, 'prompt_interaction')[0]))
        self.assertEqual("사용자 메시지 수정 기록_=full prompt",
                         parser.candidate_behavior_details(ctx, self.candidates(ctx, 'message_edit')[0]))
        self.assertIn(content, [row[8].removeprefix("'") for row in parser.conversation_rows(ctx)])
        self.assertTrue(all('Rule=' not in row[6] for row in parser.timeline_rows(ctx)))

    def test_conversation_uuid_display_suffix_normalization_only(self):
        cases = (
            ('1789494458762.conversation.json', '1789494458762', '1789494458762.conversation.json'),
            ('', '1789494458762', ''),
            ('conv-real-id-123', 'conv-real-id-123', 'conv-real-id-123'),
        )
        for conversation_id, expected, expected_internal in cases:
            with self.subTest(conversation_id=conversation_id or 'filename fallback'):
                fields = {'name': None}
                if conversation_id:
                    fields['conversationId'] = conversation_id
                ctx = self.analyze_files({
                    'conversations/1789494458762.conversation.json': conversation(message(), **fields),
                })
                rows = parser.conversation_rows(ctx)
                self.assertEqual(1, len(rows))
                row = rows[0]
                self.assertEqual(expected, row[2])
                self.assertEqual('-', row[1])
                self.assertEqual(['-', '-', '-', '1', 'user', 'TEST text'], row[3:9])
                self.assertTrue(row[9].endswith(r'conversations\1789494458762.conversation.json'))
                self.assertEqual(expected_internal, ctx.messages[0].conversation_id)

    def test_explicit_id_beats_filename(self):
        ctx = self.analyze_files({CONV: conversation(message(), conversationId='actual-id')})
        self.assertEqual('actual-id', parser.conversation_rows(ctx)[0][2])

    def test_order_preserves_all_retry_versions_numerically(self):
        versions = [message('assistant', str(i))['versions'][0] for i in range(12)]
        ctx = self.analyze_files({CONV: conversation(message(text='first'), {'versions': versions, 'currentlySelected': 11}, message('tool', 'last'))})
        rows = parser.conversation_rows(ctx)
        self.assertEqual(list(map(str, range(1, 15))), [r[6] for r in rows])
        self.assertEqual(['first'] + list(map(str, range(12))) + ['last'], [r[8] for r in rows])

    def test_other_actual_role_preserved(self):
        ctx = self.analyze_files({CONV: conversation(message('system', 'actual system message'))})
        self.assertEqual('system', parser.conversation_rows(ctx)[0][7])

    def test_metadata_only_content_is_hyphen(self):
        ctx = self.analyze_files({CONV: conversation({'versions': [{'role': 'user', 'content': []}]})})
        self.assertEqual('-', parser.conversation_rows(ctx)[0][8])

    def test_new_filename_and_exact_legacy_cleanup(self):
        ctx = self.analyze_files({CONV: conversation(message())})
        output = ctx.input_path.parent / 'out'
        output.mkdir()
        (output / 'recovered_conversations.csv').write_text('legacy')
        (output / 'unrelated.txt').write_text('keep')
        with self.assertRaises(FileExistsError):
            parser.write_outputs(ctx, output)
        self.assertEqual('legacy', (output / 'recovered_conversations.csv').read_text())
        self.assertFalse((output / 'timeline.csv').exists())
        parser.write_outputs(ctx, output, overwrite=True)
        self.assertTrue((output / 'recovered_conversations.csv').exists())
        self.assertNotEqual('legacy', (output / 'recovered_conversations.csv').read_text(encoding='utf-8-sig'))
        self.assertFalse((output / 'recovered_conversation.csv').exists())
        self.assertEqual('keep', (output / 'unrelated.txt').read_text())

    def test_output_evidence_rejected_before_legacy_cleanup(self):
        ctx = self.analyze_files({CONV: conversation(message()), 'recovered_conversations.csv': 'preserve'})
        with self.assertRaises(ValueError):
            parser.write_outputs(ctx, ctx.input_path)
        self.assertEqual('preserve', (ctx.input_path / 'recovered_conversations.csv').read_text())

    def test_protected_directories_reject_output_for_other_input(self):
        temporary = tempfile.TemporaryDirectory(prefix="SYNTHETIC_RESEARCH_PATH_")
        self.addCleanup(temporary.cleanup)
        research_root = Path(temporary.name) / "LMStudio_Research_Evidence"
        for name in ("snapshot_a", "snapshot_b"):
            input_path = research_root / name / "input.dd"
            input_path.parent.mkdir(parents=True)
            input_path.write_bytes(b"SYNTHETIC_EVIDENCE")
            self.assertEqual(research_root, parser.research_evidence_root(input_path))
            self.assertTrue(parser.validate_paths(input_path, research_root / "output"))

    def test_cli_progress_diagnostics_without_raw_prompt_or_secret(self):
        from contextlib import redirect_stdout, redirect_stderr
        raw_prompt = 'DO_NOT_ECHO_RAW_PROMPT'
        secret = 'TEST_PRIVATE_CREDENTIAL'
        ctx = self.analyze_files({CONV: conversation(message(text=raw_prompt)), 'lmstudio-hub.json': {'key': {'secret': secret}}})
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = parser.main([str(ctx.input_path), '--output', str(ctx.input_path.parent / 'cli')])
        self.assertEqual(0, rc)
        for step in range(1, 8):
            self.assertIn(f'[{step}/7]', out.getvalue())
        for label in ('ObservedFact=', 'Candidate=', 'Rule=', 'Evidence Family=', 'Direct Evidence=', 'limitation:', 'recovered_conversations.csv'):
            self.assertIn(label, out.getvalue())
        self.assertNotIn(raw_prompt, out.getvalue() + err.getvalue())
        self.assertNotIn(secret, out.getvalue() + err.getvalue())

    def test_fatal_and_nonfatal_issues_are_reported(self):
        ctx = parser.AnalysisContext(Path('.'))
        ctx.issue('test_fatal', 'test', 'fatal limitation', True)
        ctx.issue('test_partial', 'test', 'partial limitation')
        stream = io.StringIO()
        parser.report_analysis(ctx, stream)
        self.assertIn('[fatal] test_fatal', stream.getvalue())
        self.assertIn('[non-fatal] test_partial', stream.getvalue())


class ArtifactNormalizationTests(FixtureCase):
    @staticmethod
    def baseline_paths(candidate):
        return sorted({parser.safe_nonconversation_text(f.provenance.original_artifact_path, max_length=2000)
                       for f in candidate.facts if f.provenance.original_artifact_path})

    @staticmethod
    def baseline_details(candidate):
        # Freeze the 225-test baseline, including its existing USN aggregation.
        segments = set()
        groups = defaultdict(list)
        for fact in candidate.facts:
            key = parser.usn_artifact_detail_key(fact)
            if key is None:
                segments.add(parser.fact_artifact_detail(fact))
            else:
                groups[key].append(fact)
        details = list(segments)
        for facts in groups.values():
            detail = min(parser.fact_artifact_detail(f) for f in facts)
            if len(facts) > 1:
                detail += f", 동일 근거={len(facts)}건"
            details.append(detail)
        details.sort()
        if candidate.timestamp and candidate.timestamp.semantics == "download_started" and details:
            for index, detail in enumerate(details):
                if detail.startswith("[Download Record] "):
                    details[index] = detail + ", 시각 출처=다운로드 시작"
                    break
        return " | ".join(details)

    @staticmethod
    def prefetch_facts():
        facts = []
        for index, suffix in enumerate(("AAAAAAAA", "BBBBBBBB", "CCCCCCCC")):
            path = rf"volume0:\Windows\Prefetch\LM STUDIO.EXE-{suffix}.pf"
            facts.append(parser.ObservedFact(
                "application_prefetch", "windows_os", parser.Provenance("SYNTHETIC.dd", path, "", f"MFT {10 + index}#1"),
                parser.basename(path), direct_tag="lmstudio_prefetch_execution", target_path=path,
            ))
        return facts

    @staticmethod
    def log_facts():
        path = r"volume0:\Users\TEST\.lmstudio\server-logs\events.log"
        return [parser.ObservedFact(
            "model_load_log", "lmstudio_log", parser.Provenance("SYNTHETIC.dd", path, "", f"line {line}"),
            "TEST/model-A", direct_tag="explicit_model_load_log", conversation_ref="TEST-CONVERSATION",
        ) for line in (101, 112, 354)]

    @staticmethod
    def context(facts, action="application_launch"):
        ctx = parser.AnalysisContext(Path("SYNTHETIC.dd"), source_image="SYNTHETIC.dd")
        ctx.facts.extend(facts)
        parser.add_candidate(ctx, action, facts, ["observed synthetic evidence"], "synthetic context",
                             forced="suspected", timestamp=parser.iso_from_datetime("2026-10-02T00:00:00Z", "log_event"))
        return ctx, ctx.candidates[0]

    def baseline_rows(self, ctx):
        with patch.object(parser, "candidate_artifact_paths", side_effect=self.baseline_paths), \
                patch.object(parser, "candidate_artifact_details", side_effect=self.baseline_details):
            return parser.timeline_rows(ctx), parser.conversation_rows(ctx)

    def test_three_prefetch_files_have_one_display_and_keep_three_facts(self):
        ctx, candidate = self.context(self.prefetch_facts())
        before = copy.deepcopy(ctx)
        original_facts = candidate.facts
        paths = parser.candidate_artifact_paths(candidate)
        details = parser.candidate_artifact_details(candidate)
        self.assertEqual([self.prefetch_facts()[0].provenance.original_artifact_path], paths)
        self.assertTrue(details.startswith("[Prefetch] 실행 파일=LM Studio.exe, 대표 파일="))
        self.assertIn("LM STUDIO.EXE-AAAAAAAA.pf", details)
        self.assertIn("동일 근거=3건", details)
        self.assertEqual(1, len(details.split(" | ")))
        self.assertEqual(3, len(candidate.facts))
        self.assertIs(original_facts, candidate.facts)
        self.assertEqual(before, ctx)

    def test_three_server_log_lines_have_one_deterministic_detail(self):
        ctx, candidate = self.context(self.log_facts())
        before = copy.deepcopy(ctx)
        details = parser.candidate_artifact_details(candidate)
        self.assertIn("[Server Log]", details)
        self.assertIn("모델=TEST/model-A", details)
        self.assertIn("대표 위치=line 101", details)
        self.assertIn("동일 근거=3건", details)
        self.assertEqual(1, len(details.split(" | ")))
        self.assertEqual(3, len(candidate.facts))
        self.assertEqual(before, ctx)

    def test_different_server_log_event_types_stay_separate(self):
        facts = self.log_facts()
        facts[1] = replace(facts[1], fact_type="normal_exit_log", value="normal_exit_log", direct_tag="explicit_normal_exit_log")
        _, candidate = self.context(facts)
        details = parser.candidate_artifact_details(candidate)
        self.assertEqual(2, len(details.split(" | ")))
        self.assertIn("동일 근거=2건", details)
        self.assertIn("이벤트=정상 종료", details)

    def test_different_conversations_stay_separate(self):
        facts = self.log_facts()
        facts[1] = replace(facts[1], conversation_ref="OTHER-CONVERSATION")
        _, candidate = self.context(facts)
        self.assertEqual(2, len(parser.candidate_artifact_details(candidate).split(" | ")))

    def test_different_models_and_messages_stay_separate(self):
        facts = self.log_facts()
        facts[1] = replace(facts[1], value="TEST/model-B")
        facts[2] = replace(facts[2], key="OTHER-MESSAGE", message_ref="OTHER-MESSAGE")
        _, candidate = self.context(facts)
        self.assertEqual(3, len(parser.candidate_artifact_details(candidate).split(" | ")))
        self.assertNotIn("동일 근거=", parser.candidate_artifact_details(candidate))

    def test_different_log_source_files_stay_separate(self):
        facts = self.log_facts()
        facts[1] = replace(facts[1], provenance=replace(facts[1].provenance, original_artifact_path=facts[1].provenance.original_artifact_path.replace("events.log", "other.log")))
        _, candidate = self.context(facts)
        self.assertEqual(2, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(2, len(parser.candidate_artifact_details(candidate).split(" | ")))

    def test_different_images_and_prefetch_directories_stay_separate(self):
        facts = self.prefetch_facts()
        facts[1] = replace(facts[1], provenance=replace(facts[1].provenance, source_image="OTHER.dd"))
        facts[2] = replace(facts[2], provenance=replace(facts[2].provenance, original_artifact_path=facts[2].provenance.original_artifact_path.replace("volume0", "volume1")), target_path=facts[2].target_path.replace("volume0", "volume1"))
        _, candidate = self.context(facts)
        self.assertEqual(3, len(parser.candidate_artifact_paths(candidate)))
        self.assertNotIn("동일 근거=", parser.candidate_artifact_details(candidate))

    def test_different_prefetch_executables_stay_separate(self):
        facts = self.prefetch_facts()
        facts[1] = replace(facts[1], value="OTHER.EXE-BBBBBBBB.pf", provenance=replace(facts[1].provenance, original_artifact_path=facts[1].provenance.original_artifact_path.replace("LM STUDIO.EXE", "OTHER.EXE")), target_path=facts[1].target_path.replace("LM STUDIO.EXE", "OTHER.EXE"))
        _, candidate = self.context(facts)
        self.assertEqual(2, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(2, len(parser.candidate_artifact_details(candidate).split(" | ")))

    def test_different_families_and_direct_tags_stay_separate(self):
        facts = self.prefetch_facts()
        facts[1] = replace(facts[1], family="filesystem")
        facts[2] = replace(facts[2], direct_tag="")
        _, candidate = self.context(facts)
        self.assertEqual(3, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(3, len(parser.candidate_artifact_details(candidate).split(" | ")))

    def test_conversation_attachment_and_usn_roles_all_remain(self):
        facts = [
            parser.ObservedFact("user_message", "conversation_state", parser.Provenance("SYNTHETIC.dd", "TEST.conversation.json", "", "/messages/0"), "TEST"),
            parser.ObservedFact("image_metadata", "attachment", parser.Provenance("SYNTHETIC.dd", "TEST.metadata.json"), "TEST.png"),
            UsnArtifactDetailsTests().usn_fact(0x100),
        ]
        _, candidate = self.context(facts, "image_upload")
        details = parser.candidate_artifact_details(candidate)
        for label in ("Conversation", "Attachment Metadata", "$UsnJrnl"):
            self.assertIn(f"[{label}]", details)
        self.assertEqual(3, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(3, len(details.split(" | ")))

    def test_download_record_gguf_and_ads_roles_all_remain(self):
        facts = [
            parser.ObservedFact("download_completed_record", "model_state", parser.Provenance("SYNTHETIC.dd", "download-jobs-info.json", "", "/jobs/0"), "TEST.gguf"),
            parser.ObservedFact("final_gguf", "final_file", parser.Provenance("SYNTHETIC.dd", "models/TEST.gguf"), "TEST.gguf"),
            parser.ObservedFact("zone_identifier", "final_file", parser.Provenance("SYNTHETIC.dd", "models/TEST.gguf:Zone.Identifier"), target_path="models/TEST.gguf"),
        ]
        _, candidate = self.context(facts, "model_download")
        details = parser.candidate_artifact_details(candidate)
        for label in ("Download Record", "GGUF", "Zone.Identifier"):
            self.assertIn(f"[{label}]", details)
        self.assertEqual(3, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(3, len(details.split(" | ")))

    def test_existing_663_usn_group_is_byte_identical(self):
        _, candidate = UsnArtifactDetailsTests().edit_context()
        self.assertEqual(self.baseline_details(candidate), parser.candidate_artifact_details(candidate))
        self.assertEqual(self.baseline_paths(candidate), parser.candidate_artifact_paths(candidate))
        self.assertEqual(664, len(candidate.facts))

    def test_shuffled_fact_order_keeps_both_artifact_displays(self):
        import random
        facts = self.prefetch_facts() + self.log_facts()
        _, candidate = self.context(facts)
        expected = (parser.candidate_artifact_paths(candidate), parser.candidate_artifact_details(candidate))
        for seed in range(5):
            shuffled = list(facts)
            random.Random(seed).shuffle(shuffled)
            other = replace(candidate, facts=shuffled)
            self.assertEqual(expected, (parser.candidate_artifact_paths(other), parser.candidate_artifact_details(other)))

    def test_verdict_timestamp_behavior_and_internal_evidence_unchanged(self):
        ctx, candidate = self.context(self.prefetch_facts() + self.log_facts())
        before = copy.deepcopy(ctx)
        old_rows, _ = self.baseline_rows(ctx)
        new_rows = parser.timeline_rows(ctx)
        self.assertEqual([r[:5] for r in old_rows], [r[:5] for r in new_rows])
        self.assertEqual(6, len(candidate.facts))
        self.assertEqual(before, ctx)
        self.assertNotEqual(old_rows[0][5:], new_rows[0][5:])

    def test_recovered_csv_byte_identical_and_timeline_contract(self):
        ctx = self.analyze_files({CONV: conversation(message(), message("assistant"))})
        launch_ctx, _ = self.context(self.prefetch_facts() + self.log_facts())
        ctx.candidates.extend(launch_ctx.candidates)
        ctx.facts.extend(launch_ctx.facts)
        before = copy.deepcopy(ctx)
        old_rows, recovered = self.baseline_rows(ctx)
        with tempfile.TemporaryDirectory(prefix="SYNTHETIC_ARTIFACT_DISPLAY_") as temporary:
            root = Path(temporary)
            parser.write_csv(root / "before.csv", parser.CONVERSATION_HEADER, recovered)
            parser.write_csv(root / "after.csv", parser.CONVERSATION_HEADER, parser.conversation_rows(ctx))
            self.assertEqual((root / "before.csv").read_bytes(), (root / "after.csv").read_bytes())
            parser.write_csv(root / "timeline.csv", parser.TIMELINE_HEADER, parser.timeline_rows(ctx))
            raw = (root / "timeline.csv").read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
            rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
            self.assertEqual(parser.TIMELINE_HEADER, rows[0])
            self.assertTrue(all(len(row) == 7 for row in rows))
            self.assertTrue(all(cell for row in rows[1:] for cell in row))
        self.assertEqual([r[:5] for r in old_rows], [r[:5] for r in parser.timeline_rows(ctx)])
        self.assertEqual(before, ctx)

    def test_singleton_displays_keep_baseline_wording(self):
        for fact in (self.prefetch_facts()[0], self.log_facts()[0]):
            _, candidate = self.context([fact])
            self.assertEqual(self.baseline_details(candidate), parser.candidate_artifact_details(candidate))
            self.assertEqual(self.baseline_paths(candidate), parser.candidate_artifact_paths(candidate))

    def test_repeated_runtime_support_keeps_fact_count(self):
        fact = parser.ObservedFact("http_server_runtime", "filesystem", parser.Provenance("SYNTHETIC.dd", "http-server.json"), "http-server state")
        _, candidate = self.context([fact, replace(fact), replace(fact)])
        self.assertIn("동일 근거=3건", parser.candidate_artifact_details(candidate))
        self.assertEqual(3, len(candidate.facts))
        self.assertEqual(1, len(parser.candidate_artifact_paths(candidate)))

    def test_unknown_prefetch_semantics_are_not_guessed(self):
        facts = [parser.ObservedFact("application_prefetch", "windows_os", parser.Provenance("SYNTHETIC.dd", name)) for name in ("A.pf", "B.pf", "C.pf")]
        _, candidate = self.context(facts)
        self.assertEqual(3, len(parser.candidate_artifact_paths(candidate)))
        self.assertNotIn("동일 근거=", parser.candidate_artifact_details(candidate))

    def test_no_path_count_limit_or_combined_detail_truncation(self):
        facts = [replace(self.log_facts()[0], value=f"model-{index}-" + "x" * 200) for index in range(20)]
        for index, fact in enumerate(facts):
            facts[index] = replace(fact, provenance=replace(fact.provenance, original_artifact_path=fact.provenance.original_artifact_path.replace("events.log", f"event-{index}.log")))
        _, candidate = self.context(facts)
        details = parser.candidate_artifact_details(candidate)
        self.assertEqual(20, len(parser.candidate_artifact_paths(candidate)))
        self.assertEqual(20, len(details.split(" | ")))
        self.assertGreater(len(details), 4000)

    def test_display_does_not_expose_internal_grouping_keys(self):
        _, candidate = self.context(self.prefetch_facts() + self.log_facts())
        details = parser.candidate_artifact_details(candidate)
        for forbidden in (candidate.rule_id, "application_prefetch", "model_load_log", "windows_os", "lmstudio_log", "confidence=", "Direct Evidence="):
            self.assertNotIn(forbidden, details)

    def test_all_21_rule_fixtures_preserve_non_artifact_columns(self):
        for action, (positive, negative, _) in RULE_FIXTURES.items():
            for files in (positive, negative):
                with self.subTest(action=action):
                    ctx = self.analyze_files(files)
                    before = copy.deepcopy(ctx)
                    old_rows, recovered = self.baseline_rows(ctx)
                    self.assertEqual([r[:5] for r in old_rows], [r[:5] for r in parser.timeline_rows(ctx)])
                    self.assertEqual(recovered, parser.conversation_rows(ctx))
                    self.assertEqual(before, ctx)


class WindowsLiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="SYNTHETIC_LIVE_")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "WindowsRoot"
        (self.root / "Users").mkdir(parents=True)

    def profile(self, name="TEST_USER", home=".lmstudio"):
        profile = self.root / "Users" / name
        path = profile / home / CONV
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(conversation(message(), message("assistant"))), encoding="utf-8")
        return profile, path

    def analyze_live(self):
        with patch.object(sys, "platform", "win32"):
            return parser.analyze(self.root, live=True, live_root=self.root)

    def test_windows_live_cli_selects_local_collector(self):
        from contextlib import redirect_stdout, redirect_stderr
        self.profile()
        with patch.object(sys, "platform", "win32"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = parser.main(["--live", "--live-root", str(self.root), "--output", str(self.base / "out")])
        self.assertEqual(0, rc)
        self.assertTrue((self.base / "out" / "recovered_conversations.csv").exists())

    def test_live_output_collision_preserves_result_until_explicit_overwrite(self):
        from contextlib import redirect_stdout, redirect_stderr
        self.profile()
        output = self.base / "out"
        output.mkdir()
        target = output / "recovered_conversations.csv"
        content = b"SYNTHETIC_PRIOR_LIVE_RESULT"
        target.write_bytes(content)
        options = ["--live", "--live-root", str(self.root), "--output", str(output)]
        stdout = io.StringIO()
        with patch.object(sys, "platform", "win32"), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            self.assertEqual(0, parser.main(options))
        selected = output.with_name(output.name + "_001")
        self.assertIn("결과 저장 경로: " + str(selected), stdout.getvalue())
        self.assertEqual(content, target.read_bytes())
        self.assertEqual(hashlib.sha256(content).hexdigest(), hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual({target.name}, {path.name for path in output.iterdir()})
        ctx = self.analyze_live()
        parser._read_and_validate_csv(selected / target.name, parser.CONVERSATION_HEADER, parser.conversation_rows(ctx))
        self.assertTrue((selected / "timeline.csv").exists())
        selected_before = {path.name: path.read_bytes() for path in selected.iterdir()}
        with patch.object(sys, "platform", "win32"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, parser.main(options + ["--overwrite"]))
        ctx = self.analyze_live()
        parser._read_and_validate_csv(target, parser.CONVERSATION_HEADER, parser.conversation_rows(ctx))
        self.assertTrue((output / "timeline.csv").exists())
        self.assertEqual(selected_before, {path.name: path.read_bytes() for path in selected.iterdir()})
        self.assertFalse(output.with_name(output.name + "_002").exists())

    def test_non_windows_rejected(self):
        from contextlib import redirect_stderr
        error = io.StringIO()
        with patch.object(sys, "platform", "linux"), redirect_stderr(error):
            rc = parser.main(["--live", "--output", str(self.base / "out")])
        self.assertEqual(2, rc)
        self.assertIn("live_platform_unsupported", error.getvalue())
        self.assertFalse((self.base / "out").exists())

    def test_default_home_and_existing_core(self):
        _, path = self.profile()
        ctx = self.analyze_live()
        self.assertEqual(2, len(ctx.messages))
        self.assertIn(str(path.resolve()), [a.path for a in ctx.artifacts])
        self.assertTrue(ctx.candidates)

    def test_relative_home_pointer_and_custom_home_logs(self):
        profile, path = self.profile(home="custom_home")
        (profile / ".lmstudio-home-pointer").write_text("custom_home\n", encoding="utf-8")
        log = path.parent.parent / "server-logs" / "events.log"
        log.parent.mkdir()
        log.write_text("2026-09-20T00:00:00Z login succeeded", encoding="utf-8")
        ctx = self.analyze_live()
        self.assertEqual(2, len(ctx.messages))
        self.assertTrue(any(f.direct_tag == "explicit_login_log" for f in ctx.facts))
        self.assertTrue(any(a.path == str(path.resolve()) for a in ctx.artifacts))

    def test_absolute_home_pointer(self):
        profile, path = self.profile(home="relocated")
        (profile / ".lmstudio-home-pointer").write_text(str(path.parent.parent), encoding="utf-8")
        self.assertEqual(2, len(self.analyze_live().messages))

    def test_multiple_profiles_and_excluded_system_profiles(self):
        for name in ("TEST_A", "TEST_B", "Public", "Default", "Default User", "All Users"):
            self.profile(name)
        ctx = self.analyze_live()
        self.assertEqual(4, len(ctx.messages))
        self.assertEqual(2, len(ctx.lmstudio_homes))

    def test_current_profile_outside_users_root(self):
        current = self.base / "relocated_profile"
        (current / ".lmstudio").mkdir(parents=True)
        ctx = parser.AnalysisContext(self.root, live=True)
        path_type = Path
        with patch.dict(os.environ, {"SystemDrive": str(self.root), "USERPROFILE": str(current)}):
            # Keep the Windows root synthetic, but exercise USERPROFILE discovery.
            with patch.object(parser, "Path", wraps=Path) as paths:
                paths.side_effect = lambda value: self.root if str(value).endswith("\\") else path_type(value)
                roots = parser.live_roots(ctx)
        self.assertIn(current / ".lmstudio", [p for p, _ in roots])

    def test_no_home_is_diagnostic_not_user_behavior(self):
        ctx = self.analyze_live()
        self.assertIn("live_home_not_found", [i.code for i in ctx.issues])
        self.assertFalse(ctx.candidates)
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def read_failure(self, exc):
        _, target = self.profile()
        original = Path.open
        def open_read(path, *args, **kwargs):
            if path == target:
                raise exc
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", open_read):
            return self.analyze_live()

    def test_permission_denied_is_nonfatal(self):
        ctx = self.read_failure(PermissionError("synthetic denied"))
        self.assertIn("live_permission_denied", [i.code for i in ctx.issues])
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def test_locked_file_is_nonfatal(self):
        exc = OSError("synthetic sharing violation")
        exc.winerror = 32
        ctx = self.read_failure(exc)
        self.assertIn("live_artifact_locked", [i.code for i in ctx.issues])
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def test_file_removed_during_read(self):
        ctx = self.read_failure(FileNotFoundError("synthetic disappeared"))
        self.assertIn("live_artifact_not_found", [i.code for i in ctx.issues])

    def test_changed_file_content_is_not_parsed(self):
        _, target = self.profile()
        before = target.stat()
        after = SimpleNamespace(st_size=before.st_size + 1, st_mtime_ns=before.st_mtime_ns + 1, st_ctime_ns=before.st_ctime_ns)
        ctx = parser.AnalysisContext(self.root, live=True)
        with patch.object(Path, "stat", side_effect=[before, after]), patch.object(Path, "is_file", return_value=False):
            parser.add_local_file(ctx, target, str(target))
        self.assertIn("live_artifact_changed", [i.code for i in ctx.issues])
        self.assertIsNone(ctx.artifacts[0].content)

    def test_directory_permission_error_reported(self):
        ctx = parser.AnalysisContext(self.root, live=True)
        def failed_walk(root, **kwargs):
            kwargs["onerror"](PermissionError(13, "synthetic", str(root)))
            return iter(())
        with patch.object(os, "walk", side_effect=failed_walk):
            parser.walk_selected_local(ctx, self.root)
        self.assertIn("live_permission_denied", [i.code for i in ctx.issues])

    def test_output_deterministic_and_offline_equivalent(self):
        profile, path = self.profile()
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        live = self.analyze_live()
        offline = parser.analyze(profile / ".lmstudio")
        self.assertEqual(parser.timeline_rows(offline), parser.timeline_rows(live))
        self.assertEqual(parser.conversation_rows(offline), parser.conversation_rows(live))
        for index, ctx in enumerate((live, self.analyze_live(), offline)):
            parser.write_outputs(ctx, self.base / f"out{index}")
        for name in ("timeline.csv", "recovered_conversations.csv"):
            self.assertEqual((self.base / "out0" / name).read_bytes(), (self.base / "out1" / name).read_bytes())
            self.assertEqual((self.base / "out0" / name).read_bytes(), (self.base / "out2" / name).read_bytes())
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))

    def test_output_in_default_or_pointer_home_rejected(self):
        profile, _ = self.profile(home="custom")
        (profile / ".lmstudio-home-pointer").write_text("custom", encoding="utf-8")
        ctx = self.analyze_live()
        for home in (profile / "custom", profile / ".lmstudio"):
            with self.assertRaises(ValueError):
                parser.write_outputs(ctx, home / "out")

    def test_live_does_not_use_offline_history_collectors(self):
        self.profile()
        with patch.object(parser, "collect_standalone_mft") as mft, patch.object(parser, "collect_preparsed_history") as history:
            ctx = self.analyze_live()
        mft.assert_not_called()
        history.assert_not_called()
        self.assertFalse(ctx.usn_stats)
        self.assertFalse(any(f.fact_type.startswith("history_") for f in ctx.facts))

    def test_offline_pointer_cannot_escape_evidence(self):
        profile, _ = self.profile()
        external = self.base / "external"
        external.mkdir()
        (profile / ".lmstudio-home-pointer").write_text(str(external), encoding="utf-8")
        ctx = parser.analyze(profile)
        self.assertIn("home_pointer_outside_evidence", [i.code for i in ctx.issues])
        self.assertNotIn(str(external), ctx.lmstudio_homes)

    def test_network_pointer_rejected(self):
        profile, _ = self.profile()
        (profile / ".lmstudio-home-pointer").write_text(r"\\server\share\home", encoding="utf-8")
        ctx = self.analyze_live()
        self.assertIn("home_pointer_invalid", [i.code for i in ctx.issues])


class BitLockerAccessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="SYNTHETIC_BDE_")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = self.root / "evidence.dd"
        self.image.write_bytes(b"ENCRYPTED" + bytes(1015))
        self.ctx = parser.AnalysisContext(self.image, source_image=str(self.image))
        self.plain = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(1013))
        self.bde = Mock()
        self.bde.has_clear_key.return_value = False
        self.bde.open.return_value = self.plain
        self.detect = patch("dissect.fve.bde.is_bde_volume", return_value=True).start()
        self.backend = patch("dissect.fve.bde.BDE", return_value=self.bde).start()
        self.addCleanup(patch.stopall)

    def open(self, credential=None):
        return parser.open_volume_stream(self.ctx, io.BytesIO(self.image.read_bytes()), "partition1", credential)

    def test_non_bitlocker_preserves_stream(self):
        self.detect.return_value = False
        stream = io.BytesIO(b"ordinary")
        result, encrypted = parser.open_volume_stream(self.ctx, stream, "partition0")
        self.assertIs(stream, result)
        self.assertFalse(encrypted)
        self.backend.assert_not_called()

    def test_official_detection_used(self):
        self.open()
        self.detect.assert_called_once()
        self.backend.assert_called_once()
        self.assertIn("bitlocker_credential_missing", [i.code for i in self.ctx.issues])

    def test_real_detection_accepts_guid_without_oem_signature(self):
        from dissect.fve.bde import bde as implementation
        from dissect.fve.bde.c_bde import INFORMATION_OFFSET_GUID
        header = bytearray(512)
        header[160:176] = INFORMATION_OFFSET_GUID.bytes_le
        volume = io.BytesIO(header)
        volume.seek(7)
        self.assertTrue(implementation.is_bde_volume(volume))
        self.assertEqual(7, volume.tell())
        self.assertFalse(implementation.is_bde_volume(io.BytesIO(bytes(512))))

    def test_clear_key_only_when_protector_exists(self):
        self.bde.has_clear_key.return_value = True
        stream, encrypted = self.open()
        self.bde.unlock_with_clear_key.assert_called_once_with()
        self.assertIs(self.plain, stream)
        self.assertTrue(encrypted)

    def test_no_credential_skips_without_guessing(self):
        stream, encrypted = self.open()
        self.assertIsNone(stream)
        self.assertTrue(encrypted)
        self.bde.unlock_with_clear_key.assert_not_called()
        self.bde.unlock_with_recovery_password.assert_not_called()
        self.bde.open.assert_not_called()

    def test_recovery_password_path(self):
        credential = parser.BitLockerCredential("recovery", "SYNTHETIC_AUTHORIZED_RECOVERY")
        stream, _ = self.open(credential)
        self.assertIs(self.plain, stream)
        self.bde.unlock_with_recovery_password.assert_called_once_with(credential.value)

    def test_invalid_recovery_material_is_redacted(self):
        secret = "SYNTHETIC_NEVER_LOG_RECOVERY"
        self.bde.unlock_with_recovery_password.side_effect = ValueError(secret)
        stream, _ = self.open(parser.BitLockerCredential("recovery", secret))
        self.assertIsNone(stream)
        self.assertIn("bitlocker_unlock_failed", [i.code for i in self.ctx.issues])
        diagnostic = io.StringIO()
        parser.report_analysis(self.ctx, diagnostic)
        self.assertNotIn(secret, diagnostic.getvalue() + repr(self.ctx))

    def test_passphrase_path(self):
        self.open(parser.BitLockerCredential("passphrase", "SYNTHETIC_PASSPHRASE"))
        self.bde.unlock_with_passphrase.assert_called_once_with("SYNTHETIC_PASSPHRASE")

    def test_bek_file_read_only_and_closed(self):
        bek = self.root / "synthetic.bek"
        bek.write_bytes(b"SYNTHETIC_BEK")
        state = (bek.read_bytes(), bek.stat().st_mtime_ns)
        self.open(parser.BitLockerCredential("bek", bek))
        handle = self.bde.unlock_with_bek.call_args.args[0]
        self.assertEqual("rb", handle.mode)
        self.assertTrue(handle.closed)
        self.assertEqual(state, (bek.read_bytes(), bek.stat().st_mtime_ns))

    def test_fvek_uses_raw_bytes(self):
        key = bytes(range(32))
        stream, _ = self.open(parser.BitLockerCredential("fvek", key))
        self.bde.unlock_with_fvek.assert_called_once_with(key)
        self.assertIs(self.plain, stream)

    def test_wrong_fvek_header_not_reported_as_success(self):
        self.bde.open.return_value = io.BytesIO(bytes(512))
        stream, _ = self.open(parser.BitLockerCredential("fvek", bytes(32)))
        self.assertIsNone(stream)
        self.assertIn("bitlocker_unlock_failed", [i.code for i in self.ctx.issues])
        self.assertNotIn("bitlocker_unlocked", [i.code for i in self.ctx.issues])

    def test_clear_key_failure_can_use_authorized_recovery(self):
        self.bde.has_clear_key.return_value = True
        self.bde.unlock_with_clear_key.side_effect = ValueError("bad protector")
        self.assertIs(self.plain, self.open(parser.BitLockerCredential("recovery", "SYNTHETIC"))[0])
        self.bde.unlock_with_recovery_password.assert_called_once_with("SYNTHETIC")

    def test_decrypted_stream_position_and_eof(self):
        self.bde.has_clear_key.return_value = True
        stream, _ = self.open()
        self.assertEqual(0, stream.tell())
        self.assertEqual(b"NTFS    ", (stream.read(11))[3:11])
        stream.seek(0, os.SEEK_END)
        self.assertEqual(b"", stream.read(512))

    def test_real_bitlocker_stream_decrypts_sectors_read_only(self):
        from dissect.fve.bde.bde import BDE, BitlockerStream
        from dissect.fve.bde.c_bde import CIPHER_MAP, FVE_KEY_TYPE
        from dissect.fve.crypto import create_cipher
        key = bytes(range(16))
        plain = b"\xeb\x52\x90NTFS    " + bytes(1013)
        fvek_type = FVE_KEY_TYPE.AES_128
        cipher = create_cipher(CIPHER_MAP[fvek_type], key, sector_size=512)
        ciphertext = cipher.encrypt(plain)
        volume = SimpleNamespace(
            fh=io.BytesIO(ciphertext), sector_size=512, encrypted=True,
            _fvek_type=fvek_type, _fvek=key, version=2, unlocked=True,
            eow_information=None, reserved_regions=lambda: [],
            information=SimpleNamespace(virtualized_block_offset=0, virtualized_sectors=0, state_offset=0),
        )
        stream = BDE.open(volume)
        self.assertIsInstance(stream, BitlockerStream)
        self.assertFalse(stream.writable())
        self.assertEqual(plain, stream.read())
        stream.seek(510)
        self.assertEqual(plain[510:520], stream.read(10))
        stream.seek(0, os.SEEK_END)
        self.assertEqual(b"", stream.read(1))
        with self.assertRaises(NotImplementedError):
            stream.write(b"forbidden")
        self.assertEqual(ciphertext, volume.fh.getvalue())
        stream.close()

    def collect(self, path=None, partitions=None, credential=None):
        ctx = parser.AnalysisContext(path or self.image, source_image=str(path or self.image))
        def ntfs(stream):
            self.assertEqual(b"NTFS    ", stream.read(11)[3:11])
            stream.seek(0)
            return SimpleNamespace(fh=stream)
        with patch("dissect.volume.disk.Disk", return_value=SimpleNamespace(partitions=partitions)) if partitions is not None else patch("dissect.volume.disk.Disk", side_effect=ValueError("no table")), \
                patch("dissect.ntfs.NTFS", side_effect=ntfs) as constructor, \
                patch.object(parser, "collect_ntfs_current") as current, \
                patch.object(parser, "collect_ntfs_usn") as usn:
            parser.collect_image(ctx, credential)
        return ctx, constructor, current, usn

    def test_dd_decrypted_stream_enters_existing_ntfs_layer(self):
        self.bde.has_clear_key.return_value = True
        ctx, constructor, current, usn = self.collect()
        constructor.assert_called_once_with(self.plain)
        current.assert_called_once()
        usn.assert_called_once()
        self.assertFalse(any(i.fatal for i in ctx.issues))
        self.assertTrue(self.plain.closed)

    def test_ewf_container_then_inner_volume(self):
        path = self.root / "synthetic.E01"
        path.write_bytes(b"OUTER_EWF")
        self.bde.has_clear_key.return_value = True
        outer = io.BytesIO(self.image.read_bytes())
        ewf = Mock()
        ewf.open.return_value = outer
        with patch("dissect.evidence.ewf.find_files", return_value=[str(path)]) as find, patch("dissect.evidence.ewf.EWF", return_value=ewf):
            ctx, constructor, _, _ = self.collect(path)
        find.assert_called_once_with(path)
        constructor.assert_called_once_with(self.plain)
        self.assertTrue(outer.closed)
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def test_split_raw_bitlocker_without_join(self):
        first, second = self.root / "split.001", self.root / "split.002"
        first.write_bytes(self.image.read_bytes()[:100])
        second.write_bytes(self.image.read_bytes()[100:])
        state = parser.image_stat(first)
        self.bde.has_clear_key.return_value = True
        ctx, constructor, _, _ = self.collect(first)
        self.assertIsInstance(self.backend.call_args.args[0], parser.SegmentedRawStream)
        self.assertEqual(state, parser.image_stat(first))
        constructor.assert_called_once_with(self.plain)
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def test_failed_partition_does_not_block_normal_partition(self):
        normal = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        partitions = [SimpleNamespace(offset=1024, open=lambda: io.BytesIO(bytes(512))),
                      SimpleNamespace(offset=2048, open=lambda: normal)]
        self.detect.side_effect = [True, False]
        ctx, constructor, current, _ = self.collect(partitions=partitions)
        self.assertIn("bitlocker_credential_missing", [i.code for i in ctx.issues])
        constructor.assert_called_once_with(normal)
        current.assert_called_once()
        self.assertFalse(any(i.fatal for i in ctx.issues))

    def test_invalid_key_partition_does_not_block_other_partition(self):
        self.bde.unlock_with_passphrase.side_effect = ValueError("SYNTHETIC_SECRET")
        normal = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        partitions = [SimpleNamespace(offset=0, open=lambda: io.BytesIO(bytes(512))),
                      SimpleNamespace(offset=512, open=lambda: normal)]
        self.detect.side_effect = [True, False]
        ctx, constructor, _, _ = self.collect(partitions=partitions, credential=parser.BitLockerCredential("passphrase", "SYNTHETIC_SECRET"))
        self.assertIn("bitlocker_unlock_failed", [i.code for i in ctx.issues])
        constructor.assert_called_once_with(normal)
        self.assertNotIn("SYNTHETIC_SECRET", repr(ctx))

    def test_metadata_failure_and_stream_error_are_distinct(self):
        self.backend.side_effect = ValueError("SYNTHETIC_SECRET")
        self.open()
        self.assertIn("bitlocker_metadata_failed", [i.code for i in self.ctx.issues])
        self.backend.side_effect = None
        self.bde.has_clear_key.return_value = True
        self.bde.open.side_effect = OSError("SYNTHETIC_SECRET")
        self.open()
        self.assertIn("bitlocker_stream_error", [i.code for i in self.ctx.issues])
        self.assertNotIn("SYNTHETIC_SECRET", repr(self.ctx))

    def test_original_image_bytes_size_and_mtime_unchanged(self):
        before = (self.image.read_bytes(), parser.image_stat(self.image))
        self.bde.has_clear_key.return_value = True
        self.collect()
        self.assertEqual(before, (self.image.read_bytes(), parser.image_stat(self.image)))
        self.assertEqual([self.image], list(self.root.iterdir()))

    def test_credentials_absent_from_csv_validation_and_diagnostics(self):
        secret = "SYNTHETIC_SECRET_NO_LEAK"
        credential = parser.BitLockerCredential("recovery", secret)
        self.bde.unlock_with_recovery_password.side_effect = ValueError(secret)
        self.open(credential)
        output = self.root / "out"
        parser.write_outputs(self.ctx, output)
        diagnostic = io.StringIO()
        parser.report_analysis(self.ctx, diagnostic)
        with patch.object(parser, "analyze", return_value=self.ctx):
            validation = parser.validate_analysis(self.ctx, self.image, output, credential=credential)
        emitted = diagnostic.getvalue() + json.dumps(validation) + repr(credential)
        emitted += "".join(p.read_text(encoding="utf-8-sig") for p in output.iterdir())
        self.assertNotIn(secret, emitted)
        self.assertEqual([], parser.timeline_rows(self.ctx))

    def test_prompt_uses_getpass_and_rejects_echo_fallback(self):
        args = parser.build_argument_parser().parse_args(["--bitlocker-recovery-prompt"])
        with patch.object(getpass, "getpass", return_value="SYNTHETIC_RECOVERY") as prompt:
            credential = parser.read_bitlocker_credential(args)
        self.assertEqual("recovery", credential.kind)
        self.assertNotIn(credential.value, repr(credential))
        prompt.assert_called_once()
        with patch.object(getpass, "getpass", side_effect=getpass.GetPassWarning("no tty")):
            with self.assertRaises(getpass.GetPassWarning):
                parser.read_bitlocker_credential(args)

    def test_non_bitlocker_dd_and_ewf_keep_existing_path(self):
        self.detect.return_value = False
        self.image.write_bytes(b"\xeb\x52\x90NTFS    " + bytes(501))
        _, constructor, current, _ = self.collect()
        self.assertEqual(1, constructor.call_count)
        current.assert_called_once()
        path = self.root / "synthetic.E01"
        path.write_bytes(b"EWF")
        outer = io.BytesIO(self.image.read_bytes())
        with patch("dissect.evidence.ewf.find_files", return_value=[str(path)]), patch("dissect.evidence.ewf.EWF", return_value=SimpleNamespace(open=lambda: outer)):
            _, constructor, current, _ = self.collect(path)
        constructor.assert_called_once_with(outer)
        current.assert_called_once()
        self.backend.assert_not_called()

    def test_backend_unavailable_oem_is_only_a_hint(self):
        with patch.dict(sys.modules, {"dissect.fve.bde": None}):
            stream, encrypted = parser.open_volume_stream(
                self.ctx, io.BytesIO(b"\xeb\x52\x90-FVE-FS-" + bytes(501)), "partition0")
        self.assertIsNone(stream)
        self.assertFalse(encrypted)
        self.assertIn("bitlocker_backend_unavailable", [i.code for i in self.ctx.issues])

    def test_backend_exception_logging_cannot_leak_credential(self):
        secret = "SYNTHETIC_BACKEND_LOG_SECRET"
        logger = logging.getLogger("dissect.fve.bde.bde")
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        previous_disabled, previous_level = logger.disabled, logger.level
        logger.disabled, logger.level = False, logging.DEBUG
        logger.addHandler(handler)
        def failed(value):
            logger.error(value)
            raise ValueError(value)
        self.bde.unlock_with_passphrase.side_effect = failed
        try:
            self.open(parser.BitLockerCredential("passphrase", secret))
            self.assertFalse(logger.disabled)
        finally:
            logger.removeHandler(handler)
            logger.disabled, logger.level = previous_disabled, previous_level
        self.assertNotIn(secret, output.getvalue() + repr(self.ctx))

    def test_decrypted_artifact_reuses_parser_core_and_deterministic_csv(self):
        content = json.dumps(conversation(message(), message("assistant"))).encode("utf-8")
        record = SimpleNamespace(
            is_dir=lambda: False, size=lambda: len(content), open=lambda: io.BytesIO(content),
            has_stream=lambda name: False, segment=42, header=SimpleNamespace(SequenceNumber=1),
        )
        self.bde.has_clear_key.return_value = True
        self.bde.open.side_effect = lambda: io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        def current(ctx, ntfs, index):
            self.assertEqual(b"NTFS    ", ntfs.fh.read(11)[3:11])
            parser.add_ntfs_file(ctx, record, r"volume0:\Users\TEST\.lmstudio\conversations\TEST.conversation.json", index)
        with patch("dissect.volume.disk.Disk", side_effect=ValueError("volume image")), \
                patch("dissect.ntfs.NTFS", side_effect=lambda stream: SimpleNamespace(fh=stream)), \
                patch.object(parser, "collect_ntfs_current", side_effect=current), \
                patch.object(parser, "collect_ntfs_usn"):
            first = parser.analyze(self.image)
            second = parser.analyze(self.image)
        self.assertEqual(2, len(first.messages))
        self.assertTrue(first.candidates)
        for index, ctx in enumerate((first, second)):
            parser.write_outputs(ctx, self.root / f"out{index}")
        for name in ("timeline.csv", "recovered_conversations.csv"):
            self.assertEqual((self.root / "out0" / name).read_bytes(), (self.root / "out1" / name).read_bytes())

    def test_decrypted_stream_error_isolated_from_next_partition(self):
        self.bde.has_clear_key.return_value = True
        self.bde.open.side_effect = OSError("synthetic stream failure")
        normal = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        partitions = [SimpleNamespace(offset=0, open=lambda: io.BytesIO(bytes(512))),
                      SimpleNamespace(offset=512, open=lambda: normal)]
        self.detect.side_effect = [True, False]
        ctx, constructor, current, _ = self.collect(partitions=partitions)
        self.assertIn("bitlocker_stream_error", [i.code for i in ctx.issues])
        constructor.assert_called_once_with(normal)
        current.assert_called_once()
        self.assertFalse(any(i.fatal for i in ctx.issues))


class BitLockerClearKeyRegressionTests(unittest.TestCase):
    # Reuse fixtures, without inheriting and counting the original 28 tests again.
    setUp = BitLockerAccessTests.setUp
    open = BitLockerAccessTests.open
    collect = BitLockerAccessTests.collect

    ENV_KEYS = (
        "BITLOCKER_RECOVERY_KEY", "BITLOCKER_RECOVERY_PASSWORD",
        "LMSTUDIO_BITLOCKER_RECOVERY_KEY", "BITLOCKER_PASSPHRASE",
        "BITLOCKER_BEK", "BITLOCKER_FVEK",
    )

    def deferred(self, *options):
        args = parser.build_argument_parser().parse_args(list(options))
        return parser.read_bitlocker_credential(args, defer=True)

    def add_conversation(self, ctx, ntfs, index):
        content = json.dumps(conversation(message(), message("assistant"))).encode("utf-8")
        record = SimpleNamespace(
            is_dir=lambda: False, size=lambda: len(content), open=lambda: io.BytesIO(content),
            has_stream=lambda name: False, segment=42, header=SimpleNamespace(SequenceNumber=1),
        )
        parser.add_ntfs_file(ctx, record,
                            rf"volume{index}:\Users\TEST\.lmstudio\conversations\TEST.conversation.json", index)

    def test_clear_key_without_any_credential_never_prompts(self):
        self.bde.has_clear_key.return_value = True
        with patch.object(getpass, "getpass") as prompt:
            stream, encrypted = self.open()
        self.assertIs(self.plain, stream)
        self.assertTrue(encrypted)
        self.bde.has_clear_key.assert_called_once_with()
        self.bde.unlock_with_clear_key.assert_called_once_with()
        prompt.assert_not_called()
        self.assertIn("Clear Key unlock succeeded", self.ctx.issues[-1].limitation)

    def test_clear_key_stream_uses_real_read_only_bitlocker_stream(self):
        from dissect.fve.bde.bde import BDE, BitlockerStream
        from dissect.fve.bde.c_bde import CIPHER_MAP, FVE_KEY_TYPE
        from dissect.fve.crypto import create_cipher
        key = bytes(range(16))
        plaintext = b"\xeb\x52\x90NTFS    " + bytes(1013)
        key_type = FVE_KEY_TYPE.AES_128
        ciphertext = create_cipher(CIPHER_MAP[key_type], key, sector_size=512).encrypt(plaintext)
        volume = SimpleNamespace(
            fh=io.BytesIO(ciphertext), sector_size=512, encrypted=True,
            _fvek_type=key_type, _fvek=key, version=2, unlocked=True,
            eow_information=None, reserved_regions=lambda: [],
            information=SimpleNamespace(virtualized_block_offset=0, virtualized_sectors=0, state_offset=0),
        )
        self.bde.has_clear_key.return_value = True
        self.bde.open.side_effect = lambda: BDE.open(volume)
        stream, _ = self.open()
        self.addCleanup(stream.close)
        self.assertIsInstance(stream, BitlockerStream)
        self.assertTrue(stream.readable())
        self.assertFalse(stream.writable())
        self.assertEqual(plaintext, stream.read())
        with self.assertRaises(NotImplementedError):
            stream.write(b"forbidden")
        self.assertEqual(ciphertext, volume.fh.getvalue())

    def test_clear_key_stream_reconstructs_conversation_through_existing_ntfs(self):
        self.bde.has_clear_key.return_value = True
        with patch("dissect.volume.disk.Disk", side_effect=ValueError("volume image")), \
                patch("dissect.ntfs.NTFS", side_effect=lambda stream: SimpleNamespace(fh=stream)) as constructor, \
                patch.object(parser, "collect_ntfs_current", side_effect=self.add_conversation), \
                patch.object(parser, "collect_ntfs_usn") as usn:
            ctx = parser.analyze(self.image)
        constructor.assert_called_once_with(self.plain)
        usn.assert_called_once()
        self.assertEqual(2, len(ctx.messages))
        self.assertTrue(ctx.candidates)
        self.assertTrue(self.plain.closed)
        self.assertFalse(any(issue.fatal for issue in ctx.issues))

    def test_locked_partition_keeps_both_neighboring_ntfs_partitions(self):
        normals = [io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501)) for _ in range(2)]
        volumes = [normals[0], io.BytesIO(bytes(512)), normals[1]]
        partitions = [SimpleNamespace(offset=index * 512, open=lambda stream=stream: stream)
                      for index, stream in enumerate(volumes)]
        self.detect.side_effect = [False, True, False]
        ctx, constructor, current, usn = self.collect(partitions=partitions)
        self.assertEqual(2, constructor.call_count)
        self.assertEqual(2, current.call_count)
        self.assertEqual(2, usn.call_count)
        issue = next(issue for issue in ctx.issues if issue.code == "bitlocker_credential_missing")
        self.assertIn("Clear Key protector unavailable", issue.limitation)
        self.assertIn("no authorized credential provided", issue.limitation)
        self.bde.unlock_with_clear_key.assert_not_called()
        self.bde.open.assert_not_called()
        self.assertFalse(any(issue.fatal for issue in ctx.issues))

    def test_explicit_recovery_is_prompted_only_after_clear_key_check(self):
        events = []
        self.bde.has_clear_key.side_effect = lambda: events.append("clear_key_check") or False
        with patch.object(getpass, "getpass", side_effect=lambda _: events.append("prompt") or "SYNTHETIC_RECOVERY"):
            credential = self.deferred("--bitlocker-recovery-prompt")
            self.assertEqual([], events)
            stream, _ = self.open(credential)
        self.assertEqual(["clear_key_check", "prompt"], events)
        self.assertIs(self.plain, stream)
        self.bde.unlock_with_recovery_password.assert_called_once_with("SYNTHETIC_RECOVERY")

    def test_explicit_passphrase_is_deferred_until_fallback(self):
        with patch.object(getpass, "getpass", return_value="SYNTHETIC_PASSPHRASE") as prompt:
            credential = self.deferred("--bitlocker-passphrase-prompt")
            prompt.assert_not_called()
            stream, _ = self.open(credential)
        self.assertIs(self.plain, stream)
        prompt.assert_called_once()
        self.bde.unlock_with_passphrase.assert_called_once_with("SYNTHETIC_PASSPHRASE")

    def test_explicit_bek_fallback_remains_read_only(self):
        bek = self.root / "authorized.bek"
        bek.write_bytes(b"SYNTHETIC_BEK")
        before = (bek.read_bytes(), bek.stat().st_mtime_ns)
        stream, _ = self.open(self.deferred("--bitlocker-bek", str(bek)))
        self.assertIs(self.plain, stream)
        handle = self.bde.unlock_with_bek.call_args.args[0]
        self.assertEqual("rb", handle.mode)
        self.assertTrue(handle.closed)
        self.assertEqual(before, (bek.read_bytes(), bek.stat().st_mtime_ns))

    def test_explicit_fvek_fallback_reads_raw_key_once(self):
        fvek = self.root / "authorized.fvek"
        key = bytes(range(32))
        fvek.write_bytes(key)
        before = (fvek.read_bytes(), fvek.stat().st_mtime_ns)
        credential = self.deferred("--bitlocker-fvek", str(fvek))
        self.assertEqual("deferred", credential.kind)
        stream, _ = self.open(credential)
        self.assertIs(self.plain, stream)
        self.bde.unlock_with_fvek.assert_called_once_with(key)
        self.assertEqual(before, (fvek.read_bytes(), fvek.stat().st_mtime_ns))

    def test_recovery_like_environment_values_are_not_credentials(self):
        with patch.dict(os.environ, {key: "SYNTHETIC_ENV_SECRET" for key in self.ENV_KEYS}), \
                patch.object(getpass, "getpass") as prompt:
            self.assertIsNone(self.deferred())
            stream, _ = self.open()
        self.assertIsNone(stream)
        prompt.assert_not_called()
        for method in ("unlock_with_clear_key", "unlock_with_recovery_password", "unlock_with_passphrase",
                       "unlock_with_bek", "unlock_with_fvek"):
            getattr(self.bde, method).assert_not_called()
        self.assertNotIn("SYNTHETIC_ENV_SECRET", repr(self.ctx))

    def test_environment_changes_leave_cli_csv_and_candidates_identical(self):
        from contextlib import redirect_stdout, redirect_stderr
        results = []
        for index, value in enumerate(("SYNTHETIC_ENV_A", "SYNTHETIC_ENV_B")):
            self.detect.side_effect = [True, False]
            volumes = [io.BytesIO(bytes(512)), io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))]
            partitions = [SimpleNamespace(offset=i * 512, open=lambda stream=stream: stream)
                          for i, stream in enumerate(volumes)]
            output = self.root / f"env_out{index}"
            with patch.dict(os.environ, {key: value for key in self.ENV_KEYS}), \
                    patch("dissect.volume.disk.Disk", return_value=SimpleNamespace(partitions=partitions)), \
                    patch("dissect.ntfs.NTFS", side_effect=lambda stream: SimpleNamespace(fh=stream)), \
                    patch.object(parser, "collect_ntfs_current", side_effect=self.add_conversation), \
                    patch.object(parser, "collect_ntfs_usn"), \
                    patch.object(getpass, "getpass") as prompt, \
                    patch.object(parser, "report_analysis", wraps=parser.report_analysis) as report, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(0, parser.main([str(self.image), "--output", str(output)]))
                ctx = report.call_args.args[0]
            prompt.assert_not_called()
            self.assertEqual(2, len(ctx.messages))
            self.assertTrue(ctx.candidates)
            results.append((ctx.candidates, ctx.messages, ctx.issues,
                            [(output / name).read_bytes() for name in
                             ("timeline.csv", "recovered_conversations.csv")]))
        self.assertEqual(results[0], results[1])

    def test_clear_key_and_credential_exceptions_never_expose_material(self):
        clear_secret, recovery_secret = "SYNTHETIC_CLEAR_KEY_SECRET", "SYNTHETIC_RECOVERY_SECRET"
        logger = logging.getLogger("dissect.fve.bde.bde")
        logs = io.StringIO()
        handler = logging.StreamHandler(logs)
        previous_disabled, previous_level = logger.disabled, logger.level
        logger.disabled, logger.level = False, logging.DEBUG
        logger.addHandler(handler)
        def fail_clear():
            logger.error(clear_secret)
            raise ValueError(clear_secret)
        def fail_recovery(value):
            logger.error(value)
            raise ValueError(value)
        self.bde.has_clear_key.return_value = True
        self.bde.unlock_with_clear_key.side_effect = fail_clear
        self.bde.unlock_with_recovery_password.side_effect = fail_recovery
        try:
            stream, _ = self.open(parser.BitLockerCredential("recovery", recovery_secret))
        finally:
            logger.removeHandler(handler)
            logger.disabled, logger.level = previous_disabled, previous_level
        self.assertIsNone(stream)
        output = self.root / "secret_out"
        parser.write_outputs(self.ctx, output)
        diagnostic = io.StringIO()
        parser.report_analysis(self.ctx, diagnostic)
        with patch.object(parser, "analyze", return_value=self.ctx):
            validation = parser.validate_analysis(self.ctx, self.image, output)
        emitted = logs.getvalue() + diagnostic.getvalue() + json.dumps(validation) + repr(self.ctx)
        emitted += "".join((output / name).read_text(encoding="utf-8-sig") for name in
                           ("timeline.csv", "recovered_conversations.csv"))
        for secret in (clear_secret, recovery_secret):
            self.assertNotIn(secret, emitted)

    def test_clear_key_failure_skips_partition_without_blocking_next(self):
        self.bde.has_clear_key.return_value = True
        self.bde.unlock_with_clear_key.side_effect = ValueError("SYNTHETIC_CLEAR_SECRET")
        normal = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        partitions = [SimpleNamespace(offset=0, open=lambda: io.BytesIO(bytes(512))),
                      SimpleNamespace(offset=512, open=lambda: normal)]
        self.detect.side_effect = [True, False]
        ctx, constructor, current, _ = self.collect(partitions=partitions)
        self.assertIn("bitlocker_clear_key_unlock_failed", [issue.code for issue in ctx.issues])
        self.assertIn("bitlocker_unlock_failed", [issue.code for issue in ctx.issues])
        constructor.assert_called_once_with(normal)
        current.assert_called_once()
        self.assertFalse(any(issue.fatal for issue in ctx.issues))
        self.assertNotIn("SYNTHETIC_CLEAR_SECRET", repr(ctx))

    def test_non_bitlocker_dd_raw_img_ewf_split_preserve_streams(self):
        self.detect.return_value = False
        plaintext = b"\xeb\x52\x90NTFS    " + bytes(501)
        for suffix in (".dd", ".raw", ".img", ".E01", ".001"):
            with self.subTest(suffix=suffix):
                path = self.root / ("normal" + suffix)
                path.write_bytes(plaintext if suffix != ".001" else plaintext[:100])
                if suffix == ".001":
                    path.with_suffix(".002").write_bytes(plaintext[100:])
                before = parser.image_stat(path)
                if suffix == ".E01":
                    outer = io.BytesIO(plaintext)
                    with patch("dissect.evidence.ewf.find_files", return_value=[str(path)]), \
                            patch("dissect.evidence.ewf.EWF", return_value=SimpleNamespace(open=lambda: outer)):
                        ctx, constructor, current, _ = self.collect(path)
                    constructor.assert_called_once_with(outer)
                else:
                    ctx, constructor, current, _ = self.collect(path)
                    self.assertEqual(1, constructor.call_count)
                current.assert_called_once()
                self.assertFalse(any(issue.fatal for issue in ctx.issues))
                self.assertEqual(before, parser.image_stat(path))
        self.backend.assert_not_called()

    def test_live_results_ignore_bitlocker_environment_credentials(self):
        root = self.root / "live"
        home = root / "Users" / "TEST" / ".lmstudio"
        path = home / CONV
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(conversation(message(), message("assistant"))), encoding="utf-8")
        results = []
        for value in ("SYNTHETIC_ENV_A", "SYNTHETIC_ENV_B"):
            with patch.dict(os.environ, {key: value for key in self.ENV_KEYS}), \
                    patch.object(sys, "platform", "win32"), patch.object(getpass, "getpass") as prompt:
                ctx = parser.analyze(root, live=True, live_root=root)
            prompt.assert_not_called()
            self.assertEqual(2, len(ctx.messages))
            results.append((ctx.facts, ctx.candidates, parser.timeline_rows(ctx), parser.conversation_rows(ctx)))
        self.assertEqual(results[0], results[1])
        self.backend.assert_not_called()

    def test_artifact_normalization_and_raw_facts_ignore_environment_keys(self):
        home = self.root / ".lmstudio"
        prefetch = home / "Windows" / "Prefetch"
        prefetch.mkdir(parents=True)
        for name in ("LM STUDIO.EXE-AAAA.pf", "LM STUDIO.EXE-BBBB.pf"):
            (prefetch / name).write_bytes(b"SYNTHETIC")
        results = []
        for value in ("SYNTHETIC_ENV_A", "SYNTHETIC_ENV_B"):
            with patch.dict(os.environ, {key: value for key in self.ENV_KEYS}):
                ctx = parser.analyze(home)
            before = copy.deepcopy(ctx)
            rows = parser.timeline_rows(ctx)
            self.assertEqual(before, ctx)
            self.assertEqual(2, len(ctx.candidates[0].facts))
            self.assertIn("동일 근거=2건", rows[0][6])
            self.assertEqual(1, len(rows[0][5].split(" | ")))
            results.append((ctx.facts, ctx.candidates, rows, parser.conversation_rows(ctx)))
        self.assertEqual(results[0], results[1])

    def test_clear_key_priority_preserves_source_size_mtime_and_content(self):
        before = (self.image.read_bytes(), self.image.stat().st_size, self.image.stat().st_mtime_ns)
        self.bde.has_clear_key.return_value = True
        with patch.object(getpass, "getpass") as prompt:
            ctx, _, _, _ = self.collect(credential=self.deferred("--bitlocker-recovery-prompt"))
        prompt.assert_not_called()
        self.assertFalse(any(issue.fatal for issue in ctx.issues))
        self.assertEqual(before, (self.image.read_bytes(), self.image.stat().st_size, self.image.stat().st_mtime_ns))
        self.assertEqual([self.image], list(self.root.iterdir()))

    def test_cli_clear_key_skips_all_explicit_credential_reads(self):
        from contextlib import redirect_stdout, redirect_stderr
        options = [("--bitlocker-recovery-prompt",), ("--bitlocker-passphrase-prompt",),
                   ("--bitlocker-bek", str(self.root / "missing.bek")),
                   ("--bitlocker-fvek", str(self.root / "missing.fvek"))]
        self.bde.has_clear_key.return_value = True
        self.bde.open.side_effect = lambda: io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        for index, option in enumerate(options):
            with self.subTest(option=option), \
                    patch("dissect.volume.disk.Disk", side_effect=ValueError("volume image")), \
                    patch("dissect.ntfs.NTFS", side_effect=lambda stream: SimpleNamespace(fh=stream)), \
                    patch.object(parser, "collect_ntfs_current", side_effect=self.add_conversation), \
                    patch.object(parser, "collect_ntfs_usn"), \
                    patch.object(parser, "read_bitlocker_credential", wraps=parser.read_bitlocker_credential) as read, \
                    patch.object(getpass, "getpass") as prompt, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(0, parser.main([str(self.image), "--output", str(self.root / f"clear_out{index}"),
                                                "--validate", "--before", str(self.image), *option]))
                read.assert_called_once()
                self.assertTrue(read.call_args.kwargs["defer"])
                prompt.assert_not_called()
        for method in ("unlock_with_recovery_password", "unlock_with_passphrase", "unlock_with_bek", "unlock_with_fvek"):
            getattr(self.bde, method).assert_not_called()

    def test_prompt_result_is_reused_across_partitions_and_reanalysis(self):
        credential = self.deferred("--bitlocker-recovery-prompt")
        self.bde.open.side_effect = lambda: io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
        with patch.object(getpass, "getpass", return_value="SYNTHETIC_RECOVERY") as prompt:
            for _ in range(2):
                partitions = [SimpleNamespace(offset=index * 512, open=lambda: io.BytesIO(bytes(512)))
                              for index in range(2)]
                ctx, constructor, _, _ = self.collect(partitions=partitions, credential=credential)
                self.assertFalse(any(issue.fatal for issue in ctx.issues))
                self.assertEqual(2, constructor.call_count)
        prompt.assert_called_once()
        self.assertEqual(4, self.bde.unlock_with_recovery_password.call_count)
        self.assertNotIn("SYNTHETIC_RECOVERY", repr(credential))

    def test_cancelled_or_unsafe_prompt_skips_partition_without_reprompt(self):
        for failure in (EOFError("SYNTHETIC_SECRET"), KeyboardInterrupt("SYNTHETIC_SECRET"),
                        getpass.GetPassWarning("SYNTHETIC_SECRET")):
            with self.subTest(failure=type(failure).__name__):
                credential = self.deferred("--bitlocker-recovery-prompt")
                normal = io.BytesIO(b"\xeb\x52\x90NTFS    " + bytes(501))
                partitions = [SimpleNamespace(offset=0, open=lambda: io.BytesIO(bytes(512))),
                              SimpleNamespace(offset=512, open=lambda: io.BytesIO(bytes(512))),
                              SimpleNamespace(offset=1024, open=lambda: normal)]
                self.detect.side_effect = [True, True, False]
                with patch.object(getpass, "getpass", side_effect=failure) as prompt:
                    ctx, constructor, current, _ = self.collect(partitions=partitions, credential=credential)
                prompt.assert_called_once()
                constructor.assert_called_once_with(normal)
                current.assert_called_once()
                self.assertEqual(2, sum(issue.code == "bitlocker_credential_read_failed" for issue in ctx.issues))
                self.assertNotIn("SYNTHETIC_SECRET", repr(ctx) + repr(credential))
                self.assertFalse(any(issue.fatal for issue in ctx.issues))

    def test_failed_clear_key_allows_each_explicit_credential_fallback(self):
        bek, fvek = self.root / "authorized.bek", self.root / "authorized.fvek"
        bek.write_bytes(b"SYNTHETIC_BEK")
        fvek.write_bytes(bytes(range(32)))
        options = [("--bitlocker-recovery-prompt",), ("--bitlocker-passphrase-prompt",),
                   ("--bitlocker-bek", str(bek)), ("--bitlocker-fvek", str(fvek))]
        methods = ("unlock_with_recovery_password", "unlock_with_passphrase", "unlock_with_bek", "unlock_with_fvek")
        self.bde.has_clear_key.return_value = True
        self.bde.unlock_with_clear_key.side_effect = ValueError("SYNTHETIC_CLEAR_SECRET")
        for option, method in zip(options, methods):
            with self.subTest(option=option), patch.object(getpass, "getpass", return_value="SYNTHETIC_AUTHORIZED"):
                credential = self.deferred(*option)
                stream, _ = self.open(credential)
            self.assertIs(self.plain, stream)
            getattr(self.bde, method).assert_called_once()
            self.assertNotIn("SYNTHETIC_CLEAR_SECRET", repr(self.ctx))
        self.assertEqual(4, self.bde.unlock_with_clear_key.call_count)

    def test_unused_raw_fvek_cannot_override_successful_clear_key(self):
        self.bde.has_clear_key.return_value = True
        # Unsupported filesystems belong to NTFS handling, not unused-key validation.
        self.bde.open.return_value = io.BytesIO(bytes(512))
        stream, _ = self.open(parser.BitLockerCredential("fvek", bytes(32)))
        self.assertIs(self.bde.open.return_value, stream)
        self.bde.unlock_with_fvek.assert_not_called()
        self.assertNotIn("bitlocker_unlock_failed", [issue.code for issue in self.ctx.issues])

    def test_installed_clear_key_api_requires_real_protector_and_uses_vmk(self):
        from dissect.fve.bde.bde import BDE
        vmk = Mock()
        clear_key, master_key = b"SYNTHETIC_CLEAR_KEY", b"SYNTHETIC_MASTER_KEY"
        vmk.clear_key.return_value = clear_key
        vmk.decrypt.return_value = master_key
        backend = SimpleNamespace(information=SimpleNamespace(dataset=Mock()), unlock=Mock())
        backend.information.dataset.find_clear_vmk.return_value = None
        self.assertFalse(BDE.has_clear_key(backend))
        with self.assertRaisesRegex(ValueError, "No clear VMK found"):
            BDE.unlock_with_clear_key(backend)
        backend.unlock.assert_not_called()
        backend.information.dataset.find_clear_vmk.return_value = vmk
        self.assertTrue(BDE.has_clear_key(backend))
        BDE.unlock_with_clear_key(backend)
        vmk.clear_key.assert_called_once_with()
        vmk.decrypt.assert_called_once_with(clear_key)
        backend.unlock.assert_called_once_with(master_key)


class DynamicOutputPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="SYNTHETIC_DYNAMIC_PATH_")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.output = self.base / "output"
        self.ctx = parser.AnalysisContext(self.evidence, live=True, evidence_roots=[self.evidence])

    def test_offline_protection_uses_actual_input_only(self):
        with patch.object(parser, "is_inside", wraps=parser.is_inside) as inside:
            self.assertEqual("", parser.validate_paths(self.evidence, self.output))
        self.assertEqual([(self.output, self.evidence)], [call.args for call in inside.call_args_list])

    def test_offline_output_inside_input_is_rejected(self):
        self.assertEqual("출력 경로는 Evidence directory 내부일 수 없습니다.",
                         parser.validate_paths(self.evidence, self.evidence / "output"))

    def test_offline_unrelated_output_is_allowed(self):
        self.assertEqual("", parser.validate_paths(self.evidence, self.output))

    def test_live_output_inside_actual_collection_root_is_rejected(self):
        self.assertEqual("Live 출력 경로가 수집 대상 directory와 겹칩니다. 별도 output directory를 지정하십시오.",
                         parser.validate_live_output(self.ctx, self.evidence / "output"))

    def test_live_unrelated_output_is_allowed_without_fixed_roots(self):
        with patch.object(parser, "is_inside", wraps=parser.is_inside) as inside:
            self.assertEqual("", parser.validate_live_output(self.ctx, self.output))
        self.assertEqual([(self.output, self.evidence), (self.evidence, self.output)],
                         [call.args for call in inside.call_args_list])

    def test_live_output_equal_to_or_parent_of_collection_root_is_rejected(self):
        for output in (self.evidence, self.base):
            with self.subTest(output=output):
                self.assertTrue(parser.validate_live_output(self.ctx, output))

    def test_research_evidence_parent_remains_protected(self):
        research = self.base / "LMStudio_Research_Evidence"
        snapshot = research / "snapshot"
        snapshot.mkdir(parents=True)
        self.assertEqual("출력 경로는 Research Evidence 내부일 수 없습니다.",
                         parser.validate_paths(snapshot, research / "output"))
        self.assertEqual("", parser.validate_paths(snapshot, self.output))

    def test_output_cannot_replace_evidence_file(self):
        evidence = self.evidence / "input.dd"
        evidence.write_bytes(b"SYNTHETIC_EVIDENCE")
        before = (evidence.read_bytes(), evidence.stat().st_mtime_ns)
        self.assertEqual("출력 경로는 Evidence file과 같을 수 없습니다.",
                         parser.validate_paths(evidence, evidence))
        self.assertEqual(before, (evidence.read_bytes(), evidence.stat().st_mtime_ns))


class RuntimeUiStateFileTests(FixtureCase):
    def test_global_json_is_ui_state(self):
        self.assertTrue(parser.is_runtime_ui_state_file("global.json"))

    def test_server_logs_state_json_is_ui_state(self):
        self.assertTrue(parser.is_runtime_ui_state_file("server-logs-state.json"))

    def test_window_1_json_is_ui_state(self):
        self.assertTrue(parser.is_runtime_ui_state_file("window-1.json"))

    def test_window_2_json_is_ui_state(self):
        self.assertTrue(parser.is_runtime_ui_state_file("window-2.json"))

    def test_numeric_windows_and_case_insensitive_paths_are_ui_state(self):
        for path in ("window-25.json", "window-999.json", r"profile\WINDOW-10.JSON"):
            with self.subTest(path=path):
                self.assertTrue(parser.is_runtime_ui_state_file(path))

    def test_window_without_number_is_not_ui_state(self):
        self.assertFalse(parser.is_runtime_ui_state_file("window.json"))

    def test_window_with_empty_number_is_not_ui_state(self):
        self.assertFalse(parser.is_runtime_ui_state_file("window-.json"))

    def test_window_with_text_number_is_not_ui_state(self):
        self.assertFalse(parser.is_runtime_ui_state_file("window-test.json"))

    def test_window_with_wrong_extension_is_not_ui_state(self):
        self.assertFalse(parser.is_runtime_ui_state_file("window-1.txt"))

    def test_window_with_extra_prefix_is_not_ui_state(self):
        self.assertFalse(parser.is_runtime_ui_state_file("my-window-1.json"))

    def test_window_2_history_update_supports_suspected_normal_exit(self):
        ctx = self.analyze_files({"history.csv": history(
            ("$ROOT\\http-server.json", "File_Deleted"),
            ("$ROOT\\window-2.json", "Data_Overwrite"),
        )})
        candidates = self.candidates(ctx, "application_normal_exit")
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertEqual("suspected", candidate.decision_status)
        self.assertEqual(["history_delete", "history_modify"], [fact.fact_type for fact in candidate.facts])
        self.assertEqual(["http-server.json", "window-2.json"],
                         [parser.basename(fact.target_path) for fact in candidate.facts])
        self.assertEqual("LM Studio 정상 종료 흔적_state update 및 runtime 정리 근거", candidate.decision_reason)
        self.assertEqual("2026-09-16 03:51:56.973000 KST", parser.format_timestamp_kst(candidate.timestamp))
        self.assertEqual("의심", parser.timeline_rows(ctx)[0][4])

    def test_invalid_window_history_updates_do_not_support_normal_exit(self):
        for name in ("window.json", "window-.json", "window-test.json", "window-1.txt", "my-window-1.json"):
            with self.subTest(name=name):
                ctx = self.analyze_files({"history.csv": history(
                    ("$ROOT\\http-server.json", "File_Deleted"),
                    ("$ROOT\\" + name, "Data_Overwrite"),
                )})
                self.assertEqual([], self.candidates(ctx, "application_normal_exit"))


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
