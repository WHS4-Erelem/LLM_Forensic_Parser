"""결과 데이터 모델 (Coverage / ArtifactRecord / EvidenceItem / Event / RecoveredConversation / RecoveredMessage / ParseResult)."""
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
from .constants import ACTION_STATUSES, ARTIFACT_TYPES, CONFIDENCES, COVERAGE_STATUSES, DEFAULT_BROWSER, DEVICE_ATTRIBUTIONS, DISPLAY_TIMEZONE, EVIDENCE_LEVELS, FINDING_TYPES, INPUT_KINDS, MESSAGE_RECOVERY_STATUSES, PARSER_NAME, PARSER_VERSION, RECOVERY_STATUSES, RULE_VERIFICATIONS, SERVICE, TIMESTAMP_TYPES


# =============================================================================
# 2. Result Models
# =============================================================================
# 규칙
#   - 필드 순서와 이름은 docs/OUTPUT_SCHEMA.md 와 같다 (kw_only 로 순서 유지).
#   - timestamp_raw / timestamp_utc / timestamp_kst 는 str 또는 None 만 허용한다.
#     (WebKit µs 같은 큰 정수를 JSON 숫자로 두면 정밀도가 손실될 수 있음)
#   - 행위 시각이 없으면 timestamp 값을 모두 None 으로 둔다. 없는 시각을 만들지 않는다.
#   - 변환은 §3 normalize_timestamp() 가 담당한다. 여기서는 값의 형태만 검사한다.


def _require_choice(name: str, value: Any, allowed: tuple[str, ...]) -> None:
    """허용 목록에 없는 값이면 ValueError."""
    if value not in allowed:
        raise ValueError(f"{name}={value!r} is not allowed. Allowed: {', '.join(allowed)}")


def _require_str(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string, got {value!r}")


def _require_optional_str(name: str, value: Any) -> None:
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{name} must be str or None, got {type(value).__name__}")


def _require_dict(name: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be dict, got {type(value).__name__}")


def _check_timestamp_fields(obj: Any, prefix: str = "timestamp") -> None:
    """공통 시각 필드 검사: <prefix>_raw / _utc / _kst / _source 는 str 또는 None, <prefix>_type 은 허용 값."""
    for suffix in ("raw", "utc", "kst", "source"):
        _require_optional_str(f"{prefix}_{suffix}", getattr(obj, f"{prefix}_{suffix}"))
    _require_choice(f"{prefix}_type", getattr(obj, f"{prefix}_type"), TIMESTAMP_TYPES)
    raw, utc, kst = (getattr(obj, f"{prefix}_{suffix}") for suffix in ("raw", "utc", "kst"))
    if raw is None and (utc is not None or kst is not None):
        raise ValueError(f"{prefix}_utc/{prefix}_kst must be None when {prefix}_raw is None")


class _Model:
    """모든 Result Model 공통: dict 변환 (중첩 dataclass 포함)."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[call-overload]


@dataclass(kw_only=True)
class InputInfo(_Model):
    kind: str
    path: str
    partition: str | None = None
    filesystem: str | None = None
    image_sha256: str | None = None

    def __post_init__(self) -> None:
        _require_choice("kind", self.kind, INPUT_KINDS)
        _require_str("path", self.path)


@dataclass(kw_only=True)
class Coverage(_Model):
    artifact_type: str
    os_user: str | None = None
    browser: str = DEFAULT_BROWSER
    browser_profile: str | None = None
    source_path: str
    status: str
    record_count: int = 0
    source_sha256: str | None = None
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_choice("artifact_type", self.artifact_type, ARTIFACT_TYPES)
        _require_str("source_path", self.source_path)
        _require_choice("status", self.status, COVERAGE_STATUSES)
        if not isinstance(self.record_count, int) or self.record_count < 0:
            raise ValueError(f"record_count must be int >= 0, got {self.record_count!r}")


@dataclass(kw_only=True)
class ArtifactRecord(_Model):
    """Artifact에서 직접 관찰한 값 (사용자 행위 판정 없음)."""

    record_id: str
    service: str = SERVICE
    artifact_type: str
    os_user: str | None = None
    browser: str = DEFAULT_BROWSER
    browser_profile: str | None = None
    source_path: str
    record_location: str | None = None
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    timestamp_kst: str | None = None
    timestamp_type: str = "unknown"
    timestamp_source: str | None = None
    observed: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_str("record_id", self.record_id)
        _require_choice("artifact_type", self.artifact_type, ARTIFACT_TYPES)
        _require_str("source_path", self.source_path)
        _check_timestamp_fields(self)
        _require_dict("observed", self.observed)


@dataclass(kw_only=True)
class EvidenceItem(_Model):
    """Event 판정에 쓰인 개별 근거. evidence_level = 이 근거 하나의 행위 특이성."""

    evidence_id: str
    record_id: str | None = None
    evidence_level: str
    artifact_type: str
    source_path: str
    record_location: str | None = None
    source_sha256: str | None = None
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    timestamp_kst: str | None = None
    timestamp_type: str = "unknown"
    timestamp_source: str | None = None
    observed: dict[str, Any] = field(default_factory=dict)
    note: str | None = None

    def __post_init__(self) -> None:
        _require_str("evidence_id", self.evidence_id)
        _require_choice("evidence_level", self.evidence_level, EVIDENCE_LEVELS)
        _require_choice("artifact_type", self.artifact_type, ARTIFACT_TYPES)
        _require_str("source_path", self.source_path)
        _check_timestamp_fields(self)
        _require_dict("observed", self.observed)


@dataclass(kw_only=True)
class Event(_Model):
    """Rule 판정 결과. timestamp 는 representative_evidence_id 가 가리키는 근거에서 선택한 값."""

    event_id: str
    service: str = SERVICE
    finding_type: str
    action: str
    action_status: str
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    timestamp_kst: str | None = None
    timestamp_type: str = "unknown"
    timestamp_source: str | None = None
    representative_evidence_id: str | None = None
    confidence: str
    confidence_reason: list[str] = field(default_factory=list)
    rule_id: str
    rule_verification: str
    os_user: str | None = None
    browser: str = DEFAULT_BROWSER
    browser_profile: str | None = None
    device_attribution: str = "UNKNOWN"
    primary_evidence: list[EvidenceItem] = field(default_factory=list)
    supporting_evidence: list[EvidenceItem] = field(default_factory=list)
    inference: str | None = None
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_str("event_id", self.event_id)
        _require_choice("finding_type", self.finding_type, FINDING_TYPES)
        _require_str("action", self.action)
        _require_choice("action_status", self.action_status, ACTION_STATUSES)
        _check_timestamp_fields(self)
        _require_choice("confidence", self.confidence, CONFIDENCES)
        _require_str("rule_id", self.rule_id)
        _require_choice("rule_verification", self.rule_verification, RULE_VERIFICATIONS)
        _require_choice("device_attribution", self.device_attribution, DEVICE_ATTRIBUTIONS)
        _require_optional_str("inference", self.inference)

        for name in ("primary_evidence", "supporting_evidence"):
            for item in getattr(self, name):
                if not isinstance(item, EvidenceItem):
                    raise TypeError(f"{name} items must be EvidenceItem, got {type(item).__name__}")

        # Event Time 추적: 시각이 있으면 대표 근거가 반드시 있어야 하고, 그 근거가 이 Event 안에 있어야 한다.
        evidence_ids = {e.evidence_id for e in self.primary_evidence + self.supporting_evidence}
        if self.representative_evidence_id is None:
            if self.timestamp_raw is not None:
                raise ValueError("representative_evidence_id is required when the event has a timestamp")
        elif self.representative_evidence_id not in evidence_ids:
            raise ValueError(
                f"representative_evidence_id={self.representative_evidence_id!r} "
                "does not match any primary/supporting evidence"
            )


@dataclass(kw_only=True)
class RecoveredMessage(_Model):
    """
    Artifact 에서 실제로 복구한 대화 메시지 1건.
      - content 는 복구된 원문 전체 (요약·절단 금지). 복구되지 않은 내용을 채워 넣지 않는다.
      - role 은 Artifact 값 그대로 (user / assistant / system / tool …). 확인할 수 없으면 UNKNOWN.
      - 시각이 Artifact 에 없으면 timestamp 값은 모두 None.
    """

    message_id: str | None = None
    conversation_id: str | None = None
    parent_message_id: str | None = None
    sequence_index: int | None = None
    role: str = "UNKNOWN"
    content: str | None = None
    content_type: str | None = None
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    timestamp_kst: str | None = None
    timestamp_type: str = "unknown"
    timestamp_source: str | None = None
    source_artifact: str
    source_path: str
    record_location: str | None = None
    source_sha256: str | None = None
    recovery_status: str
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for name in ("message_id", "conversation_id", "parent_message_id", "content", "content_type",
                     "record_location", "source_sha256"):
            _require_optional_str(name, getattr(self, name))
        index = self.sequence_index
        if index is not None and (isinstance(index, bool) or not isinstance(index, int) or index < 0):
            raise ValueError(f"sequence_index must be int >= 0 or None, got {index!r}")
        _require_str("role", self.role)
        _check_timestamp_fields(self)
        _require_choice("source_artifact", self.source_artifact, ARTIFACT_TYPES)
        _require_str("source_path", self.source_path)
        _require_choice("recovery_status", self.recovery_status, MESSAGE_RECOVERY_STATUSES)
        if self.recovery_status == "RECOVERED" and self.content is None:
            raise ValueError("RECOVERED message must have content (use PARTIAL when content was not recovered)")


@dataclass(kw_only=True)
class RecoveredConversation(_Model):
    """
    Artifact 에서 실제로 복구한 ChatGPT 대화 1건 (사용자 행위 판정이 아니다).
    source_artifacts: 복구에 사용한 출처 목록 [{artifact_type, source_path, record_location?, source_sha256?, ...}]
    correlated_record_ids: 복구에는 쓰지 않았지만 대화 ID 가 정확히 같은 다른 Record (예: History /c/<id> 방문)
    """

    conversation_id: str | None = None
    title: str | None = None
    recovery_status: str
    create_time_raw: str | None = None
    create_time_utc: str | None = None
    create_time_kst: str | None = None
    create_time_type: str = "unknown"
    create_time_source: str | None = None
    messages: list[RecoveredMessage] = field(default_factory=list)
    source_artifacts: list[dict[str, Any]] = field(default_factory=list)
    correlated_record_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_optional_str("conversation_id", self.conversation_id)
        for record_id in self.correlated_record_ids:
            _require_str("correlated_record_ids item", record_id)
        _require_optional_str("title", self.title)
        _check_timestamp_fields(self, "create_time")
        _require_choice("recovery_status", self.recovery_status, RECOVERY_STATUSES)

        for message in self.messages:
            if not isinstance(message, RecoveredMessage):
                raise TypeError(f"messages items must be RecoveredMessage, got {type(message).__name__}")
            if None not in (self.conversation_id, message.conversation_id) and message.conversation_id != self.conversation_id:
                raise ValueError(f"message conversation_id {message.conversation_id!r} != {self.conversation_id!r}")

        if self.recovery_status == "RESIDUAL_ONLY" and self.messages:
            raise ValueError("RESIDUAL_ONLY conversation must not contain messages")
        if self.recovery_status in ("RECOVERED", "PARTIAL") and not self.messages:
            raise ValueError(f"{self.recovery_status} conversation must contain at least one message")
        if self.recovery_status == "RECOVERED" and any(m.recovery_status != "RECOVERED" for m in self.messages):
            raise ValueError("RECOVERED conversation cannot contain PARTIAL messages (use PARTIAL)")

        if not self.source_artifacts:
            raise ValueError("source_artifacts must list at least one source")
        for source in self.source_artifacts:
            _require_dict("source_artifacts item", source)
            _require_choice("source_artifacts.artifact_type", source.get("artifact_type"), ARTIFACT_TYPES)
            _require_str("source_artifacts.source_path", source.get("source_path"))


@dataclass(kw_only=True)
class ParseResult(_Model):
    """
    Parser 실행 1회의 전체 결과.
      events[]        사용자 행위 판정 (Rule)
      conversations[] Artifact 에서 실제로 복구된 대화 내용 — 두 결과를 섞지 않는다.
    """

    parser_name: str = PARSER_NAME
    parser_version: str = PARSER_VERSION
    run_id: str
    run_started_utc: str
    input: InputInfo
    display_timezone: str = DISPLAY_TIMEZONE
    coverage: list[Coverage] = field(default_factory=list)
    records: list[ArtifactRecord] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    conversations: list[RecoveredConversation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_str("run_id", self.run_id)
        _require_str("run_started_utc", self.run_started_utc)
        if not isinstance(self.input, InputInfo):
            raise TypeError(f"input must be InputInfo, got {type(self.input).__name__}")
        for name, cls in (("coverage", Coverage), ("records", ArtifactRecord), ("events", Event),
                          ("conversations", RecoveredConversation)):
            for item in getattr(self, name):
                if not isinstance(item, cls):
                    raise TypeError(f"{name} items must be {cls.__name__}, got {type(item).__name__}")

    def to_json(self, indent: int | None = 2) -> str:
        """UTF-8 JSON 문자열 (한글 그대로 유지)."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @property
    def recovered_messages(self) -> list[RecoveredMessage]:
        """
        conversations[] 안의 복구된 메시지를 대화 순서대로 편 목록 (읽기 전용 view).
        통합하는 쪽이 내부 구조를 몰라도 메시지를 바로 쓸 수 있게 두는 것이고, 저장되는 결과(JSON/CSV)는 바뀌지 않는다.
        """
        return [message for conversation in self.conversations for message in conversation.messages]
