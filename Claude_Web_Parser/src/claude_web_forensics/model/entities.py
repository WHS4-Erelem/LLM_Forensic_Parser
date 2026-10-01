"""Data model: evidence records, final events, conversation/parse status and file traces."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from ..util.common import stable_key

FAMILY_HISTORY = "history"
FAMILY_COOKIES = "cookies"
FAMILY_CACHE = "cache"
FAMILY_INDEXEDDB = "indexeddb"
FAMILY_LOCAL_STORAGE = "local_storage"
FAMILY_SESSIONS = "sessions"
FAMILY_MFT = "mft"
FAMILY_ZONE_IDENTIFIER = "zone_identifier"
FAMILY_USN = "usn"
FAMILY_RECYCLE_BIN = "recycle_bin"
FAMILY_FILESYSTEM_FILE = "filesystem_file"

FAMILY_DISPLAY = {
    FAMILY_HISTORY: "History", FAMILY_COOKIES: "Cookies", FAMILY_CACHE: "Cache",
    FAMILY_INDEXEDDB: "IndexedDB", FAMILY_LOCAL_STORAGE: "Local Storage", FAMILY_SESSIONS: "Sessions/Tabs",
    FAMILY_MFT: "$MFT", FAMILY_ZONE_IDENTIFIER: "Zone.Identifier", FAMILY_USN: "$UsnJrnl",
    FAMILY_RECYCLE_BIN: "$Recycle.Bin", FAMILY_FILESYSTEM_FILE: "File",
}

STATE_LIVE = "LIVE"
STATE_HISTORICAL_OR_DELETED = "HISTORICAL_OR_DELETED"
STATE_UNKNOWN = "UNKNOWN"

@dataclass
class EvidenceRecord:
    evidence_id: str
    artifact: str
    artifact_family: str
    source_path: str
    record_locator: str | None = None
    timestamp: dt.datetime | None = None
    account_uuid: str | None = None
    organization_uuid: str | None = None
    conversation_uuid: str | None = None
    message_uuid: str | None = None
    file_uuid: str | None = None
    summary: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    artifact_path: str = ""
    volume_id: str = ""

    def __post_init__(self) -> None:
        if not self.artifact_path:
            self.artifact_path = self.source_path or ""
        if not self.volume_id:
            self.volume_id = str(self.attributes.get("volume_id") or "")

VERDICT_CONFIRMED = "확정"
VERDICT_SUSPECTED = "의심"
VERDICT_UNDETERMINED = "판단불가"

@dataclass
class FinalEvent:
    action_id: str
    timestamp: dt.datetime | None
    action_code: str
    action_label: str
    verdict: str
    action_detail: str = ""
    evidence: list[tuple[str, str]] = field(default_factory=list)
    conversation_uuid: str | None = None
    rule_id: str = ""
    reason_code: str = ""
    timestamp_basis: str = ""

    def __post_init__(self) -> None:
        from ..analysis.rules import ACTION_LABELS, UnknownActionError

        expected = ACTION_LABELS.get(self.action_code)
        if expected is None:
            raise UnknownActionError(f"FinalEvent action code {self.action_code!r} is not in the action catalogue")
        if self.action_label != expected:
            raise UnknownActionError(
                f"FinalEvent label {self.action_label!r} for {self.action_code} "
                f"must be {expected!r}"
            )

    @property
    def detail_refs(self) -> list[str]:
        return [evidence_id for evidence_id, _ in self.evidence]

def make_evidence_id(artifact_family: str, source_path: str, locator: Any, payload: Any) -> str:
    return "EV-" + stable_key({"family": artifact_family, "source": source_path, "locator": locator,
        "payload": payload})

def make_action_id(rule_id: str, identity_keys: dict[str, Any]) -> str:
    return "ACT-" + stable_key({"rule": rule_id, "identity": identity_keys})

class EvidenceStore:
    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}
        self._by_family: dict[str, list[str]] = {}

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        existing = self._records.get(record.evidence_id)
        if existing is not None:
            return existing
        self._records[record.evidence_id] = record
        self._by_family.setdefault(record.artifact_family, []).append(record.evidence_id)
        return record

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            self.add(record)

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._records.get(evidence_id)

    def by_family(self, family: str) -> list[EvidenceRecord]:
        return [self._records[e] for e in self._by_family.get(family, [])]

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[EvidenceRecord]:
        return iter(self._records.values())

CONV_CURRENT = "CURRENT"
CONV_HISTORICAL_OR_DELETED = "HISTORICAL_OR_DELETED"
CONV_UNKNOWN = "UNKNOWN"

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLE_SYSTEM = "system"
ROLE_UNKNOWN = "unknown"

def normalize_role(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s in ("human", "user"):
        return ROLE_USER
    if s in (ROLE_ASSISTANT, ROLE_SYSTEM):
        return s
    return ROLE_UNKNOWN

@dataclass
class ConversationMessage:
    conversation_uuid: str
    message_uuid: str
    parent_message_uuid: str = ""
    conversation_title: str = ""
    timestamp: dt.datetime | None = None
    account_uuid: str | None = None
    organization_uuid: str | None = None
    role: str = ROLE_UNKNOWN
    model: str = ""
    input_mode: str = ""
    is_temporary: str = ""
    record_state: str = CONV_UNKNOWN
    content: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

ST_FOUND = "found"
ST_NOT_FOUND = "not_found"
ST_PARSED = "parsed"
ST_PARTIAL = "partial"
ST_FAILED = "failed"
ST_SKIPPED = "skipped"
ST_DECRYPTED = "decrypted"
ST_ENCRYPTED_KEY_MISSING = "encrypted_key_missing"
ST_ENCRYPTED_UNSUPPORTED = "encrypted_unsupported"

REASON_ARTIFACT_NOT_FOUND = "artifact_not_found"
REASON_AMBIGUOUS = "ambiguous"
REASON_SINGLE_SNAPSHOT_LIMIT = "single_snapshot_limit"
REASON_NO_EVIDENCE = "no_positive_evidence"
REASON_CONFLICTING = "conflicting_evidence"
REASON_DETECTOR_FAILED = "detector_failed"

REASON_TEXT = {
    REASON_ARTIFACT_NOT_FOUND: "필요 아티팩트 부재", REASON_AMBIGUOUS: "증거가 모호함",
    REASON_SINGLE_SNAPSHOT_LIMIT: "단일 시점으로 판정 불가", REASON_NO_EVIDENCE: "양성 증거 없음",
    REASON_CONFLICTING: "증거 충돌", REASON_DETECTOR_FAILED: "탐지 실행 실패",
}

@dataclass
class ParseStatus:
    artifact: str
    family: str
    status: str
    source_path: str = ""
    record_count: int = 0
    error_count: int = 0
    error_code: str = ""
    message: str = ""
    impact: str = ""

    details: list[str] = field(default_factory=list)

@dataclass
class CoverageRow:
    action_code: str
    action_label: str
    rule_id: str
    status: str
    reason: str = ""
    event_count: int = 0
    message: str = ""

DIRECTION_DOWNLOAD = "downloaded"

@dataclass
class FileTrace:
    file_id: str
    direction: str
    original_name: str = ""
    original_path: str = ""
    remote_path: str = ""
    account_uuid: str | None = None
    conversation_uuid: str | None = None
    file_uuid: str | None = None
    size: int | None = None
    mime: str = ""
    source: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    mft_reference: str | None = None
    zone_host_url: str = ""
    deletion_time: dt.datetime | None = None

    claude_verified: bool = False
    claude_link_basis: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

@dataclass
class PathEvent:
    timestamp: dt.datetime | None
    kind: str
    old_path: str = ""
    new_path: str = ""
    resolved: bool = True
    evidence_ids: list[str] = field(default_factory=list)
    note: str = ""
