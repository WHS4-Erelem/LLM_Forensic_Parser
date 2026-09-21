"""Data model: evidence records, final events, conversation/parse status and file traces.

Merged verbatim from: evidence.py, events.py, files.py.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator
from ..util.common import stable_key
from typing import Any


# ===========================================================================
# evidence
# ===========================================================================

"""Normalized evidence model (spec section 12).

Artifact parsers emit EvidenceRecord only. They never write final CSV.
Identifiers are canonical keys built from the record's own identity (family,
source, locator, payload), so re-running the same input yields identical IDs
without any hashing.
"""

# Independent artifact families (spec section 16.1). Cross-validation counts
# DISTINCT families, never record counts.
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

ALL_FAMILIES = (
    FAMILY_HISTORY,
    FAMILY_COOKIES,
    FAMILY_CACHE,
    FAMILY_INDEXEDDB,
    FAMILY_LOCAL_STORAGE,
    FAMILY_SESSIONS,
    FAMILY_MFT,
    FAMILY_ZONE_IDENTIFIER,
    FAMILY_USN,
    FAMILY_RECYCLE_BIN,
    FAMILY_FILESYSTEM_FILE,
)

# Human-facing artifact display names used in the timeline "발견근거" column.
FAMILY_DISPLAY = {
    FAMILY_HISTORY: "History",
    FAMILY_COOKIES: "Cookies",
    FAMILY_CACHE: "Cache",
    FAMILY_INDEXEDDB: "IndexedDB",
    FAMILY_LOCAL_STORAGE: "Local Storage",
    FAMILY_SESSIONS: "Sessions/Tabs",
    FAMILY_MFT: "$MFT",
    FAMILY_ZONE_IDENTIFIER: "Zone.Identifier",
    FAMILY_USN: "$UsnJrnl",
    FAMILY_RECYCLE_BIN: "$Recycle.Bin",
    FAMILY_FILESYSTEM_FILE: "File",
}

# IndexedDB / LevelDB record state. We never collapse these into "current"
# (spec sections 8.5, 8.6, 10.4).
STATE_LIVE = "LIVE"
STATE_HISTORICAL_OR_DELETED = "HISTORICAL_OR_DELETED"
STATE_UNKNOWN = "UNKNOWN"


@dataclass
class EvidenceRecord:
    """One observed record from one artifact."""

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
    raw_ref: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    # Logical path of the exact artifact inside the disk image (volume-relative,
    # "/"-separated), e.g. ".../Cache/Cache_Data/data_3" or "/$MFT". Defaults to
    # source_path; parsers set it when they know the precise file or stream.
    artifact_path: str = ""
    volume_id: str = ""

    def __post_init__(self) -> None:
        if not self.artifact_path:
            self.artifact_path = self.source_path or ""
        if not self.volume_id:
            self.volume_id = str(self.attributes.get("volume_id") or "")


@dataclass
class EventCandidate:
    """A possible user action, before the verdict engine runs."""

    candidate_id: str
    action_code: str
    action_label: str
    timestamp: dt.datetime | None
    account_uuid: str | None
    organization_uuid: str | None
    conversation_uuid: str | None
    target: str | None
    evidence_ids: list[str]
    identity_keys: dict[str, str]
    rule_id: str
    direct_evidence: bool = False
    notes: str = ""


VERDICT_CONFIRMED = "확정"
VERDICT_SUSPECTED = "의심"
VERDICT_UNDETERMINED = "판단불가"


@dataclass
class FinalEvent:
    """A verdict-carrying row destined for the Timeline sheet.

    `action_code` (E05-05) and `rule_id` (R-E0505) are INTERNAL identifiers used
    by detectors, coverage and tests. `action_label` is the only action name
    that reaches the report, so no experiment code is ever stripped with a
    regular expression at output time -- the two are separate fields.
    """

    action_id: str
    timestamp: dt.datetime | None
    action_code: str
    action_label: str
    verdict: str
    account_uuid: str | None
    target: str
    evidence_artifacts: list[str]
    detail_refs: list[str]
    action_detail: str = ""
    conversation_uuid: str | None = None
    artifact_details: list[str] = field(default_factory=list)
    rule_id: str = ""
    reason_code: str = ""
    families: list[str] = field(default_factory=list)
    timestamp_basis: str = ""

    def __post_init__(self) -> None:
        # The action name is fixed by the catalogue; an unknown code or a
        # renamed label is a programming error, not something to hide later.
        from ..analysis.rules import ACTION_LABELS, UnknownActionError

        expected = ACTION_LABELS.get(self.action_code)
        if expected is None:
            raise UnknownActionError(
                f"FinalEvent action code {self.action_code!r} is not in the action catalogue"
            )
        if self.action_label != expected:
            raise UnknownActionError(
                f"FinalEvent label {self.action_label!r} for {self.action_code} "
                f"must be {expected!r}"
            )


def make_evidence_id(artifact_family: str, source_path: str, locator: Any, payload: Any) -> str:
    """Canonical identity key, stable across runs and independent of row order."""
    return "EV-" + stable_key(
        {"family": artifact_family, "source": source_path, "locator": locator,
         "payload": payload}
    )


def make_candidate_id(rule_id: str, identity_keys: dict[str, Any]) -> str:
    return "CAND-" + stable_key({"rule": rule_id, "identity": identity_keys})


def make_action_id(rule_id: str, identity_keys: dict[str, Any]) -> str:
    return "ACT-" + stable_key({"rule": rule_id, "identity": identity_keys})


class EvidenceStore:
    """In-memory index of EvidenceRecord with the lookups detectors need."""

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

    def families_present(self) -> set[str]:
        return {f for f, ids in self._by_family.items() if ids}

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[EvidenceRecord]:
        return iter(self._records.values())

    def all(self) -> list[EvidenceRecord]:
        """Deterministic ordering for output."""
        return sorted(self._records.values(), key=lambda r: (r.artifact_family, r.evidence_id))

    def counts_by_family(self) -> dict[str, int]:
        return {f: len(ids) for f, ids in sorted(self._by_family.items())}


# ===========================================================================
# events
# ===========================================================================

"""Conversation model and parse/coverage status records."""

# Conversation record state -- evidence-level, not server-level (spec section 14).
CONV_CURRENT = "CURRENT"
CONV_HISTORICAL_OR_DELETED = "HISTORICAL_OR_DELETED"
CONV_UNKNOWN = "UNKNOWN"

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLE_SYSTEM = "system"
ROLE_UNKNOWN = "unknown"


def normalize_role(value: Any) -> str:
    """Claude uses 'human'; normalize to 'user' (spec section 19.3)."""
    s = str(value or "").strip().lower()
    if s in ("human", "user"):
        return ROLE_USER
    if s == "assistant":
        return ROLE_ASSISTANT
    if s == "system":
        return ROLE_SYSTEM
    return ROLE_UNKNOWN


@dataclass
class ConversationMessage:
    """One message or preserved branch. Branches are never merged away."""

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
    content_file: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def join_key(self) -> str:
        """Primary join key (spec section 14): message_uuid when we have one."""
        return self.message_uuid


# Artifact / parse status values.
ST_FOUND = "found"
ST_NOT_FOUND = "not_found"
ST_PARSED = "parsed"
ST_PARTIAL = "partial"
ST_FAILED = "failed"
ST_UNSUPPORTED = "unsupported"
ST_SKIPPED = "skipped"
ST_NOT_TESTED = "not_tested"
ST_DECRYPTED = "decrypted"
ST_ENCRYPTED_KEY_MISSING = "encrypted_key_missing"
ST_ENCRYPTED_UNSUPPORTED = "encrypted_unsupported"

# Coverage reason codes (spec section 16.4).
REASON_ARTIFACT_NOT_FOUND = "artifact_not_found"
REASON_PARSER_FAILED = "parser_failed"
REASON_AMBIGUOUS = "ambiguous"
REASON_SINGLE_SNAPSHOT_LIMIT = "single_snapshot_limit"
REASON_NO_DETECTOR = "no_verified_detector"
REASON_NO_EVIDENCE = "no_positive_evidence"
REASON_CONFLICTING = "conflicting_evidence"
REASON_DETECTOR_FAILED = "detector_failed"

# Human-readable explanation per reason code (console coverage log).
REASON_TEXT = {
    REASON_ARTIFACT_NOT_FOUND: "필요 아티팩트 부재",
    REASON_PARSER_FAILED: "파싱 실패",
    REASON_AMBIGUOUS: "증거가 모호함",
    REASON_SINGLE_SNAPSHOT_LIMIT: "단일 시점으로 판정 불가",
    REASON_NO_DETECTOR: "검증된 탐지 기준 없음",
    REASON_NO_EVIDENCE: "양성 증거 없음",
    REASON_CONFLICTING: "증거 충돌",
    REASON_DETECTOR_FAILED: "탐지 실행 실패",
}


@dataclass
class ParseStatus:
    """Per-artifact parse outcome. A failure here never aborts the run."""

    artifact: str
    family: str
    status: str
    source_path: str = ""
    record_count: int = 0
    error_count: int = 0
    error_code: str = ""
    message: str = ""
    impact: str = ""


@dataclass
class CoverageRow:
    """One action detector's coverage outcome."""

    action_code: str
    action_label: str
    rule_id: str
    status: str
    reason: str = ""
    event_count: int = 0
    message: str = ""


# ===========================================================================
# files
# ===========================================================================

"""File trace model (spec section 15).

A FileTrace is a Claude-related file known from metadata -- an upload, a
download, or a deleted download. It feeds the action detectors; file bytes are
never exported.
"""

DIRECTION_UPLOAD = "uploaded"
DIRECTION_DOWNLOAD = "downloaded"
DIRECTION_UNKNOWN = "unknown"


@dataclass
class FileTrace:
    """A Claude-related file, identified from artifact metadata."""

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
    zone_referrer_url: str = ""
    zone_host_url: str = ""
    deletion_time: dt.datetime | None = None
    # Set only when a strong Claude-relevance ground was established
    # (see analysis/claude_scope.py); unverified traces never reach detectors.
    claude_verified: bool = False
    claude_link_basis: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class PathEvent:
    """One step in a file's observed path history (rename/move/delete)."""

    timestamp: dt.datetime | None
    kind: str  # created | renamed | moved | deleted | observed
    old_path: str = ""
    new_path: str = ""
    resolved: bool = True
    source_family: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    note: str = ""
