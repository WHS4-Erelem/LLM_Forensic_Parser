"""File analysis: trace building, path lifecycle reconstruction and USN final-path checks.

Merged verbatim from: files.py, lifecycle.py, usn_paths.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from ..model.entities import (
    FAMILY_CACHE,
    FAMILY_INDEXEDDB,
    EvidenceRecord,
    EvidenceStore,
)
from ..model.entities import (
    DIRECTION_DOWNLOAD,
    DIRECTION_UPLOAD,
    FileTrace,
    PathEvent,
)
from ..parsers.filesystem import CollectedFile
from ..parsers.extended_fs import RecycleEntry
from ..util.common import stable_key
from .claude_scope import BASIS_CLAUDE_STORAGE
from typing import Iterable
from ..model.entities import FAMILY_RECYCLE_BIN, FAMILY_USN, EvidenceRecord
from ..parsers.extended_fs import RenamePair, UsnRecord
from ..util.common import sort_key


# ===========================================================================
# files
# ===========================================================================

"""File trace building (spec section 15).

A FileTrace describes a Claude-related file from metadata: an allocated
download, a $Recycle.Bin entry, or an attachment in Claude's own storage. The
traces feed the action detectors; file bytes are neither read nor exported.
"""

def make_file_id(*parts: Any) -> str:
    return "F-" + stable_key(list(parts))


@dataclass
class UploadMetadata:
    """Attachment metadata seen in IndexedDB/Cache."""

    file_uuid: str
    file_name: str
    size: int | None
    mime: str
    remote_path: str
    conversation_uuid: str | None
    account_uuid: str | None
    external_blob_path: str = ""
    page_count: Any = None
    token_count: Any = None
    sent: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)
    # The sending message(s) that carried this attachment: uuid -> created_at.
    sending_messages: dict[str, str] = field(default_factory=dict)

    @property
    def message_created_at(self) -> str:
        """created_at of the one sending message, or "" when absent/ambiguous."""
        times = {t for t in self.sending_messages.values() if t}
        return next(iter(times)) if len(times) == 1 else ""


_ATTACHMENT_NAME_KEYS = ("file_name", "fileName", "name", "filename")
_ATTACHMENT_UUID_KEYS = ("file_uuid", "fileUuid", "uuid", "id", "server_uuid", "serverUuid")
_ATTACHMENT_SIZE_KEYS = ("size_bytes", "sizeBytes", "file_size", "size")


def _looks_like_attachment(node: dict[str, Any]) -> bool:
    has_name = any(
        isinstance(node.get(k), str) and "." in str(node.get(k)) for k in _ATTACHMENT_NAME_KEYS
    )
    has_marker = any(
        k in node
        for k in (
            "file_kind",
            "fileKind",
            "extracted_content",
            "preview_url",
            "thumbnail_url",
            "document_asset",
            "file_variant",
            "page_count",
            "token_count",
            "size_bytes",
            "sizeBytes",
        )
    )
    return has_name and has_marker


def _first(node: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in node and node[key] not in (None, ""):
            return node[key]
    return None


def _walk_attachments(node: Any, out: list[dict[str, Any]], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(node, dict):
        if _looks_like_attachment(node):
            out.append(node)
        for value in node.values():
            _walk_attachments(value, out, depth + 1)
    elif isinstance(node, list):
        for item in node[:400]:
            _walk_attachments(item, out, depth + 1)


def collect_upload_metadata(store: EvidenceStore) -> dict[str, UploadMetadata]:
    """Gather attachment metadata from IndexedDB and Cache."""
    found: dict[str, UploadMetadata] = {}

    for family in (FAMILY_INDEXEDDB, FAMILY_CACHE):
        for record in store.by_family(family):
            attrs = record.attributes
            payload = attrs.get("value") if family == FAMILY_INDEXEDDB else attrs.get("_json")
            if payload is None:
                continue
            nodes: list[dict[str, Any]] = []
            _walk_attachments(payload, nodes)
            for node in nodes:
                name = str(_first(node, _ATTACHMENT_NAME_KEYS) or "")
                uuid = str(_first(node, _ATTACHMENT_UUID_KEYS) or "")
                if not name:
                    continue
                key = uuid or f"name:{name}"
                meta = found.get(key)
                if meta is None:
                    meta = UploadMetadata(
                        file_uuid=uuid,
                        file_name=name,
                        size=_as_int(_first(node, _ATTACHMENT_SIZE_KEYS)),
                        mime=str(node.get("file_kind") or node.get("mime_type") or ""),
                        remote_path=str(
                            node.get("file_path")
                            or node.get("path")
                            or node.get("document_asset", {}).get("path", "")
                            if isinstance(node.get("document_asset"), dict)
                            else node.get("file_path") or node.get("path") or ""
                        ),
                        conversation_uuid=record.conversation_uuid,
                        account_uuid=record.account_uuid,
                        external_blob_path=str(attrs.get("external_value_path") or ""),
                        page_count=node.get("page_count"),
                        token_count=node.get("token_count"),
                    )
                    found[key] = meta
                meta.families.add(family)
                if record.evidence_id not in meta.evidence_ids:
                    meta.evidence_ids.append(record.evidence_id)
                if not meta.conversation_uuid and record.conversation_uuid:
                    meta.conversation_uuid = record.conversation_uuid
                if not meta.external_blob_path and attrs.get("external_value_path"):
                    meta.external_blob_path = str(attrs["external_value_path"])
                # An attachment inside a SENT message body is upload proof;
                # a draft-only attachment is not.
                if attrs.get("key_kind") in ("conversation_api", "react_query_cache"):
                    message = _enclosing_message(payload, node)
                    if message is not None:
                        meta.sent = True
                        uuid_key = str(message.get("uuid") or message.get("id") or "")
                        created = message.get("created_at") or ""
                        if uuid_key:
                            meta.sending_messages.setdefault(uuid_key.lower(), str(created))
    return found


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _enclosing_message(
    payload: Any, node: dict[str, Any], depth: int = 0
) -> dict[str, Any] | None:
    """The innermost message object (has sender/role) that contains `node`."""
    if depth > 12:
        return None
    if isinstance(payload, dict):
        for value in payload.values():
            found = _enclosing_message(value, node, depth + 1)
            if found is not None:
                return found
        if any(k in payload for k in ("sender", "role")) and _contains(payload, node):
            return payload
    elif isinstance(payload, list):
        for item in payload[:400]:
            found = _enclosing_message(item, node, depth + 1)
            if found is not None:
                return found
    return None


def _in_sent_message(payload: Any, node: dict[str, Any], depth: int = 0) -> bool:
    """True when the attachment sits inside an object that has a sender/role."""
    if depth > 12:
        return False
    if isinstance(payload, dict):
        if any(k in payload for k in ("sender", "role")) and _contains(payload, node):
            return True
        for value in payload.values():
            if _in_sent_message(value, node, depth + 1):
                return True
    elif isinstance(payload, list):
        for item in payload[:400]:
            if _in_sent_message(item, node, depth + 1):
                return True
    return False


def _contains(container: Any, node: dict[str, Any], depth: int = 0) -> bool:
    if depth > 8:
        return False
    if container is node:
        return True
    if isinstance(container, dict):
        return any(_contains(v, node, depth + 1) for v in container.values())
    if isinstance(container, list):
        return any(_contains(v, node, depth + 1) for v in container[:400])
    return False


class FileBuilder:
    """Turns collected files, recycle-bin entries and metadata into FileTraces."""

    def __init__(self) -> None:
        self.traces: list[FileTrace] = []

    def add_downloaded_files(
        self, collected: Iterable[CollectedFile], download_evidence: Iterable[EvidenceRecord]
    ) -> None:
        """Allocated Claude files present in the image."""
        by_name: dict[str, list[EvidenceRecord]] = {}
        for record in download_evidence:
            name = str(record.attributes.get("file_name") or "")
            if name:
                by_name.setdefault(name.lower(), []).append(record)

        for item in collected:
            evidence_ids = list(item.evidence_ids)
            conv = item.zone.conversation_uuid if item.zone else None
            # Link to the History download record by exact target path, not name.
            for record in by_name.get(item.name.lower(), []):
                target = str(
                    record.attributes.get("target_path")
                    or record.attributes.get("current_path")
                    or ""
                )
                if _same_windows_path(target, item.windows_path):
                    evidence_ids.append(record.evidence_id)
                    conv = conv or record.conversation_uuid

            self.traces.append(
                FileTrace(
                    file_id=make_file_id("download", item.volume_id, item.windows_path),
                    direction=DIRECTION_DOWNLOAD,
                    claude_verified=bool(item.claude_link_basis),
                    claude_link_basis=item.claude_link_basis,
                    original_name=item.name,
                    original_path=item.windows_path,
                    remote_path=item.zone.remote_path if item.zone else "",
                    conversation_uuid=conv,
                    size=item.size,
                    source="filesystem allocated file",
                    evidence_ids=evidence_ids,
                    mft_reference=f"{item.mft_segment}-{item.mft_sequence}",
                    zone_referrer_url=item.zone.referrer_url if item.zone else "",
                    zone_host_url=item.zone.host_url if item.zone else "",
                    attributes={"volume_id": item.volume_id},
                )
            )

    def add_recycle_entries(self, entries: Iterable[RecycleEntry]) -> None:
        """$I deletion metadata (+ $R presence) for Claude-verified entries."""
        for entry in entries:
            self.traces.append(
                FileTrace(
                    file_id=make_file_id("recycle", entry.volume_id, entry.i_path),
                    direction=DIRECTION_DOWNLOAD,
                    claude_verified=bool(entry.claude_link_basis),
                    claude_link_basis=entry.claude_link_basis,
                    original_name=entry.original_name,
                    original_path=entry.original_path,
                    remote_path=entry.zone.remote_path if entry.zone else "",
                    conversation_uuid=entry.zone.conversation_uuid if entry.zone else None,
                    size=entry.r_logical_size if entry.has_r else entry.original_size,
                    source=f"$Recycle.Bin {'($I+$R)' if entry.has_r else '($I only)'}",
                    evidence_ids=list(entry.evidence_ids),
                    mft_reference=entry.r_frn or None,
                    zone_referrer_url=entry.zone.referrer_url if entry.zone else "",
                    zone_host_url=entry.zone.host_url if entry.zone else "",
                    deletion_time=entry.deletion_time,
                    attributes={
                        "deleted": True,
                        "recycle_token": entry.token,
                        "volume_id": entry.volume_id,
                    },
                )
            )

    def add_uploads(self, uploads: dict[str, UploadMetadata]) -> None:
        """Upload traces from Claude's own attachment metadata (never the blob)."""
        for meta in uploads.values():
            self.traces.append(
                FileTrace(
                    file_id=make_file_id("upload", meta.file_uuid or meta.file_name),
                    direction=DIRECTION_UPLOAD,
                    # The metadata itself comes from Claude's own attachment store.
                    claude_verified=True,
                    claude_link_basis=BASIS_CLAUDE_STORAGE,
                    original_name=meta.file_name,
                    original_path="",
                    remote_path=meta.remote_path,
                    account_uuid=meta.account_uuid,
                    conversation_uuid=meta.conversation_uuid,
                    file_uuid=meta.file_uuid,
                    size=meta.size,
                    mime=meta.mime,
                    source="IndexedDB/Cache attachment metadata",
                    evidence_ids=list(meta.evidence_ids),
                    attributes={
                        "sent_in_message": meta.sent,
                        "message_created_at": meta.message_created_at,
                        "sending_message_uuids": sorted(meta.sending_messages),
                        "page_count": meta.page_count,
                        "token_count": meta.token_count,
                        "families": sorted(meta.families),
                    },
                )
            )

    def deduplicate(self) -> list[FileTrace]:
        """Collapse repeat sightings of the same file IN THE SAME DIRECTION.

        Identity is the file itself (file id), never content: an upload and a
        download of identical bytes stay separate traces.
        """
        by_id: dict[str, FileTrace] = {}
        out: list[FileTrace] = []
        for trace in self.traces:
            existing = by_id.get(trace.file_id)
            if existing is None:
                by_id[trace.file_id] = trace
                out.append(trace)
                continue
            for eid in trace.evidence_ids:
                if eid not in existing.evidence_ids:
                    existing.evidence_ids.append(eid)
        return out


def _same_windows_path(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return str(a).replace("/", "\\").lower() == str(b).replace("/", "\\").lower()


# ===========================================================================
# lifecycle
# ===========================================================================

"""File move / rename / delete reconstruction (--extended-fs, spec section 11.1).

Builds a time-ordered path history per file reference from USN rename pairs,
$Recycle.Bin entries and the filesystem. Unresolved sides stay unresolved: an
inferred path is never presented as a confirmed one. When a lifecycle cannot be
reconstructed reliably, the event is left 판단불가 rather than guessed.
"""

@dataclass
class FileLifecycle:
    """Observed path history for one file reference."""

    file_reference: str
    volume_id: str = ""
    events: list[PathEvent] = field(default_factory=list)
    final_path: str = ""
    original_path: str = ""
    deleted: bool = False
    deletion_time: object = None
    unresolved_steps: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return lifecycle_key(self.volume_id, self.file_reference)

    def terminal_paths(self) -> list[str]:
        """Destinations nothing moved away from again.

        For A->B, B->C only C is terminal: B is an intermediate hop, not a
        competing final location. Two terminals mean a real branch.
        """
        moves = [
            e for e in self.events
            if e.kind in ("moved", "renamed")
            and e.new_path and not e.new_path.startswith("<unresolved>")
        ]
        sources = {_norm_lifecycle_path(e.old_path) for e in moves if e.old_path}
        terminals: dict[str, str] = {}
        for event in moves:
            norm = _norm_lifecycle_path(event.new_path)
            if norm not in sources:
                terminals.setdefault(norm, event.new_path)
        return list(terminals.values())

    @property
    def reliable(self) -> bool:
        """A lifecycle is reliable only when every step resolved on both sides."""
        return self.unresolved_steps == 0 and bool(self.events)

    def summary(self) -> str:
        if self.original_path and self.final_path and self.original_path != self.final_path:
            return f"{self.original_path} -> {self.final_path}"
        return self.final_path or self.original_path or self.file_reference


def build_lifecycles(
    rename_pairs: Iterable[RenamePair],
    usn_records: Iterable[UsnRecord],
    recycle_entries: Iterable[RecycleEntry],
    usn_evidence: Iterable[EvidenceRecord] = (),
) -> dict[str, FileLifecycle]:
    lifecycles: dict[str, FileLifecycle] = {}

    evidence_by_usn: dict[int, str] = {}
    for record in usn_evidence:
        usn = record.attributes.get("usn")
        if isinstance(usn, int):
            evidence_by_usn[usn] = record.evidence_id

    def get(volume_id: str, frn: str) -> FileLifecycle:
        # One lifecycle per (volume, FRN): FRNs are only unique within a volume.
        key = lifecycle_key(volume_id, frn)
        return lifecycles.setdefault(
            key, FileLifecycle(file_reference=frn, volume_id=volume_id)
        )

    # 1) rename / move hops
    for pair in rename_pairs:
        life = get(pair.volume_id, pair.file_reference)
        life.families.add(FAMILY_USN)
        resolved = pair.resolved and bool(pair.old_path) and bool(pair.new_path)
        if not resolved:
            life.unresolved_steps += 1
        life.events.append(
            PathEvent(
                timestamp=pair.timestamp,
                kind="moved" if pair.is_move else "renamed",
                old_path=pair.old_path or (pair.old_name and f"<unresolved>/{pair.old_name}") or "",
                new_path=pair.new_path or (pair.new_name and f"<unresolved>/{pair.new_name}") or "",
                resolved=resolved,
                source_family=FAMILY_USN,
                note=pair.note,
            )
        )

    # 2) create / delete markers
    for record in usn_records:
        if not any(r in record.reasons for r in ("FILE_CREATE", "FILE_DELETE")):
            continue
        life = get(record.volume_id, record.file_reference)
        life.families.add(FAMILY_USN)
        kind = "deleted" if "FILE_DELETE" in record.reasons else "created"
        eid = evidence_by_usn.get(record.usn)
        life.events.append(
            PathEvent(
                timestamp=record.timestamp,
                kind=kind,
                new_path=record.file_name,
                resolved=True,
                source_family=FAMILY_USN,
                evidence_ids=[eid] if eid else [],
            )
        )
        if kind == "deleted":
            life.deleted = True
            life.deletion_time = record.timestamp

    # 3) recycle bin: authoritative original path + deletion time
    for entry in recycle_entries:
        key = _match_recycle_to_lifecycle(entry, lifecycles)
        life = lifecycles.get(key) or get(entry.volume_id, key.split("|", 1)[-1])
        life.families.add(FAMILY_RECYCLE_BIN)
        life.deleted = True
        life.deletion_time = entry.deletion_time
        life.original_path = life.original_path or entry.original_path
        life.evidence_ids.extend(entry.evidence_ids)
        life.events.append(
            PathEvent(
                timestamp=entry.deletion_time,
                kind="deleted",
                old_path=entry.original_path,
                new_path=entry.r_path,
                resolved=bool(entry.original_path),
                source_family=FAMILY_RECYCLE_BIN,
                evidence_ids=list(entry.evidence_ids),
                note="" if entry.has_r else "$I only: bytes not recovered",
            )
        )

    # 4) order events and derive endpoints
    for life in lifecycles.values():
        life.events.sort(key=lambda e: sort_key(e.timestamp))
        for event in life.events:
            if event.old_path and not event.old_path.startswith("<unresolved>"):
                if not life.original_path:
                    life.original_path = event.old_path
        terminals = life.terminal_paths()
        # A final path exists only when the chain converges on one terminal.
        life.final_path = terminals[0] if len(terminals) == 1 else ""
    return lifecycles


def lifecycle_key(volume_id: str, frn: str) -> str:
    return f"{volume_id}|{frn}"


def _norm_lifecycle_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower().rstrip("/")


def _match_recycle_to_lifecycle(
    entry: RecycleEntry, lifecycles: dict[str, FileLifecycle]
) -> str:
    """Attach a recycle entry to the USN lifecycle that moved it there.

    Matching uses the $R path produced by the rename, which is a strong
    identity. Filename alone is never used across different files.
    """
    target = (entry.r_path or "").lower()
    if target:
        for frn, life in lifecycles.items():
            if entry.volume_id and life.volume_id and entry.volume_id != life.volume_id:
                continue
            for event in life.events:
                if (event.new_path or "").lower() == target:
                    return frn
    return f"recycle:{entry.sid}:{entry.token}"


def cross_volume_warning(
    create_records: Iterable[UsnRecord], delete_records: Iterable[UsnRecord]
) -> list[str]:
    """A create+delete pair is NOT proof of a cross-volume move (spec section 11.1)."""
    notes: list[str] = []
    created = {r.file_name.lower() for r in create_records if r.file_name}
    deleted = {r.file_name.lower() for r in delete_records if r.file_name}
    for name in sorted(created & deleted):
        notes.append(
            f"{name}: create and delete both observed; this is NOT treated as a "
            "cross-volume move (different FRNs cannot be linked by filename)"
        )
    return notes


# ===========================================================================
# usn_paths
# ===========================================================================

"""Additional metadata lookup at a USN-confirmed final path.

This is deliberately narrow. It looks up exactly ONE already-known path per file
(MFT entry and Zone.Identifier only; no file bytes) and never searches. All five
conditions must hold:

  1. the move is connected by the same FRN / a trustworthy rename chain
  2. RENAME_OLD_NAME and RENAME_NEW_NAME agree without contradiction
  3. the whole chain resolves to exactly ONE final path
  4. a file exists at that path and is currently allocated
  5. it is strongly tied to existing Claude-verified evidence by FRN, original
     path or Zone.Identifier

Ambiguity of any kind (several candidate endpoints, a journal gap, an
unresolved parent) means: record the state and move on. No whole-disk name
search, no recursive profile walk, no filename-only linking, no carving.
"""

# Why a candidate was rejected; reported in the console log.
SKIP_UNRELIABLE_CHAIN = "rename_chain_unreliable"
SKIP_MULTIPLE_ENDPOINTS = "multiple_final_paths"
SKIP_NO_FINAL_PATH = "no_resolved_final_path"
SKIP_NO_STRONG_LINK = "no_strong_link_to_claude_evidence"
SKIP_NOT_ALLOCATED = "final_path_not_allocated"


@dataclass
class UsnPathCandidate:
    file_reference: str
    final_path: str
    link_basis: str
    trace: FileTrace | None = None
    accepted: bool = False
    skip_reason: str = ""
    note: str = ""
    volume_id: str = ""


@dataclass
class UsnPathPlan:
    candidates: list[UsnPathCandidate] = field(default_factory=list)

    @property
    def accepted(self) -> list[UsnPathCandidate]:
        return [c for c in self.candidates if c.accepted]

    @property
    def rejected(self) -> list[UsnPathCandidate]:
        return [c for c in self.candidates if not c.accepted]


def _norm_usn_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower().lstrip("/")


def _endpoints(life: FileLifecycle) -> set[str]:
    """Terminal destinations only.

    In A->B->C the intermediate B is NOT a competing final path; only C is.
    Several terminals means the chain genuinely branches.
    """
    return set(life.terminal_paths())


def _strong_link(life: FileLifecycle, traces: Iterable[FileTrace]) -> tuple[FileTrace | None, str]:
    """Tie a lifecycle to existing Claude evidence. Filename alone never counts."""
    original = _norm_usn_path(life.original_path)
    for trace in traces:
        if not trace.claude_verified:
            continue  # only Claude-verified files can anchor a final path
        trace_volume = str(trace.attributes.get("volume_id") or "")
        if trace_volume and life.volume_id and trace_volume != life.volume_id:
            continue  # an FRN only identifies a file within its own volume
        if trace.mft_reference and trace.mft_reference == life.file_reference:
            return trace, "same_file_reference"
        if original and _norm_usn_path(trace.original_path) == original:
            return trace, "same_original_path"
        if trace.zone_host_url and trace.conversation_uuid:
            # Zone.Identifier proves the Claude origin; pair it with the path.
            if original and _norm_usn_path(trace.original_path) == original:
                return trace, "zone_identifier"
    return None, ""


def plan_usn_path_collection(
    lifecycles: dict[str, FileLifecycle],
    traces: Iterable[FileTrace],
    path_exists,
) -> UsnPathPlan:
    """Decide which USN-confirmed final paths may be opened directly.

    `path_exists(volume_id, image_path) -> bool` must confirm an allocated
    file on the lifecycle's OWN volume.
    """
    plan = UsnPathPlan()
    traces = list(traces)

    for life in lifecycles.values():
        endpoints = _endpoints(life)
        if not endpoints:
            continue

        trace, basis = _strong_link(life, traces)
        candidate = UsnPathCandidate(
            file_reference=life.file_reference,
            final_path=sorted(endpoints)[0] if len(endpoints) == 1 else "",
            link_basis=basis,
            trace=trace,
            volume_id=life.volume_id,
        )

        # (1) and (2): every hop must have resolved on both sides.
        if not life.reliable:
            candidate.skip_reason = SKIP_UNRELIABLE_CHAIN
            candidate.note = f"{life.unresolved_steps} unresolved rename step(s)"
            plan.candidates.append(candidate)
            continue

        # (3): exactly one endpoint.
        if len(endpoints) != 1:
            candidate.skip_reason = SKIP_MULTIPLE_ENDPOINTS
            candidate.note = f"{len(endpoints)} candidate final paths"
            plan.candidates.append(candidate)
            continue
        if not life.final_path:
            candidate.skip_reason = SKIP_NO_FINAL_PATH
            plan.candidates.append(candidate)
            continue

        # (5): a strong tie to Claude evidence.
        if trace is None:
            candidate.skip_reason = SKIP_NO_STRONG_LINK
            plan.candidates.append(candidate)
            continue

        # (4): an allocated file must actually be there.
        if not path_exists(life.volume_id, candidate.final_path):
            candidate.skip_reason = SKIP_NOT_ALLOCATED
            candidate.note = "no allocated file at the confirmed final path"
            plan.candidates.append(candidate)
            continue

        candidate.accepted = True
        plan.candidates.append(candidate)

    return plan
