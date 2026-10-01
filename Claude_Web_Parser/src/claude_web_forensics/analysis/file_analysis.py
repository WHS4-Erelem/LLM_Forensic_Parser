"""File analysis: trace building, path lifecycle reconstruction and USN final-path checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..model.entities import DIRECTION_DOWNLOAD, EvidenceRecord, FileTrace, PathEvent
from ..model.entities import FAMILY_RECYCLE_BIN, FAMILY_USN
from ..parsers.extended_fs import RecycleEntry, RenamePair, UsnRecord
from ..parsers.filesystem import CollectedFile
from ..util.common import sort_key, stable_key

def make_file_id(*parts: Any) -> str:
    return "F-" + stable_key(list(parts))

class FileBuilder:
    def __init__(self) -> None:
        self.traces: list[FileTrace] = []

    def add_downloaded_files(
        self, collected: Iterable[CollectedFile], download_evidence: Iterable[EvidenceRecord]
    ) -> None:
        by_name: dict[str, list[EvidenceRecord]] = {}
        for record in download_evidence:
            name = str(record.attributes.get("file_name") or "")
            if name:
                by_name.setdefault(name.lower(), []).append(record)

        for item in collected:
            evidence_ids = list(item.evidence_ids)
            conv = item.zone.conversation_uuid if item.zone else None

            for record in by_name.get(item.name.lower(), []):
                target = str(record.attributes.get("target_path") or record.attributes.get("current_path") or "")
                if _same_windows_path(target, item.windows_path):
                    evidence_ids.append(record.evidence_id)
                    conv = conv or record.conversation_uuid

            self.traces.append(
                FileTrace(
                    file_id=make_file_id("download", item.volume_id, item.windows_path),
                    direction=DIRECTION_DOWNLOAD, claude_verified=bool(item.claude_link_basis),
                    claude_link_basis=item.claude_link_basis, original_name=item.name,
                    original_path=item.windows_path, remote_path=item.zone.remote_path if item.zone else "",
                    conversation_uuid=conv, size=item.size, source="filesystem allocated file",
                    evidence_ids=evidence_ids, mft_reference=f"{item.mft_segment}-{item.mft_sequence}",
                    zone_host_url=item.zone.host_url if item.zone else "",
                    attributes={"volume_id": item.volume_id},
                )
            )

    def add_recycle_entries(self, entries: Iterable[RecycleEntry]) -> None:
        for entry in entries:
            self.traces.append(
                FileTrace(
                    file_id=make_file_id("recycle", entry.volume_id, entry.i_path),
                    direction=DIRECTION_DOWNLOAD, claude_verified=bool(entry.claude_link_basis),
                    claude_link_basis=entry.claude_link_basis, original_name=entry.original_name,
                    original_path=entry.original_path,
                    remote_path=entry.zone.remote_path if entry.zone else "",
                    conversation_uuid=entry.zone.conversation_uuid if entry.zone else None,
                    size=entry.r_logical_size if entry.has_r else entry.original_size,
                    source=f"$Recycle.Bin {'($I+$R)' if entry.has_r else '($I only)'}",
                    evidence_ids=list(entry.evidence_ids), mft_reference=entry.r_frn or None,
                    zone_host_url=entry.zone.host_url if entry.zone else "",
                    deletion_time=entry.deletion_time, attributes={"deleted": True,
                        "recycle_token": entry.token, "volume_id": entry.volume_id,},
                )
            )

    def deduplicate(self) -> list[FileTrace]:
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

@dataclass
class FileLifecycle:
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
        return self.unresolved_steps == 0 and bool(self.events)

    def summary(self) -> str:
        if self.original_path and self.final_path and self.original_path != self.final_path:
            return f"{self.original_path} -> {self.final_path}"
        return self.final_path or self.original_path or self.file_reference

def build_lifecycles(
    rename_pairs: Iterable[RenamePair], usn_records: Iterable[UsnRecord],
    recycle_entries: Iterable[RecycleEntry], usn_evidence: Iterable[EvidenceRecord] = (),
) -> dict[str, FileLifecycle]:
    lifecycles: dict[str, FileLifecycle] = {}

    evidence_by_usn: dict[int, str] = {}
    for record in usn_evidence:
        usn = record.attributes.get("usn")
        if isinstance(usn, int):
            evidence_by_usn[usn] = record.evidence_id

    def get(volume_id: str, frn: str) -> FileLifecycle:
        key = lifecycle_key(volume_id, frn)
        return lifecycles.setdefault(key, FileLifecycle(file_reference=frn, volume_id=volume_id))

    for pair in rename_pairs:
        life = get(pair.volume_id, pair.file_reference)
        life.families.add(FAMILY_USN)
        resolved = pair.resolved and bool(pair.old_path) and bool(pair.new_path)
        if not resolved:
            life.unresolved_steps += 1
        life.events.append(
            PathEvent(
                timestamp=pair.timestamp, kind="moved" if pair.is_move else "renamed",
                old_path=pair.old_path or (pair.old_name and f"<unresolved>/{pair.old_name}") or "",
                new_path=pair.new_path or (pair.new_name and f"<unresolved>/{pair.new_name}") or "",
                resolved=resolved, note=pair.note,
            )
        )

    for record in usn_records:
        if not any(r in record.reasons for r in ("FILE_CREATE", "FILE_DELETE")):
            continue
        life = get(record.volume_id, record.file_reference)
        life.families.add(FAMILY_USN)
        kind = "deleted" if "FILE_DELETE" in record.reasons else "created"
        eid = evidence_by_usn.get(record.usn)
        life.events.append(
            PathEvent(
                timestamp=record.timestamp, kind=kind, new_path=record.file_name, resolved=True,
                evidence_ids=[eid] if eid else [],
            )
        )
        if kind == "deleted":
            life.deleted = True
            life.deletion_time = record.timestamp

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
                timestamp=entry.deletion_time, kind="deleted", old_path=entry.original_path,
                new_path=entry.r_path, resolved=bool(entry.original_path),
                evidence_ids=list(entry.evidence_ids),
                note="" if entry.has_r else "$I only: bytes not recovered",
            )
        )

    for life in lifecycles.values():
        life.events.sort(key=lambda e: sort_key(e.timestamp))
        for event in life.events:
            if event.old_path and not event.old_path.startswith("<unresolved>"):
                if not life.original_path:
                    life.original_path = event.old_path
        terminals = life.terminal_paths()

        life.final_path = terminals[0] if len(terminals) == 1 else ""
    return lifecycles

def lifecycle_key(volume_id: str, frn: str) -> str:
    return f"{volume_id}|{frn}"

def _norm_lifecycle_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower().rstrip("/")

def _match_recycle_to_lifecycle(
    entry: RecycleEntry, lifecycles: dict[str, FileLifecycle]
) -> str:
    target = (entry.r_path or "").lower()
    if target:
        for frn, life in lifecycles.items():
            if entry.volume_id and life.volume_id and entry.volume_id != life.volume_id:
                continue
            for event in life.events:
                if (event.new_path or "").lower() == target:
                    return frn
    return f"recycle:{entry.sid}:{entry.token}"

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
    return set(life.terminal_paths())

def _strong_link(life: FileLifecycle, traces: Iterable[FileTrace]) -> tuple[FileTrace | None, str]:
    original = _norm_usn_path(life.original_path)
    for trace in traces:
        if not trace.claude_verified:
            continue
        trace_volume = str(trace.attributes.get("volume_id") or "")
        if trace_volume and life.volume_id and trace_volume != life.volume_id:
            continue
        if trace.mft_reference and trace.mft_reference == life.file_reference:
            return trace, "same_file_reference"
        if original and _norm_usn_path(trace.original_path) == original:
            return trace, "same_original_path"
        if trace.zone_host_url and trace.conversation_uuid:
            if original and _norm_usn_path(trace.original_path) == original:
                return trace, "zone_identifier"
    return None, ""

def plan_usn_path_collection(
    lifecycles: dict[str, FileLifecycle], traces: Iterable[FileTrace], path_exists,
) -> UsnPathPlan:
    plan = UsnPathPlan()
    traces = list(traces)

    for life in lifecycles.values():
        endpoints = _endpoints(life)
        if not endpoints:
            continue

        trace, basis = _strong_link(life, traces)
        candidate = UsnPathCandidate(
            file_reference=life.file_reference,
            final_path=sorted(endpoints)[0] if len(endpoints) == 1 else "", link_basis=basis, trace=trace,
            volume_id=life.volume_id,
        )

        if not life.reliable:
            candidate.skip_reason = SKIP_UNRELIABLE_CHAIN
            candidate.note = f"{life.unresolved_steps} unresolved rename step(s)"
            plan.candidates.append(candidate)
            continue

        if len(endpoints) != 1:
            candidate.skip_reason = SKIP_MULTIPLE_ENDPOINTS
            candidate.note = f"{len(endpoints)} candidate final paths"
            plan.candidates.append(candidate)
            continue
        if not life.final_path:
            candidate.skip_reason = SKIP_NO_FINAL_PATH
            plan.candidates.append(candidate)
            continue

        if trace is None:
            candidate.skip_reason = SKIP_NO_STRONG_LINK
            plan.candidates.append(candidate)
            continue

        if not path_exists(life.volume_id, candidate.final_path):
            candidate.skip_reason = SKIP_NOT_ALLOCATED
            candidate.note = "no allocated file at the confirmed final path"
            plan.candidates.append(candidate)
            continue

        candidate.accepted = True
        plan.candidates.append(candidate)

    return plan
