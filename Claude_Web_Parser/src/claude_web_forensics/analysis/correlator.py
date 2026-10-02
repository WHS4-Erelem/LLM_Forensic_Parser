"""Independent-family counting for cross-validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..model.entities import EvidenceRecord, EvidenceStore

@dataclass
class EvidenceGroup:
    evidence_ids: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)

    counted_sources: set[str] = field(default_factory=set)

    @property
    def independent_family_count(self) -> int:
        return len(self.families)

def derived_source_key(record: EvidenceRecord) -> str:
    attrs = record.attributes
    family = record.artifact_family
    if family == "history":
        if attrs.get("subtype") == "download":
            return f"history:download:{attrs.get('download_id')}"
        return f"history:url:{attrs.get('url')}"
    keys = {
        "mft": ("frn",), "indexeddb": ("leveldb", "database", "object_store", "key_text"),
        "cache": ("cache_key", "variant_index"), "sessions": ("session_file", "url", "index"),
        "local_storage": ("storage_key", "script_key"), "zone_identifier": ("file_path",),
        "recycle_bin": ("sid", "token"), "filesystem_file": ("image_path",), "usn": ("file_reference",),
    }.get(family)
    if keys is None:
        return f"{family}:{record.evidence_id}"
    return f"{family}:" + ":".join(str(attrs.get(k)) for k in keys)

class Correlator:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def group(self, records: Iterable[EvidenceRecord | None]) -> EvidenceGroup:
        group = EvidenceGroup()
        for record in records:
            if record is None:
                continue
            if record.evidence_id not in group.evidence_ids:
                group.evidence_ids.append(record.evidence_id)
            key = derived_source_key(record)
            if key not in group.counted_sources:
                group.counted_sources.add(key)
                group.families.add(record.artifact_family)
        return group
