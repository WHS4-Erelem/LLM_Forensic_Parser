"""Entity correlation and independent-family counting (spec section 16).

Two records are only combined when they point at the SAME entity via a strong
identity (UUID, hash, FRN, exact URL/path) plus matching account/org/conversation
context and a per-detector temporal rule. There is no global
"same filename within N minutes" rule.

Cross-validation counts DISTINCT artifact families. Records that derive from one
another -- History downloads + its url chain, MFT SI + FN, live + historical
versions of one IndexedDB key, Cache raw + decoded body, repeated commands in
one SNSS file -- all count as ONE.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterable

from ..model.entities import FAMILY_DISPLAY, EvidenceRecord, EvidenceStore


@dataclass
class EvidenceGroup:
    """A set of evidence believed to describe one entity/action."""

    evidence_ids: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)
    # Sub-source keys already counted, so derived records cannot double-count.
    counted_sources: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def independent_family_count(self) -> int:
        return len(self.families)

    def display_artifacts(self) -> list[str]:
        """Artifact display names, de-duplicated, in a stable order."""
        seen: list[str] = []
        for family in sorted(self.families):
            name = FAMILY_DISPLAY.get(family, family)
            if name not in seen:
                seen.append(name)
        return seen


def derived_source_key(record: EvidenceRecord) -> str:
    """Identify the underlying physical source a record derives from.

    Two records with the same key are NOT independent corroboration even though
    they are separate rows.
    """
    attrs = record.attributes
    family = record.artifact_family

    if family == "history":
        subtype = attrs.get("subtype")
        if subtype == "download":
            # downloads and downloads_url_chains describe one download.
            return f"history:download:{attrs.get('download_id')}"
        if subtype in ("url", "visit"):
            return f"history:url:{attrs.get('url')}"
    if family == "mft":
        # SI and FN timestamps live in the same MFT record.
        return f"mft:{attrs.get('frn')}"
    if family == "indexeddb":
        # live + historical versions of one key are one source.
        return (
            f"indexeddb:{attrs.get('leveldb')}:{attrs.get('database')}:"
            f"{attrs.get('object_store')}:{attrs.get('key_text')}"
        )
    if family == "cache":
        # raw body and decoded body are one cache entry.
        return f"cache:{attrs.get('cache_key')}:{attrs.get('variant_index')}"
    if family == "sessions":
        # repeated commands inside one SNSS file are one source.
        return f"sessions:{attrs.get('session_file')}:{attrs.get('url')}:{attrs.get('index')}"
    if family == "local_storage":
        return f"local_storage:{attrs.get('storage_key')}:{attrs.get('script_key')}"
    if family == "zone_identifier":
        return f"zone:{attrs.get('file_path')}"
    if family == "recycle_bin":
        return f"recycle:{attrs.get('sid')}:{attrs.get('token')}"
    if family == "filesystem_file":
        return f"file:{attrs.get('image_path')}"
    if family == "usn":
        return f"usn:{attrs.get('file_reference')}"
    return f"{family}:{record.evidence_id}"


class Correlator:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def group(self, records: Iterable[EvidenceRecord], note: str = "") -> EvidenceGroup:
        """Build a group, counting each independent family at most once."""
        group = EvidenceGroup()
        if note:
            group.notes.append(note)
        for record in records:
            if record is None:
                continue
            if record.evidence_id not in group.evidence_ids:
                group.evidence_ids.append(record.evidence_id)
            key = derived_source_key(record)
            if key in group.counted_sources:
                # Same underlying source: contributes evidence, not independence.
                continue
            group.counted_sources.add(key)
            group.families.add(record.artifact_family)
        return group

    def by_conversation(self, conversation_uuid: str) -> list[EvidenceRecord]:
        target = (conversation_uuid or "").lower()
        if not target:
            return []
        return [r for r in self.store if (r.conversation_uuid or "").lower() == target]

    def by_predicate(self, predicate) -> list[EvidenceRecord]:
        return [r for r in self.store if predicate(r)]


def within(
    a: dt.datetime | None, b: dt.datetime | None, seconds: float
) -> bool:
    """Per-detector temporal proximity. Unknown times never satisfy the rule."""
    if a is None or b is None:
        return False
    return abs((a - b).total_seconds()) <= seconds


def same_entity_by_uuid(a: str | None, b: str | None) -> bool:
    return bool(a and b and a.lower() == b.lower())


def same_path(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return str(a).replace("/", "\\").lower() == str(b).replace("/", "\\").lower()


def same_hash(a: str | None, b: str | None) -> bool:
    return bool(a and b and a.lower() == b.lower())
