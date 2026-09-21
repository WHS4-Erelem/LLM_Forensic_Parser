"""--extended-fs parsers: the $UsnJrnl:$J change journal and $Recycle.Bin.

Merged verbatim from: usn.py, recycle_bin.py.
"""
from __future__ import annotations

import datetime as dt
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator
from ..image.volumes import NtfsVolume
from ..model.entities import FAMILY_USN, EvidenceRecord, make_evidence_id
from ..model.entities import ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import from_filetime
from ..model.entities import FAMILY_RECYCLE_BIN, EvidenceRecord, make_evidence_id
from ..util.common import logical_size
from . import filesystem as zone_parser


# ===========================================================================
# usn
# ===========================================================================

"""$Extend/$UsnJrnl:$J parser (spec section 11.1, --extended-fs only).

Parses USN_RECORD_V2/V3 and reconstructs ONE-HOP rename/move pairs. The journal
is a partial history, not a complete audit log: wrap and truncation mean older
records may simply be absent. Cross-volume moves are never inferred from a
create+delete pair, and files are never linked on filename alone.
"""

USN_PATH = "/$Extend/$UsnJrnl"
USN_STREAM = "$J"

# Reasons required by spec section 11.1.
REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}

SUPPORTED_VERSIONS = {(2, 0), (3, 0)}
CHUNK = 4 * 1024 * 1024


def decode_reasons(mask: int) -> list[str]:
    return [name for bit, name in REASON_FLAGS.items() if mask & bit]


@dataclass
class UsnRecord:
    usn: int
    version: tuple[int, int]
    file_reference: str
    parent_reference: str
    timestamp: dt.datetime | None
    reasons: list[str]
    reason_mask: int
    file_name: str
    file_attributes: int
    offset: int
    volume_id: str = ""

    @property
    def frn_segment(self) -> int | None:
        try:
            return int(self.file_reference.split("-")[0])
        except (ValueError, IndexError):
            return None


def _ref_v2(value: int) -> str:
    return f"{value & 0x0000FFFFFFFFFFFF}-{(value >> 48) & 0xFFFF}"


def _ref_v3(raw: bytes) -> str:
    # 128-bit reference: low 8 bytes carry the MFT segment / sequence.
    low = int.from_bytes(raw[:8], "little")
    return _ref_v2(low)


def iter_usn_records(fh: BinaryIO) -> Iterator[tuple[UsnRecord | None, dict[str, Any]]]:
    """Stream the $J sparse stream. Yields (record, meta); record is None for skips."""
    base_offset = 0
    carry = b""
    while True:
        chunk = fh.read(CHUNK)
        if not chunk:
            break
        buf = carry + chunk
        pos = 0
        while pos + 8 <= len(buf):
            length = struct.unpack_from("<I", buf, pos)[0]
            if length == 0:
                # Sparse / zero-filled region: skip forward 8 bytes at a time.
                pos += 8
                continue
            if length < 60 or length > 4096:
                yield None, {
                    "skip": "invalid_length",
                    "offset": base_offset + pos,
                    "length": length,
                }
                pos += 8
                continue
            if pos + length > len(buf):
                break
            record_bytes = buf[pos : pos + length]
            major, minor = struct.unpack_from("<HH", record_bytes, 4)
            if (major, minor) not in SUPPORTED_VERSIONS:
                yield None, {
                    "skip": "unsupported_version",
                    "version": f"{major}.{minor}",
                    "offset": base_offset + pos,
                    "length": length,
                }
                pos += length
                continue
            try:
                if major == 2:
                    (
                        file_ref,
                        parent_ref,
                        usn,
                        timestamp,
                        reason,
                        _source,
                        _sid,
                        attrs,
                        name_len,
                        name_off,
                    ) = struct.unpack_from("<QQqqIIIIHH", record_bytes, 8)
                    file_reference = _ref_v2(file_ref)
                    parent_reference = _ref_v2(parent_ref)
                else:
                    file_ref_raw = record_bytes[8:24]
                    parent_ref_raw = record_bytes[24:40]
                    usn, timestamp, reason, _source, attrs, name_len, name_off = struct.unpack_from(
                        "<qqIIIHH", record_bytes, 40
                    )
                    file_reference = _ref_v3(file_ref_raw)
                    parent_reference = _ref_v3(parent_ref_raw)

                name = ""
                if 0 < name_len and name_off + name_len <= length:
                    name = record_bytes[name_off : name_off + name_len].decode(
                        "utf-16-le", errors="replace"
                    )
                yield (
                    UsnRecord(
                        usn=usn,
                        version=(major, minor),
                        file_reference=file_reference,
                        parent_reference=parent_reference,
                        timestamp=from_filetime(timestamp),
                        reasons=decode_reasons(reason),
                        reason_mask=reason,
                        file_name=name,
                        file_attributes=attrs,
                        offset=base_offset + pos,
                    ),
                    {},
                )
            except Exception as exc:
                yield None, {
                    "skip": "parse_error",
                    "offset": base_offset + pos,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            pos += length
        carry = buf[pos:]
        base_offset += pos


@dataclass
class RenamePair:
    file_reference: str
    old_name: str
    new_name: str
    old_parent: str
    new_parent: str
    old_path: str = ""
    new_path: str = ""
    timestamp: dt.datetime | None = None
    resolved: bool = False
    partial: bool = False
    note: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    volume_id: str = ""

    @property
    def is_move(self) -> bool:
        return self.old_parent != self.new_parent

    @property
    def is_rename(self) -> bool:
        return self.old_name != self.new_name


def build_rename_pairs(records: list[UsnRecord], max_gap_seconds: float = 5.0) -> list[RenamePair]:
    """Pair RENAME_OLD_NAME with RENAME_NEW_NAME on the SAME FRN.

    Pairing requires identical file reference (segment AND sequence), USN
    ordering and temporal proximity. Filename similarity alone never links two
    different files (spec section 11.1).
    """
    pairs: list[RenamePair] = []
    pending: dict[str, UsnRecord] = {}
    # Chrome/Windows emit the same rename twice (plain, then with CLOSE); both
    # describe one logical event, so they collapse to a single pair.
    seen: set[tuple[str, str, str, str]] = set()
    resolved_arrivals: set[tuple[str, str, str]] = set()

    def _emit(pair: RenamePair) -> None:
        key = (
            pair.file_reference,
            pair.old_name,
            pair.new_name,
            pair.timestamp.isoformat() if pair.timestamp else "",
        )
        if key in seen:
            return
        seen.add(key)
        pairs.append(pair)

    for record in sorted(records, key=lambda r: r.usn):
        if "RENAME_OLD_NAME" in record.reasons:
            pending[record.file_reference] = record
        if "RENAME_NEW_NAME" in record.reasons:
            old = pending.pop(record.file_reference, None)
            if old is None:
                arrival = (
                    record.file_reference,
                    record.file_name,
                    record.timestamp.isoformat() if record.timestamp else "",
                )
                if arrival in resolved_arrivals:
                    # Same rename repeated with the CLOSE flag; already paired.
                    continue
                # New name without the matching old name: journal gap.
                _emit(
                    RenamePair(
                        file_reference=record.file_reference,
                        old_name="",
                        new_name=record.file_name,
                        old_parent="",
                        new_parent=record.parent_reference,
                        timestamp=record.timestamp,
                        resolved=False,
                        partial=True,
                        note="RENAME_OLD_NAME not present (journal gap or wrap)",
                    )
                )
                continue
            if old.timestamp and record.timestamp:
                delta = abs((record.timestamp - old.timestamp).total_seconds())
                if delta > max_gap_seconds:
                    _emit(
                        RenamePair(
                            file_reference=record.file_reference,
                            old_name=old.file_name,
                            new_name=record.file_name,
                            old_parent=old.parent_reference,
                            new_parent=record.parent_reference,
                            timestamp=record.timestamp,
                            resolved=False,
                            partial=True,
                            note=f"old/new name records {delta:.1f}s apart; pairing uncertain",
                        )
                    )
                    continue
            resolved_arrivals.add(
                (
                    record.file_reference,
                    record.file_name,
                    record.timestamp.isoformat() if record.timestamp else "",
                )
            )
            _emit(
                RenamePair(
                    file_reference=record.file_reference,
                    old_name=old.file_name,
                    new_name=record.file_name,
                    old_parent=old.parent_reference,
                    new_parent=record.parent_reference,
                    timestamp=record.timestamp,
                    resolved=True,
                )
            )
    return pairs


def resolve_parent_path(volume: NtfsVolume, parent_reference: str) -> str:
    """Best-effort path for a parent FRN; empty string when unresolved."""
    try:
        segment = int(parent_reference.split("-")[0])
    except (ValueError, IndexError):
        return ""
    try:
        record = volume._fs.mft.get(segment)  # noqa: SLF001 - adapter-local access
        paths = record.full_paths()
        if paths:
            return "/" + str(paths[0]).replace("\\", "/").lstrip("/")
    except Exception:
        return ""
    return ""


def parse_usn(
    volume: NtfsVolume,
    interesting_names: set[str] | None = None,
    max_records: int = 2_000_000,
    interesting_frns: set[str] | None = None,
) -> tuple[list[EvidenceRecord], list[UsnRecord], list[RenamePair], ParseStatus]:
    """Parse $J once, sequentially, keeping only records of interest.

    Interest = an exact name in `interesting_names` (Claude History targets and
    verified Claude files) or a file reference in `interesting_frns` (verified
    Claude files). Everything else is streamed past and dropped.
    """
    source_path = f"{USN_PATH}:{USN_STREAM}"
    records: list[EvidenceRecord] = []
    kept: list[UsnRecord] = []

    record = volume.get(USN_PATH)
    if record is None:
        return (
            records,
            kept,
            [],
            ParseStatus(
                artifact="$UsnJrnl:$J",
                family=FAMILY_USN,
                status=ST_NOT_FOUND,
                source_path=source_path,
                message="$UsnJrnl not present on this volume",
                impact="rename/move/delete history unavailable (normal partial condition)",
            ),
        )

    fh = volume.open_record(record, USN_STREAM)
    if fh is None:
        return (
            records,
            kept,
            [],
            ParseStatus(
                artifact="$UsnJrnl:$J",
                family=FAMILY_USN,
                status=ST_NOT_FOUND,
                source_path=source_path,
                message="$J stream could not be opened",
            ),
        )

    total = 0
    skipped: dict[str, int] = {}
    skip_offsets: list[int] = []
    wanted = {n.lower() for n in (interesting_names or set())}
    seeded_frns = set(interesting_frns or ())
    interesting_frns = set(seeded_frns)
    # Sliding window of recently-seen records, used to recover the
    # RENAME_OLD_NAME that precedes a newly-interesting RENAME_NEW_NAME.
    recent: deque[UsnRecord] = deque(maxlen=512)

    try:
        for usn_record, meta in iter_usn_records(fh):
            if usn_record is None:
                kind = str(meta.get("skip"))
                skipped[kind] = skipped.get(kind, 0) + 1
                if len(skip_offsets) < 50:
                    skip_offsets.append(int(meta.get("offset", 0)))
                continue
            total += 1
            if total > max_records:
                skipped["record_limit"] = skipped.get("record_limit", 0) + 1
                break
            if wanted or seeded_frns:
                name_hit = usn_record.file_name.lower() in wanted
                if name_hit and usn_record.file_reference not in interesting_frns:
                    # Track the file reference so records for the SAME file are
                    # kept even when it has been renamed (e.g. moved into
                    # $Recycle.Bin as $R<token>, or renamed from .crdownload).
                    # Matching is by FRN, never by filename similarity
                    # (spec section 11.1).
                    interesting_frns.add(usn_record.file_reference)
                    # Backfill: the matching RENAME_OLD_NAME sits immediately
                    # before its RENAME_NEW_NAME, so recover it from the window.
                    for earlier in recent:
                        if earlier.file_reference == usn_record.file_reference:
                            kept.append(earlier)
                elif not name_hit and usn_record.file_reference not in interesting_frns:
                    recent.append(usn_record)
                    continue
            kept.append(usn_record)
            recent.append(usn_record)
    except Exception as exc:
        skipped[f"stream_error:{type(exc).__name__}"] = 1
    finally:
        try:
            fh.close()
        except Exception:
            pass

    for usn_record in kept:
        usn_record.volume_id = volume.info.identifier
    pairs = build_rename_pairs(kept)
    for pair in pairs:
        pair.volume_id = volume.info.identifier
    for pair in pairs:
        pair.old_path = resolve_parent_path(volume, pair.old_parent) if pair.old_parent else ""
        pair.new_path = resolve_parent_path(volume, pair.new_parent) if pair.new_parent else ""
        if pair.old_path and pair.old_name:
            pair.old_path = f"{pair.old_path.rstrip('/')}/{pair.old_name}"
        if pair.new_path and pair.new_name:
            pair.new_path = f"{pair.new_path.rstrip('/')}/{pair.new_name}"
        if not (pair.old_path and pair.new_path):
            pair.partial = True
            if not pair.note:
                pair.note = "parent path unresolved on one or both sides"

    for usn_record in kept:
        locator = f"usn={usn_record.usn};offset={usn_record.offset}"
        payload = {
            "usn": usn_record.usn,
            "frn": usn_record.file_reference,
            "reasons": usn_record.reasons,
            "name": usn_record.file_name,
        }
        records.append(
            EvidenceRecord(
                evidence_id=make_evidence_id(FAMILY_USN, source_path, locator, payload),
                artifact="$UsnJrnl:$J",
                artifact_family=FAMILY_USN,
                source_path=source_path,
                record_locator=locator,
                timestamp=usn_record.timestamp,
                summary=f"USN {'/'.join(usn_record.reasons)}: {usn_record.file_name}",
                attributes={
                    "subtype": "usn_record",
                    "usn": usn_record.usn,
                    "version": f"{usn_record.version[0]}.{usn_record.version[1]}",
                    "file_reference": usn_record.file_reference,
                    "parent_reference": usn_record.parent_reference,
                    "file_name": usn_record.file_name,
                    "reasons": usn_record.reasons,
                    "reason_mask": usn_record.reason_mask,
                    "file_attributes": usn_record.file_attributes,
                    "byte_offset": usn_record.offset,
                    "volume_id": volume.info.identifier,
                    "journal_is_partial_history": True,
                },
            )
        )

    message = (
        f"records={total} kept={len(kept)} rename_pairs={len(pairs)}"
        + (f" skipped={skipped}" if skipped else "")
    )
    status = ST_PARTIAL if skipped else ST_PARSED
    return (
        records,
        kept,
        pairs,
        ParseStatus(
            artifact="$UsnJrnl:$J",
            family=FAMILY_USN,
            status=status,
            source_path=source_path,
            record_count=len(records),
            error_count=sum(skipped.values()),
            message=message,
            impact="unsupported USN record versions skipped (offsets recorded)"
            if "unsupported_version" in skipped
            else "",
        ),
    )


# ===========================================================================
# recycle_bin
# ===========================================================================

"""$Recycle.Bin parser (spec section 11.2, --extended-fs only).

Metadata only: discover_recycle_bin() reads the $I/$R names, original path,
deletion time, $R logical size / FRN and the $R Zone.Identifier ADS. Evidence
records are built only for entries whose Claude relevance was established
(analysis/claude_scope.py). File bytes are never exported.

Shift+Delete, emptying the bin and cluster overwrite all leave nothing here --
that limitation is documented in the README.
"""

RECYCLE_ROOT = "/$Recycle.Bin"


@dataclass
class RecycleEntry:
    sid: str
    token: str
    i_path: str
    r_path: str = ""
    format_version: int | None = None
    original_path: str = ""
    original_size: int | None = None
    deletion_time: dt.datetime | None = None
    volume_id: str = ""
    r_logical_size: int | None = None
    r_frn: str = ""
    claude_link_basis: str = ""
    zone: zone_parser.ZoneInfo | None = None
    evidence_ids: list[str] = field(default_factory=list)

    @property
    def has_r(self) -> bool:
        return bool(self.r_path)

    @property
    def original_name(self) -> str:
        return self.original_path.replace("/", "\\").rsplit("\\", 1)[-1] if self.original_path else ""


def parse_i_file(data: bytes) -> tuple[int | None, int | None, dt.datetime | None, str]:
    """Parse $I. Version 1 (Vista-Win8) and 2 (Win10/11) layouts."""
    if len(data) < 24:
        return None, None, None, ""
    version, size = struct.unpack_from("<QQ", data, 0)
    deleted_raw = struct.unpack_from("<Q", data, 16)[0]
    deletion_time = from_filetime(deleted_raw)

    name = ""
    if version == 1:
        # Fixed 260-character UTF-16 path at offset 24.
        raw = data[24 : 24 + 520]
        name = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    elif version == 2:
        if len(data) >= 28:
            name_len = struct.unpack_from("<I", data, 24)[0]
            raw = data[28 : 28 + name_len * 2]
            name = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    else:
        # Unknown version: report it rather than guessing a layout.
        return version, size, deletion_time, ""
    return version, size, deletion_time, name


def discover_recycle_bin(
    volume: NtfsVolume,
) -> tuple[list[RecycleEntry], ParseStatus]:
    """Phase 1: enumerate every $I/$R pair WITHOUT reading any $R content."""
    entries: list[RecycleEntry] = []
    errors: list[str] = []

    if not volume.exists(RECYCLE_ROOT):
        return (
            entries,
            ParseStatus(
                artifact="$Recycle.Bin",
                family=FAMILY_RECYCLE_BIN,
                status=ST_NOT_FOUND,
                source_path=RECYCLE_ROOT,
                message="$Recycle.Bin not present on this volume",
                impact="deletion metadata / recoverable bytes unavailable",
            ),
        )

    unknown_versions = 0
    orphan_i = 0
    orphan_r = 0

    for sid, sid_record in sorted(volume.listdir(RECYCLE_ROOT).items()):
        try:
            if not sid_record.is_dir():
                continue
        except Exception:
            continue

        sid_path = f"{RECYCLE_ROOT}/{sid}"
        children = volume.listdir(sid_path)
        i_files = {n: r for n, r in children.items() if n.startswith("$I")}
        r_files = {n: r for n, r in children.items() if n.startswith("$R")}

        for i_name, i_record in sorted(i_files.items()):
            token = i_name[2:]
            r_name = "$R" + token
            entry = RecycleEntry(
                sid=sid, token=token, i_path=f"{sid_path}/{i_name}",
                volume_id=volume.info.identifier,
            )

            # $I is a tiny metadata record; reading it is not file-content access.
            fh = volume.open_record(i_record)
            if fh is None:
                errors.append(f"{entry.i_path}: cannot read $I")
                continue
            try:
                i_data = fh.read(4096)
            finally:
                try:
                    fh.close()
                except Exception:
                    pass

            version, size, deleted, original = parse_i_file(i_data)
            entry.format_version = version
            entry.original_size = size
            entry.deletion_time = deleted
            entry.original_path = original
            if version not in (1, 2):
                unknown_versions += 1

            r_record = r_files.get(r_name)
            if r_record is not None:
                entry.r_path = f"{sid_path}/{r_name}"
                entry.r_logical_size = logical_size(r_record)
                segment = getattr(r_record, "segment", None)
                try:
                    sequence = int(r_record.header.sequence_number)
                except Exception:
                    sequence = None
                if segment is not None:
                    entry.r_frn = f"{segment}-{sequence}" if sequence is not None else str(segment)
                # The ADS records origin; it is metadata, not the file body.
                if zone_parser.ADS_NAME in volume.data_streams(r_record):
                    zfh = volume.open_record(r_record, zone_parser.ADS_NAME)
                    if zfh is not None:
                        try:
                            entry.zone = zone_parser.parse_zone_bytes(zfh.read(65536))
                        finally:
                            try:
                                zfh.close()
                            except Exception:
                                pass
            else:
                orphan_i += 1
            entries.append(entry)

        for r_name in sorted(r_files):
            if ("$I" + r_name[2:]) not in i_files:
                orphan_r += 1

    note = (
        f"entries={len(entries)} i_only={orphan_i} r_only={orphan_r} "
        f"unknown_format_version={unknown_versions}. Metadata only; $R content is "
        "compared solely for size-matched Claude candidates. Shift+Delete, emptied "
        "bin and cluster overwrite leave no $I/$R."
    )
    status = ST_PARTIAL if (errors or unknown_versions) else ST_PARSED
    return (
        entries,
        ParseStatus(
            artifact="$Recycle.Bin",
            family=FAMILY_RECYCLE_BIN,
            status=status,
            source_path=RECYCLE_ROOT,
            record_count=len(entries),
            error_count=len(errors) + unknown_versions,
            message="; ".join(errors[:5]) or note,
        ),
    )


def recycle_evidence(entry: RecycleEntry) -> list[EvidenceRecord]:
    """Evidence records -- built only for Claude-relevant entries."""
    records: list[EvidenceRecord] = []
    locator = f"sid={entry.sid};token={entry.token}"
    payload = {
        "original_path": entry.original_path,
        "deleted": entry.deletion_time.isoformat() if entry.deletion_time else "",
    }
    evidence = EvidenceRecord(
        evidence_id=make_evidence_id(FAMILY_RECYCLE_BIN, entry.i_path, locator, payload),
        artifact="$Recycle.Bin",
        artifact_family=FAMILY_RECYCLE_BIN,
        source_path=entry.i_path,
        record_locator=locator,
        # $I deletion time IS the action time for a delete (spec section 18).
        timestamp=entry.deletion_time,
        organization_uuid=entry.zone.organization_uuid if entry.zone else None,
        conversation_uuid=entry.zone.conversation_uuid if entry.zone else None,
        summary=f"휴지통 삭제: {entry.original_name or entry.token}",
        attributes={
            "subtype": "recycle_bin_entry",
            "sid": entry.sid,
            "token": entry.token,
            "i_path": entry.i_path,
            "r_path": entry.r_path,
            "format_version": entry.format_version,
            "original_path": entry.original_path,
            "original_name": entry.original_name,
            "original_size": entry.original_size,
            "r_size": entry.r_logical_size,
            "has_r_file": entry.has_r,
            "has_zone_identifier": entry.zone is not None,
            "zone_referrer_url": entry.zone.referrer_url if entry.zone else "",
            "zone_host_url": entry.zone.host_url if entry.zone else "",
            "claude_link_basis": entry.claude_link_basis,
            "volume_id": entry.volume_id,
            "note": ""
            if entry.has_r
            else "$I only: deletion metadata present, $R file not found",
        },
    )
    records.append(evidence)
    entry.evidence_ids.append(evidence.evidence_id)
    if entry.zone is not None:
        zone_evidence = zone_parser.zone_to_evidence(
            entry.zone,
            entry.original_path or entry.r_path,
            entry.r_path,
            entry.volume_id,
            record_locator=f"ads=Zone.Identifier;recycle={entry.token}",
        )
        records.append(zone_evidence)
        entry.evidence_ids.append(zone_evidence.evidence_id)
    return records
