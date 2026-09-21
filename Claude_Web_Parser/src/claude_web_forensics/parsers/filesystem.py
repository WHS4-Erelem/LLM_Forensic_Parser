"""Filesystem parsers: $MFT entries, Zone.Identifier ADS and allocated download files.

Merged verbatim from: mft.py, zone_identifier.py, downloads.py.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any
from ..image.volumes import NtfsVolume
from ..model.entities import FAMILY_MFT, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import ensure_aware
import re
from urllib.parse import parse_qs, unquote, urlparse
from ..model.entities import FAMILY_ZONE_IDENTIFIER, EvidenceRecord, make_evidence_id
from .common import conversation_from_url, organization_from_url
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import TYPE_CHECKING
from ..model.entities import (
    FAMILY_FILESYSTEM_FILE,
    EvidenceRecord,
    make_evidence_id,
)
from ..model.entities import ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import logical_size


# ===========================================================================
# mft
# ===========================================================================

"""$MFT parser (spec section 10.7).

SI and FN timestamps come from the same MFT family and are never counted as two
independent corroborations. File mtime is never promoted to a user action time
(spec sections 16.1 and 18).
"""

# NTFS filename namespaces.
NAMESPACE = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32_DOS"}


@dataclass
class MftEntry:
    segment: int
    sequence: int | None
    parent_segment: int | None
    parent_sequence: int | None
    allocated: bool
    is_dir: bool
    full_path: str
    file_names: list[dict[str, Any]] = field(default_factory=list)
    logical_size: int | None = None
    allocated_size: int | None = None
    si_created: dt.datetime | None = None
    si_modified: dt.datetime | None = None
    si_changed: dt.datetime | None = None
    si_accessed: dt.datetime | None = None
    fn_created: dt.datetime | None = None
    fn_modified: dt.datetime | None = None
    fn_changed: dt.datetime | None = None
    fn_accessed: dt.datetime | None = None
    resident: bool | None = None
    data_streams: list[str] = field(default_factory=list)

    @property
    def frn(self) -> str:
        """File reference number: segment + sequence."""
        if self.sequence is None:
            return str(self.segment)
        return f"{self.segment}-{self.sequence}"


def _dtv(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return ensure_aware(value)
    return None


def read_entry(volume: NtfsVolume, record: Any, full_path: str) -> MftEntry:
    """Extract the minimum $MFT field set required by spec section 10.7."""
    segment = int(getattr(record, "segment", -1) or -1)
    header = getattr(record, "header", None)
    sequence = None
    allocated = True
    is_dir = False
    try:
        sequence = int(header.sequence_number)
    except Exception:
        sequence = None
    try:
        # IN_USE flag bit 0 of the record flags.
        flags = int(header.flags)
        allocated = bool(flags & 0x0001)
        is_dir = bool(flags & 0x0002)
    except Exception:
        try:
            is_dir = bool(record.is_dir())
        except Exception:
            is_dir = False

    entry = MftEntry(
        segment=segment,
        sequence=sequence,
        parent_segment=None,
        parent_sequence=None,
        allocated=allocated,
        is_dir=is_dir,
        full_path=full_path,
    )

    # $STANDARD_INFORMATION (0x10)
    try:
        for attr in record.attributes[0x10]:
            value = getattr(attr, "attribute", attr)
            entry.si_created = _dtv(getattr(value, "creation_time", None))
            entry.si_modified = _dtv(getattr(value, "last_modification_time", None))
            entry.si_changed = _dtv(getattr(value, "last_change_time", None))
            entry.si_accessed = _dtv(getattr(value, "last_access_time", None))
            break
    except Exception:
        pass

    # $FILE_NAME (0x30) -- every namespace is preserved.
    try:
        for attr in record.attributes[0x30]:
            value = getattr(attr, "attribute", attr)
            name = getattr(value, "file_name", None) or getattr(value, "filename", None)
            ns = getattr(value, "flags", None)
            try:
                ns_int = int(ns) & 0x03
            except Exception:
                ns_int = None
            entry.file_names.append(
                {
                    "name": str(name or ""),
                    "namespace": NAMESPACE.get(ns_int, str(ns_int)),
                }
            )
            if entry.parent_segment is None:
                parent = getattr(value, "parent", None)
                try:
                    entry.parent_segment = int(getattr(parent, "segment", parent))
                    entry.parent_sequence = int(getattr(parent, "sequence", 0) or 0)
                except Exception:
                    pass
            if entry.fn_created is None:
                entry.fn_created = _dtv(getattr(value, "creation_time", None))
                entry.fn_modified = _dtv(getattr(value, "last_modification_time", None))
                entry.fn_changed = _dtv(getattr(value, "last_change_time", None))
                entry.fn_accessed = _dtv(getattr(value, "last_access_time", None))
    except Exception:
        pass

    # $DATA (0x80): sizes, residency and named streams (ADS).
    try:
        for attr in record.attributes[0x80]:
            name = getattr(attr, "name", "") or ""
            if name:
                entry.data_streams.append(name)
                continue
            if entry.logical_size is None:
                entry.logical_size = getattr(attr, "size", None)
                entry.allocated_size = getattr(attr, "allocated_size", None)
                entry.resident = getattr(attr, "resident", None)
    except Exception:
        pass

    if entry.logical_size is None:
        try:
            entry.logical_size = int(record.size())
        except Exception:
            entry.logical_size = None

    return entry


def entry_to_evidence(
    entry: MftEntry, source_path: str, volume_id: str, note: str = ""
) -> EvidenceRecord:
    locator = f"mft={entry.segment};seq={entry.sequence}"
    payload = {
        "frn": entry.frn,
        "path": entry.full_path,
        "allocated": entry.allocated,
    }
    return EvidenceRecord(
        evidence_id=make_evidence_id(FAMILY_MFT, source_path, locator, payload),
        artifact="$MFT",
        artifact_family=FAMILY_MFT,
        source_path=source_path,
        # The record lives in the volume's master file table.
        artifact_path="/$MFT",
        volume_id=volume_id,
        record_locator=locator,
        # No timestamp: MFT times are file-system metadata, not a user action
        # time. They are preserved in attributes for the investigator.
        timestamp=None,
        summary=f"MFT 엔트리 {entry.frn}: {entry.full_path}",
        attributes={
            "subtype": "mft_entry",
            "mft_segment": entry.segment,
            "mft_sequence": entry.sequence,
            "frn": entry.frn,
            "parent_segment": entry.parent_segment,
            "parent_sequence": entry.parent_sequence,
            "allocated": entry.allocated,
            "is_directory": entry.is_dir,
            "full_path": entry.full_path,
            "file_names": entry.file_names,
            "logical_size": entry.logical_size,
            "allocated_size": entry.allocated_size,
            "resident": entry.resident,
            "data_streams": entry.data_streams,
            "si_created": entry.si_created.isoformat() if entry.si_created else "",
            "si_modified": entry.si_modified.isoformat() if entry.si_modified else "",
            "si_changed": entry.si_changed.isoformat() if entry.si_changed else "",
            "si_accessed": entry.si_accessed.isoformat() if entry.si_accessed else "",
            "fn_created": entry.fn_created.isoformat() if entry.fn_created else "",
            "fn_modified": entry.fn_modified.isoformat() if entry.fn_modified else "",
            "fn_changed": entry.fn_changed.isoformat() if entry.fn_changed else "",
            "fn_accessed": entry.fn_accessed.isoformat() if entry.fn_accessed else "",
            # SI and FN belong to the same MFT family (spec section 16.1).
            "si_fn_same_family": True,
            "volume_id": volume_id,
            "note": note,
        },
    )


def parse_paths(
    volume: NtfsVolume, paths: list[str], source_path: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    """Read MFT entries for a targeted set of paths (never the whole table)."""
    records: list[EvidenceRecord] = []
    errors: list[str] = []
    for path in paths:
        record = volume.get(path)
        if record is None:
            continue
        try:
            entry = read_entry(volume, record, path)
            records.append(entry_to_evidence(entry, source_path, volume.info.identifier))
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="$MFT",
        family=FAMILY_MFT,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5]),
    )


# ===========================================================================
# zone_identifier
# ===========================================================================

"""Zone.Identifier ADS parser (spec section 10.7).

Extracts ZoneId / ReferrerUrl / HostUrl and derives the Claude conversation and
organization UUIDs plus the remote path. The ABSENCE of an ADS is never
evidence that a file had no origin.
"""

ADS_NAME = "Zone.Identifier"

_KV_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$")


@dataclass
class ZoneInfo:
    zone_id: int | None = None
    referrer_url: str = ""
    host_url: str = ""
    conversation_uuid: str | None = None
    organization_uuid: str | None = None
    remote_path: str = ""
    raw_text: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def is_internet_zone(self) -> bool:
        return self.zone_id == 3


def parse_zone_bytes(data: bytes) -> ZoneInfo:
    text = data.decode("utf-8-sig", errors="replace")
    info = ZoneInfo(raw_text=text)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        lk = key.lower()
        if lk == "zoneid":
            try:
                info.zone_id = int(value)
            except ValueError:
                pass
        elif lk == "referrerurl":
            info.referrer_url = value
        elif lk == "hosturl":
            info.host_url = value
        else:
            info.extra[key] = value

    info.conversation_uuid = conversation_from_url(info.referrer_url) or conversation_from_url(
        info.host_url
    )
    info.organization_uuid = organization_from_url(info.host_url) or organization_from_url(
        info.referrer_url
    )
    info.remote_path = _remote_path(info.host_url)
    return info


def _remote_path(host_url: str) -> str:
    """Claude download URLs carry the server-side path in a `path` query param."""
    if not host_url:
        return ""
    try:
        parsed = urlparse(host_url)
    except Exception:
        return ""
    params = parse_qs(parsed.query or "")
    for key in ("path", "file_path", "filename"):
        if key in params and params[key]:
            return unquote(params[key][0])
    return unquote(parsed.path or "")


def zone_to_evidence(
    info: ZoneInfo,
    file_path: str,
    source_path: str,
    volume_id: str,
    record_locator: str = "",
) -> EvidenceRecord:
    locator = record_locator or f"ads={ADS_NAME};file={file_path}"
    payload = {
        "file": file_path,
        "zone_id": info.zone_id,
        "host_url": info.host_url,
        "referrer_url": info.referrer_url,
    }
    from pathlib import PureWindowsPath

    return EvidenceRecord(
        evidence_id=make_evidence_id(FAMILY_ZONE_IDENTIFIER, source_path, locator, payload),
        artifact="Zone.Identifier",
        artifact_family=FAMILY_ZONE_IDENTIFIER,
        source_path=source_path,
        # The ADS itself: <file>:Zone.Identifier inside the image.
        artifact_path=f"{source_path}:{ADS_NAME}" if source_path else "",
        volume_id=volume_id,
        record_locator=locator,
        # An ADS records origin, not a user action time.
        timestamp=None,
        organization_uuid=info.organization_uuid,
        conversation_uuid=info.conversation_uuid,
        summary=(
            f"Zone.Identifier (ZoneId={info.zone_id}): "
            f"{PureWindowsPath(file_path).name or file_path}"
        ),
        attributes={
            "subtype": "zone_identifier",
            "file_path": file_path,
            "file_name": PureWindowsPath(file_path).name,
            "zone_id": info.zone_id,
            "referrer_url": info.referrer_url,
            "host_url": info.host_url,
            "remote_path": info.remote_path,
            "remote_file_name": PureWindowsPath(info.remote_path.replace("/", "\\")).name
            if info.remote_path
            else "",
            "extra": info.extra,
            "volume_id": volume_id,
            # Absence of an ADS proves nothing (spec section 10.7).
            "absence_is_not_evidence": True,
        },
    )


# ===========================================================================
# downloads
# ===========================================================================

"""Downloads folder and History-referenced file collection (spec section 10.8).

Enumerates allocated files under the user's Downloads directory plus any file
named by a History download target/current path, even outside Downloads.
Only Claude-verified files become evidence; file bytes are never exported and
are read only to compare a size-matched candidate with a cached Claude body.
"""

if TYPE_CHECKING:  # pragma: no cover
    from ..analysis.claude_scope import ClaudeScope


@dataclass
class CollectedFile:
    image_path: str
    windows_path: str
    name: str
    size: int | None
    mft_segment: int | None
    mft_sequence: int | None
    zone: ZoneInfo | None
    evidence_ids: list[str]
    volume_id: str = ""
    claude_link_basis: str = ""


def windows_path_for(volume_letter: str, image_path: str) -> str:
    return f"{volume_letter}:" + image_path.replace("/", "\\")


def image_path_for_windows(windows_path: str) -> str:
    """Map C:\\Users\\x\\Downloads\\a.pdf to /Users/x/Downloads/a.pdf."""
    p = PureWindowsPath(str(windows_path or ""))
    parts = [part for part in p.parts if not part.endswith(":\\") and part not in ("\\", "/")]
    if not parts:
        return ""
    return "/" + "/".join(parts)


def collect_files(
    volume: NtfsVolume,
    downloads_dir: str,
    extra_windows_paths: list[str],
    scope: "ClaudeScope",
    volume_letter: str = "C",
) -> tuple[list[CollectedFile], list[EvidenceRecord], ParseStatus]:
    """Collect Claude files only (metadata; no bytes are exported).

    A file qualifies on its exact normalised path matching a Claude History
    download target, a Claude Zone.Identifier, or -- only for files whose size
    equals a cached Claude download body -- byte-identical content. The filename
    alone never qualifies, and no other file's content is ever read.
    """
    records: list[EvidenceRecord] = []
    collected: list[CollectedFile] = []
    errors: list[str] = []
    seen_paths: set[str] = set()

    candidates: list[str] = []
    if volume.exists(downloads_dir):
        for full_path, record in volume.walk(downloads_dir, max_depth=4):
            candidates.append(full_path)
    for win_path in extra_windows_paths:
        image_path = image_path_for_windows(win_path)
        if image_path and volume.exists(image_path):
            candidates.append(image_path)

    if not candidates:
        return (
            collected,
            records,
            ParseStatus(
                artifact="Downloads",
                family=FAMILY_FILESYSTEM_FILE,
                status=ST_NOT_FOUND,
                source_path=downloads_dir,
                message="no candidate files found",
            ),
        )

    for image_path in candidates:
        if image_path in seen_paths:
            continue
        seen_paths.add(image_path)
        record = volume.get(image_path)
        if record is None:
            continue
        try:
            if record.is_dir():
                continue
        except Exception:
            pass

        name = image_path.rsplit("/", 1)[-1]
        if name.lower() == "desktop.ini":
            continue

        # Zone.Identifier first: it is what proves Claude origin for most files.
        zone: ZoneInfo | None = None
        evidence_ids: list[str] = []
        streams = volume.data_streams(record)
        if ADS_NAME in streams:
            fh = volume.open_record(record, ADS_NAME)
            if fh is not None:
                try:
                    zone = parse_zone_bytes(fh.read(65536))
                finally:
                    try:
                        fh.close()
                    except Exception:
                        pass

        size = logical_size(record)
        basis = scope.path_basis(image_path) or scope.zone_basis(zone)
        if not basis:
            if not scope.size_is_candidate(size):
                continue  # ordinary file: never read
            try:
                basis = scope.content_basis(size, lambda: volume.open_record(record))
            except Exception as exc:
                errors.append(f"{image_path}: {type(exc).__name__}: {exc}")
            if not basis:
                continue

        entry = read_entry(volume, record, image_path)
        mft_evidence = entry_to_evidence(
            entry, image_path, volume.info.identifier, note="downloads candidate"
        )
        records.append(mft_evidence)
        evidence_ids.append(mft_evidence.evidence_id)

        win_path = windows_path_for(volume_letter, image_path)
        locator = f"file={image_path};mft={entry.segment}"
        file_evidence = EvidenceRecord(
            evidence_id=make_evidence_id(
                FAMILY_FILESYSTEM_FILE, image_path, locator, {"size": size}
            ),
            artifact="File",
            artifact_family=FAMILY_FILESYSTEM_FILE,
            source_path=image_path,
            record_locator=locator,
            timestamp=None,
            organization_uuid=zone.organization_uuid if zone else None,
            conversation_uuid=zone.conversation_uuid if zone else None,
            summary=f"파일 존재: {name} ({size} bytes)",
            volume_id=volume.info.identifier,
            attributes={
                "subtype": "filesystem_file",
                "file_name": name,
                "image_path": image_path,
                "windows_path": win_path,
                "size": size,
                "mft_segment": entry.segment,
                "mft_sequence": entry.sequence,
                "frn": entry.frn,
                "allocated": entry.allocated,
                "data_streams": streams,
                "has_zone_identifier": zone is not None,
                "claude_link_basis": basis,
                "volume_id": volume.info.identifier,
            },
        )
        records.append(file_evidence)
        evidence_ids.append(file_evidence.evidence_id)

        if zone is not None:
            zone_evidence = zone_to_evidence(
                zone, win_path, image_path, volume.info.identifier,
                record_locator=f"ads=Zone.Identifier;mft={entry.segment}",
            )
            records.append(zone_evidence)
            evidence_ids.append(zone_evidence.evidence_id)

        collected.append(
            CollectedFile(
                image_path=image_path,
                windows_path=win_path,
                name=name,
                size=size,
                mft_segment=entry.segment,
                mft_sequence=entry.sequence,
                zone=zone,
                evidence_ids=evidence_ids,
                volume_id=volume.info.identifier,
                claude_link_basis=basis,
            )
        )

    status = ST_PARSED if not errors else ST_PARTIAL
    return (
        collected,
        records,
        ParseStatus(
            artifact="Downloads",
            family=FAMILY_FILESYSTEM_FILE,
            status=status,
            source_path=downloads_dir,
            record_count=len(collected),
            error_count=len(errors),
            message="; ".join(errors[:5]),
        ),
    )
