"""Partition discovery, BitLocker handling and NTFS access."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ..model.entities import (ST_DECRYPTED, ST_ENCRYPTED_KEY_MISSING, ST_ENCRYPTED_UNSUPPORTED,)
from .adapters import ImageOpenError

BITLOCKER_SIGNATURE = b"-FVE-FS-"

@dataclass
class VolumeInfo:
    index: int
    offset: int
    size: int
    name: str = ""
    filesystem: str = ""
    encryption: str = ""
    encryption_status: str = ""
    unlock_method: str = ""
    cluster_size: int | None = None
    sector_size: int | None = None
    message: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def identifier(self) -> str:
        return f"part{self.index}@{self.offset}"

@dataclass
class KeyMaterial:
    recovery_password: str | None = None
    bek_file: Path | None = None
    fvek: bytes | None = None
    passphrase: str | None = None

    @property
    def present(self) -> bool:
        return any((self.recovery_password, self.bek_file, self.fvek, self.passphrase))

class NtfsVolume:
    def __init__(self, info: VolumeInfo, fs: Any) -> None:
        self.info = info
        self._fs = fs

    def get(self, path: str) -> Any | None:
        try:
            return self._fs.mft.get(path)
        except Exception:
            return None

    def exists(self, path: str) -> bool:
        return self.get(path) is not None

    def listdir(self, path: str) -> dict[str, Any]:
        record = self.get(path)
        if record is None:
            return {}
        out: dict[str, Any] = {}
        try:
            entries = record.listdir()
        except Exception:
            return {}
        for name, entry in entries.items():
            if name in (".", ".."):
                continue
            try:
                out[name] = entry.dereference()
            except Exception:
                continue
        return self._drop_short_names(out)

    @staticmethod
    def _drop_short_names(entries: dict[str, Any]) -> dict[str, Any]:
        by_segment: dict[int, tuple[str, Any]] = {}
        loose: dict[str, Any] = {}
        for name, record in entries.items():
            segment = getattr(record, "segment", None)
            if segment is None:
                loose[name] = record
                continue
            current = by_segment.get(segment)
            if current is None:
                by_segment[segment] = (name, record)
                continue

            best_name = current[0]
            if ("~" in best_name and "~" not in name) or ("~" not in name and len(name) > len(best_name)):
                by_segment[segment] = (name, record)
        out = {name: rec for name, rec in by_segment.values()}
        out.update(loose)
        return out

    @staticmethod
    def open_record(record: Any, stream_name: str | None = None) -> BinaryIO | None:
        try:
            if stream_name:
                return record.open(name=stream_name)
            return record.open()
        except Exception:
            return None

    @staticmethod
    def data_streams(record: Any) -> list[str]:
        names: list[str] = []
        try:
            attributes = record.attributes
        except Exception:
            return names
        try:
            data_attrs = attributes[0x80]
        except Exception:
            return names
        for attr in data_attrs:
            name = getattr(attr, "name", "") or ""
            if name:
                names.append(name)
        return names

    def walk(self, root: str, max_depth: int = 12) -> Iterator[tuple[str, Any]]:
        stack: list[tuple[str, int]] = [(root.rstrip("/"), 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth:
                continue
            for name, record in self.listdir(current).items():
                full = f"{current}/{name}"
                try:
                    is_dir = record.is_dir()
                except Exception:
                    is_dir = False
                if is_dir:
                    stack.append((full, depth + 1))
                else:
                    yield full, record

def _probe_filesystem(stream: BinaryIO, offset: int) -> tuple[str, str]:
    try:
        stream.seek(offset)
        head = stream.read(512)
    except Exception:
        return "unknown", ""
    if len(head) < 16:
        return "unknown", ""
    if head[3:11] == BITLOCKER_SIGNATURE:
        return "bitlocker", "bitlocker"
    if head[3:11] == b"NTFS    ":
        return "ntfs", ""
    if head[3:11].startswith(b"MSDOS") or head[54:62].startswith(b"FAT"):
        return "fat", ""
    return "unknown", ""

def discover_volumes(stream: BinaryIO, image_size: int) -> list[VolumeInfo]:
    volumes: list[VolumeInfo] = []
    try:
        from dissect.volume.disk.disk import Disk

        disk = Disk(stream)
        partitions = list(disk.partitions)
    except Exception:
        partitions = []

    if partitions:
        for i, part in enumerate(partitions):
            offset = int(getattr(part, "offset", 0) or 0)
            size = int(getattr(part, "size", 0) or 0)
            fs, enc = _probe_filesystem(stream, offset)
            volumes.append(
                VolumeInfo(
                    index=i, offset=offset, size=size,
                    name=str(getattr(part, "name", "") or ""), filesystem=fs, encryption=enc,
                    attributes={"scheme": type(getattr(disk, "scheme", disk)).__name__},
                )
            )
        return volumes

    fs, enc = _probe_filesystem(stream, 0)
    volumes.append(
        VolumeInfo(
            index=0, offset=0, size=image_size, name="whole-image", filesystem=fs,
            encryption=enc, attributes={"scheme": "none"},
        )
    )
    return volumes

def _partition_stream(stream: BinaryIO, volume: VolumeInfo) -> BinaryIO:
    from dissect.util.stream import RelativeStream

    return RelativeStream(stream, volume.offset, volume.size)

def _unlock_bitlocker(
    part_stream: BinaryIO, volume: VolumeInfo, key_material: KeyMaterial | None
) -> BinaryIO | None:
    try:
        from dissect.fve.bde import BDE
    except ImportError:
        volume.encryption_status = ST_ENCRYPTED_UNSUPPORTED
        volume.message = "dissect.fve not installed; BitLocker volume cannot be read"
        return None

    try:
        bde = BDE(part_stream)
    except Exception as exc:
        volume.encryption_status = ST_ENCRYPTED_UNSUPPORTED
        volume.message = f"BitLocker metadata unreadable: {type(exc).__name__}: {exc}"
        return None

    volume.attributes["bitlocker_version"] = getattr(bde, "version", None)
    volume.attributes["has_clear_key"] = bool(_safe_call(bde, "has_clear_key"))
    volume.attributes["has_recovery_password"] = bool(_safe_call(bde, "has_recovery_password"))
    volume.attributes["has_bek"] = bool(_safe_call(bde, "has_bek"))
    volume.attributes["has_passphrase"] = bool(_safe_call(bde, "has_passphrase"))

    if _safe_call(bde, "has_clear_key"):
        try:
            bde.unlock_with_clear_key()
            volume.encryption_status = ST_DECRYPTED
            volume.unlock_method = "clear_key"
            return bde.open()
        except Exception as exc:
            volume.message = f"clear key unlock failed: {type(exc).__name__}: {exc}"

    if key_material and key_material.present:
        attempts = (
            ("fvek", lambda: bde.unlock_with_fvek(key_material.fvek), key_material.fvek), (
                "recovery_password",
                lambda: bde.unlock_with_recovery_password(key_material.recovery_password),
                key_material.recovery_password,
            ),
            (
                "bek", lambda: bde.unlock_with_bek(open(key_material.bek_file, "rb"))
                if key_material.bek_file
                else None, key_material.bek_file,
            ),
            (
                "passphrase", lambda: bde.unlock_with_passphrase(key_material.passphrase),
                key_material.passphrase,
            ),
        )
        for method, call, value in attempts:
            if not value:
                continue
            try:
                call()
                volume.encryption_status = ST_DECRYPTED
                volume.unlock_method = method
                return bde.open()
            except Exception as exc:
                volume.message = f"{method} unlock failed: {type(exc).__name__}"
                continue

    volume.encryption_status = ST_ENCRYPTED_KEY_MISSING
    if not volume.message:
        volume.message = "BitLocker volume: no usable key protector (supply --key-material)"
    return None

def _safe_call(obj: Any, name: str) -> Any:
    try:
        attr = getattr(obj, name)
    except Exception:
        return None
    try:
        return attr() if callable(attr) else attr
    except Exception:
        return None

def open_ntfs_volumes(
    stream: BinaryIO, volumes: list[VolumeInfo], key_material: KeyMaterial | None = None,
) -> list[NtfsVolume]:
    try:
        from dissect.ntfs import NTFS
    except ImportError as exc:
        raise ImageOpenError("dissect.ntfs is required (pip install -r requirements.lock)") from exc

    opened: list[NtfsVolume] = []
    for volume in volumes:
        part_stream = _partition_stream(stream, volume)
        fs_stream: BinaryIO | None = part_stream

        if volume.encryption == "bitlocker":
            fs_stream = _unlock_bitlocker(part_stream, volume, key_material)
            if fs_stream is None:
                continue

        try:
            fs = NTFS(fs_stream)
        except Exception as exc:
            if volume.filesystem in ("ntfs", "bitlocker"):
                volume.message = volume.message or f"NTFS open failed: {type(exc).__name__}: {exc}"
            continue

        volume.filesystem = "ntfs"
        volume.cluster_size = getattr(fs, "cluster_size", None)
        volume.sector_size = getattr(fs, "sector_size", None)
        opened.append(NtfsVolume(volume, fs))

    return opened

class _DirRecord:
    """Host file standing in for an MFT record: no segment/header/attributes, so MFT-derived fields stay empty."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def is_dir(self) -> bool:
        return self.path.is_dir()

    def size(self) -> int:
        return self.path.stat().st_size

    def open(self, name: str | None = None) -> BinaryIO:
        return open(f"{self.path}:{name}" if name else self.path, "rb")

class DirectoryVolume(NtfsVolume):
    """A copied/mounted volume tree (``<root>/Users/...``) exposed through the NtfsVolume interface."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        super().__init__(
            VolumeInfo(index=0, offset=0, size=0, name=str(self.root),
                       filesystem="directory"), fs=None,
        )

    def get(self, path: str) -> _DirRecord | None:
        host = self.root.joinpath(*path.strip("/").split("/")) if path.strip("/") else self.root
        return _DirRecord(host) if host.exists() else None

    def listdir(self, path: str) -> dict[str, Any]:
        record = self.get(path)
        try:
            return {p.name: _DirRecord(p) for p in record.path.iterdir()} if record else {}
        except OSError:
            return {}

    @staticmethod
    def data_streams(record: Any) -> list[str]:
        try:  # ponytail: only Zone.Identifier is ever consulted; enumerate all ADS via FindFirstStreamW if needed
            with record.open("Zone.Identifier"):
                return ["Zone.Identifier"]
        except OSError:
            return []
