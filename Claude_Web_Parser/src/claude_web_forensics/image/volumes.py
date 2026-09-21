"""Partition discovery, BitLocker handling and NTFS access.

AGPL `dissect.volume` / `dissect.fve` / `dissect.ntfs` are confined to this
module (adapter isolation, decision B-1).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ..model.entities import (
    ST_DECRYPTED,
    ST_ENCRYPTED_KEY_MISSING,
    ST_ENCRYPTED_UNSUPPORTED,
)
from .adapters import ImageOpenError

BITLOCKER_SIGNATURE = b"-FVE-FS-"


@dataclass
class VolumeInfo:
    index: int
    offset: int
    size: int
    partition_type: str = ""
    name: str = ""
    filesystem: str = ""           # "ntfs" | "fat" | "bitlocker" | "unknown"
    encryption: str = ""           # "" | "bitlocker"
    encryption_status: str = ""    # decrypted | encrypted_key_missing | encrypted_unsupported
    unlock_method: str = ""        # clear_key | recovery_password | bek | fvek
    volume_serial: str = ""
    cluster_size: int | None = None
    sector_size: int | None = None
    message: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def identifier(self) -> str:
        return f"part{self.index}@{self.offset}"

    @property
    def usable(self) -> bool:
        return self.filesystem == "ntfs"


@dataclass
class KeyMaterial:
    """User-supplied BitLocker key material. Values are never logged or exported."""

    recovery_password: str | None = None
    bek_file: Path | None = None
    fvek: bytes | None = None
    passphrase: str | None = None

    @property
    def present(self) -> bool:
        return any((self.recovery_password, self.bek_file, self.fvek, self.passphrase))


class NtfsVolume:
    """Thin read-only wrapper over one NTFS filesystem inside the image."""

    def __init__(self, info: VolumeInfo, fs: Any) -> None:
        self.info = info
        self._fs = fs

    # -- lookups ---------------------------------------------------------
    def get(self, path: str) -> Any | None:
        try:
            return self._fs.mft.get(path)
        except Exception:
            return None

    def exists(self, path: str) -> bool:
        return self.get(path) is not None

    def listdir(self, path: str) -> dict[str, Any]:
        """Return {name: MftRecord}. Short (8.3) names are filtered out."""
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
        """8.3 aliases duplicate long names; keep one entry per MFT segment."""
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
            # Prefer the longer / non-tilde name.
            best_name = current[0]
            if ("~" in best_name and "~" not in name) or (
                "~" not in name and len(name) > len(best_name)
            ):
                by_segment[segment] = (name, record)
        out = {name: rec for name, rec in by_segment.values()}
        out.update(loose)
        return out

    def open_file(self, path: str, stream_name: str | None = None) -> BinaryIO | None:
        record = self.get(path)
        if record is None:
            return None
        return self.open_record(record, stream_name)

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
        """Named $DATA streams (ADS) on a record, excluding the unnamed default."""
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
        """Yield (full_path, MftRecord) for files under root."""
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
    """Return (filesystem, encryption) by reading the volume boot record."""
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
    """Enumerate MBR/GPT partitions; fall back to treating the image as one volume."""
    volumes: list[VolumeInfo] = []
    try:
        from dissect.volume.disk.disk import Disk  # noqa: PLC0415 - adapter-local

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
                    index=i,
                    offset=offset,
                    size=size,
                    partition_type=str(getattr(part, "type", "") or ""),
                    name=str(getattr(part, "name", "") or ""),
                    filesystem=fs,
                    encryption=enc,
                    attributes={"scheme": type(getattr(disk, "scheme", disk)).__name__},
                )
            )
        return volumes

    # Partition-less image (a bare filesystem dump).
    fs, enc = _probe_filesystem(stream, 0)
    volumes.append(
        VolumeInfo(
            index=0,
            offset=0,
            size=image_size,
            partition_type="none",
            name="whole-image",
            filesystem=fs,
            encryption=enc,
            attributes={"scheme": "none"},
        )
    )
    return volumes


def _partition_stream(stream: BinaryIO, volume: VolumeInfo) -> BinaryIO:
    """A seekable window over one partition, without copying bytes."""
    try:
        from dissect.util.stream import RelativeStream  # noqa: PLC0415

        return RelativeStream(stream, volume.offset, volume.size)
    except Exception:  # pragma: no cover - fallback for older dissect.util
        import io

        class _Window(io.RawIOBase):
            def __init__(self) -> None:
                self._pos = 0

            def readable(self) -> bool:
                return True

            def seekable(self) -> bool:
                return True

            def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
                if whence == io.SEEK_SET:
                    self._pos = offset
                elif whence == io.SEEK_CUR:
                    self._pos += offset
                else:
                    self._pos = volume.size + offset
                return self._pos

            def tell(self) -> int:
                return self._pos

            def read(self, n: int = -1) -> bytes:
                if n is None or n < 0:
                    n = volume.size - self._pos
                n = min(n, max(0, volume.size - self._pos))
                stream.seek(volume.offset + self._pos)
                data = stream.read(n)
                self._pos += len(data)
                return data

        return _Window()  # type: ignore[return-value]


def _unlock_bitlocker(
    part_stream: BinaryIO, volume: VolumeInfo, key_material: KeyMaterial | None
) -> BinaryIO | None:
    """Unlock a BitLocker volume. Never fabricates plaintext (spec section 9)."""
    try:
        from dissect.fve.bde import BDE  # noqa: PLC0415 - adapter-local
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

    # 1) Clear key protector -- key material lives inside the image itself, so
    #    integrity-verified decryption is legitimate (decision B-3).
    if _safe_call(bde, "has_clear_key"):
        try:
            bde.unlock_with_clear_key()
            volume.encryption_status = ST_DECRYPTED
            volume.unlock_method = "clear_key"
            return bde.open()
        except Exception as exc:
            volume.message = f"clear key unlock failed: {type(exc).__name__}: {exc}"

    # 2) Explicitly supplied key material. Values are never written to logs/CSV.
    if key_material and key_material.present:
        attempts = (
            ("fvek", lambda: bde.unlock_with_fvek(key_material.fvek), key_material.fvek),
            (
                "recovery_password",
                lambda: bde.unlock_with_recovery_password(key_material.recovery_password),
                key_material.recovery_password,
            ),
            (
                "bek",
                lambda: bde.unlock_with_bek(open(key_material.bek_file, "rb"))
                if key_material.bek_file
                else None,
                key_material.bek_file,
            ),
            (
                "passphrase",
                lambda: bde.unlock_with_passphrase(key_material.passphrase),
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
    stream: BinaryIO,
    volumes: list[VolumeInfo],
    key_material: KeyMaterial | None = None,
) -> list[NtfsVolume]:
    """Open every readable NTFS filesystem, decrypting BitLocker where possible."""
    try:
        from dissect.ntfs import NTFS  # noqa: PLC0415 - adapter-local
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise ImageOpenError("dissect.ntfs is required (pip install -r requirements.lock)") from exc

    opened: list[NtfsVolume] = []
    for volume in volumes:
        part_stream = _partition_stream(stream, volume)
        fs_stream: BinaryIO | None = part_stream

        if volume.encryption == "bitlocker":
            fs_stream = _unlock_bitlocker(part_stream, volume, key_material)
            if fs_stream is None:
                continue  # status already recorded; not a fatal error

        try:
            fs = NTFS(fs_stream)
        except Exception as exc:
            if volume.filesystem in ("ntfs", "bitlocker"):
                volume.message = volume.message or f"NTFS open failed: {type(exc).__name__}: {exc}"
            continue

        volume.filesystem = "ntfs"
        volume.volume_serial = f"{getattr(fs, 'serial', 0):x}"
        volume.cluster_size = getattr(fs, "cluster_size", None)
        volume.sector_size = getattr(fs, "sector_size", None)
        opened.append(NtfsVolume(volume, fs))

    return opened
