"""Read-only image adapters: the shared interface plus the EWF and raw/dd readers.

Merged verbatim from: base.py, ewf.py, raw.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, BinaryIO, Protocol
import re
from pathlib import Path
from typing import BinaryIO
import io


# ===========================================================================
# base
# ===========================================================================

"""Read-only image adapter interface and shared value objects.

All third-party forensic readers are isolated behind this module and its two
implementations (ewf.py, raw.py). AGPL-licensed `dissect` packages are imported
only inside this adapter layer -- see THIRD_PARTY_NOTICES.md.
"""

class ImageOpenError(RuntimeError):
    """The evidence image itself cannot be opened -- a fatal condition."""


@dataclass
class SegmentInfo:
    path: str
    size: int
    exists: bool = True
    order: int = 0
    note: str = ""


@dataclass
class ImageInfo:
    """Image provenance: path, type, sizes and segments (spec section 4.2/4.3)."""

    path: str
    image_type: str  # "ewf" | "raw"
    logical_size: int
    container_size: int
    segments: list[SegmentInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


class ImageAdapter(Protocol):
    """Minimal read-only contract the rest of the tool depends on."""

    info: ImageInfo

    def stream(self) -> BinaryIO:
        """Return a seekable, read-only stream over the logical media."""

    def close(self) -> None:
        ...


# ===========================================================================
# ewf
# ===========================================================================

"""EWF/E01 read-only adapter.

Backed by `dissect.evidence` (pure Python). pytsk3 is deliberately NOT used for
EWF: the published wheels are built without libewf, so
`pytsk3.Img_Info(path, TSK_IMG_TYPE_EWF_EWF)` fails with "Unsupported image
type (64)" and auto-detect silently mis-reads the container as RAW, reporting
the compressed file size as the logical size. Verified in
docs/design_review.md section 4.1.
"""

# EWF segment extensions run E01..E99 then EAA..ZZZ; we support the common
# numeric form plus the L01 logical variant name for discovery/reporting.
_SEGMENT_RE = re.compile(r"^\.([ELels])(\d{2}|[A-Za-z]{2})$")


def looks_like_ewf(path: Path) -> bool:
    if _SEGMENT_RE.match(path.suffix) is None:
        return False
    try:
        with path.open("rb") as fh:
            magic = fh.read(8)
    except OSError:
        return False
    # EWF1 "EVF\x09\x0d\x0a\xff\x00", EWF2 "EVF2\x0d\x0a\x81\x00", LVF variant.
    return magic.startswith(b"EVF") or magic.startswith(b"LVF") or magic.startswith(b"EVF2")


def discover_ewf_segments(first: Path) -> tuple[list[SegmentInfo], list[str]]:
    """Find sibling segments in order and report gaps instead of skipping silently."""
    warnings: list[str] = []
    m = _SEGMENT_RE.match(first.suffix)
    if m is None:
        return [SegmentInfo(path=str(first), size=first.stat().st_size, order=0)], warnings

    prefix = first.with_suffix("")
    letter, tail = m.group(1), m.group(2)
    segments: list[SegmentInfo] = []

    if tail.isdigit():
        # Numeric run: .E01, .E02, ... stop at the first gap but keep looking a
        # little further so a missing middle segment is reported, not ignored.
        index = int(tail)
        misses = 0
        order = 0
        while index <= 99 and misses < 3:
            candidate = Path(f"{prefix}.{letter}{index:02d}")
            if candidate.exists():
                if misses:
                    warnings.append(
                        f"segment gap before {candidate.name}: "
                        f"{misses} expected segment(s) missing"
                    )
                    misses = 0
                segments.append(
                    SegmentInfo(path=str(candidate), size=candidate.stat().st_size, order=order)
                )
                order += 1
            elif segments:
                misses += 1
                segments.append(
                    SegmentInfo(
                        path=str(candidate),
                        size=0,
                        exists=False,
                        order=order,
                        note="missing",
                    )
                )
                order += 1
            index += 1
        # Trim trailing placeholders that were only probes.
        while segments and not segments[-1].exists:
            segments.pop()
    else:
        segments.append(SegmentInfo(path=str(first), size=first.stat().st_size, order=0))

    if not segments:
        segments = [SegmentInfo(path=str(first), size=first.stat().st_size, order=0)]

    missing = [s for s in segments if not s.exists]
    if missing:
        warnings.append(
            "missing EWF segment(s): " + ", ".join(Path(s.path).name for s in missing)
        )
    return segments, warnings


class EwfImage:
    """Read-only EWF container. Never opened for write; never auto-mounted."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise ImageOpenError(f"image not found: {self.path}")

        try:
            from dissect.evidence import EWF  # noqa: PLC0415 - adapter-local import
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ImageOpenError(
                "dissect.evidence is required for E01/EWF input (pip install -r requirements.lock)"
            ) from exc

        segments, warnings = discover_ewf_segments(self.path)
        present = [Path(s.path) for s in segments if s.exists]

        self._handles: list[BinaryIO] = []
        try:
            self._handles = [p.open("rb") for p in present]
            self._ewf = EWF(self._handles if len(self._handles) > 1 else self._handles[0])
            self._stream = self._ewf.open()
        except Exception as exc:
            self.close()
            raise ImageOpenError(f"cannot open EWF image {self.path}: {type(exc).__name__}: {exc}") from exc

        container_size = sum(s.size for s in segments if s.exists)
        self.info = ImageInfo(
            path=str(self.path),
            image_type="ewf",
            logical_size=int(self._stream.size),
            container_size=container_size,
            segments=segments,
            warnings=warnings,
            attributes={
                "reader": "dissect.evidence",
                "segment_count": len(present),
            },
        )

    def stream(self) -> BinaryIO:
        return self._stream

    def close(self) -> None:
        for fh in self._handles:
            try:
                fh.close()
            except Exception:  # pragma: no cover - defensive
                pass
        self._handles = []


# ===========================================================================
# raw
# ===========================================================================

"""raw/dd read-only adapter.

A dd image is a flat byte stream, so this needs no third-party reader. Split
raw sets (.001/.002, .dd.001, ...) are concatenated logically.

NOTE: this path is validated against synthetic fixtures only. No real dd
acquisition was supplied for this project; see README "not_tested" entries.
"""

_RAW_SUFFIXES = {".dd", ".raw", ".img", ".bin", ".000", ".001"}
_SPLIT_RE = re.compile(r"^\.(\d{3})$")


def looks_like_raw(path: Path) -> bool:
    return path.suffix.lower() in _RAW_SUFFIXES or _SPLIT_RE.match(path.suffix) is not None


def discover_raw_segments(first: Path) -> tuple[list[SegmentInfo], list[str]]:
    warnings: list[str] = []
    m = _SPLIT_RE.match(first.suffix)
    if m is None:
        return [SegmentInfo(path=str(first), size=first.stat().st_size, order=0)], warnings

    prefix = first.with_suffix("")
    index = int(m.group(1))
    segments: list[SegmentInfo] = []
    order = 0
    while True:
        candidate = Path(f"{prefix}.{index:03d}")
        if not candidate.exists():
            break
        segments.append(SegmentInfo(path=str(candidate), size=candidate.stat().st_size, order=order))
        order += 1
        index += 1
    if not segments:
        segments = [SegmentInfo(path=str(first), size=first.stat().st_size, order=0)]
    return segments, warnings


class _ConcatStream(io.RawIOBase):
    """Seekable read-only view over an ordered list of raw segments."""

    def __init__(self, paths: list[Path]) -> None:
        super().__init__()
        self._files: list[BinaryIO] = [p.open("rb") for p in paths]
        self._sizes = [p.stat().st_size for p in paths]
        self._offsets: list[int] = []
        running = 0
        for size in self._sizes:
            self._offsets.append(running)
            running += size
        self.size = running
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self.size + offset
        else:  # pragma: no cover - defensive
            raise ValueError(f"invalid whence: {whence}")
        self._pos = max(0, self._pos)
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self.size - self._pos
        out = bytearray()
        remaining = min(n, max(0, self.size - self._pos))
        while remaining > 0:
            idx = self._segment_for(self._pos)
            if idx is None:
                break
            seg_start = self._offsets[idx]
            seg_size = self._sizes[idx]
            inner = self._pos - seg_start
            take = min(remaining, seg_size - inner)
            fh = self._files[idx]
            fh.seek(inner)
            chunk = fh.read(take)
            if not chunk:
                break
            out.extend(chunk)
            self._pos += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def _segment_for(self, pos: int) -> int | None:
        for i, start in enumerate(self._offsets):
            if start <= pos < start + self._sizes[i]:
                return i
        return None

    def close(self) -> None:
        for fh in self._files:
            try:
                fh.close()
            except Exception:  # pragma: no cover
                pass
        super().close()


class RawImage:
    """Read-only raw/dd container."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise ImageOpenError(f"image not found: {self.path}")

        segments, warnings = discover_raw_segments(self.path)
        present = [Path(s.path) for s in segments if s.exists]
        try:
            self._stream = _ConcatStream(present)
        except Exception as exc:
            raise ImageOpenError(
                f"cannot open raw image {self.path}: {type(exc).__name__}: {exc}"
            ) from exc

        self.info = ImageInfo(
            path=str(self.path),
            image_type="raw",
            logical_size=self._stream.size,
            container_size=sum(s.size for s in segments if s.exists),
            segments=segments,
            warnings=warnings,
            attributes={"reader": "builtin-raw", "segment_count": len(present)},
        )

    def stream(self) -> BinaryIO:
        return self._stream  # type: ignore[return-value]

    def close(self) -> None:
        try:
            self._stream.close()
        except Exception:  # pragma: no cover
            pass
