"""Content decoding: decompression, text/JSON deserialisation and Chrome value encryption state.

Merged verbatim from: compression.py, serialization.py, encryption.py.
"""
from __future__ import annotations

import gzip
import io
import zlib
from dataclasses import dataclass, field
from typing import Any
import json
import re
from dataclasses import dataclass


# ===========================================================================
# compression
# ===========================================================================

"""HTTP Content-Encoding handling (spec section 9).

zstd is compression, not encryption. Each stage keeps its own status so a
failure is never presented as plaintext. Adapted from
chrome_artifact_diff_v2.py:801-884, with an added decompression-bomb limit that
preserves (never discards) the raw bytes.
"""

try:
    import brotli as _brotli
except Exception:  # pragma: no cover - optional
    _brotli = None

# Python 3.14+ ships zstd in the stdlib; zstandard is the fallback.
try:
    from compression import zstd as _stdlib_zstd  # type: ignore
except Exception:  # pragma: no cover
    _stdlib_zstd = None

try:
    import zstandard as _zstandard
except Exception:  # pragma: no cover - optional
    _zstandard = None

# Status values.
NOT_ENCODED = "NOT_ENCODED"
DECOMPRESSED = "DECOMPRESSED"
DECODER_UNAVAILABLE = "DECODER_UNAVAILABLE"
UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
DECOMPRESSION_ERROR = "DECOMPRESSION_ERROR"
DECODE_LIMITED = "DECODE_LIMITED"

SUCCESS_STATUSES = (NOT_ENCODED, DECOMPRESSED)

# Decompression-bomb guards (spec section 9).
MAX_DECODED_BYTES = 256 * 1024 * 1024
MAX_RATIO = 400


@dataclass
class DecodeResult:
    data: bytes
    status: str
    content_encoding: str | None = None
    applied_decoders: list[str] = field(default_factory=list)
    error: str = ""
    unsupported_encoding: str = ""
    missing_decoder: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in SUCCESS_STATUSES


def zstd_decompress(data: bytes) -> bytes:
    """zstd with a streaming fallback for frames without a content-size header."""
    if _stdlib_zstd is not None:
        try:
            return _stdlib_zstd.decompress(data)
        except Exception:
            try:
                d = _stdlib_zstd.ZstdDecompressor()
                return d.decompress(data)
            except Exception:
                pass
    if _zstandard is not None:
        dctx = _zstandard.ZstdDecompressor()
        try:
            return dctx.decompress(data)
        except Exception:
            # Frame header may omit the decompressed size; the streaming API
            # does not need it.
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                return reader.read()
    raise RuntimeError("no zstd decoder available (install zstandard or use Python 3.14+)")


def _check_bomb(original: int, produced: int) -> bool:
    if produced > MAX_DECODED_BYTES:
        return True
    return original > 0 and produced // max(original, 1) > MAX_RATIO


def decompress_http_body(data: bytes, content_encoding: str | None) -> DecodeResult:
    """Remove Content-Encoding layers. Encodings are undone in reverse order."""
    encodings = []
    if content_encoding:
        encodings = [x.strip().lower() for x in content_encoding.split(",") if x.strip()]

    if not encodings or set(encodings) <= {"identity", ""}:
        return DecodeResult(data=data, status=NOT_ENCODED, content_encoding=content_encoding)

    decoded = data
    applied: list[str] = []
    try:
        for enc in reversed(encodings):
            if enc in ("identity", ""):
                continue
            if enc in ("gzip", "x-gzip"):
                decoded = gzip.decompress(decoded)
            elif enc in ("deflate", "x-deflate"):
                try:
                    decoded = zlib.decompress(decoded)
                except zlib.error:
                    # Some servers send raw DEFLATE rather than zlib-wrapped data.
                    decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
            elif enc == "br":
                if _brotli is None:
                    return DecodeResult(
                        data=data,
                        status=DECODER_UNAVAILABLE,
                        content_encoding=content_encoding,
                        applied_decoders=applied,
                        missing_decoder="brotli",
                    )
                decoded = _brotli.decompress(decoded)
            elif enc in ("zstd", "zstandard"):
                if _stdlib_zstd is None and _zstandard is None:
                    return DecodeResult(
                        data=data,
                        status=DECODER_UNAVAILABLE,
                        content_encoding=content_encoding,
                        applied_decoders=applied,
                        missing_decoder="zstd",
                    )
                decoded = zstd_decompress(decoded)
            else:
                return DecodeResult(
                    data=data,
                    status=UNSUPPORTED_ENCODING,
                    content_encoding=content_encoding,
                    applied_decoders=applied,
                    unsupported_encoding=enc,
                )
            applied.append(enc)

            if _check_bomb(len(data), len(decoded)):
                # Raw bytes are still preserved by the caller; we only refuse to
                # carry the expanded payload forward.
                return DecodeResult(
                    data=data,
                    status=DECODE_LIMITED,
                    content_encoding=content_encoding,
                    applied_decoders=applied,
                    error=f"decoded size {len(decoded)} exceeds limit",
                    attributes={"decoded_size": len(decoded)},
                )
    except Exception as exc:
        return DecodeResult(
            data=data,
            status=DECOMPRESSION_ERROR,
            content_encoding=content_encoding,
            applied_decoders=applied,
            error=f"{type(exc).__name__}: {exc}",
        )

    return DecodeResult(
        data=decoded,
        status=DECOMPRESSED,
        content_encoding=content_encoding,
        applied_decoders=applied,
    )


def sniff_and_decompress(data: bytes, content_encoding: str | None) -> DecodeResult:
    """Decode by header, falling back to magic-byte detection when it is absent."""
    result = decompress_http_body(data, content_encoding)
    if result.ok and result.status == NOT_ENCODED and not content_encoding:
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return decompress_http_body(data, "zstd")
        if data.startswith(b"\x1f\x8b"):
            return decompress_http_body(data, "gzip")
    return result


def available_decoders() -> dict[str, bool]:
    return {
        "gzip": True,
        "deflate": True,
        "br": _brotli is not None,
        "zstd": _stdlib_zstd is not None or _zstandard is not None,
    }


# ===========================================================================
# serialization
# ===========================================================================

"""Text / JSON classification after Content-Encoding removal.

Binary payloads are never rendered through a latin-1 fallback: that turns
intact evidence into apparent garbage (chrome_artifact_diff_v2.py:887-926).
"""

PRINTABLE_THRESHOLD = 0.85

_TEXTUAL_TOKENS = (
    "json",
    "javascript",
    "ecmascript",
    "xml",
    "html",
    "x-www-form-urlencoded",
    "graphql",
    "svg",
)

# Anti-XSSI prefixes used by web APIs before the JSON body.
_XSSI_PREFIXES = (")]}'", ")]}", "while(1);", "for(;;);", "{} &&")


def parse_charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    m = re.search(r"charset\s*=\s*[\"']?([^;\"']+)", content_type, flags=re.I)
    return m.group(1).strip() if m else None


def is_textual_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    c = content_type.lower().split(";", 1)[0].strip()
    if c.startswith("text/"):
        return True
    return any(token in c for token in _TEXTUAL_TOKENS)


def decode_text_strict(data: bytes, content_type: str | None = None) -> tuple[str | None, str]:
    """Return (text, encoding_or_reason). Only plausible text is decoded."""
    if not data:
        return "", "empty"

    if content_type and not is_textual_content_type(content_type):
        return None, "binary/non-text MIME"

    candidates: list[str] = []
    charset = parse_charset(content_type)
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"])

    for enc in dict.fromkeys(candidates):
        try:
            text = data.decode(enc)
        except Exception:
            continue
        if not text:
            return "", enc
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if printable / max(len(text), 1) >= PRINTABLE_THRESHOLD:
            return text, enc

    return None, "binary/unreadable"


def try_parse_json(text: str) -> Any | None:
    """Parse JSON, tolerating anti-XSSI prefixes."""
    if not text:
        return None
    candidates = [text.strip()]
    stripped = text.lstrip()
    for prefix in _XSSI_PREFIXES:
        if stripped.startswith(prefix):
            candidates.append(stripped[len(prefix):].lstrip("\r\n "))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None


def sniff_mime(data: bytes, fallback: str = "") -> str:
    """Signature-based MIME detection for recovered files."""
    if not data:
        return fallback
    signatures = (
        (b"%PDF-", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"BM", "image/bmp"),
        (b"RIFF", "image/webp"),
        (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"\xd0\xcf\x11\xe0", "application/vnd.ms-office"),
    )
    for magic, mime in signatures:
        if data.startswith(magic):
            if mime == "application/zip":
                head = data[:4096]
                if b"word/" in head:
                    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                if b"xl/" in head:
                    return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                if b"ppt/" in head:
                    return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            return mime

    head = data[:512].lstrip()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in data[:2048]):
        return "image/svg+xml"
    if head.startswith(b"<!DOCTYPE html") or head.startswith(b"<html"):
        return "text/html"
    if head[:1] in (b"{", b"["):
        text, _ = decode_text_strict(data[:8192], "application/json")
        if text is not None and try_parse_json(text) is not None:
            return "application/json"
    return fallback


def extension_for_mime(mime: str) -> str:
    table = {
        "application/pdf": ".pdf",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/svg+xml": ".svg",
        "image/bmp": ".bmp",
        "image/webp": ".webp",
        "application/zip": ".zip",
        "application/json": ".json",
        "text/html": ".html",
        "text/plain": ".txt",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    }
    return table.get((mime or "").split(";")[0].strip().lower(), "")


# ===========================================================================
# encryption
# ===========================================================================

"""Encryption status vocabulary (spec section 9).

This module deliberately performs no decryption of application-level data. Its
purpose is to keep "compressed" and "encrypted" apart and to force an explicit,
honest status whenever real ciphertext is encountered. Guessing, bypassing or
fabricating plaintext is prohibited.
"""

DECRYPTED = "decrypted"
ENCRYPTED_KEY_MISSING = "encrypted_key_missing"
ENCRYPTED_UNSUPPORTED = "encrypted_unsupported"
NOT_ENCRYPTED = "not_encrypted"

# Chrome v10/v20 prefixes on OS-protected values (cookie values, etc.).
_CHROME_ENCRYPTED_PREFIXES = (b"v10", b"v11", b"v20")


@dataclass
class EncryptionStatus:
    status: str
    scheme: str = ""
    message: str = ""

    @property
    def is_plaintext(self) -> bool:
        return self.status == NOT_ENCRYPTED


def classify_chrome_value(blob: bytes | None) -> EncryptionStatus:
    """Classify a Chrome-protected blob without attempting to decrypt it.

    Cookie values are not required for any action verdict, so the tool records
    host/name/path/time/flags plus a hash of the value instead of the plaintext
    (spec section 9). No DPAPI/AES unwrapping is attempted.
    """
    if not blob:
        return EncryptionStatus(NOT_ENCRYPTED)
    for prefix in _CHROME_ENCRYPTED_PREFIXES:
        if blob.startswith(prefix):
            return EncryptionStatus(
                status=ENCRYPTED_KEY_MISSING,
                scheme=prefix.decode("ascii"),
                message=(
                    "Chrome OS-bound encrypted value; not decrypted "
                    "(value is not needed for any action verdict)"
                ),
            )
    return EncryptionStatus(NOT_ENCRYPTED)
