"""Content decoding: HTTP Content-Encoding, strict text/JSON decoding and the."""
from __future__ import annotations

import gzip
import io
import json
import re
import zlib
from dataclasses import dataclass, field
from typing import Any

try:
    import brotli as _brotli
except Exception:  # pragma: no cover - optional
    _brotli = None

try:
    from compression import zstd as _stdlib_zstd  # type: ignore
except Exception:  # pragma: no cover
    _stdlib_zstd = None

try:
    import zstandard as _zstandard
except Exception:  # pragma: no cover - optional
    _zstandard = None

NOT_ENCODED = "NOT_ENCODED"
DECOMPRESSED = "DECOMPRESSED"
DECODER_UNAVAILABLE = "DECODER_UNAVAILABLE"
UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
DECOMPRESSION_ERROR = "DECOMPRESSION_ERROR"
DECODE_LIMITED = "DECODE_LIMITED"

SUCCESS_STATUSES = (NOT_ENCODED, DECOMPRESSED)

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
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                return reader.read()
    raise RuntimeError("no zstd decoder available (install zstandard or use Python 3.14+)")

def _check_bomb(original: int, produced: int) -> bool:
    if produced > MAX_DECODED_BYTES:
        return True
    return original > 0 and produced // max(original, 1) > MAX_RATIO

def decompress_http_body(data: bytes, content_encoding: str | None) -> DecodeResult:
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
                    decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
            elif enc == "br":
                if _brotli is None:
                    return DecodeResult(
                        data=data, status=DECODER_UNAVAILABLE, content_encoding=content_encoding,
                        applied_decoders=applied, missing_decoder="brotli",
                    )
                decoded = _brotli.decompress(decoded)
            elif enc in ("zstd", "zstandard"):
                if _stdlib_zstd is None and _zstandard is None:
                    return DecodeResult(
                        data=data, status=DECODER_UNAVAILABLE, content_encoding=content_encoding,
                        applied_decoders=applied, missing_decoder="zstd",
                    )
                decoded = zstd_decompress(decoded)
            else:
                return DecodeResult(
                    data=data, status=UNSUPPORTED_ENCODING, content_encoding=content_encoding,
                    applied_decoders=applied, unsupported_encoding=enc,
                )
            applied.append(enc)

            if _check_bomb(len(data), len(decoded)):
                return DecodeResult(
                    data=data, status=DECODE_LIMITED, content_encoding=content_encoding,
                    applied_decoders=applied, error=f"decoded size {len(decoded)} exceeds limit",
                    attributes={"decoded_size": len(decoded)},
                )
    except Exception as exc:
        return DecodeResult(
            data=data, status=DECOMPRESSION_ERROR, content_encoding=content_encoding,
            applied_decoders=applied, error=f"{type(exc).__name__}: {exc}",
        )

    return DecodeResult(
        data=decoded, status=DECOMPRESSED, content_encoding=content_encoding, applied_decoders=applied,
    )

def sniff_and_decompress(data: bytes, content_encoding: str | None) -> DecodeResult:
    result = decompress_http_body(data, content_encoding)
    if result.ok and result.status == NOT_ENCODED and not content_encoding:
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return decompress_http_body(data, "zstd")
        if data.startswith(b"\x1f\x8b"):
            return decompress_http_body(data, "gzip")
    return result

PRINTABLE_THRESHOLD = 0.85

_TEXTUAL_TOKENS = ("json", "javascript", "ecmascript", "xml", "html", "x-www-form-urlencoded", "graphql", "svg",)

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

_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"),
    (b"GIF89a", "gif"), (b"BM", "bmp"),
)
_SVG_ROOT = re.compile(rb"^(?:\xef\xbb\xbf)?\s*(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*|<!DOCTYPE[^>]*>\s*)*<svg[\s>]",
                       re.S | re.I)

def image_format(data: bytes) -> str:
    for magic, name in _IMAGE_SIGNATURES:
        if data.startswith(magic):
            return name
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return "svg" if _SVG_ROOT.match(data[:4096]) else ""

ENCRYPTED_KEY_MISSING = "encrypted_key_missing"
NOT_ENCRYPTED = "not_encrypted"

_CHROME_ENCRYPTED_PREFIXES = (b"v10", b"v11", b"v20")

@dataclass
class EncryptionStatus:
    status: str
    scheme: str = ""
    message: str = ""

def classify_chrome_value(blob: bytes | None) -> EncryptionStatus:
    if not blob:
        return EncryptionStatus(NOT_ENCRYPTED)
    for prefix in _CHROME_ENCRYPTED_PREFIXES:
        if blob.startswith(prefix):
            return EncryptionStatus(
                status=ENCRYPTED_KEY_MISSING, scheme=prefix.decode("ascii"), message=(
                    "Chrome OS-bound encrypted value; not decrypted "
                    "(value is not needed for any action verdict)"
                ),
            )
    return EncryptionStatus(NOT_ENCRYPTED)
