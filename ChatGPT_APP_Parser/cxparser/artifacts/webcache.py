"""채팅창(Chromium web pane) HTTP 캐시 — Chrome Blockfile Cache 저수준 Reader.

경로: %LOCALAPPDATA%\\Packages\\OpenAI.Codex_…\\LocalCache\\Roaming\\Codex\\web\\Codex\\Default\\Cache\\Cache_Data\\
      (index + data_0~3 + f_XXXXXX). 앱을 삭제하면 패키지째 사라진다 (8월 분석 보고서 계통 B).
읽는 방식은 팀 ChatGPT Web 파서(chatgpt_parser/artifacts/cache.py, 2026-09-15 검증)의 Blockfile Reader 를 옮겨 온 것이다.
그쪽은 Source 객체·Record 모델에 묶여 있어 여기서는 "파일 이름 → bytes" 함수 하나만 받는 형태로 줄였다.
  index: header 368 B 뒤 table_len 개의 CacheAddr → EntryStore.next 체인
  CacheAddr: bit31 사용 중, bit28-30 file type (0 external f_, 1 36 B, 2 256 B, 3 1 KB, 4 4 KB, 6 104 B, 7 48 B),
             bit24-25 block 수-1, bit16-23 data_N, bit0-15 시작 block
  EntryStore: +4 next, +20 state, +24 creation_time(webkit µs), +32 key_len, +36 long_key, +40 data_size[4], +56 data_addr[4], +96 key
  stream 0 = HTTP 응답 정보, stream 1 = 응답 본문. 본문 인코딩 br(brotli)·gzip·zstd 는 풀 수 있으면 푼다.
index 에 없는 entry 는 data_* block 탐색(carving)으로 보완한다. 이 모듈은 URL·시각·본문만 돌려주고 행위 판정은 하지 않는다.
"""

import gzip
import json
import struct
from datetime import datetime, timedelta, timezone

try:
    import brotli
except ImportError:  # pragma: no cover
    brotli = None
try:
    from compression import zstd as _zstd          # Python 3.14+
    _zstd_decompress = _zstd.decompress
except ImportError:  # pragma: no cover
    try:
        import zstandard
        _zstd_decompress = lambda b: zstandard.ZstdDecompressor().decompressobj().decompress(b)  # noqa: E731
    except ImportError:
        _zstd_decompress = None

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
INDEX_HEADER = 368
BLOCK_HEADER = 8192
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096, 6: 104, 7: 48}
DATA_FILES = ("data_0", "data_1", "data_2", "data_3")
MAX_KEY = 4096
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def webkit_us(v):
    return (_EPOCH + timedelta(microseconds=v)).isoformat(timespec="microseconds").replace("+00:00", "Z") if v else None


def addr_file(address):
    if not address & 0x80000000:
        return None
    t = (address >> 28) & 7
    return "f_%06x" % (address & 0x0FFFFFFF) if t == 0 else ("data_%d" % ((address >> 16) & 0xFF) if t in BLOCK_SIZES else None)


class BlockfileCache:
    def __init__(self, read_file):
        """read_file(name) -> bytes. 없는 파일은 예외를 던져야 한다."""
        self._read, self._files = read_file, {}

    def file(self, name):
        if name not in self._files:
            self._files[name] = self._read(name)
        return self._files[name]

    def read(self, address, size=None):
        if not address & 0x80000000:
            raise ValueError("cache address not initialized")
        t = (address >> 28) & 7
        if t == 0:
            data = self.file("f_%06x" % (address & 0x0FFFFFFF))
        else:
            bs = BLOCK_SIZES.get(t)
            if bs is None:
                raise ValueError("unknown block file type")
            blob = self.file("data_%d" % ((address >> 16) & 0xFF))
            if blob[:4] != struct.pack("<I", BLOCK_MAGIC):
                raise ValueError("block file magic mismatch")
            start = BLOCK_HEADER + (address & 0xFFFF) * bs
            data = blob[start:start + (((address >> 24) & 3) + 1) * bs]
        if size is not None:
            if size > len(data):
                raise ValueError("stream shorter than recorded size")
            data = data[:size]
        return data

    # -- 열거 -----------------------------------------------------------------------------------
    def index_entries(self, index):
        table_len = struct.unpack_from("<i", index, 28)[0]
        if table_len <= 0 or INDEX_HEADER + 4 * table_len > len(index):
            raise ValueError("index table out of range")
        out, unreadable, seen = [], 0, set()
        for address in struct.unpack_from("<%dI" % table_len, index, INDEX_HEADER):
            while address and address not in seen:
                seen.add(address)
                try:
                    raw = self.read(address)
                    nxt, = struct.unpack_from("<I", raw, 4)
                    state, created, key_len, long_key = struct.unpack_from("<iQiI", raw, 20)
                    sizes, addrs = struct.unpack_from("<4i", raw, 40), struct.unpack_from("<4I", raw, 56)
                    if key_len < 0:
                        raise ValueError("negative key length")
                    key = self.read(long_key, key_len) if long_key else raw[96:96 + key_len]
                    if len(key) != key_len:
                        raise ValueError("truncated key")
                except (ValueError, OSError, struct.error, KeyError):
                    unreadable += 1
                    break
                out.append((address, state, created, key.decode("latin-1"), sizes, addrs, None))
                address = nxt
        return out, unreadable

    def _entry_at(self, blob, start, file_number, bs):
        try:
            state, created, key_len, long_key = struct.unpack_from("<iQiI", blob, start + 20)
            sizes, addrs = struct.unpack_from("<4i", blob, start + 40), struct.unpack_from("<4I", blob, start + 56)
        except struct.error:
            return None
        if not 0 <= state <= 3 or created <= 0 or not 0 < key_len <= MAX_KEY:
            return None
        try:
            kb = self.read(long_key, key_len) if long_key else blob[start + 96:start + 96 + key_len]
            key = kb.decode("ascii")
        except (ValueError, OSError, KeyError, UnicodeDecodeError):
            return None
        if len(kb) != key_len or "://" not in key or not key.isprintable():
            return None
        for size, address in zip(sizes, addrs):
            if size < 0 or (size and not address):
                return None
            try:
                if address and len(self.read(address, size)) != size:
                    return None
            except (ValueError, OSError, KeyError):
                return None
        blocks = min(4, max(1, -(-(96 + (0 if long_key else key_len)) // bs)))
        address = 0x80000000 | ((file_number + 1) << 28) | ((blocks - 1) << 24) | (file_number << 16) | (start - BLOCK_HEADER) // bs
        return (address, state, created, key, sizes, addrs, "%s@offset=%d" % (DATA_FILES[file_number], start))

    def carved_entries(self):
        out = []
        for n, name in enumerate(DATA_FILES):
            bs = BLOCK_SIZES[n + 1]
            if bs < 96:
                continue
            try:
                blob = self.file(name)
            except Exception:  # noqa: BLE001
                continue
            if blob[:4] != struct.pack("<I", BLOCK_MAGIC):
                continue
            for start in range(BLOCK_HEADER, len(blob) - 96 + 1, bs):
                e = self._entry_at(blob, start, n, bs)
                if e is not None:
                    out.append(e)
        return out

    def entries(self, index):
        """index 열거 + carving 보완. 같은 (key, stream0, stream1) 은 한 번."""
        found, unreadable = self.index_entries(index)
        seen = {(e[3], e[5][0], e[5][1]) for e in found}
        carved = 0
        for e in self.carved_entries():
            k = (e[3], e[5][0], e[5][1])
            if k not in seen:
                seen.add(k); found.append(e); carved += 1
        return found, unreadable, carved

    # -- 응답 --------------------------------------------------------------------------------------
    @staticmethod
    def response_headers(info):
        start = info.find(b"HTTP/")
        if start < 0:
            return None, {}
        end = info.find(b"\x00\x00", start)
        lines = info[start:end if end >= 0 else len(info)].split(b"\x00")
        f = lines[0].split()
        status = int(f[1]) if len(f) > 1 and f[1].isdigit() else None
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if sep:
                headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
        return status, headers

    def response(self, entry):
        """entry → dict(url, created_utc, status, content_type, encoding, body(bytes|None), decoded(bytes|None), warnings)."""
        address, state, created, key, sizes, addrs, carved = entry
        url = key.rsplit(" ", 1)[-1]                       # key 는 "1/0/_dk_… <url>" 형태일 수 있다 → 마지막 토큰이 URL
        out = {"url": url, "key": key, "created_utc": webkit_us(created), "entry_address": "0x%08x" % address, "carved": carved,
               "status": None, "content_type": None, "encoding": None, "body": None, "decoded": None,
               "body_file": addr_file(addrs[1]) if sizes[1] > 0 else None, "warnings": []}
        try:
            out["status"], headers = self.response_headers(self.read(addrs[0], sizes[0]) if sizes[0] > 0 else b"")
            body = self.read(addrs[1], sizes[1]) if sizes[1] > 0 else b""
        except (ValueError, OSError, KeyError):
            out["warnings"].append("BODY_UNREADABLE")
            return out
        out["content_type"], enc = headers.get("content-type"), (headers.get("content-encoding") or "identity").strip().lower()
        out["encoding"], out["body"] = enc, body
        try:
            if enc == "identity":
                out["decoded"] = body
            elif enc == "br" and brotli is not None:
                out["decoded"] = brotli.decompress(body)
            elif enc == "gzip":
                out["decoded"] = gzip.decompress(body)
            elif enc == "zstd" and _zstd_decompress is not None:
                out["decoded"] = _zstd_decompress(body)
            else:
                out["warnings"].append("ENCODING_NOT_AVAILABLE:%s" % enc)
        except Exception as exc:  # noqa: BLE001
            out["warnings"].append("DECOMPRESS_FAILED:%s:%s" % (enc, type(exc).__name__))
        return out


def decode_json(resp):
    if resp.get("decoded") is None:
        return None
    try:
        return json.loads(resp["decoded"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
