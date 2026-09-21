"""
HTTP 디스크 캐시 리더 — 대화 본문이 실제로 남는 곳.

확인된 사실:
  대화 본문은 IndexedDB가 아니라 **HTTP 캐시**에 있다.
  키는 .../chat_conversations/<convUuid>?tree=True 이고 본문은 **zstd** 압축이다.
  그래서 로그아웃해도, 앱을 지워도 대화가 남는다.

두 갈래로 읽는다:
  1) 정식 경로 — index + data_0~3 (블록파일)을 읽어 **키와 본문을 함께** 얻는다
  2) 대체 경로 — 인덱스가 잠겼거나 깨졌을 때 f_* 파일만 훑어 **본문이라도** 건진다
                 키를 모르니 대화 UUID는 본문 안에서 찾아낸다

압축 판별은 헤더가 아니라 **매직바이트**로 한다. 헤더는 캐시에 안 남는 경우가 있다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from ..errors import DecodeError
from ..provenance import ArtifactRef, Storage
from ..timeutil import TimeSource, from_iso, to_utc_iso
from .base import Record, Source

# 압축 매직바이트
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_BROTLI_HINT = b"\xce\xb2\xcf\x81"   # brotli는 확정 매직이 없어 시도로 판별

MAX_DECOMPRESSED = 256 * 1024 * 1024      # 압축 폭탄 방지

# 대화 응답인지 알아보는 지문.
# '"sender"' 같은 흔한 낱말만 보면 JS 번들이 줄줄이 걸린다(실제로 그랬다).
# 대화 API 응답에만 나오는 키를 쓴다.
CONV_MARKERS = (b'"chat_messages"', b'"current_leaf_message_uuid"')


def decompress(data: bytes) -> tuple[bytes, str]:
    """
    매직바이트로 압축 방식을 판별해 해제한다.
    돌려주는 값: (해제된 바이트, 사용한 방식)
    """
    if data[:4] == MAGIC_ZSTD:
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise DecodeError("zstandard 패키지가 없어 zstd 본문을 해제할 수 없다") from exc
        try:
            return zstd.ZstdDecompressor().decompress(data, max_output_size=MAX_DECOMPRESSED), "zstd"
        except Exception:
            # 스트리밍 모드로 재시도 — 프레임 크기가 안 적힌 경우가 있다
            try:
                import zstandard as zstd
                with zstd.ZstdDecompressor().stream_reader(data) as r:
                    return r.read(MAX_DECOMPRESSED), "zstd-stream"
            except Exception as exc:
                raise DecodeError(f"zstd 해제 실패: {exc}") from exc

    if data[:2] == MAGIC_GZIP:
        import gzip
        try:
            return gzip.decompress(data), "gzip"
        except Exception as exc:
            raise DecodeError(f"gzip 해제 실패: {exc}") from exc

    try:
        import brotli
        out = brotli.decompress(data)
        if out:
            return out, "brotli"
    except Exception:
        pass

    return data, "none"


def looks_like_conversation(raw: bytes) -> bool:
    return any(m in raw for m in CONV_MARKERS)


# 대화 본문이 남을 수 있는 브라우저 저장소. 파싱 대상이 아니라 '알림' 대상이다.
BROWSER_DIRS = (
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "AppData/Roaming/Mozilla/Firefox/Profiles",
)
# 브라우저 쪽은 '있는지 없는지'만 보므로 조금 느슨해도 된다.
# 위의 CONV_MARKERS(엄격한 지문)를 덮어쓰지 않도록 이름을 따로 쓴다.
BROWSER_MARKERS = (b"chat_messages", b'"sender":"human"', b'"sender": "human"')


def scan_browser_conversations(user_root, errs, limit: int = 400) -> int:
    """
    브라우저 캐시에 claude.ai 대화 본문이 남아 있는지만 본다.

    본문을 꺼내지는 않는다 — 이 파서의 대상이 아니기 때문이다.
    몇 건이 어디에 있는지 알려 주는 것까지가 여기의 일이다.
    """
    if user_root is None:
        return 0
    found = 0
    where: dict[str, int] = {}
    checked = 0
    for rel in BROWSER_DIRS:
        base = user_root.joinpath(*rel.split("/"))
        try:
            if not base.is_dir():
                continue
        except Exception:
            continue
        try:
            files = [f for f in base.rglob("f_*")] + [f for f in base.rglob("*.ldb")]
        except Exception:
            continue
        for f in files:
            if checked >= limit:
                break
            checked += 1
            try:
                data = f.read_bytes()
            except Exception:
                continue
            if not data:
                continue
            try:
                raw, _ = decompress(data)
            except Exception:
                raw = data
            if any(m in raw for m in BROWSER_MARKERS):
                found += 1
                where[rel] = where.get(rel, 0) + 1
    if found:
        detail = ", ".join(f"{k} {v}건" for k, v in sorted(where.items()))
        errs.add("warning", "WEB_CONVERSATION_FOUND", "parse", "cache",
                 f"브라우저 저장소에서 대화 본문 신호 {found}건 발견 ({detail}). "
                 f"이 파서의 대상은 Claude Desktop 이므로 본문을 복원하지 않았다 — "
                 f"Claude Web 담당 도구로 따로 분석할 것")
    return found


class CacheSource(Source):
    name = "cache"
    display = "HTTP 디스크 캐시"

    def locate(self) -> list[Path]:
        d = self.root / "Cache" / "Cache_Data"
        return [d] if d.is_dir() else []

    # ── 메인 ────────────────────────────────────────────────────────────
    def read(self) -> list[Record]:
        dirs = self.locate()
        if not dirs:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name,
                          "Cache_Data 폴더가 없다")
            return []
        cache_dir = dirs[0]

        real_dir = self.realize("Cache/Cache_Data", "Cache_Data")
        indexed = self._read_blockfile(real_dir, cache_dir) if real_dir else False
        if not indexed:
            self.errs.add("warning", "CACHE_INDEX_UNAVAILABLE", "parse", self.name,
                          "캐시 인덱스를 열지 못해 f_* 파일만 훑는다 — 요청 URL 없이 본문만 복원된다",
                          str(cache_dir))
            self._read_orphans(cache_dir)
        return self.records

    # ── 1) 정식 경로: 인덱스 + 블록파일 ─────────────────────────────────
    def _read_blockfile(self, real_dir: Path, cache_dir) -> bool:
        """
        real_dir  외부 리더에 넘길 실제 경로(이미지면 작업 사본)
        cache_dir 근거에 적을 증거 안의 경로
        """
        try:
            from ccl_chromium_reader import ccl_chromium_cache as ccl
        except ImportError:
            self.errs.add("warning", "DEP_MISSING", "parse", self.name,
                          "ccl_chromium_reader가 없어 인덱스 기반 파싱을 건너뛴다")
            return False

        try:
            cache = ccl.guess_cache_class(real_dir)(real_dir)
        except PermissionError:
            self.errs.add("warning", "ARTIFACT_LOCKED", "parse", self.name,
                          "캐시 인덱스가 점유 중이다 — f_* 직접 훑기로 넘어간다",
                          str(cache_dir))
            return False
        except Exception as exc:
            # 인덱스를 못 읽어도 f_* 훑기로 본문을 건진다. 복구 가능한 상황이므로
            # 오류가 아니라 경고로 남긴다 — 오류로 두면 종료 코드가 실패가 된다.
            self.errs.add("warning", "CACHE_INDEX_UNREADABLE", "parse", self.name,
                          f"캐시 인덱스를 해석하지 못했다 ({type(exc).__name__}: "
                          f"{str(exc) or '메시지 없음'}) — f_* 직접 훑기로 넘어간다",
                          str(cache_dir))
            return False

        count = 0
        try:
            for key in cache.keys():
                with self.errs.guard("decode", self.name, str(cache_dir)):
                    count += self._handle_key(cache, key, cache_dir)
        finally:
            try:
                cache.close()
            except Exception:
                pass

        self.errs.add("info", "CACHE_INDEX_OK", "parse", self.name,
                      f"인덱스 기반 파싱 완료 — 대화 응답 {count}건")
        return True

    def _handle_key(self, cache, key, cache_dir: Path) -> int:
        key_str = str(getattr(key, "url", key) or key)
        if "chat_conversations" not in key_str:
            return 0
        chunks = cache.get_cachefile(key)
        if not chunks:
            return 0
        body = b"".join(chunks) if isinstance(chunks, list) else bytes(chunks)
        if not body:
            return 0

        raw, method = decompress(body)
        if not looks_like_conversation(raw):
            return 0

        ref = ArtifactRef(
            path=str(cache_dir),
            storage=Storage.CACHE.value,
            size=len(body),
            locator=key_str,
            note=f"압축 {method}, 해제 후 {len(raw)}B",
        )
        self._emit_conversation(raw, ref, key_str)
        return 1

    # ── 2) 대체 경로: f_* 고아 파일 ─────────────────────────────────────
    def _read_orphans(self, cache_dir: Path) -> None:
        files = sorted(cache_dir.glob("f_*"))
        hit = miss = meta_only = 0
        for f in files:
            data = self.safe_bytes(f)
            if not data:
                miss += 1
                continue
            self.manifest.add_file(f)
            try:
                deleted = f.stat().in_use is False
            except Exception:
                deleted = False
            try:
                raw, method = decompress(data)
            except Exception as exc:
                if deleted:
                    # 삭제 후 클러스터가 재할당되면 내용이 남의 것으로 바뀐다.
                    # 복구 실패가 아니라 '메타데이터만 복구'로 기록해야 정확하다.
                    self.emit(Record(
                        kind="deleted_cache_entry", source=self.name, key=f.name,
                        value={"reason": "클러스터 재할당으로 본문 복원 불가",
                               "size": len(data)},
                        ref=ArtifactRef.from_file(f, Storage.CACHE, size=len(data),
                                                  with_hash=False,
                                                  note="삭제 엔트리 · 본문 소실"),
                    ))
                    meta_only += 1
                else:
                    self.errs.from_exception(exc, "decode", self.name, str(f))
                continue
            with self.errs.guard("decode", self.name, str(f)):
                if not looks_like_conversation(raw):
                    continue
                ref = ArtifactRef.from_file(
                    f, Storage.CACHE, offset=0, size=len(data),
                    locator=None, note=f"고아 f_* · 압축 {method} · 해제 {len(raw)}B",
                )
                self._emit_conversation(raw, ref, None)
                hit += 1
        ads = self._read_named_streams(files)
        self.errs.add("info", "CACHE_ORPHAN_SCAN", "parse", self.name,
                      f"f_* {len(files)}개 중 본문 복원 {hit}건, "
                      f"메타데이터만 {meta_only}건, 읽기 실패 {miss}건"
                      + (f", 대체 데이터 스트림에서 {ads}건" if ads else ""))

    def _read_named_streams(self, files: list) -> int:
        """
        캐시 파일에 딸린 대체 데이터 스트림(ADS)도 본다.

        정상 동작으로 여기에 대화가 들어가는 일은 없다. 하지만 숨기려는 쪽은
        여기를 쓴다. 이름만 보고 넘기면 본문을 통째로 놓친다.
        """
        found = 0
        for f in files:
            try:
                names = f.stat().streams
            except (OSError, AttributeError):
                continue
            for nm in names:
                with self.errs.guard("decode", self.name, f"{f}:{nm}"):
                    data = f.read_stream(nm)
                    if not data:
                        continue
                    try:
                        raw, method = decompress(data)
                    except Exception:
                        raw, method = data, "없음"
                    if not looks_like_conversation(raw):
                        continue
                    ref = ArtifactRef.from_file(
                        f, Storage.CACHE, offset=0, size=len(data),
                        locator=f":{nm}",
                        note=f"대체 데이터 스트림 '{nm}' · 압축 {method}",
                        with_hash=False)
                    self._emit_conversation(raw, ref, f"{f.name}:{nm}")
                    found += 1
                    self.errs.add("warning", "ADS_CONTENT", "parse", self.name,
                                  f"대체 데이터 스트림에서 대화 본문이 나왔다 "
                                  f"({f.name}:{nm}) — 숨김 시도일 수 있다",
                                  str(f))
        return found

    # ── 본문 → 레코드 ───────────────────────────────────────────────────
    def _emit_conversation(self, raw: bytes, ref: ArtifactRef, key: str | None) -> None:
        try:
            obj: Any = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            # 캐시 경계에서 잘렸거나, 말도 안 되게 깊이 중첩된 본문이다.
            # 다른 파일 분석에는 지장이 없으므로 오류가 아니라 경고로 남긴다.
            why = ("중첩이 너무 깊다" if isinstance(exc, RecursionError)
                   else "잘린 응답으로 보인다")
            self.errs.add("warning", "ARTIFACT_CORRUPT", "decode", self.name,
                          f"JSON 파싱 실패 — {why}", ref.path)
            self.emit(Record(kind="conversation_fragment", source=self.name,
                             key=key, value=raw[:4096].decode("utf-8", "replace"), ref=ref))
            return

        for conv in self._iter_conversations(obj):
            uuid = conv.get("uuid")
            created = from_iso(conv.get("created_at") or "")
            updated = from_iso(conv.get("updated_at") or "")
            msgs = conv.get("chat_messages") or []

            self.emit(Record(
                kind="conversation",
                source=self.name,
                key=key or (f"conversation:{uuid}" if uuid else None),
                value={
                    "uuid": uuid,
                    "name": conv.get("name"),
                    "summary": conv.get("summary"),
                    "model": conv.get("model"),
                    "is_starred": conv.get("is_starred"),
                    "current_leaf_message_uuid": conv.get("current_leaf_message_uuid"),
                    "message_count": len(msgs),
                    "settings": conv.get("settings"),
                },
                ts_utc=to_utc_iso(updated or created),
                time_source=TimeSource.APIRESPONSE.value,
                ref=ref,
                meta={"created_at": to_utc_iso(created), "updated_at": to_utc_iso(updated)},
            ))

            for m in msgs:
                self._emit_message(m, uuid, ref, key)

    @staticmethod
    def _iter_conversations(obj: Any) -> Iterator[dict]:
        """응답이 단일 객체일 수도, 목록일 수도 있다. 둘 다 받아준다."""
        if isinstance(obj, dict):
            if "chat_messages" in obj or "uuid" in obj:
                yield obj
            for v in obj.values():
                if isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict) and ("chat_messages" in it or "uuid" in it):
                            yield it
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, dict):
                    yield it

    def _emit_message(self, m: dict, conv_uuid: str | None,
                      ref: ArtifactRef, key: str | None) -> None:
        if not isinstance(m, dict):
            return
        text = m.get("text")
        if text is not None and not isinstance(text, str):
            text = str(text)
        if not text:
            parts: list[str] = []
            content = m.get("content")
            for c in (content if isinstance(content, list) else []):
                if isinstance(c, dict) and c.get("type") == "text" and c.get("text"):
                    t = c["text"]
                    parts.append(t if isinstance(t, str) else str(t))
            text = "\n".join(parts)
        ts = from_iso(m.get("created_at") or "")
        self.emit(Record(
            kind="message",
            source=self.name,
            key=key,
            value={
                "uuid": m.get("uuid"),
                "conversation_uuid": conv_uuid,
                "sender": m.get("sender"),
                "index": m.get("index"),
                "parent_message_uuid": m.get("parent_message_uuid"),
                "text": text,
                "attachments": m.get("attachments") or [],
                "files": m.get("files") or [],
            },
            ts_utc=to_utc_iso(ts),
            time_source=TimeSource.APIRESPONSE.value,
            ref=ref,
        ))
