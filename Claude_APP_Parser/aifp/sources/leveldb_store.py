"""
IndexedDB / Local Storage 리더 — 이중 인코딩 스캔.

여기서 가장 중요한 규칙 하나:
  **UTF-8과 UTF-16LE로 항상 동시에 찾는다.**

`chat-draft` 같은 키는 IndexedDB 안에 UTF-16LE로만 존재하고 UTF-8로는 한 번도
나타나지 않는 경우가 있다. UTF-8로만 검색하면 **입력 초안이 통째로 안 보인다.**

LevelDB 정식 파서를 쓰지 않고 원시 스캔을 하는 이유:
  - 삭제 표시(tombstone)된 레코드와 압축(compaction) 전 .log의 잔존분까지 걸린다
  - 외부 LevelDB 바인딩 없이 순수 파이썬으로 동작한다 (조사 PC에 설치 부담 없음)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..provenance import ArtifactRef, Storage
from ..timeutil import TimeSource, from_iso, from_unix, to_utc_iso
from .base import Record, Source

# 찾을 마커. (마커, 레코드 종류, 설명)
MARKERS: tuple[tuple[str, str, str], ...] = (
    ("chorus-unified-composer", "draft_key", "입력 초안 저장소 키"),
    ("store:chat-draft:", "draft_key", "대화별 초안 키"),
    ("chat-draft", "draft_marker", "초안 마커"),
    ("keyval-store", "idb_store", "react-query 영속 캐시 저장소"),
    ("lastKnownAccountUuid", "account_marker", "마지막 로그인 계정"),
    ("analytics_queue", "analytics", "이벤트 큐(모델 변경·임시 채팅)"),
    ("attachment", "attachment_marker", "첨부 관련 키"),
    ("conversation", "conversation_marker", "대화 관련 키"),
    ("is_temporary", "temp_chat", "임시 채팅 플래그"),
    ("model_selected", "model_change", "모델 변경 이벤트"),
)

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
EPOCH_MS_RE = re.compile(r"\b(1[6-9]\d{11})\b")          # 2022~2033년대 밀리초
PRINTABLE_MIN = 4


def _plausible_ratio(s: str) -> float:
    """
    이 문자열이 '사람이 쓴 글'로 보이는 비율.

    정렬이 한 바이트 어긋난 채 UTF-16LE로 읽으면 글자가 나오긴 하는데
    한자·기호가 뒤섞인 쓰레기가 된다. 그걸 걸러내려고 점수를 매긴다.
    """
    if not s:
        return 0.0
    good = 0
    for ch in s:
        o = ord(ch)
        if 0x20 <= o <= 0x7E:                      # ASCII 출력 가능
            good += 1
        elif 0xAC00 <= o <= 0xD7A3:                # 한글 완성형
            good += 1
        elif 0x3131 <= o <= 0x318E:                # 한글 자모
            good += 1
        elif o in (0x0A, 0x0D, 0x09):              # 개행·탭
            good += 1
        elif ch in "·…—’‘“”":                      # 자주 쓰는 문장부호
            good += 1
    return good / len(s)


def utf16le_strings(data: bytes, min_len: int = PRINTABLE_MIN,
                    align: int = 0) -> Iterator[tuple[int, str]]:
    """
    UTF-16LE 문자열 추출.

    한글은 2바이트 코드유닛이라 ASCII 전용 추출기로는 전혀 안 걸린다.
    align으로 짝수/홀수 시작을 모두 시도한다 — LevelDB는 레코드 앞에 가변길이
    헤더가 붙어서 문자열 시작이 홀수 오프셋인 경우가 흔하다.
    """
    out: list[int] = []
    start = 0
    i = align
    n = len(data) - 1
    while i < n:
        cp = data[i] | (data[i + 1] << 8)
        # 출력 가능한 BMP 문자만 (제어문자·서로게이트 제외)
        if (0x20 <= cp <= 0xD7FF) or (0xE000 <= cp <= 0xFFFD):
            if not out:
                start = i
            out.append(cp)
            i += 2
            continue
        if len(out) >= min_len:
            yield start, "".join(chr(c) for c in out)
        out = []
        i += 2
    if len(out) >= min_len:
        yield start, "".join(chr(c) for c in out)




class _LevelDbBase(Source):
    """IndexedDB와 Local Storage가 형식이 같아 로직을 공유한다."""

    storage_kind = Storage.INDEXEDDB
    subdir: tuple[str, ...] = ()

    def locate(self) -> list[Path]:
        d = self.root.joinpath(*self.subdir)
        if not d.is_dir():
            return []
        return sorted(p for p in d.iterdir()
                      if p.is_file() and (p.suffix in (".ldb", ".log") or p.name == "CURRENT"))

    def read(self) -> list[Record]:
        files = self.locate()
        if not files:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name,
                          f"{'/'.join(self.subdir)} 없음")
            return []

        total_u8 = total_u16 = 0
        for f in files:
            data = self.safe_bytes(f)
            if data is None:
                continue
            self.manifest.add_file(f)
            with self.errs.guard("parse", self.name, str(f)):
                u8, u16 = self._scan_file(f, data)
                total_u8 += u8
                total_u16 += u16
            # 마커만 세고 끝내면 정작 입력하던 문장이 빠진다.
            # 초안은 타이핑 과정 자체가 증거이므로 본문까지 건져 낸다.
            with self.errs.guard("parse", self.name, str(f)):
                self._emit_drafts(f, data)
            with self.errs.guard("parse", self.name, str(f)):
                self._emit_opened(f, data)

        drafts = sum(1 for r in self.records if r.kind == "draft_text")
        if drafts >= self.DRAFT_CAP:
            # 말없이 자르면 조사관은 초안이 그만큼뿐이었다고 오해한다
            self.errs.add("warning", "DRAFT_CAPPED", "parse", self.name,
                          f"초안이 파일당 상한({self.DRAFT_CAP}건)에 걸렸다 — "
                          f"원본을 직접 확인할 것")
        self.errs.add("info", "DUAL_ENCODING_SCAN", "parse", self.name,
                      f"이중 인코딩 스캔 완료 — UTF-8 {total_u8}건 / UTF-16LE {total_u16}건 검출"
                      + (f", 초안 본문 {drafts}건" if drafts else ""))
        return self.records

    # ── 스캔 ────────────────────────────────────────────────────────────
    def _scan_file(self, path: Path, data: bytes) -> tuple[int, int]:
        n_u8 = n_u16 = 0
        for marker, kind, desc in MARKERS:
            b8 = marker.encode("utf-8")
            b16 = marker.encode("utf-16-le")
            for enc, needle in (("utf-8", b8), ("utf-16-le", b16)):
                off = data.find(needle)
                hits = 0
                while off != -1:
                    hits += 1
                    if hits <= 50:          # 같은 마커 폭주 방지
                        self._emit_marker(path, data, off, marker, kind, desc, enc)
                    off = data.find(needle, off + 1)
                if enc == "utf-8":
                    n_u8 += hits
                else:
                    n_u16 += hits
                if hits:
                    self.emit(Record(
                        kind="marker_count", source=self.name,
                        key=marker,
                        value={"encoding": enc, "count": hits, "description": desc},
                        ref=ArtifactRef.from_file(path, self.storage_kind,
                                                  locator=f"{marker}[{enc}]", with_hash=False),
                    ))
        return n_u8, n_u16

    def _emit_marker(self, path: Path, data: bytes, off: int, marker: str,
                     kind: str, desc: str, enc: str) -> None:
        window = data[max(0, off - 256): off + 1024]
        uuids = list(dict.fromkeys(UUID_RE.findall(
            window.decode("utf-8", "ignore") + window.decode("utf-16-le", "ignore"))))
        ts = None
        m = EPOCH_MS_RE.search(window.decode("utf-8", "ignore"))
        if m:
            ts = to_utc_iso(from_unix(int(m.group(1))))
        self.emit(Record(
            kind=kind, source=self.name, key=marker,
            value={"encoding": enc, "description": desc, "uuids": uuids[:5]},
            ts_utc=ts,
            time_source=TimeSource.APPLOG.value if ts else None,
            ref=ArtifactRef.from_file(path, self.storage_kind, offset=off,
                                      locator=f"{marker}[{enc}]", with_hash=False),
        ))

    DRAFT_CAP = 200          # 한 파일에서 뽑을 초안 최대 개수
    OPEN_CAP = 50            # 한 파일에서 뽑을 열람 기록 최대 개수

    def _emit_opened(self, path: Path, data: bytes) -> None:
        """
        대화 열람 시각(lastOpenedAt)을 원시 스캔으로도 건진다.

        구조 파싱(ccl_chromium_reader)이 성공하면 거기서 나오지만, 실제 이미지에서는
        잠김·버전 차이로 실패하는 일이 잦다. 그때 '대화 열람' 판정이 통째로 사라진다.
        키 이름 주변에서 밀리초 시각과 대화 UUID 를 함께 찾으면 같은 사실을 건질 수 있다.
        """
        found = 0
        seen: set[tuple] = set()      # (대화, 시각) — 같은 사실을 여러 번 싣지 않는다
        capped = False
        for needle in (b"lastOpenedAt", "lastOpenedAt".encode("utf-16-le")):
            pos = data.find(needle)
            while pos != -1:
                if found >= self.OPEN_CAP:
                    capped = True
                    break
                window = data[max(0, pos - 512): pos + 512]
                text = window.decode("utf-8", "replace")
                text16 = window.decode("utf-16-le", "replace")
                ms = EPOCH_MS_RE.search(text) or EPOCH_MS_RE.search(text16)
                uid = UUID_RE.search(text) or UUID_RE.search(text16)
                mark = (uid.group(0) if uid else None,
                        ms.group(1) if ms else None)
                if ms and mark not in seen:
                    seen.add(mark)
                    self.emit(Record(
                        kind="conversation_opened", source=self.name,
                        key=uid.group(0) if uid else None,
                        value={"conversation_uuid": uid.group(0) if uid else None,
                               "source": "원시 스캔",
                               "last_opened_ms": int(ms.group(1))},
                        ts_utc=to_utc_iso(from_unix(int(ms.group(1)) / 1000)),
                        time_source=TimeSource.APPLOG.value,
                        ref=ArtifactRef.from_file(path, self.storage_kind,
                                                  offset=pos,
                                                  locator="lastOpenedAt",
                                                  with_hash=False)))
                    found += 1
                pos = data.find(needle, pos + 1)
        if capped:
            self.errs.add("warning", "OPENED_CAPPED", "parse", self.name,
                          f"열람 기록이 파일당 상한({self.OPEN_CAP}건)에 걸렸다 — "
                          f"원본을 직접 확인할 것")
        if found:
            self.errs.add("info", "OPENED_RAW", "parse", self.name,
                          f"원시 스캔에서 대화 열람 기록 {found}건")

    def _emit_drafts(self, path: Path, data: bytes) -> None:
        """
        입력 초안 스냅샷 복원.
        약 2초 간격으로 쌓이기 때문에 **타이핑 과정 자체**가 남는다.
        "직접 입력했는가, 그냥 열어봤는가"를 가르는 결정적 지표다.
        """
        anchors = [a.encode("utf-16-le") for a in
                   ("chorus-unified-composer", "store:chat-draft:")]
        # 파일 시각을 대체 시각으로 쓴다. 초안 자체에는 시각이 없다.
        try:
            import datetime as _dt
            fallback_ts = to_utc_iso(_dt.datetime.fromtimestamp(
                path.stat().st_mtime, _dt.timezone.utc))
        except OSError:
            fallback_ts = None

        seen: set[str] = set()
        for anchor in anchors:
            pos = data.find(anchor)
            while pos != -1 and len(seen) < self.DRAFT_CAP:
                chunk = data[pos: pos + 8192]
                # 짝수·홀수 정렬을 모두 시도한다. 하나만 보면 글자가 깨진다.
                for align in (0, 1):
                    for off, s in utf16le_strings(chunk, min_len=6, align=align):
                        s = s.strip()
                        if len(s) < 6 or s in seen:
                            continue
                        if s.startswith(("store:", "chorus-", "keyval", "http", "blob:")):
                            continue
                        if UUID_RE.fullmatch(s):
                            continue
                        # 정렬이 어긋나면 한자·기호 범벅이 된다 → 점수로 거른다
                        if _plausible_ratio(s) < 0.85:
                            continue
                        seen.add(s)
                        self.emit(Record(
                            kind="draft_text", source=self.name,
                            key=anchor.decode("utf-16-le"),
                            value={"text": s, "encoding": "utf-16-le",
                                   "plausibility": round(_plausible_ratio(s), 2)},
                            ts_utc=fallback_ts,
                            time_source=TimeSource.MFT.value if fallback_ts else None,
                            ref=ArtifactRef.from_file(
                                path, self.storage_kind, offset=pos + off,
                                locator="chat-draft", with_hash=False,
                                note="입력 초안 스냅샷 — 시각은 파일 수정 시각(대체)"),
                        ))
                pos = data.find(anchor, pos + 1)


class IndexedDbSource(_LevelDbBase):
    """
    IndexedDB 리더.

    두 단계로 읽는다.
      1) **구조 파싱** — 정식 IndexedDB 리더로 오브젝트 스토어를 열어 값을 그대로 꺼낸다.
         claude-conversation-store 의 trees/meta 에 대화 전문과 열람 시각이 들어 있다.
         여기서 나오는 lastOpenedAt 은 앱이 직접 찍은 시각이라 파일 시각보다 훨씬 믿을 만하다.
      2) **원시 스캔** — 구조 파싱으로는 안 나오는 것들을 훑는다.
         삭제 표시된 레코드, 압축 전 .log 잔존분, 마커 출현 빈도.
         UTF-8/UTF-16LE를 동시에 본다.

    1이 실패해도 2는 돌아간다. 그게 이 구조의 이유다.
    """
    name = "indexeddb"
    display = "IndexedDB"
    storage_kind = Storage.INDEXEDDB
    subdir = ("IndexedDB", "https_claude.ai_0.indexeddb.leveldb")

    def read(self) -> list[Record]:
        with self.errs.guard("parse", self.name):
            self._read_structured()
        super().read()          # 원시 스캔은 항상 추가로 돌린다
        return self.records

    # ── 1) 구조 파싱 ────────────────────────────────────────────────────
    def _read_structured(self) -> None:
        db_dir = self.root.joinpath(*self.subdir)          # 근거에 적을 증거 경로
        if not db_dir.is_dir():
            return
        real_db = self.realize("IndexedDB/https_claude.ai_0.indexeddb.leveldb",
                               "indexeddb_leveldb")
        real_blob = self.realize("IndexedDB/https_claude.ai_0.indexeddb.blob",
                                 "indexeddb_blob")
        if real_db is None:
            self.errs.add("warning", "EXPORT_FAILED", "parse", self.name,
                          "IndexedDB 작업 사본을 만들지 못해 구조 파싱을 건너뛴다")
            return
        try:
            from ccl_chromium_reader import ccl_chromium_indexeddb as ccl_idb
        except ImportError:
            self.errs.add("warning", "DEP_MISSING", "parse", self.name,
                          "ccl_chromium_reader가 없어 구조 파싱을 건너뛰고 원시 스캔만 한다")
            return

        try:
            wrapped = ccl_idb.WrappedIndexDB(real_db, real_blob)
        except Exception as exc:
            # 구조 파싱이 실패해도 원시 스캔 결과는 남는다 — 복구 가능한 상황이다
            self.errs.add("warning", "IDB_STRUCTURED_FAILED", "parse", self.name,
                          f"구조 파싱을 하지 못했다 ({type(exc).__name__}: "
                          f"{str(exc) or '메시지 없음'}) — 원시 스캔 결과만 쓴다",
                          str(db_dir))
            return

        ref = ArtifactRef(path=str(db_dir), storage=self.storage_kind.value,
                          locator="IndexedDB", note="구조 파싱")
        total = 0
        for dbid in list(wrapped.database_ids):
            try:
                db = wrapped[dbid.dbid_no]
                store_names = list(db.object_store_names)
            except Exception as exc:
                # 스토어 하나를 못 읽어도 나머지는 계속 본다 — 복구 가능한 상황이다
                self.errs.add("warning", "IDB_STORE_FAILED", "parse", self.name,
                              f"오브젝트 스토어를 열지 못했다 ({type(exc).__name__}: "
                              f"{str(exc) or '메시지 없음'}) — 이 스토어만 건너뛴다",
                              str(db_dir))
                continue

            for sname in store_names:
                # 스토어 하나가 깨져도 나머지는 계속 읽는다
                try:
                    records = list(db[sname].iterate_records())
                except Exception as exc:
                    self.errs.add("warning", "ARTIFACT_CORRUPT", "parse", self.name,
                                  f"{dbid.name}/{sname} 읽기 실패 ({type(exc).__name__}) — "
                                  f"이 스토어만 건너뛴다", str(db_dir))
                    continue

                for rec in records:
                    total += 1
                    with self.errs.guard("decode", self.name, str(db_dir)):
                        self._emit_idb_record(dbid.name, sname, rec, ref)

        self.errs.add("info", "IDB_STRUCTURED", "parse", self.name,
                      f"구조 파싱 완료 — 오브젝트 스토어 레코드 {total}건")

    def _emit_idb_record(self, db_name: str, store: str, rec, ref: ArtifactRef) -> None:
        val = rec.value
        if not isinstance(val, dict):
            return
        locator = f"{db_name}/{store}/{rec.key}"
        my_ref = ArtifactRef(path=ref.path, storage=self.storage_kind.value,
                             locator=locator, note="IndexedDB 구조 파싱")

        conv = val.get("conversationUuid")
        account = val.get("accountUuid")
        org = val.get("orgUuid")

        # 대화 열람 이력 — 앱이 직접 찍은 시각
        if store == "meta" and val.get("lastOpenedAt"):
            self.emit(Record(
                kind="conversation_opened", source=self.name, key=conv,
                value={"conversation_uuid": conv, "account_uuid": account,
                       "org_uuid": org, "product": val.get("product"),
                       "message_count": val.get("messageCount"),
                       "approx_bytes": val.get("approxBytes")},
                ts_utc=to_utc_iso(from_unix(val["lastOpenedAt"])),
                time_source=TimeSource.APPLOG.value,
                ref=my_ref,
                meta={"written_at": to_utc_iso(from_unix(val.get("writtenAt") or 0)),
                      "fetched_at": to_utc_iso(from_unix(val.get("fetchedAt") or 0))},
            ))
            return

        # 대화 전문 — 캐시와는 **독립된 두 번째 채널**
        if store == "trees" and isinstance(val.get("tree"), dict):
            tree = val["tree"]
            self.emit(Record(
                kind="conversation", source=self.name, key=conv,
                value={"uuid": tree.get("uuid") or conv,
                       "name": tree.get("name"),
                       "summary": (tree.get("summary") or "")[:500] or None,
                       "model": tree.get("model"),
                       "account_uuid": account, "org_uuid": org,
                       "message_count": val.get("messageCount"),
                       "product": val.get("product")},
                ts_utc=to_utc_iso(from_unix(val.get("conversationUpdatedAt") or
                                            val.get("fetchedAt") or 0)),
                time_source=TimeSource.APIRESPONSE.value,
                ref=my_ref,
            ))
            for m in (tree.get("chat_messages") or []):
                if not isinstance(m, dict):
                    continue
                text = m.get("text") or "".join(
                    c.get("text", "") for c in (m.get("content") or [])
                    if isinstance(c, dict))
                if not text:
                    continue
                self.emit(Record(
                    kind="message", source=self.name, key=conv,
                    value={"uuid": m.get("uuid"), "conversation_uuid": conv,
                           "sender": m.get("sender"), "text": text,
                           "index": m.get("index")},
                    ts_utc=to_utc_iso(from_iso(m.get("created_at") or "")),
                    time_source=TimeSource.APIRESPONSE.value,
                    ref=my_ref,
                ))
            return

        # 그 밖의 스토어 — 시각이 있으면 활동 기록으로 남긴다
        for tkey in ("ts", "at", "timestamp"):
            if isinstance(val.get(tkey), (int, float)):
                self.emit(Record(
                    kind="idb_activity", source=self.name, key=f"{db_name}/{store}",
                    value={k: v for k, v in val.items() if not isinstance(v, (dict, list))},
                    ts_utc=to_utc_iso(from_unix(val[tkey])),
                    time_source=TimeSource.APPLOG.value,
                    ref=my_ref,
                ))
                return


class LocalStorageSource(_LevelDbBase):
    name = "localstorage"
    display = "Local Storage"
    storage_kind = Storage.LOCALSTORAGE
    subdir = ("Local Storage", "leveldb")


class BlobSource(Source):
    """
    IndexedDB Blob 실물.
    첨부 원본이 여기 있고, **계정 프로필이 평문으로** 들어 있는 경우가 있다.
    """
    name = "blob"
    display = "IndexedDB Blob"

    def locate(self) -> list[Path]:
        d = self.root / "IndexedDB" / "https_claude.ai_0.indexeddb.blob"
        if not d.is_dir():
            return []
        return [p for p in d.rglob("*") if p.is_file()]

    def read(self) -> list[Record]:
        files = self.locate()
        if not files:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name, "blob 폴더 없음")
            return []

        for f in files:
            data = self.safe_bytes(f)
            if data is None:
                continue
            self.manifest.add_file(f)
            ref = ArtifactRef.from_file(f, Storage.BLOB, note="IndexedDB Blob 실물")
            text8 = data.decode("utf-8", "ignore")
            text16 = data.decode("utf-16-le", "ignore")

            profile = {}
            for field_name in ("full_name", "email_address", "display_name", "tagged_id", "uuid"):
                m = re.search(rf'"{field_name}"\s*:\s*"([^"]{{1,200}})"', text8)
                if m:
                    profile[field_name] = m.group(1)
            if profile:
                self.emit(Record(kind="account_profile", source=self.name,
                                 key=f.name, value=profile, ref=ref))

            uuids = list(dict.fromkeys(UUID_RE.findall(text8) + UUID_RE.findall(text16)))
            if uuids:
                self.emit(Record(kind="blob_uuids", source=self.name, key=f.name,
                                 value={"uuids": uuids[:10], "size": len(data)}, ref=ref))

            self.emit(Record(kind="fileinfo", source=self.name, key=f.name,
                             value={"size": len(data)}, ref=ref))

        self.errs.add("info", "BLOB_SCAN", "parse", self.name, f"blob {len(files)}개 확인")
        return self.records
