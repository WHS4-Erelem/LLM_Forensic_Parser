"""$Extend/$UsnJrnl:$J (USN 변경 저널) — Claude Desktop 폴더 안의 변경 기록.

파일 자체가 남지 않는 행위(지워진 첨부, 처음 실행, 설치·삭제)의 **시각**을 잡는 보조 근거다.

무엇을 고르는가 (USN 레코드에는 경로가 없고 이름 + 부모 참조(MFT#·순번)만 있다)
  1) 부모가 이미지에서 훑은 Claude 탐색 폴더인 레코드 — 부모 참조를 MFT 번호와 **순번까지**
     맞춘다. MFT 엔트리가 재사용되면 순번이 바뀌므로 다른 파일을 Claude 것으로 잡지 않는다.
     저널 기간에 그 아래 새로 생긴 폴더(첨부 저장소 등)도 생성 기록을 따라 넓힌다.
  2) 이름만으로 Claude 것임이 분명한 것 — Claude 실행 파일의 프리패치, WindowsApps 의
     Claude 패키지 폴더, Packages 의 Claude 데이터 폴더.
  프리패치 폴더·WindowsApps 폴더 자체는 1) 에서 뺀다 (다른 프로그램 파일이 대부분이다).

한계(반드시 결과에 남긴다):
  - 저널은 크기 제한으로 오래된 레코드부터 잘린다(있던 행위가 안 보일 수 있음).
  - USN 시각은 저널 기록 시각이며 사용자 행위 시각과 같다고 단정하지 않는다 -> 최대 '추정'.
  - 저널 기간 이전에 지워진 Claude 폴더 아래 기록은 부모를 알 수 없어 고르지 못한다.
"""

import re
import struct
from datetime import datetime, timedelta, timezone

from . import events, model

# 이름만으로 Claude 것임이 분명한 항목
CLAUDE_PF = re.compile(r"^(?P<exe>CLAUDE[^\\/]*?\.EXE)-[0-9A-F]{8}\.pf$", re.I)
PACKAGE_DIR = re.compile(r"^Claude_[^_\\/]+_(x64|x86|arm64|neutral)__pzs8sxrjxfjjc$", re.I)
PACKAGE_DATA_DIR = re.compile(r"^Claude_pzs8sxrjxfjjc$", re.I)

# 부모 기준 선택에서 빼는 탐색 폴더 (다른 프로그램 파일이 섞이는 곳)
SKIP_DIR_PREFIXES = ("/windows/prefetch", "/program files/windowsapps")
BLOB_DIR_MARK = ".indexeddb.blob"
FILE_ATTRIBUTE_DIRECTORY = 0x10

REASONS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"), (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"), (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"), (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"), (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
]
# 개별 레코드로 남길 이유 (나머지는 이름별 요약으로 집계)
KEY_REASONS = ("FILE_CREATE", "FILE_DELETE")

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(v):
    if not v:
        return None
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _reason_names(mask):
    return [n for bit, n in REASONS if mask & bit]


def iter_records(data, base_offset=0):
    """$J 청크에서 USN_RECORD_V2/V3 를 훑는다. (offset, dict) 산출."""
    off, n = 0, len(data)
    while off + 8 <= n:
        (length, major, minor) = struct.unpack_from("<IHH", data, off)
        if length == 0:                      # 희소(0) 영역 -> 8바이트씩 건너뛰며 다음 레코드 탐색
            off += 8
            continue
        if length < 56 or length > 1024 or off + length > n:
            off += 8
            continue
        try:
            if major == 2:
                (fref, pref, usn, ts, reason, src, sec, attrs, nlen, noff) = \
                    struct.unpack_from("<QQQqIIIIHH", data, off + 8)
            elif major == 3:
                (fref_lo, fref_hi, pref_lo, pref_hi, usn, ts, reason, src, sec, attrs, nlen, noff) = \
                    struct.unpack_from("<QQQQQqIIIIHH", data, off + 8)
                fref, pref = fref_lo, pref_lo      # 상위 8바이트는 128bit 참조의 확장분
            else:
                off += 8
                continue
            if noff + nlen > length or nlen == 0:
                off += length
                continue
            name = data[off + noff: off + noff + nlen].decode("utf-16-le", "replace")
        except (struct.error, ValueError):
            off += 8
            continue
        yield base_offset + off, {
            "usn": usn, "file_mft_record": fref & 0xFFFFFFFFFFFF, "file_seq": fref >> 48,
            "parent_mft_record": pref & 0xFFFFFFFFFFFF, "parent_seq": pref >> 48,
            "timestamp_utc": _filetime(ts), "reasons": _reason_names(reason),
            "reason_mask": reason, "source_info": src, "security_id": sec,
            "file_attributes": attrs, "name": name, "version": "%d.%d" % (major, minor),
        }
        off += length


class Selector:
    """USN 레코드가 Claude Desktop 것인지 고른다. 고르면 rec 에 match·parent_path 를 단다."""

    def __init__(self, claude_dirs):
        # {(MFT#, seq): 볼륨 내부 경로} — vfs.TskImageVfs.scanned_dirs
        self.dirs = {k: p for k, p in (claude_dirs or {}).items()
                     if not p.lower().startswith(SKIP_DIR_PREFIXES)}

    def _parent(self, rec):
        key = (rec["parent_mft_record"], rec["parent_seq"])
        if key in self.dirs:
            return self.dirs[key]
        if rec["parent_seq"] == 0:           # 순번을 남기지 않은 레코드 — MFT 번호로만 맞춘다
            for (mft, _seq), path in self.dirs.items():
                if mft == rec["parent_mft_record"]:
                    return path
        return None

    def match(self, rec):
        name = rec["name"]
        parent = self._parent(rec)
        if parent is not None:
            rec["parent_path"] = parent
            rec["match"] = "claude_dir"
            # 저널 기간에 Claude 폴더 아래 새로 생긴 폴더 — 그 아래 기록도 고른다
            if (rec["file_attributes"] & FILE_ATTRIBUTE_DIRECTORY
                    and "FILE_CREATE" in rec["reasons"]):
                self.dirs.setdefault((rec["file_mft_record"], rec["file_seq"]),
                                     parent + "/" + name)
            return True
        if CLAUDE_PF.match(name):
            rec["match"] = "prefetch"
            return True
        if PACKAGE_DIR.match(name) or PACKAGE_DATA_DIR.match(name):
            rec["match"] = "package"
            return True
        return False


def read_journal(fs, chunk=4 << 20, max_bytes=None, claude_dirs=None):
    """$Extend/$UsnJrnl:$J 를 읽으며 Claude Desktop 레코드만 돌려준다 (Selector 기준)."""
    import pytsk3
    f = fs.open("/$Extend/$UsnJrnl")
    attr = next((a for a in f
                 if a.info.name and a.info.name.decode("utf-8", "replace") == "$J"
                 and int(a.info.type) == int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA)), None)
    if attr is None:
        raise FileNotFoundError("$UsnJrnl:$J 스트림을 찾지 못함")
    selector = Selector(claude_dirs)
    size = attr.info.size
    limit = min(size, max_bytes) if max_bytes else size
    out, scanned, tail, total = [], 0, b"", 0
    first_ts = last_ts = None      # 저널이 덮는 시간 범위 — "0건" 이 순환 탓인지 판단할 근거
    off = 0
    while off < limit:
        want = min(chunk, limit - off)
        try:
            buf = f.read_random(off, want, pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA, attr.info.id)
        except OSError:
            break
        if not buf:
            break
        if buf.count(0) == len(buf):          # 희소 구간(저널 앞부분)은 건너뛴다
            off += want
            tail = b""
            continue
        data = tail + buf
        base = off - len(tail)
        last_end = 0
        for rec_off, rec in iter_records(data, base):
            last_end = max(last_end, rec_off - base)
            total += 1
            ts = rec["timestamp_utc"]
            if ts:
                first_ts = min(first_ts or ts, ts)
                last_ts = max(last_ts or ts, ts)
            if selector.match(rec):
                out.append(rec)
        scanned += len(buf)
        tail = data[last_end:] if len(data) - last_end < 1024 else b""
        off += want
    return {"journal_size_bytes": size, "scanned_bytes": scanned,
            "records_total": total, "records_matched": len(out),
            "claude_dirs_compared": len(selector.dirs),
            "match_basis": "Claude 탐색 폴더(부모 MFT#·순번, 저널 중 새 하위 폴더 포함) + "
                           "Claude 프리패치·패키지 폴더 이름",
            "journal_earliest_utc": first_ts, "journal_latest_utc": last_ts,
            "note": "저널은 순환하므로 earliest 이전 행위는 USN 에 남지 않는다"}, out


def to_records(usn_info, usn_recs, image_desc, rb, journal_location, max_excerpt=500):
    """USN 레코드 -> 출력 레코드 (판단 가능한 생성·삭제는 개별, 나머지는 이름별 요약)."""
    records = []
    grouped = {}
    key_events = {}
    for r in usn_recs:
        # 요약은 폴더 단위 — 캐시·코드 캐시처럼 해시 이름 파일이 수백 개라 이름별로는 잡음이 된다
        gkey = r.get("parent_path") or r["match"]
        g = grouped.setdefault(gkey, {"reasons": {}, "first": None, "last": None, "count": 0,
                                      "names": set(), "match": r["match"]})
        g["count"] += 1
        g["names"].add(r["name"])
        for name in r["reasons"]:
            g["reasons"][name] = g["reasons"].get(name, 0) + 1
        ts = r["timestamp_utc"]
        if ts:
            g["first"] = min(g["first"] or ts, ts)
            g["last"] = max(g["last"] or ts, ts)
        # USN 은 파일이 닫힐 때까지 사유 비트를 누적하므로 같은 사건이 여러 줄로 찍힌다.
        # (파일, 사유)별로 첫 기록만 남기고 건수는 합친다.
        for reason in [x for x in r["reasons"] if x in KEY_REASONS]:
            if _classify(r, reason) is None:
                continue
            kkey = (r["file_mft_record"], r["file_seq"], r["name"], reason)
            prev = key_events.get(kkey)
            if prev is None:
                key_events[kkey] = {"record": r, "reason": reason, "count": 1,
                                    "last": r["timestamp_utc"]}
            else:
                prev["count"] += 1
                prev["last"] = r["timestamp_utc"] or prev["last"]

    for ke in key_events.values():
        records.append(_key_record(ke["record"], ke["reason"], ke["count"], ke["last"],
                                   image_desc, rb, journal_location))

    for where, g in sorted(grouped.items()):
        names = sorted(g["names"])
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=g["first"], original=g["first"], fmt="FILETIME(UTC)",
                            meaning="이 폴더 아래 USN 저널 최초 기록 시각",
                            source=model.TS_SOURCE_CONTENT),
            model.user_action(
                observed="USN 저널에 %s 아래 변경 %d건 · 이름 %d개 (%s)" % (
                    where if g["match"] == "claude_dir" else g["match"],
                    g["count"], len(names), ", ".join(sorted(g["reasons"]))),
                rationale="변경 사유 집계 — 개별 행위로 특정하지 않음"),
            model.evidence(image_desc, None, locator="usn_summary %s" % where,
                           extra={"location": journal_location}),
            status="ok",
            notes=["USN 레코드에는 경로가 없음 — 위치는 부모 참조로 복원"],
            details={"artifact": "usn_journal", "item_type": "usn_folder_summary",
                     "file_name": names[0], "names": names[:20], "name_count": len(names),
                     "parent_path": where if g["match"] == "claude_dir" else None,
                     "match": g["match"], "reason_counts": g["reasons"],
                     "record_count": g["count"], "first_utc": g["first"], "last_utc": g["last"]}))
    return records


def _is_dir(r):
    return bool(r["file_attributes"] & FILE_ATTRIBUTE_DIRECTORY)


def _classify(r, reason):
    """(event_id, action, confidence, rationale, candidate, lineage) 또는 None(개별 레코드로 안 남김)."""
    name, match = r["name"], r["match"]
    if match == "prefetch" and reason == "FILE_CREATE":
        exe = CLAUDE_PF.match(name).group("exe").upper()
        lineage = "prefetch:%s" % name.upper()
        if "SETUP" in exe:
            return ("E02-01", "애플리케이션 설치", model.CONF_INFERRED,
                    "Claude 설치 프로그램(%s)의 프리패치 파일이 처음 만들어짐 — 설치 프로그램 "
                    "실행 시각" % exe, None, lineage)
        return ("E08-01", "애플리케이션 실행", model.CONF_INFERRED,
                "Claude 실행 파일(%s)의 프리패치 파일이 처음 만들어짐 — 그 시점의 실행 흔적"
                % exe, None, lineage)
    if match == "package" and _is_dir(r):
        if PACKAGE_DIR.match(name) and reason == "FILE_CREATE":
            return ("E02-01", "애플리케이션 설치", model.CONF_INFERRED,
                    "WindowsApps 에 Claude 패키지 폴더 생성 — 설치 또는 버전 업데이트", None,
                    "package:%s" % name.lower())
        if PACKAGE_DIR.match(name) and reason == "FILE_DELETE":
            # 버전 업데이트도 옛 버전 폴더를 지운다 — 삭제로 단정하지 않는다
            return ("NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN,
                    "WindowsApps 의 Claude 패키지 폴더 삭제 — 앱 삭제와 버전 업데이트를 "
                    "이 기록만으로는 구분 불가", "E02-02", "package:%s" % name.lower())
        if PACKAGE_DATA_DIR.match(name) and reason == "FILE_DELETE":
            return ("E02-02", "애플리케이션 삭제", model.CONF_INFERRED,
                    "사용자 데이터 폴더 Packages\\Claude_pzs8sxrjxfjjc 삭제 — 앱 제거 시 지워지는 폴더",
                    None, "package_data")
        if PACKAGE_DATA_DIR.match(name) and reason == "FILE_CREATE":
            return ("NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN,
                    "사용자 데이터 폴더 Packages\\Claude_pzs8sxrjxfjjc 생성 — 설치 뒤 첫 실행 무렵",
                    "E02-01/E08-01", "package_data")
        return None
    if match == "claude_dir" and BLOB_DIR_MARK in (r.get("parent_path") or "").lower() \
            and not _is_dir(r):
        if reason == "FILE_CREATE":
            return ("NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN,
                    "IndexedDB 첨부 저장소에 본문 파일 생성 — 첨부 업로드 흔적. 이미지·문서 "
                    "구분은 이 기록만으로 불가", "E05-01/E05-03", None)
        return ("NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN,
                "IndexedDB 첨부 저장소의 본문 파일 삭제 — 첨부 삭제 또는 앱 정리",
                "E05-02/E05-04", None)
    return None


def _key_record(r, reason, count, last_utc, image_desc, rb, journal_location):
    event_id, action, conf, why, candidate, lineage = _classify(r, reason)
    path_hint = ((r.get("parent_path") or "") + "/" + r["name"]) if r.get("parent_path") else None
    return model.Record(
        rb.next_id(), event_id, events.name(event_id),
        model.timestamp(utc=r["timestamp_utc"], original=r["timestamp_utc"],
                        fmt="FILETIME(UTC)",
                        meaning="USN 저널에 기록된 변경 시각",
                        source=model.TS_SOURCE_CONTENT),
        model.user_action(action=action, confidence=conf, rationale=why,
                          observed="%s: %s (같은 사유 USN 레코드 %d건, 마지막 %s)"
                                   % (r["name"], reason, count, last_utc)),
        model.evidence(image_desc, None,
                       locator="usn=%d file_mft=%d" % (r["usn"], r["file_mft_record"]),
                       extra={"location": journal_location}),
        status="ok",
        notes=["USN 시각은 저널 기록 시각 — 사용자 행위 시각과 동일하다고 단정하지 않음",
               "USN 은 파일이 닫힐 때까지 사유 비트를 누적 — 같은 사유의 첫 기록만 레코드로 남김"],
        details={"artifact": "usn_journal", "file_name": r["name"], "key_reason": reason,
                 "candidate_event": candidate, "lineage": lineage, "path_hint": path_hint,
                 "same_reason_record_count": count, "last_same_reason_utc": last_utc,
                 **{k: v for k, v in r.items() if k not in ("parent_path",)}})
