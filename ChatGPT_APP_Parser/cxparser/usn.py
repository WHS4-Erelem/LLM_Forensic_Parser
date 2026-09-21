"""$Extend/$UsnJrnl:$J (USN 변경 저널) 파서 — Codex 아티팩트 이름에 한정.

파일 자체가 남지 않는 행위(삭제·이름변경)의 **시각**을 잡기 위한 보조 근거다.
분석표 근거: "로그아웃 지문 = ~/.codex\\auth.json FILE_DELETE", "강제 종료 구간 USN 0건".

한계(반드시 결과에 남긴다):
  - USN 레코드에는 경로가 없다. 파일 이름 + 부모 파일참조번호(MFT#)만 있으므로,
    같은 이름의 다른 파일일 가능성을 배제하지 못한다 -> confidence 는 최대 '추정'.
  - 저널은 크기 제한으로 오래된 레코드부터 잘린다(있던 행위가 안 보일 수 있음).
  - USN 시각은 저널 기록 시각이며 사용자 행위 시각과 같다고 단정하지 않는다.
"""

import re
import struct
from datetime import datetime, timedelta, timezone

from . import events, model

# 이름으로 Codex 아티팩트 후보를 고른다 (경로가 없으므로 이름 기준)
NAME_PATTERNS = [
    re.compile(r"^rollout-.*\.jsonl$", re.I),
    re.compile(r"^session_index\.jsonl$", re.I),
    re.compile(r"^auth\.json$", re.I),
    re.compile(r"^\.codex-global-state\.json(\.bak|\.tmp.*)?$", re.I),
    re.compile(r"^(state_\d+|thread_history_\d+|logs_\d+|goals_\d+|memories_\d+|queue_\d+)"
               r"\.sqlite(-wal|-shm)?$", re.I),
    re.compile(r"^\.coordination\.lock$", re.I),
    re.compile(r"^models_cache\.json$", re.I),
    re.compile(r"^installation_id$", re.I),
]

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
# 개별 레코드로 남길 이유 (나머지는 파일별 요약으로 집계)
KEY_REASONS = ("FILE_CREATE", "FILE_DELETE", "RENAME_OLD_NAME", "RENAME_NEW_NAME")
# 개별 레코드로 남길 파일 이름 — 전역 상태·SQLite·lock 은 원자적 재작성으로 수백 건이 찍혀
# 요약(파일별 집계)만 남긴다. 대화·인증 파일만 행위와 1:1 로 이어진다.
KEY_NAME_RE = re.compile(r"^(rollout-.*\.jsonl|auth\.json|session_index\.jsonl)$", re.I)

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


def interesting(name):
    return any(p.match(name) for p in NAME_PATTERNS)


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
            "usn": usn, "file_mft_record": fref & 0xFFFFFFFFFFFF,
            "parent_mft_record": pref & 0xFFFFFFFFFFFF,
            "timestamp_utc": _filetime(ts), "reasons": _reason_names(reason),
            "reason_mask": reason, "source_info": src, "security_id": sec,
            "file_attributes": attrs, "name": name, "version": "%d.%d" % (major, minor),
        }
        off += length


def read_journal(fs, chunk=4 << 20, max_bytes=None):
    """$Extend/$UsnJrnl:$J 를 읽으며 Codex 아티팩트 이름의 레코드만 돌려준다."""
    import pytsk3
    f = fs.open("/$Extend/$UsnJrnl")
    attr = next((a for a in f
                 if a.info.name and a.info.name.decode("utf-8", "replace") == "$J"
                 and int(a.info.type) == int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA)), None)
    if attr is None:
        raise FileNotFoundError("$UsnJrnl:$J 스트림을 찾지 못함")
    size = attr.info.size
    limit = min(size, max_bytes) if max_bytes else size
    out, scanned, tail = [], 0, b""
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
            ts = rec["timestamp_utc"]
            if ts:
                first_ts = min(first_ts or ts, ts)
                last_ts = max(last_ts or ts, ts)
            if interesting(rec["name"]):
                out.append(rec)
        scanned += len(buf)
        tail = data[last_end:] if len(data) - last_end < 1024 else b""
        off += want
    return {"journal_size_bytes": size, "scanned_bytes": scanned,
            "records_matched": len(out),
            "journal_earliest_utc": first_ts, "journal_latest_utc": last_ts,
            "note": "저널은 순환하므로 earliest 이전 행위는 USN 에 남지 않는다"}, out


def to_records(usn_info, usn_recs, image_desc, rb, journal_location, max_excerpt=500):
    """USN 레코드 -> 출력 레코드 (핵심 이유는 개별, 나머지는 파일별 요약)."""
    records = []
    grouped = {}
    key_events = {}
    for r in usn_recs:
        key = (r["file_mft_record"], r["name"])
        g = grouped.setdefault(key, {"reasons": {}, "first": None, "last": None, "count": 0,
                                     "parent": r["parent_mft_record"]})
        g["count"] += 1
        for name in r["reasons"]:
            g["reasons"][name] = g["reasons"].get(name, 0) + 1
        ts = r["timestamp_utc"]
        if ts:
            g["first"] = min(g["first"] or ts, ts)
            g["last"] = max(g["last"] or ts, ts)
        # USN 은 파일이 닫힐 때까지 사유 비트를 누적하므로 같은 사건이 여러 줄로 찍힌다.
        # (파일, 사유)별로 첫 기록만 남기고 건수는 합친다.
        if not KEY_NAME_RE.match(r["name"]):
            continue
        for reason in [x for x in r["reasons"] if x in KEY_REASONS]:
            kkey = (r["file_mft_record"], r["name"], reason)
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

    for (mft, name), g in sorted(grouped.items()):
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=g["first"], original=g["first"], fmt="FILETIME(UTC)",
                            meaning="이 파일 이름에 대한 USN 저널 최초 기록 시각",
                            source=model.TS_SOURCE_CONTENT),
            model.user_action(
                observed="USN 저널에 %s 변경 %d건 (%s)" % (name, g["count"],
                                                     ", ".join(sorted(g["reasons"]))),
                rationale="변경 사유 집계 — 개별 행위로 특정하지 않음"),
            model.evidence(image_desc, None, locator="usn_file_mft=%d" % mft,
                           extra={"location": journal_location}),
            status="ok",
            notes=["USN 레코드에는 경로가 없어 동명 파일 가능성 배제 불가"],
            details={"artifact": "usn_journal", "file_name": name,
                     "file_mft_record": mft, "parent_mft_record": g["parent"],
                     "reason_counts": g["reasons"], "record_count": g["count"],
                     "first_utc": g["first"], "last_utc": g["last"]}))
    return records


def _key_record(r, reason, count, last_utc, image_desc, rb, journal_location):
    name = r["name"]
    candidate = None
    if name.lower() == "auth.json" and "FILE_DELETE" == reason:
        event_id, action, conf = "E01-02", "로그아웃(auth.json 삭제)", model.CONF_INFERRED
        why = ("USN 저널에 auth.json FILE_DELETE — 분석표의 로그아웃 지문. "
               "다만 USN 에는 경로가 없어 동명 파일 가능성은 배제 불가")
    elif name.lower().startswith("rollout-") and "FILE_CREATE" == reason:
        event_id, action, conf = "E03-01", "새 대화 생성(rollout 파일 생성)", model.CONF_INFERRED
        why = "USN 저널에 rollout JSONL FILE_CREATE — 분석표 E03-01 의 파일 생성 흔적"
    elif name.lower().startswith("rollout-") and "FILE_DELETE" == reason:
        event_id, action, conf = "E03-02", "대화 파일 삭제", model.CONF_INFERRED
        why = "USN 저널에 rollout JSONL FILE_DELETE — 로컬 대화 파일이 지워진 흔적"
    elif name.lower() == "auth.json" and "FILE_CREATE" == reason:
        event_id, action, conf = "NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN
        why = ("USN 저널에 auth.json FILE_CREATE — 로그인/계정 전환/토큰 재발급 중 "
               "무엇인지 이 기록만으로는 구분 불가")
        candidate = "E01-01/E01-03"
    elif name.lower() == "session_index.jsonl" and "FILE_CREATE" == reason:
        event_id, action, conf = "NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN
        why = ("USN 저널에 session_index.jsonl FILE_CREATE — 대화 목록 파일 생성. "
               "대화 생성(E03-01)과 앱 재작성 중 구분 불가")
        candidate = "E03-01"
    else:
        event_id, action, conf = "NA-00", model.ACTION_UNKNOWN, model.CONF_UNKNOWN
        why = "USN 변경 사유 %s — 사용자 행위 특정 불가" % reason
    return model.Record(
        rb.next_id(), event_id, events.name(event_id),
        model.timestamp(utc=r["timestamp_utc"], original=r["timestamp_utc"],
                        fmt="FILETIME(UTC)",
                        meaning="USN 저널에 기록된 변경 시각",
                        source=model.TS_SOURCE_CONTENT),
        model.user_action(action=action, confidence=conf, rationale=why,
                          observed="%s: %s (같은 사유 USN 레코드 %d건, 마지막 %s)"
                                   % (name, reason, count, last_utc)),
        model.evidence(image_desc, None,
                       locator="usn=%d file_mft=%d" % (r["usn"], r["file_mft_record"]),
                       extra={"location": journal_location}),
        status="ok",
        notes=["USN 시각은 저널 기록 시각 — 사용자 행위 시각과 동일하다고 단정하지 않음",
               "USN 은 파일이 닫힐 때까지 사유 비트를 누적 — 같은 사유의 첫 기록만 레코드로 남김"],
        details={"artifact": "usn_journal", "file_name": name, "key_reason": reason,
                 "candidate_event": candidate,
                 "same_reason_record_count": count, "last_same_reason_utc": last_utc, **r})
