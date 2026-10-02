"""결과 출력 — result.json(전체) + 팀 공통 CSV 2종.

팀 공통 형식 (헤더는 공유본과 바이트 단위로 같게, 끝 공백 2개 포함):
  timeline.csv                Model, Timestamp, User_behavior, Behavior_details , Verdict,
                              Artifact_path, Artifact_details
  recovered_conversations.csv Model, timestamp, conversation_uuid, conversation_title,
                              message_uuid, parent_message_uuid, message order, role,
                              content, Artifact_path
"""

import csv
import json
import os
from datetime import datetime, timedelta

from . import events

MODEL = "claude-desktop"
PACKAGE_NAME = "Claude_pzs8sxrjxfjjc"
ROOT_PARENT = "00000000-0000-4000-8000-000000000000"

TIMELINE_COLUMNS = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                    "Artifact_path", "Artifact_details "]
CONV_COLUMNS = ["Model", "timestamp", "conversation_uuid", "conversation_title",
                "message_uuid", "parent_message_uuid", "message order", "role", "content",
                "Artifact_path"]

VERDICT = {"확인": "확정", "추정": "의심", "미확정": "판단 불가"}
CSV_VERDICTS = ("확정", "의심")

_ROLE = {"user": "user", "human": "user", "assistant": "assistant",
         "system": "system", "unknown": "unknown"}

# 대화 저장소는 앱이 끼워 넣은 안내와 도구 결과도 role=user 로 담는다.
# 그대로 싣으면 사용자가 한 말로 읽히므로, 무엇에서 온 본문인지로 다시 적는다.
_ORIGIN_ROLE = {"user_typed": "user", "user_upload": "user",
                "assistant": "assistant", "system": "system",
                "system_injection": "system", "tool_result": "tool",
                "unknown": "unknown"}
_TAG = {"cache_block": "Cache", "idb_leveldb": "IndexedDB", "idb_blob": "Blob",
        "local_storage": "Local Storage", "session_storage": "Session Storage",
        "config": "Config", "applog": "App Log", "applog_pkg": "App Log",
        "applog_shared": "App Log", "setuplog": "App Log", "prefetch": "Prefetch",
        "usn_journal": "USN"}
# Behavior_details 에 넣을 핵심 내용을 고르는 순서.
# identifiers 는 팀 매핑 규칙에 따라 식별자를 이 칸에 적기 위해 앞에 둔다.
_CORE_KEYS = ("text", "prompt_text", "identifiers", "title", "model",
              "file_name", "key", "log_body")

EMPTY = "-"      # 팀 공통: 값이 없는 셀은 빈칸 대신 "-"


def write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def to_kst(utc_iso):
    """UTC ISO(...Z) -> 'YYYY-MM-DD HH:MM:SS.ffffff KST'. 미상은 ''."""
    if not utc_iso:
        return ""
    dt = datetime.fromisoformat(utc_iso.replace("Z", "+00:00")) + timedelta(hours=9)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + " KST"


def _secs(utc_iso):
    return datetime.fromisoformat(utc_iso.replace("Z", "+00:00")).timestamp()


def _safe(v):
    """빈 셀은 EMPTY, 그 외는 Excel 수식 주입 방지."""
    s = "" if v is None else str(v)
    if not s.strip():
        return EMPTY
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _writer(fh):
    w = csv.writer(fh)
    return lambda row: w.writerow([_safe(c) for c in row])


def _one_line(v, limit=300):
    return " ".join(str(v).split())[:limit]


def _winpath(r):
    """이미지 내부 경로 '/Users/x/...' -> 'C:\\Users\\x\\...'"""
    p = ((r.get("evidence") or {}).get("location") or {}).get("path") or ""
    return "C:" + p.replace("/", "\\") if p else ""


def _behavior_details(r, titles):
    det = r.get("details") or {}
    core = next((det[k] for k in _CORE_KEYS if det.get(k)), None)
    if core is None and det.get("conversation_uuid"):
        core = _title_of(titles, det.get("conversation_uuid"))
    if core is None:
        core = (r["user_action"].get("observed_artifact") or
                ((r.get("evidence") or {}).get("locator") or ""))
    return "%s_%s" % (r["user_action"].get("action"), _one_line(core))


def _artifact_details(r, titles):
    det, ev = r.get("details") or {}, r.get("evidence") or {}
    loc = ev.get("location") or {}
    tag = _TAG.get(det.get("artifact"), det.get("artifact") or "Artifact")
    kv = [("유형", det.get("item_type") or det.get("key") or det.get("reason")),
          ("대화 제목", det.get("title") or _title_of(titles, det.get("conversation_uuid"))),
          ("대화 UUID", det.get("conversation_uuid")),
          ("계정 UUID", det.get("account_uuid")),
          ("조직 UUID", det.get("org_uuid")),
          ("모델", det.get("model")),
          ("위치", ev.get("locator")),
          ("MFT", loc.get("mft_record")),
          ("volume", "ntfs@%s" % loc["partition_offset_bytes"]
           if loc.get("partition_offset_bytes") is not None else None),
          ("삭제 엔트리", "True" if loc.get("allocated") is False else None),
          ("규칙", r["event"]["event_id"]),
          ("패키지", PACKAGE_NAME)]
    return "[%s] " % tag + ", ".join("%s=%s" % (k, _one_line(v, 120))
                                     for k, v in kv if v not in (None, ""))


def _titles(records):
    """대화 UUID -> 제목. 저장소마다 대소문자가 달라 소문자로 맞춰 모은다.

    cowork 세션은 대화 저장소에 제목이 없고 캐시 비콘에만 남는다. 비콘은
    세션 ID 를 원래 대소문자로 적어서, 맞추지 않으면 제목이 붙지 않는다.
    """
    titles = {}
    for r in records:
        det = r.get("details") or {}
        if det.get("title") and det.get("conversation_uuid"):
            titles.setdefault(str(det["conversation_uuid"]).lower(),
                              det["title"])
    return titles


def _title_of(titles, cid):
    return titles.get(str(cid or "").lower(), "")


def write_timeline_csv(path, records):
    """NA-00(관찰)·판단 불가 는 제외. 시각 미상은 맨 뒤."""
    titles = _titles(records)
    rows = [r for r in records if r["event"]["event_id"] != "NA-00"
            and VERDICT.get(r["user_action"].get("confidence")) in CSV_VERDICTS
            and not (r.get("details") or {}).get("superseded_by")]
    rows.sort(key=lambda r: (r["timestamp"].get("utc") is None,
                             r["timestamp"].get("utc") or "", r["record_id"]))
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = _writer(fh)
        w(TIMELINE_COLUMNS)
        for r in rows:
            w([MODEL, to_kst(r["timestamp"].get("utc")),
               events.name(r["event"]["event_id"]),
               _behavior_details(r, titles),
               VERDICT[r["user_action"].get("confidence")],
               _winpath(r), _artifact_details(r, titles)])
    return path


def write_conversations_csv(path, records):
    """역할이 확인된 메시지만 싣는다.

    같은 (역할, 본문) 이 2초 안에 두 저장소에 있으면 먼저 온 것 1행만 남긴다.
    부모는 같은 대화의 직전 메시지, 첫 메시지는 ROOT_PARENT.
    """
    titles = _titles(records)
    msgs, seen = [], {}
    for r in records:
        det = r.get("details") or {}
        role = _ROLE.get((det.get("role") or "").lower())
        if role is None or not det.get("text") or det.get("superseded_by"):
            continue
        if det.get("origin"):
            role = _ORIGIN_ROLE.get(det["origin"], role)
        utc = r["timestamp"].get("utc")
        key = (role, " ".join(det["text"].split()))
        if any(u and utc and abs(_secs(u) - _secs(utc)) <= 2 for u in seen.get(key, ())):
            continue
        if key in seen and not utc:
            continue
        seen.setdefault(key, []).append(utc)
        msgs.append((det.get("conversation_uuid") or "", utc or "", r["record_id"],
                     role, det, r))
    msgs.sort(key=lambda m: (m[0], m[1], m[2]))
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = _writer(fh)
        w(CONV_COLUMNS)
        prev_cid, prev_uuid, order = None, None, 0
        for cid, utc, rid, role, det, r in msgs:
            if cid != prev_cid:
                prev_cid, prev_uuid, order = cid, ROOT_PARENT, 0
            order += 1
            uuid = det.get("message_uuid") or "%s-%d" % (cid or "msg", order)
            # 부모는 아티팩트에 적힌 값을 쓰고, 없을 때만 같은 대화의 직전
            # 메시지로 잇는다. 순번은 팀 양식대로 대화마다 1부터 센다 —
            # 저장소의 원래 색인(0부터, 이벤트 seq)은 JSON 에 남아 있다.
            parent = det.get("parent_message_uuid") or prev_uuid
            w([MODEL, to_kst(utc), cid, _title_of(titles, cid), uuid, parent,
               order, role, det["text"], _winpath(r)])
            prev_uuid = uuid
    return path
