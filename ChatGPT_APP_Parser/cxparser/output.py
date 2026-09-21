"""결과 출력 — cx_result.json(전체) + 팀 공통 CSV 2종.

팀 공통 형식(2026-09-20 공유본 timeline.csv / recovered_conversations.csv 헤더 그대로):
  timeline.csv               Model, Timestamp, User_behavior, Behavior_details , Verdict, Artifact_path, Artifact_details
  recovered_conversations.csv Model, timestamp, conversation_uuid, conversation_title, message_uuid,
                             parent_message_uuid, message order, role, content, Artifact_path
"""

import csv
import json
import os
from datetime import datetime, timedelta

from . import events

MODEL = "chatgpt-desktop"
PACKAGE_NAME = "OpenAI.Codex_2p2nqsd0c76g0"
ROOT_PARENT = "00000000-0000-4000-8000-000000000000"   # 공유본: 첫 메시지의 부모

# 헤더는 공유본과 바이트 단위로 같게 유지한다 (끝 공백 2개 포함)
TIMELINE_COLUMNS = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                    "Artifact_path", "Artifact_details "]
CONV_COLUMNS = ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                "parent_message_uuid", "message order", "role", "content", "Artifact_path"]

# 회의록 5절: 확정 / 의심. 판단 불가(미확정) 는 CSV 에서 제외 (JSON 에는 남음)
VERDICT = {"확인": "확정", "추정": "의심", "미확정": "판단 불가"}
CSV_VERDICTS = ("확정", "의심")

_ROLE = {"user": "user", "assistant": "assistant",
         "userMessage": "user", "agentMessage": "assistant"}
_TAG = {"rollout_jsonl": "Rollout", "codex_global_state": "GlobalState", "codex_sqlite": "SQLite",
        "session_index_jsonl": "SessionIndex", "auth_json": "Auth", "usn_journal": "USN"}
# Behavior_details 의 '<흔적 성격>_<내용>' 에서 <내용> 으로 쓸 값 (우선순위)
_CORE_KEYS = ("text", "prompt_text", "title", "model_slug", "file_name", "key", "log_body")


def write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def to_kst(utc_iso):
    """UTC ISO(...Z) -> 'YYYY-MM-DD HH:MM:SS[.ffffff] KST' (팀 표시 형식). 미상은 ''."""
    if not utc_iso:
        return ""
    dt = datetime.fromisoformat(utc_iso.replace("Z", "+00:00")) + timedelta(hours=9)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + " KST"      # 팀 공통: 소수 6자리 고정


def _secs(utc_iso):
    return datetime.fromisoformat(utc_iso.replace("Z", "+00:00")).timestamp()


EMPTY = "-"   # 팀 공통: 시각·ID 등 값이 없는 셀은 빈칸 대신 "-"


def _safe(v):
    """빈 셀은 EMPTY, 그 외는 Excel 수식 주입 방지 — 팀 파서 공통 관례."""
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
    """이미지 내부 경로 '/Users/x/...' -> 'C:\\Users\\x\\...' (공유본 표기).
    ponytail: 드라이브 문자는 C: 로 가정 — 파티션→문자 매핑은 이미지에 없음 (필요 시 details.partition_index 로 구분)"""
    p = ((r.get("evidence") or {}).get("location") or {}).get("path") or ""
    return "C:" + p.replace("/", "\\") if p else ""


def _behavior_details(r, titles):
    det = r.get("details") or {}
    core = next((det[k] for k in _CORE_KEYS if det.get(k)), None)
    if core is None and det.get("thread_id") and titles.get(det["thread_id"]):
        core = titles[det["thread_id"]]
    if core is None:
        core = (r["user_action"].get("observed_artifact") or
                ((r.get("evidence") or {}).get("locator") or ""))
    return "%s_%s" % (r["user_action"].get("action"), _one_line(core))


def _artifact_details(r, titles):
    det, ev = r.get("details") or {}, r.get("evidence") or {}
    loc = ev.get("location") or {}
    tag = _TAG.get(det.get("artifact"), det.get("artifact") or "Artifact")
    kv = [("유형", det.get("item_type") or det.get("table") or det.get("key") or det.get("reason")),
          ("대화 제목", det.get("title") or titles.get(det.get("thread_id") or "")),
          ("대화 UUID", det.get("thread_id")),
          ("분기 UUID", det.get("branch_id")),
          ("모델", det.get("model") or det.get("model_slug")),
          ("위치", ev.get("locator")),
          ("MFT", loc.get("mft_record")),
          ("volume", "ntfs@%s" % loc["partition_offset_bytes"] if loc.get("partition_offset_bytes") is not None else None),
          ("삭제 엔트리", "True" if loc.get("allocated") is False else None),
          ("규칙", r["event"]["event_id"]),
          ("패키지", PACKAGE_NAME)]
    return "[%s] " % tag + ", ".join("%s=%s" % (k, _one_line(v, 120)) for k, v in kv if v not in (None, ""))


def _titles(records):
    titles = {}
    for r in records:
        det = r.get("details") or {}
        if det.get("title") and det.get("thread_id"):
            titles.setdefault(det["thread_id"], det["title"])
    return titles


def write_timeline_csv(path, records):
    """NA-00(관찰)·판단 불가 는 제외 — 확정 이벤트로 승격 금지 규칙. 시각 미상은 맨 뒤."""
    titles = _titles(records)
    rows = [r for r in records if r["event"]["event_id"] != "NA-00"
            and VERDICT.get(r["user_action"].get("confidence")) in CSV_VERDICTS]
    rows.sort(key=lambda r: (r["timestamp"].get("utc") is None,
                             r["timestamp"].get("utc") or "", r["record_id"]))
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = _writer(fh)
        w(TIMELINE_COLUMNS)
        for r in rows:
            w([MODEL, to_kst(r["timestamp"].get("utc")),
               events.name(r["event"]["event_id"]),          # 팀 카탈로그 행위명
               _behavior_details(r, titles),
               VERDICT[r["user_action"].get("confidence")],
               _winpath(r), _artifact_details(r, titles)])
    return path


def write_conversations_csv(path, records):
    """같은 (역할, 본문) 이 2초 안에 rollout 과 SQLite 양쪽에 있으면 rollout 1행만.
    분기(대화 수정) 스레드는 rollout 파일명은 원본 ID, SQLite 는 분기 ID 라 대화 ID 로 묶지 않는다.
    부모 메시지는 원본에 포인터가 없어 같은 대화의 직전 메시지(선형), 첫 메시지는 ROOT_PARENT."""
    titles = _titles(records)
    msgs, seen = [], {}      # seen: (role, text) -> [utc]
    for r in records:
        det = r.get("details") or {}
        role = _ROLE.get(det.get("role") or det.get("item_type"))
        if role is None or not det.get("text"):
            continue
        utc = r["timestamp"].get("utc")
        key = (role, " ".join(det["text"].split()))
        if any(u and utc and abs(_secs(u) - _secs(utc)) <= 2 for u in seen.get(key, ())):
            continue
        seen.setdefault(key, []).append(utc)
        msgs.append((det.get("thread_id") or "", utc or "", r["record_id"], role, det, r))
    msgs.sort(key=lambda m: (m[0], m[1], m[2]))
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = _writer(fh)
        w(CONV_COLUMNS)
        prev_tid, prev_uuid, order = None, None, 0
        for tid, utc, rid, role, det, r in msgs:
            if tid != prev_tid:
                prev_tid, prev_uuid, order = tid, ROOT_PARENT, 0
            order += 1
            uuid = det.get("message_id") or det.get("item_id") or "%s-%d" % (tid, order)
            w([MODEL, to_kst(utc), tid, titles.get(tid, ""), uuid, prev_uuid, order,
               role, det["text"], _winpath(r)])
            prev_uuid = uuid
    return path
