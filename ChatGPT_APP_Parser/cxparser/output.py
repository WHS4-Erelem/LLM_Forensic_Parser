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
        "prefetch": "Prefetch", "recent_lnk": "Recent", "webcache": "WebCache",
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


_PH_GLOBAL_KEYS = ("prompt-history.global", "prompt-history.chatgpt-global")


def _is_live(r):
    return ((r.get("evidence") or {}).get("location") or {}).get("allocated") is not False


def _fold_prompt_history(rows):
    """global-state 의 프롬프트 이력은 같은 프롬프트가 (1) 현존 파일과 삭제된 이전 버전(원자적 재작성 잔여) 양쪽,
    (2) 대화별 목록과 global/chatgpt-global 목록 양쪽에 중복으로 실린다. 타임라인에는 프롬프트당 대화별 1행만 두고
    나머지는 그 행의 Artifact_details 에 근거로 접는다. 삭제본에만 있거나 global 에만 있는 프롬프트는 그대로 남긴다.
    반환: (행 목록, {record_id: 병합 메모})."""
    groups, others = {}, []
    for r in rows:
        det = r.get("details") or {}
        if det.get("artifact") == "codex_global_state" and str(det.get("key", "")).startswith("prompt-history") and det.get("prompt_text"):
            groups.setdefault(" ".join(det["prompt_text"].split()), []).append(r)
        else:
            others.append(r)
    out, notes = list(others), {}
    # 시각이 있는 같은 프롬프트(rollout·SQLite·채팅창 캐시)가 있으면 global-state 행은 전부 그 행의 근거로 접는다
    timed = {}
    for r in others:
        det = r.get("details") or {}
        if (r.get("event") or {}).get("event_id") == "E04-01" and (r.get("timestamp") or {}).get("utc") and det.get("text"):
            timed.setdefault(" ".join(str(det["text"]).split()), r)
    for text in list(groups):
        rep = timed.get(text)
        if rep is not None:
            rs = groups.pop(text)
            notes.setdefault(rep["record_id"], []).append("global-state prompt-history 에도 기록 (%d건%s)" % (
                len(rs), ", 삭제된 이전 버전 포함" if any(not _is_live(r) for r in rs) else ""))
    for rs in groups.values():
        is_global = lambda r: r["details"]["key"] in _PH_GLOBAL_KEYS
        reps = {}                                                  # 대화(key)마다 대표 1행, 현존 파일 우선
        for r in sorted(rs, key=lambda r: (is_global(r), not _is_live(r), r["record_id"])):
            k = "_global" if is_global(r) else r["details"]["key"]
            if not reps or (k != "_global" and k not in reps):
                reps[k] = r
        first = next(iter(reps.values()))
        for r in rs:
            if any(r is x for x in reps.values()):
                continue
            target = reps.get(r["details"]["key"]) or first           # 같은 대화의 삭제본은 그 대화 행에, global 항목은 첫 행에
            mft = ((r.get("evidence") or {}).get("location") or {}).get("mft_record")
            note = ("삭제된 이전 버전(MFT %s)에도 동일" % mft) if not _is_live(r) else "%s 목록에도 기록" % r["details"]["key"].split(".")[-1]
            if is_global(r) and not _is_live(r):
                note = "삭제된 이전 버전(MFT %s)의 %s 목록에도 동일" % (mft, r["details"]["key"].split(".")[-1])
            notes.setdefault(target["record_id"], [])
            if note not in notes[target["record_id"]]:
                notes[target["record_id"]].append(note)
        out.extend(reps.values())
    return out, {k: "; ".join(v) for k, v in notes.items()}


_RUN_FOLD_SEC = 120   # ponytail: 표본에서 Prefetch 시각이 첫 로그보다 10~70초 앞섬 (첫 실행은 초기화가 길다). 표본 늘면 조정


def _fold_app_runs(rows, notes):
    """E08-01 실행: 같은 실행이 앱 로그(프로세스 시작)와 Prefetch 양쪽에 남는다. 60초 안에 겹치면 로그 행 하나만 두고
    Prefetch 시각을 그 행의 근거로 접는다. 짝이 없는 Prefetch 실행(로그가 순환·삭제된 경우)은 그대로 남긴다."""
    runs = [r for r in rows if r["event"]["event_id"] == "E08-01" and (r.get("timestamp") or {}).get("utc")]
    logs = [r for r in runs if (r.get("details") or {}).get("artifact") == "codex_sqlite"]
    # 앱 프로세스 구간: 구간 안에서 뜬 Prefetch 실행은 앱이 띄운 보조 프로세스(codex.exe app-server 등)라 사용자 실행이 아니다
    spans = [(_secs(lg["details"]["session_first_utc"]) - _RUN_FOLD_SEC, _secs(lg["details"]["session_last_utc"]))
             for lg in logs if lg["details"].get("session_first_utc") and lg["details"].get("session_last_utc")]
    drop = set()
    for pf in (r for r in runs if (r.get("details") or {}).get("artifact") == "prefetch"):
        t = _secs(pf["timestamp"]["utc"])
        near = [lg for lg in logs if abs(_secs(lg["timestamp"]["utc"]) - t) <= _RUN_FOLD_SEC]
        if near:
            lg = min(near, key=lambda x: abs(_secs(x["timestamp"]["utc"]) - t))
            drop.add(pf["record_id"])
            notes.setdefault(lg["record_id"], [])
            notes[lg["record_id"]].append("Prefetch 실행 기록 %s 와 일치" % to_kst(pf["timestamp"]["utc"])[:19])
        elif any(a <= t <= b for a, b in spans):
            drop.add(pf["record_id"])                      # 실행 중 구간 안의 보조 프로세스 기동 — JSON 에는 남고 타임라인에서만 뺀다
    return [r for r in rows if r["record_id"] not in drop]


def _artifact_details(r, titles, fold_note=None):
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
          ("중복 병합", fold_note),
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
    rows, fold_notes = _fold_prompt_history(rows)
    raw_notes = {k: v.split("; ") for k, v in fold_notes.items()}
    rows = _fold_app_runs(rows, raw_notes)
    fold_notes = {k: "; ".join(v) for k, v in raw_notes.items()}
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
               _winpath(r), _artifact_details(r, titles, fold_notes.get(r["record_id"]))])
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


if __name__ == "__main__":  # python -m cxparser.output — 프롬프트 이력 중복 병합 자체 검사
    def _rec(rid, key, text, live=True, mft=1):
        return {"record_id": rid, "details": {"artifact": "codex_global_state", "key": key, "prompt_text": text},
                "evidence": {"location": {"allocated": live, "mft_record": mft}}}
    rows, notes = _fold_prompt_history([
        _rec("r1", "prompt-history.T1", "hello"), _rec("r2", "prompt-history.T1", "hello", live=False, mft=9),
        _rec("r3", "prompt-history.global", "hello"), _rec("r4", "prompt-history.global", "hello", live=False, mft=9),
        _rec("r5", "prompt-history.global", "only-global"), _rec("r6", "prompt-history.global", "only-global", live=False, mft=9),
        _rec("r7", "prompt-history.T2", "only-deleted", live=False, mft=9),
        {"record_id": "r8", "details": {"artifact": "rollout"}, "evidence": {}}])
    ids = sorted(r["record_id"] for r in rows)
    assert ids == ["r1", "r5", "r7", "r8"], ids                       # 대화행 1 + global 만 1 + 삭제본만 1 + 무관 1
    assert notes["r1"] == "삭제된 이전 버전(MFT 9)에도 동일; global 목록에도 기록; 삭제된 이전 버전(MFT 9)의 global 목록에도 동일", notes["r1"]
    assert notes["r5"] == "삭제된 이전 버전(MFT 9)의 global 목록에도 동일" and "r7" not in notes, notes.get("r5")
    print("output self-check ok")
