"""~/.codex/*.sqlite 파서 (state_5 / thread_history_1 / logs_2).

실제 표본에서 확인한 구조 (앱 0.150.0-alpha ~ 0.154.0-alpha 공통):
  state_5.sqlite        threads(id, rollout_path, created_at[_ms], updated_at[_ms], title,
                                first_user_message, preview, model, cwd, originator, archived, archived_at)
  thread_history_1.sqlite thread_items(thread_id, turn_id, item_id, created_at_ms, item_type, item_json)
                          item_type: userMessage / agentMessage / reasoning / commandExecution / …
  logs_2.sqlite         logs(ts, ts_nanos, level, target, feedback_log_body, file, line, …)

rollout JSONL 과 달리 **시각이 행마다 들어 있어**, 전역 상태 프롬프트 이력처럼 시각 없는 흔적을
시각과 함께 뒷받침할 수 있다. 다만 DB 행은 앱이 쓴 기록이므로 사용자 행위 판정 규칙은 동일하게 적용한다.

-wal/-shm 은 본 DB 와 함께 임시 폴더로 복사한 뒤 열어야 최신 트랜잭션이 반영된다(원본은 읽기 전용).
"""

import json
import os
import re
import shutil
import sqlite3
import tempfile

from .. import events, model
from ..locate import parse_rollout_filename
from ..util import excerpt, mask_text, parse_any_time

# 본 DB 이름 -> 처리 함수 (아래에서 정의)
HANDLED = ("state_5.sqlite", "thread_history_1.sqlite", "logs_2.sqlite")

# logs_2 에서 행위 근거로 뽑는 패턴 (본문 일부 일치)
LOG_LOGOUT = 'rpc.method="account/logout"'
LOG_AUTH_CHANGED = "Reloaded auth, changed: true"
AUTO_RESTART_SEC = 10   # ponytail: 표본 2개(자동 재시작 1초 / 사용자 재실행 24초 이상)에서 잡은 값. 표본이 늘면 조정
# 같은 요청이 여러 줄로 로깅되므로 요청 ID 로 묶는다
_RPC_ID_RE = re.compile(r'rpc\.request_id=\w*\("?([^")]+)"?\)')


def is_main_db(path):
    name = path.rsplit("/", 1)[-1]
    return name in HANDLED


def _open(vfile, siblings, tmpdir):
    """본 DB + -wal/-shm 을 임시 폴더로 복사해 연다."""
    name = vfile.path.rsplit("/", 1)[-1]
    local = os.path.join(tmpdir, name)
    with open(local, "wb") as fh:
        fh.write(vfile.read())
    for ext in ("-wal", "-shm"):
        sib = (siblings or {}).get(vfile.path + ext)
        if sib is not None:
            with open(local + ext, "wb") as fh:
                fh.write(sib.read())
    conn = sqlite3.connect(local)
    conn.row_factory = sqlite3.Row
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    return conn


def _tables(conn):
    return {r[0] for r in conn.execute(
        "select name from sqlite_master where type='table'")}


def _cols(conn, table):
    return [r[1] for r in conn.execute("pragma table_info(%s)" % table)]


def _err(rb, vfile, image_desc, code, exc, note):
    return model.Record(
        rb.next_id(), "NA-00", events.name("NA-00"),
        model.timestamp(null_reason="DB 를 읽지 못해 시각 확인 불가"),
        model.user_action(observed=note),
        model.evidence(image_desc, vfile, locator="file"),
        status="error",
        errors=[{"code": code, "message": "%s: %s" % (type(exc).__name__, exc)}],
        details={"artifact": "codex_sqlite", "db": vfile.path.rsplit("/", 1)[-1]})


def parse(vfile, image_desc, rb, max_excerpt=500, siblings=None):
    name = vfile.path.rsplit("/", 1)[-1]
    if not is_main_db(vfile.path):
        return []          # -wal/-shm 및 미처리 DB 는 artifact_inventory 에만 남긴다
    tmpdir = tempfile.mkdtemp(prefix="cxsql_")
    try:
        try:
            conn = _open(vfile, siblings, tmpdir)
        except Exception as exc:  # noqa: BLE001
            return [_err(rb, vfile, image_desc, "SQLITE_OPEN_FAILED", exc,
                         "%s 열기 실패" % name)]
        try:
            handler = {"state_5.sqlite": _state,
                       "thread_history_1.sqlite": _history,
                       "logs_2.sqlite": _logs}[name]
            return handler(conn, vfile, image_desc, rb, max_excerpt)
        except sqlite3.DatabaseError as exc:
            return [_err(rb, vfile, image_desc, "SQLITE_QUERY_FAILED", exc,
                         "%s 조회 실패 (손상·부분 파싱 가능성)" % name)]
        finally:
            conn.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _ts(row, keys, meaning):
    """행의 시각 컬럼(ms 우선) -> timestamp 블록"""
    for k in keys:
        v = row[k] if k in row.keys() else None
        if v in (None, 0, ""):
            continue
        iso, fmt, note = parse_any_time(v)
        return model.timestamp(utc=iso, original=v, fmt=fmt, meaning=meaning,
                               source=model.TS_SOURCE_CONTENT,
                               null_reason=note if iso is None else None)
    return model.timestamp(null_reason="행에 시각 컬럼이 없음")


def _db_evidence(image_desc, vfile, table, key, sha=None):
    return model.evidence(image_desc, vfile,
                          locator="db_table=%s key=%s" % (table, key),
                          artifact_sha256=sha)


# --- state_5.sqlite ---------------------------------------------------------
def _state(conn, vfile, image_desc, rb, max_excerpt):
    records = []
    if "threads" not in _tables(conn):
        return [_err(rb, vfile, image_desc, "SQLITE_TABLE_MISSING",
                     KeyError("threads"), "state_5.sqlite 에 threads 테이블 없음")]
    cols = set(_cols(conn, "threads"))
    sha = vfile.sha256()
    for row in conn.execute("select * from threads"):
        tid = row["id"]
        title = row["title"] if "title" in cols else None
        first = row["first_user_message"] if "first_user_message" in cols else None
        details = {
            "artifact": "codex_sqlite", "db": "state_5.sqlite", "table": "threads",
            "thread_id": tid,
            "title": excerpt(mask_text(title), max_excerpt) if title else None,
            "first_user_message": excerpt(mask_text(first), max_excerpt) if first else None,
            "rollout_path": row["rollout_path"] if "rollout_path" in cols else None,
            "model": row["model"] if "model" in cols else None,
            "cwd": row["cwd"] if "cwd" in cols else None,
            "originator": row["originator"] if "originator" in cols else None,
            "cli_version": row["cli_version"] if "cli_version" in cols else None,
            "archived": row["archived"] if "archived" in cols else None,
            "updated_at_ms": row["updated_at_ms"] if "updated_at_ms" in cols else None,
        }
        # 대화 수정(분기) 시 threads 행의 rollout_path 가 <원본ID>_<분기ID> 파일로 바뀌고
        # created_at 도 분기 시각이 된다 (평서문 E01 표본에서 확인) → E03-03 으로 귀속
        fmeta = parse_rollout_filename(os.path.basename(str(details["rollout_path"] or "").replace("\\", "/")))
        branch = bool(fmeta and fmeta["is_branch"])
        details["branch_id"] = fmeta["branch_id"] if fmeta else None
        eid = "E03-03" if branch else "E03-01"
        records.append(model.Record(
            rb.next_id(), eid, events.name(eid),
            _ts(row, ("created_at_ms", "created_at"),
                "threads 행의 " + ("분기(수정) 시각" if branch else "대화 생성 시각")),
            model.user_action(
                action="대화 수정(프롬프트 편집)" if branch else "새 대화 생성",
                confidence=model.CONF_CONFIRMED,
                rationale=("state_5.sqlite threads 행의 rollout_path 가 분기 파일(<원본ID>_<분기ID>) — "
                           "대화 수정 시 행이 분기 시각·경로로 갱신됨 (분석표 E03-03)" if branch else
                           "state_5.sqlite threads 행 — 대화 생성 시각·제목·첫 프롬프트가 "
                           "행에 함께 기록됨 (분석표 E03-01)")),
            _db_evidence(image_desc, vfile, "threads", tid, sha),
            status="ok", details=details))
        if details["archived"]:
            records.append(model.Record(
                rb.next_id(), "E03-02", events.name("E03-02"),
                _ts(row, ("archived_at", "updated_at_ms", "updated_at"),
                    "threads 행의 보관(archived) 시각"),
                model.user_action(
                    action="대화 보관/삭제",
                    confidence=model.CONF_INFERRED,
                    rationale=("threads.archived=1 — 앱에서 대화를 목록에서 내린 상태. "
                               "서버측 삭제 여부는 로컬 아티팩트로 확정 불가")),
                _db_evidence(image_desc, vfile, "threads", tid, sha),
                status="ok", details=details))
    if not records:
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="threads 행이 없어 시각 없음"),
            model.user_action(observed="state_5.sqlite 의 threads 테이블이 비어 있음"),
            _db_evidence(image_desc, vfile, "threads", "(empty)", sha),
            status="ok",
            notes=["빈 결과와 파싱 실패를 구분하기 위한 기록"],
            details={"artifact": "codex_sqlite", "db": "state_5.sqlite",
                     "table": "threads", "row_count": 0}))
    return records


# --- thread_history_1.sqlite -------------------------------------------------
def _item_text(item):
    if not isinstance(item, dict):
        return None
    if isinstance(item.get("text"), str):
        return item["text"]
    parts = [c.get("text") for c in (item.get("content") or [])
             if isinstance(c, dict) and isinstance(c.get("text"), str)]
    return "\n".join(parts) if parts else None


def _history(conn, vfile, image_desc, rb, max_excerpt):
    records = []
    tabs = _tables(conn)
    if "thread_items" not in tabs:
        return [_err(rb, vfile, image_desc, "SQLITE_TABLE_MISSING",
                     KeyError("thread_items"),
                     "thread_history_1.sqlite 에 thread_items 테이블 없음")]
    sha = vfile.sha256()
    other_types = {}
    for row in conn.execute("select * from thread_items order by created_at_ms"):
        itype = row["item_type"]
        try:
            item = json.loads(row["item_json"])
        except (TypeError, ValueError):
            item = None
        text = _item_text(item)
        if itype == "userMessage":
            event_id, action = "E04-01", model.user_action(
                action="프롬프트 전송",
                confidence=model.CONF_CONFIRMED,
                rationale=("thread_history_1.sqlite thread_items.item_type=userMessage — "
                           "행에 전송 시각이 함께 기록됨 (분석표 E04-01)"))
        elif itype == "agentMessage":
            event_id, action = "NA-00", model.user_action(
                rationale="assistant 응답 기록 — 사용자 행위 아님",
                observed=excerpt(mask_text(text), max_excerpt))
        else:
            other_types[itype] = other_types.get(itype, 0) + 1
            continue
        records.append(model.Record(
            rb.next_id(), event_id, events.name(event_id),
            _ts(row, ("created_at_ms",), "thread_items 행의 기록 시각"),
            action,
            _db_evidence(image_desc, vfile, "thread_items", row["item_id"], sha),
            status="ok",
            details={"artifact": "codex_sqlite", "db": "thread_history_1.sqlite",
                     "table": "thread_items", "thread_id": row["thread_id"],
                     "turn_id": row["turn_id"], "item_id": row["item_id"],
                     "item_type": itype,
                     "client_id": (item or {}).get("clientId"),
                     "rollout_ordinal": row["rollout_ordinal"]
                     if "rollout_ordinal" in row.keys() else None,
                     "text": mask_text(text) if text else None}))
    turns = (conn.execute("select count(*) from thread_turns").fetchone()[0]
             if "thread_turns" in tabs else None)
    records.append(model.Record(
        rb.next_id(), "NA-00", events.name("NA-00"),
        model.timestamp(null_reason="요약 레코드 — 단일 시각 없음"),
        model.user_action(observed="thread_history_1.sqlite 항목 종류별 집계"),
        _db_evidence(image_desc, vfile, "thread_items", "(summary)", sha),
        status="ok",
        notes=["메시지 외 항목(추론·명령 실행 등)은 개별 레코드 대신 집계로 보고"],
        details={"artifact": "codex_sqlite", "db": "thread_history_1.sqlite",
                 "other_item_type_counts": other_types or None,
                 "thread_turns_rows": turns}))
    return records


# --- logs_2.sqlite -----------------------------------------------------------
def _logs(conn, vfile, image_desc, rb, max_excerpt):
    records = []
    if "logs" not in _tables(conn):
        return [_err(rb, vfile, image_desc, "SQLITE_TABLE_MISSING", KeyError("logs"),
                     "logs_2.sqlite 에 logs 테이블 없음")]
    sha = vfile.sha256()
    cols = set(_cols(conn, "logs"))
    body = "feedback_log_body" if "feedback_log_body" in cols else None
    if body:
        seen = set()
        for row in conn.execute(
                "select * from logs where %s like ? or %s like ? order by ts" % (body, body),
                ("%" + LOG_LOGOUT + "%", "%" + LOG_AUTH_CHANGED + "%")):
            text = row[body] or ""
            if LOG_LOGOUT in text:
                m = _RPC_ID_RE.search(text)
                key = ("logout", m.group(1) if m else row["ts"])
                event_id = "E01-02"
                action = model.user_action(
                    action="로그아웃",
                    confidence=model.CONF_CONFIRMED,
                    rationale=("앱 로그에 account/logout 요청 처리 기록 — 로그아웃 동작 자체의 "
                               "흔적 (분석표 E01-02). auth.json 부재와 별개 근거"))
            else:
                key, event_id = ("auth", row["ts"]), "NA-00"
                action = model.user_action(
                    action=model.ACTION_UNKNOWN,
                    confidence=model.CONF_UNKNOWN,
                    rationale=("앱 로그의 'Reloaded auth, changed: true' — 인증 상태 변경. "
                               "로그인·계정 전환·토큰 갱신 중 무엇인지 이 로그만으로는 구분 불가"),
                    observed=excerpt(text, 200))
            if key in seen:
                continue
            seen.add(key)
            records.append(model.Record(
                rb.next_id(), event_id, events.name(event_id),
                _ts(row, ("ts",), "logs 행의 기록 시각(초 단위 epoch)"),
                action,
                _db_evidence(image_desc, vfile, "logs", "id=%s" % row["id"], sha),
                status="ok",
                details={"artifact": "codex_sqlite", "db": "logs_2.sqlite",
                         "table": "logs", "level": row["level"], "target": row["target"],
                         "candidate_event": None if event_id != "NA-00" else
                         "E01-01/E01-03 (로그인·계정전환·토큰갱신 구분 불가)",
                         "source_file": row["file"] if "file" in cols else None,
                         "source_line": row["line"] if "line" in cols else None,
                         "log_body": excerpt(mask_text(text), max_excerpt)}))
    span = conn.execute("select min(ts), max(ts), count(*) from logs").fetchone()
    lo, hi, n = span[0], span[1], span[2]
    lo_iso = parse_any_time(lo)[0] if lo else None
    hi_iso = parse_any_time(hi)[0] if hi else None
    records.append(model.Record(
        rb.next_id(), "NA-00", events.name("NA-00"),
        model.timestamp(utc=lo_iso, original=lo, fmt="epoch_seconds",
                        meaning="앱 로그의 최초 기록 시각 (앱 활동 구간 시작)",
                        source=model.TS_SOURCE_CONTENT),
        model.user_action(
            observed="앱 로그 %d행, 기록 구간 %s ~ %s" % (n, lo_iso, hi_iso),
            rationale=("로그 구간은 앱이 동작한 시간대일 뿐이며, 실행/종료(E08-01/02) 시각으로 "
                       "단정하지 않음")),
        _db_evidence(image_desc, vfile, "logs", "(span)", sha),
        status="ok",
        details={"artifact": "codex_sqlite", "db": "logs_2.sqlite", "table": "logs",
                 "row_count": n, "first_ts_utc": lo_iso, "last_ts_utc": hi_iso}))
    # --- 프로세스 구간 → 실행(E08-01)·종료(E08-02) ----------------------------------------------
    # 조사(2026-09-23): process_uuid 는 앱 프로세스마다 새로 붙는다. 평서문 표본 세 구간의 시작이 Prefetch 실행 시각·
    # 재실행과 초 단위로 일치했고, 강제 종료 4초 전에 마지막 줄이 찍혔다. 앱은 종료 로그를 남기지 않아 정상/강제는 구분 못 한다.
    if "process_uuid" in cols:
        prev_hi = None
        for row in conn.execute("select process_uuid, min(ts) lo, max(ts) hi, count(*) n from logs "
                                "group by process_uuid order by lo"):
            if row["lo"] is None:
                continue
            pid = row["process_uuid"] or "-"
            lo_iso, hi_iso = parse_any_time(row["lo"])[0], parse_any_time(row["hi"])[0]
            # 사용자 실행 vs 자동 재시작: 직전 프로세스가 끝난 지 AUTO_RESTART_SEC 안에 새 프로세스가 뜨면 앱이 스스로 재실행한 것
            # (표본: 샌드박스 설정 후 1초 뒤 재시작). 팀 합의(2026-09-23): 사용자가 아이콘을 눌러 켠 횟수 = 확정 행, 자동 재시작 = 의심 행.
            gap = (row["lo"] - prev_hi) if prev_hi is not None else None
            auto = gap is not None and 0 <= gap <= AUTO_RESTART_SEC
            prev_hi = row["hi"]
            det = {"artifact": "codex_sqlite", "db": "logs_2.sqlite", "table": "logs", "process_uuid": pid,
                   "key": ("자동 재시작(직전 종료 %d초 뒤) 프로세스 %s" % (gap, pid[:12]) if auto
                           else "프로세스 %s (로그 %d줄)" % (pid[:12], row["n"])),          # Behavior_details 의 <핵심 내용>
                   "session_first_utc": lo_iso, "session_last_utc": hi_iso, "row_count": row["n"],
                   "auto_restart": auto, "gap_from_previous_exit_sec": gap}
            records.append(model.Record(
                rb.next_id(), "E08-01", events.name("E08-01"),
                model.timestamp(utc=lo_iso, original=row["lo"], fmt="epoch_seconds", meaning="이 프로세스의 첫 로그 기록 시각",
                                source=model.TS_SOURCE_CONTENT),
                model.user_action(action="애플리케이션 실행(자동 재시작)" if auto else "애플리케이션 실행(프로세스 시작)",
                                  confidence=model.CONF_INFERRED if auto else model.CONF_CONFIRMED,
                                  rationale=(("logs 의 process_uuid=%s 첫 기록이 직전 프로세스 종료 %d초 뒤 — 사용자가 켠 것이 아니라 "
                                              "앱이 스스로 재실행한 것으로 추정 (기준 %d초)") % (pid[:12], gap, AUTO_RESTART_SEC) if auto else
                                             ("logs 의 process_uuid=%s 첫 기록 — 앱 프로세스마다 새 ID 가 붙으므로 구간 하나가 "
                                              "실행 한 번이다. 직전 종료와 충분히 떨어져 있어 사용자가 켠 것으로 본다") % pid[:12])),
                _db_evidence(image_desc, vfile, "logs", "process_uuid=%s first" % pid, sha), status="ok", details=det))
            records.append(model.Record(
                rb.next_id(), "E08-02", events.name("E08-02"),
                model.timestamp(utc=hi_iso, original=row["hi"], fmt="epoch_seconds", meaning="이 프로세스의 마지막 로그 기록 시각",
                                source=model.TS_SOURCE_CONTENT),
                model.user_action(action="애플리케이션 종료(프로세스 로그 끝)", confidence=model.CONF_INFERRED,
                                  rationale=("같은 process_uuid 의 마지막 기록 — 이후 기록이 없으니 프로세스가 끝난 것. 앱이 종료 로그를 "
                                             "남기지 않아 정상 종료와 강제 종료를 구분하지 못함 (팀 규칙: 강제 종료 근거 없으면 정상 종료·의심). "
                                             "강제 종료 표본에서는 마지막 줄이 종료 4초 전이었다")),
                _db_evidence(image_desc, vfile, "logs", "process_uuid=%s last" % pid, sha), status="ok",
                notes=["정상/강제 종료 구분 불가 — 창 닫기(트레이 상주)는 프로세스 종료가 아니라 여기 잡히지 않음"], details=det))
    return records
