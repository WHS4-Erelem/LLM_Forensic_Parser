"""파생 규칙 — 이미 파싱된 레코드들을 서로 대조해 행위를 올린다 (2026-09-23, 1단계).

관찰(NA-00)로만 남던 근거가 맞물리면 새 레코드를 덧붙인다. 원본 레코드는 건드리지 않는다.
  E01-01 로그인    : 앱 로그 'Reloaded auth, changed: true' + USN auth.json FILE_CREATE 가 ±120s 안 → 확인.
                     둘 중 하나만 있으면 추정 (토큰 갱신일 수도 있음).
  E01-03 계정 전환 : USN auth.json FILE_DELETE 뒤 FILE_CREATE 가 있고 전역 상태에 계정 UUID 가 2개 이상 → 추정 (재생성 시각).
                     UUID 가 1개면 같은 계정 재로그인이라 만들지 않는다.
  E05-01/E05-03    : 프롬프트 본문의 '# Files mentioned by the user:' 목록 → 파일마다 이미지/문서 업로드 추정 (프롬프트 시각).
                     같은 파일이 rollout·SQLite·global-state 에 반복되므로 (행위, 파일명) 당 1건, 시각 있는 쪽 우선.
근거 레코드 ID 는 details.derived_from 에 남긴다.
"""

import copy
import re
from datetime import datetime

from . import events, model

LOGIN_WINDOW_SEC = 120
AUTH_CHANGED = "Reloaded auth, changed: true"
_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".tif", ".tiff", ".svg"}
_FILES_HEADER = "# Files mentioned by the user"
# '## <파일명>: <경로>' 줄만. 경로는 'C:/…' 'C:\…' '/…' 어느 표기든 (표본: C:/Users/에레렘/Downloads/x.png). 경로 없는 '## My request:' 는 제목 줄이라 제외
_FILE_LINE_RE = re.compile(r"^##\s+(?P<name>[^\r\n:]+?)\s*:\s*(?P<path>[A-Za-z]:[\\/][^\r\n]*|/[^\r\n]*)\s*$", re.M)


def _det(r):
    return r.get("details") or {}


def _utc(r):
    return (r.get("timestamp") or {}).get("utc")


def _secs(utc):
    return datetime.fromisoformat(utc.replace("Z", "+00:00")).timestamp()


def _is_usn_auth(r, reason):
    d = _det(r)
    return d.get("artifact") == "usn_journal" and (d.get("file_name") or "").lower() == "auth.json" and d.get("key_reason") == reason


def _new(rb, event_id, src, ts, action, details, notes=None):
    ev = copy.deepcopy(src.get("evidence") or {})
    return model.Record(rb.next_id(), event_id, events.name(event_id), ts, action, ev,
                        status="ok", notes=notes or [], details=details)


def _login(records, rb):
    out = []
    logs = [r for r in records if _utc(r) and AUTH_CHANGED in str(_det(r).get("log_body") or r["user_action"].get("observed_artifact") or "")]
    creates = [r for r in records if _utc(r) and _is_usn_auth(r, "FILE_CREATE")]
    used = set()
    for lg in logs:
        near = [u for u in creates if abs(_secs(_utc(u)) - _secs(_utc(lg))) <= LOGIN_WINDOW_SEC]
        if near:
            u = min(near, key=lambda x: abs(_secs(_utc(x)) - _secs(_utc(lg))))
            used.add(u["record_id"])
            gap = _secs(_utc(lg)) - _secs(_utc(u))
            act = model.user_action(action="로그인", confidence=model.CONF_CONFIRMED,
                                    rationale=("앱 로그 '%s' 와 USN auth.json FILE_CREATE 가 %.0f초 차이로 맞물림 — "
                                               "인증 파일이 새로 만들어지고 앱이 인증 상태 변경을 인식한 시각 (분석표 E01-01)") % (AUTH_CHANGED, gap))
            src, derived = lg, [lg["record_id"], u["record_id"]]
        else:
            act = model.user_action(action="로그인(인증 상태 변경 로그)", confidence=model.CONF_INFERRED,
                                    rationale=("앱 로그 '%s' 만 있음 — USN auth.json 생성 기록이 없어(저널 순환 등) "
                                               "로그인과 토큰 갱신을 구분하지 못함") % AUTH_CHANGED)
            src, derived = lg, [lg["record_id"]]
        ts = copy.deepcopy(lg["timestamp"])
        ts["meaning"] = "앱 로그에 인증 상태 변경이 기록된 시각"
        out.append(_new(rb, "E01-01", src, ts, act,
                        {"artifact": _det(src).get("artifact"), "key": "auth_changed", "derived_from": derived}))
    for u in creates:
        if u["record_id"] in used:
            continue
        ts = copy.deepcopy(u["timestamp"])
        ts["meaning"] = "USN 저널의 auth.json 생성 시각"
        out.append(_new(rb, "E01-01", u, ts,
                        model.user_action(action="로그인(auth.json 생성)", confidence=model.CONF_INFERRED,
                                          rationale="USN auth.json FILE_CREATE 만 있음 — 앱 로그 대조 없이는 재발급과 구분하지 못함"),
                        {"artifact": "usn_journal", "file_name": "auth.json", "derived_from": [u["record_id"]]}))
    return out


def _account_switch(records, rb):
    accounts = next((r for r in records if r["event"]["event_id"] == "E01-03" and _det(r).get("artifact") == "codex_global_state"), None)
    if accounts is None:                                            # 전역 상태에 계정 UUID 가 2개 이상일 때만 만들어지는 레코드
        return []
    deletes = sorted((r for r in records if _utc(r) and _is_usn_auth(r, "FILE_DELETE")), key=_utc)
    creates = sorted((r for r in records if _utc(r) and _is_usn_auth(r, "FILE_CREATE")), key=_utc)
    out = []
    for d in deletes:
        c = next((c for c in creates if _secs(_utc(c)) > _secs(_utc(d))), None)
        if c is None:
            continue
        creates.remove(c)
        ts = copy.deepcopy(c["timestamp"])
        ts["meaning"] = "로그아웃(auth.json 삭제) 뒤 auth.json 이 다시 만들어진 시각"
        out.append(_new(rb, "E01-03", c, ts,
                        model.user_action(action="계정 전환(auth.json 재생성)", confidence=model.CONF_INFERRED,
                                          rationale=("USN auth.json FILE_DELETE(%s) 뒤 FILE_CREATE + 전역 상태에 계정 UUID 2개 이상 — "
                                                     "다른 계정으로 다시 로그인한 흔적. 같은 계정 재로그인이면 UUID 가 1개라 만들지 않음")
                                          % _utc(d)[:19]),
                        {"artifact": "usn_journal", "file_name": "auth.json",
                         "accounts": accounts["user_action"].get("observed_artifact"),
                         "derived_from": [d["record_id"], c["record_id"], accounts["record_id"]]}))
    return out


def _uploads(records, rb):
    picked = {}                                                     # (event_id, 파일명 소문자) -> (시각 있음?, src, name, path)
    for r in records:
        if r["event"]["event_id"] != "E04-01":
            continue
        text = str(_det(r).get("text") or _det(r).get("prompt_text") or "")
        if _FILES_HEADER not in text:
            continue
        for m in _FILE_LINE_RE.finditer(text[text.index(_FILES_HEADER):]):
            name = m.group("name").strip()
            ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            eid = "E05-01" if ext in _IMAGE_EXT else "E05-03"
            key = (eid, name.lower())
            cand = (bool(_utc(r)), r, name, m.group("path"))
            if key not in picked or (cand[0] and not picked[key][0]):
                picked[key] = cand
    out = []
    for (eid, _), (_, src, name, path) in picked.items():
        ts = copy.deepcopy(src["timestamp"])
        if ts.get("utc"):
            ts["meaning"] = "첨부가 언급된 프롬프트의 전송 시각 (업로드 동작 자체의 시각은 아님)"
        out.append(_new(rb, eid, src, ts,
                        model.user_action(action="첨부 파일 업로드 흔적", confidence=model.CONF_INFERRED,
                                          rationale=("프롬프트 본문의 '%s' 목록에 파일명이 있음 — 앱이 첨부 파일을 프롬프트에 "
                                                     "적어 보낸 흔적 (분석표 E05). 파일 실물·해시는 확인하지 않음") % _FILES_HEADER),
                        {"artifact": _det(src).get("artifact"), "file_name": name, "file_path": path,
                         "derived_from": [src["record_id"]]}))
    return out


SESSION_MARGIN_SEC = 120


def _demote_saves_outside_sessions(records):
    """최근 항목 바로가기로 추정한 문서 저장(E05-05)은 앱 프로세스 구간(E08-01 시작~E08-02 끝, ±120s) 안에 있을 때만 유지.
    구간 밖이면 다른 프로그램이 저장한 문서일 가능성이 커 미확정으로 내린다 (레코드는 남기고 판정만 바꿈).
    로그가 없어 구간을 전혀 모르면 그대로 둔다."""
    spans = []
    for r in records:
        d = _det(r)
        if d.get("artifact") == "codex_sqlite" and d.get("session_first_utc") and d.get("session_last_utc") and r["event"]["event_id"] == "E08-01":
            spans.append((_secs(d["session_first_utc"]) - SESSION_MARGIN_SEC, _secs(d["session_last_utc"]) + SESSION_MARGIN_SEC))
    # Codex 가 다룬 파일명 모음: 프롬프트·응답·도구 호출 본문에 나온 이름만 Codex 의 저장으로 본다.
    # (표본 2026-09-23: Claude Desktop 이 내려받은 PDF 가 Codex 실행 구간 안이라 오귀속됨 → 언급 검사 추가)
    corpus = " ".join(str(v).lower() for r in records for v in (
        _det(r).get("text"), _det(r).get("prompt_text"), r["user_action"].get("observed_artifact"),
        (r.get("evidence") or {}).get("excerpt")) if v)
    for r in records:
        if r["event"]["event_id"] == "E05-05" and _det(r).get("artifact") == "recent_lnk" and _utc(r):
            t = _secs(_utc(r))
            stem = str(_det(r).get("file_name") or "").rsplit(".", 1)[0].lower()
            why = None
            if spans and not any(a <= t <= b for a, b in spans):
                why = "앱 로그 프로세스 구간(±%ds) 밖" % SESSION_MARGIN_SEC
            elif stem and stem not in corpus:
                why = "Codex 대화·도구 호출 어디에도 파일명이 없음 — 다른 프로그램이 저장한 문서일 수 있음"
            if why:
                r["user_action"]["confidence"] = model.CONF_UNKNOWN
                r["user_action"]["rationale"] = (r["user_action"].get("rationale") or "") + " — %s → 미확정" % why
                r["parse"]["notes"].append(why + " → 미확정")
            elif stem:
                r["user_action"]["rationale"] = (r["user_action"].get("rationale") or "") + " — Codex 대화에 같은 파일명이 언급됨"


def derive(records, rb):
    """records 를 읽어 파생 레코드 목록을 돌려준다 (호출 쪽에서 extend). 판정 조정은 제자리에서 한다."""
    _demote_saves_outside_sessions(records)
    return _login(records, rb) + _account_switch(records, rb) + _uploads(records, rb)


if __name__ == "__main__":  # python -m cxparser.derive — 자체 검사
    def rec(rid, eid, utc, details, observed=None):
        return {"record_id": rid, "event": {"event_id": eid}, "timestamp": {"utc": utc},
                "user_action": {"observed_artifact": observed}, "evidence": {"location": {"path": "x"}}, "details": details}
    rb = model.RecordBuilder("D")
    recs = [
        rec("L1", "NA-00", "2026-09-15T04:15:45Z", {"artifact": "codex_sqlite", "log_body": AUTH_CHANGED}),
        rec("U1", "NA-00", "2026-09-15T04:15:38Z", {"artifact": "usn_journal", "file_name": "auth.json", "key_reason": "FILE_CREATE"}),
        rec("U2", "NA-00", "2026-09-15T04:46:26Z", {"artifact": "usn_journal", "file_name": "auth.json", "key_reason": "FILE_DELETE"}),
        rec("U3", "NA-00", "2026-09-15T04:50:00Z", {"artifact": "usn_journal", "file_name": "auth.json", "key_reason": "FILE_CREATE"}),
        rec("A1", "E01-03", None, {"artifact": "codex_global_state"}, observed="계정 UUID 2개: a, b"),
        rec("P1", "E04-01", "2026-09-15T04:38:02Z", {"artifact": "rollout_jsonl",
            "text": "# Files mentioned by the user:\n## dog.png: C:\\Users\\a\\dog.png\n## 2019] 알기사 필기1(191224-수정).pdf: C:\\x\\a.pdf\n\n설명해줘"}),
        rec("P2", "E04-01", None, {"artifact": "codex_global_state", "prompt_text": "# Files mentioned by the user:\n## dog.png: C:\\Users\\a\\dog.png"}),
    ]
    out = derive(recs, rb)
    got = sorted((r["event"]["event_id"], r["user_action"]["confidence"], (r["timestamp"].get("utc") or "-")[11:19], r["details"].get("file_name") or "") for r in out)
    assert got == [("E01-01", "추정", "04:50:00", "auth.json"),        # U3: 로그 없는 생성 → 추정
                   ("E01-01", "확인", "04:15:45", ""),                 # L1+U1 7초 차 → 확인
                   ("E01-03", "추정", "04:50:00", "auth.json"),        # U2 삭제 뒤 U3 생성 + UUID 2개 → 계정 전환
                   ("E05-01", "추정", "04:38:02", "dog.png"),          # P2(시각 없음) 대신 P1 채택, 1건만
                   ("E05-03", "추정", "04:38:02", "2019] 알기사 필기1(191224-수정).pdf")], got
    assert derive([r for r in recs if r["record_id"] != "A1"], model.RecordBuilder("E")) and \
        not [r for r in derive([r for r in recs if r["record_id"] != "A1"], model.RecordBuilder("F")) if r["event"]["event_id"] == "E01-03"]  # UUID 1개면 전환 없음
    print("derive self-check ok")
