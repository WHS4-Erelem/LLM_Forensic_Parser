"""앱 로그 — 로그인·로그아웃·계정 전환·실행·종료.

패키지 폴더 밖(%LOCALAPPDATA%\\Claude\\logs)에 있어 앱을 지워도 남는다.
시간대 표시가 없는 현지시각이라, 파일 수정시각(UTC)과 마지막 줄을 견줘
오프셋을 추정해 환산한다. 추정 사실은 레코드에 남긴다.
"""

import re

from .. import events, model
from ..util import excerpt

# 2026-09-23 04:04:20  /  2026/09/23 04:04:20.123456
_TS = re.compile(r"(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?")

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

# (정규식, event_id, 행위, 확신도)
RULES = [
    (re.compile(r"Login-state transition.*?loggedOut:\s*true\s*(?:->|→)\s*false", re.I),
     "E01-01", "로그인", model.CONF_CONFIRMED),
    (re.compile(r"Login-state transition.*?loggedOut:\s*false\s*(?:->|→)\s*true", re.I),
     "E01-02", "로그아웃", model.CONF_CONFIRMED),
    (re.compile(r"beforeQuit|Shutdown signal received|going down", re.I),
     "E08-02", "정상 종료", model.CONF_INFERRED),
    (re.compile(r"app (?:started|ready)|Starting Claude|main window created", re.I),
     "E08-01", "애플리케이션 실행", model.CONF_INFERRED),
]

# 계정 전환: 한 줄에 이전 계정과 새 계정이 함께 적힌다
_SWITCH = re.compile(r"uuid:\s*(" + _UUID + r")\s*(?:->|→)\s*(" + _UUID + r")", re.I)
# 로그인 줄의 계정 (<none> -> uuid)
_LOGIN_UUID = re.compile(r"uuid:\s*(?:<none>|null)\s*(?:->|→)\s*(" + _UUID + r")", re.I)
_ACCOUNT = re.compile(r"account[_ ]?id\s*[:=]\s*[\"']?(" + _UUID + r")", re.I)
_ORG = re.compile(r"org[_ ]?id\s*[:=]\s*[\"']?(" + _UUID + r")", re.I)


def _offset_hours(lines, mtime_utc):
    """로그 마지막 줄과 파일 수정시각의 차이로 시간대를 추정한다."""
    if not mtime_utc:
        return None
    last = None
    for ln in reversed(lines):
        m = _TS.search(ln)
        if m:
            last = m
            break
    if last is None:
        return None
    from datetime import datetime, timezone
    naive = datetime(*(int(last.group(i)) for i in range(1, 7)))
    try:
        mt = datetime.fromisoformat(mtime_utc.replace("Z", "+00:00"))
    except ValueError:
        return None
    diff = (naive.replace(tzinfo=timezone.utc) - mt).total_seconds() / 3600.0
    step = round(diff * 4) / 4.0            # 15분 단위로 맞춘다
    return step if -14.0 <= step <= 14.0 else None


def _to_utc(m, off_hours):
    from datetime import datetime, timedelta, timezone
    frac = m.group(7) or ""
    micro = int(round(float(frac) * 1e6)) if frac else 0
    dt = datetime(*(int(m.group(i)) for i in range(1, 7)), micro, tzinfo=timezone.utc)
    if off_hours:
        dt -= timedelta(hours=off_hours)
    return dt.isoformat().replace("+00:00", "Z")


def parse(vfile, image, rb, max_excerpt=500):
    raw = vfile.read()
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    mtime = (vfile.si_times or {}).get("modified") or (vfile.fn_times or {}).get("modified")
    off = _offset_hours(lines, mtime)
    tz_note = ("로그에 시간대 표시가 없어 파일 수정시각과 대조해 UTC%+g 로 추정 환산"
               % off) if off is not None else "시간대 표시 없음 — 원문 그대로"

    out = []
    for i, ln in enumerate(lines, 1):
        if len(ln) > 4000:
            ln = ln[:4000]
        tm = _TS.search(ln)
        utc = _to_utc(tm, off) if tm else None
        det = {"artifact": "applog", "log_body": ln.strip(), "file": vfile.path}
        a = _ACCOUNT.search(ln)
        o = _ORG.search(ln)
        if a:
            det["account_uuid"] = a.group(1)
        if o:
            det["org_uuid"] = o.group(1)

        sw = _SWITCH.search(ln)
        matched = None
        if sw and "login-state" in ln.lower():
            det["account_uuid"] = sw.group(2)
            det["previous_account_uuid"] = sw.group(1)
            matched = ("E01-03", "계정 전환", model.CONF_CONFIRMED)
        else:
            lg = _LOGIN_UUID.search(ln)
            if lg:
                det["account_uuid"] = lg.group(1)
            for rx, eid, act, conf in RULES:
                if rx.search(ln):
                    matched = (eid, act, conf)
                    break
        if matched is None:
            continue
        eid, act, conf = matched
        ts = model.timestamp(utc=utc, original=tm.group(0) if tm else None,
                             fmt="local_naive", meaning="로그 기록 시각",
                             source=model.TS_SOURCE_CONTENT, tz_note=tz_note,
                             null_reason=None if utc else "줄에서 시각을 찾지 못함")
        out.append(model.Record(
            rb.next_id(), eid, events.name(eid), ts,
            model.user_action(act, conf, rationale="앱 로그 기록"),
            model.evidence(image, vfile, locator="line=%d" % i,
                           excerpt=excerpt(ln, max_excerpt)),
            details=det))
    return out
