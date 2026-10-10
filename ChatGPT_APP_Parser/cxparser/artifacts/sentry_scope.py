"""Sentry scope_v3.json 파서 — 채팅 모드의 서버 요청·UI 이벤트 breadcrumb.

앱(Electron)은 오류 보고용으로 `…\\Packages\\OpenAI.Codex_…\\LocalCache\\Roaming\\Codex\\web\\Codex\\sentry\\scope_v3.json`
에 최근 breadcrumb 를 남긴다. 메인 프로세스의 HTTP 요청(category `electron.net`: method·url·status_code, 본문 없음)과
렌더러의 UI 이벤트(`ui.click`·`ui.input`: DOM 선택자만). 채팅 모드 대화 본문은 로컬 어디에도 남지 않으므로
(응답은 캐시 금지, 요청 본문 미기록) 이 파일로는 "언제 보냈는가" 만 안다. 링 버퍼라 최근 100개 안팎만 남는다.

  E04-01 사용자 프롬프트 입력/전송 : POST /backend-api/sentinel/chat-requirements (전송 직전 검사, 전송마다 1회) 뒤
                                     PAIR_WINDOW_SEC 안에 POST /backend-api/f/conversation (전송 요청) 이 오면 확인,
                                     검사 요청만 있으면 추정. 시각은 전송 요청 시각.
  E03-01 새로운 대화 생성          : POST /backend-api/conversation/init — 새 대화 창을 열 때 보내는 요청.
                                     앱 시작 직후에도 올 수 있어 추정.
  NA-00                            : breadcrumb 보존 구간·요청 요약 (분석자가 "이 파일이 덮는 시간" 을 알게).

검증(2026-10-11, 해킹 가상 시나리오 E01): 정답지 전송 00:19:03·00:20:37 ↔ 전송 요청 00:19:02·00:20:35.
"""

import json
import re
from datetime import datetime, timezone

from .. import events, model

ARTIFACT = "sentry_scope"
PAIR_WINDOW_SEC = 10        # ponytail: 표본에서 검사→전송 1~2초. 재시도까지 봐도 10초면 충분, 표본 늘면 조정
_SEND_CHECK = re.compile(r"^/backend-api/sentinel/chat-requirements(?:/prepare)?/?$")   # 전송 직전 검사 (…/prepare 가 먼저 옴)
_SEND = re.compile(r"^/backend-api/(?:f/)?conversation/?$")                              # 전송 요청. …/conversation/prepare 는 준비 단계라 제외
_NEW_CONV = re.compile(r"^/backend-api/conversation/init/?$")
_URL = re.compile(r"https?://([^/?#]+)(/[^?#]*)?")


def _utc(ts):
    try:
        t = float(ts)
    except (TypeError, ValueError):
        return None
    if t > 1e11:                      # 밀리초
        t /= 1000.0
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _secs(utc):
    return datetime.fromisoformat(utc.replace("Z", "+00:00")).timestamp()


def http_events(breadcrumbs):
    """[(index, utc, METHOD, host, path, status)] 시각순. url 없는 항목(잘린 breadcrumb)은 뺀다."""
    out = []
    for i, b in enumerate(breadcrumbs or ()):
        if b.get("category") != "electron.net" and b.get("type") != "http":
            continue
        d = b.get("data") or {}
        m = _URL.match(str(d.get("url") or ""))
        utc = _utc(b.get("timestamp"))
        if not m or not utc:
            continue
        out.append((i, utc, str(d.get("method") or "").upper(), m.group(1), m.group(2) or "/", d.get("status_code")))
    out.sort(key=lambda e: (e[1], e[0]))
    return out


def sends(http):
    """전송 판정 — 전송 요청(POST …/f/conversation)마다 1건, 그 앞 PAIR_WINDOW_SEC 안의 검사 요청(chat-requirements)을 짝으로.
    짝이 없는 검사 요청(전송 요청이 버퍼에서 잘린 경우)도 1건으로 남긴다. 반환 [(check_or_None, send_or_None)] 시각순."""
    checks = [e for e in http if e[2] == "POST" and _SEND_CHECK.match(e[4])]
    used, out = set(), []
    for s in (e for e in http if e[2] == "POST" and _SEND.match(e[4])):
        c = next((c for c in reversed(checks) if c[0] not in used and 0 <= _secs(s[1]) - _secs(c[1]) <= PAIR_WINDOW_SEC), None)
        if c:
            used.add(c[0])
        out.append((c, s))
    out += [(c, None) for c in checks if c[0] not in used]
    return sorted(out, key=lambda p: (p[1] or p[0])[1])


def _ui_inputs(breadcrumbs):
    return sorted(u for u in (_utc(b.get("timestamp")) for b in breadcrumbs or () if b.get("category") == "ui.input") if u)


def parse(vfile, image_desc, rb, max_excerpt=500):
    records = []
    try:
        data = json.loads(vfile.read().decode("utf-8", "replace"))
        bc = (data.get("scope") or {}).get("breadcrumbs") or []
    except Exception as exc:  # noqa: BLE001   잘린 파일(쓰다 만 JSON)도 흔하다 — 오류 기록만 남기고 끝
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="scope_v3.json 파싱 실패"),
            model.user_action(observed="Sentry scope 파일 존재하나 JSON 으로 읽지 못함 (쓰다 만 파일로 추정)"),
            model.evidence(image_desc, vfile, locator="file"),
            status="error", errors=[{"code": "JSON_PARSE_FAILED", "message": str(exc)[:200]}],
            details={"artifact": ARTIFACT}))
        return records

    http = http_events(bc)
    inputs = _ui_inputs(bc)
    stamps = sorted(u for u in (_utc(b.get("timestamp")) for b in bc) if u)
    sha = vfile.sha256()
    note_nobody = "breadcrumb 에는 요청 메서드·경로·상태코드만 있고 본문·첨부 파일명은 없다"

    pairs = sends(http)
    send_times = [(s or c)[1] for c, s in pairs]
    inits = [e for e in http if e[2] == "POST" and _NEW_CONV.match(e[4])]
    for n, ev in enumerate(inits):
        # init 은 새 대화 창을 열 때만이 아니라 파일 내려받기·앱 종료 때도 온다(기업유출 이미지: 4건 모두 새 대화 아님).
        # 다음 init 전에 실제 전송이 이어진 것만 새 대화 생성으로 보고, 나머지는 관찰로만 남긴다.
        nxt = inits[n + 1][1] if n + 1 < len(inits) else "9"
        followed = any(ev[1] < t < nxt for t in send_times)
        ts = model.timestamp(utc=ev[1], original=ev[1], fmt="epoch_seconds",
                             meaning="앱 메인 프로세스가 기록한 서버 요청 시각 (Sentry breadcrumb)", source=model.TS_SOURCE_CONTENT)
        ev_loc = model.evidence(image_desc, vfile, locator="json_pointer=/scope/breadcrumbs/%d" % ev[0], artifact_sha256=sha)
        det = {"artifact": ARTIFACT, "request_path": ev[4], "status_code": ev[5], "followed_by_send": followed}
        if followed:
            records.append(model.Record(
                rb.next_id(), "E03-01", events.name("E03-01"), ts,
                model.user_action(action="새 대화 창 열기 요청", confidence=model.CONF_INFERRED,
                                  rationale="POST /backend-api/conversation/init 뒤 다음 init 전에 프롬프트 전송이 이어짐. "
                                            "init 만으로는 새 대화를 확정하지 않는다(내려받기·종료 때도 오는 요청)",
                                  observed="POST %s → %s" % (ev[4], ev[5])),
                ev_loc, notes=[note_nobody], details=det))
        else:
            records.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"), ts,
                model.user_action(observed="POST %s → %s (이어진 전송 없음 — 새 대화로 보지 않음)" % (ev[4], ev[5])),
                ev_loc, details=det))

    prev = None
    for check, send in pairs:
        at = send or check
        span = [u for u in inputs if (prev is None or u > prev) and u <= at[1]]
        confirmed = send is not None and check is not None
        details = {"artifact": ARTIFACT, "check_request_utc": check[1] if check else None, "send_request_utc": send[1] if send else None,
                   "request_path": at[4], "status_code": at[5], "input_events": len(span),
                   "input_span_utc": [span[0], span[-1]] if span else None}
        records.append(model.Record(
            rb.next_id(), "E04-01", events.name("E04-01"),
            model.timestamp(utc=at[1], original=at[1], fmt="epoch_seconds",
                            meaning="앱 메인 프로세스가 기록한 %s 요청 시각 (Sentry breadcrumb)" % ("전송" if confirmed else "전송 직전 검사"),
                            source=model.TS_SOURCE_CONTENT),
            model.user_action(
                action="프롬프트 전송(서버 요청)" if send else "프롬프트 전송 직전 검사 요청",
                confidence=model.CONF_CONFIRMED if confirmed else model.CONF_INFERRED,
                rationale=("전송 직전 검사 POST sentinel/chat-requirements 뒤 %d초 안에 전송 요청 POST %s 가 응답 %s 로 기록됨"
                           % (PAIR_WINDOW_SEC, at[4], at[5])) if confirmed else
                          ("전송 요청만 있고 앞선 검사 요청이 breadcrumb 에 없음 (재요청이거나 버퍼에서 잘림)" if send else
                           "검사 요청만 남고 전송 요청이 breadcrumb 에 없음 (잘렸거나 전송 취소)"),
                observed="POST %s → %s%s" % (at[4], at[5], (", 직전 입력창 입력 %d회" % len(span)) if span else "")),
            model.evidence(image_desc, vfile, locator="json_pointer=/scope/breadcrumbs/%d" % at[0], artifact_sha256=sha),
            notes=[note_nobody],
            details=details))
        prev = at[1]

    if stamps:
        paths = {}
        for e in http:
            paths[e[2] + " " + e[4]] = paths.get(e[2] + " " + e[4], 0) + 1
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=stamps[0], original=stamps[0], fmt="epoch_seconds",
                            meaning="breadcrumb 보존 구간의 첫 시각", source=model.TS_SOURCE_CONTENT),
            model.user_action(observed="Sentry breadcrumb %d건 보존 (%s ~ %s UTC): HTTP %d, UI 입력 %d. 링 버퍼라 최근 활동만 남는다"
                              % (len(bc), stamps[0][:19], stamps[-1][:19], len(http), len(inputs))),
            model.evidence(image_desc, vfile, locator="json_pointer=/scope/breadcrumbs", artifact_sha256=sha),
            details={"artifact": ARTIFACT, "breadcrumbs": len(bc), "span_utc": [stamps[0], stamps[-1]],
                     "request_counts": dict(sorted(paths.items(), key=lambda kv: -kv[1])[:40])}))
    return records


if __name__ == "__main__":  # python -m cxparser.artifacts.sentry_scope — 전송 판정 자체 검사
    import hashlib

    class _F:
        path, size, allocated, mft_record = "/x/sentry/scope_v3.json", 0, True, None

        def __init__(self, raw):
            self._raw = raw

        def read(self):
            return self._raw

        def sha256(self):
            return hashlib.sha256(self._raw).hexdigest()

        def location(self):
            return {"path": self.path}

    def _b(t, method, path, cat="electron.net"):
        return {"timestamp": t, "category": cat, "type": "http", "data": {"url": "https://chatgpt.com" + path, "method": method, "status_code": 200}}

    t0 = 1_790_000_000.0
    bc = [_b(t0 + 60, "POST", "/backend-api/f/conversation"),          # 검사 없이 온 전송 요청 → 추정
          _b(t0, "POST", "/backend-api/conversation/init"),
          _b(t0 + 9, "POST", "/backend-api/sentinel/chat-requirements/prepare"),
          _b(t0 + 10, "POST", "/backend-api/f/conversation/prepare"),   # 준비 단계 — 전송으로 세지 않음
          _b(t0 + 11, "POST", "/backend-api/f/conversation"),           # 검사 2초 뒤 전송 → 확인
          _b(t0 + 100, "POST", "/backend-api/sentinel/chat-requirements"),   # 전송 요청 없음 → 추정
          _b(t0 + 150, "POST", "/backend-api/conversation/init"),           # 이어진 전송 없음 → NA-00 관찰
          {"timestamp": t0 + 5, "category": "ui.input", "message": "div.x"},
          {"timestamp": t0 + 90, "category": "ui.input", "message": "div.x"},
          {"timestamp": t0 + 200, "category": "electron.net", "data": {"url": None}}]       # url 잘린 항목은 무시
    recs = parse(_F(json.dumps({"scope": {"breadcrumbs": bc}}).encode()), {"image_id": "t"}, model.RecordBuilder())
    kinds = [(r["event"]["event_id"], r["user_action"]["confidence"]) for r in recs]
    assert kinds == [("E03-01", "추정"), ("NA-00", "미확정"), ("E04-01", "확인"), ("E04-01", "추정"), ("E04-01", "추정"), ("NA-00", "미확정")], kinds
    assert recs[0]["details"]["followed_by_send"] is True and recs[1]["details"]["followed_by_send"] is False
    assert recs[2]["timestamp"]["utc"] == _utc(t0 + 11) and recs[2]["details"]["input_events"] == 1
    assert recs[3]["timestamp"]["utc"] == _utc(t0 + 60) and recs[3]["details"]["input_events"] == 0 and recs[3]["details"]["check_request_utc"] is None
    assert recs[4]["details"]["input_events"] == 1 and recs[4]["details"]["send_request_utc"] is None
    assert recs[5]["details"]["request_counts"]["POST /backend-api/f/conversation"] == 2
    bad = parse(_F(b'{"scope": {"breadcrumbs": [tru'), {"image_id": "t"}, model.RecordBuilder())
    assert len(bad) == 1 and bad[0]["parse"]["status"] == "error" and bad[0]["event"]["event_id"] == "NA-00"
    print("sentry_scope self-check ok")
