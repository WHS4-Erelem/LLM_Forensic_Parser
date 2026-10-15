# -*- coding: utf-8 -*-
"""ARTINEX 표시 언어 검사 — Autopsy 에 들어 있는 Jython 으로 실행한다 (Autopsy 클래스는 가짜로 바꿔 끼운다).

  cd <저장소 루트>
  "C:\\Program Files\\Autopsy-4.23.1\\jre\\bin\\java.exe" -cp "C:\\Program Files\\Autopsy-4.23.1\\autopsy\\modules\\ext\\jython-standalone-2.7.4.jar" ^
      org.python.util.jython Autopsy_Addon/tests/test_language.py [timeline.csv 가 있는 폴더 ...]

폴더를 주면 그 아래 모든 timeline.csv 를 번역해 보고, 증거 값이 보존되는지와 번역되지 않은 앞부분 목록을 출력한다.
"""
import csv
import hashlib
import imp
import json
import os
import re
import shutil
import sys
import tempfile
import types


class _Any(object):
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return _Any()

    def __call__(self, *a, **k):
        return _Any()


for _name in ("org.sleuthkit", "org.sleuthkit.autopsy", "org.sleuthkit.autopsy.casemodule", "org.sleuthkit.autopsy.coreutils",
              "org.sleuthkit.autopsy.datamodel", "org.sleuthkit.autopsy.ingest", "org.sleuthkit.autopsy.ingest.IngestModule",
              "org.sleuthkit.datamodel"):
    _mod = types.ModuleType(_name)
    for _attr in ("Case", "ExecUtil", "Logger", "ContentUtils", "DataSourceIngestModuleProcessTerminator", "IngestMessage",
                  "IngestModule", "IngestServices", "IngestModuleException", "BlackboardArtifact", "BlackboardAttribute",
                  "TimelineEventType", "TskData"):
        setattr(_mod, _attr, _Any())
    _mod.DataSourceIngestModule = _mod.IngestModuleFactoryAdapter = object
    sys.modules[_name] = _mod

HERE = os.path.dirname(__file__) or "."      # 상대 경로 그대로 — Jython abspath 는 한글 경로를 깨뜨린다
m = imp.load_source("artinex_under_test", os.path.join(HERE, "..", "ARTINEX", "ARTINEX.py"))


def sha1(path):
    with open(path, "rb") as fh:                 # Jython 은 닫지 않은 파일을 지울 수 없다
        return hashlib.sha1(fh.read()).hexdigest()


def check_language_setting():
    tmp = tempfile.mkdtemp()
    m.MODULE_DIR = tmp
    try:
        path = os.path.join(tmp, "artinex_config.json")
        assert m.load_config()["language"] == "en", "no config file"
        for value, want in ((None, "en"), ("en", "en"), ("ko", "ko"), (" KO ", "ko"), ("jp", "en"), ("", "en"), (5, "en")):
            cfg = {"python": "python", "repo_root": tmp, "keep_export": True}
            if value is not None:
                cfg["language"] = value
            with open(path, "wb") as fh:
                fh.write(json.dumps(cfg).encode("utf-8"))
            got = m.load_config()
            assert got["language"] == want, (value, got["language"])
            assert got["keep_export"] is True and got["repo_root"] == tmp
    finally:
        shutil.rmtree(tmp)


def check_fixed_cases():
    en = m.detail_en
    cases = (
        (u"사용자 메시지 전송_내 자산이고", u"User message sent_내 자산이고"),                    # 프롬프트 원문은 그대로
        (u"애플리케이션 실행_prefetch_run=1/3", u"Application launch_prefetch_run=1/3"),
        (u"애플리케이션 실행(프로세스 시작)_프로세스 pid:10444:65 (로그 1000줄)",
         u"Application launch (process start)_process pid:10444:65 (1000 log lines)"),
        (u"로그인_계정 5016bc8e-0cbb-4e66-8f23-e4ec1639bb73 / 조직 873368c0-dd15-40b8-b906-75c9163c15a1",
         u"Login_account 5016bc8e-0cbb-4e66-8f23-e4ec1639bb73 / organization 873368c0-dd15-40b8-b906-75c9163c15a1"),
        (u"임시 대화 객체(is_temporary=true)_제목_a", u"Temporary conversation object (is_temporary=true)_제목_a"),
        (u"모델 변경(gpt_5 → gpt-5.1)_x", u"Model change (gpt_5 → gpt-5.1)_x"),
        (u"세션 목록의 최근 로그인 기록_세션 1개", u"Recent login record in session list_1 session(s)"),
        (u"로그인 URL 방문 흔적(인증 완료 미확인)_A → B (7개 방문 레코드)",
         u"Login URL visit trace (authentication completion unconfirmed)_A → B (7 visit records)"),
        (u"계정 전환 흔적_계정 전환 로그 문구", u"Account switch trace_account switch log message"),
        (u"방문기록 삭제 관련 흔적(삭제 실행/범위 추가 검증 필요)",
         u"Browsing history deletion trace (execution/scope needs further verification)"),
        (u"사용자 메시지 전송_실행 로그", u"User message sent_실행 로그"),     # 라벨과 같은 프롬프트도 프롬프트 자리에선 그대로
        (u"프롬프트 전송(서버 요청)_POST /backend-api/f/conversation → 200, 직전 입력창 입력 11회",     # cxparser observed 대체값
         u"Prompt sent (server request)_POST /backend-api/f/conversation → 200, 11 prompt-box inputs just before"),
        (u"문서 저장(새 파일)_최근 항목: 보고서.docx (대상 파일은 2026-10-01T01:02:03 에 이미 존재)",
         u"Document saved (new file)_recent item: 보고서.docx (target file already existed at 2026-10-01T01:02:03)"),
        (u"사용자 메시지 전송_Prefetch 파일 존재: a", u"User message sent_Prefetch 파일 존재: a"),   # 다른 파서 앞부분 뒤에선 그대로
        (u"알 수 없는 문구_값", u"알 수 없는 문구_값"),                     # 번역표 밖은 원문 그대로
        (u"-", u"-"),
    )
    for ko, want in cases:
        assert en(ko) == want, (ko.encode("utf-8"), en(ko).encode("utf-8"))
    row = {"Model": u"claude-web", "Timestamp": u"2026-10-01 10:00:00.000000 KST", "User_behavior": u"로그인",
           "Behavior_details": u"로그아웃 URL 방문_https://claude.ai/logout", "Verdict": u"의심",
           "Artifact_path": u"C:\\Users\\u\\History", "Artifact_details": u"[History] 방문 기록 확인"}
    assert m.display_row(row, "ko") == row
    d = m.display_row(row, "en")
    assert (d["User_behavior"], d["Verdict"]) == (u"Login", u"Suspected")
    assert d["Behavior_details"] == u"Logout URL visit_https://claude.ai/logout"
    assert all(d[k] == row[k] for k in ("Model", "Timestamp", "Artifact_path"))
    assert d["Artifact_details"] == u"[History] visit record confirmed"
    row2 = dict(row, Behavior_details=u"로그아웃 URL 방문_[민감정보 비노출]", Artifact_details=u"이벤트=[바이너리 데이터 비노출], MFT=12")
    d = m.display_row(row2, "en")
    assert d["Behavior_details"] == u"Logout URL visit_[sensitive data redacted]", d["Behavior_details"].encode("utf-8")
    assert d["Artifact_details"].startswith(u"Event=[binary data redacted]"), d["Artifact_details"].encode("utf-8")
    assert m.display_row(row2, "ko") == row2
    ad = m.artifact_en
    ad_cases = (
        (u"[WebCache] 유형=conversation, 대화 제목=고객 안내문 다듬기, MFT=203169, 중복 병합=global-state prompt-history 에도 기록 (1건, 삭제된 이전 버전 포함), 규칙=E04-01",
         u"[WebCache] Type=conversation, Conversation title=고객 안내문 다듬기, MFT=203169, Merged duplicates=also recorded in "
         u"global-state prompt-history (1, including deleted earlier versions), Rule=E04-01"),
        (u"[Cache] 대화 ID=6abf, 파일명=에레렘_장애로그.pdf, 파일 형식=application/pdf, 응답 데이터 확인 | [Local Storage] 계정 세션=1개, 저장 값 확인",
         u"[Cache] Conversation ID=6abf, File name=에레렘_장애로그.pdf, File type=application/pdf, response data confirmed | "
         u"[Local Storage] Account sessions=1, stored value confirmed"),
        (u"[$UsnJrnl] 대상=삭제, 이벤트=삭제, 위치=offset 0x9d6ea90, 동일 근거=3건",       # 대상(파일명) 자리의 '삭제' 는 그대로
         u"[$UsnJrnl] Target=삭제, Event=deleted, Location=offset 0x9d6ea90, Same evidence=3"),
        (u"[IndexedDB] 초안 store:chat-draft:[uuid] 저장 6회 2026-10-02 12:06:25~12:07:01, 최종 58자\n[History] 2026-10-02 12:04:08 방문 claude.ai/chat/[uuid] (장애 로그 분석 - Claude)",
         u"[IndexedDB] draft store:chat-draft:[uuid] saved 6 times 2026-10-02 12:06:25~12:07:01, final 58 chars\n"
         u"[History] 2026-10-02 12:04:08 visit claude.ai/chat/[uuid] (장애 로그 분석 - Claude)"),
        (u"[SQLite] 중복 병합=Prefetch 실행 기록 2026-10-02 11:38:00 와 일치; Prefetch 실행 기록 2026-10-02 11:38:21 와 일",   # 파서가 자른 끝은 그대로
         u"[SQLite] Merged duplicates=matches Prefetch run record 2026-10-02 11:38:00; matches Prefetch run record 2026-10-02 11:38:21…"),
        (u"[Prefetch] 중복 병합=같은 실행의 다른 프로세스 Prefetch 11:35:35; 같은 실행의 다른 프로세스 Pre, 규칙=E08-01",
         u"[Prefetch] Merged duplicates=Prefetch of another process in the same run 11:35:35; "
         u"Prefetch of another process in the same run…, Rule=E08-01"),
        (u"-", u"-"),
    )
    for ko, want in ad_cases:
        assert ad(ko) == want, (ko.encode("utf-8"), ad(ko).encode("utf-8"))


def check_post_results():
    """post_results 를 가짜 Blackboard 로 돌려 Autopsy 에 올라가는 값을 본다 (영어: 번역, 한국어: 원문, 둘 다 증거 값 보존)."""
    tl_rows = [[u"Model", u"Timestamp", u"User_behavior", u"Behavior_details ", u"Verdict", u"Artifact_path", u"Artifact_details "],
               [u"claude-web", u"2026-10-01 10:00:00.000000 KST", u"사용자 프롬프트 입력/전송", u"사용자 메시지 전송_안녕 파일 에레렘.pdf",
                u"확정", u"C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\IndexedDB\\x.ldb", u"[IndexedDB] MFT=123 대화 ID"]]
    rc_rows = [m.CONV_HEADER, [u"claude-web", u"2026-10-01 10:00:00.000000 KST", u"c-uuid", u"한국어 제목", u"m-uuid", u"-", u"1",
                               u"user", u"안녕 원문 그대로", u"C:\\Users\\u\\x.ldb"]]
    STD = type("STD", (object,), {"__getattr__": lambda self, n: n})()

    class Attr(tuple):
        TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE = _Any()
        ATTRIBUTE_TYPE = STD

        def __new__(cls, type_, module, value):
            return tuple.__new__(cls, (type_, value))

    class Blackboard(object):
        def getOrAddArtifactType(self, *a):
            return "behavior"

        def getOrAddAttributeType(self, name, *a):
            return name

        def artifactExists(self, *a):
            return False

        def postArtifacts(self, *a):
            pass

    posted = []

    class Source(object):
        def newDataArtifact(self, type_, attrs):
            posted.append(dict(tuple(a) for a in attrs))
            return type_

    bb = Blackboard()
    fake_case = type("Case", (object,), {"getSleuthkitCase": lambda self: type("S", (object,), {"getBlackboard": lambda s: bb})()})()
    m.Case = type("CaseCls", (object,), {"getCurrentCase": staticmethod(lambda: fake_case)})
    m.BlackboardAttribute = Attr
    tmp = tempfile.mkdtemp()
    try:
        for name, rows in (("timeline.csv", tl_rows), ("recovered_conversations.csv", rc_rows)):
            with open(os.path.join(tmp, name), "wb") as fh:
                fh.write("\xef\xbb\xbf")
                csv.writer(fh).writerows([[c.encode("utf-8") for c in r] for r in rows])
        before = [sha1(os.path.join(tmp, n)) for n in ("timeline.csv", "recovered_conversations.csv")]
        p = [x for x in m.PARSERS if x["name"] == "claude_web"][0]
        for lang, behavior, verdict, detail in (("en", u"User prompt input/send", u"Confirmed", u"User message sent_안녕 파일 에레렘.pdf"),
                                                ("ko", tl_rows[1][2], tl_rows[1][4], tl_rows[1][3])):
            del posted[:]
            mod = m.ArtinexIngestModule()
            mod.lang, mod.context = lang, _Any()
            counts = {"behaviors": 0, "timeline_events": 0, "messages": 0, "duplicates": 0, "unlinked": 0}
            mod.post_results(Source(), p, {"views": {"claude_web": tmp}, "by_path": {}, "orig": {}}, tmp, counts)
            beh = [a for a in posted if "ARTINEX_USER_BEHAVIOR" in a][0]
            tl = [a for a in posted if "TSK_DESCRIPTION" in a][0]
            msg = [a for a in posted if "TSK_TEXT" in a][0]
            assert (beh["ARTINEX_USER_BEHAVIOR"], beh["ARTINEX_VERDICT"], beh["ARTINEX_BEHAVIOR_DETAILS"]) == (behavior, verdict, detail), lang
            assert tl["TSK_DESCRIPTION"] == u"[Claude Web] %s (%s): %s" % (behavior, verdict, detail), lang
            for key, col in (("ARTINEX_ARTIFACT_PATH", 5), ("ARTINEX_ARTIFACT_DETAILS", 6), ("ARTINEX_TIMESTAMP", 1), ("ARTINEX_MODEL", 0)):
                assert beh[key] == tl_rows[1][col], (lang, key)
            assert (msg["TSK_TEXT"], msg["TSK_SUBJECT"], msg["TSK_THREAD_ID"]) == (u"안녕 원문 그대로", u"한국어 제목", u"c-uuid"), lang
            assert counts["behaviors"] == counts["timeline_events"] == counts["messages"] == 1, (lang, counts)
        after = [sha1(os.path.join(tmp, n)) for n in ("timeline.csv", "recovered_conversations.csv")]
        assert before == after, "parser CSV changed"
        m.write_display_timeline(os.path.join(tmp, "timeline.csv"), os.path.join(tmp, m.DISPLAY_TIMELINE), "en")
        shown = m.read_rows(os.path.join(tmp, m.DISPLAY_TIMELINE))
        assert shown[0] == tl_rows[0] and shown[1][2:5] == [u"User prompt input/send", u"User message sent_안녕 파일 에레렘.pdf", u"Confirmed"]
        assert m.check_csv(os.path.join(tmp, m.DISPLAY_TIMELINE), m.TIMELINE_HEADER) is None   # 같은 계약 (판정값만 영어)
    finally:
        shutil.rmtree(tmp)


def head_of(value):
    """detail_en 이 고른 앞부분과 나머지 (없으면 None)."""
    for i in [i for i, ch in enumerate(value) if ch == u"_"] + [len(value)]:
        head = value[:i]
        if head in m.DETAIL_HEAD_EN or any(rx.match(head) for rx, _ in m.DETAIL_HEAD_RULES):
            return head, value[i + 1:]
    return None


def check_outputs(roots):
    files = []
    for root in roots:
        for d, _, names in os.walk(root):
            files.extend(os.path.join(d, n) for n in names if n == "timeline.csv")
    rows = done = 0
    left, ad_left = {}, {}
    for path in sorted(files):
        if not m.read_rows(path) or m.check_csv(path, m.TIMELINE_HEADER, verdict=True):
            continue                                   # 병합본 등 파서 계약 밖 파일은 건너뛴다
        before = sha1(path)
        tmp = tempfile.mkdtemp()
        try:
            out = os.path.join(tmp, m.DISPLAY_TIMELINE)
            m.write_display_timeline(path, out, "en")
            src, dst = m.read_rows(path), m.read_rows(out)
            assert src[0] == dst[0] and len(src) == len(dst), path
            for a, b in zip(src[1:], dst[1:]):
                rows += 1
                for i in (0, 1, 5):                    # Model·Timestamp·Artifact_path 는 그대로
                    assert a[i] == b[i], (path, i)
                check_artifact_details(a[6], b[6], ad_left)
                assert b[4] in (u"Confirmed", u"Suspected"), path
                if b[3] != a[3]:
                    done += 1
                    head, tail = head_of(a[3])
                    if tail not in b[3]:                # 바뀐 것은 고정 라벨뿐 — 그 안의 값(그룹)은 남아 있어야 한다
                        hit = [rx.match(tail) for heads, rx, _ in m.DETAIL_CORE_RULES if head in heads and rx.match(tail)]
                        assert hit and all(g in b[3] for g in hit[0].groups()), (path, a[3].encode("utf-8"))
                else:
                    key = a[3].split(u"_", 1)[0]
                    left[key] = left.get(key, 0) + 1
        finally:
            shutil.rmtree(tmp)
        assert sha1(path) == before, "original changed: " + path
    print("timeline files %d, rows %d, Behavior_details translated %d" % (len(files), rows, done))
    for key, n in sorted(left.items()):
        print("  not translated (%d): %s" % (n, key.encode("utf-8")))
    print("Artifact_details items still containing Korean: %d kinds" % len(ad_left))
    for item, n in sorted(ad_left.items()):
        print("  (%d) %s" % (n, item.encode("utf-8")))
    return left


HANGUL = re.compile(u"[가-힣]")
TOKEN = re.compile(u"[^\\s가-힣=,;|()\\[\\]]+")


def check_artifact_details(a, b, left):
    """Artifact_details 번역: 원문의 비한글 토큰(ID·URL·경로·시각·수치)은 모두 남고, 라벨 뒤 증거 값은 그대로 남는다.
    번역 뒤에도 한글이 남은 항목은 left 에 모은다 (제목·파일명 같은 증거 값이면 정상)."""
    assert m.artifact_en(a) == b, a.encode("utf-8")
    rest = b
    for tok in TOKEN.findall(a):                       # 원문 순서대로 찾아 지워 나간다 (같은 토큰이 여러 번 나와도 개수까지 확인)
        i = rest.find(tok)
        assert i >= 0, (tok.encode("utf-8"), a.encode("utf-8"), b.encode("utf-8"))
        rest = rest[:i] + u" " + rest[i + len(tok):]
    for seg in m._AD_SEGMENT.split(a)[::2]:
        body = m._AD_TAG.match(seg).group(2)
        for field in m._ad_split(body)[::2]:
            key, eq, value = field.partition(u"=")
            if (eq and key in m.AD_KEY_EN and m._ad_field(field) == field and m._ad_phrase(body) is None):
                assert value in b, (value.encode("utf-8"), b.encode("utf-8"))   # 번역하지 않은 값은 글자 그대로
    for seg in m._AD_SEGMENT.split(b)[::2]:
        for field in m._ad_split(m._AD_TAG.match(seg).group(2))[::2]:
            if HANGUL.search(field):
                left[field] = left.get(field, 0) + 1


if __name__ == "__main__":
    check_language_setting()
    check_fixed_cases()
    check_post_results()
    left = check_outputs(sys.argv[1:]) if sys.argv[1:] else {}
    hangul = [k for k in left if any(u"\uac00" <= ch <= u"\ud7a3" for ch in k)]
    print("OK" if not hangul else "OK (fixed cases); %d Korean prefixes not in the table" % len(hangul))
