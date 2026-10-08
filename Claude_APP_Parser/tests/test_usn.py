"""USN 저널 — Claude Desktop 기준 선택·판정 검증.

이전 모듈은 ChatGPT Codex 파일 이름(auth.json·rollout-*.jsonl …)을 골라 Claude 결과에
'로그아웃'·'새 대화 생성' 을 만들 수 있었다. 이 시험은
  양성  Claude 폴더 안 첨부 저장·Claude 프리패치·패키지 폴더 -> 기대한 레코드
  음성  Codex 이름·다른 프로그램 프리패치·MFT 재사용(순번 다름) -> 고르지 않음/행위 없음
  중복  같은 프리패치 계보·USN 근거로 다른 행을 확정으로 올리지 않음
  시각  USN 기록 시각을 그대로 (지어내지 않음)
"""

import os
import struct
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import events, model, pipeline, usn  # noqa: E402
from parser.model import RecordBuilder  # noqa: E402

CLAUDE = "/Users/u/AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude"
IDB = CLAUDE + "/IndexedDB"
DIRS = {(100, 3): CLAUDE, (101, 1): IDB,
        (200, 5): "/Windows/Prefetch", (300, 2): "/Program Files/WindowsApps"}
IMAGE = {"image_id": "t"}
LOC = {"path": "/$Extend/$UsnJrnl:$J", "partition_index": 0}
REASON = {name: bit for bit, name in usn.REASONS}


def filetime(iso):
    dt = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10 ** 7)


def rec_v2(name, mft, seq, pmft, pseq, reasons, iso="2026-10-02T03:29:07", directory=False, usn_no=1):
    """USN_RECORD_V2 바이트 하나."""
    nm = name.encode("utf-16-le")
    length = (60 + len(nm) + 7) // 8 * 8
    mask = 0
    for r in reasons:
        mask |= REASON[r]
    body = struct.pack("<IHHQQQqIIIIHH", length, 2, 0, (seq << 48) | mft, (pseq << 48) | pmft,
                       usn_no, filetime(iso), mask, 0, 0, 0x10 if directory else 0x20, len(nm), 60)
    return (body + nm).ljust(length, b"\0")


def select(*raw):
    sel = usn.Selector(DIRS)
    out = []
    for _off, r in usn.iter_records(b"".join(raw)):
        if sel.match(r):
            out.append(r)
    return out


def records(*raw):
    return usn.to_records({}, select(*raw), IMAGE, RecordBuilder(), LOC)


def key(recs, eid=None):
    return [r for r in recs if "key_reason" in r["details"] and (eid is None or r["event"]["event_id"] == eid)]


class Selection(unittest.TestCase):
    def test_parent_must_match_mft_and_sequence(self):
        hits = select(rec_v2("config.json", 500, 1, 100, 3, ["FILE_CREATE"]),
                      rec_v2("dispex.dll", 501, 9, 100, 4, ["FILE_CREATE"]))   # 같은 MFT, 다른 순번 = 재사용
        self.assertEqual([h["name"] for h in hits], ["config.json"])
        self.assertEqual(hits[0]["parent_path"], CLAUDE)

    def test_new_subfolder_is_followed(self):
        hits = select(rec_v2("https_claude.ai_0.indexeddb.blob", 600, 1, 101, 1, ["FILE_CREATE"], directory=True),
                      rec_v2("1", 601, 1, 600, 1, ["FILE_CREATE"], directory=True),
                      rec_v2("2", 602, 1, 601, 1, ["FILE_CREATE"]))
        self.assertEqual(hits[-1]["parent_path"], IDB + "/https_claude.ai_0.indexeddb.blob/1")

    def test_codex_and_other_programs_are_not_selected(self):
        hits = select(rec_v2("auth.json", 700, 1, 999, 1, ["FILE_DELETE"]),          # Codex 로그아웃 지문
                      rec_v2("rollout-2026.jsonl", 701, 1, 999, 1, ["FILE_CREATE"]),
                      rec_v2("CHROME.EXE-1A2B3C4D.pf", 702, 1, 200, 5, ["FILE_CREATE"]),  # 프리패치 폴더 자체는 제외
                      rec_v2("app.dll", 703, 1, 300, 2, ["FILE_CREATE"]))
        self.assertEqual(hits, [])

    def test_name_based_claude_items(self):
        hits = select(rec_v2("CLAUDE.EXE-6DBE243F.pf", 800, 1, 200, 5, ["FILE_CREATE"]),
                      rec_v2("Claude_1.2.3.0_x64__pzs8sxrjxfjjc", 801, 1, 300, 2, ["FILE_CREATE"], directory=True))
        self.assertEqual([h["match"] for h in hits], ["prefetch", "package"])


class Verdicts(unittest.TestCase):
    def test_prefetch_creation_is_run_inferred_with_usn_time(self):
        (r,) = key(records(rec_v2("CLAUDE.EXE-6DBE243F.pf", 800, 1, 200, 5, ["FILE_CREATE"],
                                  iso="2026-10-02T03:22:13")))
        self.assertEqual((r["event"]["event_id"], r["user_action"]["confidence"]), ("E08-01", model.CONF_INFERRED))
        self.assertEqual(r["timestamp"]["utc"], "2026-10-02T03:22:13Z")
        self.assertEqual(r["details"]["lineage"], "prefetch:CLAUDE.EXE-6DBE243F.PF")

    def test_setup_prefetch_and_package_folder_mean_install(self):
        recs = records(rec_v2("CLAUDE SETUP.EXE-11223344.pf", 810, 1, 200, 5, ["FILE_CREATE"]),
                       rec_v2("Claude_1.2.3.0_x64__pzs8sxrjxfjjc", 811, 1, 300, 2, ["FILE_CREATE"], directory=True))
        self.assertEqual(len(key(recs, "E02-01")), 2)

    def test_package_folder_delete_is_not_called_uninstall(self):
        """버전 업데이트도 옛 버전 폴더를 지운다 — 앱 삭제로 단정하지 않는다."""
        (r,) = key(records(rec_v2("Claude_1.2.3.0_x64__pzs8sxrjxfjjc", 811, 1, 300, 2, ["FILE_DELETE"], directory=True)))
        self.assertEqual((r["event"]["event_id"], r["details"]["candidate_event"]), ("NA-00", "E02-02"))

    def test_user_data_folder_delete_is_uninstall_inferred(self):
        (r,) = key(records(rec_v2("Claude_pzs8sxrjxfjjc", 820, 1, 999, 1, ["FILE_DELETE"], directory=True)))
        self.assertEqual((r["event"]["event_id"], r["user_action"]["confidence"]), ("E02-02", model.CONF_INFERRED))

    def test_attachment_blob_create_and_delete_are_observations(self):
        recs = records(rec_v2("https_claude.ai_0.indexeddb.blob", 600, 1, 101, 1, ["FILE_CREATE"], directory=True),
                       rec_v2("1", 601, 1, 600, 1, ["FILE_CREATE"], directory=True),
                       rec_v2("2", 602, 1, 601, 1, ["FILE_CREATE"], iso="2026-10-02T03:29:07"),
                       rec_v2("2", 602, 1, 601, 1, ["FILE_DELETE", "CLOSE"], iso="2026-10-02T03:31:05"))
        got = sorted((r["details"]["key_reason"], r["details"]["candidate_event"], r["event"]["event_id"])
                     for r in key(recs))
        self.assertEqual(got, [("FILE_CREATE", "E05-01/E05-03", "NA-00"),
                               ("FILE_DELETE", "E05-02/E05-04", "NA-00")])

    def test_codex_names_inside_claude_folder_make_no_behavior(self):
        recs = records(rec_v2("auth.json", 900, 1, 100, 3, ["FILE_DELETE"]),
                       rec_v2("rollout-x.jsonl", 901, 1, 100, 3, ["FILE_CREATE"]))
        self.assertEqual(key(recs), [])
        self.assertTrue(all(r["event"]["event_id"] == "NA-00" for r in recs))

    def test_folder_summary_collapses_hash_named_files(self):
        recs = records(*[rec_v2("f_%06x" % i, 1000 + i, 1, 100, 3, ["DATA_EXTEND"], usn_no=i)
                         for i in range(50)])
        (s,) = [r for r in recs if r["details"].get("item_type") == "usn_folder_summary"]
        self.assertEqual((s["details"]["record_count"], s["details"]["name_count"]), (50, 50))


def rec(eid, artifact, iso, lineage=None, conf=model.CONF_INFERRED):
    return model.Record("X", eid, events.name(eid), model.timestamp(utc=iso + "Z"),
                        model.user_action("x", conf), {"location": {"path": "/x"}},
                        details={"artifact": artifact, "lineage": lineage})


class Corroboration(unittest.TestCase):
    def test_usn_does_not_lift_another_run(self):
        """다른 프리패치 파일의 USN 생성 기록(110초 차)으로 다른 실행을 확정하지 않는다 (실측 사례)."""
        pf = rec("E08-01", "prefetch", "2026-10-02T03:24:03", "prefetch:CLAUDE.EXE-6DBE244D.PF")
        u = rec("E08-01", "usn_journal", "2026-10-02T03:22:13", "prefetch:CLAUDE.EXE-6DBE243F.PF")
        pipeline._corroborate([pf, u])
        self.assertEqual(pf["user_action"]["confidence"], model.CONF_INFERRED)

    def test_same_lineage_is_not_independent(self):
        pf = rec("E08-01", "prefetch", "2026-10-02T03:22:13", "prefetch:CLAUDE.EXE-6DBE243F.PF")
        u = rec("E08-01", "usn_journal", "2026-10-02T03:22:13", "prefetch:CLAUDE.EXE-6DBE243F.PF")
        log = rec("E08-02", "applog", "2026-10-02T03:22:13")          # 다른 행위 — 상관없음
        pipeline._corroborate([pf, u, log])
        self.assertEqual((pf["user_action"]["confidence"], u["user_action"]["confidence"]),
                         (model.CONF_INFERRED, model.CONF_INFERRED))

    def test_independent_log_confirms_usn(self):
        u = rec("E08-01", "usn_journal", "2026-10-02T03:22:13", "prefetch:CLAUDE.EXE-6DBE243F.PF")
        log = rec("E08-01", "applog", "2026-10-02T03:21:53")
        pipeline._corroborate([u, log])
        self.assertEqual(u["user_action"]["confidence"], model.CONF_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
