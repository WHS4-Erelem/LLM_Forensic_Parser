"""리뷰 반영 — 같은 앱 기동의 중복 행 접기와 교차검증 제한 검증.

1) USN 의 프리패치 FILE_CREATE 는 같은 기동의 Prefetch 실행 행에 근거로 붙고 별도 행이 되지 않는다
2) 프리패치 ↔ USN 은 서로를 확정으로 올리지 않는다 (같은 Prefetch 저장소)
3) WindowsApps 같은 패키지 폴더의 반복 생성은 설치로 여러 번 세지 않는다 (업데이트/스테이징)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import events, model, pipeline  # noqa: E402


def rec(eid, action, conf, det, utc, rid):
    return model.Record(rid, eid, events.name(eid), model.timestamp(utc=utc),
                        model.user_action(action, conf), {"location": {"path": "/x"}},
                        details=det)


def pf(name, utc, rid, conf=model.CONF_INFERRED):
    return rec("E08-01", "애플리케이션 실행", conf,
               {"artifact": "prefetch", "file_name": name, "item_type": "CLAUDE.EXE",
                "lineage": "prefetch:%s" % name.upper()}, utc, rid)


def usn_pf(name, utc, rid):
    return rec("E08-01", "애플리케이션 실행", model.CONF_INFERRED,
               {"artifact": "usn_journal", "match": "prefetch", "key_reason": "FILE_CREATE",
                "file_name": name, "lineage": "prefetch:%s" % name.upper()}, utc, rid)


def pkg(utc, rid, name="Claude_2.7_x64__pzs8sxrjxfjjc"):
    return rec("E02-01", "애플리케이션 설치", model.CONF_INFERRED,
               {"artifact": "usn_journal", "match": "package", "key_reason": "FILE_CREATE",
                "file_name": name}, utc, rid)


def setup_pf(utc, rid):
    return rec("E02-01", "애플리케이션 설치", model.CONF_INFERRED,
               {"artifact": "prefetch", "file_name": "CLAUDE SETUP.EXE-1.pf",
                "item_type": "CLAUDE SETUP.EXE"}, utc, rid)


def visible(records):
    return [r for r in records if not (r.get("details") or {}).get("superseded_by")]


class FoldUsnPrefetch(unittest.TestCase):
    def test_same_lineage_folds_into_merged_representative(self):
        recs = [pf("CLAUDE.EXE-A.pf", "2026-10-01T14:57:46Z", "a"),
                pf("CLAUDE.EXE-B.pf", "2026-10-01T14:57:47Z", "b"),
                usn_pf("CLAUDE.EXE-B.pf", "2026-10-01T14:57:48Z", "ub")]
        pipeline._merge_prefetch_runs(recs)          # a 가 대표, b 가 a 로 병합
        folded = pipeline._fold_usn_prefetch(recs)
        self.assertEqual(folded, 1)
        ub = next(r for r in recs if r["record_id"] == "ub")
        self.assertEqual(ub["details"]["superseded_by"], "a")   # b 의 대표(a)로 접힘
        self.assertIn("USN 생성 기록", recs[0]["details"]["merge_note"])

    def test_within_window_without_pf_row_folds(self):
        recs = [pf("CLAUDE.EXE-A.pf", "2026-10-01T14:57:46Z", "a"),
                usn_pf("CLAUDE.EXE-Z.pf", "2026-10-01T14:58:20Z", "uz")]   # pf 행 없음, 34초 차
        pipeline._merge_prefetch_runs(recs)
        self.assertEqual(pipeline._fold_usn_prefetch(recs), 1)
        self.assertEqual(next(r for r in recs if r["record_id"] == "uz")["details"]["superseded_by"], "a")

    def test_standalone_first_run_usn_kept(self):
        """프리패치 행이 없고 실행 구간 밖이면 USN 이 유일한 첫 실행 근거 — 접지 않는다."""
        recs = [pf("CLAUDE.EXE-A.pf", "2026-10-01T15:30:00Z", "a"),
                usn_pf("CLAUDE.EXE-Z.pf", "2026-10-01T14:57:46Z", "uz")]   # 30분 전, 매칭 pf 없음
        pipeline._merge_prefetch_runs(recs)
        self.assertEqual(pipeline._fold_usn_prefetch(recs), 0)
        self.assertNotIn("superseded_by", recs[-1]["details"])


class CorroborateGuard(unittest.TestCase):
    def test_prefetch_and_usn_do_not_raise_each_other(self):
        recs = [usn_pf("CLAUDE.EXE-A.pf", "2026-10-01T14:03:53Z", "u"),
                pf("CLAUDE.EXE-B.pf", "2026-10-01T14:05:23Z", "p")]        # 다른 .pf, ±120초
        pipeline._corroborate(recs)
        self.assertEqual(recs[0]["user_action"]["confidence"], model.CONF_INFERRED)
        self.assertEqual(recs[1]["user_action"]["confidence"], model.CONF_INFERRED)

    def test_applog_still_confirms_prefetch(self):
        recs = [pf("CLAUDE.EXE-A.pf", "2026-10-01T14:05:23Z", "p"),
                rec("E08-01", "애플리케이션 실행", model.CONF_INFERRED,
                    {"artifact": "applog", "summary": "실행 로그"}, "2026-10-01T14:05:20Z", "l")]
        pipeline._corroborate(recs)
        self.assertEqual(recs[0]["user_action"]["confidence"], model.CONF_CONFIRMED)


class FoldPackageInstalls(unittest.TestCase):
    def test_repeated_package_creates_after_setup_downgraded(self):
        recs = [setup_pf("2026-10-01T04:03:00Z", "s"),
                pkg("2026-10-01T13:25:31Z", "p1"),
                pkg("2026-10-01T13:26:04Z", "p2"),
                pkg("2026-10-01T14:03:19Z", "p3")]
        down = pipeline._fold_package_installs(recs)
        self.assertEqual(down, 3)
        installs = [r for r in recs if r["event"]["event_id"] == "E02-01"]
        self.assertEqual([r["record_id"] for r in installs], ["s"])      # SETUP 1건만 설치
        for rid in ("p1", "p2", "p3"):
            r = next(x for x in recs if x["record_id"] == rid)
            self.assertEqual(r["event"]["event_id"], "NA-00")
            self.assertEqual(r["details"]["candidate_event"], "E02-01")

    def test_first_package_create_without_prior_install_kept(self):
        recs = [pkg("2026-10-01T13:25:31Z", "p1"),
                pkg("2026-10-01T13:26:04Z", "p2")]
        down = pipeline._fold_package_installs(recs)
        self.assertEqual(down, 1)                                        # 첫 생성은 설치로 유지
        self.assertEqual(next(r for r in recs if r["record_id"] == "p1")["event"]["event_id"], "E02-01")
        self.assertEqual(next(r for r in recs if r["record_id"] == "p2")["event"]["event_id"], "NA-00")


class EventsCatalog(unittest.TestCase):
    def test_dropped_names_removed(self):
        self.assertNotIn("E05-06", events.EVENTS)
        self.assertNotIn("E10-05", events.EVENTS)


if __name__ == "__main__":
    unittest.main()
