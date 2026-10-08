"""팀 공통 CSV 양식 맞추기 — 세 가지 포맷 수정 검증.

팀원 파서(claude_web·chatgpt_desktop)와 양식을 맞추기 위한 것:
  A. Behavior_details 는 짧은 라벨만 — 앱 로그 원문(타임스탬프·[info]…)을 넣지 않는다
  B. recovered_conversations 는 발화자 확인된 메시지만 — role=unknown 바이트 조각은 뺀다
  C. 한 번의 앱 실행이 하위 프로세스 Prefetch 로 여러 행이 되던 것을 한 행으로 합친다
"""

import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import model, output, pipeline  # noqa: E402

IMG = {"image_id": "t"}


def rec(eid, action, conf, det, utc="2026-10-02T03:00:00Z", rid=None):
    return model.Record(rid or ("r%d" % (id(det) % 100000)), eid, eid,
                        model.timestamp(utc=utc), model.user_action(action, conf),
                        {"location": {"path": "/x"}}, details=det)


def _rows(path):
    with open(path, encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def write_timeline(records):
    d = tempfile.mkdtemp()
    output.write_timeline_csv(d + "/t.csv", records)
    return _rows(d + "/t.csv")


def write_conv(records):
    d = tempfile.mkdtemp()
    output.write_conversations_csv(d + "/c.csv", records)
    return _rows(d + "/c.csv")


class BehaviorDetailsLabel(unittest.TestCase):
    def test_applog_uses_short_label_not_raw_line(self):
        r = rec("E01-01", "로그인", model.CONF_CONFIRMED,
                {"artifact": "applog", "summary": "인증 상태 변경(로그인)",
                 "log_body": "2026-10-01 22:27:04 [info] [account] Login-state transition ...",
                 "account_uuid": "fe704807-3aed-4482-9304-ac5c1fdf857e"})
        (row,) = write_timeline([r])
        self.assertEqual(row["Behavior_details "], "로그인_인증 상태 변경(로그인)")
        self.assertNotIn("[info]", row["Behavior_details "])
        self.assertNotIn("2026-10-01 22:27:04", row["Behavior_details "])
        # 원문은 Artifact_details 가 아니라 result.json(details.log_body)에만 — CSV 에는 없다
        self.assertNotIn("Login-state transition", row["Behavior_details "])

    def test_raw_log_body_never_reaches_behavior_details(self):
        """summary 가 없어도 log_body(원문)는 Behavior_details 에 들어가면 안 된다."""
        r = rec("E08-02", "정상 종료", model.CONF_INFERRED,
                {"artifact": "applog",
                 "log_body": "2026/10/02 00:42:44 Shutdown signal received..."})
        (row,) = write_timeline([r])
        self.assertNotIn("Shutdown signal received", row["Behavior_details "])


class ConversationRoleFilter(unittest.TestCase):
    def test_unknown_role_fragments_excluded_user_kept(self):
        recs = [
            rec("E04-01", "사용자 프롬프트 입력/전송", model.CONF_INFERRED,
                {"artifact": "idb_leveldb", "role": "user", "origin": "user_typed",
                 "text": "내 자산 점검 결과 정리해줘", "conversation_uuid": "c1"}),
            rec("NA-00", "x", model.CONF_UNKNOWN,
                {"artifact": "idb_leveldb", "role": "unknown",
                 "text": "Nmap scan report for host", "conversation_uuid": "-"}),
            rec("NA-00", "x", model.CONF_UNKNOWN,
                {"artifact": "idb_leveldb", "role": "unknown",
                 "text": "Host is up (0.00017s latency).", "conversation_uuid": "-"}),
        ]
        rows = write_conv(recs)
        self.assertEqual([r["role"] for r in rows], ["user"])
        self.assertNotIn("unknown", {r["role"] for r in rows})

    def test_assistant_and_tool_still_kept(self):
        recs = [
            rec("NA-00", "x", model.CONF_INFERRED,
                {"artifact": "idb_leveldb", "role": "assistant", "origin": "assistant",
                 "text": "정리해 드리겠습니다", "conversation_uuid": "c1",
                 "message_uuid": "m2", "parent_message_uuid": "m1"}),
        ]
        rows = write_conv(recs)
        self.assertEqual([r["role"] for r in rows], ["assistant"])


class PrefetchRunMerge(unittest.TestCase):
    def _pf(self, name, utc, rid):
        return rec("E08-01", "애플리케이션 실행", model.CONF_INFERRED,
                   {"artifact": "prefetch", "file_name": name, "item_type": "CLAUDE.EXE",
                    "lineage": "prefetch:%s" % name.upper()}, utc=utc, rid=rid)

    def test_same_run_folds_to_one_row(self):
        recs = [self._pf("CLAUDE.EXE-725B.pf", "2026-10-01T14:57:46Z", "a"),
                self._pf("CLAUDE.EXE-725C.pf", "2026-10-01T14:57:46Z", "b"),
                self._pf("CLAUDE.EXE-725D.pf", "2026-10-01T14:57:47Z", "c"),
                self._pf("CLAUDE.EXE-7266.pf", "2026-10-01T14:57:48Z", "d")]
        merged = pipeline._merge_prefetch_runs(recs)
        self.assertEqual(merged, 3)                       # 4개 중 3개가 가려짐
        rep = [r for r in recs if not (r["details"].get("superseded_by"))]
        self.assertEqual(len(rep), 1)
        self.assertEqual(rep[0]["record_id"], "a")        # 가장 이른 것이 대표
        self.assertEqual(rep[0]["details"]["run_label"], "prefetch_run=1/4")
        rows = write_timeline(recs)                        # 가려진 것은 timeline 에서 빠진다
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Behavior_details "], "애플리케이션 실행_prefetch_run=1/4")

    def test_distant_runs_stay_separate(self):
        recs = [self._pf("CLAUDE.EXE-A.pf", "2026-10-01T14:57:46Z", "a"),
                self._pf("CLAUDE.EXE-B.pf", "2026-10-01T15:03:23Z", "b")]  # 5분 뒤 = 다른 실행
        merged = pipeline._merge_prefetch_runs(recs)
        self.assertEqual(merged, 0)
        self.assertEqual(len(write_timeline(recs)), 2)

    def test_setup_prefetch_not_merged_with_run(self):
        """설치(E02-01)와 실행(E08-01)은 다른 행위라 섞이지 않는다."""
        recs = [rec("E02-01", "애플리케이션 설치", model.CONF_INFERRED,
                    {"artifact": "prefetch", "file_name": "CLAUDE SETUP.EXE-1.pf",
                     "item_type": "CLAUDE SETUP.EXE"}, utc="2026-10-01T14:57:46Z", rid="s"),
                self._pf("CLAUDE.EXE-A.pf", "2026-10-01T14:57:46Z", "a")]
        self.assertEqual(pipeline._merge_prefetch_runs(recs), 0)


if __name__ == "__main__":
    unittest.main()
