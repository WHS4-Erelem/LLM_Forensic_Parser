r"""GUI ↔ 통합 파서 연결 회귀 테스트 (Qt 위젯 없이 adapter·loader 만 검증).

여기서 지키는 것:
  - IntegrationRunner.command() 가 integration/llm_forensic.py 의 CLI 계약과 같은 인자를 만든다
  - 파서 목록을 코드에 적지 않고 integration/parsers.json 에서 읽는다
  - ResultBundle 이 최신 병합 CSV(팀 열 + provenance 열) · report · manifest 를 그대로 읽는다
  - 부분 실패(exit=1) 에서도 결과를 읽을 수 있고, warning 과 failed 를 섞지 않는다
  - GUI 가 포렌식 값을 만들지 않는다 (Timestamp "-" · volume_ref · artifact_path_normalized 원본 유지)

실행: python -m unittest discover -s gui/tests   (PyQt6 가 설치된 GUI 실행 환경에서)
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

GUI_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = GUI_DIR.parent
sys.path.insert(0, str(GUI_DIR))

import integration_runner as ir                                     # noqa: E402
from result_loader import (EMPTY, ResultBundle, ResultLoadError, ST_COMPLETED, ST_CONTRACT_VIOLATION,
                           ST_NO_RESULT, cell, evidence_dir_conflict, find_result_dirs)  # noqa: E402

# 통합기가 만드는 병합 CSV 의 열 (integration/llm_forensic.py). 끝 공백은 팀 샘플에 실제로 있는 문자다.
TEAM_TIMELINE = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                 "Artifact_path", "Artifact_details "]
TEAM_CONVERSATION = ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                     "parent_message_uuid", "message order", "role", "content", "Artifact_path"]
PROVENANCE = ["source_parser", "parser_version", "source_file", "parse_time_utc",
              "artifact_path_normalized", "volume_ref", "evidence_id", "evidence_sha256"]

EVIDENCE_ID = "bde7c3e6d5ae5e03"


def _write_csv(path, columns, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        writer.writerows(rows)


class RunnerCommandTest(unittest.TestCase):
    """IntegrationRunner.command() 가 최신 CLI 계약과 같은 인자를 만드는지."""

    IMAGE = r"D:\test_image\Scenario.dd"
    OUT = r"D:\WHS_GUI_OUTPUT"

    def test_full_run_has_no_only_flag(self):
        _program, args = ir.IntegrationRunner().command(self.IMAGE, self.OUT)
        self.assertEqual(args[:7], ["-u", ir.RUNNER, "-i", self.IMAGE, "-o", self.OUT, "--registry"])
        self.assertEqual(args[7], ir.REGISTRY)
        self.assertNotIn("--only", args)
        self.assertNotIn("--quick", args)

    def test_selected_parsers_become_one_comma_list(self):
        _program, args = ir.IntegrationRunner().command(self.IMAGE, self.OUT, only=["chatgpt_web", "lmstudio"])
        self.assertEqual(args[args.index("--only") + 1], "chatgpt_web,lmstudio")

    def test_quick_adds_only_the_quick_flag(self):
        _program, args = ir.IntegrationRunner().command(self.IMAGE, self.OUT, quick=True)
        self.assertIn("--quick", args)
        self.assertNotIn("--only", args)

    def test_runner_and_registry_point_at_the_integration_folder(self):
        self.assertTrue(os.path.isfile(ir.RUNNER), ir.RUNNER)
        self.assertTrue(os.path.isfile(ir.REGISTRY), ir.REGISTRY)
        self.assertEqual(Path(ir.RUNNER).parent.name, "integration")

    def test_exit_meaning_matches_the_integration_docstring(self):
        """종료코드 뜻을 GUI 가 따로 정하지 않는다 — llm_forensic.py 머리말과 같은 4개."""
        self.assertEqual(sorted(ir.EXIT_MEANING), [0, 1, 2, 3])
        header = Path(ir.RUNNER).read_text(encoding="utf-8")[:4000]
        self.assertIn("종료코드", header)

    def test_parser_list_comes_from_the_registry_not_from_code(self):
        names = [name for name, _model in ir.registry_parsers()]
        with open(ir.REGISTRY, encoding="utf-8") as fh:
            registry = json.load(fh)
        expected = [p["name"] for p in registry["parsers"] if p.get("enabled", True)]
        self.assertEqual(names, expected)
        self.assertTrue(names, "레지스트리에 enabled 파서가 없다")

    def test_disabled_parsers_are_left_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "parsers.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"parsers": [{"name": "a", "model": "a"},
                                       {"name": "b", "model": "b", "enabled": False}]}, fh)
            self.assertEqual(ir.registry_parsers(path), [("a", "a")])

    def test_parsers_skipping_follows_the_registry_inputs(self):
        """inputs 를 선언한 파서만 확장자 검사 대상 — 판단 기준은 llm_forensic.py run_parser() 와 같다."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "parsers.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"parsers": [
                    {"name": "any", "model": "any"},                            # inputs 없음 → 검사 안 함
                    {"name": "img_only", "model": "m", "inputs": [".e01", ".dd"]},
                    {"name": "off", "model": "m", "enabled": False, "inputs": [".e01"]},
                ]}, fh)
            self.assertEqual(ir.parsers_skipping(r"C:\x\evidence.E01", path), [])
            self.assertEqual(ir.parsers_skipping(r"C:\x\evidence.dd", path), [])
            self.assertEqual(ir.parsers_skipping(r"C:\x\evidence.001", path), ["img_only"])
            self.assertEqual(ir.parsers_skipping(r"C:\x\evidence", path), ["img_only"])

    def test_real_registry_skips_nothing_for_e01_and_dd(self):
        """GUI 파일 선택창이 권하는 E01·DD 는 등록된 파서가 모두 받는다 (지원하지 않는 형식을 권하지 않는다)."""
        for name in ("evidence.E01", "evidence.dd"):
            with self.subTest(name=name):
                self.assertEqual(ir.parsers_skipping(name), [])


class ConsoleLineTest(unittest.TestCase):
    """stdout 한 줄씩 보내 상태 신호가 최신 출력 형식과 맞는지 (QProcess 없이 _handle_line 만)."""

    def setUp(self):
        self.runner = ir.IntegrationRunner.__new__(ir.IntegrationRunner)   # Qt 부모 없이 메서드만 쓴다
        self.runner._buffer = ""
        self.runner._result_dir = ""
        self.runner._current_parser = ""
        self.seen = []
        self.runner.logLine = _Signal()
        self.runner.stageChanged = _Signal(self.seen, "stage")
        self.runner.parserStatus = _Signal(self.seen, "parser")
        self.runner.evidenceInfo = _Signal(self.seen, "evidence")

    def test_cancel_kills_and_waits_for_the_child_process(self):
        """창을 닫으며 중단할 때 자식 프로세스가 끝난 것을 확인하고 나간다 (고아 프로세스 방지)."""
        calls = []

        class _Proc:                                       # QProcess 대역 — 실행 중 상태만 흉내낸다
            def state(self):
                return "Running"
            def kill(self):
                calls.append("kill")
            def waitForFinished(self, msecs):
                calls.append(("wait", msecs))

        self.runner._proc = _Proc()
        self.runner.is_running = lambda: True
        self.runner.cancel()
        self.assertEqual(calls, ["kill", ("wait", 3000)])

    def test_evidence_line_is_reported(self):
        self.runner._handle_line("[Evidence] id=%s kind=dd segments=1 size=64.0GB quick_fp=ab… sha256=-" % EVIDENCE_ID)
        self.assertIn(("parser", "evidence", "success"), self.seen)

    def test_runner_then_result_marks_the_parser(self):
        self.runner._handle_line("[Runner] chatgpt_web   ")
        self.runner._handle_line("   OK        1.2s events=39  messages=24")
        self.assertIn(("parser", "chatgpt_web", "running"), self.seen)
        self.assertIn(("parser", "chatgpt_web", "success"), self.seen)

    def test_contract_violation_label_maps_to_its_own_status(self):
        self.runner._handle_line("[Runner] gemini_web")
        self.runner._handle_line("   CONTRACT_VIOLATION   0.4s events=0   messages=0")
        self.assertIn(("parser", "gemini_web", "contract_violation"), self.seen)

    def test_report_line_decides_the_result_directory(self):
        self.runner._handle_line(r"[Report] D:\out\%s\integration_report.json" % EVIDENCE_ID)
        self.assertEqual(os.path.basename(self.runner._result_dir), EVIDENCE_ID)

    def test_fatal_db_line_is_surfaced(self):
        """[DB] FAILED 는 파서를 하나도 실행하지 못한 상태다 — 화면에서 바로 보여야 한다."""
        self.runner._handle_line("[DB] FAILED DB_ERROR unified.db 열기·초기화 실패 (locked)")
        self.assertIn(("parser", "db", "failed"), self.seen)
        self.assertTrue(any(kind == "stage" and "DB" in a for kind, a, *_ in self.seen))

    def test_informational_db_lines_do_not_mark_a_failure(self):
        self.runner._handle_line(r"[DB] D:\out\%s\unified.db" % EVIDENCE_ID)
        self.assertNotIn(("parser", "db", "failed"), self.seen)


class _Signal:
    """pyqtSignal 대신 호출만 기록하는 최소 더블."""

    def __init__(self, sink=None, kind=""):
        self._sink, self._kind = sink, kind

    def emit(self, *args):
        if self._sink is not None:
            self._sink.append((self._kind,) + args)


class ResultBundleFixtureTest(unittest.TestCase):
    """최신 통합 출력 구조를 fixture 로 만들어 ResultBundle 이 그대로 읽는지."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gui-result-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.case = self.root / EVIDENCE_ID
        self.case.mkdir()

    def build(self, *, quick=False, exit_code=0, parsers=None, warnings=None, errors=None,
              timeline_rows=None, conversation_rows=None, preserved=None):
        report = {"report_version": 1, "run_id": "20261008T000000Z", "generated_at_utc": "2026-10-08T00:00:00Z",
                  "mode": "full", "only": None, "quick": quick, "registry": "parsers.json",
                  "evidence": {"evidence_id": EVIDENCE_ID}, "exit_code": exit_code,
                  "summary": {}, "db": {"path": str(self.case / "unified.db")},
                  "parsers": parsers if parsers is not None else {
                      "chatgpt_web": {"status": "success", "timeline_rows": 1, "conversation_rows": 1,
                                      "artifacts_found": True, "errors": []}},
                  "integration_errors": errors or [], "warnings": warnings or []}
        if preserved is not None:
            report["preserved_from_previous_runs"] = preserved
        (self.case / "integration_report.json").write_text(
            json.dumps(report, ensure_ascii=False), encoding="utf-8")
        (self.case / "evidence_manifest.json").write_text(json.dumps({
            "evidence_id": EVIDENCE_ID, "path": r"D:\test_image\Scenario.dd", "kind": "dd",
            "size_bytes": 68719476736, "segments": ["Scenario.dd"],
            "evidence_sha256": EMPTY if quick else "a" * 64,
            "evidence_quick_fingerprint": "b" * 64}, ensure_ascii=False), encoding="utf-8")
        _write_csv(self.case / "timeline.csv", TEAM_TIMELINE + PROVENANCE,
                   timeline_rows if timeline_rows is not None else [self.timeline_row()])
        _write_csv(self.case / "recovered_conversations.csv", TEAM_CONVERSATION + PROVENANCE,
                   conversation_rows if conversation_rows is not None else [self.conversation_row()])
        (self.case / "unified.db").write_bytes(b"")
        return ResultBundle.load(str(self.case))

    @staticmethod
    def timeline_row(*, timestamp="2026-10-02 11:03:42.858000 KST", parser="chatgpt_web",
                     behavior="사용자 프롬프트 입력/전송", verdict="의심",
                     raw_path=r"C:\Users\llmtest\AppData\Local\Google\Chrome\User Data\Default\History",
                     normalized="users/llmtest/appdata/local/google/chrome/user data/default/history",
                     volume="C: (추정, ntfs@227540992)"):
        return ["chatgpt-web", timestamp, behavior, "근거_내용", verdict, raw_path, "artifact_type=history",
                parser, "0.2.0", "timeline.csv", "2026-10-08T00:00:00Z", normalized, volume,
                EVIDENCE_ID, "a" * 64]

    @staticmethod
    def conversation_row(*, uuid="conv-0001", role="user", content="프롬프트 본문", parser="chatgpt_web",
                         order="1", timestamp="2026-10-02 11:03:42.858000 KST"):
        return ["chatgpt-web", timestamp, uuid, "대화 제목", "msg-0001", EMPTY, order, role, content,
                r"C:\Users\llmtest\…\Cache\Cache_Data\data_3",
                parser, "0.2.0", "recovered_conversations.csv", "2026-10-08T00:00:00Z",
                "users/llmtest/…/cache/cache_data/data_3", "C:", EVIDENCE_ID, "a" * 64]

    # -------------------------------------------------- 열 계약 / provenance
    def test_team_columns_and_provenance_are_both_loaded(self):
        bundle = self.build()
        self.assertEqual(bundle.timeline_columns, TEAM_TIMELINE + PROVENANCE)
        self.assertEqual(bundle.conversation_columns, TEAM_CONVERSATION + PROVENANCE)

    def test_trailing_space_headers_are_kept_as_is(self):
        bundle = self.build()
        self.assertIn("Behavior_details ", bundle.timeline_columns)
        self.assertIn("Artifact_details ", bundle.timeline_columns)
        self.assertEqual(cell(bundle.timeline_rows[0], "Behavior_details "), "근거_내용")

    def test_raw_and_normalized_paths_stay_separate(self):
        row = self.build().timeline_rows[0]
        self.assertTrue(cell(row, "Artifact_path").startswith("C:\\Users\\llmtest"))
        self.assertEqual(cell(row, "artifact_path_normalized"),
                         "users/llmtest/appdata/local/google/chrome/user data/default/history")
        self.assertNotEqual(cell(row, "Artifact_path"), cell(row, "artifact_path_normalized"))

    def test_volume_ref_is_shown_exactly_as_integration_wrote_it(self):
        """통합기의 추정 표기('C: (추정, ntfs@…)')를 GUI 가 다시 계산하거나 다듬지 않는다."""
        rows = [self.timeline_row(volume=v) for v in ("C:", "C: (추정)", "C: (추정, volume0)",
                                                      "C: | D:", EMPTY)]
        bundle = self.build(timeline_rows=rows)
        self.assertEqual([cell(r, "volume_ref") for r in bundle.timeline_rows],
                         ["C:", "C: (추정)", "C: (추정, volume0)", "C: | D:", EMPTY])

    def test_missing_timestamp_stays_a_dash(self):
        bundle = self.build(timeline_rows=[self.timeline_row(timestamp=EMPTY)])
        self.assertEqual(cell(bundle.timeline_rows[0], "Timestamp"), EMPTY)

    # -------------------------------------------------- report / 상태
    def test_parser_status_comes_from_the_report(self):
        bundle = self.build(parsers={
            "chatgpt_web": {"status": "success", "timeline_rows": 1, "conversation_rows": 1,
                            "artifacts_found": True, "errors": []},
            "gemini_web": {"status": "contract_violation", "timeline_rows": 0, "conversation_rows": 0,
                           "artifacts_found": False,
                           "errors": [{"type": "INVALID_VERDICT", "message": "x"}]}})
        states = {name: status for name, status, *_ in bundle.display_parser_states()}
        self.assertEqual(states["chatgpt_web"], ST_COMPLETED)
        self.assertEqual(states["gemini_web"], ST_CONTRACT_VIOLATION)

    def test_success_with_no_rows_is_not_called_failed(self):
        bundle = self.build(parsers={"lmstudio": {"status": "success", "timeline_rows": 0,
                                                  "conversation_rows": 0, "artifacts_found": False,
                                                  "errors": []}}, timeline_rows=[], conversation_rows=[])
        states = {name: status for name, status, *_ in bundle.display_parser_states()}
        self.assertEqual(states["lmstudio"], ST_NO_RESULT)

    def test_a_warning_alone_does_not_make_a_parser_failed(self):
        """UNKNOWN_USER_BEHAVIOR 같은 warning 은 통합 계약상 경고다 — Failed 로 바꾸지 않는다."""
        bundle = self.build(parsers={"chatgpt_web": {"status": "success", "timeline_rows": 1,
                                                     "conversation_rows": 1, "artifacts_found": True,
                                                     "errors": []}},
                            warnings=["UNKNOWN_USER_BEHAVIOR: chatgpt_web '파일 업로드'"])
        states = {name: status for name, status, *_ in bundle.display_parser_states()}
        self.assertEqual(states["chatgpt_web"], ST_COMPLETED)
        self.assertTrue(any("UNKNOWN_USER_BEHAVIOR" in r["Message"] for r in bundle.error_rows()))

    def test_partial_failure_still_loads_and_keeps_the_good_rows(self):
        """exit=1 은 전체 실패가 아니다 — 결과를 읽을 수 있고 실패 파서만 오류로 보인다."""
        bundle = self.build(exit_code=1, parsers={
            "chatgpt_web": {"status": "success", "timeline_rows": 1, "conversation_rows": 1,
                            "artifacts_found": True, "errors": []},
            "claude_web": {"status": "failed", "timeline_rows": 0, "conversation_rows": 0,
                           "artifacts_found": False,
                           "errors": [{"type": "PARSER_EXECUTION_ERROR", "message": "returncode=1"}]}})
        self.assertEqual(bundle.report["exit_code"], 1)
        self.assertEqual(len(bundle.timeline_rows), 1)
        self.assertTrue(bundle.has_merged_outputs())
        self.assertTrue(any("PARSER_EXECUTION_ERROR" in str(r) for r in bundle.error_rows()))

    def test_preserved_previous_run_is_reported_not_invented(self):
        bundle = self.build(preserved=["lmstudio"])
        self.assertTrue(any("lmstudio" in note for note in bundle.limitations()))

    def test_quick_run_marks_the_missing_hash_as_skipped_not_broken(self):
        bundle = self.build(quick=True)
        sha = dict((k, v) for k, v, _mono in bundle.integrity()).get("SHA-256", "")
        self.assertIn("--quick", sha)
        self.assertTrue(any("quick" in note for note in bundle.limitations()))

    def test_full_run_shows_the_real_hash(self):
        bundle = self.build(quick=False)
        self.assertEqual(dict((k, v) for k, v, _m in bundle.integrity())["SHA-256"], "a" * 64)

    # -------------------------------------------------- 서비스 필터 / 대화
    def test_service_filter_uses_source_parser(self):
        bundle = self.build(timeline_rows=[self.timeline_row(parser="chatgpt_web"),
                                           self.timeline_row(parser="lmstudio")])
        self.assertEqual(len(bundle.timeline_rows_of("chatgpt_web")), 1)
        self.assertEqual({s for s, _n in bundle.service_counts()}, {"chatgpt_web", "lmstudio"})

    def test_empty_conversation_file_is_not_an_error(self):
        bundle = self.build(conversation_rows=[])
        self.assertEqual(bundle.conversation_rows, [])
        self.assertEqual(bundle.conversation_sessions(), [])
        self.assertTrue(bundle.has_merged_outputs())

    def test_rows_without_conversation_uuid_keep_the_dash(self):
        bundle = self.build(conversation_rows=[self.conversation_row(uuid=EMPTY)])
        session = bundle.conversation_sessions()[0]
        self.assertEqual(session.conversation_uuid, EMPTY)
        self.assertFalse(session.has_uuid)

    def test_report_without_merged_csv_still_loads(self):
        """exit=2 / exit=3 은 병합 CSV 가 없어도 report 가 남는다 — 오류를 보여 줄 수 있어야 한다."""
        self.build(exit_code=3, errors=[{"type": "DB_ERROR", "message": "unified.db 열기 실패"}])
        for name in ("timeline.csv", "recovered_conversations.csv"):
            (self.case / name).unlink()
        bundle = ResultBundle.load(str(self.case))
        self.assertFalse(bundle.has_merged_outputs())
        self.assertEqual(bundle.report["exit_code"], 3)
        self.assertTrue(any("DB_ERROR" in str(r) for r in bundle.error_rows()))

    def test_directory_without_any_integration_output_raises(self):
        with self.assertRaises(ResultLoadError):
            ResultBundle.load(str(self.case))        # report·CSV 가 하나도 없는 폴더

    def test_missing_directory_raises(self):
        with self.assertRaises(ResultLoadError):
            ResultBundle.load(str(self.case / "nope"))


class ResultDiscoveryTest(unittest.TestCase):
    """통합 출력은 <out>\\<evidence_id> 에 생긴다 — 두 모양 모두 열려야 한다."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gui-discovery-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _case(self, name):
        case = self.root / name
        case.mkdir(parents=True)
        (case / "integration_report.json").write_text("{}", encoding="utf-8")
        _write_csv(case / "timeline.csv", TEAM_TIMELINE + PROVENANCE, [])
        return case

    def test_case_directory_itself(self):
        case = self._case(EVIDENCE_ID)
        self.assertEqual(find_result_dirs(str(case)), [str(case)])

    def test_output_root_with_several_case_directories(self):
        first, second = self._case("aaaa000000000001"), self._case("bbbb000000000002")
        self.assertEqual(sorted(find_result_dirs(str(self.root))), sorted([str(first), str(second)]))

    def test_unrelated_folder_finds_nothing(self):
        (self.root / "empty").mkdir()
        self.assertEqual(find_result_dirs(str(self.root / "empty")), [])


class OutputPathSafetyTest(unittest.TestCase):
    """원본 증거 폴더 안쪽으로 출력하면 파서가 거부한다 — 실행 전에 막는다."""

    def test_output_inside_the_evidence_folder_is_refused(self):
        for out in (r"D:\test_image", r"D:\test_image\output", r"d:\TEST_IMAGE\x"):
            with self.subTest(out=out):
                self.assertTrue(evidence_dir_conflict(r"D:\test_image\Scenario.dd", out))

    def test_output_elsewhere_is_allowed(self):
        self.assertFalse(evidence_dir_conflict(r"D:\test_image\Scenario.dd", r"D:\WHS_GUI_OUTPUT"))

    def test_missing_input_is_not_a_conflict(self):
        self.assertFalse(evidence_dir_conflict("", r"D:\WHS_GUI_OUTPUT"))


class PluginIsolationTest(unittest.TestCase):
    """이번 GUI 는 통합 파서만 쓴다 — 플러그인/Autopsy 를 불러오거나 실행하지 않는다."""

    def test_gui_sources_never_mention_the_plugin(self):
        hits = []
        for path in GUI_DIR.rglob("*.py"):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue                       # 이 테스트 파일 자체는 이름을 언급한다 (검사 대상은 생산 코드)
            text = path.read_text(encoding="utf-8").lower()
            if "autopsy" in text or "plugin" in text:
                hits.append(path.name)
        self.assertEqual(hits, [])

    def test_gui_only_runs_the_integration_entry_point(self):
        """GUI 가 개별 파서를 직접 실행하지 않는다 (실행 대상은 llm_forensic.py 하나)."""
        text = (GUI_DIR / "integration_runner.py").read_text(encoding="utf-8")
        self.assertIn("llm_forensic.py", text)
        for parser_entry in ("chatgpt_web_parser.py", "claude_web", "gemini", "lmstudio_parser"):
            self.assertNotIn(parser_entry + ".py", text)


class BrandingTest(unittest.TestCase):
    """사용자에게 보이는 상단 브랜딩 — ARTINEX 텍스트 + 투명 배경 ERELM 심볼."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])
        import main_window
        cls.mw = main_window
        cls.window = main_window.MainWindow()

    def test_window_title_is_the_product_name(self):
        self.assertEqual(self.window.windowTitle(), "ARTINEX")

    def test_header_shows_the_product_name_and_tagline(self):
        from PyQt6.QtWidgets import QLabel
        texts = [w.text() for w in self.window.findChildren(QLabel)]
        self.assertIn("ARTINEX", texts)
        self.assertIn("Integrated LLM Forensic Analysis", texts)

    def test_header_has_exactly_one_brand_mark_and_no_text_badge(self):
        from PyQt6.QtWidgets import QLabel
        marks = self.window.findChildren(self.mw.BrandMark)
        self.assertEqual(len(marks), 1)
        self.assertEqual((marks[0].width(), marks[0].height()), (44, 44))
        self.assertEqual([w.text() for w in self.window.findChildren(QLabel) if w.text() == "EL"], [])

    def test_brand_mark_renders_the_logo_colours_on_a_transparent_background(self):
        """사각 타일이 아니라 심볼만 보인다 — 모서리는 투명, 안쪽에는 연두·청록이 있다."""
        from PyQt6.QtGui import QImage, QPainter
        image = QImage(44, 44, QImage.Format.Format_ARGB32)
        image.fill(0)                                   # 완전 투명으로 시작
        painter = QPainter(image)
        self.mw.BrandMark().render(painter)
        painter.end()
        for x, y in ((0, 0), (43, 0), (0, 43)):         # 로고가 닿지 않는 모서리
            self.assertEqual(image.pixelColor(x, y).alpha(), 0)
        drawn = [image.pixelColor(x, y) for y in range(44) for x in range(44)
                 if image.pixelColor(x, y).alpha() > 200]
        self.assertGreater(len(drawn), 200)             # 심볼이 실제로 그려졌다
        self.assertTrue(any(c.green() > c.red() > c.blue() for c in drawn))      # 연두
        self.assertTrue(any(c.blue() > 120 and c.green() > 120 for c in drawn))  # 청록

    def test_no_logo_image_asset_is_needed_at_runtime(self):
        source = (GUI_DIR / "main_window.py").read_text(encoding="utf-8")
        self.assertNotIn("assets", source)              # 경로 의존 없는 벡터 구현 (주석의 파일 이름은 출처 표시)
        self.assertFalse((GUI_DIR / "assets" / "Logo.png").exists())


if __name__ == "__main__":
    unittest.main()
