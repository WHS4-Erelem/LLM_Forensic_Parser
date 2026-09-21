"""
팀 통합용 패키지 구조 테스트 (chatgpt_parser).

여기서 확인하는 것은 "구조" 다 — 공개 API 로 분석이 되는가, 출력이 분리되어 있는가, 기존 CLI 가 그대로인가.
Rule 판정·CSV 내용 자체는 tests/test_chatgpt_web_parser.py 가 계속 검증한다.
"""
from __future__ import annotations

import csv
import importlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import chatgpt_parser
import chatgpt_web_parser
from test_chatgpt_web_parser import create_history_db

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FINAL_FILES = ("timeline.csv", "recovered_conversations.csv")
DEBUG_FILES = ("coverage.csv", "records.csv", "events.csv", "conversations.csv", "messages.csv")

# 패키지 안의 모든 구현 모듈 (순환 import / import side effect 검사용).
ALL_MODULES = (
    "chatgpt_parser", "chatgpt_parser.constants", "chatgpt_parser.models", "chatgpt_parser.utils",
    "chatgpt_parser.source", "chatgpt_parser.image", "chatgpt_parser.discovery",
    "chatgpt_parser.artifacts.history", "chatgpt_parser.artifacts.leveldb",
    "chatgpt_parser.artifacts.local_storage", "chatgpt_parser.artifacts.session_storage",
    "chatgpt_parser.artifacts.cache", "chatgpt_parser.artifacts.shared_proto_db",
    "chatgpt_parser.artifacts.sessions",
    "chatgpt_parser.detectors.common", "chatgpt_parser.detectors.auth",
    "chatgpt_parser.detectors.conversation", "chatgpt_parser.detectors.prompt",
    "chatgpt_parser.detectors.file_activity", "chatgpt_parser.detectors.misc",
    "chatgpt_parser.recovery.conversations", "chatgpt_parser.parser",
    "chatgpt_parser.output.debug", "chatgpt_parser.output.final_csv", "chatgpt_parser.output.csv_writer",
    "chatgpt_parser.cli",
)


class PackageTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.source_dir = self.tmp / "evidence" / "Chrome"
        (self.source_dir / "Default").mkdir(parents=True)
        create_history_db(self.source_dir / "Default" / "History")
        self.out_dir = self.tmp / "out"  # Source 밖 (원본에는 쓰지 않는다)

    def tearDown(self):
        self._tmp.cleanup()

    def analyze(self):
        return chatgpt_parser.analyze_chatgpt_web(self.source_dir, input_type="dir", history_path="Default/History")

    def read_csv(self, path):
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        return rows[0], rows[1:]


class PublicApiTest(PackageTestBase):
    def test_import_only_needs_the_package(self):
        """통합 담당자는 내부 구현을 몰라도 이 두 이름만 알면 된다."""
        from chatgpt_parser import analyze_chatgpt_web, write_final_outputs
        self.assertTrue(callable(analyze_chatgpt_web))
        self.assertTrue(callable(write_final_outputs))

    def test_public_names_do_not_leak_internal_helpers(self):
        self.assertIn("analyze_chatgpt_web", chatgpt_parser.__all__)
        private = [name for name in chatgpt_parser.__all__ if name.startswith("_")]
        self.assertEqual(private, [])
        for name in chatgpt_parser.__all__:
            self.assertTrue(hasattr(chatgpt_parser, name), name)

    def test_analyze_returns_parse_result_with_documented_attributes(self):
        result = self.analyze()
        self.assertIsInstance(result, chatgpt_parser.ParseResult)
        for name in ("events", "records", "coverage", "warnings", "conversations", "recovered_messages"):
            self.assertTrue(hasattr(result, name), name)
        self.assertIsInstance(result.recovered_messages, list)
        self.assertEqual(result.recovered_messages,
                         [message for conversation in result.conversations for message in conversation.messages])

    def test_analyze_runs_without_the_cli(self):
        result = self.analyze()
        self.assertTrue(result.events, "synthetic History 에서 Event 가 나와야 한다")
        self.assertTrue(all(event.service == chatgpt_parser.SERVICE for event in result.events))
        self.assertTrue(result.coverage)

    def test_analyze_rejects_unknown_input_type(self):
        with self.assertRaises(ValueError):
            chatgpt_parser.analyze_chatgpt_web(self.source_dir, input_type="e01")

    def test_analyze_does_not_write_any_file(self):
        """분석과 출력을 분리한다 — analyze 만으로는 파일이 생기지 않는다."""
        before = sorted(path.name for path in self.tmp.rglob("*"))
        self.analyze()
        self.assertEqual(sorted(path.name for path in self.tmp.rglob("*")), before)
        self.assertFalse(self.out_dir.exists())


class FinalOutputTest(PackageTestBase):
    def test_write_final_outputs_writes_only_the_two_final_csv(self):
        written = chatgpt_parser.write_final_outputs(self.analyze(), self.out_dir)
        self.assertEqual(sorted(path.name for path in written), sorted(FINAL_FILES))
        self.assertEqual(sorted(path.name for path in self.out_dir.iterdir()), sorted(FINAL_FILES))

    def test_write_final_outputs_debug_adds_the_development_csv(self):
        written = chatgpt_parser.write_final_outputs(self.analyze(), self.out_dir, debug=True)
        self.assertEqual(sorted(path.name for path in written), sorted(FINAL_FILES + DEBUG_FILES))

    def test_final_csv_schema_is_the_team_schema(self):
        chatgpt_parser.write_final_outputs(self.analyze(), self.out_dir)
        timeline_header, timeline_rows = self.read_csv(self.out_dir / "timeline.csv")
        recovered_header, _ = self.read_csv(self.out_dir / "recovered_conversations.csv")
        self.assertEqual(tuple(timeline_header), chatgpt_parser.CSV_TIMELINE_COLUMNS)
        self.assertEqual(tuple(recovered_header), chatgpt_parser.CSV_RECOVERED_CONVERSATION_COLUMNS)
        self.assertEqual(len(timeline_rows), len(self.analyze().events))

    def test_api_and_cli_produce_the_same_final_csv(self):
        """같은 입력이면 팀 통합(Python API) 결과와 기존 CLI 결과가 같아야 한다."""
        api_dir, cli_dir = self.tmp / "api", self.tmp / "cli"
        chatgpt_parser.write_final_outputs(self.analyze(), api_dir)
        with redirect_stdout(io.StringIO()):
            code = chatgpt_web_parser.main([
                "--dir", str(self.source_dir), "--history", "Default/History", "--csv-dir", str(cli_dir)])
        self.assertEqual(code, 0)
        for name in FINAL_FILES:
            self.assertEqual(self.read_csv(api_dir / name), self.read_csv(cli_dir / name), name)


class CliCompatibilityTest(PackageTestBase):
    def test_existing_cli_options_still_exist(self):
        parser = chatgpt_web_parser.build_arg_parser()
        options = {option for action in parser._actions for option in action.option_strings}
        for name in ("--dir", "--image", "--history", "--csv-dir", "--overwrite", "--debug-output", "--out"):
            self.assertIn(name, options)

    def test_entry_point_module_still_runs(self):
        """python chatgpt_web_parser.py ... 가 그대로 동작한다 (파일을 지우거나 옮기지 않았다)."""
        result = subprocess.run(
            [sys.executable, "-B", str(PROJECT_ROOT / "chatgpt_web_parser.py"),
             "--dir", str(self.source_dir), "--history", "Default/History", "--csv-dir", str(self.out_dir)],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.out_dir / "timeline.csv").exists())

    def test_wrapper_still_exposes_implementation_names(self):
        """기존 테스트·분석 스크립트의 `import chatgpt_web_parser as p` 참조를 끊지 않는다."""
        for name in ("run", "extract", "detect", "main", "build_arg_parser", "CliUsageError",
                     "DirectorySource", "EVENT_RULES", "CSV_TIMELINE_COLUMNS", "write_result_csv"):
            self.assertTrue(hasattr(chatgpt_web_parser, name), name)
        self.assertIs(chatgpt_web_parser.run, chatgpt_parser.run)


class ModuleStructureTest(unittest.TestCase):
    def test_every_module_imports_without_a_cycle(self):
        """각 모듈을 단독으로 먼저 import 해도 순환 import 가 생기지 않아야 한다."""
        for name in ALL_MODULES:
            with self.subTest(module=name):
                code = f"import {name}"
                result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                                        cwd=str(PROJECT_ROOT))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_import_has_no_side_effect(self):
        """import 만으로 화면 출력·파일 생성·작업 폴더 변경이 일어나지 않아야 한다."""
        with tempfile.TemporaryDirectory() as tmp:
            code = (
                "import os, sys, pathlib\n"
                f"sys.path.insert(0, {str(PROJECT_ROOT)!r})\n"
                f"os.chdir({tmp!r})\n"
                "import chatgpt_parser, chatgpt_web_parser\n"
                "print(sorted(os.listdir('.')), os.path.abspath('.') == os.path.abspath(%r))" % tmp
            )
            result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "[] True")
            self.assertEqual(result.stderr, "")

    def test_modules_are_importable_by_their_documented_path(self):
        for name in ALL_MODULES:
            self.assertIsNotNone(importlib.import_module(name))


if __name__ == "__main__":
    unittest.main()
