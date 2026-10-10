"""기존 통합 Runner(integration/llm_forensic.py)를 QProcess 로 실행하는 어댑터.

통합 코드·파서를 수정하거나 복제하지 않는다. CLI 를 그대로 호출하고 표준출력만 읽는다.
  python -u integration/llm_forensic.py -i <image> -o <out> [--only a,b] [--quick]
진행률(%)은 Runner 가 내보내지 않으므로 만들어 내지 않는다. 단계 이름만 신호로 보낸다.
"""
from __future__ import annotations

import os
import re
import sys

from PyQt6.QtCore import QObject, QProcess, QProcessEnvironment, pyqtSignal

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(REPO_ROOT, "integration", "llm_forensic.py")
REGISTRY = os.path.join(REPO_ROOT, "integration", "parsers.json")

# 종료코드 (integration/llm_forensic.py 모듈 docstring)
EXIT_MEANING = {0: "전부 성공", 1: "일부 파서 실패 또는 계약 위반", 2: "입력 자체 실패",
                3: "통합 DB·병합 출력 오류"}

_EVIDENCE = re.compile(r"^\[Evidence\]\s+(?P<body>.*)$")
_RUNNER = re.compile(r"^\[Runner\]\s+(?P<name>\S+)\s*(?P<rest>.*)$")
_RESULT = re.compile(r"^\s*(?P<label>OK|FAILED|CONTRACT_VIOLATION|NORMALIZATION_ERROR|DB_ERROR|OUTPUT_ERROR)\b")
_REPORT = re.compile(r"^\[Report\]\s+(?P<path>.+)$")
_TIMELINE = re.compile(r"^\[Timeline\]\s+(?P<path>.+?)\s+\d+행\s*$")
# [DB] 는 경로·초기화 안내와 치명적 실패를 같은 접두사로 낸다. 실패면 파서를 하나도 실행하지 않고
# 종료코드 3 으로 끝나므로(llm_forensic.py), 보고서를 읽기 전에 화면에서 바로 보이게 한다.
_DB_FAILED = re.compile(r"^\[DB\]\s+FAILED\s+(?P<code>\S+)\s*(?P<rest>.*)$")
_LABEL_TO_STATUS = {"OK": "success", "FAILED": "failed", "CONTRACT_VIOLATION": "contract_violation",
                    "NORMALIZATION_ERROR": "normalization_error", "DB_ERROR": "db_error",
                    "OUTPUT_ERROR": "output_error"}


def _registry(path=REGISTRY):
    import json
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def registry_parsers(path=REGISTRY):
    """[(parser_id, model)] — 레지스트리에 실제로 등록된 파서만. 이름을 GUI 에 하드코딩하지 않는다."""
    return [(p["name"], p.get("model", p["name"])) for p in _registry(path).get("parsers", [])
            if p.get("enabled", True)]


def parsers_skipping(image, path=REGISTRY):
    """이 이미지 확장자를 레지스트리 inputs 에 선언하지 않은 파서 이름 — 통합기가 UNSUPPORTED_INPUT 으로 건너뛴다.

    판단 기준은 llm_forensic.py run_parser() 와 같다 (inputs 가 비어 있으면 검사하지 않는다).
    확장자로 결과를 바꾸지 않고, 실행 전에 어느 파서가 건너뛰는지만 미리 알려 주기 위한 것이다.
    """
    ext = os.path.splitext(image)[1].lower()
    skipped = []
    for p in _registry(path).get("parsers", []):
        if not p.get("enabled", True):
            continue
        inputs = [str(s).lower() for s in p.get("inputs", [])]
        if inputs and ext not in inputs:
            skipped.append(p["name"])
    return skipped


class IntegrationRunner(QObject):
    """QProcess 기반 비동기 실행기. UI 스레드를 막지 않는다."""

    logLine = pyqtSignal(str)                 # 표준출력/표준오류 한 줄
    stageChanged = pyqtSignal(str)            # 사람이 읽는 현재 단계
    parserStatus = pyqtSignal(str, str)       # (parser_id, waiting|running|success|failed|…)
    evidenceInfo = pyqtSignal(str)            # [Evidence] 줄 본문
    finished = pyqtSignal(int, str)           # (exit_code, 결과 폴더 경로 또는 "")

    def __init__(self, parent=None):
        super().__init__(parent)
        self._proc = None
        self._buffer = ""
        self._result_dir = ""
        self._current_parser = ""

    def is_running(self):
        return self._proc is not None and self._proc.state() != QProcess.ProcessState.NotRunning

    def command(self, image, out_dir, only=None, quick=False):
        args = ["-u", RUNNER, "-i", image, "-o", out_dir, "--registry", REGISTRY]
        if only:
            args += ["--only", ",".join(only)]
        if quick:
            args.append("--quick")
        return sys.executable, args

    def start(self, image, out_dir, only=None, quick=False):
        if self.is_running():
            raise RuntimeError("이미 분석이 실행 중입니다")
        self._buffer, self._result_dir, self._current_parser = "", "", ""
        program, args = self.command(image, out_dir, only, quick)
        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.setWorkingDirectory(os.path.join(REPO_ROOT, "integration"))
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")          # 한글 출력이 cp949 로 깨지지 않게
        env.insert("PYTHONUTF8", "1")
        proc.setProcessEnvironment(env)
        proc.readyReadStandardOutput.connect(self._on_output)
        proc.finished.connect(self._on_finished)
        proc.errorOccurred.connect(self._on_error)
        self._proc = proc
        self.logLine.emit("$ %s %s" % (program, " ".join(args)))
        self.stageChanged.emit("증거 이미지 확인 중...")
        proc.start(program, args)

    def cancel(self):
        if self.is_running():
            self.logLine.emit("[GUI] 사용자 요청으로 분석을 중단합니다 (원본 증거는 변경되지 않습니다)")
            self._proc.kill()
            self._proc.waitForFinished(3000)   # 창을 닫는 중이면 자식 프로세스가 끝난 것을 확인하고 나간다

    # ------------------------------------------------------------ internals
    def _on_output(self):
        data = bytes(self._proc.readAllStandardOutput())
        self._buffer += data.decode("utf-8", "replace")
        while True:
            index = max(self._buffer.find("\n"), self._buffer.find("\r"))
            if index < 0:
                break
            line, self._buffer = self._buffer[:index], self._buffer[index + 1:]
            if line.strip():
                self._handle_line(line.rstrip())
        # "[Runner] name" 은 줄바꿈 없이 먼저 나온다 → 꼬리만 남은 경우도 단계 표시에 쓴다
        tail = self._buffer.strip()
        match = _RUNNER.match(tail) if tail else None
        if match and match.group("name") != self._current_parser:
            self._current_parser = match.group("name")
            self.parserStatus.emit(self._current_parser, "running")
            self.stageChanged.emit("%s 분석 중..." % self._current_parser)

    def _handle_line(self, line):
        self.logLine.emit(line)
        match = _EVIDENCE.match(line)
        if match:
            self.evidenceInfo.emit(match.group("body"))
            self.parserStatus.emit("evidence", "success" if "실패" not in match.group("body") else "failed")
            return
        match = _RUNNER.match(line)
        if match:
            name, rest = match.group("name"), match.group("rest")
            self._current_parser = name
            result = _RESULT.match(rest)
            if result:                                    # 같은 줄에 결과까지 온 경우
                self.parserStatus.emit(name, _LABEL_TO_STATUS.get(result.group("label"), "success"))
            else:
                self.parserStatus.emit(name, "running")
                self.stageChanged.emit("%s 분석 중..." % name)
            return
        match = _DB_FAILED.match(line)
        if match:                                         # 통합 DB 를 열지 못함 → 파서를 하나도 실행하지 않는다
            self.parserStatus.emit("db", "failed")
            self.stageChanged.emit("통합 DB 오류 (%s) — 파서를 실행하지 못했습니다" % match.group("code"))
            return
        result = _RESULT.match(line)
        if result and self._current_parser:               # 결과만 따로 온 줄
            self.parserStatus.emit(self._current_parser, _LABEL_TO_STATUS.get(result.group("label"), "success"))
            return
        if _TIMELINE.match(line):
            self.parserStatus.emit("normalization", "success")
            self.stageChanged.emit("결과 정규화·병합 중...")
            return
        match = _REPORT.match(line)
        if match:
            self._result_dir = os.path.dirname(os.path.abspath(match.group("path").strip()))

    def _on_error(self, error):
        self.logLine.emit("[GUI] 프로세스 오류: %s" % error.name)

    def _on_finished(self, code, status):
        if status == QProcess.ExitStatus.CrashExit:
            self.logLine.emit("[GUI] 프로세스가 비정상 종료되었습니다 (중단 요청 포함)")
        self.stageChanged.emit("종료 (exit=%d · %s)" % (code, EXIT_MEANING.get(code, "알 수 없는 종료코드")))
        self._proc = None
        self.finished.emit(code, self._result_dir)
