"""통합 결과 폴더(<out>/<evidence_id>) 읽기 전용 로더.

통합 Runner 가 만든 파일을 읽기만 한다. 다시 쓰지 않고, 헤더·값을 고치지 않는다.
GUI 표시용 가공(표시명, 집계)은 여기서 끝내고 UI 쪽은 결과만 쓴다.
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter, OrderedDict
from dataclasses import dataclass, field

# 통합이 쓰는 파일 이름 (integration/llm_forensic.py 기준)
TIMELINE_CSV = "timeline.csv"
CONVERSATIONS_CSV = "recovered_conversations.csv"
REPORT_JSON = "integration_report.json"
MANIFEST_JSON = "evidence_manifest.json"
UNIFIED_DB = "unified.db"
CASE_JSON = "case_info.json"

# 파일의 원본 헤더는 바꾸지 않고, 화면에만 쓰는 표시명 (끝 공백·소문자 그대로가 원본)
DISPLAY_NAMES = {
    "Model": "Model",
    "Timestamp": "Timestamp",
    "User_behavior": "User Behavior",
    "Behavior_details ": "Behavior Details",
    "Verdict": "Verdict",
    "Artifact_path": "Artifact Path",
    "Artifact_details ": "Artifact Details",
    "timestamp": "Timestamp",
    "conversation_uuid": "Conversation UUID",
    "conversation_title": "Conversation Title",
    "message_uuid": "Message UUID",
    "parent_message_uuid": "Parent Message UUID",
    "message order": "Message Order",
    "role": "Role",
    "content": "Content",
    "source_parser": "Source Parser",
    "parser_version": "Parser Version",
    "source_file": "Source File",
    "parse_time_utc": "Parse Time (UTC)",
    "artifact_path_normalized": "Artifact Path (normalized)",
    "volume_ref": "Volume",
    "evidence_id": "Evidence ID",
    "evidence_sha256": "Evidence SHA-256",
}
# Timeline 표에 보여 줄 열 (나머지는 상세 패널에서 전체를 보여 준다)
TIMELINE_VIEW_COLUMNS = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                         "Artifact_path", "source_parser"]
VERDICT_CONFIRMED = "확정"
VERDICT_SUSPECTED = "의심"
EMPTY = "-"


class ResultLoadError(Exception):
    """결과 폴더를 읽을 수 없을 때."""


def _read_csv(path):
    """(헤더, 행 목록). 파일이 없으면 ([], []). 통합 병합 CSV 는 utf-8-sig."""
    if not os.path.isfile(path):
        return [], []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fields = list(reader.fieldnames or [])
        return fields, [dict(row) for row in reader]


def _read_json(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def cell(row, column):
    """표시용 값. 없거나 빈 값은 '-' (값을 만들어 내지 않는다)."""
    value = row.get(column)
    return EMPTY if value is None or str(value).strip() == "" else str(value)


@dataclass
class ConversationSession:
    """recovered_conversations.csv 를 conversation_uuid 로 묶은 한 대화."""

    conversation_uuid: str
    title: str
    model: str
    first_timestamp: str
    messages: list = field(default_factory=list)


@dataclass
class ResultBundle:
    """결과 폴더 1개의 내용. 모든 값은 파일에서 읽은 그대로다."""

    result_dir: str
    timeline_columns: list
    timeline_rows: list
    conversation_columns: list
    conversation_rows: list
    report: dict | None
    manifest: dict | None
    case_info: dict | None

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, result_dir):
        result_dir = os.path.abspath(result_dir)
        if not os.path.isdir(result_dir):
            raise ResultLoadError("결과 폴더가 없습니다: %s" % result_dir)
        tl_cols, tl_rows = _read_csv(os.path.join(result_dir, TIMELINE_CSV))
        cv_cols, cv_rows = _read_csv(os.path.join(result_dir, CONVERSATIONS_CSV))
        report = _read_json(os.path.join(result_dir, REPORT_JSON))
        if not tl_cols and not cv_cols and report is None:
            raise ResultLoadError("통합 결과 파일(%s / %s / %s)을 찾을 수 없습니다: %s"
                                  % (TIMELINE_CSV, CONVERSATIONS_CSV, REPORT_JSON, result_dir))
        return cls(result_dir=result_dir, timeline_columns=tl_cols, timeline_rows=tl_rows,
                   conversation_columns=cv_cols, conversation_rows=cv_rows, report=report,
                   manifest=_read_json(os.path.join(result_dir, MANIFEST_JSON)),
                   case_info=_read_json(os.path.join(result_dir, CASE_JSON)))

    def path(self, name):
        return os.path.join(self.result_dir, name)

    def has_db(self):
        return os.path.isfile(self.path(UNIFIED_DB))

    # --------------------------------------------------------------- summary
    def evidence(self):
        """evidence_manifest.json 또는 integration_report.json 의 evidence 정보 (없으면 {})."""
        if self.manifest:
            return self.manifest
        return (self.report or {}).get("evidence", {})

    def metrics(self):
        """Overview 지표. 결과 파일에서 셀 수 있는 값만 담는다."""
        verdicts = Counter(cell(r, "Verdict") for r in self.timeline_rows)
        parsers = (self.report or {}).get("parsers", {})
        summary = (self.report or {}).get("summary", {})
        services = {cell(r, "source_parser") for r in self.timeline_rows} | {
            cell(r, "source_parser") for r in self.conversation_rows}
        services.discard(EMPTY)
        error_count = sum(int(p.get("error_count") or 0) for p in parsers.values())
        error_count += len((self.report or {}).get("integration_errors", []))
        return OrderedDict([
            ("Services with Results", str(len(services))),
            ("Timeline Events", str(len(self.timeline_rows))),
            ("Recovered Messages", str(len(self.conversation_rows))),
            (VERDICT_CONFIRMED, str(verdicts.get(VERDICT_CONFIRMED, 0))),
            (VERDICT_SUSPECTED, str(verdicts.get(VERDICT_SUSPECTED, 0))),
            ("Parser Errors", str(error_count)),
            ("Parsers Run", str(summary.get("parsers_run", len(parsers)))),
            ("Parsers Succeeded", str(summary.get("success", "-"))),
        ])

    def parser_states(self):
        """[(parser, status, timeline_rows, conversation_rows)] — report 에 있는 그대로."""
        parsers = (self.report or {}).get("parsers", {})
        rows = [(name, info.get("status", "-"), info.get("timeline_rows", 0), info.get("conversation_rows", 0))
                for name, info in parsers.items()]
        if not rows:   # report 가 없으면 CSV 의 source_parser 로만 (상태는 모른다고 표시)
            counts = Counter(cell(r, "source_parser") for r in self.timeline_rows)
            rows = [(name, "-", n, 0) for name, n in sorted(counts.items()) if name != EMPTY]
        return sorted(rows)

    def error_rows(self):
        """Errors & Limitations 표. report 의 오류를 그대로 펼친다 (원인 추측 없음)."""
        report = self.report or {}
        out = []
        for name, info in (report.get("parsers") or {}).items():
            status = info.get("status", "-")
            for err in info.get("errors") or []:
                out.append({"Module": name, "Severity": status, "Type": err.get("type", "-"),
                            "Message": _error_text(err), "Processing Result": _processing_result(status),
                            "_raw": err})
            if not (info.get("errors") or []) and status not in ("success", "-"):
                out.append({"Module": name, "Severity": status, "Type": "-",
                            "Message": "상세 오류가 보고서에 없습니다 (run.log 참조)",
                            "Processing Result": _processing_result(status),
                            "_raw": {"run_log": info.get("run_log")}})
            if info.get("errors_truncated"):
                out.append({"Module": name, "Severity": "warning", "Type": "ERRORS_TRUNCATED",
                            "Message": "보고서에는 앞 100건만 기록됨 (전체는 unified.db runs.violations)",
                            "Processing Result": "일부만 표시", "_raw": {}})
        for err in report.get("integration_errors") or []:
            out.append({"Module": err.get("parser") or "integration", "Severity": "integration",
                        "Type": err.get("type", "-"), "Message": _error_text(err),
                        "Processing Result": "통합 단계 실패", "_raw": err})
        for text in report.get("warnings") or []:
            out.append({"Module": "integration", "Severity": "warning", "Type": "WARNING",
                        "Message": str(text), "Processing Result": "계속 진행", "_raw": {}})
        return out

    def limitations(self):
        """보고서에 실제로 적힌 제한만 문장으로 모은다."""
        report = self.report or {}
        notes = []
        if report.get("quick"):
            notes.append("--quick 실행: evidence_sha256 를 계산하지 않았으므로 무결성 대조가 불가합니다.")
        if report.get("mode") == "only":
            notes.append("선택 실행(--only %s): 선택하지 않은 파서의 결과는 이번 실행에서 생성되지 않았습니다."
                         % ", ".join(report.get("only") or []))
        for name in report.get("preserved_from_previous_runs") or []:
            notes.append("%s 결과는 이번 실행이 아니라 이전 실행에서 남은 행입니다." % name)
        for name, info in (report.get("parsers") or {}).items():
            if info.get("status") != "success":
                notes.append("%s: status=%s (returncode=%s) — 이 서비스의 흔적 부재를 뜻하지 않습니다."
                             % (name, info.get("status"), info.get("returncode")))
            elif not info.get("timeline_rows") and not info.get("conversation_rows"):
                notes.append("%s: 실행은 성공했고 결과 행이 0건입니다 (미발견과 미분석은 다릅니다)." % name)
        if self.report is None:
            notes.append("integration_report.json 이 없어 실행 상태·오류 정보를 표시할 수 없습니다.")
        return notes

    # ----------------------------------------------------------- artifacts
    def artifact_rows(self):
        """Timeline 행에서 아티팩트 관점으로 추린 표. 새 사실을 만들지 않고 같은 행을 다르게 모은 것이다."""
        grouped = OrderedDict()
        for row in self.timeline_rows:
            path = cell(row, "Artifact_path")
            key = (cell(row, "source_parser"), path)
            entry = grouped.setdefault(key, {
                "Artifact Type": _artifact_type(cell(row, "Artifact_details ")),
                "Service": cell(row, "source_parser"), "Model": cell(row, "Model"),
                "Artifact Path": path, "Related Behavior": set(), "First Timestamp": EMPTY,
                "Events": 0, "_rows": []})
            entry["Related Behavior"].add(cell(row, "User_behavior"))
            entry["Events"] += 1
            entry["_rows"].append(row)
            ts = cell(row, "Timestamp")
            if ts != EMPTY and (entry["First Timestamp"] == EMPTY or ts < entry["First Timestamp"]):
                entry["First Timestamp"] = ts
        out = []
        for entry in grouped.values():
            entry["Related Behavior"] = ", ".join(sorted(entry["Related Behavior"]))
            entry["Events"] = str(entry["Events"])
            out.append(entry)
        return out

    # -------------------------------------------------------- conversations
    def conversation_sessions(self):
        """conversation_uuid 별 세션 목록 (파일 순서 유지, 메시지는 message order 로 정렬)."""
        sessions = OrderedDict()
        for row in self.conversation_rows:
            uuid = cell(row, "conversation_uuid")
            session = sessions.get(uuid)
            if session is None:
                session = ConversationSession(conversation_uuid=uuid, title=cell(row, "conversation_title"),
                                              model=cell(row, "Model"), first_timestamp=cell(row, "timestamp"))
                sessions[uuid] = session
            session.messages.append(row)
            ts = cell(row, "timestamp")
            if ts != EMPTY and (session.first_timestamp == EMPTY or ts < session.first_timestamp):
                session.first_timestamp = ts
        for session in sessions.values():
            session.messages.sort(key=lambda r: _order_key(cell(r, "message order")))
        return list(sessions.values())


def _order_key(value):
    try:
        return (0, int(value))
    except (TypeError, ValueError):
        return (1, str(value))


def _artifact_type(details):
    """Artifact_details 안에 'artifact_type=' 가 실제로 있으면 그 값, 없으면 '-' (추론하지 않는다)."""
    for part in str(details).split("|"):
        part = part.strip()
        if part.startswith("artifact_type="):
            return part.split("=", 1)[1].strip() or EMPTY
    return EMPTY


def _error_text(err):
    where = " ".join(str(x) for x in (err.get("file"), err.get("row") and "row %s" % err["row"], err.get("field")) if x)
    text = "%s%s" % (where + ": " if where else "", err.get("message", ""))
    if err.get("actual") is not None or err.get("expected") is not None:
        text += " (actual=%s, expected=%s)" % (err.get("actual"), err.get("expected"))
    return text


def _processing_result(status):
    return {"success": "적재됨", "failed": "파서 실행 실패 — 결과 미적재",
            "contract_violation": "계약 위반 — 결과 미적재", "normalization_error": "정규화 실패 — 결과 미적재",
            "db_error": "DB 적재 실패", "output_error": "병합 출력 실패"}.get(status, status or "-")


def find_result_dirs(root):
    """선택한 폴더가 결과 폴더인지, 아니면 그 안의 evidence_id 폴더들이 결과인지 찾는다."""
    root = os.path.abspath(root)
    if os.path.isfile(os.path.join(root, REPORT_JSON)) or os.path.isfile(os.path.join(root, TIMELINE_CSV)):
        return [root]
    found = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            sub = os.path.join(root, name)
            if os.path.isdir(sub) and (os.path.isfile(os.path.join(sub, REPORT_JSON))
                                       or os.path.isfile(os.path.join(sub, TIMELINE_CSV))):
                found.append(sub)
    return found
