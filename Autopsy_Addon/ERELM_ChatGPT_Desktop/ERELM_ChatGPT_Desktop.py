# -*- coding: utf-8 -*-
"""ERELM ChatGPT Desktop (Codex) — Autopsy Data Source Ingest Module (thin adapter).

경계 (PL 'DFIR 생태계 확장 — Thin Adapter' 문서 기준)
  Autopsy / TSK : 이미지·파일시스템 처리, 파일 탐색(FileManager), 결과 표시(Blackboard·Timeline·Report)
  이 모듈      : 필요한 파일만 꺼내 임시 폴더에 풀고, 외부 CPython 의 ERELM 파서를 실행, 결과 CSV 를 Blackboard 에 올림
  ERELM 파서   : LLM 아티팩트 해석·대조·행위 판정 (ChatGPT_APP_Parser, 수정 없음)

Autopsy 의 Python 은 Jython 2.7 이라 CPython 3 파서를 import 하지 않고 subprocess 로 부른다.
전역/static 상태 없음 — 모든 상태는 ingest job 마다 새로 만들어지는 모듈 인스턴스에 둔다.
"""
import csv
import inspect
import json
import os
import re

import jarray
from java.io import File
from java.lang import ProcessBuilder, System
from java.text import SimpleDateFormat
from java.util import ArrayList, Date, TimeZone
from java.util.logging import Level

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import ExecUtil, Logger
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.ingest import (DataSourceIngestModule, DataSourceIngestModuleProcessTerminator,
                                          IngestMessage, IngestModule, IngestModuleFactoryAdapter, IngestServices)
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, TimelineEventType, TskData

MODULE_NAME = "ERELM ChatGPT Desktop (Codex) Parser"
MODULE_VERSION = "0.1.0"
MODULE_DIR = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))
MAX_FILE_BYTES = 64 * 1024 * 1024          # 파서의 파일 크기 상한과 같게

# Autopsy 에 요청할 파일 (파일명 LIKE, 부모 경로에 포함될 문자열) — 파서 SCAN_ROOTS 와 같은 범위.
# WindowsApps 패키지 본체(실행 파일 수백 MB)는 내용이 아니라 폴더 생성 시각만 쓰이므로 꺼내지 않는다.
FILE_QUERIES = (
    ("%", "/.codex/"),
    ("%", "/Documents/Codex/"),
    ("%", "/Packages/OpenAI.Codex_2p2nqsd0c76g0/"),
    ("CODEX%.pf", "/Windows/Prefetch/"),
    ("CHATGPT%.pf", "/Windows/Prefetch/"),
    ("%.lnk", "/AppData/Roaming/Microsoft/Windows/Recent/"),
)
# 내용은 꺼내지 않고 메타데이터(MFT 시각 등)만 넘기는 항목 — Autopsy 가 이미 읽어 둔 값을 파서가 다시 읽지 않게.
#   폴더: 패키지 폴더의 생성 시각 = 설치 시각
#   파일: 최근 항목 바로가기가 가리킬 수 있는 저장 위치의 파일 (생성 시각·크기·첫 8바이트로 '새로 저장된 문서인지' 판정)
META_DIR_QUERIES = (
    ("OpenAI.Codex_%", "/Program Files/WindowsApps/"),
    ("OpenAI.Codex_2p2nqsd0c76g0", "/AppData/Local/Packages/"),
)
META_FILE_PARENTS = ("/Downloads/", "/Desktop/", "/Documents/")
META_FILE_LIMIT = 20000                    # ponytail: 저장 위치 3곳·2만 개 상한. 다른 드라이브·폴더 저장은 놓친다 → 필요 시 파서가 요청 목록을 내는 2단계로
HOST_META_NAME = "_host_metadata.json"     # 파서(cxparser.vfs.DirectoryVfs)와 약속한 파일명

# 볼륨 루트 기준 경로로 맞춘다 (논리 파일 세트는 앞에 '/LogicalFileSet1/<폴더>' 가 붙는다)
ANCHOR = re.compile(r"(?i)/(users|windows|programdata|program files)/")


def iso_utc(epoch):
    """Autopsy 의 epoch 초 -> 'YYYY-MM-DDTHH:MM:SSZ'. 0(없음)이면 None."""
    if not epoch:
        return None
    fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    fmt.setTimeZone(TimeZone.getTimeZone("UTC"))
    return fmt.format(Date(epoch * 1000))


def host_entry(f, rel, with_head=False):
    """AbstractFile -> 파서에 넘길 메타데이터 한 건."""
    e = {"path": rel, "size": f.getSize(), "dir": bool(f.isDir()), "mft_record": f.getMetaAddr(),
         "times": {"created": iso_utc(f.getCrtime()), "modified": iso_utc(f.getMtime()),
                   "mft_modified": iso_utc(f.getCtime()), "accessed": iso_utc(f.getAtime())}}
    if with_head and f.getSize() > 0:
        buf = jarray.zeros(8, "b")
        try:
            n = f.read(buf, 0, 8)
            e["head_hex"] = "".join("%02x" % (b & 0xFF) for b in buf[:max(n, 0)])
        except Exception:  # noqa: BLE001
            pass
    return e


def load_config():
    """erelm_config.json (모듈 폴더) + 환경변수 ERELM_PYTHON / ERELM_PARSER_DIR.
    파서를 모듈 폴더 안에 같이 넣었으면(ChatGPT_APP_Parser/) 설정 없이 그것을 쓴다."""
    cfg = {"python": "python", "parser_dir": os.path.join(MODULE_DIR, "ChatGPT_APP_Parser")}
    path = os.path.join(MODULE_DIR, "erelm_config.json")
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            cfg.update(json.loads(fh.read().decode("utf-8-sig")))
    for key, env in (("python", "ERELM_PYTHON"), ("parser_dir", "ERELM_PARSER_DIR")):
        if System.getenv(env):
            cfg[key] = System.getenv(env)
    return cfg


def read_csv(path):
    """UTF-8(BOM) CSV -> [dict]. Jython 2.7 csv 는 바이트만 다루므로 셀마다 디코드한다. 헤더 끝 공백은 떼고 쓴다."""
    if not os.path.isfile(path):
        return []
    csv.field_size_limit(1 << 30)
    with open(path, "rb") as fh:
        rows = [[c.decode("utf-8") for c in r] for r in csv.reader(fh)]
    if not rows:
        return []
    header = [h.replace(u"﻿", u"").strip() for h in rows[0]]
    return [dict(zip(header, r)) for r in rows[1:]]


def kst_to_epoch(ts):
    """팀 계약 시각 문자열(YYYY-MM-DD HH:MM:SS.ffffff KST) -> epoch 초. 시각 없음이면 None."""
    if not ts or len(ts) < 19 or ts[4] != "-":
        return None
    fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    fmt.setTimeZone(TimeZone.getTimeZone("Asia/Seoul"))
    try:
        return fmt.parse(ts[:19]).getTime() / 1000
    except Exception:  # noqa: BLE001
        return None


class ErelmChatGptDesktopIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME

    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return ("ChatGPT Desktop (Codex) user behaviors and conversations, parsed by the ERELM LLM forensic parser. "
                "Autopsy provides the files; the external ERELM parser interprets them.")

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ErelmChatGptDesktopIngestModule()


class ErelmChatGptDesktopIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(MODULE_NAME)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.cfg = load_config()
        runner = os.path.join(self.cfg["parser_dir"], "run_parser.py")
        if not os.path.isfile(runner):
            raise IngestModuleException("ERELM parser not found: %s (set parser_dir in erelm_config.json)" % runner)

    # ------------------------------------------------------------------ 1. Autopsy 에서 파일 받기
    def export_files(self, dataSource, export_dir):
        """FileManager 로 찾은 파일을 볼륨 기준 경로 그대로 export_dir 에 풀고, Autopsy 가 가진 메타데이터를 옆에 적는다.
        반환: ({소문자 경로: AbstractFile}, 건너뛴 수)."""
        fm = Case.getCurrentCase().getServices().getFileManager()
        by_path, skipped = {}, {"deleted": 0, "slack": 0, "big": 0, "ads": 0, "error": 0}
        entries = {}

        def rel_of(f):
            full = f.getParentPath() + f.getName()
            m = ANCHOR.search(full)
            return full[m.start():] if m else None

        def live(f):
            return (f.getType() != TskData.TSK_DB_FILES_TYPE_ENUM.SLACK
                    and not f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC) and ":" not in f.getName())

        for name, parent in META_DIR_QUERIES:
            for f in fm.findFiles(dataSource, name, parent):
                rel = rel_of(f)
                if rel and f.isDir() and live(f):
                    entries[rel.lower()] = host_entry(f, rel)
        for parent in META_FILE_PARENTS:
            for f in fm.findFiles(dataSource, "%", parent):
                if len(entries) >= META_FILE_LIMIT or self.context.dataSourceIngestIsCancelled():
                    break
                rel = rel_of(f)
                if rel and f.isFile() and live(f):
                    entries[rel.lower()] = host_entry(f, rel, with_head=True)
        for name, parent in FILE_QUERIES:
            for f in fm.findFiles(dataSource, name, parent):
                if self.context.dataSourceIngestIsCancelled():
                    return by_path, skipped
                if not f.isFile():
                    continue
                if f.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.SLACK:
                    skipped["slack"] += 1
                    continue
                if f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC):
                    skipped["deleted"] += 1          # 같은 경로의 현존 파일을 덮어쓰지 않게. 삭제 파일은 다음 단계 과제
                    continue
                if ":" in f.getName():
                    skipped["ads"] += 1              # 대체 데이터 스트림 — Windows 파일명으로 쓸 수 없음
                    continue
                if f.getSize() > MAX_FILE_BYTES:
                    skipped["big"] += 1
                    continue
                full = f.getParentPath() + f.getName()
                m = ANCHOR.search(full)
                if not m:
                    continue
                rel = full[m.start():]
                if rel.lower() in by_path:
                    continue
                target = File(export_dir, rel.lstrip("/"))
                target.getParentFile().mkdirs()
                try:
                    ContentUtils.writeToFile(f, target)
                    by_path[rel.lower()] = f
                    entries[rel.lower()] = host_entry(f, rel)
                except Exception as exc:  # noqa: BLE001
                    skipped["error"] += 1
                    self.log(Level.WARNING, "export failed %s: %s" % (full, exc))
        if by_path:
            with open(os.path.join(export_dir, HOST_META_NAME), "wb") as fh:
                fh.write(json.dumps({"schema": 1, "provider": "Autopsy (ERELM thin adapter %s)" % MODULE_VERSION,
                                     "entries": entries}, ensure_ascii=True).encode("ascii"))
        return by_path, skipped

    # ------------------------------------------------------------------ 2. 외부 CPython 파서 실행
    def run_parser(self, export_dir, out_dir, log_path):
        cmd = ArrayList()
        for a in (self.cfg["python"], "run_parser.py", "--input", export_dir, "--input-type", "dir",
                  "--out-dir", out_dir, "--format", "both", "--overwrite"):
            cmd.add(a)
        pb = ProcessBuilder(cmd)
        pb.directory(File(self.cfg["parser_dir"]))
        pb.environment().put("PYTHONIOENCODING", "utf-8")
        pb.redirectErrorStream(True)
        pb.redirectOutput(File(log_path))
        return ExecUtil.execute(pb, DataSourceIngestModuleProcessTerminator(self.context))   # 취소 시 프로세스 종료

    # ------------------------------------------------------------------ 3. 결과를 Blackboard 에 올리기
    def post_results(self, dataSource, by_path, out_dir):
        bb = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        STRING = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        STD = BlackboardAttribute.ATTRIBUTE_TYPE
        behavior_type = bb.getOrAddArtifactType("ERELM_LLM_USER_BEHAVIOR", "LLM User Behavior (ERELM)")
        message_type = BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE)
        tl_type = BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT)
        custom = dict((n, bb.getOrAddAttributeType(n, STRING, d)) for n, d in (
            ("ERELM_TIMESTAMP", "Timestamp (KST)"),
            ("ERELM_MODEL", "LLM Service"), ("ERELM_USER_BEHAVIOR", "User Behavior"),
            ("ERELM_BEHAVIOR_DETAILS", "Behavior Details"), ("ERELM_VERDICT", "Verdict"),
            ("ERELM_ARTIFACT_PATH", "Artifact Path"), ("ERELM_ARTIFACT_DETAILS", "Artifact Details"),
            ("ERELM_ROLE", "Role"), ("ERELM_MESSAGE_UUID", "Message UUID"), ("ERELM_MESSAGE_ORDER", "Message Order")))

        def source_of(artifact_path):
            """파서의 Artifact_path(C: 로 시작하는 Windows 표기) -> 그 파일의 AbstractFile. 못 찾으면 data source."""
            p = (artifact_path or "").split(" | ")[0].replace("\\", "/")
            p = p[2:] if p[1:2] == ":" else p
            return by_path.get(p.lower(), dataSource)

        def attr(type_, value):
            return BlackboardAttribute(type_, MODULE_NAME, value)

        posted, counts = ArrayList(), {"behaviors": 0, "timeline_events": 0, "messages": 0, "duplicates": 0}

        def add(content, art_type, attrs, key):
            if bb.artifactExists(content, art_type, attrs):          # 같은 data source 에 다시 돌려도 중복 없이
                counts["duplicates"] += 1
                return
            posted.add(content.newDataArtifact(art_type, attrs))
            counts[key] += 1

        # timeline.csv 한 행 = 'LLM User Behavior (ERELM)' 한 건 (팀 계약 7열을 값 그대로).
        # 시각은 문자열 그대로 두고, Timeline 용으로는 TSK_TL_EVENT 를 따로 올린다 — 사용자 정의 artifact 에 DATETIME 을
        # 넣으면 Timeline 설명이 '<유형>: <artifact id>' 로만 나오기 때문 (TL_EVENT 는 TSK_DESCRIPTION 이 설명이 된다).
        for r in read_csv(os.path.join(out_dir, "timeline.csv")):
            content = source_of(r.get("Artifact_path"))
            attrs = ArrayList()
            for name, col in (("ERELM_TIMESTAMP", "Timestamp"), ("ERELM_MODEL", "Model"), ("ERELM_USER_BEHAVIOR", "User_behavior"),
                              ("ERELM_BEHAVIOR_DETAILS", "Behavior_details"), ("ERELM_VERDICT", "Verdict"),
                              ("ERELM_ARTIFACT_PATH", "Artifact_path"), ("ERELM_ARTIFACT_DETAILS", "Artifact_details")):
                attrs.add(attr(custom[name], r.get(col) or "-"))
            add(content, behavior_type, attrs, "behaviors")
            epoch = kst_to_epoch(r.get("Timestamp"))
            if epoch is not None:
                tl = ArrayList()
                tl.add(attr(STD.TSK_TL_EVENT_TYPE, TimelineEventType.STANDARD_ARTIFACT_CATCH_ALL.getTypeID()))
                tl.add(attr(STD.TSK_DATETIME, epoch))
                tl.add(attr(STD.TSK_DESCRIPTION, u"[ChatGPT Desktop] %s (%s): %s" % (
                    r.get("User_behavior", ""), r.get("Verdict", ""), r.get("Behavior_details", ""))))
                add(content, tl_type, tl, "timeline_events")

        for r in read_csv(os.path.join(out_dir, "recovered_conversations.csv")):
            attrs = ArrayList()
            epoch = kst_to_epoch(r.get("timestamp"))
            if epoch is not None:
                attrs.add(attr(STD.TSK_DATETIME, epoch))
            role = r.get("role") or "-"
            attrs.add(attr(STD.TSK_MESSAGE_TYPE, "ChatGPT Desktop (Codex)"))
            attrs.add(attr(STD.TSK_DIRECTION, "Outgoing" if role == "user" else "Incoming"))
            attrs.add(attr(STD.TSK_THREAD_ID, r.get("conversation_uuid") or "-"))
            attrs.add(attr(STD.TSK_SUBJECT, r.get("conversation_title") or "-"))
            attrs.add(attr(STD.TSK_TEXT, r.get("content") or "-"))
            attrs.add(attr(custom["ERELM_ROLE"], role))
            attrs.add(attr(custom["ERELM_MESSAGE_UUID"], r.get("message_uuid") or "-"))
            attrs.add(attr(custom["ERELM_MESSAGE_ORDER"], r.get("message order") or "-"))
            attrs.add(attr(custom["ERELM_ARTIFACT_PATH"], r.get("Artifact_path") or "-"))
            add(source_of(r.get("Artifact_path")), message_type, attrs, "messages")

        if not posted.isEmpty():
            try:
                bb.postArtifacts(posted, MODULE_NAME, self.context.getJobId())
            except TypeError:                                        # 이전 Autopsy: ingest job id 인자 없음
                bb.postArtifacts(posted, MODULE_NAME)
        return counts

    # ------------------------------------------------------------------ 진입점
    def process(self, dataSource, progressBar):
        progressBar.switchToDeterminate(4)
        case = Case.getCurrentCase()
        work = os.path.join(case.getModuleDirectory(), "ERELM_ChatGPT_Desktop", "ds_%d" % dataSource.getId())
        export_dir, out_dir = os.path.join(work, "export"), os.path.join(work, "out")
        for d in (export_dir, out_dir):
            if not os.path.isdir(d):
                os.makedirs(d)

        progressBar.progress("Exporting Codex files from Autopsy", 0)
        by_path, skipped = self.export_files(dataSource, export_dir)
        self.log(Level.INFO, "exported %d files, skipped %s" % (len(by_path), skipped))
        if self.context.dataSourceIngestIsCancelled():
            return IngestModule.ProcessResult.OK
        if not by_path:                                              # 흔적 없음은 오류가 아니다 (negative control)
            self.message(IngestMessage.MessageType.INFO, "No ChatGPT Desktop (Codex) files in this data source.")
            return IngestModule.ProcessResult.OK

        progressBar.progress("Running ERELM parser", 1)
        log_path = os.path.join(work, "parser.log")
        code = self.run_parser(export_dir, out_dir, log_path)
        if self.context.dataSourceIngestIsCancelled():
            return IngestModule.ProcessResult.OK
        if code not in (0, 1):                                       # 1 = 일부 파일 오류, 결과는 생성됨
            self.message(IngestMessage.MessageType.ERROR, "ERELM parser failed (exit %s). See %s" % (code, log_path))
            return IngestModule.ProcessResult.ERROR

        progressBar.progress("Posting results to Blackboard", 2)
        counts = self.post_results(dataSource, by_path, out_dir)

        progressBar.progress("Registering reports", 3)
        if counts["behaviors"] + counts["messages"] > 0:
            for fn, label in (("timeline.csv", "ERELM ChatGPT Desktop timeline"),
                              ("recovered_conversations.csv", "ERELM ChatGPT Desktop recovered conversations"),
                              ("cx_result.json", "ERELM ChatGPT Desktop full records (JSON)")):
                path = os.path.join(out_dir, fn)
                if os.path.isfile(path):
                    case.addReport(path, MODULE_NAME, "%s (data source %d)" % (label, dataSource.getId()))

        self.message(IngestMessage.MessageType.DATA,
                     "%d user behaviors (%d on Timeline), %d conversation messages (files exported: %d, already present: %d)"
                     % (counts["behaviors"], counts["timeline_events"], counts["messages"], len(by_path), counts["duplicates"]))
        progressBar.progress(4)
        return IngestModule.ProcessResult.OK

    def message(self, kind, text):
        self.log(Level.INFO, text)
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(kind, MODULE_NAME, text))
