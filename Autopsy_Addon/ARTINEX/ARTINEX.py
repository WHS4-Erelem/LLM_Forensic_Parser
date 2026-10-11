# -*- coding: utf-8 -*-
"""ARTINEX — Autopsy Data Source Ingest Module (thin adapter).

경계 (PL 'DFIR 생태계 확장 — Thin Adapter' 문서 기준)
  Autopsy / TSK : 이미지·파일시스템 처리, 파일 탐색(FileManager), 결과 표시(Blackboard·Timeline·Report)
  이 모듈      : 필요한 파일만 꺼내 볼륨 루트 모양의 폴더에 풀고, 외부 CPython 의 ARTINEX 파서 6종을 각각의 폴더 입력 기능으로
                 실행한 뒤 결과 CSV 를 검사해 Blackboard 에 올림
  ARTINEX 파서 : LLM 아티팩트 해석·대조·행위 판정 (개별 파서 폴더)

Autopsy 의 Python 은 Jython 2.7 이라 CPython 3 파서를 import 하지 않고 subprocess 로 부른다.
전역/static 상태 없음 — 모든 상태는 ingest job 마다 새로 만들어지는 모듈 인스턴스에 둔다.
"""
import csv
import hashlib
import inspect
import json
import os
import re
import shutil

import jarray
import java.lang
from java.io import File, FileOutputStream
from java.lang import Class, ProcessBuilder, System
from java.nio.file import Files, Paths
from java.sql import DriverManager
from java.lang.ProcessBuilder import Redirect
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

MODULE_NAME = "ARTINEX"
MODULE_VERSION = "0.4.1"
MODULE_DIR = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))
PARSER_TIMEOUT_SEC = 3600                  # integration/parsers.json 의 최대 timeout_sec
ERRORS = (Exception, java.lang.Exception)  # Jython 에서 Java 예외는 Python Exception 의 하위가 아니다 — 둘 다 잡아야 한 파일 오류가 전체를 멈추지 않는다

# 파서 레지스트리 — 각 파서의 CLI 가 받는 '폴더 입력' 인자 그대로 (integration/parsers.json 의 이미지 인자는 쓰지 않는다).
#   dir   : 저장소 루트 기준 파서 폴더 = 실행 cwd      entry : 있어야 하는 진입점 (startUp 검사)
#   args  : {in}=추출 폴더(볼륨 루트 모양), {out}=결과 폴더. 출력 폴더는 입력 폴더 밖이어야 하는 파서가 있어 형제 폴더로 둔다
#   ok    : 결과 CSV 를 믿어도 되는 종료 코드. 1 을 '부분 성공(일부 파일 오류, 결과는 생성)'으로 쓰는 파서는 두 Desktop 파서뿐이다
#   nodata: 이 문자열이 로그에 있으면 '흔적 없음' (Claude Desktop 은 대상 파일이 하나도 없으면 exit 2 ARTIFACT_NOT_FOUND)
#   extra : CSV 외에 Report 로 등록할 파서 고유 산출물
#   ntfs  : 폴더 입력에서 읽는 원본 NTFS 메타파일 (볼륨 루트의 $MFT, $Extend/$UsnJrnl:$J). 이 파서를 돌리는 볼륨에서만 꺼낸다
PARSERS = (
    {"name": "chatgpt_desktop", "label": "ChatGPT Desktop", "dir": "ChatGPT_APP_Parser", "entry": "run_parser.py",
     "args": ("run_parser.py", "--input", "{in}", "--input-type", "dir", "--out-dir", "{out}", "--format", "both", "--overwrite"),
     "ok": (0, 1), "extra": ("cx_result.json",), "ntfs": ("$UsnJrnl:$J",)},
    {"name": "chatgpt_web", "label": "ChatGPT Web", "dir": "ChatGPT_Web_Parser", "entry": "chatgpt_parser/cli.py",
     "args": ("-m", "chatgpt_parser.cli", "--dir", "{in}", "--csv-dir", "{out}", "--out", "{out}/result.json", "--overwrite"),
     "ok": (0,), "extra": ("result.json",)},
    {"name": "claude_desktop", "label": "Claude Desktop", "dir": "Claude_APP_Parser", "entry": "run_parser.py",
     "args": ("run_parser.py", "--input", "{in}", "--input-type", "dir", "--out-dir", "{out}", "--no-banner"),
     "ok": (0, 1), "nodata": "ARTIFACT_NOT_FOUND", "ntfs": ("$MFT", "$UsnJrnl:$J")},
    {"name": "claude_web", "label": "Claude Web", "dir": "Claude_Web_Parser", "entry": "src/claude_web_forensics/cli.py",
     "args": ("-m", "claude_web_forensics", "analyze", "--dir", "{in}", "--output", "{out}", "--overwrite"),
     "env": {"PYTHONPATH": "src"}, "ok": (0,), "ntfs": ("$MFT",)},
    {"name": "gemini_web", "label": "Gemini Web", "dir": "Gemini_Web_Parser", "entry": "gemini_parser.py",
     "args": ("gemini_parser.py", "--folder", "{in}", "--output", "{out}", "--csv"),
     "ok": (0,), "extra": ("gemini_results.json",)},
    {"name": "lmstudio", "label": "LM Studio", "dir": "LMstudio_parser", "entry": "lmstudio_parser.py",
     "args": ("lmstudio_parser.py", "{in}", "--output", "{out}"),
     "ok": (0,), "ntfs": ("$MFT", "$UsnJrnl:$J")},
)

# Autopsy 에 요청할 파일: (파일명 LIKE, 부모 경로에 포함될 문자열(% 는 LIKE 와일드카드), 읽는 파서, keep, content).
# 범위 = integration/parsers.json 의 인자·기본 옵션으로 이미지를 넣었을 때 각 파서가 실제로 읽는 파일 (README '수집 범위' 표).
#   읽는 파서: 이름만 쓰면 그 파일이 있으면 그 파서를 실행한다(실행 근거). '~이름' 은 읽기만 하는 보조 입력 (그것만으로는 실행하지 않음)
#   keep   : 볼륨 기준 소문자 경로에 대한 정규식. 맞지 않는 파일은 꺼내지 않는다 (폴더 항목은 keep 과 무관하게 MFT 번호·순번을 기록 — USN 대조용)
#   content: 내용까지 꺼낼 파일의 정규식. 맞지 않으면 0바이트 + 원본 수정 시각의 '존재 파일'만 둔다 — 읽는 파서가 이름·시각만 쓰는 파일
#            (LM Studio 의 .gguf·실행 파일, Gemini 의 휴지통 $R). 크기와 무관한 규칙이다. None = 모두 원본 내용
# 같은 파일이 여러 항목에 걸리면 처음 꺼낸 것을 쓰고 실행 근거만 더한다 — 원본 내용 항목을 존재 파일 항목보다 앞에 둔다.
WEB = "chatgpt_web claude_web gemini_web"
UD = "/Google/Chrome/User Data/"
PROFILE = r"/google/chrome/user data/(default|profile [^/]+|guest profile)/"     # 세 웹 파서가 받는 프로필 폴더의 합집합
CLAUDE_FILES = (r"/(cache/cache_data/(data_\d+|f_[0-9a-f]+|index)|indexeddb/https_claude\.ai_\d+\.indexeddb\.(leveldb/([^/]+\.(ldb|log)"
                r"|current|manifest-\d+)|blob/.+)|local storage/leveldb/[^/]+\.(ldb|log)|session storage/[^/]+\.(ldb|log)|config\.json|ant-did"
                r"|ant-device-registry\.json|window-state\.json|plan-usage-history\.json|claude_desktop_config\.json|logs/[^/]+\.log)$")
LM_NAMES = (r"(\.conversation\.json|conversation-config\.json|local-identity\.json|user-profile\.json|lmstudio-hub\.json"
            r"|lm-link-account-status-cache\.json|lm-link-config\.json|model-data\.json|download-jobs-info\.json|single-downloads-info\.json"
            r"|\.metadata\.json|server-logs-state\.json|http-server\.json|llmster-pid\.lock|global\.json|window-\d+\.json"
            r"|lm studio(\.exe|\.lnk)?|unins\d*\.exe|\.gguf(\.part)?|\.md)$")   # lmstudio_parser.py RELEVANT_NAME_RE
LM_CONTENT = r"\.(json|md|txt|log)$|/server-logs/"   # lmstudio_parser.py should_read_content·lmstudio_log_path — 나머지는 이름·시각만 쓴다
NEVER = r"(?!)"
FILE_QUERIES = (
    # ChatGPT Desktop — cxparser locate._PATTERNS 중 PARSERS 가 내용을 읽는 종류 (config·installation_id·Documents/Codex 등은 목록용이라 제외)
    ("%", "/.codex/", "chatgpt_desktop",
     r"/\.codex/(sessions/.+/rollout-[^/]+\.jsonl|session_index\.jsonl|\.codex-global-state\.json|auth\.json"
     r"|(state_5|thread_history_1|logs_2)\.sqlite(-wal|-shm)?)$", None),
    ("%", "/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/codex/Default/Cache/Cache_Data/", "chatgpt_desktop",
     r"/cache_data/(index|data_[0-3]|f_[0-9a-f]{6})$", None),
    ("scope_v3.json", "/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/codex/sentry/", "chatgpt_desktop", None, None),
    ("%.pf", "/Windows/Prefetch/", "chatgpt_desktop", r"/(codex|chatgpt)\.exe-[0-9a-f]{8}\.pf$", None),
    ("%.lnk", "/AppData/Roaming/Microsoft/Windows/Recent/", "~chatgpt_desktop", r"/recent/[^/]+\.lnk$", None),
    # Claude Desktop — parser/locate.py SCAN_ROOTS × _PATTERNS (하위 폴더는 keep 과 무관하게 기록되어 USN 부모 대조에 쓰인다)
) + tuple(("%", root, "claude_desktop", CLAUDE_FILES, None) for root in (
    "/Packages/Claude_pzs8sxrjxfjjc/", "/AppData/Roaming/Claude/", "/AppData/Local/Claude/", "/AppData/Local/Claude-Data/",
    "/AppData/Local/AnthropicClaude/")) + (
    ("%", "/ProgramData/Claude/", "claude_desktop", r"/programdata/claude/logs/[^/]+\.log$", None),
    ("CLAUDE%.pf", "/Windows/Prefetch/", "claude_desktop", r"/windows/prefetch/claude[^/]*\.pf$", None),
    # WindowsApps 패키지는 목록(package_binary)으로만 쓰이지만, 이미지 입력에서는 그 목록이 있어야 USN 분석까지 간다 — 패키지마다 파일 하나
    ("AppxManifest.xml", "/Program Files/WindowsApps/Claude_", "claude_desktop",
     r"/program files/windowsapps/claude_[^/]+/appxmanifest\.xml$", None),
    # Chrome 프로필 — 파일마다 그것을 읽는 웹 파서만 (Local State·Network 의 Cookies 외 파일은 아무도 읽지 않아 제외)
    ("History%", UD, WEB, PROFILE + r"history(-wal|-shm|-journal)?$", None),
    ("Cookies%", UD, "claude_web gemini_web", PROFILE + r"(network/)?cookies(-wal|-shm|-journal)?$", None),
    ("Preferences", UD, "chatgpt_web gemini_web", PROFILE + r"preferences$", None),
    ("Secure Preferences", UD, "gemini_web", PROFILE + r"secure preferences$", None),
    ("%", UD + "%/Cache/Cache_Data/", WEB, PROFILE, None),
    ("%", UD + "%/IndexedDB/https_claude.", "claude_web", PROFILE, None),
    ("%", UD + "%/IndexedDB/", "gemini_web", PROFILE, None),
    ("%", UD + "%/Local Storage/leveldb/", WEB, PROFILE, None),
    ("%", UD + "%/Session Storage/", "chatgpt_web gemini_web", PROFILE, None),
    ("Session_%", UD + "%/Sessions/", WEB, PROFILE, None),
    ("Tabs_%", UD + "%/Sessions/", WEB, PROFILE, None),
    ("%", UD + "%/shared_proto_db/", "chatgpt_web", PROFILE + r"shared_proto_db/[^/]+$", None),
    ("%", UD + "%/Service Worker/", "gemini_web", PROFILE, None),
    # 다운로드 — Claude Web(Downloads 아래 파일 크기·내용·Zone.Identifier), Gemini(History 가 가리키는 받은 파일 해시·Zone.Identifier)
    ("%", "/Downloads/", "~claude_web ~gemini_web", None, None),
    # LM Studio — collect_ntfs_current 의 대상 폴더와 should_record_path 필터
    ("%", "/.lmstudio/", "lmstudio", None, LM_CONTENT),
    ("%", "/AppData/Local/Programs/LM Studio/", "lmstudio", None, LM_CONTENT),
    ("%", "/AppData/Local/lm-studio-updater/", "lmstudio", None, LM_CONTENT),
    ("%", "/Start Menu/Programs/LM Studio/", "lmstudio", None, LM_CONTENT),
    ("%LM Studio%", "/Start Menu/", "lmstudio", r"lm studio(\.exe|\.lnk)?$", LM_CONTENT),
    ("LM%STUDIO%.pf", "/Windows/Prefetch/", "lmstudio", r"/windows/prefetch/[^/]*lm[ -]?studio[^/]*\.pf$", LM_CONTENT),
) + tuple(("%", parent, "lmstudio", LM_NAMES, LM_CONTENT) for parent in ("/Downloads/", "/Desktop/", "/Documents/", "/$Recycle.Bin/")) + (
    # 휴지통 — Gemini 가 $I 를 읽고 $R 은 있는지만 본다
    ("$I%", "/$Recycle.Bin/", "~gemini_web", r"/\$recycle\.bin/[^/]+/\$i[^/]*$", None),
    ("$R%", "/$Recycle.Bin/", "~gemini_web", r"/\$recycle\.bin/[^/]+/\$r[^/]*$", NEVER),
)
FILE_QUERIES = tuple((n, par, ps.split(), re.compile(k) if k else None, re.compile(c) if c else None) for n, par, ps, k, c in FILE_QUERIES)
PARSER_NTFS = dict((p["name"], p.get("ntfs", ())) for p in PARSERS)
# NTFS 메타파일을 원본 그대로 볼륨 루트에 둔다 (1GB 초과만 제외). 그것을 읽는 파서(PARSERS ntfs)를 그 볼륨에서 돌릴 때만 꺼낸다.
NTFS_META = (("$MFT", "/"), ("$UsnJrnl:$J", "/$Extend/"))
NTFS_META_MAX_BYTES = 1024 * 1024 * 1024
BIG_WARNING = u"불완전 입력: $MFT 또는 $J가 1GB 상한을 초과하여 분석 입력에서 제외됨"
# 내용은 꺼내지 않고 메타데이터(MFT 번호·순번·시각)만 _host_metadata.json 에 넘기는 폴더: (이름, 부모, 실행 근거가 되는 파서)
META_DIR_QUERIES = (
    ("OpenAI.Codex_%", "/Program Files/WindowsApps/", "chatgpt_desktop"),   # 패키지 폴더 = 설치 행 (설치 파일이 없어도 나온다)
    ("OpenAI.Codex_2p2nqsd0c76g0", "/AppData/Local/Packages/", ""),
    # Claude Desktop 탐색 루트 — USN 레코드의 부모 MFT#·순번을 이 폴더들과 대조한다 (그것만으로는 파서가 결과를 내지 않는다)
    ("Claude_pzs8sxrjxfjjc", "/AppData/Local/Packages/", ""),
    ("Claude", "/AppData/Roaming/", ""),
    ("Claude", "/AppData/Local/", ""),
    ("Claude-Data", "/AppData/Local/", ""),
    ("AnthropicClaude", "/AppData/Local/", ""),
    ("Claude", "/ProgramData/", ""),
)
# 저장 위치의 파일 메타데이터 — ChatGPT Desktop(최근 항목 바로가기 대상의 생성 시각·크기·첫 8바이트), Claude Web(받은 파일의 $MFT 근거)
META_FILE_PARENTS = ("/Downloads/", "/Desktop/", "/Documents/")
META_FILE_LIMIT = 20000                    # ponytail: 저장 위치 3곳·2만 개 상한. 다른 드라이브·폴더 저장은 놓친다 → 필요 시 파서가 요청 목록을 내는 2단계로
META_FILE_READERS = ("~chatgpt_desktop", "~claude_web")
META_LIMIT_WARNING = u"불완전 입력: Downloads·Desktop·Documents 메타데이터가 %d개 제한을 초과하여 일부 수집되지 않음" % META_FILE_LIMIT
NOT_RUN_REASON = u"실행 조건에 해당하는 관련 입력을 찾지 못함"
FALLBACK_WORK_DIR = r"C:\artinex_work"     # 사건 폴더가 쓰기·ADS 불가일 때의 대체 작업 위치 (설정 work_dir 로 바꿀 수 있음)
HOST_META_NAME = "_host_metadata.json"     # 파서들(DirectoryVfs 등)과 약속한 파일명
DELETED_DIR = "_deleted"                   # 삭제 파일 트리 (Claude Desktop parser/vfs.py DirectoryVfs 와 약속). 다른 파서는 볼륨 루트의 Users/… 부터 찾으므로 보지 않는다
DELETED_PARSER = "claude_desktop"          # 폴더 입력에서 삭제 파일 내용을 읽는 파서. 다른 파서의 삭제 파일은 내용 대신 실행 근거(USN·MFT 로 찾을 흔적)로만 센다
MFT_RE = re.compile(r"\bMFT=(\d+)")        # Artifact_details 의 MFT 번호 (Claude Desktop 등) — 같은 경로의 현존·삭제 파일 구분용
DELETED_MARK = u"삭제 엔트리=True"
HISTORY_READERS = ("~claude_web", "~gemini_web")   # Chrome History 의 다운로드 대상 파일을 읽는 파서 (보조 입력)

# 볼륨 루트 기준 경로로 맞춘다 (논리 파일 세트는 앞에 '/LogicalFileSet1/<폴더>' 가 붙는다)
ANCHOR = re.compile(r"(?i)/(users|windows|programdata|program files|\$recycle\.bin)/")

# 팀 CSV 계약 (integration 과 같은 검사: 헤더 바이트 일치·열 수·시각 형식·판정값·빈 셀)
TIMELINE_HEADER = [u"Model", u"Timestamp", u"User_behavior", u"Behavior_details ", u"Verdict", u"Artifact_path", u"Artifact_details "]
CONV_HEADER = [u"Model", u"timestamp", u"conversation_uuid", u"conversation_title", u"message_uuid", u"parent_message_uuid",
               u"message order", u"role", u"content", u"Artifact_path"]
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6} KST|-)$")
VERDICTS = (u"확정", u"의심")


def iso_utc(epoch):
    """Autopsy 의 epoch 초 -> 'YYYY-MM-DDTHH:MM:SSZ'. 0(없음)이면 None."""
    if not epoch:
        return None
    fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    fmt.setTimeZone(TimeZone.getTimeZone("UTC"))
    return fmt.format(Date(epoch * 1000))


def host_entry(f, rel, with_head=False):
    """AbstractFile -> 파서에 넘길 메타데이터 한 건."""
    e = {"path": rel, "size": f.getSize(), "dir": bool(f.isDir()), "mft_record": f.getMetaAddr(), "mft_seq": f.getMetaSeq(),
         "times": {"created": iso_utc(f.getCrtime()), "modified": iso_utc(f.getMtime()),
                   "mft_modified": iso_utc(f.getCtime()), "accessed": iso_utc(f.getAtime())}}
    if with_head and f.getSize() > 0:
        buf = jarray.zeros(8, "b")
        try:
            n = f.read(buf, 0, 8)
            e["head_hex"] = "".join("%02x" % (b & 0xFF) for b in buf[:max(n, 0)])
        except ERRORS:
            pass
    return e


def load_config():
    """artinex_config.json (모듈 폴더) + 환경변수 ARTINEX_PYTHON·ARTINEX_REPO_ROOT·ARTINEX_WORK_DIR. 필요한 값은 python 과 repo_root(저장소 루트, 파서 폴더 6개가 그 아래) 둘뿐.
    선택 work_dir: 대체 작업 위치 (기본 C:\\artinex_work). 작업 위치는 실행마다 사건의 ModuleOutput\\ARTINEX 를 먼저 쓰고,
    그곳이 쓰기 또는 ADS(Zone.Identifier·$J) 불가일 때만 이 위치를 쓴다 (pick_work_root).
    선택 keep_export: true 면 정상 완료여도 추출본(export·in_<파서>)을 지우지 않는다 (cleanup 참조).
    모듈을 저장소 안(Autopsy_Addon/ARTINEX)에서 그대로 쓰면 설정 없이 저장소와 integration/.venv312 를 쓴다."""
    cfg = {}
    path = os.path.join(MODULE_DIR, "artinex_config.json")
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            cfg.update(json.loads(fh.read().decode("utf-8-sig")))
    for key, env in (("python", "ARTINEX_PYTHON"), ("repo_root", "ARTINEX_REPO_ROOT"), ("work_dir", "ARTINEX_WORK_DIR")):
        if System.getenv(env):
            cfg[key] = System.getenv(env)
    if not cfg.get("repo_root"):
        cfg["repo_root"] = os.path.dirname(os.path.dirname(MODULE_DIR))
    if not cfg.get("python"):
        venv = os.path.join(cfg["repo_root"], "integration", ".venv312", "Scripts", "python.exe")
        cfg["python"] = venv if os.path.isfile(venv) else "python"
    return cfg


def read_rows(path):
    """UTF-8(BOM) CSV -> [[unicode]]. Jython 2.7 csv 는 바이트만 다루므로 셀마다 디코드한다."""
    if not os.path.isfile(path):
        return []
    csv.field_size_limit(1 << 30)
    with open(path, "rb") as fh:
        rows = [[c.decode("utf-8") for c in r] for r in csv.reader(fh)]
    if rows and rows[0]:
        rows[0][0] = rows[0][0].replace(u"\ufeff", u"")
    return rows


def read_csv(path):
    """CSV -> [dict]. 헤더 끝 공백은 떼고 쓴다."""
    rows = read_rows(path)
    if not rows:
        return []
    header = [h.strip() for h in rows[0]]
    return [dict(zip(header, r)) for r in rows[1:]]


def check_csv(path, header, verdict=False):
    """팀 계약 위반이면 사유 문자열, 아니면 None. integration 처럼 위반 파일은 통째로 받지 않는다."""
    rows = read_rows(path)
    if not rows:
        return "empty or unreadable"
    if rows[0] != header:
        return "header mismatch: %s" % [h.encode("utf-8") for h in rows[0]]
    for i, r in enumerate(rows[1:], 2):
        if len(r) != len(header):
            return "row %d: %d columns (expected %d)" % (i, len(r), len(header))
        if not TS_RE.match(r[1]):
            return "row %d: invalid timestamp %r" % (i, r[1].encode("utf-8"))
        if verdict and r[4] not in VERDICTS:
            return "row %d: invalid verdict %r" % (i, r[4].encode("utf-8"))
        if verdict and u"" in r:
            return "row %d: empty cell" % i
    return None


def kst_to_epoch(ts):
    """팀 계약 시각 문자열(YYYY-MM-DD HH:MM:SS.ffffff KST) -> epoch 초. 시각 없음이면 None."""
    if not ts or len(ts) < 19 or ts[4] != "-":
        return None
    fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    fmt.setTimeZone(TimeZone.getTimeZone("Asia/Seoul"))
    try:
        return fmt.parse(ts[:19]).getTime() / 1000
    except ERRORS:
        return None


def fs_key(f):
    """파일이 속한 파일시스템(볼륨) id. 논리 파일 세트처럼 파일시스템이 없으면 0.
    볼륨마다 추출 폴더를 따로 두어 두 볼륨의 같은 경로(Users/...)가 덮어쓰거나 섞이지 않게 한다."""
    try:
        return f.getFileSystem().getId()
    except ERRORS:
        return 0


def count_missing(v, parsers, warning=None):
    """이 볼륨에서 parsers('~' 접두 포함)가 읽을 입력 하나를 넘기지 못했다 — Inbox 의 incomplete input. warning: Inbox 에 덧붙일 사유."""
    for p in parsers:
        p = p.lstrip("~")
        v["missing"][p] = v["missing"].get(p, 0) + 1
        if warning:
            v["warnings"].setdefault(p, set()).add(warning)


def link_or_copy(src, dst):
    """파서 입력 폴더에 하드 링크 (ADS 도 따라온다). 링크를 못 만들면 복사 (Windows 복사도 ADS 를 옮긴다)."""
    Files.createDirectories(dst.getParent())
    try:
        Files.createLink(dst, src)
    except ERRORS:
        Files.copy(src, dst)


def work_problem(folder):
    """작업 위치로 쓸 수 없는 사유, 쓸 수 있으면 None — 폴더를 만들고 시험 파일과 그 Zone.Identifier 스트림(ADS)을 써 본다."""
    probe = File(folder, "artinex_ads_probe.txt")
    try:
        File(folder).mkdirs()
        FileOutputStream(probe).close()
    except ERRORS as exc:
        return "not writable (%s)" % exc
    try:
        FileOutputStream(probe.getPath() + ":Zone.Identifier").close()
        return None
    except ERRORS as exc:
        return "no alternate data streams, not NTFS? (%s)" % exc
    finally:
        probe.delete()


class ArtinexIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME

    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return ("LLM service user behaviors and conversations (ChatGPT Desktop/Web, Claude Desktop/Web, Gemini Web, LM Studio), "
                "parsed by the ARTINEX parsers. Autopsy provides the files; the external ARTINEX parsers interpret them.")

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ArtinexIngestModule()


class ArtinexIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(MODULE_NAME)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.cfg = load_config()
        missing = [os.path.join(self.cfg["repo_root"], p["dir"], p["entry"]) for p in PARSERS
                   if not os.path.isfile(os.path.join(self.cfg["repo_root"], p["dir"], p["entry"]))]
        if (os.sep in self.cfg["python"] or "/" in self.cfg["python"]) and not os.path.isfile(self.cfg["python"]):
            missing.insert(0, self.cfg["python"])
        if missing:
            raise IngestModuleException("ARTINEX parser files not found (run Autopsy_Addon/setup.ps1 or set artinex_config.json): %s"
                                        % ", ".join(missing))

    # ------------------------------------------------------------------ 1. Autopsy 에서 파일 받기
    def export_files(self, dataSource, work):
        """FileManager 로 찾은 파일을 볼륨마다 'vol<id>/export' 아래 볼륨 기준 경로 그대로 풀고, Autopsy 가 가진 메타데이터를 옆에 적은 뒤
        파서마다 그 파서가 읽는 파일만 하드 링크로 모은 입력 폴더 'vol<id>/in_<파서>' 를 만든다 (input_view).
        반환: ({볼륨 id: {"dir", "by_path": {저장 경로: AbstractFile}, "orig": {원래 경로: [AbstractFile]}, "views": {파서: 입력 폴더},
                         "run": {파서: {실행 근거: 수}}, "missing": {파서: 꺼내지 못한 입력 수}}}, 건너뛴 수)."""
        fm = Case.getCurrentCase().getServices().getFileManager()
        vols, notes, failed = {}, [], set()             # failed: 꺼내지 못한 파일 — 다른 항목으로 다시 걸려도 다시 세지 않는다
        skipped = {"deleted": 0, "slack": 0, "derived": 0, "presence": 0, "ads": 0, "error": 0}
        ORIGINAL = (TskData.TSK_DB_FILES_TYPE_ENUM.FS, TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL)   # 이미지 파일시스템·논리 파일 세트의 원본

        def vol(f):
            k = fs_key(f)
            if k not in vols:
                vols[k] = {"key": k, "dir": os.path.join(work, "vol%s" % k, "export"), "by_path": {}, "orig": {}, "entries": {},
                           "store": {}, "readers": {}, "presence": set(), "views": {}, "run": {}, "missing": {}, "warnings": {}}
            return vols[k]

        def rel_of(f):
            full = f.getParentPath() + f.getName()
            m = ANCHOR.search(full)
            return full[m.start():] if m else None

        def live(f):
            return (f.getType() in ORIGINAL and not f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC) and ":" not in f.getName())

        def index(v, rel, f):                        # 원래 경로 -> 이 볼륨의 AbstractFile 들 (증거 연결용, 같은 파일은 한 번)
            same = v["orig"].setdefault(rel.lower(), [])
            if all(g.getId() != f.getId() for g in same):
                same.append(f)

        def basis(v, parsers, why):
            for p in parsers:
                if not p.startswith("~"):
                    v["run"].setdefault(p, {})[why] = v["run"].get(p, {}).get(why, 0) + 1

        def lost(v, parsers, rel, why):
            count_missing(v, parsers)
            notes.append("%s\t%s" % (why, rel))

        pending = []                                 # ADS 는 주 파일을 모두 쓴 뒤에 쓴다 (put now=True)

        def put(v, f, rel, parsers, content=None, why="file", foreign=False, now=False):
            """파일 하나를 v 의 추출 폴더에 꺼낸다. 이미 꺼냈으면 읽는 파서·실행 근거만 더한다 — 단 존재 파일(0바이트)을
            내용이 필요한 요청이 다시 가리키면 원본으로 다시 쓴다. foreign: 다른 볼륨의 파일 — 이 볼륨의 $MFT 와 맞지 않으므로
            MFT 번호를 _host_metadata.json 에 적지 않는다 (볼륨 식별 정보는 넘기지 않으므로 그 파일의 $MFT 근거는 생략).
            ADS 는 미뤄 두었다가 마지막에 쓴다 — Autopsy 는 'x.pdf:Zone.Identifier' 를 x.pdf 보다 먼저 돌려줄 수 있고,
            주 파일을 나중에 쓰면(FileOutputStream = CREATE_ALWAYS) Windows 가 그 파일의 ADS 를 지운다."""
            ads = ":" in f.getName()
            if ads and not now:
                basis(v, parsers, why)
                pending.append((v, f, rel, parsers, content, why, foreign))
                return
            store = rel                              # 추출 폴더 안 위치 (삭제 파일은 원래 경로와 다르다)
            if why == "deleted file":
                store = "/%s/%d%s" % (DELETED_DIR, f.getMetaAddr(), rel)   # 현존 파일과 겹치지 않게 MFT 번호별 별도 트리
            key = store.lower()
            if (v["key"], key) in failed or (ads and (v["key"], key.split(":")[0]) in failed):   # 주 파일을 못 꺼냈으면 그 ADS 도 쓰지 않는다 (빈 주 파일이 생기지 않게)
                return
            match = rel.lower().split(":")[0]
            presence = content is not None and not ads and not content.search(match)
            upgrade = key in v["presence"] and not presence      # 존재 파일 -> 원본 승격
            if key not in v["by_path"] or upgrade:
                target = File(v["dir"], store.lstrip("/"))   # 'x.pdf:Zone.Identifier' 는 NTFS 작업 폴더에 실제 ADS 로 써진다 (파서들이 그렇게 읽는다)
                try:
                    target.getParentFile().mkdirs()
                    if presence:
                        target.createNewFile()               # 존재 파일: 읽는 파서가 이름·시각만 쓴다 (content 주석)
                        v["presence"].add(key)
                        skipped["presence"] += 1
                        notes.append("presence\t%s\t%d" % (rel, f.getSize()))
                    else:
                        ContentUtils.writeToFile(f, target)  # 스트리밍 복사 (크기 상한 없음)
                        if not ads and target.length() != f.getSize():
                            raise IOError("size mismatch: wrote %d of %d bytes" % (target.length(), f.getSize()))
                    if f.getMtime() and not ads:
                        target.setLastModified(f.getMtime() * 1000)   # 복사본 시각이 아닌 원본 $SI 수정 시각 (LM Studio 실행 시각 fallback 이 mtime 을 본다)
                except ERRORS as exc:
                    if upgrade:                              # 승격 실패: 기존 존재 파일 사용자(LM Studio)를 위해 0바이트로 되돌린다
                        target.delete()
                        target.createNewFile()
                    else:
                        target.delete()                      # 덜 써진 파일·ADS 를 파서가 읽지 않게 (ADS 는 그 스트림만 지워진다)
                        if ads and target.exists():          # 남은 불완전 ADS 는 주 파일 링크를 따라 파서 입력에 들어간다
                            notes.append("ads_partial_not_removed\t%s" % rel)
                    skipped["error"] += 1
                    lost(v, parsers, "%s\t%s" % (rel, exc), "error")
                    self.log(Level.WARNING, "export failed %s: %s" % (rel, exc))
                    if not upgrade:
                        failed.add((v["key"], key))
                        return                               # 한 파일 실패(권한·경로·쓰기)는 기록하고 다음 파일로
                    upgrade = False
                if upgrade:
                    v["presence"].discard(key)
                    skipped["presence"] -= 1
                    notes.append("presence_upgraded\t%s" % rel)
                if key not in v["by_path"]:
                    v["by_path"][key], v["store"][key] = f, store
                    index(v, rel, f)
                    if not foreign:
                        v["entries"].setdefault(key, host_entry(f, rel))
                    if store != rel:                 # path 는 원래 경로 — 파서가 그 경로의 미할당 파일로 다룬다
                        v["entries"][key]["deleted"] = True
                        notes.append("deleted_exported\t%s\t%s" % (rel, store))
            v["readers"].setdefault(key, set()).update(p.lstrip("~") for p in parsers)
            if not now:
                basis(v, parsers, why)

        for name, parent, parsers in META_DIR_QUERIES:
            for f in fm.findFiles(dataSource, name, parent):
                rel = rel_of(f)
                if rel and f.isDir() and live(f) and f.getName() not in (".", ".."):
                    vol(f)["entries"][rel.lower()] = host_entry(f, rel)
                    index(vol(f), rel, f)                    # 설치 행이 패키지 폴더에 붙게
                    basis(vol(f), parsers.split(), "package folder")
        n_meta, over = 0, False
        for parent in META_FILE_PARENTS:
            for f in fm.findFiles(dataSource, "%", parent):
                if self.context.dataSourceIngestIsCancelled():
                    return vols, skipped
                rel = rel_of(f)
                if rel and f.isFile() and live(f):
                    if n_meta >= META_FILE_LIMIT:    # 상한 다음 대상이 실제로 있을 때만 초과 (정확히 상한 개수면 경고 없음)
                        over = True
                        break
                    vol(f)["entries"][rel.lower()] = host_entry(f, rel, with_head=True)
                    n_meta += 1
            if over:
                break
        for name, parent, parsers, keep, content in FILE_QUERIES:
            for f in fm.findFiles(dataSource, name, parent):
                if self.context.dataSourceIngestIsCancelled():
                    return vols, skipped
                rel = rel_of(f)
                if not rel:
                    continue
                if f.isDir():
                    if live(f) and f.getName() not in (".", ".."):
                        vol(f)["entries"].setdefault(rel.lower(), host_entry(f, rel))   # 폴더는 MFT 번호·순번만 (USN 대조용)
                    continue
                if not f.isFile() or (keep and not keep.search(rel.lower().split(":")[0])):   # ADS 는 주 파일 이름으로 범위를 판정한다
                    continue
                if f.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.SLACK:
                    skipped["slack"] += 1
                    continue
                if f.getType() not in ORIGINAL:     # 다른 모듈이 만든 파생·카빙 파일 (예: ZIP 안 파일) — 파서는 원본 파일시스템의 파일만 읽는다
                    skipped["derived"] += 1
                    notes.append("derived\t%s" % rel)
                    continue
                ads = ":" in f.getName()
                if ads and not f.getName().lower().endswith(":zone.identifier"):
                    skipped["ads"] += 1              # Zone.Identifier 외 대체 데이터 스트림은 어느 파서도 폴더 입력에서 읽지 않는다
                    notes.append("ads\t%s" % rel)
                    continue
                if f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC):
                    if DELETED_PARSER not in parsers or ads:
                        # 폴더 입력은 삭제 파일 내용을 읽지 못한다. USN 을 읽는 파서에는 그 볼륨의 $J 를 넘길 근거가 된다
                        basis(vol(f), [p for p in parsers if "$UsnJrnl:$J" in PARSER_NTFS.get(p, ())], "deleted trace")
                        skipped["deleted"] += 1
                        notes.append("deleted\t%s" % rel)
                        continue
                    put(vol(f), f, rel, parsers, content, "deleted file")
                    continue
                put(vol(f), f, rel, parsers, content)
        for v in list(vols.values()):                 # History 의 다운로드 대상 파일 (Downloads 밖·다른 볼륨 포함)
            for target in self.history_targets(v, work, notes):
                rel = target.replace("\\", "/")[2:] if target[1:2] == ":" else None
                if not rel or "/" not in rel:
                    continue
                parent, name = rel.rsplit("/", 1)
                found = [f for f in fm.findFiles(dataSource, name + "%", parent + "/")
                         if (f.getParentPath() + f.getName()).lower() in (rel.lower(), rel.lower() + ":zone.identifier")
                         and f.getType() in ORIGINAL and not f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC) and f.isFile()]
                # 이미지 입력도 드라이브 문자를 떼고 모든 볼륨에서 찾는다 — 같은 볼륨을 먼저, 없으면 다른 볼륨 하나의 파일을 이 볼륨 폴더에.
                # 다른 볼륨 후보가 여럿이면 고르지 않는다. 대상이 없으면(지웠거나 옮김) 이미지 입력에서도 없으므로 입력 누락이 아니다.
                others = sorted(set(fs_key(f) for f in found) - set([v["key"]]))
                pick = v["key"] if any(fs_key(f) == v["key"] for f in found) else others[0] if len(others) == 1 else None
                if not found:
                    notes.append("history_target_not_found\t%s" % target)
                elif pick is None:
                    lost(v, HISTORY_READERS, "%s\tvolumes %s" % (target, others), "history_target_ambiguous")
                for f in found:
                    if fs_key(f) == pick:
                        put(v, f, f.getParentPath() + f.getName(), HISTORY_READERS, foreign=pick != v["key"])
        for name, parent in NTFS_META:
            for f in fm.findFiles(dataSource, name, parent):
                if f.getParentPath().lower() != parent.lower() or f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC):
                    continue
                v, rel = vol(f), parent + f.getName()
                users = [p for p in v["run"] if name in PARSER_NTFS.get(p, ())]   # 이 볼륨에서 돌릴 파서 중 이 메타파일을 읽는 것
                if not users:
                    continue
                if f.getSize() > NTFS_META_MAX_BYTES:  # 이 메타파일을 읽는 파서에만 경고
                    count_missing(v, users, BIG_WARNING)
                    notes.append("big\tvol%s\t%s\tsize=%d\tlimit=%d\tparsers=%s" % (
                        v["key"], rel, f.getSize(), NTFS_META_MAX_BYTES, ",".join(users)))
                    continue
                put(v, f, rel, ["~" + p for p in users])
        for args in pending:
            put(*args, now=True)
        for vk, main in sorted(set((args[0]["key"], args[2].lower().split(":")[0]) for args in pending)):
            # ADS 를 쓰거나 지우면 Windows 가 주 파일의 수정 시각을 현재 시각으로 바꾼다 — 원본 $SI 수정 시각으로 다시 맞춘다 (put 과 같은 방식)
            v, f = vols[vk], vols[vk]["by_path"].get(main)
            if f is not None and f.getMtime() and not File(v["dir"], v["store"][main].lstrip("/")).setLastModified(f.getMtime() * 1000):
                count_missing(v, v["readers"].get(main, ()))
                notes.append("time_restore_failed\t%s" % v["store"][main])
        if over:                                      # 어느 볼륨의 대상이 빠졌는지 모르므로 모든 볼륨의 해당 파서에 경고
            notes.append("meta_limit\tall volumes\tlimit=%d\tcollected=%d\tDownloads/Desktop/Documents file metadata beyond the limit "
                         "not collected (ChatGPT Desktop recent_lnk targets, Claude Web $MFT evidence)\tparsers=%s"
                         % (META_FILE_LIMIT, n_meta, ",".join(p.lstrip("~") for p in META_FILE_READERS)))
            self.log(Level.WARNING, "metadata limit %d exceeded in %s" % (META_FILE_LIMIT, META_FILE_PARENTS))
            for v in vols.values():
                count_missing(v, META_FILE_READERS, META_LIMIT_WARNING)
        for v in sorted(vols.values(), key=lambda v: v["key"]) or [{"key": "-", "run": {}}]:
            notes.extend(u"parser_not_run\tvol%s\t%s\t%s" % (v["key"], p["label"], NOT_RUN_REASON) for p in PARSERS if p["name"] not in v["run"])
        for v in vols.values():
            if v["run"]:
                File(v["dir"]).mkdirs()
                with open(os.path.join(v["dir"], HOST_META_NAME), "wb") as fh:
                    fh.write(json.dumps({"schema": 1, "provider": "Autopsy (ARTINEX thin adapter %s)" % MODULE_VERSION,
                                         "entries": v["entries"]}, ensure_ascii=True).encode("ascii"))
                for p in v["run"]:
                    v["views"][p] = self.input_view(v, p, notes)
        if notes:                                                    # 추출 제외·실패·특수 처리와 파서 미실행 사유 — 파서 결과에 빠진 근거를 추적할 수 있게
            with open(os.path.join(work, "export_skipped.txt"), "wb") as fh:
                fh.write((u"\n".join(notes) + u"\n").encode("utf-8"))
        return vols, skipped

    def history_targets(self, v, work, notes):
        """이 볼륨에서 꺼낸 Chrome History 의 downloads.target_path·current_path. Claude Web·Gemini 가 이미지 입력에서 그 경로의 파일을 읽는다.
        추출본은 파서 입력이므로 건드리지 않고 사본(-wal 포함)을 열어 읽는다 — 경로만 읽고 해석은 파서가 한다."""
        paths = set()
        for key, store in v["store"].items():
            if not re.search(PROFILE + r"history$", key):
                continue
            tmp = os.path.join(work, "history_%d" % len(paths), "History")
            try:
                os.makedirs(os.path.dirname(tmp))
                for suffix in ("", "-wal"):
                    src = os.path.join(v["dir"], store.lstrip("/") + suffix)
                    if os.path.isfile(src):
                        shutil.copyfile(src, tmp + suffix)
                Class.forName("org.sqlite.JDBC")
                conn = DriverManager.getConnection("jdbc:sqlite:" + tmp.replace("\\", "/"))
                try:
                    rs = conn.createStatement().executeQuery("SELECT target_path, current_path FROM downloads")
                    while rs.next():
                        paths.update(p for p in (rs.getString(1), rs.getString(2)) if p)
                finally:
                    conn.close()
            except ERRORS as exc:                    # 대상 목록을 못 읽음 = 필요한 입력을 정하지 못함 — 대상이 없는 것과 달리 입력 누락으로 센다
                notes.append("history_targets_failed\t%s\t%s" % (store, exc))
                count_missing(v, HISTORY_READERS)
            finally:
                shutil.rmtree(os.path.dirname(tmp), True)
        return sorted(paths)

    def input_view(self, v, p, notes):
        """파서 p 의 입력 폴더: 추출 폴더에서 p 가 읽는 파일만 하드 링크로 모은다 (ADS 는 주 파일 링크에 따라온다).
        다른 파서용 공통 입력(예: Downloads 의 *.csv)을 p 가 자기 입력으로 오인하지 않게 한다."""
        view = os.path.join(os.path.dirname(v["dir"]), "in_" + p)
        done = set()
        link_or_copy(Paths.get(v["dir"], HOST_META_NAME), Paths.get(view, HOST_META_NAME))
        for key in sorted(v["by_path"]):
            if p not in v["readers"].get(key, ()):
                continue
            base = v["store"][key].split(":")[0] if ":" in v["store"][key].rsplit("/", 1)[-1] else v["store"][key]
            if base.lower() in done:
                continue
            done.add(base.lower())
            try:
                link_or_copy(Paths.get(v["dir"], base.lstrip("/")), Paths.get(view, base.lstrip("/")))
            except ERRORS as exc:
                count_missing(v, [p])
                notes.append("view_error\t%s\t%s\t%s" % (p, base, exc))
        return view

    # ------------------------------------------------------------------ 2. 외부 CPython 파서 실행
    def run_parser(self, p, input_dir, out_dir):
        """파서 하나를 폴더 입력으로 실행. run.log 첫 줄에 실제 명령·cwd·환경변수를 남긴다. 반환: 종료 코드."""
        parser_dir = os.path.join(self.cfg["repo_root"], p["dir"])
        env = dict(p.get("env", {}), PYTHONIOENCODING="utf-8")
        argv = [self.cfg["python"]] + [a.replace("{in}", input_dir).replace("{out}", out_dir) for a in p["args"]]
        log_path = os.path.join(out_dir, "run.log")
        with open(log_path, "wb") as fh:
            fh.write((u"$ %s\ncwd=%s env=%s\n\n" % (u" ".join(argv), parser_dir, env)).encode("utf-8"))
        cmd = ArrayList()
        for a in argv:
            cmd.add(a)
        pb = ProcessBuilder(cmd)
        pb.directory(File(parser_dir))
        for k, val in env.items():
            pb.environment().put(k, val)
        pb.redirectErrorStream(True)
        pb.redirectOutput(Redirect.appendTo(File(log_path)))
        terminators = ArrayList()
        terminators.add(DataSourceIngestModuleProcessTerminator(self.context))     # 취소 시 프로세스 종료
        terminators.add(ExecUtil.TimedProcessTerminator(PARSER_TIMEOUT_SEC))
        return ExecUtil.execute(pb, ExecUtil.HybridTerminator(terminators))        # 종료·예외 시 ExecUtil 이 프로세스를 정리한다

    # ------------------------------------------------------------------ 3. 결과를 Blackboard 에 올리기
    def post_results(self, dataSource, p, v, out_dir, counts):
        """CSV 를 Blackboard 에 올린다. counts 는 호출자가 넘긴 dict 를 갱신한다 — 중간에 예외가 나도 실제 등록 수가 남게."""
        bb = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        STRING = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        STD = BlackboardAttribute.ATTRIBUTE_TYPE
        behavior_type = bb.getOrAddArtifactType("ARTINEX_LLM_USER_BEHAVIOR", "LLM User Behavior (ARTINEX)")
        message_type = BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE)
        tl_type = BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT)
        custom = dict((n, bb.getOrAddAttributeType(n, STRING, d)) for n, d in (
            ("ARTINEX_TIMESTAMP", "Timestamp (KST)"),
            ("ARTINEX_MODEL", "LLM Service"), ("ARTINEX_USER_BEHAVIOR", "User Behavior"),
            ("ARTINEX_BEHAVIOR_DETAILS", "Behavior Details"), ("ARTINEX_VERDICT", "Verdict"),
            ("ARTINEX_ARTIFACT_PATH", "Artifact Path"), ("ARTINEX_ARTIFACT_DETAILS", "Artifact Details"),
            ("ARTINEX_ROLE", "Role"), ("ARTINEX_MESSAGE_UUID", "Message UUID"), ("ARTINEX_MESSAGE_ORDER", "Message Order"),
            ("ARTINEX_ROW_KEY", "Row Key (ARTINEX dedup)")))
        export_root = v["views"][p["name"]].replace("\\", "/").lower().rstrip("/")   # 이 파서의 입력 폴더
        link_notes = []

        def source_of(artifact_path, details=u""):
            """파서의 Artifact_path -> 이 볼륨에서 꺼낸 그 파일의 AbstractFile. 하나로 정할 수 없으면 data source (사유는 link_notes.txt).
            표기: 'C:\\Users\\...'(Desktop 파서·Claude Web), 'Users/...'(ChatGPT Web), 추출 폴더 절대 경로(Gemini·LM Studio),
            'volumeN:\\...'(LM Studio USN). 여러 경로는 '|' 로 이어지며 첫 경로를 쓴다. CSV 값 자체는 바꾸지 않는다 (해석만)."""
            raw = (artifact_path or "").split("|")[0].strip()
            path = raw.replace("\\", "/").lower()
            if path.startswith(export_root + "/"):
                path = path[len(export_root):]
                if path in v["by_path"]:             # 저장 위치 그대로 (삭제 파일의 _deleted 경로 포함) = 그 파일
                    return v["by_path"][path]
            else:
                path = re.sub(r"^(volume\d+:|[a-z]:)", "", path)
            if not path.startswith("/"):
                path = "/" + path
            cands = v["orig"].get(path, [])
            m = MFT_RE.search(details or u"")
            if m:                                    # 같은 경로의 현존·삭제 파일은 MFT 번호로 가른다
                cands = [f for f in cands if f.getMetaAddr() == int(m.group(1))]
            elif DELETED_MARK in (details or u""):
                cands = [f for f in cands if f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC)]
            if len(cands) == 1:
                return cands[0]
            if raw not in (u"", u"-"):
                counts["unlinked"] += 1
                link_notes.append(u"%s\t%s" % ("ambiguous: %d candidates (live/deleted, no MFT number)" % len(cands) if cands
                                                 else "no exported file on this volume", raw))
            return dataSource

        def attr(type_, value):
            return BlackboardAttribute(type_, MODULE_NAME, value)

        posted = ArrayList()

        root_rx = re.compile(re.escape(export_root), re.I)

        def row_key(kind, row):
            """CSV 한 행의 실행과 무관한 키 — 실행마다 바뀌는 입력 폴더 경로(Gemini·LM Studio 의 Artifact_path·상세)를 <input> 으로 바꿔 해시."""
            vals = [root_rx.sub(u"<input>", (row.get(k) or u"").replace(u"\\", u"/")) for k in sorted(row)]
            return hashlib.sha1((kind + u"\x1f" + u"\x1f".join(vals)).encode("utf-8")).hexdigest()

        def add(content, art_type, attrs, counter, key):
            """같은 data source 에 다시 돌려도 같은 행은 중복 없이 — 연결 파일과 행 키(ARTINEX_ROW_KEY)가 같은 artifact 가 있으면 건너뛴다.
            (artifactExists 는 넘긴 속성이 모두 있는 artifact 를 찾는다. 행 키가 없는 0.3.0 이전 artifact 와는 한 번 겹칠 수 있다)"""
            key_attr = attr(custom["ARTINEX_ROW_KEY"], key)
            probe = ArrayList()
            probe.add(key_attr)
            if bb.artifactExists(content, art_type, probe):
                counts["duplicates"] += 1
                return
            attrs.add(key_attr)
            posted.add(content.newDataArtifact(art_type, attrs))
            counts[counter] += 1

        try:
            # timeline.csv 한 행 = 'LLM User Behavior (ARTINEX)' 한 건 (팀 계약 7열을 값 그대로).
            # 시각은 문자열 그대로 두고, Timeline 용으로는 TSK_TL_EVENT 를 따로 올린다 — 사용자 정의 artifact 에 DATETIME 을
            # 넣으면 Timeline 설명이 '<유형>: <artifact id>' 로만 나오기 때문 (TL_EVENT 는 TSK_DESCRIPTION 이 설명이 된다).
            for r in read_csv(os.path.join(out_dir, "timeline.csv")):
                content = source_of(r.get("Artifact_path"), r.get("Artifact_details"))
                attrs = ArrayList()
                for name, col in (("ARTINEX_TIMESTAMP", "Timestamp"), ("ARTINEX_MODEL", "Model"), ("ARTINEX_USER_BEHAVIOR", "User_behavior"),
                                  ("ARTINEX_BEHAVIOR_DETAILS", "Behavior_details"), ("ARTINEX_VERDICT", "Verdict"),
                                  ("ARTINEX_ARTIFACT_PATH", "Artifact_path"), ("ARTINEX_ARTIFACT_DETAILS", "Artifact_details")):
                    attrs.add(attr(custom[name], r.get(col) or "-"))
                key = row_key(u"timeline", r)
                add(content, behavior_type, attrs, "behaviors", key)
                epoch = kst_to_epoch(r.get("Timestamp"))
                if epoch is not None:
                    tl = ArrayList()
                    tl.add(attr(STD.TSK_TL_EVENT_TYPE, TimelineEventType.STANDARD_ARTIFACT_CATCH_ALL.getTypeID()))
                    tl.add(attr(STD.TSK_DATETIME, epoch))
                    tl.add(attr(STD.TSK_DESCRIPTION, u"[%s] %s (%s): %s" % (
                        p["label"], r.get("User_behavior", ""), r.get("Verdict", ""), r.get("Behavior_details", ""))))
                    add(content, tl_type, tl, "timeline_events", key)

            for r in read_csv(os.path.join(out_dir, "recovered_conversations.csv")):
                attrs = ArrayList()
                epoch = kst_to_epoch(r.get("timestamp"))
                if epoch is not None:
                    attrs.add(attr(STD.TSK_DATETIME, epoch))
                role = r.get("role") or "-"
                attrs.add(attr(STD.TSK_MESSAGE_TYPE, p["label"]))
                attrs.add(attr(STD.TSK_DIRECTION, "Outgoing" if role == "user" else "Incoming"))
                attrs.add(attr(STD.TSK_THREAD_ID, r.get("conversation_uuid") or "-"))
                attrs.add(attr(STD.TSK_SUBJECT, r.get("conversation_title") or "-"))
                attrs.add(attr(STD.TSK_TEXT, r.get("content") or "-"))
                attrs.add(attr(custom["ARTINEX_ROLE"], role))
                attrs.add(attr(custom["ARTINEX_MESSAGE_UUID"], r.get("message_uuid") or "-"))
                attrs.add(attr(custom["ARTINEX_MESSAGE_ORDER"], r.get("message order") or "-"))
                attrs.add(attr(custom["ARTINEX_ARTIFACT_PATH"], r.get("Artifact_path") or "-"))
                add(source_of(r.get("Artifact_path")), message_type, attrs, "messages", row_key(u"message", r))
        finally:                                                     # 중간에 실패해도 이미 만든 artifact 는 게시한다 (부분 등록)
            if link_notes:
                with open(os.path.join(out_dir, "link_notes.txt"), "wb") as fh:
                    fh.write((u"\n".join(link_notes) + u"\n").encode("utf-8"))
            if not posted.isEmpty():
                try:
                    bb.postArtifacts(posted, MODULE_NAME, self.context.getJobId())
                except (TypeError, AttributeError):                  # 이전 Autopsy: ingest job id 인자 없음
                    bb.postArtifacts(posted, MODULE_NAME)

    # ------------------------------------------------------------------ 진입점
    def process(self, dataSource, progressBar):
        progressBar.switchToDeterminate(2 + len(PARSERS))
        case = Case.getCurrentCase()
        stamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())      # 실행별 작업 폴더 — 이전 추출 파일·CSV 와 섞이지 않게
        root = self.pick_work_root(case)
        if not root:
            return IngestModule.ProcessResult.ERROR
        work = os.path.join(root, "%s_ds_%d" % (case.getName(), dataSource.getId()), stamp)
        os.makedirs(work)
        self.log(Level.INFO, "work folder %s" % work)

        progressBar.progress("Exporting LLM artifacts from Autopsy", 0)
        vols, skipped = self.export_files(dataSource, work)
        n_files = sum(len(v["by_path"]) for v in vols.values())
        self.log(Level.INFO, "exported %d files in %d volume(s) to %s, skipped %s" % (n_files, len(vols), work, skipped))
        if self.context.dataSourceIngestIsCancelled():
            return IngestModule.ProcessResult.OK
        active = sorted((v for v in vols.values() if v["run"]), key=lambda v: v["key"])
        if not active:                                               # 흔적 없음은 오류가 아니다 (negative control)
            self.message(IngestMessage.MessageType.INFO, "No LLM service traces in this data source.")
            return IngestModule.ProcessResult.OK

        status, failed, warn, total = [], False, False, {"behaviors": 0, "messages": 0}
        for i, p in enumerate(PARSERS):
            progressBar.progress("Running ARTINEX %s parser" % p["label"], 1 + i)
            for v in active:
                if self.context.dataSourceIngestIsCancelled():       # 취소: 실패가 아니다. 뒤 파서는 실행하지 않는다
                    self.message(IngestMessage.MessageType.INFO, "Cancelled. Done so far: %s" % "; ".join(status))
                    return IngestModule.ProcessResult.OK
                tag = "%s%s" % (p["name"], "" if len(active) == 1 else " vol%s" % v["key"])
                why = v["run"].get(p["name"])
                if not why:
                    status.append("%s: not run (no input it reads)" % tag)
                    continue
                why = ", ".join("%s %d" % kv for kv in sorted(why.items()))
                gap = v["missing"].get(p["name"])
                gap = u" [incomplete input: %d not exported, see export_skipped.txt%s]" % (
                    gap, u"".join(u"; " + w for w in sorted(v["warnings"].get(p["name"], ())))) if gap else u""
                warn = warn or bool(gap)
                counts = {"behaviors": 0, "timeline_events": 0, "messages": 0, "duplicates": 0, "unlinked": 0}
                stage = "run"
                try:
                    out_dir = os.path.join(work, "vol%s" % v["key"], p["name"])
                    os.makedirs(out_dir)
                    code = self.run_parser(p, v["views"][p["name"]], out_dir)
                    if self.context.dataSourceIngestIsCancelled():
                        self.message(IngestMessage.MessageType.INFO, "Cancelled during %s. Done so far: %s" % (tag, "; ".join(status)))
                        return IngestModule.ProcessResult.OK
                    stage = "csv"
                    log_path = os.path.join(out_dir, "run.log")
                    with open(log_path, "rb") as fh:
                        log_text = fh.read()
                    if code not in p["ok"]:
                        if p.get("nodata") and p["nodata"] in log_text:
                            status.append("%s: no artifacts (ran on %s)%s" % (tag, why, gap))
                        else:
                            status.append("%s: failed (exit %s, see %s)%s" % (tag, code, log_path, gap))
                            failed = True
                        continue
                    tl, rc = os.path.join(out_dir, "timeline.csv"), os.path.join(out_dir, "recovered_conversations.csv")
                    if not (os.path.isfile(tl) and os.path.isfile(rc)):
                        status.append("%s: output missing (exit %s, see %s)%s" % (tag, code, log_path, gap))
                        failed = True
                        continue
                    err = check_csv(tl, TIMELINE_HEADER, verdict=True) or check_csv(rc, CONV_HEADER)
                    if err:
                        status.append("%s: CSV contract violation (%s) in %s%s" % (tag, err, out_dir, gap))
                        failed = True
                        continue
                    stage = "post"
                    self.post_results(dataSource, p, v, out_dir, counts)
                    stage = "report"
                    if counts["behaviors"] + counts["messages"] > 0:
                        report_dir = out_dir
                        if not out_dir.lower().startswith(case.getCaseDirectory().lower()):   # Report 는 사건 폴더 안 파일만 등록된다
                            report_dir = os.path.join(case.getModuleDirectory(), "ARTINEX", "ds_%d" % dataSource.getId(),
                                                      stamp, "vol%s" % v["key"], p["name"])
                            os.makedirs(report_dir)
                        for fn, label in [("timeline.csv", "timeline"), ("recovered_conversations.csv", "recovered conversations")] + \
                                         [(fn, "parser output") for fn in p.get("extra", ())]:
                            path = os.path.join(out_dir, fn)
                            if os.path.isfile(path):
                                if report_dir != out_dir:
                                    shutil.copy(path, report_dir)
                                case.addReport(os.path.join(report_dir, fn), MODULE_NAME,
                                               "ARTINEX %s %s (data source %d, %s)" % (p["label"], label, dataSource.getId(), stamp))
                    status.append("%s: %d behaviors, %d messages (ran on %s)%s%s%s%s" % (
                        tag, counts["behaviors"], counts["messages"], why,
                        " (%d already present)" % counts["duplicates"] if counts["duplicates"] else "",
                        " (%d linked to data source, see link_notes.txt)" % counts["unlinked"] if counts["unlinked"] else "",
                        " [exit %s: some files failed, see run.log]" % code if code else "", gap))
                except ERRORS as exc:                                # 이 파서만 실패로 두고 다음 파서를 계속한다
                    failed = True
                    status.append("%s: failed at %s (%s)%s%s" % (
                        tag, stage, exc, " - partially registered %d behaviors, %d messages" % (counts["behaviors"], counts["messages"])
                        if counts["behaviors"] + counts["messages"] else "", gap))
                    self.log(Level.SEVERE, "%s failed at %s: %s" % (tag, stage, exc))
                finally:
                    total["behaviors"] += counts["behaviors"]
                    total["messages"] += counts["messages"]

        progressBar.progress("Done", 1 + len(PARSERS))
        summary = "%d user behaviors, %d conversation messages (files exported: %d, skipped: %s) | %s | %s" % (
            total["behaviors"], total["messages"], n_files, dict((k, n) for k, n in skipped.items() if n), "; ".join(status),
            self.cleanup(vols, work, "a parser failed" if failed else "incomplete input" if warn else None))
        kind = IngestMessage.MessageType.ERROR if failed else IngestMessage.MessageType.WARNING if warn else IngestMessage.MessageType.DATA
        self.message(kind, summary)
        return IngestModule.ProcessResult.ERROR if failed else IngestModule.ProcessResult.OK

    def pick_work_root(self, case):
        """작업 루트: 사건의 ModuleOutput\\ARTINEX 를 먼저, 쓰기·ADS 가 안 되면 대체 위치(work_dir, 기본 C:\\artinex_work).
        다른 드라이브는 고르지 않는다. 둘 다 안 되면 사유를 남기고 None (실행 중단)."""
        tried = []
        for root in (os.path.join(case.getModuleDirectory(), "ARTINEX"), self.cfg.get("work_dir") or FALLBACK_WORK_DIR):
            why = work_problem(root)
            if not why:
                self.log(Level.INFO, "work root %s%s" % (root, " (fallback: %s)" % "; ".join(tried) if tried else " (case folder)"))
                return root
            tried.append("%s: %s" % (root, why))
        self.message(IngestMessage.MessageType.ERROR, "No usable work location (needs write + alternate data streams): %s" % "; ".join(tried))
        return None

    def cleanup(self, vols, work, problem):
        """추출본(vol<n>/export, vol<n>/in_<파서>)은 파서 입력일 뿐이라 정상 완료면 지운다 — 원본은 이미지에, 결과 CSV·run.log·
        export_skipped.txt 와 Report 사본은 남는다. 실패·입력 누락이 있으면 원인을 볼 수 있게 남긴다 (keep_export 로 항상 남김)."""
        if problem or self.cfg.get("keep_export"):
            return "extracted files kept (%s): %s" % (problem or "keep_export", work)
        try:
            for v in vols.values():
                vol_dir = os.path.dirname(v["dir"])
                if os.path.isdir(vol_dir):
                    for n in os.listdir(vol_dir):
                        if n == "export" or n.startswith("in_"):
                            shutil.rmtree(os.path.join(vol_dir, n))
            return "extracted files removed (results kept): %s" % work
        except ERRORS as exc:
            self.log(Level.WARNING, "cleanup failed: %s" % exc)
            return "extracted files partly removed (%s): %s" % (exc, work)

    def message(self, kind, text):
        self.log(Level.INFO, text)
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(kind, MODULE_NAME, text))
