"""이미지 안에서 Claude Desktop 아티팩트 위치를 식별한다.

경로 근거는 실제 이미지에서 확인한 것이다. 설치 형태가 세 가지라 전부 본다.

  %LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\   (MSIX)
  %APPDATA%\\Claude\\                                                            (일반 설치)
  %LOCALAPPDATA%\\Claude\\  +  %LOCALAPPDATA%\\Claude-Data\\                     (로그·데이터 분리형)

앱 로그는 패키지 폴더 밖에 있어 앱을 지워도 남는다 — 계정 흔적의 핵심 근거다.
"""

import re

PACKAGE_FAMILY = "claude_pzs8sxrjxfjjc"

# 디스크 이미지에서 훑을 디렉터리 (볼륨 루트 기준, 소문자·슬래시 정규화 후 비교)
SCAN_ROOTS = (
    "Users/*/AppData/Local/Packages/" + PACKAGE_FAMILY,
    "Users/*/AppData/Roaming/Claude",
    "Users/*/AppData/Local/Claude",
    "Users/*/AppData/Local/Claude-Data",
    "Users/*/AppData/Local/AnthropicClaude",
    "Program Files/WindowsApps/claude_*",
    "ProgramData/Claude",
    "Windows/Prefetch",
)

# 앱 루트 뒤에 붙는 상대 경로만 다르고 앞은 설치 형태마다 다르다.
_ROOT = (r"(?:"
         r"appdata/local/packages/" + PACKAGE_FAMILY + r"/localcache/roaming/claude"
         r"|appdata/roaming/claude"
         r"|appdata/local/claude-data"
         r"|appdata/local/claude"
         r"|appdata/local/anthropicclaude"
         r")")

# (kind, 정규식)
_PATTERNS = [
    # ── 대화 본문 ────────────────────────────────────────────────────
    ("cache_block",   re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/cache/cache_data/(?P<fn>(data_\d+|f_[0-9a-f]+|index))$")),
    # 폴더 이름 끝의 숫자는 Chromium 이 붙이는 오리진 포트 토큰이다.
    # 지금은 늘 0 이지만 고정해 두면 다른 값일 때 저장소를 통째로 놓친다.
    ("idb_leveldb",   re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/indexeddb/https_claude\.ai_\d+\.indexeddb\.leveldb/"
                                 r"(?P<fn>[^/]+\.(ldb|log)|CURRENT|MANIFEST-\d+)$", re.I)),
    ("idb_blob",      re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/indexeddb/https_claude\.ai_\d+\.indexeddb\.blob/(?P<rest>.+)$")),
    ("local_storage", re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/local storage/leveldb/(?P<fn>[^/]+\.(ldb|log))$", re.I)),
    ("session_storage", re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                   r"/session storage/(?P<fn>[^/]+\.(ldb|log))$", re.I)),
    # ── 계정·설정 ────────────────────────────────────────────────────
    ("config",        re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/(?P<fn>config\.json|ant-did|ant-device-registry\.json"
                                 r"|window-state\.json|plan-usage-history\.json)$")),
    # ── 앱 로그 (패키지 밖) ──────────────────────────────────────────
    ("applog",        re.compile(r"/users/(?P<user>[^/]+)/appdata/local/claude/logs/"
                                 r"(?P<fn>[^/]+\.log)$")),
    ("applog_pkg",    re.compile(r"/users/(?P<user>[^/]+)/" + _ROOT +
                                 r"/logs/(?P<fn>[^/]+\.log)$")),
    ("applog_shared", re.compile(r"/programdata/claude/logs/(?P<fn>[^/]+\.log)$")),
    ("setuplog",      re.compile(r"/users/(?P<user>[^/]+)/appdata/local/temp/"
                                 r"(?P<fn>claudesetup\.log)$", re.I)),
    # ── 실행 흔적 ────────────────────────────────────────────────────
    ("prefetch",      re.compile(r"/windows/prefetch/(?P<fn>claude[^/]*\.pf)$", re.I)),
    # ── 설치 패키지 ──────────────────────────────────────────────────
    ("package_binary", re.compile(r"/program files/windowsapps/claude_(?P<ver>[^/]+)/"
                                  r"(?P<rest>.+)$")),
]

# 대화 본문을 담는 아티팩트 (1차 대상)
PRIMARY_KINDS = {"cache_block", "idb_leveldb", "idb_blob", "local_storage"}

# 계정·실행 흔적
SECONDARY_KINDS = {"config", "applog", "applog_pkg", "applog_shared", "setuplog",
                   "prefetch"}


def normalize(path):
    return path.replace("\\", "/").lower()


def classify(path):
    """경로 -> (kind, groupdict) 또는 (None, {})"""
    norm = normalize(path)
    for kind, rx in _PATTERNS:
        m = rx.search(norm)
        if m:
            return kind, {k: v for k, v in m.groupdict().items() if v is not None}
    return None, {}


# 이름만 겹치는 다른 제품. 이 경로 아래 것은 Claude Desktop 이 아니다.
OTHER_PRODUCTS = (
    ("/.claude/", "Claude Code(CLI)"),
    ("/.claude.json", "Claude Code(CLI)"),
    ("/google/chrome/", "Claude Web"),
    ("/microsoft/edge/", "Claude Web"),
    ("/openai/", "다른 앱"),
    ("/.codex/", "다른 앱"),
    ("/.lmstudio/", "다른 앱"),
)


def other_product(path):
    """Claude Desktop 이 아닌 제품의 경로면 제품 이름, 아니면 None."""
    norm = normalize(path)
    for frag, name in OTHER_PRODUCTS:
        if frag in norm:
            return name
    return None
