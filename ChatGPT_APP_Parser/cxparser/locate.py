"""이미지 안에서 Codex Desktop 아티팩트 위치를 식별한다.

경로 근거는 전부 첨부 분석표(에레렘, 2026-08-29 수집)에서 확인된 것이다:
  %USERPROFILE%\\.codex\\            (auth.json, .codex-global-state.json,
                                     session_index.jsonl, sessions\\YYYY\\MM\\DD\\rollout-*.jsonl,
                                     *.sqlite/-wal/-shm, thread-writer-locks\\*.lock,
                                     config.json, installation_id, models_cache.json)
  %LOCALAPPDATA%\\Packages\\OpenAI.Codex_2p2nqsd0c76g0\\   (채팅창 Chromium 저장소, Helium 하이브)
  %ProgramFiles%\\WindowsApps\\OpenAI.Codex_<ver>_x64__2p2nqsd0c76g0\\
  %ProgramData%\\Packages\\OpenAI.Codex_2p2nqsd0c76g0
  %USERPROFILE%\\Documents\\Codex\\<날짜>\\<슬러그>\\(work|outputs|tmp)
"""

import re

PACKAGE_FAMILY = "openai.codex_2p2nqsd0c76g0"

# 디스크 이미지에서 탐색할 디렉터리 (볼륨 루트 기준, 대소문자 무시, * 와일드카드)
SCAN_ROOTS = (
    "Users/*/.codex",
    "Users/*/Documents/Codex",
    "Users/*/AppData/Local/Packages/" + PACKAGE_FAMILY,
    "Program Files/WindowsApps/openai.codex_*",
    "ProgramData/Packages/" + PACKAGE_FAMILY,
)

# (kind, 정규식) — 경로는 소문자·슬래시 정규화 후 매칭
_PATTERNS = [
    ("rollout",        re.compile(r"/users/(?P<user>[^/]+)/\.codex/sessions/(?P<y>\d{4})/(?P<m>\d{2})/(?P<d>\d{2})/(?P<fn>rollout-[^/]+\.jsonl)$")),
    ("rollout_loose",  re.compile(r"/\.codex/sessions/.*/(?P<fn>rollout-[^/]+\.jsonl)$")),
    ("session_index",  re.compile(r"/users/(?P<user>[^/]+)/\.codex/session_index\.jsonl$")),
    ("global_state",   re.compile(r"/users/(?P<user>[^/]+)/\.codex/\.codex-global-state\.json$")),
    ("auth",           re.compile(r"/users/(?P<user>[^/]+)/\.codex/auth\.json$")),
    ("config",         re.compile(r"/users/(?P<user>[^/]+)/\.codex/config\.json$")),
    ("installation_id", re.compile(r"/users/(?P<user>[^/]+)/\.codex/installation_id$")),
    ("models_cache",   re.compile(r"/users/(?P<user>[^/]+)/\.codex/models_cache\.json$")),
    ("sqlite",         re.compile(r"/users/(?P<user>[^/]+)/\.codex/(?P<db>[^/]+\.sqlite(-wal|-shm)?)$")),
    ("thread_lock",    re.compile(r"/users/(?P<user>[^/]+)/\.codex/thread-writer-locks/(?P<fn>[^/]+)$")),
    ("documents_output", re.compile(r"/users/(?P<user>[^/]+)/documents/codex/(?P<rest>.+)$")),
    ("package_userdata", re.compile(r"/users/(?P<user>[^/]+)/appdata/local/packages/" + PACKAGE_FAMILY + r"/(?P<rest>.+)$")),
    ("package_binary",  re.compile(r"/program files/windowsapps/openai\.codex_(?P<ver>[^/]+)/(?P<rest>.+)$")),
    ("package_registration", re.compile(r"/programdata/packages/" + PACKAGE_FAMILY + r"(/(?P<rest>.+))?$")),
]

# 대화 내용 파싱 대상(1차 MVP)
PRIMARY_KINDS = {"rollout", "rollout_loose"}

# 부가 추출 대상
SECONDARY_KINDS = {"session_index", "global_state", "auth"}


def normalize(path):
    return path.replace("\\", "/").lower()


def classify(path):
    """경로 -> (kind, groupdict) 또는 (None, {})"""
    norm = normalize(path)
    for kind, rx in _PATTERNS:
        m = rx.search(norm)
        if m:
            gd = {k: v for k, v in m.groupdict().items() if v is not None}
            return kind, gd
    return None, {}


ROLLOUT_NAME_RE = re.compile(
    r"^rollout-(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})-"
    r"(?P<thread>[0-9a-fA-F-]{8,})"
    r"(?:_(?P<branch>[0-9a-fA-F-]{8,}))?"
    r"\.jsonl$", re.IGNORECASE)


def parse_rollout_filename(name):
    """rollout 파일명에서 시작시각/스레드ID/분기ID 추출.

    분석표 근거:
      rollout-2026-08-29T02-22-56-01a04965-63f0-....jsonl      (E03-01 새 대화)
      rollout-...-<원본대화ID>_<분기ID>.jsonl                   (E03-03 대화 수정)
    """
    m = ROLLOUT_NAME_RE.match(name)
    if not m:
        return None
    ts = m.group("ts")
    iso = ts[:10] + "T" + ts[11:].replace("-", ":")
    return {
        "filename_timestamp_raw": ts,
        "filename_timestamp_iso_naive": iso,
        "thread_id": m.group("thread"),
        "branch_id": m.group("branch"),
        "is_branch": bool(m.group("branch")),
    }
