"""Live 수집 — 현재 실행 중인 Windows PC 에서 Chrome Artifact 를 찾아 분석용 사본을 만든다.

역할 분리:
  이 모듈      "어디에 있는가" (탐색) + "안전하게 어떻게 가져오는가" (읽기 전용 사본)
  나머지 파서   "무엇인가" (Discovery · Reader · Rule · 복구 · 최종 CSV)

수집한 사본은 `Users/<user>/AppData/Local/Google/Chrome/User Data/<profile>/...` 구조로 만들어
기존 폴더 입력(`--dir`, DirectorySource)이 그대로 읽는다. Live 전용 Reader·Rule 은 만들지 않는다.

원본 보호: 원본은 읽기로만 연다. 수정·삭제·덮어쓰기를 하지 않고, 사본은 새 폴더에만 쓴다.
Chrome 이 실행 중이면 일부 파일이 잠겨 복사에 실패할 수 있다 — 실패는 기록하고 나머지는 계속 가져온다.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .artifacts.cache import CACHE_DIR_PARTS
from .artifacts.local_storage import LOCAL_STORAGE_DIR_PARTS
from .artifacts.session_storage import SESSION_STORAGE_DIR_PARTS
from .artifacts.sessions import SESSIONS_DIR_PARTS
from .artifacts.shared_proto_db import SHARED_PROTO_DB_DIR_PARTS
from .discovery import CHROME_USER_DATA_PARTS, is_chrome_profile_name

# 파서가 실제로 읽는 Artifact 만 가져온다. 경로 조각은 Reader 가 쓰는 상수를 그대로 참조해서
# 목록이 코드와 어긋나지 않게 한다 (History 는 Profile 폴더 바로 아래 파일이다).
LIVE_PROFILE_FILES = ("History",)
LIVE_PROFILE_DIRS = (
    LOCAL_STORAGE_DIR_PARTS,
    SESSION_STORAGE_DIR_PARTS,
    CACHE_DIR_PARTS,
    SHARED_PROTO_DB_DIR_PARTS,
    SESSIONS_DIR_PARTS,
)

LIVE_NOT_WINDOWS = "LIVE_NOT_WINDOWS"
LIVE_NO_USER_DIR = "LIVE_NO_USER_DIR"
LIVE_CHROME_NOT_INSTALLED = "LIVE_CHROME_NOT_INSTALLED"
LIVE_NO_CHROME_PROFILE = "LIVE_NO_CHROME_PROFILE"
LIVE_PROFILE_WITHOUT_ARTIFACT = "LIVE_PROFILE_WITHOUT_ARTIFACT"
LIVE_COPY_FAILED = "LIVE_COPY_FAILED"
LIVE_WORK_DIR_PREFIX = "chatgpt_web_live_"


class LiveAcquisitionError(Exception):
    """Live 수집을 시작할 수 없을 때 (Windows 가 아님 · Chrome 없음 등)."""


@dataclass
class LiveProfile:
    """현재 PC 에서 찾은 Chrome Profile 하나."""

    os_user: str
    browser_profile: str
    profile_path: Path
    artifacts: list = field(default_factory=list)      # 실제로 있는 Artifact 이름


@dataclass
class LiveCollection:
    """수집 결과. working_dir 를 그대로 `--dir` 입력으로 쓴다."""

    working_dir: Path
    profiles: list = field(default_factory=list)       # [LiveProfile]
    copied: list = field(default_factory=list)         # 가져온 Artifact 상대 경로
    failed: list = field(default_factory=list)         # [(상대 경로, 사유)] — 잠긴 파일 등
    warnings: list = field(default_factory=list)
    temporary: bool = False                            # 임시 폴더를 직접 만든 경우

    def cleanup(self) -> None:
        """직접 만든 임시 폴더만 지운다 (사용자가 준 폴더는 건드리지 않는다)."""
        if self.temporary and self.working_dir.exists():
            shutil.rmtree(self.working_dir, ignore_errors=True)


def is_windows() -> bool:
    return os.name == "nt"


def user_profile_roots() -> list[Path]:
    """현재 PC 에서 볼 수 있는 Windows 사용자 홈 폴더. 사용자 이름을 하드코딩하지 않는다.

    ① 현재 로그인 사용자(USERPROFILE / Path.home())
    ② 그 홈의 상위 폴더(보통 C:\\Users) 아래에서 읽을 수 있는 다른 사용자 폴더
    권한이 없는 폴더는 조용히 건너뛴다 (권한 상승을 시도하지 않는다).
    """
    roots: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        key = os.path.normcase(str(resolved))
        if key not in seen and resolved.is_dir():
            seen.add(key)
            roots.append(resolved)

    home_env = os.environ.get("USERPROFILE")
    if home_env:
        add(Path(home_env))
    add(Path.home())

    for base in list(roots):
        parent = base.parent
        try:
            children = sorted(parent.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                if child.is_dir():
                    add(child)
            except OSError:
                continue
    return roots


def chrome_user_data_dirs(home: Path) -> list[Path]:
    """홈 폴더 아래의 Chrome User Data 경로 (discovery 와 같은 경로 규칙)."""
    candidate = home.joinpath(*CHROME_USER_DATA_PARTS)
    return [candidate] if candidate.is_dir() else []


def _profile_artifacts(profile_path: Path) -> list[str]:
    """그 Profile 에 실제로 있는 Artifact 이름 (파서가 쓰는 것만)."""
    found = []
    for name in LIVE_PROFILE_FILES:
        if (profile_path / name).is_file():
            found.append(name)
    for parts in LIVE_PROFILE_DIRS:
        if profile_path.joinpath(*parts).is_dir():
            found.append("/".join(parts))
    return found


def discover_live_profiles(warnings: list | None = None) -> list[LiveProfile]:
    """현재 PC 의 Chrome Profile 목록. 이름 목록을 고정하지 않고 실제 디렉터리에서 찾는다."""
    notes = warnings if warnings is not None else []
    if not is_windows():
        raise LiveAcquisitionError(f"{LIVE_NOT_WINDOWS}: Live 수집은 Windows 에서만 동작한다")
    homes = user_profile_roots()
    if not homes:
        raise LiveAcquisitionError(f"{LIVE_NO_USER_DIR}: 읽을 수 있는 Windows 사용자 폴더를 찾지 못했다")

    profiles: list[LiveProfile] = []
    for home in homes:
        for user_data in chrome_user_data_dirs(home):
            try:
                children = sorted(user_data.iterdir())
            except OSError as exc:
                notes.append(f"{LIVE_COPY_FAILED}:{user_data}:{exc.__class__.__name__}")
                continue
            for child in children:
                try:
                    if not child.is_dir() or not is_chrome_profile_name(child.name):
                        continue
                except OSError:
                    continue
                artifacts = _profile_artifacts(child)
                if not artifacts:
                    notes.append(f"{LIVE_PROFILE_WITHOUT_ARTIFACT}:{home.name}/{child.name}")
                    continue
                profiles.append(LiveProfile(os_user=home.name, browser_profile=child.name,
                                            profile_path=child, artifacts=artifacts))
    if not profiles:
        if not any(chrome_user_data_dirs(home) for home in homes):
            raise LiveAcquisitionError(
                f"{LIVE_CHROME_NOT_INSTALLED}: Chrome User Data 폴더를 찾지 못했다")
        raise LiveAcquisitionError(
            f"{LIVE_NO_CHROME_PROFILE}: Chrome Profile 에서 분석할 Artifact 를 찾지 못했다")
    return profiles


def _copy_file(src: Path, dest: Path, collection: LiveCollection, rel: str) -> None:
    """파일 1개를 읽기 전용으로 복사한다. 실패해도 전체를 멈추지 않는다."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(src, "rb") as fh_in, open(dest, "wb") as fh_out:   # 원본은 읽기로만 연다
            shutil.copyfileobj(fh_in, fh_out)
        collection.copied.append(rel)
    except OSError as exc:        # 잠김(Chrome 실행 중) · 권한 없음 등
        collection.failed.append((rel, exc.__class__.__name__))


def _copy_tree(src: Path, dest: Path, collection: LiveCollection, rel: str) -> None:
    try:
        entries = sorted(src.rglob("*"))
    except OSError as exc:
        collection.failed.append((rel, exc.__class__.__name__))
        return
    for entry in entries:
        try:
            if not entry.is_file():
                continue
        except OSError:
            continue
        relative = entry.relative_to(src)
        _copy_file(entry, dest / relative, collection, f"{rel}/{relative.as_posix()}")


def collect_live_artifacts(work_dir: str | os.PathLike[str] | None = None,
                           profiles: list | None = None) -> LiveCollection:
    """현재 PC 의 Chrome Artifact 를 분석용 사본으로 가져온다.

    반환한 `working_dir` 는 `Users/<user>/AppData/Local/Google/Chrome/User Data/<profile>/...`
    구조라서 기존 폴더 입력(DirectorySource)이 그대로 읽는다.
    """
    warnings: list = []
    found = profiles if profiles is not None else discover_live_profiles(warnings)
    if work_dir is None:
        root = Path(tempfile.mkdtemp(prefix=LIVE_WORK_DIR_PREFIX))
        temporary = True
    else:
        root = Path(work_dir)
        root.mkdir(parents=True, exist_ok=True)
        temporary = False
    collection = LiveCollection(working_dir=root, profiles=list(found), warnings=warnings,
                                temporary=temporary)

    for profile in found:
        dest_profile = root.joinpath("Users", profile.os_user, *CHROME_USER_DATA_PARTS,
                                     profile.browser_profile)
        rel_base = f"{profile.os_user}/{profile.browser_profile}"
        for name in LIVE_PROFILE_FILES:
            src = profile.profile_path / name
            if src.is_file():
                _copy_file(src, dest_profile / name, collection, f"{rel_base}/{name}")
        for parts in LIVE_PROFILE_DIRS:
            src = profile.profile_path.joinpath(*parts)
            if src.is_dir():
                _copy_tree(src, dest_profile.joinpath(*parts), collection,
                           f"{rel_base}/{'/'.join(parts)}")
    if collection.failed:
        collection.warnings.append(f"{LIVE_COPY_FAILED}:{len(collection.failed)}")
    return collection


def summarize(collection: LiveCollection) -> list[str]:
    """화면에 보여 줄 수집 요약. 파일 내용·계정 정보는 넣지 않는다 (경로 개수만)."""
    lines = [f"Profiles   : {len(collection.profiles)}"]
    for profile in collection.profiles:
        lines.append(f"  - {profile.os_user} / {profile.browser_profile} "
                     f"(artifact {len(profile.artifacts)}종: {', '.join(profile.artifacts)})")
    lines.append(f"Copied     : {len(collection.copied)} 파일")
    if collection.failed:
        lines.append(f"Failed     : {len(collection.failed)} 파일 (잠김·권한 등, 분석은 계속한다)")
    lines.append(f"Working    : {collection.working_dir}")
    return lines
