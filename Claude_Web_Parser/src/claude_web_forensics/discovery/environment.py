"""Environment discovery: Windows installations / users and Chrome profiles.

Merged verbatim from: windows.py, chrome.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ..image.volumes import NtfsVolume


# ===========================================================================
# windows
# ===========================================================================

"""Windows installation and user-profile discovery inside an NTFS volume."""

# Pseudo-profiles that are not real interactive users.
_SYSTEM_PROFILES = {
    "all users",
    "default",
    "default user",
    "public",
    "defaultapppool",
    "desktop.ini",
}


@dataclass
class WindowsUser:
    username: str
    profile_path: str
    volume_id: str
    sid: str = ""
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class WindowsInstall:
    volume_id: str
    windows_path: str
    users_path: str
    users: list[WindowsUser] = field(default_factory=list)


def find_windows_installs(volumes: list[NtfsVolume]) -> list[WindowsInstall]:
    """Locate every Windows installation. Multiple installs are all processed."""
    installs: list[WindowsInstall] = []
    for volume in volumes:
        if not volume.exists("/Windows") or not volume.exists("/Users"):
            continue
        install = WindowsInstall(
            volume_id=volume.info.identifier,
            windows_path="/Windows",
            users_path="/Users",
        )
        for name, record in sorted(volume.listdir("/Users").items()):
            if name.lower() in _SYSTEM_PROFILES:
                continue
            try:
                if not record.is_dir():
                    continue
            except Exception:
                continue
            install.users.append(
                WindowsUser(
                    username=name,
                    profile_path=f"/Users/{name}",
                    volume_id=volume.info.identifier,
                )
            )
        installs.append(install)
    return installs


def find_user_sids(volume: NtfsVolume) -> list[str]:
    """User SIDs observed as $Recycle.Bin subdirectories."""
    sids: list[str] = []
    for name, record in sorted(volume.listdir("/$Recycle.Bin").items()):
        try:
            if not record.is_dir():
                continue
        except Exception:
            continue
        if name.upper().startswith("S-1-"):
            sids.append(name)
    return sids


# ===========================================================================
# chrome
# ===========================================================================

"""Chrome profile discovery and the artifact file set to acquire.

Six artifact families are in scope (spec section 1.4). Login Data is excluded
everywhere -- discovery, acquisition, parsing, coverage, output and tests
(spec section 1.5).
"""

CHROME_USER_DATA = "AppData/Local/Google/Chrome/User Data"

# Never opened, never read, never listed as an artifact.
EXCLUDED_FILES = {
    "login data",
    "login data-journal",
    "login data for account",
    "login data for account-journal",
}


@dataclass
class ChromeProfile:
    windows_user: str
    profile_name: str
    volume_id: str
    source_path: str           # e.g. /Users/llmtest/.../User Data/Default
    user_data_path: str
    attributes: dict[str, object] = field(default_factory=dict)

    @property
    def context_id(self) -> str:
        return f"{self.volume_id}|{self.windows_user}|{self.profile_name}"


def _is_profile_dir(name: str) -> bool:
    lowered = name.lower()
    return lowered == "default" or lowered.startswith("profile ") or lowered == "guest profile"


def find_chrome_profiles(volume: NtfsVolume, user: WindowsUser) -> list[ChromeProfile]:
    """Standard Chrome profile folders for one Windows user."""
    user_data = f"{user.profile_path}/{CHROME_USER_DATA}"
    if not volume.exists(user_data):
        return []

    profiles: list[ChromeProfile] = []
    for name, record in sorted(volume.listdir(user_data).items()):
        if not _is_profile_dir(name):
            continue
        try:
            if not record.is_dir():
                continue
        except Exception:
            continue
        profiles.append(
            ChromeProfile(
                windows_user=user.username,
                profile_name=name,
                volume_id=volume.info.identifier,
                source_path=f"{user_data}/{name}",
                user_data_path=user_data,
                attributes={
                    # Guest Profile is recorded but we never assume Incognito
                    # traces land in a standard profile (spec section 5).
                    "is_guest_profile": name.lower() == "guest profile",
                },
            )
        )
    return profiles


# ---------------------------------------------------------------------------
# Artifact acquisition plan
# ---------------------------------------------------------------------------

@dataclass
class ArtifactPlanEntry:
    artifact: str
    family: str
    kind: str               # "file" | "dir"
    source: str             # path relative to the profile directory
    required: bool = True
    companions: tuple[str, ...] = ()   # sibling files copied as one set
    note: str = ""


# Support files (Local State, -wal/-shm, LevelDB internals, .blob, Cache index)
# are collected for consistent parsing but are NOT counted as separate
# artifacts (spec section 5).
ARTIFACT_PLAN: tuple[ArtifactPlanEntry, ...] = (
    ArtifactPlanEntry(
        artifact="History",
        family="history",
        kind="file",
        source="History",
        companions=("History-wal", "History-shm", "History-journal"),
    ),
    ArtifactPlanEntry(
        artifact="Cookies",
        family="cookies",
        kind="file",
        source="Network/Cookies",
        companions=("Network/Cookies-wal", "Network/Cookies-shm", "Network/Cookies-journal"),
    ),
    ArtifactPlanEntry(
        artifact="Cache",
        family="cache",
        kind="dir",
        source="Cache/Cache_Data",
    ),
    ArtifactPlanEntry(
        artifact="IndexedDB",
        family="indexeddb",
        kind="dir",
        source="IndexedDB",
        note="includes sibling .blob directories",
    ),
    ArtifactPlanEntry(
        artifact="Local Storage",
        family="local_storage",
        kind="dir",
        source="Local Storage/leveldb",
    ),
    ArtifactPlanEntry(
        artifact="Sessions/Tabs",
        family="sessions",
        kind="dir",
        source="Sessions",
    ),
)


def fallback_cookie_paths() -> tuple[str, ...]:
    """Older Chrome kept Cookies directly under the profile folder."""
    return ("Cookies", "Cookies-wal", "Cookies-shm", "Cookies-journal")
