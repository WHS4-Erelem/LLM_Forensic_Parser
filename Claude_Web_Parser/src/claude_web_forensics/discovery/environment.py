"""Environment discovery: Windows installations / users and Chrome profiles."""
from __future__ import annotations

from dataclasses import dataclass, field
from ..image.volumes import NtfsVolume

_SYSTEM_PROFILES = {"all users", "default", "default user", "public", "defaultapppool", "desktop.ini",}

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
    users: list[WindowsUser] = field(default_factory=list)

def find_windows_installs(volumes: list[NtfsVolume]) -> list[WindowsInstall]:
    installs: list[WindowsInstall] = []
    for volume in volumes:
        if not volume.exists("/Users") or not (volume.exists("/Windows") or volume.info.filesystem == "directory"):
            continue
        install = WindowsInstall(volume_id=volume.info.identifier, windows_path="/Windows",)
        for name, record in sorted(volume.listdir("/Users").items()):
            if name.lower() in _SYSTEM_PROFILES:
                continue
            try:
                if not record.is_dir():
                    continue
            except Exception:
                continue
            install.users.append(
                WindowsUser(username=name, profile_path=f"/Users/{name}", volume_id=volume.info.identifier,)
            )
        installs.append(install)
    return installs

def find_user_sids(volume: NtfsVolume) -> list[str]:
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

CHROME_USER_DATA = "AppData/Local/Google/Chrome/User Data"

EXCLUDED_FILES = {"login data", "login data-journal", "login data for account", "login data for account-journal",}

@dataclass
class ChromeProfile:
    windows_user: str
    profile_name: str
    volume_id: str
    source_path: str
    user_data_path: str
    attributes: dict[str, object] = field(default_factory=dict)

def _is_profile_dir(name: str) -> bool:
    lowered = name.lower()
    return lowered == "default" or lowered.startswith("profile ") or lowered == "guest profile"

def find_chrome_profiles(volume: NtfsVolume, user: WindowsUser) -> list[ChromeProfile]:
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
                windows_user=user.username, profile_name=name, volume_id=volume.info.identifier,
                source_path=f"{user_data}/{name}", user_data_path=user_data,
                    attributes={"is_guest_profile": name.lower() == "guest profile",},
            )
        )
    return profiles

@dataclass
class ArtifactPlanEntry:
    artifact: str
    family: str
    kind: str
    source: str
    companions: tuple[str, ...] = ()
    note: str = ""

ARTIFACT_PLAN: tuple[ArtifactPlanEntry, ...] = (
    ArtifactPlanEntry(
        artifact="History", family="history", kind="file", source="History",
        companions=("History-wal", "History-shm", "History-journal"),
    ),
    ArtifactPlanEntry(
        artifact="Cookies", family="cookies", kind="file", source="Network/Cookies",
        companions=("Network/Cookies-wal", "Network/Cookies-shm", "Network/Cookies-journal"),
    ),
    ArtifactPlanEntry(artifact="Cache", family="cache", kind="dir", source="Cache/Cache_Data",),
    ArtifactPlanEntry(
        artifact="IndexedDB", family="indexeddb", kind="dir", source="IndexedDB",
        note="includes sibling .blob directories",
    ),
    ArtifactPlanEntry(
        artifact="Local Storage", family="local_storage", kind="dir", source="Local Storage/leveldb",
    ),
    ArtifactPlanEntry(artifact="Sessions/Tabs", family="sessions", kind="dir", source="Sessions",),
)

def fallback_cookie_paths() -> tuple[str, ...]:
    return ("Cookies", "Cookies-wal", "Cookies-shm", "Cookies-journal")
