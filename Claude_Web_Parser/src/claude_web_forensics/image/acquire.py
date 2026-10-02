"""Artifact acquisition into an isolated staging workspace."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..discovery.environment import (ARTIFACT_PLAN, EXCLUDED_FILES, ChromeProfile, fallback_cookie_paths,)
from ..model.entities import ST_FOUND, ST_NOT_FOUND, ParseStatus
from ..image.volumes import NtfsVolume

MAX_SINGLE_FILE = 512 * 1024 * 1024

@dataclass
class StagedFile:
    staged_path: str
    source_path: str
    volume_id: str
    size: int
    mft_segment: int | None = None
    mft_sequence: int | None = None
    stream_name: str = ""
    artifact: str = ""
    family: str = ""
    note: str = ""

    @property
    def record_locator(self) -> str:
        parts = [f"volume={self.volume_id}"]
        if self.mft_segment is not None:
            parts.append(f"mft={self.mft_segment}")
            if self.mft_sequence is not None:
                parts.append(f"seq={self.mft_sequence}")
        if self.stream_name:
            parts.append(f"ads={self.stream_name}")
        return ";".join(parts)

@dataclass
class StagedArtifact:
    artifact: str
    family: str
    status: str
    source_path: str
    staged_root: str = ""
    files: list[StagedFile] = field(default_factory=list)
    message: str = ""

    @property
    def file_count(self) -> int:
        return len(self.files)

@dataclass
class ProfileStaging:
    profile: ChromeProfile
    root: str
    artifacts: dict[str, StagedArtifact] = field(default_factory=dict)

    def artifact_path(self, artifact: str) -> Path | None:
        entry = self.artifacts.get(artifact)
        if entry is None or not entry.staged_root:
            return None
        path = Path(entry.staged_root)
        return path if path.exists() else None

def _safe_component(name: str) -> str:
    cleaned = name.replace("\x00", "").strip()
    cleaned = cleaned.replace(":", "_")
    if cleaned in ("", ".", ".."):
        return "_"
    return cleaned

def _record_ids(record: Any) -> tuple[int | None, int | None]:
    segment = getattr(record, "segment", None)
    sequence = None
    try:
        sequence = int(record.header.sequence_number)
    except Exception:
        sequence = None
    try:
        segment = int(segment) if segment is not None else None
    except Exception:
        segment = None
    return segment, sequence

class Stager:
    def __init__(self, staging_root: Path) -> None:
        self.root = Path(staging_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.entries: list[StagedFile] = []
        self.warnings: list[str] = []

    def copy_record(
        self, volume: NtfsVolume, source_path: str, record: Any, dest: Path, *, artifact: str = "",
        family: str = "", stream_name: str = "",
    ) -> StagedFile | None:
        fh = volume.open_record(record, stream_name or None)
        if fh is None:
            self.warnings.append(f"cannot open {source_path}{':' + stream_name if stream_name else ''}")
            return None
        try:
            data = fh.read(MAX_SINGLE_FILE + 1)
        except Exception as exc:
            self.warnings.append(f"read failed {source_path}: {type(exc).__name__}: {exc}")
            return None
        finally:
            try:
                fh.close()
            except Exception:
                pass

        note = ""
        if len(data) > MAX_SINGLE_FILE:
            data = data[:MAX_SINGLE_FILE]
            note = "truncated at acquisition limit"
            self.warnings.append(f"{source_path}: {note}")

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        segment, sequence = _record_ids(record)
        staged = StagedFile(
            staged_path=str(dest), source_path=source_path, volume_id=volume.info.identifier, size=len(data),
            mft_segment=segment, mft_sequence=sequence, stream_name=stream_name, artifact=artifact,
            family=family, note=note,
        )
        self.entries.append(staged)
        return staged

    def copy_path(
        self, volume: NtfsVolume, source_path: str, dest: Path, *, artifact: str = "", family: str = "",
        stream_name: str = "",
    ) -> StagedFile | None:
        record = volume.get(source_path)
        if record is None:
            return None
        return self.copy_record(
            volume, source_path, record, dest, artifact=artifact, family=family, stream_name=stream_name,
        )

    def copy_tree(
        self, volume: NtfsVolume, source_dir: str, dest_dir: Path, *, artifact: str, family: str,
        max_depth: int = 6,
    ) -> list[StagedFile]:
        out: list[StagedFile] = []
        stack: list[tuple[str, Path, int]] = [(source_dir, dest_dir, 0)]
        while stack:
            src, dst, depth = stack.pop()
            if depth > max_depth:
                continue
            for name, record in sorted(volume.listdir(src).items()):
                if name.lower() in EXCLUDED_FILES:
                    continue
                child_src = f"{src}/{name}"
                child_dst = dst / _safe_component(name)
                try:
                    is_dir = record.is_dir()
                except Exception:
                    is_dir = False
                if is_dir:
                    stack.append((child_src, child_dst, depth + 1))
                    continue
                staged = self.copy_record(volume, child_src, record, child_dst, artifact=artifact, family=family)
                if staged is not None:
                    out.append(staged)
        return out

    def stage_profile(self, volume: NtfsVolume, profile: ChromeProfile) -> ProfileStaging:
        base = self.root / _safe_component(volume.info.identifier) / _safe_component(profile.windows_user
            ) / _safe_component(profile.profile_name)
        staging = ProfileStaging(profile=profile, root=str(base))

        for entry in ARTIFACT_PLAN:
            src = f"{profile.source_path}/{entry.source}"
            dest = base / Path(entry.source)
            artifact = StagedArtifact(
                artifact=entry.artifact, family=entry.family, status=ST_NOT_FOUND, source_path=src,
                staged_root=str(dest),
            )

            if entry.kind == "file":
                staged = self.copy_path(volume, src, dest, artifact=entry.artifact, family=entry.family)
                if staged is None and entry.artifact == "Cookies":
                    for candidate in fallback_cookie_paths():
                        alt_src = f"{profile.source_path}/{candidate}"
                        alt_dest = base / candidate
                        alt = self.copy_path(
                            volume, alt_src, alt_dest, artifact=entry.artifact, family=entry.family,
                        )
                        if alt is not None:
                            artifact.files.append(alt)
                            if candidate == "Cookies":
                                artifact.staged_root = str(alt_dest)
                                artifact.source_path = alt_src
                    if artifact.files:
                        artifact.status = ST_FOUND
                        artifact.message = "legacy profile-root Cookies layout"
                elif staged is not None:
                    artifact.files.append(staged)
                    artifact.status = ST_FOUND

                for companion in entry.companions:
                    comp = self.copy_path(
                        volume, f"{profile.source_path}/{companion}", base / Path(companion),
                        artifact=entry.artifact, family=entry.family,
                    )
                    if comp is not None:
                        artifact.files.append(comp)
            else:
                files = self.copy_tree(volume, src, dest, artifact=entry.artifact, family=entry.family)
                artifact.files.extend(files)
                if files:
                    artifact.status = ST_FOUND

            if artifact.status == ST_NOT_FOUND:
                artifact.message = artifact.message or "artifact path not present in image"
            staging.artifacts[entry.artifact] = artifact

        self.copy_path(
            volume, f"{profile.user_data_path}/Local State", base / "Local State", artifact="(support)",
            family="",
        )
        return staging

    def parse_statuses(self, stagings: Iterable[ProfileStaging]) -> list[ParseStatus]:
        out: list[ParseStatus] = []
        for staging in stagings:
            label = f"{staging.profile.windows_user}/{staging.profile.profile_name}"
            for artifact in staging.artifacts.values():
                out.append(
                    ParseStatus(
                        artifact=f"acquire:{artifact.artifact} [{label}]", family=artifact.family,
                        status=artifact.status if artifact.status != ST_FOUND else ST_FOUND,
                        source_path=artifact.source_path, record_count=artifact.file_count,
                        message=artifact.message,
                        impact="" if artifact.status == ST_FOUND else "artifact unavailable for parsing",
                    )
                )
        return out
