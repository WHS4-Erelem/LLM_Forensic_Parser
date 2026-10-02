"""Analysis orchestration."""
from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis.claude_scope import (
    ClaudeScope, gate_recycle_by_usn, gate_recycle_entries, interesting_usn_frns, interesting_usn_names,
)
from .analysis.conversations import ConversationBuilder
from .analysis.detectors import DetectorContext, run_all
from .analysis.file_analysis import FileBuilder, build_lifecycles, plan_usn_path_collection
from .discovery.environment import find_chrome_profiles, find_user_sids, find_windows_installs
from .image.acquire import ProfileStaging, Stager
from .image.adapters import EwfImage, ImageOpenError, RawImage, looks_like_ewf
from .image.volumes import KeyMaterial, NtfsVolume, discover_volumes, open_ntfs_volumes
from .model.entities import (
    REASON_TEXT, ST_SKIPPED, VERDICT_CONFIRMED, VERDICT_SUSPECTED, VERDICT_UNDETERMINED, EvidenceStore,
    ParseStatus,
)
from .output.csv_export import (
    ArtifactPathResolver, CsvExportError, build_conversation_rows, build_timeline_rows, write_results,
)
from .parsers import browser_storage, cache as cache_parser, cookies as cookies_parser
from .parsers import extended_fs, filesystem, history as history_parser
from .parsers.ccl_adapter import import_error

SYSTEM_DRIVE = "C"

@dataclass
class AnalysisOptions:
    image_path: Path
    output_dir: Path
    partition_offset: int | None = None
    partition_index: int | None = None
    windows_user: str = ""
    chrome_profile: str = ""
    key_material: KeyMaterial = field(default_factory=KeyMaterial)
    extended_fs: bool = False
    keep_staging: bool = False

@dataclass
class AnalysisResult:
    output_dir: Path
    evidence_count: int = 0
    confirmed: int = 0
    suspected: int = 0
    conversation_count: int = 0
    message_count: int = 0
    undated_rows: int = 0
    timeline_rows: int = 0
    conversation_rows: int = 0
    output_valid: bool = True
    warnings: list[str] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        return [
            f"evidence records : {self.evidence_count}", f"timeline.csv     : {self.timeline_rows} rows "
            f"(확정 {self.confirmed} / 의심 {self.suspected}, 시각 없음 {self.undated_rows})",
            f"recovered_conversations.csv : {self.conversation_rows} rows "
            f"({self.message_count} messages in {self.conversation_count} conversations)",
        ]

class RunLog:
    def __init__(self, logger: logging.Logger, result: AnalysisResult) -> None:
        self.logger = logger
        self.result = result

    def info(self, item: str, value: Any = "") -> None:
        self.logger.debug("%s: %s", item, value)

    def warning(self, item: str, message: str) -> None:
        self.logger.warning("%s: %s", item, message)
        self.result.warnings.append(f"{item}: {message}")

    def failed(self, artifact: str, family: str, exc: Exception) -> None:
        self.parse([ParseStatus(artifact=artifact, family=family, status="failed",
                               error_code=type(exc).__name__, message=str(exc)[:400])])

    def parse(self, statuses) -> None:
        for status in statuses:
            level = logging.WARNING if status.status == "failed" else logging.INFO
            self.logger.log(
                level, "parse %-28s %-10s records=%s %s", status.artifact, status.status, status.record_count,
                status.message[:200] if status.message else "",
            )
            for line in status.details:
                self.logger.info("  diag %s", line[:400])

    def coverage(self, rows) -> None:
        for row in rows:
            reason = f" ({REASON_TEXT.get(row.reason, row.reason)})" if row.reason else ""
            self.logger.info(
                "coverage %s %s: %s events=%d%s%s",
                row.action_code, row.action_label, row.status, row.event_count, reason,
                f" -- {row.message}" if row.message else "",
            )

def run_analysis(options: AnalysisOptions, logger: logging.Logger) -> AnalysisResult:
    output = Path(options.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    workspace = Path(tempfile.mkdtemp(prefix="cwf_work_", dir=tempfile.gettempdir()))
    result = AnalysisResult(output_dir=output)
    try:
        _run(options, logger, output, workspace, result)
    finally:
        if options.keep_staging:
            logger.info("staging workspace kept at %s", workspace)
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    return result

def _run(
    options: AnalysisOptions, logger: logging.Logger, output: Path, workspace: Path, result: AnalysisResult,
) -> None:
    log = RunLog(logger, result)
    staging_root = workspace / "staging"
    bodies_root = workspace / "bodies"
    if import_error():
        log.warning("ccl_chromium_reader", import_error() or "")

    logger.info("opening image %s", options.image_path)
    image_type = EwfImage if looks_like_ewf(Path(options.image_path)) else RawImage
    image = image_type(Path(options.image_path))
    info = image.info
    log.info("image", f"{info.image_type} logical={info.logical_size} container={info.container_size}")
    for warning in info.warnings:
        log.warning("image", warning)

    volumes = discover_volumes(image.stream(), info.logical_size)
    selected = _select_volumes(volumes, options)
    ntfs_volumes = open_ntfs_volumes(image.stream(), selected, options.key_material)
    for volume in volumes:
        log.info(
            f"partition {volume.index}", f"{volume.encryption_status or volume.filesystem or 'unknown'} "
            f"offset={volume.offset} {volume.message or volume.unlock_method or volume.name}",
        )
    if not ntfs_volumes:
        raise ImageOpenError("no readable NTFS volume found (check --partition-index / --key-material)")

    system_volumes = [v.info.identifier for v in ntfs_volumes if find_windows_installs([v])]
    drive_letters = {system_volumes[0]: SYSTEM_DRIVE} if len(system_volumes) == 1 else {}

    stager = Stager(staging_root)
    store = EvidenceStore()
    stagings: list[tuple[NtfsVolume, ProfileStaging]] = []

    for volume in ntfs_volumes:
        for install in find_windows_installs([volume]):
            for sid in find_user_sids(volume):
                log.info(f"user_sid {volume.info.identifier}", sid)
            for user in install.users:
                if options.windows_user and user.username.lower() != options.windows_user.lower():
                    continue
                for profile in find_chrome_profiles(volume, user):
                    if (
                        options.chrome_profile
                        and profile.profile_name.lower() != options.chrome_profile.lower()
                    ):
                        continue
                    logger.info("staging Chrome profile %s / %s", user.username, profile.profile_name)
                    stagings.append((volume, stager.stage_profile(volume, profile)))

    if not stagings:
        log.warning("discovery", "no Chrome profile found on any readable volume")
    for warning in stager.warnings:
        log.warning("acquisition", warning)
    log.parse(stager.parse_statuses(s for _, s in stagings))

    body_counter = [0]

    def body_writer(data: bytes, suffix: str) -> str:
        bodies_root.mkdir(parents=True, exist_ok=True)
        body_counter[0] += 1
        path = bodies_root / f"{body_counter[0]:06d}.{suffix}"
        path.write_bytes(data)
        return str(path)

    for volume, staging in stagings:
        label = f"{staging.profile.windows_user}/{staging.profile.profile_name}"
        base = Path(staging.root)
        source = staging.profile.source_path
        vid = volume.info.identifier
        jobs = (
            ("History", history_parser.parse_history, "History", ()),
            ("Cookies", cookies_parser.parse_cookies, "", ()),
            ("Cache", cache_parser.parse_cache, "Cache/Cache_Data", (body_writer,)),
            ("IndexedDB", browser_storage.parse_indexeddb, "IndexedDB", ()),
            ("Local Storage", browser_storage.parse_local_storage, "Local Storage/leveldb", ()),
            ("Sessions/Tabs", browser_storage.parse_sessions, "Sessions", ()),
        )
        for name, parser, relative, args in jobs:
            logger.info("parsing %s [%s]", name, label)
            try:
                path = base / relative if relative else _cookie_path(base)
                records, status = parser(path, f"{source}/{path.relative_to(base).as_posix()}", vid, *args)
            except Exception as exc:
                logger.exception("parser %s failed", name)
                log.failed(f"{name} [{label}]", "", exc)
                continue
            store.extend(records)
            status.artifact = f"{status.artifact} [{label}]"
            log.parse([status])

    file_builder = FileBuilder()
    collected_all: list[Any] = []
    recycle_entries_all: list[Any] = []
    rename_pairs_all: list[Any] = []
    usn_records_all: list[Any] = []

    download_records = [
        r for r in store.by_family("history") if r.attributes.get("subtype") == "download"
    ]
    download_targets = [
        str(r.attributes.get("target_path") or r.attributes.get("current_path") or "")
        for r in download_records
    ]

    scope = ClaudeScope.from_store(store)

    for volume in ntfs_volumes:
        letter = drive_letters.get(volume.info.identifier, SYSTEM_DRIVE)
        for install in find_windows_installs([volume]):
            for user in install.users:
                if options.windows_user and user.username.lower() != options.windows_user.lower():
                    continue
                logger.info("collecting Downloads for %s", user.username)
                try:
                    collected, records, status = filesystem.collect_files(
                        volume, f"{user.profile_path}/Downloads",
                        [t for t in download_targets if t], scope, volume_letter=letter,
                    )
                    store.extend(records)
                    collected_all.extend(collected)
                    log.parse([status])
                except Exception as exc:
                    logger.exception("Downloads collection failed")
                    log.failed("Downloads", "filesystem_file", exc)

        try:
            targets = [s.profile.source_path for v, s in stagings if v is volume]
            records, status = filesystem.parse_paths(volume, targets, "/$MFT")
            store.extend(records)
            log.parse([status])
        except Exception as exc:
            logger.exception("$MFT parsing failed")
            log.failed("$MFT", "mft", exc)

        if not options.extended_fs:
            log.parse([ParseStatus(artifact=a, family=f, status=ST_SKIPPED, message="--extended-fs not enabled")
                       for a, f in (("$UsnJrnl:$J", "usn"), ("$Recycle.Bin", "recycle_bin"))])
            continue

        logger.info("extended-fs: $Recycle.Bin on %s", volume.info.identifier)
        entries: list[Any] = []
        try:
            entries, status = extended_fs.discover_recycle_bin(volume)
            log.parse([status])
        except Exception as exc:
            logger.exception("$Recycle.Bin parsing failed")
            log.failed("$Recycle.Bin", "recycle_bin", exc)

        verified, content_candidates = gate_recycle_entries(volume, entries, scope)

        logger.info("extended-fs: $UsnJrnl:$J on %s", volume.info.identifier)
        interesting = interesting_usn_names(scope, [e.original_name for e in verified] + [c.name for c in
            collected_all])
        pairs: list[Any] = []
        try:
            records, usn_records, pairs, status = extended_fs.parse_usn(
                volume, interesting, interesting_frns=interesting_usn_frns(
                    [e.r_frn for e in verified]
                    + [
                        f"{c.mft_segment}-{c.mft_sequence}"
                        for c in collected_all
                        if c.mft_segment is not None and c.volume_id == volume.info.identifier
                    ]
                ),
            )
            store.extend(records)
            usn_records_all.extend(usn_records)
            rename_pairs_all.extend(pairs)
            log.parse([status])
        except Exception as exc:
            logger.exception("$UsnJrnl parsing failed")
            log.failed("$UsnJrnl:$J", "usn", exc)

        verified.extend(gate_recycle_by_usn(entries, volume.info.identifier, pairs, scope))
        for entry in verified:
            store.extend(extended_fs.recycle_evidence(entry))
        recycle_entries_all.extend(verified)
        log.info(
            f"recycle_bin_scope {volume.info.identifier}",
            f"entries={len(entries)} claude_verified={len(verified)} "
            f"content_candidates={content_candidates}",
        )

    logger.info("building conversations")
    conversations = ConversationBuilder()
    conversations.ingest(store)
    for line in conversations.summary_lines():
        logger.info("  diag %s", line)

    file_builder.add_downloaded_files(collected_all, download_records)
    file_builder.add_recycle_entries(recycle_entries_all)
    file_traces = [t for t in file_builder.deduplicate() if t.claude_verified]

    lifecycles = build_lifecycles(rename_pairs_all, usn_records_all, recycle_entries_all, store.by_family("usn"))

    ctx = DetectorContext(
        store=store, conversations=conversations, file_traces=file_traces, lifecycles=lifecycles,
        extended_fs=options.extended_fs,
    )
    logger.info("running detectors")
    detector_result = run_all(ctx)
    for note in dict.fromkeys(ctx.notes):
        logger.info("  diag %s", note)
    log.coverage(detector_result.coverage)

    if options.extended_fs and ntfs_volumes:
        volumes_by_id = {v.info.identifier: v for v in ntfs_volumes}

        def _exists_on(volume_id: str, path: str) -> bool:
            target = volumes_by_id.get(volume_id)
            return target is not None and target.exists(path)

        plan = plan_usn_path_collection(lifecycles, file_traces, _exists_on)
        for candidate in plan.accepted:
            if candidate.trace is not None:
                candidate.trace.attributes["usn_final_path"] = candidate.final_path
            logger.info(
                "usn final path %s:%s confirmed %s (link=%s)", candidate.volume_id,
                candidate.file_reference, candidate.final_path, candidate.link_basis,
            )
        for candidate in plan.rejected:
            logger.info(
                "usn final path %s:%s skipped: %s %s", candidate.volume_id,
                candidate.file_reference, candidate.skip_reason, candidate.note,
            )

    resolver = ArtifactPathResolver(store=store, drive_letters=drive_letters)
    timeline_rows = build_timeline_rows(detector_result.events, resolver)
    messages = conversations.all_messages()
    conversation_rows = build_conversation_rows(messages, resolver)
    try:
        write_results(output, timeline_rows, conversation_rows)
    except (CsvExportError, OSError) as exc:
        logger.error("result CSV could not be written or verified: %s", exc)
        result.output_valid = False

    exported = [e for e in detector_result.events if e.verdict != VERDICT_UNDETERMINED]
    result.evidence_count = len(store)
    result.confirmed = sum(1 for e in exported if e.verdict == VERDICT_CONFIRMED)
    result.suspected = sum(1 for e in exported if e.verdict == VERDICT_SUSPECTED)
    result.conversation_count = len({m.conversation_uuid for m in messages})
    result.message_count = len(messages)
    result.undated_rows = sum(1 for row in timeline_rows if not row[1])
    result.timeline_rows = len(timeline_rows)
    result.conversation_rows = len(conversation_rows)

def _cookie_path(base: Path) -> Path:
    candidate = base / "Network" / "Cookies"
    return candidate if candidate.exists() else base / "Cookies"

def _select_volumes(volumes, options: AnalysisOptions):
    if options.partition_index is not None:
        return [v for v in volumes if v.index == options.partition_index]
    if options.partition_offset is not None:
        return [v for v in volumes if v.offset == options.partition_offset]
    return volumes
