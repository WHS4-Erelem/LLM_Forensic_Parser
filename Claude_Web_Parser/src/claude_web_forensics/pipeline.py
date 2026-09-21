"""Analysis orchestration.

Image -> volumes -> discovery -> staging (once) -> parsers -> evidence store ->
correlation -> detectors -> verdicts -> timeline.csv + recovered_conversations.csv.

Error isolation: one failing parser or detector is reported on the console and
the rest of the run continues. Only an unopenable image, or a result CSV that
fails its readback check, is fatal. Nothing but the two result CSVs is written
to the output folder; working copies live in a temporary workspace that is
removed when the run ends.
"""
from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis.accounts import build_account_context
from .analysis.claude_scope import (
    ClaudeScope,
    gate_recycle_by_usn,
    gate_recycle_entries,
    interesting_usn_frns,
    interesting_usn_names,
)
from .analysis.conversations import ConversationBuilder
from .analysis.correlator import Correlator
from .analysis.detectors import DetectorContext, run_all
from .analysis.file_analysis import FileBuilder, collect_upload_metadata
from .analysis.file_analysis import build_lifecycles
from .analysis.file_analysis import plan_usn_path_collection
from .discovery.environment import find_chrome_profiles
from .discovery.environment import find_user_sids, find_windows_installs
from .image.acquire import ProfileStaging, Stager
from .image.adapters import ImageOpenError
from .image.adapters import EwfImage, looks_like_ewf
from .image.adapters import RawImage
from .image.volumes import KeyMaterial, NtfsVolume, discover_volumes, open_ntfs_volumes
from .model.entities import (
    FAMILY_LOCAL_STORAGE,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceStore,
)
from .model.entities import REASON_TEXT, ST_SKIPPED, ParseStatus
from .output.csv_export import (
    ArtifactPathResolver,
    CsvExportError,
    build_conversation_rows,
    build_timeline_rows,
    write_results,
)
from .parsers import (
    browser_storage as indexeddb_parser,
    browser_storage as local_storage_parser,
    browser_storage as sessions_parser,
    cache as cache_parser,
    cookies as cookies_parser,
    extended_fs as recycle_parser,
    extended_fs as usn_parser,
    filesystem as downloads_parser,
    filesystem as mft_parser,
    history as history_parser,
)
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
    timeline_rows: int = 0
    conversation_rows: int = 0
    output_valid: bool = True
    warnings: list[str] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        return [
            f"evidence records : {self.evidence_count}",
            f"timeline.csv     : {self.timeline_rows} rows "
            f"(확정 {self.confirmed} / 의심 {self.suspected})",
            f"recovered_conversations.csv : {self.conversation_rows} rows "
            f"({self.conversation_count} conversations)",
        ]


class RunLog:
    """Console reporting of run state (parse status, coverage, warnings).

    Nothing here is written to a file; the output folder holds the two result
    CSVs only.
    """

    def __init__(self, logger: logging.Logger, result: AnalysisResult) -> None:
        self.logger = logger
        self.result = result

    def info(self, item: str, value: Any = "") -> None:
        self.logger.debug("%s: %s", item, value)

    def warning(self, item: str, message: str) -> None:
        self.logger.warning("%s: %s", item, message)
        self.result.warnings.append(f"{item}: {message}")

    def parse(self, statuses) -> None:
        for status in statuses:
            level = logging.WARNING if status.status == "failed" else logging.INFO
            self.logger.log(
                level, "parse %-28s %-10s records=%s %s",
                status.artifact, status.status, status.record_count,
                status.message[:200] if status.message else "",
            )

    def coverage(self, rows) -> None:
        for row in rows:
            reason = f" ({REASON_TEXT.get(row.reason, row.reason)})" if row.reason else ""
            self.logger.debug(
                "coverage %s %s: %s events=%d%s",
                row.action_code, row.action_label, row.status, row.event_count, reason,
            )


def _open_image(path: Path):
    if looks_like_ewf(path):
        return EwfImage(path)
    return RawImage(path)


def run_analysis(options: AnalysisOptions, logger: logging.Logger) -> AnalysisResult:
    output = Path(options.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    # Working copies (staged artifacts, cached download bodies) never land in
    # the output folder.
    workspace = Path(tempfile.mkdtemp(prefix="cwf_work_", dir=tempfile.gettempdir()))
    result = AnalysisResult(output_dir=output)
    try:
        _run(options, logger, output, workspace, result)
    finally:
        if options.keep_staging:
            logger.info("staging workspace kept at %s", workspace)
        else:
            _remove_tree(workspace)
    return result


def _run(
    options: AnalysisOptions,
    logger: logging.Logger,
    output: Path,
    workspace: Path,
    result: AnalysisResult,
) -> None:
    log = RunLog(logger, result)
    staging_root = workspace / "staging"
    bodies_root = workspace / "bodies"
    if import_error():
        log.warning("ccl_chromium_reader", import_error() or "")

    # ---- image ----------------------------------------------------------
    logger.info("opening image %s", options.image_path)
    image = _open_image(Path(options.image_path))
    info = image.info
    log.info("image", f"{info.image_type} logical={info.logical_size} container={info.container_size}")
    for warning in info.warnings:
        log.warning("image", warning)

    # ---- volumes --------------------------------------------------------
    volumes = discover_volumes(image.stream(), info.logical_size)
    selected = _select_volumes(volumes, options)
    ntfs_volumes = open_ntfs_volumes(image.stream(), selected, options.key_material)
    for volume in volumes:
        log.info(
            f"partition {volume.index}",
            f"{volume.encryption_status or volume.filesystem or 'unknown'} "
            f"offset={volume.offset} {volume.message or volume.unlock_method or volume.name}",
        )
    if not ntfs_volumes:
        raise ImageOpenError(
            "no readable NTFS volume found (check --partition-index / --key-material)"
        )

    # The volume holding the (single) Windows installation is the system drive.
    system_volumes = [v.info.identifier for v in ntfs_volumes if find_windows_installs([v])]
    drive_letters = {system_volumes[0]: SYSTEM_DRIVE} if len(system_volumes) == 1 else {}

    # ---- discovery ------------------------------------------------------
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
                    logger.info(
                        "staging Chrome profile %s / %s", user.username, profile.profile_name
                    )
                    stagings.append((volume, stager.stage_profile(volume, profile)))

    if not stagings:
        log.warning("discovery", "no Chrome profile found on any readable volume")
    for warning in stager.warnings:
        log.warning("acquisition", warning)
    log.parse(stager.parse_statuses(s for _, s in stagings))

    # ---- Chrome parsers -------------------------------------------------
    body_counter = [0]

    def body_writer(data: bytes, suffix: str) -> str:
        """Keep a decoded Claude download body for byte comparison (workspace only)."""
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
            ("History", lambda: history_parser.parse_history(
                base / "History", f"{source}/History", vid)),
            ("Cookies", lambda: cookies_parser.parse_cookies(
                _cookie_path(base), _cookie_source(base, source), vid)),
            ("Cache", lambda: cache_parser.parse_cache(
                base / "Cache" / "Cache_Data", f"{source}/Cache/Cache_Data", vid, body_writer)),
            ("IndexedDB", lambda: indexeddb_parser.parse_indexeddb(
                base / "IndexedDB", f"{source}/IndexedDB", vid)),
            ("Local Storage", lambda: local_storage_parser.parse_local_storage(
                base / "Local Storage" / "leveldb", f"{source}/Local Storage/leveldb", vid)),
            ("Sessions/Tabs", lambda: sessions_parser.parse_sessions(
                base / "Sessions", f"{source}/Sessions", vid)),
        )
        for name, job in jobs:
            logger.info("parsing %s [%s]", name, label)
            try:
                records, status = job()
            except Exception as exc:
                logger.exception("parser %s failed", name)
                log.parse([ParseStatus(artifact=f"{name} [{label}]", family="", status="failed",
                                       error_code=type(exc).__name__, message=str(exc)[:400])])
                continue
            store.extend(records)
            status.artifact = f"{status.artifact} [{label}]"
            log.parse([status])

    # ---- filesystem -----------------------------------------------------
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
    # The Claude-relevance gate for every on-disk file (Downloads, $R, USN
    # destinations). Built once from already-parsed evidence; filename matches
    # never qualify a file on their own.
    scope = ClaudeScope.from_store(store)

    for volume in ntfs_volumes:
        letter = drive_letters.get(volume.info.identifier, SYSTEM_DRIVE)
        for install in find_windows_installs([volume]):
            for user in install.users:
                if options.windows_user and user.username.lower() != options.windows_user.lower():
                    continue
                logger.info("collecting Downloads for %s", user.username)
                try:
                    collected, records, status = downloads_parser.collect_files(
                        volume, f"{user.profile_path}/Downloads",
                        [t for t in download_targets if t], scope, volume_letter=letter,
                    )
                    store.extend(records)
                    collected_all.extend(collected)
                    log.parse([status])
                except Exception as exc:
                    logger.exception("Downloads collection failed")
                    log.parse([ParseStatus(artifact="Downloads", family="filesystem_file",
                                           status="failed", error_code=type(exc).__name__,
                                           message=str(exc)[:400])])

        # $MFT evidence for the profile paths themselves.
        try:
            targets = [s.profile.source_path for v, s in stagings if v is volume]
            records, status = mft_parser.parse_paths(volume, targets, "/$MFT")
            store.extend(records)
            log.parse([status])
        except Exception as exc:
            logger.exception("$MFT parsing failed")
            log.parse([ParseStatus(artifact="$MFT", family="mft", status="failed",
                                   error_code=type(exc).__name__, message=str(exc)[:400])])

        # ---- extended-fs ------------------------------------------------
        if not options.extended_fs:
            log.parse([ParseStatus(artifact=a, family=f, status=ST_SKIPPED,
                                   message="--extended-fs not enabled")
                       for a, f in (("$UsnJrnl:$J", "usn"), ("$Recycle.Bin", "recycle_bin"))])
            continue

        # $Recycle.Bin METADATA only -- no $R content is read.
        logger.info("extended-fs: $Recycle.Bin on %s", volume.info.identifier)
        entries: list[Any] = []
        try:
            entries, status = recycle_parser.discover_recycle_bin(volume)
            log.parse([status])
        except Exception as exc:
            logger.exception("$Recycle.Bin parsing failed")
            log.parse([ParseStatus(artifact="$Recycle.Bin", family="recycle_bin",
                                   status="failed", error_code=type(exc).__name__,
                                   message=str(exc)[:400])])

        # Claude relevance from metadata: exact History target path or a Claude
        # Zone.Identifier on the $R; size-matched candidates are compared byte
        # for byte with a cached Claude download body.
        verified, content_candidates = gate_recycle_entries(volume, entries, scope)

        # $UsnJrnl:$J -- parsed exactly once per volume, seeded only with
        # History targets and files already proven Claude-related.
        logger.info("extended-fs: $UsnJrnl:$J on %s", volume.info.identifier)
        interesting = interesting_usn_names(
            scope, [e.original_name for e in verified] + [c.name for c in collected_all]
        )
        pairs: list[Any] = []
        try:
            records, usn_records, pairs, status = usn_parser.parse_usn(
                volume,
                interesting,
                interesting_frns=interesting_usn_frns(
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
            log.parse([ParseStatus(artifact="$UsnJrnl:$J", family="usn", status="failed",
                                   error_code=type(exc).__name__, message=str(exc)[:400])])

        # Remaining entries: accept only via the SAME FRN's rename chain reaching
        # a Claude History target path (no extra journal pass).
        verified.extend(gate_recycle_by_usn(entries, volume.info.identifier, pairs, scope))
        for entry in verified:
            store.extend(recycle_parser.recycle_evidence(entry))
        recycle_entries_all.extend(verified)
        log.info(
            f"recycle_bin_scope {volume.info.identifier}",
            f"entries={len(entries)} claude_verified={len(verified)} "
            f"content_candidates={content_candidates}",
        )

    # ---- analysis -------------------------------------------------------
    logger.info("building conversations and account context")
    conversations = ConversationBuilder()
    conversations.ingest(store)
    conversations.ingest_local_storage_drafts(store.by_family(FAMILY_LOCAL_STORAGE))
    account_ctx = build_account_context(store)

    file_builder.add_downloaded_files(collected_all, download_records)
    file_builder.add_recycle_entries(recycle_entries_all)
    file_builder.add_uploads(collect_upload_metadata(store))
    file_traces = [t for t in file_builder.deduplicate() if t.claude_verified]

    lifecycles = build_lifecycles(
        rename_pairs_all, usn_records_all, recycle_entries_all, store.by_family("usn")
    )

    ctx = DetectorContext(
        store=store,
        correlator=Correlator(store),
        conversations=conversations,
        account_ctx=account_ctx,
        file_traces=file_traces,
        lifecycles=lifecycles,
        extended_fs=options.extended_fs,
        rename_pairs=rename_pairs_all,
        usn_records=usn_records_all,
        recycle_entries=recycle_entries_all,
        artifact_available={f: True for f in store.families_present()},
    )
    logger.info("running detectors")
    detector_result = run_all(ctx)
    log.coverage(detector_result.coverage)

    # ---- USN-confirmed final paths --------------------------------------
    # Narrow check: confirm exactly the one path a reliable rename chain
    # resolves to is allocated. Never a search, never bytes; the decision is
    # reported on the console. Runs after the detectors so verdicts are unchanged.
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


    # ---- outputs --------------------------------------------------------
    resolver = ArtifactPathResolver(store=store, drive_letters=drive_letters)
    timeline_rows = build_timeline_rows(detector_result.events, resolver)
    conversation_rows = build_conversation_rows(conversations.all_messages(), resolver)
    try:
        write_results(output, timeline_rows, conversation_rows)
    except (CsvExportError, OSError) as exc:
        logger.error("result CSV could not be written or verified: %s", exc)
        result.output_valid = False

    exported = [e for e in detector_result.events if e.verdict != VERDICT_UNDETERMINED]
    result.evidence_count = len(store)
    result.confirmed = sum(1 for e in exported if e.verdict == VERDICT_CONFIRMED)
    result.suspected = sum(1 for e in exported if e.verdict == VERDICT_SUSPECTED)
    result.conversation_count = len(conversations.conversations)
    result.message_count = len(conversations.all_messages())
    result.timeline_rows = len(timeline_rows)
    result.conversation_rows = len(conversation_rows)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _cookie_path(base: Path) -> Path:
    candidate = base / "Network" / "Cookies"
    if candidate.exists():
        return candidate
    return base / "Cookies"


def _cookie_source(base: Path, profile_source: str) -> str:
    """Image path of the Cookies database actually parsed (new or legacy location)."""
    if (base / "Network" / "Cookies").exists():
        return f"{profile_source}/Network/Cookies"
    return f"{profile_source}/Cookies"


def _select_volumes(volumes, options: AnalysisOptions):
    if options.partition_index is not None:
        return [v for v in volumes if v.index == options.partition_index]
    if options.partition_offset is not None:
        return [v for v in volumes if v.offset == options.partition_offset]
    return volumes


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
