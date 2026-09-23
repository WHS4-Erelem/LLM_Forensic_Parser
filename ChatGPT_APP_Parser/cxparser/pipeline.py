"""전체 파이프라인: 이미지 입력 -> 아티팩트 탐색 -> 파싱 -> 정규화 -> 타임라인."""

import os
import time

from . import locate, timeline, usn as usn_mod
from .artifacts import auth as auth_art
from .artifacts import global_state as gs_art
from .artifacts import rollout as rollout_art
from .artifacts import session_index as si_art
from .artifacts import sqlitedb as sqlite_art
from .errors import ArtifactNotFoundError, CxError
from .image import open_image
from .model import RecordBuilder
from .vfs import DirectoryVfs, TskImageVfs

PARSERS = {
    "rollout": rollout_art.parse,
    "rollout_loose": rollout_art.parse,
    "session_index": si_art.parse,
    "global_state": gs_art.parse,
    "auth": auth_art.parse,
    "sqlite": sqlite_art.parse,
}

DEFAULT_KINDS = ("rollout", "rollout_loose", "session_index", "global_state", "auth",
                 "sqlite")


class Result(dict):
    pass


def run(input_path, input_type="auto", kinds=DEFAULT_KINDS, max_excerpt=500,
        max_file_bytes=64 * 1024 * 1024, usn=True, usn_max_bytes=None):
    started = time.time()
    warnings = []
    errors = []

    # --- 1. 입력 열기 -------------------------------------------------
    if input_type == "dir" or (input_type == "auto" and os.path.isdir(input_path)):
        vfs = DirectoryVfs(input_path)
        image_desc = {
            "image_id": os.path.abspath(input_path),
            "image_type": "dir",
            "file_name": os.path.basename(os.path.abspath(input_path)),
            "note": "추출 파일 트리 입력 — 디스크 이미지 근거(MFT/파티션) 없음",
        }
        img = None
        fs_desc = vfs.describe()
    else:
        img = open_image(input_path)
        image_desc = img.describe()
        warnings.extend(image_desc.pop("warnings"))
        vfs = TskImageVfs(img)
        fs_desc = vfs.describe()

    # --- 2. 아티팩트 탐색 --------------------------------------------
    targets = []
    inventory = []
    sqlite_siblings = {}     # -wal/-shm 은 본 DB 와 함께 열어야 최신 트랜잭션이 보인다
    scanned = 0
    for vfile in vfs.iter_files():
        scanned += 1
        kind, meta = locate.classify(vfile.path)
        if kind is None:
            continue
        inventory.append({"kind": kind, **vfile.location()})
        if kind == "sqlite" and (vfile.path.endswith("-wal") or vfile.path.endswith("-shm")):
            sqlite_siblings[vfile.path] = vfile
            continue
        if kind == "sqlite" and not sqlite_art.is_main_db(vfile.path):
            continue          # 처리 대상 아닌 DB 는 발견 목록에만
        if kind in kinds:
            targets.append((kind, vfile, meta))

    if not inventory:
        raise ArtifactNotFoundError(
            "이미지에서 Codex Desktop 아티팩트 경로를 하나도 찾지 못했습니다",
            scanned_files=scanned,
            searched_patterns=[p[0] for p in locate._PATTERNS])

    if not targets:
        warnings.append(
            "Codex 관련 경로는 %d건 발견했으나, 파싱 대상 종류(%s)에 해당하는 "
            "파일은 없습니다" % (len(inventory), ", ".join(kinds)))

    # --- 3. 파싱 -------------------------------------------------------
    rb = RecordBuilder()
    records = []
    schema_observations = []
    parsed_files = []
    for kind, vfile, _meta in sorted(targets, key=lambda t: t[1].path):
        if vfile.size > max_file_bytes:
            errors.append({"code": "FILE_TOO_LARGE", "path": vfile.path,
                           "size": vfile.size, "limit": max_file_bytes})
            continue
        parser = PARSERS[kind]
        try:
            if kind in ("rollout", "rollout_loose"):
                recs, obs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt)
                schema_observations.append(obs.to_dict())
            elif kind == "sqlite":
                recs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt,
                              siblings=sqlite_siblings)
            else:
                recs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt)
            records.extend(recs)
            parsed_files.append({"kind": kind, "path": vfile.path,
                                 "records": len(recs),
                                 "allocated": vfile.allocated,
                                 "mft_record": vfile.mft_record})
        except CxError as exc:
            errors.append({"path": vfile.path, **exc.to_dict()})
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": vfile.path, "code": "UNEXPECTED",
                           "message": "%s: %s" % (type(exc).__name__, exc)})

    # --- 3b. $UsnJrnl:$J (이미지 입력일 때만, 이름 기준 필터) --------------
    usn_summary = None
    if usn and img is not None and getattr(vfs, "volumes", None):
        usn_summary = []
        for vd, fs in vfs.volumes:
            loc = {"path": "/$Extend/$UsnJrnl:$J",
                   "partition_index": vd["index"],
                   "partition_offset_bytes": vd["offset_bytes"]}
            try:
                info, recs_usn = usn_mod.read_journal(fs, max_bytes=usn_max_bytes)
            except Exception as exc:  # noqa: BLE001
                msg = "%s: %s" % (type(exc).__name__, exc)
                if "path not found" in str(exc) or isinstance(exc, FileNotFoundError):
                    # 이 볼륨에 저널이 없음 — 오류가 아니라 상태로 기록
                    usn_summary.append({**loc, "status": "not_found", "message": msg})
                else:
                    errors.append({"path": loc["path"], "code": "USN_READ_FAILED",
                                   "partition_index": vd["index"], "message": msg})
                    usn_summary.append({**loc, "status": "read_failed", "message": msg})
                continue
            records.extend(usn_mod.to_records(info, recs_usn, image_desc, rb, loc,
                                              max_excerpt=max_excerpt))
            usn_summary.append({**loc, "status": "ok", **info})

    tl = timeline.build(records)
    status_counts = {}
    for r in records:
        s = r["parse"]["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    result = Result({
        "tool": {"name": "cxparser", "version": "0.3.4",
                 "target": "MS Store 패키지 OpenAI.Codex_2p2nqsd0c76g0 "
                           "(분석표 기준 26.825.4187.0, ChatGPT 채팅 + Codex 작업 모드)"},
        "input": image_desc,
        "filesystem": fs_desc,
        "scan": {
            "files_scanned": scanned,
            "codex_paths_found": len(inventory),
            "parse_targets": len(targets),
            "parsed_files": parsed_files,
        },
        "records": records,
        "timeline": tl["timeline"],
        "undated_records": tl["undated_records"],
        "summary": {
            "record_counts": tl["counts"],
            "parse_status_counts": status_counts,
            "elapsed_seconds": round(time.time() - started, 3),
        },
        "schema_observations": schema_observations,
        "artifact_inventory": inventory,
        "usn_journal": usn_summary,
        "warnings": warnings,
        "errors": errors,
        "verification_notice": (
            "본 실행은 입력된 소스에 대한 파싱 결과다. 필드 매핑은 실제 Codex "
            "Desktop 표본과 대조하기 전까지 미확정이며, schema_observations 로 "
            "관찰된 구조를 함께 보고한다."),
    })
    if img is not None:
        img.close()
    return result
