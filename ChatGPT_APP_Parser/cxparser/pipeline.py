"""전체 파이프라인: 이미지 입력 -> 아티팩트 탐색 -> 파싱 -> 정규화 -> 타임라인."""

import os
import re
import subprocess
import time

from . import derive, locate, timeline, usn as usn_mod
from .artifacts import auth as auth_art
from .artifacts import global_state as gs_art
from .artifacts import package_install as pkg_art
from .artifacts import prefetch as prefetch_art
from .artifacts import recent_lnk as lnk_art
from .artifacts import rollout as rollout_art
from .artifacts import sentry_scope as sentry_art
from .artifacts import session_index as si_art
from .artifacts import sqlitedb as sqlite_art
from .artifacts import webcache_conv as webcache_art
from .errors import CxError, UnsupportedFormatError
from .model import RecordBuilder
from .vfs import DirectoryVfs, LiveVfs, TskImageVfs

PARSERS = {
    "rollout": rollout_art.parse,
    "rollout_loose": rollout_art.parse,
    "session_index": si_art.parse,
    "global_state": gs_art.parse,
    "auth": auth_art.parse,
    "sqlite": sqlite_art.parse,
    "prefetch": prefetch_art.parse,
    "recent_lnk": lnk_art.parse,
    "webcache": webcache_art.parse,
    "sentry_scope": sentry_art.parse,
}

DEFAULT_KINDS = ("rollout", "rollout_loose", "session_index", "global_state", "auth",
                 "sqlite", "prefetch", "recent_lnk", "webcache", "sentry_scope")


def _pid_of(process_uuid):
    """logs_2.sqlite 의 process_uuid 'pid:6884:8a5…' → 6884. 다른 형식이면 None."""
    m = re.match(r"pid:(\d+):", str(process_uuid or ""))
    return int(m.group(1)) if m else None


def _running_codex_pids():
    """지금 실행 중인 Codex/ChatGPT 프로세스의 pid 집합. Windows 의 tasklist 를 쓴다 — 그 밖의 환경이나 조회 실패는 빈 집합
    (종료 행을 그대로 둔다). pid 재사용에 대비해 실행 파일 이름도 확인한다."""
    if os.name != "nt":
        return set()
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, timeout=30).stdout.decode("ascii", "ignore")
    except (OSError, subprocess.SubprocessError):
        return set()
    pids = set()
    for line in out.splitlines():
        cols = [c.strip('"') for c in line.split('","')]
        if len(cols) > 1 and cols[0].lower().startswith(("codex", "chatgpt")) and cols[1].isdigit():
            pids.add(int(cols[1]))
    return pids


# 파싱 대상 파일 하나의 크기 상한. 파일을 통째로 메모리에 읽으므로 상한은 두되, 오래 쓴 PC 의 대화 DB
# (thread_history_1.sqlite 가 두 달 사용에 94MB)가 걸리지 않게 넉넉히 잡는다. CLI --max-file-mb 로 바꾼다.
DEFAULT_MAX_FILE_BYTES = 1024 * 1024 * 1024


class Result(dict):
    pass


def run(input_path, input_type="auto", kinds=DEFAULT_KINDS, max_excerpt=500,
        max_file_bytes=DEFAULT_MAX_FILE_BYTES, usn=True, usn_max_bytes=None, key_material=None):
    started = time.time()
    warnings = []
    errors = []

    # --- 1. 입력 열기 -------------------------------------------------
    if input_type == "live":
        vfs = LiveVfs(input_path)
        image_desc = vfs.describe_input()
        img = None
        fs_desc = vfs.describe()
    elif input_type == "dir" or (input_type == "auto" and os.path.isdir(input_path)):
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
        try:                                   # 이미지 라이브러리는 이미지 입력일 때만 불러온다 — 폴더 입력은 표준 라이브러리만으로 돈다
            from .image import open_image
        except ImportError as exc:
            raise UnsupportedFormatError("디스크 이미지를 열려면 pytsk3 와 libewf-python 이 필요합니다 (폴더 입력에는 필요 없음)",
                                         path=input_path, missing=str(exc))
        img = open_image(input_path)
        image_desc = img.describe()
        warnings.extend(image_desc.pop("warnings"))
        vfs = TskImageVfs(img, key_material=key_material)
        fs_desc = vfs.describe()
        if vfs.locked:
            warnings.append("BitLocker 볼륨 %d개는 풀지 못해 분석하지 않았습니다 (오프셋 %s)"
                            % (len(vfs.locked), ", ".join(str(v["offset_bytes"]) for v in vfs.locked)))

    # --- 2. 아티팩트 탐색 --------------------------------------------
    targets = []
    inventory = []
    sqlite_siblings = {}     # -wal/-shm 은 본 DB 와 함께 열어야 최신 트랜잭션이 보인다
    cache_parts = {}         # 채팅창 HTTP 캐시: Cache_Data 폴더별 {data_N / f_xxxxxx: vfile} — index 파서가 함께 연다
    scanned = 0
    for vfile in vfs.iter_files():
        scanned += 1
        kind, meta = locate.classify(vfile.path)
        if kind is None:
            continue
        inventory.append({"kind": kind, **vfile.location()})
        if kind == "sqlite" and (vfile.path.endswith("-wal") or vfile.path.endswith("-shm")):
            if vfile.allocated or vfile.path not in sqlite_siblings:   # 같은 경로의 삭제된 옛 WAL 이 현존 WAL 을 덮어쓰지 않게
                sqlite_siblings[vfile.path] = vfile
            continue
        if kind == "webcache_part":
            parts = cache_parts.setdefault(vfile.path.rsplit("/", 1)[0].lower(), {})
            if vfile.allocated or meta["fn"] not in parts:             # 캐시 조각도 같은 이유로 현존 파일 우선
                parts[meta["fn"]] = vfile
            continue
        if kind == "sqlite" and not sqlite_art.is_main_db(vfile.path):
            continue          # 처리 대상 아닌 DB 는 발견 목록에만
        if kind in kinds:
            targets.append((kind, vfile, meta))

    denied = getattr(vfs, "denied", None)
    if denied:
        denied = sorted(denied, key=lambda p: (p.count("/"), p))           # 얕은 경로(영향이 큰 것) 먼저
        warnings.append("권한이 없어 읽지 못한 탐색 폴더 %d곳: %s%s — 관리자 권한으로 실행하면 포함된다 "
                        "(Windows/Prefetch 가 빠지면 Prefetch 기반 실행 기록이 없다)"
                        % (len(denied), ", ".join(denied[:6]), " 외 %d곳" % (len(denied) - 6) if len(denied) > 6 else ""))

    if not inventory:
        # 음성 대조(negative control) 이미지에서는 "없음" 이 정상 결과다 — 오류가 아니라 0건 + 경고로 끝낸다.
        # 진짜 입력 오류(이미지 안 열림, NTFS 없음)는 그 전 단계에서 CxError 로 이미 걸러진다.
        warnings.append("Codex Desktop 아티팩트 경로 0건 (스캔 파일 %d, 탐색 패턴 %d종) — 앱 미설치/미사용 이미지로 판단"
                        % (scanned, len(locate._PATTERNS)))
    elif not targets:
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
                           "size": vfile.size, "limit": max_file_bytes,
                           "message": "파싱 대상 파일이 크기 상한을 넘어 건너뜀 — --max-file-mb 로 상한을 올릴 수 있다"})
            continue
        parser = PARSERS[kind]
        try:
            if kind in ("rollout", "rollout_loose"):
                recs, obs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt)
                schema_observations.append(obs.to_dict())
            elif kind == "sqlite":
                recs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt,
                              siblings=sqlite_siblings)
            elif kind == "webcache":
                recs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt,
                              siblings=cache_parts.get(vfile.path.rsplit("/", 1)[0].lower(), {}))
            else:
                recs = parser(vfile, image_desc, rb, max_excerpt=max_excerpt)
            records.extend(recs)
            parsed_files.append({"kind": kind, "path": vfile.path,
                                 "records": len(recs),
                                 "allocated": vfile.allocated,
                                 "mft_record": vfile.mft_record})
        except CxError as exc:
            errors.append({"path": vfile.path, **exc.to_dict()})
        except OSError as exc:            # 라이브 분석: 실행 중인 앱이 잠근 파일, 권한 없는 파일 — 그 파일만 건너뛴다
            errors.append({"path": vfile.path, "code": "READ_FAILED",
                           "message": "%s: %s" % (type(exc).__name__, exc)})
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
    elif usn and isinstance(vfs, DirectoryVfs) and os.path.isfile(j_path := os.path.join(vfs.root, "$Extend", "$UsnJrnl:$J")):
        # 폴더 입력: 호스트 도구가 원본 $J 를 볼륨 루트 기준 경로(ADS)로 꺼내 준 경우 같은 판정에 쓴다
        loc = {"path": "/$Extend/$UsnJrnl:$J"}
        try:
            info, recs_usn = usn_mod.read_journal_file(j_path, max_bytes=usn_max_bytes)
            records.extend(usn_mod.to_records(info, recs_usn, image_desc, rb, loc, max_excerpt=max_excerpt))
            usn_summary = [{**loc, "status": "ok", **info}]
        except OSError as exc:
            errors.append({"path": loc["path"], "code": "USN_READ_FAILED", "message": "%s: %s" % (type(exc).__name__, exc)})
            usn_summary = [{**loc, "status": "read_failed", "message": str(exc)}]

    # --- 3b'. 패키지 폴더 생성 시각 → 설치 (폴더는 iter_files 에 안 나오므로 발견 목록에서 루트를 찾아 직접 연다) --------
    records.extend(pkg_art.records_from_inventory(vfs, inventory, image_desc, rb))

    # --- 3c. 파생 규칙: 관찰 레코드끼리 대조해 로그인·계정 전환·첨부 업로드를 올린다 --------
    records.extend(derive.derive(records, rb))

    # --- 3d. 라이브 분석: 지금 실행 중인 앱 프로세스는 "로그가 끝났다 = 종료" 가 성립하지 않는다 --------
    if input_type == "live":
        running = _running_codex_pids()
        still = [r for r in records if r["event"]["event_id"] == "E08-02"
                 and _pid_of((r.get("details") or {}).get("process_uuid")) in running]
        if still:
            records = [r for r in records if r not in still]
            warnings.append("수집 시점에 Codex 프로세스가 실행 중(pid %s) — 그 프로세스의 종료 행은 만들지 않았다"
                            % ", ".join(str(_pid_of(r["details"]["process_uuid"])) for r in still))

    tl = timeline.build(records)
    status_counts = {}
    for r in records:
        s = r["parse"]["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    result = Result({
        "tool": {"name": "cxparser", "version": "0.3.31",
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
