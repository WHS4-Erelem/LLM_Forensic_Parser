"""전체 파이프라인: 이미지 입력 -> 아티팩트 탐색 -> 파싱 -> 정규화 -> 타임라인."""

import os
import time

from . import __version__, events, locate, timeline, usn as usn_mod
from .artifacts import idb as idb_art
from .artifacts import idbstore as idb_struct
from .artifacts import applog as applog_art
from .artifacts import misc as misc_art
from .errors import ArtifactNotFoundError, ClError
from .image import open_image
from . import model
from .model import RecordBuilder
from .vfs import DirectoryVfs, LiveVfs, TskImageVfs

PARSERS = {
    "idb_leveldb": idb_art.parse,
    "idb_blob": idb_art.parse,
    "local_storage": idb_art.parse,
    "session_storage": idb_art.parse,
    "cache_block": misc_art.parse_cache,
    "config": misc_art.parse_config,
    "prefetch": misc_art.parse_prefetch,
    "applog": applog_art.parse,
    "applog_pkg": applog_art.parse,
    "applog_shared": applog_art.parse,
    "setuplog": applog_art.parse,
}

DEFAULT_KINDS = tuple(PARSERS)


class Result(dict):
    pass


# 서로 다른 저장소가 같은 행위를 같은 시각에 가리키면 교차검증으로 본다.
CORROBORATE_WINDOW = 120        # 초


PREFETCH_RUN_WINDOW = 60.0      # 이 안에 연달아 찍힌 같은 실행파일 프리패치는 한 실행으로 본다


def _merge_prefetch_runs(records):
    """한 번의 앱 실행이 하위 프로세스마다 Prefetch 를 남겨 timeline 이 여러 행으로 불어나는 것을
    한 행으로 합친다(팀 양식). 가장 이른 것을 대표로 남기고, 나머지는 superseded_by 로 가린다.

    서로 떨어진(>PREFETCH_RUN_WINDOW) 실행은 각각 별개의 실행이므로 합치지 않는다.
    """
    from datetime import datetime

    def secs(r):
        u = r["timestamp"].get("utc")
        return datetime.fromisoformat(u.replace("Z", "+00:00")).timestamp() if u else None

    groups = {}
    for r in records:
        det = r.get("details") or {}
        t = secs(r)
        if det.get("artifact") != "prefetch" or t is None or det.get("superseded_by"):
            continue
        # 같은 실행파일(item_type=EXE)·같은 행위끼리만 묶는다
        groups.setdefault((r["event"]["event_id"], det.get("item_type")), []).append((t, r))

    merged = 0
    for items in groups.values():
        items.sort(key=lambda x: x[0])
        cluster = []
        for pair in items + [(None, None)]:
            if cluster and (pair[0] is None or pair[0] - cluster[-1][0] > PREFETCH_RUN_WINDOW):
                if len(cluster) >= 2:
                    merged += _fold_prefetch_cluster(cluster)
                cluster = []
            if pair[1] is not None:
                cluster.append(pair)
    return merged


def _fold_prefetch_cluster(cluster):
    rep = cluster[0][1]
    others = [r for _, r in cluster[1:]]
    n = len(cluster)
    rep_det = rep["details"]
    rep_det["summary"] = "prefetch_run=1/%d" % n
    rep_det["run_label"] = "prefetch_run=1/%d" % n
    from .output import to_kst
    times = "; ".join("같은 실행의 다른 프로세스 Prefetch %s"
                      % (to_kst(r["timestamp"].get("utc"))[11:19]) for r in others)
    rep_det["merge_note"] = times
    rep_det["merged_prefetch"] = [r["details"].get("file_name") for r in others]
    rep["parse"]["notes"].append("prefetch_run_merged=%d" % n)
    for r in others:
        r["details"]["superseded_by"] = rep["record_id"]
        r["parse"]["notes"].append("merged_into_prefetch_run=%s" % rep["record_id"])
    return len(others)


def _usn_secs(r):
    from datetime import datetime
    u = r["timestamp"].get("utc")
    return datetime.fromisoformat(u.replace("Z", "+00:00")).timestamp() if u else None


def _fold_usn_prefetch(records):
    """같은 앱 실행에 속한 USN 의 프리패치 FILE_CREATE 행을 없애고, 그 시각을 프리패치 실행 행의
    근거로 붙인다. 같은 기동이 '실행(Prefetch)' + '실행(USN)' 두 행으로 나오던 것을 막는다.

    프리패치 파일 행이 전혀 없거나(그 .pf 가 한참 전에 생성된 '첫 실행') 실행 구간 밖이면
    USN 행을 그대로 둔다 — 그때는 USN 이 유일한 첫 실행 근거다.
    """
    by_id = {r["record_id"]: r for r in records}

    def visible(r):                 # superseded 를 따라가 화면에 남는 대표 행을 찾는다
        seen = set()
        while (r.get("details") or {}).get("superseded_by") and r["record_id"] not in seen:
            seen.add(r["record_id"])
            nxt = by_id.get(r["details"]["superseded_by"])
            if nxt is None:
                break
            r = nxt
        return r

    pf_by_lineage, reps = {}, []
    for r in records:
        det = r.get("details") or {}
        if det.get("artifact") != "prefetch":
            continue
        if det.get("lineage"):
            pf_by_lineage.setdefault(det["lineage"], r)
        if not det.get("superseded_by"):
            t = _usn_secs(r)
            if t is not None:
                reps.append((t, r["event"]["event_id"], r))

    from .output import to_kst
    folded = 0
    for r in records:
        det = r.get("details") or {}
        if (det.get("artifact") != "usn_journal" or det.get("match") != "prefetch"
                or det.get("key_reason") != "FILE_CREATE" or det.get("superseded_by")):
            continue
        t = _usn_secs(r)
        target = None
        lin = det.get("lineage")
        if lin and lin in pf_by_lineage:          # 같은 .pf 의 프리패치 파일 행 = 같은 근거
            target = visible(pf_by_lineage[lin])
        elif t is not None:                        # 같은 기동 구간 안의 다른 하위 프로세스 pf
            for tt, eid, rep in reps:
                if eid == r["event"]["event_id"] and abs(tt - t) <= PREFETCH_RUN_WINDOW:
                    target = rep
                    break
        if target is None or target["record_id"] == r["record_id"]:
            continue
        det["superseded_by"] = target["record_id"]
        r["parse"]["notes"].append("usn_prefetch_folded_into=%s" % target["record_id"])
        tdet = target["details"]
        add = "USN 생성 기록 %s" % (to_kst(r["timestamp"].get("utc"))[11:19])
        tdet["merge_note"] = (tdet["merge_note"] + "; " + add) if tdet.get("merge_note") else add
        target["parse"]["notes"].append("usn_prefetch_evidence=%s" % det.get("file_name"))
        folded += 1
    return folded


def _fold_package_installs(records):
    """WindowsApps 의 같은 패키지 폴더 생성이 반복되면(자동 업데이트·MSIX 스테이징) 앱 설치로
    여러 번 세지 않는다. 앞선 설치 신호(SETUP 프리패치 또는 더 이른 패키지 폴더 생성)가 있으면
    뒤의 패키지 폴더 생성은 '업데이트/스테이징 후보(NA-00)'로 내린다 — 설치 행은 가장 이른 1건만.
    """
    installs = []
    for r in records:
        det = r.get("details") or {}
        if r["event"]["event_id"] != "E02-01":
            continue
        t = _usn_secs(r)
        if t is None:
            continue
        if det.get("artifact") == "prefetch":
            installs.append((t, "setup_pf", r))
        elif det.get("artifact") == "usn_journal" and det.get("match") == "package":
            installs.append((t, "pkg", r))
    installs.sort(key=lambda x: x[0])
    downgraded, seen_install = 0, False
    for _t, kind, r in installs:
        if kind == "pkg" and seen_install:
            r["event"]["event_id"] = "NA-00"
            r["event"]["event_name"] = events.name("NA-00")
            r["details"]["candidate_event"] = "E02-01"
            r["user_action"] = model.user_action(
                observed=r["user_action"].get("observed_artifact") or r["details"].get("file_name"),
                rationale="WindowsApps 에 같은 패키지 폴더가 앞선 설치 신호 뒤 다시 생성됨 — "
                          "자동 업데이트·MSIX 스테이징으로 보여 설치로 세지 않는다")
            r["parse"]["notes"].append("package_create_update_candidate")
            downgraded += 1
        else:
            seen_install = True
    return downgraded


def _corroborate(records):
    """
    독립된 저장소 2곳 이상이 같은 행위를 뒷받침하면 확신도를 '확인' 으로 올린다.

    예: 프리패치(파일시스템)와 앱 로그가 같은 시각의 실행을 가리키는 경우.
    같은 저장소에서 여러 건 나온 것은 근거가 늘어난 것이 아니므로 세지 않는다.
    """
    from datetime import datetime

    def secs(r):
        u = r["timestamp"].get("utc")
        if not u:
            return None
        return datetime.fromisoformat(u.replace("Z", "+00:00")).timestamp()

    buckets = {}
    for r in records:
        t = secs(r)
        if t is None or r["event"]["event_id"] == "NA-00":
            continue
        if (r.get("details") or {}).get("superseded_by"):   # 병합·접힌 행은 교차검증에 넣지 않는다
            continue
        buckets.setdefault(r["event"]["event_id"], []).append((t, r))

    upgraded = 0
    for eid, items in buckets.items():
        items.sort(key=lambda x: x[0])
        for i, (t, r) in enumerate(items):
            if r["user_action"]["confidence"] == model.CONF_CONFIRMED:
                continue
            mine = (r.get("details") or {}).get("artifact")
            lineage = (r.get("details") or {}).get("lineage")
            for t2, r2 in items:
                if abs(t2 - t) > CORROBORATE_WINDOW:
                    continue
                if (r2.get("details") or {}).get("artifact") in (None, mine):
                    continue
                # 같은 파일에서 나온 흔적(예: 프리패치 파일 시각과 그 파일의 USN 생성 기록)은
                # 저장소가 달라 보여도 독립 근거가 아니다
                if lineage and (r2.get("details") or {}).get("lineage") == lineage:
                    continue
                r2_art = (r2.get("details") or {}).get("artifact")
                # USN 시각은 저널 기록 시각이라 행위 시각과 같다고 단정하지 않는다 — USN 은 다른 행을
                # 확인으로 올리는 근거가 되지 않는다
                if r2_art == "usn_journal":
                    continue
                # 프리패치 ↔ USN 은 같은 앱 기동이 Prefetch 한 저장소에 남긴 것이라 서로 독립 근거가
                # 아니다 (다른 .pf 라도). 양방향 모두 서로를 확정으로 올리지 않는다
                if {mine, r2_art} == {"prefetch", "usn_journal"}:
                    continue
                r["user_action"]["confidence"] = model.CONF_CONFIRMED
                r["user_action"]["rationale"] = (
                    (r["user_action"].get("rationale") or "")
                    + " · 교차검증: %s 와 %s 가 같은 시각의 같은 행위를 가리킴"
                      % (mine, (r2.get("details") or {}).get("artifact")))
                r["parse"]["notes"].append("cross_channel_corroborated")
                upgraded += 1
                break
    return upgraded


# 바이트 스캔이 같은 문장을 조금 다르게 뽑았을 때 같은 것으로 볼 유사도.
# V8 문자열이 한 바이트 밀려 읽히면 한두 글자만 어긋난다 ('클로드'->'킰로드').
NEAR_DUP_RATIO = 0.80


def _drop_duplicates(records, already, corpus):
    """정식 파싱이 이미 복원한 본문은 바이트 스캔 결과에서 뺀다.

    바이트 스캔은 같은 대화를 조각내서, 때로는 한 바이트 밀린 채로 다시 뽑는다.
    그대로 두면 한 번 한 말이 보고서에 여러 줄로 앉고, 그중 일부는 글자가
    깨져 있다. 정식 파싱 쪽이 발화자·시각·대화 UUID 를 모두 갖고 있으므로
    그쪽을 남기고, 아래 셋 중 하나에 걸리면 바이트 스캔분을 뺀다.

        1) 같은 문장이거나 그 앞부분    2) 복원된 본문 안에 그대로 들어있는 조각
        3) 복원된 본문과 거의 같은 문장 (오정렬로 글자가 몇 개 어긋난 것)

    어디에도 걸리지 않는 본문은 정식 파싱이 닿지 못한 곳(압축 전 로그·삭제
    잔존분)에서 나온 것이므로 그대로 싣는다.
    """
    if not already:
        return records
    from difflib import SequenceMatcher

    out = []
    for r in records:
        t = (r.get("details") or {}).get("text")
        if t:
            flat = " ".join(t.split())
            if flat in already or any(a.startswith(flat) for a in already):
                continue
            if len(flat) >= 10 and flat in corpus:
                continue
            if _near_dup(flat, already, SequenceMatcher):
                continue
        out.append(r)
    return out


def _typing_prefix(shorter, longer):
    """shorter 가 longer 를 치던 중간 상태인가.

    마지막 글자는 조합 중일 수 있으므로 떼고 본다. 두 글자보다 짧으면
    판단 근거가 없어 접지 않는다.
    """
    if len(shorter) < 2:
        return False
    return longer.startswith(shorter) or longer.startswith(shorter[:-1])


def _merge_snapshots(records):
    """같은 공유 스냅샷이 여러 캐시 응답에 실린 것을 하나로 합친다. -> 합친 건수

    스냅샷 목록 응답과 스냅샷 상세 응답이 따로 캐시된다. 둘 다 같은 공유
    사건인데 그대로 두면 공유를 두 번 한 것처럼 보인다. 스냅샷 UUID 로 묶고
    대화 UUID 가 채워진 쪽을 남긴다.
    """
    best, drop = {}, []
    for r in records:
        det = r.get("details") or {}
        if det.get("item_type") != "share_snapshot":
            continue
        key = det.get("snapshot_uuid") or det.get("title")
        prev = best.get(key)
        if prev is None:
            best[key] = r
            continue
        # 대화 UUID 가 있는 쪽이 더 쓸모 있다
        keep, lose = ((prev, r) if (prev["details"].get("conversation_uuid")
                                    or not r["details"].get("conversation_uuid"))
                      else (r, prev))
        best[key] = keep
        drop.append(lose)
    if drop:
        ids = {id(r) for r in drop}
        records[:] = [r for r in records if id(r) not in ids]
    return len(drop)


def _drop_undefined(records):
    """팀 공통 정의에 없는 관찰을 결과에서 뺀다. -> 뺀 건수

    서비스마다 제각각 만들어 낸 관찰은 파서끼리 결과를 합칠 때 비교가 되지
    않는다. 그래서 공통 행위 분류표에 있는 것만 낸다.
    어떤 종류를 왜 빼는지는 events.DROPPED_OBSERVATIONS 에 적어 두었다.
    """
    keep, n = [], 0
    for r in records:
        if (r.get("details") or {}).get("item_type") in events.DROPPED_OBSERVATIONS:
            n += 1
            continue
        keep.append(r)
    records[:] = keep
    return n


def _collapse_drafts(records):
    """입력창 초안의 타이핑 스냅샷을 완성 문장 한 줄로 접는다.

    초안은 2초 간격으로 저장돼, 같은 문장이 한 글자씩 자라는 형태로 여러 파일에
    흩어진다. 파일 단위로 접으면 파일 수만큼 남는다. 전체를 놓고 다시 접어서
    가장 완성된 문장만 보고서에 싣고, 접힌 개수는 근거에 적는다.

    한글은 글자 단위로 자라지 않는다. 마지막 글자가 조합 중이라 'ㅋ+ㅡ'가 '크'로
    보이다가 'ㄹ'이 붙으면 '클'로 바뀐다. 그래서 앞부분만 비교하면 접히지 않고
    한 문장이 여러 줄로 남는다. 마지막 글자를 떼고 비교해 조합 중인 한 글자를
    무시한다. 그러면 같은 문장의 성장 단계는 접히고, 지웠다가 다시 친 다른
    문장은 따로 남는다.
    """
    drafts = [r for r in records
              if (r.get("details") or {}).get("item_type") == "draft"
              and not (r.get("details") or {}).get("superseded_by")]
    drafts.sort(key=lambda r: -len(r["details"]["text"]))
    kept, folded = [], 0
    for r in drafts:
        text = " ".join(r["details"]["text"].split())
        for k in kept:
            if _typing_prefix(text, " ".join(k["details"]["text"].split())):
                k["details"]["snapshots"] = (k["details"].get("snapshots", 1)
                                             + r["details"].get("snapshots", 1))
                r["details"]["superseded_by"] = "draft_snapshot_folded"
                r["parse"]["notes"].append("draft_snapshot_folded")
                folded += 1
                break
        else:
            kept.append(r)
    for k in kept:
        n = k["details"].get("snapshots", 1)
        if n > 1:
            k["user_action"]["rationale"] = (
                "입력 초안 — 사용자가 입력창에 친 문장이다. 전송 여부는 "
                "확인되지 않았다 (타이핑 스냅샷 %d건을 완성 문장으로 접음)" % n)
    return folded


def _mark_superseded(records):
    """정식 파싱이 읽어낸 저장소의 바이트 스캔 본문에 표시를 남긴다.

    같은 저장소를 객체 단위로 이미 복원했으므로, 거기서 바이트로 더 긁힌
    본문은 그 대화의 잘린 조각이거나 앱이 모델에 주는 지시문이다. 사용자가
    남긴 말이 아니다. 지우지는 않는다 — result.json 에 근거로 남겨 두고
    보고서(CSV)에만 싣지 않는다. 입력창 초안은 정식 파싱이 닿지 않는
    곳이라 그대로 둔다.
    """
    n = 0
    for r in records:
        det = r.get("details") or {}
        if det.get("item_type") != "message":
            continue
        det["superseded_by"] = "structured_indexeddb"
        r["parse"]["notes"].append("superseded_by_structured_indexeddb")
        n += 1
    return n


def _near_dup(flat, already, matcher):
    """길이가 비슷한 복원 본문과 대부분의 글자가 같으면 같은 문장으로 본다."""
    if len(flat) < 10:
        return False
    for a in already:
        if abs(len(a) - len(flat)) > max(4, len(flat) * 0.2):
            continue
        if matcher(None, a, flat).quick_ratio() < NEAR_DUP_RATIO:
            continue
        if matcher(None, a, flat).ratio() >= NEAR_DUP_RATIO:
            return True
    return False


def run(input_path, input_type="auto", kinds=DEFAULT_KINDS, max_excerpt=500,
        max_file_bytes=64 * 1024 * 1024, usn=True, usn_max_bytes=None,
        verbose=False, key_material=None):
    started = time.time()
    warnings, errors = [], []

    def say(msg):
        """진행 상황. 오래 걸리는 단계에서 멈춘 것처럼 보이지 않게 한다."""
        if verbose:
            print("  %s" % msg, flush=True)

    # --- 1. 입력 열기 -------------------------------------------------
    if input_type == "live":
        # 자동 선택되지 않는다. 폴더를 주면 추출 트리(dir)로 보고, live 는 명시해야 한다.
        vfs = LiveVfs(input_path)
        image_desc = vfs.describe_input()
        say("라이브 분석 — %s (관리자 권한 %s)" % (vfs.root, image_desc["elevated"]))
        img = None
    elif input_type == "dir" or (input_type == "auto" and os.path.isdir(input_path)):
        vfs = DirectoryVfs(input_path)
        image_desc = {"image_id": os.path.abspath(input_path), "image_type": "dir",
                      "file_name": os.path.basename(os.path.abspath(input_path)),
                      "note": "추출 파일 트리 입력 — 디스크 이미지 근거 없음"}
        img = None
    else:
        say("증거 여는 중 — 분할 세그먼트 검증 포함…")
        img = open_image(input_path)
        image_desc = img.describe()
        say("이미지 %s · 세그먼트 %d개 · %s"
            % (image_desc["image_type"], len(image_desc["segments"]),
               image_desc["file_name"]))
        warnings.extend(image_desc.pop("warnings"))
        try:
            vfs = TskImageVfs(img, key_material=key_material)
        except ClError:
            img.close()
            raise
        for vd, _fs in vfs.volumes:
            if vd.get("encryption"):
                say("BitLocker 볼륨 해제 — 파티션 %d (%s)" % (vd["index"], vd["unlock_method"]))
        for lk in vfs.locked:
            warnings.append("BitLocker 볼륨을 풀지 못해 건너뛰었습니다 — 파티션 %d: %s"
                            % (lk["index"], lk["reason"]))
    fs_desc = vfs.describe()
    say("NTFS 볼륨 %d개 — 대상 경로 훑는 중…"
        % len(getattr(vfs, "volumes", []) or [1]))

    # --- 2. 아티팩트 탐색 ---------------------------------------------
    targets, inventory, scanned, other = [], [], 0, {}
    for vfile in vfs.iter_files():
        scanned += 1
        if verbose and scanned % 2000 == 0:
            say("  훑은 파일 %d건 · 대상 %d건" % (scanned, len(inventory)))
        kind, meta = locate.classify(vfile.path)
        if kind is None:
            continue
        # 이름만 겹치는 다른 제품은 뺀다. Claude Code(CLI)·Claude Web·다른 앱의
        # 파일을 이 파서가 싣으면 그 자체가 오탐이다.
        prod = locate.other_product(vfile.path)
        if prod:
            other[prod] = other.get(prod, 0) + 1
            continue
        inventory.append({"kind": kind, **vfile.location()})
        if kind in kinds:
            targets.append((kind, vfile, meta))

    if not inventory:
        if img is not None:
            img.close()
        raise ArtifactNotFoundError(
            "%s에서 Claude Desktop 아티팩트 경로를 하나도 찾지 못했습니다"
            % ("이 PC" if input_type == "live" else "이미지"),
            scanned_files=scanned,
            searched_patterns=[p[0] for p in locate._PATTERNS],
            **({"denied": getattr(vfs, "denied", [])} if input_type == "live" else {}))
    if other:
        warnings.append("이름만 겹치는 다른 제품의 경로는 제외했습니다: "
                        + ", ".join("%s %d건" % (k, v) for k, v in other.items()))
    if not targets:
        warnings.append("Claude 관련 경로 %d건을 찾았으나 파싱 대상 종류(%s)에 "
                        "해당하는 파일이 없습니다" % (len(inventory), ", ".join(kinds)))

    say("대상 %d건 확인 — 파싱 시작" % len(targets))

    # --- 3. 파싱 --------------------------------------------------------
    rb = RecordBuilder()
    records, parsed_files = [], []
    by_kind = {}

    # 3a. IndexedDB 정식 파싱 먼저.
    # 대화 저장소 값은 V8 구조화 복제라, 정식 역직렬화하면 발화자·시각·대화
    # UUID 가 추측 없이 나온다. 바이트 스캔은 그 뒤에 남은 잔존분만 줍는다.
    idb_files = [vf for kind, vf, _ in targets
                 if kind in ("idb_leveldb", "idb_blob")]
    struct_recs, idb_summary = idb_struct.parse_group(
        idb_files, image_desc, rb, max_excerpt=max_excerpt, say=say)
    records.extend(struct_recs)
    if struct_recs:
        by_kind["idb_structured"] = len(struct_recs)
    if not idb_summary["available"]:
        warnings.append("IndexedDB 정식 파서(ccl_chromium_reader)를 불러오지 못해 "
                        "바이트 스캔만 수행했습니다: %s" % idb_summary["import_error"])
    elif not struct_recs and idb_files:
        warnings.append("IndexedDB 정식 파싱에서 대화를 얻지 못했습니다 — "
                        "바이트 스캔 결과만 실립니다")
    already = idb_struct.recovered_texts(struct_recs)
    # 조각 대조용 — 복원된 본문을 한 덩어리로 이어 붙인다.
    corpus = chr(10).join(already)
    superseded = 0

    for kind, vfile, _meta in sorted(targets, key=lambda t: t[1].path):
        if vfile.size > max_file_bytes:
            errors.append({"code": "FILE_TOO_LARGE", "path": vfile.path,
                           "size": vfile.size, "limit": max_file_bytes})
            continue
        try:
            recs = PARSERS[kind](vfile, image_desc, rb, max_excerpt=max_excerpt)
            if kind in ("idb_leveldb", "idb_blob", "local_storage", "session_storage"):
                recs = _drop_duplicates(recs, already, corpus)
            if kind in ("idb_leveldb", "idb_blob") and struct_recs:
                superseded += _mark_superseded(recs)
            records.extend(recs)
            parsed_files.append({"kind": kind, "path": vfile.path, "records": len(recs),
                                 "allocated": vfile.allocated,
                                 "mft_record": vfile.mft_record})
            if recs:
                by_kind[kind] = by_kind.get(kind, 0) + len(recs)
        except ClError as exc:
            errors.append({"path": vfile.path, **exc.to_dict()})
        except OSError as exc:
            # 파일 내용을 읽지 못함 — 이미지의 손상 클러스터, 라이브의 잠긴 파일·권한 부족
            errors.append({"path": vfile.path, "code": "FILE_READ_FAILED",
                           "message": "%s: %s" % (type(exc).__name__, exc)})
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": vfile.path, "code": "UNEXPECTED",
                           "message": "%s: %s" % (type(exc).__name__, exc)})

    if getattr(vfs, "denied", None):
        warnings.append("권한이 없어 열지 못한 폴더 %d건 — 관리자 권한으로 실행하면 더 볼 수 "
                        "있습니다 (filesystem.denied)" % len(vfs.denied))
    if getattr(vfs, "read_failures", None):
        locked = sum(1 for f in vfs.read_failures if f.get("locked"))
        warnings.append("열거는 됐지만 읽지 못한 파일 %d건%s (filesystem.read_failures)"
                        % (len(vfs.read_failures),
                           " — 그중 %d건은 실행 중인 Claude 앱이 잠근 파일이라 앱을 종료한 뒤 "
                           "다시 실행하면 읽을 수 있습니다" % locked if locked else
                           " — 권한이 없습니다"))

    for k, n in sorted(by_kind.items(), key=lambda x: -x[1]):
        say("[%s] 레코드 %d건" % (k, n))
    if superseded:
        say("이미 복원한 대화의 중복 조각 %d건 정리 "
            "(근거는 result.json 에 보존)" % superseded)
    idb_summary["byte_scan_superseded"] = superseded

    # --- 3b. $UsnJrnl:$J ------------------------------------------------
    usn_summary = None
    if usn and img is not None:
        say("$UsnJrnl:$J 읽는 중…")
    if usn and img is not None and getattr(vfs, "volumes", None):
        usn_summary = []
        for vd, fs in vfs.volumes:
            loc = {"path": "/$Extend/$UsnJrnl:$J", "partition_index": vd["index"],
                   "partition_offset_bytes": vd["offset_bytes"]}
            try:
                info, recs_usn = usn_mod.read_journal(
                    fs, max_bytes=usn_max_bytes,
                    claude_dirs=getattr(vfs, "scanned_dirs", {}).get(vd["index"]))
            except Exception as exc:  # noqa: BLE001
                usn_summary.append({**loc, "status": "not_found",
                                    "message": "%s: %s" % (type(exc).__name__, exc)})
                continue
            records.extend(usn_mod.to_records(info, recs_usn, image_desc, rb, loc,
                                              max_excerpt=max_excerpt))
            usn_summary.append({**loc, "status": "ok", **info})

    merged = _merge_snapshots(records)
    if merged:
        say("같은 공유 스냅샷 %d건을 하나로 합침" % merged)


    _drop_undefined(records)

    folded = _collapse_drafts(records)
    if folded:
        say("입력 초안 타이핑 스냅샷 %d건을 완성 문장으로 접음" % folded)

    runs_merged = _merge_prefetch_runs(records)
    if runs_merged:
        say("같은 실행의 프리패치 %d건을 한 행으로 합침" % runs_merged)

    usn_folded = _fold_usn_prefetch(records)
    if usn_folded:
        say("같은 실행의 USN 프리패치 기록 %d건을 실행 행 근거로 합침" % usn_folded)

    pkg_folded = _fold_package_installs(records)
    if pkg_folded:
        say("반복된 패키지 폴더 생성 %d건을 업데이트 후보로 내림" % pkg_folded)

    say("교차검증 중…")
    corroborated = _corroborate(records)
    say("교차검증으로 확신도 상승 %d건" % corroborated)
    tl = timeline.build(records)
    say("레코드 %d건 · 소요 %.1f초" % (len(records), time.time() - started))
    status_counts = {}
    for r in records:
        s = r["parse"]["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    result = Result({
        "tool": {"name": "parser", "version": __version__,
                 "target": "Claude Desktop (MSIX Claude_pzs8sxrjxfjjc · "
                           "%APPDATA%\\Claude · %LOCALAPPDATA%\\Claude[-Data])"},
        "input": image_desc,
        "filesystem": fs_desc,
        "scan": {"files_scanned": scanned, "claude_paths_found": len(inventory),
                 "parse_targets": len(targets), "parsed_files": parsed_files,
                 "other_products_excluded": other},
        "indexeddb": idb_summary,
        "records": records,
        "timeline": tl["timeline"],
        "undated_records": tl["undated_records"],
        "summary": {"record_counts": tl["counts"],
                    "parse_status_counts": status_counts,
                    "cross_channel_corroborated": corroborated,
                    "elapsed_seconds": round(time.time() - started, 3)},
        "not_applicable": events.NOT_APPLICABLE,
        "artifact_inventory": inventory,
        "usn_journal": usn_summary,
        "warnings": warnings,
        "errors": errors,
    })
    if img is not None:
        img.close()
    return result
