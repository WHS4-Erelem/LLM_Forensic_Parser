"""MS Store 패키지 폴더의 생성 시각 = 애플리케이션 설치 (E02-01).

조사(2026-09-28, 삭제 제외 raw 표본): Program Files\\WindowsApps\\OpenAI.Codex_26.917.6896.0_x64__2p2nqsd0c76g0 폴더 생성 03:54:19,
  Packages\\OpenAI.Codex_2p2nqsd0c76g0 (사용자 데이터 루트) 생성 03:57:13. 패키지 안 파일들의 시각은 빌드 시각(2026-03)이라 쓸 수 없고 폴더만 쓴다.
  실험 시트의 '설치 04:34:26' 은 첫 실행 시각과 같아 실제 Store 설치 완료(03:54~03:57)와 40분 차이 — 시트가 설치 '확인' 시점을 적은 것으로 보임.
앱을 삭제한 이미지에서는 폴더가 없어 잡히지 않는다 (삭제는 USN 저널이 그 구간을 덮을 때만).
"""

import re
from datetime import datetime, timezone

from .. import events, model

_PKG_ROOT_RE = re.compile(r"^(?P<root>/program files/windowsapps/openai\.codex_[^/]+)/", re.I)
_DATA_ROOT_RE = re.compile(r"^(?P<root>/users/[^/]+/appdata/local/packages/openai\.codex_2p2nqsd0c76g0)/", re.I)


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z") if epoch else None


def records_from_inventory(vfs, inventory, image_desc, rb):
    """패키지 루트 폴더의 MFT 생성 시각으로 설치 레코드를 만든다.
    이미지 입력(TSK)이면 inventory(발견 파일 목록)에서 루트를 찾아 직접 열고,
    폴더 입력이면 호스트 도구가 넘긴 폴더 메타데이터(_host_metadata.json 의 dir 항목)를 쓴다."""
    volumes = getattr(vfs, "volumes", None)
    found = []                                                     # (kind, root, created, modified, loc)
    if volumes:
        roots = {}                                                 # (partition_offset, root path) -> kind
        for item in inventory:
            p = str(item.get("path") or "")
            for rx, kind in ((_PKG_ROOT_RE, "package"), (_DATA_ROOT_RE, "userdata")):
                m = rx.match(p.lower())
                if m:
                    roots.setdefault((item.get("partition_offset_bytes"), p[:len(m.group("root"))]), kind)
        for (offset, root), kind in sorted(roots.items(), key=lambda kv: kv[1]):
            fs = next((fs for vd, fs in volumes if vd["offset_bytes"] == offset), None)
            if fs is None:
                continue
            try:
                f = fs.open(root)
                meta = f.info.meta
            except Exception:  # noqa: BLE001
                continue
            created, modified = _iso(meta.crtime), _iso(meta.mtime)
            found.append((kind, root, created, modified,
                          {"path": root, "mft_record": meta.addr, "partition_offset_bytes": offset,
                           "ntfs_standard_information": {"created": created, "modified": modified}}))
    else:
        for key, m in sorted((getattr(vfs, "host_meta", None) or {}).items()):
            if not m.get("dir"):
                continue
            for rx, kind in ((_PKG_ROOT_RE, "package"), (_DATA_ROOT_RE, "userdata")):
                if rx.match(key + "/") and rx.match(key + "/").group("root") == key:
                    t = m.get("times") or {}
                    root = m.get("path") or key
                    found.append((kind, root, t.get("created"), t.get("modified"),
                                  {"path": root, "mft_record": m.get("mft_record"),
                                   "ntfs_standard_information": {"created": t.get("created"), "modified": t.get("modified")}}))
        found.sort(key=lambda x: x[0])
    out = []
    for kind, root, created, modified, loc in found:
        if kind == "package":
            out.append(model.Record(
                rb.next_id(), "E02-01", events.name("E02-01"),
                model.timestamp(utc=created, meaning="MS Store 패키지 폴더(WindowsApps)의 MFT 생성 시각", source=model.TS_SOURCE_MFT),
                model.user_action(action="애플리케이션 설치(패키지 폴더 생성)", confidence=model.CONF_CONFIRMED,
                                  rationale="Store 가 앱을 설치할 때 만드는 패키지 폴더의 생성 시각. 폴더 안 파일들은 빌드 시각을 가져서 폴더만 근거로 쓴다"),
                model.evidence(image_desc, None, locator="directory", extra={"location": loc}), status="ok",
                details={"artifact": "package_dir", "package_dir": root.rsplit("/", 1)[-1], "key": root.rsplit("/", 1)[-1], "modified_utc": modified}))
        else:
            out.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                model.timestamp(utc=created, meaning="패키지 사용자 데이터 폴더(Packages)의 MFT 생성 시각", source=model.TS_SOURCE_MFT),
                model.user_action(observed="패키지 사용자 데이터 폴더 생성 %s" % (created or "-"),
                                  rationale="설치 직후 첫 등록 때 생기는 폴더 — 설치(E02-01) 보조 근거"),
                model.evidence(image_desc, None, locator="directory", extra={"location": loc}), status="ok",
                details={"artifact": "package_dir", "candidate_event": "E02-01", "package_dir": root.rsplit("/", 1)[-1]}))
    return out
