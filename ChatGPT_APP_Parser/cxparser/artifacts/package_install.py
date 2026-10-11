"""MS Store 패키지 폴더의 마지막 수정 시각 = 애플리케이션 설치 완료 (E02-01). 생성 시각(받기 시작)은 근거로 함께 적는다.

Store 는 받기 시작할 때 패키지 폴더를 만들고 다 받으면 폴더 수정 시각이 갱신된다. 패키지 안 파일들의 시각은 빌드 시각이라 쓸 수 없고 폴더만 쓴다.
사용자 데이터 루트(Packages 아래 사용자 데이터 폴더)의 생성 시각은 첫 실행에 가까워 '최초 설치 시점 추정' 관찰로만 남긴다.
설치 시각은 다운로드(패키지 쓰기)가 끝난 시각으로 본다.
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
            except Exception:
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
                                   "ntfs_standard_information": {"created": t.get("created"), "modified": t.get("modified")},
                                   **({"drive": m["drive"]} if m.get("drive") is not None else {})}))
        found.sort(key=lambda x: x[0])
    out = []
    for kind, root, created, modified, loc in found:
        name = root.rsplit("/", 1)[-1]
        if kind == "package":
            # 설치 시각 = 폴더의 마지막 수정 시각(파일을 다 써서 설치가 끝난 때). 생성 시각은 Store 가 받기 시작한 때라 몇 분 앞선다.
            # Store 패키지 폴더는 설치 뒤 내용이 바뀌지 않고 업데이트는 새 버전 폴더를 만들므로 수정 시각이 뒤로 밀리지 않는다.
            m = re.match(r"(?i)openai\.codex_(?P<ver>[\d.]+)_", name)
            out.append(model.Record(
                rb.next_id(), "E02-01", events.name("E02-01"),
                model.timestamp(utc=modified or created, meaning="MS Store 패키지 폴더(WindowsApps)의 MFT 마지막 수정 시각 = 패키지 쓰기 완료(설치 완료)",
                                source=model.TS_SOURCE_MFT),
                model.user_action(action="애플리케이션 설치(패키지 쓰기 완료)", confidence=model.CONF_CONFIRMED,
                                  rationale=("Store 가 앱을 설치할 때 만드는 버전별 패키지 폴더. 생성 시각 %s 은 받기 시작, 마지막 수정 시각은 "
                                             "파일 쓰기 완료 = 설치 완료. 폴더 안 파일들은 빌드 시각을 가져서 폴더만 근거로 쓴다. "
                                             "업데이트도 새 폴더를 만들므로 버전마다 한 건이다") % ((created or "-")[:19],)),
                model.evidence(image_desc, None, locator="directory", extra={"location": loc}), status="ok",
                details={"artifact": "package_dir", "package_dir": name, "key": name, "version": m.group("ver") if m else None,
                         "download_started_utc": created, "installed_utc": modified}))
        else:
            out.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                model.timestamp(utc=created, meaning="패키지 사용자 데이터 폴더(Packages)의 MFT 생성 시각", source=model.TS_SOURCE_MFT),
                model.user_action(observed="패키지 사용자 데이터 폴더 생성 %s — 최초 설치(첫 등록) 시점 추정" % (created or "-")[:19],
                                  rationale="이 폴더는 앱을 처음 등록할 때 한 번만 생기고 업데이트에도 유지된다 — 버전별 패키지 폴더와 달리 최초 설치 시점에 가깝다"),
                model.evidence(image_desc, None, locator="directory", extra={"location": loc}), status="ok",
                details={"artifact": "package_dir", "candidate_event": "E02-01", "package_dir": name}))
    return out
