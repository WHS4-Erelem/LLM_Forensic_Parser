"""파일시스템 추상화 — 디스크 이미지(The Sleuth Kit) / 추출 디렉터리를 같은 인터페이스로."""

import fnmatch
import hashlib
import json
import os
import struct
from datetime import datetime, timedelta, timezone

try:
    import pytsk3
except ImportError:      # 폴더 입력만 쓸 때는 없어도 된다 (호스트 DFIR 도구가 파일을 꺼내 주는 경우)
    pytsk3 = None

from .errors import FilesystemError, UnsupportedFormatError, VolumeLockedError
from .locate import SCAN_ROOTS

READ_CHUNK = 1024 * 1024
TSK_ERRORS = (OSError, RuntimeError)   # pytsk3 는 이미지 읽기 오류를 RuntimeError 로 감싸기도 한다
DIR = int(pytsk3.TSK_FS_META_TYPE_DIR) if pytsk3 else None
REG = int(pytsk3.TSK_FS_META_TYPE_REG) if pytsk3 else None


class VfsFile:
    """이미지/디렉터리 안의 파일 하나. 근거(evidence) 생성을 위한 위치정보 포함."""

    def __init__(self, path, size, source, *, mft_record=None, sequence=None,
                 allocated=True, si_times=None, fn_times=None, volume_index=None,
                 volume_offset=None, native_path=None, parse_errors=None,
                 path_source=None):
        self.path = path                    # '/Users/x/.codex/...' (소스 내부 경로)
        self.size = size
        self._source = source
        self.mft_record = mft_record
        self.sequence = sequence
        self.allocated = allocated
        self.si_times = si_times or {}
        self.fn_times = fn_times or {}
        self.volume_index = volume_index
        self.volume_offset = volume_offset
        self.native_path = native_path      # dir 소스일 때 실제 로컬 경로
        self.parse_errors = list(parse_errors or [])
        self.path_source = path_source
        self._cached = None

    def read(self):
        if self._cached is None:
            self._cached = self._source._read_file(self)
        return self._cached

    def sha256(self):
        return hashlib.sha256(self.read()).hexdigest()

    def location(self):
        loc = {"path": self.path, "size_bytes": self.size, "allocated": self.allocated}
        if self.path_source:
            loc["path_source"] = self.path_source
        if self.mft_record is not None:
            loc["mft_record"] = self.mft_record
            loc["mft_sequence"] = self.sequence
        if self.volume_index is not None:
            loc["partition_index"] = self.volume_index
            loc["partition_offset_bytes"] = self.volume_offset
        if self.native_path:
            loc["native_path"] = self.native_path
        if self.si_times:
            loc["ntfs_standard_information"] = self.si_times
        if self.fn_times:
            loc["ntfs_file_name"] = self.fn_times
        if self.parse_errors:
            loc["parse_errors"] = self.parse_errors
        return loc


class TskImageVfs:
    """디스크 이미지의 NTFS 볼륨에서 SCAN_ROOTS 하위 파일을 열거 (삭제 엔트리 포함)."""

    def __init__(self, image, key_material=None):
        from . import bitlocker            # 이미지 입력일 때만 (pytsk3 필요)
        img = image.img
        self.volumes = []      # [(volume_desc, FS_Info)]
        self.skipped = []
        self.locked = []       # 풀지 못한 BitLocker 볼륨 (skipped 에도 들어간다)
        self._plain_images = []   # 복호화 이미지 — FS_Info 가 쓰는 동안 살아 있어야 한다
        try:
            vs = pytsk3.Volume_Info(img)
            bs = vs.info.block_size
            scheme = {1: "MBR", 8: "GPT"}.get(int(vs.info.vstype), str(vs.info.vstype))
            parts = [(p.start * bs, p.len * bs, p.desc.decode("utf-8", "replace"), scheme)
                     for p in vs if int(p.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC)]
        except TSK_ERRORS:
            parts = [(0, img.get_size(), "볼륨 이미지(파티션 테이블 없음)", "NONE")]

        for idx, (off, length, desc, scheme) in enumerate(parts):
            vd = {"index": idx, "scheme": scheme, "offset_bytes": off,
                  "length_bytes": length, "type": desc}
            fs_img, fs_off = img, off
            if bitlocker.is_bitlocker(img, off):
                vd["encryption"] = "BitLocker"
                try:
                    fs_img, vd["unlock_method"] = bitlocker.open_volume(img, off, length, key_material)
                except VolumeLockedError as exc:
                    self.locked.append({**vd, "reason": exc.message, **exc.context})
                    self.skipped.append(self.locked[-1])
                    continue
                fs_off = 0
                self._plain_images.append(fs_img)
            try:
                fs = pytsk3.FS_Info(fs_img, offset=fs_off)
            except TSK_ERRORS as exc:
                self.skipped.append({**vd, "reason": "%s파일시스템 판독 불가: %s"
                                     % ("BitLocker 해제 후 " if "unlock_method" in vd else "",
                                        str(exc).splitlines()[0][:200])})
                continue
            if int(fs.info.ftype) != int(pytsk3.TSK_FS_TYPE_NTFS):
                self.skipped.append({**vd, "reason": "미지원 파일시스템: %s" % fs.info.ftype})
                continue
            vd.update(filesystem="NTFS", cluster_size=fs.info.block_size)
            self.volumes.append((vd, fs))

        # ponytail: 잠긴 볼륨이 있는데 하나도 못 풀었으면 중단한다 — 복구 파티션 같은 평문 NTFS 만 읽고
        # "앱 미사용" 으로 결론 내리는 것을 막기 위해서다. 평문 OS 볼륨 + 잠긴 데이터 볼륨 조합도 같이 막힌다 (키를 주면 풀림).
        if self.locked and not any("unlock_method" in vd for vd, _fs in self.volumes):
            raise VolumeLockedError(self.locked[0]["reason"], volumes=self.locked)
        if not self.volumes:
            raise UnsupportedFormatError(
                "이미지에서 판독 가능한 NTFS 볼륨을 찾지 못했습니다",
                partitions=[{"offset_bytes": p[0], "type": p[2]} for p in parts],
                skipped=self.skipped)

    def iter_files(self):
        for vd, fs in self.volumes:
            dirs = {}      # (MFT#, seq) -> 경로 : 탐색한 디렉터리
            yielded = set()
            for path, entry in _expand_roots(fs):
                for vf in self._walk(vd, fs, path, entry, dirs):
                    yielded.add(vf.mft_record)
                    yield vf
            yield from self._unlisted_deleted(vd, fs, dirs, yielded)

    def _walk(self, vd, fs, path, dir_entry, dirs):
        key = (dir_entry.info.meta.addr, dir_entry.info.meta.seq)
        if key in dirs:
            return
        dirs[key] = path
        try:
            directory = dir_entry.as_directory()
        except TSK_ERRORS:
            return
        for entry in directory:
            name = entry.info.name.name.decode("utf-8", "replace")
            meta = entry.info.meta
            if name in (".", "..") or meta is None:
                continue
            if int(meta.type) == DIR:
                yield from self._walk(vd, fs, path + "/" + name, entry, dirs)
            elif int(meta.type) == REG:
                yield self._vfile(vd, fs, path + "/" + name, entry)

    def _unlisted_deleted(self, vd, fs, dirs, yielded):
        """디렉터리 인덱스에서 이름까지 지워진 삭제 파일 — 미할당 MFT 엔트리의 $FILE_NAME
        부모 참조 (MFT#, seq) 가 탐색한 디렉터리와 정확히 일치하는 것만 경로를 복원해 채택.

        TSK 의 $OrphanFiles 는 부모 디렉터리가 살아 있는 삭제 파일을 담지 않으므로
        $MFT:$BITMAP 으로 미할당 엔트리만 골라 직접 연다.
        """
        bitmap = _mft_bitmap(fs)
        for inum in range(24, fs.info.last_inum + 1):   # 0~23 은 NTFS 예약 엔트리
            if inum in yielded or (inum // 8 < len(bitmap) and bitmap[inum // 8] >> (inum % 8) & 1):
                continue
            try:
                entry = fs.open_meta(inode=inum)
            except TSK_ERRORS:
                continue
            meta = entry.info.meta
            if meta is None or int(meta.type) != REG:
                continue
            fn = _file_name_attr(entry)
            parent = dirs.get((fn.get("parent_mft"), fn.get("parent_seq")))
            if parent is not None:
                yield self._vfile(vd, fs, parent + "/" + fn["name"], entry, fn=fn,
                                  path_source="미할당 MFT 엔트리의 $FILE_NAME 부모 참조로 복원 "
                                              "(디렉터리 인덱스에 이름 없음)")

    def _vfile(self, vd, fs, path, entry, fn=None, path_source=None):
        meta, nm = entry.info.meta, entry.info.name
        name_alloc = nm is not None and bool(int(nm.flags) & int(pytsk3.TSK_FS_NAME_FLAG_ALLOC))
        meta_alloc = bool(int(meta.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC))
        errors = []
        if nm is not None and not name_alloc and nm.meta_seq != meta.seq:
            errors.append("삭제된 이름이 가리키던 MFT 엔트리가 재할당됨 (seq %d -> %d) — "
                          "내용이 다른 파일일 수 있음" % (nm.meta_seq, meta.seq))
        fn = fn if fn is not None else _file_name_attr(entry)
        vf = VfsFile(path=path, size=meta.size, source=self,
                     mft_record=meta.addr, sequence=meta.seq,
                     allocated=name_alloc and meta_alloc,
                     si_times=_si_times(meta), fn_times=fn.get("times"),
                     volume_index=vd["index"], volume_offset=vd["offset_bytes"],
                     parse_errors=errors, path_source=path_source)
        vf._fs = fs
        return vf

    def _read_file(self, vfile):
        f = vfile._fs.open_meta(inode=vfile.mft_record)
        out = bytearray()
        while len(out) < vfile.size:
            chunk = f.read_random(len(out), min(READ_CHUNK, vfile.size - len(out)))
            if not chunk:
                raise OSError("파일 %d 바이트 중 %d 바이트만 읽힘 (클러스터 손상/덮어씀 가능)"
                              % (vfile.size, len(out)))
            out += chunk
        return bytes(out)

    def describe(self):
        return {
            "reader": "The Sleuth Kit %s (pytsk3)" % pytsk3.TSK_VERSION_STR,
            "volumes": [vd for vd, _fs in self.volumes],
            "skipped_partitions": self.skipped,
            "scan_roots": list(SCAN_ROOTS),
            "scan_note": ("SCAN_ROOTS 하위 디렉터리 열거(할당/삭제 이름) + 부모가 그 하위인 "
                          "미할당 MFT 엔트리. 부모 디렉터리까지 삭제·재할당된 파일은 경로 복원 불가"),
        }


def _mft_bitmap(fs):
    """$MFT 의 $BITMAP 속성 (비트 1 = 사용 중 엔트리). 못 읽으면 빈 값 → 전 엔트리 확인."""
    try:
        mft = fs.open_meta(inode=0)
        for attr in mft:
            if int(attr.info.type) == int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_BITMAP):
                return mft.read_random(0, attr.info.size, attr.info.type, attr.info.id)
    except TSK_ERRORS:
        pass
    return b""


def _expand_roots(fs):
    """'Users/*/.codex' 같은 패턴을 대소문자 무시로 실제 디렉터리 엔트리에 매칭."""
    for pattern in SCAN_ROOTS:
        level = [("", fs.open("/"))]
        for seg in pattern.lower().split("/"):
            nxt = []
            for path, dir_entry in level:
                try:
                    directory = dir_entry.as_directory()
                except TSK_ERRORS:
                    continue
                for entry in directory:
                    meta = entry.info.meta
                    name = entry.info.name.name.decode("utf-8", "replace")
                    if (meta is not None and name not in (".", "..")
                            and int(meta.type) == DIR
                            and fnmatch.fnmatch(name.lower(), seg)):
                        nxt.append((path + "/" + name, entry))
            level = nxt
        yield from level


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _si_times(meta):
    """TSK 가 NTFS 에서 채우는 meta 시각 = $STANDARD_INFORMATION."""
    def ts(sec, nano):
        if not sec:
            return None
        return _iso(datetime.fromtimestamp(sec, tz=timezone.utc)
                    + timedelta(microseconds=nano // 1000))
    return {
        "created": ts(meta.crtime, meta.crtime_nano),
        "modified": ts(meta.mtime, meta.mtime_nano),
        "mft_modified": ts(meta.ctime, meta.ctime_nano),
        "accessed": ts(meta.atime, meta.atime_nano),
    }


def _file_name_attr(entry):
    """$FILE_NAME 속성: 부모 참조·이름·4시각. DOS(8.3) 이름공간보다 Win32/POSIX 우선."""
    found = []
    try:
        for attr in entry:
            if int(attr.info.type) != int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME):
                continue
            raw = entry.read_random(0, attr.info.size, attr.info.type, attr.info.id)
            if len(raw) < 66:
                continue
            parent, c, m, r, a = struct.unpack_from("<QQQQQ", raw, 0)
            found.append({
                "parent_mft": parent & 0xFFFFFFFFFFFF,
                "parent_seq": parent >> 48,
                "namespace": raw[65],
                "name": raw[66:66 + raw[64] * 2].decode("utf-16-le", "replace"),
                "times": {"created": _filetime(c), "modified": _filetime(m),
                          "mft_modified": _filetime(r), "accessed": _filetime(a)},
            })
    except TSK_ERRORS:
        pass
    found.sort(key=lambda f: f["namespace"] == 2)   # 2 = DOS 전용 이름
    return found[0] if found else {}


def _filetime(v):
    if not v:
        return None
    return _iso(datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10))


HOST_META_NAME = "_host_metadata.json"


class DirectoryVfs:
    """추출된 파일 트리. 파일만 있으면 MFT 정보가 없다.

    호스트 DFIR 도구(Autopsy 등)가 파일을 꺼내 주면서 루트에 `_host_metadata.json` 을 같이 두면
    그 도구가 이미 읽어 둔 파일시스템 메타데이터(MFT 시각·레코드 번호)를 근거로 쓴다 — 이미지를 다시 읽지 않는다.
      {"provider": "...", "entries": {"<소문자 경로>": {"path", "times": {created, modified, mft_modified, accessed},
                                                    "mft_record", "size", "dir", "head_hex"}}}
    entries 에는 꺼내지 않은 항목(폴더, 바로가기 대상 파일)의 메타데이터도 들어올 수 있다 (host_stat 로 조회)."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise FilesystemError("디렉터리가 아닙니다", path=self.root)
        self.host_provider, self.host_meta = None, {}
        meta_path = os.path.join(self.root, HOST_META_NAME)
        if os.path.isfile(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.host_provider, self.host_meta = doc.get("provider"), doc.get("entries") or {}

    def host_stat(self, path):
        """'/Users/x/Downloads/f' → 호스트가 준 메타데이터 dict, 없으면 None."""
        return self.host_meta.get(path.replace("\\", "/").lower())

    @staticmethod
    def _long(path):
        """Windows 기본 설정(LongPathsEnabled=0)은 260자를 넘는 경로를 열지 못한다. 확장 길이 접두(\\\\?\\)를 붙이면
        그 설정과 무관하게 열린다 — 사건 폴더가 깊은 곳에 있어도 추출 파일을 놓치지 않게."""
        return "\\\\?\\" + path if os.name == "nt" and not path.startswith("\\\\") else path

    def scan_roots(self):
        """루트 아래에서 SCAN_ROOTS('Users/*/.codex' …)에 해당하는 폴더를 대소문자 무시로 찾는다 — 이미지 입력의
        _expand_roots 와 같은 범위. 볼륨 루트(C:\\ 나 그 사본)를 받아도 디스크 전체를 훑지 않는다."""
        found = []
        for pattern in SCAN_ROOTS:
            level = [self._long(self.root)]
            for seg in pattern.lower().split("/"):
                nxt = []
                for d in level:
                    try:
                        names = os.listdir(d)
                    except OSError:
                        continue
                    nxt += [p for p in (os.path.join(d, n) for n in names if fnmatch.fnmatch(n.lower(), seg))
                            if os.path.isdir(p)]
                level = nxt
            found += level
        return found

    def iter_files(self):
        walk_root = self._long(self.root)
        # 탐색 루트가 하나도 없으면 볼륨 모양이 아닌 부분 추출 트리(.codex 폴더만 준 경우 등)이므로 전체를 본다
        for top in self.scan_roots() or [walk_root]:
            for dirpath, _dirs, files in os.walk(top):
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    tail = os.path.relpath(full, walk_root)
                    rel = "/" + tail.replace(os.sep, "/")
                    if rel == "/" + HOST_META_NAME:
                        continue
                    m = self.host_meta.get(rel.lower()) or {}
                    yield VfsFile(path=rel, size=st.st_size, source=self, native_path=os.path.join(self.root, tail),
                                  mft_record=m.get("mft_record"), si_times=m.get("times"))

    def _read_file(self, vfile):
        with open(self._long(vfile.native_path), "rb") as fh:
            return fh.read()

    def describe(self):
        if self.host_meta:
            return {"filesystem": "host-directory", "root": self.root, "host_metadata_provider": self.host_provider,
                    "note": "호스트 DFIR 도구가 꺼낸 파일 트리 — MFT 근거는 호스트가 넘긴 %s" % HOST_META_NAME}
        return {"filesystem": "host-directory", "root": self.root,
                "note": "디스크 이미지가 아닌 추출 파일 트리 — MFT 근거 없음"}


if __name__ == "__main__":  # python -m cxparser.vfs — 폴더 입력의 탐색 범위 자체 검사
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        for rel in ("USERS/a/.codex/auth.json", "Users/a/Videos/big.bin", "Windows/Prefetch/CODEX.EXE-1.pf", "ProgramData/other/x"):
            os.makedirs(os.path.dirname(os.path.join(td, rel)), exist_ok=True)
            open(os.path.join(td, rel), "w").close()
        got = sorted(f.path.lower() for f in DirectoryVfs(td).iter_files())
        assert got == ["/users/a/.codex/auth.json", "/windows/prefetch/codex.exe-1.pf"], got      # 볼륨 모양: 탐색 루트만, 대소문자 무시
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, ".codex", "sessions"))
        open(os.path.join(td, ".codex", "sessions", "r.jsonl"), "w").close()
        assert [f.path for f in DirectoryVfs(td).iter_files()] == ["/.codex/sessions/r.jsonl"]   # 부분 추출 트리: 전체
    print("vfs self-check ok")
