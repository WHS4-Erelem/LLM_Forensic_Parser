"""파일시스템 추상화 — 디스크 이미지(The Sleuth Kit) / 추출 디렉터리 / 실행 중인 PC(라이브)를
같은 인터페이스로."""

import fnmatch
import hashlib
import os
import platform
import struct
from datetime import datetime, timedelta, timezone

import pytsk3

from . import bitlocker
from .errors import FilesystemError, LiveAccessError, UnsupportedFormatError, VolumeLockedError
from .locate import SCAN_ROOTS

READ_CHUNK = 1024 * 1024
TSK_ERRORS = (OSError, RuntimeError)   # pytsk3 는 이미지 읽기 오류를 RuntimeError 로 감싸기도 한다
DIR = int(pytsk3.TSK_FS_META_TYPE_DIR)
REG = int(pytsk3.TSK_FS_META_TYPE_REG)


class VfsFile:
    """이미지/디렉터리 안의 파일 하나. 근거(evidence) 생성을 위한 위치정보 포함."""

    def __init__(self, path, size, source, *, mft_record=None, sequence=None,
                 allocated=True, si_times=None, fn_times=None, volume_index=None,
                 volume_offset=None, native_path=None, parse_errors=None,
                 path_source=None, live_root=None, time_source=None):
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
        self.live_root = live_root          # 라이브: path 앞에 붙는 실제 위치 ('C:', 'D:\\mnt')
        self.time_source = time_source      # 라이브: si_times 가 os.stat 값임을 밝힌다
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
        if self.live_root:
            loc["live_root"] = self.live_root
        if self.time_source:
            loc["time_source"] = self.time_source
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
        img = image.img
        self.volumes = []      # [(volume_desc, FS_Info)]
        self.scanned_dirs = {}     # iter_files 가 채운다
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
                    fs_img, vd["unlock_method"], vd["protectors"] = bitlocker.open_volume(
                        img, off, length, key_material)
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

        # 잠긴 볼륨이 있는데 하나도 못 풀었으면 여기서 멈춘다. 복구 파티션 같은 평문 NTFS
        # 만 읽고 "아티팩트 없음 = 앱 미사용" 으로 읽히는 결과를 내지 않기 위해서다.
        # 평문 OS 볼륨 + 잠긴 데이터 볼륨 조합도 같이 멈춘다 (키를 주면 풀린다).
        if self.locked and not any("unlock_method" in vd for vd, _fs in self.volumes):
            raise VolumeLockedError(self.locked[0]["reason"], volumes=self.locked)
        if not self.volumes:
            raise UnsupportedFormatError(
                "이미지에서 판독 가능한 NTFS 볼륨을 찾지 못했습니다",
                partitions=[{"offset_bytes": p[0], "type": p[2]} for p in parts],
                skipped=self.skipped)

    def iter_files(self):
        self.scanned_dirs = {}     # 볼륨 index -> {(MFT#, seq): 경로} — USN 저널 대조에 쓴다
        for vd, fs in self.volumes:
            dirs = {}      # (MFT#, seq) -> 경로 : 탐색한 디렉터리
            self.scanned_dirs[vd["index"]] = dirs
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
        # pytsk3 는 이미지 읽기 실패(잘린 이미지·손상 세그먼트)를 RuntimeError 로 감싸 던진다.
        # 코드 결함(UNEXPECTED)과 구분되게 OSError 로 바꿔 파일 읽기 실패로 보고한다.
        out = bytearray()
        try:
            f = vfile._fs.open_meta(inode=vfile.mft_record)
            while len(out) < vfile.size:
                chunk = f.read_random(len(out), min(READ_CHUNK, vfile.size - len(out)))
                if not chunk:
                    break
                out += chunk
        except RuntimeError as exc:
            raise OSError("이미지에서 파일을 읽지 못함 (%d/%d 바이트): %s"
                          % (len(out), vfile.size, str(exc).splitlines()[0][:200])) from None
        if len(out) < vfile.size:
            raise OSError("파일 %d 바이트 중 %d 바이트만 읽힘 (클러스터 손상/덮어씀 가능)"
                          % (vfile.size, len(out)))
        return bytes(out)

    def describe(self):
        return {
            "reader": "The Sleuth Kit %s (pytsk3)" % pytsk3.TSK_VERSION_STR,
            "volumes": [vd for vd, _fs in self.volumes],
            "skipped_partitions": self.skipped,
            "locked_volumes": self.locked,
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


class DirectoryVfs:
    """추출된 파일 트리(개발/중간 테스트용). MFT 정보는 없음."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise FilesystemError("디렉터리가 아닙니다", path=self.root)

    def iter_files(self):
        for dirpath, _dirs, files in os.walk(self.root):
            for fn in files:
                full = os.path.join(dirpath, fn)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rel = "/" + os.path.relpath(full, self.root).replace(os.sep, "/")
                yield VfsFile(path=rel, size=st.st_size, source=self, native_path=full)

    def _read_file(self, vfile):
        with open(vfile.native_path, "rb") as fh:
            return fh.read()

    def describe(self):
        return {"filesystem": "host-directory", "root": self.root,
                "note": "디스크 이미지가 아닌 추출 파일 트리 — MFT 근거 없음"}


def _stat_times(st):
    """os.stat -> $STANDARD_INFORMATION 과 같은 모양의 시각.

    실행 중인 NTFS 에서 Windows 가 돌려주는 생성·수정·접근 시각은 $SI 값이다.
    MFT 변경 시각은 stat 으로 얻을 수 없어 None 으로 둔다 (만들어 넣지 않는다).
    """
    def ts(ns):
        if not ns:
            return None
        return _iso(datetime.fromtimestamp(0, tz=timezone.utc) + timedelta(microseconds=ns // 1000))
    birth = getattr(st, "st_birthtime_ns", None)            # Windows 는 Python 3.12+
    if os.name == "nt":
        created = birth or st.st_ctime_ns                   # Windows 의 st_ctime 은 생성 시각
    else:
        created = birth
    return {"created": ts(created), "modified": ts(st.st_mtime_ns),
            "mft_modified": None, "accessed": ts(st.st_atime_ns)}


def _stat_mft_record(st):
    """NTFS 파일 ID(64비트)의 하위 48비트 = MFT 레코드 번호. NTFS 가 아니면 None."""
    if os.name != "nt":
        return None
    return (st.st_ino & 0xFFFFFFFFFFFF) or None


def _long(path):
    r"""MAX_PATH(260) 를 넘는 경로도 열리게 \\?\ 접두를 붙인다 (Windows 만)."""
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    return "\\\\?\\" + os.path.abspath(path)


def _is_link(entry):
    """심볼릭 링크 또는 정션('Default User' 같은 호환용 폴더). 따라가면 같은 곳을 두 번 본다."""
    try:
        if entry.is_symlink():
            return True
        is_junction = getattr(entry, "is_junction", None)          # Python 3.12+
        return bool(is_junction and is_junction())
    except OSError:
        return False


# Windows 공유 위반(32)·잠금 위반(33): 실행 중인 앱이 파일을 독점으로 연 경우
_SHARING_VIOLATION = (32, 33)


def _open_shared(path):
    """읽기 전용으로 열되, 다른 프로세스의 읽기·쓰기·삭제 공유를 모두 허용한다 (Windows).

    Python open() 은 FILE_SHARE_DELETE 를 주지 않는다. 실행 중인 Claude 앱은 HTTP 캐시
    (data_0~3, index) 를 DELETE 권한까지 잡고 있어서, 이 공유 플래그가 없으면 공유
    위반(32)으로 거부된다. 공유 플래그는 "다른 프로세스가 해도 되는 것" 을 허용할 뿐이고
    여기서 요청하는 권한은 GENERIC_READ 하나라 원본을 바꾸지 않는다.
    """
    if os.name != "nt":
        return open(path, "rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    generic_read, share_all, open_existing, normal = 0x80000000, 0x7, 3, 0x80
    h = k32.CreateFileW(path, generic_read, share_all, None, open_existing, normal, None)
    if h == wintypes.HANDLE(-1).value:
        err = ctypes.get_last_error()
        raise ctypes.WinError(err)
    try:
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
    except OSError:
        k32.CloseHandle(h)
        raise
    return os.fdopen(fd, "rb")


def _is_sharing_violation(exc):
    return getattr(exc, "winerror", None) in _SHARING_VIOLATION


def _os_reason(exc):
    code = getattr(exc, "winerror", None)
    return "%s: %s%s" % (type(exc).__name__, exc.strerror or exc,
                         " (winerror %d)" % code if code else "")


class LiveVfs:
    """실행 중인 PC 의 볼륨 루트(C:\\ 등)에서 Claude Desktop 저장 경로를 직접 읽는다.

    이미지를 뜨지 않고 그 PC 에서 바로 분석할 때 쓴다 (라이브 분석).
      - SCAN_ROOTS(이미지 분석과 같은 탐색 경로)만 본다. 디스크 전체를 훑지 않는다.
      - 모든 파일은 읽기 전용으로만 연다. 복사본·임시 파일을 원본 경로에 만들지 않는다.
      - 파일 시각·MFT 번호는 os.stat 값이다. 출처를 time_source 로 밝힌다.
      - 삭제 파일과 $UsnJrnl 은 다루지 않는다 (볼륨을 원시로 열지 않으므로).
      - 권한이 없어 열지 못한 폴더·파일은 denied / read_failures 에 남기고 계속 간다.
    """

    TIME_SOURCE = "os.stat (실행 중인 파일시스템)"

    def __init__(self, root):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise LiveAccessError("라이브 분석 대상 폴더를 열 수 없습니다", path=self.root)
        # 볼륨 내부 경로('/Users/…') 앞에 붙여 실제 위치를 만드는 접두.
        # 'C:\\' -> 'C:' (드라이브 루트),  'D:\\mnt' -> 'D:\\mnt' (마운트 폴더 등)
        drive, tail = os.path.splitdrive(self.root)
        self.prefix = self.root.rstrip("\\/") if tail.strip("\\/") else drive.upper()
        self.denied = []           # 열지 못한 폴더 [{path, reason}]
        self.read_failures = []    # 열거는 됐는데 내용을 읽지 못한 파일

    def _roots(self):
        """SCAN_ROOTS 패턴을 대소문자 무시로 실제 폴더에 맞춘다. -> [(볼륨 내부 경로, 실제 경로)]"""
        for pattern in SCAN_ROOTS:
            level = [("", self.root)]
            for seg in pattern.lower().split("/"):
                nxt = []
                for rel, full in level:
                    try:
                        entries = list(os.scandir(_long(full)))
                    except OSError as exc:
                        if rel:                              # 상위 폴더 권한 문제만 남긴다
                            self._deny(rel, exc)
                        continue
                    for e in entries:
                        try:
                            is_dir = e.is_dir(follow_symlinks=False) and not _is_link(e)
                        except OSError:
                            continue
                        if is_dir and fnmatch.fnmatch(e.name.lower(), seg):
                            nxt.append((rel + "/" + e.name, os.path.join(full, e.name)))
                level = nxt
            yield from level

    def _deny(self, rel, exc):
        if any(d["path"] == rel for d in self.denied):
            return
        self.denied.append({"path": rel, "reason": _os_reason(exc)})

    def iter_files(self):
        seen = set()
        for rel_root, full_root in self._roots():
            stack = [(rel_root, full_root)]
            while stack:
                rel, full = stack.pop()
                key = os.path.normcase(full)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    entries = sorted(os.scandir(_long(full)), key=lambda e: e.name)
                except OSError as exc:
                    self._deny(rel, exc)
                    continue
                for e in entries:
                    child_rel, child_full = rel + "/" + e.name, os.path.join(full, e.name)
                    try:
                        if _is_link(e):                      # 정션·링크는 따라가지 않는다
                            continue
                        if e.is_dir():
                            stack.append((child_rel, child_full))
                            continue
                        if not e.is_file():
                            continue
                        st = e.stat()
                    except OSError as exc:
                        self._deny(child_rel, exc)
                        continue
                    yield VfsFile(path=child_rel, size=st.st_size, source=self,
                                  native_path=child_full,
                                  mft_record=_stat_mft_record(st),
                                  si_times=_stat_times(st), live_root=self.prefix,
                                  time_source=self.TIME_SOURCE)

    def _read_file(self, vfile):
        full = os.path.join(self.root, vfile.path.lstrip("/").replace("/", os.sep))
        try:
            with _open_shared(_long(full)) as fh:            # 읽기 전용
                return fh.read()
        except OSError as exc:
            self.read_failures.append({"path": vfile.path, "reason": _os_reason(exc),
                                       "locked": _is_sharing_violation(exc)})
            raise

    def describe_input(self):
        """증거 설명 — 이미지 파일 대신 '언제, 어느 PC 를, 어떤 권한으로 읽었는지' 를 남긴다."""
        elevated = None
        if os.name == "nt":
            try:
                import ctypes
                elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                pass
        return {
            "image_id": "live:%s:%s" % (platform.node(), self.root),
            "image_type": "live",
            "file_name": self.root,
            "hostname": platform.node(),
            "os": platform.platform(),
            "collected_at_utc": _iso(datetime.now(timezone.utc).replace(microsecond=0)),
            "elevated": elevated,
            "note": ("실행 중인 시스템의 파일을 직접 읽음 — 디스크 이미지가 아니므로 같은 결과를 "
                     "다시 만들 수 없고, 읽는 동안 앱이 파일을 바꿀 수 있다. 원본은 읽기 전용으로만 "
                     "열었다 (마지막 접근 시각은 운영체제 설정에 따라 갱신될 수 있음)"),
        }

    def describe(self):
        return {"filesystem": "live", "root": self.root,
                "scan_roots": list(SCAN_ROOTS),
                "denied": self.denied,
                "read_failures": self.read_failures,
                "note": ("실행 중인 시스템의 파일을 직접 읽음 — 시각·MFT 번호는 os.stat 값, "
                         "삭제 파일·$UsnJrnl 없음")}
