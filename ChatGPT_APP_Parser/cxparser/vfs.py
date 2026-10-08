"""파일시스템 추상화 — 디스크 이미지(The Sleuth Kit) / 추출 디렉터리를 같은 인터페이스로."""

import fnmatch
import hashlib
import json
import os
import platform
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
                 path_source=None, drive=None):
        self.path = path                    # '/Users/x/.codex/...' (소스 내부 경로)
        self.size = size
        self._source = source
        self.drive = drive                  # 이미지: 이 볼륨의 드라이브 문자 (SYSTEM\MountedDevices 로 확인된 경우만)
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
        # 실제 드라이브 문자: 이미지는 볼륨별(MountedDevices), 라이브는 소스 전체 ('' = 드라이브 문자가 없는 시스템)
        drive = self.drive if self.drive is not None else getattr(self._source, "drive", None)
        if drive is not None:
            loc["drive"] = drive
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
            scheme = {int(pytsk3.TSK_VS_TYPE_DOS): "MBR", int(pytsk3.TSK_VS_TYPE_GPT): "GPT"}.get(int(vs.info.vstype), str(vs.info.vstype))   # GPT 는 0x10 (0.3.24 까지 8 로 적어 '16' 으로 나왔다)
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
        from . import mounted_devices      # 볼륨 → 드라이브 문자 (vd['drive']). 못 찾으면 출력은 종전대로 C: 가정
        try:
            self.drive_letters = mounted_devices.assign(img, parts[0][3], bs if parts[0][3] != "NONE" else 512, self.volumes)
        except Exception as exc:  # noqa: BLE001 — 드라이브 문자 판정 실패는 분석을 멈출 이유가 아니다
            self.drive_letters = {"status": "드라이브 문자 판정 실패 (%s) — C: 로 가정" % str(exc)[:100]}

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
                     parse_errors=errors, path_source=path_source, drive=vd.get("drive"))
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
            "drive_letters": self.drive_letters,
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
        self.denied = []                       # 권한이 없어 열지 못한 탐색 폴더 (루트 기준 경로)
        meta_path = os.path.join(self.root, HOST_META_NAME)
        if os.path.isfile(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.host_provider, self.host_meta = doc.get("provider"), doc.get("entries") or {}

    def host_stat(self, path):
        """'/Users/x/Downloads/f' 또는 'C:/Users/x/Downloads/f'(역슬래시 표기 포함) → 호스트가 준 메타데이터 dict, 없으면 None.
        추출 폴더는 볼륨 하나의 사본이라 드라이브 문자는 떼고 찾는다."""
        key = path.replace("\\", "/")
        return self.host_meta.get((key[2:] if key[1:2] == ":" else key).lower())

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
                    except PermissionError:                # 있지만 권한이 없어 못 여는 폴더 — 숨기지 않고 보고한다
                        self._note_denied(d)
                        continue
                    except OSError:
                        continue
                    nxt += [p for p in (os.path.join(d, n) for n in names if fnmatch.fnmatch(n.lower(), seg))
                            if os.path.isdir(p)]
                level = nxt
            found += level
        return found

    walk_all_without_roots = True      # 탐색 루트가 없으면 부분 추출 트리(.codex 폴더만 준 경우 등)로 보고 전체를 본다

    def _file_meta(self, rel, st):
        """파일 한 개의 (MFT 레코드 번호, $SI 시각). 추출 폴더에서는 호스트가 넘긴 값만 쓴다 — 복사본의 시각은 의미가 없다."""
        m = self.host_meta.get(rel.lower()) or {}
        return m.get("mft_record"), m.get("times")

    def _note_denied(self, path):
        """권한이 없어 열지 못한 폴더를 기록한다. Windows 의 옛 호환용 연결('Default User', 'All Users/Documents' 등
        재분석 지점)은 관리자여도 열리지 않는 것이 정상이라 제외한다."""
        try:
            if getattr(os.lstat(path), "st_file_attributes", 0) & 0x400:       # FILE_ATTRIBUTE_REPARSE_POINT
                return
        except OSError:
            pass
        rel = "/" + os.path.relpath(path, self._long(self.root)).replace(os.sep, "/")
        if rel not in self.denied:
            self.denied.append(rel)

    def _walk_error(self, exc):
        if isinstance(exc, PermissionError) and exc.filename:
            self._note_denied(exc.filename)

    def iter_files(self):
        walk_root = self._long(self.root)
        for top in self.scan_roots() or ([walk_root] if self.walk_all_without_roots else []):
            for dirpath, _dirs, files in os.walk(top, onerror=self._walk_error):
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
                    mft_record, times = self._file_meta(rel, st)
                    yield VfsFile(path=rel, size=st.st_size, source=self, native_path=os.path.join(self.root, tail),
                                  mft_record=mft_record, si_times=times)

    def _read_file(self, vfile):
        with open(self._long(vfile.native_path), "rb") as fh:
            return fh.read()

    def describe(self):
        if self.host_meta:
            return {"filesystem": "host-directory", "root": self.root, "host_metadata_provider": self.host_provider,
                    "note": "호스트 DFIR 도구가 꺼낸 파일 트리 — MFT 근거는 호스트가 넘긴 %s" % HOST_META_NAME}
        return {"filesystem": "host-directory", "root": self.root,
                "note": "디스크 이미지가 아닌 추출 파일 트리 — MFT 근거 없음"}


def _stat_times(st):
    """os.stat 결과 → $SI 시각 표기. 실행 중인 시스템에서는 이 값이 원본 파일시스템의 시각 그 자체다.
    MFT 변경 시각($SI changed)은 Windows 의 stat 으로 얻을 수 없어 None."""
    def ts(ns):
        return _iso(datetime.fromtimestamp(0, tz=timezone.utc) + timedelta(microseconds=ns // 1000)) if ns else None
    birth = getattr(st, "st_birthtime_ns", None)           # Windows 는 3.12+, macOS 는 항상 제공
    if os.name == "nt":
        created, changed = birth or st.st_ctime_ns, None   # Windows 의 st_ctime 은 생성 시각
    else:
        created, changed = birth, st.st_ctime_ns           # POSIX 의 st_ctime 은 inode 변경 시각
    return {"created": ts(created), "modified": ts(st.st_mtime_ns), "mft_modified": ts(changed), "accessed": ts(st.st_atime_ns)}


def _stat_mft_record(st):
    """NTFS 의 파일 ID(64비트) 하위 48비트 = MFT 레코드 번호. 다른 파일시스템이면 None."""
    return (st.st_ino & 0xFFFFFFFFFFFF) or None if os.name == "nt" else None


def _registered_package_roots():
    """현재 사용자에게 설치된 Codex 패키지의 폴더(PackageRootFolder). 관리자 권한이 필요 없다. Windows 가 아니면 빈 목록."""
    try:
        import winreg
    except ImportError:
        return []
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software" + os.sep + os.sep.join(
                ("Classes", "Local Settings", "Software", "Microsoft", "Windows", "CurrentVersion",
                 "AppModel", "Repository", "Packages"))) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                name = winreg.EnumKey(key, i)
                if name.lower().startswith("openai.codex_"):
                    try:
                        with winreg.OpenKey(key, name) as sub:
                            out.append(winreg.QueryValueEx(sub, "PackageRootFolder")[0])
                    except OSError:
                        continue
    except OSError:
        pass
    return out


class LiveVfs(DirectoryVfs):
    """실행 중인 시스템의 볼륨 루트(C:\\ 등)를 직접 읽는다 — 이미지를 뜨지 않고 그 PC 에서 바로 분석할 때(라이브 분석).

    추출 폴더 입력과 다른 점
      - 탐색 폴더(SCAN_ROOTS)만 본다. 하나도 없으면 아무것도 읽지 않는다 (디스크 전체를 훑지 않는다).
      - 파일 시각은 os.stat 값 = 원본 파일시스템의 시각이라 MFT 근거 자리에 그대로 쓴다.
      - 꺼내 두지 않은 항목(패키지 폴더, 바로가기 대상 파일)은 host_stat 이 실제 경로를 그때그때 조회한다.
    모든 파일은 읽기 전용으로만 연다. 삭제된 파일과 $UsnJrnl 은 다루지 않는다."""

    walk_all_without_roots = False

    def __init__(self, root):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise FilesystemError("디렉터리가 아닙니다", path=self.root)
        self.host_provider, self.host_meta = "live filesystem (os.stat)", {}
        self.denied = []
        self.drive = os.path.splitdrive(self.root)[0].upper()      # 'C:' / POSIX 는 ''
        # 패키지 폴더의 생성 시각 = 설치 근거 (package_install 이 dir 항목에서 찾는다).
        # WindowsApps 는 관리자가 아니면 목록을 볼 수 없지만, 패키지 폴더 자체는 이름을 알면 열린다 → 레지스트리에서 이름을 얻는다.
        for d in self.scan_roots() + [self._long(p) for p in _registered_package_roots()
                                      if os.path.splitdrive(p)[0].upper() == self.drive]:
            entry = self._entry(d)
            if entry:
                self.host_meta[entry["path"].lower()] = entry

    def _entry(self, full, head=False, base=None, drive=None):
        """실제 경로 하나 → _host_metadata.json 의 항목과 같은 모양의 dict. 없거나 권한이 없으면 None.
        base/drive: 볼륨 루트가 아닌 다른 드라이브의 파일을 볼 때 (바로가기 대상이 D: 에 있는 경우)."""
        try:
            st = os.stat(full)
        except OSError:
            return None
        is_dir = os.path.isdir(full)
        entry = {"path": "/" + os.path.relpath(full, base or self._long(self.root)).replace(os.sep, "/"), "size": st.st_size,
                 "dir": is_dir, "mft_record": _stat_mft_record(st), "times": _stat_times(st),
                 "drive": self.drive if drive is None else drive}
        if head and not is_dir and st.st_size:
            try:
                with open(full, "rb") as fh:
                    entry["head_hex"] = fh.read(8).hex()
            except OSError:
                pass
        return entry

    def host_stat(self, path):
        key = path.replace("\\", "/")
        drive, key = (key[:2].upper(), key[2:]) if key[1:2] == ":" else (self.drive, key)
        if drive == self.drive:
            base = self._long(self.root)
            hit = self.host_meta.get(key.lower())
            if hit:
                return hit
        else:
            base = self._long(drive + os.sep)                  # 바로가기 대상이 다른 드라이브에 있는 경우
        return self._entry(os.path.join(base, key.lstrip("/").replace("/", os.sep)), head=True, base=base, drive=drive)

    def _file_meta(self, rel, st):
        return _stat_mft_record(st), _stat_times(st)

    def describe_input(self):
        """증거 설명(image) — 이미지 파일이 아니라 '언제, 어느 PC 를, 어떤 권한으로 읽었는지' 를 남긴다."""
        if os.name == "nt":
            import ctypes
            try:
                elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                elevated = None
        else:
            elevated = os.geteuid() == 0
        return {
            "image_id": "live:%s:%s" % (platform.node(), self.root),
            "image_type": "live",
            "file_name": self.root,
            "hostname": platform.node(),
            "os": platform.platform(),
            "collected_at_utc": _iso(datetime.now(timezone.utc).replace(microsecond=0)),
            "elevated": elevated,
            "note": ("실행 중인 시스템의 파일을 직접 읽음 — 디스크 이미지가 아니므로 같은 결과를 다시 만들 수 없고, "
                     "읽는 동안 파일이 바뀔 수 있다. 원본은 읽기 전용으로만 열었다 (마지막 접근 시각은 운영체제 설정에 따라 갱신될 수 있음)"),
        }

    def describe(self):
        return {"filesystem": "live", "root": self.root,
                "note": "실행 중인 시스템의 파일을 직접 읽음 — 시각·MFT 번호는 os.stat 값, 삭제 파일·$UsnJrnl 없음"}


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
    with tempfile.TemporaryDirectory() as td:                                                    # 라이브: 실제 시각·드라이브
        os.makedirs(os.path.join(td, "Users", "a", ".codex"))
        os.makedirs(os.path.join(td, "Users", "a", "Downloads"))
        open(os.path.join(td, "Users", "a", ".codex", "auth.json"), "w").close()
        with open(os.path.join(td, "Users", "a", "Downloads", "x"), "wb") as fh:
            fh.write(b"%PDF-1.7 ...")
        live = LiveVfs(td)
        (f,) = list(live.iter_files())
        assert f.si_times["created"] and f.si_times["modified"] and f.location()["drive"] == live.drive
        win = os.sep.join(["", "Users", "a", "Downloads", "x"])                                  # Windows 표기 (역슬래시)
        for form in ("/Users/a/Downloads/x", live.drive + win):
            hit = live.host_stat(form)
            assert hit and hit["head_hex"] == b"%PDF-1.7".hex() and hit["times"]["created"], (form, hit)
        assert live.host_stat("/Users/a/Downloads/none") is None
        assert list(LiveVfs(os.path.join(td, "Users", "a", "Downloads")).iter_files()) == []       # 탐색 폴더가 없으면 아무것도 읽지 않는다
        d = DirectoryVfs(td); d.host_meta = {"/users/a/downloads/x": {"size": 1}}
        assert d.host_stat("C:" + win) == {"size": 1} and "drive" not in next(d.iter_files()).location()
    assert _registered_package_roots() is not None                                               # 레지스트리가 없어도 예외 없이 목록
    print("vfs self-check ok")
