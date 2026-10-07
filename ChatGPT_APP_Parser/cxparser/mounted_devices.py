"""이미지의 각 NTFS 볼륨이 원래 PC 에서 어떤 드라이브 문자였는지 — SYSTEM 하이브의 MountedDevices 로 알아낸다.

파일시스템 자체에는 드라이브 문자가 없다. 부팅한 Windows 가 `HKLM\\SYSTEM\\MountedDevices` 에
`\\DosDevices\\C:` = 볼륨 식별자 로 기록해 두므로, 그 값을 이미지의 파티션과 맞춘다.
  MBR 디스크: 디스크 서명(섹터 0 의 0x1B8, 4바이트) + 파티션 시작 오프셋(바이트, u64 LE) = 12바이트
  GPT 디스크: b"DMIO:ID:" + 파티션 고유 GUID(GPT 엔트리의 16바이트 그대로) = 24바이트
하이브는 표준 라이브러리만으로 읽는다 (regf 의 nk/vk/lf/lh/li/ri 셀 중 이 키 하나를 찾는 데 필요한 만큼만).
트랜잭션 로그(.LOG1/.LOG2)는 적용하지 않는다 — MountedDevices 는 드라이브 구성이 바뀔 때만 변하므로 보통 하이브 본문과 같다.
"""

import struct

HIVE_PATH = "/Windows/System32/config/SYSTEM"
_HBIN = 0x1000                      # 첫 hbin 의 파일 오프셋. 셀 오프셋은 모두 여기 기준
_PREFIX = "\\dosdevices\\"
_NONE = 0xFFFFFFFF


def _cell(buf, off):
    size = struct.unpack_from("<i", buf, _HBIN + off)[0]
    return buf[_HBIN + off + 4: _HBIN + off + abs(size)]


def _name(cell, off, n, ascii_flag):
    raw = cell[off:off + n]
    return raw.decode("latin-1") if ascii_flag else raw.decode("utf-16le", "replace")


def _subkeys(buf, list_off):
    cell = _cell(buf, list_off)
    sig, n = cell[:2], struct.unpack_from("<H", cell, 2)[0]
    if sig in (b"lf", b"lh"):
        return [struct.unpack_from("<I", cell, 4 + 8 * i)[0] for i in range(n)]
    if sig == b"li":
        return [struct.unpack_from("<I", cell, 4 + 4 * i)[0] for i in range(n)]
    if sig == b"ri":
        return [o for i in range(n) for o in _subkeys(buf, struct.unpack_from("<I", cell, 4 + 4 * i)[0])]
    return []


def _find_key(buf, nk_off, path):
    for part in path:
        cell = _cell(buf, nk_off)
        n_sub, list_off = struct.unpack_from("<I", cell, 0x14)[0], struct.unpack_from("<I", cell, 0x1C)[0]
        for off in (_subkeys(buf, list_off) if n_sub and list_off != _NONE else []):
            c = _cell(buf, off)
            if c[:2] == b"nk" and _name(c, 0x4C, struct.unpack_from("<H", c, 0x48)[0],
                                        struct.unpack_from("<H", c, 2)[0] & 0x20).lower() == part.lower():
                nk_off = off
                break
        else:
            return None
    return nk_off


def _values(buf, nk_off):
    cell = _cell(buf, nk_off)
    count, list_off = struct.unpack_from("<II", cell, 0x24)
    out = {}
    if not count or list_off == _NONE:
        return out
    lst = _cell(buf, list_off)
    for i in range(count):
        vk = _cell(buf, struct.unpack_from("<I", lst, 4 * i)[0])
        if vk[:2] != b"vk":
            continue
        nlen, dlen, doff, _type, flags = struct.unpack_from("<HIIIH", vk, 2)
        data = struct.pack("<I", doff)[:dlen & 0x7FFFFFFF] if dlen & 0x80000000 else _cell(buf, doff)[:dlen]
        out[_name(vk, 0x14, nlen, flags & 1)] = data
    return out


def mounted_devices(hive):
    """SYSTEM 하이브 바이트 → {'C:': 볼륨 식별자 bytes, ...} (\\DosDevices\\X: 값만)."""
    if hive[:4] != b"regf":
        raise ValueError("regf 서명이 아님")
    nk = _find_key(hive, struct.unpack_from("<I", hive, 0x24)[0], ["MountedDevices"])
    if nk is None:
        return {}
    return {name[len(_PREFIX):].upper(): data for name, data in _values(hive, nk).items()
            if name.lower().startswith(_PREFIX)}


def volume_key(img, scheme, sector, offset):
    """이미지의 파티션(시작 오프셋 바이트) → MountedDevices 가 쓰는 볼륨 식별자. 못 만들면 None."""
    if scheme == "MBR":
        return img.read(0x1B8, 4) + struct.pack("<Q", offset)
    if scheme == "GPT":
        hdr = img.read(sector, 0x5C)
        if hdr[:8] != b"EFI PART":
            return None
        entries_lba, count, size = struct.unpack_from("<QII", hdr, 0x48)
        table = img.read(entries_lba * sector, count * size)
        for i in range(count):
            e = table[i * size:(i + 1) * size]
            if struct.unpack_from("<Q", e, 0x20)[0] * sector == offset:
                return b"DMIO:ID:" + e[16:32]
    return None


def _read_all(f):
    size, out = f.info.meta.size, bytearray()
    while len(out) < size:
        chunk = f.read_random(len(out), min(1024 * 1024, size - len(out)))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def assign(img, scheme, sector, volumes):
    """volumes: [(vd, fs)]. SYSTEM 하이브를 찾아 각 vd 에 'drive' 를 채운다. 반환: 근거 설명 (filesystem.drive_letters)."""
    hive = src = None
    for vd, fs in volumes:
        try:
            hive, src = _read_all(fs.open(HIVE_PATH)), vd["index"]
            break
        except Exception:  # noqa: BLE001 — 이 볼륨에는 없음 (데이터·복구 파티션)
            continue
    if hive is None:
        return {"status": "SYSTEM 하이브 없음 — Artifact_path 의 드라이브 문자는 C: 로 가정"}
    try:
        by_key = {data: letter for letter, data in mounted_devices(hive).items()}
    except Exception as exc:  # noqa: BLE001
        return {"status": "SYSTEM 하이브 판독 실패 (%s) — 드라이브 문자는 C: 로 가정" % str(exc)[:100]}
    found = {}
    for vd, _fs in volumes:
        key = volume_key(img, scheme, sector, vd["offset_bytes"])
        letter = by_key.get(key) if key else None
        if letter:
            vd["drive"] = letter
            found["partition %d" % vd["index"]] = letter
    return {"source": "파티션 %d 의 %s, HKLM\\SYSTEM\\MountedDevices \\DosDevices\\X: (%s 와 대조)"
                      % (src, HIVE_PATH, "디스크 서명+파티션 오프셋" if scheme == "MBR" else "GPT 파티션 GUID"),
            "volumes": found,
            "note": "문자가 없는 파티션(복구·예약)은 그대로 두고, 그 파티션의 경로는 C: 로 표기한다"}


def _synthetic_hive():
    """자체 검사용 최소 regf: ROOT ─ lf ─ {Select, MountedDevices(vk ×3)}."""
    cells = bytearray()

    def add(data):
        off = 0x20 + len(cells)
        size = (len(data) + 4 + 7) & ~7
        cells.extend(struct.pack("<i", -size) + data + b"\0" * (size - 4 - len(data)))
        return off

    def nk(name, sub_off, nsub, val_off, nval):
        b = bytearray(0x4C)
        b[0:2] = b"nk"
        struct.pack_into("<H", b, 2, 0x20)
        struct.pack_into("<II", b, 0x14, nsub, 0)
        struct.pack_into("<I", b, 0x1C, sub_off)
        struct.pack_into("<II", b, 0x24, nval, val_off)
        struct.pack_into("<H", b, 0x48, len(name))
        return add(bytes(b) + name.encode())

    def vk(name, data):
        b = bytearray(0x14)
        b[0:2] = b"vk"
        struct.pack_into("<H", b, 2, len(name))
        if len(data) <= 4:                                   # 실제 하이브처럼 4바이트 이하는 오프셋 자리에 inline
            struct.pack_into("<I", b, 4, 0x80000000 | len(data))
            b[8:12] = data.ljust(4, b"\0")
        else:
            struct.pack_into("<II", b, 4, len(data), add(data))
        struct.pack_into("<IH", b, 0xC, 3, 1)
        return add(bytes(b) + name.encode())

    v = [vk("\\DosDevices\\C:", b"\x11\x22\x33\x44" + struct.pack("<Q", 227540992)),
         vk("\\DosDevices\\D:", b"DMIO:ID:" + bytes(range(16))),
         vk("\\??\\Volume{x}", b"zz")]
    vlist = add(struct.pack("<III", *v))
    md = nk("MountedDevices", _NONE, 0, vlist, 3)
    sel = nk("Select", _NONE, 0, _NONE, 0)
    lf = add(b"lf" + struct.pack("<H", 2) + struct.pack("<II", sel, 0) + struct.pack("<II", md, 0))
    root = nk("ROOT", lf, 2, _NONE, 0)
    body = b"hbin" + struct.pack("<II", 0, 0x1000) + b"\0" * 20 + bytes(cells)
    hdr = bytearray(_HBIN)
    hdr[0:4] = b"regf"
    struct.pack_into("<I", hdr, 0x24, root)
    return bytes(hdr) + body + b"\0" * (-len(body) % _HBIN)


if __name__ == "__main__":  # python -m cxparser.mounted_devices — 자체 검사
    md = mounted_devices(_synthetic_hive())
    assert md == {"C:": b"\x11\x22\x33\x44" + struct.pack("<Q", 227540992), "D:": b"DMIO:ID:" + bytes(range(16))}, md

    class _Img:
        def __init__(self, data):
            self.data = data

        def read(self, off, size):
            return self.data[off:off + size]

    mbr = bytearray(512)
    mbr[0x1B8:0x1BC] = b"\x11\x22\x33\x44"
    assert volume_key(_Img(bytes(mbr)), "MBR", 512, 227540992) == md["C:"]
    assert volume_key(_Img(bytes(mbr)), "MBR", 512, 1048576) != md["C:"]
    gpt = bytearray(512 * 4)
    gpt[512:520] = b"EFI PART"
    struct.pack_into("<QII", gpt, 512 + 0x48, 2, 2, 128)
    for i, (first_lba, guid) in enumerate(((34, bytes(range(16, 32))), (2048, bytes(range(16))))):
        e = 1024 + i * 128
        gpt[e + 16:e + 32] = guid
        struct.pack_into("<Q", gpt, e + 0x20, first_lba)
    assert volume_key(_Img(bytes(gpt)), "GPT", 512, 2048 * 512) == md["D:"]
    assert volume_key(_Img(bytes(gpt)), "GPT", 512, 999 * 512) is None
    assert volume_key(_Img(bytes(gpt)), "NONE", 512, 0) is None
    print("mounted_devices self-check ok")
