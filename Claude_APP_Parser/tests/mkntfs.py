"""
검증용 NTFS 디스크 이미지 생성기.

파서를 시험하려면 정답을 아는 이미지가 필요하다. 실제 NTFS 구조를 직접 써서
$MFT·파일·삭제 엔트리·명명 스트림($UsnJrnl:$J)까지 손으로 만든다.
관리자 권한도, 마운트도 필요 없다.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

SECTOR = 512
SPC = 8                       # 클러스터당 섹터
CLUSTER = SECTOR * SPC        # 4096
REC = 1024                    # MFT 레코드 크기
ROOT_REF = 5


def filetime(dt_iso: str) -> int:
    """'2026-08-27T05:01:44' → FILETIME"""
    import datetime as _dt
    dt = _dt.datetime.fromisoformat(dt_iso)
    delta = dt - _dt.datetime(1601, 1, 1)
    return int(delta.total_seconds() * 10_000_000)


def encode_runs(runs: list[tuple[int, int]]) -> bytes:
    """[(lcn, length)] → NTFS 런리스트."""
    out = bytearray()
    prev = 0
    for lcn, ln in runs:
        delta = lcn - prev
        lb = max(1, (ln.bit_length() + 7) // 8)
        ob = max(1, (abs(delta).bit_length() + 8) // 8)   # 부호 여유 1비트
        out.append((ob << 4) | lb)
        out += ln.to_bytes(lb, "little")
        out += delta.to_bytes(ob, "little", signed=True)
        prev = lcn
    out.append(0)
    return bytes(out)


def attr_resident(atype: int, value: bytes, name: str = "", flags: int = 0,
                  attr_id: int = 0) -> bytes:
    nm = name.encode("utf-16-le")
    name_off = 24 + len(nm)
    # 이름 뒤 8바이트 정렬
    pad_name = (-name_off) % 8
    value_off = name_off + pad_name
    total = value_off + len(value)
    total += (-total) % 8
    b = bytearray(total)
    struct.pack_into("<IIBBHHH", b, 0, atype, total, 0, len(name), 24, flags, attr_id)
    if nm:
        b[24:24 + len(nm)] = nm
    struct.pack_into("<IH", b, 16, len(value), value_off)
    b[value_off:value_off + len(value)] = value
    return bytes(b)


def attr_nonresident(atype: int, runs: list[tuple[int, int]], real_size: int,
                     name: str = "", attr_id: int = 0) -> bytes:
    nm = name.encode("utf-16-le")
    name_off = 64 + len(nm)
    run_off = name_off + ((-name_off) % 8)
    rl = encode_runs(runs)
    total = run_off + len(rl)
    total += (-total) % 8
    alloc = sum(ln for _l, ln in runs) * CLUSTER
    last_vcn = max(0, sum(ln for _l, ln in runs) - 1)
    b = bytearray(total)
    struct.pack_into("<IIBBHHH", b, 0, atype, total, 1, len(name), 64, 0, attr_id)
    if nm:
        b[64:64 + len(nm)] = nm
    struct.pack_into("<Q", b, 16, 0)            # start VCN
    struct.pack_into("<Q", b, 24, last_vcn)     # last VCN
    struct.pack_into("<H", b, 32, run_off)      # run list offset
    struct.pack_into("<QQQ", b, 40, alloc, real_size, real_size)
    b[run_off:run_off + len(rl)] = rl
    return bytes(b)


def attr_standard_info(times: tuple[int, int, int, int]) -> bytes:
    v = struct.pack("<QQQQIIIIQQQQ", *times, 0x20, 0, 0, 0, 0, 0, 0, 0)
    return attr_resident(0x10, v, attr_id=0)


def attr_file_name(parent: int, name: str, times: tuple[int, int, int, int],
                   size: int, is_dir: bool) -> bytes:
    nm = name.encode("utf-16-le")
    v = bytearray(66 + len(nm))
    struct.pack_into("<Q", v, 0, parent | (1 << 48))       # 부모 ref + seq 1
    struct.pack_into("<QQQQ", v, 8, *times)
    struct.pack_into("<QQ", v, 40, size, size)
    struct.pack_into("<I", v, 56, 0x10000000 if is_dir else 0x20)
    v[64] = len(name)
    v[65] = 3                                              # namespace: Win32+DOS
    v[66:66 + len(nm)] = nm
    return attr_resident(0x30, bytes(v), attr_id=1)


def make_record(ref: int, attrs: list[bytes], *, in_use: bool = True,
                is_dir: bool = False, seq: int = 1) -> bytes:
    """MFT 레코드 하나. 섹터마다 USA 고정값을 심는다(fixup)."""
    body = b"".join(attrs) + b"\xff\xff\xff\xff\x00\x00\x00\x00"
    usa_count = REC // SECTOR + 1              # 2섹터 + 1
    usa_off = 48
    first_attr = usa_off + 2 * usa_count
    first_attr += (-first_attr) % 8
    used = first_attr + len(body)
    assert used <= REC, f"레코드 {ref} 가 너무 크다: {used}B"

    b = bytearray(REC)
    b[0:4] = b"FILE"
    struct.pack_into("<HH", b, 4, usa_off, usa_count)
    struct.pack_into("<Q", b, 8, 0)                       # LSN
    struct.pack_into("<H", b, 16, seq)
    struct.pack_into("<H", b, 18, 1)                      # hard link count
    struct.pack_into("<H", b, 20, first_attr)
    flags = (1 if in_use else 0) | (2 if is_dir else 0)
    struct.pack_into("<H", b, 22, flags)
    struct.pack_into("<II", b, 24, used, REC)
    struct.pack_into("<Q", b, 32, 0)                      # base record
    struct.pack_into("<I", b, 40, ref)
    b[first_attr:first_attr + len(body)] = body

    # fixup — USA 번호를 각 섹터 끝 2바이트에 넣고 원본은 배열에 보관
    usn = 0x0001
    struct.pack_into("<H", b, usa_off, usn)
    for i in range(1, usa_count):
        end = i * SECTOR - 2
        orig = bytes(b[end:end + 2])
        b[usa_off + 2 * i:usa_off + 2 * i + 2] = orig
        struct.pack_into("<H", b, end, usn)
    return bytes(b)


@dataclass
class Node:
    """이미지에 넣을 파일 또는 폴더 하나."""
    path: str                       # "Users/tester/AppData/.../config.json"
    data: bytes | None = None       # None이면 폴더
    deleted: bool = False
    times: tuple[str, str, str, str] = ("2026-08-27T04:30:00",) * 4
    streams: dict[str, bytes] = field(default_factory=dict)   # 명명 스트림
    fragments: int = 1              # 데이터를 몇 조각으로 흩어 놓을지


class NtfsImageBuilder:
    def __init__(self, volume_mb: int = 64, label: str = "TESTVOL") -> None:
        self.volume_bytes = volume_mb * 1024 * 1024
        self.total_clusters = self.volume_bytes // CLUSTER
        self.label = label
        self.nodes: list[Node] = []

    def add(self, node: Node) -> None:
        self.nodes.append(node)

    # ── 빌드 ──────────────────────────────────────────────────────────
    def build(self) -> bytes:
        # 경로 트리 정리 — 중간 폴더를 자동으로 채운다
        wanted: dict[str, Node] = {}
        for n in self.nodes:
            parts = n.path.strip("/").split("/")
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                wanted.setdefault(d, Node(path=d, data=None))
            wanted[n.path.strip("/")] = n

        ordered = sorted(wanted.values(), key=lambda x: x.path.count("/"))

        # ref 배정: 0=$MFT, 5=root, 16부터 사용자 엔트리
        refs: dict[str, int] = {}
        next_ref = 16
        for n in ordered:
            refs[n.path] = next_ref
            next_ref += 1
        num_records = next_ref + 8

        mft_clusters = (num_records * REC + CLUSTER - 1) // CLUSTER
        mft_lcn = 4                                   # 부트섹터 뒤 여유
        data_lcn = mft_lcn + mft_clusters + 2

        # 파일 데이터 배치
        cluster_cursor = data_lcn
        placements: dict[str, tuple[list[tuple[int, int]], bytes]] = {}
        stream_placements: dict[tuple[str, str], tuple[list[tuple[int, int]], bytes]] = {}
        for n in ordered:
            if n.data is not None and len(n.data) > 600:      # 작은 건 resident
                ln = (len(n.data) + CLUSTER - 1) // CLUSTER
                if n.fragments > 1 and ln >= n.fragments:
                    runs = []
                    per = ln // n.fragments
                    left = ln
                    for k in range(n.fragments):
                        take = per if k < n.fragments - 1 else left
                        if k == 1:
                            # 앞쪽으로 되돌아가는 조각 — 상대 오프셋이 음수가 된다
                            cluster_cursor += 8
                            runs.append((cluster_cursor - 4 - take, take))
                        else:
                            runs.append((cluster_cursor, take))
                            cluster_cursor += take + 3
                        left -= take
                    placements[n.path] = (runs, n.data)
                else:
                    placements[n.path] = ([(cluster_cursor, ln)], n.data)
                    cluster_cursor += ln
            for sname, sdata in n.streams.items():
                ln = (len(sdata) + CLUSTER - 1) // CLUSTER
                stream_placements[(n.path, sname)] = ([(cluster_cursor, ln)], sdata)
                cluster_cursor += ln
        assert cluster_cursor < self.total_clusters, "볼륨이 작다"

        # ── MFT 레코드 만들기 ──────────────────────────────────────────
        records: dict[int, bytes] = {}

        mft_runs = [(mft_lcn, mft_clusters)]
        records[0] = make_record(0, [
            attr_standard_info((filetime("2026-08-27T04:00:00"),) * 4),
            attr_file_name(ROOT_REF, "$MFT", (filetime("2026-08-27T04:00:00"),) * 4,
                           num_records * REC, False),
            attr_nonresident(0x80, mft_runs, num_records * REC, attr_id=2),
        ])
        records[ROOT_REF] = make_record(ROOT_REF, [
            attr_standard_info((filetime("2026-08-27T04:00:00"),) * 4),
            attr_file_name(ROOT_REF, ".", (filetime("2026-08-27T04:00:00"),) * 4,
                           0, True),
        ], is_dir=True)

        for n in ordered:
            ref = refs[n.path]
            parent_path = "/".join(n.path.split("/")[:-1])
            parent_ref = refs.get(parent_path, ROOT_REF)
            name = n.path.split("/")[-1]
            times = tuple(filetime(t) for t in n.times)
            attrs = [attr_standard_info(times),
                     attr_file_name(parent_ref, name, times,
                                    len(n.data or b""), n.data is None)]
            if n.data is not None:
                if n.path in placements:
                    runs, _ = placements[n.path]
                    attrs.append(attr_nonresident(0x80, runs, len(n.data), attr_id=2))
                else:
                    attrs.append(attr_resident(0x80, n.data, attr_id=2))
            for sname in n.streams:
                runs, sdata = stream_placements[(n.path, sname)]
                attrs.append(attr_nonresident(0x80, runs, len(sdata), name=sname,
                                              attr_id=3))
            records[ref] = make_record(ref, attrs, in_use=not n.deleted,
                                       is_dir=n.data is None)

        # ── 볼륨 이미지 조립 ──────────────────────────────────────────
        vol = bytearray(self.volume_bytes)

        # 부트섹터
        vol[3:11] = b"NTFS    "
        struct.pack_into("<H", vol, 11, SECTOR)
        vol[13] = SPC
        struct.pack_into("<H", vol, 14, 0)
        vol[21] = 0xF8
        struct.pack_into("<Q", vol, 40, self.total_clusters * SPC - 1)
        struct.pack_into("<Q", vol, 48, mft_lcn)
        struct.pack_into("<Q", vol, 56, mft_lcn + mft_clusters)   # $MFTMirr
        vol[64] = 246                     # 2^(256-246)=1024B 레코드
        vol[68] = 1                       # 인덱스 버퍼
        struct.pack_into("<Q", vol, 72, 0x1122334455667788)
        struct.pack_into("<H", vol, 510, 0xAA55)

        # MFT 기록
        for ref, rec in records.items():
            off = mft_lcn * CLUSTER + ref * REC
            vol[off:off + REC] = rec

        # 파일 데이터 기록
        for runs, data in list(placements.values()) + list(stream_placements.values()):
            pos = 0
            for lcn, ln in runs:
                chunk = data[pos:pos + ln * CLUSTER]
                off = lcn * CLUSTER
                vol[off:off + len(chunk)] = chunk
                pos += ln * CLUSTER

        return bytes(vol)

    def build_into(self, path, gap_mb: int = 1) -> "Path":
        """
        큰 이미지를 만들 때 쓴다. 메모리에 볼륨 전체를 들지 않고
        필요한 자리에만 써 넣는다. 디스크에서도 희소 파일로 남는다.
        """
        from pathlib import Path as _P
        path = _P(path)
        data = self.build()
        gap = gap_mb * 1024 * 1024
        with path.open("wb") as f:
            f.truncate(gap + len(data))
            f.seek(446)
            f.write(struct.pack("<BBBBBBBBII", 0, 0, 0, 0, 0x07, 0xFF, 0xFF, 0xFF,
                                gap // SECTOR, len(data) // SECTOR))
            f.seek(510)
            f.write(bytes([0x55, 0xAA]))
            f.seek(gap)
            f.write(data)
        return path


def wrap_mbr(volume: bytes, gap_mb: int = 1) -> bytes:
    """볼륨을 MBR 디스크 이미지로 감싼다."""
    gap = gap_mb * 1024 * 1024
    mbr = bytearray(gap)
    start_lba = gap // SECTOR
    sectors = len(volume) // SECTOR
    entry = struct.pack("<BBBBBBBBII", 0x80, 0, 0, 0, 0x07, 0xFE, 0xFF, 0xFF,
                        start_lba, sectors)
    mbr[446:462] = entry
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr) + volume
