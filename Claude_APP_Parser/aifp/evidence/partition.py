"""
파티션 표 해석과 볼륨 뷰.

컨테이너(.dd / .E01)가 어떤 형식이든 이 두 가지는 똑같이 필요하다.
MBR·GPT를 읽어 파티션 목록을 만들고, 그중 하나를 볼륨처럼 읽게 감싼다.
"""

from __future__ import annotations

import struct


class Volume:
    """컨테이너 위의 파티션 하나. 볼륨 기준 오프셋으로 읽게 해 준다."""

    def __init__(self, container, start_bytes: int, length_bytes: int) -> None:
        self.c = container
        self.start = start_bytes
        self.length = length_bytes

    def read(self, off: int, n: int) -> bytes:
        return self.c.read(self.start + off, n)


def partitions(container) -> list[tuple[int, int, int, str]]:
    """
    (번호, 시작 바이트, 크기 바이트, 종류)의 목록.

    GPT 보호 MBR(타입 0xEE)이 보이면 GPT로, 아니면 MBR로 읽는다.
    서명이 없으면 빈 목록을 돌려주고, 판단은 호출부가 한다.
    """
    mbr = container.read(0, 512)
    parts: list[tuple[int, int, int, str]] = []
    if mbr[510:512] != b"\x55\xaa":
        return parts

    is_gpt = any(mbr[446 + 16 * i + 4] == 0xEE for i in range(4))

    if is_gpt:
        hdr = container.read(512, 512)
        if hdr[:8] == b"EFI PART":
            plba = struct.unpack_from("<Q", hdr, 72)[0]
            nent = struct.unpack_from("<I", hdr, 80)[0]
            esz = struct.unpack_from("<I", hdr, 84)[0]
            # 헤더 값이 손상되면 수십 TB를 읽으라는 요구가 된다. 규격상
            # 항목은 128바이트, 개수는 128개가 보통이므로 그 언저리로 자른다.
            size = getattr(container, "size", 0) or 0
            if not (128 <= esz <= 4096):
                esz = 128
            nent = max(0, min(nent, 1024))
            if size and plba * 512 >= size:
                return parts
            want = nent * esz
            if size:
                want = min(want, max(0, size - plba * 512))
            tbl = container.read(plba * 512, want)
            nent = min(nent, len(tbl) // esz if esz else 0)
            for i in range(nent):
                e = tbl[i * esz:(i + 1) * esz]
                if len(e) < 128 or e[:16] == b"\0" * 16:
                    continue
                first, last = struct.unpack_from("<QQ", e, 32)
                name = e[56:128].decode("utf-16le", "replace").rstrip("\0")
                parts.append((i, first * 512, (last - first + 1) * 512, name))
    else:
        for i in range(4):
            e = mbr[446 + 16 * i: 446 + 16 * (i + 1)]
            typ = e[4]
            if typ == 0:
                continue
            lba, cnt = struct.unpack_from("<II", e, 8)
            parts.append((i, lba * 512, cnt * 512, f"MBR type 0x{typ:02x}"))
    return parts
