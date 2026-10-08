"""SYSTEM\\MountedDevices 로 볼륨별 드라이브 문자를 확인하는 로직 검증.

이미지 입력의 Artifact_path 드라이브 문자가 'C: 가정' 이 아니라 레지스트리 실측이 되는지.
공유 구현(parser/mounted_devices.py, ChatGPT Desktop 파서와 동일)의 자체 검사에 더해,
output._winpath 가 location.drive 를 우선 쓰는지와 하이브 없을 때의 폴백을 본다.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import mounted_devices, output  # noqa: E402


def row(path, drive=None, live_root=None):
    loc = {"path": path}
    if drive is not None:
        loc["drive"] = drive
    if live_root is not None:
        loc["live_root"] = live_root
    return {"evidence": {"location": loc}}


class WinPathDriveLetter(unittest.TestCase):
    def test_confirmed_drive_wins(self):
        self.assertEqual(output._winpath(row("/Users/u/x.log", drive="D:")),
                         "D:\\Users\\u\\x.log")

    def test_live_root_used_when_no_drive(self):
        self.assertEqual(output._winpath(row("/Users/u/x.log", live_root="E:")),
                         "E:\\Users\\u\\x.log")

    def test_drive_beats_live_root(self):
        self.assertEqual(output._winpath(row("/a", drive="F:", live_root="C:")), "F:\\a")

    def test_fallback_c_when_nothing(self):
        self.assertEqual(output._winpath(row("/Users/u/x.log")), "C:\\Users\\u\\x.log")

    def test_empty_path_stays_empty(self):
        self.assertEqual(output._winpath(row("")), "")


class MountedDevicesParsing(unittest.TestCase):
    def test_synthetic_hive_round_trip(self):
        md = mounted_devices.mounted_devices(mounted_devices._synthetic_hive())
        self.assertEqual(set(md), {"C:", "D:"})
        self.assertEqual(md["D:"], b"DMIO:ID:" + bytes(range(16)))

    def test_not_a_hive_raises(self):
        with self.assertRaises(ValueError):
            mounted_devices.mounted_devices(b"notregf" + b"\0" * 100)

    def test_gpt_volume_key_matches_partition_guid(self):
        gpt = bytearray(512 * 4)
        gpt[512:520] = b"EFI PART"
        struct.pack_into("<QII", gpt, 512 + 0x48, 2, 2, 128)
        guid = bytes(range(16))
        e = 1024
        gpt[e + 16:e + 32] = guid
        struct.pack_into("<Q", gpt, e + 0x20, 2048)

        class _Img:
            def read(self, off, size):
                return bytes(gpt)[off:off + size]

        self.assertEqual(mounted_devices.volume_key(_Img(), "GPT", 512, 2048 * 512),
                         b"DMIO:ID:" + guid)
        self.assertIsNone(mounted_devices.volume_key(_Img(), "GPT", 512, 999 * 512))

    def test_assign_fills_drive_and_leaves_unknown_partition(self):
        """하이브가 있는 볼륨의 문자는 채우고, MountedDevices 에 없는 파티션은 drive 를 두지 않는다."""
        hive = mounted_devices._synthetic_hive()
        # 합성 하이브의 C: 키 = 디스크서명 0x44332211 + 오프셋 227540992 (MBR)
        mbr = bytearray(512)
        mbr[0x1B8:0x1BC] = b"\x11\x22\x33\x44"

        class _Img:
            def read(self, off, size):
                return bytes(mbr)[off:off + size]

        class _FS:
            def __init__(self, has_hive):
                self._has = has_hive

            def open(self, path):
                if self._has and path == mounted_devices.HIVE_PATH:
                    return _File(hive)
                raise OSError("no hive")

        class _File:
            def __init__(self, data):
                self.data = data
                self.info = type("I", (), {"meta": type("M", (), {"size": len(data)})()})()

            def read_random(self, off, n):
                return self.data[off:off + n]

        v_os = {"index": 2, "offset_bytes": 227540992}
        v_rec = {"index": 3, "offset_bytes": 999999}
        res = mounted_devices.assign(_Img(), "MBR", 512, [(v_os, _FS(True)), (v_rec, _FS(False))])
        self.assertEqual(v_os["drive"], "C:")
        self.assertNotIn("drive", v_rec)
        self.assertEqual(res["volumes"], {"partition 2": "C:"})

    def test_assign_no_hive_reports_assumption(self):
        class _FS:
            def open(self, path):
                raise OSError("no hive")

        class _Img:
            def read(self, off, size):
                return b"\0" * size

        res = mounted_devices.assign(_Img(), "GPT", 512, [({"index": 0, "offset_bytes": 0}, _FS())])
        self.assertIn("SYSTEM 하이브 없음", res["status"])


if __name__ == "__main__":
    unittest.main()
