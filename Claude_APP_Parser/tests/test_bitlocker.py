"""BitLocker 이미지 입력 검증.

  python -m unittest discover -s tests -v

BitLocker 테스트 볼륨(dissect.fve 공개 데이터)을 처음 한 번 내려받는다. 내려받지 못하면
(오프라인) 볼륨이 필요한 시험은 건너뛰고 그 사실을 출력한다.
"""

import contextlib
import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bde_fixture  # noqa: E402
from parser import bitlocker, cli  # noqa: E402
from parser.errors import VolumeLockedError  # noqa: E402
from parser.image import open_image  # noqa: E402
from parser.vfs import TskImageVfs  # noqa: E402

WRONG_RECOVERY = "recovery:111111-222222-333333-444444-555555-666666-777777-888888"

# 평문 NTFS 에서 나와야 하는 행 (Timestamp, User_behavior, Verdict, Artifact_path)
EXPECTED_ROWS = [
    ("2026-09-23 13:03:58.000000 KST", "애플리케이션 실행", "의심",
     r"C:\Users\tester\AppData\Local\Claude\logs\main.log"),
    ("2026-09-23 13:04:10.000000 KST", "로그인", "확정",
     r"C:\Users\tester\AppData\Local\Claude\logs\main.log"),
    ("2026-09-23 13:24:50.000000 KST", "정상 종료", "확정",
     r"C:\Users\tester\AppData\Roaming\Claude\config.json"),
    ("2026-09-23 13:24:51.000000 KST", "정상 종료", "확정",
     r"C:\Users\tester\AppData\Local\Claude\logs\main.log"),
]

_FETCH_ERROR = None
_CACHE = {}


def setUpModule():
    global _FETCH_ERROR
    try:
        bde_fixture.fetch()
    except OSError as exc:
        _FETCH_ERROR = "BitLocker 테스트 볼륨을 내려받지 못함: %s" % exc


def volume(method):
    """method 로 풀리는 BitLocker 볼륨 (안에 합성 Claude NTFS). 같은 실행 안에서는 한 번만 만든다."""
    if _FETCH_ERROR:
        raise unittest.SkipTest(_FETCH_ERROR)
    if method not in _CACHE:
        _CACHE[method] = bde_fixture.bitlocker_volume(method)
    return _CACHE[method]


def run_cli(*args, env=None):
    """cli.main 을 돌려 (종료코드, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}, clear=False), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if env is None:
            os.environ.pop(bitlocker.KEY_ENV, None)
        code = cli.main(list(args) + ["--no-banner"])
    return code, out.getvalue(), err.getvalue()


def timeline_rows(out_dir):
    with open(os.path.join(out_dir, "timeline.csv"), encoding="utf-8-sig", newline="") as fh:
        return [(r["Timestamp"], r["User_behavior"], r["Verdict"], r["Artifact_path"])
                for r in csv.DictReader(fh)]


class _TmpDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cl_bde_test_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p


class SelfCheck(unittest.TestCase):
    def test_fast_xts_matches_dissect(self):
        with contextlib.redirect_stdout(io.StringIO()):
            bitlocker.demo()


class PlainImageUnchanged(_TmpDir):
    """평문 이미지는 BitLocker 처리가 끼어도 결과가 그대로여야 한다."""

    def test_plain_ntfs(self):
        img = self.write("plain.dd", bde_fixture.mbr_disk(bde_fixture.plain_ntfs()))
        out = os.path.join(self.tmp, "out")
        code, _o, err = run_cli("-i", img, "-o", out)
        self.assertEqual(code, 0, err)
        self.assertEqual(timeline_rows(out), EXPECTED_ROWS)


class EndToEnd(_TmpDir):
    def disk(self, method="recovery"):
        vol, key = volume(method)
        return self.write("bl.dd", bde_fixture.mbr_disk(vol)), key

    def test_recovery_key_gives_same_rows_as_plain(self):
        img, key = self.disk()
        out = os.path.join(self.tmp, "out")
        code, stdout, err = run_cli("-i", img, "-o", out, "--format", "both",
                                    "--key-material", key)
        self.assertEqual(code, 0, err)
        self.assertEqual(timeline_rows(out), EXPECTED_ROWS)
        self.assertIn("BitLocker : 파티션 0 해제 (recovery)", stdout)
        with open(os.path.join(out, "result.json"), encoding="utf-8") as fh:
            raw = fh.read()
        result = json.loads(raw)
        vd = result["filesystem"]["volumes"][0]
        self.assertEqual((vd["encryption"], vd["unlock_method"]), ("BitLocker", "recovery"))
        self.assertTrue(vd["protectors"]["recovery_password"])
        # 키 값은 결과 어디에도 남지 않는다
        self.assertNotIn(bde_fixture.RECOVERY, raw)
        self.assertNotIn(bde_fixture.RECOVERY, stdout + err)
        # 탐색 경로(SCAN_ROOTS) 밖의 다른 제품(~/.claude) 은 열거하지도 않는다
        self.assertEqual(result["scan"]["files_scanned"], 2)

    def test_key_from_environment(self):
        img, key = self.disk()
        out = os.path.join(self.tmp, "out")
        code, _o, err = run_cli("-i", img, "-o", out, env={bitlocker.KEY_ENV: key})
        self.assertEqual(code, 0, err)
        self.assertEqual(timeline_rows(out), EXPECTED_ROWS)

    def test_no_key_is_locked_not_empty(self):
        """키가 없으면 '아티팩트 없음' 이 아니라 잠김으로 멈춘다 (오탐·미탐 방지)."""
        img, _key = self.disk()
        out = os.path.join(self.tmp, "out")
        code, _o, err = run_cli("-i", img, "-o", out)
        self.assertEqual(code, 2)
        payload = json.loads(err)
        self.assertEqual(payload["code"], "VOLUME_LOCKED")
        locked = payload["context"]["volumes"][0]
        self.assertTrue(locked["protectors"]["recovery_password"])
        self.assertFalse(os.path.exists(os.path.join(out, "timeline.csv")))

    def test_wrong_key_is_locked_and_not_echoed(self):
        img, _key = self.disk()
        code, stdout, err = run_cli("-i", img, "-o", os.path.join(self.tmp, "out"),
                                    "--key-material", WRONG_RECOVERY)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["code"], "VOLUME_LOCKED")
        self.assertNotIn(WRONG_RECOVERY.split(":", 1)[1], stdout + err)

    def test_bad_key_format(self):
        img, _key = self.disk()
        code, _o, err = run_cli("-i", img, "-o", os.path.join(self.tmp, "out"),
                                "--key-material", "password:abc")
        self.assertEqual(code, 2)
        self.assertIn("recovery: / passphrase: / bek: / fvek:", json.loads(err)["message"])

    def test_plain_volume_beside_locked_volume_stops(self):
        """평문 NTFS 만 읽고 결론 내리지 않는다 — 잠긴 볼륨이 있으면 키를 요구한다."""
        vol, key = volume("recovery")
        img = self.write("two.dd", bde_fixture.mbr_disk(bde_fixture.plain_ntfs(), vol))
        code, _o, err = run_cli("-i", img, "-o", os.path.join(self.tmp, "out"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["code"], "VOLUME_LOCKED")
        out = os.path.join(self.tmp, "out2")
        code, _o, err = run_cli("-i", img, "-o", out, "--format", "json", "--key-material", key)
        self.assertEqual(code, 0, err)
        with open(os.path.join(out, "result.json"), encoding="utf-8") as fh:
            vols = json.load(fh)["filesystem"]["volumes"]
        self.assertEqual([v.get("encryption") for v in vols], [None, "BitLocker"])


class UnlockMethods(_TmpDir):
    """해제 방식별로 볼륨이 열리고 Claude 파일이 보이는지 (파이프라인 아래 층)."""

    def files(self, method, key_material):
        vol, _key = volume(method)
        img = open_image(self.write("v.dd", vol))      # 파티션 테이블 없는 볼륨 이미지
        self.addCleanup(img.close)
        vfs = TskImageVfs(img, key_material=key_material)
        return vfs, sorted(f.path for f in vfs.iter_files())

    def check(self, method, key_material, expect_method):
        vfs, paths = self.files(method, key_material)
        self.assertEqual(vfs.volumes[0][0]["unlock_method"], expect_method)
        self.assertIn("/Users/tester/AppData/Local/Claude/logs/main.log", paths)
        self.assertIn("/Users/tester/AppData/Roaming/Claude/config.json", paths)

    def test_passphrase(self):
        self.check("passphrase", volume("passphrase")[1], "passphrase")

    def test_bek_file(self):
        self.check("bek", volume("bek")[1], "bek")

    def test_clear_key_needs_no_key(self):
        self.check("clear_key", None, "clear_key")

    def test_decrypted_state_needs_no_key(self):
        self.check("decrypted_state", None, "decrypted_state")

    def test_missing_library_is_locked(self):
        vol, key = volume("recovery")
        img = open_image(self.write("v.dd", vol))
        self.addCleanup(img.close)
        with mock.patch.dict(sys.modules, {"dissect.fve.bde": None}):
            with self.assertRaises(VolumeLockedError) as cm:
                TskImageVfs(img, key_material=key)
        self.assertIn("dissect.fve", cm.exception.message)


if __name__ == "__main__":
    unittest.main()
