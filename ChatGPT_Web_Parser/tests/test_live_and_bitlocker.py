"""Live 수집(chatgpt_parser/live.py) 과 BitLocker 지원(chatgpt_parser/bitlocker.py) 테스트.

실제 BitLocker 이미지는 저장소에 없다 — 해제 성공 경로는 여기서 검증하지 않는다 (보고서에 NOT TESTED).
여기서 지키는 것: 감지·키 규약·잠김 상태 반환·키 미노출, 그리고 Live 수집의 탐색/사본/원본 보호.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chatgpt_parser import bitlocker, live                      # noqa: E402
from chatgpt_parser.artifacts.cache import CACHE_DIR_PARTS      # noqa: E402
from chatgpt_parser.artifacts.local_storage import LOCAL_STORAGE_DIR_PARTS  # noqa: E402
from chatgpt_parser.artifacts.session_storage import SESSION_STORAGE_DIR_PARTS  # noqa: E402
from chatgpt_parser.artifacts.sessions import SESSIONS_DIR_PARTS  # noqa: E402
from chatgpt_parser.artifacts.shared_proto_db import SHARED_PROTO_DB_DIR_PARTS  # noqa: E402
from chatgpt_parser.discovery import CHROME_USER_DATA_PARTS     # noqa: E402

SECRET_RECOVERY = "123456-123456-123456-123456-123456-123456-123456-123456"


class FakeImage:
    """pytsk3.Img_Info 처럼 read(offset, size) 를 주는 최소 더블."""

    def __init__(self, data: bytes):
        self.data = data

    def read(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]


def bitlocker_boot_sector() -> bytes:
    return b"\xeb\x58\x90" + bitlocker.SIGNATURE + bytes(512 - 11)


def ntfs_boot_sector() -> bytes:
    return b"\xeb\x52\x90" + b"NTFS    " + bytes(512 - 11)


class BitLockerDetectionTest(unittest.TestCase):
    def test_detects_fve_signature(self):
        self.assertTrue(bitlocker.is_bitlocker(FakeImage(bitlocker_boot_sector()), 0))

    def test_ntfs_volume_is_not_bitlocker(self):
        self.assertFalse(bitlocker.is_bitlocker(FakeImage(ntfs_boot_sector()), 0))

    def test_detection_uses_the_partition_offset(self):
        image = FakeImage(ntfs_boot_sector() + bitlocker_boot_sector())
        self.assertFalse(bitlocker.is_bitlocker(image, 0))
        self.assertTrue(bitlocker.is_bitlocker(image, 512))

    def test_image_without_read_is_not_bitlocker(self):
        """read() 가 없는 이미지 구현에서도 전체 분석을 멈추지 않는다."""
        self.assertFalse(bitlocker.is_bitlocker(object(), 0))

    def test_read_error_is_not_a_detection(self):
        class Broken:
            def read(self, offset, size):
                raise OSError("unreadable")

        self.assertFalse(bitlocker.is_bitlocker(Broken(), 0))


class BitLockerKeyContractTest(unittest.TestCase):
    """키 규약은 팀 공통(recovery:/passphrase:/bek:/fvek: + ERELM_KEY_MATERIAL) 을 따른다."""

    def test_key_kinds_match_the_team_contract(self):
        self.assertEqual(bitlocker.KEY_KINDS, ("recovery", "passphrase", "bek", "fvek"))
        self.assertEqual(bitlocker.KEY_ENV, "ERELM_KEY_MATERIAL")

    def test_key_kind_reports_only_the_kind(self):
        self.assertEqual(bitlocker.key_kind(f"recovery:{SECRET_RECOVERY}"), "recovery")
        self.assertEqual(bitlocker.key_kind("passphrase:hunter2"), "passphrase")
        self.assertEqual(bitlocker.key_kind("bek:C:/keys/x.BEK"), "bek")
        self.assertEqual(bitlocker.key_kind("fvek:00ff"), "fvek")

    def test_unknown_or_empty_key_format_is_rejected(self):
        for value in ("", None, "recovery", "nonsense:zzz", ":value"):
            self.assertIsNone(bitlocker.key_kind(value), value)

    def test_command_line_key_wins_over_environment(self):
        os.environ[bitlocker.KEY_ENV] = "passphrase:from-env"
        try:
            self.assertEqual(bitlocker.key_material_from_env("recovery:from-cli"), "recovery:from-cli")
            self.assertEqual(bitlocker.key_material_from_env(None), "passphrase:from-env")
        finally:
            del os.environ[bitlocker.KEY_ENV]

    def test_missing_environment_key_is_none(self):
        os.environ.pop(bitlocker.KEY_ENV, None)
        self.assertIsNone(bitlocker.key_material_from_env(None))


class BitLockerLockedVolumeTest(unittest.TestCase):
    """키가 없거나 맞지 않으면 명확히 잠김으로 돌려보낸다 — 우회·무차별 대입을 하지 않는다."""

    def _open(self, key_material=None):
        image = FakeImage(bitlocker_boot_sector() + bytes(4096))
        return bitlocker.open_volume(image, 0, 4096 + 512, key_material)

    def test_locked_volume_without_key_raises(self):
        with self.assertRaises(bitlocker.VolumeLockedError):
            self._open(None)

    def test_wrong_key_does_not_crash_the_run(self):
        with self.assertRaises(bitlocker.VolumeLockedError):
            self._open(f"recovery:{SECRET_RECOVERY}")

    def test_error_message_never_contains_the_key(self):
        for key in (f"recovery:{SECRET_RECOVERY}", "passphrase:hunter2", "fvek:00ff00ff"):
            with self.subTest(key=bitlocker.key_kind(key)):
                try:
                    self._open(key)
                except bitlocker.VolumeLockedError as exc:
                    message = str(exc)
                    self.assertNotIn(SECRET_RECOVERY, message)
                    self.assertNotIn("hunter2", message)
                    self.assertNotIn("00ff00ff", message)
                    self.assertNotIn(key.partition(":")[2], message)

    def test_unsupported_key_format_is_reported_without_the_value(self):
        try:
            self._open("madeup:secret-value")
        except bitlocker.VolumeLockedError as exc:
            self.assertNotIn("secret-value", str(exc))


class LiveArtifactListTest(unittest.TestCase):
    """수집 대상은 파서가 실제로 읽는 Artifact 와 같아야 한다 (예시 목록을 베끼지 않는다)."""

    def test_directories_match_the_reader_constants(self):
        self.assertEqual(set(live.LIVE_PROFILE_DIRS),
                         {LOCAL_STORAGE_DIR_PARTS, SESSION_STORAGE_DIR_PARTS, CACHE_DIR_PARTS,
                          SHARED_PROTO_DB_DIR_PARTS, SESSIONS_DIR_PARTS})

    def test_history_is_collected_as_a_profile_file(self):
        self.assertIn("History", live.LIVE_PROFILE_FILES)


class LiveCollectionTest(unittest.TestCase):
    """가짜 Chrome 구조로 탐색·사본·원본 보호를 확인한다 (실제 PC 를 건드리지 않는다)."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def make_profile(self, user: str, profile: str, *, history=True, cache=True) -> Path:
        base = self.root.joinpath("home", user, *CHROME_USER_DATA_PARTS, profile)
        base.mkdir(parents=True, exist_ok=True)
        if history:
            (base / "History").write_bytes(b"SQLite format 3\x00")
        if cache:
            cache_dir = base.joinpath(*CACHE_DIR_PARTS)
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / "data_0").write_bytes(b"cache")
        return base

    def live_profile(self, user: str, profile: str) -> live.LiveProfile:
        path = self.root.joinpath("home", user, *CHROME_USER_DATA_PARTS, profile)
        return live.LiveProfile(os_user=user, browser_profile=profile, profile_path=path,
                                artifacts=live._profile_artifacts(path))

    def test_collects_into_the_folder_mode_layout(self):
        self.make_profile("alice", "Default")
        work = self.root / "work"
        collection = live.collect_live_artifacts(work, [self.live_profile("alice", "Default")])
        copied = work.joinpath("Users", "alice", *CHROME_USER_DATA_PARTS, "Default")
        self.assertTrue((copied / "History").is_file())
        self.assertTrue(copied.joinpath(*CACHE_DIR_PARTS, "data_0").is_file())
        self.assertEqual(collection.failed, [])
        self.assertFalse(collection.temporary)

    def test_multiple_profiles_and_users_are_kept_apart(self):
        self.make_profile("alice", "Default")
        self.make_profile("alice", "Profile 1")
        self.make_profile("bob", "Profile 2")
        work = self.root / "work"
        profiles = [self.live_profile("alice", "Default"), self.live_profile("alice", "Profile 1"),
                    self.live_profile("bob", "Profile 2")]
        live.collect_live_artifacts(work, profiles)
        for user, profile in (("alice", "Default"), ("alice", "Profile 1"), ("bob", "Profile 2")):
            with self.subTest(user=user, profile=profile):
                self.assertTrue(work.joinpath("Users", user, *CHROME_USER_DATA_PARTS, profile, "History").is_file())

    def test_missing_artifacts_are_skipped_without_failing(self):
        self.make_profile("carol", "Default", cache=False)
        work = self.root / "work"
        collection = live.collect_live_artifacts(work, [self.live_profile("carol", "Default")])
        copied = work.joinpath("Users", "carol", *CHROME_USER_DATA_PARTS, "Default")
        self.assertTrue((copied / "History").is_file())
        self.assertFalse(copied.joinpath(*CACHE_DIR_PARTS).exists())
        self.assertEqual(collection.failed, [])

    def test_profile_with_no_relevant_artifact_is_not_collected(self):
        base = self.root.joinpath("home", "dave", *CHROME_USER_DATA_PARTS, "Default")
        base.mkdir(parents=True)
        (base / "Preferences").write_text("{}", encoding="utf-8")   # 파서가 쓰지 않는 파일
        self.assertEqual(live._profile_artifacts(base), [])

    def test_originals_are_not_modified(self):
        profile = self.make_profile("erin", "Default")
        before = {path: (path.stat().st_size, path.stat().st_mtime_ns)
                  for path in sorted(profile.rglob("*")) if path.is_file()}
        live.collect_live_artifacts(self.root / "work", [self.live_profile("erin", "Default")])
        after = {path: (path.stat().st_size, path.stat().st_mtime_ns)
                 for path in sorted(profile.rglob("*")) if path.is_file()}
        self.assertEqual(before, after)

    def test_copy_failure_is_recorded_and_does_not_stop_the_run(self):
        self.make_profile("frank", "Default")
        work = self.root / "work"
        original = live._copy_file

        def flaky(src, dest, collection, rel):
            if rel.endswith("History"):
                collection.failed.append((rel, "PermissionError"))
                return
            original(src, dest, collection, rel)

        live._copy_file = flaky
        try:
            collection = live.collect_live_artifacts(work, [self.live_profile("frank", "Default")])
        finally:
            live._copy_file = original
        self.assertTrue(any(rel.endswith("History") for rel, _ in collection.failed))
        self.assertTrue(work.joinpath("Users", "frank", *CHROME_USER_DATA_PARTS, "Default",
                                      *CACHE_DIR_PARTS, "data_0").is_file())

    def test_summary_has_no_file_contents(self):
        self.make_profile("gina", "Default")
        collection = live.collect_live_artifacts(self.root / "work", [self.live_profile("gina", "Default")])
        text = "\n".join(live.summarize(collection))
        self.assertIn("Profiles", text)
        self.assertNotIn("SQLite format 3", text)
        self.assertNotIn("cache", text.replace("Cache", ""))   # 파일 내용이 섞이지 않는다


class LiveDiscoveryTest(unittest.TestCase):
    def test_chrome_user_data_dirs_needs_the_real_layout(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self.assertEqual(live.chrome_user_data_dirs(home), [])
            home.joinpath(*CHROME_USER_DATA_PARTS).mkdir(parents=True)
            self.assertEqual(live.chrome_user_data_dirs(home), [home.joinpath(*CHROME_USER_DATA_PARTS)])

    @unittest.skipUnless(os.name == "nt", "Windows 전용 탐색")
    def test_user_profile_roots_finds_the_current_home(self):
        roots = {os.path.normcase(str(path)) for path in live.user_profile_roots()}
        self.assertIn(os.path.normcase(str(Path.home())), roots)

    @unittest.skipIf(os.name == "nt", "Windows 가 아닐 때만 확인한다")
    def test_live_requires_windows(self):
        with self.assertRaises(live.LiveAcquisitionError):
            live.discover_live_profiles()


if __name__ == "__main__":
    unittest.main()
