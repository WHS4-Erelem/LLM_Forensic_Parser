"""
chatgpt_web_parser.py 테스트 (표준 unittest)

실행 (프로젝트 루트에서):
    python -B -m unittest discover -s tests -v

S1: Result Model 테스트
S2: Timestamp Normalizer 테스트
S3: Source Interface + DirectorySource + SQLite 메모리 열기 테스트 (임시 폴더 synthetic 데이터)
S4: Chrome History Reader 테스트 (synthetic History DB)
S5: CHATGPT_LOGOUT_001 Rule 테스트 (ArtifactRecord → Event)
S6: extract / detect / run / CLI 테스트, Conversation Result Model 테스트 (추출 기능 아님)
S7: Windows User / Chrome Profile Discovery, Auto Discovery Mode 테스트 (synthetic Users 트리)
S8: History Event Rule 확대 테스트
S9-pre: LevelDB .log Reader / Local Storage Reader / Conversation Residue Extraction 테스트 (테스트가 만든 .log bytes)
S10: DD/RAW Image — pytsk3 를 흉내 낸 fake module (파티션·NTFS mock) + 실제 pytsk3 로 작은 synthetic MBR/GPT 파티션 표
실제 Evidence 파일을 읽지 않는다.
Fixture 값은 수동 분석에서 이미 확인된 값을 예시 데이터로 사용한 것이다 (synthetic).
"""

import contextlib
import csv
import dataclasses
import gc
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import chatgpt_web_parser as p  # noqa: E402

LOGOUT_URL = "https://chatgpt.com/auth/logout"
LOGOUT_RAW = "13432494600507032"  # webkit_us, History visits.id=42 에서 확인된 값
LOGOUT_UTC = "2026-08-29T16:30:00.507032Z"
LOGOUT_KST = "2026-08-30T01:30:00.507032+09:00"
HISTORY_PATH = "Users/<user>/AppData/Local/Google/Chrome/User Data/Default/History"


def make_record(**overrides):
    values = dict(
        record_id="r1",
        artifact_type="history",
        browser_profile="Default",
        source_path=HISTORY_PATH,
        record_location="visits.id=42",
        timestamp_raw=LOGOUT_RAW,
        timestamp_utc=LOGOUT_UTC,
        timestamp_kst=LOGOUT_KST,
        timestamp_type="webkit_us",
        timestamp_source="History.visits.visit_time",
        observed={"url": LOGOUT_URL, "transition": "0x30000000", "title": "로그아웃"},
    )
    values.update(overrides)
    return p.ArtifactRecord(**values)


def make_evidence(**overrides):
    values = dict(
        evidence_id="ev1",
        record_id="r1",
        evidence_level="DIRECT",
        artifact_type="history",
        source_path=HISTORY_PATH,
        record_location="visits.id=42",
        timestamp_raw=LOGOUT_RAW,
        timestamp_utc=LOGOUT_UTC,
        timestamp_kst=LOGOUT_KST,
        timestamp_type="webkit_us",
        timestamp_source="History.visits.visit_time",
        observed={"url": LOGOUT_URL, "transition": "0x30000000"},
        note="originator_cache_guid 빈 값",
    )
    values.update(overrides)
    return p.EvidenceItem(**values)


def make_event(**overrides):
    values = dict(
        event_id="e1",
        finding_type="USER_ACTION",
        action="LOGOUT",
        action_status="DETECTED",
        timestamp_raw=LOGOUT_RAW,
        timestamp_utc=LOGOUT_UTC,
        timestamp_kst=LOGOUT_KST,
        timestamp_type="webkit_us",
        timestamp_source="History.visits.visit_time",
        representative_evidence_id="ev1",
        confidence="HIGH",
        confidence_reason=["RULE_VERIFIED", "DIRECT_URL", "TIMESTAMP_EXPLAINED", "NO_KNOWN_CONTRADICTION"],
        rule_id="CHATGPT_LOGOUT_001",
        rule_verification="VERIFIED",
        browser_profile="Default",
        device_attribution="LOCAL",
        primary_evidence=[make_evidence()],
        supporting_evidence=[
            make_evidence(
                evidence_id="ev2",
                record_id=None,
                evidence_level="SUPPORTING",
                artifact_type="local_storage",
                source_path="Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb",
                record_location="key=nextauth.message",
                timestamp_raw="1788021002",
                timestamp_utc="2026-08-29T16:30:02Z",
                timestamp_kst="2026-08-30T01:30:02+09:00",
                timestamp_type="unix_s",
                timestamp_source="nextauth.message.timestamp",
                observed={"trigger": "signout"},
                note=None,
            )
        ],
    )
    values.update(overrides)
    return p.Event(**values)


def make_candidate_delete_event():
    """삭제 시각이 없는 CANDIDATE Event (timestamp 모두 None)."""
    return p.Event(
        event_id="e2",
        finding_type="USER_ACTION",
        action="CONVERSATION_DELETE",
        action_status="CANDIDATE",
        confidence="LOW",
        confidence_reason=["RULE_PARTIALLY_VERIFIED", "INFERRED_ONLY", "TIMESTAMP_MISSING"],
        rule_id="CHATGPT_CONVERSATION_DELETE_001",
        rule_verification="PARTIALLY_VERIFIED",
        supporting_evidence=[
            make_evidence(
                evidence_id="ev3",
                evidence_level="INFERRED",
                artifact_type="local_storage",
                source_path="Local Storage/leveldb/000014.ldb",
                record_location=None,
                timestamp_raw=None,
                timestamp_utc=None,
                timestamp_kst=None,
                timestamp_type="unknown",
                timestamp_source=None,
                observed={"conversation_title": "안녕 인사 응답"},
                note=None,
            )
        ],
        inference="최신 대화 목록에 없고 잔존 위치에만 있어 삭제와 양립함 (확정 아님)",
        limitations=["삭제 시각 미확인"],
    )


def make_result():
    return p.ParseResult(
        run_id="run-test-1",
        run_started_utc="2026-09-14T00:00:00Z",
        input=p.InputInfo(kind="directory", path="synthetic"),
        coverage=[
            p.Coverage(artifact_type="history", source_path=HISTORY_PATH, status="PARSED", record_count=1),
            p.Coverage(artifact_type="session_storage", source_path="Session Storage", status="NOT_PRESENT"),
        ],
        records=[make_record()],
        events=[make_event(), make_candidate_delete_event()],
        warnings=["테스트 경고"],
    )


# =============================================================================
# S1 — Result Model
# =============================================================================


class ResultModelTest(unittest.TestCase):
    # 1
    def test_parse_result_created(self):
        result = make_result()
        self.assertEqual(result.parser_name, "chatgpt_web_parser")
        self.assertEqual(result.display_timezone, "+09:00 (KST)")
        self.assertEqual(len(result.coverage), 2)
        self.assertEqual(len(result.events), 2)

    # 2
    def test_artifact_record_created(self):
        record = make_record()
        self.assertEqual(record.service, "chatgpt_web")
        self.assertEqual(record.browser, "chrome")
        self.assertEqual(record.observed["url"], LOGOUT_URL)

    # 3
    def test_evidence_item_created(self):
        evidence = make_evidence()
        self.assertEqual(evidence.evidence_level, "DIRECT")
        self.assertEqual(evidence.record_location, "visits.id=42")

    # 4
    def test_event_created(self):
        event = make_event()
        self.assertEqual(event.action, "LOGOUT")
        self.assertEqual(event.representative_evidence_id, "ev1")
        self.assertEqual(event.primary_evidence[0].evidence_id, "ev1")

    # 5
    def test_json_serialization(self):
        text = make_result().to_json()
        self.assertIsInstance(text, str)
        self.assertIn('"CHATGPT_LOGOUT_001"', text)

    # 6
    def test_json_round_trip(self):
        result = make_result()
        loaded = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
        self.assertEqual(loaded, result.to_dict())
        self.assertEqual(json.loads(result.to_json()), result.to_dict())

    # 7
    def test_korean_preserved(self):
        text = make_result().to_json()
        self.assertIn("안녕 인사 응답", text)  # ensure_ascii=False: \uXXXX 로 바뀌지 않음
        self.assertIn("테스트 경고", text)
        loaded = json.loads(text)
        self.assertEqual(loaded["events"][1]["supporting_evidence"][0]["observed"]["conversation_title"], "안녕 인사 응답")

    # 8
    def test_timestamp_raw_string_preserved(self):
        loaded = json.loads(make_result().to_json())
        raw = loaded["records"][0]["timestamp_raw"]
        self.assertIsInstance(raw, str)
        self.assertEqual(raw, "13432494600507032")
        self.assertEqual(loaded["events"][0]["primary_evidence"][0]["timestamp_raw"], "13432494600507032")
        with self.assertRaises(TypeError):
            make_record(timestamp_raw=13432494600507032)  # 정수는 거부

    # 9
    def test_action_status_detected_allowed(self):
        self.assertEqual(make_event(action_status="DETECTED").action_status, "DETECTED")

    # 10
    def test_action_status_candidate_allowed(self):
        event = make_candidate_delete_event()
        self.assertEqual(event.action_status, "CANDIDATE")
        self.assertIsNone(event.timestamp_raw)
        self.assertIsNone(event.representative_evidence_id)

    # 11
    def test_invalid_action_status_rejected(self):
        for bad in ("POSSIBLE", "OBSERVED_ONLY", "detected", "", None):
            with self.subTest(action_status=bad):
                with self.assertRaises(ValueError):
                    make_event(action_status=bad)

    # 12
    def test_nested_evidence_to_dict(self):
        data = make_event().to_dict()
        primary = data["primary_evidence"][0]
        supporting = data["supporting_evidence"][0]
        self.assertIsInstance(primary, dict)
        self.assertEqual(primary["evidence_level"], "DIRECT")
        self.assertEqual(supporting["evidence_level"], "SUPPORTING")
        self.assertEqual(supporting["timestamp_raw"], "1788021002")
        result_data = make_result().to_dict()
        self.assertIsInstance(result_data["input"], dict)
        self.assertIsInstance(result_data["events"][0]["primary_evidence"][0], dict)


class AllowedValueTest(unittest.TestCase):
    def test_invalid_allowed_values_rejected(self):
        cases = [
            (make_evidence, {"evidence_level": "STRONG"}),
            (make_event, {"confidence": "VERY_HIGH"}),
            (make_event, {"rule_verification": "PARTIAL"}),
            (make_event, {"device_attribution": "SYNCED"}),
            (make_event, {"finding_type": "OBSERVATION"}),
            (make_record, {"artifact_type": "downloads"}),
            (make_record, {"timestamp_type": "webkit"}),
        ]
        for factory, override in cases:
            with self.subTest(**override):
                with self.assertRaises(ValueError):
                    factory(**override)

    def test_invalid_coverage_status_rejected(self):
        with self.assertRaises(ValueError):
            p.Coverage(artifact_type="history", source_path="History", status="MISSING")

    def test_invalid_input_kind_rejected(self):
        with self.assertRaises(ValueError):
            p.InputInfo(kind="vmdk", path="x.vmdk")

    def test_timestamp_without_raw_rejected(self):
        with self.assertRaises(ValueError):
            make_record(timestamp_raw=None)  # utc/kst 만 있고 raw 없음

    def test_representative_evidence_must_exist(self):
        with self.assertRaises(ValueError):
            make_event(representative_evidence_id="missing")
        with self.assertRaises(ValueError):
            make_event(representative_evidence_id=None)  # 시각이 있는데 대표 근거 없음

    def test_timestamp_local_field_removed(self):
        self.assertNotIn("timestamp_local", make_record().to_dict())
        with self.assertRaises(TypeError):
            make_record(timestamp_local=LOGOUT_KST)  # 이전 필드 이름은 더 이상 받지 않음


# =============================================================================
# S2 — Timestamp Normalizer
# =============================================================================

# (raw, timestamp_type, expected_utc, expected_kst) — docs/OUTPUT_SCHEMA.md §10 기준값
REFERENCE_CASES = [
    (13432494600507032, "webkit_us", "2026-08-29T16:30:00.507032Z", "2026-08-30T01:30:00.507032+09:00"),
    (1788021002, "unix_s", "2026-08-29T16:30:02Z", "2026-08-30T01:30:02+09:00"),
    (1788255510, "unix_s", "2026-09-01T09:38:30Z", "2026-09-01T18:38:30+09:00"),
    (1788249242, "unix_s", "2026-09-01T07:54:02Z", "2026-09-01T16:54:02+09:00"),
    (1787126888000, "unix_ms", "2026-08-19T08:08:08Z", "2026-08-19T17:08:08+09:00"),
    ("2026-09-12T18:04:34Z", "iso_utc", "2026-09-12T18:04:34Z", "2026-09-13T03:04:34+09:00"),
    ("2026-09-12T18:04:34.276355Z", "iso_utc", "2026-09-12T18:04:34.276355Z", "2026-09-13T03:04:34.276355+09:00"),
]


class TimestampNormalizerTest(unittest.TestCase):
    def assert_converted(self, raw, timestamp_type, utc, kst):
        result = p.normalize_timestamp(raw, timestamp_type, source="test.source")
        self.assertEqual(result["timestamp_utc"], utc)
        self.assertEqual(result["timestamp_kst"], kst)
        self.assertEqual(result["timestamp_type"], timestamp_type)
        self.assertEqual(result["timestamp_raw"], str(raw))
        self.assertEqual(result["timestamp_source"], "test.source")
        self.assertEqual(result["warnings"], [])
        return result

    def assert_failed(self, raw, timestamp_type, warning, expected_type=None, expected_raw="same"):
        result = p.normalize_timestamp(raw, timestamp_type)
        self.assertIsNone(result["timestamp_utc"])
        self.assertIsNone(result["timestamp_kst"])
        self.assertIn(warning, result["warnings"])
        self.assertEqual(result["timestamp_type"], expected_type or timestamp_type)
        self.assertEqual(result["timestamp_raw"], (None if raw is None else str(raw)) if expected_raw == "same" else expected_raw)
        return result

    # 1
    def test_webkit_us(self):
        self.assert_converted(13432494600507032, "webkit_us", LOGOUT_UTC, LOGOUT_KST)
        self.assert_converted("13432494600507032", "webkit_us", LOGOUT_UTC, LOGOUT_KST)  # 문자열 입력도 동일

    # 2~4
    def test_unix_s_case1(self):
        self.assert_converted(1788021002, "unix_s", "2026-08-29T16:30:02Z", "2026-08-30T01:30:02+09:00")

    def test_unix_s_case2(self):
        self.assert_converted(1788255510, "unix_s", "2026-09-01T09:38:30Z", "2026-09-01T18:38:30+09:00")

    def test_unix_s_case3(self):
        self.assert_converted("1788249242", "unix_s", "2026-09-01T07:54:02Z", "2026-09-01T16:54:02+09:00")

    # 5
    def test_unix_ms(self):
        result = self.assert_converted(1787126888000, "unix_ms", "2026-08-19T08:08:08Z", "2026-08-19T17:08:08+09:00")
        self.assertEqual(result["timestamp_raw"], "1787126888000")

    # 6
    def test_iso_utc(self):
        self.assert_converted("2026-09-12T18:04:34Z", "iso_utc", "2026-09-12T18:04:34Z", "2026-09-13T03:04:34+09:00")
        self.assert_converted("2026-09-12T18:04:34.276355Z", "iso_utc",
                              "2026-09-12T18:04:34.276355Z", "2026-09-13T03:04:34.276355+09:00")

    # 7, 8, 21 — 모든 기준값을 한 번에 확인
    def test_all_reference_values(self):
        for raw, timestamp_type, utc, kst in REFERENCE_CASES:
            with self.subTest(raw=raw, timestamp_type=timestamp_type):
                self.assert_converted(raw, timestamp_type, utc, kst)

    # 9
    def test_utc_uses_z_suffix(self):
        for raw, timestamp_type, _, _ in REFERENCE_CASES:
            with self.subTest(raw=raw):
                utc = p.normalize_timestamp(raw, timestamp_type)["timestamp_utc"]
                self.assertTrue(utc.endswith("Z"))
                self.assertNotIn("+00:00", utc)

    # 10
    def test_kst_uses_plus_0900_offset(self):
        for raw, timestamp_type, _, _ in REFERENCE_CASES:
            with self.subTest(raw=raw):
                kst = p.normalize_timestamp(raw, timestamp_type)["timestamp_kst"]
                self.assertTrue(kst.endswith("+09:00"))
                self.assertNotIn("KST", kst)

    # 11
    def test_microseconds_preserved_and_not_padded(self):
        webkit = p.normalize_timestamp(13432494600507032, "webkit_us")
        self.assertIn(".507032", webkit["timestamp_utc"])
        self.assertIn(".507032", webkit["timestamp_kst"])
        whole = p.normalize_timestamp(1788021002, "unix_s")
        self.assertNotIn(".", whole["timestamp_utc"])  # .000000 을 붙이지 않음
        self.assertNotIn(".", whole["timestamp_kst"])
        # 1 µs 차이도 구별되어야 한다 (float 경유 시 손실되는 크기)
        neighbor = p.normalize_timestamp(13432494600507033, "webkit_us")
        self.assertEqual(neighbor["timestamp_utc"], "2026-08-29T16:30:00.507033Z")

    # 12
    def test_timestamp_raw_kept_as_string(self):
        result = p.normalize_timestamp(13432494600507032, "webkit_us")
        self.assertIsInstance(result["timestamp_raw"], str)
        self.assertEqual(json.loads(json.dumps(result))["timestamp_raw"], "13432494600507032")

    # 13
    def test_none_is_missing(self):
        result = self.assert_failed(None, "webkit_us", p.TS_MISSING)
        self.assertEqual(result["warnings"], ["TIMESTAMP_MISSING"])

    # 14
    def test_empty_is_missing(self):
        self.assert_failed("", "unix_s", p.TS_MISSING)
        self.assert_failed("   ", "unix_ms", p.TS_MISSING)
        self.assert_failed(0, "webkit_us", p.TS_MISSING)  # Chrome 의 WebKit 0 = 값 없음

    # 15
    def test_invalid_number(self):
        for bad in ("abc", "12.5", "1e9", "0x10", 1788021002.0, True):
            with self.subTest(raw=bad):
                self.assert_failed(bad, "unix_s", p.TS_INVALID_NUMBER)
        self.assert_failed("abc", "webkit_us", p.TS_INVALID_NUMBER)  # 지원 type 은 그대로 보존

    # 16
    def test_negative(self):
        self.assert_failed(-1, "unix_s", p.TS_OUT_OF_RANGE)
        self.assert_failed("-13432494600507032", "webkit_us", p.TS_OUT_OF_RANGE)

    # 17
    def test_out_of_range(self):
        self.assert_failed("999999999999999999999999", "webkit_us", p.TS_OUT_OF_RANGE)
        self.assert_failed(999999999999, "unix_s", p.TS_OUT_OF_RANGE)
        self.assert_failed(10**30, "unix_ms", p.TS_OUT_OF_RANGE)
        # UTC 로는 표현되지만 KST(+9h) 로 옮기면 연도 10000 이 되는 경계값
        edge = (datetime(9999, 12, 31, 20, tzinfo=timezone.utc) - p.WEBKIT_EPOCH) // timedelta(microseconds=1)
        self.assert_failed(edge, "webkit_us", p.TS_OUT_OF_RANGE)

    # 18
    def test_unsupported_type(self):
        for bad_type in ("filesystem", "unknown", "webkit", "", None):
            with self.subTest(timestamp_type=bad_type):
                result = self.assert_failed("13432494600507032", bad_type, p.TS_UNSUPPORTED_TYPE, expected_type="unknown")
                self.assertEqual(result["timestamp_raw"], "13432494600507032")

    # 19
    def test_naive_iso(self):
        self.assert_failed("2026-09-12T18:04:34", "iso_utc", p.TS_NAIVE_ISO)
        self.assert_failed("2026-09-12", "iso_utc", p.TS_NAIVE_ISO)

    # 20
    def test_invalid_iso(self):
        for bad in ("2026-13-40T99:00:00Z", "not a date", "2026/09/12 18:04:34Z", 1788021002):
            with self.subTest(raw=bad):
                self.assert_failed(bad, "iso_utc", p.TS_INVALID_ISO)

    def test_iso_with_other_offset_converted_to_utc(self):
        self.assert_converted("2026-09-13T03:04:34+09:00", "iso_utc", "2026-09-12T18:04:34Z", "2026-09-13T03:04:34+09:00")

    def test_never_raises(self):
        odd_inputs = [None, "", "abc", -1, 10**40, 1.5, True, b"123", [], {}, object(), "2026-09-12T18:04:34"]
        for raw in odd_inputs:
            for timestamp_type in ("webkit_us", "unix_s", "unix_ms", "iso_utc", "filesystem", None):
                with self.subTest(raw=repr(raw)[:30], timestamp_type=timestamp_type):
                    result = p.normalize_timestamp(raw, timestamp_type)
                    self.assertTrue(result["warnings"])
                    self.assertIsNone(result["timestamp_utc"])

    def test_same_result_regardless_of_call_order(self):
        # 전역 상태·현재 시각에 의존하지 않음: 반복 호출 결과가 같아야 한다
        first = p.normalize_timestamp(13432494600507032, "webkit_us")
        p.normalize_timestamp("2026-09-12T18:04:34Z", "iso_utc")
        self.assertEqual(p.normalize_timestamp(13432494600507032, "webkit_us"), first)

    def test_output_fits_result_model(self):
        # S1 Result Model 과 연결되는지 확인 (성공·실패 출력 모두)
        for raw, timestamp_type in ((13432494600507032, "webkit_us"), ("abc", "webkit_us"), (None, "unix_s"), ("x", "filesystem")):
            with self.subTest(raw=raw, timestamp_type=timestamp_type):
                ts = p.normalize_timestamp(raw, timestamp_type, source="History.visits.visit_time")
                warnings = ts.pop("warnings")
                record = p.ArtifactRecord(record_id="r", artifact_type="history", source_path="History",
                                          warnings=warnings, **ts)
                self.assertEqual(record.timestamp_raw, None if raw is None else str(raw))


# =============================================================================
# S3 — Source Interface + DirectorySource + SQLite 메모리 열기
# =============================================================================
# 모든 데이터는 테스트가 임시 폴더에 만든 synthetic 데이터다. 실제 Evidence 를 읽지 않는다.

HISTORY_BYTES = b"fake history bytes \x00\x01\x02"
TEXT_BYTES = "안녕 source".encode("utf-8")


def tree_snapshot(root):
    """폴더 트리 상태: {상대경로: '<dir>' 또는 (size, sha256, mtime_ns)}"""
    snapshot = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            snapshot[os.path.relpath(os.path.join(dirpath, name), root)] = "<dir>"
        for name in filenames:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            stat = os.stat(full)
            snapshot[os.path.relpath(full, root)] = (stat.st_size, digest, stat.st_mtime_ns)
    return snapshot


def create_sqlite_file(path, journal_mode="delete"):
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA journal_mode={journal_mode}")
        connection.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
        connection.executemany("INSERT INTO test (value) VALUES (?)", [("안녕",), ("chatgpt",)])
        connection.commit()
        if journal_mode == "wal":
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()


class SourceTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Chrome"
        (self.root / "Default" / "Local Storage" / "leveldb").mkdir(parents=True)
        (self.root / "Profile 1").mkdir()
        (self.root / "Default" / "History").write_bytes(HISTORY_BYTES)
        (self.root / "Default" / "test.txt").write_bytes(TEXT_BYTES)
        (self.root / "Default" / "Preferences").write_bytes(b"")  # 0 byte
        (self.base / "outside.txt").write_bytes(b"outside of source root")
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()


class DirectorySourceTest(SourceTestBase):
    # 1
    def test_directory_source_created(self):
        self.assertIsInstance(self.source, p.Source)
        self.assertEqual(self.source.kind, "directory")
        self.assertTrue(self.source.root.is_absolute())

    # 2
    def test_exists_file(self):
        self.assertTrue(self.source.exists("Default/History"))
        self.assertTrue(self.source.exists("Default\\History"))  # Windows 구분자
        self.assertTrue(self.source.exists("./Default//History"))

    # 3
    def test_exists_missing_file(self):
        self.assertFalse(self.source.exists("Default/Cookies"))
        self.assertFalse(self.source.exists("Profile 2/History"))

    # 4
    def test_is_file(self):
        self.assertTrue(self.source.is_file("Default/History"))
        self.assertFalse(self.source.is_file("Default"))
        self.assertFalse(self.source.is_file("Default/Cookies"))

    # 5
    def test_is_dir(self):
        self.assertTrue(self.source.is_dir("Default"))
        self.assertTrue(self.source.is_dir(""))  # root
        self.assertFalse(self.source.is_dir("Default/History"))
        self.assertFalse(self.source.is_dir("Missing"))

    # 6
    def test_list_dir(self):
        self.assertEqual(self.source.list_dir(), ["Default", "Profile 1"])
        self.assertEqual(self.source.list_dir("Default"), ["History", "Local Storage", "Preferences", "test.txt"])
        self.assertEqual(self.source.list_dir("Default"), self.source.list_dir("Default\\"))  # 같은 순서
        with self.assertRaises(FileNotFoundError):
            self.source.list_dir("Missing")
        with self.assertRaises(NotADirectoryError):
            self.source.list_dir("Default/History")

    # 7
    def test_read_bytes(self):
        self.assertEqual(self.source.read_bytes("Default/History"), HISTORY_BYTES)
        self.assertEqual(self.source.read_bytes("Default\\test.txt").decode("utf-8"), "안녕 source")

    # 8
    def test_size(self):
        self.assertEqual(self.source.size("Default/History"), len(HISTORY_BYTES))
        self.assertEqual(self.source.size("Default/Preferences"), 0)

    # 9
    def test_sha256(self):
        self.assertEqual(self.source.sha256("Default/History"), hashlib.sha256(HISTORY_BYTES).hexdigest())
        self.assertEqual(self.source.sha256("Default/Preferences"),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # 10
    def test_zero_byte_file_is_present_but_empty(self):
        self.assertTrue(self.source.exists("Default/Preferences"))
        self.assertTrue(self.source.is_file("Default/Preferences"))
        self.assertEqual(self.source.read_bytes("Default/Preferences"), b"")
        self.assertEqual(self.source.file_status("Default/Preferences"), p.FILE_STATUS_EMPTY)
        self.assertEqual(self.source.file_status("Default/History"), p.FILE_STATUS_PRESENT)
        self.assertEqual(self.source.file_status("Default/Cookies"), p.FILE_STATUS_NOT_PRESENT)
        self.assertEqual(self.source.file_status("Default"), p.FILE_STATUS_NOT_A_FILE)

    # 11
    def test_missing_file_raises_file_not_found(self):
        for method in (self.source.read_bytes, self.source.size, self.source.sha256):
            with self.subTest(method=method.__name__):
                with self.assertRaises(FileNotFoundError):
                    method("Default/Cookies")
        with self.assertRaises(IsADirectoryError):
            self.source.read_bytes("Default")

    # 12
    def test_invalid_root(self):
        with self.assertRaises(FileNotFoundError):
            p.DirectorySource(self.base / "no_such_root")
        with self.assertRaises(NotADirectoryError):
            p.DirectorySource(self.base / "outside.txt")

    # 13
    def test_path_traversal_rejected(self):
        bad_paths = [
            "../outside.txt",
            "..\\outside.txt",
            "Default/../../outside.txt",
            "Default\\..\\..\\outside.txt",
            str(self.base / "outside.txt"),  # 절대 경로
            "C:\\Windows\\win.ini",
            "C:relative",
            "/etc/passwd",
            "\\\\server\\share\\file",
            "Default/History\x00",
        ]
        for bad in bad_paths:
            with self.subTest(path=bad):
                with self.assertRaises(p.SourcePathError):
                    self.source.read_bytes(bad)
                with self.assertRaises(p.SourcePathError):
                    self.source.exists(bad)
        with self.assertRaises(TypeError):
            self.source.exists(None)

    # 14
    def test_sha256_unchanged_after_reads(self):
        before = hashlib.sha256((self.root / "Default" / "History").read_bytes()).hexdigest()
        self.source.exists("Default/History")
        self.source.size("Default/History")
        self.source.read_bytes("Default/History")
        self.source.sha256("Default/History")
        after = hashlib.sha256((self.root / "Default" / "History").read_bytes()).hexdigest()
        self.assertEqual(before, after)

    # 15
    def test_source_tree_unchanged_after_all_operations(self):
        create_sqlite_file(self.root / "Default" / "test.db")
        before = tree_snapshot(self.root)
        for path in ("", "Default", "Default/Local Storage/leveldb", "Profile 1"):
            self.source.list_dir(path)
        for path in ("Default/History", "Default/test.txt", "Default/Preferences", "Default/test.db", "Default/Missing"):
            self.source.exists(path)
            self.source.is_file(path)
            self.source.is_dir(path)
            self.source.file_status(path)
            if self.source.is_file(path):
                self.source.size(path)
                self.source.read_bytes(path)
                self.source.sha256(path)
        connection, _ = p.open_sqlite_bytes(self.source.read_bytes("Default/test.db"))
        connection.execute("SELECT * FROM test").fetchall()
        connection.close()
        after = tree_snapshot(self.root)
        self.assertEqual(before, after)  # 새 파일(-wal/-shm/-journal 포함) 없음, 내용·mtime 변화 없음

    def test_source_has_no_write_methods(self):
        for name in ("write", "write_bytes", "write_text", "delete", "remove", "unlink", "rename", "mkdir", "move", "copy"):
            with self.subTest(method=name):
                self.assertFalse(hasattr(p.DirectorySource, name))

    def test_normalize_source_path(self):
        self.assertEqual(p.normalize_source_path("Default\\Local Storage\\leveldb"), "Default/Local Storage/leveldb")
        self.assertEqual(p.normalize_source_path("./Default/"), "Default")
        self.assertEqual(p.normalize_source_path(""), "")


class SQLiteMemoryTest(SourceTestBase):
    # 16
    def test_sqlite_deserialize_supported(self):
        self.assertEqual(p.SQLITE_DESERIALIZE_SUPPORTED, hasattr(sqlite3.Connection, "deserialize"))
        self.assertTrue(p.SQLITE_DESERIALIZE_SUPPORTED, "Python 3.13.3 환경에서는 지원이 확인되어야 한다")

    # 17
    def test_open_sqlite_bytes_in_memory(self):
        create_sqlite_file(self.root / "Default" / "test.db")
        files_before = sorted(os.listdir(self.root / "Default"))
        connection, warnings = p.open_sqlite_bytes(self.source.read_bytes("Default/test.db"))
        try:
            self.assertIsInstance(connection, sqlite3.Connection)
            self.assertEqual(warnings, [])
        finally:
            connection.close()
        self.assertEqual(sorted(os.listdir(self.root / "Default")), files_before)
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse((self.root / "Default" / f"test.db{suffix}").exists())

    # 18
    def test_memory_sqlite_select(self):
        create_sqlite_file(self.root / "Default" / "test.db")
        connection, _ = p.open_sqlite_bytes(self.source.read_bytes("Default/test.db"))
        try:
            rows = connection.execute("SELECT id, value FROM test ORDER BY id").fetchall()
        finally:
            connection.close()
        self.assertEqual(rows, [(1, "안녕"), (2, "chatgpt")])

    def test_wal_mode_database_opens_with_header_adjusted(self):
        create_sqlite_file(self.root / "Default" / "wal.db", journal_mode="wal")
        self.assertFalse((self.root / "Default" / "wal.db-wal").exists())
        original = self.source.read_bytes("Default/wal.db")
        self.assertEqual((original[18], original[19]), (2, 2))
        sha_before = self.source.sha256("Default/wal.db")
        connection, warnings = p.open_sqlite_bytes(original)
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM test").fetchone()[0], 2)
        finally:
            connection.close()
        self.assertIn(p.SQLITE_WAL_HEADER_ADJUSTED, warnings)
        self.assertEqual((original[18], original[19]), (2, 2))  # 입력 bytes 는 바뀌지 않음
        self.assertEqual(self.source.sha256("Default/wal.db"), sha_before)  # 원본 파일도 그대로

    def test_memory_sqlite_is_read_only(self):
        create_sqlite_file(self.root / "Default" / "test.db")
        connection, _ = p.open_sqlite_bytes(self.source.read_bytes("Default/test.db"))
        try:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("INSERT INTO test (value) VALUES ('x')")
        finally:
            connection.close()

    def test_non_sqlite_bytes_rejected(self):
        for data in (b"", HISTORY_BYTES, b"not a database" * 20):
            with self.subTest(size=len(data)):
                with self.assertRaises(sqlite3.DatabaseError):
                    p.open_sqlite_bytes(data)


# =============================================================================
# S4 — Chrome History Reader
# =============================================================================
# 테스트가 임시 폴더에 만든 synthetic History DB 만 사용한다.
# 로그아웃 방문 값(visits.id=42, 13432494600507032, 0x30000000)은 수동 분석에서 확인된 값을 fixture 로 쓴 것이다.
# S4 는 ArtifactRecord 만 만든다. LOGOUT Event 판정은 S5.

HISTORY_URLS = [
    # (urls.id, url, title)
    (1, "https://chatgpt.com/", "ChatGPT"),
    (2, "https://chatgpt.com/auth/logout", "ChatGPT"),
    (3, "https://auth.openai.com/log-in/password", "로그인 - OpenAI"),
    (4, "https://example.com/", "Example Domain"),
    (5, "https://notchatgpt.com/", "Not ChatGPT"),
    (6, "https://chatgpt.com.evil.example/login", "Look-alike"),
    (7, "https://chatgpt.com/api/auth/callback/openai?code=SECRET_CODE_123&state=STATE_456&x=1", "Callback"),
]

SIGNED_SERVER_REDIRECT_CHAIN_END = (0x80000000 | 0x20000000) - 0x100000000  # signed 32bit 로 저장된 경우 음수

HISTORY_VISIT_COLUMNS = ("id", "url", "visit_time", "from_visit", "transition", "originator_cache_guid", "is_known_to_sync")
HISTORY_VISITS = [
    (41, 1, 13432494590000000, 0, 0x10000000 | 1, "", 1),
    (42, 2, 13432494600507032, 41, 0x30000000, "", 0),  # 실제 사본의 visits.id=42 도 guid 빈 값, is_known_to_sync 0
    (43, 3, 13432494610000000, 42, 0x30000000, "", 1),
    (44, 4, 13432494620000000, 0, 1, "", 0),
    (45, 5, 13432494630000000, 0, 1, "", 0),
    (46, 6, 13432494640000000, 0, 1, "", 0),
    (47, 7, 13432494650000000, 43, SIGNED_SERVER_REDIRECT_CHAIN_END, "remote-device-guid", 1),
]
CHATGPT_VISIT_IDS = [41, 42, 43, 47]


HISTORY_DOWNLOAD_COLUMNS = ("id", "guid", "current_path", "target_path", "start_time", "end_time", "received_bytes",
                           "total_bytes", "state", "danger_type", "interrupt_reason", "opened", "referrer", "site_url",
                           "tab_url", "tab_referrer_url", "http_method", "mime_type", "original_mime_type",
                           "last_access_time", "transient", "by_ext_id", "by_ext_name", "etag", "last_modified")


def create_history_db(path, *, sync_columns=True, skip_table=None, skip_visit_columns=(), urls=HISTORY_URLS,
                      visits=HISTORY_VISITS, downloads=(), url_chains=(), skip_download_columns=()):
    """Chrome History 와 같은 이름의 urls / visits / downloads / downloads_url_chains 테이블을 가진 synthetic DB."""
    connection = sqlite3.connect(path)
    try:
        if skip_table != "downloads":
            names = [name for name in HISTORY_DOWNLOAD_COLUMNS if name not in skip_download_columns]
            types = {"id": "INTEGER PRIMARY KEY", "start_time": "INTEGER NOT NULL", "end_time": "INTEGER NOT NULL",
                     "received_bytes": "INTEGER NOT NULL", "total_bytes": "INTEGER NOT NULL", "state": "INTEGER NOT NULL",
                     "danger_type": "INTEGER NOT NULL", "interrupt_reason": "INTEGER NOT NULL", "opened": "INTEGER NOT NULL"}
            definitions = ", ".join("%s %s" % (name, types.get(name, "TEXT")) for name in names)
            connection.execute(f"CREATE TABLE downloads ({definitions})")
            rows = [tuple(value for name, value in zip(HISTORY_DOWNLOAD_COLUMNS, row) if name in names) for row in downloads]
            if rows:
                connection.executemany(
                    f"INSERT INTO downloads ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})", rows)
        if skip_table != "downloads_url_chains":
            connection.execute("CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, "
                               "url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index))")
            connection.executemany("INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, ?, ?)", url_chains)
        if skip_table != "urls":
            connection.execute(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, "
                "visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL, "
                "last_visit_time INTEGER DEFAULT 0 NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL)"
            )
            connection.executemany("INSERT INTO urls (id, url, title) VALUES (?, ?, ?)", urls)
        if skip_table != "visits":
            definitions = {
                "id": "id INTEGER PRIMARY KEY", "url": "url INTEGER NOT NULL", "visit_time": "visit_time INTEGER NOT NULL",
                "from_visit": "from_visit INTEGER", "transition": "transition INTEGER DEFAULT 0 NOT NULL",
                "originator_cache_guid": "originator_cache_guid TEXT", "is_known_to_sync": "is_known_to_sync INTEGER DEFAULT 0 NOT NULL",
            }
            names = [name for name in HISTORY_VISIT_COLUMNS
                     if name not in skip_visit_columns and (sync_columns or name not in ("originator_cache_guid", "is_known_to_sync"))]
            columns = [definitions[name] for name in names] + ["segment_id INTEGER", "visit_duration INTEGER DEFAULT 0 NOT NULL"]
            connection.execute(f"CREATE TABLE visits ({', '.join(columns)})")
            rows = [tuple(value for name, value in zip(HISTORY_VISIT_COLUMNS, visit) if name in names) for visit in visits]
            connection.executemany(f"INSERT INTO visits ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})", rows)
        connection.commit()
    finally:
        connection.close()


class HistoryTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "Chrome"
        (self.root / "Default").mkdir(parents=True)
        self.history_file = self.root / "Default" / "History"
        create_history_db(self.history_file)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def variant(self, name, **kwargs):
        create_history_db(self.root / "Default" / name, **kwargs)
        return f"Default/{name}"

    @staticmethod
    def by_visit(records):
        return {record.observed["visit_id"]: record for record in records}


class HistoryReaderTest(HistoryTestBase):
    # 1
    def test_synthetic_history_db_created(self):
        connection, _ = p.open_sqlite_bytes(self.source.read_bytes("Default/History"))
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"urls", "visits"} <= tables)
            self.assertEqual(connection.execute("SELECT count(*) FROM visits").fetchone()[0], len(HISTORY_VISITS))
        finally:
            connection.close()

    # 2
    def test_memory_open_and_parsed(self):
        records, coverage = p.read_history(self.source, "Default/History")
        self.assertEqual(coverage.status, "PARSED")
        self.assertEqual(coverage.artifact_type, "history")
        self.assertEqual(coverage.record_count, len(HISTORY_VISITS))
        self.assertEqual(len(records), len(HISTORY_VISITS))
        self.assertEqual(coverage.source_sha256, hashlib.sha256(self.history_file.read_bytes()).hexdigest())
        self.assertEqual(coverage.warnings, [])
        self.assertTrue(all(isinstance(record, p.ArtifactRecord) for record in records))

    # 3
    def test_urls_visits_join(self):
        records = self.by_visit(p.read_history(self.source, "Default/History")[0])
        self.assertEqual(records[42].observed["url_id"], 2)
        self.assertEqual(records[42].observed["url"], "https://chatgpt.com/auth/logout")
        self.assertEqual(records[42].observed["title"], "ChatGPT")
        self.assertEqual(records[43].observed["title"], "로그인 - OpenAI")
        self.assertEqual(records[42].observed["from_visit"], 41)

    # 4
    def test_visit_time_extracted(self):
        record = self.by_visit(p.read_history(self.source, "Default/History")[0])[42]
        self.assertEqual(record.timestamp_raw, "13432494600507032")  # urls.last_visit_time(0) 이 아니라 visits.visit_time
        self.assertEqual(record.timestamp_type, "webkit_us")
        self.assertEqual(record.timestamp_source, "History.visits.visit_time")

    # 5, 6, 7
    def test_webkit_to_utc_kst_and_raw_string(self):
        record = self.by_visit(p.read_history(self.source, "Default/History")[0])[42]
        self.assertEqual(record.timestamp_utc, "2026-08-29T16:30:00.507032Z")
        self.assertEqual(record.timestamp_kst, "2026-08-30T01:30:00.507032+09:00")
        self.assertIsInstance(record.timestamp_raw, str)
        self.assertEqual(record.warnings, [])

    # 8
    def test_source_path_preserved(self):
        records, coverage = p.read_history(self.source, "Default\\History")
        self.assertEqual(coverage.source_path, "Default/History")
        self.assertTrue(all(record.source_path == "Default/History" for record in records))

    # 9
    def test_record_location_preserved(self):
        record = self.by_visit(p.read_history(self.source, "Default/History")[0])[42]
        self.assertEqual(record.record_location, "visits.id=42")
        self.assertIn("visits.id=42", record.record_id)

    # 10
    def test_chatgpt_filter_includes_chatgpt_com(self):
        records, coverage = p.read_chatgpt_history(self.source, "Default/History")
        visit_ids = [record.observed["visit_id"] for record in records]
        self.assertEqual(visit_ids, CHATGPT_VISIT_IDS)
        self.assertEqual(coverage.record_count, len(CHATGPT_VISIT_IDS))
        self.assertIn(42, visit_ids)

    # 11
    def test_chatgpt_filter_includes_auth_openai_com(self):
        records = self.by_visit(p.read_chatgpt_history(self.source, "Default/History")[0])
        self.assertEqual(records[43].observed["url"], "https://auth.openai.com/log-in/password")

    # 12
    def test_unrelated_domains_excluded(self):
        visit_ids = {record.observed["visit_id"] for record in p.read_chatgpt_history(self.source, "Default/History")[0]}
        self.assertTrue(visit_ids.isdisjoint({44, 45, 46}))  # example.com, notchatgpt.com, chatgpt.com.evil.example
        cases = {
            "https://chatgpt.com/": True,
            "https://CHATGPT.COM/c/abc": True,
            "http://chatgpt.com./": True,
            "https://auth.openai.com/api/accounts/authorize": True,
            "https://notchatgpt.com/": False,
            "https://chatgpt.com.evil.example/": False,
            "https://evil.example/?next=https://chatgpt.com/": False,
            "https://openai.com/": False,
            "file://chatgpt.com/x": False,
            "chatgpt.com/auth/logout": False,
            "http://[::1": False,
            "": False,
            None: False,
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(p.is_chatgpt_url(url), expected)

    # 13
    def test_transition_raw_preserved_and_decoded(self):
        records = self.by_visit(p.read_history(self.source, "Default/History")[0])
        logout = records[42].observed
        self.assertEqual(logout["transition_raw"], 805306368)
        self.assertEqual(logout["transition_hex"], "0x30000000")
        self.assertEqual(logout["transition_core"], "LINK")
        self.assertEqual(logout["transition_qualifiers"], ["CHAIN_START", "CHAIN_END"])
        self.assertEqual(records[41].observed["transition_core"], "TYPED")
        signed = records[47].observed
        self.assertEqual(signed["transition_raw"], SIGNED_SERVER_REDIRECT_CHAIN_END)  # 음수 원본 그대로
        self.assertEqual(signed["transition_hex"], "0xA0000000")
        self.assertEqual(signed["transition_qualifiers"], ["CHAIN_END", "SERVER_REDIRECT"])

    # 14
    def test_optional_sync_columns_present(self):
        records, coverage = p.read_history(self.source, "Default/History")
        records = self.by_visit(records)
        self.assertEqual(records[42].observed["originator_cache_guid"], "")
        self.assertEqual(records[42].observed["is_known_to_sync"], 0)
        self.assertEqual(records[43].observed["is_known_to_sync"], 1)
        self.assertEqual(records[47].observed["originator_cache_guid"], "remote-device-guid")
        self.assertFalse(any(w.startswith(p.HISTORY_OPTIONAL_COLUMN_ABSENT) for w in coverage.warnings))
        self.assertNotIn("device_attribution", records[47].observed)  # Reader 는 판정하지 않는다

    # 15
    def test_optional_sync_columns_absent(self):
        path = self.variant("History_nosync", sync_columns=False)
        records, coverage = p.read_history(self.source, path)
        self.assertEqual(coverage.status, "PARSED")
        self.assertEqual(len(records), len(HISTORY_VISITS))
        record = self.by_visit(records)[42]
        self.assertIsNone(record.observed["originator_cache_guid"])
        self.assertIsNone(record.observed["is_known_to_sync"])
        self.assertIn(f"{p.HISTORY_OPTIONAL_COLUMN_ABSENT}:visits.originator_cache_guid", coverage.warnings)
        self.assertIn(f"{p.HISTORY_OPTIONAL_COLUMN_ABSENT}:visits.is_known_to_sync", coverage.warnings)

    # 16
    def test_history_not_present(self):
        records, coverage = p.read_history(self.source, "Profile 9/History")
        self.assertEqual(records, [])
        self.assertEqual(coverage.status, "NOT_PRESENT")
        self.assertEqual(coverage.record_count, 0)
        self.assertIsNone(coverage.source_sha256)

    # 17
    def test_zero_byte_history(self):
        (self.root / "Default" / "History_empty").write_bytes(b"")
        records, coverage = p.read_history(self.source, "Default/History_empty")
        self.assertEqual((records, coverage.status), ([], "EMPTY"))
        self.assertIn(p.HISTORY_EMPTY_FILE, coverage.warnings)  # 존재하지만 비어 있음 (NOT_PRESENT 와 구분)
        self.assertEqual(coverage.source_sha256, hashlib.sha256(b"").hexdigest())

    # 18
    def test_invalid_sqlite(self):
        (self.root / "Default" / "History_bad").write_bytes(b"this is not sqlite " * 20)
        records, coverage = p.read_history(self.source, "Default/History_bad")
        self.assertEqual((records, coverage.status), ([], "PARSE_ERROR"))
        self.assertIn(p.HISTORY_NOT_SQLITE, coverage.warnings)
        self.assertIsNotNone(coverage.source_sha256)  # 무엇을 읽었는지는 기록

    # 19
    def test_urls_table_missing(self):
        records, coverage = p.read_history(self.source, self.variant("History_nourls", skip_table="urls"))
        self.assertEqual((records, coverage.status), ([], "PARSE_ERROR"))
        self.assertIn(f"{p.HISTORY_MISSING_TABLE}:urls", coverage.warnings)

    # 20
    def test_visits_table_missing(self):
        records, coverage = p.read_history(self.source, self.variant("History_novisits", skip_table="visits"))
        self.assertEqual((records, coverage.status), ([], "PARSE_ERROR"))
        self.assertIn(f"{p.HISTORY_MISSING_TABLE}:visits", coverage.warnings)

    def test_required_column_missing(self):
        records, coverage = p.read_history(self.source, self.variant("History_notransition", skip_visit_columns=("transition",)))
        self.assertEqual((records, coverage.status), ([], "PARSE_ERROR"))
        self.assertIn(f"{p.HISTORY_MISSING_COLUMN}:visits.transition", coverage.warnings)

    # 21
    def test_zero_chatgpt_records_is_parsed_not_missing(self):
        path = self.variant("History_other", urls=[(1, "https://example.com/", "Example")],
                            visits=[(1, 1, 13432494600000000, 0, 0, "", 0)])
        records, coverage = p.read_chatgpt_history(self.source, path)
        self.assertEqual(records, [])
        self.assertEqual(coverage.status, "PARSED")
        self.assertEqual(coverage.record_count, 0)

    # 22
    def test_wal_present_warning(self):
        (self.root / "Default" / "History-wal").write_bytes(b"synthetic wal content")
        records, coverage = p.read_history(self.source, "Default/History")
        self.assertIn(p.HISTORY_WAL_PRESENT_UNMERGED, coverage.warnings)
        self.assertEqual(coverage.status, "PARSED")  # 본 DB 파싱은 성공했지만 최신 기록 누락 가능성을 경고로 남김
        self.assertEqual(len(records), len(HISTORY_VISITS))

    # 23
    def test_history_sha256_unchanged(self):
        (self.root / "Default" / "History-wal").write_bytes(b"synthetic wal content")
        before = hashlib.sha256(self.history_file.read_bytes()).hexdigest()
        p.read_history(self.source, "Default/History")
        p.read_chatgpt_history(self.source, "Default\\History")
        after = hashlib.sha256(self.history_file.read_bytes()).hexdigest()
        self.assertEqual(before, after)

    # 24
    def test_source_directory_unchanged(self):
        self.variant("History_nosync", sync_columns=False)
        self.variant("History_nourls", skip_table="urls")
        (self.root / "Default" / "History_bad").write_bytes(b"not sqlite" * 20)
        (self.root / "Default" / "History-wal").write_bytes(b"synthetic wal content")
        before = tree_snapshot(self.root)
        for path in ("Default/History", "Default/History_nosync", "Default/History_nourls", "Default/History_bad", "Default/Missing"):
            p.read_history(self.source, path)
            p.read_chatgpt_history(self.source, path)
        after = tree_snapshot(self.root)
        self.assertEqual(before, after)
        for suffix in ("-shm", "-journal"):
            self.assertFalse((self.root / "Default" / f"History{suffix}").exists())

    def test_oauth_query_values_redacted(self):
        records, _ = p.read_chatgpt_history(self.source, "Default/History")
        callback = self.by_visit(records)[47].observed
        self.assertNotIn("SECRET_CODE_123", callback["url"])
        self.assertNotIn("STATE_456", callback["url"])
        self.assertIn("code=REDACTED", callback["url"])
        self.assertIn("x=1", callback["url"])
        self.assertEqual(callback["redacted_query_keys"], ["code", "state"])
        dumped = json.dumps([record.to_dict() for record in records], ensure_ascii=False)
        self.assertNotIn("SECRET_CODE_123", dumped)
        self.assertNotIn("redacted_query_keys", self.by_visit(records)[42].observed)

    def test_orphan_visit_without_url_row(self):
        path = self.variant("History_orphan", visits=HISTORY_VISITS + [(99, 999, 13432494660000000, 0, 0, "", 0)])
        records, coverage = p.read_history(self.source, path)
        orphan = self.by_visit(records)[99]
        self.assertIsNone(orphan.observed["url"])
        self.assertIn(p.HISTORY_URL_ROW_MISSING, orphan.warnings)
        self.assertEqual(coverage.status, "PARSED")
        self.assertNotIn(99, {r.observed["visit_id"] for r in p.read_chatgpt_history(self.source, path)[0]})

    def test_records_sorted_by_visit_time(self):
        path = self.variant("History_unsorted", visits=list(reversed(HISTORY_VISITS)))
        records, _ = p.read_history(self.source, path)
        raws = [int(record.timestamp_raw) for record in records]
        self.assertEqual(raws, sorted(raws))

    def test_reader_outputs_observations_only(self):
        records, coverage = p.read_chatgpt_history(self.source, "Default/History")
        self.assertIsInstance(coverage, p.Coverage)
        for record in records:
            self.assertIsInstance(record, p.ArtifactRecord)
            self.assertNotIsInstance(record, p.Event)
            self.assertFalse({"action", "action_status", "confidence"} & set(record.to_dict()))

    def test_decode_transition_handles_bad_values(self):
        for value in (None, "805306368", 1.5, True):
            with self.subTest(value=value):
                decoded = p.decode_transition(value)
                self.assertIsNone(decoded["transition_core"])
                self.assertEqual(decoded["transition_qualifiers"], [])


# =============================================================================
# S5 — CHATGPT_LOGOUT_001
# =============================================================================
# Rule 입력은 ArtifactRecord 만. 기본 fixture 는 수동 분석 사본에서 실제 확인된 visits.id=42 값
# (url_id 35, from_visit 41, transition 0x30000000, originator_cache_guid "", is_known_to_sync 0) 을 사용한다.

EXPECTED_LOGOUT_REASONS = ["RULE_VERIFIED", "DIRECT_URL", "TIMESTAMP_EXPLAINED"]


def make_history_record(url=LOGOUT_URL, visit_id=42, raw=LOGOUT_RAW, *, guid="", is_known_to_sync=0,
                        transition=0x30000000, source_path="Default/History", browser_profile="Default"):
    timestamp = p.normalize_timestamp(raw, "webkit_us", "History.visits.visit_time")
    warnings = timestamp.pop("warnings")
    observed = {
        "visit_id": visit_id, "url_id": 35, "url": url, "title": "ChatGPT", "from_visit": 41,
        "transition_raw": transition, **p.decode_transition(transition),
        "originator_cache_guid": guid, "is_known_to_sync": is_known_to_sync,
    }
    return p.ArtifactRecord(
        record_id=f"history:{source_path}#visits.id={visit_id}", artifact_type="history",
        browser_profile=browser_profile, source_path=source_path, record_location=f"visits.id={visit_id}",
        observed=observed, warnings=warnings, **timestamp,
    )


class LogoutRuleTest(unittest.TestCase):
    def detect_one(self, record, coverages=()):
        events = p.detect_logout([record], coverages)
        self.assertEqual(len(events), 1)
        return events[0]

    # 1
    def test_exact_logout_url_creates_one_event(self):
        events = p.detect_logout([make_history_record()])
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], p.Event)

    # 2~7
    def test_event_classification(self):
        event = self.detect_one(make_history_record())
        self.assertEqual(event.action, "LOGOUT")
        self.assertEqual(event.action_status, "DETECTED")
        self.assertEqual(event.finding_type, "USER_ACTION")
        self.assertEqual(event.confidence, "HIGH")
        self.assertEqual(event.rule_id, "CHATGPT_LOGOUT_001")
        self.assertEqual(event.rule_verification, "VERIFIED")

    # 8
    def test_evidence_level_direct(self):
        event = self.detect_one(make_history_record())
        self.assertEqual(len(event.primary_evidence), 1)
        self.assertEqual(event.primary_evidence[0].evidence_level, "DIRECT")
        self.assertEqual(event.supporting_evidence, [])

    # 9
    def test_representative_evidence_linked(self):
        record = make_history_record()
        event = self.detect_one(record)
        evidence = event.primary_evidence[0]
        self.assertEqual(event.representative_evidence_id, evidence.evidence_id)
        self.assertEqual(evidence.record_id, record.record_id)

    # 10~12
    def test_timestamps_passed_from_record(self):
        event = self.detect_one(make_history_record())
        evidence = event.primary_evidence[0]
        for obj in (event, evidence):
            self.assertEqual(obj.timestamp_raw, "13432494600507032")
            self.assertEqual(obj.timestamp_utc, "2026-08-29T16:30:00.507032Z")
            self.assertEqual(obj.timestamp_kst, "2026-08-30T01:30:00.507032+09:00")
            self.assertEqual(obj.timestamp_type, "webkit_us")
            self.assertEqual(obj.timestamp_source, "History.visits.visit_time")

    # 13~14
    def test_source_path_and_record_location_passed(self):
        coverage = p.Coverage(artifact_type="history", source_path="Default/History", status="PARSED",
                              record_count=1, source_sha256="ab" * 32)
        evidence = self.detect_one(make_history_record(), [coverage]).primary_evidence[0]
        self.assertEqual(evidence.source_path, "Default/History")
        self.assertEqual(evidence.record_location, "visits.id=42")
        self.assertEqual(evidence.source_sha256, "ab" * 32)
        self.assertIsNone(self.detect_one(make_history_record()).primary_evidence[0].source_sha256)  # Coverage 없으면 None

    # 15
    def test_unrelated_urls_create_no_event(self):
        urls = ["https://chatgpt.com/", "https://chatgpt.com/c/6a86cf88-a4d8-83ee-9ef5-d2e6b3c3952f",
                "https://chatgpt.com/profile", "https://example.com/auth/logout"]
        self.assertEqual(p.detect_logout([make_history_record(u, visit_id=i) for i, u in enumerate(urls)]), [])

    # 16
    def test_lookalike_hosts_create_no_event(self):
        urls = ["https://notchatgpt.com/auth/logout", "https://chatgpt.com.example.com/auth/logout",
                "https://evil.example/?next=https://chatgpt.com/auth/logout"]
        self.assertEqual(p.detect_logout([make_history_record(u, visit_id=i) for i, u in enumerate(urls)]), [])

    # 17
    def test_other_paths_create_no_event(self):
        urls = ["https://chatgpt.com/auth/logout2", "https://chatgpt.com/foo/auth/logout", "https://chatgpt.com/auth/logout/",
                "https://chatgpt.com/AUTH/LOGOUT", "http://chatgpt.com/auth/logout", "https://chatgpt.com/auth/logout%2F"]
        self.assertEqual(p.detect_logout([make_history_record(u, visit_id=i) for i, u in enumerate(urls)]), [])

    # 18
    def test_auth_openai_urls_create_no_event(self):
        urls = ["https://auth.openai.com/log-in/password", "https://auth.openai.com/api/accounts/authorize",
                "https://auth.openai.com/auth/logout"]
        self.assertEqual(p.detect_logout([make_history_record(u, visit_id=i) for i, u in enumerate(urls)]), [])

    # 19
    def test_duplicate_handling(self):
        record = make_history_record()
        self.assertEqual(len(p.detect_logout([record, record])), 1)  # 같은 visit 중복 입력 → 1건
        self.assertEqual(len(p.detect_logout([record, make_history_record()])), 1)  # 내용이 같은 별도 객체도 1건
        second_visit = make_history_record(visit_id=90, raw="13432495000000000")
        events = p.detect_logout([record, second_visit])  # 서로 다른 visit → 각각
        self.assertEqual([e.primary_evidence[0].record_location for e in events], ["visits.id=42", "visits.id=90"])
        other_profile = make_history_record(source_path="Profile 1/History", browser_profile="Profile 1")
        self.assertEqual(len(p.detect_logout([record, other_profile])), 2)  # 같은 visits.id 라도 다른 History
        self.assertEqual(len({e.event_id for e in p.detect_logout([record, other_profile])}), 2)

    # 20
    def test_transition_metadata_preserved(self):
        observed = self.detect_one(make_history_record()).primary_evidence[0].observed
        self.assertEqual(observed["transition_raw"], 0x30000000)
        self.assertEqual(observed["transition_hex"], "0x30000000")
        self.assertEqual(observed["transition_core"], "LINK")
        self.assertEqual(observed["transition_qualifiers"], ["CHAIN_START", "CHAIN_END"])
        self.assertIn("0x30000000", self.detect_one(make_history_record()).primary_evidence[0].note)

    # 21
    def test_redirect_reload_forward_back_do_not_lower_confidence(self):
        cases = {
            "CLIENT_REDIRECT": 0x30000000 | 0x40000000,
            "SERVER_REDIRECT": SIGNED_SERVER_REDIRECT_CHAIN_END,
            "FORWARD_BACK": 0x30000000 | 0x01000000,
            "RELOAD": 0x30000000 | 8,
        }
        for name, transition in cases.items():
            with self.subTest(metadata=name):
                event = self.detect_one(make_history_record(transition=transition))
                self.assertEqual(event.confidence, "HIGH")
                self.assertEqual(event.action_status, "DETECTED")
                self.assertEqual(event.confidence_reason, EXPECTED_LOGOUT_REASONS)
                self.assertTrue(any(name in limitation for limitation in event.limitations))
        self.assertEqual(self.detect_one(make_history_record()).limitations, [])  # 일반 LINK 는 limitation 없음

    # 22
    def test_sync_metadata_preserved(self):
        observed = self.detect_one(make_history_record()).primary_evidence[0].observed
        self.assertEqual(observed["originator_cache_guid"], "")
        self.assertEqual(observed["is_known_to_sync"], 0)

    # 23
    def test_device_attribution_policy(self):
        base = self.detect_one(make_history_record(guid="", is_known_to_sync=0))
        self.assertEqual(base.device_attribution, "UNKNOWN")
        self.assertIn("LOCAL candidate", base.primary_evidence[0].note)
        known_only = self.detect_one(make_history_record(guid="", is_known_to_sync=1))
        self.assertEqual(known_only.device_attribution, "UNKNOWN")  # is_known_to_sync 단독으로 REMOTE_SYNCED 금지
        remote = self.detect_one(make_history_record(guid="remote-device-guid", is_known_to_sync=0))
        self.assertEqual(remote.device_attribution, "REMOTE_SYNCED")
        self.assertEqual(remote.confidence, "HIGH")  # Device Attribution 이 Confidence 를 낮추지 않음
        absent = self.detect_one(make_history_record(guid=None, is_known_to_sync=None))
        self.assertEqual(absent.device_attribution, "UNKNOWN")

    # 24
    def test_timestamp_failure(self):
        for raw, warning in (("abc", "TIMESTAMP_INVALID_NUMBER"), (None, "TIMESTAMP_MISSING"), ("0", "TIMESTAMP_MISSING")):
            with self.subTest(raw=raw):
                event = self.detect_one(make_history_record(raw=raw))
                self.assertEqual(event.action, "LOGOUT")  # Evidence 는 잃지 않는다
                self.assertEqual(event.confidence, "LOW")
                self.assertEqual(event.action_status, "CANDIDATE")
                self.assertIsNone(event.timestamp_utc)
                self.assertIsNone(event.timestamp_kst)
                self.assertIn("TIMESTAMP_MISSING", event.confidence_reason)
                self.assertNotIn("TIMESTAMP_EXPLAINED", event.confidence_reason)
                self.assertIn(warning, event.warnings)
                self.assertEqual(event.representative_evidence_id, event.primary_evidence[0].evidence_id)
                self.assertTrue(event.limitations)

    def test_confidence_reason_has_no_unchecked_contradiction_code(self):
        event = self.detect_one(make_history_record())
        self.assertEqual(event.confidence_reason, EXPECTED_LOGOUT_REASONS)
        self.assertNotIn("NO_KNOWN_CONTRADICTION", event.confidence_reason)

    def test_url_variant_policy(self):
        for url in ("https://chatgpt.com/auth/logout?next=%2F", "https://chatgpt.com/auth/logout#x",
                    "https://chatgpt.com:443/auth/logout", "https://chatgpt.com./auth/logout"):
            with self.subTest(url=url):
                event = self.detect_one(make_history_record(url))
                self.assertEqual((event.action_status, event.confidence), ("DETECTED", "MEDIUM"))
                self.assertIn("URL_VARIANT_NOT_VERIFIED", event.confidence_reason)
        self.assertEqual(self.detect_one(make_history_record("https://CHATGPT.COM/auth/logout")).confidence, "HIGH")
        self.assertEqual(p.match_logout_url(LOGOUT_URL), "exact")
        for bad in (None, "", "chatgpt.com/auth/logout", "https://chatgpt.com:bad/auth/logout", "https://[::1/auth/logout"):
            with self.subTest(bad=bad):
                self.assertIsNone(p.match_logout_url(bad))

    def test_input_records_not_modified(self):
        records = [make_history_record(), make_history_record("https://chatgpt.com/", visit_id=41)]
        before = [record.to_dict() for record in records]
        events = p.detect_logout(records)
        events[0].primary_evidence[0].observed["transition_qualifiers"].append("MUTATED")
        self.assertEqual([record.to_dict() for record in records], before)  # ArtifactRecord 는 그대로 유지

    def test_non_history_records_ignored(self):
        record = make_history_record()
        record.artifact_type = "local_storage"  # 같은 URL 이라도 History 가 아니면 이 Rule 대상 아님
        self.assertEqual(p.detect_logout([record]), [])

    def test_event_fits_parse_result_json(self):
        record = make_history_record()
        result = p.ParseResult(run_id="r", run_started_utc="2026-09-14T00:00:00Z",
                               input=p.InputInfo(kind="directory", path="synthetic"),
                               records=[record], events=p.detect_logout([record]))
        loaded = json.loads(result.to_json())
        self.assertEqual(loaded["events"][0]["primary_evidence"][0]["timestamp_raw"], "13432494600507032")
        self.assertEqual(len(loaded["records"]), 1)  # Observation 과 Event 가 함께 유지됨


class LogoutEndToEndSyntheticTest(HistoryTestBase):
    def test_reader_to_rule(self):
        records, coverage = p.read_chatgpt_history(self.source, "Default/History")
        events = p.detect_logout(records, [coverage])
        self.assertEqual(len(events), 1)
        event = events[0]
        evidence = event.primary_evidence[0]
        self.assertEqual(evidence.record_location, "visits.id=42")
        self.assertEqual(evidence.source_sha256, coverage.source_sha256)
        self.assertEqual((event.action, event.action_status, event.confidence), ("LOGOUT", "DETECTED", "HIGH"))
        self.assertEqual(len(records), len(CHATGPT_VISIT_IDS))  # Record 는 그대로 남아 있음


# =============================================================================
# S6 — extract() / detect() / run() / CLI / Conversation Result Model
# =============================================================================
# 대화 추출(Conversation Extraction)은 구현하지 않았다. Conversation 테스트는 Result Model / JSON 구조 테스트뿐이다.

PARSER_FILE = Path(__file__).resolve().parent.parent / "chatgpt_web_parser.py"


def run_main(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = p.main([str(arg) for arg in argv])
    return code, stdout.getvalue(), stderr.getvalue()


class PipelineTest(HistoryTestBase):
    # 1
    def test_extract(self):
        records, coverages = p.extract(self.source, "Default/History")
        self.assertEqual([record.observed["visit_id"] for record in records], CHATGPT_VISIT_IDS)
        # S9-pre: 같은 폴더의 Local Storage/leveldb 도 읽는다 (fixture 에는 없음 → NOT_PRESENT)
        self.assertEqual([(c.artifact_type, c.status) for c in coverages],
                         [("history", "PARSED"), ("local_storage", "NOT_PRESENT"), ("session_storage", "NOT_PRESENT"),
                          ("cache", "NOT_PRESENT"), ("shared_proto_db", "NOT_PRESENT"),
                          ("sessions", "NOT_PRESENT")])

    # 2
    def test_detect(self):
        records, coverages = p.extract(self.source, "Default/History")
        events = p.detect(records, coverages)
        # fixture 에는 로그아웃 방문(42)과 callback 방문(47)이 있다 → S8 부터 LOGIN 도 함께 나온다
        self.assertEqual(sorted((e.action, e.action_status, e.confidence) for e in events),
                         [("LOGIN", "DETECTED", "MEDIUM"), ("LOGOUT", "DETECTED", "HIGH")])
        for event in events:
            self.assertEqual(event.primary_evidence[0].source_sha256, coverages[0].source_sha256)

    # 3~9
    def test_run_builds_parse_result(self):
        result = p.run(self.source, "Default/History")
        self.assertIsInstance(result, p.ParseResult)
        self.assertEqual(len(result.records), len(CHATGPT_VISIT_IDS))
        self.assertEqual(sorted(e.action for e in result.events), ["LOGIN", "LOGOUT"])
        self.assertEqual(result.coverage[0].status, "PARSED")
        self.assertEqual(result.conversations, [])
        self.assertIn("conversations", result.to_dict())
        self.assertEqual((result.input.kind, result.input.path), ("directory", str(self.source.root)))
        uuid.UUID(result.run_id)
        self.assertTrue(result.run_started_utc.endswith("Z"))
        datetime.fromisoformat(result.run_started_utc)
        self.assertEqual(result.warnings, [p.RUN_WARNING_ANALYSIS_SCOPE,
                                           p.RUN_WARNING_MESSAGE_RECOVERY_SCOPE])
        self.assertNotEqual(result.run_id, p.run(self.source, "Default/History").run_id)

    def test_sort_by_timestamp_uses_real_time(self):
        later = make_history_record(visit_id=2, raw="13432494602500000")    # ...16:30:02.500000Z
        missing = make_history_record(visit_id=3, raw=None)
        earlier = make_history_record(visit_id=1, raw="13432494602000000")  # ...16:30:02Z
        self.assertLess(later.timestamp_utc, earlier.timestamp_utc)  # 문자열 비교만 하면 순서가 뒤집히는 경우
        ordered = p.sort_by_timestamp([later, missing, earlier])
        self.assertEqual([record.observed["visit_id"] for record in ordered], [1, 2, 3])

    def test_run_sorts_records(self):
        path = self.variant("History_unsorted", visits=list(reversed(HISTORY_VISITS)))
        times = [record.timestamp_utc for record in p.run(self.source, path).records]
        self.assertEqual(times, sorted(times, key=datetime.fromisoformat))

    # 10~12
    def test_json_file_round_trip_utf8(self):
        result = p.run(self.source, "Default/History")
        out = Path(self._tmp.name) / "out" / "result.json"
        p.write_result_json(result, out)
        raw_bytes = out.read_bytes()
        self.assertIn("로그인 - OpenAI".encode("utf-8"), raw_bytes)
        self.assertNotIn(b"\\ub85c", raw_bytes)  # \uXXXX 이스케이프 없이 저장
        loaded = json.loads(raw_bytes.decode("utf-8"))
        self.assertEqual(loaded, result.to_dict())
        self.assertEqual(list(loaded)[-2:], ["conversations", "warnings"])
        with self.assertRaises(FileExistsError):
            p.write_result_json(result, out)  # 기본은 덮어쓰지 않음


class CliTest(HistoryTestBase):
    def setUp(self):
        super().setUp()
        self.out = Path(self._tmp.name) / "output" / "result.json"

    def cli(self, *extra, history="Default/History", out=None):
        return run_main(["--dir", self.root, "--history", history, "--out", out or self.out, *extra])

    # 13, 14
    def test_cli_success_summary(self):
        code, stdout, stderr = self.cli()
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertEqual(stderr, "")
        self.assertTrue(self.out.is_file())
        expected_lines = [
            "ChatGPT Web Artifact Parser", "[INPUT]", "Type".ljust(11) + ": Directory",
            "[ARTIFACTS]", "History".ljust(11) + ": PARSED (4 ChatGPT records)",
            "[USER ACTIONS]",
            "[CONVERSATIONS]", "Recovered Conversations".ljust(24) + ": 0", "Recovered Message Nodes".ljust(24) + ": 0",
            "Status".ljust(24) + ": NONE RECOVERED", "Message Recovery".ljust(24) + f": {p.MESSAGE_RECOVERY_STATUS}",
            "Local Storage: leveldb NOT_PRESENT (0 ChatGPT records)",
            "[RESULT]", "Records".ljust(14) + ": 4", "Events".ljust(14) + ": 2", "Conversations".ljust(14) + ": 0",
            "JSON:", str(self.out.resolve()),
        ]
        for line in expected_lines:
            self.assertIn(line, stdout)
        # Event 는 저장된 UTC / KST 와 함께 한 줄씩
        self.assertRegex(stdout, rf"(?m)^{re.escape(LOGOUT_UTC)}\s+{re.escape(LOGOUT_KST)}\s+LOGOUT\s+DETECTED\s+HIGH$")
        self.assertRegex(stdout, r"(?m)^\S+Z\s+\S+\+09:00\s+LOGIN\s+DETECTED\s+MEDIUM$")
        self.assertNotIn("로그인 - OpenAI", stdout)  # Record 내용은 화면에 출력하지 않음

    # 15~17
    def test_cli_json_content(self):
        self.assertEqual(self.cli()[0], p.EXIT_OK)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        for key in ("parser_name", "parser_version", "run_id", "run_started_utc", "input", "display_timezone",
                    "coverage", "records", "events", "conversations", "warnings"):
            self.assertIn(key, data)
        event = data["events"][0]
        self.assertEqual((event["action"], event["action_status"], event["confidence"], event["rule_id"]),
                         ("LOGOUT", "DETECTED", "HIGH", "CHATGPT_LOGOUT_001"))
        self.assertEqual(event["timestamp_utc"], LOGOUT_UTC)
        self.assertEqual(event["timestamp_kst"], LOGOUT_KST)
        self.assertEqual(event["primary_evidence"][0]["record_location"], "visits.id=42")
        self.assertEqual(data["conversations"], [])
        self.assertEqual(data["display_timezone"], "+09:00 (KST)")

    def test_cli_script_entry_point(self):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        completed = subprocess.run(
            [sys.executable, "-B", str(PARSER_FILE), "--dir", str(self.root), "--history", "Default/History", "--out", str(self.out)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LOGOUT", completed.stdout)
        self.assertEqual(json.loads(self.out.read_text(encoding="utf-8"))["conversations"], [])
        rejected = subprocess.run(
            [sys.executable, "-B", str(PARSER_FILE), "--image", "disk.E01", "--out", str(self.out.with_name("x.json"))],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=120,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertNotIn("Traceback", rejected.stderr)

    # 18
    def test_history_missing_is_not_fatal(self):
        code, stdout, stderr = self.cli(history="Profile 9/History")
        self.assertEqual(code, p.EXIT_OK, stderr)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(data["coverage"][0]["status"], "NOT_PRESENT")
        self.assertEqual((data["records"], data["events"], data["conversations"]), ([], [], []))
        self.assertIn("History".ljust(11) + ": NOT_PRESENT", stdout)
        self.assertIn("(none)", stdout)

    # 19
    def test_zero_chatgpt_records_is_not_fatal(self):
        path = self.variant("History_other", urls=[(1, "https://example.com/", "Example")],
                            visits=[(1, 1, 13432494600000000, 0, 0, "", 0)])
        code, _, stderr = self.cli(history=path)
        self.assertEqual(code, p.EXIT_OK, stderr)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual((data["coverage"][0]["status"], data["coverage"][0]["record_count"], data["events"]), ("PARSED", 0, []))

    # 20
    def test_image_input_e01_requires_pyewf(self):
        image = Path(self._tmp.name) / "disk.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")  # 실제 E01 이 아니라 시그니처만 흉내낸 파일
        code, stdout, stderr = run_main(["--image", image, "--out", self.out])
        self.assertEqual(code, p.EXIT_USAGE)
        self.assertIn("invalid --image", stderr)
        # pyewf 가 없는 환경이면 의존성 오류, 있는 환경이면 pyewf 가 이 파일을 열지 못한다
        self.assertRegex(stderr, f"{p.E01_REQUIRES_PYEWF}|{p.E01_SEGMENTS_UNREADABLE}|{p.E01_OPEN_FAILED}")
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(stdout, "")
        self.assertFalse(self.out.exists())

    # 21
    def test_invalid_input_exit_code(self):
        cases = [
            ["--dir", Path(self._tmp.name) / "missing", "--history", "History", "--out", self.out],
            ["--dir", self.history_file, "--history", "History", "--out", self.out],
            ["--dir", self.root, "--history", "../outside.db", "--out", self.out],
            ["--dir", self.root, "--history", "", "--out", self.out],
            ["--dir", self.root, "--image", "x.E01", "--history", "Default/History", "--out", self.out],
            [],
            ["--unknown-option"],
        ]
        for argv in cases:
            with self.subTest(argv=[str(arg) for arg in argv]):
                code, _, stderr = run_main(argv)
                self.assertEqual(code, p.EXIT_USAGE)
                self.assertTrue(stderr.strip())
                self.assertNotIn("Traceback", stderr)
                self.assertFalse(self.out.exists())

    def test_without_out_no_json_is_written(self):
        """--out 은 optional 이다. 주지 않으면 JSON 을 만들지 않고 정상 종료한다."""
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History"])
        self.assertEqual(code, p.EXIT_OK)
        self.assertFalse(self.out.exists())
        self.assertNotIn("Traceback", stderr)
        self.assertIn("ChatGPT Web Artifact Parser", stdout)

    def test_help_exit_code(self):
        self.assertEqual(run_main(["--help"])[0], p.EXIT_OK)

    # 22
    def test_output_inside_source_rejected(self):
        before = tree_snapshot(self.root)
        targets = [self.root / "result.json", self.root / "Default" / "result.json", self.history_file, self.root]
        if os.name == "nt":
            targets.append(Path(str(self.root).upper()) / "Default" / "UPPER.json")  # 대소문자만 다른 경로
        for out in targets:
            with self.subTest(out=str(out)):
                code, _, stderr = self.cli("--overwrite", out=out)
                self.assertEqual(code, p.EXIT_USAGE)
                self.assertIn("outside", stderr)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_existing_output_requires_overwrite(self):
        self.out.parent.mkdir(parents=True)
        self.out.write_text("previous", encoding="utf-8")
        code, _, stderr = self.cli()
        self.assertEqual(code, p.EXIT_USAGE)
        self.assertIn("--overwrite", stderr)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "previous")
        self.assertEqual(self.cli("--overwrite")[0], p.EXIT_OK)
        self.assertEqual(json.loads(self.out.read_text(encoding="utf-8"))["events"][0]["action"], "LOGOUT")
        self.assertEqual(self.cli("--overwrite", out=self.out.parent)[0], p.EXIT_USAGE)  # 폴더는 거부

    # 23
    def test_source_tree_unchanged_after_cli(self):
        (self.root / "Default" / "History-wal").write_bytes(b"synthetic wal content")
        before = tree_snapshot(self.root)
        self.assertEqual(self.cli()[0], p.EXIT_OK)
        self.cli(history="Profile 9/History", out=self.out.with_name("missing.json"))
        run_main(["--dir", self.root, "--history", "../x", "--out", self.out.with_name("bad.json")])
        self.assertEqual(tree_snapshot(self.root), before)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertIn(p.HISTORY_WAL_PRESENT_UNMERGED, data["coverage"][0]["warnings"])

    def test_unexpected_error_exit_code(self):
        with mock.patch("chatgpt_parser.cli.run", side_effect=RuntimeError("boom")):
            code, stdout, stderr = self.cli()
        self.assertEqual(code, p.EXIT_FATAL)
        self.assertIn("RuntimeError", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertFalse(self.out.exists())


class SummaryFormatTest(unittest.TestCase):
    def test_summary_counts_and_grouping(self):
        records = [make_history_record(), make_history_record(visit_id=90, raw="13432495000000000")]
        result = p.ParseResult(
            run_id="r", run_started_utc="2026-09-15T00:00:00Z", input=p.InputInfo(kind="directory", path="C:\\case"),
            coverage=[p.Coverage(artifact_type="history", source_path="Default/History", status="PARSED",
                                 record_count=2, warnings=["HISTORY_WAL_PRESENT_UNMERGED"])],
            records=records, events=p.detect_logout(records), conversations=[make_conversation()],
            warnings=["W1"],
        )
        text = p.format_summary(result)
        self.assertIn("History".ljust(11) + ": PARSED (2 ChatGPT records) [warnings: 1]", text)
        self.assertEqual(len(re.findall(r"(?m)^\S+Z\s+\S+\+09:00\s+LOGOUT\s+DETECTED\s+HIGH$", text)), 2)  # Event 마다 한 줄
        self.assertIn("Recovered Conversations".ljust(24) + ": 1", text)
        self.assertIn("Recovered Message Nodes".ljust(24) + ": 2", text)
        self.assertIn("Status".ljust(24) + ": RECOVERED", text)
        self.assertIn("  - W1", text)
        self.assertNotIn("JSON:", text)
        self.assertIn("Chrome History 분석 방법 알려줘", text)  # 실제로 복구된 메시지 본문은 화면에도 출력


LONG_ASSISTANT_TEXT = "Chrome History 는 SQLite 파일입니다.\n" * 500
CACHE_PATH = "Default/Cache/Cache_Data/data_1"


def make_message(index=0, **overrides):
    values = dict(
        message_id=f"msg-{index}", conversation_id="conv-1", parent_message_id=None if index == 0 else f"msg-{index - 1}",
        sequence_index=index, role="user" if index == 0 else "assistant",
        content="Chrome History 분석 방법 알려줘" if index == 0 else LONG_ASSISTANT_TEXT, content_type="text",
        timestamp_raw="2026-09-12T18:04:34.276355Z", timestamp_utc="2026-09-12T18:04:34.276355Z",
        timestamp_kst="2026-09-13T03:04:34.276355+09:00", timestamp_type="iso_utc",
        timestamp_source="synthetic.message.create_time",
        source_artifact="cache", source_path=CACHE_PATH, record_location="synthetic:offset=0",
        recovery_status="RECOVERED",
    )
    values.update(overrides)
    return p.RecoveredMessage(**values)


def make_conversation(**overrides):
    values = dict(
        conversation_id="conv-1", title="크롬 히스토리 질문", recovery_status="RECOVERED",
        messages=[make_message(0), make_message(1)],
        source_artifacts=[{"artifact_type": "cache", "source_path": CACHE_PATH, "record_location": "synthetic:offset=0",
                           "source_sha256": None}],
    )
    values.update(overrides)
    return p.RecoveredConversation(**values)


class ConversationModelTest(unittest.TestCase):
    """Conversation Result Model / JSON 구조 테스트 (synthetic). Conversation Extraction 테스트가 아니다."""

    def test_conversation_json_round_trip_keeps_full_content(self):
        result = p.ParseResult(run_id="r", run_started_utc="2026-09-15T00:00:00Z",
                               input=p.InputInfo(kind="directory", path="synthetic"), conversations=[make_conversation()])
        text = result.to_json()
        self.assertIn("Chrome History 분석 방법 알려줘", text)
        loaded = json.loads(text)
        conversation = loaded["conversations"][0]
        self.assertEqual((conversation["conversation_id"], conversation["title"], conversation["recovery_status"]),
                         ("conv-1", "크롬 히스토리 질문", "RECOVERED"))
        user, assistant = conversation["messages"]
        self.assertEqual((user["role"], user["content"]), ("user", "Chrome History 분석 방법 알려줘"))
        self.assertEqual(assistant["content"], LONG_ASSISTANT_TEXT)  # 요약·절단 없음
        self.assertEqual(len(assistant["content"]), len(LONG_ASSISTANT_TEXT))
        for key in ("timestamp_raw", "timestamp_utc", "timestamp_kst", "timestamp_type", "timestamp_source",
                    "source_artifact", "source_path", "record_location", "source_sha256", "recovery_status"):
            self.assertIn(key, user)
        self.assertEqual(loaded, result.to_dict())

    def test_message_defaults_and_unknown_time(self):
        message = p.RecoveredMessage(source_artifact="cache", source_path=CACHE_PATH, recovery_status="PARTIAL", content="부분")
        self.assertEqual(message.role, "UNKNOWN")
        self.assertIsNone(message.timestamp_raw)
        self.assertIsNone(message.timestamp_utc)
        self.assertIsNone(message.timestamp_kst)
        self.assertEqual(message.timestamp_type, "unknown")

    def test_role_value_preserved(self):
        for role in ("tool", "system", "System", "critic"):
            with self.subTest(role=role):
                self.assertEqual(make_message(role=role).role, role)
        with self.assertRaises(ValueError):
            make_message(role="")

    def test_recovery_status_rules(self):
        with self.assertRaises(ValueError):
            make_conversation(recovery_status="COMPLETE")
        with self.assertRaises(ValueError):
            make_message(recovery_status="COMPLETE")
        with self.assertRaises(ValueError):
            make_message(recovery_status="RESIDUAL_ONLY")
        with self.assertRaises(ValueError):
            make_conversation(recovery_status="RESIDUAL_ONLY")  # 메시지가 있으면 RESIDUAL_ONLY 아님
        residual = make_conversation(recovery_status="RESIDUAL_ONLY", messages=[])
        self.assertEqual(residual.messages, [])
        with self.assertRaises(ValueError):
            make_conversation(messages=[])  # RECOVERED 인데 메시지 없음
        with self.assertRaises(ValueError):
            make_conversation(messages=[make_message(0), make_message(1, recovery_status="PARTIAL")])
        partial = make_conversation(recovery_status="PARTIAL",
                                    messages=[make_message(0), make_message(1, recovery_status="PARTIAL", content=None)])
        self.assertEqual(partial.recovery_status, "PARTIAL")
        with self.assertRaises(ValueError):
            make_message(content=None)  # RECOVERED 메시지는 내용이 있어야 함

    def test_source_tracking_required(self):
        for override in ({"source_path": ""}, {"source_artifact": "web"}):
            with self.subTest(**override):
                with self.assertRaises(ValueError):
                    make_message(**override)
        with self.assertRaises(ValueError):
            make_conversation(source_artifacts=[])
        with self.assertRaises(ValueError):
            make_conversation(source_artifacts=[{"artifact_type": "cache"}])
        with self.assertRaises(TypeError):
            make_conversation(source_artifacts=["Default/Cache"])

    def test_conversation_id_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            make_conversation(messages=[make_message(0, conversation_id="other")])

    def test_timestamps_follow_utc_kst_policy(self):
        with self.assertRaises(ValueError):
            make_message(timestamp_raw=None)  # utc/kst 만 있고 raw 없음
        with self.assertRaises(ValueError):
            make_conversation(create_time_utc="2026-09-12T18:04:34Z")
        conversation = make_conversation(create_time_raw="2026-09-12T18:04:34.276355Z",
                                         create_time_utc="2026-09-12T18:04:34.276355Z",
                                         create_time_kst="2026-09-13T03:04:34.276355+09:00", create_time_type="iso_utc")
        self.assertEqual(conversation.create_time_kst, "2026-09-13T03:04:34.276355+09:00")

    def test_parse_result_rejects_non_conversation_items(self):
        with self.assertRaises(TypeError):
            p.ParseResult(run_id="r", run_started_utc="2026-09-15T00:00:00Z",
                          input=p.InputInfo(kind="directory", path="x"), conversations=[{"conversation_id": "x"}])


# =============================================================================
# S7 — Windows User / Chrome Profile Discovery (Auto Discovery Mode)
# =============================================================================
# 임시 폴더에 만든 synthetic Users 트리만 사용한다. 실제 사용자 Profile 을 읽거나 수정하지 않는다.

USER_DATA_PARTS = ("AppData", "Local", "Google", "Chrome", "User Data")
ALICE_UD = "Users/Alice/AppData/Local/Google/Chrome/User Data"
PROFILE1_URLS = [(1, "https://chatgpt.com/c/6a86cf88-a4d8-83ee-9ef5-d2e6b3c3952f", "안녕 인사 응답")]
PROFILE1_VISITS = [(1, 1, 13432490000000000, 0, 0x30000000, "", 0)]
PROFILE10_URLS = [(1, "https://example.com/", "Example"), (2, "https://auth.openai.com/log-in/password", "로그인")]
PROFILE10_VISITS = [(1, 1, 13432491000000000, 0, 1, "", 0), (2, 2, 13432492000000000, 0, 0x30000000, "", 0)]
PARSE_RESULT_KEYS = ["parser_name", "parser_version", "run_id", "run_started_utc", "input", "display_timezone",
                     "coverage", "records", "events", "conversations", "warnings"]


def user_data_dir(root, user, parts=USER_DATA_PARTS):
    return Path(root, "Users", user, *parts)


def create_directory_link(link, target):
    """디렉터리 링크 생성 (Windows 는 관리자 권한 없이 가능한 junction 우선). 실패하면 None."""
    try:
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
        return link
    except (ImportError, AttributeError, OSError):
        pass
    try:
        os.symlink(target, link, target_is_directory=True)
        return link
    except (OSError, NotImplementedError):
        return None


def build_profile_tree(root):
    """
    Users/Alice : Default, Profile 1, Profile 10 (History 있음) + System Profile / Guest Profile / Profile / Crashpad
                  / 파일 'Profile 2' / 손상된 Local State
    Users/Bob   : Default 폴더만 (History 없음)
    Users/Charlie, Users/Public : Chrome 없음
    """
    alice = user_data_dir(root, "Alice")
    for name in ("Default", "Profile 1", "Profile 10", "System Profile", "Guest Profile", "Profile", "Crashpad"):
        (alice / name).mkdir(parents=True)
    create_history_db(alice / "Default" / "History")
    create_history_db(alice / "Profile 1" / "History", urls=PROFILE1_URLS, visits=PROFILE1_VISITS)
    create_history_db(alice / "Profile 10" / "History", urls=PROFILE10_URLS, visits=PROFILE10_VISITS)
    create_history_db(alice / "System Profile" / "History")  # 로그아웃 방문이 있어도 Profile 이 아니므로 제외
    create_history_db(alice / "Guest Profile" / "History")
    (alice / "Profile 2").write_bytes(b"not a directory")
    (alice / "Local State").write_bytes(b"{ broken json")
    (user_data_dir(root, "Bob") / "Default").mkdir(parents=True)
    (Path(root) / "Users" / "Charlie" / "Documents").mkdir(parents=True)
    (Path(root) / "Users" / "Charlie" / "Documents" / "readme.txt").write_text("no chrome", encoding="utf-8")
    (Path(root) / "Users" / "Public" / "Desktop").mkdir(parents=True)
    (Path(root) / "Users" / "desktop.ini").write_bytes(b"[.ShellClassInfo]")


class ProfileDiscoveryTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "evidence"
        self.root.mkdir()
        build_profile_tree(self.root)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def found(self, source=None):
        return [(profile.os_user, profile.browser_profile) for profile in p.discover_chrome_profiles(source or self.source)]


class ProfileDiscoveryTest(ProfileDiscoveryTestBase):
    # 1, 2, 3, 5, 6
    def test_profiles_found_for_multiple_users(self):
        self.assertEqual(self.found(), [("Alice", "Default"), ("Alice", "Profile 1"), ("Alice", "Profile 10"), ("Bob", "Default")])

    def test_profile_paths_and_model(self):
        profiles = p.discover_chrome_profiles(self.source)
        alice_default = profiles[0]
        self.assertIsInstance(alice_default, p.ChromeProfile)
        self.assertEqual(alice_default.browser, p.DEFAULT_BROWSER)
        self.assertEqual(alice_default.profile_path, f"{ALICE_UD}/Default")
        self.assertEqual(alice_default.history_path, f"{ALICE_UD}/Default/History")
        self.assertEqual(profiles[2].profile_path, f"{ALICE_UD}/Profile 10")
        self.assertEqual(alice_default.to_dict()["os_user"], "Alice")
        for profile in profiles:
            self.assertTrue(self.source.is_dir(profile.profile_path))
        with self.assertRaises(ValueError):
            p.ChromeProfile(os_user="", browser_profile="Default", profile_path="x", history_path="x/History")

    # 4
    def test_natural_profile_ordering(self):
        root = self.base / "order"
        for name in ("Profile 10", "Profile 2", "Default", "Profile 1", "Profile 100"):
            (user_data_dir(root, "Erin") / name).mkdir(parents=True)
        self.assertEqual(self.found(p.DirectorySource(root)),
                         [("Erin", name) for name in ("Default", "Profile 1", "Profile 2", "Profile 10", "Profile 100")])

    def test_user_ordering_is_stable(self):
        root = self.base / "users"
        for user in ("bob", "Zed", "Alice"):
            (user_data_dir(root, user) / "Default").mkdir(parents=True)
        self.assertEqual([user for user, _ in self.found(p.DirectorySource(root))], ["Alice", "bob", "Zed"])
        self.assertEqual(self.found(), self.found())  # 반복 호출 결과 동일

    # 7, 8
    def test_non_profile_directories_excluded(self):
        names = {name for _, name in self.found()}
        for excluded in ("System Profile", "Guest Profile", "Profile", "Crashpad", "Profile 2"):
            self.assertNotIn(excluded, names)
        for name, expected in {"Default": True, "default": True, "Profile 1": True, "PROFILE 10": True,
                               "System Profile": False, "Guest Profile": False, "Profile": False, "Profile 1a": False,
                               "Profile-1": False, "Profile  1": False, "Profile ١": False, "": False}.items():
            with self.subTest(name=name):
                self.assertEqual(p.is_chrome_profile_name(name), expected)

    # 9
    def test_users_without_chrome_ignored(self):
        users = {user for user, _ in self.found()}
        self.assertTrue(users.isdisjoint({"Charlie", "Public", "desktop.ini"}))

    def test_system_user_folder_decided_by_path_not_name(self):
        (user_data_dir(self.root, "Public") / "Default").mkdir(parents=True)
        self.assertIn(("Public", "Default"), self.found())

    # 10
    def test_no_chrome_profiles_at_all(self):
        root = self.base / "empty"
        (root / "Users" / "Charlie" / "Documents").mkdir(parents=True)
        source = p.DirectorySource(root)
        self.assertEqual(p.discover_chrome_profiles(source), [])
        warnings = []
        self.assertEqual(p.extract(source, warnings=warnings), ([], []))
        self.assertEqual(warnings, [p.CHROME_PROFILE_NOT_FOUND])
        result = p.run(source)
        self.assertEqual((result.coverage, result.records, result.events, result.conversations), ([], [], [], []))
        self.assertIn(p.CHROME_PROFILE_NOT_FOUND, result.warnings)
        self.assertEqual(p.discover_chrome_profiles(p.DirectorySource(root / "Users" / "Charlie")), [])  # Users 폴더 없음

    # 11
    def test_profile_without_history(self):
        bob = [profile for profile in p.discover_chrome_profiles(self.source) if profile.os_user == "Bob"]
        self.assertEqual([profile.browser_profile for profile in bob], ["Default"])
        self.assertFalse(self.source.exists(bob[0].history_path))
        warnings = []
        _, coverages = p.extract(self.source, warnings=warnings)
        self.assertEqual([(c.artifact_type, c.browser_profile, c.status) for c in coverages if c.os_user == "Bob"],
                         [("history", "Default", "NOT_PRESENT"), ("local_storage", "Default", "NOT_PRESENT"),
                          ("session_storage", "Default", "NOT_PRESENT"), ("cache", "Default", "NOT_PRESENT"),
                          ("shared_proto_db", "Default", "NOT_PRESENT"),
                          ("sessions", "Default", "NOT_PRESENT")])
        self.assertNotIn(p.CHROME_PROFILE_NOT_FOUND, warnings)

    # 12
    def test_case_insensitive_discovery(self):
        root = self.base / "case"
        user_data = Path(root, "USERS", "Dave", "APPDATA", "local", "GOOGLE", "chrome", "user data")
        (user_data / "DEFAULT").mkdir(parents=True)
        (user_data / "profile 3").mkdir()
        create_history_db(user_data / "DEFAULT" / "HISTORY")
        source = p.DirectorySource(root)
        profiles = p.discover_chrome_profiles(source)
        self.assertEqual([(pr.os_user, pr.browser_profile) for pr in profiles], [("Dave", "DEFAULT"), ("Dave", "profile 3")])
        self.assertEqual(profiles[0].history_path, "USERS/Dave/APPDATA/local/GOOGLE/chrome/user data/DEFAULT/HISTORY")
        records, coverages = p.extract(source)
        self.assertEqual([c.status for c in coverages if c.artifact_type == "history"], ["PARSED", "NOT_PRESENT"])
        self.assertEqual(len(records), len(CHATGPT_VISIT_IDS))

    # 13
    def test_explicit_mode_unchanged(self):
        warnings = []
        records, coverages = p.extract(self.source, f"{ALICE_UD}/Profile 1/History", warnings=warnings)
        self.assertEqual([(c.artifact_type, c.os_user, c.browser_profile, c.status) for c in coverages],
                         [("history", None, None, "PARSED"), ("local_storage", None, None, "NOT_PRESENT"),
                          ("session_storage", None, None, "NOT_PRESENT"), ("cache", None, None, "NOT_PRESENT"),
                          ("shared_proto_db", None, None, "NOT_PRESENT"),
                          ("sessions", None, None, "NOT_PRESENT")])
        self.assertEqual(coverages[1].source_path, f"{ALICE_UD}/Profile 1/Local Storage/leveldb")  # History 와 같은 폴더
        self.assertEqual(coverages[2].source_path, f"{ALICE_UD}/Profile 1/Session Storage")
        self.assertEqual(coverages[3].source_path, f"{ALICE_UD}/Profile 1/Cache/Cache_Data")
        self.assertEqual(len(records), 1)
        self.assertEqual(warnings, [])  # 자동 탐색을 함께 실행하지 않음
        result = p.run(self.source, f"{ALICE_UD}/Default/History")
        self.assertEqual([c.artifact_type for c in result.coverage], ["history", "local_storage", "session_storage", "cache", "shared_proto_db", "sessions"])
        self.assertEqual(result.warnings, [p.RUN_WARNING_ANALYSIS_SCOPE,
                                           p.RUN_WARNING_MESSAGE_RECOVERY_SCOPE])

    # 14, 18
    def test_auto_mode_coverage_per_profile(self):
        _, all_coverages = p.extract(self.source)
        coverages = [c for c in all_coverages if c.artifact_type == "history"]
        self.assertEqual([(c.os_user, c.browser_profile, c.artifact_type) for c in all_coverages[:2]],
                         [("Alice", "Default", "history"), ("Alice", "Default", "local_storage")])  # Profile 마다 History 다음 Local Storage
        self.assertEqual([(c.os_user, c.browser_profile, c.status, c.record_count) for c in coverages],
                         [("Alice", "Default", "PARSED", 4), ("Alice", "Profile 1", "PARSED", 1),
                          ("Alice", "Profile 10", "PARSED", 1), ("Bob", "Default", "NOT_PRESENT", 0)])
        self.assertEqual([c.source_path for c in coverages[:3]],
                         [f"{ALICE_UD}/{name}/History" for name in ("Default", "Profile 1", "Profile 10")])
        self.assertTrue(all(c.browser == p.DEFAULT_BROWSER and c.artifact_type == "history" for c in coverages))

    # 15, 16, 17, 19
    def test_auto_mode_record_metadata_and_merge(self):
        records, _ = p.extract(self.source)
        counts = {}
        for record in records:
            self.assertEqual(record.browser, p.DEFAULT_BROWSER)
            self.assertTrue(record.source_path.startswith(f"Users/{record.os_user}/"))
            self.assertTrue(record.source_path.endswith(f"/{record.browser_profile}/History"))
            counts[(record.os_user, record.browser_profile)] = counts.get((record.os_user, record.browser_profile), 0) + 1
        self.assertEqual(counts, {("Alice", "Default"): 4, ("Alice", "Profile 1"): 1, ("Alice", "Profile 10"): 1})
        self.assertEqual({r.observed["title"] for r in records if r.browser_profile == "Profile 1"}, {"안녕 인사 응답"})
        result = p.run(self.source)
        times = [record.timestamp_utc for record in result.records]
        self.assertEqual(times, sorted(times, key=datetime.fromisoformat))
        self.assertEqual(result.records[0].browser_profile, "Profile 1")  # 가장 이른 방문

    # 20
    def test_duplicate_discovery_prevented(self):
        if create_directory_link(self.root / "Users" / "AliceAlias", self.root / "Users" / "Alice") is None:
            self.skipTest("directory link could not be created on this host")
        profiles = p.discover_chrome_profiles(self.source)
        self.assertNotIn("AliceAlias", {profile.os_user for profile in profiles})
        self.assertEqual(len(profiles), 4)
        records, coverages = p.extract(self.source)
        self.assertEqual((len([c for c in coverages if c.artifact_type == "history"]), len(records)), (4, 6))
        # 중복 없음: Alice/Default LOGOUT·LOGIN, Alice/Profile 1 CONVERSATION_ACCESS 가 한 번씩만 (S8 Rule 포함)
        self.assertEqual(sorted(e.action for e in p.detect(records, coverages)), ["CONVERSATION_ACCESS", "LOGIN", "LOGOUT"])

    # 21
    def test_source_tree_unchanged(self):
        before = tree_snapshot(self.root)
        p.discover_chrome_profiles(self.source)
        p.extract(self.source)
        p.run(self.source)
        self.assertEqual(run_main(["--dir", self.root, "--out", self.base / "output" / "auto.json"])[0], p.EXIT_OK)
        self.assertEqual(tree_snapshot(self.root), before)

    # 22, 23
    def test_logout_rule_and_conversations_in_auto_mode(self):
        result = p.run(self.source)
        self.assertEqual(sorted(e.action for e in result.events), ["CONVERSATION_ACCESS", "LOGIN", "LOGOUT"])
        self.assertTrue(all(e.browser_profile not in ("System Profile", "Guest Profile") for e in result.events))
        logouts = [e for e in result.events if e.action == "LOGOUT"]
        self.assertEqual(len(logouts), 1)  # System Profile / Guest Profile 의 로그아웃 방문은 대상 아님
        event = logouts[0]
        self.assertEqual((event.action, event.action_status, event.os_user, event.browser_profile),
                         ("LOGOUT", "DETECTED", "Alice", "Default"))
        self.assertEqual(event.primary_evidence[0].source_path, f"{ALICE_UD}/Default/History")
        self.assertEqual(result.conversations, [])
        self.assertIn(p.RUN_WARNING_MESSAGE_RECOVERY_SCOPE, result.warnings)
        self.assertNotIn(p.CHROME_PROFILE_NOT_FOUND, result.warnings)

    def test_local_state_not_required(self):
        self.assertEqual(len(p.discover_chrome_profiles(self.source)), 4)  # 손상된 Local State 가 있어도 동일
        (user_data_dir(self.root, "Alice") / "Local State").unlink()
        self.assertEqual(len(p.discover_chrome_profiles(self.source)), 4)  # 없어도 동일

    def test_discovery_does_not_read_file_contents(self):
        with mock.patch.object(p.DirectorySource, "read_bytes", side_effect=AssertionError("read_bytes called")), \
                mock.patch.object(p.DirectorySource, "sha256", side_effect=AssertionError("sha256 called")):
            self.assertEqual(len(p.discover_chrome_profiles(self.source)), 4)

    def test_user_link_escaping_source_is_skipped(self):
        outside = self.base / "outside"
        (outside / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default").mkdir(parents=True)
        create_history_db(outside / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History")
        if create_directory_link(self.root / "Users" / "Mallory", outside) is None:
            self.skipTest("directory link could not be created on this host")
        warnings = []
        profiles = p.discover_chrome_profiles(self.source, warnings)
        self.assertNotIn("Mallory", {profile.os_user for profile in profiles})
        self.assertIn(f"{p.DISCOVERY_PATH_OUTSIDE_SOURCE}:Users/Mallory", warnings)
        result = p.run(self.source)
        self.assertIn(f"{p.DISCOVERY_PATH_OUTSIDE_SOURCE}:Users/Mallory", result.warnings)
        self.assertEqual(sorted(e.action for e in result.events), ["CONVERSATION_ACCESS", "LOGIN", "LOGOUT"])
        self.assertNotIn("Mallory", {e.os_user for e in result.events})  # Source 밖 History 의 방문은 Event 로 만들지 않음

    def test_history_link_escaping_source_is_parse_error(self):
        outside = self.base / "outside_history"
        outside.mkdir()
        if create_directory_link(user_data_dir(self.root, "Bob") / "Default" / "History", outside) is None:
            self.skipTest("directory link could not be created on this host")
        records, coverages = p.extract(self.source)
        bob = [coverage for coverage in coverages if coverage.os_user == "Bob"][0]
        self.assertEqual(bob.status, "PARSE_ERROR")
        self.assertIn(p.HISTORY_PATH_OUTSIDE_SOURCE, bob.warnings)
        self.assertEqual(len(records), 6)  # 다른 Profile 은 계속 처리


class AutoDiscoveryCliTest(ProfileDiscoveryTestBase):
    def test_cli_auto_mode_summary_and_json(self):
        out = self.base / "output" / "auto.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertIn("Mode".ljust(11) + ": Auto discovery", stdout)
        self.assertIn("[CHROME PROFILES]", stdout)
        for user, profile, history in (("Alice", "Default", "FOUND"), ("Alice", "Profile 1", "FOUND"),
                                       ("Alice", "Profile 10", "FOUND"), ("Bob", "Default", "NOT_PRESENT")):
            self.assertRegex(stdout, rf"(?m)^{user}\s+{re.escape(profile)}\s+{history}\s*$")
        self.assertIn("Alice / Profile 10", stdout)
        self.assertIn("Bob / Default", stdout)
        self.assertIn("History".ljust(11) + ": NOT_PRESENT (0 ChatGPT records)", stdout)
        self.assertNotIn("System Profile", stdout)
        self.assertNotIn("안녕 인사 응답", stdout)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data), PARSE_RESULT_KEYS)  # 결과 JSON 구조는 S6 과 같음
        # Profile 4개 × (History + Local Storage + Session Storage + Cache + shared_proto_db + Sessions)
        self.assertEqual(len(data["coverage"]), 24)
        self.assertEqual(len(data["records"]), 6)
        self.assertEqual(sorted((e["action"], e["os_user"], e["browser_profile"]) for e in data["events"]),
                         [("CONVERSATION_ACCESS", "Alice", "Profile 1"), ("LOGIN", "Alice", "Default"), ("LOGOUT", "Alice", "Default")])
        self.assertEqual(data["conversations"], [])

    def test_cli_auto_mode_no_profiles_is_not_fatal(self):
        flat = self.base / "flat"
        (flat / "Default").mkdir(parents=True)
        create_history_db(flat / "Default" / "History")  # Users 구조가 아닌 평평한 사본
        out = self.base / "output" / "flat.json"
        code, stdout, stderr = run_main(["--dir", flat, "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertIn("(none found)", stdout)
        self.assertIn(p.CHROME_PROFILE_NOT_FOUND, stdout)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual((data["coverage"], data["records"], data["events"], data["conversations"]), ([], [], [], []))
        self.assertIn(p.CHROME_PROFILE_NOT_FOUND, data["warnings"])

    def test_cli_explicit_mode_still_supported(self):
        out = self.base / "output" / "explicit.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", f"{ALICE_UD}/Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertIn("Mode".ljust(11) + ": Explicit --history", stdout)
        self.assertNotIn("[CHROME PROFILES]", stdout)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual([(c["artifact_type"], c["os_user"], c["status"]) for c in data["coverage"]],
                         [("history", None, "PARSED"), ("local_storage", None, "NOT_PRESENT"),
                          ("session_storage", None, "NOT_PRESENT"), ("cache", None, "NOT_PRESENT"),
                          ("shared_proto_db", None, "NOT_PRESENT"),
                          ("sessions", None, "NOT_PRESENT")])
        self.assertEqual(sorted(e["action"] for e in data["events"]), ["LOGIN", "LOGOUT"])
        self.assertNotIn(p.CHROME_PROFILE_NOT_FOUND, data["warnings"])


# =============================================================================
# S8 — History Event 확대 (LOGIN / ACCOUNT_SWITCH / CONVERSATION_CREATE / CONVERSATION_ACCESS / PROFILE_ACCESS)
# =============================================================================
# Rule 입력은 synthetic ArtifactRecord. URL 형태는 C: History 사본 조회와 REPORT bundle3 에서 관찰된 형태를 따른다
# (callback 은 code·state 가 가려진 query 포함, WEB:<임시 ID> 와 /c/<서버 ID> 는 서로 다른 값).

BASE_WEBKIT = 13432494600000000  # 2026-08-29T16:30:00Z
LOGIN_CALLBACK_URL = "https://chatgpt.com/api/auth/callback/openai?code=REDACTED&scope=openid+email&state=REDACTED"
LOGIN_WITH_URL = "https://chatgpt.com/auth/login_with?callback_path=%2F&screen_hint=login_or_signup"
AUTHORIZE_URL = "https://auth.openai.com/api/accounts/authorize?client_id=app_x&state=REDACTED"
WEB_ID = "af0cae8d-b925-43e7-aafe-44c911128ec6"
SERVER_ID = "6a86cf88-a4d8-83ee-9ef5-d2e6b3c3952f"
WEB_URL = f"https://chatgpt.com/c/WEB:{WEB_ID}"
CONVERSATION_URL = f"https://chatgpt.com/c/{SERVER_ID}"
PROFILE_URL = "https://chatgpt.com/profile"


def visit(url, visit_id, seconds=0.0, *, raw="auto", source_path="Default/History", profile="Default", os_user=None,
          transition=0x30000000, guid=""):
    if raw == "auto":
        raw = str(BASE_WEBKIT + int(round(seconds * 1_000_000)))
    record = make_history_record(url, visit_id=visit_id, raw=raw, guid=guid, transition=transition,
                                 source_path=source_path, browser_profile=profile)
    return p.ArtifactRecord(**{**record.to_dict(), "os_user": os_user}) if os_user is not None else record


def summarize(events):
    return [(event.action, event.action_status, event.confidence) for event in events]


def switch_chain(start_id=10, *, offsets=(0, 50, 53, 152), **kwargs):
    urls = (LOGOUT_URL, LOGIN_WITH_URL, AUTHORIZE_URL, LOGIN_CALLBACK_URL)
    return [visit(url, start_id + i, seconds, **kwargs) for i, (url, seconds) in enumerate(zip(urls, offsets))]


class LoginRuleTest(unittest.TestCase):
    def test_exact_callback(self):
        record = visit(LOGIN_CALLBACK_URL, 34)
        events = p.detect_login([record])
        self.assertEqual(summarize(events), [("LOGIN", "DETECTED", "MEDIUM")])
        event = events[0]
        self.assertEqual((event.rule_id, event.rule_verification, event.finding_type),
                         ("CHATGPT_LOGIN_001", "PARTIALLY_VERIFIED", "USER_ACTION"))
        self.assertEqual(event.confidence_reason, ["RULE_PARTIALLY_VERIFIED", "DIRECT_URL", "TIMESTAMP_EXPLAINED"])
        self.assertEqual(event.primary_evidence[0].evidence_level, "DIRECT")
        self.assertEqual(event.representative_evidence_id, event.primary_evidence[0].evidence_id)
        self.assertEqual((event.timestamp_raw, event.timestamp_utc, event.timestamp_kst),
                         (record.timestamp_raw, record.timestamp_utc, record.timestamp_kst))
        self.assertTrue(any("Negative Control" in text for text in event.limitations))
        self.assertNotIn("NO_KNOWN_CONTRADICTION", event.confidence_reason)

    def test_non_matching_urls(self):
        for url in ("https://notchatgpt.com/api/auth/callback/openai?code=REDACTED",
                    "https://chatgpt.com.example.com/api/auth/callback/openai",
                    "https://chatgpt.com/api/auth/callback/openai_fake",
                    "https://chatgpt.com/api/auth/callback/google",
                    "https://auth.openai.com/api/accounts/callback/google?code=REDACTED",
                    "http://chatgpt.com/api/auth/callback/openai?code=REDACTED",
                    "https://chatgpt.com/api/auth/callback/openai/",
                    "https://evil.example/?next=https://chatgpt.com/api/auth/callback/openai"):
            with self.subTest(url=url):
                self.assertEqual(p.detect_login([visit(url, 1)]), [])

    def test_query_redaction_kept(self):
        event = p.detect_login([visit(LOGIN_CALLBACK_URL, 34)])[0]
        self.assertEqual(event.primary_evidence[0].observed["url"], LOGIN_CALLBACK_URL)
        self.assertIn("code=REDACTED", json.dumps(event.to_dict()))

    def test_variant_and_timestamp_failure(self):
        variant = p.detect_login([visit("https://chatgpt.com/api/auth/callback/openai?code=REDACTED#x", 1)])[0]
        self.assertEqual((variant.action_status, variant.confidence), ("DETECTED", "MEDIUM"))
        self.assertIn("URL_VARIANT_NOT_VERIFIED", variant.confidence_reason)
        failed = p.detect_login([visit(LOGIN_CALLBACK_URL, 2, raw="abc")])[0]
        self.assertEqual((failed.action_status, failed.confidence), ("CANDIDATE", "LOW"))
        self.assertIn("TIMESTAMP_MISSING", failed.confidence_reason)
        self.assertIsNone(failed.timestamp_utc)

    def test_other_artifact_profiles_and_duplicates(self):
        other = visit(LOGIN_CALLBACK_URL, 3)
        other = p.ArtifactRecord(**{**other.to_dict(), "artifact_type": "local_storage"})
        self.assertEqual(p.detect_login([other]), [])
        default = visit(LOGIN_CALLBACK_URL, 5)
        profile1 = visit(LOGIN_CALLBACK_URL, 5, source_path="Profile 1/History", profile="Profile 1")
        profile2_other = visit("https://chatgpt.com/", 6, source_path="Profile 2/History", profile="Profile 2")
        events = p.detect_login([default, profile1, profile2_other, default])
        self.assertEqual(sorted(e.browser_profile for e in events), ["Default", "Profile 1"])
        self.assertEqual(len({e.event_id for e in events}), 2)


class LoginRuleReaderTest(HistoryTestBase):
    def test_reader_to_login_keeps_redaction(self):
        records, coverage = p.read_chatgpt_history(self.source, "Default/History")
        events = p.detect_login(records, [coverage])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].primary_evidence[0].record_location, "visits.id=47")
        self.assertEqual(events[0].primary_evidence[0].source_sha256, coverage.source_sha256)
        self.assertEqual(events[0].device_attribution, "REMOTE_SYNCED")  # fixture guid 값 있음, Confidence 는 그대로
        self.assertEqual(events[0].confidence, "MEDIUM")
        self.assertNotIn("SECRET_CODE_123", json.dumps(events[0].to_dict()))


class AccountSwitchRuleTest(unittest.TestCase):
    def test_complete_chain_is_candidate_medium(self):
        chain = switch_chain()
        events = p.detect_account_switch(chain)
        self.assertEqual(summarize(events), [("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM")])
        event = events[0]
        self.assertEqual((event.rule_id, event.rule_verification), ("CHATGPT_ACCOUNT_SWITCH_001", "PARTIALLY_VERIFIED"))
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "SUPPORTING_CORRELATED", "NOT_UNIQUE_TO_ACTION", "TIMESTAMP_EXPLAINED"])
        self.assertEqual(event.primary_evidence, [])
        self.assertEqual([e.evidence_level for e in event.supporting_evidence], ["SUPPORTING"] * 4)
        self.assertEqual([e.observed["url"] for e in event.supporting_evidence],
                         [LOGOUT_URL, LOGIN_WITH_URL, AUTHORIZE_URL, LOGIN_CALLBACK_URL])
        self.assertEqual(event.representative_evidence_id, event.supporting_evidence[-1].evidence_id)
        self.assertEqual(event.timestamp_raw, chain[-1].timestamp_raw)
        self.assertTrue(any(text.startswith("NOT_UNIQUE_TO_ACTION") for text in event.limitations))
        self.assertTrue(any("152초" in text and "ACCOUNT_SWITCH_WINDOW_SECONDS=None" in text for text in event.limitations))

    def test_unrelated_visits_between_steps(self):
        chain = switch_chain(offsets=(0, 50, 60, 152))
        noise = [visit("https://chatgpt.com/", 11, 20), visit("https://auth.openai.com/log-in/password", 12, 55)]
        records = [chain[0], noise[0], chain[1], noise[1], chain[2], chain[3]]
        records = [p.ArtifactRecord(**{**r.to_dict(), "record_id": f"{r.record_id}#{i}", "record_location": f"visits.id={100 + i}",
                                       "observed": {**r.observed, "visit_id": 100 + i}}) for i, r in enumerate(records)]
        self.assertEqual(len(p.detect_account_switch(records)), 1)

    def test_wrong_order_and_missing_steps(self):
        logout, login_with, authorize, callback = switch_chain()
        cases = {
            "logout last": [visit(LOGIN_WITH_URL, 1, 1), visit(AUTHORIZE_URL, 2, 2), visit(LOGIN_CALLBACK_URL, 3, 3), visit(LOGOUT_URL, 4, 4)],
            "reversed": [visit(LOGOUT_URL, 1, 1), visit(LOGIN_CALLBACK_URL, 2, 2), visit(AUTHORIZE_URL, 3, 3), visit(LOGIN_WITH_URL, 4, 4)],
            "no logout": [login_with, authorize, callback],
            "no login_with": [logout, authorize, callback],
            "no authorize": [logout, login_with, callback],
            "no callback": [logout, login_with, authorize],
        }
        for name, records in cases.items():
            with self.subTest(case=name):
                self.assertEqual(p.detect_account_switch(records), [])

    def test_intervening_logout_restarts_chain(self):
        first_logout = visit(LOGOUT_URL, 5, -10)
        events = p.detect_account_switch([first_logout] + switch_chain())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, f"event:CHATGPT_ACCOUNT_SWITCH_001:{switch_chain()[0].record_id}")

    def test_no_chain_across_profiles_sources_or_users(self):
        logout, login_with, authorize, callback = switch_chain()
        other_profile = switch_chain(source_path="Profile 1/History", profile="Profile 1")
        other_source = switch_chain(source_path="Copy/History")
        other_user = switch_chain(start_id=50, os_user="Bob")
        cases = {
            "profile": [logout] + other_profile[1:],
            "source": [logout] + other_source[1:],
            "os_user": [logout] + other_user[1:],
        }
        for name, records in cases.items():
            with self.subTest(case=name):
                self.assertEqual(p.detect_account_switch(records), [])

    def test_duplicate_input(self):
        chain = switch_chain()
        self.assertEqual(len(p.detect_account_switch(chain + chain)), 1)

    def test_logout_and_login_events_are_kept(self):
        events = p.detect(switch_chain())
        self.assertEqual(sorted(summarize(events)),
                         [("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM"), ("LOGIN", "DETECTED", "MEDIUM"), ("LOGOUT", "DETECTED", "HIGH")])

    def test_timestamp_missing_and_window_parameter(self):
        chain = switch_chain()
        broken = chain[:3] + [visit(LOGIN_CALLBACK_URL, 13, raw=None)]
        event = p.detect_account_switch(broken)[0]
        self.assertEqual((event.action_status, event.confidence), ("CANDIDATE", "LOW"))
        self.assertIn("TIMESTAMP_MISSING", event.confidence_reason)
        self.assertEqual(p.detect_account_switch(chain, window_seconds=100), [])
        self.assertEqual(len(p.detect_account_switch(chain, window_seconds=200)), 1)
        self.assertIsNone(p.ACCOUNT_SWITCH_WINDOW_SECONDS)


def identity_record(user, seconds, *, source_path="Default/Local Storage/leveldb/000003.log",
                    profile="Default", os_user=None, key_kind="conversation_history", raw="auto"):
    """Local Storage 에서 "이 시각에 이 계정 식별자가 관찰됨" 을 나타내는 Record (Reader 출력 형태만 흉내낸다)."""
    base = visit("https://chatgpt.com/", 900, seconds, raw=raw, source_path=source_path, profile=profile,
                 os_user=os_user)
    return p.ArtifactRecord(**{**base.to_dict(), "artifact_type": "local_storage", "source_path": source_path,
                               "record_id": f"local_storage:{source_path}#{user}/{seconds}",
                               "timestamp_source": "LocalStorage.value",
                               "record_location": f"sequence={int(seconds)}",
                               "observed": {"key_kind": key_kind, "operation": "PUT", "sequence": int(seconds),
                                            "user_id_sha256_prefix": user}})


class AccountIdentitySwitchTest(unittest.TestCase):
    """인증 체인(History) + 계정 식별자 전이(Local Storage) 가 함께 있을 때만 DETECTED 로 올린다."""

    def test_identity_transition_upgrades_chain_to_detected(self):
        records = switch_chain() + [identity_record("aaaa1111", -60), identity_record("bbbb2222", 200)]
        events = p.detect_account_switch(records)
        self.assertEqual(summarize(events), [("ACCOUNT_SWITCH", "DETECTED", "MEDIUM")])  # HIGH 로 올리지 않는다
        event = events[0]
        self.assertEqual((event.rule_id, event.rule_verification), ("CHATGPT_ACCOUNT_SWITCH_001", "PARTIALLY_VERIFIED"))
        self.assertIn("DIRECT_VALUE", event.confidence_reason)
        self.assertEqual([e.artifact_type for e in event.supporting_evidence],
                         ["history"] * 4 + ["local_storage"] * 2)
        representative = event.supporting_evidence[-1]
        self.assertEqual(event.representative_evidence_id, representative.evidence_id)
        self.assertIn("aaaa1111 → bbbb2222", representative.note)
        self.assertEqual(representative.observed["user_id_sha256_prefix_before"], "aaaa1111")
        self.assertFalse(any("계정 식별자가 바뀌었다는 Evidence 는 없다" in text for text in event.limitations))

    def test_summary_row_explains_reason_and_keeps_schema(self):
        records = switch_chain() + [identity_record("aaaa1111", -60), identity_record("bbbb2222", 200)]
        row = p._timeline_row(p.detect_account_switch(records)[0])
        self.assertEqual(list(row), list(p.CSV_TIMELINE_COLUMNS))
        self.assertEqual(row["User_behavior"], "계정 변경")
        self.assertTrue(row["Behavior_details "].startswith("ACCOUNT_SWITCH | SUPPORTING | "))
        self.assertIn("aaaa1111 → bbbb2222", row["Behavior_details "])

    def test_single_artifact_change_without_chain_makes_no_event(self):
        # 계정 식별자 하나만 바뀌고 인증 체인이 없으면 ACCOUNT_SWITCH 를 만들지 않는다.
        self.assertEqual(p.detect_account_switch([identity_record("aaaa1111", -60), identity_record("bbbb2222", 200)]), [])

    def test_one_sided_identity_observation_stays_candidate(self):
        for name, extra in {"직전만": [identity_record("aaaa1111", -60)],
                            "직후만": [identity_record("bbbb2222", 200)]}.items():
            with self.subTest(case=name):
                self.assertEqual(summarize(p.detect_account_switch(switch_chain() + extra)),
                                 [("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM")])

    def test_plain_login_is_not_account_switch(self):
        records = [visit(LOGIN_WITH_URL, 20, 0), visit(AUTHORIZE_URL, 21, 3), visit(LOGIN_CALLBACK_URL, 22, 9),
                   identity_record("bbbb2222", 200)]
        self.assertEqual(p.detect_account_switch(records), [])
        self.assertNotIn("ACCOUNT_SWITCH", [e.action for e in p.detect(records)])

    def test_plain_logout_is_not_account_switch(self):
        records = [visit(LOGOUT_URL, 20, 0), identity_record("aaaa1111", -60)]
        self.assertEqual(p.detect_account_switch(records), [])
        self.assertNotIn("ACCOUNT_SWITCH", [e.action for e in p.detect(records)])

    def test_same_account_relogin_stays_candidate(self):
        records = switch_chain() + [identity_record("aaaa1111", -60), identity_record("aaaa1111", 200)]
        self.assertEqual(summarize(p.detect_account_switch(records)), [("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM")])

    def test_same_identity_in_two_sources_is_one_event(self):
        duplicated = [identity_record("aaaa1111", -60),
                      identity_record("aaaa1111", -60, source_path="Default/Local Storage/leveldb/000005.ldb"),
                      identity_record("bbbb2222", 200),
                      identity_record("bbbb2222", 200, source_path="Default/Local Storage/leveldb/000005.ldb")]
        events = p.detect_account_switch(switch_chain() + duplicated)
        self.assertEqual(summarize(events), [("ACCOUNT_SWITCH", "DETECTED", "MEDIUM")])
        self.assertEqual(len([e for e in events[0].supporting_evidence if e.artifact_type == "local_storage"]), 2)

    def test_identity_without_timestamp_or_other_profile_is_ignored(self):
        cases = {
            "시각 없음": [identity_record("aaaa1111", -60, raw=None), identity_record("bbbb2222", 200, raw=None)],
            "다른 profile": [identity_record("aaaa1111", -60, source_path="Profile 1/Local Storage/leveldb/000003.log",
                                             profile="Profile 1"),
                             identity_record("bbbb2222", 200, source_path="Profile 1/Local Storage/leveldb/000003.log",
                                             profile="Profile 1")],
            "다른 os_user": [identity_record("aaaa1111", -60, os_user="Bob"),
                             identity_record("bbbb2222", 200, os_user="Bob")],
        }
        for name, extra in cases.items():
            with self.subTest(case=name):
                self.assertEqual(summarize(p.detect_account_switch(switch_chain() + extra)),
                                 [("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM")])

    def test_identifier_is_only_a_hash_prefix(self):
        records = switch_chain() + [identity_record("aaaa1111", -60), identity_record("bbbb2222", 200)]
        text = json.dumps(p.detect_account_switch(records)[0].to_dict(), ensure_ascii=False)
        self.assertNotIn("userId", text)
        self.assertNotIn("sessionToken", text)
        self.assertEqual(sorted(set(re.findall(r"[ab]{4}[12]{4}", text))), ["aaaa1111", "bbbb2222"])


class ConversationCreateRuleTest(unittest.TestCase):
    def test_observed_pattern_different_ids(self):
        web, created = visit(WEB_URL, 37, 0), visit(CONVERSATION_URL, 38, 3.154)
        events = p.detect_conversation_create([web, created])
        self.assertEqual(summarize(events), [("CONVERSATION_CREATE", "DETECTED", "MEDIUM")])
        event = events[0]
        self.assertEqual(event.rule_verification, "PARTIALLY_VERIFIED")  # 2026-09-15 정정: 인접 방문 correlation
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "DIRECT_URL", "SUPPORTING_CORRELATED", "CONVERSATION_ID_NOT_LINKED", "TIMESTAMP_EXPLAINED"])
        self.assertTrue(any("직접 연결하지 못했으며" in note and "인접 방문 기반 correlation" in note for note in event.limitations))
        self.assertEqual(event.primary_evidence[0].evidence_level, "DIRECT")
        self.assertEqual(event.primary_evidence[0].observed["client_conversation_id"], WEB_ID)
        self.assertEqual(event.supporting_evidence[0].evidence_level, "SUPPORTING")
        self.assertEqual(event.supporting_evidence[0].observed["conversation_id"], SERVER_ID)
        self.assertEqual(event.representative_evidence_id, event.supporting_evidence[0].evidence_id)
        self.assertEqual(event.timestamp_raw, created.timestamp_raw)
        self.assertTrue(any("3.154초" in text for text in event.limitations))
        self.assertNotIn("conversation_id", created.observed)  # 입력 Record 는 수정하지 않음

    def test_same_id_pair(self):
        event = p.detect_conversation_create([visit(f"https://chatgpt.com/c/WEB:{SERVER_ID}", 1, 0), visit(CONVERSATION_URL, 2, 2)])[0]
        self.assertEqual((event.action_status, event.confidence), ("DETECTED", "MEDIUM"))
        self.assertNotIn("CONVERSATION_ID_NOT_LINKED", event.confidence_reason)
        self.assertTrue(any("관찰되지 않은 형태" in text for text in event.limitations))

    def test_unconfirmed_creations_are_candidates(self):
        cases = {
            "reverse order": [visit(CONVERSATION_URL, 1, 0), visit(WEB_URL, 2, 5)],
            "chatgpt visit between": [visit(WEB_URL, 1, 0), visit("https://chatgpt.com/", 2, 1), visit(CONVERSATION_URL, 3, 2)],
            "other profile": [visit(WEB_URL, 1, 0), visit(CONVERSATION_URL, 2, 3, source_path="Profile 1/History", profile="Profile 1")],
            "other source": [visit(WEB_URL, 1, 0), visit(CONVERSATION_URL, 2, 3, source_path="Copy/History")],
            "web only": [visit(WEB_URL, 1, 0)],
        }
        for name, records in cases.items():
            with self.subTest(case=name):
                events = p.detect_conversation_create(records)
                self.assertEqual(summarize(events), [("CONVERSATION_CREATE", "CANDIDATE", "LOW")])
                self.assertIn("SERVER_CONVERSATION_ID_MISSING", events[0].confidence_reason)
                self.assertEqual(events[0].supporting_evidence, [])
                access = p.detect_conversation_access(records)
                self.assertEqual(len(access), sum(1 for r in records if r.observed["url"] == CONVERSATION_URL))

    def test_non_chatgpt_visit_between_does_not_break_link(self):
        records = [visit(WEB_URL, 1, 0), visit("https://www.google.com/search?q=x", 2, 1), visit(CONVERSATION_URL, 3, 2)]
        self.assertEqual(summarize(p.detect_conversation_create(records)), [("CONVERSATION_CREATE", "DETECTED", "MEDIUM")])

    def test_timestamp_failure_and_duplicates(self):
        failed = p.detect_conversation_create([visit(WEB_URL, 1, 0), visit(CONVERSATION_URL, 2, raw=None)])[0]
        self.assertEqual((failed.action_status, failed.confidence), ("CANDIDATE", "LOW"))
        self.assertIn("TIMESTAMP_MISSING", failed.confidence_reason)
        pair = [visit(WEB_URL, 37, 0), visit(CONVERSATION_URL, 38, 3.154)]
        self.assertEqual(len(p.detect_conversation_create(pair + pair)), 1)


class ConversationAccessRuleTest(unittest.TestCase):
    def test_general_visit(self):
        record = visit(CONVERSATION_URL, 44, 100)
        events = p.detect_conversation_access([record])
        self.assertEqual(summarize(events), [("CONVERSATION_ACCESS", "DETECTED", "HIGH")])
        self.assertEqual(events[0].confidence_reason, ["RULE_VERIFIED", "DIRECT_URL", "TIMESTAMP_EXPLAINED"])
        self.assertEqual(events[0].primary_evidence[0].observed["conversation_id"], SERVER_ID)
        self.assertEqual(events[0].rule_verification, "VERIFIED")
        self.assertNotIn("conversation_id", record.observed)

    def test_create_linked_visit_is_not_access(self):
        records = [visit(WEB_URL, 40, 0), visit(CONVERSATION_URL, 41, 1.98), visit(CONVERSATION_URL, 44, 8000), visit(CONVERSATION_URL, 48, 20000)]
        access = p.detect_conversation_access(records)
        self.assertEqual([e.primary_evidence[0].record_location for e in access], ["visits.id=44", "visits.id=48"])
        self.assertEqual(len(p.detect_conversation_create(records)), 1)

    def test_non_matching_paths_and_hosts(self):
        for url in ("https://chatgpt.com/c/", f"https://chatgpt.com/c/{SERVER_ID}/extra", f"https://chatgpt.com/g/g-abc/c/{SERVER_ID}",
                    f"https://chatgpt.com/foo/c/{SERVER_ID}", WEB_URL, f"https://chatgpt.com/conversation/{SERVER_ID}",
                    f"https://chatgpt.com/C/{SERVER_ID}", f"https://chatgpt.com/c/{SERVER_ID}%2F",
                    f"https://notchatgpt.com/c/{SERVER_ID}", f"http://chatgpt.com/c/{SERVER_ID}",
                    f"https://auth.openai.com/c/{SERVER_ID}"):
            with self.subTest(url=url):
                self.assertEqual(p.detect_conversation_access([visit(url, 1)]), [])

    def test_duplicates_and_variant(self):
        record = visit(CONVERSATION_URL, 44)
        self.assertEqual(len(p.detect_conversation_access([record, record])), 1)
        variant = p.detect_conversation_access([visit(f"{CONVERSATION_URL}?model=gpt-4o", 45)])[0]
        self.assertEqual(variant.confidence, "MEDIUM")
        self.assertIn("URL_VARIANT_NOT_VERIFIED", variant.confidence_reason)


class ProfileAccessRuleTest(unittest.TestCase):
    def test_exact_profile(self):
        events = p.detect_profile_access([visit(PROFILE_URL, 1)])
        self.assertEqual(summarize(events), [("PROFILE_ACCESS", "DETECTED", "MEDIUM")])
        event = events[0]
        self.assertEqual((event.rule_id, event.rule_verification), ("CHATGPT_PROFILE_ACCESS_001", "PARTIALLY_VERIFIED"))
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "DIRECT_URL", "RULE_EVIDENCE_NOT_RECONFIRMED", "TIMESTAMP_EXPLAINED"])
        self.assertTrue(any("ACCOUNT_NAME_CHANGE" in text for text in event.limitations))
        self.assertNotIn("ACCOUNT_NAME_CHANGE", [e.action for e in p.detect([visit(PROFILE_URL, 1)])])

    def test_non_matching(self):
        for url in ("https://chatgpt.com/profile/", "https://chatgpt.com/profile2", "https://chatgpt.com/profiles",
                    "https://chatgpt.com/PROFILE", "https://chatgpt.com/settings/profile", "https://notchatgpt.com/profile",
                    "http://chatgpt.com/profile", "https://auth.openai.com/profile"):
            with self.subTest(url=url):
                self.assertEqual(p.detect_profile_access([visit(url, 1)]), [])
        other = p.ArtifactRecord(**{**visit(PROFILE_URL, 2).to_dict(), "artifact_type": "cache"})
        self.assertEqual(p.detect_profile_access([other]), [])

    def test_variant_and_timestamp_failure(self):
        for url in ("https://chatgpt.com/profile?tab=account", "https://chatgpt.com/profile#name"):
            with self.subTest(url=url):
                event = p.detect_profile_access([visit(url, 1)])[0]
                self.assertEqual((event.action_status, event.confidence), ("DETECTED", "MEDIUM"))
                self.assertIn("URL_VARIANT_NOT_VERIFIED", event.confidence_reason)
        failed = p.detect_profile_access([visit(PROFILE_URL, 2, raw="0")])[0]
        self.assertEqual((failed.action_status, failed.confidence), ("CANDIDATE", "LOW"))


S8_URLS = [
    (1, LOGOUT_URL, "ChatGPT"), (2, LOGIN_WITH_URL, "ChatGPT"), (3, AUTHORIZE_URL, "로그인"),
    (4, "https://chatgpt.com/api/auth/callback/openai?code=SECRET_CALLBACK_CODE&scope=openid&state=SECRET_STATE", "ChatGPT"),
    (5, WEB_URL, "인사"), (6, CONVERSATION_URL, "안녕 인사 응답"), (7, PROFILE_URL, "ChatGPT"), (8, "https://chatgpt.com/", "ChatGPT"),
]


def s8_time(seconds):
    return BASE_WEBKIT + int(round(seconds * 1_000_000))


S8_VISITS = [  # (id, url_id, visit_time, from_visit, transition, guid, is_known_to_sync)
    (1, 1, s8_time(0), 0, 0x30000000, "", 0), (2, 2, s8_time(50), 0, 0x30000000, "", 0),
    (3, 3, s8_time(53), 2, 0x10000000, "", 0), (4, 4, s8_time(152), 0, 0x10000000, "", 0),
    (5, 8, s8_time(152), 4, SIGNED_SERVER_REDIRECT_CHAIN_END, "", 0), (6, 5, s8_time(200), 0, 0x30000000, "", 0),
    (7, 6, s8_time(203.154), 0, 0x30000000, "", 0), (8, 6, s8_time(400), 0, 0x30000000, "", 0),
    (9, 7, s8_time(500), 0, 0x30000000, "", 0),
]
S8_EXPECTED_ORDER = ["LOGOUT", "ACCOUNT_SWITCH", "LOGIN", "CONVERSATION_CREATE", "CONVERSATION_ACCESS", "PROFILE_ACCESS"]


class S8PipelineTest(HistoryTestBase):
    def setUp(self):
        super().setUp()
        self.path = self.variant("History_s8", urls=S8_URLS, visits=S8_VISITS)

    def test_detect_all_rules_without_mutation(self):
        records, coverages = p.extract(self.source, self.path)
        before = [record.to_dict() for record in records]
        events = p.detect(records, coverages)
        self.assertEqual(sorted(e.action for e in events), sorted(S8_EXPECTED_ORDER))
        self.assertEqual(len({e.event_id for e in events}), len(events))
        self.assertEqual([record.to_dict() for record in records], before)
        self.assertNotIn("SECRET_CALLBACK_CODE", json.dumps([e.to_dict() for e in events]))

    def test_run_event_order_is_deterministic(self):
        first = p.run(self.source, self.path)
        second = p.run(self.source, self.path)
        self.assertEqual([e.action for e in first.events], S8_EXPECTED_ORDER)  # 같은 시각(LOGIN·ACCOUNT_SWITCH)은 event_id 순
        self.assertEqual([e.event_id for e in first.events], [e.event_id for e in second.events])
        self.assertEqual(first.conversations, [])

    def test_cli_user_actions_summary(self):
        out = Path(self._tmp.name) / "output" / "s8.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", self.path, "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        for action, status, confidence in (("LOGOUT", "DETECTED", "HIGH"), ("LOGIN", "DETECTED", "MEDIUM"),
                                           ("ACCOUNT_SWITCH", "CANDIDATE", "MEDIUM"), ("CONVERSATION_CREATE", "DETECTED", "MEDIUM"),
                                           ("CONVERSATION_ACCESS", "DETECTED", "HIGH"), ("PROFILE_ACCESS", "DETECTED", "MEDIUM")):
            self.assertRegex(stdout, rf"(?m)^\S+Z\s+\S+\+09:00\s+{action}\s+{status}\s+{confidence}$")
        self.assertIn("Events".ljust(14) + ": 6", stdout)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data), PARSE_RESULT_KEYS)
        self.assertEqual(data["conversations"], [])
        code, stdout, _ = run_main(["--dir", self.root, "--history", "Default/History", "--out", out.with_name("base.json")])
        self.assertNotIn("PROFILE_ACCESS", stdout)  # 발견되지 않은 Action 은 표시하지 않음
        self.assertNotIn("ACCOUNT_SWITCH", stdout)


# =============================================================================
# S9-pre — LevelDB .log Reader / Local Storage Reader / Conversation Residue Extraction
# =============================================================================
# fixture 는 테스트가 직접 만든 LevelDB .log bytes 다 (외부 LevelDB 라이브러리 없음).
# key·value byte 형식은 2026-09-15 C: 분석용 사본에서 확인한 형식을 따른다:
#   key = b"_https://chatgpt.com\x00\x01" + 이름, value = 0x01 + Latin-1 또는 0x00 + UTF-16LE
#   conversation-history 값 = {"value":{"pages":[{"items":[{id,title,create_time,update_time,...}]}]},"timestamp":<ms>,"version":..}
# ID·제목·token 값은 synthetic 이다.

LS_DIR = "Default/Local Storage/leveldb"
LS_USER_ID = "user-SYNTHETICUSER00000000000"
LS_HISTORY_KEY = f"cache/{LS_USER_ID}/0130a476-0000-4000-8000-000000000000/conversation-history"
RESIDUE_ID = SERVER_ID
RESIDUE_ID_2 = "6a86d3ee-0000-4000-8000-000000000002"
CREATE_TIME = "2026-09-12T18:04:34.276355Z"
CREATE_KST = "2026-09-13T03:04:34.276355+09:00"
SECRET_TOKEN = "SYNTHETIC-SESSION-TOKEN-" + "x" * 40
SECRET_EMAIL = "synthetic.user@example.com"


def ldb_physical(record_type, payload, crc=None):
    checksum = p.leveldb_masked_crc(record_type, payload) if crc is None else crc
    return struct.pack("<IHB", checksum, len(payload), record_type) + payload


def ldb_varint(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def ldb_batch(sequence, *operations):
    """operations: ("PUT", key, value) / ("DELETE", key)"""
    body = bytearray(struct.pack("<QI", sequence, len(operations)))
    for operation in operations:
        body += (b"\x01" if operation[0] == "PUT" else b"\x00") + ldb_varint(len(operation[1])) + operation[1]
        if operation[0] == "PUT":
            body += ldb_varint(len(operation[2])) + operation[2]
    return bytes(body)


def ldb_log(*payloads):
    """LevelDB log writer 와 같은 방식: block 에 안 들어가면 FIRST / MIDDLE / LAST 로 나누고, 7 byte 미만 남은 block 끝은 0 으로 채움."""
    out = bytearray()
    for payload in payloads:
        remaining, first = payload, True
        while True:
            left = p.LEVELDB_BLOCK_SIZE - len(out) % p.LEVELDB_BLOCK_SIZE
            if left < p.LEVELDB_HEADER_SIZE:
                out += b"\x00" * left
                continue
            chunk, remaining = remaining[:left - 7], remaining[left - 7:]
            last = not remaining
            out += ldb_physical(1 if first and last else 2 if first else 4 if last else 3, chunk)
            first = False
            if last:
                break
    return bytes(out)


def ls_key(name, origin="https://chatgpt.com"):
    return b"_" + origin.encode("latin-1") + b"\x00\x01" + name.encode("latin-1")


def ls_latin1(obj):
    return b"\x01" + (obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))).encode("latin-1")


def ls_utf16(obj):
    return b"\x00" + (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, separators=(",", ":"))).encode("utf-16-le")


def conv_item(conv_id=RESIDUE_ID, title="안녕 인사 응답", create_time=CREATE_TIME):
    return {"id": conv_id, "title": title, "create_time": create_time, "update_time": create_time,
            "mapping": None, "snippet": None, "is_archived": False}


def history_value(*items, timestamp=1788021002000):
    return {"value": {"pages": [{"items": list(items), "total": len(items), "limit": 28, "offset": 0}], "pageParams": [0]},
            "timestamp": timestamp, "version": 1}


def put_history(sequence, *items):
    return ldb_batch(sequence, ("PUT", ls_key(LS_HISTORY_KEY), ls_utf16(history_value(*items))))


class LevelDBLogReaderTest(unittest.TestCase):
    def test_crc32c_standard_check_value(self):
        self.assertEqual(p.crc32c(b"123456789"), 0xE3069283)  # CRC32C 표준 검사값 (CRC32 는 0xCBF43926)
        self.assertNotEqual(p.crc32c(b"123456789"), 0xCBF43926)

    # 1
    def test_full_record(self):
        records, warnings = p.read_leveldb_log(ldb_log(b"hello"))
        self.assertEqual(warnings, [])
        self.assertEqual([(r.offset, r.block, r.fragments, r.crc32c_verified, r.data) for r in records],
                         [(0, 0, 1, True, b"hello")])

    # 2
    def test_first_last(self):
        payload = bytes(range(256)) * 157  # 40192 byte > block
        records, warnings = p.read_leveldb_log(ldb_log(payload))
        self.assertEqual((warnings, len(records), records[0].fragments, records[0].data), ([], 1, 2, payload))

    # 3
    def test_first_middle_last(self):
        payload = b"m" * 70000
        records, warnings = p.read_leveldb_log(ldb_log(b"a", payload, b"z"))
        self.assertEqual(warnings, [])
        self.assertEqual([(r.fragments, len(r.data)) for r in records], [(1, 1), (3, 70000), (1, 1)])
        self.assertEqual(records[1].data, payload)

    # 4
    def test_block_boundary(self):
        size = p.LEVELDB_BLOCK_SIZE
        records, warnings = p.read_leveldb_log(ldb_log(b"a" * (size - 7 - 3), b"next"))  # 3 byte trailer 뒤 다음 block
        self.assertEqual(warnings, [])
        self.assertEqual([(r.offset, r.block, r.data[:4]) for r in records], [(0, 0, b"aaaa"), (size, 1, b"next")])
        # block 끝에 header 만 들어가는 7 byte 가 남으면 빈 FIRST 뒤 다음 block 에 LAST
        records, warnings = p.read_leveldb_log(ldb_log(b"b" * (size - 7 - 7), b"split"))
        self.assertEqual(warnings, [])
        self.assertEqual([(r.offset, r.fragments, r.data[-5:]) for r in records], [(0, 1, b"bbbbb"), (size - 7, 2, b"split")])

    # 5
    def test_zero_padding(self):
        first = ldb_physical(1, b"a")
        data = first + b"\x00" * (p.LEVELDB_BLOCK_SIZE - len(first)) + ldb_physical(1, b"b") + b"\x00" * 100
        records, warnings = p.read_leveldb_log(data)
        self.assertEqual(([r.data for r in records], warnings), ([b"a", b"b"], []))

    # 6
    def test_truncated_header(self):
        records, warnings = p.read_leveldb_log(ldb_log(b"a") + b"\x05\x06\x07")
        self.assertEqual([r.data for r in records], [b"a"])
        self.assertEqual(warnings, [f"{p.LEVELDB_TRUNCATED_HEADER}:offset=8"])

    # 7
    def test_invalid_length(self):
        bad = struct.pack("<IHB", 0, 40000, 1) + b"x" * 10  # block 보다 긴 length
        data = bad + b"\x00" * (p.LEVELDB_BLOCK_SIZE - len(bad)) + ldb_physical(1, b"ok")
        records, warnings = p.read_leveldb_log(data)
        self.assertEqual([r.data for r in records], [b"ok"])  # 다음 block 에서 다시 읽음
        self.assertEqual(warnings, [f"{p.LEVELDB_INVALID_LENGTH}:offset=0"])
        records, warnings = p.read_leveldb_log(struct.pack("<IHB", 0, 100, 1) + b"short")
        self.assertEqual((records, warnings), ([], [f"{p.LEVELDB_TRUNCATED_RECORD}:offset=0"]))

    # 8
    def test_invalid_fragment_sequence(self):
        code = p.LEVELDB_INVALID_FRAGMENT_SEQUENCE
        records, warnings = p.read_leveldb_log(ldb_physical(4, b"orphan") + ldb_physical(1, b"ok"))
        self.assertEqual(([r.data for r in records], warnings), ([b"ok"], [f"{code}:offset=0"]))
        records, warnings = p.read_leveldb_log(ldb_physical(2, b"first") + ldb_physical(1, b"full"))
        self.assertEqual(([r.data for r in records], warnings), ([b"full"], [f"{code}:offset=0"]))
        records, warnings = p.read_leveldb_log(ldb_physical(2, b"first") + ldb_physical(3, b"middle"))  # LAST 없이 끝남
        self.assertEqual((records, warnings), ([], [f"{code}:offset=0"]))

    # 14
    def test_unknown_record_type(self):
        records, warnings = p.read_leveldb_log(ldb_physical(9, b"??") + ldb_physical(1, b"ok"))
        self.assertEqual(([r.data for r in records], warnings), ([b"ok"], [f"{p.LEVELDB_UNKNOWN_RECORD_TYPE}:offset=0"]))

    def test_crc_mismatch_record_is_kept_and_flagged(self):
        records, warnings = p.read_leveldb_log(ldb_physical(1, b"data", crc=1234))
        self.assertEqual([(r.data, r.crc32c_verified) for r in records], [(b"data", False)])
        self.assertEqual(warnings, [f"{p.LEVELDB_CRC_MISMATCH}:offset=0"])


class LevelDBWriteBatchTest(unittest.TestCase):
    @staticmethod
    def record(data):
        return p.LevelDBLogRecord(offset=0, block=0, fragments=1, crc32c_verified=True, data=data)

    # 9~12
    def test_sequence_put_delete_multiple(self):
        record = self.record(ldb_batch(100, ("PUT", b"k1", b"v1"), ("DELETE", b"k2"), ("PUT", b"k3", b"")))
        operations, warnings = p.parse_leveldb_write_batch(record)
        self.assertEqual(warnings, [])
        self.assertEqual([(o.sequence, o.batch_sequence, o.operation_index, o.operation, o.key, o.value) for o in operations],
                         [(100, 100, 0, "PUT", b"k1", b"v1"), (101, 100, 1, "DELETE", b"k2", None), (102, 100, 2, "PUT", b"k3", b"")])
        for operation in operations:  # raw 위치 추적
            self.assertEqual(record.data[operation.key_offset:operation.key_offset + len(operation.key)], operation.key)
        self.assertEqual(record.data[operations[0].value_offset:operations[0].value_offset + 2], b"v1")
        self.assertIsNone(operations[1].value_offset)

    # 13
    def test_malformed_varint(self):
        first_operation = ldb_batch(7, ("PUT", b"k1", b"v1"))[12:]
        data = struct.pack("<QI", 7, 2) + first_operation + b"\x01\x80\x80"  # 두 번째 operation 의 key 길이 varint 가 끊김
        operations, warnings = p.parse_leveldb_write_batch(self.record(data))
        self.assertEqual([o.key for o in operations], [b"k1"])  # 손상 이전 operation 유지
        self.assertEqual(warnings, [f"{p.LEVELDB_WRITEBATCH_INVALID}:offset=0:operation=1"])

    def test_invalid_batches(self):
        code = p.LEVELDB_WRITEBATCH_INVALID
        self.assertEqual(p.parse_leveldb_write_batch(self.record(b"short")), ([], [f"{code}:offset=0:header"]))
        operations, warnings = p.parse_leveldb_write_batch(self.record(struct.pack("<QI", 1, 1) + b"\x07\x01k"))
        self.assertEqual((operations, warnings), ([], [f"{code}:offset=0:operation=0"]))  # 모르는 tag
        operations, warnings = p.parse_leveldb_write_batch(self.record(ldb_batch(1, ("DELETE", b"k")) + b"zz"))
        self.assertEqual(([o.key for o in operations], warnings), ([b"k"], [f"{code}:offset=0:trailing_bytes"]))
        operations, warnings = p.parse_leveldb_write_batch(self.record(struct.pack("<QI", 1, 3) + b"\x00\x01k"))
        self.assertEqual(([o.key for o in operations], warnings), ([b"k"], [f"{code}:offset=0:operation=1"]))  # count 보다 적음


class LocalStorageTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Chrome"
        self.leveldb = self.root / "Default" / "Local Storage" / "leveldb"
        self.leveldb.mkdir(parents=True)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def write_log(self, *payloads, name="000003.log"):
        (self.leveldb / name).write_bytes(ldb_log(*payloads))
        return f"{LS_DIR}/{name}"

    def read(self, *payloads):
        return p.read_local_storage_log(self.source, self.write_log(*payloads))

    @staticmethod
    def dumped(obj):
        return json.dumps(obj.to_dict(), ensure_ascii=False)


class LocalStorageReaderTest(LocalStorageTestBase):
    # LS 1
    def test_conversation_history_record(self):
        records, coverage = self.read(put_history(10, conv_item()))
        self.assertEqual((coverage.artifact_type, coverage.status, coverage.record_count, coverage.warnings),
                         ("local_storage", "PARSED", 1, []))
        self.assertEqual(coverage.source_sha256, hashlib.sha256((self.leveldb / "000003.log").read_bytes()).hexdigest())
        record = records[0]
        observed = record.observed
        self.assertEqual((observed["key"], observed["key_kind"], observed["operation"], observed["sequence"],
                          observed["value_encoding"], observed["crc32c_verified"]),
                         ("cache/<user>/<scope>/conversation-history", "conversation_history", "PUT", 10, "utf-16-le", True))
        self.assertEqual(observed["user_id_sha256_prefix"], hashlib.sha256(LS_USER_ID.encode()).hexdigest()[:16])
        self.assertNotIn(LS_USER_ID, self.dumped(record))  # 계정 식별자 원문 비노출
        self.assertEqual(observed["conversation_items"], [{"page_index": 0, "item_index": 0, "id": RESIDUE_ID,
                                                            "title": "안녕 인사 응답", "create_time": CREATE_TIME,
                                                            "update_time": CREATE_TIME}])
        self.assertEqual(record.record_location, "offset=0 block=0 sequence=10 operation=0")
        self.assertEqual((record.timestamp_raw, record.timestamp_utc, record.timestamp_type, record.timestamp_source),
                         ("1788021002000", "2026-08-29T16:30:02Z", "unix_ms", "LocalStorage.conversation-history.timestamp"))
        self.assertEqual(p.detect(records), [])  # Reader 결과만으로 사용자 행위를 만들지 않음

    # LS 11
    def test_nextauth_message_record_not_correlated(self):
        value = ls_latin1({"event": "session", "data": {"trigger": "signout"}, "timestamp": 1788021002})
        records, coverage = self.read(ldb_batch(115, ("PUT", ls_key("nextauth.message"), value)))
        record = records[0]
        self.assertEqual((record.observed["key_kind"], record.observed["event"], record.observed["trigger"]),
                         ("nextauth_message", "session", "signout"))
        self.assertEqual((record.timestamp_utc, record.timestamp_kst, record.timestamp_type),
                         ("2026-08-29T16:30:02Z", "2026-08-30T01:30:02+09:00", "unix_s"))
        self.assertEqual(p.detect(records, [coverage]), [])  # LOGOUT 판정·연결 없음

    # LS 12, 14
    def test_account_switch_sessions_secrets_not_exposed(self):
        session = {"email": SECRET_EMAIL, "emailDomainType": "public", "phoneNumber": "+82-10-0000-0000",
                   "sessionToken": SECRET_TOKEN, "lastLoggedInAt": 1787126888000, "name": "SYNTHETIC_NAME",
                   "userId": LS_USER_ID, "userImageUrl": "https://example.com/i.png", "authProvider": "google",
                   "workspaces": [{"workspaceAccountId": "ws-1", "workspaceName": "SYNTHETIC_NAME"}]}
        records, _ = self.read(ldb_batch(112, ("PUT", ls_key("oai/apps/accountSwitchSessions"), ls_utf16([session]))))
        observed = records[0].observed
        self.assertEqual((observed["key_kind"], observed["session_count"]), ("account_switch_sessions", 1))
        entry = observed["sessions"][0]
        self.assertEqual(entry["field_names"], sorted(session))
        self.assertEqual((entry["session_token_present"], entry["session_token_length"], entry["workspace_count"]),
                         (True, len(SECRET_TOKEN), 1))
        self.assertEqual(entry["last_logged_in_at"]["timestamp_utc"], "2026-08-19T08:08:08Z")
        text = self.dumped(records[0])
        for secret in (SECRET_TOKEN, SECRET_EMAIL, "SYNTHETIC_NAME", LS_USER_ID, "+82-10-0000-0000"):
            self.assertNotIn(secret, text)
        events = p.detect(records)
        # 계정이 1개면 ACCOUNT_SWITCH 는 만들지 않는다. lastLoggedInAt 은 LOGIN 1건으로만 쓴다.
        self.assertEqual([e.action for e in events], ["LOGIN"])
        self.assertEqual((events[0].action_status, events[0].confidence, events[0].rule_id),
                         ("DETECTED", "MEDIUM", p.ACCOUNT_SESSION_RULE_ID))
        self.assertEqual(events[0].timestamp_kst, "2026-08-19T17:08:08+09:00")
        for secret in (SECRET_TOKEN, SECRET_EMAIL, "SYNTHETIC_NAME", LS_USER_ID, "+82-10-0000-0000"):
            self.assertNotIn(secret, self.dumped(events[0]))

    # LS 12-2 — 계정 2개가 함께 기록된 세션 목록에서 ACCOUNT_SWITCH + 계정별 LOGIN
    # (실제 E01 에서 History 가 지워져 History 기반 Rule 이 아무것도 못 찾은 상황을 synthetic 으로 재현)
    def _switch_session(self, user_id, token_len, last_logged_in_at):
        return {"email": SECRET_EMAIL, "sessionToken": "T" * token_len, "lastLoggedInAt": last_logged_in_at,
                "name": "SYNTHETIC_NAME", "userId": user_id, "authProvider": "google", "workspaces": [{"a": 1}]}

    def test_account_switch_sessions_two_accounts_detect_switch_and_logins(self):
        sessions = [self._switch_session("user-AAAA", 64, 1700000000000),   # 2023-11-14T22:13:20Z
                    self._switch_session("user-BBBB", 48, 1700003600000)]   # 2023-11-14T23:13:20Z
        records, _ = self.read(ldb_batch(11, ("PUT", ls_key("oai/apps/accountSwitchSessions"), ls_utf16(sessions))))
        events = p.detect(records)
        by_action = {}
        for event in events:
            by_action.setdefault(event.action, []).append(event)
        self.assertEqual(sorted(by_action), ["ACCOUNT_SWITCH", "LOGIN"])
        self.assertEqual(sorted(e.timestamp_kst for e in by_action["LOGIN"]),
                         ["2023-11-15T07:13:20+09:00", "2023-11-15T08:13:20+09:00"])
        switch = by_action["ACCOUNT_SWITCH"][0]
        # 전환 시각 = 가장 나중에 로그인한 계정의 lastLoggedInAt
        self.assertEqual(switch.timestamp_kst, "2023-11-15T08:13:20+09:00")
        self.assertEqual((switch.action_status, switch.confidence, switch.rule_id),
                         ("DETECTED", "MEDIUM", p.ACCOUNT_SESSION_RULE_ID))
        text = self.dumped(switch)
        for secret in (SECRET_EMAIL, "SYNTHETIC_NAME", "user-AAAA", "user-BBBB", "TTTT"):
            self.assertNotIn(secret, text)

    def test_account_switch_sessions_same_state_in_two_files_is_one_event(self):
        sessions = [self._switch_session("user-AAAA", 64, 1700000000000),
                    self._switch_session("user-BBBB", 48, 1700003600000)]
        value = ls_utf16(sessions)
        a, _ = self.read(ldb_batch(11, ("PUT", ls_key("oai/apps/accountSwitchSessions"), value)))
        b, _ = self.read(ldb_batch(12, ("PUT", ls_key("oai/apps/accountSwitchSessions"), value)))
        events = p.detect(a + b)
        self.assertEqual([e.action for e in events if e.action == "ACCOUNT_SWITCH"], ["ACCOUNT_SWITCH"])
        self.assertEqual(len([e for e in events if e.action == "LOGIN"]), 2)

    def test_account_switch_sessions_without_timestamp_makes_no_event(self):
        session = {"sessionToken": "T" * 64, "userId": "user-AAAA", "workspaces": []}
        records, _ = self.read(ldb_batch(11, ("PUT", ls_key("oai/apps/accountSwitchSessions"), ls_utf16([session, dict(session, userId="user-BBBB")]))))
        self.assertEqual(p.detect(records), [])  # sequence 를 행위 시각으로 쓰지 않는다

    # LS 10
    def test_conversation_drafts_are_not_conversations(self):
        value = {"drafts": [{"id": RESIDUE_ID, "content": "작성 중인 질문", "doc": {"type": "doc"}, "timestamp": 1788021002000}],
                 "userId": LS_USER_ID}
        records, _ = self.read(ldb_batch(144, ("PUT", ls_key("oai/apps/conversationDrafts"), ls_utf16(value))))
        observed = records[0].observed
        self.assertEqual((observed["key_kind"], observed["draft_count"]), ("conversation_drafts", 1))
        self.assertEqual(observed["drafts"][0]["content"], "작성 중인 질문")
        self.assertEqual(observed["drafts"][0]["draft_id"], RESIDUE_ID)
        self.assertEqual(observed["drafts"][0]["timestamp"]["timestamp_utc"], "2026-08-29T16:30:02Z")
        self.assertEqual(p.extract_conversation_residue(records), [])  # 메시지·대화로 넣지 않음
        self.assertEqual([e.action for e in p.detect(records)], ["PROMPT_DRAFT"])  # 초안 저장 Event 만 (전송·메시지 아님)

    # LS 13
    def test_non_allowlisted_keys_not_exposed(self):
        records, coverage = self.read(ldb_batch(
            1, ("PUT", ls_key("RESUME_TOKEN_STORE_KEY"), ls_latin1("SECRET-RESUME-TOKEN")),
            ("PUT", ls_key("statsig.session_id.1"), ls_latin1("SECRET-STATSIG")),
            ("PUT", b"META:https://chatgpt.com", b"\x08SECRET-META"),
            ("PUT", ls_key("nextauth.message", origin="https://x.com"), ls_latin1("SECRET-OTHER-ORIGIN")),
            ("DELETE", ls_key("_account")),
        ))
        self.assertEqual(records, [])
        self.assertEqual((coverage.status, coverage.warnings), ("PARSED", [f"{p.LOCAL_STORAGE_NON_ALLOWLISTED_OPERATIONS}:3"]))
        self.assertNotIn("SECRET", self.dumped(coverage))

    # LS 15
    def test_invalid_encoding(self):
        records, coverage = self.read(ldb_batch(
            5, ("PUT", ls_key("nextauth.message"), b"\x02{}"), ("PUT", ls_key("oai/apps/conversationDrafts"), b"\x00{\x00\x22")))
        self.assertEqual([(r.observed["value_encoding"], r.warnings) for r in records],
                         [(None, [p.LOCAL_STORAGE_UNSUPPORTED_ENCODING]), ("utf-16-le", [p.LOCAL_STORAGE_UNSUPPORTED_ENCODING])])
        self.assertNotIn("drafts", records[1].observed)
        self.assertEqual(coverage.status, "PARTIAL")

    # LS 16
    def test_malformed_json_value(self):
        records, coverage = self.read(ldb_batch(
            5, ("PUT", ls_key("nextauth.message"), ls_latin1("{not json")),
            ("PUT", ls_key(LS_HISTORY_KEY), ls_utf16({"value": {"pages": "unexpected"}}))))
        self.assertEqual([r.warnings for r in records], [[p.LOCAL_STORAGE_VALUE_NOT_JSON], [p.LOCAL_STORAGE_UNEXPECTED_STRUCTURE]])
        self.assertNotIn("conversation_items", records[1].observed)
        self.assertEqual(coverage.status, "PARTIAL")
        self.assertEqual(p.extract_conversation_residue(records), [])

    # LS 9
    def test_delete_operation_is_observed_only(self):
        records, _ = self.read(ldb_batch(119, ("DELETE", ls_key(LS_HISTORY_KEY))))
        observed = records[0].observed
        self.assertEqual((observed["operation"], observed["value_length"], observed["value_offset_in_record"]), ("DELETE", None, None))
        self.assertIsNone(records[0].timestamp_raw)  # 파일 mtime 등 다른 시각을 넣지 않음
        self.assertEqual((p.extract_conversation_residue(records), p.detect(records)), ([], []))

    def test_damaged_log_is_partial(self):
        path = f"{LS_DIR}/000004.log"
        (self.leveldb / "000004.log").write_bytes(ldb_physical(4, b"orphan") + ldb_log(put_history(3, conv_item())))
        records, coverage = p.read_local_storage_log(self.source, path)
        self.assertEqual((coverage.status, len(records)), ("PARTIAL", 1))
        self.assertIn(f"{p.LEVELDB_INVALID_FRAGMENT_SEQUENCE}:offset=0", coverage.warnings)

    def test_folder_coverage(self):
        records, coverages = p.read_local_storage(self.source, "Profile 9/Local Storage/leveldb")
        self.assertEqual([(c.source_path, c.status) for c in coverages], [("Profile 9/Local Storage/leveldb", "NOT_PRESENT")])
        (self.leveldb / "000005.ldb").write_bytes(b"sstable bytes")
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(c.source_path, c.status, c.warnings) for c in coverages],
                         [(LS_DIR, "NOT_PRESENT", [p.LOCAL_STORAGE_LOG_NOT_PRESENT]),
                          (f"{LS_DIR}/000005.ldb", "NOT_SUPPORTED", [p.LEVELDB_TABLE_TOO_SMALL])])  # SSTable 아님
        self.assertEqual(coverages[1].source_sha256, hashlib.sha256(b"sstable bytes").hexdigest())
        (self.leveldb / "000003.log").write_bytes(b"")
        (self.leveldb / "LOG").write_text("leveldb text log", encoding="utf-8")  # 확장자 없는 LOG 는 대상 아님
        _, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(c.source_path.rpartition("/")[2], c.status) for c in coverages],
                         [("000003.log", "EMPTY"), ("000005.ldb", "NOT_SUPPORTED")])

    # 15
    def test_source_tree_unchanged(self):
        self.write_log(put_history(10, conv_item()))
        create_history_db(self.root / "Default" / "History")
        before = tree_snapshot(self.root)
        p.read_local_storage(self.source, LS_DIR)
        p.run(self.source, "Default/History")
        self.assertEqual(run_main(["--dir", self.root, "--history", "Default/History", "--out", self.base / "out.json"])[0], p.EXIT_OK)
        self.assertEqual(tree_snapshot(self.root), before)


class ConversationResidueTest(LocalStorageTestBase):
    # LS 2~7
    def test_residual_only_conversation(self):
        self.write_log(put_history(10, conv_item(), conv_item(RESIDUE_ID_2, "두 번째 대화")))
        result = p.run(self.source, "Default/History")
        self.assertEqual(len(result.conversations), 2)
        conversation = result.conversations[0]
        self.assertEqual((conversation.conversation_id, conversation.title, conversation.recovery_status, conversation.messages),
                         (RESIDUE_ID, "안녕 인사 응답", "RESIDUAL_ONLY", []))
        self.assertEqual((conversation.create_time_raw, conversation.create_time_utc, conversation.create_time_kst,
                          conversation.create_time_type, conversation.create_time_source),
                         (CREATE_TIME, CREATE_TIME, CREATE_KST, "iso_utc", p._RESIDUE_CREATE_TIME_SOURCE))
        coverage = next(c for c in result.coverage if c.artifact_type == "local_storage")
        source = conversation.source_artifacts[0]
        self.assertEqual((source["artifact_type"], source["source_path"], source["source_sha256"], source["sequence"], source["operation"]),
                         ("local_storage", f"{LS_DIR}/000003.log", coverage.source_sha256, 10, "PUT"))
        self.assertEqual(source["record_location"], "offset=0 block=0 sequence=10 operation=0 page=0 item=0")
        self.assertEqual((conversation.warnings, conversation.correlated_record_ids), ([], []))
        self.assertEqual(result.events, [])  # RECOVERED_DATA 는 사용자 행위 Event 가 아님
        self.assertIn(p.RUN_WARNING_MESSAGE_RECOVERY_SCOPE, result.warnings)
        self.assertIn('"title": "두 번째 대화"', result.to_json())

    # LS 8
    def test_multiple_versions_same_values(self):
        self.write_log(put_history(10, conv_item()), put_history(12, conv_item()))
        conversations = p.run(self.source, "Default/History").conversations
        self.assertEqual(len(conversations), 1)
        self.assertEqual((conversations[0].title, conversations[0].warnings), ("안녕 인사 응답", [p.RESIDUAL_MULTIPLE_VERSIONS]))
        self.assertEqual([s["sequence"] for s in conversations[0].source_artifacts], [10, 12])

    def test_multiple_versions_conflicting_title(self):
        self.write_log(put_history(12, conv_item(title="바뀐 제목")), put_history(10, conv_item(title="처음 제목")))
        conversation = p.run(self.source, "Default/History").conversations[0]
        self.assertIsNone(conversation.title)  # 어느 버전도 "진짜"로 고르지 않음
        self.assertEqual(conversation.warnings, [p.RESIDUAL_MULTIPLE_VERSIONS, f"{p.RESIDUAL_VALUE_CONFLICT}:title"])
        self.assertEqual([(s["sequence"], s["title"]) for s in conversation.source_artifacts], [(10, "처음 제목"), (12, "바뀐 제목")])
        self.assertEqual(conversation.create_time_utc, CREATE_TIME)  # 같은 값인 필드는 유지

    # LS 9
    def test_delete_after_put_keeps_residue(self):
        self.write_log(put_history(10, conv_item()), ldb_batch(11, ("DELETE", ls_key(LS_HISTORY_KEY))))
        result = p.run(self.source, "Default/History")
        self.assertEqual([r.observed["operation"] for r in result.records], ["PUT", "DELETE"])
        self.assertEqual([(c.conversation_id, c.recovery_status) for c in result.conversations], [(RESIDUE_ID, "RESIDUAL_ONLY")])
        self.assertEqual(result.events, [])  # CONVERSATION_DELETE 판정 없음

    # LS 17, 18
    def test_history_correlation_exact_id_only(self):
        other_id = "6a86cf88-a4d8-83ee-9ef5-d2e6b3c39530"  # 한 글자만 다른 ID
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, f"https://chatgpt.com/c/{RESIDUE_ID}", "대화"), (2, f"https://chatgpt.com/c/{other_id}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0), (2, 2, 13432490001000000, 0, 0x30000000, "", 0)])
        self.write_log(put_history(10, conv_item(), conv_item(RESIDUE_ID_2)))
        result = p.run(self.source, "Default/History")
        links = {c.conversation_id: c.correlated_record_ids for c in result.conversations}
        self.assertEqual(links, {RESIDUE_ID: ["history:Default/History#visits.id=1"], RESIDUE_ID_2: []})

    def test_history_correlation_requires_same_profile(self):
        create_history_db(self.root / "Default" / "History", urls=[(1, f"https://chatgpt.com/c/{RESIDUE_ID}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0)])
        self.write_log(put_history(10, conv_item()))
        records, coverages = p.extract(self.source, "Default/History")
        moved = [dataclasses.replace(r, browser_profile="Profile 1") if r.artifact_type == "local_storage" else r for r in records]
        self.assertEqual(p.extract_conversation_residue(moved, coverages)[0].correlated_record_ids, [])

    def test_invalid_create_time_is_not_converted(self):
        self.write_log(put_history(10, conv_item(create_time="2026-09-12 18:04:34")))  # 시간대 없음
        conversation = p.run(self.source, "Default/History").conversations[0]
        self.assertEqual((conversation.create_time_raw, conversation.create_time_utc, conversation.create_time_type),
                         ("2026-09-12 18:04:34", None, "iso_utc"))
        self.assertEqual(conversation.warnings, [p.TS_NAIVE_ISO])

    def test_cli_summary_with_residue(self):
        create_history_db(self.root / "Default" / "History")
        self.write_log(put_history(10, conv_item(), conv_item(RESIDUE_ID_2, "두 번째 대화")))
        (self.leveldb / "000005.ldb").write_bytes(b"sstable bytes")
        out = self.base / "output" / "residue.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        for line in ("Local Storage: 000003.log PARSED (1 ChatGPT records)",
                     "Local Storage: 000005.ldb NOT_SUPPORTED (not analyzed) [warnings: 1]",
                     "Recovered Conversations".ljust(24) + ": 2", "Recovered Message Nodes".ljust(24) + ": 0",
                     "Status".ljust(24) + ": RESIDUAL ONLY", "Message Recovery".ljust(24) + f": {p.MESSAGE_RECOVERY_STATUS}"):
            self.assertIn(line, stdout)
        self.assertIn("  Title".ljust(18) + ": 두 번째 대화", stdout)  # 실제로 복구된 제목은 상세에 표시
        self.assertIn("  Message Content".ljust(18) + ": NOT RECOVERED", stdout)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data), PARSE_RESULT_KEYS)
        self.assertEqual([c["recovery_status"] for c in data["conversations"]], ["RESIDUAL_ONLY", "RESIDUAL_ONLY"])
        self.assertEqual(data["conversations"][1]["title"], "두 번째 대화")


class LocalStorageProfileTest(ProfileDiscoveryTestBase):
    # 16, Profile 연결
    def test_profile_metadata_propagation_and_isolation(self):
        alice = user_data_dir(self.root, "Alice")
        for profile, folder in (("Profile 1", "Local Storage/leveldb"), ("Default", "local storage/LEVELDB")):
            leveldb = alice / profile / folder
            leveldb.mkdir(parents=True)
            (leveldb / "000003.log").write_bytes(ldb_log(put_history(10, conv_item(SERVER_ID, f"{profile} 대화"))))
        result = p.run(self.source)
        storage = [c for c in result.coverage if c.artifact_type == "local_storage"]
        self.assertEqual([(c.os_user, c.browser_profile, c.status, c.source_path) for c in storage[:2]],
                         [("Alice", "Default", "PARSED", f"{ALICE_UD}/Default/local storage/LEVELDB/000003.log"),
                          ("Alice", "Profile 1", "PARSED", f"{ALICE_UD}/Profile 1/Local Storage/leveldb/000003.log")])
        for record in result.records:
            if record.artifact_type == "local_storage":
                self.assertEqual(record.os_user, "Alice")
                self.assertTrue(record.source_path.startswith(f"{ALICE_UD}/{record.browser_profile}/"))
        # 같은 ID 라도 Profile 이 다르면 합치지 않는다. History /c/<id> 방문은 Profile 1 에만 있다 (PROFILE1_URLS)
        self.assertEqual(sorted((c.title, c.warnings, len(c.correlated_record_ids)) for c in result.conversations),
                         [("Default 대화", [], 0), ("Profile 1 대화", [], 1)])
        linked = next(c for c in result.conversations if c.correlated_record_ids)
        self.assertEqual(linked.correlated_record_ids, [f"history:{ALICE_UD}/Profile 1/History#visits.id=1"])


# =============================================================================
# CLI 표시 — Event 시각 / 대화 상세 / 복구된 메시지 본문 (표시 기능 테스트, 메시지 복구 기능이 아님)
# =============================================================================
# RecoveredMessage 는 synthetic 이다 (표시 기능 테스트). 실제 Cache 에서의 메시지 복구 테스트는 파일 끝 Cache 절.

LONG_KOREAN_TEXT = "크롬 로컬 스토리지의 잔존 데이터는 삭제 이후에도 남을 수 있습니다. 끝까지 출력되어야 합니다.\n" * 800 + "마지막 줄"


def display_result(events=(), conversations=()):
    return p.ParseResult(run_id="r", run_started_utc="2026-09-15T00:00:00Z",
                         input=p.InputInfo(kind="directory", path="C:\\case"),
                         events=list(events), conversations=list(conversations))


class CliDisplayTest(unittest.TestCase):
    # 1~4
    def test_event_rows_show_stored_utc_kst_action_status_confidence(self):
        text = p.format_summary(display_result(p.detect_logout([make_history_record()])))
        self.assertRegex(text, r"(?m)^UTC\s+KST\s+ACTION\s+STATUS\s+CONFIDENCE$")
        self.assertRegex(text, rf"(?m)^{re.escape(LOGOUT_UTC)}\s+{re.escape(LOGOUT_KST)}\s+LOGOUT\s+DETECTED\s+HIGH$")

    def test_event_timestamp_is_not_recomputed(self):
        event = p.detect_logout([make_history_record()])[0]
        shown = dataclasses.replace(event, timestamp_utc="2000-01-01T00:00:00Z", timestamp_kst="2000-01-01T09:00:00+09:00")
        text = p.format_summary(display_result([shown]))
        self.assertIn("2000-01-01T00:00:00Z", text)  # Event 에 저장된 문자열을 그대로 사용
        self.assertNotIn(LOGOUT_UTC, text)

    # 5
    def test_event_without_timestamp_shows_na(self):
        events = p.detect_logout([make_history_record(raw=None)])
        self.assertIsNone(events[0].timestamp_utc)
        text = p.format_summary(display_result(events))
        self.assertRegex(text, r"(?m)^N/A\s+N/A\s+LOGOUT\s+CANDIDATE\s+LOW$")

    # 6~12
    def test_residual_conversation_details(self):
        conversations = [
            make_conversation(conversation_id=RESIDUE_ID, title="안녕 인사 응답", recovery_status="RESIDUAL_ONLY", messages=[],
                              create_time_raw=CREATE_TIME, create_time_utc=CREATE_TIME, create_time_kst=CREATE_KST,
                              create_time_type="iso_utc", correlated_record_ids=["history:History#visits.id=38"]),
            make_conversation(conversation_id=RESIDUE_ID_2, title=None, recovery_status="RESIDUAL_ONLY", messages=[]),
        ]
        text = p.format_summary(display_result(conversations=conversations))
        self.assertIn("[CONVERSATION DETAILS]", text)
        for line in ("Conversation #1", "  ID".ljust(18) + f": {RESIDUE_ID}", "  Title".ljust(18) + ": 안녕 인사 응답",
                     "  Status".ljust(18) + ": RESIDUAL_ONLY", "  Created UTC".ljust(18) + f": {CREATE_TIME}",
                     "  Created KST".ljust(18) + f": {CREATE_KST}", "  Messages".ljust(18) + ": 0",
                     "  History Links".ljust(18) + ": history:History#visits.id=38",
                     "Conversation #2", "  Title".ljust(18) + ": N/A", "  Created UTC".ljust(18) + ": N/A",
                     "  History Links".ljust(18) + ": none",
                     "Status".ljust(24) + ": RESIDUAL ONLY"):
            self.assertIn(line, text)
        self.assertEqual(text.count("  Message Content".ljust(18) + ": NOT RECOVERED"), 2)
        self.assertNotIn("[user]", text)  # 없는 메시지를 만들지 않음

    # 13~16
    def test_recovered_messages_printed_in_full(self):
        messages = [make_message(1, content=LONG_KOREAN_TEXT), make_message(0)]  # 복구 순서가 뒤바뀌어도 sequence_index 순
        conversation = make_conversation(messages=messages)
        text = p.format_summary(display_result(conversations=[conversation]))
        self.assertLess(text.index("[user] message #1"), text.index("[assistant] message #2"))
        self.assertEqual(text.count("Chrome History 분석 방법 알려줘"), 1)
        self.assertEqual(text.count(LONG_KOREAN_TEXT), 1)  # 긴 한글 본문 전체, 절단·생략 없음
        self.assertTrue(text.split(LONG_KOREAN_TEXT)[0].endswith("    Content :\n"))
        self.assertIn("    UTC".ljust(12) + ": 2026-09-12T18:04:34.276355Z", text)
        self.assertIn("    KST".ljust(12) + ": 2026-09-13T03:04:34.276355+09:00", text)
        self.assertNotIn("NOT RECOVERED", text)
        self.assertIn("Recovered Message Nodes".ljust(24) + ": 2", text)


class CliDisplaySecretTest(LocalStorageTestBase):
    # 17
    def test_cli_detail_output_keeps_redaction(self):
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, "https://chatgpt.com/api/auth/callback/openai?code=SECRETCODE12345&state=SECRETSTATE6789", "t"),
                                (2, f"https://chatgpt.com/c/{RESIDUE_ID}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0), (2, 2, 13432490001000000, 0, 0x30000000, "", 0)])
        session = {"sessionToken": SECRET_TOKEN, "email": SECRET_EMAIL, "userId": LS_USER_ID, "lastLoggedInAt": 1787126888000}
        self.write_log(put_history(10, conv_item()),
                       ldb_batch(11, ("PUT", ls_key("oai/apps/accountSwitchSessions"), ls_utf16([session])),
                                 ("PUT", ls_key("RESUME_TOKEN_STORE_KEY"), ls_latin1("SECRET-RESUME-TOKEN"))))
        out = self.base / "output" / "secret.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertIn("  History Links".ljust(18) + ": history:Default/History#visits.id=2", stdout)
        for secret in ("SECRETCODE12345", "SECRETSTATE6789", SECRET_TOKEN, SECRET_EMAIL, LS_USER_ID, "SECRET-RESUME-TOKEN"):
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, out.read_text(encoding="utf-8"))


# =============================================================================
# S10 — DD / RAW Image → Partition → NTFS → ImageSource → 기존 Pipeline
# =============================================================================
# 실제 NTFS 이미지 fixture 를 만들 도구가 없다 (관리자 권한·mkntfs 없음). 그래서
#   - 파티션 선택·NTFS 접근·ImageSource 계약·Pipeline 연결은 pytsk3 를 흉내 낸 FakeTsk (디렉터리를 NTFS 처럼 보여 줌) 로 검증한다
#     → TESTED (synthetic/mock). 실제 NTFS 를 읽었다는 뜻이 아니다.
#   - 파티션 표 해석은 실제 pytsk3 로 작은(1 MiB) synthetic MBR / GPT 이미지를 읽어 검증한다.

class FakeTskImage:
    def __init__(self, path):
        self.path, self.closed = path, False

    def close(self):
        self.closed = True


class FakeTskVolume:
    def __init__(self, block_size, parts):
        self.info, self._parts = SimpleNamespace(block_size=block_size), parts

    def __iter__(self):
        return iter(self._parts)


class FakeTskFS:
    """디렉터리 트리를 TSK FS_Info 처럼 보여 준다 (open / open_dir / read_random)."""

    def __init__(self, tsk, ftype, root):
        self.tsk, self.root, self.info = tsk, root, SimpleNamespace(ftype=ftype)

    def _full(self, tsk_path):
        return Path(self.root, *[part for part in tsk_path.split("/") if part])

    @staticmethod
    def _meta(full):
        stat = full.stat()
        return SimpleNamespace(type=2 if full.is_dir() else 1, size=0 if full.is_dir() else stat.st_size, addr=stat.st_ino)

    def open(self, path):
        full = self._full(path)
        if not full.exists():
            raise OSError(f"fake tsk: not found {path}")
        relative = path.strip("/")

        def read_random(offset, size):
            if relative in self.tsk.failing_reads:
                raise OSError("fake tsk: read error")
            with open(full, "rb") as handle:
                handle.seek(offset)
                return handle.read(size)

        return SimpleNamespace(info=SimpleNamespace(meta=self._meta(full)), read_random=read_random)

    def open_dir(self, path="/"):
        full = self._full(path)
        entries = [SimpleNamespace(info=SimpleNamespace(name=SimpleNamespace(name=name.encode(), flags=1), meta=self._meta(full)))
                   for name in (".", "..")]
        for child in sorted(full.iterdir()):
            entries.append(SimpleNamespace(info=SimpleNamespace(
                name=SimpleNamespace(name=child.name.encode("utf-8"), flags=1), meta=self._meta(child))))
        for name in self.tsk.deleted.get(path.strip("/"), ()):  # 삭제된 항목 (unallocated name)
            entries.append(SimpleNamespace(info=SimpleNamespace(
                name=SimpleNamespace(name=name.encode(), flags=2), meta=SimpleNamespace(type=1, size=1, addr=999999))))
        return entries


class FakeTsk:
    """pytsk3 모듈 대역. partitions=None 이면 파티션 표 없음. filesystems: {byte offset: ("NTFS" | "FAT", root)}."""

    TSK_VS_PART_FLAG_ALLOC = 1
    TSK_FS_TYPE_NTFS = 1
    TSK_FS_META_TYPE_DIR = 2
    TSK_FS_META_TYPE_REG = 1
    TSK_FS_NAME_FLAG_UNALLOC = 2

    def __init__(self, *, partitions=None, filesystems=None, block_size=512, deleted=None, failing_reads=()):
        self.partitions, self.filesystems, self.block_size = partitions, filesystems or {}, block_size
        self.deleted, self.failing_reads, self.images = deleted or {}, set(failing_reads), []

    def Img_Info(self, path):
        image = FakeTskImage(path)
        self.images.append(image)
        return image

    def Volume_Info(self, image):
        if self.partitions is None:
            raise OSError("fake tsk: no volume system")
        return FakeTskVolume(self.block_size, [SimpleNamespace(addr=addr, desc=desc.encode(), start=start, len=length, flags=flags)
                                               for addr, desc, start, length, flags in self.partitions])

    def FS_Info(self, image, offset=0):
        entry = self.filesystems.get(offset)
        if entry is None:
            raise OSError("fake tsk: cannot determine file system type")
        ftype, root = entry
        return FakeTskFS(self, 1 if ftype == "NTFS" else 5, root)


NTFS_OFFSET = 2048 * 512
WINDOWS_PARTITIONS = [(1, "Unallocated", 0, 2048, 2), (2, "NTFS / exFAT (0x07)", 2048, 400000, 1),
                      (3, "Unallocated", 402048, 100, 2)]


class ImageTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base = Path(self._tmp.name)
        self.tree = self.base / "ntfs_root"
        self.tree.mkdir()
        self.image = self.base / "disk.dd"
        self.image.write_bytes(b"\x00" * 4096)  # fake module 은 내용을 읽지 않는다 (경로·불변 확인용)

    def tearDown(self):
        gc.collect()
        self._tmp.cleanup()

    def use_fake(self, **kwargs):
        fake = FakeTsk(**kwargs)
        patcher = mock.patch("chatgpt_parser.image.pytsk3", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def image_state(self):
        stat = self.image.stat()
        return stat.st_size, stat.st_mtime_ns, hashlib.sha256(self.image.read_bytes()).hexdigest()


class ImagePartitionSelectionTest(ImageTestBase):
    def test_partition_offset_uses_volume_block_size(self):
        self.use_fake(partitions=[(0, "Primary Table (#0)", 0, 1, 4), (2, "NTFS / exFAT (0x07)", 100, 50, 1)], block_size=4096)
        partitions, warnings = p.list_image_partitions(p.pytsk3.Img_Info(str(self.image)))
        self.assertEqual(warnings, [])
        self.assertEqual([(pt.index, pt.description, pt.start_sector, pt.sector_count, pt.block_size, pt.byte_offset)
                          for pt in partitions], [(2, "NTFS / exFAT (0x07)", 100, 50, 4096, 409600)])  # 512 가정 없음

    def test_selects_ntfs_partition_with_users_not_first_partition(self):
        (self.tree / "Users").mkdir()
        other_ntfs = self.base / "data_volume"
        other_ntfs.mkdir()
        partitions = [(1, "EFI System", 2048, 1000, 1), (2, "Microsoft reserved", 3048, 100, 1),
                      (3, "Basic data (data)", 3148, 1000, 1), (4, "Basic data (Windows)", 4148, 90000, 1)]
        self.use_fake(partitions=partitions, filesystems={2048 * 512: ("FAT", None), 3148 * 512: ("NTFS", other_ntfs),
                                                          4148 * 512: ("NTFS", self.tree)})
        source = p.open_image_source(self.image)
        self.assertIn("index=4 byte_offset=2123776", source.partition)
        self.assertEqual(source.warnings, [f"{p.IMAGE_PARTITION_NOT_NTFS}:partition-1", f"{p.IMAGE_FILESYSTEM_OPEN_FAILED}:partition-2",
                                           f"{p.IMAGE_NTFS_CANDIDATES}:2",
                                           f"{p.IMAGE_PARTITION_SELECTED}:partition-4:first NTFS partition with a Users directory"])
        source.close()

    def test_raw_ntfs_partition_image_fallback(self):
        (self.tree / "Users").mkdir()
        self.use_fake(partitions=None, filesystems={0: ("NTFS", self.tree)})
        source = p.open_image_source(self.image)
        self.assertEqual(source.partition, "whole image (no partition table), byte_offset=0")
        self.assertEqual(source.warnings[0], p.IMAGE_NO_PARTITION_TABLE)
        self.assertTrue(source.is_dir("Users"))
        source.close()

    def test_open_errors_are_image_open_errors(self):
        fake = self.use_fake(partitions=[(2, "Linux (0x83)", 2048, 10, 1)], filesystems={NTFS_OFFSET: ("FAT", None)})
        with self.assertRaisesRegex(p.ImageOpenError, "no NTFS filesystem"):
            p.open_image_source(self.image)
        self.assertTrue(fake.images[0].closed)
        e01 = self.base / "disk.E01"
        e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
        with mock.patch("chatgpt_parser.image.pyewf", None):  # pyewf 없는 환경: E01 만 거부, DD/RAW 는 영향 없음
            with self.assertRaisesRegex(p.ImageOpenError, p.E01_REQUIRES_PYEWF):
                p.open_image_source(e01)
        with self.assertRaisesRegex(p.ImageOpenError, "logical evidence file"):
            p.open_image_source(self.base / "case.L01")
        with self.assertRaisesRegex(p.ImageOpenError, "not found"):
            p.open_image_source(self.base / "missing.dd")
        with mock.patch("chatgpt_parser.image.pytsk3", None):
            with self.assertRaisesRegex(p.ImageOpenError, "pytsk3 is not installed"):
                p.open_image_source(self.image)


class ImageSourceContractTest(ImageTestBase):
    def setUp(self):
        super().setUp()
        (self.tree / "Default").mkdir()
        create_history_db(self.tree / "Default" / "History")
        (self.tree / "Default" / "empty.bin").write_bytes(b"")
        (self.tree / "Default" / "big.bin").write_bytes(bytes(range(256)) * 20)  # 5120 B, 여러 chunk
        (self.tree / "Users").mkdir()
        self.fake = self.use_fake(partitions=WINDOWS_PARTITIONS, filesystems={NTFS_OFFSET: ("NTFS", self.tree)},
                                  deleted={"Default": ["deleted_history.db"]}, failing_reads={"Default/broken.bin"})
        (self.tree / "Default" / "broken.bin").write_bytes(b"x" * 10)
        self.source = p.open_image_source(self.image)
        self.directory = p.DirectorySource(self.tree)

    def tearDown(self):
        self.source.close()
        super().tearDown()

    def test_same_contract_as_directory_source(self):
        with mock.patch("chatgpt_parser.image._IMAGE_READ_CHUNK", 1000):
            for path in ("", "Default", "Default/History", "Default/empty.bin", "Default/big.bin", "missing", "Default/missing"):
                with self.subTest(path=path):
                    for method in ("exists", "is_file", "is_dir", "file_status"):
                        self.assertEqual(getattr(self.source, method)(path), getattr(self.directory, method)(path))
            self.assertEqual(self.source.list_dir("Default"), self.directory.list_dir("Default"))
            self.assertEqual(self.source.list_dir(""), self.directory.list_dir(""))
            for path in ("Default/History", "Default/big.bin", "Default/empty.bin"):
                self.assertEqual(self.source.size(path), self.directory.size(path))
                self.assertEqual(self.source.read_bytes(path), self.directory.read_bytes(path))
                self.assertEqual(self.source.sha256(path), self.directory.sha256(path))
        self.assertEqual(self.source.kind, "dd")

    def test_errors_match_directory_source(self):
        for method, path, error in (("list_dir", "missing", FileNotFoundError), ("list_dir", "Default/History", NotADirectoryError),
                                    ("read_bytes", "missing", FileNotFoundError), ("read_bytes", "Default", IsADirectoryError),
                                    ("size", "Default", IsADirectoryError)):
            with self.subTest(method=method, path=path):
                with self.assertRaises(error):
                    getattr(self.source, method)(path)
        with self.assertRaises(OSError):
            self.source.read_bytes("Default/broken.bin")  # 이미지 읽기 오류는 OSError (Reader 가 warning 처리)

    def test_path_safety(self):
        for bad in ("../outside", "Default/../../x", "/Users", "\\Users", "C:/Windows", "C:\\Windows", "\\\\server\\share\\x", "Users\x00x"):
            for method in ("exists", "list_dir", "read_bytes", "path_key"):
                with self.subTest(path=bad, method=method):
                    with self.assertRaises(p.SourcePathError):
                        getattr(self.source, method)(bad)

    def test_deleted_entries_hidden_and_path_key_by_inode(self):
        self.assertNotIn("deleted_history.db", self.source.list_dir("Default"))
        self.assertEqual(self.source.path_key("Default/History"), self.source.path_key("DEFAULT/history"))
        self.assertTrue(self.source.path_key("Default/History").startswith("inode:"))
        self.assertEqual(self.source.path_key("no/such"), "no/such")


class ImagePipelineTest(ImageTestBase):
    def setUp(self):
        super().setUp()
        build_profile_tree(self.tree)
        leveldb = user_data_dir(self.tree, "Alice") / "Profile 1" / "Local Storage" / "leveldb"
        leveldb.mkdir(parents=True)
        (leveldb / "000003.log").write_bytes(ldb_log(put_history(10, conv_item())))

    def test_image_pipeline_matches_directory_pipeline(self):
        self.use_fake(partitions=WINDOWS_PARTITIONS, filesystems={NTFS_OFFSET: ("NTFS", self.tree)})
        expected = p.run(p.DirectorySource(self.tree))
        source = p.open_image_source(self.image)
        try:
            actual = p.run(source)
        finally:
            source.close()

        def events(result):
            return [(e.action, e.action_status, e.confidence, e.timestamp_utc, e.os_user, e.browser_profile) for e in result.events]

        self.assertEqual(events(actual), events(expected))
        self.assertEqual(sorted(e[0] for e in events(actual)), ["CONVERSATION_ACCESS", "LOGIN", "LOGOUT"])
        self.assertEqual([(c.artifact_type, c.os_user, c.browser_profile, c.source_path, c.status, c.record_count, c.source_sha256)
                          for c in actual.coverage],
                         [(c.artifact_type, c.os_user, c.browser_profile, c.source_path, c.status, c.record_count, c.source_sha256)
                          for c in expected.coverage])
        self.assertEqual([r.record_id for r in actual.records], [r.record_id for r in expected.records])
        self.assertEqual([(c.conversation_id, c.title, c.correlated_record_ids) for c in actual.conversations],
                         [(c.conversation_id, c.title, c.correlated_record_ids) for c in expected.conversations])
        self.assertEqual(len(actual.conversations), 1)  # Local Storage / Residue 도 같은 Source 로 연결
        self.assertEqual((actual.input.kind, actual.input.path, actual.input.filesystem), ("dd", str(self.image), "NTFS"))
        self.assertIn("index=2 byte_offset=1048576 start_sector=2048 sector_count=400000 block_size=512", actual.input.partition)
        self.assertIn(f"{p.IMAGE_PARTITION_SELECTED}:partition-2:first NTFS partition with a Users directory", actual.warnings)

    def test_profile_read_error_does_not_stop_other_profiles(self):
        broken = f"{ALICE_UD}/Default/History"
        self.use_fake(partitions=WINDOWS_PARTITIONS, filesystems={NTFS_OFFSET: ("NTFS", self.tree)}, failing_reads={broken})
        source = p.open_image_source(self.image)
        try:
            result = p.run(source)
        finally:
            source.close()
        coverage = {c.source_path: c for c in result.coverage}
        self.assertEqual((coverage[broken].status, coverage[broken].warnings), ("PARSE_ERROR", [p.HISTORY_READ_ERROR]))
        self.assertEqual(coverage[f"{ALICE_UD}/Profile 1/History"].status, "PARSED")
        self.assertEqual([e.action for e in result.events], ["CONVERSATION_ACCESS"])

    def test_cli_image_mode(self):
        fake = self.use_fake(partitions=WINDOWS_PARTITIONS, filesystems={NTFS_OFFSET: ("NTFS", self.tree)})
        before = self.image_state()
        out = self.base / "output" / "image.json"
        code, stdout, stderr = run_main(["--image", self.image, "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        for line in ("Type".ljust(11) + ": DD/RAW", "Source".ljust(11) + f": {self.image}", "Filesystem".ljust(11) + ": NTFS",
                     "[CHROME PROFILES]", "Mode".ljust(11) + ": Auto discovery"):
            self.assertIn(line, stdout)
        self.assertRegex(stdout, r"(?m)^Partition\s+: index=2 byte_offset=1048576 ")
        self.assertRegex(stdout, rf"(?m)^{re.escape(LOGOUT_UTC)}\s+{re.escape(LOGOUT_KST)}\s+LOGOUT\s+DETECTED\s+HIGH$")
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data), PARSE_RESULT_KEYS)
        self.assertEqual((data["input"]["kind"], data["input"]["filesystem"]), ("dd", "NTFS"))
        self.assertTrue(data["input"]["partition"].startswith("index=2 byte_offset=1048576"))
        self.assertTrue(all(image.closed for image in fake.images))
        self.assertEqual(self.image_state(), before)  # 이미지 파일 불변

        code, _, stderr = run_main(["--image", self.image, "--out", self.image, "--overwrite"])
        self.assertEqual(code, p.EXIT_USAGE)
        self.assertIn("must not be the --image file", stderr)
        self.assertEqual(self.image_state(), before)


def synthetic_mbr_image(path):
    data = bytearray(512 * 2048)
    for i, (ptype, start, count) in enumerate([(0x07, 64, 512), (0xEF, 600, 300)]):
        data[446 + 16 * i:462 + 16 * i] = struct.pack("<B3sB3sII", 0, b"\x00" * 3, ptype, b"\x00" * 3, start, count)
    data[510:512] = b"\x55\xAA"
    path.write_bytes(data)


def synthetic_gpt_image(path):
    sectors = 2048
    data = bytearray(512 * sectors)
    data[446:462] = struct.pack("<B3sB3sII", 0, b"\x00" * 3, 0xEE, b"\x00" * 3, 1, sectors - 1)
    data[510:512] = b"\x55\xAA"
    entries = bytearray(128 * 128)
    for i, (type_guid, first, last, name) in enumerate([("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", 34, 99, "EFI"),
                                                        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", 100, 1900, "Basic data")]):
        entries[i * 128:(i + 1) * 128] = (uuid.UUID(type_guid).bytes_le + uuid.UUID(int=i + 1).bytes_le
                                          + struct.pack("<QQQ", first, last, 0) + name.encode("utf-16-le").ljust(72, b"\x00"))
    header = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0, 1, sectors - 1, 34, sectors - 34,
                                   uuid.UUID(int=99).bytes_le, 2, 128, 128, zlib.crc32(entries) & 0xFFFFFFFF))
    header[16:20] = struct.pack("<I", zlib.crc32(header) & 0xFFFFFFFF)  # GPT 는 표준 CRC32
    data[512:604] = header
    data[1024:1024 + len(entries)] = entries
    path.write_bytes(data)


@unittest.skipIf(p.pytsk3 is None, "pytsk3 not installed")
class FakeEwfHandle:
    """pyewf handle 대역 — bytes 를 random access 로 제공한다 (실제 E01 내용 없음)."""

    def __init__(self, data=b""):
        self.data, self.offset, self.closed = data, 0, False
        self.opened, self.reads = None, []

    def open(self, filenames, *flags):
        self.opened = (list(filenames), flags)

    def get_media_size(self):
        return len(self.data)

    def seek(self, offset, whence=0):
        self.offset = offset

    def read(self, size):
        chunk = self.data[self.offset:self.offset + size]
        self.reads.append((self.offset, size))
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class FakePyewf:
    """pyewf 모듈 대역. glob/handle 만 제공하고, 필요하면 오류를 던진다."""

    def __init__(self, segments=("disk.E01",), handle=None, glob_error=None, open_error=None, read_flags=None):
        self.segments, self._handle = list(segments), handle or FakeEwfHandle()
        self.glob_error, self.open_error, self.globbed = glob_error, open_error, []
        if read_flags is not None:
            self.get_access_flags_read = lambda: read_flags

    def glob(self, filename):
        if self.glob_error is not None:
            raise self.glob_error
        self.globbed.append(filename)
        return list(self.segments)

    def handle(self):
        if self.open_error is not None:
            self._handle.open = self._raise
        return self._handle

    def _raise(self, *args):
        raise self.open_error


class EwfAdapterTest(ImageTestBase):
    """E01 Adapter — 실제 pytsk3 로 Img_Info 계약과 random access 를 확인한다 (실제 E01 이미지 없음)."""

    def setUp(self):
        super().setUp()
        p._EWF_IMG_INFO_CLASS = None
        self.addCleanup(setattr, p, "_EWF_IMG_INFO_CLASS", None)

    def test_adapter_exposes_size_read_and_close(self):
        data = bytes(range(256)) * 16
        handle = FakeEwfHandle(data)
        image = p._ewf_img_info_class()(handle, ["disk.E01", "disk.E02"])
        self.assertIsInstance(image, p.pytsk3.Img_Info)
        self.assertEqual(image.get_size(), len(data))
        self.assertEqual(image.read(10, 5), data[10:15])
        self.assertEqual(image.read(4000, 96), data[4000:4096])
        self.assertEqual(image.segments, ["disk.E01", "disk.E02"])  # split segment 목록 보존
        self.assertEqual(handle.reads[0], (10, 5))  # 전체를 RAW 로 읽지 않고 요청 구간만 읽는다
        image.close()
        self.assertTrue(handle.closed)
        del image
        gc.collect()

    def test_real_pytsk3_reads_partition_table_through_adapter(self):
        synthetic_mbr_image(self.image)
        handle = FakeEwfHandle(self.image.read_bytes())
        image = p._ewf_img_info_class()(handle, ["disk.E01"])
        try:
            partitions, warnings = p.list_image_partitions(image)
        finally:
            image.close()
            del image
            gc.collect()
        self.assertEqual([(pt.index, pt.byte_offset) for pt in partitions], [(2, 32768), (4, 307200)])
        self.assertEqual(warnings, [])
        self.assertLess(max(offset + size for offset, size in handle.reads), len(handle.data) + 1)


class EwfOpenTest(ImageTestBase):
    """open_ewf_image / open_image_source 의 E01 분기 (pyewf 대역 사용)."""

    def setUp(self):
        super().setUp()
        p._EWF_IMG_INFO_CLASS = None
        self.addCleanup(setattr, p, "_EWF_IMG_INFO_CLASS", None)
        self.e01 = self.base / "disk.E01"
        self.e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")

    def open_with(self, fake):
        with mock.patch("chatgpt_parser.image.pyewf", fake):
            return p.open_ewf_image(self.e01)

    def test_missing_pyewf_is_rejected(self):
        with mock.patch("chatgpt_parser.image.pyewf", None):
            with self.assertRaisesRegex(p.ImageOpenError, p.E01_REQUIRES_PYEWF):
                p.open_ewf_image(self.e01)

    def test_segment_errors(self):
        with self.assertRaisesRegex(p.ImageOpenError, p.E01_SEGMENTS_UNREADABLE):
            self.open_with(FakePyewf(glob_error=OSError("missing segment 3")))
        with self.assertRaisesRegex(p.ImageOpenError, p.E01_SEGMENTS_UNREADABLE):
            self.open_with(FakePyewf(segments=()))
        with self.assertRaisesRegex(p.ImageOpenError, p.E01_OPEN_FAILED):
            self.open_with(FakePyewf(open_error=OSError("invalid EWF header")))

    def test_segmented_open_passes_all_segments(self):
        handle = FakeEwfHandle(b"\x00" * 1024)
        fake = FakePyewf(segments=("disk.E01", "disk.E02", "disk.E03"), handle=handle, read_flags=1)
        image, warnings = self.open_with(fake)
        try:
            self.assertEqual(fake.globbed, [str(self.e01)])
            self.assertEqual(handle.opened, (["disk.E01", "disk.E02", "disk.E03"], (1,)))  # 읽기 flag 전달
            self.assertEqual(warnings, [f"{p.IMAGE_EWF_SEGMENTS}:3"])
            self.assertEqual(image.get_size(), 1024)
        finally:
            image.close()
            del image
            gc.collect()

    def test_open_image_source_routes_e01_to_pyewf_and_keeps_dd(self):
        self.use_fake(partitions=WINDOWS_PARTITIONS, filesystems={NTFS_OFFSET: ("NTFS", self.tree)})
        (self.tree / "Users").mkdir()
        called = []

        def fake_open_ewf(image_path):
            called.append(str(image_path))
            return FakeTskImage(str(image_path)), [f"{p.IMAGE_EWF_SEGMENTS}:2"]

        with mock.patch("chatgpt_parser.image.open_ewf_image", fake_open_ewf):
            source = p.open_image_source(self.e01)
        try:
            self.assertEqual(source.kind, "e01")
            self.assertIn(f"{p.IMAGE_EWF_SEGMENTS}:2", source.warnings)
            self.assertTrue(source.is_dir("Users"))
            self.assertEqual(called, [str(self.e01)])
        finally:
            source.close()
        dd_source = p.open_image_source(self.image)  # DD/RAW 는 기존 경로 그대로
        try:
            self.assertEqual(dd_source.kind, "dd")
        finally:
            dd_source.close()


class RealPytsk3PartitionTest(ImageTestBase):
    """실제 pytsk3 로 synthetic 파티션 표(1 MiB)를 읽는다. 파일시스템 내용은 없다 (NTFS 실제 읽기 테스트 아님)."""

    def partitions(self, builder):
        builder(self.image)
        image = p.pytsk3.Img_Info(str(self.image))
        try:
            partitions, warnings = p.list_image_partitions(image)
        finally:
            image.close()
            del image
            gc.collect()
        return [(pt.index, pt.description, pt.start_sector, pt.sector_count, pt.block_size, pt.byte_offset) for pt in partitions], warnings

    def test_real_mbr(self):
        self.assertEqual(self.partitions(synthetic_mbr_image),
                         ([(2, "NTFS / exFAT (0x07)", 64, 512, 512, 32768), (4, "EFI File System (0xef)", 600, 300, 512, 307200)], []))

    def test_real_gpt(self):
        self.assertEqual(self.partitions(synthetic_gpt_image),
                         ([(4, "EFI", 34, 66, 512, 17408), (5, "Basic data", 100, 1801, 512, 51200)], []))

    def test_real_image_without_ntfs_rejected_read_only(self):
        synthetic_mbr_image(self.image)
        before = self.image_state()
        with self.assertRaisesRegex(p.ImageOpenError, "no NTFS filesystem found in image \\(2 partition"):
            p.open_image_source(self.image)
        garbage = self.base / "garbage.raw"
        garbage.write_bytes(bytes(range(256)) * 256)
        with self.assertRaisesRegex(p.ImageOpenError, "1 partition candidate"):  # 파티션 표 없음 → offset 0 시도 → 실패
            p.open_image_source(garbage)
        code, stdout, stderr = run_main(["--image", self.image, "--out", self.base / "output" / "none.json"])
        self.assertEqual(code, p.EXIT_USAGE)
        self.assertIn("invalid --image: no NTFS filesystem", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertFalse((self.base / "output" / "none.json").exists())
        gc.collect()
        self.assertEqual(self.image_state(), before)
        self.image.unlink()  # 핸들이 풀렸는지 (Windows 는 열린 파일을 지울 수 없다)


# =============================================================================
# Cache Conversation Message Recovery — Blockfile Cache → 대화 API 응답 → RecoveredMessage
# =============================================================================
# 테스트가 직접 만든 작은 Blockfile Cache (index + data_1 + data_2 + f_ 파일). 배치는 2026-09-15 실제 사본에서 확인한 형식을 따른다.
# 대화 JSON 의 모양은 실제 응답 구조(mapping·author.role·content_type·소수 초 create_time)를 따르지만 내용·ID 는 synthetic 이다.

CACHE_CONV_ID = "6a86d3ee-0000-4000-8000-00000000c0de"
CACHE_OTHER_ID = "6a86d3ee-0000-4000-8000-00000000c0df"  # 한 글자 다른 ID
CACHE_KEY_PREFIX = "1/0/_dk_https://chatgpt.com https://chatgpt.com "
CACHE_CREATE_RAW = 1787221032.403678
CACHE_CREATE_UTC = "2026-08-20T10:17:12.403678Z"
CACHE_CREATE_KST = "2026-08-20T19:17:12.403678+09:00"
SECRET_CACHE_VALUES = ("SECRETCOOKIEVALUE", "SECRETBEARERTOKEN", "user-SECRETOWNER", "req-SECRETREQUEST")


def cache_addr(file_type, file_number, start, blocks=1):
    return 0x80000000 | (file_type << 28) | ((blocks - 1) << 24) | (file_number << 16) | start


def http_info(encoding="br"):
    lines = [b"HTTP/1.1 200", b"content-type: application/json"]
    if encoding:
        lines.append(f"content-encoding: {encoding}".encode())
    lines += [b"set-cookie: __Secure-next-auth.session-token=SECRETCOOKIEVALUE", b"authorization: Bearer SECRETBEARERTOKEN"]
    return b"\x28\x00\x00\x00" + b"\x00" * 12 + b"\x00".join(lines) + b"\x00\x00" + b"\x01" * 16


def build_blockfile_cache(directory, entries, *, table_len=64, index_magic=0xC103CAC3):
    """entries: [{"url", "body", "info"?, "slot"?}]. 응답 정보는 data_2 (1 KB block), 본문은 f_ external 파일, entry 는 data_1."""
    directory.mkdir(parents=True, exist_ok=True)
    block_header = struct.pack("<I", 0xC104CAC3).ljust(8192, b"\x00")
    data1, data2, table = bytearray(block_header), bytearray(block_header), [0] * table_len
    for number, entry in enumerate(entries, 1):
        info = entry.get("info", http_info())
        info_blocks = max(1, -(-len(info) // 1024))
        info_addr = cache_addr(3, 2, (len(data2) - 8192) // 1024, info_blocks)
        data2 += info.ljust(info_blocks * 1024, b"\x00")
        (directory / f"f_{number:06x}").write_bytes(entry["body"])
        key = (CACHE_KEY_PREFIX + entry["url"]).encode("latin-1")
        slot = entry.get("slot", number - 1)
        store = struct.pack("<IIIiiiQiI", 0, table[slot], 0, 0, 0, 0, 13432490000000000, len(key), 0)  # next = 같은 slot 의 기존 entry
        store += struct.pack("<4i", len(info), len(entry["body"]), 0, 0) + struct.pack("<4I", info_addr, 0x80000000 | number, 0, 0)
        if not entry.get("unindexed"):  # unindexed: data_1 에는 있지만 index hash table 에서 도달할 수 없는 entry
            table[slot] = cache_addr(2, 1, (len(data1) - 8192) // 256)
        data1 += (store.ljust(96, b"\x00") + key).ljust(256, b"\x00")
    header = struct.pack("<IIiiiiIi", index_magic, 0x30000, len(entries), 0, 0, 0, 0, table_len).ljust(368, b"\x00")
    (directory / "index").write_bytes(header + struct.pack(f"<{table_len}I", *table))
    (directory / "data_1").write_bytes(data1)
    (directory / "data_2").write_bytes(data2)


def cache_message(message_id, role, content, create_time, *, name=None, message_type=None, attachments=None):
    return {"id": message_id, "author": {"role": role, "name": name, "metadata": {}}, "create_time": create_time,
            "update_time": create_time, "content": content, "status": "finished_successfully", "end_turn": None, "weight": 1.0,
            "metadata": {"message_type": message_type, "request_id": "req-SECRETREQUEST", "attachments": attachments},
            "recipient": "all", "channel": None}


def cache_conversation(conversation_id=CACHE_CONV_ID, nodes=None):
    if nodes is None:  # user → (assistant → code → execution_output → multimodal) + assistant variant 분기
        nodes = [
            ("root", None, ["m-user"], None),
            ("m-user", "root", ["m-assistant", "m-variant"],
             cache_message("m-user", "user", {"content_type": "text", "parts": ["캐시 합성 질문"]}, CACHE_CREATE_RAW)),
            ("m-assistant", "m-user", ["m-code"],
             cache_message("m-assistant", "assistant", {"content_type": "text", "parts": [LONG_KOREAN_TEXT]}, 1787221040.5,
                           message_type="next")),
            ("m-code", "m-assistant", ["m-output"],
             cache_message("m-code", "assistant", {"content_type": "code", "language": "python", "text": "print(1)",
                                                   "response_format_name": None}, 1787221041)),
            ("m-output", "m-code", ["m-image"],
             cache_message("m-output", "tool", {"content_type": "execution_output", "text": "1"}, 1787221042.25, name="python")),
            ("m-image", "m-output", [],
             cache_message("m-image", "tool", {"content_type": "multimodal_text", "parts": [
                 {"asset_pointer": "file-service://file-synthetic", "content_type": "image_asset_pointer"}, "그림 설명"]},
                 1787221043.125, name="python")),
            ("m-variant", "m-user", [],
             cache_message("m-variant", "assistant", {"content_type": "text", "parts": ["다시 생성한 합성 답변"]}, 1787221050.0,
                           message_type="variant")),
        ]
    mapping = {node_id: {"id": node_id, "message": message, "parent": parent, "children": children}
               for node_id, parent, children, message in nodes}
    return {"conversation_id": conversation_id, "title": "합성 캐시 대화", "create_time": CACHE_CREATE_RAW, "update_time": 1787221050.0,
            "current_node": "m-image", "mapping": mapping, "owner": "user-SECRETOWNER", "moderation_results": []}


def br_json(obj):
    return p.brotli.compress(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


class UnixSecondsDecimalTest(unittest.TestCase):
    def test_decimal_seconds_without_float_math(self):
        result = p.normalize_timestamp("1787221032.403678", "unix_s_decimal", "src")
        self.assertEqual((result["timestamp_raw"], result["timestamp_utc"], result["timestamp_kst"], result["timestamp_type"],
                          result["warnings"]), ("1787221032.403678", CACHE_CREATE_UTC, CACHE_CREATE_KST, "unix_s_decimal", []))
        self.assertEqual(p.normalize_timestamp("1787221032.4036789", "unix_s_decimal")["timestamp_utc"], CACHE_CREATE_UTC)  # µs 미만 버림
        self.assertEqual(p.normalize_timestamp("1787221032.4036789", "unix_s_decimal")["timestamp_raw"], "1787221032.4036789")
        self.assertEqual(p.normalize_timestamp("1787221032", "unix_s_decimal")["timestamp_utc"], "2026-08-20T10:17:12Z")
        for bad in ("1.2e3", "0x10", "abc", "1.", ".5", "1.0123456789", 1787221032.403678):
            with self.subTest(raw=bad):
                failed = p.normalize_timestamp(bad, "unix_s_decimal")
                self.assertEqual((failed["timestamp_utc"], failed["timestamp_type"], failed["warnings"]),
                                 (None, "unix_s_decimal", [p.TS_INVALID_NUMBER]))
        self.assertEqual(p.normalize_timestamp("-1.5", "unix_s_decimal")["warnings"], [p.TS_OUT_OF_RANGE])
        self.assertEqual(p.normalize_timestamp("", "unix_s_decimal")["warnings"], [p.TS_MISSING])
        self.assertEqual(p.normalize_timestamp("12.5", "unix_s")["warnings"], [p.TS_INVALID_NUMBER])  # 기존 unix_s 정책 유지


@unittest.skipIf(p.brotli is None, "brotli not installed")
class CacheTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Chrome"
        self.cache_dir = self.root / "Default" / "Cache" / "Cache_Data"
        (self.root / "Default").mkdir(parents=True)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def conversation_entry(obj=None, conversation_id=CACHE_CONV_ID, **overrides):
        return {"url": f"https://chatgpt.com/backend-api/conversation/{conversation_id}",
                "body": br_json(obj if obj is not None else cache_conversation()), **overrides}

    @staticmethod
    def noise_entries():
        return [
            {"url": f"https://chatgpt.com/backend-api/conversation/{CACHE_CONV_ID}/stream_status", "body": b'{"status":"ok"}',
             "info": http_info(None)},
            {"url": f"https://chatgpt.com/backend-api/conversation/{CACHE_CONV_ID}/textdocs", "body": b"[]", "info": http_info(None)},
            {"url": "https://chatgpt.com/backend-api/conversations?offset=0&limit=28", "body": b"\x0b\x01", "info": http_info("br")},
            {"url": f"https://example.com/backend-api/conversation/{CACHE_CONV_ID}", "body": b"{}", "info": http_info(None)},
        ]

    def read(self):
        return p.read_chrome_cache(self.source, "Default/Cache/Cache_Data")


class ChromeCacheReaderTest(CacheTestBase):
    def test_conversation_response_record(self):
        build_blockfile_cache(self.cache_dir, self.noise_entries() + [self.conversation_entry()])
        records, coverage = self.read()
        self.assertEqual((coverage.artifact_type, coverage.status, coverage.record_count, coverage.warnings, coverage.source_path),
                         ("cache", "PARSED", 1, [], "Default/Cache/Cache_Data"))  # stream_status·textdocs·목록·다른 host 제외
        self.assertEqual(coverage.source_sha256, hashlib.sha256((self.cache_dir / "index").read_bytes()).hexdigest())
        record, body = records[0], (self.cache_dir / "f_000005").read_bytes()
        decoded = p.brotli.decompress(body)
        observed = record.observed
        self.assertEqual((observed["http_status"], observed["content_type"], observed["content_encoding"],
                          observed["url_conversation_id"], observed["body_length"], observed["body_sha256"],
                          observed["decoded_length"], observed["decoded_sha256"]),
                         (200, "application/json", "br", CACHE_CONV_ID, len(body), hashlib.sha256(body).hexdigest(),
                          len(decoded), hashlib.sha256(decoded).hexdigest()))
        conversation = observed["conversation"]
        self.assertEqual((conversation["conversation_id"], conversation["title"], conversation["current_node"],
                          len(conversation["mapping"])), (CACHE_CONV_ID, "합성 캐시 대화", "m-image", 7))
        self.assertEqual((record.artifact_type, record.timestamp_type, record.timestamp_source),
                         ("cache", "webkit_us", "Cache.EntryStore.creation_time"))
        text = json.dumps(record.to_dict(), ensure_ascii=False)
        for secret in SECRET_CACHE_VALUES:  # 응답 헤더 (set-cookie 등) · owner · request_id 비출력
            self.assertNotIn(secret, text)
        # Cache Reader 는 판정하지 않는다. 합성 대화의 variant 분기 → CONVERSATION_RETRY, user 메시지 → PROMPT_SEND (CANDIDATE).
        self.assertEqual([e.action for e in p.detect(records)], ["CONVERSATION_RETRY", "PROMPT_SEND"])

    def test_identity_and_unsupported_encoding(self):
        plain = json.dumps(cache_conversation(), ensure_ascii=False).encode("utf-8")
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(body=plain, info=http_info(None)),
                                               self.conversation_entry(conversation_id=CACHE_OTHER_ID, body=b"gz", info=http_info("gzip"))])
        records, coverage = self.read()
        by_id = {r.observed["url_conversation_id"]: r for r in records}
        self.assertEqual(by_id[CACHE_CONV_ID].observed["conversation"]["conversation_id"], CACHE_CONV_ID)
        self.assertEqual((by_id[CACHE_OTHER_ID].warnings, "conversation" in by_id[CACHE_OTHER_ID].observed),
                         ([f"{p.CACHE_CONTENT_ENCODING_NOT_SUPPORTED}:gzip"], False))
        self.assertEqual(coverage.status, "PARTIAL")

    def test_bad_entries_do_not_stop_other_entries(self):
        ids = ["6a86d3ee-0000-4000-8000-0000000000a1", "6a86d3ee-0000-4000-8000-0000000000a2", "6a86d3ee-0000-4000-8000-0000000000a3"]
        build_blockfile_cache(self.cache_dir, [
            self.conversation_entry(conversation_id=ids[0], body=b"this is not brotli data"),
            self.conversation_entry(conversation_id=ids[1], body=p.brotli.compress(b"{not json")),
            self.conversation_entry(conversation_id=ids[2], body=br_json({"conversation_id": ids[2], "title": "mapping 없음"})),
            self.conversation_entry(),
        ])
        records, coverage = self.read()
        warnings = {r.observed["url_conversation_id"]: r.warnings for r in records}
        self.assertEqual(warnings, {ids[0]: [p.CACHE_BROTLI_DECOMPRESSION_FAILED], ids[1]: [p.CACHE_BODY_NOT_JSON],
                                    ids[2]: [p.CACHE_UNEXPECTED_STRUCTURE], CACHE_CONV_ID: []})
        self.assertEqual(coverage.status, "PARTIAL")
        self.assertEqual([c.conversation_id for c in p.extract_cache_conversations(records)], [CACHE_CONV_ID])

    def test_coverage_states(self):
        self.assertEqual(self.read()[1].status, "NOT_PRESENT")
        self.cache_dir.mkdir(parents=True)
        (self.cache_dir / "0123456789abcdef_0").write_bytes(b"simple cache entry")  # index 없음
        coverage = self.read()[1]
        self.assertEqual((coverage.status, coverage.warnings), ("NOT_SUPPORTED", [p.CACHE_FORMAT_NOT_SUPPORTED]))
        build_blockfile_cache(self.cache_dir, [self.conversation_entry()], index_magic=0x12345678)
        self.assertEqual(self.read()[1].status, "NOT_SUPPORTED")
        build_blockfile_cache(self.cache_dir, self.noise_entries())
        records, coverage = self.read()
        self.assertEqual((records, coverage.status, coverage.record_count), ([], "PARSED", 0))  # 분석했으나 대화 응답 없음
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(slot=3), self.conversation_entry(conversation_id=CACHE_OTHER_ID, slot=3)])
        self.assertEqual(sorted(r.observed["url_conversation_id"] for r in self.read()[0]), sorted([CACHE_CONV_ID, CACHE_OTHER_ID]))  # 같은 slot 체인
        (self.cache_dir / "f_000001").unlink()
        records, coverage = self.read()
        self.assertEqual((coverage.status, sorted(w for r in records for w in r.warnings)), ("PARTIAL", [p.CACHE_BODY_UNREADABLE]))
        with mock.patch("chatgpt_parser.artifacts.cache.brotli", None):
            self.assertIn(p.CACHE_BROTLI_NOT_AVAILABLE, [w for r in self.read()[0] for w in r.warnings])

    def test_source_tree_unchanged(self):
        build_blockfile_cache(self.cache_dir, self.noise_entries() + [self.conversation_entry()])
        create_history_db(self.root / "Default" / "History")
        before = tree_snapshot(self.root)
        self.read()
        p.run(self.source, "Default/History")
        self.assertEqual(run_main(["--dir", self.root, "--history", "Default/History", "--out", self.base / "out.json"])[0], p.EXIT_OK)
        self.assertEqual(tree_snapshot(self.root), before)


class CacheBlockfileCarvingTest(CacheTestBase):
    """index 에서 도달할 수 없는 EntryStore 를 data_* 전체 탐색으로 복구한다 (2026-09-20). index 열거는 그대로 primary."""

    def append_blocks(self, payload):
        path = self.cache_dir / "data_1"
        path.write_bytes(path.read_bytes() + payload.ljust(-(-len(payload) // 256) * 256, b"\x00"))

    def test_indexed_entry_is_not_duplicated_by_carving(self):
        build_blockfile_cache(self.cache_dir, self.noise_entries() + [self.conversation_entry()])
        records, coverage = self.read()
        self.assertEqual((len(records), coverage.record_count, coverage.status, coverage.warnings), (1, 1, "PARSED", []))
        self.assertEqual(records[0].observed["entry_origin"], "index")
        self.assertNotIn("carved=", records[0].record_location)

    def test_unindexed_entry_is_carved(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(unindexed=True)])
        records, coverage = self.read()
        self.assertEqual((len(records), coverage.warnings), (1, [f"{p.CACHE_BLOCKFILE_CARVED_ENTRY}:1"]))
        record = records[0]
        self.assertEqual((record.observed["entry_origin"], record.observed["content_encoding"]), ("carved", "br"))
        self.assertIn("carved=data_1@offset=", record.record_location)  # provenance: data 파일 + EntryStore offset
        self.assertEqual((record.artifact_type, record.observed["conversation"]["conversation_id"]), ("cache", CACHE_CONV_ID))

    def test_carving_recovers_entry_without_any_marker_string(self):
        entry = self.conversation_entry(cache_conversation(conversation_id=CACHE_OTHER_ID), conversation_id=CACHE_OTHER_ID)
        build_blockfile_cache(self.cache_dir, [dict(entry, unindexed=True)])
        records, _ = self.read()
        self.assertEqual([r.observed["url_conversation_id"] for r in records], [CACHE_OTHER_ID])

    def test_invalid_entry_like_bytes_are_ignored(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry()])
        self.append_blocks(b"\xff" * 256)  # state·key_len 범위 밖
        self.append_blocks(struct.pack("<20xiQiI", 0, 13432490000000000, 40, 0).ljust(96, b"\x00") + b"\x00" * 40)  # key 가 URL 이 아님
        records, coverage = self.read()
        self.assertEqual((len(records), coverage.warnings), (1, []))

    def test_truncated_candidate_does_not_crash(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(unindexed=True)])
        path = self.cache_dir / "data_1"
        path.write_bytes(path.read_bytes()[:-160] + b"\x01" * 40)  # key 가 잘린 마지막 block + block 경계 미만 잔여
        records, coverage = self.read()
        self.assertEqual((records, coverage.warnings), ([], []))

    def test_non_chatgpt_carved_entry_is_not_recovered(self):
        build_blockfile_cache(self.cache_dir, [{"url": f"https://example.com/backend-api/conversation/{CACHE_CONV_ID}",
                                                "body": b"{}", "info": http_info(None), "unindexed": True}])
        records, coverage = self.read()
        self.assertEqual((records, coverage.warnings), ([], [f"{p.CACHE_BLOCKFILE_CARVED_ENTRY}:1"]))

    def test_carved_entry_with_invalid_json_makes_no_conversation(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(body=b"not json", info=http_info(None), unindexed=True)])
        records, coverage = self.read()
        self.assertEqual((len(records), coverage.status), (1, "PARTIAL"))
        self.assertIn(p.CACHE_BODY_NOT_JSON, records[0].warnings)
        self.assertNotIn("conversation", records[0].observed)


class CacheConversationExtractionTest(CacheTestBase):
    def setUp(self):
        super().setUp()
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, f"https://chatgpt.com/c/{CACHE_CONV_ID}", "대화"), (2, f"https://chatgpt.com/c/{CACHE_OTHER_ID}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0), (2, 2, 13432490001000000, 0, 0x30000000, "", 0)])

    def run_with(self, *entries):
        build_blockfile_cache(self.cache_dir, list(entries))
        return p.run(self.source, "Default/History")

    def test_messages_from_conversation_tree(self):
        result = self.run_with(*self.noise_entries(), self.conversation_entry())
        self.assertEqual(len(result.conversations), 1)
        conversation = result.conversations[0]
        self.assertEqual((conversation.conversation_id, conversation.title, conversation.recovery_status),
                         (CACHE_CONV_ID, "합성 캐시 대화", "PARTIAL"))  # 이미지 part 가 있는 메시지 → PARTIAL
        self.assertEqual((conversation.create_time_raw, conversation.create_time_utc, conversation.create_time_kst,
                          conversation.create_time_type), (repr(CACHE_CREATE_RAW), CACHE_CREATE_UTC, CACHE_CREATE_KST, "unix_s_decimal"))
        self.assertEqual(conversation.warnings, [f"{p.CONVERSATION_BRANCHES}:1"])
        self.assertEqual(conversation.correlated_record_ids, ["history:Default/History#visits.id=1"])  # 한 글자 다른 visit 2 는 연결 안 함
        messages = conversation.messages
        self.assertEqual([(m.sequence_index, m.message_id, m.parent_message_id, m.role, m.content_type, m.recovery_status)
                          for m in messages],
                         [(0, "m-user", None, "user", "text", "RECOVERED"),
                          (1, "m-assistant", "m-user", "assistant", "text", "RECOVERED"),
                          (2, "m-code", "m-assistant", "assistant", "code", "RECOVERED"),
                          (3, "m-output", "m-code", "tool", "execution_output", "RECOVERED"),
                          (4, "m-image", "m-output", "tool", "multimodal_text", "PARTIAL"),
                          (5, "m-variant", "m-user", "assistant", "text", "RECOVERED")])  # 분기: 같은 parent m-user
        self.assertEqual(messages[1].content, LONG_KOREAN_TEXT)  # 긴 한글 본문 전체
        self.assertEqual([m.content for m in messages], ["캐시 합성 질문", LONG_KOREAN_TEXT, "print(1)", "1", "그림 설명", "다시 생성한 합성 답변"])
        self.assertEqual(messages[4].warnings, [f"{p.MESSAGE_NON_TEXT_PARTS}:1"])
        self.assertEqual((messages[0].timestamp_raw, messages[0].timestamp_utc, messages[0].timestamp_kst, messages[0].timestamp_type,
                          messages[0].timestamp_source),
                         (repr(CACHE_CREATE_RAW), CACHE_CREATE_UTC, CACHE_CREATE_KST, "unix_s_decimal", p._CACHE_MESSAGE_TIME_SOURCE))
        self.assertEqual((messages[1].timestamp_utc, messages[2].timestamp_type, messages[2].timestamp_utc),
                         ("2026-08-20T10:17:20.500000Z", "unix_s", "2026-08-20T10:17:21Z"))
        self.assertTrue(all(m.conversation_id == CACHE_CONV_ID and m.source_artifact == "cache"
                            and m.source_path == "Default/Cache/Cache_Data" for m in messages))
        self.assertTrue(messages[4].record_location.endswith("mapping=m-image"))
        source = conversation.source_artifacts[0]
        self.assertEqual((source["artifact_type"], source["http_status"], source["content_encoding"], source["current_node"],
                          source["url_conversation_id"]), ("cache", 200, "br", "m-image", CACHE_CONV_ID))
        # 합성 대화의 user 메시지 → PROMPT_SEND, variant 분기 → CONVERSATION_RETRY. 기존 History 기준 판정은 그대로다.
        self.assertEqual([e.action for e in result.events],
                         ["PROMPT_SEND", "CONVERSATION_RETRY", "CONVERSATION_ACCESS", "CONVERSATION_ACCESS"])
        text = result.to_json()
        for secret in SECRET_CACHE_VALUES:
            self.assertNotIn(secret, text)
        self.assertEqual(result.warnings[:2], [p.RUN_WARNING_ANALYSIS_SCOPE, p.RUN_WARNING_MESSAGE_RECOVERY_SCOPE])

    def test_all_text_conversation_recovered(self):
        nodes = [("root", None, ["u"], None),
                 ("u", "root", ["a"], cache_message("u", "user", {"content_type": "text", "parts": ["질문"]}, 1787221032)),
                 ("a", "u", [], cache_message("a", "assistant", {"content_type": "text", "parts": ["답", "이어지는 part"]}, 1787221033))]
        conversation = self.run_with(self.conversation_entry(cache_conversation(nodes=nodes))).conversations[0]
        self.assertEqual((conversation.recovery_status, conversation.warnings), ("RECOVERED", []))
        self.assertEqual((conversation.messages[1].content, conversation.messages[1].recovery_status, conversation.messages[1].warnings),
                         ("답\n이어지는 part", "RECOVERED", [p.MESSAGE_PARTS_JOINED]))

    def test_unsupported_content_and_extra_fields_are_partial(self):
        nodes = [("root", None, ["u", "t"], None),
                 ("u", "root", [], cache_message("u", "user", {"content_type": "future_widget", "payload": {}}, None)),
                 ("t", "root", [], cache_message("t", "tool", {"content_type": "tether_browsing_display", "result": "결과",
                                                               "summary": "요약", "assets": None}, 1787221033.0))]
        conversation = self.run_with(self.conversation_entry(cache_conversation(nodes=nodes))).conversations[0]
        self.assertEqual((conversation.recovery_status, conversation.warnings), ("PARTIAL", [f"{p.CONVERSATION_BRANCHES}:1"]))
        user, tool = conversation.messages
        self.assertEqual((user.content, user.recovery_status, user.warnings, user.timestamp_raw),
                         (None, "PARTIAL", [f"{p.MESSAGE_CONTENT_TYPE_NOT_SUPPORTED}:future_widget"], None))
        self.assertEqual((tool.content, tool.recovery_status, tool.warnings), ("결과", "PARTIAL", [f"{p.MESSAGE_FIELDS_NOT_IN_CONTENT}:summary"]))

    def test_conversation_id_mismatch_and_exact_correlation(self):
        conversation = self.run_with(self.conversation_entry(cache_conversation(conversation_id=CACHE_OTHER_ID))).conversations[0]
        self.assertEqual((conversation.conversation_id, conversation.warnings[0]), (CACHE_OTHER_ID, p.CACHE_CONVERSATION_ID_MISMATCH))
        self.assertEqual(conversation.source_artifacts[0]["url_conversation_id"], CACHE_CONV_ID)
        self.assertEqual(conversation.correlated_record_ids, ["history:Default/History#visits.id=2"])  # JSON ID 와 정확히 같은 방문만

    def test_duplicate_sources_merged_versions_and_profiles_kept_apart(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry()])
        record = self.read()[0][0]
        copy = dataclasses.replace(record, record_id="cache:PRE/Cache/Cache_Data#entry=0x1", source_path="PRE/Cache/Cache_Data")
        merged = p.extract_cache_conversations([record, copy])
        self.assertEqual(len(merged), 1)
        self.assertEqual([s["source_path"] for s in merged[0].source_artifacts], ["Default/Cache/Cache_Data", "PRE/Cache/Cache_Data"])
        self.assertNotIn(p.CACHE_MULTIPLE_RESPONSE_VERSIONS, merged[0].warnings)
        changed = dataclasses.replace(copy, observed={**copy.observed, "decoded_sha256": "different-body"})
        split = p.extract_cache_conversations([record, changed])
        self.assertEqual(len(split), 2)
        self.assertTrue(all(p.CACHE_MULTIPLE_RESPONSE_VERSIONS in c.warnings for c in split))
        other_profile = dataclasses.replace(copy, browser_profile="Profile 1")
        apart = p.extract_cache_conversations([record, other_profile])
        self.assertEqual((len(apart), [p.CACHE_MULTIPLE_RESPONSE_VERSIONS in c.warnings for c in apart]), (2, [False, False]))

    def test_cli_prints_full_recovered_messages(self):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry()])
        out = self.base / "output" / "cache.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        for line in ("Cache".ljust(11) + ": PARSED (1 ChatGPT records)", "Recovered Message Nodes".ljust(24) + ": 6",
                     "Status".ljust(24) + ": PARTIAL", "Message Recovery".ljust(24) + f": {p.MESSAGE_RECOVERY_STATUS}",
                     "  Status".ljust(18) + ": PARTIAL", "  [user] message #1", "  [assistant] message #2", "  [tool] message #5",
                     "    UTC".ljust(12) + f": {CACHE_CREATE_UTC}", "    KST".ljust(12) + f": {CACHE_CREATE_KST}"):
            self.assertIn(line, stdout)
        self.assertEqual(stdout.count(LONG_KOREAN_TEXT), 1)  # 본문 전체, 절단 없음
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["conversations"][0]["messages"][1]["content"], LONG_KOREAN_TEXT)
        for secret in SECRET_CACHE_VALUES:
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, out.read_text(encoding="utf-8"))


# =============================================================================
# Session Storage → DATA_EXPORT_REQUEST
# =============================================================================
# key·value byte 형식은 2026-09-15 D: E07-01 원자료에서 확인한 형식을 따른다:
#   namespace-<id>-<origin> = ASCII map 번호, map-<번호>-<key> = UTF-16LE 문자열 (prefix byte 없음), DELETE 는 value 없음.
# namespace id·비밀 값은 synthetic 이다.

SS_DIR = "Default/Session Storage"
SS_NAMESPACE = b"11111111_2222_3333_4444_555555555555"
SS_EXPORT_KEY = "chatgpt_export_data_pending_confirm"
EXPORT_MS = "1788249242085"
EXPORT_UTC = "2026-09-01T07:54:02.085000Z"
EXPORT_KST = "2026-09-01T16:54:02.085000+09:00"
SECRET_SESSION_VALUES = ("SYNTHETIC-PRIVATE-KEY-SECRET", "SYNTHETIC-AUTH-SESSION-SECRET")


def ss_namespace(origin, map_id):
    return ("PUT", b"namespace-" + SS_NAMESPACE + b"-" + origin.encode(), str(map_id).encode())


def ss_namespace_delete(origin):
    return ("DELETE", b"namespace-" + SS_NAMESPACE + b"-" + origin.encode())


def ss_put(map_id, name, value):
    return ("PUT", f"map-{map_id}-{name}".encode("latin-1"), value.encode("utf-16-le") if isinstance(value, str) else value)


def ss_delete(map_id, name):
    return ("DELETE", f"map-{map_id}-{name}".encode("latin-1"))


def export_session_log(*, with_delete=True):
    """E07-01 POST 와 같은 흐름: map-2 가 먼저 www.google.com 에 쓰였다가 정리된 뒤 chatgpt.com 에 다시 쓰이고, 확인 대기 키 PUT → DELETE."""
    batches = [
        ldb_batch(5, ss_namespace("https://www.google.com/", 2), ss_put(2, "_c;;i", "google"),
                  ss_put(2, SS_EXPORT_KEY, "1111111111111")),  # 다른 origin 의 같은 이름 → 제외
        ldb_batch(8, ss_namespace_delete("https://www.google.com/"), ss_delete(2, "_c;;i")),
        ldb_batch(20, ss_namespace("https://accounts.google.com/", 0), ss_put(0, "sessionPrivateKey", SECRET_SESSION_VALUES[0])),
        ldb_batch(30, ss_namespace("https://chatgpt.com/", 2), ss_put(2, SS_EXPORT_KEY, EXPORT_MS),
                  ss_namespace("https://auth.openai.com/", 3), ss_put(3, "authapi:client_auth_session_id", SECRET_SESSION_VALUES[1])),
    ]
    if with_delete:
        batches.append(ldb_batch(40, ss_namespace("https://chatgpt.com/", 2), ss_delete(2, SS_EXPORT_KEY),
                                 ss_put(2, "react-router-scroll-positions", "{}")))
    return ldb_log(*batches)


class SessionStorageTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Chrome"
        self.ss_dir = self.root / "Default" / "Session Storage"
        self.ss_dir.mkdir(parents=True)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, data, name="000003.log"):
        (self.ss_dir / name).write_bytes(data)

    def read(self):
        return p.read_session_storage(self.source, SS_DIR)


class SessionStorageReaderTest(SessionStorageTestBase):
    def test_export_key_put_and_delete_records(self):
        self.write(export_session_log())
        records, coverages = self.read()
        self.assertEqual([(c.artifact_type, c.source_path, c.status, c.record_count, c.warnings) for c in coverages],
                         [("session_storage", f"{SS_DIR}/000003.log", "PARSED", 2,
                           [f"{p.SESSION_STORAGE_NON_ALLOWLISTED_OPERATIONS}:1"])])  # chatgpt.com 의 react-router-scroll-positions 만 셈
        put, delete = records
        self.assertEqual((put.observed["storage_origin"], put.observed["key"], put.observed["key_kind"], put.observed["operation"],
                          put.observed["sequence"], put.observed["map_id"], put.observed["value"], put.observed["value_encoding"]),
                         ("https://chatgpt.com/", SS_EXPORT_KEY, "data_export_pending_confirm", "PUT", 31, "2", EXPORT_MS, "utf-16-le"))
        self.assertEqual((put.timestamp_raw, put.timestamp_utc, put.timestamp_kst, put.timestamp_type, put.timestamp_source),
                         (EXPORT_MS, EXPORT_UTC, EXPORT_KST, "unix_ms", p._SESSION_EXPORT_TIME_SOURCE))
        self.assertEqual((delete.observed["operation"], delete.observed["sequence"], delete.observed["value"], delete.timestamp_raw),
                         ("DELETE", 41, None, None))  # DELETE 에 시각을 만들지 않음
        self.assertEqual(put.record_location, f"offset={put.observed['log_record_offset']} block=0 sequence=31 operation=1")
        self.assertEqual(put.observed["namespace_id_sha256_prefix"], hashlib.sha256(SS_NAMESPACE).hexdigest()[:16])
        text = json.dumps([r.to_dict() for r in records] + [c.to_dict() for c in coverages], ensure_ascii=False)
        for secret in SECRET_SESSION_VALUES + (SS_NAMESPACE.decode(), "1111111111111"):
            self.assertNotIn(secret, text)

    def test_malformed_value_and_unresolved_origin(self):
        self.write(ldb_log(
            ldb_batch(1, ss_namespace("https://chatgpt.com/", 2), ss_put(2, SS_EXPORT_KEY, "not-a-time"),
                      ss_put(2, SS_EXPORT_KEY, b"\x31")),  # UTF-16LE 로 읽을 수 없는 홀수 byte
            ldb_batch(5, ss_put(7, SS_EXPORT_KEY, EXPORT_MS)),  # namespace 가 없는 map 번호
        ))
        records, coverages = self.read()
        self.assertEqual([r.warnings for r in records], [[p.TS_INVALID_NUMBER], [p.SESSION_STORAGE_UNSUPPORTED_ENCODING]])
        self.assertEqual((records[0].timestamp_raw, records[0].timestamp_utc, records[0].timestamp_type), ("not-a-time", None, "unix_ms"))
        self.assertEqual((records[1].observed["value"], records[1].timestamp_raw), (None, None))
        self.assertEqual(coverages[0].status, "PARTIAL")
        self.assertIn(f"{p.SESSION_STORAGE_ORIGIN_UNRESOLVED}:1", coverages[0].warnings)

    def test_folder_coverage_and_failure_isolation(self):
        self.assertEqual([(c.source_path, c.status, c.warnings) for c in self.read()[1]],
                         [(SS_DIR, "NOT_PRESENT", [p.SESSION_STORAGE_LOG_NOT_PRESENT])])
        self.assertEqual([c.status for c in p.read_session_storage(self.source, "Profile 9/Session Storage")[1]], ["NOT_PRESENT"])
        self.write(ldb_physical(4, b"orphan"), name="000001.log")  # 손상 .log
        self.write(export_session_log())
        (self.ss_dir / "000004.ldb").write_bytes(b"sstable bytes")
        records, coverages = self.read()
        self.assertEqual([(c.source_path.rpartition("/")[2], c.status) for c in coverages],
                         [("000001.log", "PARTIAL"), ("000003.log", "PARSED"), ("000004.ldb", "NOT_SUPPORTED")])
        self.assertEqual(coverages[2].warnings, [p.SESSION_STORAGE_LDB_NOT_SUPPORTED])
        self.assertEqual(len(records), 2)  # 손상 파일이 있어도 다른 .log 는 계속

    def test_source_tree_unchanged(self):
        self.write(export_session_log())
        create_history_db(self.root / "Default" / "History")
        before = tree_snapshot(self.root)
        self.read()
        p.run(self.source, "Default/History")
        self.assertEqual(run_main(["--dir", self.root, "--history", "Default/History", "--out", self.base / "out.json"])[0], p.EXIT_OK)
        self.assertEqual(tree_snapshot(self.root), before)


class DataExportRequestRuleTest(SessionStorageTestBase):
    def test_event_from_put_with_later_delete(self):
        self.write(export_session_log())
        records, coverages = self.read()
        events = p.detect(records, coverages)
        self.assertEqual([(e.action, e.action_status, e.confidence, e.rule_id, e.rule_verification, e.finding_type) for e in events],
                         [("DATA_EXPORT_REQUEST", "DETECTED", "MEDIUM", "CHATGPT_DATA_EXPORT_REQUEST_001", "PARTIALLY_VERIFIED", "USER_ACTION")])
        event = events[0]
        self.assertEqual((event.timestamp_raw, event.timestamp_utc, event.timestamp_kst, event.timestamp_type, event.device_attribution),
                         (EXPORT_MS, EXPORT_UTC, EXPORT_KST, "unix_ms", "UNKNOWN"))
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "DIRECT_KEY", "EMBEDDED_TIMESTAMP", "SUPPORTING_CORRELATED", "TIMESTAMP_EXPLAINED"])
        self.assertEqual([(e.evidence_level, e.observed["operation"]) for e in event.primary_evidence + event.supporting_evidence],
                         [("DIRECT", "PUT"), ("SUPPORTING", "DELETE")])
        self.assertEqual(event.representative_evidence_id, event.primary_evidence[0].evidence_id)
        self.assertEqual(event.primary_evidence[0].source_sha256, coverages[0].source_sha256)
        self.assertTrue(any("Export 완료" in note for note in event.limitations))
        self.assertTrue(any("Negative Control" in note for note in event.limitations))
        self.assertTrue(any("sequence 41" in note for note in event.limitations))
        self.assertIsNotNone(event.inference)
        self.assertFalse(any(e.action in ("DATA_EXPORT_CONFIRMATION", "DATA_EXPORT_COMPLETION") for e in events))  # 완료 오탐 없음

    def test_pre_without_key_and_post_without_delete(self):
        self.write(ldb_log(ldb_batch(1, ss_namespace("https://chatgpt.com/", 2), ss_put(2, "_sli", "x"))))  # PRE 처럼 키 없음
        records, coverages = self.read()
        self.assertEqual((records, p.detect(records, coverages)), ([], []))
        self.write(export_session_log(with_delete=False))
        records, coverages = self.read()
        event = p.detect(records, coverages)[0]
        self.assertEqual((event.supporting_evidence, "SUPPORTING_CORRELATED" in event.confidence_reason), ([], False))
        self.assertTrue(any("DELETE 가 없음" in note for note in event.limitations))

    def test_invalid_timestamp_is_candidate_and_duplicates_collapse(self):
        self.write(ldb_log(ldb_batch(1, ss_namespace("https://chatgpt.com/", 2), ss_put(2, SS_EXPORT_KEY, "not-a-time"))))
        records, coverages = self.read()
        events = p.detect(records + records, coverages)  # 같은 Record 중복 입력
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual((event.action_status, event.confidence, event.timestamp_raw, event.timestamp_utc),
                         ("CANDIDATE", "LOW", "not-a-time", None))
        self.assertIn("TIMESTAMP_MISSING", event.confidence_reason)
        self.assertEqual(event.warnings, [p.TS_INVALID_NUMBER])

    def test_cli_pipeline_with_history(self):
        create_history_db(self.root / "Default" / "History")
        self.write(export_session_log())
        out = self.base / "output" / "export.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertIn("Session Storage: 000003.log PARSED (2 ChatGPT records) [warnings: 1]", stdout)
        self.assertRegex(stdout, rf"(?m)^{re.escape(EXPORT_UTC)}\s+{re.escape(EXPORT_KST)}\s+DATA_EXPORT_REQUEST\s+DETECTED\s+MEDIUM$")
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data), PARSE_RESULT_KEYS)
        self.assertEqual(sorted(e["action"] for e in data["events"]), ["DATA_EXPORT_REQUEST", "LOGIN", "LOGOUT"])
        for secret in SECRET_SESSION_VALUES:
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, out.read_text(encoding="utf-8"))


# imagegen_progress 구조는 2026-09-18 실제 마커 DD 의 Session Storage .log 에서 확인한 형식을 따른다:
#   imagegen_progress:<uuid> PUT 이 진행률만 바뀌며 여러 번, 그 뒤 같은 key DELETE. uuid·대화 id 는 synthetic 이다.
IMAGEGEN_UUID = "4649d650-2b37-4178-981c-781c18584de3"
IMAGEGEN_KEY = f"imagegen_progress:{IMAGEGEN_UUID}"
IMAGEGEN_MS = 1789403298265
IMAGEGEN_UTC = "2026-09-14T16:28:18.265000Z"
IMAGEGEN_KST = "2026-09-15T01:28:18.265000+09:00"


def imagegen_value(percent, started_at_ms=IMAGEGEN_MS):
    return json.dumps({"startedAtMs": started_at_ms, "estimatedDurationMs": 40397, "lastDisplayedPercent": percent},
                      separators=(",", ":"))


def imagegen_session_log(*, with_delete=True, percents=(40, 50, 61, 74)):
    """실제 DD 와 같은 흐름: chatgpt.com map 에 진행률 PUT 이 이어지고, 완료 후 같은 key DELETE."""
    batches = [ldb_batch(10, ss_namespace("https://chatgpt.com/", 1),
                         ss_put(1, f"image_gen_checkpoint_dedupe:{IMAGEGEN_UUID}:STAGE", "1"))]  # 허용 목록 아님 → 개수만
    for index, percent in enumerate(percents):
        batches.append(ldb_batch(20 + index * 2, ss_put(1, IMAGEGEN_KEY, imagegen_value(percent))))
    if with_delete:
        batches.append(ldb_batch(20 + len(percents) * 2, ss_delete(1, IMAGEGEN_KEY)))
    return ldb_log(*batches)


class ImageGenerationRequestRuleTest(SessionStorageTestBase):
    def test_reader_keeps_only_observed_fields(self):
        self.write(imagegen_session_log())
        records, coverages = self.read()
        self.assertEqual([(r.observed["operation"], r.observed["key_kind"], r.observed["key_suffix"],
                           r.observed["last_displayed_percent"]) for r in records],
                         [("PUT", "imagegen_progress", IMAGEGEN_UUID, percent) for percent in (40, 50, 61, 74)]
                         + [("DELETE", "imagegen_progress", IMAGEGEN_UUID, None)])
        first = records[0]
        self.assertEqual((first.observed["key"], first.observed["started_at_ms"], first.observed["estimated_duration_ms"]),
                         (IMAGEGEN_KEY, IMAGEGEN_MS, 40397))
        self.assertEqual((first.timestamp_raw, first.timestamp_utc, first.timestamp_kst, first.timestamp_type,
                          first.timestamp_source),
                         (str(IMAGEGEN_MS), IMAGEGEN_UTC, IMAGEGEN_KST, "unix_ms", p._SESSION_IMAGEGEN_TIME_SOURCE))
        self.assertEqual((records[-1].observed["started_at_ms"], records[-1].timestamp_raw), (None, None))
        self.assertIn(f"{p.SESSION_STORAGE_NON_ALLOWLISTED_OPERATIONS}:1", coverages[0].warnings)  # checkpoint 키는 Record 아님

    def test_progress_updates_collapse_into_one_event(self):
        self.write(imagegen_session_log())
        records, coverages = self.read()
        events = p.detect(records + records, coverages)  # 같은 Record 중복 입력
        self.assertEqual([(e.action, e.action_status, e.confidence, e.rule_id, e.rule_verification) for e in events],
                         [("IMAGE_GENERATION_REQUEST", "DETECTED", "MEDIUM", "CHATGPT_IMAGE_GENERATION_REQUEST_001",
                           "PARTIALLY_VERIFIED")])
        event = events[0]
        self.assertEqual((event.timestamp_utc, event.timestamp_kst, event.timestamp_source, event.device_attribution),
                         (IMAGEGEN_UTC, IMAGEGEN_KST, p._SESSION_IMAGEGEN_TIME_SOURCE, "UNKNOWN"))
        self.assertEqual([(e.evidence_level, e.observed["last_displayed_percent"])
                          for e in event.primary_evidence + event.supporting_evidence],
                         [("DIRECT", 40), ("SUPPORTING", 50), ("SUPPORTING", 61), ("SUPPORTING", 74)])
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "DIRECT_KEY", "EMBEDDED_TIMESTAMP", "SUPPORTING_CORRELATED",
                          "TIMESTAMP_EXPLAINED"])
        self.assertTrue(any("생성 성공" in note for note in event.limitations))
        self.assertTrue(any("Negative Control" in note for note in event.limitations))
        self.assertTrue(any("conversation id" in note for note in event.limitations))
        self.assertFalse(any(e.action in ("IMAGE_GENERATION_COMPLETED", "IMAGE_DOWNLOAD") for e in events))  # 완료 판정 없음

    def test_separate_requests_and_broken_value(self):
        self.write(ldb_log(
            ldb_batch(1, ss_namespace("https://chatgpt.com/", 1), ss_put(1, IMAGEGEN_KEY, imagegen_value(10))),
            ldb_batch(5, ss_put(1, IMAGEGEN_KEY, imagegen_value(20, IMAGEGEN_MS + 90_000))),  # 같은 key, 다른 요청
            ldb_batch(9, ss_put(1, f"imagegen_progress:{'a' * 8}", "not json")),
        ))
        records, coverages = self.read()
        self.assertEqual((records[2].observed["started_at_ms"], records[2].warnings),
                         (None, [p.SESSION_STORAGE_VALUE_NOT_JSON]))
        events = p.detect(records, coverages)
        self.assertEqual([e.timestamp_kst for e in events],
                         [IMAGEGEN_KST, "2026-09-15T01:29:48.265000+09:00"])  # startedAtMs 가 다르면 Event 도 별개
        self.assertEqual([e.supporting_evidence for e in events], [[], []])

    def test_invalid_started_at_is_candidate(self):
        self.write(ldb_log(ldb_batch(1, ss_namespace("https://chatgpt.com/", 1),
                                     ss_put(1, IMAGEGEN_KEY, json.dumps({"startedAtMs": "not-a-time"})))))
        records, coverages = self.read()
        event = p.detect(records, coverages)[0]
        self.assertEqual((event.action_status, event.confidence, event.timestamp_raw, event.timestamp_utc),
                         ("CANDIDATE", "LOW", "not-a-time", None))
        self.assertIn("TIMESTAMP_MISSING", event.confidence_reason)
        self.assertTrue(any("변환하지 못해" in note for note in event.limitations))

    def test_other_origin_and_unrelated_keys_make_no_event(self):
        """다른 서비스 origin (Claude·Gemini) 의 같은 이름 키와 chatgpt.com 의 무관한 키 → Record·Event 0건."""
        self.write(ldb_log(
            ldb_batch(1, ss_namespace("https://claude.ai/", 4), ss_put(4, IMAGEGEN_KEY, imagegen_value(30))),
            ldb_batch(5, ss_namespace("https://gemini.google.com/", 5), ss_put(5, IMAGEGEN_KEY, imagegen_value(60))),
            ldb_batch(9, ss_namespace("https://chatgpt.com/", 6), ss_put(6, "react-router-scroll-positions", "{}"),
                      ss_put(6, f"image_gen_checkpoint_dedupe:{IMAGEGEN_UUID}:STAGE", "1")),
        ))
        records, coverages = self.read()
        self.assertEqual((records, p.detect(records, coverages)), ([], []))
        self.assertIn(f"{p.SESSION_STORAGE_NON_ALLOWLISTED_OPERATIONS}:2", coverages[0].warnings)

    def test_marker_like_key_changes_nothing_and_other_rule_unchanged(self):
        """key suffix 가 마커처럼 보여도 판정은 같고, 같은 .log 의 Data Export 판정도 그대로다."""
        def events_for(suffix):
            self.write(ldb_log(
                ldb_batch(1, ss_namespace("https://chatgpt.com/", 2),
                          ss_put(2, f"imagegen_progress:{suffix}", imagegen_value(40)),
                          ss_put(2, SS_EXPORT_KEY, EXPORT_MS)),
                ldb_batch(5, ss_put(2, f"imagegen_progress:{suffix}", imagegen_value(80))),
            ))
            records, coverages = self.read()
            return p.detect(records, coverages)

        plain, marked = events_for(IMAGEGEN_UUID), events_for("MRK_E0601_" + IMAGEGEN_UUID)
        self.assertEqual([(e.action, e.action_status, e.confidence, e.timestamp_kst, len(e.supporting_evidence))
                          for e in plain],
                         [("DATA_EXPORT_REQUEST", "DETECTED", "MEDIUM", EXPORT_KST, 0),
                          ("IMAGE_GENERATION_REQUEST", "DETECTED", "MEDIUM", IMAGEGEN_KST, 1)])
        self.assertEqual([(e.action, e.action_status, e.confidence, e.timestamp_kst, len(e.supporting_evidence))
                          for e in plain],
                         [(e.action, e.action_status, e.confidence, e.timestamp_kst, len(e.supporting_evidence))
                          for e in marked])

    def test_cli_pipeline_with_history(self):
        create_history_db(self.root / "Default" / "History")
        self.write(imagegen_session_log())
        out = self.base / "output" / "imagegen.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertRegex(stdout, rf"(?m)^{re.escape(IMAGEGEN_UTC)}\s+{re.escape(IMAGEGEN_KST)}\s+"
                                 rf"IMAGE_GENERATION_REQUEST\s+DETECTED\s+MEDIUM$")
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(sorted(e["action"] for e in data["events"]), ["IMAGE_GENERATION_REQUEST", "LOGIN", "LOGOUT"])


class HistoryAuthQueryRedactionTest(unittest.TestCase):
    """E07-01 History 인증 흐름 URL 에서 확인된 계정 이메일·인증 세션 id query (값은 synthetic)."""

    def test_login_hint_and_auth_session_id_redacted(self):
        url = ("https://auth.openai.com/api/accounts/authorize?client_id=app_x&login_hint=synthetic.user%40example.com"
               "&auth_session_logging_id=00000000-1111-4222-8333-444444444444&state=SECRETSTATE")
        safe, keys = p.redact_url_query(url)
        self.assertEqual(keys, ["auth_session_logging_id", "login_hint", "state"])
        for secret in ("synthetic.user", "example.com", "00000000-1111-4222-8333-444444444444", "SECRETSTATE"):
            self.assertNotIn(secret, safe)
        self.assertIn("client_id=app_x", safe)  # 인증 값이 아닌 query 는 그대로


# =============================================================================
# Local Storage conversationDrafts → PROMPT_DRAFT
# =============================================================================
# 값 형식은 2026-09-15 C: SNAPSHOT_EXTRACT .log 에서 확인한 형식을 따른다:
#   {"drafts":[{"id","content","doc","timestamp"(Unix ms)}],"userId"} — 비울 때는 {"drafts":[],"userId":null} PUT.
# 초안 내용·ID 는 synthetic 이다.

DRAFT_KEY = "oai/apps/conversationDrafts"
DRAFT_TS = 1788021002000
DRAFT_UTC = "2026-08-29T16:30:02Z"
DRAFT_KST = "2026-08-30T01:30:02+09:00"


def draft_item(draft_id="null_thread", content="합성 초안 질문입니다", timestamp=DRAFT_TS):
    item = {"id": draft_id, "content": content,
            "doc": {"type": "doc", "attrs": {}, "content": [{"type": "paragraph", "attrs": {}, "content": [{"type": "text", "text": content}]}]}}
    if timestamp is not None:
        item["timestamp"] = timestamp
    return item


def draft_put(sequence, *drafts):
    return ldb_batch(sequence, ("PUT", ls_key(DRAFT_KEY), ls_utf16({"drafts": list(drafts), "userId": LS_USER_ID})))


def drafts_cleared(sequence):
    return ldb_batch(sequence, ("PUT", ls_key(DRAFT_KEY), ls_latin1({"drafts": [], "userId": None})))


class PromptDraftRuleTest(LocalStorageTestBase):
    def events(self, *batches):
        records, coverage = self.read(*batches)
        return records, coverage, p.detect_prompt_draft(records, [coverage])

    def test_draft_put_creates_prompt_draft_event_only(self):
        records, coverage, events = self.events(drafts_cleared(1), draft_put(2, draft_item()), drafts_cleared(3))
        self.assertEqual([(e.action, e.action_status, e.confidence, e.rule_id, e.rule_verification, e.device_attribution) for e in events],
                         [("PROMPT_DRAFT", "DETECTED", "MEDIUM", "CHATGPT_PROMPT_DRAFT_001", "PARTIALLY_VERIFIED", "UNKNOWN")])
        event = events[0]
        self.assertEqual((event.timestamp_raw, event.timestamp_utc, event.timestamp_kst, event.timestamp_type),
                         (str(DRAFT_TS), DRAFT_UTC, DRAFT_KST, "unix_ms"))
        self.assertEqual(event.confidence_reason, ["RULE_PARTIALLY_VERIFIED", "DIRECT_VALUE", "EMBEDDED_TIMESTAMP", "TIMESTAMP_EXPLAINED"])
        evidence = event.primary_evidence[0]
        self.assertEqual((evidence.evidence_level, evidence.observed["sequence"], evidence.observed["draft"]["content_length"],
                          evidence.observed["draft"]["draft_id"], evidence.source_sha256),
                         ("DIRECT", 2, len("합성 초안 질문입니다"), "null_thread", coverage.source_sha256))
        self.assertNotIn("drafts", evidence.observed)
        event_text = json.dumps(event.to_dict(), ensure_ascii=False)
        for hidden in ("합성 초안 질문입니다", LS_USER_ID):  # Event 에 원문·계정 id 를 복사하지 않음
            self.assertNotIn(hidden, event_text)
        self.assertTrue(any("전송" in note for note in event.limitations))
        self.assertTrue(any("Negative Control" in note for note in event.limitations))
        self.assertEqual(event.supporting_evidence, [])  # 비워진 PUT 을 전송 근거로 붙이지 않음
        self.assertEqual(records[1].observed["drafts"][0]["content"], "합성 초안 질문입니다")  # 원문은 Record 에 보존

    def test_state_changes_create_events_and_identical_state_merges(self):
        """content 또는 저장 시각이 다르면 다른 Draft 상태, 셋 다 같으면 물리 Record 가 여러 개라도 Event 1건."""
        same_id = RESIDUE_ID
        records, coverage, events = self.events(draft_put(1, draft_item(same_id, "초안", DRAFT_TS)),
                                                draft_put(2, draft_item(same_id, "초안", DRAFT_TS + 14000)),
                                                draft_put(3, draft_item(same_id, "초안 수정", DRAFT_TS + 20000)))
        self.assertEqual([(e.primary_evidence[0].observed["sequence"], len(e.supporting_evidence)) for e in events],
                         [(1, 0), (2, 0), (3, 0)])  # 같은 내용이라도 저장 시각이 다르면 다른 상태
        self.assertEqual([e.timestamp_utc for e in events],
                         ["2026-08-29T16:30:02Z", "2026-08-29T16:30:16Z", "2026-08-29T16:30:22Z"])
        # 같은 상태가 물리 Record 2개로 남은 경우 (같은 draft id·내용·저장 시각)
        records, coverage, events = self.events(draft_put(1, draft_item(same_id, "초안", DRAFT_TS)),
                                                draft_put(2, draft_item(same_id, "초안", DRAFT_TS)))
        self.assertEqual([(e.primary_evidence[0].observed["sequence"], len(e.supporting_evidence)) for e in events], [(1, 1)])
        self.assertIn("SUPPORTING_CORRELATED", events[0].confidence_reason)
        self.assertEqual(len(records), 2)  # 물리 Record 는 둘 다 보존
        self.assertEqual(len(p.detect_prompt_draft(records + records, [coverage])), 1)  # 중복 입력

    def test_same_draft_state_in_log_and_ldb_is_one_event(self):
        """.log 와 .ldb 에 같은 Draft 상태가 남아 있으면 Event 1건 + 물리 Record 2건."""
        if p.cramjam is None:  # pragma: no cover
            self.skipTest("cramjam 미설치")
        self.write_log(draft_put(50, draft_item()))
        value = ls_utf16({"drafts": [draft_item()], "userId": LS_USER_ID})
        (self.leveldb / "000005.ldb").write_bytes(sst_table([([(sst_key(ls_key(DRAFT_KEY), 50), value)], 1)]))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        events = p.detect_prompt_draft(records, coverages)
        self.assertEqual(len(records), 2)  # provenance 는 둘 다 유지
        self.assertEqual(sorted(r.source_path.rpartition("/")[2] for r in records), ["000003.log", "000005.ldb"])
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual((len(event.primary_evidence), len(event.supporting_evidence), event.confidence), (1, 1, "MEDIUM"))
        self.assertEqual(sorted(e.source_path.rpartition("/")[2] for e in event.primary_evidence + event.supporting_evidence),
                         ["000003.log", "000005.ldb"])
        self.assertTrue(all(e.source_sha256 for e in event.primary_evidence + event.supporting_evidence))
        self.assertTrue(any("물리 Record 2건" in note for note in event.limitations))

    def test_ldb_tombstone_and_empty_drafts_create_no_event(self):
        """.ldb 의 DELETE tombstone 과 빈 초안은 Record 로만 남는다."""
        if p.cramjam is None:  # pragma: no cover
            self.skipTest("cramjam 미설치")
        entries = [(sst_key(ls_key(DRAFT_KEY), 60, 0), b""),
                   (sst_key(ls_key(DRAFT_KEY), 61), ls_latin1({"drafts": [], "userId": None}))]
        (self.leveldb / "000005.ldb").write_bytes(sst_table([(entries, 1)]))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(r.observed["operation"], r.observed.get("draft_count")) for r in records],
                         [("DELETE", None), ("PUT", 0)])
        self.assertEqual(p.detect_prompt_draft(records, coverages), [])

    def test_ldb_old_version_without_timestamp_is_candidate(self):
        """.ldb 에만 남은 옛 초안도 시각이 없으면 기존 정책대로 CANDIDATE / LOW."""
        if p.cramjam is None:  # pragma: no cover
            self.skipTest("cramjam 미설치")
        draft = {"id": "null_thread", "content": "시각 없는 옛 초안"}
        value = ls_utf16({"drafts": [draft], "userId": LS_USER_ID})
        (self.leveldb / "000005.ldb").write_bytes(sst_table([([(sst_key(ls_key(DRAFT_KEY), 70), value)], 1)]))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        events = p.detect_prompt_draft(records, coverages)
        self.assertEqual([(e.action_status, e.confidence, e.timestamp_utc, e.timestamp_raw) for e in events],
                         [("CANDIDATE", "LOW", None, None)])
        self.assertIn("TIMESTAMP_MISSING", events[0].confidence_reason)
        self.assertEqual(events[0].primary_evidence[0].observed["table_block_index"], 0)  # 물리 위치는 유지

    def test_empty_malformed_and_unrelated_values_create_no_event(self):
        records, _, events = self.events(
            drafts_cleared(1), draft_put(2, draft_item(content="")),
            ldb_batch(3, ("PUT", ls_key(DRAFT_KEY), ls_latin1("{broken json"))),
            ldb_batch(4, ("PUT", ls_key("oai/apps/otherSetting"), ls_utf16({"drafts": [draft_item()]}))),
            ldb_batch(5, ("DELETE", ls_key(DRAFT_KEY))),
        )
        self.assertEqual(events, [])
        self.assertEqual([r.warnings for r in records if r.observed["sequence"] == 3], [[p.LOCAL_STORAGE_VALUE_NOT_JSON]])

    def test_timestamp_missing_is_candidate_and_multiple_drafts(self):
        _, _, events = self.events(draft_put(1, draft_item("null_thread", "첫 초안", None), draft_item(RESIDUE_ID, "둘째 초안", DRAFT_TS)))
        self.assertEqual([(e.primary_evidence[0].observed["draft"]["draft_index"], e.action_status, e.confidence, e.timestamp_utc)
                          for e in events], [(0, "CANDIDATE", "LOW", None), (1, "DETECTED", "MEDIUM", DRAFT_UTC)])
        self.assertIn("TIMESTAMP_MISSING", events[0].confidence_reason)
        self.assertNotIn("EMBEDDED_TIMESTAMP", events[0].confidence_reason)

    def test_history_correlation_exact_and_separate_from_conversation_create(self):
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, WEB_URL, "ChatGPT"), (2, CONVERSATION_URL, "대화")],
                          visits=[(1, 1, BASE_WEBKIT, 0, 0x30000000, "", 0), (2, 2, BASE_WEBKIT + 3_000_000, 0, 0x30000000, "", 0)])
        self.write_log(draft_put(1, draft_item(SERVER_ID, "서버 대화 초안"), draft_item("null_thread", "새 대화 초안"),
                                 draft_item(SERVER_ID[:-1] + "0", "한 글자 다른 ID 초안")))
        result = p.run(self.source, "Default/History")
        drafts = {e.primary_evidence[0].observed["draft"]["draft_id"]: e for e in result.events if e.action == "PROMPT_DRAFT"}
        self.assertEqual(sorted(e.action for e in result.events), ["CONVERSATION_CREATE", "PROMPT_DRAFT", "PROMPT_DRAFT", "PROMPT_DRAFT"])
        self.assertEqual(drafts[SERVER_ID].primary_evidence[0].observed["history_conversation_record_ids"],
                         ["history:Default/History#visits.id=2"])
        self.assertEqual(drafts["null_thread"].primary_evidence[0].observed["history_conversation_record_ids"], [])
        self.assertEqual(drafts[SERVER_ID[:-1] + "0"].primary_evidence[0].observed["history_conversation_record_ids"], [])
        self.assertFalse(any(e.action in ("PROMPT_SENT", "MESSAGE_SENT") for e in result.events))
        self.assertEqual(result.conversations, [])  # 초안을 대화·메시지로 만들지 않음

    def test_cli_row_and_privacy(self):
        create_history_db(self.root / "Default" / "History")
        self.write_log(ldb_batch(1, ("PUT", ls_key("RESUME_TOKEN_STORE_KEY"), ls_latin1("SECRET-RESUME-TOKEN"))),
                       draft_put(2, draft_item()))
        out = self.base / "output" / "draft.json"
        code, stdout, stderr = run_main(["--dir", self.root, "--history", "Default/History", "--out", out])
        self.assertEqual(code, p.EXIT_OK, stderr)
        self.assertRegex(stdout, rf"(?m)^{re.escape(DRAFT_UTC)}\s+{re.escape(DRAFT_KST)}\s+PROMPT_DRAFT\s+DETECTED\s+MEDIUM$")
        self.assertNotIn("합성 초안 질문입니다", stdout)  # CLI 에 초안 원문을 출력하지 않음
        data = json.loads(out.read_text(encoding="utf-8"))
        for secret in ("SECRET-RESUME-TOKEN", LS_USER_ID):
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, json.dumps(data, ensure_ascii=False))
        self.assertEqual(sum(json.dumps(e, ensure_ascii=False).count("합성 초안 질문입니다") for e in data["events"]), 0)


# =============================================================================
# LevelDB .ldb (SSTable) Reader — synthetic
# =============================================================================
# 실제 .ldb 에서 확인한 형식대로 만든 합성 SSTable 만 쓴다 (실제 Evidence 내용을 복사하지 않는다).


def sst_entry_bytes(entries, restart_interval=2):
    """entry* + restart offset 배열 + restart 개수. restart 지점에서는 공통 접두를 쓰지 않는다."""
    out, restarts, previous = bytearray(), [], b""
    for index, (key, value) in enumerate(entries):
        if index % restart_interval == 0:
            restarts.append(len(out))
            shared = 0
        else:
            shared = 0
            while shared < min(len(previous), len(key)) and previous[shared] == key[shared]:
                shared += 1
        out += ldb_varint(shared) + ldb_varint(len(key) - shared) + ldb_varint(len(value)) + key[shared:] + value
        previous = key
    for restart in restarts:
        out += struct.pack("<I", restart)
    return bytes(out + struct.pack("<I", len(restarts)))


def sst_raw_block(payload, compression=0, crc=None):
    """payload 를 압축하지 않고 block trailer 만 붙인다."""
    checksum = p.leveldb_mask_crc(p.crc32c(payload + bytes([compression]))) if crc is None else crc
    return payload + bytes([compression]) + struct.pack("<I", checksum)


def sst_block(entries, compression=0, crc=None, restart_interval=2):
    payload = sst_entry_bytes(entries, restart_interval)
    if compression == 1:
        payload = bytes(p.cramjam.snappy.compress_raw(payload))
    return sst_raw_block(payload, compression, crc)


def sst_key(user_key, sequence=10, value_type=1):
    """internal key = user key + 8 byte trailer (sequence << 8 | type)."""
    return user_key + struct.pack("<Q", (sequence << 8) | value_type)


def sst_table(blocks, *, magic=None, index_compression=0, meta_entries=()):
    """blocks: (entries, compression) 또는 이미 만든 block bytes. 실제 파일과 같은 배치로 SSTable bytes 를 만든다."""
    body, index_entries = bytearray(), []
    for spec in blocks:
        if isinstance(spec, bytes):
            block, last_key = spec, sst_key(b"\xff")
        else:
            entries, compression = spec
            block, last_key = sst_block(entries, compression), (entries[-1][0] if entries else sst_key(b"\xff"))
        offset = len(body)
        body += block
        index_entries.append((last_key, ldb_varint(offset) + ldb_varint(len(block) - 5)))
    meta_offset, meta_block = len(body), sst_block(list(meta_entries))
    body += meta_block
    index_offset, index_block = len(body), sst_block(index_entries, index_compression)
    body += index_block
    footer = (ldb_varint(meta_offset) + ldb_varint(len(meta_block) - 5)
              + ldb_varint(index_offset) + ldb_varint(len(index_block) - 5))
    footer = footer.ljust(p.LEVELDB_TABLE_FOOTER_SIZE - 8, b"\x00")
    return bytes(body) + footer + struct.pack("<Q", p.LEVELDB_TABLE_MAGIC if magic is None else magic)


CHAT_KEY_A = ls_key("nextauth.message")
CHAT_KEY_B = ls_key("oai/apps/accountSwitchSessions")


class SSTableReaderTest(unittest.TestCase):
    """TC-LDB-01 — footer / block / restart / internal key (실제 형식 기준 synthetic)."""

    def setUp(self):
        if p.cramjam is None:  # pragma: no cover - 설치 환경에 따라 다름
            self.skipTest("cramjam 미설치")

    # 1, 3, 4, 11, 12, 13
    def test_footer_block_handle_and_internal_key(self):
        data = sst_table([([(sst_key(b"a-key", 7), b"v1"), (sst_key(b"b-key", 8, 0), b"")], 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual(warnings, [])
        self.assertEqual([(e.key, e.sequence, e.operation, e.value, e.compression, e.crc32c_verified) for e in entries],
                         [(b"a-key", 7, "PUT", b"v1", "none", True), (b"b-key", 8, "DELETE", None, "none", True)])
        self.assertEqual([(e.block_index, e.entry_index, e.block_offset) for e in entries], [(0, 0, 0), (0, 1, 0)])

    # 2
    def test_bad_magic_and_too_small(self):
        self.assertEqual(p.read_leveldb_table(b"short file"), ([], [p.LEVELDB_TABLE_TOO_SMALL]))
        data = sst_table([([(sst_key(b"k"), b"v")], 0)], magic=0x1234567890ABCDEF)
        self.assertEqual(p.read_leveldb_table(data), ([], [p.LEVELDB_TABLE_BAD_MAGIC]))

    # 5, 17
    def test_snappy_data_block_and_snappy_index_block(self):
        for index_compression in (0, 1):
            data = sst_table([([(sst_key(b"k1", 3), b"value-1"), (sst_key(b"k2", 4), b"value-2")], 1)],
                             index_compression=index_compression)
            entries, warnings = p.read_leveldb_table(data)
            self.assertEqual(warnings, [])
            self.assertEqual([(e.key, e.sequence, e.value, e.compression) for e in entries],
                             [(b"k1", 3, b"value-1", "snappy"), (b"k2", 4, b"value-2", "snappy")])

    # 6, 22
    def test_invalid_snappy_block_does_not_stop_other_blocks(self):
        broken = sst_raw_block(b"\xff\xfe not snappy at all", 1)
        data = sst_table([broken, ([(sst_key(b"ok", 9), b"v")], 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual([(e.key, e.block_index) for e in entries], [(b"ok", 1)])
        self.assertEqual(warnings, [f"{p.LEVELDB_TABLE_SNAPPY_DECOMPRESSION_FAILED}:data_block=0"])

    # 7, 8
    def test_crc_mismatch_keeps_entries_with_flag(self):
        block = sst_block([(sst_key(b"k", 5), b"v")], 0, crc=0xDEADBEEF)
        entries, warnings = p.read_leveldb_table(sst_table([block]))
        self.assertEqual([(e.key, e.crc32c_verified) for e in entries], [(b"k", False)])
        self.assertIn(f"{p.LEVELDB_TABLE_CRC_MISMATCH}:data_block=0", warnings)

    # 9, 10
    def test_restart_array_and_prefix_compression(self):
        keys = [sst_key(b"prefix-key-" + bytes([65 + i]), 20 + i) for i in range(5)]
        data = sst_table([([(key, b"v%d" % i) for i, key in enumerate(keys)], 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual(warnings, [])
        self.assertEqual([e.key for e in entries], [key[:-8] for key in keys])
        self.assertEqual([e.sequence for e in entries], [20, 21, 22, 23, 24])

    # 14
    def test_multiple_versions_of_same_key_are_all_kept(self):
        key = b"_https://chatgpt.com\x00\x01x"
        data = sst_table([([(sst_key(key, 30), b"old"), (sst_key(key, 31, 0), b""), (sst_key(key, 32), b"new")], 0)])
        entries, _ = p.read_leveldb_table(data)
        self.assertEqual([(e.sequence, e.operation, e.value) for e in entries],
                         [(30, "PUT", b"old"), (31, "DELETE", None), (32, "PUT", b"new")])

    # 15
    def test_malformed_entry_length_stops_safely(self):
        payload = bytearray(sst_entry_bytes([(sst_key(b"k1", 1), b"v1"), (sst_key(b"k2", 2), b"v2")]))
        payload[2] = 0x7F  # value 길이를 block 밖으로
        data = sst_table([sst_raw_block(bytes(payload), 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual(entries, [])
        self.assertEqual(warnings, [f"{p.LEVELDB_TABLE_BLOCK_INVALID}:data_block=0:entry=0"])

    # 21
    def test_unsupported_compression_type(self):
        data = sst_table([sst_raw_block(b"whatever", 9), ([(sst_key(b"ok", 2), b"v")], 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual([e.key for e in entries], [b"ok"])
        self.assertEqual(warnings, [f"{p.LEVELDB_TABLE_UNSUPPORTED_COMPRESSION}:data_block=0:9"])

    # 16
    def test_invalid_internal_key_is_skipped(self):
        data = sst_table([([(b"short", b"v"), (sst_key(b"ok", 4), b"v"), (b"badtype" + struct.pack("<Q", (5 << 8) | 7), b"v")], 0)])
        entries, warnings = p.read_leveldb_table(data)
        self.assertEqual([e.key for e in entries], [b"ok"])
        self.assertEqual(warnings, [f"{p.LEVELDB_TABLE_INVALID_INTERNAL_KEY}:data_block=0:entry=0",
                                    f"{p.LEVELDB_TABLE_INVALID_INTERNAL_KEY}:data_block=0:entry=2:type=7"])

    def test_invalid_block_handle_is_reported(self):
        data = bytearray(sst_table([([(sst_key(b"k", 1), b"v")], 0)]))
        data[-p.LEVELDB_TABLE_FOOTER_SIZE + 2] = 0x7F  # index handle offset 을 파일 밖으로
        entries, warnings = p.read_leveldb_table(bytes(data))
        self.assertEqual(entries, [])
        self.assertTrue(any(w.startswith(p.LEVELDB_TABLE_INVALID_HANDLE) for w in warnings), warnings)


class LocalStorageTableTest(LocalStorageTestBase):
    """TC-LDB-02 — .ldb → 기존 Local Storage Decoder → ArtifactRecord → 잔존 대화 / Prompt Draft."""

    def setUp(self):
        super().setUp()
        if p.cramjam is None:  # pragma: no cover
            self.skipTest("cramjam 미설치")

    def write_table(self, *entries, name="000005.ldb", compression=1):
        (self.leveldb / name).write_bytes(sst_table([(list(entries), compression)]))
        return f"{LS_DIR}/{name}"

    # 18, 19
    def test_conversation_history_recovered_from_ldb(self):
        path = self.write_table((sst_key(ls_key(LS_HISTORY_KEY), 113), ls_utf16(history_value(conv_item()))))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(c.source_path, c.status, c.record_count) for c in coverages],
                         [(LS_DIR, "NOT_PRESENT", 0), (path, "PARSED", 1)])
        record = records[0]
        self.assertEqual((record.observed["key"], record.observed["key_kind"], record.observed["operation"],
                          record.observed["sequence"], record.observed["table_block_compression"],
                          record.observed["value_encoding"], record.warnings),
                         ("cache/<user>/<scope>/conversation-history", "conversation_history", "PUT", 113,
                          "snappy", "utf-16-le", []))
        self.assertEqual(record.record_location.split()[-2:], ["sequence=113", "operation=PUT"])
        self.assertEqual([(c.conversation_id, c.recovery_status, c.title) for c in
                          p.extract_conversation_residue(records, coverages)],
                         [(RESIDUE_ID, "RESIDUAL_ONLY", "안녕 인사 응답")])
        self.assertNotIn(LS_USER_ID, self.dumped(record))  # 사용자 식별자는 해시로만

    # 20
    def test_conversation_drafts_recovered_from_ldb(self):
        self.write_table((sst_key(ls_key(DRAFT_KEY), 77),
                          ls_utf16({"drafts": [draft_item()], "userId": LS_USER_ID})))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual(records[0].observed["drafts"][0]["content"], "합성 초안 질문입니다")
        events = p.detect_prompt_draft(records, coverages)
        self.assertEqual([(e.action, e.action_status, e.confidence) for e in events], [("PROMPT_DRAFT", "DETECTED", "MEDIUM")])

    def test_tombstone_and_allowlist(self):
        path = self.write_table(
            (sst_key(ls_key(LS_HISTORY_KEY), 40, 0), b""),                      # tombstone
            (sst_key(ls_key("oai/apps/somethingElse"), 41), ls_latin1("{}")),   # 허용 목록 밖
            (sst_key(ls_key("nextauth.message", origin="https://other.example"), 42), ls_latin1("{}")),
        )
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(r.observed["key_kind"], r.observed["operation"], r.observed["value_length"]) for r in records],
                         [("conversation_history", "DELETE", None)])
        self.assertEqual([c.warnings for c in coverages if c.source_path == path],
                         [[f"{p.LOCAL_STORAGE_NON_ALLOWLISTED_OPERATIONS}:1"]])  # 다른 origin 은 세지 않는다
        self.assertEqual(p.extract_conversation_residue(records, coverages), [])  # DELETE 로 대화를 만들지 않는다

    def test_log_and_ldb_in_one_folder(self):
        self.write_log(put_history(10, conv_item()))
        self.write_table((sst_key(ls_key(LS_HISTORY_KEY), 113), ls_utf16(history_value(conv_item(conv_id=RESIDUE_ID_2)))))
        records, coverages = p.read_local_storage(self.source, LS_DIR)
        self.assertEqual([(c.source_path.rpartition("/")[2], c.status) for c in coverages],
                         [("000003.log", "PARSED"), ("000005.ldb", "PARSED")])
        self.assertEqual(sorted(c.conversation_id for c in p.extract_conversation_residue(records, coverages)),
                         sorted([RESIDUE_ID, RESIDUE_ID_2]))

    def test_non_sstable_file_is_not_supported(self):
        (self.leveldb / "000009.ldb").write_bytes(b"x" * 100)
        coverage = [c for c in p.read_local_storage(self.source, LS_DIR)[1] if c.source_path.endswith("000009.ldb")][0]
        self.assertEqual((coverage.status, coverage.warnings), ("NOT_SUPPORTED", [p.LEVELDB_TABLE_BAD_MAGIC]))

    def test_source_tree_unchanged(self):
        self.write_table((sst_key(ls_key(LS_HISTORY_KEY), 113), ls_utf16(history_value(conv_item()))))
        before = {path.name: (path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                  for path in self.leveldb.iterdir()}
        p.read_local_storage(self.source, LS_DIR)
        after = {path.name: (path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                 for path in self.leveldb.iterdir()}
        self.assertEqual(before, after)


# =============================================================================
# CONVERSATION_REMOVED_FROM_LIST Rule — synthetic
# =============================================================================
# 실제 재실험(E03-02)에서 확인한 전이 형태만 합성한다. 실제 Evidence 내용을 복사하지 않는다.

REMOVED_IDS = [f"6aa59431-0000-4000-8000-{i:012d}" for i in range(15)]
REMOVED_TARGET = REMOVED_IDS[7]
REMOVED_TS_A = 1789231345000  # 값 안의 timestamp (unix ms)
REMOVED_TS_B = REMOVED_TS_A + 14000


def history_items(ids):
    return [conv_item(conv_id=i, title=f"대화 {i[-3:]}") for i in ids]


def history_put(sequence, ids, timestamp=REMOVED_TS_A):
    return ldb_batch(sequence, ("PUT", ls_key(LS_HISTORY_KEY),
                                ls_utf16(history_value(*history_items(ids), timestamp=timestamp))))


class ConversationRemovedFromListTest(LocalStorageTestBase):
    def events(self, *batches, extra_records=()):
        records, coverage = self.read(*batches)
        return records, coverage, p.detect_conversation_removed_from_list(list(records) + list(extra_records), [coverage])

    # 1, 2, 10, 11, 12
    def test_single_removal_creates_candidate_event(self):
        records, coverage, events = self.events(
            history_put(120, REMOVED_IDS, REMOVED_TS_A),
            history_put(146, [i for i in REMOVED_IDS if i != REMOVED_TARGET], REMOVED_TS_B))
        self.assertEqual([(e.action, e.action_status, e.confidence, e.rule_id, e.rule_verification, e.device_attribution)
                          for e in events],
                         [("CONVERSATION_REMOVED_FROM_LIST", "CANDIDATE", "MEDIUM",
                           "CHATGPT_CONVERSATION_REMOVED_FROM_LIST_001", "PARTIALLY_VERIFIED", "UNKNOWN")])
        event = events[0]
        self.assertEqual(event.timestamp_raw, str(REMOVED_TS_B))  # 값 안의 시각 (sequence 아님)
        self.assertEqual([e.evidence_level for e in event.primary_evidence + event.supporting_evidence],
                         ["SUPPORTING", "SUPPORTING"])  # DIRECT 없음
        self.assertNotIn("DIRECT_KEY", event.confidence_reason)
        self.assertNotIn("DIRECT_VALUE", event.confidence_reason)
        self.assertNotIn("DIRECT_URL", event.confidence_reason)
        observed = event.primary_evidence[0].observed
        self.assertEqual((observed["removed_conversation_id"], observed["conversation_count_before"],
                          observed["conversation_count_after"], observed["previous_sequence"], observed["sequence"],
                          observed["other_conversations_unchanged"]),
                         (REMOVED_TARGET, 15, 14, 120, 146, True))
        self.assertNotIn("conversation_items", self.dumped(event))  # 대화 제목 목록은 Evidence 에 넣지 않는다
        self.assertTrue(any("Archive" in note for note in event.limitations))
        self.assertTrue(any("삭제 행위를 직접 나타내지 않는다" in note for note in event.limitations))
        self.assertTrue(any("Negative Control" in note for note in event.limitations))
        # 제거된 대화도 복구 결과에는 그대로 남는다
        conversations = p.extract_conversation_residue(records, [coverage])
        self.assertIn(REMOVED_TARGET, [c.conversation_id for c in conversations])

    # 3, 4, 5
    def test_multiple_or_mixed_changes_create_no_event(self):
        rest = [i for i in REMOVED_IDS if i not in (REMOVED_IDS[1], REMOVED_IDS[2])]
        self.assertEqual(self.events(history_put(10, REMOVED_IDS), history_put(20, rest))[2], [])  # 2건 제거
        self.tearDown(); self.setUp()
        swapped = [i for i in REMOVED_IDS if i != REMOVED_TARGET] + ["6aa59431-0000-4000-8000-999999999999"]
        self.assertEqual(self.events(history_put(10, REMOVED_IDS), history_put(20, swapped))[2], [])  # 제거+추가
        self.tearDown(); self.setUp()
        empty = ldb_batch(20, ("PUT", ls_key(LS_HISTORY_KEY), ls_utf16(history_value(timestamp=REMOVED_TS_B))))
        self.assertEqual(self.events(history_put(10, REMOVED_IDS), empty)[2], [])  # 전체 비움

    # 6
    def test_lower_sequence_version_creates_no_event(self):
        # 파일 안 순서는 반대지만 sequence 순으로 비교하므로 "제거" 가 아니라 "추가" 로 보인다
        records, coverage, events = self.events(
            history_put(30, REMOVED_IDS, REMOVED_TS_B),
            history_put(20, [i for i in REMOVED_IDS if i != REMOVED_TARGET], REMOVED_TS_A))
        self.assertEqual(events, [])

    # 7
    def test_missing_timestamp_creates_no_event(self):
        records, coverage, events = self.events(
            history_put(120, REMOVED_IDS, REMOVED_TS_A),
            history_put(146, [i for i in REMOVED_IDS if i != REMOVED_TARGET], None))
        self.assertIsNone(records[-1].timestamp_utc)
        self.assertEqual(events, [])

    # 8
    def test_tombstone_only_creates_no_event(self):
        records, coverage, events = self.events(
            history_put(120, REMOVED_IDS, REMOVED_TS_A),
            ldb_batch(130, ("DELETE", ls_key(LS_HISTORY_KEY))))
        self.assertEqual([r.observed["operation"] for r in records], ["PUT", "DELETE"])
        self.assertEqual(events, [])

    # 9
    def test_cache_record_of_removed_conversation_becomes_supporting(self):
        cache_record = p.ArtifactRecord(
            record_id="cache:Cache/Cache_Data#entry=0x1", artifact_type="cache", source_path="Cache/Cache_Data",
            record_location="entry=0x1", observed={"url_conversation_id": REMOVED_TARGET, "entry_state": 0})
        records, coverage, events = self.events(
            history_put(120, REMOVED_IDS, REMOVED_TS_A),
            history_put(146, [i for i in REMOVED_IDS if i != REMOVED_TARGET], REMOVED_TS_B),
            extra_records=[cache_record])
        self.assertEqual(len(events), 1)
        levels = [(e.artifact_type, e.evidence_level) for e in events[0].supporting_evidence]
        self.assertEqual(levels, [("local_storage", "SUPPORTING"), ("cache", "SUPPORTING")])
        self.assertTrue(any("Cache 응답 Record 1건" in note for note in events[0].limitations))


# =============================================================================
# CSV Export — ParseResult -> coverage / records / events / conversations / messages
# =============================================================================
# CSV 는 JSON 과 같은 ParseResult 를 표현하는 파생 산출물이다. 새 분석 결과를 만들지 않는다.
# 실제 Scenario 이미지 데이터는 fixture 에 쓰지 않는다 (전부 synthetic).


class CsvExportTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="csv-export-"))
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def read_csv(self, name):
        """CSV 를 (header, data rows) 로 읽는다. utf-8-sig 로 읽혀야 BOM 이 값에 섞이지 않는다."""
        with open(self.dir / name, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        return rows[0], rows[1:]

    def export(self, result, **kwargs):
        kwargs.setdefault("debug", True)  # 이 클래스는 개발용 CSV 5종을 검증한다
        return p.write_result_csv(result, self.dir, **kwargs)

    # A — events.csv 행 수와 핵심 field
    def test_events_csv_rows_and_core_fields(self):
        result = make_result()
        self.assertEqual(len(self.export(result)), 7)
        header, rows = self.read_csv("events.csv")
        self.assertEqual(len(rows), len(result.events))
        for column in ("service", "action", "action_status", "timestamp_utc", "timestamp_kst", "confidence",
                       "rule_id", "rule_verification", "browser_profile", "representative_evidence_id",
                       "primary_evidence_count", "supporting_evidence_count", "limitations", "warnings"):
            self.assertIn(column, header)
        row = dict(zip(header, rows[0]))
        event = result.events[0]
        self.assertEqual(row["action"], event.action)
        self.assertEqual(row["timestamp_kst"], event.timestamp_kst)
        self.assertEqual(row["confidence"], event.confidence)
        self.assertEqual(row["rule_id"], event.rule_id)
        self.assertEqual(row["timestamp_source"], event.timestamp_source)
        self.assertEqual(row["primary_evidence_count"], str(len(event.primary_evidence)))
        self.assertEqual(row["supporting_evidence_count"], str(len(event.supporting_evidence)))

    # A — 모든 CSV 의 행 수가 ParseResult 와 일치 (CSV 가 별도 결과를 만들지 않는다)
    def test_row_counts_match_parse_result(self):
        result = make_result()
        result.conversations = [make_conversation(),
                                make_conversation(conversation_id="conv-residual", title=None,
                                                  recovery_status="RESIDUAL_ONLY", messages=[])]
        self.export(result)
        self.assertEqual(len(self.read_csv("coverage.csv")[1]), len(result.coverage))
        self.assertEqual(len(self.read_csv("records.csv")[1]), len(result.records))
        self.assertEqual(len(self.read_csv("events.csv")[1]), len(result.events))
        self.assertEqual(len(self.read_csv("conversations.csv")[1]), len(result.conversations))
        self.assertEqual(len(self.read_csv("messages.csv")[1]),
                         sum(len(c.messages) for c in result.conversations))

    # B — 복구된 메시지 본문이 절단 없이 그대로 나온다
    def test_messages_csv_content_is_not_truncated(self):
        conversation = make_conversation()
        result = display_result(conversations=[conversation])
        self.export(result)
        header, rows = self.read_csv("messages.csv")
        self.assertEqual(len(rows), 2)
        first = dict(zip(header, rows[0]))
        self.assertEqual(first["conversation_id"], conversation.conversation_id)
        self.assertEqual(first["conversation_title"], conversation.title)
        self.assertEqual(first["role"], "user")
        self.assertEqual(first["content"], conversation.messages[0].content)
        self.assertEqual(dict(zip(header, rows[1]))["content"], conversation.messages[1].content)
        self.assertEqual(first["timestamp_kst"], conversation.messages[0].timestamp_kst)

    # C — 메시지 0개여도 header 만 있는 messages.csv 를 만든다 (오류 아님)
    def test_messages_csv_header_only_when_no_message(self):
        residual = make_conversation(conversation_id="conv-residual", title="잔존 대화",
                                     recovery_status="RESIDUAL_ONLY", messages=[])
        self.export(display_result(conversations=[residual]))
        header, rows = self.read_csv("messages.csv")
        self.assertEqual(rows, [])
        self.assertEqual(header, list(p.CSV_MESSAGE_COLUMNS))
        # 본문이 복구되지 않아도 대화 자체는 conversations.csv 에 한 행으로 남는다
        conv_header, conv_rows = self.read_csv("conversations.csv")
        self.assertEqual(len(conv_rows), 1)
        row = dict(zip(conv_header, conv_rows[0]))
        self.assertEqual((row["conversation_id"], row["title"], row["recovery_status"], row["message_count"]),
                         ("conv-residual", "잔존 대화", "RESIDUAL_ONLY", "0"))

    # D — utf-8-sig (Windows Excel 한글)
    def test_written_as_utf8_with_bom(self):
        self.export(display_result(conversations=[make_conversation(title="한글 제목 확인")]))
        raw = (self.dir / "conversations.csv").read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        self.assertIn("한글 제목 확인", raw.decode("utf-8-sig"))
        self.assertNotIn("\r\r\n", raw.decode("utf-8-sig"))  # Windows 에서 빈 줄이 생기지 않는다

    # E — nested dict / list 직렬화
    def test_nested_values_serialized_as_json(self):
        result = make_result()
        self.export(result)
        header, rows = self.read_csv("records.csv")
        row = dict(zip(header, rows[0]))
        self.assertEqual(json.loads(row["observed"]), result.records[0].observed)
        self.assertEqual(json.loads(row["warnings"]), result.records[0].warnings)
        cov_header, cov_rows = self.read_csv("coverage.csv")
        self.assertEqual(dict(zip(cov_header, cov_rows[1]))["source_sha256"], "")  # None 은 빈 cell

    # E — 수식처럼 보이는 값은 되돌릴 수 있게 처리하고 JSON 원본은 바꾸지 않는다
    def test_formula_like_values_are_escaped_reversibly(self):
        title = "=cmd|x /c calc!A1"
        result = display_result(conversations=[make_conversation(conversation_id="conv-residual", title=title,
                                                                recovery_status="RESIDUAL_ONLY", messages=[])])
        self.export(result)
        header, rows = self.read_csv("conversations.csv")
        cell = dict(zip(header, rows[0]))["title"]
        self.assertEqual(cell, "'" + title)
        self.assertEqual(cell[1:], title)          # 맨 앞 따옴표 1개만 떼면 원문
        self.assertEqual(result.conversations[0].title, title)  # JSON 쪽 값은 그대로
        self.assertEqual(p.csv_cell("'이미 따옴표"), "''이미 따옴표")
        self.assertEqual(p.csv_cell("2026-09-14T17:24:34+09:00"), "2026-09-14T17:24:34+09:00")

    # F — overwrite 정책 (partial output 방지)
    def test_overwrite_policy(self):
        result = make_result()
        self.export(result)
        with self.assertRaises(FileExistsError):
            self.export(result)
        # 한 파일만 남아 있어도 전부 거부하고, 아무 파일도 새로 쓰지 않는다
        (self.dir / "events.csv").unlink()
        with self.assertRaises(FileExistsError):
            self.export(result)
        self.assertFalse((self.dir / "events.csv").exists())
        self.assertEqual(len(self.export(result, overwrite=True)), 7)

    def test_creates_directory_when_missing(self):
        target = self.dir / "new" / "csv"
        p.write_result_csv(make_result(), target, debug=True)
        self.assertEqual(sorted(f.name for f in target.iterdir()), sorted(name for name, _ in p.CSV_FILES))

    def test_default_export_writes_only_the_two_final_files(self):
        target = self.dir / "final" / "csv"
        written = p.write_result_csv(make_result(), target)
        self.assertEqual([path.name for path in written], ["timeline.csv", "recovered_conversations.csv"])
        self.assertEqual(sorted(f.name for f in target.iterdir()),
                         ["recovered_conversations.csv", "timeline.csv"])


class CsvCliTest(unittest.TestCase):
    """--csv-dir 은 optional 이다. 주지 않으면 기존 동작(JSON 만) 이 그대로 유지된다."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="csv-cli-"))
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.source = self.dir / "source"
        (self.source / "Default").mkdir(parents=True)
        self.out = self.dir / "result.json"

    def run_cli(self, *extra):
        return p.main(["--dir", str(self.source), "--out", str(self.out), *extra])

    # G — --csv-dir 미지정 시 기존 동작
    def test_without_csv_dir_only_json_is_written(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.run_cli(), p.EXIT_OK)
        self.assertTrue(self.out.exists())
        self.assertEqual(sorted(f.name for f in self.dir.iterdir()), ["result.json", "source"])
        self.assertNotIn("CSV:", out.getvalue())

    def test_with_csv_dir_writes_only_the_two_final_files(self):
        csv_dir = self.dir / "csv"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.run_cli("--csv-dir", str(csv_dir)), p.EXIT_OK)
        self.assertEqual(sorted(f.name for f in csv_dir.iterdir()),
                         ["recovered_conversations.csv", "timeline.csv"])
        self.assertIn("CSV:", out.getvalue())
        self.assertIn(str(csv_dir / "timeline.csv"), out.getvalue())

    def test_debug_output_adds_the_development_files(self):
        csv_dir = self.dir / "csv"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.run_cli("--csv-dir", str(csv_dir), "--debug-output"), p.EXIT_OK)
        self.assertEqual(sorted(f.name for f in csv_dir.iterdir()), sorted(name for name, _ in p.CSV_FILES))
        self.assertIn(str(csv_dir / "events.csv"), out.getvalue())

    def test_existing_csv_needs_overwrite(self):
        csv_dir = self.dir / "csv"
        csv_dir.mkdir()
        (csv_dir / "timeline.csv").write_text("stale", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_cli("--csv-dir", str(csv_dir)), p.EXIT_USAGE)
        self.assertIn("--csv-dir already contains timeline.csv", err.getvalue())
        self.assertEqual((csv_dir / "timeline.csv").read_text(encoding="utf-8"), "stale")  # 조용히 덮어쓰지 않는다
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_cli("--csv-dir", str(csv_dir), "--overwrite"), p.EXIT_OK)
        self.assertNotEqual((csv_dir / "timeline.csv").read_text(encoding="utf-8-sig"), "stale")

    def test_existing_development_csv_does_not_block_the_default_run(self):
        """기본 실행은 개발용 CSV 이름을 쓰지 않으므로 그런 파일이 이미 있어도 막지 않고, 지우지도 않는다."""
        csv_dir = self.dir / "csv"
        csv_dir.mkdir()
        (csv_dir / "events.csv").write_text("stale", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_cli("--csv-dir", str(csv_dir)), p.EXIT_OK)
        self.assertEqual((csv_dir / "events.csv").read_text(encoding="utf-8"), "stale")
        self.assertEqual(sorted(f.name for f in csv_dir.iterdir()),
                         ["events.csv", "recovered_conversations.csv", "timeline.csv"])

    def test_csv_dir_inside_source_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_cli("--csv-dir", str(self.source / "csv")), p.EXIT_USAGE)
        self.assertIn("--csv-dir must be outside", err.getvalue())
        self.assertFalse((self.source / "csv").exists())


CHATGPT_ESTUARY_URL = ("https://chatgpt.com/backend-api/estuary/content?id=file_0000000000000000&fn=report.pdf"
                       "&cd=attachment&p=fs&cid=1&sig=abcdef0123456789&v=0")
CHATGPT_TAB_URL = "https://chatgpt.com/c/00000000-1111-2222-3333-444444444444"


def download_row(**values):
    """HISTORY_DOWNLOAD_COLUMNS 순서의 downloads 행. 지정하지 않은 값은 Chrome 기본값에 해당하는 빈 값."""
    defaults = dict(id=1, guid="guid-1", current_path=r"C:\Users\u\Downloads\report.pdf",
                    target_path=r"C:\Users\u\Downloads\report.pdf", start_time=13433876833869648,
                    end_time=13433876838520705, received_bytes=1361, total_bytes=1361, state=1, danger_type=0,
                    interrupt_reason=0, opened=0, referrer="", site_url="", tab_url="", tab_referrer_url="",
                    http_method="", mime_type="application/pdf", original_mime_type="application/pdf",
                    last_access_time=0, transient=0, by_ext_id="", by_ext_name="", etag="", last_modified="")
    defaults.update(values)
    return tuple(defaults[name] for name in HISTORY_DOWNLOAD_COLUMNS)


class HistoryDownloadMixin:
    def read(self, **kwargs):
        self._n = getattr(self, "_n", 0) + 1  # 한 테스트에서 여러 번 부를 수 있으므로 파일 이름을 나눈다
        return p.read_history(self.source, self.variant(f"HistoryDL{self._n}", **kwargs))

    def download_records(self, records):
        return [r for r in records if r.observed.get("record_kind") == "download"]


class HistoryDownloadReaderTest(HistoryDownloadMixin, HistoryTestBase):
    """§7.1-b History downloads / downloads_url_chains Reader."""

    # A — estuary 다운로드 1건이 Record 1건이 된다
    def test_download_row_becomes_record(self):
        records, coverage = self.read(downloads=[download_row(tab_url=CHATGPT_TAB_URL)],
                                      url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        self.assertEqual(coverage.status, "PARSED")
        record, = self.download_records(records)
        self.assertEqual(record.record_location, "downloads.id=1")
        self.assertEqual(record.observed["download_id"], 1)
        self.assertEqual(record.observed["filename"], "report.pdf")
        self.assertEqual(record.observed["mime_type"], "application/pdf")
        self.assertEqual(record.observed["total_bytes"], 1361)
        self.assertIsNone(record.observed.get("url"))  # visits 기반 Rule 이 읽는 key 를 만들지 않는다

    # B — url chain 여러 행은 순서대로 한 Record 에 보존된다
    def test_url_chain_rows_are_ordered_in_one_record(self):
        records, _ = self.read(downloads=[download_row()],
                               url_chains=[(1, 1, CHATGPT_ESTUARY_URL), (1, 0, "https://chatgpt.com/redirect")])
        record, = self.download_records(records)
        self.assertEqual([item["chain_index"] for item in record.observed["url_chain"]], [0, 1])
        self.assertEqual(record.observed["url_chain"][0]["url"], "https://chatgpt.com/redirect")
        self.assertTrue(record.observed["download_url"].startswith("https://chatgpt.com/backend-api/estuary/content"))

    # F — 컬럼이 없어도 죽지 않는다
    def test_missing_optional_column_does_not_crash(self):
        records, coverage = self.read(downloads=[download_row()], url_chains=[(1, 0, CHATGPT_ESTUARY_URL)],
                                      skip_download_columns=("mime_type", "tab_url"))
        record, = self.download_records(records)
        self.assertEqual(coverage.status, "PARSED")
        self.assertIsNone(record.observed["mime_type"])
        self.assertIn("HISTORY_DOWNLOADS_COLUMN_ABSENT:downloads.mime_type", coverage.warnings)

    def test_missing_required_column_is_reported(self):
        records, coverage = self.read(downloads=[], skip_download_columns=("target_path",))
        self.assertEqual(self.download_records(records), [])
        self.assertIn("HISTORY_DOWNLOADS_SCHEMA_UNSUPPORTED", coverage.warnings)

    def test_absent_tables_are_reported(self):
        _, coverage = self.read(skip_table="downloads")
        self.assertIn("HISTORY_DOWNLOADS_TABLE_ABSENT", coverage.warnings)
        _, chains_absent = self.read(downloads=[download_row()], skip_table="downloads_url_chains")
        self.assertIn("HISTORY_DOWNLOAD_URL_CHAINS_ABSENT", chains_absent.warnings)

    # G — 서명 query 는 가린다
    def test_signature_query_is_redacted(self):
        records, _ = self.read(downloads=[download_row()], url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        record, = self.download_records(records)
        self.assertNotIn("abcdef0123456789", json.dumps(record.observed))
        self.assertIn("sig", record.observed["redacted_query_keys"])
        self.assertIn("fn=report.pdf", record.observed["download_url"])  # 가리지 않는 값은 그대로

    # H — start_time / end_time 은 WebKit 변환
    def test_timestamps_use_webkit_conversion(self):
        records, _ = self.read(downloads=[download_row()], url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        record, = self.download_records(records)
        self.assertEqual(record.timestamp_type, "webkit_us")
        self.assertEqual(record.timestamp_source, "History.downloads.start_time")
        self.assertEqual(record.timestamp_kst, "2026-09-15T01:27:13.869648+09:00")
        self.assertEqual(record.observed["end_timestamp_kst"], "2026-09-15T01:27:18.520705+09:00")

    def test_zero_end_time_is_not_converted(self):
        records, _ = self.read(downloads=[download_row(end_time=0)], url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        record, = self.download_records(records)
        self.assertEqual(record.observed["end_time"], 0)
        self.assertNotIn("end_timestamp_kst", record.observed)

    def test_downloads_do_not_reach_visit_rules(self):
        records, _ = self.read(downloads=[download_row(tab_url=CHATGPT_TAB_URL)],
                               url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        self.assertEqual(p.detect_conversation_access(records), [])


class FileDownloadRuleTest(HistoryDownloadMixin, HistoryTestBase):
    """§8.12 CHATGPT_FILE_DOWNLOAD_001."""

    def events(self, **kwargs):
        records, coverage = self.read(**kwargs)
        return p.detect_file_download(records, [coverage])

    # A — estuary 다운로드 1건 → Event 1건 DETECTED / MEDIUM (PARTIALLY_VERIFIED 인 동안 HIGH 금지)
    def test_estuary_download_creates_one_detected_medium_event(self):
        event, = self.events(downloads=[download_row(tab_url=CHATGPT_TAB_URL)],
                             url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        self.assertEqual(event.action, "FILE_DOWNLOAD")
        self.assertEqual(event.action_status, "DETECTED")
        self.assertEqual(event.confidence, "MEDIUM")
        self.assertEqual(event.rule_verification, "PARTIALLY_VERIFIED")
        self.assertEqual(event.rule_id, "CHATGPT_FILE_DOWNLOAD_001")
        self.assertEqual(event.timestamp_kst, "2026-09-15T01:27:13.869648+09:00")
        self.assertIn(p.REASON_DIRECT_DOWNLOAD_URL, event.confidence_reason)
        self.assertEqual(event.primary_evidence[0].evidence_level, "DIRECT")

    def test_partially_verified_rule_never_reports_high(self):
        for chains in ([(1, 0, CHATGPT_ESTUARY_URL)], [(1, 0, "https://files.example.com/report.pdf")]):
            with self.subTest(chains=chains):
                event, = self.events(downloads=[download_row(tab_url=CHATGPT_TAB_URL)], url_chains=chains)
                self.assertIn(p.REASON_RULE_PARTIALLY_VERIFIED, event.confidence_reason)
                self.assertNotEqual(event.confidence, "HIGH")

    # B — chain 이 여러 행이어도 download_id 당 Event 1건
    def test_multi_row_chain_still_one_event(self):
        events = self.events(downloads=[download_row()],
                             url_chains=[(1, 0, "https://chatgpt.com/redirect"), (1, 1, CHATGPT_ESTUARY_URL)])
        self.assertEqual(len(events), 1)

    # C — tab_url 만 ChatGPT 이면 CANDIDATE, DIRECT 로 올리지 않고 대안 설명을 남긴다
    def test_tab_url_only_is_candidate_not_direct(self):
        event, = self.events(downloads=[download_row(tab_url=CHATGPT_TAB_URL)],
                             url_chains=[(1, 0, "https://files.example.com/report.pdf")])
        self.assertEqual(event.action_status, "CANDIDATE")
        self.assertEqual(event.confidence, "LOW")
        self.assertEqual(event.primary_evidence[0].evidence_level, "SUPPORTING")
        self.assertIn(p.REASON_TAB_CONTEXT_ONLY, event.confidence_reason)
        self.assertIn(p.REASON_NOT_UNIQUE_TO_ACTION, event.confidence_reason)
        self.assertTrue(any("Alternative explanation" in note for note in event.limitations))
        self.assertNotIn("생성한 파일", event.inference)
        self.assertEqual(event.primary_evidence[0].observed["tab_conversation_id"],
                         "00000000-1111-2222-3333-444444444444")

    # D — 일반 웹 다운로드는 Event 를 만들지 않는다
    def test_plain_web_download_is_not_an_event(self):
        self.assertEqual(self.events(downloads=[download_row(tab_url="https://example.com/files")],
                                     url_chains=[(1, 0, "https://example.com/report.pdf")]), [])

    # E — 다른 LLM 다운로드 (Negative Control)
    def test_other_llm_downloads_are_not_events(self):
        claude = "https://claude.ai/api/organizations/o/conversations/c/wiggle/download-file?path=%2Freport.pdf"
        gemini = "https://contribution.usercontent.google.com/download?c=abc&filename=report.pdf"
        self.assertEqual(self.events(downloads=[download_row(id=1, tab_url="https://claude.ai/chat/abc"),
                                                download_row(id=2, tab_url="")],
                                     url_chains=[(1, 0, claude), (2, 0, gemini)]), [])

    # 파일 이름에 의존하지 않는다
    def test_rule_does_not_depend_on_filename(self):
        for name in ("report.pdf", "image.png", "document.docx"):
            with self.subTest(name=name):
                url = CHATGPT_ESTUARY_URL.replace("report.pdf", name)
                event, = self.events(downloads=[download_row(target_path=rf"C:\Users\u\Downloads\{name}")],
                                     url_chains=[(1, 0, url)])
                self.assertEqual((event.action_status, event.confidence), ("DETECTED", "MEDIUM"))
                self.assertEqual(event.primary_evidence[0].observed["filename"], name)

    def test_marker_like_filename_changes_nothing(self):
        plain, = self.events(downloads=[download_row(target_path=r"C:\Users\u\Downloads\report.pdf")],
                             url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        marked, = self.events(downloads=[download_row(target_path=r"C:\Users\u\Downloads\MRK_E505.pdf")],
                              url_chains=[(1, 0, CHATGPT_ESTUARY_URL.replace("report.pdf", "MRK_E505.pdf"))])
        self.assertEqual((plain.action_status, plain.confidence, plain.primary_evidence[0].evidence_level),
                         (marked.action_status, marked.confidence, marked.primary_evidence[0].evidence_level))
        self.assertEqual(plain.confidence_reason, marked.confidence_reason)

    def test_unconverted_timestamp_becomes_candidate(self):
        event, = self.events(downloads=[download_row(start_time=-1)], url_chains=[(1, 0, CHATGPT_ESTUARY_URL)])
        self.assertEqual(event.confidence, "LOW")
        self.assertEqual(event.action_status, "CANDIDATE")


def proto_field(number, wire, payload):
    tag = ldb_varint((number << 3) | wire)
    if wire == 0:
        return tag + ldb_varint(payload)
    if wire == 1:
        return tag + struct.pack("<Q", payload)
    return tag + ldb_varint(len(payload)) + payload


SPDB_GUID = "ddfcd808-0000-4000-8000-000000000001"
SPDB_START_MS = 13433876833869  # History 의 webkit_us 13433876833869648 과 같은 순간 (ms 단위)
SPDB_END_MS = 13433876838520


def spdb_path(text):
    """Chromium Pickle 경로 field: payload_size + char_count + UTF-16LE + 4 byte 정렬 padding."""
    body = struct.pack("<I", len(text)) + text.encode("utf-16-le")
    body += b"\x00" * (-len(body) % 4)
    return struct.pack("<I", len(body)) + body


def spdb_value(url_chain=(CHATGPT_ESTUARY_URL,), tab_url=CHATGPT_TAB_URL, start=SPDB_START_MS, end=SPDB_END_MS,
               target=r"C:\Users\u\Downloads\report.pdf", guid=SPDB_GUID, extra=b"", target_raw=None):
    """§7.6 에서 실측한 구조와 같은 모양의 21_download value."""
    progress = b"".join(proto_field(1, 2, url.encode()) for url in url_chain)
    if tab_url is not None:
        progress += proto_field(4, 2, tab_url.encode())
    progress += (proto_field(10, 0, 1361) + proto_field(11, 2, b"application/pdf")
                 + proto_field(13, 2, spdb_path(target + ".crdownload"))
                 + proto_field(14, 2, spdb_path(target) if target_raw is None else target_raw)
                 + proto_field(15, 0, 1361)
                 + proto_field(16, 0, start) + proto_field(17, 0, end) + extra)
    info = proto_field(1, 2, guid.encode()) + proto_field(4, 2, progress)
    return proto_field(1, 2, info)


class SharedProtoDbReaderTest(unittest.TestCase):
    """§7.6 shared_proto_db 21_download Reader."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "Chrome"
        self.directory = self.root / "Default" / "shared_proto_db"
        self.directory.mkdir(parents=True)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def read(self, *payloads, name="000003.log"):
        (self.directory / name).write_bytes(ldb_log(*payloads))
        return p.read_shared_proto_db(self.source, "Default/shared_proto_db")

    @staticmethod
    def put(sequence, value, guid=SPDB_GUID):
        return ldb_batch(sequence, ("PUT", b"21_download," + guid.encode(), value))

    def test_download_record_fields(self):
        records, coverages = self.read(self.put(10, spdb_value()))
        self.assertEqual([(c.artifact_type, c.status) for c in coverages], [("shared_proto_db", "PARSED")])
        record, = records
        self.assertEqual(record.record_location, f"21_download,{SPDB_GUID}")
        observed = record.observed
        self.assertEqual((observed["record_kind"], observed["guid"], observed["deleted_in_log"]),
                         ("download", SPDB_GUID, False))
        self.assertEqual(observed["target_path"], r"C:\Users\u\Downloads\report.pdf")
        self.assertEqual(observed["filename"], "report.pdf")
        self.assertTrue(observed["current_path"].endswith(".crdownload"))
        self.assertEqual((observed["mime_type"], observed["total_bytes"], observed["received_bytes"]),
                         ("application/pdf", 1361, 1361))
        self.assertEqual(observed["tab_url"], CHATGPT_TAB_URL)
        self.assertTrue(observed["download_url"].startswith("https://chatgpt.com/backend-api/estuary/content"))

    def test_path_pickle_padding_is_not_part_of_the_path(self):
        # 31 자 경로 → 4 byte 정렬 padding 2 byte 가 붙는다 (실측 docx 와 같은 모양)
        record, = self.read(self.put(10, spdb_value()))[0]
        self.assertNotIn("\x00", record.observed["target_path"] + record.observed["filename"])

    def test_path_with_broken_pickle_structure_is_not_decoded(self):
        broken = spdb_path(r"C:\Users\u\Downloads\report.pdf")[:-4]  # char_count 와 실제 payload 불일치
        record, = self.read(self.put(10, spdb_value(target_raw=broken)))[0]
        self.assertIsNone(record.observed["target_path"])
        self.assertIsNone(record.observed["filename"])
        self.assertIn(f"{p.SHARED_PROTO_DB_PATH_UNPARSED}:target_path", record.warnings)

    def test_start_and_end_time_use_webkit_ms(self):
        (record,), _ = self.read(self.put(10, spdb_value()))
        self.assertEqual((record.timestamp_type, record.timestamp_source),
                         ("webkit_ms", "shared_proto_db.21_download.start_time"))
        self.assertEqual(record.timestamp_kst, "2026-09-15T01:27:13.869000+09:00")
        self.assertEqual(record.observed["end_timestamp_kst"], "2026-09-15T01:27:18.520000+09:00")

    def test_unrecorded_end_time_is_kept_raw(self):
        (record,), _ = self.read(self.put(10, spdb_value(end=0xFFFFFFFFFFFFFFFF)))
        self.assertNotIn("end_timestamp_kst", record.observed)
        self.assertEqual(record.observed["end_time_raw_unconverted"], str(0xFFFFFFFFFFFFFFFF))

    def test_latest_put_wins_and_delete_is_recorded(self):
        records, _ = self.read(self.put(10, spdb_value(end=0xFFFFFFFFFFFFFFFF)), self.put(11, spdb_value()),
                               ldb_batch(12, ("DELETE", b"21_download," + SPDB_GUID.encode())))
        record, = records  # 진행 단계마다 PUT 이 있어도 다운로드 1건 = Record 1건
        self.assertEqual(record.observed["end_timestamp_kst"], "2026-09-15T01:27:18.520000+09:00")
        self.assertTrue(record.observed["deleted_in_log"])  # record 가 지워진 사실만 (파일 삭제가 아니다)

    def test_signature_query_is_redacted(self):
        (record,), _ = self.read(self.put(10, spdb_value()))
        self.assertNotIn("abcdef0123456789", json.dumps(record.observed))
        self.assertIn("sig", record.observed["redacted_query_keys"])

    def test_unmapped_fields_are_preserved_not_interpreted(self):
        (record,), _ = self.read(self.put(10, spdb_value(extra=proto_field(21, 0, 1))))
        self.assertEqual(record.observed["unmapped_proto_fields"], {"21": [1]})
        self.assertNotIn("state", record.observed)  # downloads.state 에 대응하는 field 를 확정하지 못했다

    def test_other_keys_and_damaged_value_do_not_crash(self):
        records, coverages = self.read(ldb_batch(10, ("PUT", b"12_other,x", b"\x00")), self.put(11, b"\x0a\x7f"))
        record, = records
        self.assertIn(p.SHARED_PROTO_DB_VALUE_UNPARSED, record.warnings)
        self.assertTrue(any(w.startswith("SHARED_PROTO_DB_NON_ALLOWLISTED_OPERATIONS") for w in coverages[0].warnings))

    def test_ldb_is_reported_as_not_supported(self):
        (self.directory / "000005.ldb").write_bytes(b"\x00")
        _, coverages = self.read(self.put(10, spdb_value()))
        self.assertIn(("shared_proto_db", "NOT_SUPPORTED"), [(c.artifact_type, c.status) for c in coverages])


class SharedProtoDbFileDownloadRuleTest(SharedProtoDbReaderTest):
    """§8.12 Rule 이 shared_proto_db Record 도 같은 Rule ID 로 판정한다."""

    def events(self, *payloads):
        records, coverages = self.read(*payloads)
        return p.detect_file_download(records, coverages)

    def test_estuary_record_creates_same_rule_event(self):
        event, = self.events(self.put(10, spdb_value()))
        self.assertEqual((event.rule_id, event.action, event.action_status, event.confidence),
                         ("CHATGPT_FILE_DOWNLOAD_001", "FILE_DOWNLOAD", "DETECTED", "MEDIUM"))
        self.assertEqual(event.primary_evidence[0].artifact_type, "shared_proto_db")
        self.assertEqual(event.timestamp_kst, "2026-09-15T01:27:13.869000+09:00")
        self.assertTrue(any("shared_proto_db" in note for note in event.limitations))

    def test_tab_context_only_record_is_candidate(self):
        event, = self.events(self.put(10, spdb_value(url_chain=("blob:https://chatgpt.com/abc",))))
        self.assertEqual((event.action_status, event.confidence), ("CANDIDATE", "LOW"))
        self.assertEqual(event.primary_evidence[0].evidence_level, "SUPPORTING")

    def test_non_chatgpt_download_is_not_an_event(self):
        self.assertEqual(self.events(self.put(10, spdb_value(url_chain=("https://get.microsoft.com/setup.exe",),
                                                             tab_url="https://chatgpt.com/ko-KR/download/"))), [])

    def test_same_guid_in_history_keeps_both_sources_in_one_event(self):
        records, coverages = self.read(self.put(10, spdb_value()))
        history_record = p._history_download_record(
            "Default/History", None, "Default",
            {"id": 1, "guid": SPDB_GUID, "target_path": r"C:\Users\u\Downloads\report.pdf",
             "start_time": 13433876833869648, "end_time": 0, "tab_url": CHATGPT_TAB_URL},
            [(0, CHATGPT_ESTUARY_URL)])
        event, = p.detect_file_download([history_record] + records, coverages)
        self.assertEqual(event.primary_evidence[0].artifact_type, "history")  # 기존 Event 를 덮어쓰지 않는다
        self.assertEqual([e.artifact_type for e in event.supporting_evidence], ["shared_proto_db"])
        self.assertEqual(event.supporting_evidence[0].evidence_level, "SUPPORTING")
        self.assertIn(p.REASON_SUPPORTING_CORRELATED, event.confidence_reason)


SNSS_TEMPORARY_CHAT_URL = "https://chatgpt.com/?temporary-chat=true"
SNSS_TIMESTAMP = 13433848575041619  # 2026-09-14T17:36:15.041619+09:00


def snss_string(text, wide=False):
    raw = text.encode("utf-16-le") if wide else text.encode("utf-8")
    count = len(text) if wide else len(raw)
    return struct.pack("<i", count) + raw + b"\x00" * (-len(raw) % 4)


def snss_navigation(url, *, tab_id=17553065, index=0, title="ChatGPT", transition=0,
                    referrer="", original="https://chatgpt.com/", timestamp=SNSS_TIMESTAMP, status=200, tail=True):
    """UpdateTabNavigation payload (관찰된 필드 순서)."""
    body = (struct.pack("<i", index) + snss_string(url) + snss_string(title, wide=True)
            + snss_string("page-state") + struct.pack("<II", transition, 0))
    if tail:
        body += (snss_string(referrer) + struct.pack("<i", 1) + snss_string(original) + struct.pack("<i", 0)
                 + struct.pack("<q", timestamp) + snss_string("", wide=True) + struct.pack("<i", status))
    return struct.pack("<I", len(body) + 4) + struct.pack("<i", tab_id) + body


def snss_file(*commands, version=3):
    out = p.SNSS_MAGIC + struct.pack("<i", version)
    for command_id, payload in commands:
        out += struct.pack("<HB", len(payload) + 1, command_id) + payload
    return out


class SnssReaderTest(unittest.TestCase):
    """§7.7 Chrome Sessions (SNSS) Navigation Reader."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "Chrome"
        self.directory = self.root / "Profile 1" / "Sessions"
        self.directory.mkdir(parents=True)
        self.source = p.DirectorySource(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        (self.directory / name).write_bytes(data)
        return f"Profile 1/Sessions/{name}"

    def read(self, name="Session_13433848693271468", *commands, **kwargs):
        path = self.write(name, snss_file(*commands, **kwargs))
        return p.read_chrome_session_file(self.source, path, browser_profile="Profile 1")

    # SNSS 1
    def test_temporary_chat_navigation_record(self):
        records, coverage = self.read("Session_13433848693271468", (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL)))
        self.assertEqual((coverage.artifact_type, coverage.status, coverage.record_count), ("sessions", "PARSED", 1))
        record, = records
        observed = record.observed
        self.assertEqual((observed["url"], observed["title"], observed["tab_id"], observed["navigation_index"]),
                         (SNSS_TEMPORARY_CHAT_URL, "ChatGPT", 17553065, 0))
        self.assertEqual((observed["snss_command_id"], observed["http_status_code"]), (6, 200))
        self.assertEqual(record.timestamp_raw, str(SNSS_TIMESTAMP))
        self.assertEqual(record.timestamp_kst, "2026-09-14T17:36:15.041619+09:00")
        self.assertEqual((record.timestamp_type, record.timestamp_source),
                         ("webkit_us", "Sessions.UpdateTabNavigation.timestamp"))
        self.assertEqual(record.record_location, "command=6@8")

    # SNSS 2 — Tabs_ 파일의 navigation command id 는 1 이다
    def test_tabs_file_uses_command_one(self):
        records, coverage = self.read("Tabs_13433848648354897", (1, snss_navigation(SNSS_TEMPORARY_CHAT_URL)),
                                      (6, snss_navigation("https://chatgpt.com/c/abc")))
        self.assertEqual([r.observed["url"] for r in records], [SNSS_TEMPORARY_CHAT_URL])  # cmd 6 은 Tabs_ 에서 navigation 아님
        self.assertEqual(coverage.status, "PARSED")

    # SNSS 3 — ChatGPT host 가 아닌 navigation 은 Record 로 만들지 않는다
    def test_other_service_navigation_is_not_recorded(self):
        records, coverage = self.read("Session_1", (6, snss_navigation("https://gemini.google.com/app")),
                                      (6, snss_navigation("https://claude.ai/new")),
                                      (6, snss_navigation("https://www.google.com/search?q=temporary-chat%3Dtrue")))
        self.assertEqual((records, coverage.status), ([], "PARSED"))

    # SNSS 4 — 잘린 record 에서 멈추고 앞 record 는 보존한다
    def test_truncated_record_is_partial(self):
        data = snss_file((6, snss_navigation(SNSS_TEMPORARY_CHAT_URL)))
        path = self.write("Session_2", data + struct.pack("<H", 4096) + b"\x06ab")
        records, coverage = p.read_chrome_session_file(self.source, path)
        self.assertEqual((len(records), coverage.status), (1, "PARTIAL"))
        self.assertTrue(any(w.startswith(p.SNSS_RECORD_TRUNCATED) for w in coverage.warnings))

    # SNSS 5 — payload 가 깨져도 다른 record 를 계속 읽는다
    def test_malformed_navigation_does_not_stop_parsing(self):
        records, coverage = self.read("Session_3", (6, b"\x10\x00\x00\x00short"),
                                      (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL)))
        self.assertEqual([r.observed["url"] for r in records], [SNSS_TEMPORARY_CHAT_URL])
        self.assertEqual(coverage.status, "PARTIAL")
        self.assertIn(f"{p.SNSS_NAVIGATION_UNPARSED}:1", coverage.warnings)

    # SNSS 6 — tail 필드가 없으면 url·title 만 남기고 시각은 없음으로 둔다
    def test_missing_tail_keeps_url_without_timestamp(self):
        records, coverage = self.read("Session_4", (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tail=False)))
        record, = records
        self.assertEqual(record.observed["url"], SNSS_TEMPORARY_CHAT_URL)
        self.assertIsNone(record.timestamp_raw)
        self.assertIn(p.SNSS_NAVIGATION_TAIL_UNPARSED, record.warnings)
        self.assertIn(p.SNSS_NAVIGATION_TIMESTAMP_ABSENT, record.warnings)
        self.assertEqual(coverage.status, "PARTIAL")

    # SNSS 7 — SNSS 가 아닌 파일 / Session_·Tabs_ 가 아닌 이름
    def test_not_supported_files(self):
        path = self.write("Session_5", b"NOTSNSS" + b"\x00" * 16)
        _, coverage = p.read_chrome_session_file(self.source, path)
        self.assertEqual((coverage.status, coverage.warnings), ("NOT_SUPPORTED", [p.SNSS_FORMAT_NOT_SUPPORTED]))
        other = self.write("Session_Blocklist", snss_file())
        _, coverage = p.read_chrome_session_file(self.source, self.write("LOG", snss_file()))
        self.assertEqual((coverage.status, coverage.warnings), ("NOT_SUPPORTED", [p.SNSS_FILE_KIND_UNKNOWN]))
        self.assertTrue(other)

    # SNSS 8 — 인증 query 값은 Record 에 남기지 않는다
    def test_auth_query_is_redacted(self):
        records, _ = self.read("Session_6", (6, snss_navigation(
            "https://chatgpt.com/api/auth/callback/openai?code=SECRETVALUE&state=SECRETSTATE")))
        observed = records[0].observed
        self.assertNotIn("SECRETVALUE", observed["url"])
        self.assertEqual(observed["redacted_query_keys"], ["url.code", "url.state"])

    # SNSS 9 — 폴더 Coverage
    def test_folder_coverage(self):
        records, coverages = p.read_chrome_sessions(self.source, "Profile 1/Sessions")
        self.assertEqual([(c.source_path, c.status) for c in coverages], [("Profile 1/Sessions", "EMPTY")])
        self.write("Session_7", snss_file((6, snss_navigation(SNSS_TEMPORARY_CHAT_URL))))
        self.write("Tabs_8", snss_file((1, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tab_id=17553079))))
        self.write("LOG", b"text")  # Session_ / Tabs_ 가 아닌 파일은 대상이 아니다
        records, coverages = p.read_chrome_sessions(self.source, "Profile 1/Sessions")
        self.assertEqual([(c.source_path.rpartition("/")[2], c.status) for c in coverages],
                         [("Session_7", "PARSED"), ("Tabs_8", "PARSED")])
        self.assertEqual(len(records), 2)
        records, coverages = p.read_chrome_sessions(self.source, "Profile 9/Sessions")
        self.assertEqual([(c.source_path, c.status) for c in coverages], [("Profile 9/Sessions", "NOT_PRESENT")])


class TemporaryChatRuleTest(SnssReaderTest):
    """§8.14 CHATGPT_TEMPORARY_CHAT_001."""

    def events(self, *files):
        records, coverages = [], []
        for name, commands in files:
            self.write(name, snss_file(*commands))
        records, coverages = p.read_chrome_sessions(self.source, "Profile 1/Sessions", os_user="llmtest",
                                                    browser_profile="Profile 1")
        return p.detect_temporary_chat(records, coverages), records, coverages

    # TC 1
    def test_temporary_chat_event_fields(self):
        events, records, coverages = self.events(("Session_1", [(6, snss_navigation(SNSS_TEMPORARY_CHAT_URL))]))
        event, = events
        self.assertEqual((event.rule_id, event.action, event.action_status, event.confidence, event.rule_verification),
                         ("CHATGPT_TEMPORARY_CHAT_001", "TEMPORARY_CHAT", "DETECTED", "MEDIUM", "PARTIALLY_VERIFIED"))
        self.assertEqual(event.timestamp_kst, "2026-09-14T17:36:15.041619+09:00")
        self.assertEqual((event.primary_evidence[0].evidence_level, event.primary_evidence[0].artifact_type),
                         ("DIRECT", "sessions"))
        self.assertEqual(event.primary_evidence[0].source_sha256, coverages[0].source_sha256)
        self.assertEqual((event.os_user, event.browser_profile, event.device_attribution),
                         ("llmtest", "Profile 1", "UNKNOWN"))
        self.assertIn(p.REASON_RULE_PARTIALLY_VERIFIED, event.confidence_reason)
        self.assertTrue(event.limitations)

    # TC 2 — 일반 chatgpt.com URL / 대화 URL / 다른 query 는 Event 가 아니다
    def test_negative_urls(self):
        events, _, _ = self.events(("Session_1", [
            (6, snss_navigation("https://chatgpt.com/")),
            (6, snss_navigation("https://chatgpt.com/c/6aa7afa3-e810-83e8-b673-9143af4cd79b")),
            (6, snss_navigation("https://chatgpt.com/?account_switch_action=logout")),
            (6, snss_navigation("https://chatgpt.com/auth/logout")),
            (6, snss_navigation("https://chatgpt.com/?temporary-chat=false")),
        ]))
        self.assertEqual(events, [])

    # TC 3 — referrer / original_request_url 에만 있는 경우는 Event 가 아니다
    def test_temporary_chat_only_in_referrer_is_not_an_event(self):
        events, _, _ = self.events(("Session_1", [(6, snss_navigation("https://chatgpt.com/auth/logout",
                                                                      referrer=SNSS_TEMPORARY_CHAT_URL,
                                                                      original=SNSS_TEMPORARY_CHAT_URL))]))
        self.assertEqual(events, [])

    # TC 4 — 같은 navigation 이 여러 SNSS 파일에 중복 저장되면 Event 1건 + 보조 Evidence
    def test_duplicate_navigation_is_one_event(self):
        events, _, _ = self.events(
            ("Session_1", [(6, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tab_id=17553065))]),
            ("Tabs_2", [(1, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tab_id=17553079))]),
            ("Tabs_3", [(1, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tab_id=17553309))]),
        )
        event, = events
        self.assertEqual([e.evidence_level for e in event.supporting_evidence], ["SUPPORTING", "SUPPORTING"])
        self.assertIn(p.REASON_SUPPORTING_CORRELATED, event.confidence_reason)

    # TC 5 — navigation 시각이 다르면 별개 Event
    def test_different_timestamps_are_separate_events(self):
        events, _, _ = self.events(("Session_1", [
            (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL)),
            (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL, timestamp=SNSS_TIMESTAMP + 60_000_000)),
        ]))
        self.assertEqual(len(events), 2)

    # TC 6 — 시각이 없으면 CANDIDATE / LOW
    def test_missing_timestamp_is_candidate(self):
        events, _, _ = self.events(("Session_1", [(6, snss_navigation(SNSS_TEMPORARY_CHAT_URL, tail=False))]))
        event, = events
        self.assertEqual((event.action_status, event.confidence), ("CANDIDATE", "LOW"))
        self.assertIn(p.REASON_TIMESTAMP_MISSING, event.confidence_reason)

    # TC 7 — marker 문자열이나 특정 대화 ID 에 의존하지 않는다
    def test_rule_matches_structure_not_marker_strings(self):
        self.assertTrue(p.match_temporary_chat_url("https://chatgpt.com/?foo=bar&Temporary-Chat=TRUE"))
        self.assertFalse(p.match_temporary_chat_url("https://chatgpt.com.evil.example/?temporary-chat=true"))
        self.assertFalse(p.match_temporary_chat_url("https://notchatgpt.com/?temporary-chat=true"))
        self.assertFalse(p.match_temporary_chat_url("https://chatgpt.com/temporary-chat=true"))
        self.assertFalse(p.match_temporary_chat_url("https://gemini.google.com/?temporary-chat=true"))

    # TC 8 — 다른 Rule 의 Event 를 만들지 않는다 (회귀)
    def test_sessions_records_do_not_create_other_events(self):
        _, records, coverages = self.events(("Session_1", [(6, snss_navigation("https://chatgpt.com/auth/logout")),
                                                           (6, snss_navigation(SNSS_TEMPORARY_CHAT_URL))]))
        self.assertEqual([e.action for e in p.detect(records, coverages)], ["TEMPORARY_CHAT"])


# --- E03-04 CONVERSATION_RETRY (CHATGPT_CONVERSATION_RETRY_001, Cache 대화 응답 variant) ---------
# 조건은 구조(같은 부모 아래 assistant 응답 2개 이상 + message_type=variant)뿐이고 마커 문자열·GT label 을 쓰지 않는다.

def retry_nodes(*, variant_type="variant", variant_role="assistant", sibling_role="assistant",
                sibling_type="next", with_sibling=True, variant_create=1787221050.0):
    """user 부모 아래 assistant 응답 1~2개 (하나는 variant) — 조건 하나씩만 바꿔 negative 를 만든다."""
    children = ["m-assistant", "m-variant"] if with_sibling else ["m-variant"]
    nodes = [("root", None, ["m-user"], None),
             ("m-user", "root", children,
              cache_message("m-user", "user", {"content_type": "text", "parts": ["합성 질문"]}, CACHE_CREATE_RAW))]
    if with_sibling:
        nodes.append(("m-assistant", "m-user", [],
                      cache_message("m-assistant", sibling_role, {"content_type": "text", "parts": ["첫 응답"]},
                                    1787221040.5, message_type=sibling_type)))
    nodes.append(("m-variant", "m-user", [],
                  cache_message("m-variant", variant_role, {"content_type": "text", "parts": ["두 번째 응답"]},
                                variant_create, message_type=variant_type)))
    return nodes


class ConversationRetryRuleTest(CacheTestBase):
    def records_for(self, obj):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(obj)])
        return self.read()

    def events_for(self, obj):
        records, coverage = self.records_for(obj)
        return p.detect_conversation_retry(records, [coverage])

    def test_variant_sibling_response_is_detected(self):
        events = self.events_for(cache_conversation(nodes=retry_nodes()))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual((event.action, event.finding_type, event.action_status, event.confidence,
                          event.rule_id, event.rule_verification, event.device_attribution),
                         ("CONVERSATION_RETRY", "USER_ACTION", "DETECTED", "MEDIUM",
                          "CHATGPT_CONVERSATION_RETRY_001", "PARTIALLY_VERIFIED", "SERVER_SIDE_CACHE"))
        self.assertEqual((event.timestamp_raw, event.timestamp_utc, event.timestamp_kst, event.timestamp_type),
                         ("1787221050.0", "2026-08-20T10:17:30Z", "2026-08-20T19:17:30+09:00", "unix_s_decimal"))
        self.assertEqual(event.timestamp_source, "Cache.conversation.mapping[].message.create_time")
        self.assertEqual(event.confidence_reason,
                         ["RULE_PARTIALLY_VERIFIED", "SIBLING_VARIANT_RESPONSE", "NOT_UNIQUE_TO_ACTION",
                          "TIMESTAMP_EXPLAINED"])
        evidence = event.primary_evidence[0]
        self.assertEqual((evidence.evidence_level, evidence.artifact_type), ("SUPPORTING", "cache"))
        self.assertEqual(evidence.observed["variant_message_id"], "m-variant")
        self.assertEqual(evidence.observed["sibling_assistant_message_ids"], ["m-assistant"])
        self.assertEqual((evidence.observed["parent_role"], evidence.observed["assistant_children_count"]), ("user", 2))
        self.assertEqual(event.representative_evidence_id, evidence.evidence_id)
        self.assertTrue(event.limitations)

    def test_evidence_has_no_message_body_or_secret(self):
        event = self.events_for(cache_conversation(nodes=retry_nodes()))[0]
        dumped = json.dumps(result_to_dict_events(event), ensure_ascii=False)
        for secret in SECRET_CACHE_VALUES:
            self.assertNotIn(secret, dumped)
        for body in ("첫 응답", "두 번째 응답", "합성 질문"):
            self.assertNotIn(body, dumped)

    def test_plain_next_response_is_not_detected(self):
        self.assertEqual(self.events_for(cache_conversation(nodes=retry_nodes(variant_type="next"))), [])

    def test_conversation_without_branch_is_not_detected(self):
        nodes = [("root", None, ["m-user"], None),
                 ("m-user", "root", ["m-assistant"],
                  cache_message("m-user", "user", {"content_type": "text", "parts": ["질문"]}, CACHE_CREATE_RAW)),
                 ("m-assistant", "m-user", [],
                  cache_message("m-assistant", "assistant", {"content_type": "text", "parts": ["응답"]},
                                1787221040.5, message_type="next"))]
        self.assertEqual(self.events_for(cache_conversation(nodes=nodes)), [])

    def test_user_branch_and_tool_branch_are_not_detected(self):
        nodes = [("root", None, ["m-user", "m-user2"], None),
                 ("m-user", "root", ["m-tool", "m-tool2"],
                  cache_message("m-user", "user", {"content_type": "text", "parts": ["질문"]}, CACHE_CREATE_RAW)),
                 ("m-user2", "root", [],
                  cache_message("m-user2", "user", {"content_type": "text", "parts": ["편집한 질문"]}, 1787221060.0)),
                 ("m-tool", "m-user", [],
                  cache_message("m-tool", "tool", {"content_type": "execution_output", "text": "1"}, 1787221041.0,
                                name="python", message_type="next")),
                 ("m-tool2", "m-user", [],
                  cache_message("m-tool2", "tool", {"content_type": "execution_output", "text": "2"}, 1787221042.0,
                                name="python", message_type="next"))]
        self.assertEqual(self.events_for(cache_conversation(nodes=nodes)), [])

    def test_variant_without_assistant_sibling_is_not_detected(self):
        self.assertEqual(self.events_for(cache_conversation(nodes=retry_nodes(with_sibling=False))), [])
        self.assertEqual(self.events_for(cache_conversation(nodes=retry_nodes(sibling_role="tool"))), [])

    def test_malformed_structure_does_not_crash(self):
        broken = cache_conversation(nodes=retry_nodes())
        broken["mapping"]["m-variant"]["parent"] = None  # 부모 없음
        self.assertEqual(self.events_for(broken), [])
        record, coverage = self.records_for(cache_conversation(nodes=retry_nodes()))
        record[0].observed["conversation"] = {"mapping": "not-a-list"}
        self.assertEqual(p.detect_conversation_retry(record, [coverage]), [])
        record[0].observed["conversation"] = None
        self.assertEqual(p.detect_conversation_retry(record, [coverage]), [])
        record[0].observed.pop("conversation")
        self.assertEqual(p.detect_conversation_retry(record, [coverage]), [])

    def test_same_variant_in_two_cache_copies_is_one_event(self):
        other_dir = self.root / "Profile 1" / "Cache" / "Cache_Data"
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(cache_conversation(nodes=retry_nodes()))])
        build_blockfile_cache(other_dir, [self.conversation_entry(cache_conversation(nodes=retry_nodes()))])
        records, coverages = [], []
        for path, profile in (("Default/Cache/Cache_Data", "Default"), ("Profile 1/Cache/Cache_Data", "Profile 1")):
            found, coverage = p.read_chrome_cache(self.source, path, browser_profile=profile)
            records += found
            coverages.append(coverage)
        events = p.detect_conversation_retry(records, coverages)
        self.assertEqual([(e.action, len(e.supporting_evidence)) for e in events],
                         [("CONVERSATION_RETRY", 0), ("CONVERSATION_RETRY", 0)])  # Profile 이 다르면 합치지 않는다
        same_profile = [r for r in records]
        for record in same_profile:
            record.browser_profile = "Default"
        merged = p.detect_conversation_retry(same_profile, coverages)
        self.assertEqual(len(merged), 1)
        self.assertEqual([e.evidence_level for e in merged[0].supporting_evidence], ["SUPPORTING"])
        self.assertIn("SUPPORTING_CORRELATED", merged[0].confidence_reason)

    def test_detection_does_not_depend_on_marker_text(self):
        renamed = cache_conversation(nodes=retry_nodes())
        renamed["title"] = "제목 없는 대화"
        for node_id in ("m-user", "m-assistant", "m-variant"):
            renamed["mapping"][node_id]["message"]["content"]["parts"] = ["내용 없음"]
        self.assertEqual([e.action for e in self.events_for(renamed)], ["CONVERSATION_RETRY"])

    def test_timestamp_missing_downgrades_to_candidate(self):
        without_time = cache_conversation(nodes=retry_nodes(variant_create=None))
        events = self.events_for(without_time)
        self.assertEqual([(e.action_status, e.confidence) for e in events], [("CANDIDATE", "LOW")])
        self.assertIn("TIMESTAMP_MISSING", events[0].confidence_reason)

    def test_existing_rules_are_not_affected(self):
        build_blockfile_cache(self.cache_dir, [*self.noise_entries(),
                                               self.conversation_entry(cache_conversation(nodes=retry_nodes()))])
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, f"https://chatgpt.com/c/{CACHE_CONV_ID}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0)])
        result = p.run(self.source, "Default/History")
        self.assertEqual([e.action for e in result.events],
                         ["PROMPT_SEND", "CONVERSATION_RETRY", "CONVERSATION_ACCESS"])
        self.assertEqual(len(result.conversations), 1)


def result_to_dict_events(event):
    return json.loads(json.dumps(event, default=lambda o: o.__dict__, ensure_ascii=False))


# --- E05-01 / E05-03 FILE_UPLOAD (CHATGPT_FILE_UPLOAD_001, Cache user 메시지 첨부) ----------------
# 조건은 구조(user 메시지 metadata.attachments 에 source="local")뿐이고 파일명 마커·GT label 을 쓰지 않는다.

def upload_attachment(file_id="file-upload-1", name="합성 첨부.jpg", mime="image/jpeg", size=38024, source="local"):
    return {"id": file_id, "size": size, "name": name, "mime_type": mime, "source": source,
            "library_file_id": "libfile-1", "is_big_paste": False}


def upload_nodes(*, role="user", attachments=None, create_time=1787221050.0):
    """user 메시지 1건 + assistant 응답 1건 — 첨부 구조만 바꿔 negative 를 만든다."""
    if attachments is None:
        attachments = [upload_attachment()]
    return [("root", None, ["m-user"], None),
            ("m-user", "root", ["m-assistant"],
             cache_message("m-user", role, {"content_type": "text", "parts": ["합성 질문"]}, create_time,
                           attachments=attachments)),
            ("m-assistant", "m-user", [],
             cache_message("m-assistant", "assistant", {"content_type": "text", "parts": ["합성 응답 본문"]}, 1787221060.5,
                           message_type="next"))]


class FileUploadRuleTest(CacheTestBase):
    def records_for(self, obj):
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(obj)])
        return self.read()

    def events_for(self, obj):
        records, coverage = self.records_for(obj)
        return p.detect_file_upload(records, [coverage])

    def test_local_attachment_is_detected(self):
        events = self.events_for(cache_conversation(nodes=upload_nodes()))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual((event.action, event.finding_type, event.action_status, event.confidence,
                          event.rule_id, event.rule_verification, event.device_attribution),
                         ("FILE_UPLOAD", "USER_ACTION", "DETECTED", "MEDIUM",
                          "CHATGPT_FILE_UPLOAD_001", "VERIFIED", "SERVER_SIDE_CACHE"))
        self.assertEqual((event.timestamp_raw, event.timestamp_utc, event.timestamp_kst, event.timestamp_type),
                         ("1787221050.0", "2026-08-20T10:17:30Z", "2026-08-20T19:17:30+09:00", "unix_s_decimal"))
        self.assertEqual(event.timestamp_source, "Cache.conversation.mapping[].message.create_time")
        self.assertEqual(event.confidence_reason,
                         ["RULE_VERIFIED", "LOCAL_ATTACHMENT", "TIMESTAMP_APPROXIMATED"])
        evidence = event.primary_evidence[0]
        self.assertEqual((evidence.evidence_level, evidence.artifact_type), ("DIRECT", "cache"))
        self.assertEqual((evidence.observed["file_id"], evidence.observed["mime_type"],
                          evidence.observed["size_bytes"], evidence.observed["attachment_source"]),
                         ("file-upload-1", "image/jpeg", 38024, "local"))
        self.assertEqual(evidence.observed["message_id"], "m-user")
        self.assertEqual(event.representative_evidence_id, evidence.evidence_id)
        self.assertTrue(event.limitations)

    def test_document_attachment_keeps_mime_type(self):
        nodes = upload_nodes(attachments=[upload_attachment(file_id="file-doc", name="합성.pdf",
                                                            mime="application/pdf", size=26779)])
        event = self.events_for(cache_conversation(nodes=nodes))[0]
        self.assertEqual((event.action, event.primary_evidence[0].observed["mime_type"]),
                         ("FILE_UPLOAD", "application/pdf"))

    def test_two_attachments_in_one_message_are_two_events(self):
        nodes = upload_nodes(attachments=[upload_attachment(file_id="file-a"),
                                          upload_attachment(file_id="file-b", name="합성2.pdf", mime="application/pdf")])
        events = self.events_for(cache_conversation(nodes=nodes))
        self.assertEqual([e.primary_evidence[0].observed["file_id"] for e in events], ["file-a", "file-b"])

    def test_evidence_has_no_message_body_or_secret(self):
        event = self.events_for(cache_conversation(nodes=upload_nodes()))[0]
        dumped = json.dumps(result_to_dict_events(event), ensure_ascii=False)
        for secret in SECRET_CACHE_VALUES:
            self.assertNotIn(secret, dumped)
        for body in ("합성 질문", "합성 응답 본문"):
            self.assertNotIn(body, dumped)

    def test_message_without_attachment_is_not_detected(self):
        self.assertEqual(self.events_for(cache_conversation(nodes=upload_nodes(attachments=[]))), [])
        no_key = cache_conversation(nodes=upload_nodes())
        no_key["mapping"]["m-user"]["message"]["metadata"].pop("attachments")
        self.assertEqual(self.events_for(no_key), [])

    def test_non_local_source_is_not_detected(self):
        nodes = upload_nodes(attachments=[upload_attachment(source="gdrive")])
        self.assertEqual(self.events_for(cache_conversation(nodes=nodes)), [])

    def test_assistant_attachment_is_not_detected(self):
        self.assertEqual(self.events_for(cache_conversation(nodes=upload_nodes(role="assistant"))), [])

    def test_generated_image_without_attachment_is_not_detected(self):
        # 기본 합성 대화는 assistant 가 만든 image_asset_pointer 만 있고 attachments 가 없다
        self.assertEqual(self.events_for(cache_conversation()), [])

    def test_malformed_structure_does_not_crash(self):
        broken = cache_conversation(nodes=upload_nodes())
        broken["mapping"]["m-user"]["message"]["metadata"]["attachments"] = "not-a-list"
        self.assertEqual(self.events_for(broken), [])
        record, coverage = self.records_for(cache_conversation(nodes=upload_nodes()))
        record[0].observed["conversation"]["mapping"][1]["message"]["attachments"] = ["not-a-dict"]
        self.assertEqual(p.detect_file_upload(record, [coverage]), [])
        record[0].observed["conversation"] = None
        self.assertEqual(p.detect_file_upload(record, [coverage]), [])
        record[0].observed.pop("conversation")
        self.assertEqual(p.detect_file_upload(record, [coverage]), [])

    def test_same_attachment_in_two_cache_copies_is_one_event(self):
        other_dir = self.root / "Profile 1" / "Cache" / "Cache_Data"
        build_blockfile_cache(self.cache_dir, [self.conversation_entry(cache_conversation(nodes=upload_nodes()))])
        build_blockfile_cache(other_dir, [self.conversation_entry(cache_conversation(nodes=upload_nodes()))])
        records, coverages = [], []
        for path, profile in (("Default/Cache/Cache_Data", "Default"), ("Profile 1/Cache/Cache_Data", "Profile 1")):
            found, coverage = p.read_chrome_cache(self.source, path, browser_profile=profile)
            records += found
            coverages.append(coverage)
        self.assertEqual([(e.action, len(e.supporting_evidence)) for e in p.detect_file_upload(records, coverages)],
                         [("FILE_UPLOAD", 0), ("FILE_UPLOAD", 0)])  # Profile 이 다르면 합치지 않는다
        for record in records:
            record.browser_profile = "Default"
        merged = p.detect_file_upload(records, coverages)
        self.assertEqual(len(merged), 1)
        self.assertEqual([e.evidence_level for e in merged[0].supporting_evidence], ["DIRECT"])
        self.assertIn("SUPPORTING_CORRELATED", merged[0].confidence_reason)

    def test_detection_does_not_depend_on_file_name(self):
        nodes = upload_nodes(attachments=[upload_attachment(name="이름 없음")])
        renamed = cache_conversation(nodes=nodes)
        renamed["title"] = "제목 없는 대화"
        self.assertEqual([e.action for e in self.events_for(renamed)], ["FILE_UPLOAD"])

    def test_timestamp_missing_downgrades_to_candidate(self):
        events = self.events_for(cache_conversation(nodes=upload_nodes(create_time=None)))
        self.assertEqual([(e.action_status, e.confidence) for e in events], [("CANDIDATE", "LOW")])
        self.assertIn("TIMESTAMP_MISSING", events[0].confidence_reason)

    def test_existing_rules_are_not_affected(self):
        build_blockfile_cache(self.cache_dir, [*self.noise_entries(),
                                               self.conversation_entry(cache_conversation(nodes=upload_nodes()))])
        create_history_db(self.root / "Default" / "History",
                          urls=[(1, f"https://chatgpt.com/c/{CACHE_CONV_ID}", "대화")],
                          visits=[(1, 1, 13432490000000000, 0, 0x30000000, "", 0)])
        result = p.run(self.source, "Default/History")
        # Event 는 시각순 정렬: 첨부 2026-08-20 < 방문 2026-08-30. 같은 user 메시지에서 PROMPT_SEND 도 함께 나온다.
        self.assertEqual([e.action for e in result.events],
                         ["FILE_UPLOAD", "PROMPT_SEND", "CONVERSATION_ACCESS"])
        self.assertEqual(len(result.conversations), 1)


# --- 최종 사용자용 CSV 2종 (timeline.csv / recovered_conversations.csv) --------------------------
# 새 판정을 만들지 않는 파생 산출물이다 — 행 수가 Event 수 · 복구된 메시지 수와 정확히 일치해야 한다.

class FinalCsvExportTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="csv-final-"))
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def read_csv(self, name):
        with open(self.dir / name, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        return rows[0], rows[1:]

    def export(self, result):
        return p.write_result_csv(result, self.dir)

    def test_timeline_columns_are_exact_and_ordered(self):
        self.export(make_result())
        header, _ = self.read_csv("timeline.csv")
        self.assertEqual(header, ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                                  "Artifact_path", "Artifact_details "])

    def test_timeline_keeps_team_trailing_spaces(self):
        """팀 샘플 컬럼명 끝 공백 1개는 실제 문자다 - 정규화하면 샘플과 어긋난다."""
        self.export(make_result())
        header, _ = self.read_csv("timeline.csv")
        self.assertIn("Behavior_details ", header)
        self.assertIn("Artifact_details ", header)
        self.assertNotIn("Behavior_details", header)  # 공백 없는 이름은 없어야 한다
        self.assertNotIn("Artifact_details", header)

    def test_timeline_row_count_equals_event_count(self):
        result = make_result()
        self.export(result)
        _, rows = self.read_csv("timeline.csv")
        self.assertEqual(len(rows), len(result.events))

    def test_timeline_is_sorted_by_timestamp_and_has_no_duplicate_event(self):
        result = make_result()
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        stamps = [dict(zip(header, row))["Timestamp"] for row in rows if dict(zip(header, row))["Timestamp"]]
        self.assertEqual(stamps, sorted(stamps))  # run() 이 시각순으로 정렬한 순서를 그대로 쓴다
        self.assertEqual(len(rows), len({tuple(row) for row in rows}))

    def test_timeline_model_is_team_value(self):
        self.export(make_result())
        header, rows = self.read_csv("timeline.csv")
        self.assertEqual({dict(zip(header, row))["Model"] for row in rows}, {"chatgpt-web"})

    def test_timeline_keeps_rule_id_status_and_kst_timestamp(self):
        result = make_result()
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        by_rule = {}
        for row in rows:
            cells = dict(zip(header, row))
            by_rule[cells["Artifact_details "].split("rule_id=")[1].split(" | ")[0]] = cells
        for event in result.events:
            row = by_rule[event.rule_id]
            self.assertEqual(row["Timestamp"], p.csv_final_timestamp(event.timestamp_kst) or "")
            self.assertIn(f"confidence={event.confidence}", row["Artifact_details "])  # 내부 상세는 이 칸에 남는다
            self.assertIn("KST", row["Timestamp"] or "KST")

    def test_final_timestamp_uses_team_notation_without_fake_precision(self):
        """팀 표기는 "YYYY-MM-DD HH:MM:SS[.ffffff] KST" — 소수 자리를 늘리거나 줄이지 않는다."""
        self.assertEqual(p.csv_final_timestamp("2026-09-01T18:41:00.065000+09:00"),
                         "2026-09-01 18:41:00.065000 KST")
        self.assertEqual(p.csv_final_timestamp("2026-09-01T18:06:16+09:00"), "2026-09-01 18:06:16 KST")
        self.assertEqual(p.csv_final_timestamp("2026-09-01T18:06:16.5+09:00"), "2026-09-01 18:06:16.5 KST")
        self.assertIsNone(p.csv_final_timestamp(None))
        self.assertEqual(p.csv_final_timestamp("2026-09-01T09:41:00Z"), "2026-09-01T09:41:00Z")  # KST 아니면 그대로

    def test_final_timestamp_applies_to_both_csv(self):
        result = make_result()
        result.conversations = [make_conversation()]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        for row in rows:
            stamp = dict(zip(header, row))["Timestamp"]
            if stamp:
                self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? KST$")
        header, rows = self.read_csv("recovered_conversations.csv")
        for row in rows:
            stamp = dict(zip(header, row))["timestamp"]
            if stamp:
                self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? KST$")

    def test_timeline_verdict_maps_detected_and_candidate(self):
        result = make_result()
        detected, candidate = make_event(), make_event(event_id="event:2", action_status="CANDIDATE")
        detected.action_status = "DETECTED"
        result.events = [detected, candidate]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        self.assertEqual([dict(zip(header, row))["Verdict"] for row in rows], ["확정", "의심"])

    def test_timeline_user_behavior_uses_korean_label_or_keeps_action(self):
        result = make_result()
        known, unknown = make_event(), make_event(event_id="event:2")
        known.action, unknown.action = "ACCOUNT_SWITCH", "SOME_FUTURE_ACTION"
        result.events = [known, unknown]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        behaviors = [dict(zip(header, row))["User_behavior"] for row in rows]
        self.assertEqual(behaviors, ["계정 변경", "SOME_FUTURE_ACTION"])  # 모르는 action 은 번역하지 않는다

    def test_timeline_builds_artifact_path_and_behavior_details(self):
        result = make_result()
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        row = dict(zip(header, rows[0]))
        event = result.events[0]
        evidence = event.primary_evidence[0]
        self.assertIn(evidence.source_path, row["Artifact_path"])
        if evidence.record_location:  # record 상세는 경로가 아니라 Artifact_details 칸에 둔다
            self.assertNotIn(evidence.record_location, row["Artifact_path"])
            self.assertIn(f"record={evidence.record_location}", row["Artifact_details "])
        self.assertNotIn("#", row["Artifact_path"])
        self.assertIn(evidence.evidence_level, row["Behavior_details "])
        self.assertIn(f"artifact_type={evidence.artifact_type}", row["Artifact_details "])
        # 두 칸의 역할이 다르다 - 같은 문장을 그대로 복제하지 않는다
        self.assertNotEqual(row["Behavior_details "], row["Artifact_details "])

    def test_timeline_conversation_id_is_empty_when_not_observed(self):
        event = make_event()
        event.primary_evidence[0].observed = {"url": "https://chatgpt.com/auth/logout"}
        result = make_result()
        result.events = [event]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        self.assertNotIn("conversation_id=", dict(zip(header, rows[0]))["Behavior_details "])

    def test_timeline_conversation_id_comes_from_observed_evidence(self):
        event = make_event()
        event.primary_evidence[0].observed = {"conversation_id": "conv-xyz"}
        result = make_result()
        result.events = [event]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        self.assertIn("conversation_id=conv-xyz", dict(zip(header, rows[0]))["Behavior_details "])

    def test_timeline_redacts_auth_query_values(self):
        event = make_event()
        event.primary_evidence[0].note = ("https://chatgpt.com/auth/callback"
                                          "?code=SECRETAUTHCODE&state=SECRETSTATE&access_token=SECRETTOKEN")
        event.primary_evidence[0].record_location = "urls.id=1"
        result = make_result()
        result.events = [event]
        self.export(result)
        header, rows = self.read_csv("timeline.csv")
        row = dict(zip(header, rows[0]))
        for secret in ("SECRETAUTHCODE", "SECRETSTATE", "SECRETTOKEN"):
            self.assertNotIn(secret, row["Behavior_details "])
        self.assertIn("REDACTED", row["Behavior_details "])

    def test_recovered_conversations_columns_are_exact_and_ordered(self):
        self.export(make_result())
        header, _ = self.read_csv("recovered_conversations.csv")
        self.assertEqual(header, ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                                  "parent_message_uuid", "message order", "role", "content", "Artifact_path"])

    def test_recovered_conversations_keeps_space_in_message_order(self):
        """팀 샘플의 "message order" 는 underscore 가 아니라 공백이다."""
        self.export(make_result())
        header, _ = self.read_csv("recovered_conversations.csv")
        self.assertIn("message order", header)
        self.assertNotIn("message_order", header)

    def test_recovered_conversations_has_header_only_when_no_message(self):
        result = make_result()
        result.conversations = [make_conversation(messages=[], recovery_status="RESIDUAL_ONLY")]
        self.export(result)
        header, rows = self.read_csv("recovered_conversations.csv")
        self.assertTrue(header)  # 파일은 만들되
        self.assertEqual(rows, [])  # row 는 0건 - 복구되지 않은 내용을 채우지 않는다

    def test_recovered_conversations_preserves_recovered_message(self):
        result = make_result()
        conversation = make_conversation()
        result.conversations = [conversation]
        self.export(result)
        header, rows = self.read_csv("recovered_conversations.csv")
        self.assertEqual(len(rows), len(conversation.messages))
        first, second = (dict(zip(header, row)) for row in rows)
        self.assertEqual([first["message order"], second["message order"]], ["0", "1"])  # 대화·메시지 순서 유지
        self.assertEqual([first["role"], second["role"]], ["user", "assistant"])
        self.assertEqual(first["content"], conversation.messages[0].content)  # 절단 없음
        self.assertEqual(second["content"], conversation.messages[1].content)
        self.assertEqual(first["parent_message_uuid"], "")
        self.assertEqual(second["parent_message_uuid"], "msg-0")
        self.assertEqual(first["conversation_uuid"], "conv-1")
        self.assertEqual(first["message_uuid"], "msg-0")
        self.assertEqual(first["conversation_title"], conversation.title)
        self.assertEqual(first["timestamp"], p.csv_final_timestamp(conversation.messages[0].timestamp_kst))
        self.assertEqual(first["Model"], "chatgpt-web")

    def test_recovered_conversations_artifact_path_is_a_plain_source_file(self):
        """Artifact_path 는 실제 복구 원본 파일 경로만이다 — entry·offset·mapping 을 붙이지 않는다."""
        message = make_message(0, source_path="Default/Cache/Cache_Data",
                               record_location=("file=data_3 entry=0xa0010647 stream1=0xc2030328 "
                                                "carved=data_1@offset=419584 mapping=abc"))
        result = make_result()
        result.conversations = [make_conversation(messages=[message])]
        self.export(result)
        header, rows = self.read_csv("recovered_conversations.csv")
        self.assertEqual(dict(zip(header, rows[0]))["Artifact_path"], "Default/Cache/Cache_Data/data_3")

    def test_recovered_conversations_artifact_path_keeps_folder_when_file_unknown(self):
        """파일을 특정할 수 없으면 경로를 만들어 내지 않고 알고 있는 만큼만 남긴다."""
        message = make_message(0, source_path="Default/Cache/Cache_Data", record_location="entry=0xa0010647")
        result = make_result()
        result.conversations = [make_conversation(messages=[message])]
        self.export(result)
        header, rows = self.read_csv("recovered_conversations.csv")
        self.assertEqual(dict(zip(header, rows[0]))["Artifact_path"], "Default/Cache/Cache_Data")

    def test_cache_address_file_resolves_real_data_file(self):
        """CacheAddr 해석: block file 은 data_N, 외부 파일은 f_xxxxxx. 해석 못 하면 None."""
        self.assertEqual(p._cache_address_file(0xc2030328), "data_3")
        self.assertEqual(p._cache_address_file(0xa0010647), "data_1")
        self.assertEqual(p._cache_address_file(0x8000014e), "f_00014e")
        self.assertIsNone(p._cache_address_file(0x00030328))  # initialized bit 없음

    def test_recovered_conversations_keeps_partial_status_and_unknown_role(self):
        message = make_message(0, recovery_status="PARTIAL", content=None, role="UNKNOWN", timestamp_kst=None,
                               timestamp_raw=None, timestamp_utc=None, timestamp_type="unknown", timestamp_source=None)
        result = make_result()
        result.conversations = [make_conversation(messages=[message], recovery_status="PARTIAL")]
        self.export(result)
        header, rows = self.read_csv("recovered_conversations.csv")
        row = dict(zip(header, rows[0]))
        self.assertEqual((row["role"], row["content"], row["timestamp"]), ("UNKNOWN", "", ""))

    def test_debug_output_keeps_detailed_internal_fields(self):
        """최종 CSV 에서 빠진 상세 정보는 --debug-output 쪽에 그대로 남아 있어야 한다."""
        result = make_result()
        result.conversations = [make_conversation()]
        written = p.write_result_csv(result, self.dir, debug=True)
        self.assertEqual(len(written), 7)
        events_header, _ = self.read_csv("events.csv")
        for column in ("action", "action_status", "confidence", "rule_id", "rule_verification"):
            self.assertIn(column, events_header)
        messages_header, _ = self.read_csv("messages.csv")
        for column in ("recovery_status", "source_artifact", "source_path", "record_location"):
            self.assertIn(column, messages_header)

    def test_default_export_writes_only_two_files(self):
        self.export(make_result())
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()),
                         ["recovered_conversations.csv", "timeline.csv"])

    def test_final_csv_has_no_secret_value(self):
        result = make_result()
        result.conversations = [make_conversation()]
        self.export(result)
        for name in ("timeline.csv", "recovered_conversations.csv"):
            text = (self.dir / name).read_text(encoding="utf-8-sig")
            for secret in ("session-token", "Bearer ", "__Secure-next-auth"):
                self.assertNotIn(secret, text)


# --- 행위 Rule 9종 (PROMPT_SEND · FILE_UPLOAD_DELETE · SHARE_LINK · MODEL_CHANGE · ACCOUNT_NAME_CHANGE ·
#     HISTORY_DELETE · CONVERSATION_DELETE · CACHE_DELETE · INCOGNITO) -----------------------------
# 모두 heuristic Rule 이라 기대값은 CANDIDATE 고정이고 HIGH 는 나오지 않는다.
# Rule 마다 positive / negative / 약한 근거 / 잘못된 구조 / 무관한 Artifact / 중복 억제를 본다.

NEW_RULE_CONV_ID = "11111111-2222-4333-8444-555555555555"


def kst_of(utc):
    return (datetime.strptime(utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            .astimezone(timezone(timedelta(hours=9))).isoformat())


def cache_record(nodes, *, record_id="c1", conversation_id=NEW_RULE_CONV_ID, source_path="Default/Cache/data_1",
                 utc="2026-08-20T10:00:00Z", **observed_extra):
    """mapping node 목록 → Cache 대화 응답 Record (Reader 가 만드는 구조와 같은 모양)."""
    observed = {"url": f"https://chatgpt.com/backend-api/conversation/{conversation_id}",
                "cache_key_kind": "conversation_response", "url_conversation_id": conversation_id,
                "conversation": {"conversation_id": conversation_id, "title": "합성 대화",
                                 "mapping": list(nodes)}}
    observed.update(observed_extra)
    return make_record(record_id=record_id, artifact_type="cache", source_path=source_path, record_location="entry=1",
                       timestamp_raw="13432490000000000", timestamp_utc=utc, timestamp_kst=kst_of(utc),
                       timestamp_type="webkit_us", timestamp_source="Cache.entry.creation_time", observed=observed)


def msg_node(node_id, role, *, create_time=1787221050.0, model_slug=None, attachments=None, parent="root"):
    message = {"id": node_id, "role": role, "author_name": None, "create_time": create_time, "update_time": None,
               "status": "finished_successfully", "recipient": "all", "message_type": None,
               "content": {"content_type": "text", "parts": ["합성 본문"]}, "attachments": attachments,
               "model_slug": model_slug}
    return {"node_id": node_id, "message": message, "parent": parent, "children": []}


def local_attachment(file_id, *, name="합성.pdf", mime="application/pdf", source="local"):
    return {"id": file_id, "name": name, "mime_type": mime, "size": 100, "source": source, "library_file_id": None}


def ls_record(key_kind, observed, *, record_id="l1", sequence=10, utc="2026-08-20T09:00:00Z", operation="PUT"):
    values = {"key_kind": key_kind, "operation": operation, "sequence": sequence}
    values.update(observed)
    return make_record(record_id=record_id, artifact_type="local_storage",
                       source_path="Default/Local Storage/leveldb/000003.log", record_location=f"seq={sequence}",
                       timestamp_raw="1787221050000", timestamp_utc=utc, timestamp_kst=kst_of(utc),
                       timestamp_type="unix_ms", timestamp_source="LocalStorage.value.timestamp", observed=values)


class NewRuleAssertMixin:
    def assert_candidate(self, event, action, rule_id, confidence):
        self.assertEqual((event.action, event.finding_type, event.action_status, event.confidence, event.rule_id,
                          event.rule_verification),
                         (action, "USER_ACTION", "CANDIDATE", confidence, rule_id, "PARTIALLY_VERIFIED"))
        self.assertIn("HEURISTIC_RULE", event.confidence_reason)
        self.assertTrue(event.limitations and event.inference)


class PromptSendRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def test_user_message_creates_candidate_with_message_time(self):
        events = p.detect_prompt_send([cache_record([msg_node("m-user", "user")])])
        self.assertEqual(len(events), 1)
        self.assert_candidate(events[0], "PROMPT_SEND", "CHATGPT_PROMPT_SEND_001", "MEDIUM")
        self.assertEqual((events[0].timestamp_raw, events[0].timestamp_kst, events[0].device_attribution),
                         ("1787221050.0", "2026-08-20T19:17:30+09:00", "SERVER_SIDE_CACHE"))
        self.assertEqual(events[0].primary_evidence[0].evidence_level, "SUPPORTING")  # DIRECT 아님

    def test_message_body_is_not_copied_into_evidence(self):
        event = p.detect_prompt_send([cache_record([msg_node("m-user", "user")])])[0]
        text = json.dumps(result_to_dict_events(event), ensure_ascii=False)
        self.assertNotIn("합성 본문", text)

    def test_missing_message_time_drops_confidence_to_low(self):
        events = p.detect_prompt_send([cache_record([msg_node("m-user", "user", create_time=None)])])
        self.assert_candidate(events[0], "PROMPT_SEND", "CHATGPT_PROMPT_SEND_001", "LOW")
        self.assertIsNone(events[0].timestamp_utc)  # 시각을 만들어 내지 않는다
        self.assertIn("TIMESTAMP_MISSING", events[0].confidence_reason)

    def test_assistant_only_conversation_creates_no_event(self):
        self.assertEqual(p.detect_prompt_send([cache_record([msg_node("m-a", "assistant")])]), [])

    def test_malformed_and_unrelated_records_are_ignored(self):
        broken = cache_record([])
        broken.observed["conversation"] = {"mapping": "not-a-list"}
        self.assertEqual(p.detect_prompt_send([broken, make_record()]), [])

    def test_same_message_in_two_cache_copies_is_one_event(self):
        events = p.detect_prompt_send([cache_record([msg_node("m-user", "user")], record_id="c1"),
                                       cache_record([msg_node("m-user", "user")], record_id="c2",
                                                    source_path="Default/Cache/data_2")])
        self.assertEqual(len(events), 1)
        self.assertEqual(len(events[0].supporting_evidence), 1)

    def test_draft_cleared_transition_is_low_and_only_without_message(self):
        drafts = [ls_record("conversation_drafts", {"drafts": [{"id": "d1"}]}, record_id="l1", sequence=10),
                  ls_record("conversation_drafts", {"drafts": []}, record_id="l2", sequence=20)]
        events = p.detect_prompt_send(drafts)
        self.assert_candidate(events[0], "PROMPT_SEND", "CHATGPT_PROMPT_SEND_001", "LOW")
        self.assertIn("DRAFT_CLEARED_AFTER_NON_EMPTY", events[0].confidence_reason)
        with_message = p.detect_prompt_send(drafts + [cache_record([msg_node("m-user", "user")])])
        self.assertEqual([e.confidence_reason[1] for e in with_message], ["USER_MESSAGE_PRESENT"])

    def test_empty_then_non_empty_draft_is_not_an_event(self):
        self.assertEqual(p.detect_prompt_send(
            [ls_record("conversation_drafts", {"drafts": []}, record_id="l1", sequence=10),
             ls_record("conversation_drafts", {"drafts": [{"id": "d1"}]}, record_id="l2", sequence=20)]), [])


class FileUploadDeleteRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def copies(self, before, after):
        return [cache_record([msg_node("m-user", "user", attachments=before)], record_id="c1",
                             utc="2026-08-20T10:00:00Z"),
                cache_record([msg_node("m-user", "user", attachments=after)], record_id="c2",
                             source_path="Default/Cache/data_2", utc="2026-08-20T11:00:00Z")]

    def test_attachment_disappearing_between_copies_is_candidate_low(self):
        events = p.detect_file_upload_delete(self.copies([local_attachment("file-a")], []))
        self.assertEqual(len(events), 1)
        self.assert_candidate(events[0], "FILE_UPLOAD_DELETE", "CHATGPT_FILE_UPLOAD_DELETE_001", "LOW")
        observed = events[0].primary_evidence[0].observed
        self.assertEqual((observed["removed_file_id"], observed["mime_type"], observed["file_name"]),
                         ("file-a", "application/pdf", "합성.pdf"))
        self.assertEqual(events[0].timestamp_kst, kst_of("2026-08-20T11:00:00Z"))

    def test_attachment_still_present_creates_no_event(self):
        self.assertEqual(p.detect_file_upload_delete(
            self.copies([local_attachment("file-a")], [local_attachment("file-a")])), [])

    def test_added_attachment_is_not_a_deletion(self):
        self.assertEqual(p.detect_file_upload_delete(
            self.copies([local_attachment("file-a")], [local_attachment("file-b")])), [])

    def test_single_copy_creates_no_event(self):
        self.assertEqual(p.detect_file_upload_delete([self.copies([local_attachment("file-a")], [])[0]]), [])

    def test_remote_attachment_is_out_of_scope(self):
        self.assertEqual(p.detect_file_upload_delete(
            self.copies([local_attachment("file-a", source="remote")], [])), [])

    def test_malformed_and_unrelated_records_are_ignored(self):
        broken = cache_record([{"node_id": "x", "message": "not-a-dict", "parent": None, "children": []}])
        self.assertEqual(p.detect_file_upload_delete([broken, make_record()]), [])

    def test_two_conversations_do_not_mix(self):
        other = cache_record([msg_node("m-user", "user", attachments=[local_attachment("file-a")])], record_id="c3",
                             conversation_id="99999999-2222-4333-8444-555555555555")
        self.assertEqual(p.detect_file_upload_delete([other, self.copies([local_attachment("file-a")], [])[0]]), [])


class ShareLinkRuleTest(NewRuleAssertMixin, unittest.TestCase):
    SHARE_URL = "https://chatgpt.com/share/abcd1234-5678-4000-8000-000000000001"

    def test_share_view_url_is_candidate_medium(self):
        events = p.detect_share_link([make_record(observed={"url": self.SHARE_URL})])
        self.assert_candidate(events[0], "SHARE_LINK", "CHATGPT_SHARE_LINK_001", "MEDIUM")
        self.assertEqual(events[0].primary_evidence[0].observed["share_url_kind"], "share_view")

    def test_share_api_url_is_only_low(self):
        events = p.detect_share_link([make_record(
            observed={"url": "https://chatgpt.com/backend-api/conversation/x/share"})])
        self.assert_candidate(events[0], "SHARE_LINK", "CHATGPT_SHARE_LINK_001", "LOW")

    def test_url_query_is_redacted(self):
        events = p.detect_share_link([make_record(observed={"url": self.SHARE_URL + "?token=SECRETSHARETOKEN"})])
        self.assertNotIn("SECRETSHARETOKEN", json.dumps(result_to_dict_events(events[0]), ensure_ascii=False))

    def test_ordinary_chatgpt_url_creates_no_event(self):
        self.assertEqual(p.detect_share_link(
            [make_record(observed={"url": f"https://chatgpt.com/c/{NEW_RULE_CONV_ID}"})]), [])

    def test_other_site_share_url_creates_no_event(self):
        self.assertEqual(p.detect_share_link([make_record(observed={"url": "https://example.com/share/abc"})]), [])

    def test_malformed_url_value_is_ignored(self):
        self.assertEqual(p.detect_share_link([make_record(observed={"url": 12345}), make_record(observed={})]), [])

    def test_same_url_in_two_artifacts_is_one_event(self):
        events = p.detect_share_link([
            make_record(record_id="r1", observed={"url": self.SHARE_URL}),
            make_record(record_id="r2", artifact_type="sessions", source_path="Default/Sessions/Session_1",
                        observed={"url": self.SHARE_URL})])
        self.assertEqual(len(events), 1)
        self.assertEqual(len(events[0].supporting_evidence), 1)


class ModelChangeRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def nodes(self, first, second):
        return [msg_node("m-a1", "assistant", create_time=1787221050.0, model_slug=first),
                msg_node("m-a2", "assistant", create_time=1787221060.0, model_slug=second)]

    def test_model_slug_transition_is_candidate_medium(self):
        events = p.detect_model_change([cache_record(self.nodes("gpt-4o", "o3"))])
        self.assert_candidate(events[0], "MODEL_CHANGE", "CHATGPT_MODEL_CHANGE_001", "MEDIUM")
        observed = events[0].primary_evidence[0].observed
        self.assertEqual((observed["model_slug_before"], observed["model_slug_after"]), ("gpt-4o", "o3"))
        self.assertEqual(events[0].timestamp_utc, "2026-08-20T10:17:40Z")

    def test_same_model_creates_no_event(self):
        self.assertEqual(p.detect_model_change([cache_record(self.nodes("auto", "auto"))]), [])

    def test_model_catalog_record_alone_creates_no_event(self):
        catalog = make_record(artifact_type="cache", source_path="Default/Cache/data_1",
                              observed={"url": "https://chatgpt.com/backend-api/models",
                                        "cache_key_kind": "other", "models": ["gpt-4o", "o3"]})
        self.assertEqual(p.detect_model_change([catalog]), [])

    def test_missing_model_slug_is_ignored(self):
        self.assertEqual(p.detect_model_change([cache_record(self.nodes(None, "o3"))]), [])

    def test_malformed_and_unrelated_records_are_ignored(self):
        broken = cache_record([])
        broken.observed["conversation"] = "not-a-dict"
        self.assertEqual(p.detect_model_change([broken, make_record()]), [])

    def test_duplicate_cache_copies_create_one_event(self):
        events = p.detect_model_change([cache_record(self.nodes("gpt-4o", "o3"), record_id="c1"),
                                        cache_record(self.nodes("gpt-4o", "o3"), record_id="c2",
                                                     source_path="Default/Cache/data_2")])
        self.assertEqual(len(events), 1)


class AccountNameChangeRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def sessions(self, name_hash, *, sequence, record_id, with_time=True):
        session = {"user_id_sha256_prefix": "user00", "account_name_sha256_prefix": name_hash,
                   "session_token_present": True,
                   "last_logged_in_at": {"timestamp_raw": "1787221050000", "timestamp_utc": "2026-08-20T10:17:30Z",
                                         "timestamp_kst": "2026-08-20T19:17:30+09:00", "timestamp_type": "unix_ms",
                                         "timestamp_source": "LocalStorage.accountSwitchSessions[].lastLoggedInAt"}
                   if with_time else None}
        return ls_record("account_switch_sessions", {"sessions": [session]}, record_id=record_id, sequence=sequence)

    def test_name_hash_transition_is_candidate_medium(self):
        events = p.detect_account_name_change([self.sessions("aaa", sequence=10, record_id="l1"),
                                               self.sessions("bbb", sequence=20, record_id="l2")])
        self.assert_candidate(events[0], "ACCOUNT_NAME_CHANGE", "CHATGPT_ACCOUNT_NAME_CHANGE_001", "MEDIUM")
        observed = events[0].primary_evidence[0].observed
        self.assertEqual((observed["account_name_sha256_prefix_before"], observed["account_name_sha256_prefix_after"]),
                         ("aaa", "bbb"))

    def test_single_name_creates_no_event(self):
        self.assertEqual(p.detect_account_name_change([self.sessions("aaa", sequence=10, record_id="l1")]), [])

    def test_same_name_creates_no_event(self):
        self.assertEqual(p.detect_account_name_change([self.sessions("aaa", sequence=10, record_id="l1"),
                                                       self.sessions("aaa", sequence=20, record_id="l2")]), [])

    def test_missing_time_drops_confidence_to_low(self):
        events = p.detect_account_name_change([self.sessions("aaa", sequence=10, record_id="l1"),
                                               self.sessions("bbb", sequence=20, record_id="l2", with_time=False)])
        self.assert_candidate(events[0], "ACCOUNT_NAME_CHANGE", "CHATGPT_ACCOUNT_NAME_CHANGE_001", "LOW")
        self.assertIsNone(events[0].timestamp_utc)

    def test_malformed_and_unrelated_records_are_ignored(self):
        broken = ls_record("account_switch_sessions", {"sessions": ["not-a-dict"]}, record_id="l1")
        self.assertEqual(p.detect_account_name_change([broken, make_record()]), [])


class HistoryDeleteRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def conversation_list(self):
        return ls_record("conversation_history",
                         {"conversation_items": [{"id": NEW_RULE_CONV_ID, "title": "합성"}],
                          "user_id_sha256_prefix": "user00", "cache_scope_sha256_prefix": "scope0"},
                         record_id="l1")

    def coverage(self, status="PARSED"):
        return p.Coverage(artifact_type="history", browser_profile="Default", source_path=HISTORY_PATH, status=status)

    def test_two_signals_create_candidate_low(self):
        events = p.detect_history_delete([self.conversation_list(),
                                          make_record(record_id="h1", timestamp_utc="2026-08-20T12:00:00Z")],
                                         [self.coverage()])
        self.assert_candidate(events[0], "HISTORY_DELETE", "CHATGPT_HISTORY_DELETE_001", "LOW")
        self.assertIsNone(events[0].timestamp_utc)  # 삭제 시각의 근거가 없다
        self.assertEqual({e.evidence_level for e in events[0].primary_evidence}, {"INFERRED"})

    def test_single_signal_creates_no_event(self):
        self.assertEqual(p.detect_history_delete([self.conversation_list()], []), [])

    def test_visits_only_without_conversation_list_create_no_event(self):
        self.assertEqual(p.detect_history_delete(
            [make_record(record_id="h1", timestamp_utc="2026-08-20T12:00:00Z")], [self.coverage()]), [])

    def test_visits_covering_all_conversations_create_no_event(self):
        visit = make_record(record_id="h1", timestamp_utc="2026-08-20T08:00:00Z",
                            observed={"url": f"https://chatgpt.com/c/{NEW_RULE_CONV_ID}"})
        self.assertEqual(p.detect_history_delete([self.conversation_list(), visit], [self.coverage()]), [])

    def test_activity_before_first_visit_is_a_second_signal_and_stays_low(self):
        visit = make_record(record_id="h1", timestamp_utc="2026-08-20T12:00:00Z",
                            observed={"url": "https://chatgpt.com/"})
        cache = cache_record([msg_node("m-user", "user")], utc="2026-08-01T00:00:00Z")
        events = p.detect_history_delete([self.conversation_list(), visit, cache], [self.coverage()])
        self.assert_candidate(events[0], "HISTORY_DELETE", "CHATGPT_HISTORY_DELETE_001", "LOW")
        self.assertIn("ACTIVITY_BEFORE_FIRST_VISIT", events[0].confidence_reason)
        self.assertIn("MULTIPLE_SUPPORTING_SIGNALS", events[0].confidence_reason)

    def test_malformed_conversation_items_are_ignored(self):
        broken = ls_record("conversation_history", {"conversation_items": "not-a-list"}, record_id="l1")
        self.assertEqual(p.detect_history_delete([broken], [self.coverage()]), [])


class ConversationDeleteRuleTest(NewRuleAssertMixin, unittest.TestCase):
    IDS = ("conv-a", "conv-b", "conv-c")

    def history(self, ids, *, sequence, record_id):
        return ls_record("conversation_history",
                         {"conversation_items": [{"id": i, "title": i} for i in ids],
                          "user_id_sha256_prefix": "user00", "cache_scope_sha256_prefix": "scope0"},
                         record_id=record_id, sequence=sequence)

    def test_single_removal_without_cache_is_candidate_medium(self):
        events = p.detect_conversation_delete([self.history(self.IDS, sequence=10, record_id="l1"),
                                               self.history(("conv-a", "conv-c"), sequence=20, record_id="l2")])
        self.assert_candidate(events[0], "CONVERSATION_DELETE", "CHATGPT_CONVERSATION_DELETE_001", "MEDIUM")
        self.assertEqual(events[0].primary_evidence[0].observed["removed_conversation_id"], "conv-b")

    def test_cache_response_of_removed_conversation_blocks_delete_interpretation(self):
        cache = cache_record([msg_node("m-user", "user")], conversation_id="conv-b")
        self.assertEqual(p.detect_conversation_delete(
            [self.history(self.IDS, sequence=10, record_id="l1"),
             self.history(("conv-a", "conv-c"), sequence=20, record_id="l2"), cache]), [])

    def test_conversation_returning_later_is_not_a_delete(self):
        self.assertEqual(p.detect_conversation_delete([
            self.history(self.IDS, sequence=10, record_id="l1"),
            self.history(("conv-a", "conv-c"), sequence=20, record_id="l2"),
            self.history(self.IDS, sequence=30, record_id="l3")]), [])

    def test_whole_list_disappearing_is_not_a_single_delete(self):
        self.assertEqual(p.detect_conversation_delete([
            self.history(self.IDS, sequence=10, record_id="l1"),
            self.history(("conv-a",), sequence=20, record_id="l2")]), [])

    def test_observed_fact_rule_still_reports_the_same_transition(self):
        records = [self.history(self.IDS, sequence=10, record_id="l1"),
                   self.history(("conv-a", "conv-c"), sequence=20, record_id="l2")]
        removed = p.detect_conversation_removed_from_list(records)
        self.assertEqual([e.action for e in removed], ["CONVERSATION_REMOVED_FROM_LIST"])  # 관찰 사실 Event 는 유지
        self.assertNotEqual(removed[0].event_id, p.detect_conversation_delete(records)[0].event_id)

    def test_malformed_and_unrelated_records_are_ignored(self):
        broken = ls_record("conversation_history", {"conversation_items": [{"id": None}]}, record_id="l1")
        self.assertEqual(p.detect_conversation_delete([broken, make_record()]), [])


class CacheDeleteRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def coverage(self, status="PARSED"):
        return p.Coverage(artifact_type="cache", browser_profile="Default", source_path="Default/Cache",
                          status=status, record_count=0)

    def conversation_list(self):
        return ls_record("conversation_history", {"conversation_items": [{"id": NEW_RULE_CONV_ID, "title": "합성"}]},
                         record_id="l1")

    def test_parsed_cache_without_entries_and_a_conversation_list_is_candidate_low(self):
        events = p.detect_cache_delete([self.conversation_list()], [self.coverage()])
        self.assert_candidate(events[0], "CACHE_DELETE", "CHATGPT_CACHE_DELETE_001", "LOW")
        self.assertIsNone(events[0].timestamp_utc)

    def test_remaining_conversation_response_blocks_the_event(self):
        self.assertEqual(p.detect_cache_delete([self.conversation_list(), cache_record([msg_node("m-user", "user")])],
                                               [self.coverage()]), [])

    def test_missing_cache_is_not_a_deletion(self):
        self.assertEqual(p.detect_cache_delete([self.conversation_list()], [self.coverage("NOT_PRESENT")]), [])

    def test_cache_without_any_other_chatgpt_trace_creates_no_event(self):
        self.assertEqual(p.detect_cache_delete([], [self.coverage()]), [])

    def test_visit_record_alone_is_also_a_signal(self):
        visit = make_record(record_id="h1", observed={"url": f"https://chatgpt.com/c/{NEW_RULE_CONV_ID}"})
        self.assertEqual(len(p.detect_cache_delete([visit], [self.coverage()])), 1)

    def test_unrelated_history_url_is_not_a_signal(self):
        self.assertEqual(p.detect_cache_delete([make_record(record_id="h1", observed={"url": "https://example.com/"})],
                                               [self.coverage()]), [])


class IncognitoRuleTest(NewRuleAssertMixin, unittest.TestCase):
    def test_command_line_flag_is_candidate_medium(self):
        events = p.detect_incognito([make_record(artifact_type="local_state", source_path="Local State",
                                                 observed={"command_line": "chrome.exe --incognito"})])
        self.assert_candidate(events[0], "INCOGNITO", "CHATGPT_INCOGNITO_001", "MEDIUM")
        self.assertEqual(events[0].primary_evidence[0].observed["marker"], "--incognito")

    def test_weak_marker_is_low(self):
        events = p.detect_incognito([make_record(artifact_type="preferences", source_path="Preferences",
                                                 timestamp_utc=None, timestamp_kst=None,
                                                 observed={"profile_label": "Incognito profile"})])
        self.assert_candidate(events[0], "INCOGNITO", "CHATGPT_INCOGNITO_001", "LOW")

    def test_absence_of_artifacts_creates_no_event(self):
        self.assertEqual(p.detect_incognito([]), [])

    def test_ordinary_records_create_no_event(self):
        self.assertEqual(p.detect_incognito([make_record(), cache_record([msg_node("m-user", "user")])]), [])

    def test_marker_value_is_not_copied_verbatim(self):
        event = p.detect_incognito([make_record(artifact_type="local_state", source_path="Local State",
                                                observed={"command_line": "chrome.exe --incognito SECRETARG"})])[0]
        self.assertNotIn("SECRETARG", json.dumps(result_to_dict_events(event), ensure_ascii=False))

    def test_non_string_values_are_ignored(self):
        self.assertEqual(p.detect_incognito([make_record(observed={"count": 3, "flag": None})]), [])


class NewRuleRegressionTest(unittest.TestCase):
    NEW_RULES = ("detect_prompt_send", "detect_file_upload_delete", "detect_share_link", "detect_model_change",
                 "detect_account_name_change", "detect_history_delete", "detect_conversation_delete",
                 "detect_cache_delete", "detect_incognito")

    def test_new_rules_are_registered_exactly_once(self):
        self.assertEqual(len(p.EVENT_RULES), 25)
        self.assertEqual(len(set(p.EVENT_RULES)), len(p.EVENT_RULES))
        for name in self.NEW_RULES:
            self.assertIn(getattr(p, name), p.EVENT_RULES)

    def test_empty_input_creates_no_event(self):
        self.assertEqual(p.detect([], []), [])

    def test_existing_history_rule_is_unchanged(self):
        self.assertEqual([(e.action, e.action_status, e.confidence) for e in p.detect([make_record()], [])],
                         [("LOGOUT", "DETECTED", "HIGH")])

    def test_heuristic_rules_never_return_high_confidence(self):
        records = [cache_record([msg_node("m-user", "user", model_slug="gpt-4o")]),
                   make_record(observed={"url": "https://chatgpt.com/share/abcd"})]
        heuristic = {"CHATGPT_PROMPT_SEND_001", "CHATGPT_SHARE_LINK_001", "CHATGPT_MODEL_CHANGE_001",
                     "CHATGPT_FILE_UPLOAD_DELETE_001", "CHATGPT_ACCOUNT_NAME_CHANGE_001",
                     "CHATGPT_HISTORY_DELETE_001", "CHATGPT_CONVERSATION_DELETE_001", "CHATGPT_CACHE_DELETE_001",
                     "CHATGPT_INCOGNITO_001"}
        found = [e for e in p.detect(records, []) if e.rule_id in heuristic]
        self.assertTrue(found)
        for event in found:
            self.assertEqual(event.action_status, "CANDIDATE")
            self.assertNotEqual(event.confidence, "HIGH")


if __name__ == "__main__":
    unittest.main()
