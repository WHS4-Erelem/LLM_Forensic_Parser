"""--dir (copied volume tree) and live-volume input: the one check that fails if the input layer breaks."""
from __future__ import annotations

import csv
import logging
import sqlite3
import struct
from pathlib import Path

import pytest

from claude_web_forensics.cli import main
from claude_web_forensics.discovery.environment import find_chrome_profiles, find_windows_installs
from claude_web_forensics.image.adapters import ImageOpenError, RawImage, is_device_path
from claude_web_forensics.image.volumes import DirectoryVolume

PROFILE = "Users/alice/AppData/Local/Google/Chrome/User Data/Default"

def _tree(root: Path) -> Path:
    profile = root / PROFILE
    profile.mkdir(parents=True)
    (profile.parent / "Local State").write_text("{}")
    db = sqlite3.connect(profile / "History")
    db.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,"
        " last_visit_time INTEGER, hidden INTEGER);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,"
        " transition INTEGER, segment_id INTEGER, visit_duration INTEGER);"
        "INSERT INTO urls VALUES(1,'https://claude.ai/new','Claude',1,0,13390000000000000,0);"
        "INSERT INTO visits VALUES(1,1,13390000000000000,0,805306368,0,0);"
    )
    db.commit()
    db.close()
    (root / "Users/alice/Downloads").mkdir()
    (root / "Users/alice/Downloads/a.pdf").write_bytes(b"%PDF-1.4 claude")
    (root / "Users/Public").mkdir()
    return root

def test_directory_volume_walks_the_users_tree(tmp_path):
    volume = DirectoryVolume(_tree(tmp_path / "vol"))
    installs = find_windows_installs([volume])
    assert [u.username for u in installs[0].users] == ["alice"]
    profiles = find_chrome_profiles(volume, installs[0].users[0])
    assert [p.source_path for p in profiles] == [f"/{PROFILE}"]
    assert volume.get(f"/{PROFILE}/History").size() > 0
    assert volume.get("/nope") is None and volume.listdir("/nope") == {}
    assert volume.data_streams(volume.get("/Users/alice/Downloads/a.pdf")) == []

def test_dir_mode_writes_both_csvs_with_image_logical_paths(tmp_path):
    root = _tree(tmp_path / "vol")
    out = tmp_path / "out"
    assert main(["analyze", "--dir", str(root), "--output", str(out), "--extended-fs", "--log-level", "ERROR"]) == 0
    rows = list(csv.reader((out / "timeline.csv").open(encoding="utf-8-sig")))
    assert rows[0][0] == "Model" and (out / "recovered_conversations.csv").exists()
    paths = "|".join(r[5] for r in rows[1:])
    assert "$MFT" not in paths and "staging" not in paths
    assert not paths or paths.startswith("C:\\Users\\alice\\")
    logging.getLogger("claude_web_forensics").handlers.clear()

def test_dir_mode_rejects_missing_folder_and_output_inside_it(tmp_path):
    assert main(["analyze", "--dir", str(tmp_path / "missing"), "--output", str(tmp_path / "o")]) == 2
    root = _tree(tmp_path / "vol")
    assert main(["analyze", "--dir", str(root), "--output", str(root / "o")]) == 2

def test_image_input_has_no_output_location_rule(tmp_path):
    image = tmp_path / "integration" / "case.dd"
    image.parent.mkdir()
    image.write_bytes(b"\0" * 4096)
    for out in (image.parent / "out" / "id" / "claude_web", image.parent, tmp_path):  # ARTINEX default -o out, beside, above
        assert main(["analyze", "--image", str(image), "--output", str(out), "--log-level", "ERROR"]) == 1  # not 2
    logging.getLogger("claude_web_forensics").handlers.clear()

def test_usn_reader_jumps_zero_runs_and_stops_where_stepping_by_8_would():
    import io

    from claude_web_forensics.parsers.extended_fs import CHUNK, iter_usn_records

    record = struct.pack("<IHHQQqqIIIIHH", 64, 2, 0, 5, 5, 1, 0, 0x100, 0, 0, 0x20, 2, 60) + "a".encode("utf-16-le") + b"\0\0"
    data = bytearray(CHUNK + 4096)
    at_record, at_junk = CHUNK + 16, CHUNK + 1024
    data[at_record:at_record + 64] = record
    data[CHUNK + 512 + 5] = 0xFF  # upper half of a slot: its length field is still 0, so it is skipped
    data[at_junk] = 7  # slot-aligned: an invalid length that must still be reported
    seen = [(r.offset, r.file_name) if r else (m["skip"], m["offset"]) for r, m in iter_usn_records(io.BytesIO(data))]
    assert seen == [(at_record, "a"), ("invalid_length", at_junk)]

def test_device_paths_are_recognised_and_need_ntfs(tmp_path, monkeypatch):
    assert is_device_path(r"\\.\C:") and is_device_path(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1")
    assert not is_device_path(tmp_path / "x.dd")
    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"\x00" * 3 + b"NTFS    " + struct.pack("<H", 512) + b"\x00" * 27 + struct.pack("<Q", 7) + b"\x00" * 464)
    monkeypatch.setattr("claude_web_forensics.image.adapters.is_device_path", lambda p: True)
    image = RawImage(fake)
    assert image.info.image_type == "live-volume" and image.info.logical_size == 8 * 512
    fake.write_bytes(b"\x00" * 512)
    with pytest.raises(ImageOpenError):
        RawImage(fake)
