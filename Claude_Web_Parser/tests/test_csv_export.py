"""timeline.csv / recovered_conversations.csv: format, paths, order and status."""
from __future__ import annotations

import csv
import re
import datetime as dt

import pytest

from claude_web_forensics.analysis.rules import label_for
from claude_web_forensics.model.entities import (
    FAMILY_CACHE,
    FAMILY_HISTORY,
    FAMILY_INDEXEDDB,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceRecord,
    EvidenceStore,
    FinalEvent,
    make_evidence_id,
)
from claude_web_forensics.model.entities import ConversationMessage
from claude_web_forensics.output.csv_export import (
    CONVERSATION_COLUMNS,
    CONVERSATIONS_FILE,
    MODEL_NAME,
    TIMELINE_COLUMNS,
    TIMELINE_FILE,
    ArtifactPathResolver,
    CsvExportError,
    build_conversation_rows,
    build_timeline_rows,
    message_order,
    write_csv,
    write_results,
)

KST = dt.timezone(dt.timedelta(hours=9))
T = dt.datetime(2026, 8, 22, 12, 0, tzinfo=KST)
PROFILE = "/Users/llmtest/AppData/Local/Google/Chrome/User Data/Default"
ROOT = "00000000-0000-4000-8000-000000000000"


def record(family, locator, artifact_path="", source_path=f"{PROFILE}/History",
           volume="vol-c", **attrs) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=make_evidence_id(family, source_path, locator, attrs),
        artifact=family, artifact_family=family, source_path=source_path,
        artifact_path=artifact_path, volume_id=volume, record_locator=locator,
        attributes=attrs,
    )


def make_store(*records) -> EvidenceStore:
    store = EvidenceStore()
    store.extend(records)
    return store


def resolver_for(store, letters=None):
    return ArtifactPathResolver(store=store, drive_letters=letters or {"vol-c": "C"})


def event(code="E05-05", verdict=VERDICT_CONFIRMED, refs=(), ts=T, detail="report.pdf",
          action_id=None, lines=None) -> FinalEvent:
    return FinalEvent(
        action_id=action_id or f"ACT-{code}-{ts}", timestamp=ts, action_code=code,
        action_label=label_for(code), verdict=verdict, action_detail=detail,
        evidence=[(ref, (lines or {}).get(ref, "")) for ref in refs], conversation_uuid="conv-1",
    )


def message(uuid, parent="", role="user", content="hi", ts=T, conv="c1", title="제목",
            evidence=()) -> ConversationMessage:
    return ConversationMessage(
        conversation_uuid=conv, message_uuid=uuid, parent_message_uuid=parent,
        conversation_title=title, timestamp=ts, role=role, content=content,
        model="claude-sonnet-5", input_mode="retry", is_temporary="False",
        account_uuid="acct", evidence_ids=list(evidence), families=["cache"],
        attributes={"attachments": [{"file_name": "x.png"}]},
    )


def read(path):
    csv.field_size_limit(2**31 - 1)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------

def test_timeline_header_is_exact():
    assert TIMELINE_COLUMNS == [
        "Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
        "Artifact_path", "Artifact_details ",
    ]
    assert len(TIMELINE_COLUMNS) == 7
    # The two detail headers keep their single trailing ASCII space.
    assert TIMELINE_COLUMNS[3] == "Behavior_details " and TIMELINE_COLUMNS[3].endswith(" ")
    assert TIMELINE_COLUMNS[6] == "Artifact_details " and TIMELINE_COLUMNS[6].endswith(" ")
    for dropped in ("accountuuid", "conversation_uuid", "모델명", "판정"):
        assert dropped not in TIMELINE_COLUMNS


def test_conversation_header_is_exact_and_dropped_columns_are_gone():
    assert CONVERSATION_COLUMNS == [
        "Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
        "parent_message_uuid", "message order", "role", "content", "Artifact_path",
    ]
    assert len(CONVERSATION_COLUMNS) == 10
    for dropped in ("model", "input_mode", "is_temporary", "accountuuid", "첨부파일",
                    "발견 근거", "content_part", "content_parts", "복구상태", "모델명",
                    "메시지 순서", "근거 아티팩트"):
        assert dropped not in CONVERSATION_COLUMNS


def test_empty_results_still_write_both_headers(tmp_path):
    write_results(tmp_path, [], [])
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([TIMELINE_FILE, CONVERSATIONS_FILE])
    assert read(tmp_path / TIMELINE_FILE) == [TIMELINE_COLUMNS]
    assert read(tmp_path / CONVERSATIONS_FILE) == [CONVERSATION_COLUMNS]


# ---------------------------------------------------------------------------
# timeline rows
# ---------------------------------------------------------------------------

def test_model_name_is_claude_web_everywhere(tmp_path):
    store = make_store()
    t_rows = build_timeline_rows([event(), event("E04-01", VERDICT_SUSPECTED)], resolver_for(store))
    c_rows = build_conversation_rows([message("m1", ROOT)], resolver_for(store))
    write_results(tmp_path, t_rows, c_rows)
    for name in (TIMELINE_FILE, CONVERSATIONS_FILE):
        rows = read(tmp_path / name)[1:]
        assert rows and {r[0] for r in rows} == {MODEL_NAME} == {"claude-web"}


def test_undetermined_is_never_exported():
    rows = build_timeline_rows(
        [event(), event("E06-03", VERDICT_UNDETERMINED)], resolver_for(make_store())
    )
    assert [r[4] for r in rows] == [VERDICT_CONFIRMED]


def test_artifact_path_is_the_logical_image_path_not_the_family_name():
    history = record(FAMILY_HISTORY, "h1", source_path=f"{PROFILE}/History")
    cache = record(FAMILY_CACHE, "c1", source_path=f"{PROFILE}/Cache/Cache_Data",
                   artifact_path=f"{PROFILE}/Cache/Cache_Data/data_3")
    cache2 = record(FAMILY_CACHE, "c2", source_path=f"{PROFILE}/Cache/Cache_Data",
                    artifact_path=f"{PROFILE}/Cache/Cache_Data/data_3")   # same file
    mft = record("mft", "m1", source_path="/Users/llmtest/Downloads/a.pdf", artifact_path="/$MFT")
    usn = record("usn", "u1", source_path="/$Extend/$UsnJrnl:$J")
    store = make_store(history, cache, cache2, mft, usn)
    lines = {
        history.evidence_id: "[History] 다운로드 상태=COMPLETE",
        cache.evidence_id: "[Cache] 유형=download_file",
        cache2.evidence_id: "[Cache] 두 번째 레코드",
        mft.evidence_id: "[$MFT] 경로=/Users/llmtest/Downloads/a.pdf",
    }
    row = build_timeline_rows(
        [event(refs=[history.evidence_id, cache.evidence_id, cache2.evidence_id,
                     mft.evidence_id, usn.evidence_id], lines=lines)],
        resolver_for(store),
    )[0]
    paths = row[5].split("|")
    base = r"C:\Users\llmtest\AppData\Local\Google\Chrome\User Data\Default"
    # Detector order (most direct first), duplicates removed.
    assert paths == [
        rf"{base}\History",
        rf"{base}\Cache\Cache_Data\data_3",
        r"C:\$MFT",
        r"C:\$Extend\$UsnJrnl:$J",
    ]
    for family_name in ("Cache", "History", "$MFT"):
        assert row[5] != family_name
    details = row[6].split("\n")
    # Exactly one detail line per path, in the same order.
    assert len(details) == len(paths)
    assert details[:3] == [
        "[History] 다운로드 상태=COMPLETE",
        "[Cache] 유형=download_file; 두 번째 레코드",       # same path: one merged line
        "[$MFT] 경로=/Users/llmtest/Downloads/a.pdf",
    ]
    assert details[3].startswith("[$UsnJrnl]")             # default summary of that record


def test_unknown_or_staging_paths_are_left_empty_not_invented():
    staging = record(FAMILY_CACHE, "s", source_path=r"C:\Temp\cwf_work_x\staging\Cache")
    no_path = record(FAMILY_HISTORY, "n", source_path="")
    store = make_store(staging, no_path)
    row = build_timeline_rows(
        [event(refs=[staging.evidence_id, no_path.evidence_id, "EV-missing"])],
        resolver_for(store),
    )[0]
    assert row[5] == ""
    assert row[6] == ""                                  # no path -> no detail line either


def test_unknown_drive_letter_keeps_the_volume_relative_path():
    rec = record("usn", "u", source_path="/$Extend/$UsnJrnl:$J", volume="vol-d")
    resolver = resolver_for(make_store(rec), letters={"vol-c": "C"})
    assert resolver.path_of(rec) == r"\$Extend\$UsnJrnl:$J"


def test_timeline_rows_are_sorted_deterministically():
    later = event("E05-05", ts=T + dt.timedelta(hours=1))
    earlier = event("E04-01", ts=T)
    undated = event("E03-01", ts=None)
    rows = build_timeline_rows([undated, later, earlier], resolver_for(make_store()))
    assert [r[2] for r in rows] == ["사용자 프롬프트 입력/전송", "문서 다운로드", "새로운 대화 생성"]
    again = build_timeline_rows([earlier, undated, later], resolver_for(make_store()))
    assert again == rows


# ---------------------------------------------------------------------------
# conversation rows
# ---------------------------------------------------------------------------

def test_message_order_follows_the_parent_chain_not_the_clock():
    # The reply's clock is earlier than its parent's, but the tree wins.
    root = message("m1", ROOT, ts=T + dt.timedelta(seconds=10))
    reply = message("m2", "m1", role="assistant", ts=T)
    follow = message("m3", "m2", ts=T + dt.timedelta(seconds=20))
    assert [m.message_uuid for m in message_order([follow, reply, root])] == ["m1", "m2", "m3"]


def test_retry_branches_are_ordered_by_time_then_uuid():
    root = message("m1", ROOT)
    a = message("m2b", "m1", role="assistant", ts=T + dt.timedelta(seconds=5))
    b = message("m2a", "m1", role="assistant", ts=T + dt.timedelta(seconds=5))
    c = message("m2c", "m1", role="assistant", ts=T + dt.timedelta(seconds=1))
    assert [m.message_uuid for m in message_order([a, b, c, root])] == ["m1", "m2c", "m2a", "m2b"]


def test_cycle_and_missing_parent_fall_back_to_time_order():
    orphan = message("o1", "not-in-this-conversation", ts=T + dt.timedelta(seconds=3))
    x = message("x", "y", ts=T + dt.timedelta(seconds=1))
    y = message("y", "x", ts=T + dt.timedelta(seconds=2))
    order = [m.message_uuid for m in message_order([y, orphan, x])]
    assert sorted(order) == ["o1", "x", "y"] and len(order) == 3
    assert order == [m.message_uuid for m in message_order([x, y, orphan])]


def test_order_restarts_per_conversation_without_gaps_or_duplicates():
    messages = [
        message("a1", ROOT, conv="ca"), message("a2", "a1", role="assistant", conv="ca"),
        message("a3", "a2", conv="ca"),
        message("b1", ROOT, conv="cb", ts=T + dt.timedelta(days=1)),
        message("b2", "b1", role="assistant", conv="cb", ts=T + dt.timedelta(days=1)),
    ]
    rows = build_conversation_rows(messages, resolver_for(make_store()))
    by_conv: dict[str, list[int]] = {}
    for row in rows:
        by_conv.setdefault(row[2], []).append(int(row[6]))
    assert by_conv == {"ca": [1, 2, 3], "cb": [1, 2]}


def test_conversation_evidence_paths_and_dropped_fields(tmp_path):
    idb = record(FAMILY_INDEXEDDB, "i", source_path=f"{PROFILE}/IndexedDB",
                 artifact_path=f"{PROFILE}/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000005.ldb")
    cache = record(FAMILY_CACHE, "c", source_path=f"{PROFILE}/Cache/Cache_Data",
                   artifact_path=f"{PROFILE}/Cache/Cache_Data/f_00000a")
    store = make_store(idb, cache)
    rows = build_conversation_rows(
        [message("m1", ROOT, evidence=[cache.evidence_id, idb.evidence_id, cache.evidence_id])],
        resolver_for(store),
    )
    write_results(tmp_path, [], rows)
    header, data = read(tmp_path / CONVERSATIONS_FILE)[0], read(tmp_path / CONVERSATIONS_FILE)[1]
    row = dict(zip(header, data))
    assert row["Artifact_path"].split("|") == sorted([
        r"C:\Users\llmtest\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_00000a",
        r"C:\Users\llmtest\AppData\Local\Google\Chrome\User Data\Default\IndexedDB"
        r"\https_claude.ai_0.indexeddb.leveldb\000005.ldb",
    ])
    assert row["message order"] == "1"
    joined = ",".join(data)
    for dropped_value in ("claude-sonnet-5", "retry", "x.png", "acct"):
        assert dropped_value not in joined


# ---------------------------------------------------------------------------
# CSV mechanics
# ---------------------------------------------------------------------------

def test_commas_quotes_and_newlines_stay_in_one_cell(tmp_path):
    content = 'line one, with comma\nline "two"\r\nthird,\n'
    rows = build_conversation_rows([message("m1", ROOT, content=content)], resolver_for(make_store()))
    write_results(tmp_path, [], rows)
    data = read(tmp_path / CONVERSATIONS_FILE)
    assert len(data) == 2                                  # header + ONE record
    assert data[1][CONVERSATION_COLUMNS.index("content")] == content
    assert len(data[1]) == len(CONVERSATION_COLUMNS)


def test_long_content_is_one_row_and_unchanged(tmp_path):
    content = ("가나다, 라마\n" * 20_000)
    rows = build_conversation_rows([message("m1", ROOT, content=content)], resolver_for(make_store()))
    write_results(tmp_path, [], rows)
    data = read(tmp_path / CONVERSATIONS_FILE)
    assert len(data) == 2 and data[1][CONVERSATION_COLUMNS.index("content")] == content


def test_utf8_bom_no_index_column_and_formula_guard(tmp_path):
    path = tmp_path / "t.csv"
    write_csv(path, ["a", "b"], [["=1+1", "한글"], ["@SUM(A1)", "-2"]])
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    data = read(path)
    assert data[0] == ["a", "b"]                            # no index column
    assert data[1] == ["'=1+1", "한글"]
    assert data[2] == ["'@SUM(A1)", "'-2"]


def test_row_width_mismatch_is_refused_and_leaves_no_file(tmp_path):
    with pytest.raises(CsvExportError):
        write_csv(tmp_path / "t.csv", ["a", "b"], [["only one"]])
    assert list(tmp_path.iterdir()) == []


def test_same_input_gives_identical_bytes(tmp_path):
    messages = [message("m2", "m1", role="assistant"), message("m1", ROOT)]
    events = [event("E04-01", VERDICT_SUSPECTED), event()]
    for folder in ("a", "b"):
        out = tmp_path / folder
        out.mkdir()
        write_results(out, build_timeline_rows(events, resolver_for(make_store())),
                      build_conversation_rows(messages, resolver_for(make_store())))
    for name in (TIMELINE_FILE, CONVERSATIONS_FILE):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


# ---------------------------------------------------------------------------
# parsers carry the logical artifact path
# ---------------------------------------------------------------------------

def test_cache_entry_path_uses_the_data_file_from_the_ccl_location():
    from claude_web_forensics.parsers.cache import _entry_file_path

    base = f"{PROFILE}/Cache/Cache_Data"
    assert _entry_file_path(base, "data_3@12288", "data_1@512") == f"{base}/data_3"
    assert _entry_file_path(base, "", "f_00001a@0") == f"{base}/f_00001a"
    assert _entry_file_path(base, "", "") == ""


def test_mft_and_zone_records_point_at_their_own_streams():
    from claude_web_forensics.parsers.filesystem import MftEntry, entry_to_evidence
    from claude_web_forensics.parsers.filesystem import ZoneInfo, zone_to_evidence

    mft = entry_to_evidence(
        MftEntry(segment=1, sequence=1, parent_segment=5, parent_sequence=5, allocated=True,
                 is_dir=False, full_path="/Users/u/Downloads/a.pdf"),
        "/Users/u/Downloads/a.pdf", "vol-c",
    )
    assert mft.artifact_path == "/$MFT"
    zone = zone_to_evidence(ZoneInfo(zone_id=3), r"C:\Users\u\Downloads\a.pdf",
                            "/Users/u/Downloads/a.pdf", "vol-c")
    assert zone.artifact_path == "/Users/u/Downloads/a.pdf:Zone.Identifier"
    resolver = resolver_for(make_store(mft, zone))
    assert resolver.path_of(mft) == r"C:\$MFT"
    assert resolver.path_of(zone) == r"C:\Users\u\Downloads\a.pdf:Zone.Identifier"


def test_record_defaults_its_artifact_path_to_the_source_path():
    rec = record(FAMILY_HISTORY, "h", source_path=f"{PROFILE}/History")
    assert rec.artifact_path == f"{PROFILE}/History"
    assert rec.volume_id == "vol-c"


# ---------------------------------------------------------------------------
# timeline.csv never shows a real UUID (analysis keeps them internally)
# ---------------------------------------------------------------------------

REAL_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
ACCOUNT_UUID = "f218da89-507d-4665-94b2-887aff8214f8"
CONV_UUID = "3bb411fb-2909-477e-8696-0295a669c024"


UUID_RECORDS = [
    record(FAMILY_CACHE, "u1", artifact_path=f"{PROFILE}/Cache/Cache_Data/data_1"),
    record("local_storage", "u2", artifact_path=f"{PROFILE}/Local Storage/leveldb/000005.ldb"),
    record("zone_identifier", "u3", artifact_path="/Users/u/Downloads/a.png:Zone.Identifier"),
]


def uuid_event() -> FinalEvent:
    """An event whose internal fields and detail lines are full of real UUIDs."""
    lines = [
        f"[Cache] 유형=conversation_api, 대화 제목=파이썬 리스트 정렬 방법, "
        f"대화 UUID={CONV_UUID}, 임시 대화=False",
        f'[Local Storage] key=static-composer-draft-data, 내용={{"accountUuid":"{ACCOUNT_UUID}"}}',
        f"[Zone.Identifier] ZoneId=3, HostUrl=https://claude.ai/api/organizations/"
        f"{ACCOUNT_UUID}/conversations/{CONV_UUID}/wiggle/download-file, MIME=image/png",
    ]
    return FinalEvent(
        action_id=f"ACT-{CONV_UUID}", timestamp=T, action_code="E03-01",
        action_label=label_for("E03-01"), verdict=VERDICT_CONFIRMED,
        action_detail=f"대화 생성 기록_회의록 {CONV_UUID} 정리", conversation_uuid=CONV_UUID,
        evidence=[(r.evidence_id, line) for r, line in zip(UUID_RECORDS, lines)],
    )


def test_timeline_csv_contains_no_real_uuid(tmp_path):
    event = uuid_event()
    rows = build_timeline_rows([event], resolver_for(make_store(*UUID_RECORDS)))
    write_results(tmp_path, rows, [])
    text = (tmp_path / TIMELINE_FILE).read_text(encoding="utf-8-sig")
    assert not REAL_UUID.search(text), REAL_UUID.search(text).group(0)
    # The event object itself still carries every UUID for analysis.
    assert event.conversation_uuid == CONV_UUID
    assert CONV_UUID in event.action_detail
    assert any(CONV_UUID in line for _, line in event.evidence)


def test_uuid_removal_keeps_every_other_detail():
    row = build_timeline_rows([uuid_event()], resolver_for(make_store(*UUID_RECORDS)))[0]
    details = row[TIMELINE_COLUMNS.index("Artifact_details ")]
    for kept in ("[Cache]", "유형=conversation_api", "대화 제목=파이썬 리스트 정렬 방법",
                 "임시 대화=False", "[Local Storage]", "key=static-composer-draft-data",
                 "accountUuid", "[Zone.Identifier]", "ZoneId=3",
                 "https://claude.ai/api/organizations/", "MIME=image/png"):
        assert kept in details, kept
    assert "대화 UUID=" not in details          # labelled pair removed outright
    behaviour = row[TIMELINE_COLUMNS.index("Behavior_details ")]
    assert behaviour.startswith("대화 생성 기록_회의록") and behaviour.endswith("정리")


def test_literal_uuid_placeholder_typed_by_a_user_is_kept():
    event = uuid_event()
    event.action_detail = "사용자 메시지 전송_[MRK_PROMPT_<uuid>] 정렬 방법을 알려줘"
    row = build_timeline_rows([event], resolver_for(make_store()))[0]
    assert row[TIMELINE_COLUMNS.index("Behavior_details ")] == (
        "사용자 메시지 전송_[MRK_PROMPT_<uuid>] 정렬 방법을 알려줘"
    )


def test_strip_uuids_is_display_only():
    from claude_web_forensics.output import csv_export

    text = f"대화 UUID={CONV_UUID}, 대화 제목=제목"
    assert csv_export.strip_uuids(text) == "대화 제목=제목"
    assert csv_export.strip_uuids("변경 없음") == "변경 없음"


def test_conversations_csv_keeps_its_uuids(tmp_path):
    message_row = message("01a02158-6ac0-7366-adae-3f3299711458", ROOT, conv=CONV_UUID,
                          content="원문, 그대로\n유지")
    rows = build_conversation_rows([message_row], resolver_for(make_store()))
    write_results(tmp_path, [], rows)
    data = read(tmp_path / CONVERSATIONS_FILE)
    row = dict(zip(data[0], data[1]))
    assert row["conversation_uuid"] == CONV_UUID
    assert row["message_uuid"] == "01a02158-6ac0-7366-adae-3f3299711458"
    assert row["parent_message_uuid"] == ROOT
    assert row["content"] == "원문, 그대로\n유지"


