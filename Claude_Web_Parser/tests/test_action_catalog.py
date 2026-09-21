"""Fixed 24-action catalogue: names, 행위_상세 format, registry, Timeline/COVERAGE."""
from __future__ import annotations

import datetime as dt

import pytest

from claude_web_forensics.analysis import detectors as detectors_module
from claude_web_forensics.analysis.accounts import build_account_context
from claude_web_forensics.analysis.rules import (
    ACTION_LABELS,
    EXCLUDED_ACTION_CODES,
    RULE_IDS,
    UnknownActionError,
    compose_detail,
    label_for,
)
from claude_web_forensics.analysis.conversations import ConversationBuilder, DraftTrace
from claude_web_forensics.analysis.correlator import Correlator
from claude_web_forensics.analysis.detectors import (
    DETECTOR_REGISTRY,
    DetectorContext,
    DetectorResult,
    detect_document_upload,
    detect_export,
    detect_image_upload,
    detect_prompt,
    run_all,
)
from claude_web_forensics.analysis.file_analysis import FileBuilder, collect_upload_metadata
from claude_web_forensics.model.entities import (
    FAMILY_CACHE,
    FAMILY_HISTORY,
    FAMILY_INDEXEDDB,
    FAMILY_LOCAL_STORAGE,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceRecord,
    EvidenceStore,
    make_evidence_id,
)
from claude_web_forensics.output.csv_export import (
    TIMELINE_COLUMNS,
    ArtifactPathResolver,
    build_timeline_rows as _build_rows,
)

KST = dt.timezone(dt.timedelta(hours=9))
T0 = dt.datetime(2026, 8, 22, 21, 0, tzinfo=KST)

EXPECTED = {
    "E01-01": "로그인",
    "E01-02": "로그아웃",
    "E01-03": "계정 전환",
    "E03-01": "새로운 대화 생성",
    "E03-02": "기존 대화 삭제",
    "E03-03": "대화 수정",
    "E03-04": "대화 재시도",
    "E04-01": "사용자 프롬프트 입력/전송",
    "E05-01": "이미지 업로드",
    "E05-02": "이미지 업로드 삭제",
    "E05-03": "문서 업로드",
    "E05-04": "문서 업로드 삭제",
    "E05-05": "문서 다운로드",
    "E06-01": "이미지 생성 요청",
    "E06-02": "생성 이미지 다운로드",
    "E06-03": "생성 이미지 다운로드 삭제",
    "E07-01": "대화 데이터 Export",
    "E07-02": "공유 링크 생성",
    "E09-01": "모델 변경",
    "E09-02": "계정 이름 변경",
    "E10-01": "임시 채팅 사용",
    "E10-02": "브라우저 시크릿 모드",
    "E10-03": "방문기록 삭제",
    "E10-04": "캐시 삭제",
}

# Descriptive phrases that must never appear as an action name.
FORBIDDEN_ACTION_NAMES = {
    "프롬프트 작성 흔적(전송 미확인)", "이미지 업로드 준비 흔적(전송 불확인)",
    "문서 업로드 준비 흔적(전송 불확인)", "데이터 내보내기 화면 접근", "임시 대화",
    "프롬프트 전송", "대화 생성", "대화 편집", "응답 재시도", "계정명 변경",
    "다운로드 파일 삭제", "프롬프트 작성", "데이터 내보내기",
}


def build_timeline_rows(events, store=None):
    """timeline.csv rows as dicts keyed by the CSV header."""
    resolver = ArtifactPathResolver(store=store or EvidenceStore(), drive_letters={})
    return [dict(zip(TIMELINE_COLUMNS, row)) for row in _build_rows(events, resolver)]


def rec(family, locator, ts=None, **attrs) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=make_evidence_id(family, "src", locator, attrs),
        artifact=family,
        artifact_family=family,
        source_path="src",
        record_locator=locator,
        timestamp=ts,
        account_uuid=attrs.pop("account_uuid", None),
        conversation_uuid=attrs.pop("conversation_uuid", None),
        attributes=attrs,
    )


def ctx_for(records, *, drafts=(), file_traces=(), extended_fs=False, conversations=None):
    store = EvidenceStore()
    store.extend(records)
    builder = conversations or ConversationBuilder()
    if conversations is None:
        builder.ingest(store)
    builder.drafts.extend(drafts)
    return DetectorContext(
        store=store, correlator=Correlator(store), conversations=builder,
        account_ctx=build_account_context(store), file_traces=list(file_traces),
        lifecycles={}, extended_fs=extended_fs,
        artifact_available={f: True for f in store.families_present()},
    )


def draft(text, record):
    return DraftTrace(
        draft_id="d1", text=text, timestamp=T0, account_uuid=None, conversation_uuid=None,
        attachment_count=None, file_count=None, family=FAMILY_LOCAL_STORAGE,
        evidence_ids=[record.evidence_id],
    )


def rich_context():
    """Evidence that drives many detectors at once (sent + draft + export + upload)."""
    payload = {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "name": "실험 대화",
        "created_at": "2026-08-22T10:00:00Z",
        "chat_messages": [
            {"uuid": "m1", "sender": "human", "created_at": "2026-08-22T10:00:05Z",
             "content": [{"type": "text", "text": "안녕"}],
             "files": [{"file_name": "sent.png", "file_uuid": "f-sent", "size_bytes": 3,
                        "file_kind": "image"}]},
            {"uuid": "m2", "sender": "assistant", "parent_message_uuid": "m1",
             "created_at": "2026-08-22T10:00:09Z",
             "content": [{"type": "text", "text": "hi"}]},
        ],
    }
    cache = rec(FAMILY_CACHE, "k", conversation_uuid="11111111-1111-1111-1111-111111111111",
                key_kind="conversation_api", _json=payload, cache_key="k", variant_index=0)
    draft_idb = rec(FAMILY_INDEXEDDB, "d", key_kind="chat_draft",
                    value={"state": {"files": [
                        {"file_name": "[MRK_E0501].png", "file_uuid": "f-d1", "size_bytes": 4,
                         "file_kind": "image"},
                        {"file_name": "[MRK_E0503].pdf", "file_uuid": "f-d2", "size_bytes": 5,
                         "file_kind": "document"}]}})
    settings = rec(FAMILY_HISTORY, "u", T0, subtype="url",
                   url="https://claude.ai/new#settings/data-privacy-controls/export-data")
    ls = rec(FAMILY_LOCAL_STORAGE, "ls", T0, script_key="static-composer-draft-data")
    records = [cache, draft_idb, settings, ls]
    store = EvidenceStore()
    store.extend(records)
    files = FileBuilder()
    files.add_uploads(collect_upload_metadata(store))
    return ctx_for(
        records,
        drafts=[draft("[MRK_E0505] 문서 다운로드 실험ㅎ\n두 번째 줄", ls)],
        file_traces=files.traces,
    )


# ---------------------------------------------------------------------------
# 9. catalogue
# ---------------------------------------------------------------------------

def test_catalogue_is_exactly_the_24_actions():
    assert ACTION_LABELS == EXPECTED
    assert set(RULE_IDS) == set(EXPECTED)


def test_excluded_and_invented_codes_are_absent():
    for code in EXCLUDED_ACTION_CODES | {"E04-01d", "E07-01a"}:
        assert code not in ACTION_LABELS
        with pytest.raises(UnknownActionError):
            label_for(code)


def test_registry_maps_each_action_once():
    codes = [code for code, _ in DETECTOR_REGISTRY]
    assert sorted(codes) == sorted(EXPECTED)
    assert len(codes) == len(set(codes)) == 24


# ---------------------------------------------------------------------------
# 10-18. FinalEvent labels and 행위_상세
# ---------------------------------------------------------------------------

def test_every_final_event_uses_the_catalogue_label():
    result = run_all(rich_context())
    assert result.events
    for event in result.events:
        assert event.action_label == ACTION_LABELS[event.action_code]
        assert event.action_label not in FORBIDDEN_ACTION_NAMES


def test_timeline_action_column_only_holds_catalogue_names():
    rows = build_timeline_rows(run_all(rich_context()).events)
    assert rows
    assert {r["User_behavior"] for r in rows} <= set(EXPECTED.values())
    assert not {r["User_behavior"] for r in rows} & FORBIDDEN_ACTION_NAMES


def test_draft_is_e0401_suspected_with_nature_in_detail():
    ctx = rich_context()
    events = [e for e in detect_prompt(ctx).events if e.verdict == VERDICT_SUSPECTED]
    assert len(events) == 1
    event = events[0]
    assert event.action_code == "E04-01"
    assert event.action_label == "사용자 프롬프트 입력/전송"
    assert event.action_detail == "프롬프트 작성 흔적(전송 미확인)_[MRK_E0505] 문서 다운로드 실험ㅎ"
    row = [r for r in build_timeline_rows([event])][0]
    assert (row["User_behavior"], row["Behavior_details "], row["Verdict"]) == (
        "사용자 프롬프트 입력/전송",
        "프롬프트 작성 흔적(전송 미확인)_[MRK_E0505] 문서 다운로드 실험ㅎ",
        "의심",
    )


def test_sent_prompt_and_draft_share_one_coverage_row():
    result = detect_prompt(rich_context())
    verdicts = {e.verdict for e in result.events}
    assert verdicts == {VERDICT_CONFIRMED, VERDICT_SUSPECTED}
    assert [c.action_code for c in result.coverage] == ["E04-01"]
    assert result.coverage[0].status == VERDICT_CONFIRMED


def test_unsent_image_upload_keeps_the_action_name():
    events = {e.action_detail: e for e in detect_image_upload(rich_context()).events}
    draft_event = events["이미지 업로드 준비 흔적(전송 불확인)_[MRK_E0501].png"]
    assert draft_event.action_label == "이미지 업로드"
    assert draft_event.verdict == VERDICT_SUSPECTED
    sent_event = events["전송 메시지 첨부_sent.png"]
    assert sent_event.action_label == "이미지 업로드"
    assert sent_event.verdict == VERDICT_CONFIRMED


def test_unsent_document_upload_keeps_the_action_name():
    events = detect_document_upload(rich_context()).events
    assert [(e.action_label, e.action_detail, e.verdict) for e in events] == [
        ("문서 업로드", "문서 업로드 준비 흔적(전송 불확인)_[MRK_E0503].pdf", VERDICT_SUSPECTED)
    ]


def test_export_screen_access_is_detail_of_e0701():
    events = detect_export(rich_context()).events
    assert [(e.action_code, e.action_label, e.verdict) for e in events] == [
        ("E07-01", "대화 데이터 Export", VERDICT_SUSPECTED)
    ]
    assert events[0].action_detail.startswith("Export 설정 화면 접근(완료 미확인)_https://")


def test_detail_never_contains_codes_or_ids():
    for event in run_all(rich_context()).events:
        detail = event.action_detail
        assert "E0" not in detail.replace("[MRK_E0", "")  # MRK_ markers are user content
        assert "R-E" not in detail
        assert event.action_id not in detail
        for eid in event.detail_refs:
            assert eid not in detail
        assert not detail.endswith("_")


def test_compose_detail_format():
    assert compose_detail("흔적", "내용") == "흔적_내용"
    assert compose_detail("흔적", "") == "흔적"
    assert compose_detail("흔적", None) == "흔적"
    assert compose_detail("흔적", "  여러   공백 \n 줄 ") == "흔적_여러 공백 줄"


def test_detectors_cannot_pass_a_custom_label():
    import inspect

    params = inspect.signature(detectors_module._build_event).parameters
    assert "label" not in params


# ---------------------------------------------------------------------------
# 18-21. COVERAGE and Timeline separation
# ---------------------------------------------------------------------------

def test_coverage_has_each_action_exactly_once():
    result = run_all(rich_context())
    codes = [c.action_code for c in result.coverage]
    assert sorted(codes) == sorted(EXPECTED)
    for row in result.coverage:
        assert row.action_label == EXPECTED[row.action_code]
    assert not {"E04-01d", "E07-01a", "E04-02"} & set(codes)


def test_removed_codes_never_reach_the_timeline_or_coverage():
    result = run_all(rich_context())
    assert not {"E04-01d", "E07-01a", "E04-02"} & {e.action_code for e in result.events}
    codes = [c.action_code for c in result.coverage]
    assert len(codes) == 24
    assert not {"E04-01d", "E07-01a", "E04-02"} & set(codes)


def test_undetermined_is_never_exported():
    result = run_all(ctx_for([]))
    assert result.events == []
    assert build_timeline_rows(result.events) == []
    assert len(result.coverage) == 24
    assert all(c.status == VERDICT_UNDETERMINED and c.reason for c in result.coverage)


def test_failed_detector_reports_its_action_not_its_function_name(monkeypatch):
    def broken(ctx):
        raise RuntimeError("boom")

    registry = tuple(
        (code, broken if code == "E01-01" else fn) for code, fn in DETECTOR_REGISTRY
    )
    monkeypatch.setattr(detectors_module, "DETECTOR_REGISTRY", registry)
    result = detectors_module.run_all(ctx_for([]))
    failed = [c for c in result.coverage if c.reason == "detector_failed"]
    assert len(failed) == 1
    assert failed[0].action_code == "E01-01"
    assert failed[0].action_label == "로그인"
    assert "detect_" not in failed[0].action_label
    assert "broken" not in failed[0].action_label


def test_detector_emitting_a_foreign_code_is_a_contract_error(monkeypatch):
    def rogue(ctx):
        from claude_web_forensics.model.entities import CoverageRow

        return DetectorResult(coverage=[CoverageRow("E05-05", "문서 다운로드", "R-E0505",
                                                    VERDICT_UNDETERMINED)])

    registry = tuple(
        (code, rogue if code == "E01-01" else fn) for code, fn in DETECTOR_REGISTRY
    )
    monkeypatch.setattr(detectors_module, "DETECTOR_REGISTRY", registry)
    with pytest.raises(detectors_module.DetectorContractError):
        detectors_module.run_all(ctx_for([]))
