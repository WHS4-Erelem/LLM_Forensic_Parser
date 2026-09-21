"""False-positive guards (spec section 24 "판정/false positive", section 26).

Each test encodes a mistake the tool must NOT make.
"""
from __future__ import annotations

import datetime as dt

from claude_web_forensics.analysis.accounts import (
    M_NONE,
    M_SINGLE_SESSION_CONTEXT,
    build_account_context,
    link_account,
)
from claude_web_forensics.analysis.conversations import ConversationBuilder
from claude_web_forensics.analysis.correlator import Correlator
from claude_web_forensics.analysis.detectors import (
    DetectorContext,
    detect_cache_cleared,
    detect_chrome_incognito,
    detect_conversation_delete,
    detect_document_attachment_removed,
    detect_downloaded_file_deleted,
    detect_export,
    detect_history_cleared,
    detect_image_generation,
    detect_logout,
    detect_model_change,
)
from claude_web_forensics.model.entities import (
    FAMILY_CACHE,
    FAMILY_COOKIES,
    FAMILY_HISTORY,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceRecord,
    EvidenceStore,
    make_evidence_id,
)

KST = dt.timezone(dt.timedelta(hours=9))


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
        organization_uuid=attrs.pop("organization_uuid", None),
        attributes=attrs,
    )


def make_ctx(records, extended_fs=False, file_traces=None, conversations=None) -> DetectorContext:
    store = EvidenceStore()
    store.extend(records)
    builder = conversations or ConversationBuilder()
    return DetectorContext(
        store=store,
        correlator=Correlator(store),
        conversations=builder,
        account_ctx=build_account_context(store),
        file_traces=file_traces or [],
        lifecycles={},
        extended_fs=extended_fs,
        artifact_available={f: True for f in store.families_present()},
    )


def test_cookie_absence_never_creates_a_logout():
    """Only a cookie exists; no /logout URL. Must stay 판단불가."""
    ctx = make_ctx([rec(FAMILY_COOKIES, "c", name="sessionKey", is_session_cookie_name=True)])
    result = detect_logout(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_cache_residue_alone_is_not_a_conversation_deletion():
    ctx = make_ctx(
        [rec(FAMILY_CACHE, "k", cache_key="https://claude.ai/api/.../chat_conversations/x",
             variant_index=0, key_kind="conversation_api")]
    )
    result = detect_conversation_delete(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED
    assert "residue" in result.coverage[0].message


def test_residual_attachment_metadata_is_not_removal_proof():
    ctx = make_ctx([rec(FAMILY_CACHE, "a", cache_key="k", variant_index=0)])
    result = detect_document_attachment_removed(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_prompt_keyword_alone_does_not_confirm_image_generation():
    """A user asking for an image, with no tool result, must not confirm."""
    builder = ConversationBuilder()
    from claude_web_forensics.analysis.conversations import ConversationInfo
    from claude_web_forensics.model.entities import ConversationMessage

    info = ConversationInfo(conversation_uuid="c1", title="이미지 생성 요청")
    info.messages["m1"] = ConversationMessage(
        conversation_uuid="c1", message_uuid="m1", role="user",
        content="이미지 생성해줘 generate an image please",
        timestamp=dt.datetime(2026, 8, 22, tzinfo=KST),
    )
    builder.conversations["c1"] = info
    ctx = make_ctx([rec(FAMILY_CACHE, "k", cache_key="k", variant_index=0)], conversations=builder)
    result = detect_image_generation(ctx)
    assert result.events == []


def test_settings_url_alone_does_not_confirm_export_completion():
    ctx = make_ctx(
        [rec(FAMILY_HISTORY, "u", subtype="url",
             url="https://claude.ai/new#settings/data-privacy-controls/export-data")]
    )
    result = detect_export(ctx)
    # Screen access is E07-01 at 의심: fixed action name, partial nature in 상세.
    assert len(result.events) == 1
    event = result.events[0]
    assert event.action_code == "E07-01"
    assert event.action_label == "대화 데이터 Export"
    assert event.verdict == VERDICT_SUSPECTED
    assert event.action_detail == (
        "Export 설정 화면 접근(완료 미확인)_"
        "https://claude.ai/new#settings/data-privacy-controls/export-data"
    )
    assert result.coverage[0].status == VERDICT_SUSPECTED


def test_current_model_alone_does_not_create_a_change_event():
    builder = ConversationBuilder()
    from claude_web_forensics.analysis.conversations import ConversationInfo
    from claude_web_forensics.model.entities import ConversationMessage

    info = ConversationInfo(conversation_uuid="c1", model="claude-sonnet-5")
    info.messages["m1"] = ConversationMessage(
        conversation_uuid="c1", message_uuid="m1", role="user", model="claude-sonnet-5"
    )
    builder.conversations["c1"] = info
    ctx = make_ctx([], conversations=builder)
    assert detect_model_change(ctx).events == []


def test_history_absence_never_confirms_history_deletion():
    ctx = make_ctx([])
    result = detect_history_cleared(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_empty_cache_alone_never_confirms_cache_deletion():
    ctx = make_ctx([], extended_fs=True)
    result = detect_cache_cleared(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_absence_of_default_traces_never_confirms_incognito():
    ctx = make_ctx([])
    result = detect_chrome_incognito(ctx)
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_history_download_alone_does_not_confirm_local_deletion():
    """History proves the download only; deletion needs FS evidence."""
    ctx = make_ctx(
        [rec(FAMILY_HISTORY, "d", subtype="download", download_id=1,
             target_path=r"C:\Users\u\Downloads\a.png", state=1, file_name="a.png")],
        extended_fs=True,
    )
    assert detect_downloaded_file_deleted(ctx).events == []


def test_multiple_account_candidates_leave_account_empty():
    records = [
        rec(FAMILY_CACHE, "a", cache_key="k1", variant_index=0,
            account_uuid="aaaaaaaa-0000-0000-0000-000000000001",
            organization_uuid="org-1"),
        rec(FAMILY_CACHE, "b", cache_key="k2", variant_index=0,
            account_uuid="bbbbbbbb-0000-0000-0000-000000000002",
            organization_uuid="org-1"),
    ]
    store = EvidenceStore()
    store.extend(records)
    ctx = build_account_context(store)
    orphan = rec(FAMILY_HISTORY, "u", subtype="url", url="https://claude.ai/new",
                 organization_uuid="org-1")
    link = link_account(orphan, ctx)
    assert link.account_uuid is None
    assert link.method == M_NONE
    assert len(link.candidates) == 2


def test_single_account_context_is_used_but_labelled():
    records = [
        rec(FAMILY_CACHE, "a", cache_key="k1", variant_index=0,
            account_uuid="aaaaaaaa-0000-0000-0000-000000000001")
    ]
    store = EvidenceStore()
    store.extend(records)
    ctx = build_account_context(store)
    orphan = rec(FAMILY_HISTORY, "u", subtype="url", url="https://claude.ai/new")
    link = link_account(orphan, ctx)
    assert link.account_uuid == "aaaaaaaa-0000-0000-0000-000000000001"
    assert link.method == M_SINGLE_SESSION_CONTEXT


def test_organization_uuid_never_becomes_an_account_uuid():
    records = [rec(FAMILY_HISTORY, "u", subtype="url",
                   url="https://claude.ai/api/organizations/org-1/x",
                   organization_uuid="org-1")]
    store = EvidenceStore()
    store.extend(records)
    ctx = build_account_context(store)
    assert "org-1" not in ctx.account_uuids
    link = link_account(records[0], ctx)
    assert link.account_uuid is None
