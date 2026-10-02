"""False-positive guards (spec section 24 "판정/false positive", section 26).

Each test encodes a mistake the tool must NOT make.
"""
from __future__ import annotations

import datetime as dt

from claude_web_forensics.analysis.conversations import ConversationBuilder
from claude_web_forensics.analysis.detectors import (
    DetectorContext,
    detect_account_switch,
    detect_cache_cleared,
    detect_chrome_incognito,
    detect_conversation_delete,
    detect_document_attachment_removed,
    detect_document_download,
    detect_downloaded_file_deleted,
    detect_export,
    detect_history_cleared,
    detect_image_generation,
    detect_login,
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
    return DetectorContext(
        store=store,
        conversations=conversations or ConversationBuilder(),
        file_traces=file_traces or [],
        extended_fs=extended_fs,
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
        "claude.ai/new#settings/data-privacy-controls/export-data"
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


def visit(locator, when, url, title="Claude"):
    return rec(FAMILY_HISTORY, locator, when, subtype="visit", url=url, title=title)


T = dt.datetime(2026, 9, 23, 1, 56, tzinfo=KST)
S = dt.timedelta(seconds=1)


def test_desktop_app_delegation_is_not_a_web_login():
    """The desktop app finishing its OAuth in the browser is not a Claude web login."""
    ctx = make_ctx([
        visit("a", T, "https://claude.ai/login/app-google-auth?open_in_browser=1&hop_nonce=x"),
        visit("b", T + 4 * S, "https://accounts.google.com/o/oauth2/v2/auth?client_id=c"),
        visit("c", T + 18 * S, "https://claude.ai/login/popup-google-auth?code=secret"),
        visit("d", T + 60 * S, "https://claude.ai/new", "새 채팅 - Claude"),
    ])
    assert detect_login(ctx).events == []
    assert any("desktop-app" in note for note in ctx.notes)


def test_separate_login_flows_stay_separate_with_their_own_landing_time():
    day2 = T + dt.timedelta(hours=11)
    ctx = make_ctx([
        visit("a1", T, "https://claude.ai/login"),
        visit("a2", T + 5 * S, "https://accounts.google.com/v3/signin/challenge/pwd?TL=x"),
        visit("a3", T + 40 * S, "https://claude.ai/new", "새 채팅 - Claude"),
        visit("b1", day2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=c"),
        visit("b2", day2 + 30 * S, "https://claude.ai/new", "새 채팅 - Claude"),
    ])
    events = detect_login(ctx).events
    assert sorted(e.timestamp for e in events) == [T + 40 * S, day2 + 30 * S]


def test_login_detail_and_verdict_never_contradict():
    """History alone stays 의심; a sign-in landing says 인증 완료 미확인; 확정 never says 미확인."""
    history_only = make_ctx([
        visit("a1", T, "https://claude.ai/login"),
        visit("a2", T + 40 * S, "https://claude.ai/new", "새 채팅 - Claude"),
    ])
    [event] = detect_login(history_only).events
    assert event.verdict == VERDICT_SUSPECTED and "세션 생성 기록 미확인" in event.action_detail

    marker = rec("local_storage", "m", T + 41 * S, script_key="rq-cache-confirmed-account-session",
                 marker_at=T + 41 * S)
    confirmed = make_ctx(list(history_only.store) + [marker])
    [event] = detect_login(confirmed).events
    assert event.verdict == VERDICT_CONFIRMED and "미확인" not in event.action_detail

    sign_in = make_ctx([
        visit("a1", T, "https://accounts.google.com/o/oauth2/v2/auth?client_id=c"),
        visit("a2", T + 40 * S, "https://claude.ai/new", "Sign in - Claude"),
    ])
    [event] = detect_login(sign_in).events
    assert event.verdict == VERDICT_SUSPECTED and "인증 완료 미확인" in event.action_detail


def test_residual_organization_uuids_alone_never_create_a_switch():
    """Two organizations cached in one profile are multi-account traces, not a switch."""
    records = [
        rec(FAMILY_CACHE, "a", cache_key="https://claude.ai/api/organizations/o1/x", variant_index=0,
            organization_uuid="org-1", response_at=T),
        rec(FAMILY_CACHE, "b", cache_key="https://claude.ai/api/organizations/o2/x", variant_index=0,
            organization_uuid="org-2", response_at=T + 60 * S),
    ]
    result = detect_account_switch(make_ctx(records))
    assert result.events == []
    assert result.coverage[0].status == VERDICT_UNDETERMINED


def test_switch_needs_two_login_sessions_with_different_organizations():
    later = T + dt.timedelta(minutes=30)
    records = [
        visit("a1", T, "https://claude.ai/login"),
        visit("a2", T + 40 * S, "https://claude.ai/new", "새 채팅 - Claude"),
        rec(FAMILY_CACHE, "c1", cache_key="https://claude.ai/api/organizations/o1/x",
            variant_index=0, organization_uuid="org-1", response_at=T + 50 * S),
        visit("l1", T + 600 * S, "https://claude.ai/logout"),
        visit("b1", later, "https://claude.ai/login"),
        visit("b2", later + 30 * S, "https://claude.ai/new", "새 채팅 - Claude"),
        rec(FAMILY_CACHE, "c2", cache_key="https://claude.ai/api/organizations/o2/x",
            variant_index=0, organization_uuid="org-2", response_at=later + 35 * S),
    ]
    [event] = detect_account_switch(make_ctx(records)).events
    assert event.timestamp == later + 30 * S
    assert event.verdict == VERDICT_CONFIRMED
    assert "조직 A" in event.action_detail and "조직 B" in event.action_detail
    same_org = [r for r in records if r.record_locator != "c2"] + [
        rec(FAMILY_CACHE, "c3", cache_key="https://claude.ai/api/organizations/o1/y",
            variant_index=0, organization_uuid="org-1", response_at=later + 35 * S)]
    assert detect_account_switch(make_ctx(same_org)).events == []


def test_installer_download_is_not_a_document_download():
    ctx = make_ctx([rec(FAMILY_HISTORY, "d", T, subtype="download", download_id=1, state=1,
                        file_name="Claude Setup.exe", mime_type="application/x-msdownload",
                        target_path=r"C:\Users\u\Downloads\Claude Setup.exe",
                        chain_urls=["https://claude.ai/api/desktop/win32/x64/setup/latest/redirect"])])
    assert detect_document_download(ctx).events == []


def test_unresolved_session_in_between_leaves_the_switch_unreported():
    """org-1 session, a session with no org record, then org-2: the switch moment is unknown."""
    def login(prefix, start, org=None):
        out = [visit(f"{prefix}1", start, "https://claude.ai/login"),
               visit(f"{prefix}2", start + 30 * S, "https://claude.ai/new", "새 채팅 - Claude"),
               visit(f"{prefix}3", start + 300 * S, "https://claude.ai/logout")]
        if org:
            out.append(rec(FAMILY_CACHE, f"{prefix}c", cache_key=f"https://claude.ai/api/organizations/{org}/x",
                           variant_index=0, organization_uuid=org, response_at=start + 40 * S))
        return out
    hour = dt.timedelta(hours=1)
    records = login("a", T, "org-1") + login("b", T + hour) + login("c", T + 2 * hour, "org-2")
    assert detect_account_switch(make_ctx(records)).events == []
