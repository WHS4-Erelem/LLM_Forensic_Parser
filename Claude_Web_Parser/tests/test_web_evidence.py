"""Claude web structures as stored by Chrome, and the detectors built on them."""
from __future__ import annotations

import datetime as dt

from claude_web_forensics.analysis.conversations import ConversationBuilder, DraftTrace
from claude_web_forensics.analysis.detectors import (
    DetectorContext,
    detect_document_upload,
    detect_image_upload,
    detect_model_change,
    detect_new_conversation,
    detect_prompt,
    detect_share_link,
    url_kind,
)
from claude_web_forensics.analysis.summaries import short_url
from claude_web_forensics.model.entities import (
    FAMILY_CACHE,
    FAMILY_HISTORY,
    FAMILY_INDEXEDDB,
    FAMILY_LOCAL_STORAGE,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    EvidenceRecord,
    EvidenceStore,
    make_evidence_id,
)
from claude_web_forensics.parsers.browser_storage import _extract, parse_indexeddb
from claude_web_forensics.parsers.cache import classify_key

UTC = dt.timezone.utc
T = dt.datetime(2026, 9, 22, 16, 59, 41, tzinfo=UTC)
S = dt.timedelta(seconds=1)
CONV = "8de10100-d87b-48f8-bc9d-fc63ab54d1cb"
OTHER = "e458ac8c-0000-4000-8000-000000000000"
ORG = "7b4208c2-9e4e-436a-ad1b-0e5b30e20327"


def rec(family, locator, ts=None, *, conversation=None, org=None, account=None, **attrs):
    return EvidenceRecord(
        evidence_id=make_evidence_id(family, "src", locator, attrs.get("cache_key") or locator),
        artifact=family, artifact_family=family, source_path="src", record_locator=locator,
        timestamp=ts, conversation_uuid=conversation, organization_uuid=org,
        account_uuid=account, attributes=attrs,
    )


def context(*records, drafts=()):
    store = EvidenceStore()
    store.extend(records)
    builder = ConversationBuilder()
    builder.ingest(store)
    builder.drafts.extend(drafts)
    return DetectorContext(store=store, conversations=builder)


def list_page(*items):
    return rec(FAMILY_CACHE, "list", org=ORG, key_kind="conversation_list",
               cache_key=f"https://claude.ai/api/organizations/{ORG}/chat_conversations_v2?limit=30",
               variant_index=0, response_at=T + 3600 * S, _json={"data": list(items), "has_more": False})


def item(uuid, name, created, updated=None, model="claude-fable-5-1"):
    return {"uuid": uuid, "name": name, "created_at": created, "updated_at": updated or created,
            "model": model, "is_temporary": False, "current_leaf_message_uuid": None}


def analytics(locator, *events):
    return rec(FAMILY_LOCAL_STORAGE, locator, script_key="antalytics_queue_v1",
               storage_key="https://claude.ai", analytics_events=list(events))


def event(name, when, **props):
    return {"eventName": name, "eventTimestamp": when.isoformat().replace("+00:00", "Z"),
            "eventId": f"{name}-{when.timestamp()}", "account_uuid": "acct", "properties": props}


# ---------------------------------------------------------------------------
# key classification and structures
# ---------------------------------------------------------------------------

def test_cache_keys_are_bucketed_by_what_the_body_holds():
    base = f"https://claude.ai/api/organizations/{ORG}/chat_conversations/{CONV}"
    assert classify_key(base + "?tree=True&rendering_mode=messages") == "conversation_api"
    assert classify_key(base + "/latest") == "latest_or_snapshot"
    for sub in ("share_access", "shares", "access_requests"):
        assert classify_key(f"{base}/{sub}") == "share_api"
    assert classify_key(f"{base}/composer_notices") == "organization_api"
    assert classify_key(f"https://claude.ai/api/{ORG}/files/{CONV}/preview") == "file_asset"
    assert classify_key(f"https://claude.ai/api/organizations/{ORG}/chat_conversations_v2?x=1") \
        == "conversation_list"


def test_list_page_items_are_conversation_objects_without_messages():
    ctx = context(list_page(item(CONV, "MRK_E0301", "2026-09-22T16:59:41.971069Z"),
                            item(OTHER, "다른 대화", "2026-09-22T17:32:38Z")))
    infos = ctx.conversations.conversations
    assert set(infos) == {CONV, OTHER}
    assert infos[CONV].organization_uuid == ORG and not infos[CONV].messages
    assert infos[CONV].created_at == dt.datetime(2026, 9, 22, 16, 59, 41, 971069, tzinfo=UTC)


def test_snapshot_uuid_is_never_taken_for_a_conversation():
    snapshot = rec(FAMILY_CACHE, "latest", conversation=CONV, key_kind="latest_or_snapshot",
                   cache_key=f"https://claude.ai/api/organizations/{ORG}/chat_conversations/{CONV}/latest",
                   variant_index=0, response_at=T, snapshot_uuid="f55d7be4-0000-4000-8000-000000000000",
                   _json={"snapshot": {"uuid": "f55d7be4-0000-4000-8000-000000000000",
                                       "chat_messages": []}})
    ctx = context(snapshot)
    assert set(ctx.conversations.conversations) == {CONV}
    assert ctx.conversations.conversations[CONV].snapshot_uuid.startswith("f55d7be4")


def test_messages_stay_with_their_enclosing_conversation():
    body = {"data": [
        {"uuid": CONV, "created_at": "2026-09-22T16:59:41Z", "chat_messages": [
            {"uuid": "m1", "sender": "human", "created_at": "2026-09-22T16:59:41Z",
             "content": [{"type": "text", "text": "첫 질문"}]}]},
        {"uuid": OTHER, "created_at": "2026-09-22T17:00:00Z", "chat_messages": [
            {"uuid": "m2", "sender": "human", "created_at": "2026-09-22T17:00:01Z",
             "content": [{"type": "text", "text": "다른 질문"}]}]},
    ]}
    cached = rec(FAMILY_CACHE, "body", key_kind="conversation_list", cache_key="k",
                 variant_index=0, _json=body)
    assert context(cached).conversations.all_messages() == []
    ctx = context(cached,
                  rec(FAMILY_INDEXEDDB, "trees", key_kind="react_query_cache", record_state="LIVE",
                      value={"clientState": {"queries": [{"state": {"data": body}}]}}),
                  rec(FAMILY_INDEXEDDB, "rq", key_kind="react_query_cache", record_state="LIVE",
                      value={"clientState": {"queries": [{"state": {"data": [
                          {"uuid": "orphan", "sender": "human", "content": "x"}]}}]}}))
    infos = ctx.conversations.conversations
    assert set(infos[CONV].messages) == {"m1"} and set(infos[OTHER].messages) == {"m2"}
    assert ctx.conversations.stats["idb:react_query: message dropped (owner conversation unknown)"] == 1


def test_partial_draft_versions_form_one_composition_until_cleared():
    def version(seq, text):
        return DraftTrace(draft_id="store:chat-draft:composer", text=text, timestamp=T + seq * S,
                          account_uuid=None, family=FAMILY_INDEXEDDB, evidence_ids=[f"e{seq}"],
                          sequence=seq)
    builder = ConversationBuilder()
    builder.drafts = [version(i, t) for i, t in enumerate(
        ["[]", "[M]", "[MRK_E0301] 크", "[MRK_E0301] ㅋ", "[MRK_E0301] Claude 앱", "",
         "완전히 다른 초안"])]
    groups = builder.draft_compositions()
    assert [g[-1].text for g in groups] == ["[MRK_E0301] Claude 앱", "완전히 다른 초안"]


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------

def test_send_event_takes_the_matching_draft_and_the_draft_is_not_repeated():
    draft = rec(FAMILY_LOCAL_STORAGE, "draft", T - 40 * S, account="acct",
                script_key="static-composer-draft-data", text="[MRK_E0401] 파이썬 정렬")
    sent = analytics("queue", event("claudeai.message.sent", T, conversation_uuid=CONV,
                                    message_length=len("[MRK_E0401] 파이썬 정렬"), model="m"))
    idb = [rec(FAMILY_INDEXEDDB, f"d{i}", T + (100 + i) * S, key_kind="chat_draft",
               key_text="store:chat-draft:composer", ldb_seq_no=i,
               value={"state": {"tipTapEditorState": {"type": "doc", "content": [
                   {"type": "paragraph", "content": [{"type": "text", "text": text}]}]}}})
           for i, text in enumerate(["[MRK", "[MRK_E03", "[MRK_E0301] 새 대화"])]
    events = detect_prompt(context(draft, sent, *idb)).events
    confirmed = [e for e in events if e.verdict == VERDICT_CONFIRMED]
    suspected = [e for e in events if e.verdict == VERDICT_SUSPECTED]
    assert len(confirmed) == 1 and confirmed[0].timestamp == T
    assert confirmed[0].action_detail.endswith("_[MRK_E0401] 파이썬 정렬")
    assert len(suspected) == 1                                  # one composition, one row
    assert suspected[0].action_detail == "프롬프트 작성 흔적(전송 미확인)_[MRK_E0301] 새 대화"
    assert suspected[0].timestamp == T + 102 * S                # last save of the composition


def test_creation_event_confirms_and_object_alone_is_not_reported():
    visit = rec(FAMILY_HISTORY, "v", T + 1 * S, conversation=CONV, subtype="visit",
                url=f"https://claude.ai/chat/{CONV}", title="MRK_E0301 - Claude")
    new = rec(FAMILY_HISTORY, "n", T - 60 * S, subtype="visit", url="https://claude.ai/new")
    created = analytics("q", event("chorus.conversation_created", T, conversation_uuid=CONV))
    page = list_page(item(CONV, "MRK_E0301", "2026-09-22T16:59:41Z"),
                     item(OTHER, "데스크톱에서 만든 대화", "2026-09-22T19:32:10Z"))
    events = detect_new_conversation(context(new, visit, created, page)).events
    assert [(e.conversation_uuid, e.verdict) for e in events] == [(CONV, VERDICT_CONFIRMED)]


def test_first_visit_after_new_without_object_is_only_suspected():
    ctx = context(rec(FAMILY_HISTORY, "n", T, subtype="visit", url="https://claude.ai/new"),
                  rec(FAMILY_HISTORY, "v", T + 30 * S, conversation=CONV, subtype="visit",
                      url=f"https://claude.ai/chat/{CONV}", title="새로운 대화 시작 - Claude"))
    [e] = detect_new_conversation(ctx).events
    assert e.verdict == VERDICT_SUSPECTED
    assert e.action_detail == "새 대화 URL 최초 방문(생성 객체 미확인)_새로운 대화 시작"


def test_share_time_is_the_snapshot_objects_own_time_never_a_page_visit():
    snapshot = rec(FAMILY_CACHE, "latest", conversation=CONV, key_kind="latest_or_snapshot",
                   cache_key=f"https://claude.ai/api/organizations/{ORG}/chat_conversations/{CONV}/latest",
                   variant_index=0, response_at=T, snapshot_uuid="f55d7be4-0000-4000-8000-000000000000",
                   snapshot_visibility="invite_only",
                   _json={"snapshot": {"uuid": "f55d7be4-0000-4000-8000-000000000000"}})
    settings = rec(FAMILY_HISTORY, "s", T - 600 * S, subtype="visit",
                   url=f"https://claude.ai/chat/{CONV}#settings/account")
    [e] = detect_share_link(context(snapshot, settings)).events
    assert e.timestamp is None and e.verdict == VERDICT_CONFIRMED
    assert "생성 시각 미상" in e.action_detail
    assert e.detail_refs == [snapshot.evidence_id]            # the settings visit is not used


def test_uploaded_file_assets_are_suspected_uploads_by_rendition():
    def asset(file_uuid, variant, at, content_type):
        return rec(FAMILY_CACHE, f"{file_uuid}{variant}", key_kind="file_asset", file_uuid=file_uuid,
                   file_variant=variant, response_at=at, content_type=content_type, variant_index=0,
                   cache_key=f"https://claude.ai/api/{ORG}/files/{file_uuid}/{variant}")
    image = asset("img", "preview", T, "image/webp")
    doc = [asset("doc", "thumbnail", T + 60 * S, "image/webp"),
           asset("doc", "document_pdf", T + 150 * S, "application/pdf")]
    ctx = context(image, *doc)
    [img] = detect_image_upload(ctx).events
    [pdf] = detect_document_upload(ctx).events
    assert (img.timestamp, img.verdict) == (T, VERDICT_SUSPECTED)
    assert (pdf.timestamp, pdf.verdict) == (T + 60 * S, VERDICT_SUSPECTED)
    assert "전송 미확인" in pdf.action_detail


def test_model_change_from_send_event_to_conversation_object():
    sent = analytics("q", event("claudeai.message.sent", T, conversation_uuid=CONV, model="claude-opus-5-5"))
    page = list_page(item(CONV, "MRK_E0301", "2026-09-22T16:59:41Z", "2026-09-22T17:20:05Z"))
    [e] = detect_model_change(context(sent, page)).events
    assert e.action_detail.endswith("claude-opus-5-5 → claude-fable-5-1")
    assert e.timestamp == dt.datetime(2026, 9, 22, 17, 20, 5, tzinfo=UTC)
    assert e.verdict == VERDICT_CONFIRMED
    single = context(page)
    assert detect_model_change(single).events == []


# ---------------------------------------------------------------------------
# parsers and display helpers
# ---------------------------------------------------------------------------

def test_local_storage_values_carry_their_own_times():
    marker = _extract("rq-cache-confirmed-account-session",
                      '{"account":"f218da89-507d-4665-94b2-887aff8214f8","marker":"1790096248105"}')
    assert marker["account_uuid"].startswith("f218da89")
    assert marker["marker_at"] == dt.datetime(2026, 9, 22, 16, 57, 28, 105000, tzinfo=UTC)
    assert _extract("hub-chat-document-ids-logout-at", "1790136661594")["marker_at"].second == 1
    queue = _extract("antalytics_queue_v1", '[{"eventName":"claudeai.message.sent",'
                     '"eventTimestamp":"2026-09-22T16:59:41.094Z","eventId":"e1",'
                     '"properties":{"message_length":35,"url":"https://secret","text":"x"}}]')
    [parsed] = queue["analytics_events"]
    assert parsed["properties"] == {"message_length": 35}      # content fields are dropped


def test_indexeddb_parses_only_claude_origins(tmp_path):
    (tmp_path / "https_chatgpt.com_0.indexeddb.leveldb").mkdir()
    records, status = parse_indexeddb(tmp_path, "/p/IndexedDB", "v")
    assert records == [] and status.status == "not_found"
    assert "1 other origin(s) skipped" in status.message


def test_url_kinds_and_short_urls():
    assert url_kind("https://claude.ai/login?from=logout") == "logout"
    assert url_kind("https://claude.ai/login/app-google-auth?open_in_browser=1") == "delegate"
    assert url_kind("https://accounts.google.com/v3/signin/challenge/pwd?TL=x") == "auth"
    assert url_kind("https://claude.ai/new") == "app"
    assert url_kind("https://claude.com/ko") == "other"
    assert short_url("https://claude.ai/login/popup-google-auth?state=a&code=secret") \
        == "claude.ai/login/popup-google-auth?…"
    assert short_url("https://claude.ai/login?from=logout") == "claude.ai/login?from=logout"
    assert short_url("https://claude.ai/chat/x#settings/data-privacy-controls") \
        == "claude.ai/chat/x#settings/data-privacy-controls"


# ---------------------------------------------------------------------------
# E06-01 image generation: tree-less path
# ---------------------------------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
SVG = b'<?xml version="1.0"?>\n<!-- made by claude -->\n<svg xmlns="http://www.w3.org/2000/svg"></svg>'


def test_generated_file_bodies_are_identified_by_their_bytes():
    from claude_web_forensics.decode.content import image_format
    from claude_web_forensics.parsers.cache import _decode_body

    assert (image_format(PNG), image_format(SVG)) == ("png", "svg")
    assert image_format(b"<html><body><svg></svg></body></html>") == ""   # root must be <svg>
    assert image_format(b'{"error": "not found"}') == ""
    attrs = {"content_encoding": "", "content_type": "image/png"}
    _decode_body(PNG, "download_file", attrs, None)
    assert attrs["body_format"] == "png"


def generated_file(conv, at, body_format="png", name="dog.png"):
    path = f"/mnt/user-data/outputs/{name}"
    return rec(FAMILY_CACHE, f"file-{conv}-{name}", conversation=conv, key_kind="download_file",
               variant_index=0, response_at=at, body_format=body_format, output_path=path,
               cache_key=f"https://claude.ai/api/organizations/{ORG}/conversations/{conv}"
                         f"/wiggle/download-file?path={path}")


def test_send_event_plus_verified_image_response_is_a_suspected_generation():
    from claude_web_forensics.analysis.detectors import detect_image_generation

    sent = analytics("q", event("claudeai.message.sent", T, conversation_uuid=CONV))
    title = rec(FAMILY_HISTORY, "t", T + 20 * S, conversation=CONV, subtype="visit",
                url=f"https://claude.ai/chat/{CONV}", title="강아지 이미지 생성 - Claude")
    [e] = detect_image_generation(context(sent, generated_file(CONV, T + 15 * S), title)).events
    assert (e.verdict, e.timestamp, e.conversation_uuid) == (VERDICT_SUSPECTED, T, CONV)
    assert title.evidence_id in e.detail_refs                  # supporting line only


def test_no_generation_row_from_a_single_trace_or_an_unlinked_pair():
    from claude_web_forensics.analysis.detectors import detect_image_generation

    sent = analytics("q", event("claudeai.message.sent", T, conversation_uuid=CONV))
    title = rec(FAMILY_HISTORY, "t", T, conversation=CONV, subtype="visit",
                url=f"https://claude.ai/chat/{CONV}", title="이미지 생성 - Claude")
    cases = [
        (sent,), (title,), (generated_file(CONV, T),),                       # one trace alone
        (sent, generated_file(CONV, T + 15 * S, body_format="")),           # URL, body not an image
        (sent, generated_file(OTHER, T + 15 * S)),                          # other conversation
        (sent, generated_file(CONV, T - 15 * S)),                           # response before the send
        (title, generated_file(CONV, T + 15 * S)),                          # title is not a send
    ]
    for records in cases:
        assert detect_image_generation(context(*records)).events == [], records


def test_tree_and_tree_less_paths_merge_into_one_confirmed_row():
    from claude_web_forensics.analysis.detectors import detect_image_generation

    body = {"uuid": CONV, "created_at": "2026-09-22T16:59:41Z", "chat_messages": [
        {"uuid": "m1", "sender": "human", "created_at": "2026-09-22T16:59:41Z", "content": "강아지 그려줘"},
        {"uuid": "m2", "sender": "assistant", "parent_message_uuid": "m1",
         "created_at": "2026-09-22T16:59:50Z",
         "content": "File created successfully: /mnt/user-data/outputs/dog.png"}]}
    tree = rec(FAMILY_INDEXEDDB, "tree", conversation=CONV, key_kind="react_query_cache",
               record_state="LIVE",
               value={"clientState": {"queries": [{"state": {"data": body}}]}})
    sent = analytics("q", event("claudeai.message.sent", T, conversation_uuid=CONV))
    file = generated_file(CONV, T + 15 * S)
    [e] = detect_image_generation(context(tree, sent, file)).events
    assert e.verdict == VERDICT_CONFIRMED
    assert {tree.evidence_id, file.evidence_id} <= set(e.detail_refs)


def test_download_file_response_is_never_a_generated_image_download():
    from claude_web_forensics.analysis.detectors import detect_generated_image_download

    sent = analytics("q", event("claudeai.message.sent", T, conversation_uuid=CONV))
    assert detect_generated_image_download(context(sent, generated_file(CONV, T + 15 * S))).events == []


def test_conversation_store_trees_are_recovered_with_their_state():
    body = {"conversationUuid": CONV, "chat_messages": [
        {"uuid": "m1", "sender": "human", "content": "IndexedDB 질문"},
        {"uuid": "m2", "sender": "assistant", "parent_message_uuid": "m1", "content": "답변"}]}
    record = rec(FAMILY_INDEXEDDB, "trees", database="claude-conversation-store", object_store="trees",
                 record_state="HISTORICAL_OR_DELETED", value=body)
    messages = context(record).conversations.all_messages()
    assert [(m.message_uuid, m.content) for m in messages] == [("m1", "IndexedDB 질문"), ("m2", "답변")]
    assert all(m.conversation_uuid == CONV and m.record_state == "HISTORICAL_OR_DELETED" for m in messages)
    assert messages[1].parent_message_uuid == "m1"
    for database, object_store in [("unrelated", "trees"), ("claude-conversation-store", "meta")]:
        assert context(rec(FAMILY_INDEXEDDB, database + object_store, database=database,
                           object_store=object_store, value=body)).conversations.all_messages() == []


def test_cache_bodies_and_snapshot_bodies_never_supply_messages():
    body = {"uuid": CONV, "name": "대화 제목", "chat_messages": [
        {"uuid": "m1", "sender": "human", "content": "캐시 질문"}]}
    for kind in ["conversation_api", "conversation_list", "latest_or_snapshot"]:
        cached = rec(FAMILY_CACHE, kind, conversation=CONV, key_kind=kind,
                     snapshot_uuid="snapshot", _json={"snapshot": body} if kind == "latest_or_snapshot" else body)
        ctx = context(cached)
        assert ctx.conversations.all_messages() == []
        assert CONV in ctx.conversations.conversations
    idb_body = {**body, "chat_messages": [{"uuid": "m1", "sender": "human", "content": "IndexedDB 질문"}]}
    idb = rec(FAMILY_INDEXEDDB, "rq", key_kind="react_query_cache", record_state="LIVE",
              value={"clientState": {"queries": [{"state": {"data": idb_body}}]}})
    [message] = context(cached, idb).conversations.all_messages()
    assert message.content == "IndexedDB 질문" and message.evidence_ids == [idb.evidence_id]
