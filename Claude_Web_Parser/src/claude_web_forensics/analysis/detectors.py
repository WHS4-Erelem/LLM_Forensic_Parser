"""Deterministic action detectors (spec sections 16.5 and 17).

Every detector declares, in code:
  * candidate predicate
  * entity identity key
  * direct-evidence allowlist
  * independent-family requirement
  * temporal rule
  * disqualifiers
  * verdict + reason code

No confidence arithmetic. Absence of evidence never creates an event.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..model.entities import (
    FAMILY_CACHE,
    FAMILY_HISTORY,
    FAMILY_LOCAL_STORAGE,
    FAMILY_SESSIONS,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceRecord,
    EvidenceStore,
    FinalEvent,
    make_action_id,
)
from ..model.entities import (
    REASON_AMBIGUOUS,
    REASON_ARTIFACT_NOT_FOUND,
    REASON_NO_EVIDENCE,
    REASON_CONFLICTING,
    REASON_DETECTOR_FAILED,
    REASON_SINGLE_SNAPSHOT_LIMIT,
    CoverageRow,
)
from ..model.entities import FileTrace
from ..util.common import KST, from_webkit
from .accounts import AccountContext, link_account
from .rules import (
    ACTION_LABELS,
    compose_detail,
    first_meaningful_line,
    label_for,
    rule_for,
)
from .conversations import ConversationBuilder, ConversationInfo
from .correlator import Correlator, EvidenceGroup
from .file_analysis import FileLifecycle
from .summaries import summarize_group
from .rules import VerdictInput, VerdictResult, decide


@dataclass
class DetectorContext:
    store: EvidenceStore
    correlator: Correlator
    conversations: ConversationBuilder
    account_ctx: AccountContext
    file_traces: list[FileTrace]
    lifecycles: dict[str, FileLifecycle]
    extended_fs: bool
    rename_pairs: list[Any] = field(default_factory=list)
    usn_records: list[Any] = field(default_factory=list)
    recycle_entries: list[Any] = field(default_factory=list)
    artifact_available: dict[str, bool] = field(default_factory=dict)

    def family_available(self, family: str) -> bool:
        return self.artifact_available.get(family, False)


@dataclass
class DetectorResult:
    events: list[FinalEvent] = field(default_factory=list)
    coverage: list[CoverageRow] = field(default_factory=list)


def _account_for(ctx: DetectorContext, records: Iterable[EvidenceRecord]) -> str | None:
    """Resolve the account for a set of records, or leave it empty."""
    from .accounts import best_link

    links = [link_account(r, ctx.account_ctx) for r in records if r is not None]
    if not links:
        return None
    return best_link(links).account_uuid


def _build_event(
    rule_id: str,
    action_code: str,
    identity: dict[str, str],
    timestamp: dt.datetime | None,
    account_uuid: str | None,
    target: str,
    group: EvidenceGroup,
    result: VerdictResult,
    *,
    ctx: DetectorContext | None = None,
    nature: str = "",
    core: str | None = None,
    conversation_uuid: str | None = None,
    timestamp_basis: str = "",
) -> FinalEvent:
    """Build the final event.

    The action name always comes from the catalogue (label_for); a detector
    cannot rename an action. What kind of trace was found goes into 행위_상세
    as "<nature>_<core>". Artifact details are derived from the records the
    detector actually relied on.
    """
    artifact_details: list[str] = []
    if ctx is not None:
        records = [ctx.store.get(eid) for eid in group.evidence_ids]
        artifact_details = summarize_group([r for r in records if r is not None])

    return FinalEvent(
        action_id=make_action_id(rule_id, identity),
        timestamp=timestamp,
        action_code=action_code,
        action_label=label_for(action_code),
        action_detail=compose_detail(nature, target if core is None else core),
        verdict=result.verdict,
        account_uuid=account_uuid,
        conversation_uuid=conversation_uuid,
        target=target,
        evidence_artifacts=result.artifacts,
        artifact_details=artifact_details,
        detail_refs=list(group.evidence_ids),
        rule_id=rule_id,
        reason_code=result.reason_code,
        families=result.families,
        timestamp_basis=timestamp_basis,
    )


def _coverage(
    action_code: str,
    label: str,
    rule_id: str,
    events: list[FinalEvent],
    reason: str = "",
    message: str = "",
) -> CoverageRow:
    if events:
        verdicts = {e.verdict for e in events}
        if VERDICT_CONFIRMED in verdicts:
            best = VERDICT_CONFIRMED
        elif VERDICT_SUSPECTED in verdicts:
            best = VERDICT_SUSPECTED
        else:
            # Evidence exists but every event is undetermined (e.g. conflicting).
            return CoverageRow(
                action_code=action_code,
                action_label=label,
                rule_id=rule_id,
                status=VERDICT_UNDETERMINED,
                reason=REASON_CONFLICTING,
                event_count=len(events),
                message=message or "; ".join(sorted({e.reason_code for e in events if e.reason_code})),
            )
        return CoverageRow(
            action_code=action_code,
            action_label=label,
            rule_id=rule_id,
            status=best,
            reason="",
            event_count=len(events),
            message=message,
        )
    return CoverageRow(
        action_code=action_code,
        action_label=label,
        rule_id=rule_id,
        status=VERDICT_UNDETERMINED,
        reason=reason or REASON_NO_EVIDENCE,
        event_count=0,
        message=message,
    )


# ===========================================================================
# E01 -- login / logout / account switch
# ===========================================================================

_AUTH_URL_MARKERS = ("/magic-link", "/login", "/oauth", "/auth/")
_LOGOUT_URL_MARKERS = ("/logout", "login?from=logout")


def detect_login(ctx: DetectorContext) -> DetectorResult:
    """R-E0101.

    predicate  : authentication-flow URL observed in History or Sessions
    identity   : account_uuid + authentication URL
    direct     : explicit magic-link / auth callback record carrying a token
    families   : >= 2 (history + sessions, or history + cookies)
    temporal   : none (the auth record itself carries the time)
    disqualify : current session cookie alone; a single /new visit alone
    """
    rule_id = "R-E0101"
    code = "E01-01"
    label = label_for(code)
    events: list[FinalEvent] = []

    auth_records = [
        r
        for r in ctx.store
        if r.artifact_family in (FAMILY_HISTORY, FAMILY_SESSIONS)
        and any(m in str(r.attributes.get("url", "")).lower() for m in _AUTH_URL_MARKERS)
    ]
    if not auth_records:
        return DetectorResult(
            coverage=[_coverage(code, label, rule_id, [], REASON_NO_EVIDENCE,
                                "no authentication-flow URL observed")]
        )

    # A magic-link URL carrying a token fragment is an explicit auth record.
    direct = [
        r
        for r in auth_records
        if "/magic-link#" in str(r.attributes.get("url", ""))
    ]

    # Session cookies corroborate, but never on their own (spec section 17).
    cookie_records = [
        r
        for r in ctx.store.by_family("cookies")
        if r.attributes.get("is_session_cookie_name")
    ]

    members = list(auth_records)
    if direct:
        members.extend(cookie_records)

    group = ctx.correlator.group(members)
    # Representative time = the record that directly demonstrates the login
    # (the magic-link callback), not simply the earliest corroborating record.
    basis_records = direct or auth_records
    timestamp = min((r.timestamp for r in basis_records if r.timestamp), default=None)
    timestamp_basis = "history_magic_link" if direct else "history_auth_url"
    account = _account_for(ctx, auth_records)

    disqualifiers: list[str] = []
    if not direct and group.independent_family_count < 2:
        disqualifiers.append(
            "only a generic /login visit observed; a current cookie or a single "
            "/new visit does not confirm a past login"
        )

    result = decide(
        VerdictInput(
            rule_id=rule_id,
            group=group,
            direct_evidence=bool(direct),
            direct_evidence_reason="magic-link authentication URL with token fragment",
            disqualifiers=disqualifiers,
        )
    )
    identity = {"account_uuid": account or "", "auth_flow": "claude_web_login"}
    events.append(
        _build_event(
                     rule_id, code, identity, timestamp, account, "Claude 로그인 흐름", group, result,
                     ctx=ctx,
                     nature="magic-link 인증 URL 방문" if direct
                     else "로그인 URL 방문 흔적(인증 완료 미확인)",
                     core="", timestamp_basis=timestamp_basis)
    )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_logout(ctx: DetectorContext) -> DetectorResult:
    """R-E0102.

    predicate  : explicit /logout or /login?from=logout URL, or a
                 Local Storage *logout-at marker
    identity   : account_uuid + logout URL/event
    direct     : explicit logout URL record
    families   : >= 2 to confirm; direct URL alone also confirms
    disqualify : absence of cookies is never a logout
    """
    rule_id = "R-E0102"
    code = "E01-02"
    label = label_for(code)

    url_records = [
        r
        for r in ctx.store
        if r.artifact_family in (FAMILY_HISTORY, FAMILY_SESSIONS)
        and any(m in str(r.attributes.get("url", "")).lower() for m in _LOGOUT_URL_MARKERS)
    ]
    ls_records = [
        r
        for r in ctx.store.by_family(FAMILY_LOCAL_STORAGE)
        if "logout" in str(r.attributes.get("script_key", "")).lower()
    ]

    if not url_records and not ls_records:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E01-02", label, rule_id, [], REASON_NO_EVIDENCE,
                    "no /logout URL and no logout-at marker; cookie absence is not used",
                )
            ]
        )

    members = url_records + ls_records
    group = ctx.correlator.group(members)
    basis_records = url_records or ls_records
    timestamp = min((r.timestamp for r in basis_records if r.timestamp), default=None)
    account = _account_for(ctx, members)
    result = decide(
        VerdictInput(
            rule_id=rule_id,
            group=group,
            direct_evidence=bool(url_records),
            direct_evidence_reason="explicit logout URL record",
        )
    )
    events = [
        _build_event(
                     rule_id, code, {"account_uuid": account or "", "flow": "logout"},
                     timestamp, account, "Claude 로그아웃", group, result,
                     ctx=ctx,
                     nature="로그아웃 URL 방문" if url_records else "로그아웃 시각 기록",
                     core="",
                     timestamp_basis="history_logout_url" if url_records
                     else "local_storage_logout_marker")
    ]
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_account_switch(ctx: DetectorContext) -> DetectorResult:
    """R-E0103.

    predicate  : two or more DISTINCT current-account contexts in time order,
                 plus a reauth/onboarding or explicit switch event
    identity   : ordered pair of account UUIDs
    disqualify : multiple residual UUIDs alone are "multi-account traces",
                 never a switch with a time (spec section 17)
    """
    rule_id = "R-E0103"
    code = "E01-03"
    label = label_for(code)
    accounts = sorted(ctx.account_ctx.account_uuids)

    if len(accounts) < 2:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E01-03", label, rule_id, [], REASON_NO_EVIDENCE,
                    f"{len(accounts)} account UUID observed; a switch needs two ordered contexts",
                )
            ]
        )

    reauth = [
        r
        for r in ctx.store
        if any(
            m in str(r.attributes.get("url", "")).lower()
            for m in ("/magic-link", "/onboarding", "login?returnTo")
        )
    ]
    if not reauth:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E01-03", label, rule_id, [], REASON_AMBIGUOUS,
                    "multiple account UUIDs present but no reauth/onboarding or explicit "
                    "switch event; residual UUIDs alone do not establish a switch time",
                )
            ]
        )

    group = ctx.correlator.group(reauth)
    timestamp = min((r.timestamp for r in reauth if r.timestamp), default=None)
    result = decide(VerdictInput(rule_id=rule_id, group=group))
    events = [
        _build_event(
            rule_id, code, {"accounts": ",".join(accounts)}, timestamp, None,
            f"{accounts[0][:8]} -> {accounts[1][:8]}", group, result, ctx=ctx,
            nature="재인증 이벤트와 복수 계정 컨텍스트",
            core=f"{accounts[0]} → {accounts[1]}",
            timestamp_basis="reauth_event",
        )
    ]
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# E03 -- conversation create / delete / edit / retry
# ===========================================================================

def detect_new_conversation(ctx: DetectorContext) -> DetectorResult:
    """R-E0301.

    predicate  : conversation UUID + created_at + a root user message
    identity   : conversation_uuid
    direct     : a complete conversation API object with a root message
    families   : >= 2 (Cache + IndexedDB)
    """
    rule_id = "R-E0301"
    code = "E03-01"
    label = label_for(code)
    events: list[FinalEvent] = []

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        roots = [m for m in info.root_messages if m.role == "user"]
        if not info.created_at or not roots:
            continue
        records = ctx.correlator.by_conversation(uuid)
        group = ctx.correlator.group(records)
        account = _account_for(ctx, records)
        direct = FAMILY_CACHE in info.families and bool(roots)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=direct,
                direct_evidence_reason=(
                    "complete conversation API object with created_at and a root user message"
                ),
            )
        )
        events.append(
            _build_event(
                rule_id, code, {"conversation_uuid": uuid}, info.created_at, account,
                info.title or uuid, group, result, ctx=ctx,
                nature="대화 생성 기록", core=info.title, conversation_uuid=uuid,
                timestamp_basis="conversation_created_at",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_conversation_delete(ctx: DetectorContext) -> DetectorResult:
    """R-E0302.

    predicate  : explicit delete request/event/tombstone
    identity   : conversation_uuid
    disqualify : Cache residue alone is NOT deletion; absence from a current
                 list is not proof. We never say "permanently deleted on the
                 server" (spec section 17).
    """
    rule_id = "R-E0302"
    code = "E03-02"
    label = label_for(code)

    tombstones = [
        r
        for r in ctx.store
        if str(r.attributes.get("cache_key", "")).lower().find("delete") >= 0
        or "tombstone" in str(r.attributes.get("key_text", "")).lower()
    ]
    if not tombstones:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E03-02", label, rule_id, [], REASON_SINGLE_SNAPSHOT_LIMIT,
                    "no explicit delete request/event/tombstone; Cache residue alone is "
                    "not treated as deletion",
                )
            ]
        )

    events: list[FinalEvent] = []
    for record in tombstones:
        conv = record.conversation_uuid or ""
        group = ctx.correlator.group([record] + ctx.correlator.by_conversation(conv))
        result = decide(VerdictInput(rule_id=rule_id, group=group, direct_evidence=True,
                                     direct_evidence_reason="explicit delete request/tombstone"))
        events.append(
            _build_event(
                         rule_id, code, {"conversation_uuid": conv}, record.timestamp,
                         _account_for(ctx, [record]), conv, group, result, ctx=ctx,
                         nature="대화 삭제 요청/이벤트",
                         core=_conversation_title(ctx, conv) or conv,
                         conversation_uuid=conv, timestamp_basis="delete_event")
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_conversation_edit(ctx: DetectorContext) -> DetectorResult:
    """R-E0303.

    predicate  : two or more DISTINCT human message UUIDs under the same parent
    identity   : conversation_uuid + parent_message_uuid
    disqualify : two differing texts alone are not an edit
    """
    rule_id = "R-E0303"
    code = "E03-03"
    label = label_for(code)
    events: list[FinalEvent] = []

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        parents: dict[str, list] = {}
        for message in info.messages.values():
            if message.role != "user":
                continue
            parents.setdefault(message.parent_message_uuid or "<root>", []).append(message)
        for parent, siblings in parents.items():
            if len(siblings) < 2:
                continue
            records = [
                ctx.store.get(eid)
                for message in siblings
                for eid in message.evidence_ids
            ]
            group = ctx.correlator.group([r for r in records if r])
            account = _account_for(ctx, [r for r in records if r])
            result = decide(
                VerdictInput(
                    rule_id=rule_id,
                    group=group,
                    direct_evidence=len({m.message_uuid for m in siblings}) >= 2
                    and FAMILY_CACHE in info.families,
                    direct_evidence_reason=(
                        "multiple distinct human message UUIDs share one parent in the "
                        "conversation tree"
                    ),
                )
            )
            timestamp = max((m.timestamp for m in siblings if m.timestamp), default=None)
            events.append(
                _build_event(
                    rule_id, code,
                    {"conversation_uuid": uuid, "parent_message_uuid": parent},
                    timestamp, account, info.title or uuid, group, result, ctx=ctx,
                    nature="동일 부모 아래 사용자 메시지 분기", core=info.title,
                    conversation_uuid=uuid,
                    timestamp_basis="branch_message_created_at",
                )
            )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_retry(ctx: DetectorContext) -> DetectorResult:
    """R-E0304.

    predicate  : multiple assistant children under one human parent
    identity   : conversation_uuid + human parent message_uuid
    direct     : input_mode=retry attached to one of those assistant branches
    """
    rule_id = "R-E0304"
    code = "E03-04"
    label = label_for(code)
    events: list[FinalEvent] = []

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        parents: dict[str, list] = {}
        for message in info.messages.values():
            if message.role != "assistant" or not message.parent_message_uuid:
                continue
            parents.setdefault(message.parent_message_uuid, []).append(message)
        for parent, children in parents.items():
            if len(children) < 2:
                continue
            retry_marker = [m for m in children if str(m.input_mode).lower() == "retry"]
            records = [
                ctx.store.get(eid) for message in children for eid in message.evidence_ids
            ]
            group = ctx.correlator.group([r for r in records if r])
            account = _account_for(ctx, [r for r in records if r])
            result = decide(
                VerdictInput(
                    rule_id=rule_id,
                    group=group,
                    direct_evidence=bool(retry_marker),
                    direct_evidence_reason="input_mode=retry is attached directly to an "
                                           "assistant branch under the same human parent",
                )
            )
            timestamp = max((m.timestamp for m in children if m.timestamp), default=None)
            events.append(
                _build_event(
                    rule_id, code,
                    {"conversation_uuid": uuid, "parent_message_uuid": parent},
                    timestamp, account, info.title or uuid, group, result, ctx=ctx,
                    nature="동일 사용자 메시지 아래 응답 분기", core=info.title,
                    conversation_uuid=uuid,
                    timestamp_basis="retry_branch_created_at",
                )
            )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# E04 -- prompt input / send (drafts included)
# ===========================================================================

def detect_prompt(ctx: DetectorContext) -> DetectorResult:
    """R-E0401: sent user messages (확정) and composer drafts (의심).

    Both are E04-01 -- one action, one coverage row. A draft is reported under
    the same action name with "프롬프트 작성 흔적(전송 미확인)" in 행위_상세.
    """
    rule_id = "R-E0401"
    code = "E04-01"
    label = label_for(code)
    events = _prompt_sent_events(ctx) + _prompt_draft_events(ctx)
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def _prompt_sent_events(ctx: DetectorContext) -> list[FinalEvent]:
    """predicate  : a real user message UUID with created_at in a conversation
    identity   : message_uuid
    direct     : the sent user message object itself
    families   : assistant reply / second family corroborates
    """
    events: list[FinalEvent] = []
    rule_id = "R-E0401"
    code = "E04-01"

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        for message in sorted(
            info.messages.values(), key=lambda m: (m.timestamp is None, m.timestamp or dt.datetime.min.replace(tzinfo=KST))
        ):
            if message.role != "user" or not message.message_uuid or not message.timestamp:
                continue
            records = [ctx.store.get(eid) for eid in message.evidence_ids]
            records = [r for r in records if r]
            group = ctx.correlator.group(records)
            account = _account_for(ctx, records) or info.account_uuid
            result = decide(
                VerdictInput(
                    rule_id=rule_id,
                    group=group,
                    direct_evidence=True,
                    direct_evidence_reason=(
                        "actual user message UUID with created_at in the conversation tree"
                    ),
                )
            )
            preview = first_meaningful_line(message.content)
            events.append(
                _build_event(
                    rule_id, code, {"message_uuid": message.message_uuid},
                    message.timestamp, account,
                    (preview[:60] or info.title or uuid), group, result, ctx=ctx,
                    nature="사용자 메시지 전송", core=preview,
                    conversation_uuid=uuid,
                    timestamp_basis="user_message_created_at",
                )
            )
    return events


def _prompt_draft_events(ctx: DetectorContext) -> list[FinalEvent]:
    """Draft only -- ALWAYS 의심 under E04-01.

    A draft proves composition, never transmission, so it can never be 확정
    (spec section 17). The partial nature is stated in 행위_상세 only.
    """
    rule_id = "R-E0401"
    code = "E04-01"
    events: list[FinalEvent] = []

    sent_texts = {
        m.content.strip()
        for info in ctx.conversations.conversations.values()
        for m in info.messages.values()
        if m.role == "user" and m.content.strip()
    }

    # One event per distinct draft text. LevelDB keeps many historical versions
    # of the same composer draft; they are one composition, not many.
    by_text: dict[str, list] = {}
    for draft in ctx.conversations.drafts:
        text = draft.text.strip()
        if not text or text in sent_texts:
            continue  # already proven sent; the sent event covers it
        by_text.setdefault(text, []).append(draft)

    for text, versions in by_text.items():
        # Earliest defensible timestamp across the observed versions.
        timestamps = [d.timestamp for d in versions if d.timestamp]
        draft = versions[0]
        draft_timestamp = min(timestamps) if timestamps else None
        evidence_ids = [eid for d in versions for eid in d.evidence_ids]
        records = [ctx.store.get(eid) for eid in evidence_ids]
        records = [r for r in records if r]
        group = ctx.correlator.group(records)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                # Never allowlisted: a draft cannot confirm transmission.
                direct_evidence=False,
                disqualifiers=["draft only; transmission not observed"],
            )
        )
        events.append(
            _build_event(
                rule_id, code, {"text_head": text[:80]},
                draft_timestamp, draft.account_uuid or _account_for(ctx, records),
                first_meaningful_line(text)[:60], group, result, ctx=ctx,
                nature="프롬프트 작성 흔적(전송 미확인)",
                core=first_meaningful_line(text),
                timestamp_basis="draft_updated_at",
            )
        )
    return events


# ===========================================================================
# E05 -- upload / attachment removal / document download
# ===========================================================================

def _upload_events(
    ctx: DetectorContext, rule_id: str, code: str, wanted_image: bool
) -> DetectorResult:
    label = label_for(code)
    events: list[FinalEvent] = []
    for trace in ctx.file_traces:
        if trace.direction != "uploaded":
            continue
        is_image = "image" in (trace.mime or "").lower() or trace.original_name.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg")
        )
        if is_image != wanted_image:
            continue
        records = [ctx.store.get(eid) for eid in trace.evidence_ids]
        records = [r for r in records if r]
        group = ctx.correlator.group(records)
        account = trace.account_uuid or _account_for(ctx, records)
        sent = bool(trace.attributes.get("sent_in_message"))
        disqualifiers = [] if sent else ["attachment metadata present but no sent message links it"]
        # Upload time = created_at of the message that actually carried the
        # attachment. Never the conversation's creation time; if the sending
        # message cannot be pinned down, the time stays empty.
        timestamp = _iso(trace.attributes.get("message_created_at")) if sent else None
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=sent,
                direct_evidence_reason="attachment linked to a sent user message with file metadata",
                disqualifiers=disqualifiers,
            )
        )
        kind = "이미지" if wanted_image else "문서"
        nature = "전송 메시지 첨부" if sent else f"{kind} 업로드 준비 흔적(전송 불확인)"
        events.append(
            _build_event(
                rule_id, code,
                {"file_uuid": trace.file_uuid or trace.original_name,
                 "conversation_uuid": trace.conversation_uuid or ""},
                timestamp, account, trace.original_name, group, result, ctx=ctx,
                nature=nature, core=trace.original_name,
                conversation_uuid=trace.conversation_uuid,
                timestamp_basis="attachment_message_created_at" if timestamp else "",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_image_upload(ctx: DetectorContext) -> DetectorResult:
    """R-E0501: image upload. Draft/blob metadata alone stays 의심."""
    return _upload_events(ctx, "R-E0501", "E05-01", wanted_image=True)


def detect_document_upload(ctx: DetectorContext) -> DetectorResult:
    """R-E0503: document upload. Draft/blob metadata alone stays 의심."""
    return _upload_events(ctx, "R-E0503", "E05-03", wanted_image=False)


def _attachment_removal(ctx: DetectorContext, rule_id: str, code: str) -> DetectorResult:
    """R-E0502 / R-E0504.

    Residual attachment metadata is NOT removal evidence. An explicit removal
    event/tombstone, or a verifiable prior attachment on the same draft identity
    now shown as removed, is required. Otherwise no event is created.
    """
    label = label_for(code)
    removal = [
        r
        for r in ctx.store
        if "removal" in str(r.attributes.get("key_text", "")).lower()
        or "attachment_removed" in str(r.attributes.get("value_preview", "")).lower()
    ]
    if not removal:
        return DetectorResult(
            coverage=[
                _coverage(
                    code, label, rule_id, [], REASON_SINGLE_SNAPSHOT_LIMIT,
                    "no explicit removal event/tombstone; residual attachment metadata is "
                    "not treated as removal evidence",
                )
            ]
        )
    events: list[FinalEvent] = []
    for record in removal:
        group = ctx.correlator.group([record])
        result = decide(VerdictInput(rule_id=rule_id, group=group, direct_evidence=True,
                                     direct_evidence_reason="explicit attachment removal event"))
        events.append(
            _build_event(
                         rule_id, code, {"evidence": record.evidence_id}, record.timestamp,
                         _account_for(ctx, [record]), record.summary, group, result, ctx=ctx,
                         nature="첨부 제거 이벤트", core=record.summary,
                         timestamp_basis="removal_event")
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_image_attachment_removed(ctx: DetectorContext) -> DetectorResult:
    return _attachment_removal(ctx, "R-E0502", "E05-02")


def detect_document_attachment_removed(ctx: DetectorContext) -> DetectorResult:
    return _attachment_removal(ctx, "R-E0504", "E05-04")


def _download_events(
    ctx: DetectorContext,
    rule_id: str,
    code: str,
    mime_predicate: Callable[[str, str], bool],
) -> DetectorResult:
    """Shared logic for E05-05 and E06-02.

    predicate  : History downloads record for a Claude URL
    identity   : download URL + target path
    direct     : COMPLETE state with a target path and a Claude URL chain
    families   : History + Zone.Identifier / filesystem file corroborate
    temporal   : completion uses downloads.end_time, an attempt uses start_time
    """
    label = label_for(code)
    events: list[FinalEvent] = []
    for record in ctx.store.by_family(FAMILY_HISTORY):
        if record.attributes.get("subtype") != "download":
            continue
        name = str(record.attributes.get("file_name") or "")
        mime = str(record.attributes.get("mime_type") or "")
        if not mime_predicate(name, mime):
            continue

        target = str(
            record.attributes.get("target_path") or record.attributes.get("current_path") or ""
        )
        members = [record]
        # Correlate by EXACT path / hash, never by filename alone.
        for trace in ctx.file_traces:
            if trace.direction != "downloaded":
                continue
            same_path = (
                trace.original_path
                and target
                and trace.original_path.replace("/", "\\").lower() == target.replace("/", "\\").lower()
            )
            same_remote = (
                trace.zone_host_url
                and any(
                    trace.zone_host_url == u for u in record.attributes.get("chain_urls", [])
                )
            )
            if same_path or same_remote:
                members.extend(ctx.store.get(eid) for eid in trace.evidence_ids)

        members = [m for m in members if m]
        group = ctx.correlator.group(members)
        account = _account_for(ctx, members)
        state = record.attributes.get("state")
        complete = state == 1
        disqualifiers = []
        nature = "다운로드 완료 기록"
        if not complete:
            nature = "다운로드 시도 흔적(완료 미확인)"
            disqualifiers.append(
                f"download state={record.attributes.get('state_label')} (not COMPLETE)"
            )
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=complete and bool(target)
                and bool(record.attributes.get("chain_urls")),
                direct_evidence_reason=(
                    "History downloads record in COMPLETE state with a target path and a "
                    "Claude URL chain"
                ),
                disqualifiers=disqualifiers,
            )
        )
        # Representative time: completion uses downloads.end_time, an
        # unfinished attempt uses downloads.start_time.
        if complete:
            timestamp = from_webkit(record.attributes.get("end_time")) or record.timestamp
            basis = "history_downloads_end_time"
        else:
            timestamp = record.timestamp
            basis = "history_downloads_start_time"

        events.append(
            _build_event(
                rule_id, code,
                {"download_url": ",".join(record.attributes.get("chain_urls", [])[:1]),
                 "target_path": target},
                timestamp, account, name or target, group, result, ctx=ctx,
                nature=nature, core=name or target,
                conversation_uuid=record.conversation_uuid,
                timestamp_basis=basis,
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico")


def detect_document_download(ctx: DetectorContext) -> DetectorResult:
    """R-E0505: document download."""
    return _download_events(
        ctx, "R-E0505", "E05-05",
        lambda name, mime: not (
            name.lower().endswith(_IMAGE_EXT) or mime.lower().startswith("image/")
        ),
    )


def detect_generated_image_download(ctx: DetectorContext) -> DetectorResult:
    """R-E0602: generated-image download."""
    return _download_events(
        ctx, "R-E0602", "E06-02",
        lambda name, mime: name.lower().endswith(_IMAGE_EXT) or mime.lower().startswith("image/"),
    )


# ===========================================================================
# E06 -- image generation / download / local deletion
# ===========================================================================

_GENERATED_MARKERS = ("/mnt/user-data/outputs/", "file created successfully")


def detect_image_generation(ctx: DetectorContext) -> DetectorResult:
    """R-E0601.

    predicate  : an assistant tool result / generated-resource object linked to
                 a real user message
    identity   : conversation_uuid + assistant message_uuid
    disqualify : a prompt merely containing the words "generate an image" is
                 never sufficient (spec section 17)
    """
    rule_id = "R-E0601"
    code = "E06-01"
    label = label_for(code)
    events: list[FinalEvent] = []

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        user_messages = [m for m in info.messages.values() if m.role == "user"]
        if not user_messages:
            continue
        outputs: list[Any] = []
        for message in info.messages.values():
            if message.role != "assistant":
                continue
            content = message.content.lower()
            if any(marker in content for marker in _GENERATED_MARKERS):
                if any(content.find(ext) >= 0 for ext in _IMAGE_EXT):
                    outputs.append(message)
        if not outputs:
            continue

        records = [
            ctx.store.get(eid) for message in outputs for eid in message.evidence_ids
        ]
        records = [r for r in records if r]
        group = ctx.correlator.group(records)
        account = _account_for(ctx, records)
        timestamp = max((m.timestamp for m in outputs if m.timestamp), default=None)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=True,
                direct_evidence_reason=(
                    "assistant tool result / generated image resource object linked to a "
                    "real user message"
                ),
            )
        )
        events.append(
            _build_event(
                rule_id, code, {"conversation_uuid": uuid},
                timestamp, account, info.title or uuid, group, result, ctx=ctx,
                nature="생성 이미지 결과 객체", core=info.title, conversation_uuid=uuid,
                timestamp_basis="assistant_output_created_at",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_downloaded_file_deleted(ctx: DetectorContext) -> DetectorResult:
    """R-E0603.

    predicate  : $I deletion metadata, USN FILE_DELETE, or a verified deleted
                 MFT entry for a file that History proves was downloaded
    identity   : original path + FRN
    families   : recycle_bin + history + filesystem_file
    disqualify : History proves the DOWNLOAD only, never the local deletion
    """
    rule_id = "R-E0603"
    code = "E06-03"
    label = label_for(code)
    events: list[FinalEvent] = []

    if not ctx.extended_fs:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E06-03", label, rule_id, [], REASON_ARTIFACT_NOT_FOUND,
                    "--extended-fs not enabled: $Recycle.Bin / $UsnJrnl not analysed",
                )
            ]
        )

    download_records = [
        r
        for r in ctx.store.by_family(FAMILY_HISTORY)
        if r.attributes.get("subtype") == "download"
    ]

    for trace in ctx.file_traces:
        if not trace.attributes.get("deleted"):
            continue
        members = [ctx.store.get(eid) for eid in trace.evidence_ids]
        members = [m for m in members if m]

        # Link the deletion to the download by EXACT original path.
        matched_download = None
        for record in download_records:
            target = str(
                record.attributes.get("target_path")
                or record.attributes.get("current_path")
                or ""
            )
            if target and trace.original_path and (
                target.replace("/", "\\").lower()
                == trace.original_path.replace("/", "\\").lower()
            ):
                matched_download = record
                members.append(record)
                break

        # USN lifecycle for the same file adds an independent family.
        final_path = ""
        for life in ctx.lifecycles.values():
            if life.original_path and trace.original_path and (
                life.original_path.replace("/", "\\").lower()
                == trace.original_path.replace("/", "\\").lower()
            ):
                members.extend(ctx.store.get(eid) for eid in life.evidence_ids)
                for record in ctx.store.by_family("usn"):
                    if (
                        record.attributes.get("file_reference") == life.file_reference
                        and record.attributes.get("volume_id", life.volume_id) == life.volume_id
                    ):
                        members.append(record)
                if life.reliable and life.final_path:
                    final_path = life.final_path

        members = [m for m in members if m]
        group = ctx.correlator.group(members)
        account = _account_for(ctx, members)
        conflicts: list[str] = []
        if matched_download is None:
            conflicts.append(
                "deleted file could not be linked to a Claude download by exact path"
            )
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=bool(trace.deletion_time) and matched_download is not None,
                direct_evidence_reason="$I deletion metadata for a file proven downloaded from Claude",
                conflicts=conflicts,
            )
        )
        # 행위_상세: original location -> where the file ended up.
        destination = final_path or str(trace.attributes.get("recycle_token") and "$Recycle.Bin" or "")
        detail = trace.original_path or trace.original_name
        if destination:
            detail = f"{detail} → {destination}"

        events.append(
            _build_event(
                rule_id, code,
                {"original_path": trace.original_path, "frn": trace.mft_reference or ""},
                trace.deletion_time, account, trace.original_name or trace.original_path,
                group, result, ctx=ctx,
                nature="휴지통 이동 기록" if trace.deletion_time else "USN 삭제 기록",
                core=detail, conversation_uuid=trace.conversation_uuid,
                timestamp_basis="recycle_bin_i_deletion_time"
                if trace.deletion_time else "usn_delete_event",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# E07 -- data export / share link
# ===========================================================================

def detect_export(ctx: DetectorContext) -> DetectorResult:
    """R-E0701.

    A visit to the export settings page is "Export 화면 접근" (의심), never
    Export completion. Completion needs an export API request, an export
    archive/download, or an explicit completion object (spec section 17).
    """
    rule_id = "R-E0701"
    code = "E07-01"
    label = label_for(code)

    settings_visits = [
        r
        for r in ctx.store
        if "export-data" in str(r.attributes.get("url", "")).lower()
        or "data-privacy-controls" in str(r.attributes.get("url", "")).lower()
    ]
    completions = [
        r
        for r in ctx.store
        if "export" in str(r.attributes.get("cache_key", "")).lower()
        and any(
            token in str(r.attributes.get("cache_key", "")).lower()
            for token in ("/api/", "archive", "download")
        )
    ]

    events: list[FinalEvent] = []
    coverage: list[CoverageRow] = []

    if completions:
        group = ctx.correlator.group(completions + settings_visits)
        timestamp = min((r.timestamp for r in completions if r.timestamp), default=None)
        result = decide(
            VerdictInput(rule_id=rule_id, group=group, direct_evidence=True,
                         direct_evidence_reason="export API request / archive object observed")
        )
        events.append(
            _build_event(
                         rule_id, code, {"flow": "export_complete"}, timestamp,
                         _account_for(ctx, completions), "대화 데이터 Export", group, result,
                         ctx=ctx, nature="Export 요청/아카이브 확인",
                         core=_first_url(completions, "cache_key"),
                         timestamp_basis="export_api_object")
        )
        coverage.append(_coverage(code, label, rule_id, events))
        return DetectorResult(events=events, coverage=coverage)

    if settings_visits:
        group = ctx.correlator.group(settings_visits)
        timestamp = min((r.timestamp for r in settings_visits if r.timestamp), default=None)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=False,
                disqualifiers=[
                    "settings page visit only; no export API request, archive or completion object"
                ],
            )
        )
        events.append(
            # Screen access is E07-01 at 의심: the action name stays fixed and
            # "completion not observed" is stated in 행위_상세.
            _build_event(rule_id, code, {"flow": "export_screen_access"}, timestamp,
                         _account_for(ctx, settings_visits), "Export 설정 화면", group, result,
                         ctx=ctx,
                         nature="Export 설정 화면 접근(완료 미확인)",
                         core=_first_url(settings_visits, "url"),
                         timestamp_basis="history_settings_visit")
        )
        coverage.append(
            _coverage(code, label, rule_id, events,
                      message="settings-screen access only; export completion not observed")
        )
        return DetectorResult(events=events, coverage=coverage)

    return DetectorResult(
        coverage=[_coverage(code, label, rule_id, [], REASON_NO_EVIDENCE,
                            "no export settings visit and no export API object")]
    )


def detect_share_link(ctx: DetectorContext) -> DetectorResult:
    """R-E0702.

    predicate  : a snapshot object mapping a snapshot UUID to a conversation
    identity   : snapshot_uuid + conversation_uuid
    direct     : the snapshot object itself
    disqualify : visiting a share page is not link creation
    """
    rule_id = "R-E0702"
    code = "E07-02"
    label = label_for(code)
    events: list[FinalEvent] = []

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        if not info.snapshot_uuid:
            continue
        records = ctx.correlator.by_conversation(uuid)
        snapshot_records = [
            r for r in ctx.store if r.attributes.get("snapshot_uuid") == info.snapshot_uuid
        ]
        group = ctx.correlator.group(snapshot_records + records)
        account = _account_for(ctx, snapshot_records or records)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=True,
                direct_evidence_reason=(
                    "snapshot object maps snapshot_uuid to conversation_uuid"
                ),
            )
        )
        events.append(
            _build_event(
                rule_id, code,
                {"snapshot_uuid": info.snapshot_uuid, "conversation_uuid": uuid},
                info.snapshot_created_at or info.updated_at, account,
                info.title or uuid, group, result, ctx=ctx,
                nature="공유 스냅샷 객체", core=info.title, conversation_uuid=uuid,
                timestamp_basis="snapshot_created_at",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# E09 -- model change / account rename
# ===========================================================================

def detect_model_change(ctx: DetectorContext) -> DetectorResult:
    """R-E0901.

    predicate  : previous_model -> model transition, or a time-ordered model
                 change inside ONE conversation
    identity   : conversation_uuid + (from_model, to_model)
    disqualify : a single current model value never creates a change event
    """
    rule_id = "R-E0901"
    code = "E09-01"
    label = label_for(code)
    events: list[FinalEvent] = []
    seen_transitions: set[tuple[str, str, str]] = set()

    # (a) Explicit model_selector analytics event carrying previous_model.
    # This survives in a single snapshot even when per-message model fields do
    # not, and it states the transition directly.
    for record in ctx.store.by_family(FAMILY_LOCAL_STORAGE):
        for selection in record.attributes.get("model_selection_events", []) or []:
            previous = str(selection.get("previous_model") or "")
            current = str(selection.get("model") or "")
            if not previous or not current or previous == current:
                continue
            timestamp = _iso(selection.get("eventTimestamp"))
            key = ("analytics", previous, current)
            if key in seen_transitions:
                continue
            seen_transitions.add(key)
            group = ctx.correlator.group([record])
            account = (
                str(selection.get("account_uuid") or "").lower() or record.account_uuid
            )
            result = decide(
                VerdictInput(
                    rule_id=rule_id,
                    group=group,
                    direct_evidence=True,
                    direct_evidence_reason=(
                        "model_selector.model_selected analytics event states "
                        "previous_model -> model directly"
                    ),
                )
            )
            events.append(
                _build_event(
                    rule_id, code,
                    {"source": "analytics", "from": previous, "to": current},
                    timestamp, account, f"{previous} -> {current}", group, result, ctx=ctx,
                    nature="모델 선택 이벤트", core=f"{previous} → {current}",
                    timestamp_basis="model_selected_event",
                )
            )

    # (b) Time-ordered model change inside one conversation.
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        ordered = [
            m
            for m in sorted(
                info.messages.values(),
                key=lambda m: (m.timestamp is None, m.timestamp or dt.datetime.min.replace(tzinfo=KST)),
            )
            if m.model
        ]
        transitions: list[tuple[str, str, Any, Any]] = []
        for i in range(1, len(ordered)):
            previous, current = ordered[i - 1], ordered[i]
            if previous.model and current.model and previous.model != current.model:
                transitions.append((previous.model, current.model, current.timestamp, current))
        # Explicit previous_model field is direct evidence.
        for message in info.messages.values():
            prev = message.attributes.get("previous_model")
            if isinstance(prev, str) and prev and message.model and prev != message.model:
                transitions.append((prev, message.model, message.timestamp, message))

        for from_model, to_model, timestamp, message in transitions:
            key = (uuid, from_model, to_model)
            if key in seen_transitions:
                continue
            seen_transitions.add(key)
            records = [ctx.store.get(eid) for eid in message.evidence_ids]
            analytics = [
                r
                for r in ctx.store.by_family(FAMILY_LOCAL_STORAGE)
                if to_model in str(r.attributes.get("value_preview", ""))
                and "model" in str(r.attributes.get("value_preview", "")).lower()
            ]
            members = [r for r in records if r] + analytics
            group = ctx.correlator.group(members)
            account = _account_for(ctx, members)
            result = decide(
                VerdictInput(
                    rule_id=rule_id,
                    group=group,
                    direct_evidence=bool(message.attributes.get("previous_model")),
                    direct_evidence_reason="explicit previous_model -> model transition",
                )
            )
            events.append(
                _build_event(
                    rule_id, code,
                    {"conversation_uuid": uuid, "from": from_model, "to": to_model},
                    timestamp, account, f"{from_model} -> {to_model}", group, result, ctx=ctx,
                    nature="대화 내 모델 변경", core=f"{from_model} → {to_model}",
                    conversation_uuid=uuid,
                    timestamp_basis="conversation_model_order",
                )
            )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_account_rename(ctx: DetectorContext) -> DetectorResult:
    """R-E0902.

    predicate  : two ordered display names for the SAME account UUID
    identity   : account_uuid + (old_name, new_name)
    disqualify : a single current name is account metadata, not a change
    """
    rule_id = "R-E0902"
    code = "E09-02"
    label = label_for(code)
    events: list[FinalEvent] = []

    for account, entries in sorted(ctx.account_ctx.display_names.items()):
        ordered = sorted(
            entries, key=lambda item: (item[0] is None, item[0] if item[0] is not None else 0)
        )
        names: list[tuple[str, str]] = []
        for _seq, name, evidence_id in ordered:
            if not names or names[-1][0] != name:
                names.append((name, evidence_id))
        if len(names) < 2:
            continue
        old_name, old_eid = names[0]
        new_name, new_eid = names[-1]
        records = [ctx.store.get(old_eid), ctx.store.get(new_eid)]
        records = [r for r in records if r]
        group = ctx.correlator.group(records)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=True,
                direct_evidence_reason=(
                    "same account UUID carries two display names in LevelDB sequence order"
                ),
            )
        )
        timestamp = max((r.timestamp for r in records if r.timestamp), default=None)
        events.append(
            _build_event(
                rule_id, code,
                {"account_uuid": account, "from": old_name, "to": new_name},
                timestamp, account, f"{old_name} -> {new_name}", group, result, ctx=ctx,
                nature="계정 표시 이름 변경 기록", core=f"{old_name} → {new_name}",
                timestamp_basis="display_name_record",
            )
        )
    if not events:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E09-02", label, rule_id, [], REASON_NO_EVIDENCE,
                    "fewer than two ordered display names for one account UUID",
                )
            ]
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# E10 -- temporary chat / incognito / history+cache deletion
# ===========================================================================

def detect_temporary_chat(ctx: DetectorContext) -> DetectorResult:
    """R-E1001.

    predicate  : conversation with is_temporary=true
    identity   : conversation_uuid
    direct     : is_temporary=true is allowlisted direct evidence
    families   : /new?incognito= URL and incognito analytics corroborate
    disqualify : Claude temporary chat is NOT Chrome Incognito
    """
    rule_id = "R-E1001"
    code = "E10-01"
    label = label_for(code)
    events: list[FinalEvent] = []

    incognito_urls = [
        r for r in ctx.store if "incognito=" in str(r.attributes.get("url", "")).lower()
    ]
    incognito_analytics = [
        r
        for r in ctx.store.by_family(FAMILY_LOCAL_STORAGE)
        if r.attributes.get("incognito_mode") is True
        or '"incognito_mode":true' in str(r.attributes.get("value_preview", "")).lower()
    ]

    for uuid, info in sorted(ctx.conversations.conversations.items()):
        if info.is_temporary is not True:
            continue
        members = ctx.correlator.by_conversation(uuid) + incognito_urls + incognito_analytics
        group = ctx.correlator.group(members)
        account = _account_for(ctx, members)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=True,
                direct_evidence_reason="conversation object carries is_temporary=true",
            )
        )
        events.append(
            _build_event(
                rule_id, code, {"conversation_uuid": uuid},
                info.created_at, account, info.title or uuid, group, result, ctx=ctx,
                nature="임시 대화 객체(is_temporary=true)", core=info.title,
                conversation_uuid=uuid,
                timestamp_basis="conversation_created_at",
            )
        )

    if not events and incognito_urls:
        group = ctx.correlator.group(incognito_urls + incognito_analytics)
        result = decide(
            VerdictInput(
                rule_id=rule_id,
                group=group,
                direct_evidence=False,
                disqualifiers=["/new?incognito= visit observed but no is_temporary conversation"],
            )
        )
        events.append(
            _build_event(
                rule_id, code, {"flow": "incognito_url"},
                min((r.timestamp for r in incognito_urls if r.timestamp), default=None),
                _account_for(ctx, incognito_urls), "/new?incognito=", group, result, ctx=ctx,
                nature="임시 채팅 URL 접근 흔적(대화 미확인)",
                core=_first_url(incognito_urls, "url"),
                timestamp_basis="history_incognito_url",
            )
        )
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


def detect_chrome_incognito(ctx: DetectorContext) -> DetectorResult:
    """R-E1002 -- fixed 판단불가.

    Chrome Incognito is never inferred from the absence of traces in a standard
    profile, and is never conflated with Claude temporary chat (spec section 17).
    """
    rule_id = "R-E1002"
    code = "E10-02"
    label = label_for(code)
    return DetectorResult(
        coverage=[
            _coverage(
                "E10-02", label, rule_id, [], REASON_SINGLE_SNAPSHOT_LIMIT,
                "out of scope by rule: absence of traces in the standard profile is not "
                "used to infer Incognito usage",
            )
        ]
    )


def detect_history_cleared(ctx: DetectorContext) -> DetectorResult:
    """R-E1003.

    History absence alone is never a verdict. Only a structural inconsistency
    between a provably complete store and other residual evidence could raise
    suspicion; with no direct evidence this stays 판단불가 (spec section 17).
    """
    rule_id = "R-E1003"
    code = "E10-03"
    label = label_for(code)
    return DetectorResult(
        coverage=[
            _coverage(
                "E10-03", label, rule_id, [], REASON_SINGLE_SNAPSHOT_LIMIT,
                "no direct evidence of History deletion; record absence alone is not used",
            )
        ]
    )


def detect_cache_cleared(ctx: DetectorContext) -> DetectorResult:
    """R-E1004.

    A small or empty Cache is never sufficient. With --extended-fs, a
    simultaneous bulk deletion of Cache files confirmed in USN, with matching
    times and paths, can raise suspicion.
    """
    rule_id = "R-E1004"
    code = "E10-04"
    label = label_for(code)

    if not ctx.extended_fs:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E10-04", label, rule_id, [], REASON_ARTIFACT_NOT_FOUND,
                    "--extended-fs not enabled: USN bulk-deletion check not performed; "
                    "Cache emptiness alone is not used",
                )
            ]
        )

    deletions = [
        r
        for r in ctx.store.by_family("usn")
        if "FILE_DELETE" in (r.attributes.get("reasons") or [])
        and "cache_data" in str(r.attributes.get("file_name", "")).lower()
    ]
    if len(deletions) < 50:
        return DetectorResult(
            coverage=[
                _coverage(
                    "E10-04", label, rule_id, [], REASON_NO_EVIDENCE,
                    f"no bulk Cache deletion pattern in USN ({len(deletions)} cache deletions); "
                    "Cache emptiness alone is not used",
                )
            ]
        )

    group = ctx.correlator.group(deletions)
    timestamp = min((r.timestamp for r in deletions if r.timestamp), default=None)
    result = decide(
        VerdictInput(
            rule_id=rule_id,
            group=group,
            direct_evidence=False,
            disqualifiers=["bulk deletion observed in USN; user intent not directly proven"],
        )
    )
    events = [
        _build_event(
                     rule_id, code, {"flow": "cache_bulk_delete"}, timestamp, None,
                     f"Cache 파일 {len(deletions)}건 삭제", group, result, ctx=ctx,
                     nature="USN Cache 파일 일괄 삭제(사용자 의도 미확인)",
                     core=f"Cache 파일 {len(deletions)}건 삭제",
                     timestamp_basis="usn_bulk_delete")
    ]
    return DetectorResult(events=events, coverage=[_coverage(code, label, rule_id, events)])


# ===========================================================================
# registry
# ===========================================================================

def _iso(value: Any) -> dt.datetime | None:
    from ..util.common import from_iso8601

    return from_iso8601(value)


def _conversation_title(ctx: DetectorContext, conversation_uuid: str | None) -> str:
    info = ctx.conversations.conversations.get(conversation_uuid or "")
    return info.title if info is not None and info.title else ""


def _first_url(records: Iterable[EvidenceRecord], attribute: str) -> str:
    """Earliest record's URL-like attribute; a credential-like fragment is dropped.

    Claude settings pages live in the fragment (#settings/...), so a fragment is
    kept unless it carries key=value data (e.g. a magic-link token).
    """
    ordered = sorted(
        records, key=lambda r: (r.timestamp is None, r.timestamp or dt.datetime.min.replace(tzinfo=KST))
    )
    for record in ordered:
        value = str(record.attributes.get(attribute) or "")
        if "http" in value:
            value = value[value.index("http"):].split(" ")[0]
        base, _, fragment = value.partition("#")
        if fragment and ("=" in fragment or "token" in fragment.lower()):
            value = base
        if value:
            return value[:200]
    return ""


def _conversation_time(ctx: DetectorContext, conversation_uuid: str | None) -> dt.datetime | None:
    if not conversation_uuid:
        return None
    info: ConversationInfo | None = ctx.conversations.conversations.get(conversation_uuid)
    if info is None:
        return None
    return info.created_at or info.updated_at


# (action_code, detector): exactly one detector per catalogue action.
DETECTOR_REGISTRY: tuple[tuple[str, Callable[[DetectorContext], DetectorResult]], ...] = (
    ("E01-01", detect_login),
    ("E01-02", detect_logout),
    ("E01-03", detect_account_switch),
    ("E03-01", detect_new_conversation),
    ("E03-02", detect_conversation_delete),
    ("E03-03", detect_conversation_edit),
    ("E03-04", detect_retry),
    ("E04-01", detect_prompt),
    ("E05-01", detect_image_upload),
    ("E05-02", detect_image_attachment_removed),
    ("E05-03", detect_document_upload),
    ("E05-04", detect_document_attachment_removed),
    ("E05-05", detect_document_download),
    ("E06-01", detect_image_generation),
    ("E06-02", detect_generated_image_download),
    ("E06-03", detect_downloaded_file_deleted),
    ("E07-01", detect_export),
    ("E07-02", detect_share_link),
    ("E09-01", detect_model_change),
    ("E09-02", detect_account_rename),
    ("E10-01", detect_temporary_chat),
    ("E10-02", detect_chrome_incognito),
    ("E10-03", detect_history_cleared),
    ("E10-04", detect_cache_cleared),
)

ALL_DETECTORS: tuple[Callable[[DetectorContext], DetectorResult], ...] = tuple(
    detector for _code, detector in DETECTOR_REGISTRY
)


class DetectorContractError(RuntimeError):
    """A detector produced an action outside its registered code/catalogue."""


def _check_registry() -> None:
    codes = [code for code, _ in DETECTOR_REGISTRY]
    if sorted(codes) != sorted(ACTION_LABELS) or len(set(codes)) != len(codes):
        raise DetectorContractError(
            "detector registry must map each catalogue action exactly once"
        )


_check_registry()


def run_all(ctx: DetectorContext) -> DetectorResult:
    """Run every registered detector. One detector failing never aborts the rest.

    A failure is reported under the REGISTERED action code and its catalogue
    name, never the Python function name. A detector emitting a code other than
    its own is a contract violation and raises.
    """
    combined = DetectorResult()
    for code, detector in DETECTOR_REGISTRY:
        try:
            result = detector(ctx)
        except Exception as exc:  # isolation (spec section 21.1)
            combined.coverage.append(
                CoverageRow(
                    action_code=code,
                    action_label=label_for(code),
                    rule_id=rule_for(code),
                    status=VERDICT_UNDETERMINED,
                    reason=REASON_DETECTOR_FAILED,
                    message=f"{type(exc).__name__}: {exc}",
                )
            )
            continue
        stray = {e.action_code for e in result.events} | {c.action_code for c in result.coverage}
        if stray - {code}:
            raise DetectorContractError(
                f"detector for {code} emitted action code(s) {sorted(stray - {code})}"
            )
        if len(result.coverage) != 1:
            raise DetectorContractError(
                f"detector for {code} returned {len(result.coverage)} coverage rows"
            )
        combined.events.extend(result.events)
        combined.coverage.extend(result.coverage)
    return combined
