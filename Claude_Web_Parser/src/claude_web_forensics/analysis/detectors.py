"""Deterministic action detectors."""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..model.entities import (
    FAMILY_CACHE, FAMILY_COOKIES, FAMILY_DISPLAY, FAMILY_HISTORY, FAMILY_LOCAL_STORAGE, FAMILY_SESSIONS,
    REASON_ARTIFACT_NOT_FOUND, REASON_CONFLICTING, REASON_DETECTOR_FAILED, REASON_NO_EVIDENCE,
    REASON_SINGLE_SNAPSHOT_LIMIT, VERDICT_CONFIRMED, VERDICT_SUSPECTED, VERDICT_UNDETERMINED, CoverageRow,
    EvidenceRecord, EvidenceStore, FileTrace, FinalEvent, make_action_id,
)
from ..parsers.browser_storage import event_time
from ..util.common import ensure_aware, from_iso8601, from_webkit
from .conversations import ConversationBuilder, ConversationInfo, _continues, draft_attachment_names
from .correlator import Correlator
from .file_analysis import FileLifecycle
from .rules import ACTION_LABELS, VerdictInput, compose_detail, decide, first_meaningful_line
from .rules import label_for, rule_for
from .summaries import clip, kst, short_url, summarize_record

FLOW_GAP = dt.timedelta(minutes=10)
AUTH_ACTIVITY = dt.timedelta(minutes=10)
SAME_STEP = dt.timedelta(seconds=60)
REDIRECT = dt.timedelta(seconds=5)
CREATION_NAVIGATION = dt.timedelta(seconds=60)
DRAFT_TO_SEND = dt.timedelta(minutes=30)

Evidence = list[tuple[EvidenceRecord | None, str]]

@dataclass
class DetectorContext:
    store: EvidenceStore
    conversations: ConversationBuilder
    file_traces: list[FileTrace] = field(default_factory=list)
    lifecycles: dict[str, FileLifecycle] = field(default_factory=dict)
    extended_fs: bool = False

    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.correlator = Correlator(self.store)
        self._memo: dict[str, Any] = {}

    def memo(self, key: str, build: Callable[[], Any]) -> Any:
        if key not in self._memo:
            self._memo[key] = build()
        return self._memo[key]

@dataclass
class DetectorResult:
    events: list[FinalEvent] = field(default_factory=list)
    coverage: list[CoverageRow] = field(default_factory=list)

def _build_event(
    ctx: DetectorContext, code: str, identity: dict[str, Any], timestamp: dt.datetime | None, nature: str,
    core: str, evidence: Evidence, *, basis: str = "", direct: bool = False, why: str = "",
    disqualifiers: Iterable[str] = (), conflicts: Iterable[str] = (), conversation_uuid: str | None = None,
) -> FinalEvent:
    kept: list[tuple[EvidenceRecord, str]] = []
    seen: set[tuple[str, str]] = set()
    for record, line in evidence:
        if record is not None and (record.evidence_id, line) not in seen:
            seen.add((record.evidence_id, line))
            kept.append((record, line))
    rule_id = rule_for(code)
    result = decide(VerdictInput(
        rule_id=rule_id, group=ctx.correlator.group(r for r, _ in kept),
        direct_evidence=direct, direct_evidence_reason=why,
        disqualifiers=list(disqualifiers), conflicts=list(conflicts),
    ))
    return FinalEvent(
        action_id=make_action_id(rule_id, identity), timestamp=timestamp, action_code=code,
        action_label=label_for(code), verdict=result.verdict, action_detail=compose_detail(nature, core),
        evidence=[(r.evidence_id, line) for r, line in kept], conversation_uuid=conversation_uuid,
        rule_id=rule_id, reason_code=result.reason_code, timestamp_basis=basis,
    )

def _coverage(code: str, events: list[FinalEvent], reason: str, message: str) -> CoverageRow:
    label, rule_id = label_for(code), rule_for(code)
    verdicts = {e.verdict for e in events}
    for verdict in (VERDICT_CONFIRMED, VERDICT_SUSPECTED):
        if verdict in verdicts:
            return CoverageRow(code, label, rule_id, verdict, "", len(events), message)
    if events:
        return CoverageRow(code, label, rule_id, VERDICT_UNDETERMINED, REASON_CONFLICTING, len(events), message)
    return CoverageRow(code, label, rule_id, VERDICT_UNDETERMINED, reason, 0, message)

def _detector(code: str, message: str = "", reason: str = REASON_NO_EVIDENCE):
    def wrap(fn: Callable[[DetectorContext], list[FinalEvent]]):
        def run(ctx: DetectorContext) -> DetectorResult:
            events = fn(ctx)
            return DetectorResult(events, [_coverage(code, events, reason, "" if events else message)])
        run.__name__, run.__doc__ = fn.__name__, fn.__doc__
        return run
    return wrap

_PROFILE = re.compile(r"^(.*?/User Data/[^/]+)")

def _profile(record: EvidenceRecord) -> str:
    match = _PROFILE.match(record.source_path or "")
    return match.group(1) if match else ""

def _at(record: EvidenceRecord) -> dt.datetime | None:
    if record.artifact_family == FAMILY_CACHE:
        return ensure_aware(record.attributes.get("response_at"))
    return ensure_aware(record.timestamp)

def _order(value: dt.datetime | None) -> tuple[bool, float]:
    return (value is None, value.timestamp() if value else 0.0)

def _visits(ctx: DetectorContext) -> list[EvidenceRecord]:
    def build() -> list[EvidenceRecord]:
        visits = [r for r in ctx.store.by_family(FAMILY_HISTORY)
                  if r.attributes.get("subtype") == "visit" and r.timestamp]
        return sorted(visits, key=lambda r: (r.timestamp, r.evidence_id))
    return ctx.memo("visits", build)

def _analytics(ctx: DetectorContext) -> list[tuple[dict[str, Any], EvidenceRecord]]:
    def build() -> list[tuple[dict[str, Any], EvidenceRecord]]:
        seen: dict[Any, tuple[dict[str, Any], EvidenceRecord]] = {}
        for record in ctx.store.by_family(FAMILY_LOCAL_STORAGE):
            for event in record.attributes.get("analytics_events") or []:
                key = event.get("eventId") or (event.get("eventName"), event.get("eventTimestamp"))
                seen.setdefault(key, (event, record))
        return sorted(seen.values(), key=lambda item: _order(event_time(item[0])))
    return ctx.memo("analytics", build)

def _events_named(ctx: DetectorContext, name: str) -> list[tuple[dict[str, Any], EvidenceRecord]]:
    return [(e, r) for e, r in _analytics(ctx) if e.get("eventName") == name]

def _event_line(event: dict[str, Any], *keys: str) -> str:
    props = event.get("properties") or {}
    values = ", ".join(f"{k}={clip(props[k], 40)}" for k in keys if props.get(k) not in (None, ""))
    return (f"[Local Storage] antalytics {event.get('eventName')} {kst(event_time(event))}"
            + (f", {values}" if values else ""))

def _object_line(info: ConversationInfo, record: EvidenceRecord, *, updated: bool = False) -> str:
    title = f" '{clip(info.title, 40)}'" if info.title else ""
    moment = (f"updated_at {kst(info.updated_at)}" if updated else f"created_at {kst(info.created_at)}")
    model = f", model={info.model}" if info.model else ""
    return f"[{FAMILY_DISPLAY[record.artifact_family]}] 대화 객체{title} {moment}{model}"

_AUTH_PATHS = ("/login", "/magic-link", "/oauth", "/auth/", "/cai/login", "/api/auth")
_APP_PATHS = ("/new", "/chat/", "/project", "/recents", "/artifacts", "/cowork", "/settings", "/customize", "/library")
_SIGN_IN_TITLES = ("sign in", "log in", "로그인")

def url_kind(url: str) -> str:
    u = str(url or "").lower()
    host, _, rest = re.sub(r"^[a-z]+://", "", u).partition("/")
    path = "/" + re.split(r"[?#]", rest, 1)[0]
    if "app-google-auth" in u or "open_in_browser=1" in u:
        return "delegate"
    if path.startswith("/logout") or "from=logout" in u:
        return "logout"
    if host.endswith(("accounts.google.com", "appleid.apple.com")):
        return "auth"
    if host.endswith(("claude.ai", "claude.com")) and path.startswith(_AUTH_PATHS):
        return "auth"
    if host.endswith("claude.ai") and path.startswith(_APP_PATHS):
        return "app"
    return "other"

@dataclass
class _Login:
    profile: str
    flow: list[EvidenceRecord]
    landing: EvidenceRecord
    begin: dt.datetime | None = None
    end: dt.datetime | None = None
    org: str = ""
    org_traces: list[tuple[dt.datetime, str, EvidenceRecord, str]] = field(default_factory=list)

    @property
    def at(self) -> dt.datetime:
        return self.landing.timestamp

@dataclass
class _Sessions:
    logins: list[_Login] = field(default_factory=list)
    logouts: list[list[EvidenceRecord]] = field(default_factory=list)

def _org_traces(ctx: DetectorContext, profile: str) -> list[tuple[dt.datetime, str, EvidenceRecord, str]]:
    conversations = ctx.conversations.conversations
    traces = []
    for record in ctx.store.by_family(FAMILY_CACHE):
        at = _at(record)
        if record.organization_uuid and at and _profile(record) == profile:
            traces.append((at, record.organization_uuid, record, ""))
    opened = {(p, c): v for (p, c), (v, _new) in _first_chat_visits(ctx).items()}
    for info in conversations.values():
        record = ctx.store.get(info.object_ids[0]) if info.object_ids else None
        visit = opened.get((profile, info.conversation_uuid))

        if (record and info.created_at and info.organization_uuid and visit
                and abs(visit.timestamp - info.created_at) <= CREATION_NAVIGATION):
            traces.append((info.created_at, info.organization_uuid, record, _object_line(info, record)))
    for visit in _visits(ctx):
        info = conversations.get(visit.conversation_uuid or "")
        if info and info.organization_uuid and _profile(visit) == profile:
            traces.append((visit.timestamp, info.organization_uuid, visit, ""))
    return sorted(traces, key=lambda t: (t[0], t[2].evidence_id))

def _sessions(ctx: DetectorContext) -> dict[str, _Sessions]:
    def build() -> dict[str, _Sessions]:
        out: dict[str, _Sessions] = defaultdict(_Sessions)
        by_profile: dict[str, list[EvidenceRecord]] = defaultdict(list)
        for visit in _visits(ctx):
            by_profile[_profile(visit)].append(visit)
        delegated = 0
        for profile, visits in by_profile.items():
            state = out[profile]
            flow: list[EvidenceRecord] = []
            delegate = False
            for visit in visits:
                kind = url_kind(visit.attributes.get("url"))
                if flow and visit.timestamp - flow[-1].timestamp > FLOW_GAP:
                    delegated += delegate
                    flow, delegate = [], False
                if kind in ("auth", "delegate"):
                    flow.append(visit)
                    delegate = delegate or kind == "delegate"
                elif kind == "logout":
                    redirect = "/logout" not in str(visit.attributes.get("url"))
                    if (redirect and state.logouts
                            and visit.timestamp - state.logouts[-1][-1].timestamp <= REDIRECT):
                        state.logouts[-1].append(visit)
                    else:
                        state.logouts.append([visit])
                    flow, delegate = [], False
                elif kind == "app":
                    if flow and not delegate:
                        state.logins.append(_Login(profile, flow, visit))
                    delegated += bool(flow) and delegate
                    flow, delegate = [], False
            delegated += bool(flow) and delegate

            traces = _org_traces(ctx, profile)
            boundaries = sorted([g[0].timestamp for g in state.logouts] + [l.at for l in state.logins])
            for login in state.logins:
                login.begin = max((b for b in boundaries if b < login.flow[0].timestamp), default=None)
                login.end = next((b for b in boundaries if b > login.at), None)
                login.org_traces = [t for t in traces
                                    if t[0] >= login.at and (login.end is None or t[0] < login.end)]
                orgs = {t[1] for t in login.org_traces}
                login.org = next(iter(orgs)) if len(orgs) == 1 else ""
                if len(orgs) > 1:
                    ctx.notes.append(f"login session {kst(login.at)}: {len(orgs)} organizations "
                                     "observed; organization left unresolved")
        if delegated:
            ctx.notes.append(f"{delegated} desktop-app sign-in delegation flow(s) in the browser "
                             "(app-google-auth) not reported as web logins")
        return out
    return ctx.memo("sessions", build)

def _flow_line(login: _Login) -> str:
    first, last = login.flow[0], login.flow[-1]
    return (f"[History] {kst(first.timestamp)}~{kst(last.timestamp)[11:]} 인증 URL {len(login.flow)}건"
            f"({short_url(first.attributes.get('url'), 50)} → {short_url(last.attributes.get('url'), 50)})"
            f" 후 {kst(login.at)} {short_url(login.landing.attributes.get('url'))} 진입"
            + (f" ({clip(login.landing.attributes.get('title'), 30)})"
               if login.landing.attributes.get("title") else ""))

def _login_corroboration(ctx: DetectorContext, login: _Login) -> tuple[Evidence, bool]:
    start, stop = login.flow[0].timestamp - SAME_STEP, login.at + SAME_STEP
    start = max(start, login.begin) if login.begin else start
    stop = min(stop, login.end) if login.end else stop
    evidence: Evidence = []
    explicit = False
    for record in ctx.store.by_family(FAMILY_LOCAL_STORAGE):
        marker = record.attributes.get("marker_at")
        if (_profile(record) == login.profile and marker and start <= marker <= stop
                and record.attributes.get("script_key") == "rq-cache-confirmed-account-session"):
            evidence.append((record, f"[Local Storage] rq-cache-confirmed-account-session " f"세션 확인 {kst(marker)}"))
            explicit = True
    for event, record in _analytics(ctx):
        at = event_time(event)
        if (str(event.get("eventName", "")).startswith("login.") and at and start <= at <= stop
                and _profile(record) == login.profile):
            evidence.append((record, _event_line(event, "flow_type")))
    for record in ctx.store.by_family(FAMILY_COOKIES):
        if (_profile(record) == login.profile and record.timestamp
                and start <= record.timestamp <= stop
                and str(record.attributes.get("name", "")).lower() in ("sessionkey", "sessionkeylc")):
            evidence.append((record, ""))
            explicit = True
    for at, _org, record, line in login.org_traces:
        if at <= login.at + AUTH_ACTIVITY and record.artifact_family != FAMILY_HISTORY:
            evidence.append((record, line or _cache_activity_line(record)))
            break
    return evidence, explicit

def _cache_activity_line(record: EvidenceRecord) -> str:
    return (f"[Cache] 로그인 후 조직 범위 API 응답 {kst(_at(record))} "
            f"{short_url(record.attributes.get('cache_key'), 70)}")

@_detector("E01-01", "no web authentication flow followed by an authenticated page")
def detect_login(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    for sessions in _sessions(ctx).values():
        for login in sessions.logins:
            corroboration, explicit = _login_corroboration(ctx, login)
            title = str(login.landing.attributes.get("title") or "").lower()
            completed = not any(t in title for t in _SIGN_IN_TITLES)
            evidence: Evidence = [(login.landing, _flow_line(login))]
            evidence += [(r, "") for r in login.flow] + corroboration
            if not completed:
                nature = "로그인 인증 흐름 흔적(인증 완료 미확인)"
            elif corroboration:
                nature = "로그인 인증 흐름 후 인증 페이지 진입"
            else:
                nature = "로그인 인증 흐름 후 인증 페이지 진입(세션 생성 기록 미확인)"
            events.append(_build_event(
                ctx, "E01-01", {"profile": login.profile, "landing": login.landing.evidence_id},
                login.at, nature, short_url(login.flow[0].attributes.get("url"), 60), evidence,
                basis="history_login_landing", direct=explicit and completed,
                why="account-session marker / session cookie created within the flow",
                disqualifiers=[] if completed else ["landing page is still a sign-in page"],
            ))
    return events

@_detector("E01-02", "no /logout URL and no logout-at marker; cookie absence is not used")
def detect_logout(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    markers = [r for r in ctx.store.by_family(FAMILY_LOCAL_STORAGE)
               if "logout" in str(r.attributes.get("script_key", "")).lower()
               and r.attributes.get("marker_at")]
    for profile, sessions in _sessions(ctx).items():
        mains = [next((v for v in g if "/logout" in str(v.attributes.get("url"))), g[0])
                 for g in sessions.logouts]

        owner = {m.evidence_id: min(mains, key=lambda v: abs(m.attributes["marker_at"] - v.timestamp))
                 for m in markers if _profile(m) == profile and mains}
        for group, main in zip(sessions.logouts, mains):
            near = [m for m in markers if owner.get(m.evidence_id) is main
                    and abs(m.attributes["marker_at"] - main.timestamp) <= SAME_STEP]
            evidence: Evidence = [(main, "")] + [(v, "") for v in group]
            if near:
                keys = sorted({str(m.attributes.get("script_key")) for m in near})
                evidence.append((near[0], f"[Local Storage] logout-at 마커 {len(keys)}건 "
                                          f"{kst(near[0].attributes['marker_at'])} ({', '.join(keys[:3])})"))
                evidence += [(m, "") for m in near[1:]]
            events.append(_build_event(
                ctx, "E01-02", {"profile": profile, "logout": main.evidence_id}, main.timestamp,
                "로그아웃 URL 방문", "", evidence, basis="history_logout_url",
                direct=True, why="explicit logout URL record",
            ))
    return events

@_detector("E01-03", "no two consecutive login sessions with different organizations; "
                     "residual UUIDs alone do not establish a switch")
def detect_account_switch(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    for profile, sessions in _sessions(ctx).items():
        orgs = dict.fromkeys(login.org for login in sessions.logins if login.org)
        names = {org: f"조직 {chr(65 + i)}" for i, org in enumerate(orgs)}

        for before, after in zip(sessions.logins, sessions.logins[1:]):
            if not before.org or not after.org or before.org == after.org:
                continue
            evidence: Evidence = [(after.landing, _flow_line(after))]
            for label, login in (("이전 세션", before), ("전환 후 세션", after)):
                _at_, _org, record, line = _org_anchor(login)
                line = line or _cache_activity_line(record)
                evidence.append((record, line.replace("] ", f"] {label} {names[login.org]} — ", 1)))
            events.append(_build_event(
                ctx, "E01-03", {"profile": profile, "from": before.org, "to": after.org, "at": after.at.isoformat()},
                after.at, "로그아웃·재인증 후 다른 조직 계정의 세션 시작",
                f"{names[before.org]}(로그인 {kst(before.at)}) → {names[after.org]}", evidence,
                basis="history_login_landing",
            ))
    return events

def _org_anchor(login: _Login) -> tuple[dt.datetime, str, EvidenceRecord, str]:
    return next((t for t in login.org_traces if t[2].artifact_family != FAMILY_HISTORY), login.org_traces[0])

def _first_chat_visits(ctx: DetectorContext) -> dict[tuple[str, str], tuple[EvidenceRecord, bool]]:
    def build() -> dict[tuple[str, str], tuple[EvidenceRecord, bool]]:
        out: dict[tuple[str, str], tuple[EvidenceRecord, bool]] = {}
        previous: dict[str, str] = {}
        for visit in _visits(ctx):
            url = str(visit.attributes.get("url") or "")
            profile = _profile(visit)
            if url_kind(url) != "app":
                continue
            conv = visit.conversation_uuid
            if conv and (profile, conv) not in out:
                out[(profile, conv)] = (visit, previous.get(profile, "").rstrip("/").endswith("claude.ai/new"))
            previous[profile] = re.split(r"[?#]", url, 1)[0]
        return out
    return ctx.memo("first_chat_visits", build)

@_detector("E03-01", "no conversation creation event, and no conversation object opened "
                     "in this profile when it was created")
def detect_new_conversation(ctx: DetectorContext) -> list[FinalEvent]:
    created = {str((e.get("properties") or {}).get("conversation_uuid") or "").lower(): (e, r)
               for e, r in _events_named(ctx, "chorus.conversation_created")}
    first_visits = _first_chat_visits(ctx)
    conversations = ctx.conversations.conversations
    events, object_only = [], 0
    for key in sorted(set(created) | {k[1] for k in first_visits} | set(conversations)):
        if not key:
            continue
        info = conversations.get(key) or ConversationInfo(conversation_uuid=key)
        event_record = created.get(key)
        visit, after_new = next(((v, n) for (p, c), (v, n) in first_visits.items() if c == key), (None, False))
        obj = ctx.store.get(info.object_ids[0]) if info.object_ids and info.created_at else None
        opened = bool(visit and obj and abs(visit.timestamp - info.created_at) <= CREATION_NAVIGATION)
        if not (event_record or opened or (visit and after_new and not obj)):
            object_only += bool(obj)
            continue
        evidence: Evidence = []
        if event_record:
            e, record = event_record
            evidence.append((record, _event_line(e, "source", "client_platform")))
        if obj:
            evidence.append((obj, _object_line(info, obj)))
        if visit:
            evidence.append((visit, ""))
        proven = bool(event_record) or opened
        timestamp = info.created_at if obj else (event_time(event_record[0]) if event_record
                                                 else visit.timestamp)
        page_title = str(visit.attributes.get("title") or "") if visit else ""
        events.append(_build_event(
            ctx, "E03-01", {"conversation_uuid": key}, timestamp,
            "대화 생성 기록" if proven else "새 대화 URL 최초 방문(생성 객체 미확인)",
            info.title or re.sub(r"\s*-\s*Claude$", "", page_title), evidence, conversation_uuid=key,
            basis="conversation_created_at" if obj else
            ("conversation_created_event" if event_record else "history_first_chat_visit"),
            direct=bool(event_record), why="conversation_created analytics event",
            disqualifiers=[] if proven else ["page visit only; no conversation object or event"],
        ))
    if object_only:
        ctx.notes.append(f"{object_only} conversation object(s) with created_at but no creation "
                         "event or navigation in this profile at creation time (not reported)")
    return events

@_detector("E03-02", "no explicit delete request/event/tombstone; Cache residue alone is "
                     "not treated as deletion", REASON_SINGLE_SNAPSHOT_LIMIT)
def detect_conversation_delete(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    for record in ctx.store:
        attrs = record.attributes
        path = str(attrs.get("cache_key", "")).split("?", 1)[0].lower()
        match = re.search(r"/(?:chat_conversations|conversations)/([0-9a-f-]{36})(/delete)?$", path)
        payload = attrs.get("_json")
        if not match or not (match[2] or attrs.get("request_method") == "DELETE"
                or isinstance(payload, dict) and payload.get("uuid") == match[1]
                and payload.get("deleted") is True):
            continue
        conv = match[1]
        info = ctx.conversations.conversations.get(conv)
        events.append(_build_event(
            ctx, "E03-02", {"conversation_uuid": conv}, record.timestamp, "대화 삭제 요청/이벤트",
            (info.title if info else "") or conv, [(record, "")], conversation_uuid=conv,
            basis="delete_event", direct=True, why="explicit delete request/tombstone",
        ))
    return events

def _branch_events(ctx: DetectorContext, code: str, role: str, nature: str) -> list[FinalEvent]:
    events, observed = [], []
    name = "claudeai.message.edited" if role == "user" else "claudeai.message.user_triggered_retry"
    for event, record in _events_named(ctx, name):
        props = event.get("properties") or {}
        uuid = str(props.get("conversation_uuid") or "").lower()
        if not uuid or not props.get("message_uuid") or (role == "user" and
                (props.get("edit_kind") != "text_edit" or props.get("is_identical_content") is not False)):
            continue
        action = _build_event(
            ctx, code, {"event": event.get("eventId") or (uuid, event.get("eventTimestamp"))},
            event_time(event), "사용자 메시지 내용 수정" if role == "user" else "사용자 재시도 실행",
            "", [(record, _event_line(event, "edit_kind", "is_identical_content", "source"))],
            conversation_uuid=uuid, basis="analytics_event", direct=True, why=name,
        )
        events.append(action)
        observed.append((action, props))
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        parents: dict[str, list] = defaultdict(list)
        for message in info.messages.values():
            if message.role == role and (message.parent_message_uuid or role == "user"):
                parents[message.parent_message_uuid or "<root>"].append(message)
        for parent, siblings in sorted(parents.items()):
            if len({m.message_uuid for m in siblings}) < 2:
                continue
            if role == "user" and len({m.content for m in siblings if m.content}) < 2:
                continue
            retry = any(str(m.input_mode).lower() == "retry" for m in siblings)
            evidence = [(ctx.store.get(eid), "") for m in siblings for eid in m.evidence_ids]
            ids = {m.message_uuid for m in siblings} if role == "user" else {parent}
            matches = [e for e, p in observed if e.conversation_uuid == uuid and
                       str(p.get("message_uuid" if role == "user" else "branch_parent_message_uuid") or
                           p.get("message_uuid") or "").lower() in ids]
            if matches:
                action = max(matches, key=lambda e: _order(e.timestamp))
                action.evidence = list(dict.fromkeys(action.evidence + [(r.evidence_id, line) for r,
                    line in evidence if r]))
                continue
            events.append(_build_event(
                ctx, code, {"conversation_uuid": uuid, "parent_message_uuid": parent},
                max((m.timestamp for m in siblings if m.timestamp), default=None),
                nature, info.title, evidence, conversation_uuid=uuid, basis="branch_message_created_at",
                direct=role == "user" or retry,
                why="distinct message UUIDs under one parent in the conversation tree",
            ))
    return events

@_detector("E03-03", "no conversation tree with two user messages under one parent")
def detect_conversation_edit(ctx: DetectorContext) -> list[FinalEvent]:
    return _branch_events(ctx, "E03-03", "user", "동일 부모 아래 사용자 메시지 분기")

@_detector("E03-04", "no conversation tree with two assistant replies under one user message")
def detect_retry(ctx: DetectorContext) -> list[FinalEvent]:
    return _branch_events(ctx, "E03-04", "assistant", "동일 사용자 메시지 아래 응답 분기")

@_detector("E04-01", "no sent-message event, no user message and no composer draft")
def detect_prompt(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    sent_texts = set()
    drafts = ctx.conversations.draft_compositions()
    known = ctx.conversations.conversations
    # A composition saved shortly before a message of the same conversation, whose text that message continues
    # (a few more characters typed before Enter), is that message's writing trace, not a separate unsent draft.
    written: dict[str, Any] = {}
    for message in sorted((m for i in known.values() for m in i.messages.values() if m.role == "user" and m.timestamp),
                          key=lambda m: (m.timestamp, m.message_uuid)):
        own = [c for c in drafts
               if c[-1].timestamp and c[-1].timestamp <= message.timestamp <= c[-1].timestamp + DRAFT_TO_SEND
               and ((tail := c[-1].draft_id.rsplit(":", 1)[-1]) == message.conversation_uuid or tail not in known)
               and _continues(c[-1].text.strip(), message.content.strip())]
        if own:
            best = max(own, key=lambda c: c[-1].timestamp)
            drafts.remove(best)
            written[message.message_uuid] = best[-1]
    for uuid, info in sorted(known.items()):
        for message in info.messages.values():
            if message.role != "user" or not message.timestamp:
                continue
            sent_texts.add(message.content.strip())
            preview = first_meaningful_line(message.content)
            last = written.get(message.message_uuid)
            events.append(_build_event(
                ctx, "E04-01", {"message_uuid": message.message_uuid}, message.timestamp,
                "사용자 메시지 전송", preview or info.title,
                [(r, summarize_record(r) if r and last else "")   # spelled out so the draft line joins it, not hides it
                 for r in map(ctx.store.get, message.evidence_ids)]
                + [(ctx.store.get(eid), f"[{FAMILY_DISPLAY[last.family]}] 전송 직전 초안 {last.draft_id} "
                                        f"{len(last.text)}자 {kst(last.timestamp)}")
                   for eid in (last.evidence_ids if last else ())],
                conversation_uuid=uuid, basis="user_message_created_at", direct=True,
                why="user message UUID with created_at in the conversation tree",
            ))

    compositions = [c for c in drafts if c[-1].text.strip() not in sent_texts]
    used: set[int] = set()
    for event, record in _events_named(ctx, "claudeai.message.sent"):
        props = event.get("properties") or {}
        at = event_time(event)
        conv = str(props.get("conversation_uuid") or "").lower()
        match = None
        for index, composition in enumerate(compositions):
            last = composition[-1]
            if (index not in used and at and last.timestamp and last.timestamp <= at <= last.timestamp + DRAFT_TO_SEND
                    and len(last.text) == props.get("message_length", props.get("prompt_length"))
                    and (not last.account_uuid or not event.get("account_uuid")
                         or last.account_uuid == event["account_uuid"])):
                if match is None or last.timestamp > compositions[match][-1].timestamp:
                    match = index
        evidence: Evidence = [(record, _event_line(event, "message_index", "message_length",
            "is_new_conversation", "model"))]
        core = ctx.conversations.conversations.get(conv, ConversationInfo(conv)).title
        if match is not None:
            used.add(match)
            last = compositions[match][-1]
            core = first_meaningful_line(last.text)
            evidence += [(ctx.store.get(eid), f"전송 직전 초안 {last.draft_id} {len(last.text)}자 " f"{kst(last.
                timestamp)}") for eid in last.evidence_ids]
        events.append(_build_event(
            ctx, "E04-01", {"event": event.get("eventId") or (at.isoformat() if at else "")}, at,
            "사용자 메시지 전송 이벤트" + ("(초안 길이 일치)" if match is not None else ""), core,
            evidence, conversation_uuid=conv or None, basis="message_sent_event", direct=True,
            why="claudeai.message.sent analytics event with its own timestamp",
        ))

    by_text: dict[str, list] = defaultdict(list)
    for index, composition in enumerate(compositions):
        if index not in used:
            by_text[composition[-1].text.strip()].append(composition)
    for text, groups in by_text.items():
        versions = [d for group in groups for d in group]

        last = max((g[-1] for g in groups),
                   key=lambda d: (d.timestamp is not None, d.timestamp.timestamp() if d.timestamp else 0))
        evidence: Evidence = []
        for draft in sorted(versions, key=lambda d: d.family):
            line = ""
            if len(versions) > 1 or draft.family != FAMILY_LOCAL_STORAGE:
                same = [d for d in versions if d.family == draft.family]
                times = [d.timestamp for d in same if d.timestamp]
                line = (f"[{FAMILY_DISPLAY[draft.family]}] 초안 {draft.draft_id} 저장 {len(same)}회"
                        + (f" {kst(min(times))}~{kst(max(times))[11:]}" if times else "")
                        + f", 최종 {len(text)}자")
            evidence += [(ctx.store.get(eid), line) for eid in draft.evidence_ids]
        events.append(_build_event(
            ctx, "E04-01", {"text_head": text[:80]}, last.timestamp,
            "프롬프트 작성 흔적(전송 미확인)", first_meaningful_line(text), evidence,
            basis="draft_updated_at", disqualifiers=["draft only; transmission not observed"],
        ))
    return events

_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico", ".heic")
_EXECUTABLE_EXT = (".exe", ".msi", ".msix", ".appx", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
                   ".bat", ".cmd", ".ps1", ".dll", ".sys", ".scr", ".com")
_EXECUTABLE_MIME = ("application/x-msdownload", "application/x-msi", "application/x-ms-installer",
                    "application/vnd.microsoft.portable-executable", "application/x-apple-diskimage",
                    "application/x-dosexec")

def _is_image(name: str, mime: str = "") -> bool:
    return name.lower().endswith(_IMAGE_EXT) or mime.lower().startswith("image")

def _event_file(props: dict[str, Any]) -> tuple[str, bool | None]:
    name = str(props.get("file_name") or props.get("fileName") or "")
    ext = str(props.get("file_extension") or "").lstrip(".")
    name = name or ("file." + ext if ext else "")
    mime = str(props.get("mime_type") or props.get("file_kind") or "")
    known = "." in name.replace("\\", "/").rsplit("/",
        1)[-1] or mime == "document" or bool(mime.startswith(("image", "text/", "application/"))
            and mime != "application/octet-stream")
    label = str(props.get("file_name") or props.get("fileName") or "") or (f"확장자 {ext}" if ext else mime)
    return label, _is_image(name, mime) if known and not is_executable_download(name, mime) else None

def _file_ids(item: dict[str, Any]) -> set[str]:
    """Every identifier one upload carries: the page's own file_uuid and the server's id / uuid / serverFileUuid."""
    return {str(item[k]).lower() for k in ("id", "file_uuid", "uuid", "serverFileUuid") if item.get(k)}

def _asset_line(record: EvidenceRecord) -> str:
    return (f"[Cache] 업로드 파일 {record.attributes.get('file_variant')} 조회 "
            f"{kst(_at(record))}, {clip(record.attributes.get('content_type'), 30)}")

def _uploads(ctx: DetectorContext, want_image: bool) -> list[FinalEvent]:
    code, kind = ("E05-01", "이미지") if want_image else ("E05-03", "문서")
    events, sent_files, sent_bodies = [], set(), set()
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        for message in info.messages.values():
            if message.role != "user":
                continue
            for item in (message.attributes.get("attachments") or []) + (message.attributes.get("files") or []):
                name = str(item.get("file_name") or item.get("fileName") or "")
                file_uuid = str(item.get("file_uuid") or item.get("uuid") or item.get("id") or "").lower()
                sent_files |= _file_ids(item)
                sent_bodies.add((uuid, name, item.get("extracted_content")))
                if not name or _is_image(name, str(item.get("file_kind") or "")) != want_image:
                    continue
                events.append(_build_event(
                    ctx, code, {"file": file_uuid or name, "conversation_uuid": uuid},
                    message.timestamp, "전송 메시지 첨부", name,
                    [(ctx.store.get(eid), "") for eid in message.evidence_ids],
                    conversation_uuid=uuid, basis="attachment_message_created_at", direct=True,
                    why="attachment inside a sent user message",
                ))
    assets: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for record in ctx.store.by_family(FAMILY_CACHE):
        if record.attributes.get("key_kind") == "file_asset":
            assets[record.attributes["file_uuid"]].append(record)
    by_file: dict[str, list[tuple[Any, str, dict[str, Any]]]] = defaultdict(list)
    for draft in ctx.conversations.drafts:
        for name, item in draft_attachment_names([draft]):
            by_file[str(item.get("file_uuid") or name)].append((draft, name, item))
    draft_files: set[str] = set()
    for key, versions in by_file.items():
        drafts = [d for d, _, _ in versions]
        # the version the server answered (success, its own uuid and created_at) describes the upload best
        _, name, item = next((v for v in versions if v[2].get("success")), versions[0])
        ids = set().union(*(_file_ids(a) for _, _, a in versions))
        draft_files |= ids
        tail, body = drafts[0].draft_id.rsplit(":", 1)[-1], item.get("extracted_content")
        # sent already: same identifier, or (inline text has none) the same name and extracted body in that chat
        if (ids & sent_files or _is_image(name, str(item.get("file_kind") or "")) != want_image
                or body and any(s[1:] == (name, body) and (s[0] == tail or tail not in ctx.conversations.conversations)
                                for s in sent_bodies)):
            continue
        events.append(_build_event(
            ctx, code, {"file": key, "draft": True},
            from_iso8601(item.get("created_at")) or min((d.timestamp for d in drafts if d.timestamp), default=None),
            f"{kind} 서버 업로드 완료(메시지 첨부 전송 미확인)" if item.get("success") is True
            else f"{kind} 업로드 준비 흔적(전송 불확인)", name,
            [(ctx.store.get(eid), "") for d in drafts for eid in d.evidence_ids]
            + [(r, _asset_line(r)) for file_uuid in sorted(ids) for r in assets.get(file_uuid, ())],
            basis="attachment_created_at", disqualifiers=["attachment in a draft only"],
        ))
    for file_uuid, records in sorted(assets.items()):
        variants = {r.attributes.get("file_variant") for r in records}
        image = "preview" in variants and "document_pdf" not in variants
        if (file_uuid in sent_files or file_uuid in draft_files or image != want_image
                or not ({"preview", "document_pdf"} & variants)):
            continue
        records.sort(key=lambda r: _order(_at(r)))
        downloads = [r for r in ctx.store.by_family(FAMILY_HISTORY)
                     if r.attributes.get("subtype") == "download"
                     and any(file_uuid in str(u).lower() for u in r.attributes.get("chain_urls") or [])]
        name = str(downloads[0].attributes.get("file_name") or "") if downloads else ""
        evidence: Evidence = [(r, _asset_line(r)) for r in records]
        evidence += [(d, f"[History] 같은 파일 UUID 다운로드 기록: {d.attributes.get('file_name')}, "
                         f"MIME={d.attributes.get('mime_type')}") for d in downloads[:1]]
        events.append(_build_event(
            ctx, code, {"file": file_uuid}, _at(records[0]),
            f"업로드 {kind} 파일 조회 흔적(첫 조회 시각 기준, 메시지 첨부 전송 미확인)",
            f"다운로드 저장명 {name}" if name else "파일명 미확인", evidence, basis="cache_first_asset_response",
            disqualifiers=["uploaded-file asset only; no sent message links it"],
        ))
    for event, record in _events_named(ctx, "claudeai.chat.file_upload.added"):
        props = event.get("properties") or {}
        name, image = _event_file(props)
        if image is None or image != want_image:
            continue
        uuid = str(props.get("conversation_uuid") or "").lower()
        action = _build_event(
            ctx, code, {"event": event.get("eventId") or (uuid, event.get("eventTimestamp"))},
            event_time(event), f"{kind} 파일 추가(서버 업로드 완료 미확인)", name,
            [(record, _event_line(event, "file_name", "file_extension", "mime_type", "file_count", "via"))],
            conversation_uuid=uuid, basis="file_added_event", disqualifiers=["file added to composer only"],
        )
        previous = next((e for e in events if props.get("file_id")
            and e.action_id == make_action_id(rule_for(code), {"file": str(props["file_id"]).lower(),
                "conversation_uuid": uuid})), None)
        if previous:
            previous.evidence = list(dict.fromkeys(previous.evidence + action.evidence))
        else:
            events.append(action)
    return events

@_detector("E05-01", "no image attachment in a message, draft or uploaded-file asset")
def detect_image_upload(ctx: DetectorContext) -> list[FinalEvent]:
    return _uploads(ctx, True)

@_detector("E05-03", "no document attachment in a message, draft or uploaded-file asset")
def detect_document_upload(ctx: DetectorContext) -> list[FinalEvent]:
    return _uploads(ctx, False)

def _attachment_removal(ctx: DetectorContext, code: str) -> list[FinalEvent]:
    events = []
    for event, record in _events_named(ctx, "claudeai.message.edited"):
        props = event.get("properties") or {}
        name, image = _event_file(props)
        if (props.get("edit_kind") != "remove_attachments" or not props.get("conversation_uuid")
                or not props.get("message_uuid") or image is None or image != (code == "E05-02")):
            continue
        events.append(_build_event(
            ctx, code, {"event": event.get("eventId") or event.get("eventTimestamp")},
            event_time(event), "메시지 첨부파일 제거", name,
            [(record, _event_line(event, "edit_kind", "file_name", "file_extension", "mime_type"))],
            conversation_uuid=props.get("conversation_uuid"), basis="attachment_removed_event",
            direct=True, why="completed attachment removal with a known file type",
        ))
    return events

_REMOVAL_MESSAGE = ("no explicit removal event/tombstone; residual attachment metadata is not "
                    "treated as removal evidence")

@_detector("E05-02", _REMOVAL_MESSAGE, REASON_SINGLE_SNAPSHOT_LIMIT)
def detect_image_attachment_removed(ctx: DetectorContext) -> list[FinalEvent]:
    return _attachment_removal(ctx, "E05-02")

@_detector("E05-04", _REMOVAL_MESSAGE, REASON_SINGLE_SNAPSHOT_LIMIT)
def detect_document_attachment_removed(ctx: DetectorContext) -> list[FinalEvent]:
    return _attachment_removal(ctx, "E05-04")

def _same_path(a: str | None, b: str | None) -> bool:
    return bool(a and b) and str(a).replace("/", "\\").lower() == str(b).replace("/", "\\").lower()

def is_executable_download(name: str, mime: str, urls: Iterable[str] = ()) -> bool:
    return (name.lower().endswith(_EXECUTABLE_EXT) or mime.lower() in _EXECUTABLE_MIME
            or any("/setup/" in str(u).lower() or "/desktop/" in str(u).lower() for u in urls))

def _downloads(ctx: DetectorContext, code: str, want_image: bool) -> list[FinalEvent]:
    events = []
    for record in ctx.store.by_family(FAMILY_HISTORY):
        attrs = record.attributes
        if attrs.get("subtype") != "download":
            continue
        name, mime = str(attrs.get("file_name") or ""), str(attrs.get("mime_type") or "")
        chain = attrs.get("chain_urls") or []
        if is_executable_download(name, mime, chain):
            if not want_image:
                ctx.notes.append(f"download {name!r} ({mime}) is an installer/executable; "
                                 "not reported as a document download")
            continue
        if _is_image(name, mime) != want_image:
            continue
        target = str(attrs.get("target_path") or attrs.get("current_path") or "")
        evidence: Evidence = [(record, "")]
        for trace in ctx.file_traces:
            if trace.direction == "downloaded" and (
                _same_path(trace.original_path, target)
                or (trace.zone_host_url and trace.zone_host_url in chain)
            ):
                evidence += [(ctx.store.get(eid), "") for eid in trace.evidence_ids]
        complete = attrs.get("state") == 1
        events.append(_build_event(
            ctx, code, {"download_url": ",".join(chain[:1]), "target_path": target},
            (from_webkit(attrs.get("end_time")) or record.timestamp) if complete else record.timestamp,
            "다운로드 완료 기록" if complete else "다운로드 시도 흔적(완료 미확인)", name or target,
            evidence, conversation_uuid=record.conversation_uuid,
            basis="history_downloads_end_time" if complete else "history_downloads_start_time",
            direct=complete and bool(target) and bool(chain),
            why="History downloads record in COMPLETE state with a target path and Claude URL chain",
            disqualifiers=[] if complete else [f"download state={attrs.get('state_label')}"],
        ))
    return events

@_detector("E05-05", "no completed non-image, non-executable Claude download")
def detect_document_download(ctx: DetectorContext) -> list[FinalEvent]:
    events, matched = _downloads(ctx, "E05-05", False), set()
    for event, record in _events_named(ctx, "wiggle.file.downloaded"):
        props = event.get("properties") or {}
        name, image = _event_file(props)
        if image is not False:
            continue
        uuid, at = str(props.get("conversation_uuid") or "").lower(), event_time(event)
        ext = str(props.get("file_extension") or name.rsplit(".", 1)[-1]).lower().lstrip(".")
        evidence = [(record.evidence_id, _event_line(event, "file_extension", "is_output_file", "source"))]
        matches = [e for e in events if e.action_id not in matched and e.conversation_uuid == uuid
                   and at and e.timestamp and abs(at - e.timestamp) <= SAME_STEP and any(
                       r and str(r.attributes.get("file_name") or "").lower().endswith("." + ext)
                       for r in (ctx.store.get(eid) for eid, _ in e.evidence))]
        if len(matches) == 1:
            matches[0].evidence = list(dict.fromkeys(matches[0].evidence + evidence))
            matched.add(matches[0].action_id)
            continue
        events.append(_build_event(
            ctx, "E05-05", {"event": event.get("eventId") or (uuid, event.get("eventTimestamp"))},
            at, "문서 다운로드 동작(저장 완료 미확인)", name, [(record, evidence[0][1])],
            conversation_uuid=uuid, basis="file_downloaded_event",
            disqualifiers=["analytics download action only; file completion unverified"],
        ))
    return events

_OUTPUTS_DIR = "/mnt/user-data/outputs/"
_GENERATED_MARKERS = (_OUTPUTS_DIR, "file created successfully")
_IMAGE_TITLE_WORDS = ("이미지", "그림", "사진", "image", "picture", "draw", "illustration")

def _generated_image_files(ctx: DetectorContext) -> dict[tuple[str, str], list[EvidenceRecord]]:
    files: dict[tuple[str, str], list[EvidenceRecord]] = defaultdict(list)
    for record in ctx.store.by_family(FAMILY_CACHE):
        attrs = record.attributes
        if (attrs.get("key_kind") == "download_file" and record.conversation_uuid
                and _OUTPUTS_DIR in str(attrs.get("output_path", "")) and attrs.get("body_format")):
            files[(_profile(record), record.conversation_uuid)].append(record)
    return files

# A web image response supports generation; it does not prove a completed local download.
def _generation_aux_evidence(
    ctx: DetectorContext,
) -> dict[str, tuple[dt.datetime, Evidence]]:
    out: dict[str, tuple[dt.datetime, Evidence]] = {}
    for (profile, conv), files in sorted(_generated_image_files(ctx).items()):
        files.sort(key=lambda r: _order(_at(r)))
        first = _at(files[0])
        sends = [(event_time(e), e, r) for e, r in _events_named(ctx, "claudeai.message.sent")
                 if _profile(r) == profile and event_time(e) and first
                 and str((e.get("properties") or {}).get("conversation_uuid") or "").lower() == conv
                 and event_time(e) <= first]
        if not sends:
            continue
        at, event, record = max(sends, key=lambda s: s[0])
        evidence: Evidence = [(record, _event_line(event, "message_index", "model"))]
        evidence += [(r, f"[Cache] 생성 파일 {short_url(r.attributes.get('output_path'), 60)} 응답 "
                         f"{kst(_at(r))}, 본문 형식={r.attributes['body_format']}") for r in files]
        titled = [v for v in _visits(ctx) if v.conversation_uuid == conv and _profile(v) == profile
                  and any(w in str(v.attributes.get("title", "")).lower() for w in _IMAGE_TITLE_WORDS)]
        evidence += [(v, "") for v in titled[:1]]
        out[conv] = (at, evidence)
    return out

@_detector("E06-01", "no generated-image object in a recovered conversation and no send event "
                     "linked to a verified generated-image response")
def detect_image_generation(ctx: DetectorContext) -> list[FinalEvent]:
    aux = _generation_aux_evidence(ctx)
    events = []
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        if not any(m.role == "user" for m in info.messages.values()):
            continue
        outputs = [m for m in info.messages.values() if m.role == "assistant"
                   and any(k in m.content.lower() for k in _GENERATED_MARKERS)
                   and any(ext in m.content.lower() for ext in _IMAGE_EXT)]
        if outputs:
            evidence = [(ctx.store.get(eid), "") for m in outputs for eid in m.evidence_ids]
            events.append(_build_event(
                ctx, "E06-01", {"conversation_uuid": uuid},
                max((m.timestamp for m in outputs if m.timestamp), default=None),
                "생성 이미지 결과 객체", info.title, evidence + aux.pop(uuid, (None, []))[1],
                conversation_uuid=uuid, basis="assistant_output_created_at", direct=True,
                why="assistant tool result / generated image object",
            ))
    for uuid, (at, evidence) in sorted(aux.items()):
        info = ctx.conversations.conversations.get(uuid)
        events.append(_build_event(
            ctx, "E06-01", {"conversation_uuid": uuid}, at,
            "생성 이미지 파일 응답과 연결된 메시지 전송(대화 트리 미확인)", info.title if info else "",
            evidence, conversation_uuid=uuid, basis="message_sent_event",
            disqualifiers=["conversation tree not recovered; request and result linked by " "conversation UUID only"],
        ))
    return events

@_detector("E06-02", "no completed image download from Claude")
def detect_generated_image_download(ctx: DetectorContext) -> list[FinalEvent]:
    return _downloads(ctx, "E06-02", True)

@_detector("E06-03", "no $I deletion metadata / USN delete for a Claude download", REASON_ARTIFACT_NOT_FOUND)
def detect_downloaded_file_deleted(ctx: DetectorContext) -> list[FinalEvent]:
    if not ctx.extended_fs:
        ctx.notes.append("E06-03: --extended-fs not enabled ($Recycle.Bin / $UsnJrnl not analysed)")
        return []
    downloads = [r for r in ctx.store.by_family(FAMILY_HISTORY) if r.attributes.get("subtype") == "download"]
    events = []
    for trace in ctx.file_traces:
        if not trace.attributes.get("deleted"):
            continue
        evidence: Evidence = [(ctx.store.get(eid), "") for eid in trace.evidence_ids]
        matched = next((r for r in downloads if _same_path(r.attributes.get("target_path")
            or r.attributes.get("current_path"), trace.original_path)), None)
        evidence.append((matched, ""))
        final_path = ""
        for life in ctx.lifecycles.values():
            if _same_path(life.original_path, trace.original_path):
                evidence += [(ctx.store.get(eid), "") for eid in life.evidence_ids]
                evidence += [(r, "") for r in ctx.store.by_family("usn")
                             if r.attributes.get("file_reference") == life.file_reference]
                final_path = life.final_path if life.reliable else final_path
        destination = final_path or ("$Recycle.Bin" if trace.attributes.get("recycle_token") else "")
        detail = trace.original_path or trace.original_name
        events.append(_build_event(
            ctx, "E06-03", {"original_path": trace.original_path, "frn": trace.mft_reference or ""},
            trace.deletion_time, "휴지통 이동 기록" if trace.deletion_time else "USN 삭제 기록",
            f"{detail} → {destination}" if destination else detail, evidence,
            conversation_uuid=trace.conversation_uuid,
            basis="recycle_bin_i_deletion_time" if trace.deletion_time else "usn_delete_event",
            direct=bool(trace.deletion_time) and matched is not None,
            why="$I deletion metadata for a file proven downloaded from Claude",
            conflicts=[] if matched else ["deleted file not linked to a Claude download by exact path"],
        ))
    return events

@_detector("E07-01", "no export settings visit and no export API object")
def detect_export(ctx: DetectorContext) -> list[FinalEvent]:
    completions = [r for r in ctx.store.by_family(FAMILY_CACHE)
                   if "export" in str(r.attributes.get("cache_key", "")).lower()
                   and any(t in str(r.attributes.get("cache_key", "")).lower()
                           for t in ("/api/", "archive", "download"))]
    if completions:
        completions.sort(key=lambda r: _order(_at(r)))
        return [_build_event(
            ctx, "E07-01", {"flow": "export_complete"}, _at(completions[0]),
            "Export 요청/아카이브 확인", short_url(completions[0].attributes.get("cache_key")),
            [(r, "") for r in completions], basis="export_api_object", direct=True,
            why="export API request / archive object",
        )]
    visits = [r for r in ctx.store if r.artifact_family in (FAMILY_HISTORY, FAMILY_SESSIONS)
              and "data-privacy-controls" in str(r.attributes.get("url", "")).lower()]

    visits = [r for r in visits if r.artifact_family == FAMILY_HISTORY] or visits
    dialog =[r for r in visits if "export-data" in str(r.attributes.get("url", "")).lower()]
    basis = sorted(dialog or visits, key=lambda r: (_order(r.timestamp), r.evidence_id))
    if not basis:
        return []
    return [_build_event(
        ctx, "E07-01", {"flow": "export_screen_access"}, basis[0].timestamp,
        "Export 설정 화면 접근(완료 미확인)", short_url(basis[0].attributes.get("url")),
        [(r, "") for r in basis], basis="export_screen_visit",
        disqualifiers=["settings page visit only; no export API request or archive"],
    )]

@_detector("E07-02", "no share snapshot object")
def detect_share_link(ctx: DetectorContext) -> list[FinalEvent]:
    events, known, flows = [], {}, {}
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        if not info.snapshot_uuid:
            continue
        snapshots = [r for r in (ctx.store.get(eid) for eid in info.snapshot_ids) if r]
        shares = [r for r in ctx.store.by_family(FAMILY_CACHE)
                  if r.attributes.get("key_kind") == "share_api" and r.conversation_uuid == uuid
                  and r.attributes.get("share_people_count") is not None]
        evidence: Evidence = [
            (r, f"[Cache] 공유 스냅샷 객체 visibility={r.attributes.get('snapshot_visibility')}"
                f", 응답 {kst(_at(r))}") for r in snapshots]
        evidence += [(r, f"공유 접근 대상 {r.attributes.get('share_people_count')}명") for r in shares]
        created = info.snapshot_created_at
        events.append(_build_event(
            ctx, "E07-02", {"snapshot_uuid": info.snapshot_uuid, "conversation_uuid": uuid}, created,
            "공유 스냅샷 객체" if created else "공유 스냅샷 객체(생성 시각 미상)", info.title, evidence, conversation_uuid=uuid,
            basis="snapshot_created_at",
            direct=True, why="snapshot object maps snapshot_uuid to conversation_uuid",
        ))
        known[(uuid, info.snapshot_uuid)] = events[-1]
    for event, record in _analytics(ctx):
        props = event.get("properties") or {}
        uuid = str(props.get("conversation_uuid") or "").lower()
        if not uuid:
            continue
        key = (_profile(record), event.get("account_uuid"), event.get("organization_uuid"), uuid)
        name, flow = event.get("eventName"), flows.get(key, [])
        if name == "chat.share.modal.opened":
            flows[key] = [(event, record)] if props.get("is_shared") is False else []
        elif name == "chat.share.modal.share_button.clicked" and flow:
            flows[key] = flow[:1] + [(event, record)]
        elif name == "chat.share.copy_link.clicked" and props.get("snapshot_uuid"):
            at = event_time(event)
            times = [event_time(e) for e, _ in flow] + [at]
            proven = len(flow) == 2 and all(times) and times == sorted(times) and times[-1] - times[0] <= FLOW_GAP
            evidence = [(record, _event_line(event, "snapshot_uuid"))]
            if proven:
                evidence += [(r, _event_line(e, "is_shared")) for e, r in flow]
            identity = (uuid, str(props["snapshot_uuid"]))
            if identity in known:
                action = known[identity]
                action.evidence = list(dict.fromkeys(action.evidence + [(r.evidence_id, line) for r, line in evidence]))
                if proven:
                    if action.verdict != VERDICT_CONFIRMED:
                        action.action_detail = "공유 실행 후 링크 복사(생성 시각 미상)"
                    action.verdict, action.reason_code = VERDICT_CONFIRMED, "direct_evidence_allowlisted"
                continue
            events.append(_build_event(
                ctx, "E07-02", {"conversation_uuid": uuid, "snapshot_uuid": identity[1]}, None,
                "공유 실행 후 링크 복사(생성 시각 미상)" if proven else "공유 링크 흔적(신규 생성·시각 미확인)",
                "", evidence, conversation_uuid=uuid, direct=proven, why="unshared -> share -> snapshot link copy",
                disqualifiers=[] if proven else ["copy alone does not establish a newly generated link"],
            ))
            known[identity] = events[-1]
    return events

@_detector("E09-01", "no explicit model transition and no ordered model observations "
                     "differing within one conversation")
def detect_model_change(ctx: DetectorContext) -> list[FinalEvent]:
    events, seen = [], set()
    for event, record in _analytics(ctx):
        props = event.get("properties") or {}
        previous, current = props.get("previous_model"), props.get("model") or props.get("selected_model")
        if "model_selected" in str(event.get("eventName")) and previous and current and previous != current:
            events.append(_build_event(
                ctx, "E09-01", {"source": "analytics", "event": event.get("eventId") or str(event_time(event))},
                event_time(event), "모델 선택 이벤트", f"{previous} → {current}",
                [(record, _event_line(event, "previous_model", "model"))],
                basis="model_selected_event", direct=True, why="model_selected event states the transition",
            ))
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        observations: list[tuple[dt.datetime, str, EvidenceRecord | None, str, str]] = []
        for message in info.messages.values():
            if message.model and message.timestamp:
                record = ctx.store.get(message.evidence_ids[0]) if message.evidence_ids else None
                observations.append((message.timestamp, message.model, record, "",
                                     str(message.attributes.get("previous_model") or "")))
        for event, record in _events_named(ctx, "claudeai.message.sent"):
            props = event.get("properties") or {}
            if str(props.get("conversation_uuid") or "").lower() == uuid and props.get("model") and event_time(event):
                observations.append((event_time(event), props["model"], record, _event_line(event, "model",
                    "message_index"), ""))
        if info.model and info.updated_at and info.object_ids:
            record = ctx.store.get(info.object_ids[0])
            observations.append((info.updated_at, info.model, record, _object_line(info, record, updated=True), ""))
        observations.sort(key=lambda o: o[0])
        for before, after in zip(observations, observations[1:]):
            key = (uuid, before[1], after[1])
            if before[1] == after[1] or key in seen:
                continue
            seen.add(key)
            events.append(_build_event(
                ctx, "E09-01", {"conversation_uuid": uuid, "from": before[1], "to": after[1]},
                after[0], "대화 내 모델 변경(변경 반영 시각 기준)", f"{before[1]} → {after[1]}",
                [(before[2], before[3]), (after[2], after[3])], conversation_uuid=uuid,
                basis="conversation_model_order", direct=after[4] == before[1],
                why="explicit previous_model -> model transition",
            ))
    return events

@_detector("E09-02", "fewer than two differing values of one name field for one account")
def detect_account_rename(ctx: DetectorContext) -> list[FinalEvent]:
    observations: dict[tuple[str, str], list] = defaultdict(list)
    for record in ctx.store:
        for account, at in _account_objects(record):
            for name_field in ("display_name", "full_name"):
                if isinstance(account.get(name_field), str) and account.get("uuid"):
                    observations[(str(account["uuid"]).lower(), name_field)].append(
                        (at, account[name_field], record))
    events = []
    for (account, name_field), values in sorted(observations.items()):
        values = sorted((v for v in values if v[0]), key=lambda v: v[0])
        changes = [(a, b) for a, b in zip(values, values[1:]) if a[1] != b[1]]
        for before, after in changes:
            events.append(_build_event(
                ctx, "E09-02", {"account_uuid": account, "field": name_field, "to": after[1]}, None,
                f"계정 {name_field} 변경 전후 값 관측(변경 시각 미상)", f"{before[1]} → {after[1]}",
                [(before[2], f"[{FAMILY_DISPLAY[before[2].artifact_family]}] {name_field}={before[1]} "
                             f"관측 {kst(before[0])}"),
                 (after[2], f"[{FAMILY_DISPLAY[after[2].artifact_family]}] {name_field}={after[1]} "
                            f"관측 {kst(after[0])}")],
                basis="", direct=True, why="same account UUID carries two ordered values",
            ))
    return events

def _account_objects(record: EvidenceRecord) -> list[tuple[dict[str, Any], dt.datetime | None]]:
    attrs = record.attributes
    if record.artifact_family == FAMILY_CACHE:
        def accounts(node):
            if isinstance(node, list):
                for item in node:
                    yield from accounts(item)
            elif isinstance(node, dict):
                for key in ("account", "creator"):
                    if isinstance(node.get(key), dict):
                        yield node[key]
                yield from accounts(node.get("data"))
        return [(account, _at(record)) for account in accounts(attrs.get("_json"))]
    if attrs.get("key_kind") == "react_query_cache" and isinstance(attrs.get("value"), dict):
        out = []
        for query in (attrs["value"].get("clientState") or {}).get("queries") or []:
            data = (query.get("state") or {}).get("data") if isinstance(query, dict) else None
            if isinstance(data, dict) and isinstance(data.get("account"), dict):
                updated = (query.get("state") or {}).get("dataUpdatedAt")
                at = dt.datetime.fromtimestamp(updated / 1000, dt.timezone.utc) \
                    if isinstance(updated, (int, float)) else None
                out.append((data["account"], at))
        return out
    return []

@_detector("E10-01", "no is_temporary conversation, no is_incognito send event and no " "incognito URL")
def detect_temporary_chat(ctx: DetectorContext) -> list[FinalEvent]:
    events = []
    for uuid, info in sorted(ctx.conversations.conversations.items()):
        if info.is_temporary is True:
            events.append(_build_event(
                ctx, "E10-01", {"conversation_uuid": uuid}, info.created_at,
                "임시 대화 객체(is_temporary=true)", info.title,
                [(ctx.store.get(eid), "") for eid in info.object_ids], conversation_uuid=uuid,
                basis="conversation_created_at", direct=True, why="is_temporary=true",
            ))
    for event, record in _events_named(ctx, "claudeai.message.sent"):
        if (event.get("properties") or {}).get("is_incognito") is True:
            events.append(_build_event(
                ctx, "E10-01", {"event": event.get("eventId") or str(event_time(event))},
                event_time(event), "임시 채팅 메시지 전송 이벤트(is_incognito=true)", "",
                [(record, _event_line(event, "is_incognito", "conversation_uuid"))],
                basis="message_sent_event", direct=True, why="send event with is_incognito=true",
            ))
    urls = sorted((r for r in ctx.store if "incognito=" in str(r.attributes.get("url", "")).lower()),
                  key=lambda r: _order(r.timestamp))
    if not events and urls:
        events.append(_build_event(
            ctx, "E10-01", {"flow": "incognito_url"}, urls[0].timestamp,
            "임시 채팅 URL 접근 흔적(대화 미확인)", short_url(urls[0].attributes.get("url")),
            [(r, "") for r in urls], basis="history_incognito_url",
            disqualifiers=["incognito URL visit without a temporary conversation"],
        ))
    return events

@_detector("E10-02", "out of scope by rule: absence of traces in the standard profile is not "
                     "used to infer Incognito usage", REASON_SINGLE_SNAPSHOT_LIMIT)
def detect_chrome_incognito(ctx: DetectorContext) -> list[FinalEvent]:
    return []

@_detector("E10-03", "no direct evidence of History deletion; record absence alone is not used",
           REASON_SINGLE_SNAPSHOT_LIMIT)
def detect_history_cleared(ctx: DetectorContext) -> list[FinalEvent]:
    return []

@_detector("E10-04", "no bulk Cache deletion pattern in USN; Cache emptiness alone is not used")
def detect_cache_cleared(ctx: DetectorContext) -> list[FinalEvent]:
    if not ctx.extended_fs:
        return []
    deletions = [r for r in ctx.store.by_family("usn")
                 if "FILE_DELETE" in (r.attributes.get("reasons") or [])
                 and "cache_data" in str(r.attributes.get("file_name", "")).lower()]
    if len(deletions) < 50:
        return []
    return [_build_event(
        ctx, "E10-04", {"flow": "cache_bulk_delete"},
        min((r.timestamp for r in deletions if r.timestamp), default=None),
        "USN Cache 파일 일괄 삭제(사용자 의도 미확인)", f"Cache 파일 {len(deletions)}건 삭제",
        [(r, "") for r in deletions], basis="usn_bulk_delete",
        disqualifiers=["bulk deletion observed in USN; user intent not directly proven"],
    )]

DETECTOR_REGISTRY: tuple[tuple[str, Callable[[DetectorContext], DetectorResult]], ...] = (
    ("E01-01", detect_login), ("E01-02", detect_logout), ("E01-03", detect_account_switch),
    ("E03-01", detect_new_conversation), ("E03-02", detect_conversation_delete),
    ("E03-03", detect_conversation_edit), ("E03-04", detect_retry), ("E04-01", detect_prompt),
    ("E05-01", detect_image_upload), ("E05-02", detect_image_attachment_removed),
    ("E05-03", detect_document_upload), ("E05-04", detect_document_attachment_removed),
    ("E05-05", detect_document_download), ("E06-01", detect_image_generation),
    ("E06-02", detect_generated_image_download), ("E06-03", detect_downloaded_file_deleted),
    ("E07-01", detect_export), ("E07-02", detect_share_link), ("E09-01", detect_model_change),
    ("E09-02", detect_account_rename), ("E10-01", detect_temporary_chat), ("E10-02", detect_chrome_incognito),
    ("E10-03", detect_history_cleared), ("E10-04", detect_cache_cleared),
)

class DetectorContractError(RuntimeError):
    pass

if sorted(code for code, _ in DETECTOR_REGISTRY) != sorted(ACTION_LABELS):
    raise DetectorContractError("detector registry must map each catalogue action exactly once")

def run_all(ctx: DetectorContext) -> DetectorResult:
    combined = DetectorResult()
    for code, detector in DETECTOR_REGISTRY:
        try:
            result = detector(ctx)
        except Exception as exc:
            combined.coverage.append(CoverageRow(
                code, label_for(code), rule_for(code), VERDICT_UNDETERMINED,
                REASON_DETECTOR_FAILED, message=f"{type(exc).__name__}: {exc}",
            ))
            continue
        stray = {e.action_code for e in result.events} | {c.action_code for c in result.coverage}
        if stray - {code}:
            raise DetectorContractError(f"detector for {code} emitted action code(s) {sorted(stray - {code})}")
        if len(result.coverage) != 1:
            raise DetectorContractError(f"detector for {code} returned {len(result.coverage)} coverage rows")
        combined.events.extend(result.events)
        combined.coverage.extend(result.coverage)
    return combined
