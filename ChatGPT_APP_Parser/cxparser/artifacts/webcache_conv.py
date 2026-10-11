"""채팅창 HTTP 캐시(Cache_Data) 안의 ChatGPT API 응답 → 채팅 모드 행위·대화 복원.

~/.codex 는 Codex 에이전트 모드만 남기고, ChatGPT 채팅 모드의 대화는 채팅창(Chromium)의 HTTP 캐시에만 남는다.
  conversation/<id> 응답 JSON  : create_time(대화 생성), mapping(메시지 트리: 시각·role·본문·첨부·model_slug),
                                 is_temporary_chat(임시 채팅), default_model_slug
  user 메시지 metadata.attachments : (name, mime_type) → 이미지/문서 업로드
  tool 메시지 image_asset_pointer + metadata.image_gen_title : 이미지 생성
  mapping 분기 : 같은 부모 아래 user 2개 = 대화 수정 / 같은 user 아래 assistant 2개 = 대화 재시도
  default_model_slug 변화 : 모델 변경(추정)
  estuary/content?…&fn=<파일명> : 파일을 이름 붙여 내려받은 요청 → 다운로드
  files/download/<id>?conversation_id= 는 표시용 fetch(JSON) 라 관찰로만.
계정 이름 변경·공유 링크는 캐시에 흔적 없음 (POST 는 캐시되지 않음).

앱 26.928 부터 대화 응답의 주소와 형식이 바뀌었다:
  conversations/<id>?num_turns=10&include_has_versions=true  (복수형 + 쿼리)
  본문은 mapping(트리) 대신 messages(목록). 메시지 필드(author·create_time·content.parts·metadata.attachments)는 같고,
  부모는 metadata.parent_id (user 메시지는 없음). page_info.has_previous_page=true 면 앞쪽 turn 이 응답에 없다.
  대화 목록 응답(conversations?offset=…)과 ~/.codex/sqlite/codex-dev.db 의 local_thread_catalog 는 서버 계정의 대화 목록이라
  다른 기기에서 만든 대화도 들어 있다 → 이 PC 의 행위 근거로 쓰지 않는다.
"""

import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlsplit

from .. import events, model
from ..util import excerpt, mask_text
from .webcache import BlockfileCache, decode_json

_CONV_URL = re.compile(r"^https://chatgpt\.com/backend-api/conversations?/([0-9A-Za-z-]+)(?:\?.*)?$")
_ESTUARY_URL = re.compile(r"^https://chatgpt\.com/backend-api/estuary/content\?")
_IMAGE_MIME = ("image/",)
_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


def _iso(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z") if epoch else None
    except (TypeError, ValueError, OSError):
        return None


def _ts(epoch, meaning):
    iso = _iso(epoch)
    return model.timestamp(utc=iso, original=epoch, fmt="epoch_seconds", meaning=meaning, source=model.TS_SOURCE_CONTENT,
                           null_reason=None if iso else "응답 JSON 에 시각 없음")


def _text_parts(message):
    content = message.get("content") or {}
    return [p for p in (content.get("parts") or []) if isinstance(p, str) and p.strip()]


def _has_image_part(message):
    content = message.get("content") or {}
    return any(isinstance(p, dict) and p.get("content_type") == "image_asset_pointer" for p in (content.get("parts") or []))


def _mapping_from_messages(conv):
    """새 형식(messages 목록) → 기존 mapping 형태 {id: {message, parent, children}}. 응답에 없는 부모는 연결하지 않는다."""
    nodes = {}
    for m in conv.get("messages") or []:
        if isinstance(m, dict) and m.get("id"):
            nodes[m["id"]] = {"message": m, "parent": (m.get("metadata") or {}).get("parent_id"), "children": []}
    for nid, node in nodes.items():
        if node["parent"] in nodes:
            nodes[node["parent"]]["children"].append(nid)
    return nodes


class _Ctx:
    def __init__(self, image_desc, rb, index_vfile, siblings, max_excerpt):
        self.image_desc, self.rb, self.index, self.sib, self.max = image_desc, rb, index_vfile, siblings or {}, max_excerpt

    def evidence(self, resp, extra_locator=""):
        vf = self.sib.get(resp.get("body_file") or "") or self.index
        loc = "cache_entry=%s url=%s%s" % (resp["entry_address"], resp["url"][:160], (" " + extra_locator) if extra_locator else "")
        return model.evidence(self.image_desc, vf, locator=loc)

    def rec(self, event_id, ts, action, ev, details, status="ok", notes=None):
        return model.Record(self.rb.next_id(), event_id, events.name(event_id), ts, action, ev, status=status, notes=notes or [], details=details)


def _conversation_records(ctx, conv, resp):
    """대화 JSON 하나 → 레코드 목록 (대화 생성·임시 채팅·메시지·첨부·이미지 생성·분기)."""
    out = []
    cid, title = conv.get("conversation_id") or "", conv.get("title") or ""
    base = {"artifact": "webcache", "thread_id": cid, "title": title, "conversation_id": cid,
            "default_model_slug": conv.get("default_model_slug"), "is_temporary_chat": conv.get("is_temporary_chat"),
            "cache_created_utc": resp["created_utc"]}
    if (conv.get("page_info") or {}).get("has_previous_page"):
        base["partial"] = "응답이 최근 turn 만 담고 있음 (page_info.has_previous_page) — 앞쪽 메시지는 이 캐시에 없다"
    ev = ctx.evidence(resp)
    out.append(ctx.rec("E03-01", _ts(conv.get("create_time"), "대화 JSON 의 create_time"),
                       model.user_action(action="새 대화 생성(채팅 모드)", confidence=model.CONF_CONFIRMED,
                                         rationale="채팅창 HTTP 캐시의 conversation 응답 — 서버가 준 대화 생성 시각. 에이전트 모드 rollout 과 별개인 ChatGPT 채팅 모드 대화"),
                       ev, dict(base, key="conversation")))
    if conv.get("is_temporary_chat") is True:
        out.append(ctx.rec("E10-01", _ts(conv.get("create_time"), "임시 채팅 대화의 create_time"),
                           model.user_action(action="임시 채팅 사용", confidence=model.CONF_CONFIRMED,
                                             rationale="conversation 응답의 is_temporary_chat=true — 임시 채팅은 ~/.codex 에 rollout 을 남기지 않아 캐시가 유일한 로컬 근거"),
                           ev, dict(base, key="is_temporary_chat")))
    mapping = conv.get("mapping") or {}
    nodes = {nid: n for nid, n in mapping.items() if isinstance(n, dict)}
    seen_gen = set()
    for nid, node in nodes.items():
        m = node.get("message")
        if not isinstance(m, dict):
            continue
        role = (m.get("author") or {}).get("role")
        md = m.get("metadata") or {}
        texts = _text_parts(m)
        text = "\n".join(texts)
        det = dict(base, message_id=m.get("id"), node_id=nid, parent=node.get("parent"), role=role,
                   model_slug=md.get("model_slug"), text=mask_text(text) if text else None)
        if role == "user" and text:
            out.append(ctx.rec("E04-01", _ts(m.get("create_time"), "user 메시지의 create_time"),
                               model.user_action(action="프롬프트 전송(채팅 모드)", confidence=model.CONF_CONFIRMED,
                                                 rationale="conversation 응답 mapping 의 role=user 메시지 — 서버에 도착한 프롬프트 원문"),
                               ctx.evidence(resp, "message=%s" % m.get("id")), det))
        elif role in ("assistant", "tool") and text and not md.get("is_visually_hidden_from_conversation"):
            out.append(ctx.rec("NA-00", _ts(m.get("create_time"), "%s 메시지의 create_time" % role),
                               model.user_action(observed="채팅 모드 %s 응답: %s" % (role, excerpt(mask_text(text), 120)),
                                                 rationale="사용자 행위가 아닌 모델 응답 — 대화 복원(recovered_conversations)용"),
                               ctx.evidence(resp, "message=%s" % m.get("id")), det))
        for att in (md.get("attachments") or []):
            if not isinstance(att, dict):
                continue
            name, mime = att.get("name") or "", (att.get("mime_type") or att.get("mimeType") or "").lower()
            ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            eid = "E05-01" if mime.startswith(_IMAGE_MIME) or ext in _IMAGE_EXT else "E05-03"
            out.append(ctx.rec(eid, _ts(m.get("create_time"), "첨부가 붙은 user 메시지의 create_time"),
                               model.user_action(action="첨부 업로드(채팅 모드)", confidence=model.CONF_CONFIRMED,
                                                 rationale="user 메시지 metadata.attachments 에 파일명·MIME — 서버가 받은 첨부 목록"),
                               ctx.evidence(resp, "message=%s attachment=%s" % (m.get("id"), name)),
                               dict(base, message_id=m.get("id"), role=role, file_name=name, mime_type=mime, size=att.get("size"), key=None)))
        if role in ("assistant", "tool") and (_has_image_part(m) or md.get("image_gen_title") or md.get("image_gen_group_id")):
            gid = md.get("image_gen_group_id") or m.get("id")
            if gid in seen_gen:                            # 한 요청에 이미지 여러 장 → 행 하나
                continue
            seen_gen.add(gid)
            out.append(ctx.rec("E06-01", _ts(m.get("create_time"), "생성 이미지가 담긴 메시지의 create_time"),
                               model.user_action(action="이미지 생성 결과 수신", confidence=model.CONF_CONFIRMED,
                                                 rationale="assistant/tool 메시지에 image_asset_pointer 와 metadata.image_gen_* — 이미지 생성 요청이 처리된 결과. 요청 시각은 직전 user 메시지"),
                               ctx.evidence(resp, "message=%s" % m.get("id")),
                               dict(base, message_id=m.get("id"), role=role, title=md.get("image_gen_title") or title,
                                    image_gen_title=md.get("image_gen_title"), image_gen_group_id=md.get("image_gen_group_id"), key=None)))
    # 분기: 같은 부모 아래 형제 메시지
    for nid, node in nodes.items():
        kids = [nodes[c]["message"] for c in (node.get("children") or []) if c in nodes and isinstance(nodes[c].get("message"), dict)]
        if len(kids) < 2:
            continue
        kids.sort(key=lambda m: m.get("create_time") or 0)
        for later in kids[1:]:
            role = (later.get("author") or {}).get("role")
            if role == "user":
                eid, act, why = "E03-03", "대화 수정(프롬프트 편집)", "같은 부모 아래 user 메시지가 둘 — 앞 프롬프트를 고쳐 다시 보낸 분기"
            elif role == "assistant":
                eid, act, why = "E03-04", "대화 재시도(응답 재생성)", "같은 user 메시지 아래 assistant 응답이 둘 — 응답 재생성 분기"
            else:
                continue
            out.append(ctx.rec(eid, _ts(later.get("create_time"), "분기 메시지의 create_time"),
                               model.user_action(action=act, confidence=model.CONF_CONFIRMED, rationale=why),
                               ctx.evidence(resp, "message=%s" % later.get("id")),
                               dict(base, message_id=later.get("id"), parent=nid, role=role,
                                    text=mask_text("\n".join(_text_parts(later)))[:200] or None)))
    return out


def _download_records(ctx, resp):
    q = parse_qs(urlsplit(resp["url"]).query)
    fn = unquote(q.get("fn", [""])[0])
    if not fn:
        return []
    ctype = (resp.get("content_type") or "").lower()
    ext = ("." + fn.rsplit(".", 1)[-1].lower()) if "." in fn else ""
    eid = "E06-02" if ctype.startswith("image/") or ext in _IMAGE_EXT else "E05-05"
    ts = model.timestamp(utc=resp["created_utc"], fmt="webkit_us", meaning="캐시 entry 생성 시각 = 파일을 내려받은 요청 시각", source=model.TS_SOURCE_CONTENT)
    return [ctx.rec(eid, ts,
                    model.user_action(action="파일 내려받기(채팅 모드)", confidence=model.CONF_CONFIRMED,
                                      rationale="estuary/content 요청에 fn=<파일명> — 사용자가 '다운로드'를 눌러 이름 붙여 받을 때만 붙는 매개변수. 표시용 fetch 에는 없음"),
                    ctx.evidence(resp), {"artifact": "webcache", "file_name": fn, "file_id": q.get("id", [""])[0], "mime_type": ctype,
                                         "size": len(resp.get("body") or b""), "cache_created_utc": resp["created_utc"]})]


def _model_change_records(ctx, convs):
    """대화들을 create_time 순으로 보며 default_model_slug 가 바뀐 지점 = 모델 변경(추정)."""
    out, prev = [], None
    for conv, resp in sorted(convs, key=lambda c: c[0].get("create_time") or 0):
        slug = conv.get("default_model_slug")
        if prev is not None and slug and slug != prev:
            out.append(ctx.rec("E09-01", _ts(conv.get("create_time"), "기본 모델이 바뀐 첫 대화의 create_time"),
                               model.user_action(action="모델 변경(기본 모델 %s → %s)" % (prev, slug), confidence=model.CONF_INFERRED,
                                                 rationale="이전 대화들의 default_model_slug 와 다른 값으로 만들어진 첫 대화 — 그 사이에 모델을 바꾼 것으로 추정 (정확한 클릭 시각은 없음)"),
                               ctx.evidence(resp), {"artifact": "webcache", "thread_id": conv.get("conversation_id"), "title": conv.get("title"),
                                                    "model_slug": slug, "previous_model_slug": prev, "key": "%s -> %s" % (prev, slug)}))
        if slug:
            prev = slug
    return out


def parse(vfile, image_desc, rb, max_excerpt=500, siblings=None):
    """vfile = Cache_Data/index. siblings = {파일명: VfsFile} (data_0~3, f_*)."""
    sib = siblings or {}
    ctx = _Ctx(image_desc, rb, vfile, sib, max_excerpt)

    def read(name):
        if name == "index":
            return vfile.read()
        if name not in sib:
            raise KeyError(name)
        return sib[name].read()
    try:
        cache = BlockfileCache(read)
        entries, unreadable, carved = cache.entries(vfile.read())
    except Exception as exc:
        return [model.Record(rb.next_id(), "NA-00", events.name("NA-00"), model.timestamp(null_reason="캐시 index 해석 실패"),
                             model.user_action(observed="채팅창 HTTP 캐시 index 존재, 해석 실패"), model.evidence(image_desc, vfile, locator="index"),
                             status="error", errors=[{"code": "CACHE_INDEX_FAILED", "message": str(exc)}], details={"artifact": "webcache"})]
    records, convs, warn = [], {}, []
    for e in sorted(entries, key=lambda e: e[2]):
        resp = cache.response(e)
        url = resp["url"]
        m = _CONV_URL.match(url)
        if m:
            obj = decode_json(resp)
            if isinstance(obj, dict) and not isinstance(obj.get("mapping"), dict) and isinstance(obj.get("messages"), list):
                obj["mapping"] = _mapping_from_messages(obj)     # 앱 26.928 이후 형식
            if isinstance(obj, dict) and isinstance(obj.get("mapping"), dict):
                cid = obj.get("conversation_id") or m.group(1)
                prev = convs.get(cid)
                if prev is None or (obj.get("update_time") or 0) >= (prev[0].get("update_time") or 0):
                    convs[cid] = (obj, resp)                # 같은 대화의 여러 시점 중 가장 나중 것 (메시지가 가장 많다)
            elif resp["warnings"]:
                warn.append("%s: %s" % (url[-20:], ",".join(resp["warnings"])))
        elif _ESTUARY_URL.match(url):
            records.extend(_download_records(ctx, resp))
    for conv, resp in convs.values():
        records.extend(_conversation_records(ctx, conv, resp))
    records.extend(_model_change_records(ctx, list(convs.values())))
    records.append(model.Record(
        rb.next_id(), "NA-00", events.name("NA-00"), model.timestamp(null_reason="요약 레코드 — 단일 시각 없음"),
        model.user_action(observed="채팅창 HTTP 캐시: entry %d (index 밖 carving %d, 못 읽음 %d), 대화 %d개" % (len(entries), carved, unreadable, len(convs)),
                          rationale="캐시 해석 범위 요약. 본문을 풀지 못한 응답: %s" % ("; ".join(warn[:5]) or "없음")),
        model.evidence(image_desc, vfile, locator="index"), status="ok" if not unreadable else "partial",
        details={"artifact": "webcache", "entries": len(entries), "carved": carved, "unreadable": unreadable,
                 "conversations": sorted(convs), "undecoded": warn}))
    return records
