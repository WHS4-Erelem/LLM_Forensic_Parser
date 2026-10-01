"""IndexedDB 정식 파싱 — 대화를 객체 단위로 복원한다.

바이트를 긁어 본문을 찾는 방식은 누가 한 말인지, 언제 한 말인지 알 수 없었다.
IndexedDB 값은 V8 구조화 복제(structured clone)라서 정식 역직렬화를 거치면
파이썬 dict 로 나온다. 그러면 발화자·시각·대화 UUID 를 추측 없이 읽는다.

Claude Desktop 은 claude.ai 오리진 아래 IndexedDB 를 여섯 개 쓰는데, 대화는
두 곳에 두 가지 형태로 들어간다.

  claude-conversation-store / trees
      product='chat'    tree = {uuid, name, chat_messages:[{sender, content, …}]}
      product='cowork'  tree = {events:[{payload:{message:{role, content}, …}}]}
  keyval-store / keyval
      'react-query-cache' -> 대화 목록(제목·생성시각·모델·임시채팅 플래그)

한 대화가 여러 레코드에 걸쳐 여러 판본으로 남는다 (앱이 갱신할 때마다 쌓임).
메시지 UUID 로 접고 가장 긴 본문을 남긴다 — 잘린 판본 때문에 본문을 잃지 않는다.
"""

from __future__ import annotations

import hashlib
import os
import re

_IMPORT_ERROR = None
try:
    from ccl_chromium_reader import ccl_chromium_indexeddb as _idb
except Exception as exc:                       # pragma: no cover
    _idb = None
    _IMPORT_ERROR = "%s: %s" % (type(exc).__name__, exc)

MAX_DEPTH = 14
MAX_LIST = 800

ROLE_MAP = {"human": "user", "user": "user", "assistant": "assistant",
            "system": "system", "model": "assistant"}

# 대화 객체와 모양이 겹치지만 대화가 아닌 것들
ORG_MARKERS = ("capabilities", "billing_type", "organization_type",
               "rate_limit_tier", "raven_settings", "api_disabled_reason")
PROJECT_MARKERS = ("creator", "archiver", "is_private", "prompt_template")

# 사용자가 직접 친 말이 아닌 본문
SYS_INJECT = re.compile(r"^\s*<(system-reminder|env|system)>", re.I)
UPLOAD_BLOCK = re.compile(r"^\s*<uploaded_files>", re.I)


def import_error():
    return _IMPORT_ERROR


# ── 이미지 안의 파일을 임시 폴더로 꺼낸다 ─────────────────────────────
# ccl 은 디스크 위의 LevelDB 디렉터리를 요구한다. 이미지 안 파일은 그대로
# 열 수 없으므로 원래 디렉터리 구조를 유지해 임시 폴더에 쓴다. 대소문자를
# 보존해야 한다 — LevelDB 는 CURRENT / MANIFEST-nnnnnn 을 정확히 찾는다.

_IDB_SPLIT = ".indexeddb."


def _slot(path):
    """이 파일이 어느 저장소에 속하는지 — 원본 경로에서 만든 짧은 이름.

    한 이미지에 Windows 사용자가 여럿이면 IndexedDB 폴더 이름이 모두 같다
    (https_claude.ai_0.indexeddb.leveldb). 그대로 풀면 뒤에 나온 사용자가
    앞 사용자를 덮어써서 한 사람의 대화를 통째로 잃는다. 그래서 저장소가
    있던 자리(사용자·설치 형태)까지 이름에 담아 따로 둔다.
    """
    norm = path.replace(chr(92), "/")
    i = norm.lower().find(_IDB_SPLIT)
    holder = norm[:norm.rfind("/", 0, i)]              # 'Users/alice/AppData/…/IndexedDB'
    tag = re.sub(r"[^0-9A-Za-z]+", "_", holder).strip("_").lower()
    return "%s_%s" % (tag[-48:], hashlib.sha1(holder.encode("utf-8")).hexdigest()[:8])


def materialize(vfiles, dst):
    """
    -> {디렉터리이름: 경로}, [(원본 VfsFile, 임시경로)]

    저장소마다 자기 자리(_slot)에 푼다. 사용자가 여럿이어도 섞이지 않는다.
    삭제된 엔트리는 같은 이름으로 덮어쓰면 살아있는 파일을 가리므로 별도
    디렉터리에 담는다 (deleted_<MFT#>/).
    """
    dirs, written = {}, []
    for vfile in vfiles:
        norm = vfile.path.replace("\\", "/")
        low = norm.lower()
        i = low.find(_IDB_SPLIT)
        if i < 0:
            continue
        rel = norm[low.rfind("/", 0, i) + 1:]           # 'https_…leveldb/000003.log'
        base = os.path.join(dst, _slot(vfile.path))
        if not vfile.allocated:
            base = os.path.join(base, "deleted_%s" % (vfile.mft_record or 0))
        out = os.path.join(base, *rel.split("/"))
        try:
            data = vfile.read()
        except Exception:
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(data)
        written.append((vfile, out))
        top = rel.split("/", 1)[0]
        dirs.setdefault((base, top), os.path.join(base, top))
    return dirs, written


def db_pairs(dirs):
    """materialize 결과에서 (leveldb 디렉터리, blob 디렉터리) 짝을 만든다."""
    pairs = []
    for (base, top), path in sorted(dirs.items()):
        if not top.lower().endswith(".leveldb"):
            continue
        blob = os.path.join(base, top[:-len(".leveldb")] + ".blob")
        pairs.append((path, blob if os.path.isdir(blob) else None))
    return pairs


def open_db(leveldb_dir, blob_dir=None):
    """열지 못하면 None — 호출한 쪽이 바이트 스캔으로 넘어간다."""
    if _idb is None:
        return None
    try:
        return _idb.WrappedIndexDB(str(leveldb_dir),
                                   str(blob_dir) if blob_dir else None)
    except Exception:
        return None


def iter_records(db):
    """모든 데이터베이스·스토어의 레코드. -> (db이름, 스토어명, 키, 값, live)"""
    meta = getattr(db, "global_metadata", None) or getattr(
        getattr(db, "_raw_db", None), "global_metadata", None)
    try:
        ids = list(meta.db_ids)
    except Exception:
        return
    for dbid in ids:
        try:
            wrapped = db[dbid.dbid_no]
            names = list(wrapped.object_store_names)
        except Exception:
            continue
        for store_name in names:
            try:
                store = wrapped[store_name]
                it = store.iterate_records()
            except Exception:
                continue
            while True:                       # 한 레코드가 깨져도 멈추지 않는다
                try:
                    rec = next(it)
                except StopIteration:
                    break
                except Exception:
                    break
                yield (dbid.name, store_name,
                       rec.key.value if rec.key else None, rec.value,
                       bool(rec.is_live))


# ── 본문 추출 ─────────────────────────────────────────────────────────

def content_text(content):
    """
    -> (본문, 블록종류들)

    content 는 문자열이거나 블록 배열이다. 블록에는 사용자 본문(text) 말고도
    모델 내부 사고(thinking)·도구 호출(tool_use)·도구 결과(tool_result)가 섞여
    있다. 본문만 모으고 나머지는 종류만 기록한다 — 도구 출력을 사용자 발화로
    싣지 않기 위해서다.
    """
    kinds = []
    if isinstance(content, str):
        return content, kinds
    if not isinstance(content, list):
        return "", kinds
    parts = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        t = str(item.get("type") or "")
        kinds.append(t or "?")
        if t in ("text", "") and isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif t == "thinking":
            continue                                   # 모델 내부 사고
        elif t in ("tool_use", "tool_result", "server_tool_use",
                   "web_search_tool_result", "knowledge"):
            continue                                   # 도구 왕복
        elif isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif item.get("content"):
            inner, ik = content_text(item["content"])
            kinds.extend(ik)
            if inner:
                parts.append(inner)
    return "\n".join(p for p in parts if p), kinds


def as_text(value):
    """V8 역직렬화가 일부 값을 bytes 로 준다. 문자열로 맞춘다."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _norm(uuid):
    return str(uuid).lower() if uuid else ""


def _msg(role, text, kinds, *, uuid, conversation, created_at=None,
         index=None, parent=None, model_id="", session="", source="",
         is_live=True, attachments=None, files=None):
    """메시지 한 건을 평평한 사전으로. 본문이 없으면 None."""
    if not text or not text.strip():
        return None
    role = ROLE_MAP.get(str(role).lower(), "unknown")
    if role == "user" and ("tool_result" in kinds and "text" not in kinds):
        origin = "tool_result"                 # 도구 결과를 앱이 user 로 넣는다
    elif SYS_INJECT.match(text):
        origin = "system_injection"
    elif UPLOAD_BLOCK.match(text):
        origin = "user_upload"
    elif role == "user":
        origin = "user_typed"
    else:
        origin = role
    return {"conversation_uuid": _norm(conversation), "message_uuid": _norm(uuid),
            "role": role, "origin": origin, "text": text.strip(),
            "created_at": created_at, "index": index,
            "parent_message_uuid": _norm(parent), "model": str(model_id or ""),
            "session_id": str(session or ""), "source": source,
            "is_live": is_live, "block_kinds": sorted(set(kinds)),
            "attachments": attachments or [], "files": files or []}


def from_chat_tree(tree, key, is_live):
    """product='chat' — 고전 대화 객체. tree.chat_messages 를 순서대로."""
    out = []
    conv = tree.get("uuid") or key
    model_id = tree.get("model") or ""
    for m in tree.get("chat_messages") or []:
        if not isinstance(m, dict):
            continue
        text, kinds = content_text(m.get("content"))
        if not text and isinstance(m.get("text"), str):
            text = m["text"]
        rec = _msg(m.get("sender") or m.get("role"), text, kinds,
                   uuid=m.get("uuid"), conversation=conv,
                   created_at=m.get("created_at"), index=m.get("index"),
                   parent=m.get("parent_message_uuid"), model_id=model_id,
                   source="conversation_store/chat", is_live=is_live,
                   attachments=m.get("attachments"), files=m.get("files"))
        if rec:
            out.append(rec)
    return out


def from_cowork_tree(tree, key, is_live):
    """product='cowork' — 이벤트 스트림. events[].payload.message 가 본문."""
    out = []
    for ev in tree.get("events") or []:
        if not isinstance(ev, dict):
            continue
        p = ev.get("payload")
        if not isinstance(p, dict):
            continue                            # permission_resolved 등 본문 없음
        msg = p.get("message")
        if not isinstance(msg, dict):
            continue
        text, kinds = content_text(msg.get("content"))
        # 모델 응답 payload 에는 created_at 이 없다. 이벤트의 서버 수신 시각
        # (epoch ms) 이 같은 값을 가리키므로 그것으로 대신한다.
        when = p.get("created_at") or ev.get("serverCreatedAt")
        rec = _msg(msg.get("role") or p.get("type"), text, kinds,
                   uuid=p.get("uuid") or ev.get("dedupKey"), conversation=key,
                   created_at=when, index=ev.get("seq"),
                   parent=p.get("parent_tool_use_id"),
                   model_id=msg.get("model") or "",
                   session=p.get("session_id") or "",
                   source="conversation_store/cowork", is_live=is_live)
        if rec:
            out.append(rec)
    return out


# ── 일반 순회 (스키마를 모르는 저장소용) ──────────────────────────────

def walk_messages(node, out, depth=0, conversation=""):
    """
    메시지로 보이는 dict 를 찾되 그것을 감싼 대화를 함께 기억한다.

    한 레코드가 여러 대화의 메시지를 담기도 한다. 대화를 따라가지 않으면
    서로 다른 대화의 메시지가 한 대화로 뭉쳐 없던 흐름이 생긴다.
    """
    if depth > MAX_DEPTH:
        return
    if isinstance(node, dict):
        context = conversation
        if isinstance(node.get("uuid"), str) and (
                "chat_messages" in node or "current_leaf_message_uuid" in node):
            context = _norm(node["uuid"])
        has_id = any(k in node for k in ("uuid", "message_uuid"))
        has_sender = any(k in node for k in ("sender", "role", "author"))
        if has_id and has_sender:
            explicit = node.get("conversation_uuid") or node.get("chat_conversation_uuid")
            out.append((node, _norm(explicit) if explicit else context))
        for value in node.values():
            walk_messages(value, out, depth + 1, context)
    elif isinstance(node, list):
        for item in node[:MAX_LIST]:
            walk_messages(item, out, depth + 1, conversation)


def find_conversations(node, out, depth=0):
    """대화 목록 객체 (uuid + name + 생성시각). 조직·프로젝트는 뺀다."""
    if depth > MAX_DEPTH:
        return
    if isinstance(node, dict):
        if (isinstance(node.get("uuid"), str) and "name" in node
                and ("created_at" in node or "updated_at" in node)
                and "sender" not in node
                and not any(m in node for m in ORG_MARKERS)
                and not any(m in node for m in PROJECT_MARKERS)):
            out.append(node)
        for value in node.values():
            find_conversations(value, out, depth + 1)
    elif isinstance(node, list):
        for item in node[:MAX_LIST]:
            find_conversations(item, out, depth + 1)


def _fold(store, rec):
    """같은 메시지의 여러 판본을 하나로. 가장 긴 본문과 채워진 필드를 남긴다."""
    key = rec["message_uuid"] or ("%s#%s" % (rec["conversation_uuid"], rec["text"][:40]))
    prev = store.get(key)
    if prev is None:
        store[key] = rec
        return
    if len(rec["text"]) > len(prev["text"]):
        prev["text"] = rec["text"]
        prev["origin"] = rec["origin"]
        prev["block_kinds"] = rec["block_kinds"]
    for k in ("conversation_uuid", "created_at", "index", "parent_message_uuid",
              "model", "session_id"):
        if not prev.get(k) and rec.get(k):
            prev[k] = rec[k]
    if rec["is_live"]:
        prev["is_live"] = True


def harvest(db):
    """
    IndexedDB 하나에서 대화를 전부 꺼낸다.

    -> {"messages": [...], "conversations": {uuid: 메타}, "opened": [...],
        "stats": {...}}
    """
    messages, conversations, opened = {}, {}, []
    stats = {"records": 0, "trees_chat": 0, "trees_cowork": 0,
             "generic": 0, "stores": {}}

    for dbname, store, key, value, is_live in iter_records(db):
        stats["records"] += 1
        sk = "%s/%s" % (dbname, store)
        stats["stores"][sk] = stats["stores"].get(sk, 0) + 1
        if not isinstance(value, dict):
            continue
        skey = str(key) if key is not None else ""

        # 1) 대화 저장소 — 스키마를 아는 두 형태
        tree = value.get("tree")
        if isinstance(tree, dict):
            if tree.get("chat_messages") is not None:
                stats["trees_chat"] += 1
                for rec in from_chat_tree(tree, skey, is_live):
                    _fold(messages, rec)
                if tree.get("uuid") and tree.get("name") is not None:
                    conversations.setdefault(_norm(tree["uuid"]), {}).update(
                        {"name": tree.get("name"), "created_at": tree.get("created_at"),
                         "updated_at": tree.get("updated_at"),
                         "model": tree.get("model") or value.get("product") or "",
                         "source": "conversation_store"})
            elif tree.get("events") is not None:
                stats["trees_cowork"] += 1
                for rec in from_cowork_tree(tree, skey, is_live):
                    _fold(messages, rec)
                conversations.setdefault(_norm(skey), {}).update(
                    {"name": conversations.get(_norm(skey), {}).get("name"),
                     "created_at": None, "source": "conversation_store",
                     "model": "", "product": value.get("product") or "cowork"})
            for k in ("accountUuid", "orgUuid", "messageCount", "sessionMarker"):
                if value.get(k) is not None:
                    conversations.setdefault(
                        _norm(value.get("conversationUuid") or skey), {})[k] = value[k]
            continue

        # 2) 열어본 기록 — meta 스토어
        if store == "meta" and value.get("conversationUuid"):
            opened.append({"conversation_uuid": _norm(value["conversationUuid"]),
                           "last_opened_at": value.get("lastOpenedAt"),
                           "fetched_at": value.get("fetchedAt"),
                           "written_at": value.get("writtenAt"),
                           "message_count": value.get("messageCount"),
                           "product": value.get("product")})
            continue

        # 3) 그 밖의 저장소 — 스키마를 모르니 일반 순회
        convs = []
        find_conversations(value, convs)
        for c in convs:
            meta = conversations.setdefault(_norm(c["uuid"]), {})
            for k, dst in (("name", "name"), ("created_at", "created_at"),
                           ("updated_at", "updated_at"), ("model", "model"),
                           ("is_temporary", "is_temporary"),
                           ("project_uuid", "project_uuid"),
                           ("is_starred", "is_starred"),
                           ("is_archived", "is_archived")):
                if c.get(k) is not None and meta.get(dst) in (None, ""):
                    meta[dst] = c[k]
            # 요약은 본문이 남지 않은 대화의 유일한 내용 단서다. 판본마다
            # 길이가 달라서, 가장 긴 것을 남긴다.
            summary = as_text(c.get("summary"))
            if summary and len(summary) > len(meta.get("summary") or ""):
                meta["summary"] = summary
            meta.setdefault("source", "%s/%s" % (dbname, store))
        found = []
        walk_messages(value, found)
        for obj, conv in found:
            text, kinds = content_text(obj.get("content"))
            if not text and isinstance(obj.get("text"), str):
                text = obj["text"]
            rec = _msg(obj.get("sender") or obj.get("role") or obj.get("author"),
                       text, kinds, uuid=obj.get("uuid") or obj.get("message_uuid"),
                       conversation=conv, created_at=obj.get("created_at"),
                       index=obj.get("index"),
                       parent=obj.get("parent_message_uuid"),
                       model_id=obj.get("model") or "",
                       source="%s/%s" % (dbname, store), is_live=is_live,
                       attachments=obj.get("attachments"), files=obj.get("files"))
            if rec:
                stats["generic"] += 1
                _fold(messages, rec)

    out = list(messages.values())
    out.sort(key=lambda r: (r["conversation_uuid"], str(r["created_at"] or ""),
                            r["index"] if isinstance(r["index"], int) else 0))
    return {"messages": out, "conversations": conversations, "opened": opened,
            "stats": stats}
