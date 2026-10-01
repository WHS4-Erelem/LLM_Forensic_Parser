"""IndexedDB 정식 파싱 결과를 레코드로 옮긴다.

idbtree 가 객체를 꺼내 오면 여기서 사용자 행위로 판정한다. 바이트 스캔과 달리
발화자·시각·대화 UUID 가 아티팩트에 그대로 적혀 있으므로 확신도는 '확인' 이다.

본문이 사용자 발화인지 앱이 끼워 넣은 것인지 구분한다. Claude Desktop 은
시스템 안내와 도구 결과도 role=user 로 저장한다. 그것을 사용자가 친 말로
싣는 순간 보고서가 틀린다.
"""

import os
import shutil
import tempfile

from .. import events, model
from ..util import excerpt, parse_any_time
from . import idbtree
from .idb import _event_of

# 대화 저장소는 앱이 갱신할 때마다 판본을 쌓는다. 한 이미지에서 이 이상
# 나오면 다루지 않고 경고한다 (정상 범위는 수십 건).
MAX_MESSAGES = 20000

# origin -> (타임라인에 올릴지, NA-00 일 때 적을 관찰 내용)
_OBSERVED = {
    "assistant": "모델 응답 본문",
    "system": "시스템 메시지",
    "system_injection": "앱이 대화에 끼워 넣은 시스템 안내 — 사용자 입력이 아님",
    "tool_result": "도구 실행 결과 — 사용자 입력이 아님",
    "unknown": "대화 저장소의 본문 — 역할 표식 없음",
}

ROOT_PARENT = "00000000-0000-4000-8000-000000000000"

_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".heic")


def _ts(value, meaning):
    """아티팩트에 적힌 시각. 해석 못 하면 사유를 남긴다."""
    utc, fmt, note = parse_any_time(value)
    return model.timestamp(utc=utc, original=value, fmt=fmt, meaning=meaning,
                           source=model.TS_SOURCE_CONTENT,
                           tz_note=note if utc else None,
                           null_reason=None if utc else (note or "시각 해석 실패"))


def _upload_event(msg):
    """<uploaded_files> 본문 — 파일 확장자로 이미지/문서를 가른다."""
    low = msg["text"].lower()
    for f in (msg.get("files") or []) + (msg.get("attachments") or []):
        name = str((f or {}).get("file_name") or (f or {}).get("name") or "").lower()
        if name.endswith(_IMG_EXT):
            return "E05-01", "이미지 업로드"
    if any(e in low for e in _IMG_EXT):
        return "E05-01", "이미지 업로드"
    return "E05-03", "문서 업로드"


def _locator(msg):
    bits = ["idb=claude-conversation-store", "source=%s" % msg["source"]]
    if msg["message_uuid"]:
        bits.append("message_uuid=%s" % msg["message_uuid"])
    if msg["index"] is not None:
        bits.append("index=%s" % msg["index"])
    if not msg["is_live"]:
        bits.append("state=historical_or_deleted")
    return " ".join(bits)


def _message_records(harvest, vfile, image, rb, max_excerpt):
    out = []
    convs = harvest["conversations"]
    for msg in harvest["messages"][:MAX_MESSAGES]:
        origin = msg["origin"]
        ts = _ts(msg["created_at"], "메시지 전송 시각")
        if origin in ("user_typed", "user_upload"):
            eid, act = (_event_of(msg["text"]) if origin == "user_typed"
                        else _upload_event(msg))
            conf = model.CONF_CONFIRMED
            observed = None
            rationale = ("대화 저장소 레코드에 발화자(%s)와 본문이 함께 기록됨"
                         % msg["role"])
        else:
            eid, act = "NA-00", model.ACTION_UNKNOWN
            conf = model.CONF_UNKNOWN
            observed = _OBSERVED.get(origin, "대화 저장소의 본문")
            rationale = "대화 저장소 레코드 — 사용자 발화가 아님(%s)" % origin
        if not msg["is_live"]:
            rationale += " · 현재 값이 아닌 과거/삭제 판본"
        title = (convs.get(msg["conversation_uuid"]) or {}).get("name")
        out.append(model.Record(
            rb.next_id(), eid, events.name(eid), ts,
            model.user_action(act, conf, rationale=rationale, observed=observed),
            model.evidence(image, vfile, locator=_locator(msg),
                           excerpt=excerpt(msg["text"], max_excerpt)),
            notes=["structured_indexeddb"],
            details={"artifact": "idb_leveldb", "item_type": "message",
                     "text": msg["text"], "role": msg["role"], "origin": origin,
                     "conversation_uuid": msg["conversation_uuid"],
                     "message_uuid": msg["message_uuid"],
                     "parent_message_uuid": msg["parent_message_uuid"],
                     "message_index": msg["index"], "title": title,
                     "model": msg["model"], "session_id": msg["session_id"],
                     "block_kinds": msg["block_kinds"],
                     "live_state": "live" if msg["is_live"] else "historical",
                     "role_known": True}))
    return out


def _branch_records(harvest, vfile, image, rb, max_excerpt):
    """같은 부모를 둔 형제 메시지 — 대화가 갈라진 자리.

    Claude 는 메시지를 고쳐 보내거나 응답을 다시 받으면 원본을 지우지 않고
    같은 부모 아래에 새 가지를 만든다. 그래서 한 부모에 형제가 둘 이상이면
    그 자리에서 수정이나 재시도가 있었다는 뜻이다.

        사용자 메시지 형제   -> 대화 수정  (보낸 말을 고쳐 다시 보냄)
        모델 응답 형제       -> 대화 재시도 (같은 말에 응답을 다시 받음)

    형제가 없는 부모는 평범한 대화 진행이므로 아무것도 내지 않는다.
    """
    groups = {}
    for m in harvest["messages"]:
        # 루트도 부모로 센다. 대화의 첫 메시지를 고쳐 보내면 형제가 루트
        # 아래에 생기는데, 그 경우를 빼면 첫 질문의 수정을 통째로 놓친다.
        parent = m["parent_message_uuid"]
        if not parent:
            continue
        if m["origin"] in ("system_injection", "tool_result"):
            continue
        groups.setdefault((m["conversation_uuid"], parent, m["role"]), []).append(m)

    out = []
    for (conv, parent, role), sibs in sorted(groups.items()):
        uniq = {m["message_uuid"]: m for m in sibs}
        if len(uniq) < 2:
            continue
        kids = sorted(uniq.values(), key=lambda m: str(m["created_at"] or ""))
        eid, act = (("E03-03", "대화 수정") if role == "user"
                    else ("E03-04", "대화 재시도"))
        title = (harvest["conversations"].get(conv) or {}).get("name")
        for later in kids[1:]:
            out.append(model.Record(
                rb.next_id(), eid, events.name(eid),
                _ts(later["created_at"], "가지가 갈라진 메시지의 시각"),
                model.user_action(act, model.CONF_CONFIRMED,
                                  rationale="같은 부모 메시지(%s) 아래 %s 메시지가 "
                                            "%d개 — 그 자리에서 가지가 갈라졌다"
                                            % (parent[:8], role, len(uniq))),
                model.evidence(image, vfile,
                               locator="parent_message_uuid=%s message_uuid=%s"
                                       % (parent, later["message_uuid"]),
                               excerpt=excerpt(later["text"], max_excerpt)),
                notes=["structured_indexeddb", "sibling_branch"],
                details={"artifact": "idb_leveldb", "item_type": "branch",
                         "conversation_uuid": conv, "title": title,
                         "parent_message_uuid": parent,
                         "message_uuid": later["message_uuid"],
                         "role": role, "siblings": len(uniq),
                         "text": later["text"]}))
    return out


def _conversation_records(harvest, vfile, image, rb, max_excerpt):
    """대화 목록 객체 — 생성 시각과 제목이 적혀 있다."""
    out = []
    for uuid, meta in sorted(harvest["conversations"].items(),
                             key=lambda kv: str(kv[1].get("created_at") or "")):
        name = meta.get("name")
        if not name:
            continue
        created = meta.get("created_at")
        if created:
            out.append(model.Record(
                rb.next_id(), "E03-01", events.name("E03-01"),
                _ts(created, "대화 생성 시각"),
                model.user_action("새로운 대화 생성", model.CONF_CONFIRMED,
                                  rationale="대화 목록 객체에 생성 시각과 제목이 "
                                            "기록됨"),
                model.evidence(image, vfile,
                               locator="idb=keyval-store key=react-query-cache "
                                       "conversation_uuid=%s" % uuid,
                               excerpt=excerpt(str(name), max_excerpt)),
                notes=["structured_indexeddb"],
                details={"artifact": "idb_leveldb", "item_type": "conversation",
                         "conversation_uuid": uuid, "title": str(name),
                         "model": meta.get("model") or "",
                         "project_uuid": meta.get("project_uuid") or "",
                         "message_count": meta.get("messageCount")}))
        # 대화 요약 — 모델이 만든 문장이다. 사용자가 한 말이 아니므로 대화
        # 복원 파일에는 싣지 않고 관찰 기록으로만 남긴다. 본문이 지워진
        # 대화에서는 무슨 이야기였는지 알 수 있는 유일한 단서다.
        summary = str(meta.get("summary") or "").strip()
        if summary:
            out.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                _ts(meta.get("updated_at") or created, "대화 마지막 갱신 시각"),
                model.user_action(observed="대화 요약 — 모델이 생성한 문장이며 "
                                           "사용자 발화가 아니다. 본문이 남지 않은 "
                                           "대화의 내용 단서로만 쓴다"),
                model.evidence(image, vfile,
                               locator="idb=keyval-store key=react-query-cache "
                                       "field=summary conversation_uuid=%s" % uuid,
                               excerpt=excerpt(summary, max_excerpt)),
                notes=["structured_indexeddb", "model_generated_summary"],
                details={"artifact": "idb_leveldb", "item_type": "conversation_summary",
                         "conversation_uuid": uuid, "title": str(name),
                         "summary": summary, "origin": "model_summary"}))

        if meta.get("is_temporary") is True:
            out.append(model.Record(
                rb.next_id(), "E10-01", events.name("E10-01"),
                _ts(created or meta.get("updated_at"), "대화 생성 시각"),
                model.user_action("임시 채팅 사용", model.CONF_CONFIRMED,
                                  rationale="대화 객체의 is_temporary 플래그가 true"),
                model.evidence(image, vfile,
                               locator="conversation_uuid=%s is_temporary=true" % uuid),
                notes=["structured_indexeddb"],
                details={"artifact": "idb_leveldb", "item_type": "temp_chat",
                         "conversation_uuid": uuid, "title": str(name)}))
    return out


def _opened_records(harvest, vfile, image, rb):
    """meta 스토어의 lastOpenedAt — 행위 카탈로그에 없어 관찰로만 남긴다."""
    out = []
    for o in harvest["opened"]:
        if not o.get("last_opened_at"):
            continue
        title = (harvest["conversations"].get(o["conversation_uuid"]) or {}).get("name")
        out.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            _ts(o["last_opened_at"], "대화를 마지막으로 연 시각"),
            model.user_action(observed="대화를 연 기록 (lastOpenedAt) — 대화 %s"
                                       % (title or o["conversation_uuid"][:8])),
            model.evidence(image, vfile,
                           locator="idb=claude-conversation-store store=meta "
                                   "conversation_uuid=%s" % o["conversation_uuid"]),
            notes=["structured_indexeddb"],
            details={"artifact": "idb_leveldb", "item_type": "conversation_opened",
                     "conversation_uuid": o["conversation_uuid"], "title": title,
                     "message_count": o.get("message_count"),
                     "product": o.get("product")}))
    return out


def parse_group(vfiles, image, rb, max_excerpt=500, say=None):
    """
    IndexedDB 파일 묶음을 정식 파서로 읽는다. -> (레코드, 요약)

    ccl 은 디스크 위의 LevelDB 디렉터리를 요구하므로 이미지 안 파일을 임시
    폴더에 원래 구조대로 풀었다가 지운다. 원본 이미지는 건드리지 않는다.
    """
    def note(msg):
        if say:
            say(msg)

    summary = {"available": idbtree.import_error() is None,
               "import_error": idbtree.import_error(), "databases": [],
               "messages": 0, "conversations": 0, "user_messages": 0}
    if not summary["available"] or not vfiles:
        return [], summary

    tmp = tempfile.mkdtemp(prefix="parser_idb_")
    records = []
    try:
        dirs, written = idbtree.materialize(vfiles, tmp)
        note("IndexedDB 정식 파싱 — 파일 %d건 전개" % len(written))
        anchor = next((v for v in vfiles if v.path.lower().endswith(".log")), vfiles[0])
        for leveldb_dir, blob_dir in idbtree.db_pairs(dirs):
            db = idbtree.open_db(leveldb_dir, blob_dir)
            if db is None:
                summary["databases"].append({"dir": os.path.basename(leveldb_dir),
                                             "status": "open_failed"})
                continue
            try:
                h = idbtree.harvest(db)
            except Exception as exc:                       # noqa: BLE001
                summary["databases"].append(
                    {"dir": os.path.basename(leveldb_dir), "status": "harvest_failed",
                     "message": "%s: %s" % (type(exc).__name__, exc)})
                continue
            n_user = sum(1 for m in h["messages"]
                         if m["origin"] in ("user_typed", "user_upload"))
            summary["databases"].append(
                {"dir": os.path.basename(leveldb_dir), "status": "ok",
                 "blob_dir": bool(blob_dir), **h["stats"],
                 "messages": len(h["messages"]), "user_messages": n_user,
                 "conversations": len(h["conversations"]),
                 "opened": len(h["opened"])})
            summary["messages"] += len(h["messages"])
            summary["user_messages"] += n_user
            summary["conversations"] += len(h["conversations"])
            note("  %s — 메시지 %d건(사용자 %d) · 대화 %d건"
                 % (os.path.basename(leveldb_dir), len(h["messages"]), n_user,
                    len(h["conversations"])))
            records.extend(_message_records(h, anchor, image, rb, max_excerpt))
            records.extend(_branch_records(h, anchor, image, rb, max_excerpt))
            records.extend(_conversation_records(h, anchor, image, rb, max_excerpt))
            records.extend(_opened_records(h, anchor, image, rb))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return records, summary


def recovered_texts(records):
    """정식 파싱으로 이미 복원한 본문 — 바이트 스캔이 같은 말을 또 싣지 않게."""
    out = set()
    for r in records:
        t = (r.get("details") or {}).get("text")
        if t:
            out.add(" ".join(t.split()))
    return out
