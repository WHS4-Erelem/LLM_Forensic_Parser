"""IndexedDB / Local Storage / Blob — 대화 본문과 입력 초안.

Claude Desktop 은 대화를 HTTP 캐시가 아니라 IndexedDB 에 넣는다. 값은 V8
직렬화라 JSON 파서로는 못 읽고, 바이트에서 직접 본문과 역할을 꺼내야 한다
(v8text 참조). LevelDB 정식 파서를 쓰지 않는 이유는 삭제 표시된 레코드와
압축 전 .log 의 잔존분까지 걸리기 때문이다.
"""

import re

from .. import events, model
from ..util import excerpt
from .misc import _BY_MARKER, _MARKER_RE
from .v8text import SKIP_FILES, TEXT_RUN, is_human_text, messages, views

# 입력 초안 — 사용자가 친 문장. 키 바로 뒤에 값이 온다.
# 뿌리 메시지의 부모 (팀 공통 양식)
ROOT_PARENT = "00000000-0000-4000-8000-000000000000"

DRAFT_ANCHORS = ("chorus-unified-composer", "store:chat-draft:")
DRAFT_WINDOW = 1024
DRAFT_CAP = 200

_SKIP_PREFIX = ("store:", "chorus-", "keyval", "http", "blob:", "data:")
_TEMP_CHAT = re.compile(r'"?is_temporary"?\s*[:=]\s*true', re.I)
_MODEL = re.compile(r'"?model"?\s*[:=]\s*"?(claude[-\w.]{3,40})', re.I)
_TITLE = re.compile(r'"?(?:name|title)"?\s*[:=]\s*"([^"]{2,120})"')


def _draft_texts(data):
    """
    초안 키 주변에서 사용자가 친 문장만 잘라낸다.

    초안은 2초 간격으로 스냅샷이 쌓여서 같은 문장이 한 글자씩 자라는 형태로
    수십 건 남는다. 그대로 실으면 한 문장이 표를 가득 채운다. 앞부분이 겹치는
    것끼리 묶어 가장 완성된 것만 남기고, 스냅샷 수를 함께 적는다.
    """
    found, seen = [], set()
    for anchor in DRAFT_ANCHORS:
        needle = anchor.encode("utf-16-le")
        pos = data.find(needle)
        while pos != -1 and len(seen) < DRAFT_CAP:
            chunk = data[pos: pos + DRAFT_WINDOW]
            for enc, text, shift in views(chunk):
                if enc == "utf-8":
                    continue                 # 초안 값은 UTF-16LE 로 들어간다
                for m in TEXT_RUN.finditer(text):
                    s = m.group(0).strip()
                    if len(s) < 6 or s in seen or s.startswith(_SKIP_PREFIX):
                        continue
                    if not is_human_text(s):
                        continue
                    seen.add(s)
                    found.append((s, pos + m.start() * 2 + shift, anchor))
            pos = data.find(needle, pos + 1)
    return _collapse(found)


def _collapse(found):
    """타이핑 스냅샷을 최종 문장 하나로 접는다. -> [(문장, 오프셋, 앵커, 스냅샷수)]"""
    # 긴 것부터 보면서, 이미 채택한 문장의 앞부분이면 흡수한다
    found.sort(key=lambda t: -len(t[0]))
    kept = []
    for s, off, anchor in found:
        for i, (ks, koff, kanchor, n) in enumerate(kept):
            if ks.startswith(s):
                kept[i] = (ks, koff, kanchor, n + 1)
                break
        else:
            kept.append((s, off, anchor, 1))
    kept.sort(key=lambda t: t[1])
    return kept


# 삭제된 파일의 클러스터는 다른 데이터가 덮어쓴다. 경로만 보고 내용을 읽으면
# 다른 프로그램이 남긴 로그나 문자열이 'Claude 대화'로 실릴 수 있다.
# Chromium 저장소라면 아래 중 하나는 반드시 남는다.
LEVELDB_MAGIC = bytes.fromhex("57fb808b247547db")
STORAGE_SIGNS = (b"claude.ai", b"_chrome", b"META:", b"VERSION", LEVELDB_MAGIC,
                 b"chorus-", b"store:", b"conversation")


def is_storage_data(data):
    """이 바이트가 실제로 Chromium 저장소 파일인가."""
    head = data[:2_000_000]
    tail = data[-65536:] if len(data) > 65536 else b""
    return any(sig in head or sig in tail for sig in STORAGE_SIGNS)


def parse(vfile, image, rb, max_excerpt=500):
    data = vfile.read()
    kind, _ = _kind_of(vfile.path)
    mtime = (vfile.si_times or {}).get("modified")
    out = []

    # 할당 해제된 엔트리는 내용이 그 파일의 것이라는 보장이 없다.
    # 저장소 서명이 없으면 클러스터가 재사용된 것으로 보고 본문을 읽지 않는다.
    if not vfile.allocated and not is_storage_data(data):
        return [model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=mtime, source=model.TS_SOURCE_MFT,
                            null_reason=None if mtime else "파일 시각 없음"),
            model.user_action(observed="삭제된 %s 엔트리 — 클러스터가 다른 데이터로 "
                                       "덮여 있어 내용을 이 아티팩트의 것으로 "
                                       "볼 수 없음" % kind),
            model.evidence(image, vfile, locator="deleted_entry_content_reused"),
            notes=["deleted_entry_cluster_reused"],
            details={"artifact": kind, "item_type": "deleted_entry_unreadable"})]

    # ── 1) 대화 본문 ───────────────────────────────────────────────
    # 앱 번역 번들에는 대화가 없고 사람 문장만 수천 건 나온다. 건너뛴다.
    low = vfile.path.replace(chr(92), '/').lower()
    skip_bodies = any(f in low for f in SKIP_FILES)
    for msg in ([] if skip_bodies else messages(data)):
        ts = model.timestamp(null_reason="V8 레코드에 메시지 시각이 남지 않음")
        user = msg["role"] == "user"
        known = msg["role_known"]
        # 사용자 발화만 타임라인에 올린다. 모델 응답과 역할 미상 본문은
        # 대화 복원 파일에만 싣는다 — 본문은 버리지 않되 사용자 행위로는
        # 주장하지 않는다.
        if user:
            eid, act = _event_of(msg["text"])
            conf = model.CONF_CONFIRMED if msg["role_near"] else model.CONF_INFERRED
            observed = None
        else:
            eid, act = "NA-00", model.ACTION_UNKNOWN
            conf = model.CONF_UNKNOWN
            observed = ("모델 응답 본문" if known
                        else "대화 저장소의 본문 — 역할 표식 없음")
        rationale = (
            "저장소 값에 역할 표식(%s)과 함께 본문이 남음 — 표식 거리 %sB"
            % (msg["role"], msg["role_distance"]) if known else
            "대화 저장소에 본문이 남았으나 역할 표식이 없어 누가 한 말인지 미확인")
        out.append(model.Record(
            rb.next_id(), eid, events.name(eid), ts,
            model.user_action(act, conf, rationale=rationale, observed=observed),
            model.evidence(image, vfile,
                           locator="offset=%d(%s) role_distance=%s"
                                   % (msg["offset"], msg["encoding"],
                                      msg["role_distance"]),
                           excerpt=excerpt(msg["text"], max_excerpt)),
            details={"artifact": kind, "text": msg["text"], "role": msg["role"],
                     "conversation_uuid": msg["conversation_uuid"],
                     "role_distance": msg["role_distance"],
                     "role_known": known,
                     "item_type": "message"}))

    # ── 2) 입력 초안 (전송 미확인) ─────────────────────────────────
    for text, off, anchor, snaps in _draft_texts(data):
        ts = model.timestamp(utc=mtime, original=mtime, meaning="파일 수정 시각(대체)",
                             source=model.TS_SOURCE_MFT,
                             tz_note="초안 자체에 시각이 없어 파일 수정 시각으로 대체",
                             null_reason=None if mtime else "파일 시각 없음")
        out.append(model.Record(
            rb.next_id(), "E04-01", events.name("E04-01"), ts,
            model.user_action("사용자 프롬프트 입력/전송", model.CONF_INFERRED,
                              rationale="입력 초안 — 사용자가 입력창에 친 문장이다. "
                                        "전송 여부는 확인되지 않았다 (타이핑 스냅샷 %d건)"
                                        % snaps),
            model.evidence(image, vfile, locator="offset=%d(chat-draft)" % off,
                           excerpt=excerpt(text, max_excerpt)),
            details={"artifact": kind, "text": text, "role": "user",
                     "item_type": "draft", "key": anchor, "snapshots": snaps,
                     # 초안끼리는 대화가 아니다. 부모를 이어 붙이면 주고받은
                     # 스레드처럼 보이므로 전부 뿌리로 둔다.
                     "parent_message_uuid": ROOT_PARENT,
                     "conversation_uuid": "draft:%s" % vfile.path.rsplit("/", 1)[-1]}))

    # ── 3) 부가 신호 ───────────────────────────────────────────────
    head = data[:4_000_000].decode("utf-8", "replace")
    if _TEMP_CHAT.search(head):
        out.append(model.Record(
            rb.next_id(), "E10-01", events.name("E10-01"),
            model.timestamp(utc=mtime, source=model.TS_SOURCE_MFT,
                            null_reason=None if mtime else "파일 시각 없음"),
            model.user_action("임시 채팅 사용", model.CONF_INFERRED,
                              rationale="is_temporary 플래그"),
            model.evidence(image, vfile, locator="is_temporary"),
            details={"artifact": kind, "item_type": "temp_chat"}))
    mm = _MODEL.search(head)
    if mm:
        out.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=mtime, source=model.TS_SOURCE_MFT,
                            null_reason=None if mtime else "파일 시각 없음"),
            model.user_action(observed="모델 식별자 %s" % mm.group(1)),
            model.evidence(image, vfile, locator="model"),
            details={"artifact": kind, "model": mm.group(1), "item_type": "model"}))
    return out


def _kind_of(path):
    from ..locate import classify
    return classify(path)


# 본문에 첨부·생성 요청이 드러나면 그에 맞는 행위로 올린다.
_ATTACH = re.compile(r"<uploaded_files>|첨부|업로드", re.I)
_IMAGE_REQ = re.compile(r"그려\s*줘|이미지.{0,6}(만들|생성)|그림.{0,6}(그려|만들)", re.I)
_DOC_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|hwpx?|txt|csv)\b", re.I)
_IMG_EXT = re.compile(r"\.(png|jpe?g|gif|webp|bmp|svg)\b", re.I)


def _event_of(text):
    """사용자 본문에서 행위를 가른다. 단서가 없으면 프롬프트 전송."""
    # 시나리오 마커가 있으면 그것이 가장 확실한 단서다.
    m = _MARKER_RE.search(text)
    if m:
        hit = _BY_MARKER.get(m.group(1))
        if hit:
            return hit
    if _IMG_EXT.search(text) or ("사진" in text and _ATTACH.search(text)):
        return "E05-01", "이미지 업로드"
    if _DOC_EXT.search(text) or ("파일" in text and _ATTACH.search(text)):
        return "E05-03", "문서 업로드"
    if _IMAGE_REQ.search(text):
        return "E06-01", "이미지 생성 요청"
    return "E04-01", "사용자 프롬프트 입력/전송"
