"""~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl 파서 (MVP 1차 대상).

분석표 근거:
  E03-01 새 대화 생성 : rollout-<시각>-<스레드ID>.jsonl 최초 생성, 대화 전문 평문 JSON
  E03-03 대화 수정    : 파일명이 <원본대화ID>_<분기ID> 형태인 새 JSONL + 원본 미삭제
  E04-01 프롬프트 전송 : rollout JSONL 안의 user 메시지

필드 매핑 방침:
  라인마다 envelope({timestamp, ordinal, type, payload}) / 평면 형태를 모두 허용하고,
  관찰된 구조를 schema_observation 으로 보고하며, 매핑되지 않은 라인은 버리지 않는다.

실제 표본 반영 (WHS4_snap S1~S5 폴더 표본, 패키지 26.825.4187.0, 2026-09-18 확인):
  - 모든 라인이 {timestamp(Z), ordinal, type, payload}.
  - role=user 메시지는 payload.internal_chat_message_metadata_passthrough.content_item_kinds
    로 구분된다: user.text = 사용자 입력 / plugins.recommendations,
    environments.environment_context = 앱 자동 주입 문맥.
  - ChatGPT 채팅에서 작업 모드로 넘어온 요청은 '## Referenced ChatGPT conversation' 블록 +
    '## My request:' (3인칭 요청문) 형태.
  - event_msg/item_completed(UserMessage) 가 같은 본문으로 뒤따른다 (교차 확인용).
  - session_meta.timestamp(Z) 와 파일명 시각의 차이가 +9h (VM 타임존 Asia/Seoul) — 파일명은 로컬시각으로 보임.
"""

import json
import re
from datetime import datetime

from .. import events, model
from ..util import excerpt, mask_text, parse_any_time
from ..locate import parse_rollout_filename

# 시각 후보 키 (envelope -> payload 순으로 탐색)
TIME_KEYS = ("timestamp", "ts", "created_at", "time", "created", "at")
ROLE_KEYS = ("role",)
TEXT_ELEMENT_TYPES = ("input_text", "output_text", "text", "summary_text",
                      "reasoning_text", "refusal")

USER_ROLES = {"user"}
ASSISTANT_ROLES = {"assistant"}
SYSTEM_ROLES = {"system", "developer", "tool"}

# 실제 표본에서 관찰된 "type/payload.type" 조합. 이 밖의 라인은 unmapped 로 집계·원문 보존.
KNOWN_LINE_TYPES = {
    "session_meta", "world_state", "turn_context",
    "response_item/message", "response_item/reasoning",
    "response_item/custom_tool_call", "response_item/custom_tool_call_output",
    "event_msg/task_started", "event_msg/task_complete", "event_msg/token_count",
    "event_msg/thread_settings_applied", "event_msg/item_completed",
    "token_usage_record",   # 앱 0.154.0-alpha 표본(IMG_MRK_VER.E01)에서 추가 관찰 — 토큰 사용량 통계
}
# 행위 판단에 쓰지 않는 상태·통계 라인, response_item 과 본문이 중복되는 item_completed 항목.
# 개별 레코드 대신 파일 레코드의 line_type_counts 로만 남긴다 (원문은 sha256 + 라인으로 재확인).
SUMMARY_LINE_TYPES = {
    "world_state", "turn_context", "response_item/reasoning",
    "event_msg/task_started", "event_msg/task_complete", "event_msg/token_count",
    "event_msg/thread_settings_applied",
    "item_completed/UserMessage", "item_completed/AgentMessage", "item_completed/Reasoning",
    "token_usage_record",
}
_IMAGE_GEN_RE = re.compile(r"imagegen|image_gen|generate[ _]image", re.I)
HANDOFF_PREFIX = "## Referenced ChatGPT conversation"
HANDOFF_REQUEST_MARK = "## My request:"


class SchemaObservation:
    """실제 표본과 대조하기 위한 관찰 결과(추측 방지용)."""

    def __init__(self, path):
        self.path = path
        self.line_count = 0
        self.json_error_lines = 0
        self.envelope_lines = 0
        self.flat_lines = 0
        self.top_level_keys = {}
        self.payload_types = {}
        self.roles = {}
        self.content_shapes = {}
        self.time_key_used = {}
        self.unmapped_lines = 0

    def bump(self, d, key):
        d[key] = d.get(key, 0) + 1

    def to_dict(self):
        return {
            "path": self.path,
            "line_count": self.line_count,
            "json_error_lines": self.json_error_lines,
            "envelope_lines": self.envelope_lines,
            "flat_lines": self.flat_lines,
            "top_level_keys": dict(sorted(self.top_level_keys.items(),
                                          key=lambda kv: -kv[1])),
            "payload_types": dict(sorted(self.payload_types.items(),
                                         key=lambda kv: -kv[1])),
            "roles": self.roles,
            "content_shapes": self.content_shapes,
            "timestamp_key_used": self.time_key_used,
            "unmapped_lines": self.unmapped_lines,
        }


def _first_time(obj, obs=None):
    for k in TIME_KEYS:
        if isinstance(obj, dict) and k in obj:
            iso, fmt, note = parse_any_time(obj[k])
            if obs is not None:
                obs.bump(obs.time_key_used, k)
            return obj[k], iso, fmt, note
    return None, None, None, "시각 키를 찾지 못함"


def _extract_text(content, obs=None):
    """content 필드에서 텍스트를 추출. 반환 (text, shape_desc, attachments)"""
    attachments = []
    if content is None:
        return None, "none", attachments
    if isinstance(content, str):
        return content, "str", attachments
    if isinstance(content, dict):
        content = [content]
        shape = "dict"
    else:
        shape = "list" if isinstance(content, list) else type(content).__name__
    if not isinstance(content, list):
        return None, shape, attachments
    parts = []
    for el in content:
        if isinstance(el, str):
            parts.append(el)
            continue
        if not isinstance(el, dict):
            continue
        etype = el.get("type")
        if etype in TEXT_ELEMENT_TYPES or "text" in el:
            t = el.get("text")
            if isinstance(t, str):
                parts.append(t)
                continue
        # 첨부(이미지/파일) 후보 — 확인된 구조에 한해 메타만 기록
        meta = {k: v for k, v in el.items()
                if k in ("type", "name", "filename", "file_id", "mime_type",
                         "media_type", "size", "detail")}
        if meta:
            attachments.append(meta)
    return ("\n".join(parts) if parts else None), shape, attachments


def _line_type(obj):
    """('type/payload.type', item_completed 이면 'item_completed/<item.type>' 아니면 None)"""
    payload = obj.get("payload")
    sub = payload.get("type") if isinstance(payload, dict) else None
    line_type = "%s/%s" % (obj.get("type"), sub) if sub else str(obj.get("type"))
    item = payload.get("item") if isinstance(payload, dict) else None
    item_detail = ("item_completed/%s" % item.get("type")
                   if sub == "item_completed" and isinstance(item, dict) else None)
    return line_type, item_detail


def _content_item_kinds(item):
    meta = item.get("internal_chat_message_metadata_passthrough")
    kinds = meta.get("content_item_kinds") if isinstance(meta, dict) else None
    return kinds if isinstance(kinds, list) else None


def _classify_user_message(text, kinds):
    """role=user 메시지 분류.

    injected_context : content_item_kinds 에 user.text 없음 (앱 자동 주입 문맥)
    chatgpt_handoff  : 본문이 '## Referenced ChatGPT conversation' 으로 시작 (채팅→작업 모드 인계)
    user_text        : content_item_kinds 에 user.text
    user_unverified  : content_item_kinds 없음 (미관찰 스키마)
    """
    if kinds and "user.text" not in kinds:
        return "injected_context"
    if text and text.lstrip().startswith(HANDOFF_PREFIX):
        return "chatgpt_handoff"
    if kinds:
        return "user_text"
    return "user_unverified"


def _parse_handoff(text):
    """인계 요청 본문 -> 참조 대화 ID/제목, 캐시된 이전 사용자 발화, 요청문."""
    out = {"referenced_conversation_id": None, "referenced_title": None,
           "prior_user_texts": None, "request_text": None, "parse_note": None}
    head, _, req = text.partition(HANDOFF_REQUEST_MARK)
    out["request_text"] = req.strip() or None
    i = head.find("{")
    if i < 0:
        out["parse_note"] = "참조 JSON 블록 없음"
        return out
    try:
        ref, _ = json.JSONDecoder().raw_decode(head[i:])
    except json.JSONDecodeError as exc:
        out["parse_note"] = "참조 JSON 파싱 실패: %s" % exc
        return out
    if not isinstance(ref, dict):
        out["parse_note"] = "참조 JSON 이 객체가 아님"
        return out
    out["referenced_conversation_id"] = ref.get("conversationId")
    out["referenced_title"] = ref.get("title")
    conv = (ref.get("priorConversation") or {}).get("conversation")
    if isinstance(conv, list):
        out["prior_user_texts"] = [
            c["text"] for m in conv if isinstance(m, dict) and m.get("role") == "user"
            for c in (m.get("content") or [])
            if isinstance(c, dict) and isinstance(c.get("text"), str)]
    return out


def _user_message_events(lines):
    """item_completed(UserMessage) 이벤트를 본문 -> [{line, client_id, completed_at_ms}] 로 색인."""
    idx = {}
    for lineno, line in enumerate(lines, start=1):
        if "UserMessage" not in line:
            continue
        try:
            payload = json.loads(line).get("payload")
        except (json.JSONDecodeError, AttributeError):
            continue
        item = payload.get("item") if isinstance(payload, dict) else None
        if not isinstance(item, dict) or item.get("type") != "UserMessage":
            continue
        text, _, _ = _extract_text(item.get("content"))
        idx.setdefault(text, []).append({
            "line": lineno, "client_id": item.get("client_id"),
            "completed_at_ms": payload.get("completed_at_ms")})
    return idx


def _mask_any(v):
    if isinstance(v, str):
        return mask_text(v)
    if isinstance(v, list):
        return [mask_text(x) for x in v]
    return v


def _user_action_for(uclass, kinds, matches, content_text, details, max_excerpt):
    """role=user 메시지 -> (event_id, user_action)"""
    if uclass == "user_text":
        return "E04-01", model.user_action(
            action="프롬프트 전송",
            confidence=model.CONF_CONFIRMED,
            rationale=("rollout JSONL role=user 메시지, content_item_kinds=user.text "
                       "(분석표 E04-01)" +
                       (" + 동일 본문 item_completed(UserMessage) 이벤트 %d건" % len(matches)
                        if matches else "")))
    if uclass == "chatgpt_handoff":
        handoff = _parse_handoff(content_text)
        details["handoff"] = {k: _mask_any(v) for k, v in handoff.items()}
        return "E04-01", model.user_action(
            action="ChatGPT 대화 참조 작업 요청(채팅→작업 모드 인계)",
            confidence=model.CONF_INFERRED,
            rationale=("role=user(user.text) 이나 본문이 '%s' 블록 — '%s' 요청문이 3인칭 "
                       "서술이라 사용자가 직접 입력한 문장으로 단정하지 않음. 캐시된 이전 사용자 "
                       "발화는 details.handoff 에 보존(시각 미상)"
                       % (HANDOFF_PREFIX, HANDOFF_REQUEST_MARK)),
            observed=excerpt(mask_text(handoff["request_text"]), max_excerpt))
    if uclass == "injected_context":
        return "NA-00", model.user_action(
            rationale=("role=user 이나 content_item_kinds=%s — 앱이 자동 주입한 문맥으로 "
                       "사용자 입력 아님" % ",".join(map(str, kinds))),
            observed=excerpt(mask_text(content_text), 200))
    return "E04-01", model.user_action(
        action="프롬프트 전송",
        confidence=model.CONF_INFERRED,
        rationale=("rollout JSONL role=user 메시지 (분석표 E04-01). content_item_kinds 가 "
                   "없어 자동 주입 문맥과 구분하지 못함"))


def parse(vfile, image_desc, rb, max_excerpt=500, include_assistant=True):
    """rollout JSONL 1개 -> (records, schema_observation)"""
    records = []
    obs = SchemaObservation(vfile.path)
    fname = vfile.path.rsplit("/", 1)[-1]
    fmeta = parse_rollout_filename(fname) or {}

    try:
        raw = vfile.read()
    except Exception as exc:  # noqa: BLE001
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="파일을 읽지 못해 시각 확인 불가"),
            model.user_action(observed="rollout 파일 읽기 실패"),
            model.evidence(image_desc, vfile, locator="file"),
            status="error",
            errors=[{"code": "READ_FAILED", "message": str(exc)}]))
        return records, obs

    text = raw.decode("utf-8", "replace")
    lines = text.split("\n")
    user_events = _user_message_events(lines)
    session_meta = None
    models_seen = []
    last_turn_model = None
    user_class_counts = {}
    msg_seq = 0

    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        obs.line_count += 1
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            obs.json_error_lines += 1
            records.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                model.timestamp(null_reason="JSON 파싱 실패로 시각 확인 불가"),
                model.user_action(observed=excerpt(mask_text(line), max_excerpt)),
                model.evidence(image_desc, vfile, locator="line=%d" % lineno,
                               excerpt=excerpt(mask_text(line), max_excerpt)),
                status="error",
                errors=[{"code": "JSON_DECODE_ERROR", "message": str(exc)}]))
            continue
        if not isinstance(obj, dict):
            obs.unmapped_lines += 1
            continue

        for k in obj:
            obs.bump(obs.top_level_keys, k)

        payload = obj.get("payload")
        if isinstance(payload, dict):
            obs.envelope_lines += 1
            item = payload
            item_type = obj.get("type") or payload.get("type")
        else:
            obs.flat_lines += 1
            item = obj
            item_type = obj.get("type")
        line_type, item_detail = _line_type(obj)
        obs.bump(obs.payload_types, item_detail or line_type)
        ev_extra = {"ordinal": obj["ordinal"]} if "ordinal" in obj else None

        raw_ts, iso, fmt, note = _first_time(obj, obs)
        if iso is None and isinstance(payload, dict):
            raw_ts2, iso2, fmt2, note2 = _first_time(payload, obs)
            if iso2 is not None or raw_ts is None:
                raw_ts, iso, fmt, note = raw_ts2, iso2, fmt2, note2

        model_name = _find_model(item)
        if model_name and model_name not in models_seen:
            models_seen.append(model_name)
        # turn_context 의 model 이 앞 turn 과 다르면 그 사이에 모델을 바꾼 것 (E09-01). 2026-09-23 표본: "5.5로 모델 변경 후" 프롬프트 직전 turn 에서 확인
        if item_type == "turn_context" and model_name:
            if last_turn_model is not None and model_name != last_turn_model:
                records.append(model.Record(
                    rb.next_id(), "E09-01", events.name("E09-01"),
                    model.timestamp(utc=iso, original=raw_ts, fmt=fmt, meaning="모델이 바뀐 turn_context 라인의 기록 시각",
                                    source=model.TS_SOURCE_CONTENT, null_reason=note if iso is None else None),
                    model.user_action(action="모델 변경(%s → %s)" % (last_turn_model, model_name), confidence=model.CONF_CONFIRMED,
                                      rationale="rollout turn_context.model 이 직전 turn 과 다름 — 이 turn 부터 다른 모델로 요청됨 (에이전트 모드)"),
                    model.evidence(image_desc, vfile, locator="line=%d" % lineno, extra=ev_extra), status="ok",
                    details={"artifact": "rollout_jsonl", "thread_id": fmeta.get("thread_id"), "item_type": "turn_context",
                             "model": model_name, "previous_model": last_turn_model, "key": "%s -> %s" % (last_turn_model, model_name)}))
            last_turn_model = model_name

        # --- 세션 메타 라인 ------------------------------------------
        if item_type in ("session_meta", "session", "meta") or (
                session_meta is None and item_type != "turn_context" and
                any(k in item for k in ("instructions", "cwd", "originator", "cli_version"))
                and "role" not in item):
            session_meta = {k: item.get(k) for k in
                            ("id", "session_id", "cwd", "originator", "cli_version",
                             "timestamp", "instructions", "git", "source",
                             "thread_source", "model_provider")
                            if k in item}
            if isinstance(session_meta.get("instructions"), str):
                session_meta["instructions"] = excerpt(
                    session_meta["instructions"], 200)
            continue

        if line_type in SUMMARY_LINE_TYPES or item_detail in SUMMARY_LINE_TYPES:
            continue

        role = None
        for k in ROLE_KEYS:
            if isinstance(item.get(k), str):
                role = item[k]
                break
        if role:
            obs.bump(obs.roles, role)

        content_text, shape, attachments = _extract_text(item.get("content"), obs)
        obs.bump(obs.content_shapes, shape)
        if content_text is None and isinstance(item.get("text"), str):
            content_text = item["text"]

        # 메시지가 아닌 라인 (도구 호출, 명령 실행, 미관찰 타입 등)
        if role is None and content_text is None:
            known = line_type in KNOWN_LINE_TYPES
            if not known:
                obs.unmapped_lines += 1
            # 에이전트가 이미지 생성 도구를 찾거나 부른 도구 호출 = 사용자가 이미지 생성을 요청한 흔적 (E06-01).
            # 2026-09-23 표본: imagegen/SKILL.md 읽기 → ALL_TOOLS 에서 /image_gen|generate image/ 검색 (정답 68초 뒤)
            if line_type.endswith("custom_tool_call") and _IMAGE_GEN_RE.search(json.dumps(item, ensure_ascii=False)):
                records.append(model.Record(
                    rb.next_id(), "E06-01", events.name("E06-01"),
                    model.timestamp(utc=iso, original=raw_ts, fmt=fmt, meaning="이미지 생성 도구 호출 라인의 기록 시각",
                                    source=model.TS_SOURCE_CONTENT, null_reason=note if iso is None else None),
                    model.user_action(action="이미지 생성 시도(도구 호출)", confidence=model.CONF_CONFIRMED,
                                      rationale="rollout custom_tool_call 입력에 이미지 생성 도구(imagegen/image_gen) 탐색·호출 — 직전 user 프롬프트의 생성 요청을 처리한 흔적. 생성 성공 여부는 별개"),
                    model.evidence(image_desc, vfile, locator="line=%d" % lineno,
                                   excerpt=excerpt(mask_text(json.dumps(obj, ensure_ascii=False)), max_excerpt), extra=ev_extra),
                    status="ok", details={"artifact": "rollout_jsonl", "item_type": line_type, "thread_id": fmeta.get("thread_id"),
                                          "key": "imagegen 도구 호출", "model": model_name}))
                continue
            if model_name or item_type:
                records.append(_nonmessage_record(
                    rb, vfile, image_desc, lineno, obj, item_detail or line_type,
                    model_name, raw_ts, iso, fmt, note, fmeta, max_excerpt,
                    known, ev_extra))
            continue

        msg_seq += 1
        kinds = _content_item_kinds(item)
        details = {
            "artifact": "rollout_jsonl",
            "thread_id": fmeta.get("thread_id"),
            "branch_id": fmeta.get("branch_id"),
            "is_branch_file": fmeta.get("is_branch"),
            "message_index_in_file": msg_seq,
            "role": role,
            "item_type": line_type,
            "content_item_kinds": kinds,
            "message_id": item.get("id"),
            "text": None,
            "text_length": len(content_text) if content_text else 0,
            "attachments_observed": attachments or None,
            "model": model_name or _find_model(obj),
        }

        if role in USER_ROLES:
            uclass = _classify_user_message(content_text, kinds)
            user_class_counts[uclass] = user_class_counts.get(uclass, 0) + 1
            matches = user_events.get(content_text) or []
            details["user_message_class"] = uclass
            details["corroborating_user_message_events"] = matches or None
            event_id, action = _user_action_for(uclass, kinds, matches, content_text,
                                                details, max_excerpt)
        elif role in ASSISTANT_ROLES:
            if not include_assistant:
                continue
            event_id = "NA-00"
            action = model.user_action(
                rationale="assistant 응답 기록 — 사용자 행위가 아니므로 미확정",
                observed=excerpt(mask_text(content_text), max_excerpt))
        else:
            event_id = "NA-00"
            action = model.user_action(
                rationale="role=%s 메시지 — 사용자 행위 특정 불가" % role,
                observed=excerpt(mask_text(content_text), 200))

        # 자동 주입 문맥·developer 지시문은 길고 행위와 무관 — 발췌만 두고 전문은 싣지 않음
        if content_text and role in (USER_ROLES | ASSISTANT_ROLES) and \
                details.get("user_message_class") != "injected_context":
            details["text"] = mask_text(content_text)

        ts = model.timestamp(
            utc=iso, original=raw_ts, fmt=fmt,
            meaning="rollout JSONL 라인에 기록된 메시지 시각",
            source=model.TS_SOURCE_CONTENT,
            null_reason=note if iso is None else None)
        records.append(model.Record(
            rb.next_id(), event_id, events.name(event_id), ts, action,
            model.evidence(image_desc, vfile,
                           locator="line=%d" % lineno,
                           excerpt=excerpt(mask_text(content_text), max_excerpt),
                           extra=ev_extra),
            status="ok" if iso else "partial",
            notes=([] if iso else ["시각 미상 — 타임라인 별도 목록으로 분리"]),
            details=details))

    # --- 파일 단위(대화 생성/분기) 레코드 -----------------------------
    records.append(_session_record(rb, vfile, image_desc, fmeta, session_meta,
                                   msg_seq, obs, models_seen, user_class_counts))
    return records, obs


def _find_model(obj):
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("model"), str):
        return obj["model"]
    tc = obj.get("turn_context")
    if isinstance(tc, dict) and isinstance(tc.get("model"), str):
        return tc["model"]
    return None


def _nonmessage_record(rb, vfile, image_desc, lineno, obj, line_type, model_name,
                       raw_ts, iso, fmt, note, fmeta, max_excerpt, known, ev_extra):
    return model.Record(
        rb.next_id(), "NA-00", events.name("NA-00"),
        model.timestamp(utc=iso, original=raw_ts, fmt=fmt,
                        meaning="rollout JSONL 라인 기록 시각",
                        source=model.TS_SOURCE_CONTENT,
                        null_reason=note if iso is None else None),
        model.user_action(
            observed="메시지가 아닌 rollout 라인 (type=%s)" % line_type),
        model.evidence(image_desc, vfile, locator="line=%d" % lineno,
                       excerpt=excerpt(mask_text(json.dumps(obj, ensure_ascii=False)),
                                       max_excerpt),
                       extra=ev_extra),
        status="partial",
        notes=["실제 표본에서 관찰된 비메시지 라인(도구 호출·명령 실행 등) — 원문 발췌 보존"
               if known else "메시지 스키마에 매핑되지 않은 라인 — 원문 보존"],
        details={"artifact": "rollout_jsonl", "item_type": line_type,
                 "known_line_type": known,
                 "model": model_name, "thread_id": fmeta.get("thread_id")})


def _filename_offset_seconds(fmeta, meta_iso):
    """파일명 시각(타임존 없음) - session_meta UTC 시각. 로컬 타임존 추정 근거로만 보고."""
    naive = fmeta.get("filename_timestamp_iso_naive")
    if not (naive and meta_iso):
        return None
    try:
        a = datetime.fromisoformat(naive)
        b = datetime.fromisoformat(meta_iso.replace("Z", "+00:00")).replace(
            tzinfo=None, microsecond=0)  # 파일명은 초 단위
    except ValueError:
        return None
    return int((a - b).total_seconds())


def _session_record(rb, vfile, image_desc, fmeta, session_meta, msg_count, obs,
                    models_seen, user_class_counts):
    is_branch = bool(fmeta.get("is_branch"))
    event_id = "E03-03" if is_branch else "E03-01"
    if is_branch:
        rationale = ("rollout 파일명이 <원본대화ID>_<분기ID> 형태 — 분석표 E03-03 "
                     "(대화 수정 시 분기 JSONL 생성, 원본 미삭제)")
        action_name = "대화 수정(프롬프트 편집)"
    else:
        rationale = ("~/.codex/sessions 아래 rollout JSONL 파일 존재 — "
                     "분석표 E03-01 (새 대화 생성 시 파일 최초 생성)")
        action_name = "새 대화 생성"

    raw_ts = fmeta.get("filename_timestamp_raw")
    meta_raw = (session_meta or {}).get("timestamp")
    meta_iso, meta_fmt, _ = parse_any_time(meta_raw)
    if meta_iso:
        ts = model.timestamp(
            utc=meta_iso, original=meta_raw, fmt=meta_fmt,
            meaning="대화(스레드) 시작 시각 — session_meta.timestamp",
            source=model.TS_SOURCE_CONTENT)
    else:
        ts = model.timestamp(
            utc=None,
            original=raw_ts,
            fmt="rollout 파일명 내 로컬시각(YYYY-MM-DDTHH-MM-SS)",
            meaning="대화(스레드) 시작 시각 — 파일명에 기록된 값",
            source=model.TS_SOURCE_FILENAME,
            tz_note="파일명에 타임존 표기가 없어 UTC 로 단정하지 않음",
            null_reason=("파일명에 타임존 표기가 없어 UTC 로 확정 불가 "
                         "(original_value 로 원본 보존)") if raw_ts else
                        "파일명에서 시각을 해석하지 못함")
    obs_dict = obs.to_dict()
    return model.Record(
        rb.next_id(), event_id, events.name(event_id), ts,
        model.user_action(action=action_name,
                          confidence=model.CONF_INFERRED,
                          rationale=rationale),
        model.evidence(image_desc, vfile, locator="file",
                       artifact_sha256=vfile.sha256(),
                       excerpt=None),
        status="ok",
        notes=["파일 MFT 시각은 evidence.location 에 별도 보존 — 메시지 시각으로 대체하지 않음"],
        details={
            "artifact": "rollout_jsonl",
            "thread_id": fmeta.get("thread_id"),
            "branch_id": fmeta.get("branch_id"),
            "message_count": msg_count,
            "session_meta": session_meta,
            "filename_timestamp_raw": raw_ts,
            "filename_minus_meta_seconds": _filename_offset_seconds(fmeta, meta_iso),
            "models_observed": models_seen or None,
            "user_message_class_counts": user_class_counts or None,
            "line_type_counts": obs_dict["payload_types"],
            "schema_observation": obs_dict,
        })
