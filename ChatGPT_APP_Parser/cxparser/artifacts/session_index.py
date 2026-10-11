"""~/.codex/session_index.jsonl 파서 (대화 목록).

새 대화(E03-01)마다 1행이 추가된다. 대화를 삭제(E03-02)해도 파일이 그대로라 삭제 근거로는 쓰지 못한다.
행 스키마는 확정되지 않았으므로 관용적으로 추출하고 원문을 보존한다.
"""

import json

from .. import events, model
from ..util import excerpt, mask_text, parse_any_time

ID_KEYS = ("id", "session_id", "thread_id", "conversation_id", "uuid")
TIME_KEYS = ("timestamp", "created_at", "updated_at", "ts", "time")
TITLE_KEYS = ("thread_name", "title", "preview", "summary", "name", "first_prompt", "description")
PATH_KEYS = ("path", "file", "rollout_path", "filename")


def _pick(obj, keys):
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return k, obj[k]
    return None, None


def parse(vfile, image_desc, rb, max_excerpt=500):
    records = []
    try:
        raw = vfile.read()
    except Exception as exc:
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="파일 읽기 실패"),
            model.user_action(observed="session_index.jsonl 읽기 실패"),
            model.evidence(image_desc, vfile, locator="file"),
            status="error", errors=[{"code": "READ_FAILED", "message": str(exc)}]))
        return records

    sha = vfile.sha256()
    for lineno, line in enumerate(raw.decode("utf-8", "replace").split("\n"), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            records.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                model.timestamp(null_reason="JSON 파싱 실패"),
                model.user_action(observed=excerpt(mask_text(line), max_excerpt)),
                model.evidence(image_desc, vfile, locator="line=%d" % lineno,
                               excerpt=excerpt(mask_text(line), max_excerpt),
                               artifact_sha256=sha),
                status="error",
                errors=[{"code": "JSON_DECODE_ERROR", "message": str(exc)}]))
            continue
        if not isinstance(obj, dict):
            continue

        id_key, thread_id = _pick(obj, ID_KEYS)
        ts_key, raw_ts = _pick(obj, TIME_KEYS)
        title_key, title = _pick(obj, TITLE_KEYS)
        path_key, rpath = _pick(obj, PATH_KEYS)
        iso, fmt, note = parse_any_time(raw_ts)

        records.append(model.Record(
            rb.next_id(), "E03-01", events.name("E03-01"),
            model.timestamp(
                utc=iso, original=raw_ts, fmt=fmt,
                meaning=("session_index 행의 최종 갱신 시각 (키: updated_at — 대화 생성 시각 아님)"
                         if ts_key == "updated_at" else
                         "session_index 행에 기록된 시각 (키: %s)" % ts_key),
                source=model.TS_SOURCE_CONTENT,
                null_reason=note if iso is None else None),
            model.user_action(
                action="새 대화 생성(대화 목록 등재)",
                confidence=model.CONF_INFERRED,
                rationale=("session_index.jsonl 에 대화 1행 등재 — 규칙 E03-01. "
                           "단, 이 행의 존재만으로 삭제 여부는 판단하지 않음"),
                observed=excerpt(mask_text(title), max_excerpt) if title else None),
            model.evidence(image_desc, vfile, locator="line=%d" % lineno,
                           excerpt=excerpt(mask_text(line), max_excerpt),
                           artifact_sha256=sha),
            status="ok" if iso else "partial",
            notes=([] if iso else ["시각 미상 — 타임라인 별도 목록으로 분리"]),
            details={"artifact": "session_index_jsonl",
                     "thread_id": thread_id, "id_key": id_key,
                     "title": mask_text(title) if title else None,
                     "title_key": title_key,
                     "rollout_path": rpath, "path_key": path_key,
                     "observed_keys": sorted(obj.keys())}))
    return records
