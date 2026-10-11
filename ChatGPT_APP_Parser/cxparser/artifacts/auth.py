"""~/.codex/auth.json 파서 — 토큰 값은 절대 출력하지 않는다.

근거:
  E01-01 로그인   : auth.json 최초 생성 (JWT id/access/refresh + 계정 UUID 평문)
  E01-02 로그아웃 : auth.json FILE_DELETE (명시적 로그아웃에서만 삭제)
  E01-03 계정전환 : auth.json 재생성 (새 account_id)
파일의 존재/부재만으로 로그인·로그아웃을 확정하지 않는다.
"""

import json

from .. import events, model
from ..util import parse_any_time, redact
from .jsontree import find_key


def parse(vfile, image_desc, rb, max_excerpt=500):
    records = []
    try:
        data = json.loads(vfile.read().decode("utf-8", "replace"))
    except Exception as exc:
        records.append(model.Record(
            rb.next_id(), "E01-01", events.name("E01-01"),
            model.timestamp(null_reason="auth.json 파싱 실패"),
            model.user_action(observed="auth.json 존재하나 파싱 실패"),
            model.evidence(image_desc, vfile, locator="file"),
            status="error", errors=[{"code": "JSON_PARSE_FAILED",
                                     "message": str(exc)}]))
        return records

    account_ids = [v for _p, v in find_key(data, "account_id") if isinstance(v, str)]
    last_refresh = None
    lr_ptr = None
    for ptr, v in find_key(data, "last_refresh"):
        last_refresh, lr_ptr = v, ptr
        break
    iso, fmt, note = parse_any_time(last_refresh)

    token_presence = {}
    for key in ("id_token", "access_token", "refresh_token", "OPENAI_API_KEY"):
        hits = find_key(data, key)
        if hits:
            v = hits[0][1]
            token_presence[key] = {
                "present": v is not None,
                "length": len(v) if isinstance(v, str) else None,
                "value": "[REDACTED — 토큰 값은 출력하지 않음]"
                         if isinstance(v, str) else None,
            }

    records.append(model.Record(
        rb.next_id(), "E01-01", events.name("E01-01"),
        model.timestamp(
            utc=iso, original=last_refresh, fmt=fmt,
            meaning="auth.json 의 last_refresh (토큰 갱신 시각, 로그인 시각과 다를 수 있음)",
            source=model.TS_SOURCE_CONTENT,
            null_reason=note if iso is None else None),
        model.user_action(
            action=model.ACTION_UNKNOWN,
            confidence=model.CONF_UNKNOWN,
            rationale=("auth.json 의 존재만으로 로그인 행위·시각을 확정하지 않음 "
                       "(앱 삭제 후에도 잔존, 재로그인 시 토큰만 갱신). "
                       "로그인 시각 확정에는 MFT 생성시각·$UsnJrnl 대조 필요"),
            observed="계정 UUID %s, 토큰 필드 %s"
                     % (account_ids or "미확인", sorted(token_presence) or "미확인")),
        model.evidence(image_desc, vfile,
                       locator="json_pointer=%s" % (lr_ptr or "/"),
                       artifact_sha256=vfile.sha256()),
        status="ok",
        notes=["인증 토큰·쿠키 값은 출력·로그에 포함하지 않음 (길이/존재만 기록)"],
        details={"artifact": "auth_json",
                 "account_ids": account_ids,
                 "token_fields": token_presence,
                 "redacted_document": redact(data)}))
    return records
