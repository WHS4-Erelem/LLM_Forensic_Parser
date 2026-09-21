"""~/.codex/.codex-global-state.json 파서.

분석표에서 확인된 키:
  prompt-history.chatgpt-global                       -> E04-01 프롬프트 전송(평문 배열)
    (실제 표본: "prompt-history": {"global": [...], "chatgpt-global": [...]} 중첩 dict.
     점 표기 단일 키 형태도 함께 허용)
  chatgpt-last-selected-model-v1 {slug, versionId}    -> E09-01 모델 변경
  client-thread-bindings-v1.local-chatgpt:<UUID>      -> E07-02/03 공유 링크·대화 공유
  sidebar-onboarding-checklist-state-by-account-id-v2 -> 이 PC 에서 로그인한 계정 UUID 열거
키 중첩 위치는 단정하지 않고 JSON 트리 전체에서 탐색한다.
"""

import json
import re

from .. import events, model
from ..util import excerpt, mask_text, parse_any_time
from .jsontree import find_key, find_key_prefix

K_PROMPT_HISTORY = "prompt-history.chatgpt-global"
K_PROMPT_HISTORY_PARENT = "prompt-history"
K_LAST_MODEL = "chatgpt-last-selected-model-v1"
K_THREAD_BINDINGS = "client-thread-bindings-v1"
K_ONBOARDING_BY_ACCOUNT = "sidebar-onboarding-checklist-state-by-account-id-v2"
# 실제 표본(S6a~c)에서 계정 UUID 를 dict 키로 쓰는 것이 관찰된 atom
ACCOUNT_KEYED_ATOMS = (K_ONBOARDING_BY_ACCOUNT,
                       "electron:onboarding-conversational-completed-by-account-id",
                       "chatgpt-sidebar-state-v1", "sidebar-custom-sections-v3")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def parse(vfile, image_desc, rb, max_excerpt=500):
    records = []
    try:
        raw = vfile.read()
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="파일 파싱 실패로 시각 확인 불가"),
            model.user_action(observed=".codex-global-state.json 파싱 실패"),
            model.evidence(image_desc, vfile, locator="file"),
            status="error",
            errors=[{"code": "JSON_PARSE_FAILED", "message": str(exc)}]))
        return records

    sha = vfile.sha256()

    # --- 프롬프트 이력 (E04-01) --------------------------------------
    histories = [(ptr, K_PROMPT_HISTORY, val) for ptr, val in find_key(data, K_PROMPT_HISTORY)
                 if val is not None]
    for ptr, val in find_key(data, K_PROMPT_HISTORY_PARENT):
        if isinstance(val, dict):
            histories += [(ptr + "/" + sub.replace("~", "~0").replace("/", "~1"),
                           "%s.%s" % (K_PROMPT_HISTORY_PARENT, sub), lst)
                          for sub, lst in val.items() if lst is not None]
    for ptr, key_name, val in histories:
        items = val if isinstance(val, list) else [val]
        for i, item in enumerate(items):
            text = item if isinstance(item, str) else (
                item.get("text") if isinstance(item, dict) else None)
            raw_ts = item.get("timestamp") if isinstance(item, dict) else None
            iso, fmt, note = parse_any_time(raw_ts)
            records.append(model.Record(
                rb.next_id(), "E04-01", events.name("E04-01"),
                model.timestamp(
                    utc=iso, original=raw_ts, fmt=fmt,
                    meaning="프롬프트 이력 항목에 기록된 시각",
                    source=model.TS_SOURCE_CONTENT,
                    null_reason=("prompt-history 항목에 시각 필드가 없음 — "
                                 "배열 순서만 확인 가능") if iso is None else None),
                model.user_action(
                    action="프롬프트 전송",
                    confidence=model.CONF_CONFIRMED,
                    rationale=("전역 상태 파일의 %s 배열 — 분석표 E04-01 "
                               "(입력 프롬프트 평문 누적)" % key_name)),
                model.evidence(image_desc, vfile,
                               locator="json_pointer=%s/%d" % (ptr, i),
                               excerpt=excerpt(mask_text(text), max_excerpt),
                               artifact_sha256=sha),
                status="ok" if iso else "partial",
                notes=([] if iso else
                       ["시각 미상 — 배열 인덱스 순서만 근거 (타임라인 별도 목록)"]),
                details={"artifact": "codex_global_state",
                         "key": key_name,
                         "array_index": i,
                         "prompt_text": mask_text(text) if text else None,
                         "raw_item_type": type(item).__name__}))

    # --- 마지막 선택 모델 (E09-01) -----------------------------------
    for ptr, val in find_key(data, K_LAST_MODEL):
        slug = val.get("slug") if isinstance(val, dict) else val
        version = val.get("versionId") if isinstance(val, dict) else None
        records.append(model.Record(
            rb.next_id(), "E09-01", events.name("E09-01"),
            model.timestamp(
                null_reason=("모델 선택 키 자체에 시각이 없음 — 파일 MFT 시각은 "
                             "evidence.location 참조(행위 시각으로 대체하지 않음)")),
            model.user_action(
                action="모델 변경(마지막 선택 모델 기록)",
                confidence=model.CONF_INFERRED,
                rationale=("전역 상태 파일의 %s 키 — 분석표 E09-01 "
                           "(선택 모델명 평문)" % K_LAST_MODEL)),
            model.evidence(image_desc, vfile, locator="json_pointer=%s" % ptr,
                           excerpt=excerpt(json.dumps(val, ensure_ascii=False),
                                           max_excerpt),
                           artifact_sha256=sha),
            status="ok",
            notes=["이 키는 '마지막 선택' 상태값 — 변경 시각·이전 모델은 알 수 없음"],
            details={"artifact": "codex_global_state", "key": K_LAST_MODEL,
                     "model_slug": slug, "version_id": version}))

    # --- 스레드 바인딩 (공유 후보 관찰 — E07-02/03 로 단정하지 않음) --------
    # 실제 표본 대조(WHS4_snap S1·S2): 공유 행위 이전 스냅샷에도 바인딩이 이미 7건 있었다.
    # 즉 바인딩 존재는 스레드 생성·동기화 흔적이지 공유 지문이 아니다 -> NA-00 관찰로 남긴다.
    for ptr, val in find_key(data, K_THREAD_BINDINGS):
        bindings = val if isinstance(val, dict) else {}
        for local_key, server_id in bindings.items():
            records.append(model.Record(
                rb.next_id(), "NA-00", events.name("NA-00"),
                model.timestamp(
                    null_reason="바인딩 항목에 시각 없음 (분석표: 서버측 처리)"),
                model.user_action(
                    action=model.ACTION_UNKNOWN,
                    confidence=model.CONF_UNKNOWN,
                    rationale=("client-thread-bindings 항목 — 로컬 스레드와 서버 스레드 매핑. "
                               "공유 전 스냅샷에도 존재해 공유(E07-02/03) 근거로 쓰지 않음. "
                               "스냅샷 간 신규 항목 증가는 공유 후보로 검토 가능"),
                    observed="로컬 스레드 %s -> 서버 스레드 %s"
                             % (local_key, server_id)),
                model.evidence(image_desc, vfile,
                               locator="json_pointer=%s/%s" % (ptr, local_key),
                               artifact_sha256=sha),
                status="ok",
                details={"artifact": "codex_global_state",
                         "key": K_THREAD_BINDINGS,
                         "candidate_event": "E07-02/E07-03 (미확정)",
                         "local_thread_key": local_key,
                         "server_thread_id": server_id}))

    # --- 계정 UUID 열거 (E01-01/03 보조) ------------------------------
    # 실제 표본(S6c): 이전 계정 A 는 onboarding 키에, 현재 계정 B 는 chatgpt-sidebar-state-v1 에만
    # 남아 있었다 -> 계정 UUID 를 키로 쓰는 atom 들을 모두 모아 출처와 함께 보고.
    sources = {}
    for key in ACCOUNT_KEYED_ATOMS:
        for ptr, val in find_key(data, key):
            for acc in (val.keys() if isinstance(val, dict) else []):
                if _UUID_RE.match(acc):
                    sources.setdefault(acc, []).append(ptr + "/" + acc)
    for ptr, val in find_key(data, "accountId"):
        if isinstance(val, str) and _UUID_RE.match(val):
            sources.setdefault(val, []).append(ptr)
    if sources:
        account_ids = list(sources)
        # 계정 UUID 가 2개 이상일 때만 E01-03(계정 전환) 흔적. 1개면 로그인 계정 열거일 뿐(NA-00).
        # (평서문 시나리오 E01 표본: 계정 전환 미수행인데 UUID 1개로 E01-03 이 붙던 오탐 수정)
        eid = "E01-03" if len(account_ids) >= 2 else "NA-00"
        records.append(model.Record(
            rb.next_id(), eid, events.name(eid),
            model.timestamp(null_reason="계정 목록 키에 시각 정보 없음"),
            model.user_action(
                action=model.ACTION_UNKNOWN,
                confidence=model.CONF_UNKNOWN,
                rationale=("이 PC 에서 로그인했던 계정 UUID 가 전역 상태에 잔존 — "
                           "분석표 E01-03. 각 계정의 로그인 시각은 이 키로 알 수 없음"
                           if eid == "E01-03" else
                           "전역 상태에 계정 UUID 1개 잔존 — 로그인 계정 식별용. 계정 전환 근거 아님"),
                observed="계정 UUID %d개: %s" % (len(account_ids),
                                                ", ".join(account_ids))),
            model.evidence(image_desc, vfile,
                           locator="json_pointer=%s" % sources[account_ids[0]][0],
                           artifact_sha256=sha),
            status="ok",
            details={"artifact": "codex_global_state",
                     "keys": list(ACCOUNT_KEYED_ATOMS) + ["accountId"],
                     "account_ids": account_ids,
                     "account_id_sources": sources,
                     "candidate_event": None if eid == "E01-03" else "E01-01 (로그인 계정 식별)"}))

    if not records:
        records.append(model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(null_reason="추출 대상 키 미발견"),
            model.user_action(
                observed="전역 상태 파일은 존재하나 분석표의 대상 키를 찾지 못함"),
            model.evidence(image_desc, vfile, locator="file",
                           artifact_sha256=sha),
            status="partial",
            notes=["앱 버전에 따라 키 이름이 다를 수 있음 — 실제 표본으로 확인 필요"],
            details={"artifact": "codex_global_state",
                     "observed_top_level_keys": sorted(data.keys())[:80]
                     if isinstance(data, dict) else None}))
    return records
