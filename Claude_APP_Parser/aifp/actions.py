"""
행위 판정 — 원시 레코드를 사용자 행위로 매핑한다.

규칙은 코드가 아니라 rules/claude_desktop.json 에 있다.
앱이 업데이트돼 키 이름이 바뀌면 규칙 파일만 고치면 되고 여기는 손대지 않는다.

세 가지를 지킨다.
  1. 판정마다 **증거 수준**을 붙인다 (직접 / 보조 / 확인 어려움)
  2. 규칙이 요구하는 아티팩트가 없으면 **"확인한 경로와 함께" 부정 결과를 남긴다**
     — "흔적 없음"과 "안 찾아봤음"은 다른 결론이다
  3. 기능 자체가 없는 행위는 **미검출이 아니라 「해당 없음」** 으로 출력한다
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .errors import ErrorCollector, RuleError
from .schema import EvidenceLevel, Event, Recovery
from .sources.base import Record
from .timeutil import TimeSource, confidence_for


class RuleSet:
    """규칙 파일 로더."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleError(f"규칙 파일을 읽지 못했다: {path} ({exc})") from exc
        except UnicodeDecodeError as exc:
            raise RuleError(f"규칙 파일이 UTF-8 이 아니다: {path} "
                            f"(위치 {exc.start}) — UTF-8 로 저장할 것") from exc
        try:
            self.data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuleError(f"규칙 파일 형식 오류: {exc}") from exc

        self.version: str = self.data.get("rule_version", "unknown")
        self.service_key: str = self.data.get("service_key", "default")
        self.target: dict[str, Any] = self.data.get("target", {})
        self.rules: list[dict] = self.data.get("rules", [])
        self.categories: dict[str, str] = self.data.get("categories", {})
        self.not_applicable: list[dict] = self.data.get("not_applicable", [])
        if not self.rules:
            raise RuleError("규칙이 하나도 없다")
        self._validate()

    # 규칙 파일은 손으로 고치는 파일이다. 오타 하나가 조용한 미검출로 이어지면
    # 조사관은 "흔적이 없다"는 틀린 결론을 받는다. 적재 시점에 잡는다.
    ALLOWED_COND = {"kind", "source", "key_has", "value_has", "value_eq",
                    "min_count", "max_count", "absent"}
    ALLOWED_RULE = {"id", "name", "category", "evidence_level", "summary",
                    "require", "per_record", "time_from", "explain",
                    "conflict_note", "distinct_uuids_min"}
    LEVELS = {"direct", "supporting", "inconclusive"}

    def _validate(self) -> None:
        problems: list[str] = []
        seen: set[str] = set()
        sources = set(self.target.get("sources", []))
        sources |= set(self.target.get("sources_extended", []))

        for r in self.rules + self.not_applicable:
            rid = r.get("id")
            if not rid:
                problems.append(f"id 가 없는 항목: {r.get('name', '이름도 없음')}")
                continue
            if rid in seen:
                problems.append(f"id 중복: {rid}")
            seen.add(rid)
            if not r.get("name"):
                problems.append(f"{rid}: name 이 없다")

        from .sources import REGISTRY
        prefix = f"{self.service_key}."
        if not any(k.startswith(prefix) for k in REGISTRY):
            known = sorted({k.split(".")[0] for k in REGISTRY})
            problems.append(f"service_key '{self.service_key}' 에 맞는 리더가 "
                            f"없다 — 등록된 것: {known}")

        app_root = self.target.get("app_root")
        if app_root is not None and not isinstance(app_root, (str, list, dict)):
            problems.append("target.app_root 는 경로 문자열이거나 "
                            "{relative, alternatives} 형태여야 한다")

        for r in self.rules:
            rid = r.get("id", "?")
            if r.get("category") and r["category"] not in self.categories:
                problems.append(f"{rid}: 모르는 category '{r['category']}'")
            if r.get("evidence_level") not in self.LEVELS:
                problems.append(f"{rid}: evidence_level 이 "
                                f"{sorted(self.LEVELS)} 중 하나가 아니다")
            unknown = set(r) - self.ALLOWED_RULE
            if unknown:
                problems.append(f"{rid}: 모르는 항목 {sorted(unknown)}")
            req = r.get("require")
            if not req:
                problems.append(f"{rid}: require 가 비었다 — 아무 근거 없이 판정한다")
                continue
            if all(c.get("absent") for c in req):
                # 없다는 조건만으로는 붙일 근거 레코드가 없어 영영 성립하지 않는다
                problems.append(f"{rid}: require 가 absent 조건뿐이다 — "
                                f"근거로 삼을 레코드가 없어 절대 성립하지 않는다")
            for cond in req:
                bad = set(cond) - self.ALLOWED_COND
                if bad:
                    problems.append(f"{rid}: require 에 모르는 조건 {sorted(bad)}")
                if not cond.get("kind"):
                    problems.append(f"{rid}: require 에 kind 가 없다")
                if "value_has" in cond and not isinstance(cond["value_has"], str):
                    problems.append(f"{rid}: value_has 는 값 안의 키 이름(문자열)이다")
                if "value_eq" in cond and not isinstance(cond["value_eq"], dict):
                    problems.append(f"{rid}: value_eq 는 "
                                    f"{{키: 값}} 형태여야 한다")
                src = cond.get("source")
                if src and sources and src not in sources:
                    problems.append(f"{rid}: source '{src}' 가 "
                                    f"target.sources 에 없다 — 영영 안 걸린다")

        if problems:
            raise RuleError("규칙 파일에 문제가 있다 — " + " / ".join(problems[:8])
                            + (f" 외 {len(problems) - 8}건" if len(problems) > 8 else ""))

    def category_name(self, key: str) -> str:
        return self.categories.get(key, key)


class ActionMapper:
    """규칙을 레코드 집합에 적용해 Event를 만든다."""

    def __init__(self, ruleset: RuleSet, errs: ErrorCollector) -> None:
        self.rules = ruleset
        self.errs = errs

    # ── 진입점 ──────────────────────────────────────────────────────────
    def map_all(self, records: list[Record], checked_paths: list[str]) -> tuple[list[Event], list[dict]]:
        by_kind: dict[str, list[Record]] = defaultdict(list)
        for r in records:
            by_kind[r.kind].append(r)

        events: list[Event] = []
        negatives: list[dict] = []

        for rule in self.rules.rules:
            with self.errs.guard("map", rule.get("id", "?")):
                fired = self._apply(rule, by_kind)
                if fired:
                    events.extend(fired)
                else:
                    negatives.append(self._negative(rule, by_kind, checked_paths))

        # 같은 행위를 다른 규칙이 이미 판정했으면 미검출로 적지 않는다.
        # 예를 들어 '로그인'은 설정 파일 규칙과 로그 규칙 둘 다 낼 수 있다.
        # 로그에서 로그인을 찾았는데 표에 "로그인: 미검출"이 함께 실리면
        # 보고서를 읽는 사람이 상반된 두 문장을 보게 된다.
        detected = {e.action_name for e in events}
        negatives = [n for n in negatives if n["action_name"] not in detected]
        # 같은 행위 이름을 여러 규칙이 나눠 보는 경우가 있다 — 미검출은 한 번만 적는다
        deduped: list[dict] = []
        seen_names: set[str] = set()
        for n in negatives:
            if n["action_name"] in seen_names:
                continue
            seen_names.add(n["action_name"])
            deduped.append(n)
        negatives = deduped

        # 기능 부재로 애초에 판정할 수 없는 행위
        for na in self.rules.not_applicable:
            negatives.append({
                "action_id": na["id"],
                "action_name": na["name"],
                "result": "not_applicable",      # 미검출이 아니다
                "reason": na["reason"],
            })

        return events, negatives

    # ── 규칙 1개 적용 ───────────────────────────────────────────────────
    def _apply(self, rule: dict, by_kind: dict[str, list[Record]]) -> list[Event]:
        matched: list[Record] = []

        for cond in rule.get("require", []):
            recs = self._match(cond, by_kind)
            if cond.get("absent"):
                # 없어야 성립하는 조건
                if recs:
                    return []
                continue
            if not recs:
                return []
            if len(recs) < int(cond.get("min_count", 1)):
                return []
            if "max_count" in cond and len(recs) > int(cond["max_count"]):
                return []
            matched.extend(recs)

        if not matched:
            return []

        # 고유 UUID 개수 조건 (계정 전환 판정용)
        if "distinct_uuids_min" in rule:
            uuids: set[str] = set()
            for r in matched:
                v = r.value
                if isinstance(v, dict):
                    for key in ("uuids", "org_uuid", "account_uuid"):
                        got = v.get(key)
                        if isinstance(got, list):
                            uuids.update(got)
                        elif isinstance(got, str):
                            uuids.add(got)
            if len(uuids) < int(rule["distinct_uuids_min"]):
                return []

        if rule.get("per_record"):
            return [self._make_event(rule, [r]) for r in matched]
        return [self._make_event(rule, matched)]

    def _match(self, cond: dict, by_kind: dict[str, list[Record]]) -> list[Record]:
        recs = list(by_kind.get(cond.get("kind", ""), []))
        if src := cond.get("source"):
            recs = [r for r in recs if r.source == src]
        if key_has := cond.get("key_has"):
            recs = [r for r in recs if r.key and key_has in r.key]
        if val_has := cond.get("value_has"):
            recs = [r for r in recs
                    if isinstance(r.value, dict) and r.value.get(val_has) not in (None, "", [])]
        if val_eq := cond.get("value_eq"):
            recs = [r for r in recs
                    if isinstance(r.value, dict)
                    and all(r.value.get(k) == v for k, v in val_eq.items())]
        return recs

    # ── Event 생성 ──────────────────────────────────────────────────────
    def _make_event(self, rule: dict, recs: list[Record]) -> Event:
        ev = Event(
            action_id=rule["id"],
            action_name=rule["name"],
            action_category=self.rules.category_name(rule.get("category", "")),
            summary=rule.get("summary", ""),
            evidence_level=rule.get("evidence_level", EvidenceLevel.SUPPORTING.value),
        )

        # 시각 — 규칙이 지정한 출처에서 가져온다
        ts_rec = self._pick_time_record(rule, recs)
        if ts_rec and ts_rec.ts_utc:
            ev.timestamp_utc = ts_rec.ts_utc
            ev.time_source = ts_rec.time_source or TimeSource.UNKNOWN.value
            ev.time_confidence = confidence_for(TimeSource(ev.time_source)).value
            if ev.time_source == TimeSource.MFT.value:
                ev.time_note = ("파일시스템 시각 — 앱 종료 시 일괄 flush로 수렴했을 수 있어 "
                                "행위 시각으로 단정하면 안 된다")
        else:
            ev.time_note = "시각 근거를 찾지 못했다 — 순서 판단에만 사용할 것"

        # 내용·식별자 채우기
        for r in recs:
            self._enrich(ev, r)
            if r.ref:
                ev.add_artifact(r.ref)

        if explain := rule.get("explain"):
            ev.add_note(explain)
        if conflict := rule.get("conflict_note"):
            ev.add_note(f"[상충] {conflict}")

        problems = ev.validate()
        for p in problems:
            self.errs.add("warning", "SCHEMA_VIOLATION", "map", rule["id"], p)
        return ev

    @staticmethod
    def _pick_time_record(rule: dict, recs: list[Record]) -> Record | None:
        want = rule.get("time_from", "self")
        timed = [r for r in recs if r.ts_utc]
        if not timed:
            return None
        if want in ("self", "context"):
            return timed[0]
        for r in timed:
            if r.kind == want:
                return r
        return timed[0]

    @staticmethod
    def _enrich(ev: Event, r: Record) -> None:
        v = r.value
        if not isinstance(v, dict):
            return
        ev.account_uuid = ev.account_uuid or v.get("account_uuid")
        ev.org_uuid = ev.org_uuid or v.get("org_uuid")
        ev.conversation_uuid = ev.conversation_uuid or v.get("conversation_uuid") or (
            v.get("uuid") if r.kind == "conversation" else None)
        ev.device_id = ev.device_id or v.get("device_id")
        ev.client_version = ev.client_version or v.get("version")

        if r.kind == "message":
            ev.content = v.get("text")
            ev.content_role = v.get("sender")
        elif r.kind == "draft_text":
            ev.content = v.get("text")
            ev.content_role = "human"
        elif r.kind == "conversation" and v.get("name"):
            ev.add_note(f"대화 제목: {v['name']}")
            if v.get("model"):
                ev.add_note(f"모델: {v['model']}")
        elif r.kind in ("usn_delete", "usn_rename", "usn_create", "usn_event"):
            ev.content = v.get("detail") or v.get("name")
        elif r.kind == "recycle_entry":
            ev.content = v.get("original_path")
        elif r.kind == "prefetch_run":
            ev.content = f"{v.get('prefetch')} — 마지막 실행 {v.get('last_run_utc')}"
        elif r.kind.startswith("log_"):
            # 로그에서 뽑은 사실은 그 줄 자체가 근거다 — 요약 대신 원문을 싣는다
            ev.content = v.get("line")
        elif r.kind == "account_profile":
            parts = [f"{k}={x}" for k, x in v.items()]
            ev.content = " · ".join(parts)

        if r.ref and r.ref.recovered:
            ev.recovery = Recovery.DELETED_RECOVERED.value

    # ── 부정 결과 ───────────────────────────────────────────────────────
    def _negative(self, rule: dict, by_kind: dict[str, list[Record]],
                  checked_paths: list[str]) -> dict:
        """
        판정하지 못한 이유를 남긴다.
        무엇을 찾았고 무엇이 없었는지 적어야 '흔적 없음'이 근거 있는 결론이 된다.
        """
        missing = []
        for cond in rule.get("require", []):
            if cond.get("absent"):
                continue
            got = len(self._match(cond, by_kind))
            need = int(cond.get("min_count", 1))
            if got < need:
                missing.append({
                    "kind": cond.get("kind"),
                    "source": cond.get("source"),
                    "needed": need,
                    "found": got,
                })
        return {
            "action_id": rule["id"],
            "action_name": rule["name"],
            "result": "not_detected",
            "missing": missing,
            "checked_paths": checked_paths[:20],
            "note": "규칙이 요구하는 아티팩트를 찾지 못했다. 행위가 없었다는 뜻이 아니라, "
                    "이 수집 범위에서는 확인되지 않았다는 뜻이다.",
        }


def correlate(events: list[Event], window_seconds: int = 5) -> list[Event]:
    """
    교차 검증 — 같은 행위를 가리키는 서로 독립적인 근거를 묶어 확신도를 올린다.

    저장소가 다르면 독립 채널로 본다.
    캐시와 IndexedDB 양쪽에서 같은 행위가 보이면 한쪽만 보일 때보다 훨씬 강한 근거다.
    """
    from .timeutil import from_iso

    buckets: dict[tuple[str, str | None], list[Event]] = defaultdict(list)
    for ev in events:
        buckets[(ev.action_id, ev.conversation_uuid)].append(ev)

    for group in buckets.values():
        if len(group) < 2:
            continue
        timed = [e for e in group if e.timestamp_utc]
        timed.sort(key=lambda e: e.timestamp_utc or "")
        for i, ev in enumerate(timed):
            near = [o for o in timed
                    if o is not ev and o.timestamp_utc and ev.timestamp_utc
                    and abs((from_iso(o.timestamp_utc) - from_iso(ev.timestamp_utc)).total_seconds())
                    <= window_seconds]
            extra = {c for o in near for c in o.channels} - ev.channels
            if extra:
                for o in near:
                    for a in o.artifacts:
                        if a.storage in extra:
                            ev.add_artifact(a)
                ev.add_note(f"교차 검증: 독립 채널 {len(ev.channels)}개에서 동일 행위 확인")
                ev.score_confidence()
    return events
