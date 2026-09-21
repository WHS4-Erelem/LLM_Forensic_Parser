"""
집계 — 판정 결과를 사람이 읽고 기계가 쓸 수 있는 형태로 모은다.

산출물 파일을 쓰는 일은 csvout.py 가 한다. 여기서는 세는 일만 한다.

  summary()       이벤트·수집·문제 통계
  statistics()    원시 레코드 통계 — 무엇을 얼마나 읽었는지
  identifiers()   계정·조직·대화·기기 식별자
  conversations() 복원된 대화와 메시지
  print_console() 실행 끝의 요약 출력
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import ErrorCollector
from .provenance import Manifest
from .schema import Event, ParseResult
from .sources.base import Record
from .timeutil import TimeConfidence, TimeSource, display, to_utc_iso

SOURCE_LABEL = {
    TimeSource.USNJRNL.value: "$UsnJrnl",
    TimeSource.APPLOG.value: "앱 로그",
    TimeSource.APIRESPONSE.value: "API 응답",
    TimeSource.CONFIG.value: "설정 파일",
    TimeSource.FILENAME.value: "파일명",
    TimeSource.MFT.value: "$MFT",
    TimeSource.UNKNOWN.value: "미상",
}
LEVEL_LABEL = {"direct": "직접 증거", "supporting": "보조 증거", "inconclusive": "확인 어려움"}
RECOVERY_LABEL = {"live": "잔존", "deleted_recovered": "삭제·복구",
                  "deleted_metadata_only": "메타데이터만"}

_SAFE = re.compile(r"[^0-9A-Za-z가-힣._-]+")




def _flatten(value: Any, limit: int = 400) -> str:
    """CSV 한 칸에 들어가도록 값을 납작하게."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        s = json.dumps(value, ensure_ascii=False)
    else:
        s = str(value)
    s = s.replace("\r", " ").replace("\n", " ")
    return s[:limit] + ("…" if len(s) > limit else "")






class Reporter:
    def __init__(self, result: ParseResult, manifest: Manifest, errs: ErrorCollector,
                 negatives: list[dict], tz: str = "UTC",
                 records: list[Record] | None = None,
                 started_utc: str | None = None,
                 integrity: dict[str, Any] | None = None,
                 unmask: bool = False) -> None:
        self.result = result
        self.manifest = manifest
        self.errs = errs
        self.negatives = negatives
        self.tz = tz
        self.records = records or []
        self.started_utc = started_utc
        self.integrity = integrity or {}
        self.finished_utc = to_utc_iso(datetime.now(timezone.utc))

    # ══ 집계 ═══════════════════════════════════════════════════════════
    def summary(self) -> dict[str, Any]:
        evs = self.result.events
        by_level = Counter(e.evidence_level for e in evs)
        by_action = Counter(e.action_name for e in evs)
        by_category = Counter(e.action_category for e in evs)
        by_time_src = Counter(e.time_source for e in evs)
        by_recovery = Counter(e.recovery for e in evs)
        timed = [e for e in evs if e.timestamp_utc]
        return {
            "events_total": len(evs),
            "events_with_time": len(timed),
            "time_range": {
                "first": min((e.timestamp_utc for e in timed), default=None),
                "last": max((e.timestamp_utc for e in timed), default=None),
            },
            "by_evidence_level": dict(by_level),
            "by_action": dict(by_action.most_common()),
            "by_category": dict(by_category.most_common()),
            "by_time_source": dict(by_time_src),
            "by_recovery": dict(by_recovery),
            "low_time_confidence": sum(
                1 for e in evs if e.time_confidence == TimeConfidence.LOW.value),
            "multi_channel_events": sum(1 for e in evs if len(e.channels) > 1),
            "not_detected": sum(1 for n in self.negatives if n["result"] == "not_detected"),
            "not_applicable": sum(1 for n in self.negatives if n["result"] == "not_applicable"),
            "records_total": len(self.records),
            "collected_files": self.manifest.counts(),
            "collected_bytes": self.manifest.total_bytes,
            "manifest_digest": self.manifest.digest(),
            "issues": self.errs.counts(),
        }

    def statistics(self) -> dict[str, Any]:
        """원시 레코드 수준 통계 — 무엇을 얼마나 읽었는지."""
        by_source = Counter(r.source for r in self.records)
        by_kind = Counter(r.kind for r in self.records)
        by_storage = Counter(r.ref.storage for r in self.records if r.ref)
        enc = Counter()
        marker_counts: dict[str, dict[str, int]] = defaultdict(dict)
        for r in self.records:
            if isinstance(r.value, dict):
                if e := r.value.get("encoding"):
                    enc[e] += 1
                if r.kind == "marker_count":
                    marker_counts[str(r.key)][str(r.value.get("encoding"))] = \
                        int(r.value.get("count", 0))
        return {
            "records_by_source": dict(by_source.most_common()),
            "records_by_kind": dict(by_kind.most_common()),
            "records_by_storage": dict(by_storage.most_common()),
            "records_by_encoding": dict(enc),
            "marker_counts": dict(marker_counts),
            "artifacts_total": sum(len(e.artifacts) for e in self.result.events),
            "distinct_artifact_paths": len({a.path for e in self.result.events
                                            for a in e.artifacts}),
        }

    def identifiers(self) -> dict[str, list[str]]:
        """수집된 식별자 전량 — 계정 귀속의 출발점."""
        out: dict[str, set[str]] = defaultdict(set)
        for e in self.result.events:
            for k, v in (("account_uuid", e.account_uuid), ("org_uuid", e.org_uuid),
                         ("conversation_uuid", e.conversation_uuid),
                         ("device_id", e.device_id)):
                if v:
                    # 깨진 JSON 에서는 uuid 가 숫자로 올라오기도 한다 — 섞이면 정렬이 터진다
                    out[k].add(v if isinstance(v, str) else str(v))
        for r in self.records:
            if not isinstance(r.value, dict):
                continue
            for k in ("account_uuid", "org_uuid", "conversation_uuid", "device_id", "uuid"):
                v = r.value.get(k)
                if isinstance(v, str) and v:
                    out["conversation_uuid" if k == "uuid" else k].add(v)
            for v in (r.value.get("uuids") or []):
                if isinstance(v, str):
                    out["observed_uuid"].add(v)
            for k in ("full_name", "email_address", "display_name"):
                if v := r.value.get(k):
                    out["profile"].add(f"{k}={v}")
        return {k: sorted(v) for k, v in sorted(out.items())}

    def conversations(self) -> list[dict[str, Any]]:
        """복원된 대화 목록 — 메시지 본문 포함."""
        convs: dict[str, dict[str, Any]] = {}
        for r in self.records:
            if r.kind != "conversation" or not isinstance(r.value, dict):
                continue
            uid = r.value.get("uuid") or r.key or "unknown"
            entry = convs.setdefault(uid, {
                "conversation_uuid": uid, "name": None, "summary": None,
                "model": None, "product": None, "message_count": 0,
                "account_uuid": None, "org_uuid": None,
                "sources": set(), "timestamps": set(), "artifacts": [], "messages": [],
            })
            for k in ("name", "summary", "model", "product", "account_uuid", "org_uuid"):
                entry[k] = entry[k] or r.value.get(k)
            entry["message_count"] = max(entry["message_count"],
                                         int(r.value.get("message_count") or 0))
            entry["sources"].add(r.source)
            if r.ts_utc:
                entry["timestamps"].add(r.ts_utc)
            if r.ref:
                entry["artifacts"].append(r.ref.to_dict())

        for r in self.records:
            if r.kind != "message" or not isinstance(r.value, dict):
                continue
            uid = r.value.get("conversation_uuid") or r.key or "unknown"
            entry = convs.setdefault(uid, {
                "conversation_uuid": uid, "name": None, "summary": None, "model": None,
                "product": None, "message_count": 0, "account_uuid": None, "org_uuid": None,
                "sources": set(), "timestamps": set(), "artifacts": [], "messages": [],
            })
            entry["sources"].add(r.source)
            entry["messages"].append({
                "uuid": r.value.get("uuid"),
                "parent_message_uuid": r.value.get("parent_message_uuid"),
                "sender": r.value.get("sender"),
                "index": r.value.get("index"),
                "timestamp_utc": r.ts_utc,
                "text": r.value.get("text") or "",
                "attachments": r.value.get("attachments") or [],
                "files": r.value.get("files") or [],
                "source": r.source,
                "artifact": r.ref.path if r.ref else "",
            })

        # 열람 이력 붙이기
        opens: dict[str, list[str]] = defaultdict(list)
        for r in self.records:
            if r.kind == "conversation_opened" and r.ts_utc:
                uid = (r.value or {}).get("conversation_uuid") or r.key
                if uid:
                    opens[uid].append(r.ts_utc)

        out = []
        for uid, e in convs.items():
            e["sources"] = sorted(e["sources"])
            e["timestamps"] = sorted(e["timestamps"])
            e["opened_at"] = sorted(opens.get(uid, []))
            e["messages"].sort(key=lambda m: (m["timestamp_utc"] or "", m.get("index") or 0))
            e["recovered_messages"] = len(e["messages"])
            e["channel_count"] = len(e["sources"])
            # 어디까지 복원됐는지 명시한다. "대화 복원"이라는 말만으로는
            # 본문까지 나온 것인지 제목만 나온 것인지 구분되지 않는다.
            if e["messages"]:
                e["recovery_level"] = "본문"
            elif e["summary"]:
                e["recovery_level"] = "요약만"
            else:
                e["recovery_level"] = "메타데이터만"
            out.append(e)
        out.sort(key=lambda c: (c["timestamps"][0] if c["timestamps"] else ""))
        return out




    # ══ 파일 출력 ══════════════════════════════════════════════════════






    def print_console(self) -> None:
        s = self.summary()
        st = self.statistics()
        print()
        print(f"  원시 레코드 {s['records_total']}건 → 이벤트 {s['events_total']}건 "
              f"(시각 확보 {s['events_with_time']}건)")
        lv = s["by_evidence_level"]
        print(f"  직접 증거 {lv.get('direct', 0)} · 보조 증거 {lv.get('supporting', 0)} · "
              f"교차검증 {s['multi_channel_events']} · 미검출 {s['not_detected']} · "
              f"해당없음 {s['not_applicable']}")
        print(f"  복원 대화 {len(self.conversations())}건 · "
              f"근거 아티팩트 {st['artifacts_total']}건 · "
              f"식별자 {sum(len(v) for v in self.identifiers().values())}건")
        c = s["collected_files"]
        print(f"  수집 {c.get('ok', 0)}건 정상, {c.get('locked', 0)}건 점유 중, "
              f"{s['collected_bytes']:,}B")
        iss = s["issues"]
        if iss:
            print("  문제: " + " · ".join(f"{k} {v}" for k, v in iss.items()))
