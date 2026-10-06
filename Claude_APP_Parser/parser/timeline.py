"""타임라인 구성 — 확인 가능한 시각만 정렬하고, 시각 미상은 별도 유지."""


def build(records):
    dated = []
    undated = []
    for r in records:
        ts = r.get("timestamp") or {}
        if ts.get("utc"):
            dated.append(r)
        else:
            undated.append(r)
    dated.sort(key=lambda r: (r["timestamp"]["utc"], r["record_id"]))
    return {
        "timeline": [_entry(r) for r in dated],
        "undated_records": [_entry(r) for r in undated],
        "counts": {
            "total": len(records),
            "dated": len(dated),
            "undated": len(undated),
        },
    }


def _entry(r):
    ev = r.get("evidence") or {}
    loc = ev.get("location") or {}
    return {
        "record_id": r["record_id"],
        "utc": r["timestamp"].get("utc"),
        "original_value": r["timestamp"].get("original_value"),
        "timestamp_source": r["timestamp"].get("source"),
        "timestamp_meaning": r["timestamp"].get("meaning"),
        "null_reason": r["timestamp"].get("null_reason"),
        "event_id": r["event"]["event_id"],
        "event_name": r["event"]["event_name"],
        "action": r["user_action"]["action"],
        "confidence": r["user_action"]["confidence"],
        "path": loc.get("path"),
        "mft_record": loc.get("mft_record"),
        "locator": ev.get("locator"),
        "parse_status": r["parse"]["status"],
    }
