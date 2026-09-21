"""Chrome History parser (spec section 10.1).

Targeted queries over urls / visits / downloads / downloads_url_chains, after
schema introspection. `downloads` and `downloads_url_chains` belong to the same
History family and are never counted as two independent corroborations
(spec section 16.1).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..model.entities import FAMILY_HISTORY, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import from_webkit
from .common import (
    conversation_from_url,
    is_claude_url,
    open_readonly,
    organization_from_url,
    row_to_dict,
    select_available,
    table_names,
    truncate,
)

# Chrome download state values.
DOWNLOAD_STATE_IN_PROGRESS = 0
DOWNLOAD_STATE_COMPLETE = 1
DOWNLOAD_STATE_CANCELLED = 2
DOWNLOAD_STATE_INTERRUPTED = 4

_STATE_LABEL = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "BUG_140687",
    4: "INTERRUPTED",
}


def parse_history(
    db_path: Path, source_path: str, volume_id: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []

    if not db_path.exists():
        return records, ParseStatus(
            artifact="History",
            family=FAMILY_HISTORY,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="History database not staged",
            impact="URL/visit/download evidence unavailable",
        )

    try:
        conn = open_readonly(db_path)
    except Exception as exc:
        return records, ParseStatus(
            artifact="History",
            family=FAMILY_HISTORY,
            status=ST_FAILED,
            source_path=source_path,
            error_code=type(exc).__name__,
            message=str(exc),
            impact="URL/visit/download evidence unavailable",
        )

    try:
        tables = table_names(conn)

        # -- urls -------------------------------------------------------
        if "urls" in tables:
            try:
                for row in select_available(
                    conn,
                    "urls",
                    ("id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"),
                ):
                    data = row_to_dict(row)
                    url = data.get("url") or ""
                    if not is_claude_url(url):
                        continue
                    ts = from_webkit(data.get("last_visit_time"))
                    locator = f"table=urls;id={data.get('id')}"
                    records.append(
                        EvidenceRecord(
                            evidence_id=make_evidence_id(FAMILY_HISTORY, source_path, locator, data),
                            artifact="History",
                            artifact_family=FAMILY_HISTORY,
                            source_path=source_path,
                            record_locator=locator,
                            timestamp=ts,
                            organization_uuid=organization_from_url(url),
                            conversation_uuid=conversation_from_url(url),
                            summary=f"URL 방문: {truncate(url, 160)}",
                            attributes={
                                "subtype": "url",
                                "url": url,
                                "title": data.get("title") or "",
                                "visit_count": data.get("visit_count"),
                                "typed_count": data.get("typed_count"),
                                "volume_id": volume_id,
                            },
                        )
                    )
            except Exception as exc:
                errors.append(f"urls: {type(exc).__name__}: {exc}")

        # -- visits (joined to urls for context) ------------------------
        if "visits" in tables and "urls" in tables:
            try:
                sql = (
                    "SELECT v.id AS visit_id, v.url AS url_id, v.visit_time AS visit_time, "
                    "v.from_visit AS from_visit, v.transition AS transition, u.url AS url, "
                    "u.title AS title FROM visits v JOIN urls u ON u.id = v.url "
                    "ORDER BY v.visit_time"
                )
                for row in conn.execute(sql):
                    data = row_to_dict(row)
                    url = data.get("url") or ""
                    if not is_claude_url(url):
                        continue
                    ts = from_webkit(data.get("visit_time"))
                    locator = f"table=visits;id={data.get('visit_id')}"
                    records.append(
                        EvidenceRecord(
                            evidence_id=make_evidence_id(FAMILY_HISTORY, source_path, locator, data),
                            artifact="History",
                            artifact_family=FAMILY_HISTORY,
                            source_path=source_path,
                            record_locator=locator,
                            timestamp=ts,
                            organization_uuid=organization_from_url(url),
                            conversation_uuid=conversation_from_url(url),
                            summary=f"방문 기록: {truncate(url, 160)}",
                            attributes={
                                "subtype": "visit",
                                "url": url,
                                "title": data.get("title") or "",
                                "transition": data.get("transition"),
                                "from_visit": data.get("from_visit"),
                                "volume_id": volume_id,
                            },
                        )
                    )
            except Exception as exc:
                errors.append(f"visits: {type(exc).__name__}: {exc}")

        # -- downloads + url chains (one family, one corroboration) -----
        chains: dict[int, list[dict[str, Any]]] = {}
        if "downloads_url_chains" in tables:
            try:
                for row in select_available(
                    conn,
                    "downloads_url_chains",
                    ("id", "chain_index", "url"),
                    order_by="id, chain_index",
                ):
                    data = row_to_dict(row)
                    chains.setdefault(int(data.get("id") or -1), []).append(data)
            except Exception as exc:
                errors.append(f"downloads_url_chains: {type(exc).__name__}: {exc}")

        if "downloads" in tables:
            try:
                for row in select_available(
                    conn,
                    "downloads",
                    (
                        "id", "guid", "current_path", "target_path", "start_time", "end_time",
                        "received_bytes", "total_bytes", "state", "danger_type",
                        "interrupt_reason", "mime_type", "original_mime_type",
                        "referrer", "tab_url", "tab_referrer_url", "site_url",
                        "last_access_time", "opened", "by_ext_id", "by_ext_name",
                    ),
                ):
                    data = row_to_dict(row)
                    did = int(data.get("id") or -1)
                    chain = chains.get(did, [])
                    chain_urls = [c.get("url") or "" for c in chain]

                    # Claude relevance: any of the chain URLs, the referrer or
                    # the originating tab URL must point at Claude.
                    relevant = (
                        any(is_claude_url(u) for u in chain_urls)
                        or is_claude_url(data.get("referrer"))
                        or is_claude_url(data.get("tab_url"))
                        or is_claude_url(data.get("site_url"))
                    )
                    if not relevant:
                        continue

                    state = data.get("state")
                    try:
                        state_int = int(state) if state is not None else None
                    except (TypeError, ValueError):
                        state_int = None

                    # Download action time is History start_time (spec section 18).
                    ts = from_webkit(data.get("start_time"))
                    target = data.get("target_path") or data.get("current_path") or ""
                    locator = f"table=downloads;id={did}"
                    source_url = next((u for u in chain_urls if is_claude_url(u)), "")
                    payload = dict(data)
                    payload["chain"] = chain

                    records.append(
                        EvidenceRecord(
                            evidence_id=make_evidence_id(FAMILY_HISTORY, source_path, locator, payload),
                            artifact="History",
                            artifact_family=FAMILY_HISTORY,
                            source_path=source_path,
                            record_locator=locator,
                            timestamp=ts,
                            organization_uuid=organization_from_url(source_url)
                            or organization_from_url(data.get("referrer")),
                            conversation_uuid=conversation_from_url(source_url)
                            or conversation_from_url(data.get("referrer"))
                            or conversation_from_url(data.get("tab_url")),
                            summary=(
                                f"다운로드 {_STATE_LABEL.get(state_int, state_int)}: "
                                f"{Path(str(target)).name or truncate(source_url, 80)}"
                            ),
                            attributes={
                                "subtype": "download",
                                "download_id": did,
                                "guid": data.get("guid"),
                                "target_path": data.get("target_path") or "",
                                "current_path": data.get("current_path") or "",
                                "file_name": Path(str(target)).name if target else "",
                                "state": state_int,
                                "state_label": _STATE_LABEL.get(state_int, str(state_int)),
                                "danger_type": data.get("danger_type"),
                                "interrupt_reason": data.get("interrupt_reason"),
                                "received_bytes": data.get("received_bytes"),
                                "total_bytes": data.get("total_bytes"),
                                "mime_type": data.get("mime_type") or "",
                                "original_mime_type": data.get("original_mime_type") or "",
                                "referrer": data.get("referrer") or "",
                                "tab_url": data.get("tab_url") or "",
                                "end_time": data.get("end_time"),
                                "chain_urls": chain_urls,
                                # Same History family -- NOT an independent source.
                                "chain_is_same_family": True,
                                "volume_id": volume_id,
                            },
                        )
                    )
            except Exception as exc:
                errors.append(f"downloads: {type(exc).__name__}: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="History",
        family=FAMILY_HISTORY,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5]),
        impact="partial URL/download evidence" if errors else "",
    )
