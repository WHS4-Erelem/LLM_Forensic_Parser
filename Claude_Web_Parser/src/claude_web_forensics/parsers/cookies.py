"""Chrome Cookies parser (spec section 10.2).

Only claude.ai-related hosts are processed. Cookie VALUES are never emitted in
human-readable output: host/name/path/time/flags plus the value length are
sufficient for every verdict (spec section 9). Login Data is never opened.
"""
from __future__ import annotations

from pathlib import Path

from ..decode.content import classify_chrome_value
from ..model.entities import FAMILY_COOKIES, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import from_webkit
from .common import CLAUDE_HOSTS, open_readonly, row_to_dict, select_available, table_names

# Session-bearing cookie names worth flagging for the login/logout detectors.
SESSION_COOKIE_NAMES = {
    "sessionkey",
    "sessionkeylc",
    "lastactiveorg",
    "activitysessionid",
    "anthropic-device-id",
}


def _is_claude_host(value: str) -> bool:
    host = (value or "").lstrip(".").lower()
    return any(host == h or host.endswith("." + h) for h in CLAUDE_HOSTS)


def parse_cookies(
    db_path: Path, source_path: str, volume_id: str
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    errors: list[str] = []

    if not db_path.exists():
        return records, ParseStatus(
            artifact="Cookies",
            family=FAMILY_COOKIES,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="Cookies database not staged",
            impact="cookie metadata unavailable",
        )

    try:
        conn = open_readonly(db_path)
    except Exception as exc:
        return records, ParseStatus(
            artifact="Cookies",
            family=FAMILY_COOKIES,
            status=ST_FAILED,
            source_path=source_path,
            error_code=type(exc).__name__,
            message=str(exc),
            impact="cookie metadata unavailable",
        )

    try:
        if "cookies" not in table_names(conn):
            return records, ParseStatus(
                artifact="Cookies",
                family=FAMILY_COOKIES,
                status=ST_FAILED,
                source_path=source_path,
                message="no 'cookies' table in database",
            )

        rows = select_available(
            conn,
            "cookies",
            (
                "creation_utc", "host_key", "name", "value", "encrypted_value", "path",
                "expires_utc", "is_secure", "secure", "is_httponly", "httponly",
                "last_access_utc", "has_expires", "is_persistent", "priority",
                "samesite", "source_scheme", "last_update_utc",
            ),
        )
        for row in rows:
            data = row_to_dict(row)
            host = str(data.get("host_key") or "")
            if not _is_claude_host(host):
                continue

            name = str(data.get("name") or "")
            encrypted = data.get("encrypted_value")
            plain = data.get("value")

            if isinstance(encrypted, (bytes, bytearray)) and encrypted:
                blob = bytes(encrypted)
                enc_status = classify_chrome_value(blob)
                value_length = len(blob)
                value_kind = "encrypted_value"
            elif plain:
                blob = str(plain).encode("utf-8", errors="surrogatepass")
                enc_status = classify_chrome_value(blob)
                value_length = len(blob)
                value_kind = "value"
            else:
                enc_status = classify_chrome_value(None)
                value_length = 0
                value_kind = "empty"

            created = from_webkit(data.get("creation_utc"))
            locator = f"table=cookies;host={host};name={name};path={data.get('path')}"
            # The value itself is intentionally absent from the payload.
            payload = {
                "host": host,
                "name": name,
                "path": data.get("path"),
                "creation_utc": data.get("creation_utc"),
            }
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(FAMILY_COOKIES, source_path, locator, payload),
                    artifact="Cookies",
                    artifact_family=FAMILY_COOKIES,
                    source_path=source_path,
                    record_locator=locator,
                    timestamp=created,
                    summary=f"쿠키: {host} / {name}",
                    attributes={
                        "subtype": "cookie",
                        "host_key": host,
                        "name": name,
                        "path": data.get("path") or "",
                        "creation_utc": data.get("creation_utc"),
                        "last_access_utc": data.get("last_access_utc"),
                        "expires_utc": data.get("expires_utc"),
                        "is_secure": data.get("is_secure", data.get("secure")),
                        "is_httponly": data.get("is_httponly", data.get("httponly")),
                        "samesite": data.get("samesite"),
                        "is_persistent": data.get("is_persistent"),
                        "value_kind": value_kind,
                        "value_length": value_length,
                        "value_encryption_status": enc_status.status,
                        "value_encryption_scheme": enc_status.scheme,
                        "is_session_cookie_name": name.lower() in SESSION_COOKIE_NAMES,
                        "volume_id": volume_id,
                    },
                )
            )
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="Cookies",
        family=FAMILY_COOKIES,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5]),
    )
