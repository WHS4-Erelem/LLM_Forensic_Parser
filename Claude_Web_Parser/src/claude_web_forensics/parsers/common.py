"""Shared helpers for artifact parsers."""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

CLAUDE_HOSTS = ("claude.ai", "claude.com", "anthropic.com")

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ORG_URL_RE = re.compile(r"/organizations/([0-9a-fA-F-]{36})")
_CONV_URL_RE = re.compile(r"/(?:chat_conversations|conversations|chat)/([0-9a-fA-F-]{36})")
_SNAPSHOT_RE = re.compile(r"/snapshot[s]?/([0-9a-fA-F-]{36})")


def is_claude_url(value: Any) -> bool:
    s = str(value or "").lower()
    return any(host in s for host in CLAUDE_HOSTS)


def extract_uuids(value: Any) -> list[str]:
    return _UUID_RE.findall(str(value or ""))


def organization_from_url(value: Any) -> str | None:
    m = _ORG_URL_RE.search(str(value or ""))
    return m.group(1).lower() if m else None


def conversation_from_url(value: Any) -> str | None:
    m = _CONV_URL_RE.search(str(value or ""))
    return m.group(1).lower() if m else None


def snapshot_from_url(value: Any) -> str | None:
    m = _SNAPSHOT_RE.search(str(value or ""))
    return m.group(1).lower() if m else None


def truncate(value: Any, limit: int = 300) -> str:
    s = str(value or "")
    if len(s) <= limit:
        return s
    return s[:limit] + f"...(+{len(s) - limit})"


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------

def open_readonly(db_path: Path) -> sqlite3.Connection:
    """Open a staged SQLite copy read-only. WAL/SHM siblings must sit next to it."""
    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def table_names(conn: sqlite3.Connection) -> set[str]:
    try:
        return {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    except sqlite3.DatabaseError:
        return set()


def column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    escaped = table.replace("'", "''")
    try:
        return {r["name"] for r in conn.execute(f"PRAGMA table_info('{escaped}')")}
    except sqlite3.DatabaseError:
        return set()


def select_available(
    conn: sqlite3.Connection,
    table: str,
    wanted: Iterable[str],
    where: str = "",
    params: tuple = (),
    order_by: str = "",
) -> list[sqlite3.Row]:
    """Targeted query over only the columns this Chrome version actually has.

    Chrome schemas vary across versions, so columns are introspected first
    (spec section 10.1) instead of dumping every table.
    """
    available = column_names(conn, table)
    if not available:
        return []
    cols = [c for c in wanted if c in available]
    if not cols:
        return []
    quoted_table = '"' + table.replace('"', '""') + '"'
    select_list = ", ".join('"' + c.replace('"', '""') + '"' for c in cols)
    if "rowid" not in available:
        select_list = "rowid AS __rowid__, " + select_list
    sql = f"SELECT {select_list} FROM {quoted_table}"
    if where:
        sql += f" WHERE {where}"
    if order_by:
        sql += f" ORDER BY {order_by}"
    try:
        return list(conn.execute(sql, params))
    except sqlite3.DatabaseError:
        return []


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}
