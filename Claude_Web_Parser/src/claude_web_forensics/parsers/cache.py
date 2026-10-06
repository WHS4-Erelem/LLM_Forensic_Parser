"""Chrome Cache parser."""
from __future__ import annotations

import collections
import datetime as dt
import re
from pathlib import Path
from typing import Any, Callable

from ..decode.content import DECODE_LIMITED, decode_text_strict, sniff_and_decompress
from ..decode.content import image_format, try_parse_json
from ..model.entities import FAMILY_CACHE, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import UTC, ensure_aware
from . import ccl_adapter as ccl
from .common import conversation_from_url, is_claude_url, organization_from_url, truncate
from .filesystem import remote_path

KEY_CONVERSATION = "conversation_api"
KEY_CONVERSATION_LIST = "conversation_list"
KEY_LATEST_SNAPSHOT = "latest_or_snapshot"
KEY_SHARE = "share_api"
KEY_FILE_ASSET = "file_asset"
KEY_DOWNLOAD_FILE = "download_file"
KEY_ORGANIZATION = "organization_api"
KEY_ACCOUNT = "account_api"
KEY_OTHER_CLAUDE = "other_claude"

HYDRATE_KINDS = {
    KEY_CONVERSATION, KEY_CONVERSATION_LIST, KEY_LATEST_SNAPSHOT, KEY_SHARE,
    KEY_DOWNLOAD_FILE, KEY_ORGANIZATION, KEY_ACCOUNT,
}

_CONVERSATION_PATH = re.compile(r"/chat_conversations/[0-9a-f-]{36}(?:/([a-z_]+))?(?:[/?#]|$)")
_FILE_ASSET_PATH = re.compile(r"/api/[0-9a-f-]{36}/files/([0-9a-f-]{36})/([a-z_]+)")
_SHARE_SUBRESOURCES = {"share_access", "shares", "access_requests", "share"}

def classify_key(key: str) -> str:
    k = key.lower()
    if "/wiggle/download-file" in k or "download-file?" in k:
        return KEY_DOWNLOAD_FILE
    match = _CONVERSATION_PATH.search(k)
    if match:
        sub = match.group(1) or ""
        if not sub:
            return KEY_CONVERSATION
        if sub == "latest" or sub.startswith("snapshot"):
            return KEY_LATEST_SNAPSHOT
        if sub in _SHARE_SUBRESOURCES:
            return KEY_SHARE
        return KEY_ORGANIZATION
    if "chat_conversations_v2" in k or "chat_conversations?" in k:
        return KEY_CONVERSATION_LIST
    if _FILE_ASSET_PATH.search(k):
        return KEY_FILE_ASSET
    if "/api/account" in k or "/api/bootstrap" in k or "current_account" in k:
        return KEY_ACCOUNT
    if "/api/organizations/" in k:
        return KEY_ORGANIZATION
    return KEY_OTHER_CLAUDE

def _as_time(value: Any) -> dt.datetime | None:
    return ensure_aware(value, UTC) if isinstance(value, dt.datetime) else None

def _shape(value: Any) -> str:
    if isinstance(value, dict):
        keys = sorted(value)
        return "{" + ",".join(keys[:12]) + (",…" if len(keys) > 12 else "") + "}"
    if isinstance(value, list):
        return f"list[{len(value)}]"
    return type(value).__name__

def parse_cache(
    cache_dir: Path, source_path: str, volume_id: str, raw_writer: Callable[[bytes, str], str] | None = None,
) -> tuple[list[EvidenceRecord], ParseStatus]:
    records: list[EvidenceRecord] = []
    if not cache_dir.exists():
        return records, ParseStatus(
            artifact="Cache", family=FAMILY_CACHE, status=ST_NOT_FOUND,
            source_path=source_path, message="Cache_Data directory not staged",
        )
    try:
        cache = ccl.open_cache(cache_dir)
    except Exception as exc:
        return records, ParseStatus(
            artifact="Cache", family=FAMILY_CACHE, status=ST_FAILED, source_path=source_path,
            message=str(exc),
        )

    errors: list[str] = []
    total_keys = hydrated = 0

    stats: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    shapes: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    try:
        for key in ccl.cache_keys(cache):
            total_keys += 1
            if not is_claude_url(key):
                continue
            kind = classify_key(key)
            metas = ccl.cache_metadata(cache, key)
            meta_locs, body_locs = ccl.cache_locations(cache, key)
            bodies = ccl.cache_bodies(cache, key) if kind in HYDRATE_KINDS else []
            for variant in range(max(len(metas), len(meta_locs), len(body_locs), 1)):
                meta = metas[variant] if variant < len(metas) else None
                meta_loc = ccl.location_str(meta_locs[variant] if variant < len(meta_locs) else None)
                body_loc = ccl.location_str(body_locs[variant] if variant < len(body_locs) else None)
                attributes: dict[str, Any] = {
                    "subtype": "cache_entry", "cache_key": key, "key_kind": kind, "variant_index": variant,
                    "content_type": ccl.header_value(meta, "content-type") or "",
                    "content_encoding": ccl.header_value(meta, "content-encoding") or "",
                    "metadata_location": meta_loc, "body_location": body_loc,
                    "request_at": _as_time(ccl.get_attr_any_meta(meta, "request_time")),
                    "response_at": _as_time(ccl.get_attr_any_meta(meta, "response_time")),
                    "body_hydrated": False, "volume_id": volume_id,
                }
                asset = _FILE_ASSET_PATH.search(key.lower())
                if asset:
                    attributes["file_uuid"], attributes["file_variant"] = asset.groups()
                if kind == KEY_DOWNLOAD_FILE:
                    attributes["output_path"] = remote_path(key.split(" ")[-1])
                stats[kind]["entries"] += 1
                body = bodies[variant] if variant < len(bodies) else None
                if body is not None:
                    hydrated += 1
                    parsed = _decode_body(body, kind, attributes, raw_writer)
                    stats[kind][f"decode:{attributes.get('decode_status')}"] += 1
                    stats[kind][f"json:{attributes.get('json_parse_status')}"] += 1
                    if parsed is not None:
                        attributes["_json"] = parsed
                        shapes[kind][_shape(parsed)] += 1
                        _enrich_from_json(kind, attributes, parsed)
                locator = f"key={key};variant={variant}"
                records.append(
                    EvidenceRecord(
                        evidence_id=make_evidence_id(
                            FAMILY_CACHE, source_path, locator,
                            {"key": key, "variant": variant, "meta_location": meta_loc,
                             "body_location": body_loc},
                        ),
                        artifact="Cache", artifact_family=FAMILY_CACHE, source_path=source_path,

                        artifact_path=_entry_file_path(source_path, body_loc, meta_loc), volume_id=volume_id,
                        record_locator=locator, account_uuid=attributes.get("account_uuid"),
                        organization_uuid=organization_from_url(key),
                        conversation_uuid=conversation_from_url(key),
                        summary=f"Cache entry ({kind}): {truncate(key, 140)}", attributes=attributes,
                    )
                )
    except Exception as exc:
        errors.append(f"cache iteration: {type(exc).__name__}: {exc}")
    finally:
        ccl.close_cache(cache)

    details = []
    for kind in sorted(stats):
        if kind == KEY_OTHER_CLAUDE:
            continue
        counts = ", ".join(f"{k}={v}" for k, v in sorted(stats[kind].items()))
        shape = "; ".join(f"{s}×{n}" for s, n in shapes[kind].most_common(4))
        details.append(f"cache {kind}: {counts}" + (f"; top-level {shape}" if shape else ""))
    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="Cache", family=FAMILY_CACHE, status=status, source_path=source_path,
        record_count=len(records), message="; ".join(errors[:5])
        or f"keys={total_keys} claude={len(records)} hydrated={hydrated}", details=details,
    )

def _decode_body(
    body: bytes, kind: str, attributes: dict[str, Any], raw_writer
) -> Any | None:
    attributes.update({"body_hydrated": True, "raw_size": len(body)})
    result = sniff_and_decompress(body, attributes["content_encoding"] or None)
    attributes["decode_status"] = result.status
    if result.error:
        attributes["decode_error"] = result.error
    if not result.ok:
        attributes["json_parse_status"] = (
            "DECODE_LIMITED" if result.status == DECODE_LIMITED else "DECODE_FAILED"
        )
        return None
    decoded = result.data
    attributes["decoded_size"] = len(decoded)
    if kind == KEY_DOWNLOAD_FILE:
        attributes["body_format"] = image_format(decoded)
        if raw_writer is not None:
            attributes["decoded_body_path"] = raw_writer(decoded, "body.bin")
    text, _encoding = decode_text_strict(decoded, attributes["content_type"])
    if text is None:
        attributes["json_parse_status"] = "BINARY"
        return None
    parsed = try_parse_json(text)
    attributes["json_parse_status"] = "PARSED" if parsed is not None else "NOT_JSON"
    return parsed

def _entry_file_path(source_path: str, *locations: str) -> str:
    for location in locations:
        name = (location or "").rsplit("@", 1)[0].strip()
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
        if name and name != "None":
            return f"{source_path.rstrip('/')}/{name}"
    return ""

def _enrich_from_json(kind: str, attributes: dict[str, Any], parsed: Any) -> None:
    if not isinstance(parsed, dict):
        return
    snapshot = parsed.get("snapshot")
    if kind == KEY_LATEST_SNAPSHOT and isinstance(snapshot, dict) and snapshot.get("uuid"):
        attributes["snapshot_uuid"] = str(snapshot["uuid"]).lower()
        attributes["snapshot_created_at"] = snapshot.get("created_at")
        attributes["snapshot_visibility"] = snapshot.get("visibility")
    if kind == KEY_SHARE and isinstance(parsed.get("people"), list):
        attributes["share_people_count"] = len(parsed["people"])
        attributes["share_visibility"] = parsed.get("visibility")
    account = parsed.get("account")
    if isinstance(account, dict) and isinstance(account.get("uuid"), str):
        attributes["account_uuid"] = account["uuid"].lower()
