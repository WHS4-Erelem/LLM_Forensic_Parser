"""Chrome Cache parser (spec section 10.3).

Order of work: index entry metadata, select Claude-related keys, hydrate bodies
only when needed, decode, extract semantics. Only decoded Claude download-file
bodies are kept (in the temporary workspace) so on-disk files can be matched to
them byte for byte; nothing is exported.
Bodies are never all loaded into memory (fix for chrome_artifact_diff_v2.py:960-1099).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..decode.content import DECODE_LIMITED, sniff_and_decompress
from ..decode.content import decode_text_strict, try_parse_json
from ..model.entities import FAMILY_CACHE, EvidenceRecord, make_evidence_id
from ..model.entities import ST_FAILED, ST_NOT_FOUND, ST_PARSED, ST_PARTIAL, ParseStatus
from ..util.common import from_iso8601
from . import ccl_adapter as ccl
from .common import (
    conversation_from_url,
    is_claude_url,
    organization_from_url,
    truncate,
)

# Claude API surfaces worth indexing first (spec section 10.3).
KEY_CONVERSATION = "conversation_api"
KEY_CONVERSATION_LIST = "conversation_list"
KEY_LATEST_SNAPSHOT = "latest_or_snapshot"
KEY_DOWNLOAD_FILE = "download_file"
KEY_ORGANIZATION = "organization_api"
KEY_ACCOUNT = "account_api"
KEY_OTHER_CLAUDE = "other_claude"

# Only these are hydrated; static assets are indexed but their bodies are not read.
HYDRATE_KINDS = {
    KEY_CONVERSATION,
    KEY_CONVERSATION_LIST,
    KEY_LATEST_SNAPSHOT,
    KEY_DOWNLOAD_FILE,
    KEY_ORGANIZATION,
    KEY_ACCOUNT,
}

_STATIC_MARKERS = (
    "/_next/", "/static/", ".js", ".css", ".woff", ".woff2", ".ttf",
    ".ico", ".map", "/sdk/", "assets.claude", "a-cdn",
)


def classify_key(key: str) -> str:
    """Bucket a cache key so hydration can stay selective."""
    k = key.lower()
    if "/wiggle/download-file" in k or "download-file?" in k:
        return KEY_DOWNLOAD_FILE
    if "/chat_conversations/" in k and "composer_notices" not in k:
        if k.rstrip("/").endswith("/latest") or "/snapshot" in k:
            return KEY_LATEST_SNAPSHOT
        return KEY_CONVERSATION
    if "chat_conversations_v2" in k or "chat_conversations?" in k:
        return KEY_CONVERSATION_LIST
    if "/api/account" in k or "/api/bootstrap" in k or "current_account" in k:
        return KEY_ACCOUNT
    if "/api/organizations/" in k:
        return KEY_ORGANIZATION
    if any(marker in k for marker in _STATIC_MARKERS):
        return KEY_OTHER_CLAUDE
    return KEY_OTHER_CLAUDE


@dataclass
class CacheIndexEntry:
    key: str
    kind: str
    variant: int
    metadata: Any
    meta_location: str
    body_location: str
    content_type: str = ""
    content_encoding: str = ""
    organization_uuid: str | None = None
    conversation_uuid: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


def parse_cache(
    cache_dir: Path,
    source_path: str,
    volume_id: str,
    raw_writer: Callable[[bytes, str], str] | None = None,
) -> tuple[list[EvidenceRecord], ParseStatus]:
    """Parse the Chromium cache. `raw_writer(data, suffix) -> path` keeps download bodies."""
    records: list[EvidenceRecord] = []
    errors: list[str] = []

    if not cache_dir.exists():
        return records, ParseStatus(
            artifact="Cache",
            family=FAMILY_CACHE,
            status=ST_NOT_FOUND,
            source_path=source_path,
            message="Cache_Data directory not staged",
            impact="cached conversation/API bodies unavailable",
        )

    try:
        cache = ccl.open_cache(cache_dir)
    except Exception as exc:
        return records, ParseStatus(
            artifact="Cache",
            family=FAMILY_CACHE,
            status=ST_FAILED,
            source_path=source_path,
            error_code=type(exc).__name__,
            message=str(exc),
            impact="cached conversation/API bodies unavailable",
        )

    total_keys = 0
    claude_keys = 0
    hydrated = 0

    try:
        # ---- 1) metadata-first indexing --------------------------------
        index: list[CacheIndexEntry] = []
        for key in ccl.cache_keys(cache):
            total_keys += 1
            if not is_claude_url(key):
                continue
            claude_keys += 1
            kind = classify_key(key)
            metas = ccl.cache_metadata(cache, key)
            meta_locs, body_locs = ccl.cache_locations(cache, key)
            count = max(len(metas), len(meta_locs), len(body_locs), 1)
            for i in range(count):
                meta = metas[i] if i < len(metas) else None
                index.append(
                    CacheIndexEntry(
                        key=key,
                        kind=kind,
                        variant=i,
                        metadata=meta,
                        meta_location=ccl.location_str(
                            meta_locs[i] if i < len(meta_locs) else None
                        ),
                        body_location=ccl.location_str(
                            body_locs[i] if i < len(body_locs) else None
                        ),
                        content_type=ccl.header_value(meta, "content-type") or "",
                        content_encoding=ccl.header_value(meta, "content-encoding") or "",
                        organization_uuid=organization_from_url(key),
                        conversation_uuid=conversation_from_url(key),
                    )
                )

        # ---- 2) selective hydration -----------------------------------
        bodies_by_key: dict[str, list[bytes]] = {}
        for entry in index:
            locator = f"key={entry.key};variant={entry.variant}"
            attributes: dict[str, Any] = {
                "subtype": "cache_entry",
                "cache_key": entry.key,
                "key_kind": entry.kind,
                "variant_index": entry.variant,
                "content_type": entry.content_type,
                "content_encoding": entry.content_encoding,
                "metadata_location": entry.meta_location,
                "body_location": entry.body_location,
                "volume_id": volume_id,
                "body_hydrated": False,
            }

            request_time = ccl.get_attr_any_meta(entry.metadata, "request_time")
            response_time = ccl.get_attr_any_meta(entry.metadata, "response_time")
            attributes["request_time"] = str(request_time) if request_time else ""
            attributes["response_time"] = str(response_time) if response_time else ""

            summary = f"Cache entry ({entry.kind}): {truncate(entry.key, 140)}"
            timestamp = None
            message_payload: Any = None

            if entry.kind in HYDRATE_KINDS:
                if entry.key not in bodies_by_key:
                    bodies_by_key[entry.key] = ccl.cache_bodies(cache, entry.key)
                bodies = bodies_by_key[entry.key]
                body = bodies[entry.variant] if entry.variant < len(bodies) else None

                if body is not None:
                    hydrated += 1
                    attributes.update({"body_hydrated": True, "raw_size": len(body)})

                    result = sniff_and_decompress(body, entry.content_encoding or None)
                    attributes["decode_status"] = result.status
                    attributes["decoders"] = list(result.applied_decoders)
                    if result.error:
                        attributes["decode_error"] = result.error

                    if result.ok:
                        decoded = result.data
                        attributes["decoded_size"] = len(decoded)
                        # A Claude download body is kept only so an on-disk
                        # file can be matched to it byte for byte.
                        if raw_writer is not None and entry.kind == KEY_DOWNLOAD_FILE:
                            attributes["decoded_body_path"] = raw_writer(decoded, "body.bin")

                        text, encoding = decode_text_strict(decoded, entry.content_type)
                        attributes["text_encoding"] = encoding
                        if text is not None:
                            parsed = try_parse_json(text)
                            if parsed is not None:
                                attributes["json_parse_status"] = "PARSED"
                                message_payload = parsed
                                _enrich_from_json(entry, attributes, parsed)
                            else:
                                attributes["json_parse_status"] = "NOT_JSON"
                                attributes["text_preview"] = text[:4096]
                        else:
                            attributes["json_parse_status"] = "BINARY"
                    elif result.status == DECODE_LIMITED:
                        attributes["json_parse_status"] = "DECODE_LIMITED"
                    else:
                        attributes["json_parse_status"] = "DECODE_FAILED"

                    created = attributes.get("conversation_created_at")
                    timestamp = from_iso8601(created) if created else None

            payload = {
                "key": entry.key,
                "variant": entry.variant,
                "meta_location": entry.meta_location,
                "body_location": entry.body_location,
            }
            records.append(
                EvidenceRecord(
                    evidence_id=make_evidence_id(FAMILY_CACHE, source_path, locator, payload),
                    artifact="Cache",
                    artifact_family=FAMILY_CACHE,
                    source_path=source_path,
                    # The exact cache file holding this entry (data_N or f_xxxxxx).
                    artifact_path=_entry_file_path(
                        source_path, entry.body_location, entry.meta_location
                    ),
                    volume_id=volume_id,
                    record_locator=locator,
                    timestamp=timestamp,
                    account_uuid=attributes.get("account_uuid"),
                    organization_uuid=entry.organization_uuid,
                    conversation_uuid=entry.conversation_uuid
                    or attributes.get("conversation_uuid"),
                    summary=summary,
                    attributes=attributes,
                )
            )
            if message_payload is not None:
                records[-1].attributes["_json"] = message_payload
    except Exception as exc:
        errors.append(f"cache iteration: {type(exc).__name__}: {exc}")
    finally:
        ccl.close_cache(cache)

    status = ST_PARSED if not errors else (ST_PARTIAL if records else ST_FAILED)
    return records, ParseStatus(
        artifact="Cache",
        family=FAMILY_CACHE,
        status=status,
        source_path=source_path,
        record_count=len(records),
        error_count=len(errors),
        message="; ".join(errors[:5])
        or f"keys={total_keys} claude={claude_keys} hydrated={hydrated}",
    )


def _entry_file_path(source_path: str, *locations: str) -> str:
    """Cache_Data/<file> from a CCL location string ("data_3@1234", "f_00001a@0").

    The body location is preferred (the file that holds the response); the
    metadata location is the fallback. Empty when neither names a file.
    """
    for location in locations:
        name = (location or "").rsplit("@", 1)[0].strip()
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
        if name and name not in ("None",):
            return f"{source_path.rstrip('/')}/{name}"
    return ""


def _enrich_from_json(entry: CacheIndexEntry, attributes: dict[str, Any], parsed: Any) -> None:
    """Pull identifiers out of a decoded Claude API body."""
    if isinstance(parsed, dict):
        uuid = parsed.get("uuid")
        if isinstance(uuid, str) and entry.kind == KEY_CONVERSATION:
            attributes["conversation_uuid"] = uuid.lower()
        if isinstance(parsed.get("name"), str):
            attributes["conversation_title"] = parsed["name"]
        if isinstance(parsed.get("created_at"), str):
            attributes["conversation_created_at"] = parsed["created_at"]
        if isinstance(parsed.get("updated_at"), str):
            attributes["conversation_updated_at"] = parsed["updated_at"]
        if isinstance(parsed.get("model"), str):
            attributes["conversation_model"] = parsed["model"]
        if parsed.get("is_temporary") is not None:
            attributes["is_temporary"] = parsed.get("is_temporary")
        if parsed.get("current_leaf_message_uuid"):
            attributes["current_leaf_message_uuid"] = parsed["current_leaf_message_uuid"]

        # Share-link snapshot object (E07-02 direct evidence).
        snapshot = parsed.get("snapshot")
        if isinstance(snapshot, dict):
            attributes["snapshot_uuid"] = snapshot.get("uuid")
            attributes["snapshot_name"] = snapshot.get("snapshot_name") or snapshot.get("name")
            attributes["snapshot_created_at"] = snapshot.get("created_at")
            attributes["snapshot_conversation_uuid"] = snapshot.get("conversation_uuid")
            creator = snapshot.get("created_by") or snapshot.get("creator")
            if isinstance(creator, dict):
                attributes["snapshot_creator_uuid"] = creator.get("uuid")
                attributes["snapshot_creator_name"] = creator.get("full_name") or creator.get(
                    "display_name"
                )
        account = parsed.get("account")
        if isinstance(account, dict) and isinstance(account.get("uuid"), str):
            attributes["account_uuid"] = account["uuid"].lower()
