"""Claude-relevance gate for filesystem files."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterable

from ..model.entities import FAMILY_CACHE, FAMILY_HISTORY, EvidenceStore

BASIS_HISTORY_TARGET = "history_target_path"
BASIS_ZONE = "claude_zone_identifier"
BASIS_CACHE_RESPONSE = "claude_cache_response"
BASIS_USN_CHAIN = "usn_chain_same_frn"

def norm_path(path: str) -> str:
    text = str(path or "").replace("\\", "/")
    if len(text) > 1 and text[1] == ":":
        text = text[2:]
    return text.lower().lstrip("/").rstrip("/")

def zone_is_claude(zone) -> bool:
    if zone is None:
        return False
    if getattr(zone, "conversation_uuid", None):
        return True
    urls = f"{getattr(zone, 'host_url', '') or ''} {getattr(zone, 'referrer_url', '') or ''}"
    return "claude.ai" in urls.lower() or "claude.com" in urls.lower()

@dataclass
class ClaudeScope:
    target_paths: set[str] = field(default_factory=set)
    target_names: set[str] = field(default_factory=set)

    cache_bodies: dict[int, list[Path]] = field(default_factory=dict)

    @classmethod
    def from_store(cls, store: EvidenceStore) -> "ClaudeScope":
        scope = cls()
        for record in store.by_family(FAMILY_HISTORY):
            attrs = record.attributes
            if attrs.get("subtype") != "download":
                continue
            for key in ("target_path", "current_path"):
                value = attrs.get(key)
                if value:
                    scope.target_paths.add(norm_path(value))
                    scope.target_names.add(str(value).replace("\\", "/").rsplit("/", 1)[-1])
        for record in store.by_family(FAMILY_CACHE):
            attrs = record.attributes
            if attrs.get("key_kind") != "download_file":
                continue
            size = attrs.get("decoded_size")
            body = attrs.get("decoded_body_path")
            if isinstance(size, int) and size > 0 and body and Path(body).exists():
                scope.cache_bodies.setdefault(size, []).append(Path(body))
        return scope

    def path_basis(self, path: str) -> str:
        return BASIS_HISTORY_TARGET if path and norm_path(path) in self.target_paths else ""

    def zone_basis(self, zone) -> str:
        return BASIS_ZONE if zone_is_claude(zone) else ""

    def size_is_candidate(self, size: int | None) -> bool:
        return isinstance(size, int) and size > 0 and size in self.cache_bodies

    def content_basis(
        self, size: int | None, open_stream: Callable[[], BinaryIO | None]
    ) -> str:
        from ..util.common import stream_equals_file

        if not self.size_is_candidate(size):
            return ""
        for body in self.cache_bodies[size]:
            stream = open_stream()
            try:
                if stream_equals_file(stream, body):
                    return BASIS_CACHE_RESPONSE
            finally:
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
        return ""

def usn_chain_basis(
    volume_id: str, destination_path: str, lifecycles: dict, scope: ClaudeScope,
) -> str:
    target = norm_path(destination_path)
    if not target:
        return ""
    for life in lifecycles.values():
        if volume_id and life.volume_id and life.volume_id != volume_id:
            continue
        paths = {norm_path(e.new_path) for e in life.events if e.new_path}
        if target not in paths:
            continue
        chain = paths | {norm_path(e.old_path) for e in life.events if e.old_path}
        if chain & scope.target_paths:
            return BASIS_USN_CHAIN
    return ""

def interesting_usn_names(scope: ClaudeScope, verified_names: Iterable[str]) -> set[str]:
    names = set(scope.target_names)
    names.update(n for n in verified_names if n)
    return names

def interesting_usn_frns(verified_frns: Iterable[str]) -> set[str]:
    return {f for f in verified_frns if f and "-" in f}

def gate_recycle_entries(volume, entries, scope: ClaudeScope) -> tuple[list, int]:
    verified = []
    content_candidates = 0
    for entry in entries:
        basis = scope.path_basis(entry.original_path) or scope.zone_basis(entry.zone)
        if not basis and entry.r_path and scope.size_is_candidate(entry.r_logical_size):
            content_candidates += 1
            record = volume.get(entry.r_path)
            if record is not None:
                basis = scope.content_basis(entry.r_logical_size, lambda: volume.open_record(record))
        if basis:
            entry.claude_link_basis = basis
            verified.append(entry)
    return verified, content_candidates

def gate_recycle_by_usn(entries, volume_id: str, pairs, scope: ClaudeScope) -> list:
    from .file_analysis import build_lifecycles

    pending = [e for e in entries if not e.claude_link_basis]
    if not pending or not pairs:
        return []
    chains = build_lifecycles(pairs, [], [])
    accepted = []
    for entry in pending:
        basis = usn_chain_basis(volume_id, entry.r_path, chains, scope)
        if basis:
            entry.claude_link_basis = basis
            accepted.append(entry)
    return accepted
