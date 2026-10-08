"""The only analysis outputs: timeline.csv and recovered_conversations.csv."""
from __future__ import annotations

import csv
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..analysis.rules import ACTION_LABELS
from ..analysis.summaries import summarize_record
from ..model.entities import (
    VERDICT_CONFIRMED, VERDICT_SUSPECTED, ConversationMessage, EvidenceRecord, EvidenceStore, FinalEvent,
)
from ..util.common import sort_key, to_kst_display

MODEL_NAME = "claude-web"

TIMELINE_FILE = "timeline.csv"
CONVERSATIONS_FILE = "recovered_conversations.csv"
RESULT_FILES = (TIMELINE_FILE, CONVERSATIONS_FILE)

# Two header names intentionally retain their trailing space.
TIMELINE_COLUMNS: list[str] = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
    "Artifact_path", "Artifact_details ",]

CONVERSATION_COLUMNS: list[str] = [
    "Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid", "parent_message_uuid",
    "message order", "role", "content", "Artifact_path",
]

EXPORTED_VERDICTS = (VERDICT_CONFIRMED, VERDICT_SUSPECTED)

PATH_SEPARATOR = "|"
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_FIELD_LIMIT = 2**31 - 1

_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

_LABELLED_UUID = re.compile(r"(?:^|,[ \t]*)[^,=\n]*(?:UUID|uuid)[ \t]*=[ \t]*" + _UUID.pattern)

_JSON_UUID = re.compile(r'("(?:[^"\\]|\\.)*"[ \t]*:[ \t]*)"' + _UUID.pattern + '"')
UUID_PLACEHOLDER = "[uuid]"

EMPTY_PLACEHOLDER = "-"

def strip_uuids(text: str) -> str:
    if not text or not _UUID.search(text):
        return text

    cleaned = _LABELLED_UUID.sub("", text)

    cleaned = _JSON_UUID.sub(lambda m: m.group(1) + '"' + UUID_PLACEHOLDER + '"', cleaned)
    cleaned = _UUID.sub(UUID_PLACEHOLDER, cleaned)

    cleaned = re.sub(r"\([ \t]*,[ \t]*", "(", cleaned)
    cleaned = re.sub(r",[ \t]*(?=,)", "", cleaned)
    cleaned = re.sub(r"[ \t]+,", ",", cleaned)
    cleaned = re.sub(r"(?m)^[,\t ]+", "", cleaned)
    return re.sub(r"(?m)[,\t ]+$", "", cleaned)

class CsvExportError(RuntimeError):
    pass

class OutputDirectoryError(RuntimeError):
    pass

@dataclass
class ArtifactPathResolver:
    store: EvidenceStore
    drive_letters: dict[str, str]

    def path_of(self, record: EvidenceRecord | None) -> str:
        if record is None:
            return ""
        logical = str(record.artifact_path or "")

        if not logical.startswith("/"):
            return ""
        letter = self.drive_letters.get(record.volume_id, "")
        windows = logical.replace("/", "\\")
        return f"{letter}:{windows}" if letter else windows

    def paths_for(self, evidence_ids: Iterable[str]) -> str:
        paths = {self.path_of(self.store.get(eid)) for eid in evidence_ids}
        return PATH_SEPARATOR.join(sorted(p for p in paths if p))

    def evidence_cells(self, evidence: Iterable[tuple[str, str]]) -> tuple[str, str]:
        order: list[str] = []
        first: dict[str, EvidenceRecord] = {}
        explicit: dict[str, list[str]] = defaultdict(list)
        for evidence_id, line in evidence:
            record = self.store.get(evidence_id)
            path = self.path_of(record)
            if not path:
                continue
            if path not in first:
                order.append(path)
                first[path] = record
            if line and line not in explicit[path]:
                explicit[path].append(line)
        lines = [_merge_lines(explicit[p]) or summarize_record(first[p]) for p in order]
        return PATH_SEPARATOR.join(order), "\n".join(lines)

def _merge_lines(lines: list[str]) -> str:
    if not lines:
        return ""
    head = lines[0]
    prefix = head[: head.index("] ") + 2] if head.startswith("[") and "] " in head else ""
    rest = [line[len(prefix):] if prefix and line.startswith(prefix) else line for line in lines[1:]]
    return "; ".join([head, *rest]).replace("\n", " ")

def build_timeline_rows(
    events: Iterable[FinalEvent], resolver: ArtifactPathResolver
) -> list[list[str]]:
    kept = [e for e in events if e.verdict in EXPORTED_VERDICTS]
    for event in kept:
        if event.action_label != ACTION_LABELS.get(event.action_code):
            raise CsvExportError(
                f"event {event.action_id}: {event.action_label!r} is not the catalogue "
                f"name for {event.action_code}"
            )
    kept.sort(key=lambda e: (sort_key(e.timestamp), e.action_label, e.action_id))
    rows = []
    for event in kept:
        paths, details = resolver.evidence_cells(event.evidence)
        rows.append([
            MODEL_NAME, to_kst_display(event.timestamp), event.action_label,

            strip_uuids(event.action_detail), event.verdict, paths,
            "\n".join(strip_uuids(line) for line in details.split("\n")) if details else "",
        ])
    return rows

def _message_key(message: ConversationMessage) -> tuple:
    return (sort_key(message.timestamp), message.message_uuid or "", message.content or "")

def message_order(messages: Sequence[ConversationMessage]) -> list[ConversationMessage]:
    by_uuid: dict[str, ConversationMessage] = {}
    for message in messages:
        if message.message_uuid and message.message_uuid not in by_uuid:
            by_uuid[message.message_uuid] = message

    children: dict[str, list[ConversationMessage]] = defaultdict(list)
    roots: list[ConversationMessage] = []
    for message in messages:
        parent = message.parent_message_uuid or ""
        if parent and parent in by_uuid and parent != message.message_uuid:
            children[parent].append(message)
        else:
            roots.append(message)
    for siblings in children.values():
        siblings.sort(key=_message_key)

    ordered: list[ConversationMessage] = []
    seen: set[int] = set()

    def walk(start: ConversationMessage) -> None:
        stack = [start]
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            ordered.append(node)

            for child in reversed(children.get(node.message_uuid, []) if node.message_uuid else []):
                if id(child) not in seen:
                    stack.append(child)

    for root in sorted(roots, key=_message_key):
        walk(root)
    for message in sorted(messages, key=_message_key):
        if id(message) not in seen:
            walk(message)
    return ordered

def build_conversation_rows(
    messages: Iterable[ConversationMessage], resolver: ArtifactPathResolver
) -> list[list[str]]:
    by_conversation: dict[str, list[ConversationMessage]] = defaultdict(list)
    for message in messages:
        by_conversation[message.conversation_uuid or ""].append(message)

    def conversation_key(item: tuple[str, list[ConversationMessage]]) -> tuple:
        uuid, items = item
        return (min(sort_key(m.timestamp) for m in items), uuid)

    rows: list[list[str]] = []
    for uuid, items in sorted(by_conversation.items(), key=conversation_key):
        for position, message in enumerate(message_order(items), start=1):
            rows.append(
                [
                    MODEL_NAME, to_kst_display(message.timestamp), uuid, message.conversation_title or "",
                    message.message_uuid or "", message.parent_message_uuid or "", str(position),
                    message.role or "", message.content or "", resolver.paths_for(message.evidence_ids),
                ]
            )
    return rows

def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if "\x00" in text:
        text = text.replace("\x00", "\\x00")
    if not text:
        return EMPTY_PLACEHOLDER
    if text.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    return text

def write_csv(path: Path, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> int:
    path = Path(path)
    temp = path.with_name(f".{path.name}.partial")
    rows = [[_cell(v) for v in row] for row in rows]
    for row in rows:
        if len(row) != len(columns):
            raise CsvExportError(f"{path.name}: row has {len(row)} cells, expected {len(columns)}")
    try:
        with temp.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
            writer.writerow(columns)
            writer.writerows(rows)
        _verify(temp, columns, rows)
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            pass
        raise
    return len(rows)

def _verify(path: Path, columns: Sequence[str], rows: list[list[str]]) -> None:
    raw = path.read_bytes()
    if not raw.startswith(b"\xef\xbb\xbf"):
        raise CsvExportError(f"{path.name}: UTF-8 BOM missing")

    csv.field_size_limit(_FIELD_LIMIT)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        read = list(csv.reader(fh))
    if not read or read[0] != list(columns):
        raise CsvExportError(f"{path.name}: header mismatch after readback")
    if read[1:] != rows:
        raise CsvExportError(f"{path.name}: data rows differ after readback")

def prepare_output_dir(output: Path, overwrite: bool = False) -> list[str]:
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    existing = [name for name in RESULT_FILES if (output / name).exists()]
    if existing and not overwrite:
        raise OutputDirectoryError(
            f"{output} already contains {', '.join(existing)}; "
            "choose another folder or pass --overwrite to replace them"
        )
    return sorted(p.name for p in output.iterdir() if p.name not in RESULT_FILES)

def write_results(
    output: Path, timeline_rows: list[list[str]], conversation_rows: list[list[str]],
) -> dict[str, int]:
    output = Path(output)
    return {
        TIMELINE_FILE: write_csv(output / TIMELINE_FILE, TIMELINE_COLUMNS, timeline_rows),
        CONVERSATIONS_FILE: write_csv(output / CONVERSATIONS_FILE, CONVERSATION_COLUMNS, conversation_rows),
    }
