"""The only analysis outputs: timeline.csv and recovered_conversations.csv.

Both files are UTF-8 with BOM (Excel-safe Korean), have no index column, use
standard RFC 4180 quoting (a comma, quote or line break inside a value stays in
one cell), always carry their fixed header even with zero rows, and are
written to a temporary name, read back and verified, then atomically renamed.
Row order is fully deterministic for the same input.

Artifact paths are the logical paths inside the disk image (e.g.
``C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History``),
never the analyst machine's staging copies. A path that cannot be established
is left empty rather than invented.
"""
from __future__ import annotations

import csv
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..analysis.rules import ACTION_LABELS
from ..model.entities import (
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    EvidenceRecord,
    EvidenceStore,
    FinalEvent,
)
from ..model.entities import (
    ROLE_ASSISTANT,
    ROLE_SYSTEM,
    ROLE_USER,
    ConversationMessage,
)
from ..util.common import sort_key, to_kst_display

MODEL_NAME = "claude-web"

TIMELINE_FILE = "timeline.csv"
CONVERSATIONS_FILE = "recovered_conversations.csv"
RESULT_FILES = (TIMELINE_FILE, CONVERSATIONS_FILE)

# NOTE: "Behavior_details " and "Artifact_details " end with one ASCII space,
# exactly as in the reference CSV; the header must match it byte for byte.
TIMELINE_COLUMNS: list[str] = [
    "Model",
    "Timestamp",
    "User_behavior",
    "Behavior_details ",
    "Verdict",
    "Artifact_path",
    "Artifact_details ",
]

CONVERSATION_COLUMNS: list[str] = [
    "Model",
    "timestamp",
    "conversation_uuid",
    "conversation_title",
    "message_uuid",
    "parent_message_uuid",
    "message order",
    "role",
    "content",
    "Artifact_path",
]

# Only these verdicts are exported; 판단불가 never reaches an output file.
EXPORTED_VERDICTS = (VERDICT_CONFIRMED, VERDICT_SUSPECTED)

RECOVERY_COMPLETE = "완전 복구"
RECOVERY_PARTIAL = "부분 복구"

PATH_SEPARATOR = "|"
_KNOWN_ROLES = (ROLE_USER, ROLE_ASSISTANT, ROLE_SYSTEM)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_FIELD_LIMIT = 2**31 - 1   # C long limit on Windows

# A real UUID value, e.g. f218da89-507d-4665-94b2-887aff8214f8. The literal
# text "<uuid>" that a user typed into a prompt is not one and stays untouched.
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# A labelled pair as the summaries render it: "대화 UUID=<uuid>".
_LABELLED_UUID = re.compile(r"(?:^|,[ \t]*)[^,=\n]*(?:UUID|uuid)[ \t]*=[ \t]*" + _UUID.pattern)
# A JSON preview pair: "accountUuid":"<uuid>", "eventId":"<uuid>", …
_JSON_UUID = re.compile(r'("(?:[^"\\]|\\.)*"[ \t]*:[ \t]*)"' + _UUID.pattern + '"')
UUID_PLACEHOLDER = "[uuid]"
# Written instead of an empty cell (no defensible time, no artifact path, …).
EMPTY_PLACEHOLDER = "-"


def strip_uuids(text: str) -> str:
    """Remove real UUID values from a timeline cell, keeping everything else.

    Display layer only: evidence records, the data model, detectors and the
    correlator keep every UUID, which is what links accounts, conversations,
    messages and files during analysis. Only what timeline.csv shows is
    scrubbed, and only there -- recovered_conversations.csv keeps its UUIDs.
    """
    if not text or not _UUID.search(text):
        return text
    # A labelled pair carries no information once its value is gone.
    cleaned = _LABELLED_UUID.sub("", text)
    # Elsewhere (URLs, JSON previews, paths) the surrounding text is kept.
    cleaned = _JSON_UUID.sub(lambda m: m.group(1) + '"' + UUID_PLACEHOLDER + '"', cleaned)
    cleaned = _UUID.sub(UUID_PLACEHOLDER, cleaned)
    # Tidy separators left behind by a removed pair.
    cleaned = re.sub(r"\([ \t]*,[ \t]*", "(", cleaned)
    cleaned = re.sub(r",[ \t]*(?=,)", "", cleaned)
    cleaned = re.sub(r"[ \t]+,", ",", cleaned)
    cleaned = re.sub(r"(?m)^[,\t ]+", "", cleaned)
    return re.sub(r"(?m)[,\t ]+$", "", cleaned)


class CsvExportError(RuntimeError):
    pass


class OutputDirectoryError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# artifact paths
# ---------------------------------------------------------------------------

@dataclass
class ArtifactPathResolver:
    """EvidenceRecord -> logical Windows path inside the image.

    `drive_letters` maps a volume identifier to its drive letter when it is
    known (the volume holding the Windows installation is ``C``). On a volume
    whose letter is unknown the volume-relative path is used, without a letter.
    """

    store: EvidenceStore
    drive_letters: dict[str, str]

    def path_of(self, record: EvidenceRecord | None) -> str:
        if record is None:
            return ""
        logical = str(record.artifact_path or "")
        # Image-internal paths are volume-relative and "/"-rooted; anything else
        # (e.g. an analyst-side staging path) is not a disk-image path.
        if not logical.startswith("/"):
            return ""
        letter = self.drive_letters.get(record.volume_id, "")
        windows = logical.replace("/", "\\")
        return f"{letter}:{windows}" if letter else windows

    def paths_for(self, evidence_ids: Iterable[str]) -> str:
        paths = {self.path_of(self.store.get(eid)) for eid in evidence_ids}
        return PATH_SEPARATOR.join(sorted(p for p in paths if p))


# ---------------------------------------------------------------------------
# timeline.csv
# ---------------------------------------------------------------------------

def build_timeline_rows(
    events: Iterable[FinalEvent], resolver: ArtifactPathResolver
) -> list[list[str]]:
    """One row per 확정 / 의심 event; 판단불가 is never exported."""
    kept = [e for e in events if e.verdict in EXPORTED_VERDICTS]
    for event in kept:
        if event.action_label != ACTION_LABELS.get(event.action_code):
            raise CsvExportError(
                f"event {event.action_id}: {event.action_label!r} is not the catalogue "
                f"name for {event.action_code}"
            )
    kept.sort(key=lambda e: (sort_key(e.timestamp), e.action_label, e.action_id))
    return [
        [
            MODEL_NAME,
            to_kst_display(event.timestamp),
            event.action_label,
            # UUIDs stay on the event; only the exported text is scrubbed.
            strip_uuids(event.action_detail),
            event.verdict,
            resolver.paths_for(event.detail_refs),
            strip_uuids("\n".join(line for line in event.artifact_details if line)),
        ]
        for event in kept
    ]


# ---------------------------------------------------------------------------
# recovered_conversations.csv
# ---------------------------------------------------------------------------

def _message_key(message: ConversationMessage) -> tuple:
    """Deterministic tie-break: time, then message uuid, then content."""
    return (sort_key(message.timestamp), message.message_uuid or "", message.content or "")


def message_order(messages: Sequence[ConversationMessage]) -> list[ConversationMessage]:
    """Reconstruct the conversation order of ONE conversation's messages.

    Depth-first from the root(s) along parent_message_uuid, siblings (branches
    such as retries) ordered by timestamp then message_uuid. A message whose
    parent is absent, empty or itself is a root. Messages left unreached by
    the tree walk (a parent cycle) are appended in timestamp / message_uuid
    order, each followed by its own unreached descendants.
    """
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
            # Reverse so the earliest child is visited first.
            for child in reversed(children.get(node.message_uuid, []) if node.message_uuid else []):
                if id(child) not in seen:
                    stack.append(child)

    for root in sorted(roots, key=_message_key):
        walk(root)
    for message in sorted(messages, key=_message_key):
        if id(message) not in seen:
            walk(message)
    return ordered


def recovery_status(message: ConversationMessage) -> str:
    """완전 복구 only when identity, role and full content were all recovered.

    This measures completeness of the recovered data, not whether the
    conversation was deleted (a Cache hit alone is not a deletion).
    """
    attrs = message.attributes or {}
    truncated = bool(
        attrs.get("recovery_status") == RECOVERY_PARTIAL
        or attrs.get("truncated")
        or attrs.get("content_truncated")
    )
    complete = (
        bool(message.conversation_uuid)
        and bool(message.message_uuid)
        and message.role in _KNOWN_ROLES
        and bool((message.content or "").strip())
        and not truncated
    )
    return RECOVERY_COMPLETE if complete else RECOVERY_PARTIAL


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
        # Numbering restarts at 1 for every conversation.
        for position, message in enumerate(message_order(items), start=1):
            rows.append(
                [
                    MODEL_NAME,
                    to_kst_display(message.timestamp),
                    uuid,
                    message.conversation_title or "",
                    message.message_uuid or "",
                    message.parent_message_uuid or "",
                    str(position),
                    message.role or "",
                    message.content or "",
                    resolver.paths_for(message.evidence_ids),
                ]
            )
    return rows


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------

def _cell(value: Any) -> str:
    """Excel-safe cell text: NUL made visible, formulas neutralised.

    Line breaks and commas are kept as-is; RFC 4180 quoting keeps them inside
    the cell. A cell with no value is written as EMPTY_PLACEHOLDER so a blank
    is visible in the report instead of an empty field.
    """
    text = "" if value is None else str(value)
    if "\x00" in text:
        text = text.replace("\x00", "\\x00")
    if not text:
        # Returned before the formula guard: "-" must stay "-", not "'-".
        return EMPTY_PLACEHOLDER
    if text.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    return text


def write_csv(path: Path, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> int:
    """Write, read back, verify, then atomically publish one CSV. Returns row count."""
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
    # Messages can exceed the csv module's default 128 KiB field limit.
    csv.field_size_limit(_FIELD_LIMIT)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        read = list(csv.reader(fh))
    if not read or read[0] != list(columns):
        raise CsvExportError(f"{path.name}: header mismatch after readback")
    if read[1:] != rows:
        raise CsvExportError(f"{path.name}: data rows differ after readback")


def prepare_output_dir(output: Path, overwrite: bool = False) -> list[str]:
    """Create the output folder; never delete anything.

    A previous run's result file is replaced only with --overwrite. Any other
    file in the folder is left untouched. Returns the names of such unrelated
    entries so the caller can mention them.
    """
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
    output: Path,
    timeline_rows: list[list[str]],
    conversation_rows: list[list[str]],
) -> dict[str, int]:
    output = Path(output)
    return {
        TIMELINE_FILE: write_csv(output / TIMELINE_FILE, TIMELINE_COLUMNS, timeline_rows),
        CONVERSATIONS_FILE: write_csv(
            output / CONVERSATIONS_FILE, CONVERSATION_COLUMNS, conversation_rows
        ),
    }
