"""CLI (argparse · 화면 출력 · 종료 코드)."""
from __future__ import annotations
import argparse
import copy
import csv
import gc
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .image import ImageOpenError, ImageSource, open_image_source
from .output.csv_writer import CSV_DEBUG_FILES, CSV_FINAL_FILES, write_result_csv
from .output.debug import write_result_json
from .parser import run
from . import bitlocker, live
from .source import DirectorySource, SourcePathError, normalize_source_path


# =============================================================================
# 13. CLI / main()
# =============================================================================
# 종료 코드: 0 = 분석 완료 (결과 0건·Artifact NOT_PRESENT 포함), 2 = 잘못된 인자·입력 경로, 1 = 예상하지 못한 오류.
# 화면: 요약 + Event 표 (저장된 UTC/KST 그대로, 없으면 N/A) + 복구된 대화 상세 (실제로 복구된 메시지 본문은 전체 출력,
#       메시지가 없으면 NOT RECOVERED). Record·Evidence 는 JSON 에서 확인한다. 토큰·쿠키·OAuth 값은 화면에도 넣지 않는다.
# 결과 JSON 은 --dir 폴더 밖에만 쓴다 (원본 Source 에 쓰기 방지). 기존 파일은 --overwrite 없이 덮어쓰지 않는다.

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
MESSAGE_RECOVERY_STATUS = "Cache conversation API responses only (Blockfile; identity / br)"
CONVERSATION_SCOPE = "Local Storage .log + Cache conversation responses (.ldb not analyzed)"
_ARTIFACT_LABELS = {"history": "History", "cache": "Cache"}
_LEVELDB_LABELS = {"local_storage": "Local Storage", "session_storage": "Session Storage"}


class CliUsageError(Exception):
    """잘못된 인자·입력 경로 (종료 코드 2)."""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chatgpt_web_parser.py",
        description="ChatGPT Web Artifact Parser v0.1 - Chrome History + Local Storage .log (folder input) "
                    "-> History rule events + conversation residue -> JSON. "
                    "Without --history, Chrome Stable profiles under Users/*/AppData/Local/Google/Chrome/User Data are discovered.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dir", metavar="FOLDER", help="folder to analyze (copied/mounted Chrome data). read-only")
    source.add_argument("--image", metavar="IMAGE",
                        help="DD/RAW or E01/EWF disk image (read-only). Needs pytsk3; E01 also needs pyewf")
    source.add_argument("--live", action="store_true",
                        help="collect Chrome artifacts from this Windows PC (read-only copy) and analyze them")
    parser.add_argument("--live-work-dir", metavar="FOLDER",
                        help="where --live keeps its working copy (default: a temporary folder removed afterwards)")
    parser.add_argument("--key-material", metavar="KEY",
                        help="BitLocker volume key for --image: recovery:<48 digits> | passphrase:<text> | "
                             "bek:<path> | fvek:<hex>. Clear-key / suspended volumes open without a key. "
                             f"Can also be given via the {bitlocker.KEY_ENV} environment variable "
                             "(keeps the key out of the command line). The key is never logged or written to output.")
    parser.add_argument("--history", metavar="RELATIVE_PATH",
                        help="analyze only this History file (relative to --dir, e.g. Default/History). "
                             "omit to auto-discover Chrome profiles")
    parser.add_argument("--out", metavar="JSON_PATH",
                        help="optional result JSON path (must be outside --dir). omit to write no JSON")
    parser.add_argument("--csv-dir", metavar="CSV_DIR",
                        help="write timeline.csv and recovered_conversations.csv here (must be outside --dir)")
    parser.add_argument("--debug-output", action="store_true",
                        help="also write the development CSVs "
                             "(coverage/records/events/conversations/messages) into --csv-dir")
    parser.add_argument("--overwrite", action="store_true",
                        help="replace --out (and the CSV files this run writes into --csv-dir) if they already exist")
    return parser


def _is_within(path: Path, root: Path) -> bool:
    candidate, base = os.path.normcase(str(path)), os.path.normcase(str(root))
    try:
        return os.path.commonpath([candidate, base]) == base
    except ValueError:  # 다른 드라이브
        return False


def _row(label: str, value: Any, width: int) -> str:
    return f"{label.ljust(width)}: {value}"


NOT_AVAILABLE = "N/A"


def _table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    """고정 폭 표 (마지막 열은 폭 맞춤 없음)."""
    widths = [max(len(header), *(len(row[i]) for row in rows)) + 2 for i, header in enumerate(headers[:-1])]

    def render(values: tuple[str, ...]) -> str:
        return "".join(value.ljust(width) for value, width in zip(values, widths)) + values[-1]

    last_width = max(len(headers[-1]), *(len(row[-1]) for row in rows))
    return [render(headers), "-" * (sum(widths) + last_width), *(render(row) for row in rows)]


def _event_lines(events: list[Event]) -> list[str]:
    """Event 마다 저장된 timestamp_utc / timestamp_kst 를 그대로 표시한다 (새로 계산하지 않음, 없으면 N/A)."""
    if not events:
        return ["(none)"]
    rows = [(event.timestamp_utc or NOT_AVAILABLE, event.timestamp_kst or NOT_AVAILABLE, event.action,
             event.action_status, event.confidence) for event in events]
    return _table(("UTC", "KST", "ACTION", "STATUS", "CONFIDENCE"), rows)


def _conversation_detail_lines(conversations: list[RecoveredConversation]) -> list[str]:
    """
    복구된 대화별 상세. 메시지가 있으면 role·시각과 함께 content 전체를 그대로 출력한다 (요약·절단·생략 없음).
    메시지가 없으면 NOT RECOVERED 로만 표시한다 — 메시지 내용을 만들지 않는다.
    """
    if not conversations:
        return ["(none)"]
    lines: list[str] = []
    for number, conversation in enumerate(conversations, 1):
        lines += [f"Conversation #{number}",
                  _row("  ID", conversation.conversation_id or NOT_AVAILABLE, 18),
                  _row("  Title", NOT_AVAILABLE if conversation.title is None else conversation.title, 18),
                  _row("  Status", conversation.recovery_status, 18),
                  _row("  Created UTC", conversation.create_time_utc or NOT_AVAILABLE, 18),
                  _row("  Created KST", conversation.create_time_kst or NOT_AVAILABLE, 18),
                  _row("  Messages", len(conversation.messages), 18),
                  _row("  History Links", ", ".join(conversation.correlated_record_ids) or "none", 18)]
        if not conversation.messages:
            lines += [_row("  Message Content", "NOT RECOVERED", 18), ""]
            continue
        ordered = sorted(conversation.messages,  # sequence_index 순, 없는 메시지는 복구 순서대로 뒤에
                         key=lambda message: (message.sequence_index is None, message.sequence_index or 0))
        for index, message in enumerate(ordered, 1):
            lines += ["", f"  [{message.role}] message #{index}",
                      _row("    Status", message.recovery_status, 12),
                      _row("    UTC", message.timestamp_utc or NOT_AVAILABLE, 12),
                      _row("    KST", message.timestamp_kst or NOT_AVAILABLE, 12),
                      "    Content :",
                      NOT_AVAILABLE if message.content is None else message.content]
        lines.append("")
    return lines


def format_summary(result: ParseResult, out_path: str | os.PathLike[str] | None = None, *,
                   auto_discovery: bool = False, csv_paths: list[Path] | None = None) -> str:
    """
    CLI 화면 출력. Record·Evidence 내용은 넣지 않는다 (JSON 에서 확인).
    Event 는 시각(UTC/KST)과 함께 한 줄씩, 복구된 대화는 상세와 복구된 메시지 본문 전체를 표시한다.
    auto_discovery=True 이면 Chrome Profile 표를 넣는다. csv_paths 가 있으면 생성한 CSV 경로도 표시한다.
    """
    rule = "=" * 60
    mode = "Auto discovery (Users/*/AppData/Local/Google/Chrome/User Data)" if auto_discovery else "Explicit --history"
    lines = [rule, " ChatGPT Web Artifact Parser", rule, "", "[INPUT]",
             _row("Type", "DD/RAW" if result.input.kind == "dd" else result.input.kind.capitalize(), 11),
             _row("Source", result.input.path, 11)]
    if result.input.partition is not None:
        lines.append(_row("Partition", result.input.partition, 11))
    if result.input.filesystem is not None:
        lines.append(_row("Filesystem", result.input.filesystem, 11))
    lines += [_row("Mode", mode, 11), _row("Timezone", "UTC / KST (+09:00)", 11), ""]
    if auto_discovery:
        lines.append("[CHROME PROFILES]")
        histories = [c for c in result.coverage if c.artifact_type == "history"]  # Profile 당 1건
        if histories:
            user_width = max(len("User"), *(len(c.os_user or "-") for c in histories)) + 3
            profile_width = max(len("Profile"), *(len(c.browser_profile or "-") for c in histories)) + 3
            lines.append("User".ljust(user_width) + "Profile".ljust(profile_width) + "History")
            lines.append("-" * (user_width + profile_width + len("NOT_PRESENT")))
            for coverage in histories:
                history = "NOT_PRESENT" if coverage.status == "NOT_PRESENT" else "FOUND"
                lines.append((coverage.os_user or "-").ljust(user_width)
                             + (coverage.browser_profile or "-").ljust(profile_width) + history)
        else:
            lines.append("(none found)")
        lines.append("")
    lines.append("[ARTIFACTS]")
    previous_owner: tuple[str | None, str | None] | None = None
    for coverage in result.coverage:
        owner = (coverage.os_user, coverage.browser_profile)
        if auto_discovery and owner != previous_owner:
            lines.append(f"{coverage.os_user} / {coverage.browser_profile}")
        previous_owner = owner
        if coverage.status == "NOT_SUPPORTED":
            text = f"{coverage.status} (not analyzed)"
        else:
            text = f"{coverage.status} ({coverage.record_count} ChatGPT records)"
        if coverage.warnings:
            text += f" [warnings: {len(coverage.warnings)}]"
        if coverage.artifact_type in _LEVELDB_LABELS:  # LevelDB 폴더는 파일마다 한 줄
            label = _LEVELDB_LABELS[coverage.artifact_type]
            lines.append(_row(label, f"{coverage.source_path.rpartition('/')[2]} {text}", len(label)))
        else:
            lines.append(_row(_ARTIFACT_LABELS.get(coverage.artifact_type, coverage.artifact_type), text, 11))
    if not result.coverage:
        lines.append("(none)")

    lines += ["", "[USER ACTIONS]", *_event_lines(result.events)]

    message_count = sum(len(conversation.messages) for conversation in result.conversations)
    statuses = sorted({conversation.recovery_status for conversation in result.conversations})
    lines += ["", "[CONVERSATIONS]",
              _row("Recovered Conversations", len(result.conversations), 24),
              _row("Recovered Message Nodes", message_count, 24),  # 분기·tool 노드 포함 — 선형 대화 턴 수가 아니다
              _row("Status", " / ".join(s.replace("_", " ") for s in statuses) if statuses else "NONE RECOVERED", 24),
              _row("Scope", CONVERSATION_SCOPE, 24),
              _row("Message Recovery", MESSAGE_RECOVERY_STATUS, 24),
              "", "[CONVERSATION DETAILS]", *_conversation_detail_lines(result.conversations),
              "", "[RESULT]",
              _row("Records", len(result.records), 14),
              _row("Events", len(result.events), 14),
              _row("Conversations", len(result.conversations), 14),
              _row("Warnings", len(result.warnings), 14)]
    lines += [f"  - {warning}" for warning in result.warnings]
    if out_path is not None:
        lines += ["", "JSON:", str(out_path)]
    if csv_paths:
        lines += ["", "CSV:"] + [str(path) for path in csv_paths]
    lines += ["", rule]
    return "\n".join(lines)


def _print_text(text: str, stream: Any = None) -> None:
    """콘솔 인코딩이 표현하지 못하는 문자가 있어도 출력 때문에 실패하지 않게 한다."""
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    print(text.encode(encoding, errors="replace").decode(encoding, errors="replace"), file=stream)


def _run_cli(args: argparse.Namespace) -> int:
    if getattr(args, "live", False):
        return _run_cli_live(args)
    if args.image is None:
        try:
            source = DirectorySource(args.dir)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise CliUsageError(f"invalid --dir: {exc}") from None
        return _run_cli_on_source(args, source)
    try:
        image_source = open_image_source(args.image,
                                         bitlocker.key_material_from_env(getattr(args, "key_material", None)))
    except ImageOpenError as exc:
        raise CliUsageError(f"invalid --image: {exc}") from None
    try:
        return _run_cli_on_source(args, image_source)
    finally:
        image_source.close()


def _run_cli_live(args: argparse.Namespace) -> int:
    """Live: 현재 PC 에서 Artifact 를 사본으로 가져온 뒤 폴더 입력과 같은 경로로 분석한다.

    Live 전용 Reader·Rule 은 없다. 수집(live.py) 과 해석(기존 파이프라인) 을 나눈다.
    """
    try:
        collection = live.collect_live_artifacts(getattr(args, "live_work_dir", None))
    except live.LiveAcquisitionError as exc:
        raise CliUsageError(f"--live: {exc}") from None
    _print_text(os.linesep.join(["", "[LIVE ACQUISITION]"] + live.summarize(collection)))
    try:
        source = DirectorySource(str(collection.working_dir))
        return _run_cli_on_source(args, source)
    finally:
        collection.cleanup()        # 직접 만든 임시 폴더만 정리한다


def _csv_dir_from_args(args: argparse.Namespace, source: Source) -> Path | None:
    """--csv-dir 검증 (--out 과 같은 정책): 원본 Source 안에는 쓰지 않는다. 미지정이면 None = CSV 를 쓰지 않는다."""
    if not getattr(args, "csv_dir", None):
        return None
    csv_dir = Path(args.csv_dir).resolve()
    if isinstance(source, ImageSource):
        if os.path.normcase(str(csv_dir)) == os.path.normcase(str(Path(source.root).resolve())):
            raise CliUsageError(f"--csv-dir must not be the --image file (the image is read-only): {csv_dir}")
    elif _is_within(csv_dir, source.root):
        raise CliUsageError(f"--csv-dir must be outside the --dir source folder (the source is read-only): {csv_dir}")
    if csv_dir.exists() and not csv_dir.is_dir():
        raise CliUsageError(f"--csv-dir is not a directory: {csv_dir}")
    if not args.overwrite:
        # 이번 실행이 실제로 쓰는 파일 이름만 본다 (폴더의 다른 파일은 건드리지도, 막지도 않는다).
        writing = CSV_FINAL_FILES + CSV_DEBUG_FILES if getattr(args, "debug_output", False) else CSV_FINAL_FILES
        existing = [name for name, _ in writing if (csv_dir / name).exists()]
        if existing:
            raise CliUsageError(f"--csv-dir already contains {', '.join(existing)}: {csv_dir} "
                                "(use --overwrite to replace them)")
    return csv_dir


def _run_cli_on_source(args: argparse.Namespace, source: Source) -> int:
    history_path: str | None = None  # None = Chrome Profile 자동 탐색
    if args.history is not None:
        try:
            history_path = normalize_source_path(args.history)
        except SourcePathError as exc:
            raise CliUsageError(f"invalid --history: {exc}") from None
        if not history_path:
            raise CliUsageError("invalid --history: must be a file path inside the source")

    out_path = Path(args.out).resolve() if args.out else None  # 미지정이면 JSON 을 쓰지 않는다
    if out_path is not None:
        if isinstance(source, ImageSource):
            if os.path.normcase(str(out_path)) == os.path.normcase(str(Path(source.root).resolve())):
                raise CliUsageError(f"--out must not be the --image file (the image is read-only): {out_path}")
        elif _is_within(out_path, source.root):
            raise CliUsageError(f"--out must be outside the --dir source folder (the source is read-only): {out_path}")
        if out_path.is_dir():
            raise CliUsageError(f"--out is a directory: {out_path}")
        if out_path.exists() and not args.overwrite:
            raise CliUsageError(f"--out already exists: {out_path} (use --overwrite to replace it)")

    csv_dir = _csv_dir_from_args(args, source)

    try:
        result = run(source, history_path)
    except SourcePathError as exc:  # Reader·탐색은 Source 밖 경로를 warning 으로 처리하므로 방어용
        raise CliUsageError(f"invalid source path: {exc}") from None
    if out_path is not None:
        try:
            write_result_json(result, out_path, overwrite=args.overwrite)
        except FileExistsError:
            raise CliUsageError(f"--out already exists: {out_path} (use --overwrite to replace it)") from None
    csv_paths: list[Path] = []
    if csv_dir is not None:
        try:
            csv_paths = write_result_csv(result, csv_dir, overwrite=args.overwrite,
                                         debug=getattr(args, "debug_output", False))
        except FileExistsError as exc:
            raise CliUsageError(f"{exc} (use --overwrite to replace it)") from None
    _print_text(format_summary(result, out_path, auto_discovery=history_path is None, csv_paths=csv_paths))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: 인자 오류 2, --help 0 (메시지는 argparse 가 이미 출력)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        return _run_cli(args)
    except CliUsageError as exc:
        _print_text(f"error: {exc}", sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # 스택 트레이스 대신 짧은 메시지
        _print_text(f"fatal error: {type(exc).__name__}: {exc}", sys.stderr)
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
