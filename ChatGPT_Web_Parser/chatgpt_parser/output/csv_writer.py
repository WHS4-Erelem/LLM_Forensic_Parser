"""CSV 직렬화·파일 쓰기 (debug 5종과 최종 2종이 함께 쓴다)."""
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
from ..output.debug import CSV_CONVERSATION_COLUMNS, CSV_COVERAGE_COLUMNS, CSV_EVENT_COLUMNS, CSV_MESSAGE_COLUMNS, CSV_RECORD_COLUMNS
from ..output.final_csv import (CSV_NON_TEAM_ACTIONS, CSV_RECOVERED_CONVERSATION_COLUMNS, CSV_TIMELINE_COLUMNS,
                                _recovered_conversation_row, _timeline_row)


# =============================================================================
# 12-1. CSV Export
# =============================================================================
# JSON 은 전체 정보를 보존하는 canonical output 이고, CSV 는 거기서 파생되는 사람용 / 팀 통합용 output 이다.
# CSV 는 새로운 분석 결과를 만들지 않는다. 같은 ParseResult 를 그대로 표현하며 행 수가 정확히 일치해야 한다.
#   coverage.csv / records.csv / events.csv / conversations.csv / messages.csv
# 값 정책: None -> 빈 cell, list·dict -> JSON 문자열 (ensure_ascii=False, dict 는 key 정렬), 나머지는 str().
#          본문·제목·경로·시각·ID 는 절대 변형하지 않는다 (요약·절단 없음).
# Encoding: utf-8-sig (Windows Excel 한글), newline="" + csv 모듈 (빈 줄 방지). pandas 를 쓰지 않는다.

CSV_ENCODING = "utf-8-sig"


# 최종 사용자용 CSV 2종 — 기본 실행에서 만드는 파일은 이 두 개뿐이다.
CSV_FINAL_FILES = (
    ("timeline.csv", CSV_TIMELINE_COLUMNS),
    ("recovered_conversations.csv", CSV_RECOVERED_CONVERSATION_COLUMNS),
)
# 개발·디버그용 CSV 5종 — --debug-output 을 줬을 때만 만든다. 내부 구조(records/events/…)는 그대로 쓴다.
CSV_DEBUG_FILES = (
    ("coverage.csv", CSV_COVERAGE_COLUMNS),
    ("records.csv", CSV_RECORD_COLUMNS),
    ("events.csv", CSV_EVENT_COLUMNS),
    ("conversations.csv", CSV_CONVERSATION_COLUMNS),
    ("messages.csv", CSV_MESSAGE_COLUMNS),
)
CSV_FILES = CSV_FINAL_FILES + CSV_DEBUG_FILES  # 전체 목록 (파일 이름·컬럼 정의 참조용)

# Excel 은 = + - @ (와 앞의 tab·CR) 로 시작하는 cell 을 수식으로 해석한다.
# 정책: 그런 cell 과 이미 ' 로 시작하는 cell 앞에 작은따옴표 1개를 붙인다.
#       ' 로 시작하는 cell 에서 맨 앞 ' 1개만 제거하면 언제나 원문이 되므로 원문과 구분 불가능해지지 않는다.
#       JSON 원본 값은 바꾸지 않는다.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "'")


def csv_escape_cell(text: str) -> str:
    """Excel 수식 해석 방지 (되돌릴 수 있는 형태). 숫자·시각 문자열은 - 로 시작하지 않는 한 그대로 둔다."""
    if text == "-":  # 팀 공통 빈 셀 placeholder — 수식이 아니다
        return text
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


def csv_cell(value: Any) -> str:
    """CSV cell 직렬화: None -> "", list/dict -> JSON 문자열, 나머지 -> str(). 값의 의미는 바꾸지 않는다."""
    if value is None:
        return ""
    if isinstance(value, str):
        return csv_escape_cell(value)
    if isinstance(value, (list, dict)):
        return csv_escape_cell(json.dumps(value, ensure_ascii=False, sort_keys=isinstance(value, dict)))
    return csv_escape_cell(str(value))


def _csv_rows(result: ParseResult, filename: str) -> list[dict[str, Any]]:
    """ParseResult 를 CSV 한 파일분의 행 목록으로 편다 (행 수 = 해당 list 길이)."""
    if filename == "coverage.csv":
        return [item.to_dict() for item in result.coverage]
    if filename == "records.csv":
        return [item.to_dict() for item in result.records]
    if filename == "events.csv":
        return [dict(event.to_dict(),
                     primary_evidence_count=len(event.primary_evidence),
                     supporting_evidence_count=len(event.supporting_evidence))
                for event in result.events]
    if filename == "conversations.csv":
        return [dict(conversation.to_dict(),
                     message_count=len(conversation.messages),
                     source_artifact_count=len(conversation.source_artifacts),
                     correlated_record_count=len(conversation.correlated_record_ids))
                for conversation in result.conversations]
    if filename == "messages.csv":
        return [dict(message.to_dict(), conversation_title=conversation.title)
                for conversation in result.conversations for message in conversation.messages]
    if filename == "timeline.csv":
        # 팀 분류 체계 밖 행위는 최종 timeline 행을 만들지 않는다 (Event 자체는 events.csv / JSON 에 그대로 남는다).
        return [_timeline_row(event) for event in result.events if event.action not in CSV_NON_TEAM_ACTIONS]
    if filename == "recovered_conversations.csv":
        return [_recovered_conversation_row(conversation, message)
                for conversation in result.conversations for message in conversation.messages]
    raise ValueError(f"unknown csv file: {filename!r}")


def write_result_csv(result: ParseResult, directory: str | os.PathLike[str], *,
                     overwrite: bool = False, debug: bool = False) -> list[Path]:
    """
    최종 사용자용 CSV 2종을 directory 에 쓴다. debug=True 이면 개발용 CSV 5종도 함께 쓴다.
    행이 0건이어도 header 만 있는 파일을 만든다 (오류 아님). directory 의 다른 파일은 건드리지 않는다.
    overwrite=False 인데 같은 이름이 이미 있으면 **한 파일도 쓰지 않고** FileExistsError (partial output 방지).
    """
    out_dir = Path(directory)
    files = CSV_FINAL_FILES + CSV_DEBUG_FILES if debug else CSV_FINAL_FILES
    targets = [(out_dir / name, columns) for name, columns in files]
    if not overwrite:
        existing = [str(path) for path, _ in targets if path.exists()]
        if existing:
            raise FileExistsError(f"csv output already exists: {', '.join(existing)}")

    rendered = []  # 모든 행을 먼저 만들어 둔다 (직렬화 중 오류가 나도 파일이 남지 않게).
    for (path, columns), (name, _) in zip(targets, files):
        rows = [[csv_cell(row.get(column)) for column in columns] for row in _csv_rows(result, name)]
        rendered.append((path, columns, rows))

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for path, columns, rows in rendered:
        with open(path, "w" if overwrite else "x", encoding=CSV_ENCODING, newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(columns)
            writer.writerows(rows)
        written.append(path)
    return written
