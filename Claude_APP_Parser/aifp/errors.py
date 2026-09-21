"""
예외·오류 처리 계층.

포렌식 파서의 원칙: **절대 중단하지 않는다.**
아티팩트 하나가 잠겨 있거나 손상돼도 나머지는 계속 읽고,
읽지 못한 사실 자체를 결과에 남긴다. "흔적 없음"과 "읽지 못함"은 다른 결론이다.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """오류 심각도. FATAL만 해당 소스를 포기하고, 나머지는 부분 결과를 낸다."""
    INFO = "info"          # 정상 범위. 대상이 애초에 없음(미설치 등)
    WARNING = "warning"    # 일부 레코드 손상. 건너뛰고 계속
    ERROR = "error"        # 소스 하나 실패. 다른 소스는 계속
    FATAL = "fatal"        # 입력 자체가 잘못됨. 파이프라인 중단


class AifpError(Exception):
    """모든 파서 예외의 뿌리."""
    severity = Severity.ERROR
    code = "AIFP_ERROR"


class InputError(AifpError):
    """입력 경로가 없거나 대상 구조가 아님."""
    severity = Severity.FATAL
    code = "INPUT_INVALID"


class TargetNotFound(AifpError):
    """분석 대상이 설치되지 않음. 오류가 아니라 사실 기록."""
    severity = Severity.INFO
    code = "TARGET_NOT_FOUND"


class ArtifactLocked(AifpError):
    """다른 프로세스가 파일을 점유 중. 라이브 수집에서 가장 흔한 실패."""
    severity = Severity.ERROR
    code = "ARTIFACT_LOCKED"


class ArtifactCorrupt(AifpError):
    """구조가 깨져 일부만 해석 가능."""
    severity = Severity.WARNING
    code = "ARTIFACT_CORRUPT"


class DecodeError(AifpError):
    """압축 해제·역직렬화 실패."""
    severity = Severity.WARNING
    code = "DECODE_FAILED"


class RuleError(AifpError):
    """규칙 파일이 잘못됨."""
    severity = Severity.FATAL
    code = "RULE_INVALID"


@dataclass
class Issue:
    """수집·파싱 중 발생한 문제 1건. 결과 JSON에 그대로 실린다."""
    severity: str
    code: str
    stage: str                      # collect | parse | decode | map | report
    source: str                     # 어떤 아티팩트에서
    message: str
    path: str | None = None
    detail: str | None = None       # 스택트레이스 요약 (디버그용)
    ts_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class ErrorCollector:
    """
    파이프라인 전 구간에서 공유하는 오류 수집기.

    사용법:
        with errs.guard("parse", "cache", path=p):
            ...           # 예외가 나도 여기서 삼키고 기록한다
    """

    def __init__(self, verbose: bool = False) -> None:
        self.issues: list[Issue] = []
        self.verbose = verbose

    # ── 기록 ────────────────────────────────────────────────────────────
    def add(self, severity: Severity | str, code: str, stage: str, source: str,
            message: str, path: str | None = None, detail: str | None = None) -> None:
        sev = severity.value if isinstance(severity, Severity) else str(severity)
        issue = Issue(sev, code, stage, source, message, path, detail)
        self.issues.append(issue)
        if self.verbose:
            print(f"  [{sev:7}] {source}: {message}")

    def from_exception(self, exc: BaseException, stage: str, source: str,
                       path: str | None = None) -> None:
        if isinstance(exc, AifpError):
            sev, code = exc.severity, exc.code
        elif isinstance(exc, PermissionError):
            sev, code = Severity.ERROR, ArtifactLocked.code
        elif isinstance(exc, FileNotFoundError):
            sev, code = Severity.INFO, TargetNotFound.code
        elif isinstance(exc, (OSError, IOError)):
            sev, code = Severity.ERROR, "IO_ERROR"
        else:
            sev, code = Severity.ERROR, exc.__class__.__name__.upper()
        detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        # 예외에 메시지가 없으면 타입 이름만 남아 원인을 추적할 수 없다.
        # 어디서 난 일인지라도 함께 남긴다.
        text = str(exc).strip()
        if not text:
            where = f" — {path}" if path else ""
            text = f"{type(exc).__name__} (메시지 없음){where}"
        else:
            text = f"{type(exc).__name__}: {text}"
        self.add(sev, code, stage, source, text, path, detail)

    # ── 컨텍스트 매니저 ─────────────────────────────────────────────────
    def guard(self, stage: str, source: str, path: str | None = None) -> "_Guard":
        return _Guard(self, stage, source, path)

    # ── 집계 ────────────────────────────────────────────────────────────
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in self.issues:
            out[i.severity] = out.get(i.severity, 0) + 1
        return out

    @property
    def has_fatal(self) -> bool:
        return any(i.severity == Severity.FATAL.value for i in self.issues)

    def to_list(self) -> list[dict[str, Any]]:
        return [i.to_dict() for i in self.issues]


class _Guard:
    """예외를 삼키고 기록하는 컨텍스트. FATAL만 다시 던진다."""

    def __init__(self, collector: ErrorCollector, stage: str, source: str, path: str | None):
        self.c, self.stage, self.source, self.path = collector, stage, source, path

    def __enter__(self) -> "_Guard":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is None:
            return False
        self.c.from_exception(exc, self.stage, self.source, self.path)
        # FATAL은 위로 전파, 나머지는 흡수하고 계속 진행
        return not (isinstance(exc, AifpError) and exc.severity == Severity.FATAL)
