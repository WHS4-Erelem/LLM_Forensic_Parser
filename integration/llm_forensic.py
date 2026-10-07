#!/usr/bin/env python3
"""LLM 파서 통합 제어 프로그램 (표준 라이브러리만 사용).

    python llm_forensic.py -i <이미지.E01|.dd> -o <출력폴더> [--only a,b] [--registry parsers.json]

층 구성 (팀 설계도 순서):
  1. Evidence Manager   입력 확인 · evidence_id · E01/DD 구분 · 세그먼트 결번 검사
  2. Parser Runner      parsers.json 레지스트리대로 파서 6개를 subprocess 실행 (각자 venv). 파서 stdout/stderr 는 run.log 에만
  3. Normalizer         원본 헤더 계약 검사 → canonical(snake_case) 열의 공통 Event/Message 형식 (+ artifact_path_normalized, volume_ref)
  4. Unified DB         SQLite (evidence / runs / events / messages). 시작 시 이번 실행이 다시 만들 events/messages 만 지운다
  5. Timeline Generator 정렬 후 병합 timeline.csv · recovered_conversations.csv, 실행 요약 integration_report.json
종료코드: 0 전부 성공 / 1 일부 파서 실패 또는 계약 위반 / 2 입력 자체 실패 / 3 통합 DB·병합 출력 오류
"""

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# 파서 CSV 원본 헤더 = 팀 계약. 바이트 단위로 같아야 받는다 (끝 공백 포함, 틀려도 고쳐 받지 않는다)
TIMELINE_COLUMNS = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                    "Artifact_path", "Artifact_details "]
CONV_COLUMNS = ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                "parent_message_uuid", "message order", "role", "content", "Artifact_path"]


def canonical_header(name):
    """통합 내부(DB·병합 CSV) 열 이름: 앞뒤 공백 제거 → 소문자 → 공백은 '_' (snake_case)."""
    return re.sub(r"\s+", "_", str(name).strip()).lower()


# 계약 검사를 통과한 뒤에만 쓰는 canonical 열 이름. 파서가 쓴 CSV 파일 자체는 다시 쓰지 않는다
TIMELINE_FIELDS = [canonical_header(c) for c in TIMELINE_COLUMNS]
CONV_FIELDS = [canonical_header(c) for c in CONV_COLUMNS]
# provenance 열 (병합 CSV 와 DB 에 팀 7/10열 뒤에 붙는다). 원본 값은 절대 덮어쓰지 않는다:
#   timestamp = timestamp_raw (파서 표기 그대로), timestamp_utc = 정규화 (DB) / artifact_path = raw, artifact_path_normalized = 정규화
EXTRA_COLUMNS = ["source_parser", "parser_version", "source_file", "parse_time_utc",
                 "artifact_path_normalized", "volume_ref", "evidence_id", "evidence_sha256"]
VERDICTS = {"확정", "의심"}
USER_BEHAVIORS_FILE = os.path.join(HERE, "user_behaviors.txt")


def load_user_behaviors(path=USER_BEHAVIORS_FILE):
    """팀 행위 분류 체계 (한 줄에 하나, # 주석). 파일이 없으면 None → 검사 안 함."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")}


USER_BEHAVIORS = load_user_behaviors()
VERDICT_RULE = "확정 | 의심"
EMPTY = "-"
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST$")
TS_RULE = "YYYY-MM-DD HH:MM:SS.ffffff KST 또는 '-'"
EWF1_SIG = b"EVF\x09\x0d\x0a\xff\x00"
REPORT_NAME = "integration_report.json"


# ---------------------------------------------------------------- 오류 유형
# 파서 결과는 고쳐 받지 않는다. 어느 파서의 어느 파일·행·열이 어떤 값이었고 무엇이 기대됐는지만 남긴다.
ERROR_STATUS = {
    "PARSER_EXECUTION_ERROR": "failed",              # 종료코드≠0 · 시간 초과 · 실행 불가
    "UNSUPPORTED_INPUT": "failed",                   # 레지스트리 inputs 에 없는 이미지 확장자 → 실행하지 않음
    "OUTPUT_MISSING": "failed",                      # 레지스트리 outputs 의 CSV 가 없음
    "CSV_FORMAT_ERROR": "contract_violation",        # UTF-8 CSV 로 읽히지 않음
    "HEADER_MISMATCH": "contract_violation",
    "COLUMN_COUNT_MISMATCH": "contract_violation",
    "INVALID_TIMESTAMP": "contract_violation",
    "INVALID_VERDICT": "contract_violation",
    "EMPTY_CELL": "contract_violation",
    "NORMALIZATION_ERROR": "normalization_error",    # 통합 쪽 정규화 계산 실패
    "DB_ERROR": "db_error",
    "OUTPUT_WRITE_ERROR": "output_error",            # 병합 CSV·보고서 쓰기 실패 (다른 프로그램이 파일을 연 경우 등)
    "UNKNOWN_USER_BEHAVIOR": "warning",              # user_behaviors.txt 에 없는 행위명. 경고만 하고 적재는 한다 (파서 담당자가 이름을 맞춘다)
}
# ponytail: 경고는 상태에 영향 없음. 파서들이 이름을 다 맞추면 "warning" → "contract_violation" 으로 바꿔 승격한다
_STATUS_ORDER = ["failed", "contract_violation", "normalization_error", "db_error", "output_error"]
REPORT_ERROR_LIMIT = 100                             # 보고서에는 파서당 앞 100건만 (전체는 DB runs.violations)


def make_error(parser, kind, message, file=None, row=None, field=None, actual=None, expected=None):
    if kind not in ERROR_STATUS:
        raise ValueError("알 수 없는 오류 유형: %s" % kind)
    return {"parser": parser, "type": kind, "file": file, "row": row, "field": field,
            "actual": actual, "expected": expected, "message": message}


def status_of(errors):
    """오류 목록 → success / failed / contract_violation / normalization_error / db_error (앞쪽이 우선)."""
    found = {ERROR_STATUS[e["type"]] for e in errors}
    return next((s for s in _STATUS_ORDER if s in found), "success")


def utc_now():
    """UTC 현재 시각, 초 단위 ISO 8601 + 'Z' (예: 2026-09-21T19:22:46Z)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------- 1. Evidence Manager
def _ewf_ext(n):
    return "E%02d" % n if n <= 99 else "E" + chr(ord("A") + (n - 100) // 26) + chr(ord("A") + (n - 100) % 26)


def evidence_manager(path, quick=False):
    """입력 이미지 검사. 문제가 있으면 ValueError.
    evidence_quick_fingerprint: 첫 세그먼트 64MiB SHA-256. 폴더명(evidence_id)용 식별자일 뿐 무결성 값이 아니다.
    evidence_sha256: 세그먼트 전체를 순서대로 이어 계산한 SHA-256 (컨테이너 파일 기준). 무결성 대조는 이 값으로 한다.
    segment_hashes: 세그먼트별 SHA-256 매니페스트. --quick 이면 전체 해시를 건너뛰고 둘 다 '-'."""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ValueError("이미지 파일이 없습니다: %s" % path)
    with open(path, "rb") as fh:
        head = fh.read(8)
    kind = "e01" if head == EWF1_SIG else "raw"
    segments = [path]
    m = re.match(r"^(.*)\.(\d{3})$", path) if kind == "raw" else None
    if m:                                               # raw 분할 (image.001, .002, …): 주어진 번호부터 연속으로 모은다
        stem, n = m.group(1), int(m.group(2))
        segments = []
        while os.path.isfile("%s.%03d" % (stem, n)):
            segments.append("%s.%03d" % (stem, n)); n += 1
        if os.path.isfile("%s.%03d" % (stem, n + 1)):
            raise ValueError("raw 중간 세그먼트 누락: .%03d" % n)
    if kind == "e01":
        stem = os.path.splitext(path)[0]
        segments, n = [], 1
        while os.path.isfile("%s.%s" % (stem, _ewf_ext(n))):
            segments.append("%s.%s" % (stem, _ewf_ext(n))); n += 1
        if os.path.isfile("%s.%s" % (stem, _ewf_ext(n + 1))):
            raise ValueError("E01 중간 세그먼트 누락: .%s" % _ewf_ext(n))
        with open(segments[-1], "rb") as fh:            # 마지막 세그먼트는 'done' 섹션으로 끝나야 한다
            fh.seek(-76, os.SEEK_END)
            if fh.read(16).rstrip(b"\x00") == b"next":
                raise ValueError("E01 마지막 세그먼트 누락 (%s 가 next 로 끝남)" % os.path.basename(segments[-1]))
    h = hashlib.sha256()
    with open(segments[0], "rb") as fh:
        h.update(fh.read(64 * 1024 * 1024))
    quick_fp = h.hexdigest()
    evidence_sha256, evidence_md5, evidence_sha1, segment_hashes = EMPTY, EMPTY, EMPTY, []
    if not quick:                                       # 한 번 읽으면서 세그먼트별 SHA-256 과 전체 SHA-256·MD5·SHA-1 을 같이 계산 (36GB 기준 수 분)
        full, full_md5, full_sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        for s in segments:
            seg = hashlib.sha256()
            with open(s, "rb") as fh:
                for chunk in iter(lambda: fh.read(8 << 20), b""):
                    seg.update(chunk); full.update(chunk); full_md5.update(chunk); full_sha1.update(chunk)
            segment_hashes.append({"file": os.path.basename(s), "size_bytes": os.path.getsize(s), "sha256": seg.hexdigest()})
        evidence_sha256, evidence_md5, evidence_sha1 = full.hexdigest(), full_md5.hexdigest(), full_sha1.hexdigest()
    sidecars, sidecar_hashes = {}, {}
    stem = os.path.basename(path).rsplit(".", 1)[0].lower()
    for f in os.listdir(os.path.dirname(path)):
        fl = f.lower()
        if fl.endswith((".sha256", ".md5", ".sha1", "_md5.txt", "_sha256.txt")) or (fl.endswith(".txt") and fl.startswith(stem)):
            with open(os.path.join(os.path.dirname(path), f), encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            sidecars[f] = text.strip()[:300]
            for algo, n in (("md5", 32), ("sha1", 40), ("sha256", 64)):
                m = re.search(r"(?i)\b%s\b.{0,40}?\b([0-9a-f]{%d})\b" % (algo.replace("sha", "sha-?"), n), text)
                if m:
                    sidecar_hashes.setdefault(algo, m.group(1).lower())
    verification = {}
    if kind == "raw" and not quick:
        for algo, mine in (("md5", evidence_md5), ("sha1", evidence_sha1), ("sha256", evidence_sha256)):
            if algo in sidecar_hashes:
                verification[algo] = "match" if sidecar_hashes[algo] == mine else "MISMATCH"
    return {"evidence_id": quick_fp[:16], "evidence_quick_fingerprint": quick_fp, "evidence_sha256": evidence_sha256,
            "evidence_md5": evidence_md5, "evidence_sha1": evidence_sha1,
            "sidecar_declared_hashes": sidecar_hashes, "sidecar_verification": verification,
            "segment_hashes": segment_hashes, "path": path, "kind": kind,
            "segments": [os.path.basename(s) for s in segments],
            "size_bytes": sum(os.path.getsize(s) for s in segments), "sidecar_hashes": sidecars,
            "checked_at": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------- 2. Parser Runner / Registry
def load_registry(path):
    with open(path, encoding="utf-8") as fh:
        reg = json.load(fh)
    for p in reg["parsers"]:
        p["python"] = os.path.abspath(os.path.join(HERE, p["python"]))
        p["cwd"] = os.path.abspath(os.path.join(HERE, p["cwd"]))
    return reg


def parser_version(p, env):
    """레지스트리 version_args(CLI) 또는 version_file+version_regex(소스 상수)로 버전 문자열을 얻는다. 없으면 '-'."""
    try:
        if p.get("version_args"):
            r = subprocess.run([p["python"]] + p["version_args"], cwd=p["cwd"], env=env, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=60)
            return ((r.stdout or r.stderr).strip().splitlines() or ["-"])[0][:80]
        if p.get("version_file"):
            with open(os.path.join(p["cwd"], p["version_file"]), encoding="utf-8", errors="replace") as fh:
                m = re.search(p["version_regex"], fh.read())
            return m.group(1) if m else "-"
    except (OSError, subprocess.SubprocessError, re.error):
        pass
    return "-"


def code_hash(cwd):
    """파서 소스(.py/.json) 전체의 SHA-256 앞 16자리 — 어떤 코드로 결과가 나왔는지 재현 식별용."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(cwd):
        dirs[:] = sorted(d for d in dirs if d not in (".venv", ".git", "__pycache__", "tests", "test_output", "out"))
        for f in sorted(files):
            if f.endswith((".py", ".json")):
                h.update(os.path.relpath(os.path.join(root, f), cwd).encode())
                with open(os.path.join(root, f), "rb") as fh:
                    h.update(fh.read().replace(b"\r\n", b"\n"))   # git autocrlf 로 줄바꿈만 다른 같은 코드는 같은 해시
    return h.hexdigest()[:16]


def _text(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")


def run_parser(p, image, out_dir):
    """파서 1개를 subprocess 로 실행. stdout/stderr 는 콘솔로 내보내지 않고 캡처해 run.log 에만 남긴다."""
    shutil.rmtree(out_dir, ignore_errors=True)         # 이전 실행 결과는 지운다 (gemini 처럼 기존 출력이 있으면 거부하는 파서가 있음; 이전 행은 DB runs 에 남아 있다)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [p["python"]] + [a.format(image=image, out=out_dir) for a in p["args"]]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", **p.get("env", {}))
    version = "%s (code=%s)" % (parser_version(p, env), code_hash(p["cwd"]))
    parse_time_utc = utc_now()
    timeout = p.get("timeout_sec", 1800)
    exec_problem = None
    inputs = [s.lower() for s in p.get("inputs", [])]   # 파서가 확장자를 검사해 거절하는 경우만 레지스트리에 선언 (비어 있으면 검사 안 함)
    unsupported = bool(inputs) and os.path.splitext(image)[1].lower() not in inputs
    t0 = time.time()
    try:
        if unsupported:                                # 실행해도 파서가 거절하므로 시간 낭비 없이 사유만 남긴다
            raise ValueError("파서가 이 입력 확장자를 지원하지 않음: %s (지원: %s). 파서 담당자가 확장자 검사를 넓히면 parsers.json inputs 도 갱신"
                             % (os.path.splitext(image)[1] or "(없음)", ", ".join(inputs)))
        r = subprocess.run(cmd, cwd=p["cwd"], env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except ValueError as exc:
        rc, out, err = -3, "", str(exc)
        exec_problem = str(exc)
    except subprocess.TimeoutExpired as exc:           # 강제 종료 전까지 나온 출력도 run.log 에 남긴다
        rc, out, err = -1, _text(exc.stdout), _text(exc.stderr) + "\ntimeout %ss" % timeout
        exec_problem = "시간 초과로 강제 종료 (timeout_sec=%s)" % timeout
    except OSError as exc:
        rc, out, err = -2, "", str(exc)
        exec_problem = "파서를 실행할 수 없음: %s" % exc
    elapsed = round(time.time() - t0, 1)
    log_path = os.path.join(out_dir, "run.log")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("# parser=%s version=%s python=%s cwd=%s started=%s\n$ %s\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n"
                 % (p["name"], version, p["python"], p["cwd"], parse_time_utc, " ".join(cmd), out, err))
        fh.write("--- exit ---\nreturncode=%s elapsed_sec=%s\n" % (rc, elapsed))
    files = {k: os.path.join(out_dir, v) for k, v in p["outputs"].items()}
    missing = [k for k, v in files.items() if not os.path.isfile(v)]
    errors = []
    if unsupported:
        errors.append(make_error(p["name"], "UNSUPPORTED_INPUT", exec_problem, file="run.log", field="inputs",
                                 actual=os.path.splitext(image)[1].lower(), expected=inputs))
        missing = []                                   # 실행하지 않았으니 결과 없음은 당연 — 별도 오류로 세지 않는다
    elif rc != 0:
        errors.append(make_error(p["name"], "PARSER_EXECUTION_ERROR", exec_problem or "파서가 비정상 종료 (stdout/stderr 는 run.log)",
                                 file="run.log", field="returncode", actual=rc, expected=0))
    for k in missing:
        errors.append(make_error(p["name"], "OUTPUT_MISSING", "결과 CSV 가 생성되지 않음 (레지스트리 outputs.%s)" % k,
                                 file=os.path.basename(files[k]), expected="파일 존재"))
    return {"parser": p["name"], "model": p["model"], "parser_version": version, "parse_time_utc": parse_time_utc,
            "python": p["python"], "cmd": cmd, "returncode": rc,
            "elapsed_sec": elapsed, "outputs": files, "missing_outputs": missing,
            "ok": rc == 0 and not missing, "stderr_tail": err[-500:], "run_log": log_path, "errors": errors}


# ---------------------------------------------------------------- 3. Normalizer
_PREFIXES = [re.compile(r"^[A-Za-z]:[\\/]"), re.compile(r"^volume\d+:[\\/]", re.I),
             re.compile(r"^.*::NTFS@\d+[\\/]", re.I), re.compile(r"^[\\/]+")]
_PATH_SPLIT = re.compile(r"\s*\|\s*")                 # 'a|b', 'a | b', 'a| b', 'a |b' 모두 같은 구분자


def _normalize_one_path(one):
    s = one.strip()
    for rx in _PREFIXES:
        s = rx.sub("", s)
    s = s.replace("/", "\\")
    head, sep, last = s.rpartition("\\")
    name, colon, stream = last.partition(":")
    if colon and name:                                 # NTFS ADS (x.pdf:Zone.Identifier, $UsnJrnl:$J): 스트림 표기는 원문 그대로
        return (head + sep + name).lower() + colon + stream
    return s.lower()


def normalize_path(raw):
    """경로마다 드라이브·볼륨·이미지 접두어를 떼고 볼륨 루트 기준, 구분자 \\, 소문자.
    여러 경로는 '|' (앞뒤 공백 무관)로 나눠 각각 정규화한 뒤 ' | ' 로 잇는다. NTFS ADS 스트림 표기는 바꾸지 않는다."""
    parts = [_normalize_one_path(one) for one in _PATH_SPLIT.split(str(raw))]
    return " | ".join(x for x in parts if x) or EMPTY


_VOL_KEY = re.compile(r"^(?:.*?::(NTFS@\d+)[\\/]|(volume\d+):|([A-Za-z]):[\\/])", re.I)
_SYSTEM_DIRS = {"users", "windows"}                   # 이 폴더가 있는 볼륨 = Windows 시스템 볼륨 (C:)


def _volume_key(one):
    """경로 한 개 → (볼륨 키, 볼륨 루트 기준 첫 폴더). 키: 'C:' / 'volume0' / 'ntfs@227540992',
    볼륨 표기 없는 루트 기준 경로('Users/x/History')는 '' (한 파서 결과 안에서 같은 볼륨으로 본다), 빈 값·'-' 는 None."""
    s = one.strip()
    if not s or s == EMPTY:
        return None, None
    m = _VOL_KEY.match(s)
    if m:
        key, rest = (m.group(3).upper() + ":" if m.group(3) else (m.group(1) or m.group(2)).lower()), s[m.end():]
    else:
        key, rest = "", s
    return key, rest.replace("/", "\\").lstrip("\\").split("\\", 1)[0].lower()


def system_volume_keys(paths):
    """파서 결과 전체에서 Users\\ 또는 Windows\\ 경로를 가진 볼륨 키 집합. 파서가 volume0 / NTFS@오프셋 으로만 부르는 볼륨도
    그 안에 Users 가 있으면 시스템 볼륨이다 (번호는 파서가 열 수 있었던 NTFS 순서라 0 이 곧 C: 는 아니다)."""
    keys = set()
    for raw in paths:
        for one in _PATH_SPLIT.split(str(raw)):
            key, first = _volume_key(one)
            if key is not None and first in _SYSTEM_DIRS:
                keys.add(key)
    return keys


def volume_ref(raw, system_keys=()):
    """드라이브 문자 경로는 그 문자(C:). volumeN / NTFS@오프셋 볼륨은 같은 결과 안에 Users·Windows 경로가 있어 시스템 볼륨으로
    판정될 때만 C:, 그 외(복구·데이터 파티션, 경로 없음)는 '-'. 여러 경로는 서로 다른 값만 ' | ' 로 잇는다."""
    refs = []
    for one in _PATH_SPLIT.split(str(raw)):
        key, _ = _volume_key(one)
        ref = key if key and key.endswith(":") else ("C:" if key is not None and key in system_keys else None)
        if ref and ref not in refs:
            refs.append(ref)
    return " | ".join(refs) or EMPTY


def kst_to_utc(ts):
    if not TS_RE.match(ts or ""):
        return None
    dt = datetime.strptime(ts[:-4], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone(timedelta(hours=9)))
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _header_hint(got, want):
    if got is None:
        return " (열 없음)"
    if want is None:
        return " (계약에 없는 열)"
    if got.strip() == want.strip():
        return " (앞뒤 공백 차이)"
    if canonical_header(got) == canonical_header(want):
        return " (대소문자·공백 차이)"
    return ""


def read_contract_csv(parser, path, columns, errors):
    """원본 헤더 계약 검사 (바이트 단위, 고쳐 받지 않음). 오류는 errors 에 덧붙인다.
    반환: 헤더가 맞으면 (데이터 행 수, [(행 번호, 값 목록)]), 헤더부터 틀리거나 못 읽으면 (행 수 또는 None, None).
    행 번호는 헤더를 1행으로 센 CSV 레코드 번호 (엑셀에서 연 행 번호와 같다)."""
    name = os.path.basename(path)
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))   # 긴 대화 content 도 그대로 읽는다 (기본 128KiB 제한은 계약이 아님)
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
    except (UnicodeDecodeError, csv.Error) as exc:
        errors.append(make_error(parser, "CSV_FORMAT_ERROR", "CSV 로 읽을 수 없음: %s" % exc, file=name, expected="UTF-8 CSV"))
        return None, None
    except OSError as exc:
        errors.append(make_error(parser, "OUTPUT_MISSING", "결과 CSV 를 열 수 없음: %s" % exc, file=name, expected="파일 존재"))
        return None, None
    if not rows:
        errors.append(make_error(parser, "HEADER_MISMATCH", "빈 파일 (헤더 행 없음)", file=name, row=1, expected=columns))
        return 0, None
    header = rows[0]
    if header != columns:
        for i in range(max(len(header), len(columns))):
            got = header[i] if i < len(header) else None
            want = columns[i] if i < len(columns) else None
            if got != want:
                errors.append(make_error(parser, "HEADER_MISMATCH", "%d번째 열 헤더가 계약과 다름%s" % (i + 1, _header_hint(got, want)),
                                         file=name, row=1, field=canonical_header(want) if want is not None else "column %d" % (i + 1),
                                         actual=got, expected=want))
        return len(rows) - 1, None
    return len(rows) - 1, list(enumerate(rows[1:], 2))


def normalize(run, evidence):
    """파서 결과 CSV 2개 → (events, messages, errors, source_rows).
    원본 헤더 계약을 먼저 검사하고, 통과한 행만 canonical 열 이름으로 옮긴다. 값은 고치지 않고 provenance·정규화 열만 덧붙인다.
    source_rows: 파일별 데이터 행 수 (헤더 제외, 못 읽으면 None)."""
    parser, errors, warnings, source_rows = run["parser"], [], [], {}
    prov = {"source_parser": parser, "parser_version": run["parser_version"], "parse_time_utc": run["parse_time_utc"],
            "evidence_id": evidence["evidence_id"], "evidence_sha256": evidence["evidence_sha256"]}
    out = {"timeline": [], "conversations": []}
    for kind, columns, fields in (("timeline", TIMELINE_COLUMNS, TIMELINE_FIELDS), ("conversations", CONV_COLUMNS, CONV_FIELDS)):
        name = os.path.basename(run["outputs"][kind])
        source_rows[name], rows = read_contract_csv(parser, run["outputs"][kind], columns, errors)
        for i, values in rows or []:
            if len(values) != len(columns):
                errors.append(make_error(parser, "COLUMN_COUNT_MISMATCH", "열 수가 계약과 다름", file=name, row=i,
                                         actual=len(values), expected=len(columns)))
                continue
            r = dict(zip(fields, values))
            before = len(errors)
            if kind == "timeline":                     # 타임라인은 빈 셀 금지 (값이 없으면 '-')
                for f, v in r.items():
                    if v == "":
                        errors.append(make_error(parser, "EMPTY_CELL", "빈 셀", file=name, row=i, field=f,
                                                 actual=v, expected="값 또는 '-'"))
                if r["verdict"] != "" and r["verdict"] not in VERDICTS:
                    errors.append(make_error(parser, "INVALID_VERDICT", "허용되지 않은 Verdict", file=name, row=i,
                                             field="verdict", actual=r["verdict"], expected=VERDICT_RULE))
            ts = r["timestamp"]
            if not (kind == "timeline" and ts == "") and ts != EMPTY and not TS_RE.match(ts):
                errors.append(make_error(parser, "INVALID_TIMESTAMP", "시각 형식이 계약과 다름", file=name, row=i,
                                         field="timestamp", actual=ts, expected=TS_RULE))
            if len(errors) > before:                   # 위반 행은 정규화하지 않는다 (이 파서 결과 전체가 적재에서 빠진다)
                continue
            derived = {}
            for target, src, fn in (("timestamp_utc", "timestamp", lambda: kst_to_utc(r["timestamp"])),
                                    ("artifact_path_normalized", "artifact_path", lambda: normalize_path(r["artifact_path"]))):
                try:
                    derived[target] = fn()
                except Exception as exc:               # 통합 쪽 계산 실패 — 파서 값은 고치지 않고 오류로만 남긴다
                    errors.append(make_error(parser, "NORMALIZATION_ERROR", "%s 계산 실패 (%s: %s)" % (target, type(exc).__name__, exc),
                                             file=name, row=i, field=src, actual=r[src]))
            if len(errors) > before:
                continue
            if kind == "timeline" and USER_BEHAVIORS is not None and r["user_behavior"] not in USER_BEHAVIORS:
                warnings.append(make_error(parser, "UNKNOWN_USER_BEHAVIOR", "팀 행위 분류 체계에 없는 행위명 (적재는 함)", file=name, row=i,
                                           field="user_behavior", actual=r["user_behavior"], expected=os.path.basename(USER_BEHAVIORS_FILE)))
            raw = dict(zip(columns, values))           # row_hash 는 파서 원본 헤더·값 기준 (이전 버전과 같은 값)
            row_hash = hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]
            out[kind].append({**r, **prov, **derived, "source_file": name, "row_hash": row_hash})
    keys = system_volume_keys(x["artifact_path"] for rows in out.values() for x in rows)   # 볼륨 판정은 이 파서 결과 전체를 보고
    for rows in out.values():
        for x in rows:
            x["volume_ref"] = volume_ref(x["artifact_path"], keys)
    return out["timeline"], out["conversations"], errors + warnings, source_rows


# ---------------------------------------------------------------- 4. Unified DB
_EV_COLS = TIMELINE_FIELDS + ["timestamp_utc"] + EXTRA_COLUMNS + ["row_hash"]
_MSG_COLS = CONV_FIELDS + ["timestamp_utc"] + EXTRA_COLUMNS + ["row_hash"]
_RUN_COLS = ["run_id", "evidence_id", "parser", "parser_version", "parse_time_utc", "python", "ok", "returncode",
             "elapsed_sec", "violations", "info", "status"]
_RUN_TYPES = {"ok": "int", "returncode": "int", "elapsed_sec": "real"}
# 이전 버전 unified.db 의 열 이름 → 현재 이름. 열 이름만 바꾸고 행·runs 이력은 그대로 둔다
LEGACY_PARSE_TIME = "parse_time"
_LEGACY_RENAMES = {
    "runs": {LEGACY_PARSE_TIME: "parse_time_utc"},
    "events": dict(zip(TIMELINE_COLUMNS, TIMELINE_FIELDS), **{LEGACY_PARSE_TIME: "parse_time_utc"}),
    "messages": dict(zip(CONV_COLUMNS, CONV_FIELDS), **{LEGACY_PARSE_TIME: "parse_time_utc"}),
}


def _q(c):
    return '"%s"' % c


def _cols(db, table):
    return [r[1] for r in db.execute("pragma table_info(%s)" % table)]


@contextmanager
def _tx(db):
    """BEGIN IMMEDIATE … COMMIT. 예외가 나면 ROLLBACK 후 다시 올린다 (DB 는 시작 전 상태 그대로)."""
    db.execute("begin immediate")
    try:
        yield db
        db.execute("commit")
    except BaseException:
        if db.in_transaction:
            db.execute("rollback")
        raise


def _migrate_legacy(db):
    """이전 버전 DB(원본 헤더 열 이름 · parse_time)를 현재 열 이름으로 바꾼다. 바꾼 것이 있으면 True.
    이전 행의 artifact_path_normalized 는 현재 normalize_path 로 다시 계산한다 (파생 열이라 원본 값은 그대로)."""
    renamed = False
    for table, renames in _LEGACY_RENAMES.items():
        cols = _cols(db, table)
        for old, new in renames.items():
            if old != new and old in cols:
                db.execute("alter table %s rename column %s to %s" % (table, _q(old), _q(new)))
                renamed = True
    if "status" not in _cols(db, "runs"):
        db.execute("alter table runs add column status text")
        renamed = True
    if renamed:
        for table in ("events", "messages"):
            rows = db.execute("select rowid, artifact_path from %s" % table).fetchall()
            db.executemany("update %s set artifact_path_normalized=? where rowid=?" % table,
                           [(normalize_path(p) if p is not None else None, rid) for rid, p in rows])
    for table, want in (("runs", _RUN_COLS), ("events", _EV_COLS), ("messages", _MSG_COLS)):
        missing = [c for c in want if c not in _cols(db, table)]
        if missing:
            raise sqlite3.DatabaseError("%s 테이블에 열이 없음: %s" % (table, missing))
    return renamed


def open_db(path):
    """unified.db 를 열고 스키마를 맞춘다 (없으면 생성, 이전 버전이면 열 이름 이전). 실패는 sqlite3.Error 로 올린다.
    반환: (연결, 이전 버전 스키마를 옮겼는지)."""
    db = sqlite3.connect(path, isolation_level=None)    # 트랜잭션은 _tx 로 직접 연다
    try:
        with _tx(db):
            db.execute("create table if not exists evidence (evidence_id text primary key, info text)")
            db.execute("create table if not exists runs (%s)" % ", ".join("%s %s" % (c, _RUN_TYPES.get(c, "text")) for c in _RUN_COLS))
            db.execute("create table if not exists events (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in _EV_COLS))
            db.execute("create table if not exists messages (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in _MSG_COLS))
            migrated = _migrate_legacy(db)
    except BaseException:
        db.close()
        raise
    return db, migrated


def reset_results(db, evidence_id, parsers=None):
    """이번 실행이 다시 만들 결과만 지운다. parsers=None(전체 실행)이면 evidence_id 의 events/messages 전체,
    목록이면 (evidence_id, source_parser) 가 맞는 행만. runs 는 이력이라 지우지 않는다.
    한 트랜잭션: 실패하면 아무것도 지워지지 않은 채 sqlite3.Error 가 올라간다. 반환: 지운 행 수."""
    deleted = {"events": 0, "messages": 0}
    with _tx(db):
        for table in deleted:
            if parsers is None:
                deleted[table] += db.execute("delete from %s where evidence_id=?" % table, (evidence_id,)).rowcount
            else:
                for name in parsers:
                    deleted[table] += db.execute("delete from %s where evidence_id=? and source_parser=?" % table,
                                                 (evidence_id, name)).rowcount
    return deleted


def _insert_run(db, evidence, run_id, run, status, errors):
    info = {k: v for k, v in run.items() if k != "errors"}
    vals = {"run_id": run_id, "evidence_id": evidence["evidence_id"], "parser": run["parser"],
            "parser_version": run["parser_version"], "parse_time_utc": run["parse_time_utc"], "python": run["python"],
            "ok": int(run["ok"]), "returncode": run["returncode"], "elapsed_sec": run["elapsed_sec"],
            "violations": json.dumps(errors, ensure_ascii=False), "info": json.dumps(info, ensure_ascii=False, default=str),
            "status": status}
    db.execute("insert into runs (%s) values (%s)" % (", ".join(_RUN_COLS), ", ".join("?" * len(_RUN_COLS))),
               [vals[c] for c in _RUN_COLS])


def store(db, evidence, run_id, run, status, events, messages, errors):
    """runs 이력 행 + 이 파서의 events/messages 를 한 트랜잭션으로 적재. 반환: 실제로 들어간 행 수
    (같은 파서가 완전히 같은 행을 두 번 쓰면 row_hash 가 같아 한 번만 들어간다)."""
    inserted = {"events": 0, "messages": 0}
    with _tx(db):
        db.execute("insert or replace into evidence values (?, ?)", (evidence["evidence_id"], json.dumps(evidence, ensure_ascii=False)))
        _insert_run(db, evidence, run_id, run, status, errors)
        for table, cols, rows in (("events", _EV_COLS, events), ("messages", _MSG_COLS, messages)):
            if rows:
                cur = db.executemany("insert or ignore into %s (%s) values (%s)" % (table, ", ".join(map(_q, cols)), ", ".join("?" * len(cols))),
                                     [[r.get(c) for c in cols] for r in rows])
                inserted[table] = cur.rowcount
    return inserted


# ---------------------------------------------------------------- 5. Timeline Generator
def _safe(v):
    s = EMPTY if v is None or str(v).strip() == "" else str(v)
    return "'" + s if s != EMPTY and s[:1] in ("=", "+", "-", "@") else s


def write_merged(db, evidence_id, out_dir):
    """반환: [(경로, 행 수, {source_parser: 행 수})]."""
    written = []
    for name, table, fields, columns in (("timeline.csv", "events", TIMELINE_FIELDS, TIMELINE_COLUMNS),
                                         ("recovered_conversations.csv", "messages", CONV_FIELDS, CONV_COLUMNS)):
        out_cols = fields + EXTRA_COLUMNS
        header = columns + EXTRA_COLUMNS                 # 사람이 보는 병합 CSV 는 팀 계약 헤더 그대로 (DB 안에서만 snake_case)
        rows = db.execute("select %s from %s where evidence_id=? order by (timestamp_utc is null), timestamp_utc, source_parser"
                          % (", ".join(map(_q, out_cols)), table), (evidence_id,)).fetchall()
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            by_parser = Counter()
            parser_index = out_cols.index("source_parser")
            for r in rows:
                w.writerow([_safe(v) for v in r])
                by_parser[r[parser_index]] += 1
        written.append((path, sum(by_parser.values()), dict(sorted(by_parser.items()))))
    return written


def write_report(path, report):
    report["generated_at_utc"] = utc_now()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------- 콘솔 (통합이 만든 요약만. 파서 stdout/stderr 는 run.log 에)
def _short(v, n=60):
    s = repr(v) if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[:n - 3] + "..."


def describe_error(e):
    where = " ".join(x for x in (e["file"], "row %d" % e["row"] if e["row"] is not None else "", e["field"]) if x)
    s = "%s%s" % (where + ": " if where else "", e["message"])
    if e["actual"] is not None or e["expected"] is not None:
        s += " (actual=%s, expected=%s)" % (_short(e["actual"]), _short(e["expected"]))
    return s


def _console_result(status, run, events, messages, errors, dup, detail_path):
    label = "OK" if status == "success" else status.upper()
    types = ", ".join("%s x%d" % kv for kv in Counter(e["type"] for e in errors).items())
    note = types or ("동일 행 %d건은 1회만 적재" % dup if dup else "")
    if status == "success" and not events and not messages:
        note = (note + " · " if note else "") + "0건 — 흔적 없음이거나 파서가 입력을 못 읽은 것. run.log 확인"
    print((" %-8s %6.1fs  events=%-3d messages=%-3d %s" % (label, run["elapsed_sec"], len(events), len(messages), note)).rstrip())
    if errors:
        more = " (외 %d건)" % (len(errors) - 1) if len(errors) > 1 else ""
        print("         %s%s" % (describe_error(errors[0]), more))
        print("         detail: %s" % detail_path)


def _parser_entry(status, run, events, messages, errors, source_rows, inserted):
    return {"status": status, "timeline_rows": len(events), "conversation_rows": len(messages),
            "artifacts_found": bool(events or messages),   # success 라도 False 면 흔적 없음 또는 입력 미인식 — run.log 로 구분
            "source_rows": source_rows, "db_inserted": inserted,
            "returncode": run["returncode"], "elapsed_sec": run["elapsed_sec"],
            "parser_version": run["parser_version"], "parse_time_utc": run["parse_time_utc"],
            "output_dir": os.path.dirname(run["run_log"]), "run_log": run["run_log"],
            "error_count": len(errors), "error_types": dict(Counter(e["type"] for e in errors)),
            "errors": errors[:REPORT_ERROR_LIMIT], "errors_truncated": len(errors) > REPORT_ERROR_LIMIT}


def run_one(p, ev, case_dir, db, run_id, report_path):
    """파서 1개: 실행 → 계약 검사·정규화 → 적재. 반환: (status, 보고서 항목)."""
    out_dir = os.path.join(case_dir, p["name"])
    print("[Runner] %-16s" % p["name"], end="", flush=True)
    run = run_parser(p, ev["path"], out_dir)
    errors, events, messages, source_rows = list(run["errors"]), [], [], {}
    if not errors:
        try:
            events, messages, errors, source_rows = normalize(run, ev)
        except Exception as exc:                       # 통합 코드 결함이 전체 실행을 멈추지 않게
            errors = [make_error(p["name"], "NORMALIZATION_ERROR", "정규화 중 예외 (%s: %s)" % (type(exc).__name__, exc))]
    status = status_of(errors)
    if status != "success":
        events, messages = [], []                      # 계약을 어긴 결과는 적재하지 않는다 (병합본 오염 방지)
    inserted = {"events": 0, "messages": 0}
    try:
        inserted = store(db, ev, run_id, run, status, events, messages, errors)
    except sqlite3.Error as exc:                       # 트랜잭션 롤백됨: 이 파서의 행은 DB 에 없다
        errors.append(make_error(p["name"], "DB_ERROR", "적재 실패, 이 파서 결과는 DB 에 없음 (%s)" % exc, file="unified.db"))
        status, events, messages = status_of(errors), [], []
        try:
            with _tx(db):                              # 실행 이력만이라도 남긴다
                _insert_run(db, ev, run_id, run, status, errors)
        except sqlite3.Error as exc2:
            errors.append(make_error(p["name"], "DB_ERROR", "runs 이력 기록도 실패 (%s)" % exc2, file="unified.db"))
    dup = len(events) + len(messages) - inserted["events"] - inserted["messages"]
    detail = run["run_log"] if status == "failed" else report_path
    _console_result(status, run, events, messages, errors, dup, detail)
    return status, _parser_entry(status, run, events, messages, errors, source_rows, inserted)


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--image")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--registry", default=os.path.join(HERE, "parsers.json"))
    ap.add_argument("--only", help="쉼표로 구분한 파서 이름만 실행. DB 에서는 이 파서들의 이전 events/messages 만 새 결과로 "
                                   "교체하고, 실행하지 않은 파서의 결과는 그대로 둔다")
    ap.add_argument("--quick", action="store_true",
                    help="세그먼트별·전체 SHA-256 계산을 건너뛴다 (evidence_sha256='-', 무결성 대조 불가. 개발 중 빠른 반복용)")
    ap.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.image:
        ap.error("-i/--image 가 필요합니다")

    try:
        ev = evidence_manager(args.image, quick=args.quick)
    except ValueError as exc:
        print("[Evidence] 실패:", exc, file=sys.stderr)
        return 2
    print("[Evidence] id=%s kind=%s segments=%d size=%.1fGB quick_fp=%s sha256=%s" % (
        ev["evidence_id"], ev["kind"], len(ev["segments"]), ev["size_bytes"] / 1e9,
        ev["evidence_quick_fingerprint"][:16] + "...", ev["evidence_sha256"]))
    if ev.get("sidecar_verification"):
        print("[Evidence] 취득 해시 대조: %s" % ", ".join("%s=%s" % kv for kv in sorted(ev["sidecar_verification"].items())))
    elif ev.get("sidecar_declared_hashes") and ev["kind"] == "e01":
        print("[Evidence] 동봉 해시 %s 는 매체 해시 — E01 컨테이너 해시와 직접 비교 불가 (기록만)" % ", ".join(sorted(ev["sidecar_declared_hashes"])))

    reg = load_registry(args.registry)
    only = [s.strip() for s in args.only.split(",") if s.strip()] if args.only else None
    parsers = [p for p in reg["parsers"] if p.get("enabled", True) and (only is None or p["name"] in only)]
    case_dir = os.path.join(os.path.abspath(args.out), ev["evidence_id"])
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "evidence_manifest.json"), "w", encoding="utf-8") as fh:   # 세그먼트별 SHA-256 매니페스트
        json.dump(ev, fh, ensure_ascii=False, indent=2)
    db_path = os.path.join(case_dir, "unified.db")
    report_path = os.path.join(case_dir, REPORT_NAME)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # 전체 실행: evidence_id 의 events/messages 를 모두 다시 만든다. --only: 실행하는 파서 몫만 교체하고 나머지는 유지
    reset_scope = None if only is None else [p["name"] for p in parsers]
    report = {"report_version": 1, "run_id": run_id, "generated_at_utc": None,
              "mode": "full" if only is None else "only", "only": only, "quick": args.quick,
              "registry": os.path.abspath(args.registry),
               "evidence": {"evidence_id": ev["evidence_id"]},
               "exit_code": None, "summary": {}, "db": {"path": db_path}, "parsers": {},
               "integration_errors": [], "warnings": []}
    unknown = [n for n in only or [] if n not in {p["name"] for p in reg["parsers"]}]
    if unknown:
        report["warnings"].append("레지스트리에 없는 파서 이름은 무시: %s" % ", ".join(unknown))
        print("[Runner] 경고: %s" % report["warnings"][-1])

    db = None
    try:
        db, migrated = open_db(db_path)
        deleted = reset_results(db, ev["evidence_id"], reset_scope)
    except sqlite3.Error as exc:                        # 초기화 실패를 넘기면 이전 결과가 섞인다 → 파서를 돌리지 않고 중단
        if db is not None:
            db.close()
        report["integration_errors"].append(make_error(None, "DB_ERROR", "unified.db 열기·초기화 실패, 파서를 실행하지 않고 중단 (%s)" % exc,
                                                       file="unified.db"))
        print("[DB] FAILED DB_ERROR unified.db 열기·초기화 실패 (%s)" % exc)
        return _finish(report, report_path, 3, "DB 초기화 실패로 파서를 실행하지 않음 (run_id=%s)" % run_id)
    report["db"].update({"schema_migrated_from_legacy": migrated,
                         "reset": {"scope": "evidence" if reset_scope is None else "parsers", "parsers": reset_scope,
                                   "events_deleted": deleted["events"], "messages_deleted": deleted["messages"],
                                   "runs_deleted": 0}})
    print("[DB] 이전 결과 초기화 (%s): events %d행 · messages %d행 삭제, runs 이력 유지%s" % (
        "evidence 전체" if reset_scope is None else "파서 " + (", ".join(reset_scope) or "없음"),
        deleted["events"], deleted["messages"], " · 이전 버전 스키마 열 이름 변환" if migrated else ""))

    statuses = Counter()
    for p in parsers:
        status, report["parsers"][p["name"]] = run_one(p, ev, case_dir, db, run_id, report_path)
        statuses[status] += 1
    failed = len(parsers) - statuses["success"]

    fatal, merged_parsers = False, set()
    try:
        for path, n, by_parser in write_merged(db, ev["evidence_id"], case_dir):
            field = "timeline_rows" if os.path.basename(path) == "timeline.csv" else "conversation_rows"
            merged_parsers.update(by_parser)
            for parser, count in by_parser.items():
                if parser in report["parsers"]:
                    report["parsers"][parser][field] = count
            print("[Timeline] %s  %d행" % (path, n))
    except sqlite3.Error as exc:
        fatal = True
        report["integration_errors"].append(make_error(None, "DB_ERROR", "병합 조회 실패 (%s)" % exc, file="unified.db"))
        print("[Timeline] FAILED DB_ERROR 병합 조회 실패 (%s)" % exc)
    except OSError as exc:
        fatal = True
        report["integration_errors"].append(make_error(None, "OUTPUT_WRITE_ERROR", "병합 CSV 쓰기 실패 (%s)" % exc,
                                                       file=os.path.basename(exc.filename) if exc.filename else None))
        print("[Timeline] FAILED OUTPUT_WRITE_ERROR 병합 CSV 쓰기 실패 (%s)" % exc)
    db.close()
    print("[DB] %s" % db_path)
    preserved = sorted(merged_parsers - set(report["parsers"]))
    report["preserved_from_previous_runs"] = preserved     # --only 로 이번에 실행하지 않았지만 병합본에 남은 파서
    report["summary"] = {"parsers_run": len(parsers), "success": statuses["success"], "failed": statuses["failed"],
                         "contract_violation": statuses["contract_violation"],
                         "normalization_error": statuses["normalization_error"], "db_error": statuses["db_error"]}
    code = 3 if fatal else (1 if failed else 0)
    return _finish(report, report_path, code, "파서 %d개 중 %d 성공, %d 실패·위반 (run_id=%s)"
                   % (len(parsers), len(parsers) - failed, failed, run_id))


def _finish(report, report_path, code, summary):
    report["exit_code"] = code
    try:
        write_report(report_path, report)
        print("[Report] %s" % report_path)
    except OSError as exc:
        print("[Report] FAILED OUTPUT_WRITE_ERROR %s (%s)" % (report_path, exc))
        code = code or 3
    print("[Summary] %s" % summary)
    return code


# ---------------------------------------------------------------- self-test
_FAKE_PARSER = r'''
import csv, os, sys
name, mode, out = sys.argv[1], sys.argv[2], sys.argv[3]
mode = os.environ.get("FAKE_MODE_" + name.upper(), mode)
print("완료: timeline 2건 (fake stdout)")
print("INFO recovered_conversations.csv : 1 rows (fake stderr)", file=sys.stderr)
if mode == "fail":
    sys.exit(3)
TL = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict", "Artifact_path", "Artifact_details "]
CV = ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid", "parent_message_uuid",
      "message order", "role", "content", "Artifact_path"]
ts = "2026-09-15 13:20:41.807000 KST"
tl = [[name, ts, "프롬프트 전송", "v=" + mode, "확정",
       r"C:\Users\A\Downloads\x.pdf|C:\Users\A\Downloads\x.pdf:Zone.Identifier", "volume=ntfs@5"],
      [name, "-", "테스트용 비표준 행위", "b", "의심", r"volume0:\Users\A\y.txt | D:/img.E01::NTFS@7/Users/A/z", "-"]]
cv = [[name, ts, "c1", "t", "m1", "-", "1", "user", "hello " + mode, r"C:\Users\A\conv.json"]]
if mode == "bad":
    TL = TL[:3] + ["Behavior_details"] + TL[4:] if os.environ.get("FAKE_BAD_HEADER") else TL
    tl.append([name, "2026-09-15 13:20:41 KST", "x", "", "추정", "-", "-"])
with open(os.path.join(out, "timeline.csv"), "w", encoding="utf-8-sig", newline="") as fh:
    w = csv.writer(fh); w.writerow(TL); w.writerows(tl)
if mode != "missing":
    with open(os.path.join(out, "recovered_conversations.csv"), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh); w.writerow(CV); w.writerows(cv)
'''


def self_test():
    import tempfile
    assert normalize_path(r"C:\Users\A\x.txt") == r"users\a\x.txt"
    assert normalize_path("Users/A/x.txt | volume0:\\Users\\B\\y") == r"users\a\x.txt | users\b\y"
    assert normalize_path("D:/img.E01::NTFS@227540992/Users/llmtest/History") == r"users\llmtest\history"
    # 다중 경로: 구분자 앞뒤 공백 유무와 관계없이 경로마다 접두어 제거
    for raw in (r"C:\A\x|D:\B\y", r"C:\A\x | D:\B\y", r"C:\A\x| D:\B\y", r"C:\A\x |D:\B\y"):
        assert normalize_path(raw) == r"a\x | b\y", raw
    assert normalize_path(r"C:\$MFT|volume0:\Users\A\H||  ") == r"$mft | users\a\h"
    # NTFS ADS 스트림 표기는 그대로
    assert normalize_path(r"C:\Users\A\Downloads\MRK (1).pdf:Zone.Identifier") == r"users\a\downloads\mrk (1).pdf:Zone.Identifier"
    assert normalize_path(r"C:\U\x.pdf|C:\U\x.pdf:Zone.Identifier") == r"u\x.pdf | u\x.pdf:Zone.Identifier"
    assert normalize_path(r"volume0:\$Extend\$UsnJrnl:$J | volume0:\A\B.exe") == r"$extend\$usnjrnl:$J | a\b.exe"
    assert normalize_path(r"C:\A\f.txt::$DATA") == r"a\f.txt::$DATA"
    assert normalize_path("-") == EMPTY and normalize_path("") == EMPTY
    # volume_ref: 드라이브 문자는 그대로, volumeN / NTFS@오프셋 은 그 볼륨에 Users·Windows 가 있을 때만 C:, 아니면 '-'
    assert volume_ref("C:\\Users\\A") == "C:" and volume_ref("d:/Data/x") == "D:" and volume_ref("-") == EMPTY
    assert volume_ref("volume0:\\$Extend\\$UsnJrnl:$J") == EMPTY                    # 혼자서는 어느 볼륨인지 모른다
    sys_keys = system_volume_keys(["volume0:\\Users\\A\\x", "volume1:\\Recovery\\WindowsRE", "img.E01::NTFS@227540992/Windows/Prefetch/a.pf"])
    assert sys_keys == {"volume0", "ntfs@227540992"}, sys_keys
    assert volume_ref("volume0:\\$Extend\\$UsnJrnl:$J", sys_keys) == "C:" and volume_ref("volume1:\\Recovery\\x", sys_keys) == EMPTY
    assert volume_ref("D:/img.E01::NTFS@227540992/Users/llmtest/History", sys_keys) == "C:"   # 이미지 경로의 D: 는 볼륨이 아니다
    assert volume_ref("volume0:\\Users\\A\\y | C:\\Users\\A\\z", sys_keys) == "C:" and volume_ref("C:\\a | D:\\b") == "C: | D:"
    rel_keys = system_volume_keys(["Users/llmtest/AppData/Local/Google/Chrome/User Data/Default/History", "-"])   # 볼륨 표기 없는 루트 기준 경로 (chatgpt_web)
    assert rel_keys == {""} and volume_ref("Users/llmtest/x", rel_keys) == "C:" and volume_ref("-", rel_keys) == EMPTY
    assert volume_ref("Recovery/WindowsRE/x", system_volume_keys(["Recovery/WindowsRE/x"])) == EMPTY
    assert kst_to_utc("2026-09-15 13:20:41.807000 KST") == "2026-09-15T04:20:41.807000Z"
    assert kst_to_utc("-") is None and kst_to_utc("2026-09-15 13:20:41 KST") is None
    assert _safe("=1") == "'=1" and _safe("") == EMPTY and _safe("-") == EMPTY
    assert _ewf_ext(1) == "E01" and _ewf_ext(99) == "E99" and _ewf_ext(100) == "EAA"
    assert len(code_hash(HERE)) == 16 and code_hash(HERE) == code_hash(HERE)
    # canonical header · provenance 열
    assert TIMELINE_FIELDS == ["model", "timestamp", "user_behavior", "behavior_details", "verdict", "artifact_path", "artifact_details"]
    assert CONV_FIELDS == ["model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                           "parent_message_uuid", "message_order", "role", "content", "artifact_path"]
    assert canonical_header(" Behavior_details ") == "behavior_details" and canonical_header("message  order") == "message_order"
    assert EXTRA_COLUMNS == ["source_parser", "parser_version", "source_file", "parse_time_utc",
                             "artifact_path_normalized", "volume_ref", "evidence_id", "evidence_sha256"]
    snake = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")
    assert all(snake.match(c) for c in _EV_COLS + _MSG_COLS + _RUN_COLS)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", utc_now())
    assert status_of([]) == "success" and status_of([make_error("x", "EMPTY_CELL", "m")]) == "contract_violation"
    assert status_of([make_error("x", "DB_ERROR", "m"), make_error("x", "OUTPUT_MISSING", "m")]) == "failed"

    with tempfile.TemporaryDirectory() as td:
        raw = os.path.join(td, "x.dd"); data = os.urandom(1000)
        with open(raw, "wb") as fh:
            fh.write(data)
        ev = evidence_manager(raw)                                  # 전체 해시 == 세그먼트 이어붙인 해시, quick 은 '-'
        assert ev["evidence_sha256"] == hashlib.sha256(data).hexdigest() == ev["segment_hashes"][0]["sha256"]
        assert ev["evidence_quick_fingerprint"] == ev["evidence_sha256"] and ev["evidence_id"] == ev["evidence_sha256"][:16]
        assert evidence_manager(raw, quick=True)["evidence_sha256"] == EMPTY
        assert ev["evidence_md5"] == hashlib.md5(data).hexdigest() and ev["evidence_sha1"] == hashlib.sha1(data).hexdigest()
        with open(os.path.join(td, "x.txt"), "w", encoding="utf-8") as fh:
            fh.write("Created By FTK Imager\n  [Computed Hashes]\n    MD5 Hash:    %s\n    SHA1 Hash:   %s\n" % (hashlib.md5(data).hexdigest(), "0" * 40))
        ev2 = evidence_manager(raw)
        assert ev2["sidecar_declared_hashes"] == {"md5": hashlib.md5(data).hexdigest(), "sha1": "0" * 40}, ev2["sidecar_declared_hashes"]
        assert ev2["sidecar_verification"] == {"md5": "match", "sha1": "MISMATCH"}, ev2["sidecar_verification"]
        os.remove(os.path.join(td, "x.txt"))
        # raw 분할 (image.001/.002): 세그먼트를 모두 모으고 전체 해시는 이어붙인 값, 결번은 거부
        a, b = os.urandom(700), os.urandom(300)
        for n, chunk in ((1, a), (2, b)):
            with open(os.path.join(td, "split.%03d" % n), "wb") as fh:
                fh.write(chunk)
        sp = evidence_manager(os.path.join(td, "split.001"))
        assert sp["kind"] == "raw" and sp["segments"] == ["split.001", "split.002"] and sp["size_bytes"] == 1000
        assert sp["evidence_sha256"] == hashlib.sha256(a + b).hexdigest() and len(sp["segment_hashes"]) == 2
        os.rename(os.path.join(td, "split.002"), os.path.join(td, "split.003"))
        try:
            evidence_manager(os.path.join(td, "split.001")); assert False, "결번을 잡아야 한다"
        except ValueError as exc:
            assert "누락" in str(exc)
        os.remove(os.path.join(td, "split.001")); os.remove(os.path.join(td, "split.003"))
        # 소스 해시는 줄바꿈(CRLF/LF)에 영향받지 않는다 (git autocrlf 로 PC 마다 다른 파일)
        for sub, nl in (("lf", b"\n"), ("crlf", b"\r\n")):
            os.makedirs(os.path.join(td, sub))
            with open(os.path.join(td, sub, "m.py"), "wb") as fh:
                fh.write(b"x = 1" + nl + "print('한글')".encode() + nl)
        assert code_hash(os.path.join(td, "lf")) == code_hash(os.path.join(td, "crlf"))
        _self_test_contract(td)
        _self_test_db(td)
        _self_test_end_to_end(td, raw, ev["evidence_id"])
    print("self-test ok")
    return 0


def _write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _self_test_contract(td):
    """원본 헤더 계약은 엄격하게, 오류는 유형·파일·행·열·값으로."""
    ev = {"evidence_id": "e", "evidence_sha256": "-"}
    tl, cv = os.path.join(td, "timeline.csv"), os.path.join(td, "recovered_conversations.csv")
    run = {"parser": "t", "parser_version": "v", "parse_time_utc": "2026-09-21T19:22:46Z",
           "outputs": {"timeline": tl, "conversations": cv}}
    ts = "2026-09-15 13:20:41.807000 KST"
    _write_csv(tl, TIMELINE_COLUMNS, [["m", ts, "a", "b", "확정", r"C:\A\x|C:\A\x:Zone.Identifier", "-"],
                                      ["m", "-", "a", "", "추정", "-", "-"],
                                      ["m", "2026-09-15 13:20:41 KST", "a", "b", "의심", "-", "-"],
                                      ["m", ts, "a"]])
    _write_csv(cv, CONV_COLUMNS, [["m", ts, "c", "t", "u", "-", "1", "user", "hi", "-"]])
    events, messages, errors, source_rows = normalize(run, ev)
    got = [(e["type"], e["file"], e["row"], e["field"], e["actual"], e["expected"]) for e in errors if e["type"] != "UNKNOWN_USER_BEHAVIOR"]
    assert got == [("EMPTY_CELL", "timeline.csv", 3, "behavior_details", "", "값 또는 '-'"),
                   ("INVALID_VERDICT", "timeline.csv", 3, "verdict", "추정", "확정 | 의심"),
                   ("INVALID_TIMESTAMP", "timeline.csv", 4, "timestamp", "2026-09-15 13:20:41 KST", TS_RULE),
                   ("COLUMN_COUNT_MISMATCH", "timeline.csv", 5, None, 3, 7)], got
    assert source_rows == {"timeline.csv": 4, "recovered_conversations.csv": 1}
    assert all(e["parser"] == "t" for e in errors) and status_of(errors) == "contract_violation"
    ok = events[0]                                                  # 통과한 행: canonical 키, 원본 값 그대로
    assert list(ok)[:7] == TIMELINE_FIELDS and ok["artifact_path"] == r"C:\A\x|C:\A\x:Zone.Identifier"
    assert ok["artifact_path_normalized"] == r"a\x | a\x:Zone.Identifier" and ok["parse_time_utc"] == "2026-09-21T19:22:46Z"
    raw = dict(zip(TIMELINE_COLUMNS, ["m", ts, "a", "b", "확정", r"C:\A\x|C:\A\x:Zone.Identifier", "-"]))
    assert ok["row_hash"] == hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]
    assert list(messages[0])[:10] == CONV_FIELDS
    # 헤더 끝 공백이 빠진 CSV 는 고쳐 받지 않는다
    _write_csv(tl, [c.strip() for c in TIMELINE_COLUMNS], [["m", ts, "a", "b", "확정", "-", "-"]])
    events, _, errors, _ = normalize(run, ev)
    assert not events and [(e["type"], e["row"], e["field"], e["actual"], e["expected"]) for e in errors] == [
        ("HEADER_MISMATCH", 1, "behavior_details", "Behavior_details", "Behavior_details "),
        ("HEADER_MISMATCH", 1, "artifact_details", "Artifact_details", "Artifact_details ")]
    assert "앞뒤 공백" in errors[0]["message"]
    with open(tl, "wb") as fh:
        fh.write(b"\xff\xfe\x00bad")
    _, _, errors, _ = normalize(run, ev)
    assert errors[0]["type"] == "CSV_FORMAT_ERROR"
    os.remove(tl); os.remove(cv)


def _legacy_db(path):
    """이전 버전 llm_forensic.py 가 만들던 스키마 (원본 헤더 열 이름 + parse_time)."""
    db = sqlite3.connect(path)
    ev_cols = TIMELINE_COLUMNS + ["timestamp_utc"] + [LEGACY_PARSE_TIME if c == "parse_time_utc" else c for c in EXTRA_COLUMNS] + ["row_hash"]
    msg_cols = CONV_COLUMNS + ev_cols[len(TIMELINE_COLUMNS):]
    db.execute("create table evidence (evidence_id text primary key, info text)")
    db.execute("create table runs (run_id text, evidence_id text, parser text, parser_version text, "
               "%s text, python text, ok int, returncode int, elapsed_sec real, violations text, info text)" % LEGACY_PARSE_TIME)
    db.execute("create table events (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in ev_cols))
    db.execute("create table messages (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in msg_cols))
    db.execute("insert into runs values ('r0','e','old','v','2026-09-20T00:00:00Z','py',1,0,1.0,'[]','{}')")
    for i, parser in enumerate(("old", "keep")):
        row = dict.fromkeys(ev_cols, "-")
        row.update({"Artifact_path": r"C:\A\x|C:\B\y", "artifact_path_normalized": r"a\x|c:\b\y", "volume_ref": "ntfs@9",
                    "source_parser": parser, "evidence_id": "e", "row_hash": "h%d" % i})
        db.execute("insert into events values (%s)" % ",".join("?" * len(ev_cols)), [row[c] for c in ev_cols])
    db.commit()
    db.close()


def _self_test_db(td):
    """이전 스키마 열 이름 변환, 초기화 범위(전체 / --only), runs 이력 보존, 트랜잭션 롤백."""
    path = os.path.join(td, "legacy.db")
    _legacy_db(path)
    db, migrated = open_db(path)
    assert migrated and _cols(db, "events")[:len(_EV_COLS)] == _EV_COLS and "status" in _cols(db, "runs")
    assert _cols(db, "runs")[:len(_RUN_COLS)] == _RUN_COLS and _cols(db, "messages")[:len(_MSG_COLS)] == _MSG_COLS
    assert db.execute("select artifact_path, artifact_path_normalized, volume_ref from events where row_hash='h0'").fetchone() \
        == (r"C:\A\x|C:\B\y", r"a\x | b\y", "ntfs@9")           # 원본·volume_ref 그대로, 정규화 열만 다시 계산
    assert db.execute("select parse_time_utc from runs").fetchone() == ("2026-09-20T00:00:00Z",)
    db.close()
    db, migrated = open_db(path)                                 # 두 번째 열기는 변환 없음
    assert not migrated
    assert reset_results(db, "e", ["old"]) == {"events": 1, "messages": 0}    # --only old: keep 은 남는다
    assert [r[0] for r in db.execute("select source_parser from events")] == ["keep"]
    assert reset_results(db, "e") == {"events": 1, "messages": 0}             # 전체 실행: evidence 전체
    assert db.execute("select count(*) from runs").fetchone() == (1,)        # runs 이력은 지우지 않는다
    try:
        with _tx(db):
            db.execute("insert into runs (run_id) values ('tmp')")
            raise sqlite3.OperationalError("boom")
    except sqlite3.OperationalError:
        pass
    assert db.execute("select count(*) from runs").fetchone() == (1,) and not db.in_transaction
    db.close()


def _self_test_end_to_end(td, image, evidence_id):
    """가짜 파서 3개로 실제 CLI 를 subprocess 로 실행: 콘솔 분리, run.log, 보고서, 재실행 초기화, --only 보존."""
    fake = os.path.join(td, "fake_parser.py")
    with open(fake, "w", encoding="utf-8") as fh:
        fh.write(_FAKE_PARSER)
    reg = {"parsers": [{"name": n, "model": n, "python": sys.executable, "cwd": td,
                        "args": ["fake_parser.py", n, mode, "{out}"],
                        "outputs": {"timeline": "timeline.csv", "conversations": "recovered_conversations.csv"}}
                       for n, mode in (("alpha", "ok"), ("beta", "bad"), ("gamma", "fail"), ("delta", "ok"))]}
    reg["parsers"][3]["inputs"] = [".e01"]             # delta 는 E01 만 지원한다고 선언 → .dd 입력이면 실행 없이 UNSUPPORTED_INPUT
    reg_path, out = os.path.join(td, "reg.json"), os.path.join(td, "out")
    with open(reg_path, "w", encoding="utf-8") as fh:
        json.dump(reg, fh)
    case = os.path.join(out, evidence_id)

    def cli(*extra, **env):
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "-i", image, "-o", out, "--registry", reg_path] + list(extra),
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env=dict(os.environ, PYTHONIOENCODING="utf-8", **env))
        console = r.stdout + r.stderr
        assert "fake stdout" not in console and "fake stderr" not in console, console   # 파서 출력은 콘솔에 없다
        with open(os.path.join(case, REPORT_NAME), encoding="utf-8") as fh:
            return r.returncode, console, json.load(fh)

    def db_rows(sql):
        db = sqlite3.connect(os.path.join(case, "unified.db"))
        try:
            return db.execute(sql).fetchall()
        finally:
            db.close()

    # 1) 전체 실행: alpha 성공, beta 계약 위반, gamma 실행 실패
    rc, console, rep = cli()
    assert rc == 1, console
    assert re.search(r"\[Runner\] alpha +OK ", console) and re.search(r"\[Runner\] beta +CONTRACT_VIOLATION", console)
    assert re.search(r"\[Runner\] gamma +FAILED .*PARSER_EXECUTION_ERROR", console)
    assert os.path.join(case, "gamma", "run.log") in console and "[Report] " in console
    with open(os.path.join(case, "alpha", "run.log"), encoding="utf-8") as fh:
        log = fh.read()
    assert "fake stdout" in log and "fake stderr" in log and "returncode=0" in log                # 상세는 run.log 에
    p = rep["parsers"]
    assert (p["alpha"]["status"], p["alpha"]["timeline_rows"], p["alpha"]["conversation_rows"]) == ("success", 2, 1)
    assert p["beta"]["status"] == "contract_violation" and p["beta"]["timeline_rows"] == 0
    assert {"type": "INVALID_VERDICT", "file": "timeline.csv", "row": 4, "field": "verdict", "actual": "추정",
            "expected": "확정 | 의심"}.items() <= next(e for e in p["beta"]["errors"] if e["type"] == "INVALID_VERDICT").items()
    assert set(p["beta"]["error_types"]) - {"UNKNOWN_USER_BEHAVIOR"} == {"EMPTY_CELL", "INVALID_VERDICT", "INVALID_TIMESTAMP"}
    # 행위명 경고: alpha 의 '프롬프트 전송'·'테스트용 비표준 행위' 는 목록에 없는 이름 → 경고 2건, 그래도 success 이고 2행 다 적재
    assert p["alpha"]["error_types"] == {"UNKNOWN_USER_BEHAVIOR": 2} and p["alpha"]["status"] == "success"
    assert {(e["row"], e["actual"]) for e in p["alpha"]["errors"]} == {(2, "프롬프트 전송"), (3, "테스트용 비표준 행위")}
    assert "UNKNOWN_USER_BEHAVIOR x2" in console
    assert p["gamma"]["status"] == "failed" and [e["type"] for e in p["gamma"]["errors"]] == [
        "PARSER_EXECUTION_ERROR", "OUTPUT_MISSING", "OUTPUT_MISSING"]
    assert p["delta"]["status"] == "failed" and [e["type"] for e in p["delta"]["errors"]] == ["UNSUPPORTED_INPUT"]
    assert re.search(r"\[Runner\] delta +FAILED .*UNSUPPORTED_INPUT", console) and p["delta"]["elapsed_sec"] < 1
    with open(os.path.join(case, "delta", "run.log"), encoding="utf-8") as fh:
        assert "지원하지 않음" in fh.read()               # 실행 안 했어도 사유는 run.log 에 남는다
    assert p["alpha"]["artifacts_found"] and not p["gamma"]["artifacts_found"]
    assert rep["summary"] == {"parsers_run": 4, "success": 1, "failed": 2, "contract_violation": 1,
                              "normalization_error": 0, "db_error": 0} and rep["exit_code"] == 1
    with open(os.path.join(case, "timeline.csv"), encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == TIMELINE_COLUMNS + EXTRA_COLUMNS                      # 병합 CSV 헤더는 팀 계약 그대로
    tl = [dict(zip([canonical_header(h) for h in rows[0]], r)) for r in rows[1:]]
    assert {r["artifact_path_normalized"] for r in tl} == {r"users\a\downloads\x.pdf | users\a\downloads\x.pdf:Zone.Identifier",
                                                          r"users\a\y.txt | users\a\z"}
    assert {r["volume_ref"] for r in tl} == {"C:"}                             # C:\ · volume0:\Users · NTFS@7/Users 모두 C:
    assert all(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", r["parse_time_utc"]) for r in tl)
    with open(os.path.join(case, "recovered_conversations.csv"), encoding="utf-8-sig", newline="") as fh:
        assert next(csv.reader(fh)) == CONV_COLUMNS + EXTRA_COLUMNS

    # 2) 같은 evidence 재실행 (alpha 출력이 바뀜): 이전 alpha 행은 남지 않고 runs 이력은 쌓인다
    rc, console, rep = cli(FAKE_MODE_ALPHA="v2")
    assert db_rows("select distinct behavior_details from events where source_parser='alpha' and behavior_details like 'v=%'") == [("v=v2",)]
    assert db_rows("select content from messages") == [("hello v2",)]
    assert db_rows("select count(*) from runs") == [(8,)] and rep["db"]["reset"]["scope"] == "evidence"

    # 3) --only beta (이번엔 성공): alpha 결과는 유지, beta 만 교체
    rc, console, rep = cli("--only", "beta", FAKE_MODE_BETA="ok")
    assert rc == 0 and list(rep["parsers"]) == ["beta"] and rep["db"]["reset"]["parsers"] == ["beta"]
    assert db_rows("select source_parser, count(*) from events group by source_parser order by 1") == [("alpha", 2), ("beta", 2)]
    assert rep["preserved_from_previous_runs"] == ["alpha"]
    # 4) --only beta 가 다시 계약 위반이면 beta 의 이전 결과도 빠진다 (alpha 는 그대로)
    rc, console, rep = cli("--only", "beta")
    assert rc == 1 and db_rows("select source_parser, count(*) from events group by source_parser order by 1") == [("alpha", 2)]
    assert db_rows("select count(*) from runs") == [(10,)]
    # 5) 헤더 끝 공백이 빠진 CSV → HEADER_MISMATCH 로 거부
    rc, console, rep = cli("--only", "beta", FAKE_BAD_HEADER="1")
    assert rep["parsers"]["beta"]["error_types"].get("HEADER_MISMATCH") == 1 and "HEADER_MISMATCH" in console

    # 6) DB 초기화 실패 → DB_ERROR, 파서를 실행하지 않고 종료코드 3
    os.remove(os.path.join(case, "unified.db"))
    os.makedirs(os.path.join(case, "unified.db"))
    rc, console, rep = cli()
    assert rc == 3 and not rep["parsers"] and rep["integration_errors"][0]["type"] == "DB_ERROR" and "[Runner]" not in console


if __name__ == "__main__":
    sys.exit(main())
