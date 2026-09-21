#!/usr/bin/env python3
"""LLM 파서 통합 제어 프로그램 (표준 라이브러리만 사용).

    python llm_forensic.py -i <이미지.E01|.dd> -o <출력폴더> [--only a,b] [--registry parsers.json]

층 구성 (팀 설계도 순서):
  1. Evidence Manager   입력 확인 · evidence_id · E01/DD 구분 · 세그먼트 결번 검사
  2. Parser Runner      parsers.json 레지스트리대로 파서 6개를 subprocess 실행 (각자 venv)
  3. Normalizer         CSV 계약 검사 → 공통 Event/Message 형식 (+ artifact_path_normalized, volume_ref)
  4. Unified DB         SQLite (evidence / runs / events / messages)
  5. Timeline Generator 정렬 후 병합 timeline.csv · recovered_conversations.csv
종료코드: 0 전부 성공 / 1 일부 파서 실패 또는 계약 위반 / 2 입력 자체 실패
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
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TIMELINE_COLUMNS = ["Model", "Timestamp", "User_behavior", "Behavior_details ", "Verdict",
                    "Artifact_path", "Artifact_details "]
CONV_COLUMNS = ["Model", "timestamp", "conversation_uuid", "conversation_title", "message_uuid",
                "parent_message_uuid", "message order", "role", "content", "Artifact_path"]
# provenance 열 (병합 CSV 와 DB 에 팀 7/10열 뒤에 붙는다). 원본 열은 절대 덮어쓰지 않는다:
#   Timestamp/timestamp = timestamp_raw (파서 표기 그대로), timestamp_utc = 정규화 / Artifact_path = raw, artifact_path_normalized = 정규화
EXTRA_COLUMNS = ["source_parser", "parser_version", "source_file", "parse_time",
                 "artifact_path_normalized", "volume_ref", "evidence_id", "evidence_sha256"]
VERDICTS = {"확정", "의심"}
EMPTY = "-"
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} KST$")
EWF1_SIG = b"EVF\x09\x0d\x0a\xff\x00"


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
    evidence_sha256, segment_hashes = EMPTY, []
    if not quick:                                       # 한 번 읽으면서 세그먼트별 해시와 전체 해시를 같이 계산 (36GB 기준 수 분)
        full = hashlib.sha256()
        for s in segments:
            seg = hashlib.sha256()
            with open(s, "rb") as fh:
                for chunk in iter(lambda: fh.read(8 << 20), b""):
                    seg.update(chunk); full.update(chunk)
            segment_hashes.append({"file": os.path.basename(s), "size_bytes": os.path.getsize(s), "sha256": seg.hexdigest()})
        evidence_sha256 = full.hexdigest()
    sidecars = {}
    for f in os.listdir(os.path.dirname(path)):        # 동봉 해시 파일은 내용만 기록 (대조는 분석자 몫)
        if f.lower().endswith((".sha256", ".md5", "_md5.txt", "_sha256.txt")):
            with open(os.path.join(os.path.dirname(path), f), encoding="utf-8", errors="replace") as fh:
                sidecars[f] = fh.read().strip()[:300]
    return {"evidence_id": quick_fp[:16], "evidence_quick_fingerprint": quick_fp, "evidence_sha256": evidence_sha256,
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
                    h.update(fh.read())
    return h.hexdigest()[:16]


def run_parser(p, image, out_dir):
    shutil.rmtree(out_dir, ignore_errors=True)         # 이전 실행 결과는 지운다 (gemini 처럼 기존 출력이 있으면 거부하는 파서가 있음; 이전 행은 DB runs 에 남아 있다)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [p["python"]] + [a.format(image=image, out=out_dir) for a in p["args"]]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", **p.get("env", {}))
    version = "%s (code=%s)" % (parser_version(p, env), code_hash(p["cwd"]))
    parse_time = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=p["cwd"], env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=p.get("timeout_sec", 1800))
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = -1, "", "timeout %ss" % p.get("timeout_sec", 1800)
    except OSError as exc:
        rc, out, err = -2, "", str(exc)
    with open(os.path.join(out_dir, "run.log"), "w", encoding="utf-8") as fh:
        fh.write("# parser=%s version=%s python=%s cwd=%s started=%s\n$ %s\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n"
                 % (p["name"], version, p["python"], p["cwd"], parse_time, " ".join(cmd), out, err))
    files = {k: os.path.join(out_dir, v) for k, v in p["outputs"].items()}
    missing = [k for k, v in files.items() if not os.path.isfile(v)]
    return {"parser": p["name"], "model": p["model"], "parser_version": version, "parse_time": parse_time,
            "python": p["python"], "cmd": cmd, "returncode": rc,
            "elapsed_sec": round(time.time() - t0, 1), "outputs": files, "missing_outputs": missing,
            "ok": rc == 0 and not missing, "stderr_tail": err[-500:]}


# ---------------------------------------------------------------- 3. Normalizer
_PREFIXES = [re.compile(r"^[A-Za-z]:[\\/]"), re.compile(r"^volume\d+:[\\/]", re.I),
             re.compile(r"^.*::NTFS@\d+[\\/]", re.I), re.compile(r"^[\\/]+")]


def normalize_path(raw):
    """드라이브·볼륨·이미지 접두어를 떼고 볼륨 루트 기준, 구분자 \\, 소문자. 여러 경로는 ' | ' 로 유지."""
    parts = []
    for one in str(raw).split(" | "):
        s = one.strip()
        for rx in _PREFIXES:
            s = rx.sub("", s)
        parts.append(s.replace("/", "\\").lower())
    return " | ".join(x for x in parts if x) or EMPTY


def volume_ref(path, details="", run_volume=None):
    """볼륨 식별자. 우선순위: Artifact_details 의 volume=/partition_offset= 키 → 경로의 NTFS@오프셋·volumeN → 실행 단위 값 → '-'."""
    m = re.search(r"\bvolume=([^,;|\s]+)", str(details), re.I) or re.search(r"partition_offset=(\d+)", str(details), re.I)
    if m:
        v = m.group(1)
        return v if v.lower().startswith(("ntfs@", "volume")) else "ntfs@%s" % v
    m = re.search(r"NTFS@(\d+)", str(path), re.I)
    if m:
        return "ntfs@%s" % m.group(1)
    m = re.match(r"^(volume\d+):", str(path), re.I)
    if m:
        return m.group(1).lower()
    return run_volume or EMPTY


def run_volume_from_json(p, out_dir):
    """레지스트리 volume_json: 파서가 실행 단위로 고른 파티션을 JSON 에서 읽는다 (행 단위 정보가 없는 파서용)."""
    spec = p.get("volume_json")
    if not spec:
        return None
    try:
        with open(os.path.join(out_dir, spec["file"]), encoding="utf-8") as fh:
            node = json.load(fh)
        for key in spec["pointer"].strip("/").split("/"):
            node = node[int(key)] if isinstance(node, list) else node[key]
        m = re.search(spec["regex"], str(node))
        return spec["format"].format(*m.groups()) if m else None
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        return None


def kst_to_utc(ts):
    if not TS_RE.match(ts or ""):
        return None
    dt = datetime.strptime(ts[:-4], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone(timedelta(hours=9)))
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def read_csv(path, columns):
    """헤더가 계약과 바이트 단위로 같아야 한다. 아니면 ValueError."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows or rows[0] != columns:
        raise ValueError("헤더 불일치 %s: %r" % (os.path.basename(path), rows[0] if rows else None))
    bad = [i for i, r in enumerate(rows[1:], 2) if len(r) != len(columns)]
    if bad:
        raise ValueError("열 수 불일치 %s: 행 %s" % (os.path.basename(path), bad[:5]))
    return [dict(zip(columns, r)) for r in rows[1:]]


def normalize(run, evidence, run_volume=None):
    """파서 결과 CSV 2개 → (events, messages, violations). 원본 열은 그대로, provenance·정규화 열만 덧붙인다."""
    violations, events, messages = [], [], []
    tl = read_csv(run["outputs"]["timeline"], TIMELINE_COLUMNS)
    cv = read_csv(run["outputs"]["conversations"], CONV_COLUMNS)
    evidence_id = evidence["evidence_id"]
    prov = {"source_parser": run["parser"], "parser_version": run["parser_version"], "parse_time": run["parse_time"],
            "evidence_id": evidence_id, "evidence_sha256": evidence["evidence_sha256"]}
    for i, r in enumerate(tl, 2):
        if r["Verdict"] not in VERDICTS:
            violations.append("timeline 행 %d Verdict=%r" % (i, r["Verdict"]))
        if r["Timestamp"] != EMPTY and not TS_RE.match(r["Timestamp"]):
            violations.append("timeline 행 %d Timestamp=%r" % (i, r["Timestamp"]))
        if any(v == "" for v in r.values()):
            violations.append("timeline 행 %d 빈 셀" % i)
        row_hash = hashlib.sha256(json.dumps(r, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]
        events.append({**r, **prov, "timestamp_utc": kst_to_utc(r["Timestamp"]),
                       "source_file": os.path.basename(run["outputs"]["timeline"]),
                       "artifact_path_normalized": normalize_path(r["Artifact_path"]),
                       "volume_ref": volume_ref(r["Artifact_path"], r["Artifact_details "], run_volume),
                       "row_hash": row_hash})
    for i, r in enumerate(cv, 2):
        if r["timestamp"] != EMPTY and not TS_RE.match(r["timestamp"]):
            violations.append("conversations 행 %d timestamp=%r" % (i, r["timestamp"]))
        row_hash = hashlib.sha256(json.dumps(r, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]
        messages.append({**r, **prov, "timestamp_utc": kst_to_utc(r["timestamp"]),
                         "source_file": os.path.basename(run["outputs"]["conversations"]),
                         "artifact_path_normalized": normalize_path(r["Artifact_path"]),
                         "volume_ref": volume_ref(r["Artifact_path"], "", run_volume),
                         "row_hash": row_hash})
    return events, messages, violations


# ---------------------------------------------------------------- 4. Unified DB
_EV_COLS = TIMELINE_COLUMNS + ["timestamp_utc"] + EXTRA_COLUMNS + ["row_hash"]
_MSG_COLS = CONV_COLUMNS + ["timestamp_utc"] + EXTRA_COLUMNS + ["row_hash"]


def _q(c):
    return '"%s"' % c


def open_db(path):
    db = sqlite3.connect(path)
    db.execute("create table if not exists evidence (evidence_id text primary key, info text)")
    db.execute("create table if not exists runs (run_id text, evidence_id text, parser text, parser_version text, "
               "parse_time text, python text, ok int, returncode int, elapsed_sec real, violations text, info text)")
    db.execute("create table if not exists events (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in _EV_COLS))
    db.execute("create table if not exists messages (%s, primary key(evidence_id, row_hash))" % ", ".join(_q(c) + " text" for c in _MSG_COLS))
    return db


def store(db, evidence, run_id, run, events, messages, violations):
    db.execute("insert or replace into evidence values (?, ?)", (evidence["evidence_id"], json.dumps(evidence, ensure_ascii=False)))
    db.execute("insert into runs values (?,?,?,?,?,?,?,?,?,?,?)",
               (run_id, evidence["evidence_id"], run["parser"], run["parser_version"], run["parse_time"], run["python"],
                int(run["ok"]), run["returncode"], run["elapsed_sec"],
                json.dumps(violations, ensure_ascii=False), json.dumps(run, ensure_ascii=False, default=str)))
    for table, cols, rows in (("events", _EV_COLS, events), ("messages", _MSG_COLS, messages)):
        db.executemany("insert or ignore into %s (%s) values (%s)" % (table, ", ".join(map(_q, cols)), ", ".join("?" * len(cols))),
                       [[r.get(c) for c in cols] for r in rows])
    db.commit()


# ---------------------------------------------------------------- 5. Timeline Generator
def _safe(v):
    s = EMPTY if v is None or str(v).strip() == "" else str(v)
    return "'" + s if s != EMPTY and s[:1] in ("=", "+", "-", "@") else s


def write_merged(db, evidence_id, out_dir):
    written = []
    for name, table, cols, ts in (("timeline.csv", "events", TIMELINE_COLUMNS, "Timestamp"),
                                  ("recovered_conversations.csv", "messages", CONV_COLUMNS, "timestamp")):
        out_cols = cols + EXTRA_COLUMNS
        rows = db.execute("select %s from %s where evidence_id=? order by (timestamp_utc is null), timestamp_utc, source_parser"
                          % (", ".join(map(_q, out_cols)), table), (evidence_id,)).fetchall()
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(out_cols)
            for r in rows:
                w.writerow([_safe(c) for c in r])
        written.append((path, len(rows)))
    return written


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--image")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--registry", default=os.path.join(HERE, "parsers.json"))
    ap.add_argument("--only", help="쉼표로 구분한 파서 이름만 실행")
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

    reg = load_registry(args.registry)
    only = set(args.only.split(",")) if args.only else None
    parsers = [p for p in reg["parsers"] if p.get("enabled", True) and (only is None or p["name"] in only)]
    case_dir = os.path.join(os.path.abspath(args.out), ev["evidence_id"])
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "evidence_manifest.json"), "w", encoding="utf-8") as fh:   # 세그먼트별 SHA-256 매니페스트
        json.dump(ev, fh, ensure_ascii=False, indent=2)
    db = open_db(os.path.join(case_dir, "unified.db"))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    failed = 0
    for p in parsers:
        print("[Runner] %-16s" % p["name"], end="", flush=True)
        run = run_parser(p, ev["path"], os.path.join(case_dir, p["name"]))
        events = messages = []
        violations = []
        if run["ok"]:
            try:
                events, messages, violations = normalize(run, ev, run_volume_from_json(p, os.path.join(case_dir, p["name"])))
            except ValueError as exc:
                violations = [str(exc)]
        status = "OK" if run["ok"] and not violations else ("계약 위반" if run["ok"] else "실패 rc=%s" % run["returncode"])
        if status != "OK":
            failed += 1
            events, messages = [], []          # 계약을 어긴 결과는 적재하지 않는다 (병합본 오염 방지)
        store(db, ev, run_id, run, events, messages, violations)
        print(" %-10s %6.1fs  events=%-3d messages=%-3d %s" % (status, run["elapsed_sec"], len(events), len(messages),
                                                             ("; ".join(violations[:2]) or run["stderr_tail"].strip().splitlines()[-1:] or [""])[0][:90]))

    for path, n in write_merged(db, ev["evidence_id"], case_dir):
        print("[Timeline] %s  %d행" % (path, n))
    print("[DB] %s" % os.path.join(case_dir, "unified.db"))
    print("[Summary] 파서 %d개 중 %d 성공, %d 실패·위반 (run_id=%s)" % (len(parsers), len(parsers) - failed, failed, run_id))
    return 1 if failed else 0


def self_test():
    assert normalize_path(r"C:\Users\A\x.txt") == r"users\a\x.txt"
    assert normalize_path("Users/A/x.txt | volume0:\\Users\\B\\y") == r"users\a\x.txt | users\b\y"
    assert normalize_path("D:/img.E01::NTFS@227540992/Users/llmtest/History") == r"users\llmtest\history"
    assert volume_ref("img.E01::NTFS@227540992/Users") == "ntfs@227540992"
    assert volume_ref("volume0:\\Users") == "volume0" and volume_ref("C:\\Users") == EMPTY
    assert volume_ref("C:\\Users", "[Rollout] MFT=1, volume=ntfs@227540992, 규칙=E04-01") == "ntfs@227540992"
    assert volume_ref("C:\\Users", "x, partition_offset=1048576; y") == "ntfs@1048576"
    assert volume_ref("Users/a", "", "ntfs@5") == "ntfs@5"
    assert kst_to_utc("2026-09-15 13:20:41.807000 KST") == "2026-09-15T04:20:41.807000Z"
    assert kst_to_utc("-") is None and kst_to_utc("2026-09-15 13:20:41 KST") is None
    assert _safe("=1") == "'=1" and _safe("") == EMPTY and _safe("-") == EMPTY
    assert _ewf_ext(1) == "E01" and _ewf_ext(99) == "E99" and _ewf_ext(100) == "EAA"
    assert len(code_hash(HERE)) == 16 and code_hash(HERE) == code_hash(HERE)
    assert set(EXTRA_COLUMNS) >= {"source_parser", "parser_version", "source_file", "parse_time",
                                  "artifact_path_normalized", "volume_ref", "evidence_id", "evidence_sha256"}
    import tempfile
    with tempfile.TemporaryDirectory() as td:                       # 전체 해시 == 세그먼트 이어붙인 해시, quick 은 '-'
        raw = os.path.join(td, "x.dd"); data = os.urandom(1000)
        with open(raw, "wb") as fh:
            fh.write(data)
        ev = evidence_manager(raw)
        assert ev["evidence_sha256"] == hashlib.sha256(data).hexdigest() == ev["segment_hashes"][0]["sha256"]
        assert ev["evidence_quick_fingerprint"] == ev["evidence_sha256"] and ev["evidence_id"] == ev["evidence_sha256"][:16]
        assert evidence_manager(raw, quick=True)["evidence_sha256"] == EMPTY
    print("self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
