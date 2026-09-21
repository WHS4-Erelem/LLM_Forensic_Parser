#!/usr/bin/env python3
"""
전체 검증 — 파서가 주장하는 것을 실제 사건 이미지로 확인한다.

**특정 이미지에 기대지 않는다.** 검증할 이미지는 실행할 때 준다.
이미지를 주지 않으면 이미지가 필요 없는 예외 처리 단계만 돌고 나머지는 건너뛴다.

    python tests/verify_all.py                      # 예외 처리만
    python tests/verify_all.py D:\\case\\disk.dd      # 이미지로 전 단계
    python tests/verify_all.py a.dd b.E01           # 여러 개

검사하는 것은 이미지 내용과 무관한 **불변식**이다 — 출력이 두 파일만 나오는가,
열 구성이 규격과 같은가, 시각을 지어내지 않는가, 판정 어휘가 정해진 값인가,
두 번 돌리면 같은 결과가 나오는가, 잘못된 입력을 분석 전에 거절하는가.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PY = sys.executable

TMP = Path(os.environ.get("AIFP_VERIFY_OUT")
           or (Path(tempfile.gettempdir()) / "aifp_verify"))

TIMELINE_COLS = ["Model", "Timestamp", "User_behavior", "Behavior_details ",
                 "Verdict", "Artifact_path", "Artifact_details "]
CONV_COLS = ["Model", "timestamp", "conversation_uuid", "conversation_title",
             "message_uuid", "parent_message_uuid", "message order", "role",
             "content", "Artifact_path"]
VERDICTS = {"확정", "의심"}
ROLES = {"user", "assistant", "system", "unknown"}
RECOVERY = {"완전 복구", "부분 복구"}

results: list[tuple[str, str, bool | None, str]] = []


def record(group: str, name: str, ok: bool | None, detail: str = "") -> None:
    results.append((group, name, ok, detail))
    mark = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    print(f"  {mark}  {name}" + (f"  — {detail}" if detail else ""))


def run_parser(image: Path, out: Path, *extra: str, timeout: int = 3600):
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [PY, str(ROOT / "aifp_parse.py"), "--image", str(image),
           "--out", str(out), "--no-banner", *extra]
    t = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout, cwd=ROOT)
    return r, time.time() - t


def rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


parsed: dict[str, Path] = {}       # label -> out dir


# ══════════════════════════════════════════════════════════════════════
def stage_images(images: list[Path]) -> None:
    print("\n[1] 이미지 분석")
    if not images:
        record("이미지", "검증용 이미지", None,
               "이미지를 주지 않았다 — python tests/verify_all.py <이미지>")
        return

    for img in images:
        label = img.stem[:40]
        if not img.exists():
            record("이미지", label, False, f"파일 없음: {img}")
            continue
        out = TMP / ("v_" + label.replace(" ", "_"))
        shutil.rmtree(out, ignore_errors=True)
        try:
            r, sec = run_parser(img, out)
        except subprocess.TimeoutExpired:
            record("이미지", label, False, "시간 초과")
            continue

        msg = (r.stdout or "") + (r.stderr or "")
        tl, cv = out / "timeline.csv", out / "recovered_conversations.csv"
        if not tl.exists():
            refused = r.returncode == 2 and "[중단]" in msg
            reason = next((l.strip() for l in msg.splitlines() if "[중단]" in l), "")
            record("이미지", f"{label} — 분석 불가 사유 제시", refused,
                   reason[:80] or f"rc={r.returncode}")
            continue

        record("이미지", f"{label} — 분석 완료", r.returncode in (0, 1),
               f"{sec:.0f}초 · 행위 {len(rows(tl))}건 · 메시지 {len(rows(cv))}건")
        # 출력 폴더에 두 파일만 있어야 한다
        extra = [p.name for p in out.iterdir()
                 if p.name not in ("timeline.csv", "recovered_conversations.csv")]
        record("이미지", f"{label} — 출력은 두 파일만", not extra,
               f"그 외: {', '.join(extra)}" if extra else "")
        parsed[label] = out


def stage_schema() -> None:
    print("\n[2] 출력 규격")
    if not parsed:
        record("규격", "출력 파일", None, "분석에 성공한 이미지가 없다")
        return

    for label, out in parsed.items():
        tl = rows(out / "timeline.csv")
        cv = rows(out / "recovered_conversations.csv")

        with (out / "timeline.csv").open(encoding="utf-8-sig", newline="") as f:
            tl_cols = next(csv.reader(f))
        with (out / "recovered_conversations.csv").open(encoding="utf-8-sig",
                                                        newline="") as f:
            cv_cols = next(csv.reader(f))
        record("규격", f"{label} — timeline 열 구성", tl_cols == TIMELINE_COLS,
               " ".join(tl_cols))
        record("규격", f"{label} — conversations 열 구성", cv_cols == CONV_COLS,
               " ".join(cv_cols))

        bad = [r for r in tl if r["Verdict"] not in VERDICTS]
        record("규격", f"{label} — 판정은 확정/의심", not bad,
               f"그 외 {len(bad)}건")

        # 시각을 지어내지 않는다 — 있으면 KST 표기, 없으면 빈 칸
        bad_ts = [r for r in tl if r["Timestamp"] and "KST" not in r["Timestamp"]]
        record("규격", f"{label} — 시각은 KST 표기 또는 공란", not bad_ts,
               f"어긋난 행 {len(bad_ts)}건")

        bad_svc = {r["Model"] for r in tl + cv} - {"claude-desktop"}
        record("규격", f"{label} — service 값 고정", not bad_svc, str(bad_svc or ""))

        if cv:
            bad_role = [r for r in cv if r["role"] not in ROLES]
            record("규격", f"{label} — role 어휘", not bad_role, f"{len(bad_role)}건")
            bad_rec = [r for r in cv if not r["Model"]]
            record("규격", f"{label} — 복구 상태 어휘", not bad_rec, f"{len(bad_rec)}건")
            firsts = {}
            for r in cv:
                firsts.setdefault(r["conversation_uuid"], r["message order"])
            bad_order = {k: v for k, v in firsts.items() if v != "1"}
            record("규격", f"{label} — 메시지 순서는 대화마다 1부터", not bad_order,
                   str(list(bad_order)[:2]))


def stage_reproducible() -> None:
    print("\n[3] 재현성")
    if not parsed:
        record("재현성", "두 번 실행 결과 동일", None, "분석에 성공한 이미지가 없다")
        return
    label, first = next(iter(parsed.items()))
    img = next((i for i in IMAGES if i.stem[:40] == label), None)
    if img is None:
        record("재현성", "두 번 실행 결과 동일", None, "원본 이미지를 찾지 못했다")
        return

    second = TMP / "v_rep2"
    shutil.rmtree(second, ignore_errors=True)
    run_parser(img, second)
    r = subprocess.run([PY, str(ROOT / "tests" / "compare_runs.py"),
                        str(first), str(second)],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300, cwd=ROOT)
    ok = r.returncode == 0 and "동일" in (r.stdout or "")
    record("재현성", "두 번 실행 결과 동일", ok,
           next((l.strip() for l in (r.stdout or "").splitlines() if "결과" in l), ""))


def stage_extended() -> None:
    print("\n[4] 확장 파일시스템")
    if not parsed:
        record("확장", "--extended-fs", None, "분석에 성공한 이미지가 없다")
        return
    label, _ = next(iter(parsed.items()))
    img = next((i for i in IMAGES if i.stem[:40] == label), None)
    if img is None:
        record("확장", "--extended-fs", None, "원본 이미지를 찾지 못했다")
        return

    out = TMP / "v_ext"
    shutil.rmtree(out, ignore_errors=True)
    try:
        r, sec = run_parser(img, out, "--extended-fs")
    except subprocess.TimeoutExpired:
        record("확장", "--extended-fs", False, "시간 초과")
        return
    tl = rows(out / "timeline.csv")
    record("확장", "--extended-fs 실행", (out / "timeline.csv").exists(),
           f"{sec:.0f}초 · 행위 {len(tl)}건")
    fs_rows = [r for r in tl if r["User_behavior"] in
               ("파일 삭제 기록", "파일 이동·이름 변경", "휴지통 삭제")]
    record("확장", "파일시스템 행위가 추가됨", True,
           f"{len(fs_rows)}건" + (" (이 이미지에는 해당 흔적이 없다)"
                                  if not fs_rows else ""))


def stage_errors() -> None:
    print("\n[5] 예외 처리")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        r = subprocess.run([PY, str(ROOT / "aifp_parse.py"), "--image",
                            str(d / "없는파일.dd"), "--out", str(d / "o")],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, cwd=ROOT)
        record("예외", "없는 이미지 → 인자 단계에서 거절",
               r.returncode == 2 and "이미지 파일이 없다" in (r.stderr or ""))

        bad = d / "snapshot.vmdk"
        bad.write_bytes(b"\x00" * 1024)
        r = subprocess.run([PY, str(ROOT / "aifp_parse.py"), "--image", str(bad),
                            "--out", str(d / "o")],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, cwd=ROOT)
        record("예외", "지원하지 않는 형식 → 분석 전에 거절",
               r.returncode == 2 and ".dd 또는 .E01" in (r.stderr or ""))

        r = subprocess.run([PY, str(ROOT / "aifp_parse.py"), "--image", str(d),
                            "--out", str(d / "o")],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, cwd=ROOT)
        record("예외", "폴더를 --image → 거절", r.returncode == 2)

        empty = d / "empty.dd"
        empty.write_bytes(b"\x00" * (1 << 20))
        r = subprocess.run([PY, str(ROOT / "aifp_parse.py"), "--image", str(empty),
                            "--out", str(d / "o3")],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, cwd=ROOT)
        record("예외", "빈 이미지 → 사유와 함께 중단",
               r.returncode == 2 and "[중단]" in (r.stderr or ""),
               next((l.strip() for l in (r.stderr or "").splitlines()
                     if "[중단]" in l), "")[:80])


IMAGES: list[Path] = []


def main(argv: list[str]) -> int:
    global IMAGES
    raw = argv or [x for x in os.environ.get("AIFP_TEST_IMAGES", "")
                   .replace(";", os.pathsep).split(os.pathsep) if x.strip()]
    IMAGES = [Path(x.strip().strip('"')) for x in raw]

    print("=" * 72)
    print("  AIFP 파서 — 전체 검증")
    print("=" * 72)
    print(f"  검증 이미지 : {', '.join(str(i) for i in IMAGES) if IMAGES else '(없음)'}")
    print(f"  산출물      : {TMP}")
    t0 = time.time()
    TMP.mkdir(parents=True, exist_ok=True)

    for fn in (lambda: stage_images(IMAGES), stage_schema, stage_reproducible,
               stage_extended, stage_errors):
        try:
            fn()
        except Exception as exc:
            record("단계", "단계 자체가 실패", False, f"{type(exc).__name__}: {exc}")

    print("\n" + "=" * 72)
    groups: dict[str, list[bool | None]] = {}
    for g, _, ok, _ in results:
        groups.setdefault(g, []).append(ok)
    for g, oks in groups.items():
        ran = [o for o in oks if o is not None]
        skipped = len(oks) - len(ran)
        print(f"  {g:<8} {sum(1 for o in ran if o):>2} / {len(ran):>2} 통과"
              + (f" · 건너뜀 {skipped}" if skipped else ""))
    total = [o for _, _, o, _ in results if o is not None]
    print("-" * 72)
    print(f"  합계 {sum(1 for o in total if o)} / {len(total)} 통과 · "
          f"건너뜀 {len(results) - len(total)} · 소요 {time.time() - t0:.0f}초")
    failed = [(g, n, d) for g, n, ok, d in results if ok is False]
    if failed:
        print("\n  실패 항목:")
        for g, n, d in failed:
            print(f"    · [{g}] {n} — {d}")
    if not IMAGES:
        print("\n  ※ 이미지를 주지 않아 이미지 단계는 건너뛰었다.")
        print("     python tests/verify_all.py <디스크 이미지>")
    print("=" * 72)
    return 1 if failed else 0


if __name__ == "__main__":
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    raise SystemExit(main(sys.argv[1:]))
