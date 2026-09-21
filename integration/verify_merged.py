#!/usr/bin/env python3
"""병합 timeline.csv ↔ 시나리오 정답지 대조.

    python verify_merged.py --timeline out/<id>/timeline.csv --key scenario_keys/plain_2026-09-15.csv [--window 120] [--out report.md]

정답지 행(model, event_id, action, kst)마다:
  일치      같은 Model 에 같은 행위명이 표 시각 ±window 초 안에 있음
  부분 차이 같은 행위명은 있으나 시각이 창 밖 (또는 시각 미상)
  불일치    같은 행위명 자체가 없음 → 가장 가까운 다른 행위를 참고로 표시
"""

import argparse
import csv
import os
import sys
from collections import Counter
from datetime import datetime

# 정답지 이름과 파서 이름이 뜻은 같지만 표기가 다른 경우만 (파서 쪽 수정이 끝나면 비워도 됨)
ALIASES = {
    "사용자 프롬프트 입력/전송": {"사용자 프롬프트 입력/전송", "프롬프트 전송"},
}


def _kst(s):
    s = s.replace(" KST", "")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def compare(timeline, key, window):
    by_model = {}
    for r in timeline:
        by_model.setdefault(r["Model"], []).append(r)
    out = []
    for k in key:
        rows = by_model.get(k["model"], [])
        want = ALIASES.get(k["action"], {k["action"]})
        target = _kst(k["kst"])
        same = [r for r in rows if r["User_behavior"] in want]
        best = None
        for r in same:
            t = _kst(r["Timestamp"])
            d = abs((t - target).total_seconds()) if t and target else None
            if d is not None and (best is None or d < best[0]):
                best = (d, r)
        if best and best[0] <= window:
            res, obs = "일치", "%s (%+ds) %s" % (best[1]["Timestamp"][:19], (_kst(best[1]["Timestamp"]) - target).total_seconds(), best[1]["Behavior_details "][:60])
        elif same:
            res, obs = "부분 차이", "같은 행위 %d건이나 ±%ds 밖 (예: %s)" % (len(same), window, same[0]["Timestamp"][:19])
        else:
            near = None
            for r in rows:
                t = _kst(r["Timestamp"])
                d = abs((t - target).total_seconds()) if t and target else None
                if d is not None and (near is None or d < near[0]):
                    near = (d, r)
            res = "불일치"
            obs = "해당 행위 없음. 가장 가까운 행: %s %s (%+ds)" % (near[1]["Timestamp"][:19], near[1]["User_behavior"],
                                                   (_kst(near[1]["Timestamp"]) - target).total_seconds()) if near else "해당 Model 행 없음"
        out.append({**k, "result": res, "observed": obs})
    return out


def to_markdown(rows, timeline_path, key_path, window):
    c = Counter(r["result"] for r in rows)
    lines = ["# 병합 타임라인 ↔ 정답지 대조", "",
             "- 타임라인: `%s`  - 정답지: `%s`  - 창: ±%ds" % (timeline_path, key_path, window),
             "- 결과: " + ", ".join("%s %d" % kv for kv in sorted(c.items())), ""]
    for model in sorted({r["model"] for r in rows}):
        sub = [r for r in rows if r["model"] == model]
        cm = Counter(r["result"] for r in sub)
        lines += ["## %s — %s" % (model, ", ".join("%s %d" % kv for kv in sorted(cm.items()))), "",
                  "| 이벤트 | 행위 | 표 시각(KST) | 결과 | 관찰 |", "|---|---|---|---|---|"]
        lines += ["| %s | %s | %s | %s | %s |" % (r["event_id"], r["action"], r["kst"], r["result"], r["observed"].replace("|", "/")) for r in sub]
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeline", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--window", type=int, default=120)
    ap.add_argument("--out", help="markdown 보고서 경로 (기본: 타임라인 옆 verify_report.md)")
    a = ap.parse_args(argv)
    with open(a.timeline, encoding="utf-8-sig", newline="") as fh:
        timeline = list(csv.DictReader(fh))
    with open(a.key, encoding="utf-8-sig", newline="") as fh:
        key = list(csv.DictReader(fh))
    rows = compare(timeline, key, a.window)
    md = to_markdown(rows, a.timeline, a.key, a.window)
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.timeline)), "verify_report.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(md)
    c = Counter(r["result"] for r in rows)
    for model in sorted({r["model"] for r in rows}):
        cm = Counter(r["result"] for r in rows if r["model"] == model)
        print("%-16s 일치 %2d / 부분 %2d / 불일치 %2d" % (model, cm["일치"], cm["부분 차이"], cm["불일치"]))
    print("합계             일치 %2d / 부분 %2d / 불일치 %2d  → %s" % (c["일치"], c["부분 차이"], c["불일치"], out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
