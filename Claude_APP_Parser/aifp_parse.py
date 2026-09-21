#!/usr/bin/env python3
"""
AIFP — Claude Desktop 포렌식 파서 (CLI)

**디스크 이미지를 입력으로 받는다.** 살아 있는 시스템을 직접 분석하지 않는다.
이미지를 마운트하지 않고 읽기 전용으로만 파싱하며, 분석 전후 해시를 비교해
원본이 바뀌지 않았음을 증명한다.

  python aifp_parse.py --image D:\\case\\disk.dd  --out D:\\case\\result
  python aifp_parse.py --image D:\\case\\disk.E01 --out D:\\case\\result
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# 한국어 Windows 콘솔은 기본이 cp949라 한글·기호 출력이 깨진다. UTF-8로 고정한다.
for _stream in (sys.stdout, sys.stderr):
    try:
        if (_stream.encoding or "").lower().replace("-", "") != "utf8":
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from aifp.banner import render as render_banner                      # noqa: E402
from aifp.csvout import (rows_from_reporter, write_conversations,    # noqa: E402
                         write_timeline)
from aifp.errors import AifpError, InputError                        # noqa: E402
from aifp.pipeline import TOOL_VERSION, Pipeline                     # noqa: E402

DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "claude_desktop.json"

# 명세상 입력은 두 가지다.
ALLOWED_SUFFIXES = {".dd": "RAW 디스크 이미지", ".e01": "EnCase Evidence File"}


def image_arg(value: str) -> Path:
    """
    입력은 .dd 와 .E01 두 가지뿐이다.
    인자를 받는 자리에서 걸러 내므로 그 밖의 형식은 분석이 시작되지도 않는다.
    """
    path = Path(value)
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise argparse.ArgumentTypeError(
            f"입력은 .dd 또는 .E01 만 받는다 (받은 값: {path.suffix or '확장자 없음'})")
    if not path.exists():
        raise argparse.ArgumentTypeError(f"이미지 파일이 없다: {path}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"이미지 파일을 지정해야 한다(폴더가 아님): {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aifp_parse",
        description="디스크 이미지에서 Claude Desktop 아티팩트를 파싱해 행위 타임라인과 "
                    "복원 대화를 만든다",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
입력
  --image   디스크 이미지 — .dd (RAW) 또는 .E01 (EnCase)
            마운트하지 않고 직접 파싱한다. 관리자 권한이 필요 없다.

  --extended-fs
            $UsnJrnl:$J 와 $Recycle.Bin 을 추가로 분석해
            파일의 삭제·이동·이름 변경과 휴지통 삭제 경로를 추적한다.

출력 (출력 폴더에 두 파일만 만든다)
  timeline.csv                 흔적이 확인된 사용자 행위를 시간순으로
  recovered_conversations.csv  복원한 대화를 메시지 단위로

  시각은 KST로 적는다. 근거 있는 시각이 없으면 timestamp 를 비워 둔다.
  대화 본문은 마스킹하지 않는다 — 산출물을 사건 폴더 밖으로 내보내지 말 것.
""")
    p.add_argument("--image", type=image_arg, required=True,
                   help="디스크 이미지 (.dd 또는 .E01)")
    p.add_argument("--out", type=Path, default=Path("aifp_out"), help="결과 저장 폴더")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="행위 판별 규칙 파일")
    p.add_argument("--volume", type=int, default=None,
                   help="분석할 파티션 번호 "
                        "(미지정 시 대상 흔적이 있는 NTFS 볼륨을 찾아 자동 선택)")
    p.add_argument("--case-id", type=str, default=None, help="사건 ID (미지정 시 자동 생성)")
    p.add_argument("--log", type=Path, default=None,
                   help="실행 기록(수집·파싱·판정 과정과 오류)을 이 파일에 남긴다. "
                        "미검출 사유와 실패한 저장소를 나중에 확인하려면 켤 것")
    p.add_argument("--extended-fs", action="store_true",
                   help="$UsnJrnl:$J 와 $Recycle.Bin 을 추가로 분석한다 "
                        "(파일 삭제·이동·이름 변경, 휴지통 삭제 경로)")
    p.add_argument("--resume", action="store_true",
                   help="중단된 분석을 체크포인트부터 이어서 실행")
    p.add_argument("--keep-work", action="store_true",
                   help="이미지에서 꺼낸 작업 사본을 지우지 않고 보존")
    p.add_argument("--workdir", type=Path, default=None, help="작업 사본 위치")
    p.add_argument("--no-banner", action="store_true", help="시작 배너 생략")
    p.add_argument("--verbose", "-v", action="store_true", help="진행 상황 출력")
    p.add_argument("--version", action="version", version=TOOL_VERSION)
    return p


def write_run_log(path: Path, reporter, args) -> None:
    """
    실행 기록. 산출물은 CSV 두 개로 고정이므로, 감사 추적이 필요하면
    조사관이 --log 로 명시해 따로 남긴다.
    """
    import csv as _csv
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = reporter.summary()
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["구분", "항목", "값"])
        w.writerow(["실행", "명령", " ".join(sys.argv)])
        w.writerow(["실행", "도구", TOOL_VERSION])
        w.writerow(["실행", "증거", str(args.image)])
        w.writerow(["실행", "분석 대상", reporter.result.target_root])
        integ = reporter.integrity or {}
        w.writerow(["무결성", "검증", str(integ.get("integrity_verified"))])
        w.writerow(["무결성", "마운트", str(integ.get("mounted"))])
        for src in (integ.get("container") or {}).get("files", []):
            name = Path(src.get("path", "")).name
            w.writerow(["무결성", f"{name} 크기", src.get("size")])
            w.writerow(["무결성", f"{name} SHA-256 (분석 전)", src.get("sha256_open")])
            w.writerow(["무결성", f"{name} SHA-256 (분석 후)", src.get("sha256_close")])
        for k, v in summary.get("collected_files", {}).items():
            w.writerow(["수집", k, v])
        w.writerow(["판정", "이벤트", summary.get("events_total")])
        w.writerow(["판정", "시각 확보", summary.get("events_with_time")])
        for n in reporter.negatives:
            w.writerow(["미검출" if n["result"] == "not_detected" else "해당없음",
                        n["action_name"],
                        n.get("reason") or _flatten_paths(n.get("checked_paths"))])
        for i in reporter.errs.to_list():
            w.writerow([i["severity"], i["code"], f"{i['source']}: {i['message']}"])


def _flatten_paths(paths) -> str:
    if not paths:
        return ""
    if isinstance(paths, str):
        return paths[:300]
    return " | ".join(str(p) for p in paths[:5])[:300]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner:
        print(render_banner())
    print("─" * 66)
    print(f"  버전     : {TOOL_VERSION}")
    print(f"  증거     : {args.image}")
    print(f"  모드     : 디스크 이미지 직접 파싱 (마운트 없음)")
    print(f"  규칙     : {args.rules.name}")
    print(f"  출력     : {args.out}")
    print(f"  민감정보 : 원문 그대로 — 사건 폴더 밖으로 내보내지 말 것")
    if args.extended_fs:
        print(f"  확장 분석 : $UsnJrnl:$J · $Recycle.Bin 포함")
    print("─" * 66)

    if args.out.exists():
        own = {"timeline.csv", "recovered_conversations.csv"}
        work = {"_checkpoint.json", "_records.pkl"}
        names = {p.name for p in args.out.iterdir()}
        if names & work:
            print("  [주의] 이전 실행이 끝나기 전에 멈춘 흔적이 있다"
                  " (_checkpoint.json)")
            print("         --resume 을 주면 이어서, 주지 않으면 처음부터 분석한다")
        leftovers = sorted(names - own - work)
        if leftovers:
            print(f"  [주의] 출력 폴더에 이전 파일이 있다: {', '.join(leftovers[:5])}"
                  f"{' …' if len(leftovers) > 5 else ''}")
            print("         사건이 섞이지 않도록 비어 있는 폴더를 쓰는 것이 안전하다")

    try:
        pipe = Pipeline(args.image, args.rules, out_dir=args.out,
                        case_id=args.case_id, tz="KST",
                        mode="image", volume_index=args.volume,
                        workdir=args.workdir, keep_work=args.keep_work,
                        unmask=True, resume=args.resume,
                        extended_fs=args.extended_fs,
                        verbose=args.verbose)
        reporter = pipe.run()
    except InputError as exc:
        print(f"\n  [중단] {exc}\n", file=sys.stderr)
        return 2
    except AifpError as exc:
        print(f"\n  [중단] {exc.code}: {exc}\n", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n  사용자가 중단했다.\n", file=sys.stderr)
        return 130

    timeline, conversations = rows_from_reporter(reporter)
    try:
        write_timeline(timeline, args.out / "timeline.csv")
        write_conversations(conversations, args.out / "recovered_conversations.csv")
        if args.log:
            write_run_log(args.log, reporter, args)
    except OSError as exc:
        print(f"\n  [중단] 결과 파일을 쓰지 못했다: {exc}", file=sys.stderr)
        print("         해당 CSV를 엑셀 등에서 열어 두었다면 닫고 다시 실행할 것.\n"
              "         분석 자체는 끝났으므로 다시 돌리면 같은 결과가 나온다\n",
              file=sys.stderr)
        return 2

    reporter.print_console()
    print("─" * 66)
    print(f"  저장: timeline.csv                 {len(timeline):>5}행")
    print(f"  저장: recovered_conversations.csv  {len(conversations):>5}행")
    print()

    counts = reporter.errs.counts()
    return 1 if counts.get("error", 0) or counts.get("fatal", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
