"""명령행 인터페이스.

  python -m parser --input <image.E01|image.dd|디렉터리> --out-dir <결과폴더>
"""

import argparse
import json
import os
import sys

from . import __version__, banner, output, pipeline
from .errors import ClError


def build_parser():
    p = argparse.ArgumentParser(
        prog="parser",
        description="Claude Desktop 아티팩트 파서 (E01/RAW 디스크 이미지 -> JSON/CSV)")
    p.add_argument("--input", "-i", required=True,
                   help="E01(분할 포함)/RAW .dd/.raw 이미지 또는 추출 디렉터리")
    p.add_argument("--input-type", choices=("auto", "image", "dir"), default="auto")
    p.add_argument("--out-dir", "-o", default="cl_out", help="결과 출력 폴더")
    p.add_argument("--format", choices=("json", "csv", "both"), default="csv",
                   help="csv=timeline.csv + recovered_conversations.csv (기본) / "
                        "json=result.json(전체 레코드·근거) / both")
    p.add_argument("--kinds", default=",".join(pipeline.DEFAULT_KINDS),
                   help="파싱할 아티팩트 종류 (쉼표구분): "
                        + ",".join(pipeline.DEFAULT_KINDS))
    p.add_argument("--max-excerpt", type=int, default=500,
                   help="근거 발췌 최대 길이(문자)")
    p.add_argument("--no-usn", action="store_true",
                   help="$UsnJrnl:$J 파싱 생략 (이미지 입력일 때만 해당)")
    p.add_argument("--usn-max-bytes", type=int, default=None,
                   help="$J 에서 읽을 최대 바이트 (기본: 전체)")
    p.add_argument("--overwrite", action="store_true",
                   help="출력 폴더에 기존 결과 파일이 있어도 덮어쓴다 (기본: 거부, 종료코드 2)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="진행 상황을 단계별로 출력한다")
    p.add_argument("--no-banner", action="store_true", help="시작 배너 생략")
    p.add_argument("--quiet", action="store_true")
    # 통합기(parsers.json)가 파서 버전을 읽어 실행 기록에 남긴다.
    p.add_argument("--version", action="version",
                   version="parser %s" % __version__)
    return p


OUTPUT_FILES = ("result.json", "timeline.csv", "recovered_conversations.csv")


def _utf8_console():
    """콘솔을 UTF-8 로 맞춘다.

    Windows 기본 콘솔은 CP949 라서 한글 진행 메시지에 '—' 같은 글자가 섞이면
    출력이 예외로 죽는다. 사용자가 실행 전에 chcp 65001 을 치게 하지 않고
    파서가 스스로 맞춘다. 실패해도 파싱은 계속한다(치환 출력).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass


def main(argv=None):
    _utf8_console()
    args = build_parser().parse_args(argv)
    kinds = tuple(k.strip() for k in args.kinds.split(",") if k.strip())

    if not args.no_banner and not args.quiet:
        print(banner.render())

    existing = [f for f in OUTPUT_FILES if os.path.exists(os.path.join(args.out_dir, f))]
    if existing and not args.overwrite:
        print("기존 결과 파일이 있습니다 (--overwrite 로 덮어쓰기): %s" % ", ".join(existing),
              file=sys.stderr)
        return 2

    try:
        result = pipeline.run(args.input, input_type=args.input_type, kinds=kinds,
                              max_excerpt=args.max_excerpt, usn=not args.no_usn,
                              verbose=args.verbose,
                              usn_max_bytes=args.usn_max_bytes)
    except ClError as exc:
        payload = {"status": "failed", **exc.to_dict()}
        print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    written = []
    if args.format in ("json", "both"):
        written.append(output.write_json(
            os.path.join(args.out_dir, "result.json"), result))
    if args.format in ("csv", "both"):
        written.append(output.write_timeline_csv(
            os.path.join(args.out_dir, "timeline.csv"), result["records"]))
        written.append(output.write_conversations_csv(
            os.path.join(args.out_dir, "recovered_conversations.csv"), result["records"]))

    if not args.quiet:
        s = result["summary"]
        print("입력      : %s" % result["input"]["image_id"])
        print("스캔 파일 : %d, Claude 경로 %d건, 파싱 대상 %d건"
              % (result["scan"]["files_scanned"],
                 result["scan"]["claude_paths_found"],
                 result["scan"]["parse_targets"]))
        print("레코드    : 총 %d (시각확인 %d / 시각미상 %d)"
              % (s["record_counts"]["total"], s["record_counts"]["dated"],
                 s["record_counts"]["undated"]))
        print("파싱상태  : %s" % s["parse_status_counts"])
        if result["warnings"]:
            print("경고      : %d건" % len(result["warnings"]))
            for w in result["warnings"][:5]:
                print("  - %s" % w)
        if result["errors"]:
            print("오류      : %d건" % len(result["errors"]))
            for e in result["errors"][:5]:
                print("  - %s" % json.dumps(e, ensure_ascii=False))
        for path in written:
            print("출력      : %s" % path)
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
