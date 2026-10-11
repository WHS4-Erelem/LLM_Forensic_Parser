"""명령행 인터페이스.

  python -m cxparser --input <image.E01|image.dd|디렉터리> --out-dir <결과폴더>
  python -m cxparser --input-type live --out-dir <결과폴더>        (실행 중인 이 PC 를 직접 분석)
"""

import argparse
import json
import os
import sys

from . import output, pipeline
from .errors import CxError


KEY_ENV = "ERELM_KEY_MATERIAL"   # BitLocker 키를 받는 환경변수 (다른 파서와 공용이라 파서 이름을 넣지 않았다)


def build_parser():
    p = argparse.ArgumentParser(
        prog="cxparser",
        description="Codex Desktop 아티팩트 파서 (E01/RAW 디스크 이미지 -> JSON/CSV)")
    p.add_argument("--input", "-i",
                   help="E01(분할 포함)/RAW .dd/.raw 이미지, 추출 디렉터리, 또는 (live) 볼륨 루트. "
                        "live 에서 생략하면 시스템 드라이브")
    p.add_argument("--input-type", choices=("auto", "image", "dir", "live"), default="auto",
                   help="auto=경로를 보고 image/dir 판별 (기본) / image / dir=추출 폴더 / "
                        "live=실행 중인 이 PC 를 직접 분석 (자동 선택되지 않음, 명시해야 함)")
    p.add_argument("--out-dir", "-o", default="cx_out", help="결과 출력 폴더")
    p.add_argument("--format", choices=("json", "csv", "both"), default="csv",
                   help="csv=공통 형식 timeline.csv + recovered_conversations.csv (기본) / "
                        "json=cx_result.json(전체 레코드·근거) / both")
    p.add_argument("--kinds", default=",".join(pipeline.DEFAULT_KINDS),
                   help="파싱할 아티팩트 종류 (쉼표구분): "
                        + ",".join(pipeline.DEFAULT_KINDS))
    p.add_argument("--max-file-mb", type=int, default=pipeline.DEFAULT_MAX_FILE_BYTES // (1024 * 1024),
                   help="파싱 대상 파일 하나의 크기 상한(MB). 넘으면 그 파일만 FILE_TOO_LARGE 로 건너뛴다 (기본 %(default)s)")
    p.add_argument("--max-excerpt", type=int, default=500,
                   help="근거 발췌 최대 길이(문자)")
    p.add_argument("--no-usn", action="store_true",
                   help="$UsnJrnl:$J 파싱 생략 (이미지 입력일 때만 해당)")
    p.add_argument("--usn-max-bytes", type=int, default=None,
                   help="$J 에서 읽을 최대 바이트 (기본: 전체)")
    p.add_argument("--key-material", default=os.environ.get(KEY_ENV),
                   help="BitLocker 볼륨의 키: recovery:<48자리 복구 키> | passphrase:<암호> | bek:<.BEK 경로> | "
                        "fvek:<hex>. 일시 중단·활성화 대기 상태는 키 없이 풀린다. "
                        "환경변수 %s 로 줘도 된다 (명령행 기록에 남기지 않을 때)" % KEY_ENV)
    p.add_argument("--overwrite", action="store_true",
                   help="출력 폴더에 기존 결과 파일이 있어도 덮어쓴다 (기본: 거부, 종료코드 2)")
    p.add_argument("--quiet", action="store_true")
    return p


OUTPUT_FILES = ("cx_result.json", "timeline.csv", "recovered_conversations.csv")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.input:
        if args.input_type != "live":
            parser.error("--input 이 필요합니다 (live 일 때만 생략 가능)")
        args.input = os.environ.get("SystemDrive", "C:") + os.sep
    kinds = tuple(k.strip() for k in args.kinds.split(",") if k.strip())

    existing = [f for f in OUTPUT_FILES if os.path.exists(os.path.join(args.out_dir, f))]
    if existing and not args.overwrite:
        print("기존 결과 파일이 있습니다 (--overwrite 로 덮어쓰기): %s" % ", ".join(existing),
              file=sys.stderr)
        return 2

    try:
        result = pipeline.run(args.input, input_type=args.input_type, kinds=kinds,
                              max_excerpt=args.max_excerpt, max_file_bytes=args.max_file_mb * 1024 * 1024,
                              usn=not args.no_usn,
                              usn_max_bytes=args.usn_max_bytes, key_material=args.key_material)
    except CxError as exc:
        payload = {"status": "failed", **exc.to_dict()}
        print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    written = []
    if args.format in ("json", "both"):
        written.append(output.write_json(
            os.path.join(args.out_dir, "cx_result.json"), result))
    if args.format in ("csv", "both"):
        written.append(output.write_timeline_csv(
            os.path.join(args.out_dir, "timeline.csv"), result["records"]))
        written.append(output.write_conversations_csv(
            os.path.join(args.out_dir, "recovered_conversations.csv"), result["records"]))

    if not args.quiet:
        s = result["summary"]
        print("입력      : %s" % result["input"]["image_id"])
        if result["input"].get("image_type") == "live":
            print("라이브    : %s, 수집 %s, 관리자 권한 %s"
                  % (result["input"]["os"], result["input"]["collected_at_utc"],
                     {True: "예", False: "아니오"}.get(result["input"]["elevated"], "확인 불가")))
        print("스캔 파일 : %d, Codex 경로 %d건, 파싱 대상 %d건"
              % (result["scan"]["files_scanned"],
                 result["scan"]["codex_paths_found"],
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
