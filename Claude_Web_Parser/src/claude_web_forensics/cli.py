"""Command-line entry point."""
from __future__ import annotations

import argparse
import logging
import platform
import sys
import time
from pathlib import Path

from . import __version__
from .pipeline import AnalysisOptions, run_analysis
from .image.adapters import ImageOpenError
from .image.volumes import KeyMaterial

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claude-web-forensics", description=(
            "Single-snapshot forensic parser for Claude Web traces in Google Chrome "
            "on Windows. Input is an E01-family or raw/dd disk image. Writes exactly "
            "two files to --output: timeline.csv and recovered_conversations.csv "
            "(UTF-8 with BOM). Progress is logged to the console only."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyse a disk image")
    analyze.add_argument("--image", required=True, type=Path, help="E01 or raw/dd image path")
    analyze.add_argument(
        "--output", required=True, type=Path,
        help="output directory for timeline.csv and recovered_conversations.csv",
    )
    analyze.add_argument(
        "--partition-offset", type=int, default=None, help="byte offset of the target partition"
    )
    analyze.add_argument("--partition-index", type=int, default=None, help="index of the target partition")
    analyze.add_argument("--windows-user", default="", help="limit analysis to one Windows user")
    analyze.add_argument("--chrome-profile", default="", help="limit analysis to one Chrome profile")
    analyze.add_argument(
        "--key-material", default="", help=(
            "BitLocker key material: 'recovery:<48-digit>', 'bek:<path>' or 'fvek:<hex>'. "
            "Never logged or written to the CSVs."
        ),
    )
    analyze.add_argument(
        "--extended-fs", action="store_true", help="additionally analyse $UsnJrnl:$J and $Recycle.Bin",
    )
    analyze.add_argument(
        "--keep-staging", action="store_true",
        help="keep the temporary working directory instead of deleting it",
    )
    analyze.add_argument(
        "--overwrite", action="store_true", help=(
            "replace timeline.csv / recovered_conversations.csv from a previous run; "
            "other files in the folder are never touched"
        ),
    )
    analyze.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="console log level (no log file is written)",
    )

    sub.add_parser("version", help="print version and dependency provenance")
    return parser

def parse_key_material(spec: str) -> KeyMaterial:
    material = KeyMaterial()
    if not spec:
        return material
    kind, _, value = spec.partition(":")
    kind = kind.strip().lower()
    value = value.strip()
    if kind == "recovery":
        material.recovery_password = value
    elif kind == "bek":
        material.bek_file = Path(value)
    elif kind == "fvek":
        try:
            material.fvek = bytes.fromhex(value)
        except ValueError as exc:
            raise SystemExit(f"--key-material fvek must be hex: {exc}")
    elif kind == "passphrase":
        material.passphrase = value
    else:
        raise SystemExit("--key-material must start with recovery:, bek:, fvek: or passphrase:")
    return material

def setup_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("claude_web_forensics")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(getattr(logging, level))
    console.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    logger.addHandler(console)
    return logger

def _validate_output(image: Path, output: Path) -> None:
    image = image.resolve()
    output = output.resolve()
    if output == image.parent or image.parent in output.parents or output in image.parents:
        raise SystemExit(f"refusing to write output inside the evidence directory: {output}")

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        from .parsers.ccl_adapter import ccl_provenance

        print(f"claude-web-forensics {__version__}")
        print(f"python {platform.python_version()} on {platform.platform()}")
        provenance = ccl_provenance()
        print(f"ccl_chromium_reader {provenance['version']} @ {provenance['commit']}")
        return EXIT_OK

    image = Path(args.image)
    output = Path(args.output)
    if not image.exists():
        print(f"image not found: {image}", file=sys.stderr)
        return EXIT_USAGE
    try:
        _validate_output(image, output)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    from .output.csv_export import OutputDirectoryError, prepare_output_dir

    try:
        others = prepare_output_dir(output, overwrite=args.overwrite)
    except OutputDirectoryError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    logger = setup_logging(args.log_level)
    if others:
        logger.info("output folder also contains %s (left untouched)", ", ".join(others[:10]))

    try:
        key_material = parse_key_material(args.key_material)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    options = AnalysisOptions(
        image_path=image, output_dir=output, partition_offset=args.partition_offset,
        partition_index=args.partition_index, windows_user=args.windows_user,
        chrome_profile=args.chrome_profile, key_material=key_material, extended_fs=args.extended_fs,
        keep_staging=args.keep_staging,
    )

    started = time.time()
    try:
        result = run_analysis(options, logger)
    except ImageOpenError as exc:
        logger.error("fatal: %s", exc)
        return EXIT_FATAL
    except Exception as exc:  # pragma: no cover - last-resort guard
        logger.exception("fatal: unexpected error: %s", exc)
        return EXIT_FATAL

    elapsed = time.time() - started
    logger.info("analysis finished in %.1fs -> %s", elapsed, output)
    for line in result.summary_lines():
        logger.info("  %s", line)

    if not result.output_valid:
        logger.error("result CSV verification failed")
        return EXIT_FATAL
    return EXIT_OK

if __name__ == "__main__":
    raise SystemExit(main())
