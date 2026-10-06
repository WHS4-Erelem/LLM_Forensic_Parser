#!/usr/bin/env python3
"""어디서든 실행할 수 있는 런처.

  python run_parser.py --input D:\\case\\image.E01 --out-dir out
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
