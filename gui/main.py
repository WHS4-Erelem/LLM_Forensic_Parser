"""elelem LLM Forensic Parser GUI 진입점.

    python gui/main.py

기존 통합 Runner(integration/llm_forensic.py)와 파서 6개를 수정하지 않고 호출만 한다.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from PyQt6.QtWidgets import QApplication     # noqa: E402

from main_window import MainWindow           # noqa: E402

QSS = os.path.join(HERE, "styles.qss")


def load_stylesheet(path=QSS):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def main(argv=None):
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("elelem LLM Forensic Parser")
    app.setStyle("Fusion")                   # QSS 가 플랫폼 테마에 덜 흔들리게
    app.setStyleSheet(load_stylesheet())
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
