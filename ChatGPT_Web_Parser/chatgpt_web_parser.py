"""기존 진입점 · 하위호환 wrapper (구현은 모두 chatgpt_parser 패키지에 있다).

리팩터링으로 구현이 `chatgpt_parser/` 하위 모듈로 나뉘었지만, 기존 CLI(`python chatgpt_web_parser.py ...`)와
`import chatgpt_web_parser as p` 로 쓰던 테스트·분석 스크립트를 끊지 않기 위해 **공개 이름만** 평면으로 다시 묶는다.
여기서는 이름을 다시 노출할 뿐 동작은 바꾸지 않는다 — Rule·판정·출력 로직은 전부 패키지 쪽에 그대로 있다.

private(`_` 로 시작) 구현은 일부러 노출하지 않는다. 모듈 전역을 바꿔 가며 확인하는 코드가 있어
(`chatgpt_parser.image._EWF_IMG_INFO_CLASS` 처럼) 평면 복사본에 쓰면 실제 모듈이 보는 값과 어긋난다.
그런 이름은 소유 모듈에서 직접 참조한다.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys
import types as _types

# 평면 재노출 대상. 의존성이 낮은 것부터 적었지만 순서는 결과에 영향을 주지 않는다
# (서로 다른 객체가 같은 이름을 쓰는 충돌은 없다 — 있으면 아래 루프가 먼저 만난 것을 유지한다).
_MODULES = (
    "chatgpt_parser.utils",
    "chatgpt_parser.models",
    "chatgpt_parser.source",
    "chatgpt_parser.discovery",
    "chatgpt_parser.image",
    "chatgpt_parser.artifacts.leveldb",
    "chatgpt_parser.artifacts.history",
    "chatgpt_parser.artifacts.local_storage",
    "chatgpt_parser.artifacts.preferences",
    "chatgpt_parser.artifacts.session_storage",
    "chatgpt_parser.artifacts.sessions",
    "chatgpt_parser.artifacts.shared_proto_db",
    "chatgpt_parser.artifacts.cache",
    "chatgpt_parser.recovery.conversations",
    "chatgpt_parser.detectors.common",
    "chatgpt_parser.detectors.auth",
    "chatgpt_parser.detectors.conversation",
    "chatgpt_parser.detectors.prompt",
    "chatgpt_parser.detectors.file_activity",
    "chatgpt_parser.detectors.misc",
    "chatgpt_parser.output.csv_writer",
    "chatgpt_parser.output.debug",
    "chatgpt_parser.output.final_csv",
    "chatgpt_parser.parser",
    "chatgpt_parser.cli",
)

for _module_name in _MODULES:
    _module = _importlib.import_module(_module_name)
    for _key, _value in vars(_module).items():
        if _key.startswith("_") or isinstance(_value, _types.ModuleType):
            continue
        globals().setdefault(_key, _value)

# 선택 의존성은 모듈 객체 자체가 필요하다 (미설치면 None). 위 루프는 모듈 객체를 건너뛰므로 여기서 묶는다.
from chatgpt_parser.artifacts.cache import brotli
from chatgpt_parser.artifacts.leveldb import cramjam
from chatgpt_parser.image import pyewf, pytsk3

if __name__ == "__main__":
    _sys.exit(main())  # noqa: F821  (main 은 위 루프가 chatgpt_parser.cli 에서 가져온다)
