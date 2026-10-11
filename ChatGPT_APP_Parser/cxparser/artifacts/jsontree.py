"""JSON 트리에서 키를 재귀 탐색하고 JSON Pointer 를 근거 위치로 만든다.

파일 내부 중첩 구조를 단정하지 않기 위해 쓴다.
"""


def _escape(token):
    return str(token).replace("~", "~0").replace("/", "~1")


def walk(obj, pointer=""):
    yield pointer, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, pointer + "/" + _escape(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, pointer + "/" + str(i))


def find_key(obj, key, exact=True):
    """키 이름이 일치하는 모든 (json_pointer, value) 를 반환."""
    out = []
    for ptr, node in walk(obj):
        if isinstance(node, dict):
            for k, v in node.items():
                if (k == key) if exact else (key in str(k)):
                    out.append((ptr + "/" + _escape(k), v))
    return out


def find_key_prefix(obj, prefix):
    out = []
    for ptr, node in walk(obj):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.startswith(prefix):
                    out.append((ptr + "/" + _escape(k), k, v))
    return out
