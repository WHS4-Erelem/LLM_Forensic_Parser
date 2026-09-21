"""
새 출력 규격 — timeline.csv 와 recovered_conversations.csv 두 개만 낸다.

열 이름은 영어, 시각은 KST, 근거 있는 시각이 없으면 timestamp 는 비운다.
대화 본문은 마스킹하지 않는다.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any, Iterable

from .timeutil import display

SERVICE_DEFAULT = "claude-desktop"

TIMELINE_COLUMNS = [
    "Model",              # 대상 서비스
    "Timestamp",          # KST, 마이크로초까지
    "User_behavior",      # 사용자 행위
    "Behavior_details ",  # 판단 근거 — 양식의 열 이름에 뒤 공백이 있다
    "Verdict",            # 확정 · 의심
    "Artifact_path",      # 근거 파일의 실제 경로, 여럿이면 | 로 잇는다
    "Artifact_details ",  # 근거 상세 — [저장소] 키=값
]

CONVERSATION_COLUMNS = [
    "Model",
    "timestamp",
    "conversation_uuid",
    "conversation_title",
    "message_uuid",
    "parent_message_uuid",
    "message order",      # 양식이 밑줄 없이 띄어쓰기를 쓴다
    "role",
    "content",
    "Artifact_path",
]

SERVICE_DEFAULT = "claude-desktop"

# 뿌리 메시지의 부모 — 양식이 쓰는 고정값
ROOT_PARENT = "00000000-0000-4000-8000-000000000000"

ROLE_MAP = {"human": "user", "user": "user", "assistant": "assistant",
            "system": "system"}

# 저장소 이름 표기
STORAGE_LABEL = {
    "cache": "Cache",
    "indexeddb": "IndexedDB",
    "localstorage": "Local Storage",
    "blob": "Blob",
    "configfile": "Config",
    "applog": "App Log",
    "filesystem": "$MFT",
    "registry": "Registry",
}

FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")

# 셀 하나가 무한정 커지는 것을 막는다. 압축 폭탄 하나로 산출물이 수백 MB가 되면
# 표 계산기도 표준 csv 모듈도 그 파일을 읽지 못한다.
MAX_CELL = 32_000

# 표 계산기와 csv 모듈이 읽지 못하는 제어문자. 탭·줄바꿈은 정상 문자로 둔다.
CONTROL_KEEP = {chr(9), chr(10), chr(13)}


def escape_surrogates(text: str) -> str:
    """
    짝 없는 서러게이트를 표기로 바꾼다.

    UTF-16 조각을 디스크에서 건져 오면 짝이 맞지 않는 문자가 남는다. 그대로는
    UTF-8 파일에 쓸 수 없어 산출물 저장 자체가 실패한다. 지우지 않고 표기로
    남겨서, 그런 문자가 있었다는 사실을 조사관이 볼 수 있게 한다.
    """
    if not any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text
    return "".join(chr(92) + f"u{ord(ch):04x}" if 0xD800 <= ord(ch) <= 0xDFFF
                   else ch for ch in text)


def escape_controls(text: str) -> str:
    """
    널 문자 같은 제어문자를 눈에 보이는 표기로 바꾼다.

    지우지 않고 16진 표기로 남기는 이유는, 대화 본문에 제어문자가 들어 있었다는
    사실 자체가 증거이기 때문이다. 내용을 감추는 것이 아니라 표기를 바꾸는 것이다.
    """
    if not any(ch < " " or ch == chr(127) for ch in text):
        return text
    return "".join(ch if ch in CONTROL_KEEP or (ch >= " " and ch != chr(127))
                   else chr(92) + f"x{ord(ch):02x}" for ch in text)


def sanitize_cell(value: Any) -> tuple[str, bool]:
    """
    (내보낼 값, 잘렸는지)

    수식 실행을 막고, 제어문자를 표기로 바꾸고, 길이를 제한한다.
    원문을 바꾸는 일이므로 잘린 사실은 표시한다.
    """
    text = "" if value is None else str(value)
    text = escape_surrogates(escape_controls(text))
    if not text.strip():
        return "-", False           # 팀 공통: 값 없는 셀은 "-" (빈칸 금지)
    truncated = False
    if len(text) > MAX_CELL:
        text = text[:MAX_CELL] + f"…(총 {len(text):,}자 중 {MAX_CELL:,}자만 기록)"
        truncated = True
    if text[:1] in FORMULA_LEAD:
        text = "'" + text
    return text, truncated


# Claude Desktop 이 존재할 수 있는 범위. 이 밖의 값은 파싱 사고로 본다.
YEAR_MIN, YEAR_MAX = 1990, 2100


def to_kst(ts_utc: str | None) -> str:
    """근거 있는 시각만 KST로 적는다. 없거나 말이 안 되면 빈 칸."""
    if not ts_utc:
        return ""
    try:
        text = display(ts_utc, "KST")
    except Exception:
        return ""
    head = text[:4]
    if not head.isdigit() or not (YEAR_MIN <= int(head) <= YEAR_MAX):
        return ""
    # 양식은 마이크로초까지 적는다. 원본에 소수점이 없으면 0으로 채운다 —
    # 자리를 맞추려는 것이지 없는 정밀도를 지어내는 것이 아니다.
    if " KST" in text and "." not in text.split(" KST")[0]:
        text = text.replace(" KST", ".000000 KST")
    return text




def verdict_of(evidence_level: str, channel_count: int) -> str:
    """
    확정 — 서로 독립적인 2개 이상의 아티팩트 계열에서 교차 검증되었거나
           그 행위를 직접 입증하는 명시적 증거가 있는 경우
    의심 — 구체적 흔적은 있으나 확정 기준에 못 미치는 경우
    """
    if channel_count >= 2 or evidence_level == "direct":
        return "확정"
    return "의심"


def as_text(value: Any) -> str:
    """
    디스크에서 건진 값은 문자열이 아닐 수 있다.

    깨진 JSON 에서는 uuid 가 숫자로, 부모 uuid 가 사전으로 들어오기도 한다.
    그대로 두면 정렬이나 사전 키로 쓸 때 터진다. 버리지 않고 문자열로 맞춘다.
    """
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def as_order(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def order_messages(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    부모·자식 관계로 메시지 순서를 재구성한다.
    재시도나 수정으로 갈라진 가지도 버리지 않고 순서를 부여한다.
    """
    by_parent: dict[str | None, list[dict]] = {}
    for m in msgs:
        by_parent.setdefault(m.get("parent_message_uuid") or None, []).append(m)
    for lst in by_parent.values():
        lst.sort(key=lambda m: (as_text(m.get("timestamp_utc")),
                                as_order(m.get("index"))))

    known = {m.get("message_uuid") for m in msgs}
    roots = [m for m in msgs
             if not m.get("parent_message_uuid")
             or m.get("parent_message_uuid") not in known]
    roots.sort(key=lambda m: (as_text(m.get("timestamp_utc")),
                              as_order(m.get("index"))))

    # 재귀로 내려가면 긴 대화에서 파이썬 재귀 한계에 걸려 대화가 통째로 날아간다.
    # 수천 턴짜리 대화도 있으므로 스택을 직접 들고 내려간다.
    # 방문 표시는 UUID가 아니라 객체 기준이다. 같은 UUID를 쓰는 메시지가
    # 두 개 있어도 하나를 조용히 버리면 안 되기 때문이다.
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        out.append(node)
        children = by_parent.get(node.get("message_uuid"), [])
        stack.extend(reversed(children))

    # 부모를 못 찾아 어디에도 못 붙은 메시지도 뒤에 붙인다
    for m in msgs:
        if id(m) not in seen:
            out.append(m)
    return out


def write_timeline(rows: list[dict[str, Any]], path: Path,
                   service: str = SERVICE_DEFAULT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=TIMELINE_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r = dict(r)
            r.setdefault("Model", service)
            w.writerow({c: sanitize_cell(r.get(c, ""))[0] for c in TIMELINE_COLUMNS})
    return path


def write_conversations(rows: list[dict[str, Any]], path: Path,
                        service: str = SERVICE_DEFAULT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CONVERSATION_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r = dict(r)
            r.setdefault("Model", service)
            w.writerow({c: sanitize_cell(r.get(c, ""))[0]
                        for c in CONVERSATION_COLUMNS})
    return path


def windows_path(raw: str) -> str:
    """
    증거 안의 경로를 실제 윈도 경로로 바꾼다.

        IMG.dd::Basic data partition/Users/llmtest/AppData/...
        → C:\\Users\\llmtest\\AppData\\...

    볼륨 문자는 이미지에 적혀 있지 않다. 분석 대상 볼륨을 C: 로 적고,
    그 사실은 실행 기록에 남긴다.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    if "::" in text:
        text = text.split("::", 1)[1]
        if "/" in text:
            text = text.split("/", 1)[1] if not text.startswith("/") else text[1:]
    text = text.replace("/", "\\").lstrip("\\")
    if re.match(r"^[A-Za-z]:", text):
        return text
    return "C:\\" + text


def artifact_paths(ev: Any) -> str:
    seen: list[str] = []
    for a in getattr(ev, "artifacts", []) or []:
        w = windows_path(getattr(a, "path", ""))
        if w and w not in seen:
            seen.append(w)
    return "|".join(seen)


def artifact_details(ev: Any) -> str:
    """
    근거 하나를 [저장소] 키=값 한 줄로 적는다.

    양식에는 계정·대화 UUID 전용 열이 없다. 그렇다고 빼면 누구의 행위인지가
    표에서 사라지므로, 참조 양식이 하는 대로 키=값으로 같이 적는다.
    """
    head: list[str] = []
    if getattr(ev, "account_uuid", None):
        head.append(f"계정 UUID={ev.account_uuid}")
    if getattr(ev, "org_uuid", None):
        head.append(f"조직 UUID={ev.org_uuid}")
    if getattr(ev, "conversation_uuid", None):
        head.append(f"대화 UUID={ev.conversation_uuid}")
    if getattr(ev, "client_version", None):
        head.append(f"앱 버전={ev.client_version}")
    if getattr(ev, "device_id", None):
        head.append(f"기기 ID={ev.device_id}")

    lines: list[str] = []
    for a in getattr(ev, "artifacts", []) or []:
        raw_path = (getattr(a, "path", "") or "")
        low = raw_path.lower()
        if "$usnjrnl" in low:
            label = "$UsnJrnl"
        elif "$recycle.bin" in low:
            label = "$Recycle.Bin"
        elif "prefetch" in low:
            label = "Prefetch"
        else:
            label = STORAGE_LABEL.get(getattr(a, "storage", "") or "", "Artifact")
        parts: list[str] = list(head)
        if getattr(a, "locator", None):
            parts.append(f"key={a.locator}")
        if getattr(a, "offset", None) is not None:
            parts.append(f"오프셋={a.offset}")
        if getattr(a, "size", None) is not None:
            parts.append(f"크기={a.size}")
        if getattr(a, "recovered", False):
            parts.append("복원=삭제분")
        if getattr(a, "sha256", None):
            parts.append(f"sha256={a.sha256[:16]}…")
        if getattr(a, "note", None):
            parts.append(str(a.note))
        line = f"[{label}] " + ", ".join(parts) if parts else f"[{label}]"
        if line not in lines:
            lines.append(line)
    return "\n".join(lines)


def behavior_details(ev: Any) -> str:
    """양식은 '유형_내용' 꼴로 적는다. 내용이 없으면 유형만."""
    kind = (getattr(ev, "summary", "") or "").strip()
    body = (getattr(ev, "content", "") or "").strip()
    if not body:
        notes = getattr(ev, "notes", None) or []
        body = (notes[0] if notes else "").strip()
    body = " ".join(body.split())[:300]
    if kind and body:
        return f"{kind}_{body}"
    return kind or body


def rows_from_reporter(rep: Any) -> tuple[list[dict], list[dict]]:
    """
    분석 결과에서 두 출력 파일의 행을 만든다.

    timeline                판정된 사용자 행위 (미검출은 싣지 않는다)
    recovered_conversations 복원된 메시지 — 대화마다 1부터 순서를 다시 매긴다
    """
    timeline: list[dict[str, Any]] = []
    for e in rep.result.sorted_events():
        timeline.append({
            "Timestamp": to_kst(e.timestamp_utc),
            "User_behavior": e.action_name,
            "Behavior_details ": behavior_details(e),
            "Verdict": verdict_of(e.evidence_level, len(e.channels)),
            "Artifact_path": artifact_paths(e),
            "Artifact_details ": artifact_details(e),
        })

    conversations: list[dict[str, Any]] = []
    for c in rep.conversations():
        msgs = [{
            "message_uuid": as_text(m.get("uuid")),
            "parent_message_uuid": as_text(m.get("parent_message_uuid")),
            "timestamp_utc": as_text(m.get("timestamp_utc")) or None,
            "index": as_order(m.get("index")),
            "role": ROLE_MAP.get(as_text(m.get("sender")).lower(), "unknown"),
            "content": as_text(m.get("text")),
            "artifacts": m.get("artifacts") or [],
        } for m in c.get("messages", []) if isinstance(m, dict)]

        paths = []
        for a in (c.get("artifacts") or []):
            raw = a.get("path") if isinstance(a, dict) else getattr(a, "path", "")
            w = windows_path(raw or "")
            if w and w not in paths:
                paths.append(w)
        for m in c.get("messages", []):
            if isinstance(m, dict) and m.get("artifact"):
                w = windows_path(m["artifact"])
                if w and w not in paths:
                    paths.append(w)
        conv_paths = "|".join(paths)

        ordered = [m for m in order_messages(msgs)
                   if m["message_uuid"] or (m["content"] or "").strip()
                   or m["timestamp_utc"]]
        for n, m in enumerate(ordered, 1):
            conversations.append({
                "timestamp": to_kst(m["timestamp_utc"]),
                "conversation_uuid": c["conversation_uuid"],
                "conversation_title": c.get("name") or "",
                "message_uuid": m["message_uuid"],
                # 양식은 뿌리 메시지의 부모를 고정값으로 적는다
                "parent_message_uuid": m["parent_message_uuid"] or ROOT_PARENT,
                "message order": n,
                "role": m["role"],
                "content": m["content"],
                "Artifact_path": conv_paths,
            })

    # 잘린 캐시에서 건진 조각도 싣는다. 온전한 대화로 복원되지는 않았지만
    # 본문 일부가 남아 있다는 사실 자체가 증거다. 모으고 안 보여 주면 버린 것과 같다.
    for r in getattr(rep, "records", []):
        if r.kind != "conversation_fragment":
            continue
        text = r.value if isinstance(r.value, str) else as_text(r.value)
        if not text.strip():
            continue
        conversations.append({
            "timestamp": to_kst(getattr(r, "ts_utc", None)),
            "conversation_uuid": "",
            "conversation_title": "(잘린 응답에서 건진 조각)",
            "message_uuid": "",
            "parent_message_uuid": ROOT_PARENT,
            "message order": 1 + sum(1 for c in conversations
                                     if c["conversation_uuid"] == ""),
            "role": "unknown",
            "content": text,
            "Artifact_path": windows_path(getattr(getattr(r, "ref", None),
                                                  "path", "")),
        })

    return timeline, conversations
