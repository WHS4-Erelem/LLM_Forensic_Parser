"""V8 구조화 복제(structured clone) 바이트에서 본문과 역할을 꺼낸다.

Chromium 은 IndexedDB 값을 V8 직렬화로 넣는데, 문자열을 내용에 따라 다르게 담는다.

    ASCII 만        1바이트(Latin-1)  ->  "role" "user" "session_id" "cse_…"
    비ASCII 포함     UTF-16LE          ->  "이 사진을 분석해 주세요 …"

한 레코드 안에 두 인코딩이 나란히 있어서, 한쪽 기준으로만 읽으면 다른 쪽이
통째로 깨진다. 한글 기준으로 읽으면 ASCII 키가 한자로 보이고, ASCII 기준으로
읽으면 한글이 대체문자로 뭉개진다. 그래서 양쪽을 동시에 본다.

레코드 헤더 길이가 가변이라 UTF-16 문자열이 홀수 오프셋에서 시작하기도 한다.
짝수 정렬로만 읽으면 글자가 한 칸씩 밀려 전부 깨지므로 두 정렬을 모두 본다.
"""

import re

# 사람이 읽는 글자만 — 한글(완성형·자모)·ASCII 출력문자·흔한 문장부호.
# 한자·가나는 정렬이 어긋났을 때 나오는 찌꺼기라 뺀다.
TEXT_RUN = re.compile(r"[가-힣ㄱ-ㆎ -~·‘’“”…°]{6,}")

_HANGUL = re.compile(r"[가-힣ㄱ-ㆎ]")
_WORD = re.compile(r"[A-Za-z]{2,}")
_KEYLIKE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.\-]{0,60}"?$')
_TSLIKE = re.compile(r'^[\d\-:.TZ+ ]{8,}"?$')

# 본문 주변 ASCII 에서 읽어 내는 표식
ROLE_NEAR = re.compile(r"role.{0,8}?(user|assistant|system|human)", re.I | re.S)
SENDER_NEAR = re.compile(r"sender.{0,8}?(human|assistant|user)", re.I | re.S)
SESSION_NEAR = re.compile(r"(cse_[0-9A-Za-z]{18,30})")
UUID_NEAR = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                       re.I)

# 앱이 화면에 쓰는 문구·도구 지시문. 사용자 발화가 아니다.
UI_HINTS = ("<a ", "href=", "</", "ToolSearch", "connectors`", "Note: The set of",
            "개인정보 처리방침", "약관", "자세히 알아보",
            # 도구·스킬 지시문. 모델에게 주는 지침이지 대화 본문이 아니다.
            "your reply", "this step", "skill before", "description\"",
            "<svg", "xmlns", "http://", "https://")

# 셸 명령·코드·직렬화 잔재. 역할 표식이 없어도 대화 본문이 아닌 것들이라
# 따로 거른다. 이걸 안 걸러내면 '역할 미상' 칸이 도구 출력으로 채워진다.
NOISE_RE = re.compile(
    r"(\$\(|2>/dev/null|2>&1|\|\||&&\s|npm\s|node\s|python3?\s-c|NODE_PATH|"
    r"chmod|mkdir\s|wc\s-|\.exe\b|/opt/|/usr/|C:\\\\|"
    r"^\s*[\{\[]|\"ops\"|\"op\"\s*:|_status\b|Uuid\"|AtN?\b|CountI\b|"
    r"[A-Za-z0-9+/]{28,}={0,2}$)")           # base64·토큰 덩어리

# 이 저장소에는 대화가 없다. 앱 번역 번들이라 사람 문장이 수천 건 나온다.
SKIP_FILES = ("indexeddb_blob/2/00/e",)

# 본문 앞뒤에 붙은 직렬화 찌꺼기를 떼어낸다.
_LEAD_JUNK = re.compile(r'^[^가-힣A-Za-z\[(]{1,6}')
# 뒤쪽에는 값의 끝을 알리는 JSON/V8 구분자('"}', '","', '"' …)가 딸려 온다.
_TAIL_JUNK = re.compile(r'["\'\]\},:;\\]{1,6}$')


def views(data):
    """같은 구역을 읽을 수 있는 모든 방식으로. -> [(표기, 문자열, 바이트보정)]"""
    return [("utf-8", data.decode("utf-8", "replace"), 0),
            ("utf-16le", data.decode("utf-16-le", "replace"), 0),
            ("utf-16le+1", data[1:].decode("utf-16-le", "replace"), 1)]


def is_human_text(s):
    """사람이 쓴 문장으로 보이는가. 키 이름·상태값·시각 문자열은 거른다."""
    if _KEYLIKE.match(s) or _TSLIKE.match(s):
        return False
    if "{" in s and "}" in s:            # {max} 같은 번역 자리표시자
        return False
    if any(h in s for h in UI_HINTS):
        return False
    if len(_HANGUL.findall(s)) >= 4:
        return True
    return " " in s and len(s) >= 20 and len(_WORD.findall(s)) >= 4


# 역할 표식이 본문에서 이 거리 안에 있으면 같은 메시지 것으로 본다.
# 멀리 있는 것도 버리지 않되 확신도를 낮춘다.
NEAR_BYTES = 200


def attribute(ascii_view, start, end, window=900):
    """
    본문 주변 ASCII 에서 역할·세션·UUID 를 읽는다.
    -> (역할, 세션ID, UUID, 거리, 모호함) — 역할을 못 읽으면 role 이 None.

    거리는 본문 경계로부터의 바이트 수다. 조사관이 판단할 수 있도록 근거에 남긴다.
    창 안에 서로 다른 역할이 함께 있으면 모호함으로 표시한다.
    """
    lo, hi = max(0, start - window), end + window
    seg = ascii_view[lo:hi]
    hits = []
    for rx in (ROLE_NEAR, SENDER_NEAR):
        for m in rx.finditer(seg):
            pos = lo + m.start()
            dist = pos - end if pos >= end else start - pos
            v = m.group(1).lower()
            hits.append((abs(dist), "user" if v in ("user", "human") else v))
    role, dist, ambiguous = None, None, False
    if hits:
        hits.sort()
        dist, role = hits[0]
        ambiguous = len({v for _, v in hits}) > 1
    s = SESSION_NEAR.search(seg)
    u = UUID_NEAR.search(seg)
    return role, (s.group(1) if s else None), (u.group(1) if u else None), dist, ambiguous


def messages(data, min_len=10, cap=400):
    """
    대화 저장소에서 사람이 읽는 본문을 뽑는다.
    -> [{text, role, conversation_uuid, offset, encoding, role_distance, ...}]

    역할 표식이 없다고 본문을 버리지 않는다. V8 직렬화에서 role 은 일부 구조에만
    붙어서, 표식 없는 본문이 훨씬 많다. 버리면 사용자가 남긴 대화를 통째로 놓친다.

    대신 세 갈래로 나눈다.
        role 표식 가까이(<=200B)  -> user/assistant, 확정
        role 표식 멀리            -> user/assistant, 추정
        role 표식 없음            -> unknown, 역할 미확인
    서로 다른 역할이 섞인 경우만 버린다. 잘못 귀속하느니 안 싣는다.
    """
    ascii_view = data.decode("utf-8", "replace")
    out, seen = [], set()
    for enc, text, shift in views(data):
        for m in TEXT_RUN.finditer(text):
            s = _LEAD_JUNK.sub("", m.group(0).strip()).strip('"\u0000 ').strip()
            s = _TAIL_JUNK.sub("", s).strip()
            if len(s) < min_len or s in seen or not is_human_text(s):
                continue
            if NOISE_RE.search(s):
                continue          # 셸 명령·코드·직렬화 잔재
            width = 2 if enc.startswith("utf-16") else 1
            start = m.start() * width + shift
            end = m.end() * width + shift
            role, sess, uuid, dist, ambiguous = attribute(ascii_view, start, end)
            if ambiguous:
                continue          # 역할이 섞이면 잘못 귀속하느니 안 싣는다
            seen.add(s)
            out.append({"text": s, "role": role or "unknown", "offset": start,
                        "encoding": enc, "role_distance": dist,
                        "role_known": role is not None,
                        "role_near": bool(role) and dist is not None
                                     and dist <= NEAR_BYTES,
                        "conversation_uuid": ("cowork:" + sess) if sess else (uuid or "")})
            if len(out) >= cap:
                return out
    return out
